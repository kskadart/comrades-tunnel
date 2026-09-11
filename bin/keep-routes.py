#!/usr/bin/env python3
"""Compute which of the personal VPN's routes must survive a route-lift.

Used by bin/lib-routes.sh's compute_keep_set() (shared by
bin/cp-connect.sh --method routes and bin/route-lift-watcher.sh) so a
long-lived connection to a configured endpoint -- e.g. a streaming LLM API
reachable only through the personal VPN -- is not disrupted while the rest
of the personal VPN's routes are lifted for a corporate-VPN connect. See
config/example/keep-routes-for.txt for the entry format and the README for
why this exists.

CIDR containment has no sane POSIX sh implementation, so this one
computation (and the DNS resolution that feeds it) lives here instead of
in lib-routes.sh; the repo already depends on python3 for
bin/gen-amnezia-sites.py. This script only reads its two input files and
performs DNS lookups -- it never touches a route or any other system
state, and is safe to run from --dry-run.

Usage:
  keep-routes.py compute KEEP_FILE ROUTES_FILE
      KEEP_FILE   -- config/example/keep-routes-for.txt format: one domain
                     or literal CIDR/IP per line, '#' starts a comment,
                     blank lines ignored. A missing file behaves exactly
                     like an empty one (the feature is simply not
                     configured -- not an error).
      ROUTES_FILE -- "dest gateway" pairs, one per line, dest already
                     normalised (see lib-routes.sh normalize_dest) --
                     exactly what save_amnezia_routes writes.
      Prints one TAB-separated line per KEPT route to stdout:
          dest<TAB>gateway<TAB>entry<TAB>detail
      (detail is the resolved IP for a domain entry, or "-" for a literal
      CIDR/IP entry). Warnings for individual failed entries go to stderr
      and do NOT affect the exit code -- a domain that fails to resolve
      while others succeed is not fatal. Exit 0 on success (a keep-set was
      computed, even if empty, or if it matched no routes). Exit 1 only
      when KEEP_FILE has active entries but every single one failed to
      resolve/parse: the caller must then treat this exactly like any
      other "cannot verify it's safe to proceed" case and lift nothing.

  keep-routes.py --self-test
      Exercises the containment rule and the empty-file/total-failure
      rules against fixed inputs; PASS/FAIL per case; exit 0 iff all pass.
"""
import ipaddress
import socket
import sys

RESOLVE_TIMEOUT = 3  # seconds per domain lookup, per the README/header


def parse_active_entries(path):
    """Non-comment, non-blank lines from path. A missing/unreadable path
    yields [] -- that means "feature not configured", not an error."""
    entries = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line)
    except OSError:
        return []
    return entries


def is_literal(entry):
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def resolve_entry(entry, timeout=RESOLVE_TIMEOUT):
    """Return (list of (network, detail), error_or_None) for one keep-file
    entry. A literal IP/CIDR always succeeds with detail "-". A domain is
    resolved to its IPv4 addresses via getaddrinfo; error is a short
    human-readable string on failure, None on success."""
    if is_literal(entry):
        net = ipaddress.ip_network(entry, strict=False)
        return [(net, "-")], None
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(entry, None, socket.AF_INET)
    except OSError as exc:
        return [], str(exc)
    finally:
        socket.setdefaulttimeout(old_timeout)
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        return [], "no A records"
    return [(ipaddress.ip_network(addr + "/32"), addr) for addr in addrs], None


def network_contains(outer, inner):
    """True if inner's whole address range is within outer's (an equal
    network counts as contained -- this is what makes a literal keep-CIDR
    match a route that equals it, and a route that merely contains it)."""
    return (int(inner.network_address) >= int(outer.network_address)
            and int(inner.broadcast_address) <= int(outer.broadcast_address))


def parse_routes(path):
    """Yield (dest_text, gateway_text, network_or_None) for every line in
    path. network is None for "default" or anything else that fails to
    parse -- callers must simply skip those, never treat it as fatal (the
    default route is never a candidate to keep or delete -- see
    lib-routes.sh delete_amnezia_routes)."""
    routes = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split(" ", 1)
            dest = parts[0]
            gw = parts[1] if len(parts) > 1 else ""
            if dest == "default":
                routes.append((dest, gw, None))
                continue
            try:
                net = ipaddress.ip_network(dest, strict=False)
            except ValueError:
                net = None
            routes.append((dest, gw, net))
    return routes


def compute(keep_file, routes_file):
    """Return (kept_lines, warnings, fatal_or_None).
    kept_lines: "dest\\tgateway\\tentry\\tdetail" strings, one per kept route.
    warnings: human-readable per-entry warning strings (non-fatal).
    fatal_or_None: set exactly when every active entry failed to
    resolve/parse -- the caller must then lift nothing this cycle."""
    entries = parse_active_entries(keep_file)
    if not entries:
        return [], [], None

    resolved = []  # (network, entry, detail)
    warnings = []
    for entry in entries:
        nets, err = resolve_entry(entry)
        if err is not None:
            warnings.append(
                "keep-routes: '%s' did not resolve (%s) -- skipping this entry"
                % (entry, err)
            )
            continue
        for net, detail in nets:
            resolved.append((net, entry, detail))

    if not resolved:
        return [], warnings, (
            "%d active entr%s in %s but none resolved/parsed -- "
            "cannot compute the keep-set"
            % (len(entries), "y" if len(entries) == 1 else "ies", keep_file)
        )

    routes = parse_routes(routes_file)
    kept = []
    for dest, gw, net in routes:
        if net is None:
            continue
        for keep_net, entry, detail in resolved:
            if network_contains(net, keep_net):
                kept.append("%s\t%s\t%s\t%s" % (dest, gw, entry, detail))
                break
    return kept, warnings, None


def cmd_compute(argv):
    if len(argv) != 2:
        print("usage: keep-routes.py compute KEEP_FILE ROUTES_FILE", file=sys.stderr)
        return 2
    keep_file, routes_file = argv
    kept, warnings, fatal = compute(keep_file, routes_file)
    for w in warnings:
        print("WARNING: %s" % w, file=sys.stderr)
    if fatal:
        print("FATAL: %s" % fatal, file=sys.stderr)
        return 1
    for line in kept:
        print(line)
    return 0


def cmd_self_test():
    fail = [0]

    def check(desc, cond):
        if cond:
            print("PASS  %s" % desc)
        else:
            print("FAIL  %s" % desc)
            fail[0] = 1

    big = ipaddress.ip_network("5.32.0.0/13")
    inside = ipaddress.ip_network("5.35.10.20/32")
    outside = ipaddress.ip_network("6.0.0.1/32")
    check("address inside a large aggregated block is matched", network_contains(big, inside))
    check("address outside it is not", not network_contains(big, outside))

    equal_route = ipaddress.ip_network("1.2.3.0/24")
    equal_keep = ipaddress.ip_network("1.2.3.0/24")
    check("literal CIDR entry matches a route that equals it", network_contains(equal_route, equal_keep))

    broad_route = ipaddress.ip_network("1.2.0.0/16")
    narrow_keep = ipaddress.ip_network("1.2.3.0/24")
    check("literal CIDR entry matches a route that contains it", network_contains(broad_route, narrow_keep))

    import os
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        routes_path = os.path.join(d, "routes.txt")
        with open(routes_path, "w") as f:
            f.write("1.2.3.0/24 utun9\n")

        empty_keep = os.path.join(d, "empty.txt")
        open(empty_keep, "w").close()
        kept, _warnings, fatal = compute(empty_keep, routes_path)
        check("empty keep file yields an empty keep-set and no fail-safe", kept == [] and fatal is None)

        missing_keep = os.path.join(d, "does-not-exist.txt")
        kept, _warnings, fatal = compute(missing_keep, routes_path)
        check("missing keep file behaves like an empty one", kept == [] and fatal is None)

        allfail_keep = os.path.join(d, "allfail.txt")
        with open(allfail_keep, "w") as f:
            f.write("this-name-does-not-exist-comrades-tunnel.invalid\n")
        kept, _warnings, fatal = compute(allfail_keep, routes_path)
        check("a keep file whose every lookup failed triggers the fail-safe", fatal is not None and kept == [])

        literal_keep = os.path.join(d, "literal.txt")
        with open(literal_keep, "w") as f:
            f.write("1.2.3.0/24\n")
        kept, _warnings, fatal = compute(literal_keep, routes_path)
        check("a literal CIDR entry keeps a route on a real compute() call", fatal is None and len(kept) == 1)

    return fail[0]


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "compute":
        sys.exit(cmd_compute(sys.argv[2:]))
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        sys.exit(cmd_self_test())
    sys.stderr.write(__doc__ + "\n")
    sys.exit(2)


if __name__ == "__main__":
    main()
