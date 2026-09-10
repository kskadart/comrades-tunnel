#!/usr/bin/env python3
"""Generate the AmneziaVPN "only selected sites" list.

Amnezia is kept in "only selected sites" split-tunneling mode (the "except
selected sites" mode has open macOS bugs). So this script generates the
*complement*: every IPv4 address MINUS everything that must stay off the
personal VPN:

  - special-purpose / reserved IPv4 ranges (RFC 1918 and friends)
  - configured direct-cidrs.txt (corporate VPN gateways / public netblocks)
  - resolved IPv4 addresses of direct-domains.txt (geo-blocking-sensitive
    Russian services that must be reached directly)
  - resolved IPv4 addresses of corp-hosts-check.txt (known corporate hosts)
  - the nameservers of the primary system DNS resolver (resolver #1 in
    `scutil --dns`), so DNS itself never goes through the tunnel

The corporate 10.x/172.16.x prefixes pushed into the Check Point tunnel and
the excluded RFC 1918 space overlap by design -- longest-prefix-match
routing keeps corporate traffic on the corporate tunnel regardless of what
this tool excludes from the personal VPN.

Output (AmneziaVPN JSON import format -- see importSitesFromJson() in
amnezia-vpn/amnezia-client, client/core/controllers/ipSplitTunnelingController.cpp):
    build/amnezia-sites.json   -- [{"hostname": "<cidr>", "ips": [], "ip": ""}, ...]
    build/amnezia-sites.txt    -- one CIDR per line, for human review

Usage:
    gen-amnezia-sites.py [--config DIR] [--dry-run]
"""
import argparse
import ipaddress
import socket
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

# Special-purpose IPv4 ranges excluded from the personal VPN. Includes the
# well-known private/reserved blocks (RFC 1918 / RFC 6598 / RFC 3927 / etc.)
# plus the small documentation/benchmarking/shared-NAT ranges (192.0.0.0/24,
# 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24). Those last
# five carry no real traffic, so including them is harmless and keeps the
# exclusion set "complete" against RFC 6890; they are included rather than
# omitted.
SPECIAL_RANGES = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
]

FULL_IPV4 = ipaddress.ip_network("0.0.0.0/0")
MAX_ADDR = 2 ** 32


def read_list(path: Path) -> list:
    """Read a config file: one entry per line, '#' comments, blanks skipped."""
    if not path.exists():
        return []
    out = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def resolve_ipv4(host: str) -> list:
    """Resolve a hostname to its IPv4 addresses. Warn and continue on failure."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
    except socket.gaierror as exc:
        print(f"WARNING: failed to resolve '{host}': {exc}")
        return []
    return sorted({info[4][0] for info in infos})


def primary_resolver_nameservers() -> list:
    """Nameservers of resolver #1 from `scutil --dns` (the primary system resolver)."""
    try:
        proc = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, check=True
        )
    except Exception as exc:  # noqa: BLE001 - best-effort, never fatal
        print(f"WARNING: failed to run 'scutil --dns': {exc}")
        return []

    # `scutil --dns` prints a "DNS configuration" section followed by a
    # separate "DNS configuration (for scoped queries)" section, each with
    # its own "resolver #1" -- stop after the first resolver #1 block so
    # scoped-query duplicates of the same nameservers aren't double counted.
    nameservers = []
    in_resolver_1 = False
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("resolver #") or stripped.startswith("DNS configuration"):
            if in_resolver_1:
                break  # end of the first resolver #1 block
            in_resolver_1 = stripped == "resolver #1"
            continue
        if in_resolver_1 and stripped.startswith("nameserver["):
            _, _, value = stripped.partition(":")
            ip = value.strip()
            if ip:
                nameservers.append(ip)
    return nameservers


def address_exclude_all(base_networks, exclusions):
    """Complement of the full IPv4 space minus `exclusions`, computed linearly
    over the gaps between consecutive collapsed exclusions.

    Exclusions are merged with ipaddress.collapse_addresses() and sorted by
    start address; then, walking from 0 to 2^32-1, every gap between one
    exclusion and the next is emitted via ipaddress.summarize_address_range().
    This is linear in the number of collapsed exclusions, so it scales to
    exclusion sets of tens of thousands of networks (e.g. a country's IP
    ranges) -- unlike repeated IPv4Network.address_exclude() calls, which are
    quadratic. `base_networks` is accepted for caller compatibility but the
    complement always spans the whole 0.0.0.0/0 space."""
    collapsed = sorted(
        ipaddress.collapse_addresses(exclusions),
        key=lambda n: (int(n.network_address), n.prefixlen),
    )
    sites = []
    cursor = 0  # integer start of the not-yet-covered span
    for net in collapsed:
        start = int(net.network_address)
        if start > cursor:
            sites.extend(
                ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(cursor),
                    ipaddress.IPv4Address(start - 1),
                )
            )
        cursor = int(net.broadcast_address) + 1
    if cursor <= MAX_ADDR - 1:
        sites.extend(
            ipaddress.summarize_address_range(
                ipaddress.IPv4Address(cursor),
                ipaddress.IPv4Address(MAX_ADDR - 1),
            )
        )
    return sites, collapsed


def covered_by(ip_str: str, networks) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return any(ip in net for net in networks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--config",
        default=None,
        help="config directory (default: local/ next to the repo root)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be generated but do not write build/ files",
    )
    args = parser.parse_args()

    config_dir = Path(args.config).resolve() if args.config else (REPO_ROOT / "local")
    if not config_dir.is_dir():
        print(f"ERROR: config dir not found: {config_dir}", file=sys.stderr)
        return 1

    print(f"Config dir: {config_dir}")

    direct_cidrs_raw = read_list(config_dir / "direct-cidrs.txt")
    direct_domains = read_list(config_dir / "direct-domains.txt")
    corp_hosts_check = read_list(config_dir / "corp-hosts-check.txt")

    exclusions = set()

    for cidr in SPECIAL_RANGES:
        exclusions.add(ipaddress.ip_network(cidr))

    n_direct_cidrs = 0
    parsed_direct_cidrs = []  # valid CIDR networks parsed from direct-cidrs.txt
    for cidr in direct_cidrs_raw:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            print(f"WARNING: skipping invalid CIDR '{cidr}' in direct-cidrs.txt: {exc}")
            continue
        exclusions.add(net)
        parsed_direct_cidrs.append(net)
        n_direct_cidrs += 1

    resolved_direct = []  # (host, ip)
    for host in direct_domains:
        for ip in resolve_ipv4(host):
            exclusions.add(ipaddress.ip_network(f"{ip}/32"))
            resolved_direct.append((host, ip))

    resolved_corp_hosts = []  # (host, ip)
    for host in corp_hosts_check:
        for ip in resolve_ipv4(host):
            exclusions.add(ipaddress.ip_network(f"{ip}/32"))
            resolved_corp_hosts.append((host, ip))

    resolver_ns = primary_resolver_nameservers()
    for ip in resolver_ns:
        exclusions.add(ipaddress.ip_network(f"{ip}/32"))

    sites, collapsed_exclusions = address_exclude_all([FULL_IPV4], exclusions)
    sites.sort(key=lambda n: (int(n.network_address), n.prefixlen))

    total_excluded = sum(net.num_addresses for net in collapsed_exclusions)
    total_covered = sum(net.num_addresses for net in sites)

    print()
    print("=== Exclusion summary ===")
    print(f"  special/reserved ranges     : {len(SPECIAL_RANGES)}")
    print(f"  direct-cidrs.txt entries    : {n_direct_cidrs}")
    print(f"  direct-domains.txt          : {len(direct_domains)} domain(s) -> {len(resolved_direct)} resolved IPv4")
    for host, ip in resolved_direct:
        print(f"      {host} -> {ip}")
    print(f"  corp-hosts-check.txt        : {len(corp_hosts_check)} host(s) -> {len(resolved_corp_hosts)} resolved IPv4")
    for host, ip in resolved_corp_hosts:
        print(f"      {host} -> {ip}")
    print(f"  primary resolver nameservers: {len(resolver_ns)} -> {resolver_ns}")
    print(f"  collapsed exclusion networks: {len(collapsed_exclusions)}")
    print(f"  total excluded addresses    : {total_excluded}")
    print()
    print("=== Result ===")
    print(f"  site networks (covered)     : {len(sites)}")
    print(f"  total covered addresses     : {total_covered}")
    print(f"  covered + excluded          : {total_covered + total_excluded} (2^32 = {MAX_ADDR})")

    build_dir = REPO_ROOT / "build"
    json_path = build_dir / "amnezia-sites.json"
    txt_path = build_dir / "amnezia-sites.txt"

    if args.dry_run:
        print()
        print(f"[dry-run] would write {len(sites)} entries to {json_path} and {txt_path}")
    else:
        build_dir.mkdir(parents=True, exist_ok=True)
        entries = [{"hostname": str(net), "ips": [], "ip": ""} for net in sites]
        with json_path.open("w") as fh:
            fh.write("[\n")
            for i, entry in enumerate(entries):
                comma = "," if i < len(entries) - 1 else ""
                fh.write(
                    '  {"hostname": "%s", "ips": [], "ip": ""}%s\n' % (entry["hostname"], comma)
                )
            fh.write("]\n")
        with txt_path.open("w") as fh:
            for net in sites:
                fh.write(f"{net}\n")
        print()
        print(f"Wrote {len(sites)} entries to {json_path}")
        print(f"Wrote {len(sites)} lines to {txt_path}")

    # --- Self-checks ---
    print()
    print("=== Self-checks ===")
    ok = True

    def check(label, cond):
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        print(f"  [{status}] {label}")

    check("8.8.8.8 is covered by the site list", covered_by("8.8.8.8", sites))
    check("1.1.1.1 is covered by the site list", covered_by("1.1.1.1", sites))

    # Representative private (RFC 1918) addresses must NOT be covered -- they
    # are excluded via the special-purpose ranges above.
    for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        check(f"{ip} is NOT covered by the site list", not covered_by(ip, sites))

    # First address of every direct-cidrs.txt entry must NOT be covered (the
    # entire entry is excluded, so even its first host must stay off the site
    # list). Config-driven -- no machine-specific IP hardcoded here.
    for net in parsed_direct_cidrs:
        first = net.network_address
        check(f"direct-cidrs.txt first address {first} is NOT covered by the site list",
              not covered_by(str(first), sites))

    # Every resolved direct-domains.txt IP must NOT be covered. Unresolvable
    # placeholder domains (e.g. in config/example) only produce WARNINGs above,
    # so this check is skipped when nothing resolved.
    if resolved_direct:
        for host, ip in resolved_direct:
            check(f"direct-domains.txt host {host} ({ip}) is NOT covered by the site list",
                  not covered_by(ip, sites))
    else:
        print("  [SKIP] no direct-domains.txt hosts resolved")

    # corp-hosts-check.txt may resolve to public (non-RFC1918, non-direct-cidr)
    # IPs -- e.g. a corporate host hosted outside the corporate network's own
    # netblocks. Those are excluded from the site list only via this
    # host-resolution step, not via any CIDR range, so verifying each one is
    # a meaningful check of that exclusion path (config-driven, no hostname
    # hardcoded here -- see resolved_corp_hosts, built from corp-hosts-check.txt).
    if resolved_corp_hosts:
        for host, ip in resolved_corp_hosts:
            check(f"corp-hosts-check.txt host {host} ({ip}) is NOT covered by the site list",
                  not covered_by(ip, sites))
    else:
        print("  [SKIP] no corp-hosts-check.txt hosts resolved")

    # Every primary-resolver nameserver must NOT be covered, so DNS traffic
    # itself never enters the personal VPN tunnel.
    for ip in resolver_ns:
        check(f"primary resolver nameserver {ip} is NOT covered by the site list",
              not covered_by(ip, sites))

    # Linear disjointness sweep: sites and collapsed exclusions merged into one
    # list sorted by start address; each network must begin after the previous
    # one ends. Linear in the combined size -- no site-vs-exclusion pairwise
    # loop (which would be quadratic with tens of thousands of exclusions).
    disjoint = True
    merged = sorted(
        sites + collapsed_exclusions,
        key=lambda n: (int(n.network_address), n.prefixlen),
    )
    prev_end = None
    for net in merged:
        start = int(net.network_address)
        if prev_end is not None and start <= prev_end:
            disjoint = False
            print(f"      overlap: network {net} starts at {start}, "
                  f"previous ends at {prev_end + 1}")
            break
        prev_end = int(net.broadcast_address)
    check("site list is disjoint from every exclusion", disjoint)

    check("covered + excluded addresses == 2^32", total_covered + total_excluded == MAX_ADDR)

    print()
    if ok:
        print("All self-checks PASSED")
    else:
        print("Some self-checks FAILED")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
