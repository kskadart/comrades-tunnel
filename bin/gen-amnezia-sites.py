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
  - DNS servers handed out by DHCP on the primary interface (`ipconfig
    getoption <iface> domain_name_server`), so DNS traffic never goes through
    the tunnel -- plus any extra IPs from direct-dns.txt
    (e.g. an office resolver on a network where DHCP does not offer it)

By default each direct-domains.txt entry is *expanded* to the whole
autonomous system (AS) that owns it when that is safe: the domain is
resolved, the first IP is looked up in RIPEstat to find the owning ASN(s),
and if the ASN is registered to country RU (per the RIPE NCC delegated
file) and announces a bounded number of IPv4 prefixes, then ALL of those
prefixes are excluded -- not just the resolved /32s. This covers
CDN/load-balancer ranges whose member addresses change over time. See the
"--no-asn" flag and the direct-domains.txt syntax below.

The corporate 10.x/172.16.x prefixes pushed into the Check Point tunnel and
the excluded RFC 1918 space overlap by design -- longest-prefix-match
routing keeps corporate traffic on the corporate tunnel regardless of what
this tool excludes from the personal VPN.

`--max-sites N` shrinks the site list by greedily merging the smallest gaps
between exclusions until it fits N networks. keep-tunneled.txt pins networks
(public DNS resolvers by default) that this merging must never swallow: a
gap containing a pinned network is never merged, however small it is. If
the budget cannot be reached because every remaining gap is protected, the
tool prints a WARNING and keeps the pins intact rather than exceeding the
budget silently. This works as an efficient additive budget specifically
because each gap's own site-block count can be removed independently of
every other merge (see merge_gaps_to_budget()'s docstring) -- once merges
start chaining, the resulting *exclusion* entry count is a property of the
whole fused range, not a sum of the parts, so the same trick does not carry
over to shrinking the exclusion list. That is why `--mode exclude` (below)
ignores `--max-sites` outright, with a WARNING, rather than offer a budget
that cannot honestly guarantee the requested count.

`--mode {forward,exclude}` selects which AmneziaVPN split-tunneling mode
this run generates for:
  - forward (default): today's behaviour, unchanged -- writes the *site
    list* (the complement) for AmneziaVPN's "only selected sites" mode.
  - exclude: writes the *exclusion set itself* -- the very same
    `collapsed_exclusions` this script always computes internally -- for
    AmneziaVPN's "all sites except the listed ones" mode. Client-side (see
    MacosRouteMonitor::addExclusionRoute), that mode installs only four
    fixed half-space routes on the personal VPN's own interface plus one
    real kernel route per excluded network via the physical gateway, so
    writing the (much smaller) exclusion set instead of its complement
    cuts the installed route count dramatically -- see the README.
  Each mode only ever touches its own two output files below; the other
  mode's files are left untouched.

Output (AmneziaVPN JSON import format -- see importSitesFromJson() in
amnezia-vpn/amnezia-client, client/core/controllers/ipSplitTunnelingController.cpp):
    --mode forward (default):
        build/amnezia-sites.json    -- [{"hostname": "<cidr>", "ips": [], "ip": ""}, ...]
        build/amnezia-sites.txt     -- one CIDR per line, for human review
    --mode exclude:
        build/amnezia-exclude.json  -- same JSON shape, one entry per excluded network
        build/amnezia-exclude.txt   -- one CIDR per line, for human review
  The paths above are exactly right for the default config (local/, or no
  --config at all). Passing --config anywhere else (e.g. config/example)
  writes the very same four filenames under build/<config-dir-basename>/
  instead -- e.g. build/example/amnezia-sites.json -- so a demo/offline run
  against a non-default config can never clobber the real build/ output.
  RIPEstat/RIPE NCC caches and the last-known-good DNS cache under
  build/cache/ are shared across configs on purpose (they are keyed by
  hostname/IP/ASN, not by config, so two configs' entries simply coexist
  there without colliding).

Usage:
    gen-amnezia-sites.py [--config DIR] [--dry-run] [--dry-run-output PATH]
                         [--mode {forward,exclude}] [--no-asn]
                         [--refresh] [--max-sites N] [--resolve-timeout N]
                         [--fallback-dns IP] [--self-test]

direct-domains.txt syntax (optional second token after the domain):
    <domain>            expand to whole ASN when safe (RU-country, under cap)
    <domain> asn        force expansion to the whole ASN (ignore cap/country rule)
    <domain> ip         force IP-only expansion (only the resolved /32s)
"""
import argparse
import heapq
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
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

# ASN expansion tunables.
ASN_MAX_PREFIXES = 200  # cap: bigger ISPs announce thousands of prefixes
CACHE_AGE_SECONDS = 7 * 24 * 3600  # reuse cache / RIPE file inside a week
HTTP_TIMEOUT = 20  # seconds per request
USER_AGENT = "comrades-tunnel/1.0"
RIPENCC_URL = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}&sourceapp=comrades-tunnel"
ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=comrades-tunnel"
AS_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}&sourceapp=comrades-tunnel"

# DNS resolution tunables (see resolve_ipv4()/dns_query_a() below): bounding
# every hostname lookup matters specifically because /etc/resolver/<zone>
# points corporate-zone lookups at corporate DNS servers that are only
# reachable through the corporate VPN tunnel -- with the tunnel down, the
# system resolver retries unreachable servers for a long time per host.
DEFAULT_RESOLVE_TIMEOUT = 5.0  # seconds; hard cap per system-resolver lookup
DEFAULT_FALLBACK_DNS = "1.1.1.1"  # public resolver for corp-hosts-check.txt
DNS_FALLBACK_TIMEOUT = 3.0  # seconds; one attempt against --fallback-dns


def _atomic_write_text(path: Path, text: str) -> None:
    """Write text to `path` atomically: write to '<path>.tmp' then rename."""
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes to `path` atomically: write to '<path>.tmp' then rename."""
    tmp = Path(str(path) + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


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


def read_direct_domains(path: Path) -> list:
    """Read direct-domains.txt. Returns a list of (domain, override) tuples.

    Each non-empty line is "<domain> [asn|ip]" -- the optional second token
    forces whole-ASN ("asn") or IP-only ("ip") expansion for that domain.
    """
    if not path.exists():
        return []
    out = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.split()
        domain = toks[0]
        override = None
        if len(toks) >= 2:
            override = toks[1].lower()
            if override not in ("asn", "ip"):
                print(f"WARNING: invalid override '{toks[1]}' for '{domain}'; ignoring it")
                override = None
        out.append((domain, override))
    return out


def resolve_ipv4(host: str, timeout: float = DEFAULT_RESOLVE_TIMEOUT) -> list:
    """Resolve a hostname to its IPv4 addresses via the system resolver, with
    a hard wall-clock cap of `timeout` seconds. Warn and continue on failure.

    socket.getaddrinfo() has no timeout of its own -- when /etc/resolver/
    <zone> points a corporate zone at corporate DNS servers that are only
    reachable through the corporate VPN tunnel, an unreachable resolver makes
    getaddrinfo() block for a long time (the system resolver retries each
    configured server with its own multi-second timeout). So the actual
    lookup runs in a daemon thread that this function joins with `timeout`:
    if the thread is still running when the join returns, the lookup is
    treated exactly like a resolution failure and abandoned -- the thread
    keeps blocking on the real, unreachable resolver in the background, but
    because it is a daemon thread it never delays process exit.
    """
    outcome = {}

    def worker():
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
            outcome["ips"] = sorted({info[4][0] for info in infos})
        except socket.gaierror as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        print(f"WARNING: failed to resolve '{host}': timed out after {timeout}s")
        return []
    if "error" in outcome:
        print(f"WARNING: failed to resolve '{host}': {outcome['error']}")
        return []
    return outcome.get("ips", [])


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Advance past one DNS-encoded name (RFC 1035 SS4.1.4, including pointer
    compression) starting at `offset`; return the offset of the first byte
    after it. Used only to walk past names in a reply this code itself
    parses (question/answer sections of dns_query_a()'s own response)."""
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer: 2 bytes, then done
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length
    return offset


def dns_query_a(qname: str, server: str, timeout: float = DNS_FALLBACK_TIMEOUT) -> list:
    """Minimal stdlib DNS client: query `server` for the IPv4 (A) records of
    `qname` over UDP (RFC 1035), one attempt, with a hard `timeout`. No
    `dig`/external dependency. Returns [] on any failure -- timeout,
    unreachable server, malformed reply, NXDOMAIN, no A records -- never
    raises to the caller.
    """
    try:
        qid = random.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
        question = b"".join(
            struct.pack("B", len(label)) + label.encode("ascii")
            for label in qname.rstrip(".").split(".")
        ) + b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(header + question, (server, 53))
            data, _ = sock.recvfrom(512)
    except (OSError, UnicodeEncodeError):
        return []

    if len(data) < 12 or data[0:2] != struct.pack(">H", qid):
        return []
    rcode = data[3] & 0x0F
    qdcount, ancount = struct.unpack(">HH", data[4:8])
    if rcode != 0 or ancount == 0:
        return []

    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset) + 4  # + QTYPE + QCLASS

    ips = []
    for _ in range(ancount):
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == 1 and rclass == 1 and rdlength == 4:  # A record, IN class
            ips.append(".".join(str(b) for b in data[offset:offset + 4]))
        offset += rdlength
    return sorted(set(ips))


def dns_cache_path(cache_dir: Path, host: str) -> Path:
    """Path of the last-known-good DNS cache file for `host`."""
    return cache_dir / f"{host}.json"


def dns_cache_read(cache_dir: Path, host: str, max_age: float):
    """Return (ips, resolved_at) for `host` if a cache file exists, parses,
    and is younger than `max_age` seconds; else None. Never raises."""
    path = dns_cache_path(cache_dir, host)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        ips, resolved_at = data.get("ips") or [], data.get("resolved_at") or 0
    except (json.JSONDecodeError, OSError):
        return None
    if not ips or (time.time() - resolved_at) >= max_age:
        return None
    return ips, resolved_at


def dns_cache_write(cache_dir: Path, host: str, ips: list) -> None:
    """Persist a successful resolution of `host` as the last-known-good
    cache, atomically. Best-effort: a write failure is not fatal to the
    caller's resolution result, just to the cache update."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(
            dns_cache_path(cache_dir, host),
            json.dumps({"host": host, "ips": ips, "resolved_at": time.time()}),
        )
    except OSError as exc:
        print(f"WARNING: failed to write DNS cache for '{host}': {exc}")


def resolve_corp_host(host: str, timeout: float, fallback_dns: str, cache_dir: Path,
                       refresh: bool, stats: dict):
    """Resolve one corp-hosts-check.txt entry: system resolver -> public
    fallback DNS -> last-known-good cache (in that order), updating `stats`
    with which path supplied the answer. Returns (ips, source) where source
    is one of "live", "fallback", "cache", "fail".

    The public fallback exists because a corp-hosts-check.txt entry can be a
    public hostname (hosted outside the corporate network) that is normally
    excluded from the personal VPN via its resolved /32 -- with the
    corporate VPN down, /etc/resolver/<zone> routes its lookup at an
    unreachable corporate server even though a public resolver would answer
    it fine, so without this fallback its /32 would silently drop out of the
    exclusion list. Internal-only names legitimately fail both ways; that is
    not an error, just a WARNING.
    """
    ips = resolve_ipv4(host, timeout)
    if ips:
        dns_cache_write(cache_dir, host, ips)
        stats["live"] += 1
        return ips, "live"

    fallback_ips = dns_query_a(host, fallback_dns, timeout=DNS_FALLBACK_TIMEOUT)
    if fallback_ips:
        print(f"INFO: '{host}' resolved via public fallback DNS {fallback_dns} "
              f"because the corporate resolver was unreachable: {','.join(fallback_ips)}")
        dns_cache_write(cache_dir, host, fallback_ips)
        stats["fallback"] += 1
        return fallback_ips, "fallback"

    if not refresh:
        cached = dns_cache_read(cache_dir, host, CACHE_AGE_SECONDS)
        if cached:
            cached_ips, resolved_at = cached
            age = time.strftime("%Y-%m-%d %H:%M", time.localtime(resolved_at))
            print(f"WARNING: '{host}' unreachable via the corporate resolver and the public "
                  f"fallback -- the corporate VPN tunnel seems to be down; using the last "
                  f"known addresses from {age}: {','.join(cached_ips)}")
            stats["cache"] += 1
            return cached_ips, "cache"

    print(f"WARNING: '{host}' could not be resolved (corporate resolver, public fallback, "
          f"and cache all failed, are stale, or --refresh was requested)")
    stats["failed"] += 1
    return [], "fail"


def resolve_direct_domain(domain: str, timeout: float, cache_dir: Path, refresh: bool, stats: dict):
    """Resolve one direct-domains.txt entry: system resolver -> last-known-
    good cache (no public fallback -- these must resolve the way the user
    actually experiences them, via the system resolver). Returns (ips,
    source) where source is one of "live", "cache", "fail"."""
    ips = resolve_ipv4(domain, timeout)
    if ips:
        dns_cache_write(cache_dir, domain, ips)
        stats["live"] += 1
        return ips, "live"

    if not refresh:
        cached = dns_cache_read(cache_dir, domain, CACHE_AGE_SECONDS)
        if cached:
            cached_ips, resolved_at = cached
            age = time.strftime("%Y-%m-%d %H:%M", time.localtime(resolved_at))
            print(f"WARNING: '{domain}' failed to resolve; using last known addresses "
                  f"from {age}: {','.join(cached_ips)}")
            stats["cache"] += 1
            return cached_ips, "cache"

    stats["failed"] += 1
    return [], "fail"


def self_test(fallback_dns: str) -> int:
    """Quick self-test of dns_query_a(): a positive case against a real
    public resolver and a negative case against a non-routable resolver
    address that must time out within DNS_FALLBACK_TIMEOUT and never raise."""
    print("=== --self-test: minimal stdlib DNS client (dns_query_a) ===")
    ok = True

    print(f"  positive: A query for 'dns.google' via {fallback_dns} ...")
    start = time.perf_counter()
    ips = dns_query_a("dns.google", fallback_dns)
    elapsed = time.perf_counter() - start
    well_formed = bool(ips) and all(_looks_like_ipv4(ip) for ip in ips)
    print(f"    result: {ips} ({elapsed:.2f}s)")
    check_label = "positive case returned a well-formed IPv4 answer"
    print(f"  [{'PASS' if well_formed else 'FAIL'}] {check_label}")
    ok = ok and well_formed

    non_routable = "192.0.2.1"  # TEST-NET-1 (RFC 5737): documented, never routable
    print(f"  negative: A query for 'dns.google' via non-routable {non_routable} ...")
    start = time.perf_counter()
    raised = False
    try:
        ips2 = dns_query_a("dns.google", non_routable)
    except Exception as exc:  # noqa: BLE001 - the case under test is "must not raise"
        raised = True
        ips2 = None
        print(f"    raised: {exc!r}")
    elapsed2 = time.perf_counter() - start
    within_cap = elapsed2 <= DNS_FALLBACK_TIMEOUT + 1.0  # scheduling slack
    print(f"    result: {ips2} ({elapsed2:.2f}s, within {DNS_FALLBACK_TIMEOUT}s cap: {within_cap})")
    negative_ok = (not raised) and ips2 == [] and within_cap
    check_label = "negative case timed out within the cap and did not raise"
    print(f"  [{'PASS' if negative_ok else 'FAIL'}] {check_label}")
    ok = ok and negative_ok

    print()
    print("Self-test " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def _looks_like_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def http_get_json(url: str) -> dict:
    """GET a JSON URL with the tool User-Agent and a bounded timeout."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.load(resp)


def fetch_cached_json(url: str, cache_path: Path, refresh: bool) -> dict:
    """Fetch a JSON URL, caching it under build/cache (7-day freshness).

    'refresh' forces a re-download. Prints a one-line cache hit/miss note.
    A cache file that fails to parse as JSON is deleted and re-fetched once;
    if that re-fetch also fails, the exception propagates to the caller,
    which already warns and falls back.
    """
    if cache_path.exists() and not refresh and (time.time() - cache_path.stat().st_mtime) < CACHE_AGE_SECONDS:
        try:
            data = json.loads(cache_path.read_text())
            print(f"  cache: hit {cache_path.relative_to(REPO_ROOT)}")
            return data
        except json.JSONDecodeError as exc:
            print(f"  cache: corrupt {cache_path.relative_to(REPO_ROOT)} ({exc}); deleting and re-fetching")
            cache_path.unlink(missing_ok=True)
    data = http_get_json(url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(cache_path, json.dumps(data))
    print(f"  cache: fetched {cache_path.relative_to(REPO_ROOT)}")
    return data


def ensure_ripencc_file(path: Path, refresh: bool) -> bool:
    """Ensure the RIPE NCC delegated-extended file is on disk and fresh.

    Returns True if a usable file exists (freshly downloaded, cached-still-
    usable, or stale-but-present after a failed download). Returns False only
    when there is nothing to read at all.
    """
    if path.exists() and not refresh and (time.time() - path.stat().st_mtime) < CACHE_AGE_SECONDS:
        print(f"cache: hit {path.relative_to(REPO_ROOT)}")
        return True
    try:
        req = urllib.request.Request(RIPENCC_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = resp.read()
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(path, data)
        print(f"cache: fetched {path.relative_to(REPO_ROOT)} ({len(data)} bytes)")
        return True
    except Exception as exc:  # noqa: BLE001 - best-effort, fall back gracefully
        print(f"WARNING: failed to fetch {RIPENCC_URL}: {exc}")
        return path.exists()


def default_interface() -> str:
    """Name of the primary interface (the default route's interface)."""
    try:
        proc = subprocess.run(
            ["route", "-n", "get", "default"], capture_output=True, text=True, check=True
        )
    except Exception as exc:  # noqa: BLE001 - best-effort, never fatal
        print(f"INFO: failed to run 'route -n get default': {exc}; no primary interface")
        return ""
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface:"):
            return stripped.partition(":")[2].strip()
    print("INFO: no interface found in 'route -n get default' output")
    return ""


def dhcp_nameservers() -> list:
    """Nameservers handed out by DHCP on the primary interface.

    The primary interface is `default_interface()`. `ipconfig getoption
    <iface> domain_name_server` only ever prints the first DHCP nameserver,
    even when the DHCP lease offered several -- so nameservers are parsed
    from `ipconfig getpacket <iface>` instead, which prints the full option
    as a `domain_name_server (ip_mult): {a, b, c}` line. `getoption` is used
    only as a fallback when `getpacket` yields nothing (e.g. no active
    lease). Best-effort: any failure or empty result returns [] with an
    INFO line -- never fatal.
    """
    iface = default_interface()
    if not iface:
        print("INFO: unknown primary interface; no DHCP nameservers")
        return []

    nameservers = []
    try:
        proc = subprocess.run(
            ["ipconfig", "getpacket", iface],
            capture_output=True, text=True, check=True,
        )
    except Exception as exc:  # noqa: BLE001 - best-effort, never fatal
        print(f"INFO: failed to run 'ipconfig getpacket {iface}': {exc}")
        proc = None
    if proc is not None:
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if not stripped.startswith("domain_name_server"):
                continue
            match = re.search(r"\{([^}]*)\}", stripped)
            if not match:
                continue
            nameservers = [
                ip.strip() for ip in match.group(1).split(",") if ip.strip()
            ]
            break

    if not nameservers:
        try:
            proc = subprocess.run(
                ["ipconfig", "getoption", iface, "domain_name_server"],
                capture_output=True, text=True, check=True,
            )
        except Exception as exc:  # noqa: BLE001 - best-effort, never fatal
            print(f"INFO: failed to run 'ipconfig getoption {iface} domain_name_server': {exc}")
            return []
        nameservers = [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    if not nameservers:
        print(f"INFO: DHCP offers no nameservers on interface {iface}")
        return []
    return nameservers


def load_ru_asns(path: Path) -> set:
    """Parse the RIPE NCC delegated file into the set of ASN numbers registered
    to country RU. Lines are 'ripencc|RU|asn|<start>|<count>|...'; each asn
    line denotes the ASN range [start, start+count).

    Raises on read/parse failure (e.g. a truncated/corrupt file) -- the
    caller self-heals by deleting and re-fetching the file once.
    """
    ru = set()
    with path.open() as fh:
        for raw in fh:
            line = raw.strip()
            if not line.startswith("ripencc"):
                continue
            parts = line.split("|")
            if len(parts) < 6 or parts[2] != "asn":
                continue
            # Skip '*' summary lines (e.g. "ripencc|*|asn|*|N|summary").
            if not (parts[3].lstrip("+").isdigit() and parts[4].lstrip("+").isdigit()):
                continue
            cc, start, count = parts[1], int(parts[3]), int(parts[4])
            if cc == "RU":
                ru.update(range(start, start + count))
    return ru


def as_holder(asn: str, refresh: bool, cache_dir: Path) -> str:
    """AS holder/name from RIPEstat as-overview, cached like the other
    RIPEstat calls. Best-effort: any failure returns '-' and never affects
    the caller's mode decision."""
    cache_path = cache_dir / f"as-overview-AS{asn}.json"
    try:
        data = fetch_cached_json(AS_OVERVIEW_URL.format(asn=asn), cache_path, refresh)
        return data.get("data", {}).get("holder") or "-"
    except Exception as exc:  # noqa: BLE001 - best-effort, never affects mode decision
        print(f"WARNING: failed to fetch AS holder for AS{asn}: {exc}")
        return "-"


def asn_country(asn_str, ru_asns: set) -> str:
    """'RU' if the ASN is registered to RU in the RIPE file, else 'other'."""
    try:
        return "RU" if int(asn_str) in ru_asns else "other"
    except ValueError:
        return "other"


def announced_prefixes(asn: str, refresh: bool, cache_dir: Path) -> list:
    """IPv4 prefixes (list of ipaddress.IPv4Network) announced by an ASN.

    Raises on network failure -- the caller decides how to fall back.
    """
    cache_path = cache_dir / f"announced-prefixes-AS{asn}.json"
    data = fetch_cached_json(
        ANNOUNCED_PREFIXES_URL.format(asn=asn), cache_path, refresh
    )
    nets = []
    for item in data.get("data", {}).get("prefixes", []):
        prefix = item.get("prefix")
        if prefix and ":" not in prefix:  # IPv4 only
            try:
                nets.append(ipaddress.ip_network(prefix, strict=False))
            except ValueError:
                pass
    return nets


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


def merge_gaps_to_budget(collapsed, current_site_count, max_sites, pinned=None):
    """Greedily merge the smallest gaps between consecutive collapsed
    exclusions until the resulting site-network count is at most
    `max_sites`, or no eligible gaps remain.

    A "gap" is the address range strictly between two consecutive entries
    of the already-collapsed, sorted exclusion list. Merging a gap means
    folding that range into the exclusions, so the exclusion before it,
    the gap itself, and the exclusion after it become one contiguous
    excluded range.

    `pinned` is an optional list of ipaddress networks (see
    keep-tunneled.txt) that must never be pushed out of the personal VPN.
    Any gap whose address range intersects a pinned network is PROTECTED:
    it is never added to the merge candidate heap, so no matter how small
    it is it can never be merged. If every remaining gap ends up protected
    before the budget is reached, merging simply stops -- the budget is
    reported unmet (see `budget_met` below) rather than merging a
    protected gap to reach it.

    SAFETY (preserved and must hold): merging a gap only ever ADDS the
    gap's address range to the exclusions -- it never removes or shrinks
    an existing exclusion. So everything that was already excluded
    (corporate CIDRs, VPN gateways, direct-domains IPs/ASN prefixes, DNS
    servers, RFC 1918 ranges, ...) stays excluded; merging can only push
    MORE address space out of the personal VPN, never less back in. Every
    existing self-check therefore continues to pass unchanged (verified
    below at the call site). Pinned networks add a second safety property:
    they can never be part of that "more address space", because a gap
    that contains one is never a merge candidate in the first place.

    Efficiency: the number of site-CIDR-blocks a gap contributes depends
    only on that gap's own start/end addresses, never on whether other
    gaps are merged (merging elsewhere only changes which exclusion a gap
    is adjacent to, not the gap's own address range). So each gap's cost
    (site-network count removed when merged) is computed exactly once, up
    front, and a min-heap picks the globally smallest gaps first without
    ever recomputing the full complement -- linear in the number of
    collapsed exclusions, not quadratic. Checking a gap against `pinned`
    is O(len(pinned)) per gap, which stays cheap because keep-tunneled.txt
    is expected to hold a handful of entries, not thousands.

    Returns (merged_flags, merges_performed, extra_addresses, largest_gap,
    protected_gaps, pinned_hits, budget_met):
    merged_flags[i] is True if the gap between collapsed[i] and
    collapsed[i + 1] was merged; largest_gap is (size, start_int, end_int)
    of the biggest merged gap, or None if no merge was needed/possible.
    protected_gaps is the number of gaps skipped because they intersect a
    pinned network. pinned_hits maps str(pinned network) -> number of gaps
    it protected (present with count 0 for every pinned entry that never
    blocked anything). budget_met is False when merging ran out of
    eligible (unprotected) gaps before the site count reached max_sites.
    """
    pinned = pinned or []
    pinned_hits = {str(net): 0 for net in pinned}
    n = len(collapsed)
    merged_flags = [False] * max(0, n - 1)
    merges_performed = 0
    extra_addresses = 0
    largest_gap = None
    protected_gaps = 0
    if n < 2 or current_site_count <= max_sites:
        return merged_flags, merges_performed, extra_addresses, largest_gap, protected_gaps, pinned_hits, True

    heap = []  # (gap size, gap index, start, end)
    gap_site_counts = {}  # gap index -> number of site networks it contributes
    for i in range(n - 1):
        start = int(collapsed[i].broadcast_address) + 1
        end = int(collapsed[i + 1].network_address) - 1
        if start > end:
            # collapse_addresses() only merges two networks into one CIDR
            # when their union is itself a valid CIDR block; two networks
            # can otherwise sit immediately adjacent (zero addresses
            # between them) without being combined. There is no address
            # space to merge here, so this pair is simply not a candidate.
            continue
        blockers = [
            net for net in pinned
            if int(net.network_address) <= end and int(net.broadcast_address) >= start
        ]
        if blockers:
            protected_gaps += 1
            for net in blockers:
                pinned_hits[str(net)] += 1
            continue
        size = end - start + 1
        gap_site_counts[i] = sum(
            1
            for _ in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
            )
        )
        heapq.heappush(heap, (size, i, start, end))

    total_sites = current_site_count
    while heap and total_sites > max_sites:
        size, i, start, end = heapq.heappop(heap)
        merged_flags[i] = True
        total_sites -= gap_site_counts[i]
        merges_performed += 1
        extra_addresses += size
        if largest_gap is None or size > largest_gap[0]:
            largest_gap = (size, start, end)

    budget_met = total_sites <= max_sites
    return merged_flags, merges_performed, extra_addresses, largest_gap, protected_gaps, pinned_hits, budget_met


def apply_gap_merges(collapsed, merged_flags):
    """Rebuild the collapsed-exclusion list and the site list after gap
    merges chosen by merge_gaps_to_budget(). merged_flags[i] == True means
    the gap between collapsed[i] and collapsed[i + 1] is folded into the
    exclusions, joining both into one contiguous excluded range. A single
    linear pass groups runs of merged exclusions and re-derives their
    minimal CIDR representation (and that of the surviving gaps) via
    summarize_address_range -- no full recomputation of the complement."""
    if not collapsed:
        return [], []
    final_excl = []
    final_sites = []
    group_start = int(collapsed[0].network_address)
    group_end = int(collapsed[0].broadcast_address)
    for i in range(len(collapsed) - 1):
        nxt = collapsed[i + 1]
        if merged_flags[i]:
            group_end = int(nxt.broadcast_address)
        else:
            final_excl.extend(
                ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(group_start), ipaddress.IPv4Address(group_end)
                )
            )
            gap_start, gap_end = group_end + 1, int(nxt.network_address) - 1
            if gap_start <= gap_end:  # zero-address gaps (adjacent, unmergeable) emit nothing
                final_sites.extend(
                    ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(gap_start), ipaddress.IPv4Address(gap_end)
                    )
                )
            group_start = int(nxt.network_address)
            group_end = int(nxt.broadcast_address)
    final_excl.extend(
        ipaddress.summarize_address_range(
            ipaddress.IPv4Address(group_start), ipaddress.IPv4Address(group_end)
        )
    )
    return final_excl, final_sites


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
    parser.add_argument(
        "--dry-run-output",
        default=None,
        metavar="PATH",
        help="write the computed list for the active --mode (one CIDR per line, "
             "same content as the normal .txt output) to PATH instead of the "
             "usual build/<...>.txt location, and do not touch build/ at all. "
             "Implies the same non-writing behaviour as --dry-run for build/ "
             "itself; PATH is written regardless. Meant for split-health.sh's "
             "registry-drift check, which runs this generator with --refresh "
             "in the background and diffs PATH against the currently generated "
             "file without disturbing it.",
    )
    parser.add_argument(
        "--mode",
        choices=("forward", "exclude"),
        default="forward",
        help="which AmneziaVPN split-tunneling mode to generate for: 'forward' "
             "(default, unchanged) writes the site list (the complement) for "
             "\"only selected sites\" mode into build/amnezia-sites.{json,txt}; "
             "'exclude' writes the exclusion set itself for \"all sites except "
             "the listed ones\" mode into build/amnezia-exclude.{json,txt}. "
             "Each mode only touches its own output files.",
    )
    parser.add_argument(
        "--no-asn",
        action="store_true",
        help="disable whole-ASN expansion of direct domains (old /32-only behaviour)",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="force re-downloading RIPEstat/RIPE caches instead of reusing them; "
             "also skips the last-known-good DNS cache fallback (build/cache/dns/) "
             "so a stale cache never papers over a live resolution failure",
    )
    parser.add_argument(
        "--resolve-timeout",
        type=float,
        default=DEFAULT_RESOLVE_TIMEOUT,
        metavar="N",
        help="hard wall-clock cap in seconds for every hostname lookup via the "
             "system resolver (default: %(default)s). getaddrinfo() has no "
             "timeout of its own, so a lookup still running after N seconds is "
             "treated as a failure and abandoned in a background thread -- this "
             "is what keeps the generator from hanging when a corp-hosts-check.txt "
             "zone's /etc/resolver DNS server is unreachable (corporate VPN down)",
    )
    parser.add_argument(
        "--fallback-dns",
        default=DEFAULT_FALLBACK_DNS,
        metavar="IP",
        help="public DNS resolver queried (minimal stdlib UDP A-record query, "
             "%(default)s by default) for corp-hosts-check.txt entries the system "
             "resolver could not reach -- not used for direct-domains.txt, which "
             "must resolve the way the user actually experiences it",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run a self-test of the minimal stdlib DNS client (dns_query_a) "
             "against --fallback-dns and a non-routable resolver, print PASS/FAIL, "
             "and exit -- does not touch --config or build/",
    )
    parser.add_argument(
        "--max-sites",
        type=int,
        default=None,
        metavar="N",
        help="cap the site list at N networks by greedily merging the smallest "
             "gaps between exclusions until it fits (default: unlimited, i.e. "
             "today's behaviour). Merging only ever ADDS address space to the "
             "exclusions, so it can only shrink the personal VPN's coverage, "
             "never weaken what must stay off it. Networks pinned in "
             "keep-tunneled.txt are never merged away; if the budget cannot "
             "be reached because of that, a WARNING is printed instead of "
             "exceeding the budget. Ignored (with a WARNING) in --mode exclude: "
             "it caps the *site list* count specifically and has no equivalent "
             "guarantee for the exclusion list's entry count once merges chain "
             "(see the module docstring).",
    )
    args = parser.parse_args()
    if args.max_sites is not None and args.max_sites <= 0:
        parser.error("--max-sites must be a positive integer")

    if args.self_test:
        return self_test(args.fallback_dns)

    config_dir = Path(args.config).resolve() if args.config else (REPO_ROOT / "local")
    if not config_dir.is_dir():
        print(f"ERROR: config dir not found: {config_dir}", file=sys.stderr)
        return 1

    print(f"Config dir: {config_dir}")

    # Namespace build/ output by config so a run against anything other than
    # the default local/ (e.g. --config config/example) can never clobber the
    # real generated files: build/<config-dir-basename>/amnezia-*.{json,txt}
    # instead of build/amnezia-*.{json,txt}. The default local/ config keeps
    # writing straight to build/, unchanged, so nothing existing moves.
    # build/cache/ (RIPEstat, RIPE NCC, DNS) stays shared across configs on
    # purpose -- see the module docstring.
    default_config_dir = REPO_ROOT / "local"
    if config_dir == default_config_dir:
        build_dir = REPO_ROOT / "build"
    else:
        build_dir = REPO_ROOT / "build" / config_dir.name
        print(f"Build dir: {build_dir} (namespaced: --config is not the default local/)")

    cache_dir = REPO_ROOT / "build" / "cache"
    ripestat_dir = cache_dir / "ripestat"
    ripencc_path = cache_dir / "delegated-ripencc-extended-latest"
    dns_cache_dir = cache_dir / "dns"

    direct_cidrs_raw = read_list(config_dir / "direct-cidrs.txt")
    domain_specs = read_direct_domains(config_dir / "direct-domains.txt")
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

    # --- keep-tunneled.txt: networks pinned to stay inside the personal VPN -
    # These are never added to `exclusions` -- they are ordinary addresses
    # that the rest of this script's logic already leaves uncovered (public
    # DNS resolvers, by default). Their only special treatment is in
    # merge_gaps_to_budget(): a gap that contains one of them is never a
    # merge candidate, however small, so --max-sites can never trade them
    # away. See the self-checks below for the coverage verification.
    keep_tunneled_raw = read_list(config_dir / "keep-tunneled.txt")
    parsed_keep_tunneled = []  # valid networks parsed from keep-tunneled.txt
    for entry in keep_tunneled_raw:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            print(f"WARNING: skipping invalid entry '{entry}' in keep-tunneled.txt: {exc}")
            continue
        parsed_keep_tunneled.append(net)

    # --- Whole-ASN expansion of direct-domains.txt -------------------------
    # Load the RIPE NCC country file (cached 7 days) unless expansion is off.
    ripencc_ok = False
    ru_asns = set()
    if not args.no_asn:
        ripencc_ok = ensure_ripencc_file(ripencc_path, args.refresh)
        if ripencc_ok:
            try:
                ru_asns = load_ru_asns(ripencc_path)
            except Exception as exc:  # noqa: BLE001 - self-heal: delete and re-fetch once
                print(f"cache: corrupt {ripencc_path.relative_to(REPO_ROOT)} ({exc}); deleting and re-fetching")
                ripencc_path.unlink(missing_ok=True)
                if ensure_ripencc_file(ripencc_path, refresh=True):
                    try:
                        ru_asns = load_ru_asns(ripencc_path)
                    except Exception as exc2:  # noqa: BLE001 - fall back as before
                        print(f"WARNING: {ripencc_path.relative_to(REPO_ROOT)} still fails to parse after re-fetch: {exc2}")
                        ru_asns = set()
                else:
                    print(f"WARNING: failed to re-fetch {ripencc_path.relative_to(REPO_ROOT)} after parse failure")
                    ru_asns = set()

    resolved_direct = []  # (host, ip), one per resolved address (for checks)
    domain_records = []   # per-domain reporting records
    fallback_count = 0    # domains that had to fall back to IP due to network

    # --- DNS resolution phase (direct-domains.txt + corp-hosts-check.txt) --
    # Timed and summarized below: this is exactly the phase that used to
    # hang for minutes when the corporate VPN is down and /etc/resolver/
    # <zone> points at an unreachable corporate DNS server (see
    # resolve_ipv4()/resolve_corp_host()).
    resolution_start = time.perf_counter()
    resolution_stats = {"live": 0, "fallback": 0, "cache": 0, "failed": 0}

    for domain, override in domain_specs:
        ips, domain_source = resolve_direct_domain(
            domain, args.resolve_timeout, dns_cache_dir, args.refresh, resolution_stats
        )
        ip_nets = [ipaddress.ip_network(f"{ip}/32") for ip in ips]
        for ip in ips:
            resolved_direct.append((domain, ip))

        asn_list = []
        holder = "-"
        asn_prefix_nets = []  # whole-ASN prefix networks added for this domain
        mode = "ip"
        fell_back = False

        if args.no_asn or not ips:
            mode = "ip"
        else:
            first_ip = ips[0]
            ni = None
            try:
                ni = fetch_cached_json(
                    NETWORK_INFO_URL.format(ip=first_ip),
                    ripestat_dir / f"network-info-{first_ip}.json",
                    args.refresh,
                )
            except Exception as exc:  # noqa: BLE001 - best-effort, fall back
                print(f"WARNING: failed to fetch network-info for '{domain}' ({first_ip}): {exc}")
                # This failure always leaves mode == "ip" below (ni stays None),
                # regardless of whether a stale cache file happens to still be
                # on disk -- it is never read as a substitute here, so count it.
                fell_back = True

            if ni:
                data = ni.get("data", {})
                asn_list = data.get("asns") or []
                # network-info does not return a holder name -- fetch it
                # separately (as-overview), cached per ASN. Best-effort: a
                # failure here only prints '-' and never changes 'mode'.
                if asn_list:
                    holder = as_holder(asn_list[0], args.refresh, ripestat_dir)

                if override == "asn":
                    mode = "asn"
                elif override == "ip":
                    mode = "ip"
                else:
                    # Auto mode: whole-ASN only when safe (RU country, under cap).
                    if asn_list:
                        primary = asn_list[0]
                        country = asn_country(primary, ru_asns)
                        # Need the primary's prefix count to enforce the cap.
                        try:
                            n_primary = len(
                                announced_prefixes(primary, args.refresh, ripestat_dir)
                            )
                        except Exception as exc:  # noqa: BLE001
                            print(f"WARNING: failed to fetch announced-prefixes for AS{primary} ('{domain}'): {exc}")
                            # This failure always forces mode == "ip" below (cap
                            # treated as exceeded), regardless of a stale cache
                            # file on disk -- it is never read as a substitute
                            # here, so count it.
                            fell_back = True
                            n_primary = ASN_MAX_PREFIXES + 1  # treat as over-cap
                        if country == "RU" and n_primary <= ASN_MAX_PREFIXES:
                            mode = "asn"
                        else:
                            mode = "ip"
                    else:
                        mode = "ip"
            else:
                # Could not obtain network-info and no cache -> stay IP-only.
                mode = "ip"
                if fell_back:
                    pass  # already marked

            if mode == "asn":
                for asn in asn_list:
                    asn_cc = asn_country(asn, ru_asns)
                    if override == "asn":
                        pass  # force whole-ASN, ignore cap/country rule
                    else:
                        if asn_cc != "RU":
                            continue
                        try:
                            if len(announced_prefixes(asn, args.refresh, ripestat_dir)) > ASN_MAX_PREFIXES:
                                continue
                        except Exception as exc:  # noqa: BLE001
                            print(f"WARNING: failed to fetch announced-prefixes for AS{asn} ('{domain}'): {exc}")
                            continue
                    try:
                        for net in announced_prefixes(asn, args.refresh, ripestat_dir):
                            asn_prefix_nets.append(net)
                    except Exception as exc:  # noqa: BLE001
                        print(f"WARNING: failed to fetch announced-prefixes for AS{asn} ('{domain}'): {exc}")
                        continue
                # If we forced 'asn' but nothing could be added, degrade to IP.
                if not asn_prefix_nets and not (ips):
                    mode = "ip"
                elif not asn_prefix_nets:
                    # No ASN prefixes added (e.g. resolver gave none) -- still
                    # keep the resolved /32s; that is the useful part.
                    pass

        if fell_back:
            fallback_count += 1

        for net in ip_nets:
            exclusions.add(net)
        for net in asn_prefix_nets:
            exclusions.add(net)

        # Reporting record: country taken from the primary ASN.
        primary = asn_list[0] if asn_list else None
        if not asn_list:
            country = "none"
        elif primary is not None:
            country = asn_country(primary, ru_asns)
        else:
            country = "none"
        asns_display = ",".join(f"AS{a}" for a in asn_list) if asn_list else "-"
        domain_records.append({
            "domain": domain,
            "ips": ips,
            "asns": asns_display,
            "holder": holder,
            "country": country,
            "mode": mode,
            "n_prefixes": len(asn_prefix_nets),
            "asn_prefixes": asn_prefix_nets,
            "source": domain_source,
        })

    resolved_corp_hosts = []  # (host, ip, source)
    failed_corp_hosts = []    # hosts that failed live + fallback + cache
    for host in corp_hosts_check:
        ips, host_source = resolve_corp_host(
            host, args.resolve_timeout, args.fallback_dns, dns_cache_dir,
            args.refresh, resolution_stats,
        )
        if host_source == "fail":
            failed_corp_hosts.append(host)
        for ip in ips:
            exclusions.add(ipaddress.ip_network(f"{ip}/32"))
            resolved_corp_hosts.append((host, ip, host_source))

    resolution_elapsed = time.perf_counter() - resolution_start
    print()
    print(
        f"Resolution phase took {resolution_elapsed:.2f}s "
        f"(--resolve-timeout {args.resolve_timeout}s cap per host, "
        f"{len(domain_specs)} direct-domains.txt + {len(corp_hosts_check)} "
        f"corp-hosts-check.txt entries)"
    )
    print(
        f"  resolved live: {resolution_stats['live']}, "
        f"via public fallback: {resolution_stats['fallback']}, "
        f"via cache: {resolution_stats['cache']}, "
        f"failed outright: {resolution_stats['failed']}"
    )
    if failed_corp_hosts:
        print(
            f"WARNING: {len(failed_corp_hosts)} corp-hosts-check.txt host(s) failed to "
            f"resolve outright ({', '.join(failed_corp_hosts)}) -- their /32 is missing "
            f"from the exclusion list. Regenerate once with the corporate VPN connected "
            f"to fill the cache."
        )

    dhcp_ns = dhcp_nameservers()
    for ip in dhcp_ns:
        exclusions.add(ipaddress.ip_network(f"{ip}/32"))
    direct_dns = read_list(config_dir / "direct-dns.txt")
    for ip in direct_dns:
        exclusions.add(ipaddress.ip_network(f"{ip}/32"))

    sites, collapsed_exclusions = address_exclude_all([FULL_IPV4], exclusions)
    sites.sort(key=lambda n: (int(n.network_address), n.prefixlen))

    # --- Route budget (--max-sites): merge smallest gaps until it fits ------
    # See merge_gaps_to_budget()'s docstring for the safety property (merging
    # only ever ADDS address space to the exclusions) and why a heap over
    # precomputed per-gap costs avoids recomputing the full complement.
    budget_merges = budget_extra_addresses = 0
    budget_largest_gap = None
    budget_protected_gaps = 0
    budget_pinned_hits = {str(net): 0 for net in parsed_keep_tunneled}
    budget_met = True
    # --max-sites targets the *site list* count via an additive per-gap cost
    # (see merge_gaps_to_budget()'s docstring): each gap's own site-block
    # count can be subtracted independently of every other merge. That
    # property does not carry over to the *exclusion* list's entry count --
    # once merges chain, the fused range's minimal CIDR count is a property
    # of the whole range, not a sum of the parts -- so rather than offer a
    # budget that cannot honestly guarantee the requested exclusion count,
    # --mode exclude ignores --max-sites outright, loudly.
    max_sites_applies = args.max_sites is not None and args.mode == "forward"
    if args.max_sites is not None and args.mode == "exclude":
        print()
        print(
            f"WARNING: --max-sites {args.max_sites} is ignored in --mode exclude: it caps "
            f"the site-list count, which has no meaning here (this run writes the exclusion "
            f"list itself). The exclusion list is written at its full precision, "
            f"{len(collapsed_exclusions)} network(s)."
        )
    if max_sites_applies:
        (merged_flags, budget_merges, budget_extra_addresses, budget_largest_gap,
         budget_protected_gaps, budget_pinned_hits, budget_met) = merge_gaps_to_budget(
            collapsed_exclusions, len(sites), args.max_sites, parsed_keep_tunneled
        )
        if budget_merges:
            collapsed_exclusions, sites = apply_gap_merges(collapsed_exclusions, merged_flags)
            sites.sort(key=lambda n: (int(n.network_address), n.prefixlen))
            collapsed_exclusions.sort(key=lambda n: (int(n.network_address), n.prefixlen))

    total_excluded = sum(net.num_addresses for net in collapsed_exclusions)
    total_covered = sum(net.num_addresses for net in sites)

    n_asn_mode = sum(1 for r in domain_records if r["mode"] == "asn")
    n_ip_mode = sum(1 for r in domain_records if r["mode"] == "ip")

    print()
    print("=== Exclusion summary ===")
    print(f"  special/reserved ranges     : {len(SPECIAL_RANGES)}")
    print(f"  direct-cidrs.txt entries    : {n_direct_cidrs}")
    n_total_resolved = sum(len(r["ips"]) for r in domain_records)
    print(f"  direct-domains.txt          : {len(domain_records)} domain(s) -> {n_total_resolved} resolved IPv4")
    for r in domain_records:
        print(f"      {r['domain']} -> {','.join(r['ips']) if r['ips'] else '-'} -> {r['asns']} ({r['holder']}) "
              f"country={r['country']} mode={r['mode']} prefixes={r['n_prefixes']} source={r['source']}")
    print(f"      modes: {n_asn_mode} domain(s) in asn mode, {n_ip_mode} in ip mode, "
          f"{fallback_count} fell back to ip due to network")
    print(f"  corp-hosts-check.txt        : {len(corp_hosts_check)} host(s) -> {len(resolved_corp_hosts)} resolved IPv4")
    for host, ip, host_source in resolved_corp_hosts:
        tag = f" [{host_source}]" if host_source != "live" else ""
        print(f"      {host} -> {ip}{tag}")
    print(f"  DHCP nameservers ({default_interface()}): {len(dhcp_ns)} -> {dhcp_ns}")
    print(f"  direct-dns.txt                : {len(direct_dns)} -> {direct_dns}")
    print(f"  keep-tunneled.txt entries   : {len(parsed_keep_tunneled)} -> "
          f"{', '.join(str(n) for n in parsed_keep_tunneled) if parsed_keep_tunneled else '-'}")
    print(f"  gaps protected by pins      : {budget_protected_gaps}")
    print(f"  collapsed exclusion networks: {len(collapsed_exclusions)}")
    print(f"  total excluded addresses    : {total_excluded}")
    print()
    print("=== Result ===")
    print(f"  site networks (covered)     : {len(sites)}")
    print(f"  total covered addresses     : {total_covered}")
    print(f"  covered + excluded          : {total_covered + total_excluded} (2^32 = {MAX_ADDR})")

    if max_sites_applies:
        pct = budget_extra_addresses / MAX_ADDR * 100
        print()
        print("=== Route budget (--max-sites) ===")
        print(f"  requested budget            : {args.max_sites}")
        print(f"  gap merges performed        : {budget_merges}")
        print(f"  resulting site networks     : {len(sites)}")
        print(f"  extra addresses excluded    : {budget_extra_addresses} ({pct:.4f}% of all IPv4)")
        print(f"  gaps protected by pins      : {budget_protected_gaps}")
        if budget_largest_gap:
            size, start, end = budget_largest_gap
            print(
                f"  largest merged gap          : "
                f"{ipaddress.IPv4Address(start)}-{ipaddress.IPv4Address(end)} ({size} addresses)"
            )
        else:
            print("  largest merged gap          : none (no merge was needed/possible)")

        if not budget_met:
            # The heap ran out of eligible (unprotected) gaps before the site
            # count reached the budget. This is a legitimate outcome, not an
            # error: keep-tunneled.txt pins are respected instead of being
            # silently traded away to hit an unreachable number.
            top_blockers = sorted(
                (item for item in budget_pinned_hits.items() if item[1] > 0),
                key=lambda kv: kv[1], reverse=True,
            )
            blockers_desc = (
                ", ".join(f"{net} ({count} gap(s))" for net, count in top_blockers)
                if top_blockers else "none"
            )
            print()
            print(
                f"WARNING: --max-sites {args.max_sites} could not be met: every remaining "
                f"gap small enough to merge is protected by keep-tunneled.txt. The site list "
                f"has {len(sites)} network(s) instead of the requested {args.max_sites}; "
                f"{budget_protected_gaps} gap(s) were protected. Pinned entries blocking the "
                f"most merges: {blockers_desc}."
            )

    # build_dir was already resolved above (namespaced per --config).
    # --mode forward writes the site list (today's files, untouched by
    # --mode exclude); --mode exclude writes the exclusion set itself into
    # its own pair of files. Each mode only ever touches its own two files.
    if args.mode == "exclude":
        out_networks = collapsed_exclusions
        json_path = build_dir / "amnezia-exclude.json"
        txt_path = build_dir / "amnezia-exclude.txt"
    else:
        out_networks = sites
        json_path = build_dir / "amnezia-sites.json"
        txt_path = build_dir / "amnezia-sites.txt"

    if args.dry_run_output:
        dry_run_output_path = Path(args.dry_run_output)
        dry_run_output_path.parent.mkdir(parents=True, exist_ok=True)
        with dry_run_output_path.open("w") as fh:
            for net in out_networks:
                fh.write(f"{net}\n")
        print()
        print(f"[dry-run-output] wrote {len(out_networks)} entries to {dry_run_output_path} (build/ untouched)")
    elif args.dry_run:
        print()
        print(f"[dry-run] would write {len(out_networks)} entries to {json_path} and {txt_path}")
    else:
        build_dir.mkdir(parents=True, exist_ok=True)
        entries = [{"hostname": str(net), "ips": [], "ip": ""} for net in out_networks]
        with json_path.open("w") as fh:
            fh.write("[\n")
            for i, entry in enumerate(entries):
                comma = "," if i < len(entries) - 1 else ""
                fh.write(
                    '  {"hostname": "%s", "ips": [], "ip": ""}%s\n' % (entry["hostname"], comma)
                )
            fh.write("]\n")
        with txt_path.open("w") as fh:
            for net in out_networks:
                fh.write(f"{net}\n")
        print()
        print(f"Wrote {len(out_networks)} entries to {json_path}")
        print(f"Wrote {len(out_networks)} lines to {txt_path}")

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

    # Every check below is phrased in terms of the real-world routing outcome
    # ("stays in the personal VPN" vs. "goes direct"), not in terms of a
    # specific file, so the same check bodies work for both modes. `sites`
    # and `collapsed_exclusions` are always an exact partition of all of
    # IPv4 (that is exactly what the disjointness and address-conservation
    # checks below verify), so "covered by the site list" and "covered by
    # the exclusion list" are logical negations of each other. Which one
    # actually determines real routing depends on which file this run
    # writes: --mode forward writes the site list, so the personal VPN
    # tunnels an address iff `sites` covers it; --mode exclude writes the
    # exclusion list, so the personal VPN tunnels an address iff
    # `collapsed_exclusions` does NOT cover it (MacosRouteMonitor::
    # addExclusionRoute leaves everything not explicitly excluded on the
    # four half-space routes into the tunnel). This is exactly why the
    # self-checks "invert" between modes without needing separate per-mode
    # check bodies -- only this one function's polarity against the written
    # file changes.
    def goes_direct(ip_str: str) -> bool:
        """True if ip_str bypasses the personal VPN under the active --mode."""
        if args.mode == "exclude":
            return covered_by(ip_str, collapsed_exclusions)
        return not covered_by(ip_str, sites)

    # keep-tunneled.txt entries must stay IN the personal VPN -- config-driven,
    # not hardcoded: with the default config this exercises 8.8.8.8/1.1.1.1/
    # etc, but if the user empties keep-tunneled.txt these checks simply
    # disappear instead of failing (there is nothing left to pin, so nothing
    # left to assert).
    if parsed_keep_tunneled:
        for net in parsed_keep_tunneled:
            first, last = net.network_address, net.broadcast_address
            stays_tunneled = not goes_direct(str(first)) and not goes_direct(str(last))
            check(f"keep-tunneled.txt entry {net} stays in the personal VPN", stays_tunneled)
    else:
        print("  [SKIP] no keep-tunneled.txt entries configured")

    # Representative private (RFC 1918) addresses must go direct -- they are
    # excluded via the special-purpose ranges above.
    for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        check(f"{ip} goes direct (not tunneled)", goes_direct(ip))

    # First address of every direct-cidrs.txt entry must go direct (the
    # entire entry is excluded, so even its first host must stay off the
    # personal VPN). Config-driven -- no machine-specific IP hardcoded here.
    for net in parsed_direct_cidrs:
        first = net.network_address
        check(f"direct-cidrs.txt first address {first} goes direct (not tunneled)",
              goes_direct(str(first)))

    # Every resolved direct-domains.txt IP must go direct. Unresolvable
    # placeholder domains (e.g. in config/example) only produce WARNINGs above,
    # so this check is skipped when nothing resolved.
    if resolved_direct:
        for host, ip in resolved_direct:
            check(f"direct-domains.txt host {host} ({ip}) goes direct (not tunneled)",
                  goes_direct(ip))
    else:
        print("  [SKIP] no direct-domains.txt hosts resolved")

    # Every whole-ASN prefix added for a direct domain must go direct too:
    # test one representative address (the prefix's network address) of every
    # added ASN prefix -- linear, not every address.
    for r in domain_records:
        for net in r["asn_prefixes"]:
            rep = str(net.network_address)
            check(f"direct-domains.txt {r['domain']} ASN prefix {net} ({rep}) goes direct",
                  goes_direct(rep))

    # corp-hosts-check.txt may resolve to public (non-RFC1918, non-direct-cidr)
    # IPs -- e.g. a corporate host hosted outside the corporate network's own
    # netblocks. Those are routed direct only via this host-resolution step,
    # not via any CIDR range, so verifying each one is a meaningful check of
    # that exclusion path (config-driven, no hostname hardcoded here -- see
    # resolved_corp_hosts, built from corp-hosts-check.txt).
    if resolved_corp_hosts:
        for host, ip, _host_source in resolved_corp_hosts:
            check(f"corp-hosts-check.txt host {host} ({ip}) goes direct (not tunneled)",
                  goes_direct(ip))
    else:
        print("  [SKIP] no corp-hosts-check.txt hosts resolved")

    # Every DHCP nameserver and every direct-dns.txt IP must go direct, so
    # DNS traffic itself never enters the personal VPN tunnel.
    for ip in dhcp_ns:
        check(f"DHCP nameserver {ip} goes direct (not tunneled)", goes_direct(ip))
    for ip in direct_dns:
        check(f"direct-dns.txt {ip} goes direct (not tunneled)", goes_direct(ip))

    # Linear disjointness sweep: sites and collapsed exclusions merged into one
    # list sorted by start address; each network must begin after the previous
    # one ends. Linear in the combined size -- no site-vs-exclusion pairwise
    # loop (which would be quadratic with tens of thousands of exclusions).
    # This invariant and the address-conservation check right after it are
    # about the sites/exclusions partition itself, so they hold unchanged in
    # both --mode forward and --mode exclude -- goes_direct() above relies on
    # them being true.
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
