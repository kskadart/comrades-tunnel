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

Output (AmneziaVPN JSON import format -- see importSitesFromJson() in
amnezia-vpn/amnezia-client, client/core/controllers/ipSplitTunnelingController.cpp):
    build/amnezia-sites.json   -- [{"hostname": "<cidr>", "ips": [], "ip": ""}, ...]
    build/amnezia-sites.txt    -- one CIDR per line, for human review

Usage:
    gen-amnezia-sites.py [--config DIR] [--dry-run] [--no-asn] [--refresh]

direct-domains.txt syntax (optional second token after the domain):
    <domain>            expand to whole ASN when safe (RU-country, under cap)
    <domain> asn        force expansion to the whole ASN (ignore cap/country rule)
    <domain> ip         force IP-only expansion (only the resolved /32s)
"""
import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
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


def resolve_ipv4(host: str) -> list:
    """Resolve a hostname to its IPv4 addresses. Warn and continue on failure."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
    except socket.gaierror as exc:
        print(f"WARNING: failed to resolve '{host}': {exc}")
        return []
    return sorted({info[4][0] for info in infos})


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

    The primary interface is `default_interface()`; its DHCP nameservers come
    from `ipconfig getoption <iface> domain_name_server` (one IP per line,
    empty when DHCP offered none). Best-effort: any failure or empty result
    returns [] with an INFO line -- never fatal.
    """
    iface = default_interface()
    if not iface:
        print("INFO: unknown primary interface; no DHCP nameservers")
        return []
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
        "--no-asn",
        action="store_true",
        help="disable whole-ASN expansion of direct domains (old /32-only behaviour)",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="force re-downloading RIPEstat/RIPE caches instead of reusing them",
    )
    args = parser.parse_args()

    config_dir = Path(args.config).resolve() if args.config else (REPO_ROOT / "local")
    if not config_dir.is_dir():
        print(f"ERROR: config dir not found: {config_dir}", file=sys.stderr)
        return 1

    print(f"Config dir: {config_dir}")

    cache_dir = REPO_ROOT / "build" / "cache"
    ripestat_dir = cache_dir / "ripestat"
    ripencc_path = cache_dir / "delegated-ripencc-extended-latest"

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

    for domain, override in domain_specs:
        ips = resolve_ipv4(domain)
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
        })

    resolved_corp_hosts = []  # (host, ip)
    for host in corp_hosts_check:
        for ip in resolve_ipv4(host):
            exclusions.add(ipaddress.ip_network(f"{ip}/32"))
            resolved_corp_hosts.append((host, ip))

    dhcp_ns = dhcp_nameservers()
    for ip in dhcp_ns:
        exclusions.add(ipaddress.ip_network(f"{ip}/32"))
    direct_dns = read_list(config_dir / "direct-dns.txt")
    for ip in direct_dns:
        exclusions.add(ipaddress.ip_network(f"{ip}/32"))

    sites, collapsed_exclusions = address_exclude_all([FULL_IPV4], exclusions)
    sites.sort(key=lambda n: (int(n.network_address), n.prefixlen))

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
              f"country={r['country']} mode={r['mode']} prefixes={r['n_prefixes']}")
    print(f"      modes: {n_asn_mode} domain(s) in asn mode, {n_ip_mode} in ip mode, "
          f"{fallback_count} fell back to ip due to network")
    print(f"  corp-hosts-check.txt        : {len(corp_hosts_check)} host(s) -> {len(resolved_corp_hosts)} resolved IPv4")
    for host, ip in resolved_corp_hosts:
        print(f"      {host} -> {ip}")
    print(f"  DHCP nameservers ({default_interface()}): {len(dhcp_ns)} -> {dhcp_ns}")
    print(f"  direct-dns.txt                : {len(direct_dns)} -> {direct_dns}")
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

    # Every whole-ASN prefix added for a direct domain must be excluded too:
    # test one representative address (the prefix's network address) of every
    # added ASN prefix -- linear, not every address.
    for r in domain_records:
        for net in r["asn_prefixes"]:
            rep = str(net.network_address)
            check(f"direct-domains.txt {r['domain']} ASN prefix {net} ({rep}) is NOT covered",
                  not covered_by(rep, sites))

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

    # Every DHCP nameserver and every direct-dns.txt IP must NOT be covered,
    # so DNS traffic itself never enters the personal VPN tunnel.
    for ip in dhcp_ns:
        check(f"DHCP nameserver {ip} is NOT covered by the site list",
              not covered_by(ip, sites))
    for ip in direct_dns:
        check(f"direct-dns.txt {ip} is NOT covered by the site list",
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
