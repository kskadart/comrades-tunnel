#!/bin/sh
# Read-only, no-sudo sanity check of the dual-VPN split routing.
#
# Prints a table and PASS/FAIL per expectation:
#   - each host in corp-hosts-check.txt: resolved IP, route interface, and
#     whether it matches expectations (corporate VPN vs direct)
#   - a handful of public IPs + the first direct-domain IP: route interface
#     (some of these are EXPECTED to fail before the Amnezia site list is
#     imported -- that's not a bug, it's the whole point of this tool)
#   - egress IP via the default route vs. forced out en0
#   - route counts per utun interface
#
# corp-hosts-check.txt lookups use dscacheutil_bounded (a hard 3s wall-clock
# cap, see that function) rather than a bare dscacheutil call: dscacheutil
# honors /etc/resolver/<zone>, so with the corporate VPN down its configured
# (unreachable) resolver used to make the whole run take ~118s for 5 hosts
# (long per-host retries) instead of a few seconds; `dig` is still tried as
# a fallback exactly as before, and the PASS/FAIL table's behaviour is
# otherwise unchanged.
#
# --mode selects which AmneziaVPN split-tunneling mode is being checked
# against (mirrors bin/gen-amnezia-sites.py --mode): 'forward' (default,
# unchanged) expects excluded destinations to merely NOT be the personal
# VPN's utun (the AmneziaVPN "only selected sites" mode installs no route
# for them, so they fall through to whatever else claims them); 'exclude'
# expects them to be routed via the physical interface (en0) specifically,
# because in AmneziaVPN's "all sites except the listed ones" mode the client
# installs a real kernel route for each excluded network via the physical
# gateway (see MacosRouteMonitor::addExclusionRoute) -- and it also checks
# that the personal VPN's utun carries only a handful of routes (the four
# fixed half-space routes), not one per excluded network.
#
# Usage: check-split.sh [--config DIR] [--mode {forward,exclude}]
# Exit code: 0 if every expectation PASSed, 1 otherwise.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
CONFIG_DIR="$REPO_ROOT/local"
MODE="forward"

while [ $# -gt 0 ]; do
    case "$1" in
        --config)
            CONFIG_DIR=$2
            shift 2
            ;;
        --config=*)
            CONFIG_DIR=${1#--config=}
            shift
            ;;
        --mode)
            MODE=$2
            shift 2
            ;;
        --mode=*)
            MODE=${1#--mode=}
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--mode {forward,exclude}]" >&2
            exit 2
            ;;
    esac
done

case "$MODE" in
    forward|exclude) ;;
    *)
        echo "ERROR: invalid --mode '$MODE' (expected 'forward' or 'exclude')" >&2
        exit 2
        ;;
esac

read_lines() {
    [ -f "$1" ] || return 0
    sed -e 's/#.*$//' "$1" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$'
}

# dscacheutil_bounded HOST -- same query as `dscacheutil -q host -a name
# HOST`, hard-capped at DSCACHEUTIL_TIMEOUT_SECONDS wall-clock seconds.
# macOS has no timeout(1): this backgrounds the command directly (so $! is
# its own pid, not a wrapping subshell's) and races it against a watchdog
# that kills it after the bound. Needed because dscacheutil, unlike `dig`,
# honors /etc/resolver/<zone> -- with the corporate VPN down, a
# corporate-zone host's configured resolver is unreachable and the system
# resolver retries it for a long time (measured: ~118s total for this
# script's whole run against 5 corp-hosts-check.txt entries); bounding it
# preserves that resolver awareness (the caller still falls back to dig on
# top) without hanging. Same helper as bin/split-health.sh's own.
DSCACHEUTIL_TIMEOUT_SECONDS=3
dscacheutil_bounded() {
    host=$1
    out=$(mktemp) || return 1
    dscacheutil -q host -a name "$host" >"$out" 2>/dev/null &
    cmd_pid=$!
    ( sleep "$DSCACHEUTIL_TIMEOUT_SECONDS"; kill -TERM "$cmd_pid" 2>/dev/null ) &
    watchdog_pid=$!
    wait "$cmd_pid" 2>/dev/null
    kill "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null
    awk '/^ip_address:/{print $2; exit}' "$out"
    rm -f "$out"
}

FAIL_COUNT=0
TOTAL_COUNT=0

count_result() {
    # count_result <status: 0=pass 1=fail> -- tally only, the table row
    # already printed the PASS/FAIL for this check.
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    [ "$1" != 0 ] && FAIL_COUNT=$((FAIL_COUNT + 1))
}

# --- detect the two VPN utun interfaces dynamically (never hardcode a number) ---
detect_utun_by_prefix() {
    prefix=$1
    for iface in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun'); do
        ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}')
        case "$ip" in
            ${prefix}*) echo "$iface"; return 0 ;;
        esac
    done
    return 1
}

# Tunnel interface prefixes are machine-specific, so they live in the config
# dir as tunnels.txt (KEY=VALUE lines, parsed with grep/cut -- never sourced).
TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"

get_tunnel_prefix() {
    # get_tunnel_prefix KEY -- return the VALUE of "KEY=" in tunnels.txt
    key=$1
    grep "^${key}=" "$TUNNELS_FILE" 2>/dev/null | head -1 | cut -d= -f2-
}

CORP_TUNNEL_PREFIX=$(get_tunnel_prefix CORP_TUNNEL_PREFIX)     # inet prefix of the corporate VPN utun
PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)  # inet prefix of the personal (Amnezia) utun

CP_UTUN=$(detect_utun_by_prefix "$CORP_TUNNEL_PREFIX")
AMNEZIA_UTUN=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")

echo "Config dir: $CONFIG_DIR"
if [ "$MODE" = "exclude" ]; then
    echo "Mode: $MODE"
fi
echo "Corporate utun prefix (inet ${CORP_TUNNEL_PREFIX:-<unset>}): ${CP_UTUN:-<not found>}"
echo "Personal (Amnezia) utun prefix (inet ${PERSONAL_TUNNEL_PREFIX:-<unset>}): ${AMNEZIA_UTUN:-<not found>}"
echo

route_iface() {
    route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'
}

is_rfc1918() {
    # RFC 1918 private ranges (10/8, 172.16/12, 192.168/16).
    case "$1" in
        10.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        192.168.*) return 0 ;;
        *) return 1 ;;
    esac
}

# Known corporate VPN gateway host-routes: the single-IP (/32, or bare IP
# with no prefix) entries in direct-cidrs.txt. These are always expected to
# route via en0 (the physical interface) -- the corporate VPN client reaches
# its own gateway directly, never through the personal VPN.
GATEWAY_IPS=$(read_lines "$CONFIG_DIR/direct-cidrs.txt" | awk -F/ 'NF==1 || $2=="32" {print $1}')

is_gateway_ip() {
    ip=$1
    for g in $GATEWAY_IPS; do
        [ "$g" = "$ip" ] && return 0
    done
    return 1
}

echo "=== corp-hosts-check.txt ==="
printf '  %-52s %-16s %-16s %-10s %-10s %s\n' "HOST" "DSCACHEUTIL_IP" "DIG_IP" "IFACE" "EXPECTED" "RESULT"

HOSTS=$(read_lines "$CONFIG_DIR/corp-hosts-check.txt")
if [ -z "$HOSTS" ]; then
    echo "  (no hosts configured)"
fi

for host in $HOSTS; do
    dscache_ip=$(dscacheutil_bounded "$host")
    dig_ip=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    test_ip=${dscache_ip:-$dig_ip}

    if [ -z "$test_ip" ]; then
        printf '  %-52s %-16s %-16s %-10s %-10s %s\n' "$host" "-" "-" "-" "-" "WARN(no resolve)"
        continue
    fi

    iface=$(route_iface "$test_ip")

    # Expected route interface for this host, generalized (no corporate
    # netblocks hardcoded here):
    #   - resolved IP is a direct-cidrs.txt gateway  -> en0 (always; the
    #     corporate VPN client reaches its own gateway directly)
    #   - otherwise the IP is RFC 1918               -> corporate VPN utun
    #   - otherwise (public corporate host)          -> in --mode forward it
    #     is merely NOT the personal utun (no site-list route claims it, so
    #     it falls through to whatever else does); in --mode exclude it is
    #     specifically en0, because AmneziaVPN installs a real kernel route
    #     for it via the physical gateway (MacosRouteMonitor::
    #     addExclusionRoute) rather than just leaving it unclaimed.
    if is_gateway_ip "$test_ip"; then
        expected="en0"
    elif is_rfc1918 "$test_ip"; then
        expected="${CP_UTUN:-CP_utun}"
    elif [ "$MODE" = "exclude" ]; then
        expected="en0"
    else
        expected="!${AMNEZIA_UTUN:-Amnezia_utun}"
    fi

    result_status=1
    case "$expected" in
        '!'*)
            # "NOT the personal utun" expectation: PASS if a different interface
            personal=${expected#!}
            [ "$iface" != "$personal" ] && result_status=0
            ;;
        *)
            [ "$iface" = "$expected" ] && result_status=0
            ;;
    esac

    printf '  %-52s %-16s %-16s %-10s %-10s ' "$host" "${dscache_ip:--}" "${dig_ip:--}" "${iface:--}" "$expected"
    if [ "$result_status" = 0 ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
    count_result "$result_status"
done

echo
echo "=== public IPs / direct-domain (before Amnezia import, some FAIL is expected) ==="
printf '  %-40s %-16s %-10s %-10s %s\n' "TARGET" "IP" "IFACE" "EXPECTED" "RESULT"

check_public_ip() {
    label=$1
    ip=$2
    expected=$3
    iface=$(route_iface "$ip")
    result_status=1
    [ "$iface" = "$expected" ] && result_status=0
    printf '  %-40s %-16s %-10s %-10s ' "$label" "$ip" "${iface:--}" "$expected"
    if [ "$result_status" = 0 ]; then
        echo "PASS"
    else
        echo "FAIL (expected before Amnezia site-list import)"
    fi
    count_result "$result_status"
}

check_public_ip "8.8.8.8" "8.8.8.8" "${AMNEZIA_UTUN:-Amnezia_utun}"
check_public_ip "1.1.1.1" "1.1.1.1" "${AMNEZIA_UTUN:-Amnezia_utun}"
check_public_ip "142.250.0.100 (Google)" "142.250.0.100" "${AMNEZIA_UTUN:-Amnezia_utun}"

FIRST_DIRECT_DOMAIN=$(read_lines "$CONFIG_DIR/direct-domains.txt" | head -1)
if [ -n "$FIRST_DIRECT_DOMAIN" ]; then
    dd_ip=$(dig +short +time=2 +tries=1 A "$FIRST_DIRECT_DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -n "$dd_ip" ]; then
        check_public_ip "$FIRST_DIRECT_DOMAIN (direct-domain)" "$dd_ip" "en0"
    else
        echo "  WARNING: failed to resolve first direct-domain '$FIRST_DIRECT_DOMAIN'"
    fi
else
    echo "  (no direct-domains configured)"
fi

echo
echo "=== egress IP ==="
EGRESS_DEFAULT=$(curl -sS -m 10 --noproxy '*' https://api.ipify.org 2>/dev/null)
EGRESS_EN0=$(curl -sS -m 10 --noproxy '*' --interface en0 https://api.ipify.org 2>/dev/null)
printf '  %-20s %s\n' "default route:" "${EGRESS_DEFAULT:-<failed>}"
printf '  %-20s %s\n' "forced en0 (direct):" "${EGRESS_EN0:-<failed>}"

echo
echo "=== route counts per utun interface (netstat -rn -f inet) ==="
netstat -rn -f inet 2>/dev/null | grep -oE 'utun[0-9]+' | sort | uniq -c | sort -k2 -V | \
    awk '{printf "  %-8s %s routes\n", $2, $1}'

if [ "$MODE" = "exclude" ] && [ -n "$AMNEZIA_UTUN" ]; then
    # In --mode exclude the client installs only four fixed half-space
    # routes on the personal VPN's own utun (see MacosRouteMonitor::
    # addExclusionRoute); every excluded destination instead gets a real
    # kernel route via the physical gateway, so it shows up under en0 (or
    # the corporate utun), never here. A little slack (<=10) absorbs
    # incidental system-managed entries without weakening the point: this
    # must stay small, unlike --mode forward's ~2,200 with the full list.
    AMNEZIA_ROUTE_COUNT=$(netstat -rn -f inet 2>/dev/null | grep -oE 'utun[0-9]+' | grep -cE "^${AMNEZIA_UTUN}\$")
    echo
    if [ "$AMNEZIA_ROUTE_COUNT" -le 10 ] 2>/dev/null; then
        echo "  [PASS] personal VPN utun ($AMNEZIA_UTUN) carries only $AMNEZIA_ROUTE_COUNT route(s) (<=10 expected: the four half-space routes plus incidental slack)"
        count_result 0
    else
        echo "  [FAIL] personal VPN utun ($AMNEZIA_UTUN) carries $AMNEZIA_ROUTE_COUNT routes (>10 expected only the four half-space routes -- was the exclusion list imported into \"only selected sites\" by mistake?)"
        count_result 1
    fi
fi

echo
echo "=== summary ==="
echo "  $((TOTAL_COUNT - FAIL_COUNT))/$TOTAL_COUNT checks PASSED"
if [ "$FAIL_COUNT" = 0 ]; then
    echo "All checks PASSED"
    exit 0
else
    echo "$FAIL_COUNT check(s) FAILED (see table above)"
    exit 1
fi
