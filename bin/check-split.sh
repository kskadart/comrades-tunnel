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
# Usage: check-split.sh [--config DIR]
# Exit code: 0 if every expectation PASSed, 1 otherwise.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
CONFIG_DIR="$REPO_ROOT/local"

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
        *)
            echo "Usage: $0 [--config DIR]" >&2
            exit 2
            ;;
    esac
done

read_lines() {
    [ -f "$1" ] || return 0
    sed -e 's/#.*$//' "$1" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$'
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

CP_UTUN=$(detect_utun_by_prefix "10.0.42.")
AMNEZIA_UTUN=$(detect_utun_by_prefix "10.8.")

echo "Config dir: $CONFIG_DIR"
echo "Detected Check Point utun (inet 10.0.42.x): ${CP_UTUN:-<not found>}"
echo "Detected Amnezia utun (inet 10.8.x):        ${AMNEZIA_UTUN:-<not found>}"
echo

route_iface() {
    route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'
}

is_rfc1918_or_corp_public() {
    case "$1" in
        10.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        192.168.*) return 0 ;;
        203.0.113.*) return 0 ;;
        *) return 1 ;;
    esac
}

# Known VPN gateway host-routes: any /32 entry in direct-cidrs.txt. These
# must always reach the internet via en0 (the physical interface), even
# though their address may otherwise look like it belongs to the Check
# Point-pushed 203.0.113.x range -- a VPN client cannot tunnel packets to its
# own gateway through the tunnel it's building.
GATEWAY_IPS=$(read_lines "$CONFIG_DIR/direct-cidrs.txt" | grep '/32$' | sed 's#/32$##')

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
    dscache_ip=$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/{print $2; exit}')
    dig_ip=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    test_ip=${dscache_ip:-$dig_ip}

    if [ -z "$test_ip" ]; then
        printf '  %-52s %-16s %-16s %-10s %-10s %s\n' "$host" "-" "-" "-" "-" "WARN(no resolve)"
        continue
    fi

    iface=$(route_iface "$test_ip")

    if is_gateway_ip "$test_ip"; then
        expected="en0"
    elif is_rfc1918_or_corp_public "$test_ip"; then
        expected="${CP_UTUN:-CP_utun}"
    else
        expected="en0"
    fi

    result_status=1
    [ "$iface" = "$expected" ] && result_status=0

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
