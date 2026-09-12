#!/bin/sh
# Periodic, read-only health monitor for the dual-VPN split routing --
# unlike bin/check-split.sh (a command a human has to remember to run), this
# is meant to run every few minutes as a LaunchAgent (see
# bin/install-split-health.sh) and ping Telegram only when something
# changes. It never touches routes, DNS, or VPN state -- same read-only
# discipline as check-split.sh.
#
# Why this exists: in AmneziaVPN's "all sites except the listed ones" mode
# (--mode exclude), a silent split-tunnel failure means ALL traffic,
# including corporate, goes through the personal VPN -- and nothing about
# the UI changes to say so. Today the only detector is a human remembering
# to run `make check`. This script is mode-independent (it reads the
# expected mode from local/split-mode.txt rather than assuming one), so it
# is correct both before and after a switch between forward/exclude.
#
# Utun detection is identical to check-split.sh (dynamic, from
# tunnels.txt's inet prefixes -- never a hardcoded utun number); the
# detect_utun_by_prefix/get_tunnel_prefix/routes_on_iface helpers are
# reused from lib-routes.sh (sourced below) instead of re-implemented, the
# same way cp-connect.sh/route-lift-watcher.sh already do. check-split.sh
# itself is untouched.
#
# Checks performed every run (OK/WARN/FAIL each), full rationale for the
# thresholds in the corresponding code below:
#   1. FAIL -- a host in corp-hosts-check.txt, or (in --gateway-mode direct)
#      a vpn-gateways.txt entry or the first address of a direct-cidrs.txt
#      CIDR, resolves/routes via the PERSONAL VPN's utun. Wrong in every
#      mode -- this is the dangerous case.
#   2. FAIL -- the personal utun is up but carries a route count that does
#      not match local/split-mode.txt's MODE: more than 50 in `exclude`
#      (should be ~4 fixed half-space routes) or fewer than 50 while
#      build/amnezia-sites.txt has hundreds of entries in `forward`.
#   3. WARN -- the primary interface has a global (non-fe80:) IPv6 address
#      while the personal utun is up: the exclusion list is IPv4-only, so
#      IPv6 traffic bypasses it straight into the personal tunnel.
#   4. WARN -- the primary network service's first DNS server is a
#      corporate one from corp-dns.txt -- the same condition dns-guard.sh
#      intervenes on; this only reports, it never calls networksetup.
#   5. INFO -- corporate/personal utun presence and route counts.
#
# Drift detection (checks 5a/5b/5c below) replaces the old "list not
# regenerated in 30 days" timer as the primary signal -- that timer is kept
# as check 5d, lowest priority, because "not regenerated in a while" is only
# ever a proxy for the three real symptoms/causes below:
#   5a. SYMPTOM_LIVE, every tick, bounded to ~30s total -- resolves every
#       direct-domains.txt domain and every corp-hosts-check.txt host that
#       resolves to a public address RIGHT NOW (short DNS timeout, see
#       below) and checks each resolved IPv4 against the generated file for
#       the current MODE: must NOT be covered by build/.../amnezia-sites.txt
#       in forward mode, must BE covered by build/.../amnezia-exclude.txt in
#       exclude mode. A miss means that address is tunneled through the
#       personal VPN right now even though it must not be -- WARN. Caches
#       nothing (must reflect live state); if resolution is failing broadly
#       (no network), reports INFO instead of flooding WARNs.
#   5b. REGISTRY_DIFF, at most once every 7 days (persisted in STATE_DIR) --
#       runs gen-amnezia-sites.py in the background with --refresh and
#       --dry-run-output (a temp file, build/ untouched) for the current
#       MODE, so RIPEstat/RIPE NCC data is re-fetched, then diffs that
#       against the currently generated file and WARNs with +added/-removed
#       network counts on any difference. This is the check that catches an
#       ISP/company changing its announced prefixes, which 5a cannot see
#       (5a only checks addresses already known to matter, not the ASN's
#       announced-prefix set as a whole). Bounded to 420s (measured: a real
#       --refresh run against ~30 direct-domains.txt entries took 3m51s); a
#       timeout or generator failure reports INFO, not WARN, and still
#       counts as this week's attempt.
#   5c. IMPORT_MISMATCH, every tick -- compares the generated file for the
#       current MODE against what AmneziaVPN currently has imported, read
#       read-only from ~/Library/Preferences/org.amneziavpn.AmneziaVPN.plist
#       (Conf.ForwardSites in forward mode, Conf.ExceptSites in exclude
#       mode -- see client/settings.cpp's routeModeString()/vpnSites() in
#       the AmneziaVPN source). WARNs with +added/-removed network counts
#       (never hostnames/CIDRs) on any difference -- this is the check that
#       catches "regenerated but forgot to reimport", which neither 5a nor
#       5b can see. Only that one key is ever read; Servers.serversList
#       (encrypted server config) is never touched or printed.
#   5d. STALE, WARN -- the site list file for the current mode is older
#       than --stale-days (default 30). Lowest priority: a fresh list can
#       still be wrong (5b/5c) and a stale list can still be accurate, but
#       an untouched-for-months list is still worth a nudge on its own.
#
# Notification policy (see also README): a Telegram message is sent only on
# a state transition of one check (OK->FAIL, FAIL->OK, OK->WARN, WARN->OK,
# and WARN<->FAIL for completeness), read from per-check state files under
# STATE_DIR; while a check stays FAIL, a reminder resends at most once every
# 6 hours. Every real run appends one compact line to LOG_FILE regardless of
# whether anything was sent. Telegram credentials are read from the same two
# Keychain items ~/.claude/hooks/telegram-notify.sh uses (tg_creds/
# tg_send_raw in that script): "comrades-tunnel-telegram-bot-token"
# and "comrades-tunnel-telegram-bot-chat", both `-a "$USER"`. They are
# never printed or logged.
#
# Build output is namespaced per --config (see gen-amnezia-sites.py): the
# default local/ writes to build/, anything else writes to
# build/<config-dir-basename>/. This script resolves the same BUILD_DIR so
# SITES_FILE (used by checks 5a/5b/5d) always points at the file the active
# --config actually produced.
#
# Usage: split-health.sh [--config DIR] [--gateway-mode {direct,tunnel}]
#                         [--stale-days N] [--dry-run] [--status]
#                         [--test-telegram] [--self-test]
# With no mode flag, this performs a real run: checks, updates state,
# sends Telegram per the policy above, and appends one log line. Exit code
# is always 0 in that mode (a LaunchAgent tick must never look like a
# crash); --dry-run/--status/--test-telegram also exit 0 except on a usage
# error (2). --self-test runs fully offline against synthetic data (no
# network, no real config/plist) and exits 0 only if every case PASSes.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# shellcheck source=lib-routes.sh
. "$SCRIPT_DIR/lib-routes.sh"

CONFIG_DIR="$REPO_ROOT/local"
GATEWAY_MODE="direct"
STALE_DAYS=30
DRY_RUN=0
STATUS=0
TEST_TELEGRAM=0
SELF_TEST=0

while [ $# -gt 0 ]; do
    case "$1" in
        --config) CONFIG_DIR=$2; shift 2 ;;
        --config=*) CONFIG_DIR=${1#--config=}; shift ;;
        --gateway-mode) GATEWAY_MODE=$2; shift 2 ;;
        --gateway-mode=*) GATEWAY_MODE=${1#--gateway-mode=}; shift ;;
        --stale-days) STALE_DAYS=$2; shift 2 ;;
        --stale-days=*) STALE_DAYS=${1#--stale-days=}; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --status) STATUS=1; shift ;;
        --test-telegram) TEST_TELEGRAM=1; shift ;;
        --self-test) SELF_TEST=1; shift ;;
        *)
            echo "Usage: $0 [--config DIR] [--gateway-mode {direct,tunnel}] [--stale-days N] [--dry-run] [--status] [--test-telegram] [--self-test]" >&2
            exit 2
            ;;
    esac
done

case "$GATEWAY_MODE" in
    direct|tunnel) ;;
    *)
        echo "ERROR: invalid --gateway-mode '$GATEWAY_MODE' (expected 'direct' or 'tunnel')" >&2
        exit 2
        ;;
esac

STATE_DIR="$HOME/Library/Application Support/comrades-tunnel/split-health-state"
LOG_FILE="$HOME/Library/Logs/comrades-tunnel-split-health.log"
PLIST_LABEL="dev.comrades-tunnel.split-health"
NOW=$(date +%s)
FAIL_RENOTIFY_SECONDS=$((6 * 3600))

# --- small helpers (deliberately duplicated from check-split.sh/dns-guard.sh
# rather than factored further -- same convention those two already follow
# for their own copies of read_lines/normalize_list) ---

read_lines() {
    [ -f "$1" ] || return 0
    sed -e 's/#.*$//' "$1" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$'
}

# A literal newline, for building up a multi-line variable: $(...) always
# strips a trailing newline, so appending "$(printf ...'\n')" alone loses
# the separator between rows -- append this instead after each row.
NL='
'

route_iface() {
    route -n get "$1" 2>/dev/null | awk '/interface:/{print $2}'
}

# --- Telegram: reuse the exact Keychain services and the plain (non-reply)
# curl POST shape from ~/.claude/hooks/telegram-notify.sh's tg_creds/
# tg_send_raw. Never echoes TG_TOKEN/TG_CHAT_ID.
tg_creds() {
    TG_TOKEN=$(security find-generic-password -a "$USER" -s comrades-tunnel-telegram-bot-token -w 2>/dev/null)
    TG_CHAT_ID=$(security find-generic-password -a "$USER" -s comrades-tunnel-telegram-bot-chat -w 2>/dev/null)
    [ -n "$TG_TOKEN" ] && [ -n "$TG_CHAT_ID" ]
}

tg_send() {   # $1 = plain text. Prints one status line; returns 0 if HTTP 200.
    if ! tg_creds; then
        echo "  (Telegram: Keychain lookup failed for user $USER -- skipping send)"
        return 1
    fi
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT_ID}" \
        --data-urlencode "text=$1")
    if [ "$code" = "200" ]; then
        echo "  (Telegram: sent, HTTP $code)"
        return 0
    else
        echo "  (Telegram: send FAILED, HTTP ${code:-<no response>})"
        return 1
    fi
}

if [ "$TEST_TELEGRAM" = 1 ]; then
    if ! tg_creds; then
        echo "Telegram credentials did not resolve from Keychain for user $USER (comrades-tunnel-telegram-bot-token / -chat) -- skipping test send."
        exit 0
    fi
    echo "Sending exactly one test message..."
    tg_send "comrades-tunnel split-health: test"
    exit 0
fi

# --- helpers for the three drift-detection checks (5a/5b/5c, see header) ---

# ip_covered_by_file IP FILE -- prints 1 if IP falls inside any CIDR line of
# FILE (one CIDR/host per line, '#' comments allowed), else 0. A missing
# FILE counts as "covers nothing". python3 stdlib ipaddress; used by
# SYMPTOM_LIVE (a few dozen calls per tick, each fast: one interpreter
# startup plus a linear scan of FILE) and by --self-test.
ip_covered_by_file() {
    ip=$1
    file=$2
    if [ ! -f "$file" ]; then
        echo 0
        return
    fi
    python3 -c '
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
covered = 0
try:
    with open(sys.argv[2]) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if ip in net:
                covered = 1
                break
except OSError:
    pass
print(covered)
' "$ip" "$file"
}

# is_private_ipv4 IP -- true (0) for RFC 1918 private ranges (10/8,
# 172.16/12, 192.168/16); same case-pattern as check-split.sh's is_rfc1918
# (duplicated, not sourced -- see this script's own note on small helpers
# above). Used by SYMPTOM_LIVE to decide whether a resolved
# corp-hosts-check.txt address is public (checkable against the generated
# file) or internal (handled by the corporate tunnel, not this check).
is_private_ipv4() {
    case "$1" in
        10.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        192.168.*) return 0 ;;
        *) return 1 ;;
    esac
}

# net_diff_counts FILE_A FILE_B FORMAT_B -- prints "ADDED REMOVED A_COUNT
# B_COUNT" for the symmetric difference between two CIDR sets. FILE_A is
# always one CIDR per line. FILE_B is the same when FORMAT_B is "lines", or
# a JSON object whose KEYS are CIDRs when FORMAT_B is "json" (AmneziaVPN
# stores each imported site as a hostname/CIDR key with its resolved ip --
# often empty for our own generated entries -- as the value; see
# SitesController::importSites() in the AmneziaVPN client source). ADDED is
# present in FILE_A but not FILE_B; REMOVED is the reverse. A missing or
# unparseable file on either side counts as an empty set, never an error.
# Shared by REGISTRY_DIFF (lines vs. lines), IMPORT_MISMATCH (lines vs. the
# plist's JSON export), and --self-test (both, entirely offline).
net_diff_counts() {
    python3 -c '
import ipaddress, json, sys

def normalize(items):
    out = set()
    for item in items:
        try:
            out.add(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue
    return out

def read_lines_set(path):
    try:
        with open(path) as fh:
            return normalize(line.strip() for line in fh if line.strip())
    except OSError:
        return set()

def read_json_keys_set(path):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return set()
    return normalize(data.keys()) if isinstance(data, dict) else set()

a = read_lines_set(sys.argv[1])
b = read_json_keys_set(sys.argv[2]) if sys.argv[3] == "json" else read_lines_set(sys.argv[2])
added = a - b
removed = b - a
print(len(added), len(removed), len(a), len(b))
' "$1" "$2" "$3"
}

# import_mismatch_diff GEN_FILE MODE_KEY -- prints "ADDED REMOVED GEN_COUNT
# IMP_COUNT" comparing GEN_FILE against what AmneziaVPN currently has
# imported under the literal top-level plist key "Conf.<MODE_KEY>" in
# ~/Library/Preferences/org.amneziavpn.AmneziaVPN.plist. MODE_KEY is
# "ForwardSites" for --mode forward or "ExceptSites" for --mode exclude --
# see Settings::routeModeString()/vpnSites()/getVpnIps() in
# client/settings.cpp of the AmneziaVPN source: QSettings groups map "/" to
# "." on macOS's native (CFPreferences) format, so "Conf/ForwardSites"
# becomes the single top-level key "Conf.ForwardSites", confirmed against
# this machine's real plist. `defaults read DOMAIN "Conf.<MODE_KEY>"`
# extracts ONLY that one key as an old-style NeXTSTEP property list (a
# whole-file `plutil -convert json` fails on this plist because
# Servers.serversList holds NSData -- the encrypted per-server config --
# which JSON cannot represent); `plutil -convert json` then turns that
# single extracted key into JSON for net_diff_counts. Servers.serversList
# and Servers.defaultServerIndex are never read, converted, or printed at
# any point. A missing plist, missing key (e.g. exclude mode never used
# yet), or absent AmneziaVPN install is treated as "nothing imported"
# (IMP_COUNT=0), not an error.
import_mismatch_diff() {
    gen_file=$1
    mode_key=$2
    plist="$HOME/Library/Preferences/org.amneziavpn.AmneziaVPN.plist"
    nextstep=$(mktemp)
    imp_json=$(mktemp)
    echo '{}' >"$imp_json"
    if [ -f "$plist" ] && defaults read org.amneziavpn.AmneziaVPN "Conf.$mode_key" >"$nextstep" 2>/dev/null; then
        plutil -convert json -o "$imp_json" "$nextstep" 2>/dev/null || echo '{}' >"$imp_json"
    fi
    net_diff_counts "$gen_file" "$imp_json" json
    rm -f "$nextstep" "$imp_json"
}

if [ "$SELF_TEST" = 1 ]; then
    echo "=== split-health.sh --self-test (offline: synthetic data only, no network/config/plist) ==="
    ST_OK=1
    ST_TMPDIR=$(mktemp -d)

    st_check() {   # st_check LABEL RESULT(0=pass)
        if [ "$2" = 0 ]; then
            echo "  [PASS] $1"
        else
            echo "  [FAIL] $1"
            ST_OK=0
        fi
    }

    # --- (a) SYMPTOM_LIVE: covered / not-covered against a synthetic list ---
    printf '10.0.0.0/8\n1.2.3.0/24\n' >"$ST_TMPDIR/sites.txt"
    st_covered=$(ip_covered_by_file "1.2.3.4" "$ST_TMPDIR/sites.txt")
    st_check "(a) 1.2.3.4 reported covered by a synthetic list containing 1.2.3.0/24" \
        "$([ "$st_covered" = 1 ] && echo 0 || echo 1)"
    st_not_covered=$(ip_covered_by_file "8.8.8.8" "$ST_TMPDIR/sites.txt")
    st_check "(a) 8.8.8.8 reported NOT covered by the same synthetic list" \
        "$([ "$st_not_covered" = 0 ] && echo 0 || echo 1)"

    # --- (b) REGISTRY_DIFF: diff detected between two synthetic lists ---
    printf '5.6.7.0/24\n8.9.10.0/24\n' >"$ST_TMPDIR/old.txt"
    printf '5.6.7.0/24\n11.12.13.0/24\n' >"$ST_TMPDIR/new.txt"
    set -- $(net_diff_counts "$ST_TMPDIR/old.txt" "$ST_TMPDIR/new.txt" lines)
    st_check "(b) synthetic diff detects +1 added / -1 removed network" \
        "$([ "$1" = 1 ] && [ "$2" = 1 ] && echo 0 || echo 1)"
    set -- $(net_diff_counts "$ST_TMPDIR/old.txt" "$ST_TMPDIR/old.txt" lines)
    st_check "(b) identical synthetic lists show no diff" \
        "$([ "$1" = 0 ] && [ "$2" = 0 ] && echo 0 || echo 1)"

    # --- (c) IMPORT_MISMATCH: matching and mismatching synthetic sets ---
    # (net_diff_counts directly, not import_mismatch_diff -- the real plist
    # is never touched in --self-test, per its own requirement.)
    printf '1.2.3.0/24\n4.5.6.0/24\n' >"$ST_TMPDIR/gen.txt"
    printf '{"1.2.3.0/24": "", "4.5.6.0/24": ""}' >"$ST_TMPDIR/imp_match.json"
    printf '{"1.2.3.0/24": "", "9.9.9.0/24": ""}' >"$ST_TMPDIR/imp_mismatch.json"
    set -- $(net_diff_counts "$ST_TMPDIR/gen.txt" "$ST_TMPDIR/imp_match.json" json)
    st_check "(c) matching synthetic sets show no diff" \
        "$([ "$1" = 0 ] && [ "$2" = 0 ] && echo 0 || echo 1)"
    set -- $(net_diff_counts "$ST_TMPDIR/gen.txt" "$ST_TMPDIR/imp_mismatch.json" json)
    st_check "(c) mismatching synthetic sets show +1 added / -1 removed" \
        "$([ "$1" = 1 ] && [ "$2" = 1 ] && echo 0 || echo 1)"

    rm -rf "$ST_TMPDIR"
    echo
    if [ "$ST_OK" = 1 ]; then
        echo "Self-test PASSED"
        exit 0
    else
        echo "Self-test FAILED"
        exit 1
    fi
fi

# --- per-check state, KEY=VALUE files under STATE_DIR, read with grep/cut
# only (never sourced/eval'd) -- same discipline as every other config file
# in this repo.
state_read() {   # state_read CHECKID KEY
    f="$STATE_DIR/$1.state"
    [ -f "$f" ] || return 0
    grep "^$2=" "$f" 2>/dev/null | tail -1 | cut -d= -f2-
}

state_write() {   # state_write CHECKID STATUS EVIDENCE LAST_FAIL_NOTIFY
    mkdir -p "$STATE_DIR"
    f="$STATE_DIR/$1.state"
    tmp="$STATE_DIR/.$1.tmp"
    {
        printf 'STATUS=%s\n' "$2"
        printf 'EVIDENCE=%s\n' "$3"
        printf 'LAST_FAIL_NOTIFY=%s\n' "$4"
        printf 'LAST_TS=%s\n' "$NOW"
    } >"$tmp" 2>/dev/null && mv -f "$tmp" "$f"
}

# --- MODE (forward|exclude) from split-mode.txt; missing/unset defaults to
# forward (Amnezia's historical default here) with a note, matching how the
# rest of this repo treats missing optional config as "least surprising
# default" rather than a hard error. ---
MODE_FILE="$CONFIG_DIR/split-mode.txt"
MODE_NOTE=""
MODE=$(grep '^MODE=' "$MODE_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')
case "$MODE" in
    forward|exclude) ;;
    '')
        MODE_NOTE="NOTE: $MODE_FILE not found or MODE= not set -- defaulting to forward (see config/example/split-mode.txt)."
        MODE=forward
        ;;
    *)
        echo "ERROR: invalid MODE '$MODE' in $MODE_FILE (expected 'forward' or 'exclude')" >&2
        exit 2
        ;;
esac

# --- build output is namespaced per --config (see gen-amnezia-sites.py's
# module docstring): the default local/ writes to build/, anything else
# writes to build/<config-dir-basename>/. Resolve CONFIG_DIR to an absolute
# path first (same "relative is relative to REPO_ROOT" convention
# install-split-health.sh already uses) so the comparison against
# REPO_ROOT/local is exact regardless of how --config was spelled. ---
case "$CONFIG_DIR" in
    /*) CONFIG_DIR_ABS=$CONFIG_DIR ;;
    *) CONFIG_DIR_ABS="$REPO_ROOT/$CONFIG_DIR" ;;
esac
[ -d "$CONFIG_DIR_ABS" ] && CONFIG_DIR_ABS=$(cd "$CONFIG_DIR_ABS" && pwd)

if [ "$CONFIG_DIR_ABS" = "$REPO_ROOT/local" ]; then
    BUILD_DIR="$REPO_ROOT/build"
else
    BUILD_DIR="$REPO_ROOT/build/$(basename "$CONFIG_DIR_ABS")"
fi

case "$MODE" in
    forward) SITES_FILE="$BUILD_DIR/amnezia-sites.txt" ;;
    exclude) SITES_FILE="$BUILD_DIR/amnezia-exclude.txt" ;;
esac

# --- detect the two VPN utun interfaces (see lib-routes.sh) ---
TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
CORP_TUNNEL_PREFIX=$(get_tunnel_prefix CORP_TUNNEL_PREFIX)
PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)
CP_UTUN=$(detect_utun_by_prefix "$CORP_TUNNEL_PREFIX")
AMNEZIA_UTUN=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
CP_ROUTES=0
AMNEZIA_ROUTES=0
[ -n "$CP_UTUN" ] && CP_ROUTES=$(routes_on_iface "$CP_UTUN")
[ -n "$AMNEZIA_UTUN" ] && AMNEZIA_ROUTES=$(routes_on_iface "$AMNEZIA_UTUN")

# =========================================================================
# Check 1 -- FAIL: corporate host/gateway/netblock routed via personal VPN
# =========================================================================
CORP_LEAK_STATUS=OK
if [ "$GATEWAY_MODE" = "direct" ]; then
    CORP_LEAK_EVIDENCE="ни один хост из corp-hosts-check.txt, ни шлюз/сеть из vpn-gateways.txt/direct-cidrs.txt не идёт через личный VPN"
else
    CORP_LEAK_EVIDENCE="ни один хост из corp-hosts-check.txt не идёт через личный VPN (gateway-mode=tunnel: шлюзы не проверяются)"
fi
CORP_LEAK_HIT=0
CORP_LEAK_TABLE=""

for host in $(read_lines "$CONFIG_DIR/corp-hosts-check.txt"); do
    dscache_ip=$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/{print $2; exit}')
    dig_ip=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    test_ip=${dscache_ip:-$dig_ip}
    [ -z "$test_ip" ] && continue
    iface=$(route_iface "$test_ip")
    CORP_LEAK_TABLE="${CORP_LEAK_TABLE}$(printf '  %-42s %-16s %s' "$host" "$test_ip" "${iface:--}")${NL}"
    if [ -n "$AMNEZIA_UTUN" ] && [ "$iface" = "$AMNEZIA_UTUN" ]; then
        CORP_LEAK_HIT=1
        CORP_LEAK_STATUS=FAIL
        CORP_LEAK_EVIDENCE="корпоративный хост $host ($test_ip) идёт через личный VPN ($AMNEZIA_UTUN)"
    fi
done

if [ "$GATEWAY_MODE" = "direct" ] && [ "$CORP_LEAK_HIT" = 0 ]; then
    for src in "$CONFIG_DIR/direct-cidrs.txt" "$CONFIG_DIR/vpn-gateways.txt"; do
        [ -f "$src" ] || continue
        for entry in $(read_lines "$src"); do
            ip=${entry%%/*}
            [ -z "$ip" ] && continue
            iface=$(route_iface "$ip")
            CORP_LEAK_TABLE="${CORP_LEAK_TABLE}$(printf '  %-42s %-16s %s' "$ip ($(basename "$src"))" "-" "${iface:--}")${NL}"
            if [ -n "$AMNEZIA_UTUN" ] && [ "$iface" = "$AMNEZIA_UTUN" ]; then
                CORP_LEAK_HIT=1
                CORP_LEAK_STATUS=FAIL
                CORP_LEAK_EVIDENCE="сеть/шлюз $ip (из $(basename "$src")) идёт через личный VPN ($AMNEZIA_UTUN)"
                break 2
            fi
        done
    done
fi

# =========================================================================
# Check 2 -- FAIL: personal VPN up but route count wrong for MODE
# =========================================================================
SPLIT_ABSENT_STATUS=OK
if [ -n "$AMNEZIA_UTUN" ]; then
    case "$MODE" in
        exclude)
            if [ "$AMNEZIA_ROUTES" -gt 50 ] 2>/dev/null; then
                SPLIT_ABSENT_STATUS=FAIL
                SPLIT_ABSENT_EVIDENCE="личный VPN ($AMNEZIA_UTUN) несёт $AMNEZIA_ROUTES маршрутов (ожидалось около 4, допуск до 50) -- похоже, импортирован не тот список или включён не тот режим в приложении"
            else
                SPLIT_ABSENT_EVIDENCE="личный VPN ($AMNEZIA_UTUN) несёт $AMNEZIA_ROUTES маршрутов, как и ожидается для режима exclude"
            fi
            ;;
        forward)
            SITES_LINES=0
            [ -f "$SITES_FILE" ] && SITES_LINES=$(wc -l <"$SITES_FILE" 2>/dev/null | tr -d ' ')
            [ -z "$SITES_LINES" ] && SITES_LINES=0
            if [ "$SITES_LINES" -gt 100 ] 2>/dev/null && [ "$AMNEZIA_ROUTES" -lt 50 ] 2>/dev/null; then
                SPLIT_ABSENT_STATUS=FAIL
                SPLIT_ABSENT_EVIDENCE="личный VPN ($AMNEZIA_UTUN) несёт только $AMNEZIA_ROUTES маршрутов, а $SITES_FILE содержит $SITES_LINES сетей -- сплит не применён"
            else
                SPLIT_ABSENT_EVIDENCE="личный VPN ($AMNEZIA_UTUN) несёт $AMNEZIA_ROUTES маршрутов из $SITES_LINES в списке для режима forward"
            fi
            ;;
    esac
else
    SPLIT_ABSENT_EVIDENCE="личный VPN не поднят -- нечего проверять"
fi

# =========================================================================
# Check 3 -- WARN: global IPv6 on the primary interface while personal VPN up
# =========================================================================
PRIMARY_IFACE=$(route -n get default 2>/dev/null | sed -n 's/^[[:space:]]*interface: *//p' | head -1)
IPV6_STATUS=OK
IPV6_EVIDENCE="на ${PRIMARY_IFACE:-<интерфейс не найден>} нет глобального IPv6, либо личный VPN не поднят"
if [ -n "$PRIMARY_IFACE" ] && [ -n "$AMNEZIA_UTUN" ]; then
    GLOBAL_V6=$(ifconfig "$PRIMARY_IFACE" 2>/dev/null | awk '/inet6 /{print $2}' | grep -v '^fe80:' | head -1)
    if [ -n "$GLOBAL_V6" ]; then
        IPV6_STATUS=WARN
        IPV6_EVIDENCE="на $PRIMARY_IFACE обнаружен глобальный IPv6 $GLOBAL_V6, пока личный VPN ($AMNEZIA_UTUN) поднят -- список исключений только IPv4, IPv6-трафик уходит в обход прямо в личный VPN"
    fi
fi

# =========================================================================
# Check STALE (5d in the header's drift-detection family, lowest priority) --
# WARN: generated site list for current MODE is stale
# =========================================================================
STALE_STATUS=OK
if [ ! -f "$SITES_FILE" ]; then
    STALE_STATUS=WARN
    STALE_EVIDENCE="$SITES_FILE не найден -- список для режима $MODE ещё не сгенерирован"
else
    MTIME=$(stat -f %m "$SITES_FILE" 2>/dev/null || echo "$NOW")
    AGE_DAYS=$(( (NOW - MTIME) / 86400 ))
    if [ "$AGE_DAYS" -gt "$STALE_DAYS" ]; then
        STALE_STATUS=WARN
        STALE_EVIDENCE="$SITES_FILE не обновлялся $AGE_DAYS дней (порог $STALE_DAYS) -- IP-адреса сервисов могли смениться"
    else
        STALE_EVIDENCE="$SITES_FILE обновлялся $AGE_DAYS дней назад (порог $STALE_DAYS)"
    fi
fi

# =========================================================================
# Check DNS_CLOBBER (4 in the header) -- WARN: primary service's DNS list
# starts with a corporate server
# =========================================================================
DNS_SERVICE=""
if [ -n "$PRIMARY_IFACE" ]; then
    DNS_SERVICE=$(networksetup -listnetworkserviceorder 2>/dev/null | awk -v want="Device: $PRIMARY_IFACE)" '
        /^\([0-9]+\)/ { name = $0; sub(/^\([0-9]+\)[ \t]*/, "", name) }
        index($0, want) { print name; exit }
    ')
fi
DNS_FIRST=""
if [ -n "$DNS_SERVICE" ]; then
    DNS_RAW=$(networksetup -getdnsservers "$DNS_SERVICE" 2>/dev/null)
    case "$DNS_RAW" in
        "There aren't any DNS Servers set on "*) DNS_FIRST="" ;;
        *) DNS_FIRST=$(printf '%s\n' "$DNS_RAW" | head -1) ;;
    esac
fi
DNS_CLOBBER_STATUS=OK
DNS_CLOBBER_EVIDENCE="DNS сервиса ${DNS_SERVICE:-<не определён>} не начинается с корпоративного сервера"
if [ -n "$DNS_FIRST" ]; then
    for c in $(read_lines "$CONFIG_DIR/corp-dns.txt"); do
        if [ "$c" = "$DNS_FIRST" ]; then
            DNS_CLOBBER_STATUS=WARN
            DNS_CLOBBER_EVIDENCE="DNS сервиса $DNS_SERVICE начинается с корпоративного сервера $DNS_FIRST (см. dns-guard.sh)"
            break
        fi
    done
fi

# =========================================================================
# Notification decision: shared by --dry-run (read-only preview) and the
# real run (writes state + sends). ID list kept in one place for --status.
# =========================================================================
CHECK_IDS="CORP_LEAK SPLIT_ABSENT IPV6 STALE DNS_CLOBBER SYMPTOM_LIVE REGISTRY_DIFF IMPORT_MISMATCH"

check_label() {
    case "$1" in
        CORP_LEAK) echo "корпоративный хост через личный VPN" ;;
        SPLIT_ABSENT) echo "личный VPN поднят, но сплит не применён" ;;
        IPV6) echo "глобальный IPv6 обходит исключения" ;;
        STALE) echo "список сайтов устарел" ;;
        DNS_CLOBBER) echo "DNS основного сервиса подменён" ;;
        SYMPTOM_LIVE) echo "живой адрес идёт через личный VPN вопреки списку" ;;
        REGISTRY_DIFF) echo "сверка с реестром RIPEstat/RIPE показала изменения" ;;
        IMPORT_MISMATCH) echo "сгенерированный список расходится с импортированным в Amnezia" ;;
    esac
}

# decide_send CHECKID NEW_STATUS -- reads state read-only, prints "1 <new_fail_notify>"
# or "0 <prev_fail_notify>" (whether to send, and what LAST_FAIL_NOTIFY should
# become if the caller proceeds to write state).
decide_send() {
    id=$1; new_status=$2
    prev_status=$(state_read "$id" STATUS)
    [ -z "$prev_status" ] && prev_status=OK
    prev_fail_notify=$(state_read "$id" LAST_FAIL_NOTIFY)
    [ -z "$prev_fail_notify" ] && prev_fail_notify=0
    send=0
    [ "$new_status" != "$prev_status" ] && send=1
    fail_notify=$prev_fail_notify
    if [ "$new_status" = FAIL ]; then
        elapsed=$((NOW - prev_fail_notify))
        [ "$send" = 0 ] && [ "$elapsed" -ge "$FAIL_RENOTIFY_SECONDS" ] && send=1
        [ "$send" = 1 ] && fail_notify=$NOW
    fi
    echo "$send $fail_notify"
}

if [ "$STATUS" = 1 ]; then
    echo "=== split-health status ==="
    echo "Config: $CONFIG_DIR"
    echo "State dir: $STATE_DIR"
    echo
    for id in $CHECK_IDS; do
        st=$(state_read "$id" STATUS)
        ev=$(state_read "$id" EVIDENCE)
        ts=$(state_read "$id" LAST_TS)
        if [ -z "$st" ]; then
            printf '%-14s %s\n' "$id" "no state yet (never run without --dry-run/--status/--test-telegram)"
        else
            age="?"
            [ -n "$ts" ] && age=$(( (NOW - ts) / 60 ))
            printf '%-14s %-5s %s (обновлено %sм назад)\n' "$id" "$st" "$ev" "$age"
        fi
    done
    echo
    echo "Last 10 log lines ($LOG_FILE):"
    if [ -r "$LOG_FILE" ]; then
        tail -10 "$LOG_FILE"
    else
        echo "  (no log yet)"
    fi
    echo
    if launchctl print "gui/$(id -u)/$PLIST_LABEL" >/dev/null 2>&1; then
        echo "LaunchAgent loaded: YES ($PLIST_LABEL)"
    else
        echo "LaunchAgent loaded: NO ($PLIST_LABEL)"
    fi
    exit 0
fi

# =========================================================================
# Check SYMPTOM_LIVE (5a) -- WARN: a direct-domains.txt domain, or a public
# corp-hosts-check.txt address, resolves RIGHT NOW to an IPv4 that the
# generated file for the current MODE does not (yet) handle correctly.
# Deliberately skipped for --status above (DNS resolution here can take up
# to SYMPTOM_BUDGET_SECONDS) so `make health-status` stays fast; --dry-run
# and a real run both compute it for real, per SITES_FILE (already
# namespaced per --config, see above).
# =========================================================================
SYMPTOM_BUDGET_SECONDS=25
SYMPTOM_START=$(date +%s)
SYMPTOM_ATTEMPTED=0
SYMPTOM_RESOLVED=0
SYMPTOM_VIOLATIONS=0
SYMPTOM_SKIPPED=0
SYMPTOM_TABLE=""
SYMPTOM_LAST_MISS=""

symptom_budget_left() {
    [ $(( $(date +%s) - SYMPTOM_START )) -lt "$SYMPTOM_BUDGET_SECONDS" ]
}

# symptom_check_host HOST PUBLIC_ONLY -- resolves HOST with the same
# `dig +time=2 +tries=1` convention check 1 already uses in this script,
# then (if PUBLIC_ONLY=1, only for public addresses -- corp-hosts-check.txt
# may legitimately resolve to an internal RFC1918 address, which is not
# this check's concern) tests coverage against SITES_FILE for the active
# MODE via ip_covered_by_file.
symptom_check_host() {
    host=$1
    public_only=$2
    ip=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    SYMPTOM_ATTEMPTED=$((SYMPTOM_ATTEMPTED + 1))
    [ -z "$ip" ] && return
    if [ "$public_only" = 1 ] && is_private_ipv4 "$ip"; then
        return
    fi
    SYMPTOM_RESOLVED=$((SYMPTOM_RESOLVED + 1))
    covered=$(ip_covered_by_file "$ip" "$SITES_FILE")
    if [ "$MODE" = "exclude" ]; then
        ok=$([ "$covered" = 1 ] && echo 1 || echo 0)
    else
        ok=$([ "$covered" = 0 ] && echo 1 || echo 0)
    fi
    result="OK"
    if [ "$ok" != 1 ]; then
        result="MISS"
        SYMPTOM_VIOLATIONS=$((SYMPTOM_VIOLATIONS + 1))
        SYMPTOM_LAST_MISS="домен/хост $host ($ip) сейчас идёт через личный VPN, перегенерируйте и переимпортируйте список"
    fi
    SYMPTOM_TABLE="${SYMPTOM_TABLE}$(printf '  %-42s %-16s %s' "$host" "$ip" "$result")${NL}"
}

DIRECT_DOMAINS_TMP=$(mktemp)
read_lines "$CONFIG_DIR/direct-domains.txt" >"$DIRECT_DOMAINS_TMP"
DIRECT_DOMAINS_TOTAL=$(grep -c . "$DIRECT_DOMAINS_TMP" 2>/dev/null || echo 0)
DIRECT_DOMAINS_SEEN=0
while IFS= read -r line; do
    domain=${line%% *}
    [ -z "$domain" ] && continue
    DIRECT_DOMAINS_SEEN=$((DIRECT_DOMAINS_SEEN + 1))
    if ! symptom_budget_left; then
        SYMPTOM_SKIPPED=$((SYMPTOM_SKIPPED + DIRECT_DOMAINS_TOTAL - DIRECT_DOMAINS_SEEN + 1))
        break
    fi
    symptom_check_host "$domain" 0
done <"$DIRECT_DOMAINS_TMP"
rm -f "$DIRECT_DOMAINS_TMP"

CORP_HOSTS_TMP=$(mktemp)
read_lines "$CONFIG_DIR/corp-hosts-check.txt" >"$CORP_HOSTS_TMP"
CORP_HOSTS_TOTAL=$(grep -c . "$CORP_HOSTS_TMP" 2>/dev/null || echo 0)
CORP_HOSTS_SEEN=0
while IFS= read -r host; do
    [ -z "$host" ] && continue
    CORP_HOSTS_SEEN=$((CORP_HOSTS_SEEN + 1))
    if ! symptom_budget_left; then
        SYMPTOM_SKIPPED=$((SYMPTOM_SKIPPED + CORP_HOSTS_TOTAL - CORP_HOSTS_SEEN + 1))
        break
    fi
    symptom_check_host "$host" 1
done <"$CORP_HOSTS_TMP"
rm -f "$CORP_HOSTS_TMP"

SYMPTOM_SKIPPED_NOTE=""
[ "$SYMPTOM_SKIPPED" -gt 0 ] && SYMPTOM_SKIPPED_NOTE=" (бюджет времени исчерпан, $SYMPTOM_SKIPPED не проверено в этом тике)"

if [ "$SYMPTOM_ATTEMPTED" -eq 0 ]; then
    SYMPTOM_LIVE_STATUS=OK
    SYMPTOM_LIVE_EVIDENCE="нет доменов/хостов для живой проверки"
elif [ "$SYMPTOM_RESOLVED" -eq 0 ] && [ "$SYMPTOM_ATTEMPTED" -ge 3 ]; then
    SYMPTOM_LIVE_STATUS=INFO
    SYMPTOM_LIVE_EVIDENCE="живая проверка не смогла резолвить ни один из $SYMPTOM_ATTEMPTED адресов (сети нет?) -- пропущено в этом тике$SYMPTOM_SKIPPED_NOTE"
elif [ "$SYMPTOM_VIOLATIONS" -gt 0 ]; then
    SYMPTOM_LIVE_STATUS=WARN
    SYMPTOM_LIVE_EVIDENCE="$SYMPTOM_LAST_MISS (всего проблемных: $SYMPTOM_VIOLATIONS из $SYMPTOM_RESOLVED резолвленных)$SYMPTOM_SKIPPED_NOTE"
else
    SYMPTOM_LIVE_STATUS=OK
    SYMPTOM_LIVE_EVIDENCE="проверено вживую $SYMPTOM_RESOLVED адрес(ов) из $SYMPTOM_ATTEMPTED, утечек через личный VPN не найдено (режим $MODE)$SYMPTOM_SKIPPED_NOTE"
fi

# =========================================================================
# Check REGISTRY_DIFF (5b) -- WARN: re-fetching RIPEstat/RIPE NCC data for
# the current MODE and regenerating (dry-run, build/ untouched) produces a
# different network list than what is currently generated. At most once
# every 7 days (persisted in STATE_DIR); a timeout/failure reports INFO and
# still counts as this cycle's attempt so a persistent outage does not
# retry every single tick. Also deliberately skipped for --status (this can
# take up to REGISTRY_DIFF_TIMEOUT_SECONDS on a real run).
# =========================================================================
REGISTRY_DIFF_LAST_RUN_FILE="$STATE_DIR/registry-diff-last-run"
REGISTRY_DIFF_INTERVAL_SECONDS=$((7 * 24 * 3600))
REGISTRY_DIFF_TIMEOUT_SECONDS=420
REGISTRY_DIFF_LAST_RUN=0
[ -f "$REGISTRY_DIFF_LAST_RUN_FILE" ] && REGISTRY_DIFF_LAST_RUN=$(cat "$REGISTRY_DIFF_LAST_RUN_FILE" 2>/dev/null)
case "$REGISTRY_DIFF_LAST_RUN" in ''|*[!0-9]*) REGISTRY_DIFF_LAST_RUN=0 ;; esac
REGISTRY_DIFF_DUE=0
[ $(( NOW - REGISTRY_DIFF_LAST_RUN )) -ge "$REGISTRY_DIFF_INTERVAL_SECONDS" ] && REGISTRY_DIFF_DUE=1
REGISTRY_DIFF_DID_RUN=0

if [ "$REGISTRY_DIFF_DUE" = 1 ]; then
    REGISTRY_DIFF_DID_RUN=1
    RD_TMP_LIST=$(mktemp)
    RD_GEN_LOG=$(mktemp)
    RD_START=$(date +%s)
    python3 "$SCRIPT_DIR/gen-amnezia-sites.py" --config "$CONFIG_DIR_ABS" --mode "$MODE" \
        --refresh --dry-run-output "$RD_TMP_LIST" >"$RD_GEN_LOG" 2>&1 &
    RD_PID=$!
    ( sleep "$REGISTRY_DIFF_TIMEOUT_SECONDS"; kill -TERM "$RD_PID" 2>/dev/null ) &
    RD_WATCHDOG=$!
    wait "$RD_PID" 2>/dev/null
    RD_RC=$?
    kill "$RD_WATCHDOG" 2>/dev/null
    wait "$RD_WATCHDOG" 2>/dev/null
    RD_ELAPSED=$(( $(date +%s) - RD_START ))

    if [ "$RD_RC" -ne 0 ] || [ ! -s "$RD_TMP_LIST" ]; then
        REGISTRY_DIFF_STATUS=INFO
        REGISTRY_DIFF_EVIDENCE="сверка с реестром RIPEstat/RIPE не выполнена (генератор завершился с кодом $RD_RC за ${RD_ELAPSED}с, возможно нет сети или таймаут ${REGISTRY_DIFF_TIMEOUT_SECONDS}с) -- следующая попытка через 7 дней"
    else
        set -- $(net_diff_counts "$SITES_FILE" "$RD_TMP_LIST" lines)
        RD_ADDED=$1
        RD_REMOVED=$2
        if [ "$RD_ADDED" -eq 0 ] 2>/dev/null && [ "$RD_REMOVED" -eq 0 ] 2>/dev/null; then
            REGISTRY_DIFF_STATUS=OK
            REGISTRY_DIFF_EVIDENCE="сверка с реестром (--refresh, режим $MODE) изменений не показала (${RD_ELAPSED}с)"
        else
            REGISTRY_DIFF_STATUS=WARN
            REGISTRY_DIFF_EVIDENCE="сверка с реестром показала изменения: +$RD_ADDED/-$RD_REMOVED сетей относительно $SITES_FILE (${RD_ELAPSED}с) -- перегенерируйте и переимпортируйте список"
        fi
    fi
    rm -f "$RD_TMP_LIST" "$RD_GEN_LOG"
else
    REGISTRY_DIFF_STATUS=$(state_read REGISTRY_DIFF STATUS)
    REGISTRY_DIFF_EVIDENCE=$(state_read REGISTRY_DIFF EVIDENCE)
    [ -z "$REGISTRY_DIFF_STATUS" ] && REGISTRY_DIFF_STATUS=OK
    [ -z "$REGISTRY_DIFF_EVIDENCE" ] && REGISTRY_DIFF_EVIDENCE="сверка с реестром ещё не выполнялась"
    if [ "$REGISTRY_DIFF_LAST_RUN" = 0 ]; then
        REGISTRY_DIFF_EVIDENCE="$REGISTRY_DIFF_EVIDENCE (ни разу не выполнялась; раз в 7 дней)"
    else
        RD_AGE_DAYS=$(( (NOW - REGISTRY_DIFF_LAST_RUN) / 86400 ))
        REGISTRY_DIFF_EVIDENCE="$REGISTRY_DIFF_EVIDENCE (последняя проверка ${RD_AGE_DAYS}д назад; раз в 7 дней)"
    fi
fi

# =========================================================================
# Check IMPORT_MISMATCH (5c) -- WARN: the generated file for the current
# MODE differs from what AmneziaVPN currently has imported (read read-only
# from its plist, see import_mismatch_diff() above). Cheap (one `defaults
# read` + one python3 diff), so this runs every tick including --dry-run;
# deliberately still skipped for --status above, for uniformity with the
# other two drift checks.
# =========================================================================
case "$MODE" in
    forward) IMPORT_MODE_KEY="ForwardSites" ;;
    exclude) IMPORT_MODE_KEY="ExceptSites" ;;
esac
set -- $(import_mismatch_diff "$SITES_FILE" "$IMPORT_MODE_KEY")
IMPORT_ADDED=$1
IMPORT_REMOVED=$2
IMPORT_GEN_COUNT=$3
IMPORT_IMP_COUNT=$4
if [ "$IMPORT_ADDED" -eq 0 ] 2>/dev/null && [ "$IMPORT_REMOVED" -eq 0 ] 2>/dev/null; then
    IMPORT_MISMATCH_STATUS=OK
    IMPORT_MISMATCH_EVIDENCE="сгенерированный список (Conf.$IMPORT_MODE_KEY, $IMPORT_GEN_COUNT сетей) совпадает с импортированным в Amnezia ($IMPORT_IMP_COUNT сетей)"
else
    IMPORT_MISMATCH_STATUS=WARN
    IMPORT_MISMATCH_EVIDENCE="сгенерированный список отличается от импортированного в Amnezia: +$IMPORT_ADDED/-$IMPORT_REMOVED сетей -- переимпортируйте"
fi

print_table() {   # shared by --dry-run and the real run's own echo to stdout
    echo "Config dir: $CONFIG_DIR"
    echo "Gateway mode: $GATEWAY_MODE   Split mode (from $MODE_FILE): $MODE   Stale threshold: ${STALE_DAYS}d"
    [ -n "$MODE_NOTE" ] && echo "$MODE_NOTE"
    echo
    echo "=== INFO ==="
    if [ -n "$CP_UTUN" ]; then
        echo "  Corporate utun: $CP_UTUN ($CP_ROUTES routes)"
    else
        echo "  Corporate utun: not present"
    fi
    if [ -n "$AMNEZIA_UTUN" ]; then
        echo "  Personal utun:  $AMNEZIA_UTUN ($AMNEZIA_ROUTES routes)"
    else
        echo "  Personal utun:  not present"
    fi
    echo
    echo "=== check 1: corp-hosts-check.txt / vpn-gateways.txt / direct-cidrs.txt routing ==="
    printf '  %-42s %-16s %s\n' "TARGET" "IP" "IFACE"
    if [ -n "$CORP_LEAK_TABLE" ]; then
        printf '%b' "$CORP_LEAK_TABLE"
    else
        echo "  (no hosts configured / none resolved)"
    fi
    echo "  [$CORP_LEAK_STATUS] $CORP_LEAK_EVIDENCE"
    echo
    echo "=== check 2: personal VPN route count vs MODE=$MODE ==="
    echo "  [$SPLIT_ABSENT_STATUS] $SPLIT_ABSENT_EVIDENCE"
    echo
    echo "=== check 3: IPv6 exposure ==="
    echo "  [$IPV6_STATUS] $IPV6_EVIDENCE"
    echo
    echo "=== check 4: site-list staleness ==="
    echo "  [$STALE_STATUS] $STALE_EVIDENCE"
    echo
    echo "=== check 5: DNS clobbered ==="
    echo "  [$DNS_CLOBBER_STATUS] $DNS_CLOBBER_EVIDENCE"
    echo
    echo "=== check 5a: live symptom -- direct-domains.txt/corp-hosts-check.txt vs $SITES_FILE ==="
    printf '  %-42s %-16s %s\n' "HOST" "IP" "RESULT"
    if [ -n "$SYMPTOM_TABLE" ]; then
        printf '%b' "$SYMPTOM_TABLE"
    else
        echo "  (nothing resolved this tick)"
    fi
    echo "  [$SYMPTOM_LIVE_STATUS] $SYMPTOM_LIVE_EVIDENCE"
    echo
    echo "=== check 5b: registry diff -- RIPEstat/RIPE NCC re-fetch vs $SITES_FILE (at most once/7d) ==="
    echo "  [$REGISTRY_DIFF_STATUS] $REGISTRY_DIFF_EVIDENCE"
    echo
    echo "=== check 5c: generated vs imported -- Conf.$IMPORT_MODE_KEY in AmneziaVPN's plist ==="
    echo "  [$IMPORT_MISMATCH_STATUS] $IMPORT_MISMATCH_EVIDENCE"
}

status_of() {   # status_of CHECKID -- current run's computed status
    case "$1" in
        CORP_LEAK) echo "$CORP_LEAK_STATUS" ;;
        SPLIT_ABSENT) echo "$SPLIT_ABSENT_STATUS" ;;
        IPV6) echo "$IPV6_STATUS" ;;
        STALE) echo "$STALE_STATUS" ;;
        DNS_CLOBBER) echo "$DNS_CLOBBER_STATUS" ;;
        SYMPTOM_LIVE) echo "$SYMPTOM_LIVE_STATUS" ;;
        REGISTRY_DIFF) echo "$REGISTRY_DIFF_STATUS" ;;
        IMPORT_MISMATCH) echo "$IMPORT_MISMATCH_STATUS" ;;
    esac
}

evidence_of() {   # evidence_of CHECKID -- current run's computed evidence
    case "$1" in
        CORP_LEAK) echo "$CORP_LEAK_EVIDENCE" ;;
        SPLIT_ABSENT) echo "$SPLIT_ABSENT_EVIDENCE" ;;
        IPV6) echo "$IPV6_EVIDENCE" ;;
        STALE) echo "$STALE_EVIDENCE" ;;
        DNS_CLOBBER) echo "$DNS_CLOBBER_EVIDENCE" ;;
        SYMPTOM_LIVE) echo "$SYMPTOM_LIVE_EVIDENCE" ;;
        REGISTRY_DIFF) echo "$REGISTRY_DIFF_EVIDENCE" ;;
        IMPORT_MISMATCH) echo "$IMPORT_MISMATCH_EVIDENCE" ;;
    esac
}

if [ "$DRY_RUN" = 1 ]; then
    echo "=== split-health: dry-run (touches nothing, sends nothing) ==="
    print_table
    echo
    echo "=== would notify? ==="
    for id in $CHECK_IDS; do
        st=$(status_of "$id")
        ev=$(evidence_of "$id")
        decision=$(decide_send "$id" "$st")
        send=${decision% *}
        if [ "$send" = 1 ]; then
            echo "  $id: WOULD SEND -> split-health: $st -- $ev Режим: $MODE."
        else
            echo "  $id: no send (no transition, or FAIL repeat not yet due)"
        fi
    done
    exit 0
fi

# --- real run: notify per policy, write state, append one log line ---
LOG_PARTS=""
for id in $CHECK_IDS; do
    st=$(status_of "$id")
    ev=$(evidence_of "$id")
    decision=$(decide_send "$id" "$st")
    send=${decision% *}
    fail_notify=${decision#* }
    if [ "$send" = 1 ]; then
        if [ "$st" = OK ]; then
            msg="split-health: OK -- $(check_label "$id") устранено: $ev Режим: $MODE."
        else
            msg="split-health: $st -- $ev Режим: $MODE."
        fi
        tg_send "$msg" >/dev/null 2>&1
    fi
    state_write "$id" "$st" "$ev" "$fail_notify"
    LOG_PARTS="${LOG_PARTS}${id}=${st} "
done

# REGISTRY_DIFF's 7-day gate is persisted only on a real run that actually
# invoked the generator this tick (see the check's own comment above) --
# never in --dry-run, so re-running --dry-run does not consume the budget.
if [ "$REGISTRY_DIFF_DID_RUN" = 1 ]; then
    mkdir -p "$STATE_DIR"
    printf '%s\n' "$NOW" >"$REGISTRY_DIFF_LAST_RUN_FILE" 2>/dev/null
fi

LOG_LINE="$(date '+%Y-%m-%dT%H:%M:%S%z') ${LOG_PARTS}MODE=${MODE} CP_UTUN=${CP_UTUN:-none}(${CP_ROUTES}) AMNEZIA_UTUN=${AMNEZIA_UTUN:-none}(${AMNEZIA_ROUTES})"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
printf '%s\n' "$LOG_LINE" >>"$LOG_FILE" 2>/dev/null

exit 0
