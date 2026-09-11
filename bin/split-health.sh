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
#   4. WARN -- the site list file for the current mode is older than
#      --stale-days (default 30).
#   5. WARN -- the primary network service's first DNS server is a
#      corporate one from corp-dns.txt -- the same condition dns-guard.sh
#      intervenes on; this only reports, it never calls networksetup.
#   6. INFO -- corporate/personal utun presence and route counts.
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
# Usage: split-health.sh [--config DIR] [--gateway-mode {direct,tunnel}]
#                         [--stale-days N] [--dry-run] [--status] [--test-telegram]
# With no mode flag, this performs a real run: checks, updates state,
# sends Telegram per the policy above, and appends one log line. Exit code
# is always 0 in that mode (a LaunchAgent tick must never look like a
# crash); --dry-run/--status/--test-telegram also exit 0 except on a usage
# error (2).

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
        *)
            echo "Usage: $0 [--config DIR] [--gateway-mode {direct,tunnel}] [--stale-days N] [--dry-run] [--status] [--test-telegram]" >&2
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

case "$MODE" in
    forward) SITES_FILE="$REPO_ROOT/build/amnezia-sites.txt" ;;
    exclude) SITES_FILE="$REPO_ROOT/build/amnezia-exclude.txt" ;;
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
# Check 4 -- WARN: generated site list for current MODE is stale
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
# Check 5 -- WARN: primary service's DNS list starts with a corporate server
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
CHECK_IDS="CORP_LEAK SPLIT_ABSENT IPV6 STALE DNS_CLOBBER"

check_label() {
    case "$1" in
        CORP_LEAK) echo "корпоративный хост через личный VPN" ;;
        SPLIT_ABSENT) echo "личный VPN поднят, но сплит не применён" ;;
        IPV6) echo "глобальный IPv6 обходит исключения" ;;
        STALE) echo "список сайтов устарел" ;;
        DNS_CLOBBER) echo "DNS основного сервиса подменён" ;;
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
}

status_of() {   # status_of CHECKID -- current run's computed status
    case "$1" in
        CORP_LEAK) echo "$CORP_LEAK_STATUS" ;;
        SPLIT_ABSENT) echo "$SPLIT_ABSENT_STATUS" ;;
        IPV6) echo "$IPV6_STATUS" ;;
        STALE) echo "$STALE_STATUS" ;;
        DNS_CLOBBER) echo "$DNS_CLOBBER_STATUS" ;;
    esac
}

evidence_of() {   # evidence_of CHECKID -- current run's computed evidence
    case "$1" in
        CORP_LEAK) echo "$CORP_LEAK_EVIDENCE" ;;
        SPLIT_ABSENT) echo "$SPLIT_ABSENT_EVIDENCE" ;;
        IPV6) echo "$IPV6_EVIDENCE" ;;
        STALE) echo "$STALE_EVIDENCE" ;;
        DNS_CLOBBER) echo "$DNS_CLOBBER_EVIDENCE" ;;
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

LOG_LINE="$(date '+%Y-%m-%dT%H:%M:%S%z') ${LOG_PARTS}MODE=${MODE} CP_UTUN=${CP_UTUN:-none}(${CP_ROUTES}) AMNEZIA_UTUN=${AMNEZIA_UTUN:-none}(${AMNEZIA_ROUTES})"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
printf '%s\n' "$LOG_LINE" >>"$LOG_FILE" 2>/dev/null

exit 0
