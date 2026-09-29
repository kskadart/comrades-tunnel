#!/bin/sh
# Revert the corporate VPN client's rewrite of the primary network service's
# DNS servers.
#
# On connect, Check Point Endpoint Security VPN rewrites the DNS server list
# of the primary network service at the "Setup" layer (the same layer as
# System Settings / `networksetup -setdnsservers`): it prepends the
# corporate DNS servers and search domains, keeping the DHCP servers behind
# them. Corporate DNS filters some public names while it is first in the
# list. This guard restores the desired DNS server list; it never touches
# search domains or corporate split-DNS (/etc/resolver/<zone>), which keep
# working regardless of the system DNS server list.
#
# Settings come from a KEY=VALUE conf file, parsed with grep/cut only --
# this script may run unattended as root via a LaunchDaemon and must never
# `.`/source or eval file content:
#   SERVERS   space-separated desired DNS servers (e.g. "1.1.1.1 1.0.0.1"),
#             or the single word "dhcp" to clear the manual list instead
#             (`networksetup -setdnsservers <service> Empty`) so the
#             service falls back to whatever DNS the current network's
#             DHCP offers. Prefer "dhcp" on a laptop that moves between
#             networks: a manual server list written here is stored in the
#             service's Setup layer and stays in force on EVERY network
#             until something rewrites it -- so a fixed "1.1.1.1" keeps
#             overriding an office/home DHCP resolver long after the
#             corporate client's rewrite that triggered it, whereas "dhcp"
#             simply hands DNS back to the network you are on.
#   MODE      "corp-only" -- intervene only when the current DNS list
#             contains a corporate DNS server; "always" -- enforce SERVERS
#             whenever the current list differs from it
#   CORP_DNS  space-separated corporate DNS servers (required for
#             MODE=corp-only, used to detect the corporate rewrite)
#   KILLSWITCH_DNS  "auto" (default) -- when AmneziaVPN's Kill Switch has
#             its pf anchor amn/310.blockDNS loaded, add CORP_DNS to that
#             anchor's <dnsaddr> table so DNS queries to the corporate
#             resolvers (port 53 through the corporate utun) are not
#             dropped; "off" -- never touch pf. See the Kill Switch block
#             below for why this is needed at all.
#
# Config source:
#   default: <script-dir>/dns-guard.conf (the installed location, rendered
#            by install-dns-guard.sh)
#   --config DIR: read DIR/dns-guard.txt (SERVERS, MODE, one KEY=VALUE per
#                 line) and DIR/corp-dns.txt (one IP per line, '#' comments
#                 allowed, same format install-resolvers.sh already reads)
#                 to derive CORP_DNS -- lets this script run straight
#                 against config/example/ or local/ without installing
#                 anything.
#
# --dry-run prints the decision and the exact networksetup command without
# executing it. Exit 0 in every handled case (including "nothing to do");
# exit 2 on a usage/config error.
#
# Usage: dns-guard.sh [--config DIR] [--dry-run] [--print-service] [--self-test]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

CONFIG_DIR=""
CONF_FILE="$SCRIPT_DIR/dns-guard.conf"
DRY_RUN=0
PRINT_SERVICE=0
SELF_TEST=0

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
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --print-service)
            PRINT_SERVICE=1
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--dry-run] [--print-service] [--self-test]" >&2
            exit 2
            ;;
    esac
done

# resolve_config_dir REPO_ROOT DIR -- resolve a possibly-relative --config
# DIR to an absolute path: an absolute DIR is returned unchanged; a
# relative DIR is resolved against the current working directory when it
# exists there (unchanged behaviour), else against REPO_ROOT (the script's
# parent directory) instead, so `--config local` works from any CWD, not
# just the repo root. A DIR that exists in neither location is returned as
# a CWD-relative absolute path (still unresolved further) so the caller's
# own "not found" error still names the path as given.
resolve_config_dir() {
    repo_root=$1
    dir=$2
    case "$dir" in
        /*) printf '%s\n' "$dir"; return 0 ;;
    esac
    if [ -d "$dir" ]; then
        (cd "$dir" && pwd)
        return 0
    fi
    if [ -d "$repo_root/$dir" ]; then
        (cd "$repo_root/$dir" && pwd)
        return 0
    fi
    printf '%s/%s\n' "$(pwd)" "$dir"
}

# service_for_interface IFACE -- print the network service name whose
# Device matches IFACE in `networksetup -listnetworkserviceorder`'s output.
# Moved above the --print-service early-exit below so both paths share this
# one copy (see finding 11 in the review this fixes: the two copies used to
# diverge, and the old --print-service copy's own bug -- see next
# paragraph -- went unnoticed there for exactly that reason).
#
# A disabled service is prefixed "(*)" instead of "(N)" in that listing, and
# can share the same Device as an enabled one (e.g. right after a hardware
# port is toggled off in System Settings, or a duplicate virtual service).
# The awk state machine resets `name`/`disabled` on either prefix form, and
# only reports a match when the entry is NOT disabled -- printing the
# disabled entry's name instead of an active one on the same Device would
# silently mis-target every dns-guard action at the wrong network service.
service_for_interface() {
    iface=$1
    networksetup -listnetworkserviceorder | awk -v want="Device: $iface)" '
        /^\([0-9*]+\)/ {
            disabled = ($0 ~ /^\(\*\)/)
            name = $0
            sub(/^\([0-9*]+\)[\t ]*/, "", name)
        }
        index($0, want) && !disabled { print name; exit }
    '
}

# same_set A B -- true if space-separated lists A and B contain exactly the
# same members, ignoring order. networksetup may echo DNS servers back in a
# different order than SERVERS lists them (or than the OS applies them), so
# an ordered string comparison would treat that as "still wrong" forever --
# see the MODE=always convergence check below (finding 12).
same_set() {
    s1=$(printf '%s\n' $1 | sort)
    s2=$(printf '%s\n' $2 | sort)
    [ "$s1" = "$s2" ]
}

# servers_means_dhcp SERVERS -- true if the (normalized) SERVERS value is
# the single keyword "dhcp" (any letter case), i.e. the desired state is
# "no manual DNS servers on the service; use the network's DHCP-offered
# ones". networksetup spells that state "Empty", which is also accepted
# here so `SERVERS=Empty` reads the same as the `make dns-reset` target.
servers_means_dhcp() {
    case "$1" in
        [Dd][Hh][Cc][Pp]|[Ee][Mm][Pp][Tt][Yy]) return 0 ;;
        *) return 1 ;;
    esac
}

# log MESSAGE -- timestamped append to LOG_FILE, falling back to stderr if
# LOG_FILE cannot be written (e.g. running unprivileged). Moved above
# run_self_test so --self-test can exercise it directly.
log() {
    ts=$(date '+%Y-%m-%dT%H:%M:%S%z')
    line="$ts $1"
    if ! { printf '%s\n' "$line" >>"$LOG_FILE"; } 2>/dev/null; then
        printf '%s\n' "$line" >&2
    fi
}

# log_if_changed MESSAGE -- log MESSAGE only when it differs from the last
# message logged this way (remembered in STATE_FILE). The daemon also runs
# on a 30 s StartInterval (see the installer: Amnezia can replace its Kill
# Switch DNS table on events that touch no watched file, e.g. the corporate
# client connecting), and without this every such run would append the
# same "ok current=[...]" line forever. Interventions, warnings and Kill
# Switch additions still log every time through log(); an intervention
# also forgets the remembered line, so the next "ok" is logged once again.
STATE_FILE="/var/run/comrades-tunnel-dns-guard.state"
log_if_changed() {
    last=$(cat "$STATE_FILE" 2>/dev/null || true)
    if [ "$last" != "$1" ]; then
        log "$1"
        { printf '%s\n' "$1" >"$STATE_FILE"; } 2>/dev/null || true
    fi
}

# --- AmneziaVPN Kill Switch DNS exceptions (KILLSWITCH_DNS=auto) ---
# AmneziaVPN's Kill Switch loads the pf anchor amn/310.blockDNS:
#   block return out proto { tcp, udp } to port 53
#   pass out proto { tcp, udp } to <dnsaddr> port 53
# and fills <dnsaddr> with its own DNS servers only. Every query to the
# corporate resolvers behind /etc/resolver/<zone> (port 53 through the
# corporate utun) is therefore dropped and corporate names stop resolving,
# while the corporate tunnel itself is fine (200.allowVPN passes every
# utun). Amnezia has a "DNS exceptions" setting for exactly this, but on
# macOS it never reaches the table for WireGuard/AmneziaWG (amnezia-client
# issue #2513; still so on 5.0.1 -- the addresses sit in
# Conf.allowedDnsServers, the table stays [1.1.1.1 1.0.0.1]). So this
# daemon adds CORP_DNS to the table itself whenever the anchor is loaded.
# Amnezia replaces the table on every (re)connect, and every (re)connect
# also rewrites the system DNS, which is what fires this daemon via
# WatchPaths -- plus a second look a few seconds later (finish), in case
# the table is replaced after the DNS event that woke us.
KS_ANCHOR="amn/310.blockDNS"
KS_TABLE="dnsaddr"

# killswitch_missing_dns CURRENT WANTED -- print the members of WANTED
# (space-separated) that are not in CURRENT, in WANTED's order, space-
# separated; empty when nothing is missing.
killswitch_missing_dns() {
    missing=""
    for want in $2; do
        found=0
        for have in $1; do
            if [ "$have" = "$want" ]; then
                found=1
                break
            fi
        done
        [ "$found" = 0 ] && missing="$missing $want"
    done
    printf '%s\n' "${missing# }"
}

# ensure_killswitch_dns -- add whatever of CORP_DNS is missing from the
# Kill Switch DNS table. No-op (and in --dry-run says why) when
# KILLSWITCH_DNS=off, CORP_DNS is empty, we are not root (pf cannot even
# be inspected unprivileged), or the anchor is not loaded (Kill Switch off
# or Amnezia not connected).
ensure_killswitch_dns() {
    [ "$KILLSWITCH_DNS" = "auto" ] || return 0
    [ -n "$CORP_DNS" ] || return 0
    if [ "$(id -u)" != 0 ]; then
        [ "$DRY_RUN" = 1 ] && echo "killswitch: pf needs root to inspect -- skipped in this unprivileged run"
        return 0
    fi
    if ! current=$(pfctl -q -a "$KS_ANCHOR" -t "$KS_TABLE" -T show 2>/dev/null); then
        [ "$DRY_RUN" = 1 ] && echo "killswitch: pf anchor $KS_ANCHOR not loaded (Amnezia Kill Switch off or not connected) -- nothing to do"
        return 0
    fi
    current=$(normalize_list "$(printf '%s\n' "$current" | tr -d '\t' | tr '\n' ' ')")
    missing=$(killswitch_missing_dns "$current" "$CORP_DNS")
    if [ -z "$missing" ]; then
        [ "$DRY_RUN" = 1 ] && echo "killswitch: table <$KS_TABLE> already has [$CORP_DNS] (table: [$current])"
        return 0
    fi
    if [ "$DRY_RUN" = 1 ]; then
        echo "killswitch: would run: pfctl -a '$KS_ANCHOR' -t $KS_TABLE -T add $missing   (table now [$current])"
        return 0
    fi
    if pfctl -q -a "$KS_ANCHOR" -t "$KS_TABLE" -T add $missing >/dev/null 2>&1; then
        log "killswitch: added [$missing] to pf table $KS_ANCHOR <$KS_TABLE> (was [$current]) -- Amnezia ignores its own DNS exceptions on macOS, issue #2513"
    else
        log "WARNING: killswitch: pfctl -a '$KS_ANCHOR' -t $KS_TABLE -T add $missing failed"
    fi
}

# flush_dns_cache -- drop mDNSResponder's cache right after the corporate
# client rewrote the DNS list, i.e. right after the corporate VPN came up.
# While it was down, a lookup of an internal-only name behind
# /etc/resolver/<zone> could not reach the corporate resolvers, and the
# system resolver ended up caching that name's PUBLIC address for the
# record's full TTL (seen 2026-09-21: the corporate webmail host kept
# landing on the public server's 404 page for most of an hour after the
# tunnel was up, while a direct query to the corporate DNS already gave
# the internal address). Connecting the VPN does not invalidate that
# cache; this does, so the next lookup goes to the corporate resolver,
# which is reachable now.
flush_dns_cache() {
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
}

# finish -- the normal-path exit: one more look at the Kill Switch table a
# few seconds later (see the block above), then exit 0.
finish() {
    if [ "$DRY_RUN" = 0 ] && [ "$KILLSWITCH_DNS" = "auto" ] && [ "$(id -u)" = 0 ]; then
        sleep 5
        ensure_killswitch_dns
    fi
    exit 0
}

# run_self_test: exercise service_for_interface (finding 11) against a
# synthetic `networksetup -listnetworkserviceorder`-style listing containing
# a disabled ("(*)") duplicate, and same_set (finding 12) against
# reordered/genuinely-different lists. Independent of any config directory
# or real networksetup/DNS state -- networksetup is shadowed for the
# duration of this function only.
run_self_test() {
    fail=0
    tmp_listing=$(mktemp) || { echo "FAIL  could not create a temp file" >&2; return 1; }
    trap 'rm -f "$tmp_listing"' EXIT

    cat >"$tmp_listing" <<'LISTING'
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(*) Old USB LAN (disabled)
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(3) iPhone USB
(Hardware Port: iPhone USB, Device: en8)
LISTING

    networksetup() {
        case "$1" in
            -listnetworkserviceorder) cat "$FAKE_LISTING" ;;
            *) return 1 ;;
        esac
    }
    FAKE_LISTING="$tmp_listing"

    result=$(service_for_interface en7)
    if [ "$result" = "USB LAN" ]; then
        echo "PASS  [finding 11] service_for_interface returns the enabled service, skipping a disabled duplicate on the same Device"
    else
        echo "FAIL  [finding 11] service_for_interface en7 -> '$result' (expected 'USB LAN')"
        fail=1
    fi

    result=$(service_for_interface en0)
    if [ "$result" = "Wi-Fi" ]; then
        echo "PASS  [finding 11] service_for_interface still finds a normal (non-disabled-duplicate) service"
    else
        echo "FAIL  [finding 11] service_for_interface en0 -> '$result' (expected 'Wi-Fi')"
        fail=1
    fi

    result=$(service_for_interface en99)
    if [ -z "$result" ]; then
        echo "PASS  [finding 11] service_for_interface returns empty for an interface with no matching (enabled) service"
    else
        echo "FAIL  [finding 11] service_for_interface en99 -> '$result' (expected empty)"
        fail=1
    fi

    if same_set "1.1.1.1 1.0.0.1" "1.0.0.1 1.1.1.1"; then
        echo "PASS  [finding 12] same_set treats reordered lists as equal"
    else
        echo "FAIL  [finding 12] same_set treated reordered lists as different"
        fail=1
    fi
    if same_set "1.1.1.1 1.0.0.1" "1.1.1.1 8.8.8.8"; then
        echo "FAIL  [finding 12] same_set treated genuinely different lists as equal"
        fail=1
    else
        echo "PASS  [finding 12] same_set correctly rejects genuinely different lists"
    fi

    # Finding 16: log() must not leak the shell's own "cannot open"
    # diagnostic to stderr when LOG_FILE is unwritable -- only the intended
    # fallback line.
    f16_dir=$(mktemp -d) || { echo "FAIL  [finding 16] could not create a temp dir" >&2; fail=1; f16_dir=""; }
    if [ -n "$f16_dir" ]; then
        LOG_FILE="$f16_dir/does-not-exist/nested/unwritable.log"
        log_err=$(log "self-test message" 2>&1)
        if printf '%s' "$log_err" | grep -q "self-test message" && \
           ! printf '%s' "$log_err" | grep -qi "no such file\|cannot open\|: .*\.log:"; then
            echo "PASS  [finding 16] log() falls back to stderr without leaking a shell redirection error"
        else
            echo "FAIL  [finding 16] log() stderr: $log_err"
            fail=1
        fi
        rm -rf "$f16_dir"
    fi

    if servers_means_dhcp "dhcp" && servers_means_dhcp "DHCP" && servers_means_dhcp "Empty"; then
        echo "PASS  [dhcp] servers_means_dhcp accepts dhcp/DHCP/Empty"
    else
        echo "FAIL  [dhcp] servers_means_dhcp rejected a valid keyword"
        fail=1
    fi
    if servers_means_dhcp "1.1.1.1 1.0.0.1" || servers_means_dhcp "dhcp 1.1.1.1" || servers_means_dhcp ""; then
        echo "FAIL  [dhcp] servers_means_dhcp accepted a real server list (or an empty one)"
        fail=1
    else
        echo "PASS  [dhcp] servers_means_dhcp rejects real server lists and an empty value"
    fi

    st_dir=$(mktemp -d) || { echo "FAIL  [state] could not create a temp dir" >&2; fail=1; st_dir=""; }
    if [ -n "$st_dir" ]; then
        LOG_FILE="$st_dir/log"
        STATE_FILE="$st_dir/state"
        log_if_changed "service=Wi-Fi ok current=[]"
        log_if_changed "service=Wi-Fi ok current=[]"
        log_if_changed "service=Wi-Fi ok current=[1.1.1.1]"
        log_if_changed "service=Wi-Fi ok current=[1.1.1.1]"
        n=$(wc -l <"$LOG_FILE" | tr -d ' ')
        if [ "$n" = 2 ] && grep -q 'current=\[\]' "$LOG_FILE" && grep -q 'current=\[1.1.1.1\]' "$LOG_FILE"; then
            echo "PASS  [state] log_if_changed logs a repeated message once and a changed one again"
        else
            echo "FAIL  [state] log_if_changed wrote $n line(s), expected 2"
            fail=1
        fi
        rm -rf "$st_dir"
    fi

    if [ "$(killswitch_missing_dns "1.1.1.1 1.0.0.1" "10.0.0.53 10.0.1.53")" = "10.0.0.53 10.0.1.53" ] && \
       [ "$(killswitch_missing_dns "1.1.1.1 10.0.1.53 1.0.0.1" "10.0.0.53 10.0.1.53")" = "10.0.0.53" ] && \
       [ -z "$(killswitch_missing_dns "10.0.1.53 1.1.1.1 10.0.0.53" "10.0.0.53 10.0.1.53")" ] && \
       [ "$(killswitch_missing_dns "" "10.0.0.53")" = "10.0.0.53" ]; then
        echo "PASS  [killswitch] killswitch_missing_dns reports exactly the corporate servers absent from the pf table"
    else
        echo "FAIL  [killswitch] killswitch_missing_dns gave an unexpected result"
        fail=1
    fi

    if [ "$fail" = 0 ]; then
        echo "self-test: all cases PASS"
    else
        echo "self-test: at least one case FAILED" >&2
    fi
    return "$fail"
}

if [ "$SELF_TEST" = 1 ]; then
    run_self_test
    exit $?
fi

# Standalone mode: print the detected primary service name (the one DNS
# guard would act on) and exit 0. Reuses service_for_interface() (defined
# above this early-exit path, so there is exactly one copy). Exits 2 if no
# default interface/service can be found.
if [ "$PRINT_SERVICE" = 1 ]; then
    iface=$(route -n get default 2>/dev/null | sed -n 's/^[[:space:]]*interface: *//p' | head -1)
    if [ -z "$iface" ]; then
        echo "dns-guard: no default interface found" >&2
        exit 2
    fi
    service=$(service_for_interface "$iface")
    if [ -z "$service" ]; then
        echo "dns-guard: no network service found for interface $iface" >&2
        exit 2
    fi
    printf '%s\n' "$service"
    exit 0
fi

LOG_FILE="/var/log/comrades-tunnel-dns-guard.log"

# Strip comments/blank lines from a config file, one entry per output line.
read_lines() {
    sed -e 's/#.*$//' "$1" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$'
}

# Collapse a possibly multi-line / multi-space value into one space-joined,
# trimmed line.
normalize_list() {
    printf '%s\n' "$1" | tr '\n' ' ' | tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//'
}

# log() is defined above, before run_self_test -- see finding 16.

if [ -n "$CONFIG_DIR" ]; then
    # A relative --config is resolved against the CWD first (unchanged
    # behaviour), falling back to REPO_ROOT so it also works from any
    # other directory.
    CONFIG_DIR=$(resolve_config_dir "$REPO_ROOT" "$CONFIG_DIR")
    echo "Config dir: $CONFIG_DIR"
    DNS_GUARD_TXT="$CONFIG_DIR/dns-guard.txt"
    CORP_DNS_TXT="$CONFIG_DIR/corp-dns.txt"
    if [ ! -f "$DNS_GUARD_TXT" ]; then
        echo "ERROR: $DNS_GUARD_TXT not found" >&2
        exit 2
    fi
    if [ ! -f "$CORP_DNS_TXT" ]; then
        echo "ERROR: $CORP_DNS_TXT not found" >&2
        exit 2
    fi
    SERVERS=$(grep '^SERVERS=' "$DNS_GUARD_TXT" | tail -1 | cut -d= -f2-)
    MODE=$(grep '^MODE=' "$DNS_GUARD_TXT" | tail -1 | cut -d= -f2-)
    KILLSWITCH_DNS=$(grep '^KILLSWITCH_DNS=' "$DNS_GUARD_TXT" | tail -1 | cut -d= -f2-)
    CORP_DNS=$(normalize_list "$(read_lines "$CORP_DNS_TXT" | tr '\n' ' ')")
else
    if [ ! -f "$CONF_FILE" ]; then
        echo "ERROR: $CONF_FILE not found (use --config DIR to read a repo config dir instead)" >&2
        exit 2
    fi
    SERVERS=$(grep '^SERVERS=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    MODE=$(grep '^MODE=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    KILLSWITCH_DNS=$(grep '^KILLSWITCH_DNS=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    CORP_DNS=$(grep '^CORP_DNS=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
fi

SERVERS=$(normalize_list "$SERVERS")
MODE=$(normalize_list "$MODE")
CORP_DNS=$(normalize_list "$CORP_DNS")
KILLSWITCH_DNS=$(normalize_list "$KILLSWITCH_DNS")

if [ -z "$SERVERS" ]; then
    echo "ERROR: SERVERS not set" >&2
    exit 2
fi
# SERVERS=dhcp: the desired state is an EMPTY manual list (DNS back to the
# network's DHCP), spelled "Empty" for networksetup -setdnsservers.
RESET_TO_DHCP=0
if servers_means_dhcp "$SERVERS"; then
    RESET_TO_DHCP=1
    SERVERS="Empty"
fi
if [ -z "$MODE" ]; then
    MODE="corp-only"
fi
if [ "$MODE" != "corp-only" ] && [ "$MODE" != "always" ]; then
    echo "ERROR: MODE must be 'corp-only' or 'always', got '$MODE'" >&2
    exit 2
fi
if [ "$MODE" = "corp-only" ] && [ -z "$CORP_DNS" ]; then
    echo "ERROR: MODE=corp-only requires CORP_DNS to be set" >&2
    exit 2
fi
if [ -z "$KILLSWITCH_DNS" ]; then
    KILLSWITCH_DNS="auto"
fi
if [ "$KILLSWITCH_DNS" != "auto" ] && [ "$KILLSWITCH_DNS" != "off" ]; then
    echo "ERROR: KILLSWITCH_DNS must be 'auto' or 'off', got '$KILLSWITCH_DNS'" >&2
    exit 2
fi

default_interface() {
    route -n get default 2>/dev/null | sed -n 's/^[[:space:]]*interface: *//p' | head -1
}

# service_for_interface is defined above, before the --print-service
# early-exit -- see finding 11.

current_dns_list() {
    service=$1
    out=$(networksetup -getdnsservers "$service" 2>/dev/null || true)
    case "$out" in
        "There aren't any DNS Servers set on "*) printf '' ;;
        *) printf '%s' "$out" ;;
    esac
}

list_contains_any() {
    # $1 = space-separated haystack, $2 = space-separated needles
    for needle in $2; do
        for hay in $1; do
            if [ "$hay" = "$needle" ]; then
                return 0
            fi
        done
    done
    return 1
}

# Kill Switch first: independent of the DNS-list decision below, and the
# corporate resolvers are useless while port 53 to them is dropped.
ensure_killswitch_dns

IFACE=$(default_interface)
if [ -z "$IFACE" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (no primary interface found)"
    else
        log_if_changed "no primary interface found, nothing to do"
    fi
    finish
fi

SERVICE=$(service_for_interface "$IFACE")
if [ -z "$SERVICE" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (no network service found for interface $IFACE)"
    else
        log_if_changed "no network service found for interface $IFACE, nothing to do"
    fi
    finish
fi

CURRENT_LIST=$(normalize_list "$(current_dns_list "$SERVICE" | tr '\n' ' ')")

NEED_CHANGE=0
case "$MODE" in
    corp-only)
        if list_contains_any "$CURRENT_LIST" "$CORP_DNS"; then
            NEED_CHANGE=1
        fi
        ;;
    always)
        if [ "$RESET_TO_DHCP" = 1 ]; then
            # Desired state is "no manual list at all": any manual entry
            # is a deviation.
            [ -n "$CURRENT_LIST" ] && NEED_CHANGE=1
        elif ! same_set "$CURRENT_LIST" "$SERVERS"; then
            NEED_CHANGE=1
        fi
        ;;
esac

if [ "$NEED_CHANGE" = 1 ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: intervene (mode=$MODE) service=$SERVICE before=[$CURRENT_LIST]"
        if [ "$RESET_TO_DHCP" = 1 ]; then
            echo "would run: networksetup -setdnsservers \"$SERVICE\" Empty   (clear the manual list; DNS back to DHCP)"
        else
            echo "would run: networksetup -setdnsservers \"$SERVICE\" $SERVERS"
        fi
        echo "would run: dscacheutil -flushcache; killall -HUP mDNSResponder   (drop answers cached while the corporate VPN was down)"
        finish
    fi
    networksetup -setdnsservers "$SERVICE" $SERVERS
    rm -f "$STATE_FILE" 2>/dev/null || true
    flush_dns_cache
    AFTER_LIST=$(normalize_list "$(current_dns_list "$SERVICE" | tr '\n' ' ')")
    if [ "$RESET_TO_DHCP" = 1 ]; then
        converged=0
        [ -z "$AFTER_LIST" ] && converged=1
    elif same_set "$AFTER_LIST" "$SERVERS"; then
        converged=1
    else
        converged=0
    fi
    if [ "$MODE" = "always" ] && [ "$converged" = 0 ]; then
        # Re-read once after setting; if it still does not match, this is
        # not converging (some other process, or the OS itself, keeps
        # overriding it) -- log once and stop for this invocation instead
        # of rewriting on every tick (this runs on a 3s ThrottleInterval --
        # see the installer -- so "every tick" is every few seconds,
        # forever).
        log "WARNING: service=$SERVICE set SERVERS=[$SERVERS] but re-read shows [$AFTER_LIST] -- not converging; leaving it and exiting cleanly instead of rewriting every tick"
        finish
    fi
    if [ "$RESET_TO_DHCP" = 1 ]; then
        log "service=$SERVICE before=[$CURRENT_LIST] -> after=[${AFTER_LIST:-<dhcp>}] (manual list cleared, DNS back to DHCP; resolver cache flushed)"
    else
        log "service=$SERVICE before=[$CURRENT_LIST] -> after=[$AFTER_LIST] (resolver cache flushed)"
    fi
else
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (mode=$MODE) service=$SERVICE current=[$CURRENT_LIST]"
        finish
    fi
    log_if_changed "service=$SERVICE ok current=[$CURRENT_LIST]"
fi

finish
