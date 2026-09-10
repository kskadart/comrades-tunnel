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
#   SERVERS   space-separated desired DNS servers (e.g. "1.1.1.1 1.0.0.1")
#   MODE      "corp-only" -- intervene only when the current DNS list
#             contains a corporate DNS server; "always" -- enforce SERVERS
#             whenever the current list differs from it
#   CORP_DNS  space-separated corporate DNS servers (required for
#             MODE=corp-only, used to detect the corporate rewrite)
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
# Usage: dns-guard.sh [--config DIR] [--dry-run]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

CONFIG_DIR=""
CONF_FILE="$SCRIPT_DIR/dns-guard.conf"
DRY_RUN=0
PRINT_SERVICE=0

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
        *)
            echo "Usage: $0 [--config DIR] [--dry-run] [--print-service]" >&2
            exit 2
            ;;
    esac
done

# Standalone mode: print the detected primary service name (the one DNS guard
# would act on) and exit 0. This duplicates the interface -> service awk
# mapping from service_for_interface() below, because this early-exit path
# runs before that helper is defined; keep both copies in sync if the mapping
# ever changes. Exits 2 if no default interface/service can be found.
if [ "$PRINT_SERVICE" = 1 ]; then
    iface=$(route -n get default 2>/dev/null | sed -n 's/^[[:space:]]*interface: *//p' | head -1)
    if [ -z "$iface" ]; then
        echo "dns-guard: no default interface found" >&2
        exit 2
    fi
    service=$(networksetup -listnetworkserviceorder | awk -v want="Device: $iface)" '
        /^\([0-9]+\)/ { name = $0; sub(/^\([0-9]+\)[ \t]*/, "", name) }
        index($0, want) { print name; exit }
    ')
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

log() {
    ts=$(date '+%Y-%m-%dT%H:%M:%S%z')
    line="$ts $1"
    if ! printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null; then
        printf '%s\n' "$line" >&2
    fi
}

if [ -n "$CONFIG_DIR" ]; then
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
    CORP_DNS=$(normalize_list "$(read_lines "$CORP_DNS_TXT" | tr '\n' ' ')")
else
    if [ ! -f "$CONF_FILE" ]; then
        echo "ERROR: $CONF_FILE not found (use --config DIR to read a repo config dir instead)" >&2
        exit 2
    fi
    SERVERS=$(grep '^SERVERS=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    MODE=$(grep '^MODE=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    CORP_DNS=$(grep '^CORP_DNS=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
fi

SERVERS=$(normalize_list "$SERVERS")
MODE=$(normalize_list "$MODE")
CORP_DNS=$(normalize_list "$CORP_DNS")

if [ -z "$SERVERS" ]; then
    echo "ERROR: SERVERS not set" >&2
    exit 2
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

default_interface() {
    route -n get default 2>/dev/null | sed -n 's/^[[:space:]]*interface: *//p' | head -1
}

service_for_interface() {
    iface=$1
    networksetup -listnetworkserviceorder | awk -v want="Device: $iface)" '
        /^\([0-9]+\)/ { name = $0; sub(/^\([0-9]+\)[ \t]*/, "", name) }
        index($0, want) { print name; exit }
    '
}

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

IFACE=$(default_interface)
if [ -z "$IFACE" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (no primary interface found)"
    else
        log "no primary interface found, nothing to do"
    fi
    exit 0
fi

SERVICE=$(service_for_interface "$IFACE")
if [ -z "$SERVICE" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (no network service found for interface $IFACE)"
    else
        log "no network service found for interface $IFACE, nothing to do"
    fi
    exit 0
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
        if [ "$CURRENT_LIST" != "$SERVERS" ]; then
            NEED_CHANGE=1
        fi
        ;;
esac

if [ "$NEED_CHANGE" = 1 ]; then
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: intervene (mode=$MODE) service=$SERVICE before=[$CURRENT_LIST]"
        echo "would run: networksetup -setdnsservers \"$SERVICE\" $SERVERS"
        exit 0
    fi
    networksetup -setdnsservers "$SERVICE" $SERVERS
    log "service=$SERVICE before=[$CURRENT_LIST] -> after=[$SERVERS]"
else
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (mode=$MODE) service=$SERVICE current=[$CURRENT_LIST]"
        exit 0
    fi
    log "service=$SERVICE ok current=[$CURRENT_LIST]"
fi

exit 0
