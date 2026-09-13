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
        if ! same_set "$CURRENT_LIST" "$SERVERS"; then
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
    AFTER_LIST=$(normalize_list "$(current_dns_list "$SERVICE" | tr '\n' ' ')")
    if [ "$MODE" = "always" ] && ! same_set "$AFTER_LIST" "$SERVERS"; then
        # Re-read once after setting; if it still does not match, this is
        # not converging (some other process, or the OS itself, keeps
        # overriding it) -- log once and stop for this invocation instead
        # of rewriting on every tick (this runs on a 3s ThrottleInterval --
        # see the installer -- so "every tick" is every few seconds,
        # forever).
        log "WARNING: service=$SERVICE set SERVERS=[$SERVERS] but re-read shows [$AFTER_LIST] -- not converging; leaving it and exiting cleanly instead of rewriting every tick"
        exit 0
    fi
    log "service=$SERVICE before=[$CURRENT_LIST] -> after=[$AFTER_LIST]"
else
    if [ "$DRY_RUN" = 1 ]; then
        echo "decision: ok (mode=$MODE) service=$SERVICE current=[$CURRENT_LIST]"
        exit 0
    fi
    log "service=$SERVICE ok current=[$CURRENT_LIST]"
fi

exit 0
