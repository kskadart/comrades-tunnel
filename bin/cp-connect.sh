#!/bin/sh
# Get the corporate Check Point VPN connected quickly by shrinking the
# routing table for the few seconds it takes to connect, then restore the
# personal AmneziaVPN.
#
# Why: Check Point's client compares every route it is about to install
# against every route already in the table at connect time. With
# AmneziaVPN's site-based split tunnel (~2,200 routes) that comparison takes
# 2-5 minutes; with a small table it takes about a second (see README).
# pf-based policy routing (`route-to`) was investigated and does not affect
# locally-originated traffic on macOS -- see Apple Technical Note TN3165,
# "Packet Filter is not API" -- so the only lever left is sequencing.
#
# Four ways to shrink the table were researched (full writeup + source
# citations in README):
#   prompt  (default, never sudo) -- ask the human to click Disconnect/
#           Connect in the AmneziaVPN GUI. Zero risk: it is the same action
#           the human would take anyway, just sequenced and timed here.
#   routes  (sudo)  -- leave the AmneziaVPN app and its tunnel alone; delete
#           only the kernel routes that point at its utun, let Check Point
#           connect, then re-add them from a saved snapshot.
#   launchd (sudo)  -- bootout/bootstrap the AmneziaVPN-service LaunchDaemon.
#           Kept for completeness, but on this codebase's own research the
#           actual WireGuard data plane runs as a separate `wireguard-go`
#           child process with no evidence the service forwards a shutdown
#           signal to it, so bootout most likely leaves that child (and its
#           routes) running as an orphan -- this method is NOT expected to
#           reliably shrink the table. Treat it as experimental.
#   ipc     (not implemented live) -- AmneziaVPN's control socket speaks the
#           Qt Remote Objects binary replica/source protocol (see
#           ipc/ipc_interface.rep in amnezia-vpn/amnezia-client), not a line
#           protocol `nc`/a small script can drive, and it exposes no single
#           connect/disconnect call anyway. --dry-run explains this; the
#           live path refuses.
#
# Restoration is unconditional: a trap on EXIT/INT/TERM runs the restore
# path exactly once, so an interrupted script or a corporate-connect timeout
# still brings the personal VPN back. For --method routes the saved routes
# are written to a git-ignored file under build/ BEFORE anything is deleted,
# and the manual one-liner to restore from it is printed up front -- that
# file is data only (destination/gateway pairs), read back with `read` and
# passed to `route` as literal arguments, never sourced or eval'd, the same
# discipline dns-guard.sh uses for its own config files. The ancestor-chain
# safety check from install-dns-guard.sh (assert_safe_path) does not apply
# here: nothing this script writes is later executed as code by a
# privileged daemon, so there is no privilege-escalation path for a
# writable ancestor to exploit.
#
# --dry-run prints every step and every command it would run, touching
# nothing (including no `sudo -n true` check, so it always works whether or
# not the caller has cached sudo credentials).
#
# Usage: cp-connect.sh [--config DIR] [--method prompt|launchd|routes|ipc]
#                       [--dry-run] [--timeout N]

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

CONFIG_DIR="$REPO_ROOT/local"
METHOD="prompt"
DRY_RUN=0
TIMEOUT=60
CORP_TIMEOUT=300   # corporate-connect wait; not exposed as a flag, see header

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
        --method)
            METHOD=$2
            shift 2
            ;;
        --method=*)
            METHOD=${1#--method=}
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --timeout)
            TIMEOUT=$2
            shift 2
            ;;
        --timeout=*)
            TIMEOUT=${1#--timeout=}
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--method prompt|launchd|routes|ipc] [--dry-run] [--timeout N]" >&2
            exit 2
            ;;
    esac
done

case "$METHOD" in
    prompt|launchd|routes|ipc) ;;
    *)
        echo "ERROR: invalid --method '$METHOD' (expected prompt, launchd, routes, or ipc)" >&2
        exit 2
        ;;
esac

case "$TIMEOUT" in
    ''|*[!0-9]*)
        echo "ERROR: --timeout must be a positive integer, got '$TIMEOUT'" >&2
        exit 2
        ;;
esac

TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
if [ ! -f "$TUNNELS_FILE" ]; then
    echo "ERROR: $TUNNELS_FILE not found (see config/example/tunnels.txt)" >&2
    exit 2
fi

# get_tunnel_prefix KEY -- return the VALUE of "KEY=" in tunnels.txt. Same
# grep/cut parsing as bin/check-split.sh; never sourced/eval'd.
get_tunnel_prefix() {
    key=$1
    grep "^${key}=" "$TUNNELS_FILE" 2>/dev/null | head -1 | cut -d= -f2-
}

CORP_TUNNEL_PREFIX=$(get_tunnel_prefix CORP_TUNNEL_PREFIX)
PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)

if [ -z "$CORP_TUNNEL_PREFIX" ] || [ -z "$PERSONAL_TUNNEL_PREFIX" ]; then
    echo "ERROR: CORP_TUNNEL_PREFIX / PERSONAL_TUNNEL_PREFIX not set in $TUNNELS_FILE" >&2
    exit 2
fi

BUILD_DIR="$REPO_ROOT/build"
SAVED_ROUTES_FILE="$BUILD_DIR/cp-connect-saved-routes.txt"
AMNEZIA_SERVICE_LABEL="AmneziaVPN-service"
AMNEZIA_PLIST="/Library/LaunchDaemons/AmneziaVPN.plist"

# --- utun / route inspection (read-only, always safe to run for real) ---

# detect_utun_by_prefix PREFIX -- print the first utunN whose inet address
# starts with PREFIX, never hardcoding a specific utun number. Same pattern
# as bin/check-split.sh.
detect_utun_by_prefix() {
    prefix=$1
    for iface in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun'); do
        ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}')
        case "$ip" in
            "${prefix}"*) echo "$iface"; return 0 ;;
        esac
    done
    return 1
}

list_utuns() {
    found=0
    for iface in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun'); do
        ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}')
        printf '  %-8s inet %s\n' "$iface" "${ip:-<no inet>}"
        found=1
    done
    [ "$found" = 0 ] && echo "  (no utun interfaces)"
}

# Total route count exactly as `netstat -rn -f inet | wc -l` -- matches the
# metric used to verify nothing changed, so before/during/after are directly
# comparable to that command.
route_count() {
    netstat -rn -f inet 2>/dev/null | wc -l | tr -d ' '
}

# wait_for_utun_gone PREFIX BOUND -- poll every 2s, up to BOUND seconds, for
# no utun with an inet address starting PREFIX to remain.
wait_for_utun_gone() {
    prefix=$1
    bound=$2
    if [ "$DRY_RUN" = 1 ]; then
        echo "  (dry-run: would poll every 2s, up to ${bound}s, for no utun with inet ${prefix}* to remain)"
        return 0
    fi
    start=$(date +%s)
    while detect_utun_by_prefix "$prefix" >/dev/null 2>&1; do
        now=$(date +%s)
        elapsed=$((now - start))
        if [ "$elapsed" -ge "$bound" ]; then
            echo "  TIMEOUT after ${elapsed}s waiting for the personal VPN interface to disappear."
            return 1
        fi
        sleep 2
    done
    now=$(date +%s)
    echo "  personal VPN interface gone after $((now - start))s."
    return 0
}

# wait_for_utun_present PREFIX BOUND LABEL -- poll every 2s, up to BOUND
# seconds, for a utun with an inet address starting PREFIX to appear.
wait_for_utun_present() {
    prefix=$1
    bound=$2
    label=$3
    if [ "$DRY_RUN" = 1 ]; then
        echo "  (dry-run: would poll every 2s, up to ${bound}s, for a utun with inet ${prefix}* to appear)"
        return 0
    fi
    start=$(date +%s)
    while ! detect_utun_by_prefix "$prefix" >/dev/null 2>&1; do
        now=$(date +%s)
        elapsed=$((now - start))
        if [ "$elapsed" -ge "$bound" ]; then
            echo "  TIMEOUT after ${elapsed}s waiting for $label to appear."
            return 1
        fi
        sleep 2
    done
    now=$(date +%s)
    echo "  $label appeared after $((now - start))s."
    return 0
}

# --- method: prompt (default, never sudo) ---

prompt_down() {
    echo "ACTION NEEDED: disconnect AmneziaVPN now (menu bar icon -> Disconnect)."
}

prompt_up() {
    echo "ACTION NEEDED: reconnect AmneziaVPN now (menu bar icon -> Connect)."
}

# --- method: routes (sudo) ---

# save_amnezia_routes IFACE -- write "destination gateway" pairs for every
# route whose Netif is IFACE to SAVED_ROUTES_FILE, in the exact compact
# notation netstat/route already share (e.g. "5.32/13"), which round-trips
# straight back into `route add/delete -net`.
save_amnezia_routes() {
    iface=$1
    mkdir -p "$BUILD_DIR"
    netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1, $2}' >"$SAVED_ROUTES_FILE"
}

# delete_amnezia_routes IFACE -- delete every route currently pointing at
# IFACE. In --dry-run, SAVED_ROUTES_FILE does not exist yet (nothing is
# written to disk in dry-run), so the preview is computed straight from the
# live table instead; in a real run it reads SAVED_ROUTES_FILE (already
# written by save_amnezia_routes) with `read`, never sourcing/eval'ing it --
# fields are passed to `route` as literal, quoted arguments only.
delete_amnezia_routes() {
    iface=$1
    if [ "$DRY_RUN" = 1 ]; then
        netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1}' |
        while read -r dest; do
            [ "$dest" = "default" ] && continue   # never touch the default route
            echo "  would run: sudo route -n -q delete -net \"$dest\""
        done
        return 0
    fi
    while read -r dest _gw; do
        [ -z "$dest" ] && continue
        [ "$dest" = "default" ] && continue   # never touch the default route
        sudo route -n -q delete -net "$dest" >/dev/null 2>&1 || true
    done <"$SAVED_ROUTES_FILE"
}

# restore_saved_routes -- re-add every route from SAVED_ROUTES_FILE. A
# gateway that is itself a utunN name means the original route was an
# interface route (point-to-point tunnel, no separate gateway IP); anything
# else is added with that literal gateway, matching how AmneziaVPN's own
# router_mac.cpp calls `route add -net <ip> <gw> <mask>`. In --dry-run,
# SAVED_ROUTES_FILE was never written (nothing is written to disk in
# dry-run), so the preview is computed from the live table for the personal
# utun detected at startup instead.
restore_saved_routes() {
    if [ "$DRY_RUN" = 1 ]; then
        if [ -z "$AMNEZIA_UTUN_START" ]; then
            echo "  (dry-run: no personal-VPN utun currently present to preview restore commands for)"
            return 0
        fi
        netstat -rn -f inet 2>/dev/null | awk -v i="$AMNEZIA_UTUN_START" '$NF==i {print $1, $2}' |
        while read -r dest gw; do
            case "$gw" in
                utun*) echo "  would run: sudo route -n -q add -net \"$dest\" -interface \"$gw\"" ;;
                *) echo "  would run: sudo route -n -q add -net \"$dest\" \"$gw\"" ;;
            esac
        done
        return 0
    fi
    if [ ! -f "$SAVED_ROUTES_FILE" ]; then
        echo "  (no saved-routes file at $SAVED_ROUTES_FILE, nothing to restore)"
        return 0
    fi
    while read -r dest gw; do
        [ -z "$dest" ] && continue
        case "$gw" in
            utun*) sudo route -n -q add -net "$dest" -interface "$gw" >/dev/null 2>&1 || true ;;
            *) sudo route -n -q add -net "$dest" "$gw" >/dev/null 2>&1 || true ;;
        esac
    done <"$SAVED_ROUTES_FILE"
}

# --- method: launchd (sudo) ---

launchd_down() {
    echo "About to run: sudo launchctl bootout system/$AMNEZIA_SERVICE_LABEL"
    echo "NOTE (see README): the WireGuard data plane runs as a separate wireguard-go"
    echo "child process of this service; bootout may not tear it down, so this method"
    echo "is not expected to reliably shrink the route table. Prefer --method routes"
    echo "or --method prompt."
    [ "$DRY_RUN" = 1 ] && return 0
    sudo launchctl bootout "system/$AMNEZIA_SERVICE_LABEL" 2>/dev/null || true
}

launchd_up() {
    echo "About to run: sudo launchctl bootstrap system $AMNEZIA_PLIST"
    [ "$DRY_RUN" = 1 ] && return 0
    sudo launchctl bootstrap system "$AMNEZIA_PLIST" 2>/dev/null || true
    echo "NOTE: this only restarts the privileged helper. If the personal VPN tunnel"
    echo "did not come back on its own, open AmneziaVPN and click Connect."
}

# --- method: ipc (not implemented live) ---

ipc_explain() {
    cat <<'EOF'
--method ipc is not implemented for live use.

Research finding (see README for full citations): AmneziaVPN's control
socket (/private/tmp/local:AmneziaVpnIpcInterface, and the launchd
socket-activated 127.0.0.1:5959 listener that starts the same
AmneziaVPN-service binary) speaks the Qt Remote Objects binary
replica/source protocol (ipc/ipc_interface.rep in amnezia-vpn/amnezia-
client), not a line protocol a shell/nc/python script can drive. The
interface it exposes is also a set of low-level privileged primitives
(createTun, routeAddList/routeDeleteList, enableKillSwitch, ...) with no
single connect/disconnect call -- the actual connect/disconnect sequencing
lives in the GUI app. Use --method prompt (default), --method routes, or
--method launchd instead.
EOF
}

ipc_down() {
    ipc_explain
    if [ "$DRY_RUN" = 1 ]; then
        echo "(dry-run: nothing would be sent to the socket)"
        return 0
    fi
    exit 1
}

echo "=== cp-connect: shrink the routing table while the corporate VPN connects ==="
echo "Config dir: $CONFIG_DIR"
echo "Method: $METHOD"
[ "$DRY_RUN" = 1 ] && echo "Mode: --dry-run (no changes will be made)"
echo "Personal-VPN wait timeout: ${TIMEOUT}s   Corporate-VPN wait timeout: ${CORP_TIMEOUT}s (fixed)"
echo

if [ "$METHOD" = "routes" ]; then
    echo "If this script is interrupted after routes are deleted, restore them by hand with:"
    echo "  while read -r dest gw; do case \"\$gw\" in utun*) sudo route -n -q add -net \"\$dest\" -interface \"\$gw\";; *) sudo route -n -q add -net \"\$dest\" \"\$gw\";; esac; done < $SAVED_ROUTES_FILE"
    echo
fi

if [ "$METHOD" = "launchd" ] || [ "$METHOD" = "routes" ]; then
    echo "NOTE: --method $METHOD requires sudo (route/launchctl commands need root)."
    if [ "$DRY_RUN" = 1 ]; then
        echo "  (dry-run: would check 'sudo -n true' here and refuse to continue without it)"
    else
        if ! sudo -n true 2>/dev/null; then
            echo "ERROR: no cached sudo credentials for --method $METHOD." >&2
            echo "Re-run as: sudo sh $0 --method $METHOD [other flags]" >&2
            exit 1
        fi
    fi
    echo
fi

echo "--- starting state ---"
echo "utuns:"
list_utuns
BEFORE_TOTAL=$(route_count)
echo "total routes (netstat -rn -f inet | wc -l): $BEFORE_TOTAL"
echo

AMNEZIA_UTUN_START=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")

RESTORE_DONE=0
# Restore the personal VPN exactly once, no matter how the script ends: a
# normal finish calls this explicitly (see bottom), and the EXIT/INT/TERM
# trap below is the backstop for a corporate-connect timeout, a Ctrl-C, or
# any early `exit` -- the RESTORE_DONE guard keeps a double invocation (the
# explicit call, then the EXIT trap firing anyway) a harmless no-op.
restore_personal_vpn() {
    [ "$RESTORE_DONE" = 1 ] && return 0
    RESTORE_DONE=1
    echo
    echo "--- restoring the personal VPN (method=$METHOD) ---"
    case "$METHOD" in
        prompt)
            prompt_up
            [ "$DRY_RUN" = 1 ] || wait_for_utun_present "$PERSONAL_TUNNEL_PREFIX" "$TIMEOUT" "the personal VPN interface"
            ;;
        routes)
            restore_saved_routes
            ;;
        launchd)
            launchd_up
            [ "$DRY_RUN" = 1 ] || wait_for_utun_present "$PERSONAL_TUNNEL_PREFIX" "$TIMEOUT" "the personal VPN interface"
            ;;
        ipc)
            : # ipc_down always refuses before anything is torn down
            ;;
    esac
}
trap 'restore_personal_vpn' EXIT
trap 'restore_personal_vpn; exit 130' INT
trap 'restore_personal_vpn; exit 143' TERM

echo "--- bringing the personal VPN down (method=$METHOD) ---"
case "$METHOD" in
    prompt)
        prompt_down
        ;;
    routes)
        if [ -z "$AMNEZIA_UTUN_START" ]; then
            echo "ERROR: no utun found with inet prefix $PERSONAL_TUNNEL_PREFIX; is AmneziaVPN connected?" >&2
            exit 1
        fi
        echo "About to save routes for $AMNEZIA_UTUN_START to $SAVED_ROUTES_FILE, then delete them."
        if [ "$DRY_RUN" = 1 ]; then
            echo "  would run: mkdir -p $BUILD_DIR"
            echo "  would run: netstat -rn -f inet | awk '\$NF==\"$AMNEZIA_UTUN_START\" {print \$1, \$2}' > $SAVED_ROUTES_FILE"
        else
            save_amnezia_routes "$AMNEZIA_UTUN_START"
            echo "Saved $(wc -l <"$SAVED_ROUTES_FILE" | tr -d ' ') routes to $SAVED_ROUTES_FILE."
        fi
        delete_amnezia_routes "$AMNEZIA_UTUN_START"
        ;;
    launchd)
        launchd_down
        ;;
    ipc)
        ipc_down
        ;;
esac

# routes never removes the utun itself (only its routes), and ipc_down
# never touches the personal VPN at all (it explains itself and, live,
# refuses) -- only prompt/launchd actually take the tunnel down, so only
# they have anything to wait for here.
if [ "$METHOD" = "prompt" ] || [ "$METHOD" = "launchd" ]; then
    wait_for_utun_gone "$PERSONAL_TUNNEL_PREFIX" "$TIMEOUT"
fi

DURING_TOTAL=$(route_count)
echo
echo "--- corporate VPN connect ---"
echo "total routes (netstat -rn -f inet | wc -l) now: $DURING_TOTAL"
echo "ACTION NEEDED: connect the corporate Check Point VPN now."
echo "Waiting up to ${CORP_TIMEOUT}s for a utun with inet ${CORP_TUNNEL_PREFIX}* to appear..."
CONNECT_START=$(date +%s)
wait_for_utun_present "$CORP_TUNNEL_PREFIX" "$CORP_TIMEOUT" "the corporate VPN interface"
CONNECT_RESULT=$?
CONNECT_ELAPSED=$(( $(date +%s) - CONNECT_START ))
if [ "$DRY_RUN" = 1 ]; then
    CONNECT_ELAPSED="n/a"
elif [ "$CONNECT_RESULT" = 0 ]; then
    echo "Corporate VPN connected in ${CONNECT_ELAPSED}s."
else
    echo "Corporate VPN did not connect within ${CORP_TIMEOUT}s; restoring the personal VPN anyway."
fi

restore_personal_vpn
AFTER_TOTAL=$(route_count)

echo
echo "--- summary ---"
printf '  %-8s %s\n' "phase" "total routes (netstat -rn -f inet | wc -l)"
printf '  %-8s %s\n' "before" "$BEFORE_TOTAL"
printf '  %-8s %s\n' "during" "$DURING_TOTAL"
printf '  %-8s %s\n' "after" "$AFTER_TOTAL"
echo
echo "Corporate VPN connect time: ${CONNECT_ELAPSED}s"

exit 0
