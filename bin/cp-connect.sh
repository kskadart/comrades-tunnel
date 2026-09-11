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
# --method routes additionally: counts route add/delete successes and
# failures instead of silently swallowing them (a failed restore prints a
# prominent warning and the manual one-liner again, and makes the script
# exit non-zero even if everything else finished); verifies after restore
# that the route count on the personal VPN's utun matches what was saved,
# and says plainly if that utun is not even present rather than reporting a
# confusing count mismatch; and normalises netstat's compact destination
# notation (e.g. "5.32/13", or a bare "1" for 1.0.0.0/8) to an explicit
# a.b.c.d/len form before it is saved or replayed through `route`, since the
# bare form is genuinely ambiguous. `--self-test` exercises that
# normalisation against a fixed table of inputs/outputs.
#
# The corporate-VPN wait does not rely on CORP_TUNNEL_PREFIX alone: Check
# Point assigns its Office Mode address dynamically (the third octet has
# been observed to change every session), so any utun that gains an inet
# address during the wait and is not the personal VPN's utun is also
# treated as the corporate VPN coming up, with a note suggesting a broader
# prefix, and a timeout dumps the current utun list instead of failing
# silently. If the corporate VPN already looks connected at startup, the
# script refuses to proceed (nothing is touched) rather than report a
# meaningless near-instant connect time; --force overrides this and the
# summary then reports the connect time as n/a instead of a bogus number.
#
# --dry-run prints every step and every command it would run, touching
# nothing (including no `sudo -n true` check, so it always works whether or
# not the caller has cached sudo credentials).
#
# Usage: cp-connect.sh [--config DIR] [--method prompt|launchd|routes|ipc]
#                       [--dry-run] [--timeout N] [--force] [--self-test]

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
ORIG_CMDLINE="$0 $*"

CONFIG_DIR="$REPO_ROOT/local"
METHOD="prompt"
DRY_RUN=0
FORCE=0
TIMEOUT=60
CORP_TIMEOUT=300   # corporate-connect wait; not exposed as a flag, see header
SELF_TEST=0
RESTORE_HAD_FAILURES=0    # set by restore_saved_routes on any failed route add
RESTORE_VERIFY_FAILED=0   # set by verify_restore on a post-restore mismatch
CONNECT_TIMED_OUT=0       # set when the corporate-VPN wait times out
CORP_ALREADY_PRESENT=""   # "iface ip" if the corporate VPN was already up at startup

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
        --force)
            FORCE=1
            shift
            ;;
        --self-test)
            SELF_TEST=1
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
            echo "Usage: $0 [--config DIR] [--method prompt|launchd|routes|ipc] [--dry-run] [--timeout N] [--force] [--self-test]" >&2
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

# normalize_dest DEST -- expand netstat's compact "destination" notation
# into an explicit, unambiguous a.b.c.d/len (or unchanged host/"default")
# before it is written to SAVED_ROUTES_FILE or fed to `route add/delete
# -net`. netstat -rn -f inet prints a network destination with trailing
# zero octets dropped and, when the mask differs from the classful default
# for that network, an explicit "/len" suffix (e.g. "5.32/13" for
# 5.32.0.0/13); when the mask happens to equal the classful default it
# drops the slash entirely too (e.g. a bare "1" for the class-A network
# 1.0.0.0/8) -- that bare form is genuinely ambiguous if handed back to
# `route` as-is, which is what this normalises. Already-explicit
# a.b.c.d/len values, plain host addresses, and "default" pass through
# unchanged.
normalize_dest() {
    dest=$1
    case "$dest" in
        default)
            echo "$dest"
            ;;
        */*)
            addr=${dest%/*}
            plen=${dest#*/}
            oldifs=$IFS
            IFS=.
            set -- $addr
            IFS=$oldifs
            printf '%s.%s.%s.%s/%s\n' "${1:-0}" "${2:-0}" "${3:-0}" "${4:-0}" "$plen"
            ;;
        *.*)
            echo "$dest"
            ;;
        *)
            echo "${dest}.0.0.0/8"
            ;;
    esac
}

# --self-test: exercise normalize_dest against a fixed table of
# inputs/expected outputs, independent of any config directory.
run_self_test() {
    fail=0
    test_case() {
        actual=$(normalize_dest "$1")
        if [ "$actual" = "$2" ]; then
            echo "PASS  normalize_dest '$1' -> '$actual'"
        else
            echo "FAIL  normalize_dest '$1' -> '$actual' (expected '$2')"
            fail=1
        fi
    }
    test_case "1" "1.0.0.0/8"
    test_case "5.32/13" "5.32.0.0/13"
    test_case "128.204.80/20" "128.204.80.0/20"
    test_case "10.8.1.1" "10.8.1.1"
    test_case "1.1.1.1/32" "1.1.1.1/32"
    test_case "default" "default"
    test_case "172.16/12" "172.16.0.0/12"
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

# utuns_with_inet -- print, one per line, every utunN that currently has an
# inet address (used to snapshot "already up before we started" interfaces
# for the corporate-VPN wait, see wait_for_corp_utun/detect_corp_present).
utuns_with_inet() {
    for iface in $(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun'); do
        ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}')
        [ -n "$ip" ] && echo "$iface"
    done
}

# detect_corp_present -- one-shot (non-polling) check for whether a
# corporate-VPN utun is already up right now: the same rule
# wait_for_corp_utun polls for, minus the "new since startup" part (there is
# no "since startup" yet -- this runs at startup, before any wait). Echoes
# "iface ip" and returns 0 on a hit, prints nothing and returns 1 otherwise.
detect_corp_present() {
    hit=$(detect_utun_by_prefix "$CORP_TUNNEL_PREFIX")
    if [ -n "$hit" ]; then
        echo "$hit $(ifconfig "$hit" 2>/dev/null | awk '/inet /{print $2}')"
        return 0
    fi
    personal_now=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
    for iface in $(utuns_with_inet); do
        [ "$iface" = "$personal_now" ] && continue
        echo "$iface $(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}')"
        return 0
    done
    return 1
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

# wait_for_corp_utun BOUND -- poll every 2s, up to BOUND seconds, for the
# corporate VPN's utun to appear. Check Point assigns its Office Mode
# address dynamically (the third octet has been observed to change every
# session), so a fixed CORP_TUNNEL_PREFIX is brittle on its own: treat as
# "the corporate VPN came up" either (i) a utun matching CORP_TUNNEL_PREFIX,
# or (ii) any utun that gained an inet address since STARTUP_UTUNS was
# captured and is not the personal VPN's utun. On (ii) it names the
# interface and address actually seen and suggests a broader prefix. On
# timeout it dumps the current utun list instead of failing silently.
wait_for_corp_utun() {
    bound=$1
    if [ "$DRY_RUN" = 1 ]; then
        echo "  (dry-run: would poll every 2s, up to ${bound}s, for a utun matching ${CORP_TUNNEL_PREFIX}*, or any new non-personal utun that gains an inet address)"
        echo "  (dry-run: a timeout would instead print the full utun list, the configured prefix, and a note that Check Point's address is dynamic -- for example, right now:)"
        list_utuns
        echo "    configured CORP_TUNNEL_PREFIX: $CORP_TUNNEL_PREFIX"
        return 0
    fi
    start=$(date +%s)
    while :; do
        hit=$(detect_utun_by_prefix "$CORP_TUNNEL_PREFIX")
        if [ -n "$hit" ]; then
            now=$(date +%s)
            echo "  corporate VPN interface $hit appeared after $((now - start))s (matched CORP_TUNNEL_PREFIX)."
            return 0
        fi
        personal_now=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
        for iface in $(utuns_with_inet); do
            case " $STARTUP_UTUNS " in
                *" $iface "*) continue ;;   # already up before we started
            esac
            [ "$iface" = "$personal_now" ] && continue   # that's the personal VPN, not corporate
            ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2}')
            now=$(date +%s)
            echo "  corporate VPN interface $iface appeared after $((now - start))s with address $ip (did not match CORP_TUNNEL_PREFIX '$CORP_TUNNEL_PREFIX')."
            suggested="$(echo "$ip" | cut -d. -f1-2)."
            echo "  NOTE: CORP_TUNNEL_PREFIX in tunnels.txt does not match this address; consider broadening it to '$suggested'."
            return 0
        done
        now=$(date +%s)
        elapsed=$((now - start))
        if [ "$elapsed" -ge "$bound" ]; then
            echo "  TIMEOUT after ${elapsed}s waiting for the corporate VPN interface to appear."
            echo "  current utun interfaces:"
            list_utuns
            echo "  configured CORP_TUNNEL_PREFIX: $CORP_TUNNEL_PREFIX"
            echo "  Check Point's Office Mode address is assigned dynamically and can differ every session -- if the corporate VPN did connect, this prefix probably just does not match it; broaden CORP_TUNNEL_PREFIX in tunnels.txt (see the interfaces above)."
            return 1
        fi
        sleep 2
    done
}

# --- method: prompt (default, never sudo) ---

prompt_down() {
    echo "ACTION NEEDED: disconnect AmneziaVPN now (menu bar icon -> Disconnect)."
}

prompt_up() {
    echo "ACTION NEEDED: reconnect AmneziaVPN now (menu bar icon -> Connect)."
}

# --- method: routes (sudo) ---

# manual_restore_hint -- print the one-liner that restores SAVED_ROUTES_FILE
# by hand. Printed up front (before anything is deleted) and reprinted by
# restore_saved_routes/verify_restore on any failure, so it must stay a
# single source of truth for that command.
manual_restore_hint() {
    echo "  while read -r dest gw; do case \"\$gw\" in utun*) sudo route -n -q add -net \"\$dest\" -interface \"\$gw\";; *) sudo route -n -q add -net \"\$dest\" \"\$gw\";; esac; done < $SAVED_ROUTES_FILE"
}

# save_amnezia_routes IFACE -- write "destination gateway" pairs for every
# route whose Netif is IFACE to SAVED_ROUTES_FILE, normalising each
# destination out of netstat's compact notation (see normalize_dest) so the
# file on disk -- and the manual one-liner printed from it -- are
# unambiguous.
save_amnezia_routes() {
    iface=$1
    mkdir -p "$BUILD_DIR"
    : >"$SAVED_ROUTES_FILE"
    netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1, $2}' |
    while read -r dest gw; do
        [ -z "$dest" ] && continue
        ndest=$(normalize_dest "$dest")
        echo "$ndest $gw" >>"$SAVED_ROUTES_FILE"
    done
}

# delete_amnezia_routes IFACE -- delete every route currently pointing at
# IFACE, counting successes/failures instead of silencing them (the first
# few failures, with their stderr, are shown; the rest are just counted so a
# systematic failure does not flood the terminal). In --dry-run,
# SAVED_ROUTES_FILE does not exist yet (nothing is written to disk in
# dry-run), so the preview is computed straight from the live table instead;
# in a real run it reads SAVED_ROUTES_FILE (already written by
# save_amnezia_routes, already normalised) with `read`, never sourcing/
# eval'ing it -- fields are passed to `route` as literal, quoted arguments
# only.
delete_amnezia_routes() {
    iface=$1
    if [ "$DRY_RUN" = 1 ]; then
        netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1}' |
        while read -r dest; do
            [ "$dest" = "default" ] && continue   # never touch the default route
            ndest=$(normalize_dest "$dest")
            echo "  would run: sudo route -n -q delete -net \"$ndest\""
        done
        return 0
    fi
    del_ok=0
    del_fail=0
    del_fail_detail=""
    fail_cap=10
    while read -r dest _gw; do
        [ -z "$dest" ] && continue
        [ "$dest" = "default" ] && continue   # never touch the default route
        err=$(sudo route -n -q delete -net "$dest" 2>&1 >/dev/null)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            del_ok=$((del_ok + 1))
        else
            del_fail=$((del_fail + 1))
            if [ "$del_fail" -le "$fail_cap" ]; then
                del_fail_detail="${del_fail_detail}    sudo route -n -q delete -net \"$dest\"  ->  ${err:-(no output, exit $rc)}\n"
            fi
        fi
    done <"$SAVED_ROUTES_FILE"
    echo "Deleted routes from $iface: $del_ok succeeded, $del_fail failed."
    if [ "$del_fail" -gt 0 ]; then
        printf '%b' "$del_fail_detail"
        [ "$del_fail" -gt "$fail_cap" ] && echo "  (showing first $fail_cap of $del_fail failures)"
    fi
}

# restore_saved_routes -- re-add every route from SAVED_ROUTES_FILE,
# counting successes/failures the same way delete_amnezia_routes does. A
# gateway that is itself a utunN name means the original route was an
# interface route (point-to-point tunnel, no separate gateway IP); anything
# else is added with that literal gateway, matching how AmneziaVPN's own
# router_mac.cpp calls `route add -net <ip> <gw> <mask>`. Any failure prints
# a prominent warning naming SAVED_ROUTES_FILE and the manual one-liner
# again, and sets RESTORE_HAD_FAILURES so the script exits non-zero even if
# everything else finished. In --dry-run, SAVED_ROUTES_FILE was never
# written (nothing is written to disk in dry-run), so the preview is
# computed from the live table for the personal utun detected at startup
# instead.
restore_saved_routes() {
    if [ "$DRY_RUN" = 1 ]; then
        if [ -z "$AMNEZIA_UTUN_START" ]; then
            echo "  (dry-run: no personal-VPN utun currently present to preview restore commands for)"
            return 0
        fi
        netstat -rn -f inet 2>/dev/null | awk -v i="$AMNEZIA_UTUN_START" '$NF==i {print $1, $2}' |
        while read -r dest gw; do
            ndest=$(normalize_dest "$dest")
            case "$gw" in
                utun*) echo "  would run: sudo route -n -q add -net \"$ndest\" -interface \"$gw\"" ;;
                *) echo "  would run: sudo route -n -q add -net \"$ndest\" \"$gw\"" ;;
            esac
        done
        return 0
    fi
    if [ ! -f "$SAVED_ROUTES_FILE" ]; then
        echo "  (no saved-routes file at $SAVED_ROUTES_FILE, nothing to restore)"
        return 0
    fi
    restore_ok=0
    restore_fail=0
    restore_fail_detail=""
    fail_cap=10
    while read -r dest gw; do
        [ -z "$dest" ] && continue
        case "$gw" in
            utun*)
                cmd="sudo route -n -q add -net \"$dest\" -interface \"$gw\""
                err=$(sudo route -n -q add -net "$dest" -interface "$gw" 2>&1 >/dev/null)
                ;;
            *)
                cmd="sudo route -n -q add -net \"$dest\" \"$gw\""
                err=$(sudo route -n -q add -net "$dest" "$gw" 2>&1 >/dev/null)
                ;;
        esac
        rc=$?
        if [ "$rc" -eq 0 ]; then
            restore_ok=$((restore_ok + 1))
        else
            restore_fail=$((restore_fail + 1))
            if [ "$restore_fail" -le "$fail_cap" ]; then
                restore_fail_detail="${restore_fail_detail}    $cmd  ->  ${err:-(no output, exit $rc)}\n"
            fi
        fi
    done <"$SAVED_ROUTES_FILE"
    echo "Restored routes: $restore_ok succeeded, $restore_fail failed (of $((restore_ok + restore_fail)) saved)."
    if [ "$restore_fail" -gt 0 ]; then
        printf '%b' "$restore_fail_detail"
        [ "$restore_fail" -gt "$fail_cap" ] && echo "  (showing first $fail_cap of $restore_fail failures)"
        echo
        echo "WARNING: $restore_fail route(s) failed to restore; the personal VPN's routing may be incomplete."
        echo "Saved routes are in $SAVED_ROUTES_FILE -- to retry by hand:"
        manual_restore_hint
        RESTORE_HAD_FAILURES=1
    fi
}

# verify_restore -- after restore_saved_routes, confirm the personal VPN's
# route count actually came back to what was saved. Reports loudly (with
# both numbers) and marks the run failed on a mismatch; separately reports
# the personal-VPN utun being altogether absent, since that is not a
# route-count problem and would only confuse if reported as one.
verify_restore() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ ! -f "$SAVED_ROUTES_FILE" ] && return 0   # nothing was saved this run
    saved_count=$(wc -l <"$SAVED_ROUTES_FILE" | tr -d ' ')
    utun_now=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
    if [ -z "$utun_now" ]; then
        echo
        echo "ERROR: the personal VPN interface (prefix $PERSONAL_TUNNEL_PREFIX) is not present after restore -- cannot verify the $saved_count saved routes came back." >&2
        echo "Reconnect AmneziaVPN, then check its routes once it is back." >&2
        echo "Saved routes are in $SAVED_ROUTES_FILE -- to restore by hand once the tunnel is back:" >&2
        manual_restore_hint >&2
        RESTORE_VERIFY_FAILED=1
        return 1
    fi
    now_count=$(netstat -rn -f inet 2>/dev/null | awk -v i="$utun_now" '$NF==i' | wc -l | tr -d ' ')
    if [ "$now_count" != "$saved_count" ]; then
        echo
        echo "ERROR: route count mismatch after restore: saved $saved_count, now $now_count routes point at $utun_now." >&2
        echo "Saved routes are in $SAVED_ROUTES_FILE -- to restore by hand:" >&2
        manual_restore_hint >&2
        RESTORE_VERIFY_FAILED=1
        return 1
    fi
    echo "Verified: $now_count/$saved_count routes are back on $utun_now."
    return 0
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
[ "$FORCE" = 1 ] && echo "Mode: --force (the already-connected refusal below, if it applies, is a warning instead)"
echo "Personal-VPN wait timeout: ${TIMEOUT}s   Corporate-VPN wait timeout: ${CORP_TIMEOUT}s (fixed)"
echo

echo "--- starting state ---"
echo "utuns:"
list_utuns
BEFORE_TOTAL=$(route_count)
echo "total routes (netstat -rn -f inet | wc -l): $BEFORE_TOTAL"
STARTUP_UTUNS=$(utuns_with_inet | tr '\n' ' ')
echo "utuns with an inet address already up at startup (excluded as \"new\" for corporate-VPN detection): ${STARTUP_UTUNS:-<none>}"
echo

AMNEZIA_UTUN_START=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")

CORP_HIT=$(detect_corp_present)
if [ -n "$CORP_HIT" ]; then
    corp_iface=${CORP_HIT% *}
    corp_ip=${CORP_HIT#* }
    echo "NOTE: the corporate VPN already looks connected ($corp_iface, inet $corp_ip)."
    echo "The connect time this script measures is only meaningful if it starts disconnected."
    if [ "$DRY_RUN" = 1 ]; then
        echo "(dry-run preview: a live run would refuse and stop here -- see below -- unless --force is given; continuing the preview.)"
        CORP_ALREADY_PRESENT="$CORP_HIT"
    elif [ "$FORCE" = 1 ]; then
        echo "Continuing anyway because --force was given; the connect time will be reported as n/a."
        CORP_ALREADY_PRESENT="$CORP_HIT"
    else
        echo
        echo "ERROR: refusing to start -- nothing has been touched. To proceed:" >&2
        echo "  1. Disconnect the corporate Check Point VPN." >&2
        echo "  2. Re-run:  $ORIG_CMDLINE" >&2
        echo "  3. Follow the prompts." >&2
        echo "(Pass --force to skip this check and run anyway; the connect time will then be reported as n/a.)" >&2
        exit 1
    fi
    echo
fi

if [ "$METHOD" = "routes" ]; then
    echo "If this script is interrupted after routes are deleted, restore them by hand with:"
    manual_restore_hint
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
            verify_restore
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
if [ -n "$CORP_ALREADY_PRESENT" ]; then
    echo "Corporate VPN is already connected (see NOTE above) -- not waiting for it; the connect time cannot be measured this run."
    CONNECT_RESULT=0
    CONNECT_ELAPSED="n/a (corporate VPN was already connected)"
else
    echo "ACTION NEEDED: connect the corporate Check Point VPN now."
    echo "Waiting up to ${CORP_TIMEOUT}s for a utun matching ${CORP_TUNNEL_PREFIX}*, or any new non-personal utun, to appear..."
    CONNECT_START=$(date +%s)
    wait_for_corp_utun "$CORP_TIMEOUT"
    CONNECT_RESULT=$?
    if [ "$DRY_RUN" = 1 ]; then
        CONNECT_ELAPSED="n/a (dry-run)"
    elif [ "$CONNECT_RESULT" = 0 ]; then
        CONNECT_ELAPSED=$(( $(date +%s) - CONNECT_START ))
        echo "Corporate VPN connected in ${CONNECT_ELAPSED}s."
    else
        CONNECT_ELAPSED="n/a (did not connect within ${CORP_TIMEOUT}s)"
        CONNECT_TIMED_OUT=1
        echo "Corporate VPN did not connect within ${CORP_TIMEOUT}s; restoring the personal VPN anyway."
    fi
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
case "$CONNECT_ELAPSED" in
    n/a*) echo "Corporate VPN connect time: $CONNECT_ELAPSED" ;;
    *) echo "Corporate VPN connect time: ${CONNECT_ELAPSED}s" ;;
esac

EXIT_CODE=0
[ "$RESTORE_HAD_FAILURES" = 1 ] && EXIT_CODE=1
[ "$RESTORE_VERIFY_FAILED" = 1 ] && EXIT_CODE=1
[ "$CONNECT_TIMED_OUT" = 1 ] && EXIT_CODE=1
exit "$EXIT_CODE"
