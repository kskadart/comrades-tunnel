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
# --method routes also excludes, from both the save and the delete step,
# any route to an endpoint listed in config/example/keep-routes-for.txt
# (see that file and lib-routes.sh's compute_keep_set) -- e.g. a streaming
# LLM API reachable only through the personal VPN, so an already-open
# connection to it is never disrupted by a lift at all, not merely for a
# shorter window. If that keep-set cannot be computed (no python3, or
# every configured entry fails to resolve), this method refuses to delete
# anything rather than risk the very routes it was meant to protect --
# --dry-run resolves the same keep-set for real (read-only) to preview it.
# --method prompt cannot benefit from this at all: it disconnects the
# whole personal VPN, so every route -- kept or not -- goes away with the
# interface (see README).
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
SAVED_THIS_RUN=0          # set only once THIS run's own save_amnezia_routes has run -- see restore_personal_vpn

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
    0)
        echo "ERROR: --timeout must be greater than 0, got '$TIMEOUT'" >&2
        exit 2
        ;;
esac

# normalize_dest, save_amnezia_routes, delete_amnezia_routes,
# restore_saved_routes, verify_restore, detect_utun_by_prefix, route_count,
# routes_on_iface, get_tunnel_prefix, and manual_restore_hint now live in
# lib-routes.sh (shared with bin/route-lift-watcher.sh) so they are defined
# in exactly one place. They still read/write this script's own globals
# (DRY_RUN, SAVED_ROUTES_FILE, BUILD_DIR, PERSONAL_TUNNEL_PREFIX,
# RESTORE_HAD_FAILURES, RESTORE_VERIFY_FAILED, TUNNELS_FILE) -- see
# lib-routes.sh's header comment for the exact contract.
. "$SCRIPT_DIR/lib-routes.sh"

# routes_restore_should_run -- true (0) when a live (non-dry-run) restore
# for --method routes should actually touch SAVED_ROUTES_FILE this run:
# only once THIS run's own save_amnezia_routes has actually run
# (SAVED_THIS_RUN=1). A preview (--dry-run) always runs regardless, since
# it never touches anything real. Defined here (before restore_personal_vpn,
# and before the --self-test dispatch below) so --self-test can exercise
# this decision directly -- see finding 8 in the review this fixes: the
# "no personal-VPN utun found" refusal (in the bring-down case, below) exits
# AFTER the EXIT trap is already armed, and without this guard that exit
# would replay whatever SAVED_ROUTES_FILE happens to already be on disk
# from a PREVIOUS successful run (this method deliberately leaves it there
# as a historical record -- see the header), even though THIS run never
# actually saved or deleted anything.
routes_restore_should_run() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ "$SAVED_THIS_RUN" = 1 ]
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
    # Finding 6: 2- and 3-octet no-slash forms (netstat drops the "/len"
    # when it equals the classful default for that octet count) must be
    # expanded, not passed through -- ipaddress.ip_network() in
    # keep-routes.py rejects a bare "104.16"/"192.168.50" outright, so
    # leaving them unexpanded made that route silently never matchable by
    # the keep-routes feature.
    test_case "104.16" "104.16.0.0/16"
    test_case "192.168.50" "192.168.50.0/24"

    # --- Finding 5(i) / Finding 10: save_amnezia_routes must keep only
    # Amnezia's own interface-style routes (gw == the interface itself),
    # skipping the kernel's own point-to-point host route on that same
    # interface (dest==gw==the tunnel's own address, a literal IP, not the
    # interface name) and "default" (never a candidate to save/delete/
    # restore -- see delete_amnezia_routes). Subshell so the netstat()
    # override below never leaks.
    f5_result=$(
        netstat() {
            cat <<'ROWS'
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
1.2.3.0/24          utun9              UGSc                  utun9
10.9.9.9            10.9.9.9           UH                    utun9
default             utun9              UGSc                  utun9
ROWS
        }
        f5_dir=$(mktemp -d) || exit 1
        trap 'rm -rf "$f5_dir"' EXIT
        BUILD_DIR="$f5_dir"
        SAVED_ROUTES_FILE="$f5_dir/saved.txt"
        save_amnezia_routes utun9
        cat "$SAVED_ROUTES_FILE"
    )
    if printf '%s\n' "$f5_result" | grep -qx '1.2.3.0/24 utun9' && \
       ! printf '%s\n' "$f5_result" | grep -q '10\.9\.9\.9' && \
       ! printf '%s\n' "$f5_result" | grep -q '^default'; then
        echo "PASS  [finding 5i] save_amnezia_routes keeps Amnezia's interface routes, skips the kernel's own point-to-point host route"
        echo "PASS  [finding 10] save_amnezia_routes never saves the default route"
    else
        echo "FAIL  [finding 5i/10] save_amnezia_routes result: $f5_result"
        fail=1
    fi

    # --- Finding 5(i), dry-run preview: delete_amnezia_routes's own
    # DRY_RUN branch must apply the same self-route/default exclusion as
    # save_amnezia_routes -- a real run's SAVED_ROUTES_FILE would never
    # contain either, so the preview must not claim it "would delete" them.
    # Subshell so the netstat() override never leaks.
    f5c_result=$(
        netstat() {
            cat <<'ROWS'
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
1.2.3.0/24          utun9              UGSc                  utun9
10.9.9.9            10.9.9.9           UH                    utun9
default             utun9              UGSc                  utun9
ROWS
        }
        DRY_RUN=1
        delete_amnezia_routes utun9
    )
    if printf '%s\n' "$f5c_result" | grep -q 'delete -net "1.2.3.0/24"' && \
       ! printf '%s\n' "$f5c_result" | grep -q '10\.9\.9\.9' && \
       ! printf '%s\n' "$f5c_result" | grep -q 'default'; then
        echo "PASS  [finding 5i] delete_amnezia_routes's dry-run preview also skips the kernel's own point-to-point host route and default"
    else
        echo "FAIL  [finding 5i] delete_amnezia_routes dry-run preview: $f5c_result"
        fail=1
    fi

    # --- Finding 8: restore_personal_vpn's "routes" branch must not
    # replay a stale SAVED_ROUTES_FILE left on disk by a PREVIOUS run when
    # THIS run never actually saved anything.
    f8_dir=$(mktemp -d) || { echo "FAIL  [finding 8] could not create temp dir" >&2; fail=1; f8_dir=""; }
    if [ -n "$f8_dir" ]; then
        SAVED_ROUTES_FILE="$f8_dir/saved.txt"
        DRY_RUN=0
        printf '10.9.9.0/24 utun9\n' >"$SAVED_ROUTES_FILE"   # stale file "from last week"
        SAVED_THIS_RUN=0
        if routes_restore_should_run; then
            echo "FAIL  [finding 8] routes_restore_should_run said yes when nothing was saved this run"
            fail=1
        else
            echo "PASS  [finding 8] routes_restore_should_run refuses to touch a stale saved-routes file when nothing was saved this run"
        fi
        SAVED_THIS_RUN=1
        if routes_restore_should_run; then
            echo "PASS  [finding 8] routes_restore_should_run allows the restore once this run's own save actually happened"
        else
            echo "FAIL  [finding 8] routes_restore_should_run refused even though this run did save"
            fail=1
        fi
        rm -rf "$f8_dir"
    fi

    # --- Finding 9: delete_amnezia_routes must re-check each route's
    # CURRENT interface before deleting it -- skip and count a mismatch
    # rather than delete a route that, by now, belongs to someone else.
    # Plain "( ) >file" subshell (NOT "$(...)") so the route()/sudo()
    # overrides never leak and no real `route get`/`route delete` is ever
    # invoked -- a case statement defined inline inside a "$(...)" command
    # substitution mis-parses on this platform's /bin/sh (bash 3.2's
    # long-standing case-in-command-substitution parser bug), so the
    # override function bodies are exercised via output redirection
    # instead of output capture.
    f9_dir=$(mktemp -d) || { echo "FAIL  [finding 9] could not create temp dir" >&2; fail=1; f9_dir=""; }
    if [ -n "$f9_dir" ]; then
        f9_outfile="$f9_dir/out"
        (
            route() {
                case "$*" in
                    *"10.1.1.0/24"*) echo "   interface: utun42" ;;
                    *) echo "   interface: en0" ;;
                esac
            }
            sudo() { return 0; }
            SAVED_ROUTES_FILE="$f9_dir/saved.txt"
            printf '10.1.1.0/24 utun42\n10.2.2.0/24 utun42\n' >"$SAVED_ROUTES_FILE"
            DRY_RUN=0
            delete_amnezia_routes utun42
        ) >"$f9_outfile" 2>&1
        f9_out=$(cat "$f9_outfile")
        if printf '%s\n' "$f9_out" | grep -q '1 succeeded, 0 failed, 1 skipped'; then
            echo "PASS  [finding 9] delete_amnezia_routes skips a route whose current interface no longer matches"
        else
            echo "FAIL  [finding 9] delete_amnezia_routes output: $f9_out"
            fail=1
        fi
        rm -rf "$f9_dir"
    fi

    # --- Finding 14: compute_keep_set must invoke /usr/bin/python3
    # directly, never a PATH-resolved "python3". Subshell so the fake PATH
    # entry never leaks.
    if [ "$SUDO" = "sudo" ]; then
        echo "PASS  [finding 14] lib-routes.sh's \$SUDO is 'sudo' when not running as root"
    else
        echo "FAIL  [finding 14] \$SUDO='$SUDO' while not root (expected 'sudo')"
        fail=1
    fi
    if (
        f14_dir=$(mktemp -d) || exit 1
        trap 'rm -rf "$f14_dir"' EXIT
        cat >"$f14_dir/python3" <<'EOF'
#!/bin/sh
echo "FAKE-PYTHON-RAN" >&2
exit 1
EOF
        chmod +x "$f14_dir/python3"
        PATH="$f14_dir:$PATH"
        export PATH
        KEEP_ROUTES_FILE="$f14_dir/keep.txt"
        KEEP_ROUTES_SCRIPT="$SCRIPT_DIR/keep-routes.py"
        KEPT_ROUTES_FILE="$f14_dir/kept.txt"
        routes_file="$f14_dir/routes.txt"
        printf '1.2.3.0/24 utun9\n' >"$routes_file"
        printf '1.2.3.0/24\n' >"$KEEP_ROUTES_FILE"
        out=$(compute_keep_set "$routes_file" 2>&1)
        if printf '%s' "$out" | grep -q "FAKE-PYTHON-RAN"; then
            echo "FAIL  [finding 14] compute_keep_set ran a PATH-shadowed python3 instead of /usr/bin/python3"
            exit 1
        else
            echo "PASS  [finding 14] compute_keep_set invokes /usr/bin/python3 directly, ignoring a shadowing PATH entry"
        fi
    ); then
        :
    else
        fail=1
    fi

    # --- Finding 16: reject --timeout 0.
    f16_out=$("$0" --timeout 0 --dry-run 2>&1)
    f16_rc=$?
    if [ "$f16_rc" -ne 0 ] && printf '%s' "$f16_out" | grep -qi 'timeout'; then
        echo "PASS  [finding 16] --timeout 0 is rejected"
    else
        echo "FAIL  [finding 16] --timeout 0 -> rc=$f16_rc out='$f16_out' (expected a rejection)"
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

TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
if [ ! -f "$TUNNELS_FILE" ]; then
    echo "ERROR: $TUNNELS_FILE not found (see config/example/tunnels.txt)" >&2
    exit 2
fi

# get_tunnel_prefix (KEY -> VALUE from tunnels.txt) is defined in
# lib-routes.sh, already sourced above; it reads the global $TUNNELS_FILE
# just set.
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

# KEEP_ROUTES_FILE/KEEP_ROUTES_SCRIPT/KEPT_ROUTES_FILE: see lib-routes.sh's
# compute_keep_set() header. Shared with route-lift-watcher.sh so a
# configured endpoint (config/example/keep-routes-for.txt) survives a
# --method routes lift the same way it survives an automatic one.
KEEP_ROUTES_FILE="$CONFIG_DIR/keep-routes-for.txt"
KEEP_ROUTES_SCRIPT="$SCRIPT_DIR/keep-routes.py"
KEPT_ROUTES_FILE="$BUILD_DIR/cp-connect-kept-routes.txt"

# --- utun / route inspection (read-only, always safe to run for real) ---
#
# detect_utun_by_prefix, route_count, and routes_on_iface are defined in
# lib-routes.sh, already sourced above.

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
#
# manual_restore_hint, save_amnezia_routes, delete_amnezia_routes,
# restore_saved_routes, and verify_restore are defined in lib-routes.sh,
# already sourced above.

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
            if ! routes_restore_should_run; then
                echo "  (nothing was saved this run -- not touching any existing $SAVED_ROUTES_FILE)"
                return 0
            fi
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
        ROUTES_SKIP_DELETE=0
        if [ "$DRY_RUN" = 1 ]; then
            echo "  would run: mkdir -p $BUILD_DIR"
            echo "  would run: netstat -rn -f inet | awk '\$NF==\"$AMNEZIA_UTUN_START\" {print \$1, \$2}' > $SAVED_ROUTES_FILE"
            # Keep-routes preview: resolves KEEP_ROUTES_FILE for real
            # (read-only) against a throwaway file instead of the real
            # SAVED_ROUTES_FILE, so nothing is actually saved/deleted here.
            kr_preview_file=$(mktemp)
            netstat -rn -f inet 2>/dev/null | awk -v i="$AMNEZIA_UTUN_START" '$NF==i {print $1, $2}' |
            while read -r dest gw; do
                [ -z "$dest" ] && continue
                echo "$(normalize_dest "$dest") $gw"
            done >"$kr_preview_file"
            echo "  (dry-run: resolving $KEEP_ROUTES_FILE for real to preview the keep-set -- nothing will be saved/deleted)"
            if compute_keep_set "$kr_preview_file"; then
                if [ -s "$KEPT_ROUTES_FILE" ]; then
                    echo "  would keep $(wc -l <"$KEPT_ROUTES_FILE" | tr -d ' ') route(s):"
                    while IFS= read -r kline; do echo "    kept: $kline"; done <"$KEPT_ROUTES_FILE"
                else
                    echo "  would keep 0 routes (no active entries in $KEEP_ROUTES_FILE, or none matched)"
                fi
            else
                echo "  NOTE: keep-set could not be computed (see above) -- a live run would refuse to delete anything and leave the corporate connect slow."
            fi
            rm -f "$kr_preview_file"
            # KEPT_ROUTES_FILE is left as compute_keep_set wrote it above so
            # delete_amnezia_routes's own dry-run preview (below) excludes
            # the same kept routes; cleaned up once that preview is done.
        else
            save_amnezia_routes "$AMNEZIA_UTUN_START"
            SAVED_THIS_RUN=1
            echo "Saved $(wc -l <"$SAVED_ROUTES_FILE" | tr -d ' ') routes to $SAVED_ROUTES_FILE."
            if compute_keep_set "$SAVED_ROUTES_FILE"; then
                if [ -s "$KEPT_ROUTES_FILE" ]; then
                    echo "Keeping $(wc -l <"$KEPT_ROUTES_FILE" | tr -d ' ') route(s) per $KEEP_ROUTES_FILE:"
                    while IFS= read -r kline; do echo "  kept: $kline"; done <"$KEPT_ROUTES_FILE"
                fi
            else
                echo "ERROR: keep-set could not be computed from $KEEP_ROUTES_FILE (see above); NOT deleting any routes -- the corporate VPN connect will be slow this run." >&2
                rm -f "$SAVED_ROUTES_FILE" "$KEPT_ROUTES_FILE"
                ROUTES_SKIP_DELETE=1
            fi
        fi
        if [ "$ROUTES_SKIP_DELETE" = 0 ]; then
            delete_amnezia_routes "$AMNEZIA_UTUN_START"
        fi
        # KEPT_ROUTES_FILE (--dry-run only -- a real run's already exists as
        # part of SAVED_ROUTES_FILE's own bookkeeping and is cleaned up by
        # verify_restore's caller elsewhere) is deliberately NOT removed
        # here: restore_personal_vpn's own dry-run preview, called near the
        # end of this script, also needs it to exclude the same kept routes
        # from "would restore" -- see its own comment. Removed once that
        # preview has run too (bottom of this script).
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
[ "$METHOD" = "routes" ] && [ "$DRY_RUN" = 1 ] && rm -f "$KEPT_ROUTES_FILE"
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
