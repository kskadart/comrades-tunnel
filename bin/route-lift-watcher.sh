#!/bin/sh
# Automatically lift the personal AmneziaVPN's routes while the corporate
# Check Point VPN performs a full reconnect, then restore them.
#
# Why: bin/cp-connect.sh already shrinks the routing table for a *manual*
# corporate-VPN connect the human triggers by hand. But full corporate
# reconnects are not only user-initiated: parsing 1,019 "Starting new
# connection" events across 295 days of this machine's own
# "/Library/Application Support/Checkpoint/Endpoint Connect/helpdesk.log"
# shows roughly 1.5-2 genuine AUTOMATIC full reconnects per day (post-sleep
# resume, roaming timeout, always-connect retry), each paying the same
# 2-3.5 minute route-conflict-scan cost cp-connect.sh's header describes,
# with nobody around to run cp-connect.sh for them. This watcher covers
# that case by watching the same log Check Point itself writes.
#
# Trigger: every full reconnect appends "Starting connect" or "Starting new
# connection" to helpdesk.log within about a second of starting; completion
# appends "Connection was successfully established". Terminal-but-not-
# successful outcomes ("Site is not responding", "User cancelled the
# connection", "Disconnect initiated by user") also end the window. Short
# "Interface change ... Reconnect finished successfully" pairs and a lone
# "Policy changed, restarting connection" do NOT rebuild the virtual
# adapter and must NOT trigger a lift -- see decide_state()/run_self_test
# below, which is exactly the decision logic --self-test exercises. The log
# file is root:wheel, world-readable -- no privilege is needed to read it.
#
# Route save/normalise/delete/restore/verify logic is shared with
# cp-connect.sh via lib-routes.sh (see that file's header for the exact
# global-variable contract); this script sets the same globals cp-connect.sh
# does before calling into it.
#
# Safety design (see README for the one-paragraph version):
#   - Never delete a route this script has not first verified it saved: the
#     live route count on the personal VPN's utun is enumerated *before*
#     save_amnezia_routes runs, and the saved file's own line count must
#     match that enumeration and be non-zero before delete_amnezia_routes is
#     ever called (do_lift below).
#   - A hard timeout (default 240s, --timeout / TIMEOUT overrides) restores
#     unconditionally if no completion line ever appears.
#   - A trap on EXIT/INT/TERM restores exactly once if this process's own
#     saved-routes file is still present when it exits for any reason.
#   - A completely independent safety net (meant to be invoked periodically
#     by the installed LaunchDaemon's StartInterval, but it is just the
#     normal invocation path -- see run_safety_net_check) restores
#     unconditionally and logs loudly if a saved-routes file is older than
#     the timeout and the personal VPN's utun currently has fewer routes
#     than were saved -- this is what self-heals a crash between delete and
#     restore, independent of the trap above (which only fires for the
#     process that actually did the deleting).
#   - Unlike cp-connect.sh (a one-shot interactive script, where the saved-
#     routes file is left on disk after a restore as a historical record),
#     this watcher runs unattended and repeatedly, so it treats the saved-
#     routes file's mere existence as the single source of truth for
#     "routes are currently lifted": do_restore below removes the file once
#     a restore is verified to have succeeded, and deliberately leaves it in
#     place on any failure so the safety net and --status keep seeing the
#     incomplete state.
#   - Single-instance lock (mkdir-based, POSIX, no bashisms): concurrent
#     invocations (multiple WatchPaths/StartInterval firings) that find the
#     lock held by a live instance do nothing at all. A lock older than the
#     timeout is presumed to belong to a dead process, is broken with a log
#     line, and the safety-net check above runs immediately afterwards.
#   - Fail safe, not closed: no personal VPN utun, no saved-routes file,
#     helpdesk.log unreadable, or PERSONAL_TUNNEL_PREFIX unset -- log why
#     and do nothing, never guess.
#
# Usage: route-lift-watcher.sh [--config DIR] [--timeout N]
#                               [--dry-run] [--status] [--self-test]
#
# With no --config, reads the installed conf next to this script
# (route-lift.conf, rendered by install-route-lift-watcher.sh). --config DIR
# reads DIR/tunnels.txt directly (same convention as cp-connect.sh --config)
# so this can run straight from a repo checkout against local/ or
# config/example/ without installing anything.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd 2>/dev/null || echo "$SCRIPT_DIR")

# shellcheck source=lib-routes.sh
. "$SCRIPT_DIR/lib-routes.sh"

CONFIG_DIR=""
CONF_FILE="$SCRIPT_DIR/route-lift.conf"
TIMEOUT_FLAG=""
DRY_RUN=0
STATUS=0
SELF_TEST=0

PLIST_LABEL="dev.comrades-tunnel.route-lift"
LOG_FILE="/var/log/comrades-tunnel-route-lift.log"
HELPDESK_LOG_DEFAULT="/Library/Application Support/Checkpoint/Endpoint Connect/helpdesk.log"

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
        --timeout)
            TIMEOUT_FLAG=$2
            shift 2
            ;;
        --timeout=*)
            TIMEOUT_FLAG=${1#--timeout=}
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --status)
            STATUS=1
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--timeout N] [--dry-run] [--status] [--self-test]" >&2
            exit 2
            ;;
    esac
done

case "$TIMEOUT_FLAG" in
    '') ;;
    *[!0-9]*)
        echo "ERROR: --timeout must be a positive integer, got '$TIMEOUT_FLAG'" >&2
        exit 2
        ;;
esac

# decide_state INITIAL FILE -- given the current persisted INITIAL state
# ("STARTED" or "IDLE") and a FILE containing zero or more new log lines
# (either the newly-appended slice of helpdesk.log, or a whole synthetic
# excerpt for --self-test), return the resulting state. The line number of
# the LAST connect-start line and the LAST completion/terminal line in FILE
# are compared; whichever comes later determines the result (ties cannot
# occur -- they are different lines). If neither pattern appears anywhere in
# FILE, INITIAL is returned unchanged -- this is why "Interface change",
# "Trying to reconnect", "Reconnect finished successfully", and "Policy
# changed, restarting connection" never affect the result: they match
# neither pattern.
decide_state() {
    initial=$1
    file=$2
    start_line=$(grep -n -E 'Starting connect|Starting new connection' "$file" 2>/dev/null | tail -1 | cut -d: -f1)
    done_line=$(grep -n -E 'Connection was successfully established|Site is not responding|User cancelled the connection|Disconnect initiated by user' "$file" 2>/dev/null | tail -1 | cut -d: -f1)
    if [ -z "$start_line" ] && [ -z "$done_line" ]; then
        printf '%s\n' "$initial"
        return 0
    fi
    if [ -n "$start_line" ] && { [ -z "$done_line" ] || [ "$start_line" -gt "$done_line" ]; }; then
        printf '%s\n' "STARTED"
    else
        printf '%s\n' "IDLE"
    fi
}

# --self-test: exercise decide_state against a fixed table of synthetic
# helpdesk.log excerpts, independent of any config directory or the real
# log. All six cases required by the brief; PASS/FAIL per case, non-zero
# exit on any failure.
run_self_test() {
    fail=0
    tmpfile=$(mktemp) || { echo "FAIL  could not create a temp file for self-test" >&2; return 1; }
    trap 'rm -f "$tmpfile"' EXIT

    test_case() {
        desc=$1
        initial=$2
        content=$3
        expected=$4
        printf '%s' "$content" >"$tmpfile"
        actual=$(decide_state "$initial" "$tmpfile")
        if [ "$actual" = "$expected" ]; then
            echo "PASS  $desc -> $actual"
        else
            echo "FAIL  $desc -> $actual (expected $expected)"
            fail=1
        fi
    }

    test_case "fresh 'Starting new connection', no completion yet (trigger)" "IDLE" \
"[11 Sep 14:47:38] Starting new connection (0x9)
" "STARTED"

    test_case "same, followed by 'Connection was successfully established' (no trigger)" "IDLE" \
"[11 Sep 14:47:38] Starting new connection (0x9)
[11 Sep 14:47:52] Connection was successfully established (0x9)
" "IDLE"

    test_case "'Interface change'/'Reconnect finished successfully' pair alone (no trigger)" "IDLE" \
"[11 Sep  1:50:59] Interface change - location is OUT, trying to reconnect
[11 Sep  1:51:00] Reconnect finished successfully (0x9)
" "IDLE"

    test_case "'Policy changed, restarting connection' alone (no trigger)" "IDLE" \
"[10 Sep 11:28:39] Policy changed, restarting connection (0x9)
" "IDLE"

    test_case "connect-start followed by 'Site is not responding' (terminal, no trigger)" "IDLE" \
"[11 Sep  0:58:11] Starting connect...
[11 Sep  1:00:57] IKE connection failed, error code=-1000. Reason: Site is not responding.
" "IDLE"

    test_case "empty/unchanged tail (no trigger)" "IDLE" "" "IDLE"

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

# --- config resolution (same dual-mode convention as dns-guard.sh: an
# installed conf file by default, or --config DIR to read a repo config dir
# directly without installing anything) ---
if [ -n "$CONFIG_DIR" ]; then
    TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
    if [ ! -f "$TUNNELS_FILE" ]; then
        echo "ERROR: $TUNNELS_FILE not found (see config/example/tunnels.txt)" >&2
        exit 2
    fi
    PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)
    TIMEOUT=240
    HELPDESK_LOG="$HELPDESK_LOG_DEFAULT"
    STATE_DIR="$REPO_ROOT/build/route-lift-state"
else
    if [ ! -f "$CONF_FILE" ]; then
        echo "ERROR: $CONF_FILE not found (use --config DIR to read a repo config dir instead)" >&2
        exit 2
    fi
    PERSONAL_TUNNEL_PREFIX=$(grep '^PERSONAL_TUNNEL_PREFIX=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    TIMEOUT=$(grep '^TIMEOUT=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    HELPDESK_LOG=$(grep '^HELPDESK_LOG=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    STATE_DIR=$(grep '^STATE_DIR=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    [ -z "$TIMEOUT" ] && TIMEOUT=240
    [ -z "$HELPDESK_LOG" ] && HELPDESK_LOG="$HELPDESK_LOG_DEFAULT"
fi
[ -n "$TIMEOUT_FLAG" ] && TIMEOUT=$TIMEOUT_FLAG

if [ -z "$PERSONAL_TUNNEL_PREFIX" ]; then
    echo "ERROR: PERSONAL_TUNNEL_PREFIX not set (ambiguous -- fail safe, doing nothing)" >&2
    exit 2
fi
if [ -z "$STATE_DIR" ]; then
    echo "ERROR: STATE_DIR not set (ambiguous -- fail safe, doing nothing)" >&2
    exit 2
fi

# lib-routes.sh's functions expect this global name for the directory they
# mkdir -p and write SAVED_ROUTES_FILE under (see its header comment). DRY_RUN
# itself is already the same variable name lib-routes.sh expects.
BUILD_DIR="$STATE_DIR"

SAVED_ROUTES_FILE="$STATE_DIR/route-lift-saved-routes.txt"
OFFSET_FILE="$STATE_DIR/offset"
WATCH_STATE_FILE="$STATE_DIR/state"
LOCK_DIR="$STATE_DIR/lock"

RESTORE_HAD_FAILURES=0
RESTORE_VERIFY_FAILED=0
RESTORE_DONE=0
LOCK_HELD=0

# log MESSAGE -- timestamped append to LOG_FILE, falling back to stderr if
# LOG_FILE cannot be written (e.g. running unprivileged), same fallback
# dns-guard.sh uses. In --dry-run nothing is written to disk; MESSAGE goes
# to stdout instead, prefixed to make that obvious.
log() {
    ts=$(date '+%Y-%m-%dT%H:%M:%S%z')
    line="$ts $1"
    if [ "$DRY_RUN" = 1 ]; then
        printf '[dry-run, not logged] %s\n' "$line"
        return 0
    fi
    if ! printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null; then
        printf '%s\n' "$line" >&2
    fi
}

# age_seconds PATH -- seconds since PATH's mtime, or empty if PATH does not
# exist / stat fails.
age_seconds() {
    mtime=$(stat -f '%m' "$1" 2>/dev/null) || return 1
    now=$(date +%s)
    echo $((now - mtime))
}

# do_restore -- restore_saved_routes + verify_restore (from lib-routes.sh),
# then clear SAVED_ROUTES_FILE only if both succeeded. See the header
# comment above for why this differs from cp-connect.sh (which always
# leaves the file in place): here, file presence must mean "still lifted".
do_restore() {
    RESTORE_DONE=1
    log "restoring saved routes from $SAVED_ROUTES_FILE"
    RESTORE_HAD_FAILURES=0
    RESTORE_VERIFY_FAILED=0
    restore_saved_routes
    verify_restore
    if [ "$RESTORE_HAD_FAILURES" = 0 ] && [ "$RESTORE_VERIFY_FAILED" = 0 ]; then
        rm -f "$SAVED_ROUTES_FILE"
        log "restore verified; cleared $SAVED_ROUTES_FILE"
    else
        log "WARNING: restore incomplete or unverified; keeping $SAVED_ROUTES_FILE in place for the safety net / a retry"
    fi
}

# restore_if_needed -- EXIT/INT/TERM trap body. Restores exactly once, and
# only if this process's own saved-routes file is still present (idempotent:
# do_restore already cleared it on a normal successful path).
restore_if_needed() {
    [ "$RESTORE_DONE" = 1 ] && return 0
    if [ -f "$SAVED_ROUTES_FILE" ]; then
        log "EXIT/signal trap firing with routes still lifted; restoring now"
        do_restore
    fi
    RESTORE_DONE=1
}

release_lock_if_held() {
    if [ "$LOCK_HELD" = 1 ]; then
        rmdir "$LOCK_DIR" 2>/dev/null
        LOCK_HELD=0
    fi
}

cleanup_and_exit() {
    restore_if_needed
    release_lock_if_held
}

# acquire_lock -- mkdir-based single-instance lock, POSIX, no bashisms.
# Returns 0 holding the lock, 1 if another live instance holds it. A lock
# older than TIMEOUT is presumed to belong to a dead process: broken with a
# log line, then re-acquired.
acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        return 0
    fi
    lock_age=$(age_seconds "$LOCK_DIR")
    if [ -n "$lock_age" ] && [ "$lock_age" -gt "$TIMEOUT" ]; then
        log "WARNING: breaking stale lock at $LOCK_DIR (age ${lock_age}s > timeout ${TIMEOUT}s) -- presumed to belong to a dead process"
        rmdir "$LOCK_DIR" 2>/dev/null
        if mkdir "$LOCK_DIR" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# do_lift -- enumerate routes on the personal VPN's utun, save them, verify
# the saved file is non-empty and its line count matches the enumeration
# taken just before saving, and only then delete them. Never deletes
# anything it has not first verified it saved.
do_lift() {
    personal_utun=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
    if [ -z "$personal_utun" ]; then
        log "no personal VPN utun found (prefix $PERSONAL_TUNNEL_PREFIX); fail safe, not lifting anything"
        return 1
    fi
    enumerated=$(routes_on_iface "$personal_utun")
    if [ "$enumerated" -eq 0 ] 2>/dev/null; then
        log "0 routes currently on $personal_utun; nothing to lift"
        return 0
    fi
    mkdir -p "$STATE_DIR"
    save_amnezia_routes "$personal_utun"
    saved_lines=$(wc -l <"$SAVED_ROUTES_FILE" 2>/dev/null | tr -d ' ')
    if [ -z "$saved_lines" ] || [ "$saved_lines" -eq 0 ] 2>/dev/null || [ "$saved_lines" != "$enumerated" ]; then
        log "ERROR: saved-routes verification failed (enumerated=$enumerated saved=${saved_lines:-0}); NOT deleting any routes"
        rm -f "$SAVED_ROUTES_FILE"
        return 1
    fi
    log "saved $saved_lines routes from $personal_utun to $SAVED_ROUTES_FILE (verified against $enumerated enumerated); deleting them now"
    delete_amnezia_routes "$personal_utun" | while IFS= read -r dline; do log "$dline"; done
    log "lifted (deleted) $saved_lines routes from $personal_utun"
    return 0
}

# wait_for_completion_then_restore -- poll helpdesk.log every 2s, up to
# TIMEOUT seconds, advancing the same offset/state files the main decision
# cycle uses, until a completion/terminal line is seen or the timeout
# elapses; then restore unconditionally either way.
wait_for_completion_then_restore() {
    start_ts=$(date +%s)
    while :; do
        cur_size=$(wc -c <"$HELPDESK_LOG" 2>/dev/null | tr -d ' ')
        if [ -n "$cur_size" ]; then
            prev_offset=$(cat "$OFFSET_FILE" 2>/dev/null)
            case "$prev_offset" in ''|*[!0-9]*) prev_offset=0 ;; esac
            [ "$prev_offset" -gt "$cur_size" ] && prev_offset=0
            if [ "$cur_size" -gt "$prev_offset" ]; then
                slice_file="$STATE_DIR/.slice.$$"
                tail -c +"$((prev_offset + 1))" "$HELPDESK_LOG" >"$slice_file" 2>/dev/null
                prev_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
                case "$prev_state" in STARTED|IDLE) ;; *) prev_state=STARTED ;; esac
                new_state=$(decide_state "$prev_state" "$slice_file")
                rm -f "$slice_file"
                echo "$cur_size" >"$OFFSET_FILE"
                echo "$new_state" >"$WATCH_STATE_FILE"
                if [ "$new_state" = "IDLE" ]; then
                    elapsed=$(( $(date +%s) - start_ts ))
                    log "completion observed after ${elapsed}s; restoring"
                    do_restore
                    return 0
                fi
            fi
        fi
        elapsed=$(( $(date +%s) - start_ts ))
        if [ "$elapsed" -ge "$TIMEOUT" ]; then
            log "TIMEOUT after ${elapsed}s waiting for corporate-VPN completion; restoring unconditionally"
            do_restore
            return 0
        fi
        sleep 2
    done
}

# run_safety_net_check -- the independent backstop meant to run on every
# StartInterval tick (which, in this design, is just a normal invocation of
# this script -- see header). Returns 1 (and has already restored) if it
# acted; 0 otherwise, including every "nothing to check" / "not old enough
# yet" / "utun missing" case.
run_safety_net_check() {
    [ -f "$SAVED_ROUTES_FILE" ] || return 0
    saved_age=$(age_seconds "$SAVED_ROUTES_FILE")
    if [ -z "$saved_age" ] || [ "$saved_age" -le "$TIMEOUT" ]; then
        return 0
    fi
    personal_utun=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
    if [ -z "$personal_utun" ]; then
        log "SAFETY-NET: saved-routes file is ${saved_age}s old (> ${TIMEOUT}s) but no personal VPN utun is present; cannot verify or restore -- leaving the saved file in place for the next check"
        return 0
    fi
    saved_count=$(wc -l <"$SAVED_ROUTES_FILE" 2>/dev/null | tr -d ' ')
    now_count=$(routes_on_iface "$personal_utun")
    if [ "$now_count" -lt "$saved_count" ] 2>/dev/null; then
        log "SAFETY-NET: saved-routes file is ${saved_age}s old (> ${TIMEOUT}s) and $personal_utun has $now_count/$saved_count routes -- restoring unconditionally"
        do_restore
        return 1
    fi
    return 0
}

# run_decision_cycle -- the normal WatchPaths-triggered path: advance the
# offset, decide, and act.
run_decision_cycle() {
    cur_size=$(wc -c <"$HELPDESK_LOG" 2>/dev/null | tr -d ' ')
    if [ -z "$cur_size" ]; then
        log "cannot read $HELPDESK_LOG; fail safe, doing nothing"
        return 0
    fi
    prev_offset=$(cat "$OFFSET_FILE" 2>/dev/null)
    case "$prev_offset" in ''|*[!0-9]*) prev_offset=0 ;; esac
    if [ "$prev_offset" -gt "$cur_size" ]; then
        log "helpdesk.log appears to have rotated (offset $prev_offset > size $cur_size); resetting offset to 0"
        prev_offset=0
    fi
    prev_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
    case "$prev_state" in STARTED|IDLE) ;; *) prev_state=IDLE ;; esac

    mkdir -p "$STATE_DIR"
    slice_file="$STATE_DIR/.slice.$$"
    tail -c +"$((prev_offset + 1))" "$HELPDESK_LOG" >"$slice_file" 2>/dev/null
    new_state=$(decide_state "$prev_state" "$slice_file")
    rm -f "$slice_file"

    echo "$cur_size" >"$OFFSET_FILE"
    echo "$new_state" >"$WATCH_STATE_FILE"

    if [ -f "$SAVED_ROUTES_FILE" ]; then
        already_lifted=1
    else
        already_lifted=0
    fi

    case "$new_state" in
        STARTED)
            if [ "$already_lifted" = 0 ]; then
                if do_lift; then
                    [ -f "$SAVED_ROUTES_FILE" ] && already_lifted=1
                fi
            else
                log "connect-start pending; routes already lifted, will wait for completion"
            fi
            [ "$already_lifted" = 1 ] && wait_for_completion_then_restore
            ;;
        IDLE)
            if [ "$already_lifted" = 1 ]; then
                log "completion/idle observed while routes were still lifted; restoring now"
                do_restore
            else
                log "no active corporate-VPN connect; nothing to do"
            fi
            ;;
    esac
}

# --- --status ---
if [ "$STATUS" = 1 ]; then
    echo "=== route-lift-watcher status ==="
    echo "Config: ${CONFIG_DIR:-$CONF_FILE}"
    echo "State dir: $STATE_DIR"
    if [ -f "$SAVED_ROUTES_FILE" ]; then
        age=$(age_seconds "$SAVED_ROUTES_FILE")
        lines=$(wc -l <"$SAVED_ROUTES_FILE" 2>/dev/null | tr -d ' ')
        echo "Routes lifted: YES"
        echo "Saved-routes file: $SAVED_ROUTES_FILE (age: ${age:-unknown}s, $lines routes)"
    else
        echo "Routes lifted: NO"
        echo "Saved-routes file: none ($SAVED_ROUTES_FILE)"
    fi
    echo
    echo "Last 10 log lines ($LOG_FILE):"
    if [ -r "$LOG_FILE" ]; then
        tail -10 "$LOG_FILE"
    else
        echo "  (no log yet, or not readable)"
    fi
    echo
    if launchctl print "system/$PLIST_LABEL" >/dev/null 2>&1; then
        echo "Daemon loaded: YES ($PLIST_LABEL)"
    else
        echo "Daemon loaded: NO ($PLIST_LABEL)"
    fi
    exit 0
fi

# --- --dry-run ---
if [ "$DRY_RUN" = 1 ]; then
    echo "=== route-lift-watcher: dry-run (touches nothing) ==="
    echo "Config: ${CONFIG_DIR:-$CONF_FILE}"
    echo "helpdesk.log: $HELPDESK_LOG"
    echo "State dir: $STATE_DIR"
    echo "Timeout: ${TIMEOUT}s"
    echo "Personal VPN prefix: $PERSONAL_TUNNEL_PREFIX"
    echo
    if [ ! -r "$HELPDESK_LOG" ]; then
        echo "DECISION: no action -- $HELPDESK_LOG is not readable."
        exit 0
    fi
    cur_size=$(wc -c <"$HELPDESK_LOG" 2>/dev/null | tr -d ' ')
    prev_offset=$(cat "$OFFSET_FILE" 2>/dev/null)
    case "$prev_offset" in ''|*[!0-9]*) prev_offset=0 ;; esac
    rotated=0
    if [ "$prev_offset" -gt "$cur_size" ]; then
        rotated=1
        prev_offset=0
    fi
    prev_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
    case "$prev_state" in STARTED|IDLE) ;; *) prev_state=IDLE ;; esac

    echo "Persisted offset: $prev_offset   Current file size: $cur_size bytes   New bytes: $((cur_size - prev_offset))"
    [ "$rotated" = 1 ] && echo "NOTE: persisted offset exceeded the file size -- log rotation detected, would reset offset to 0"
    echo "Persisted state: $prev_state"

    slice_file=$(mktemp)
    tail -c +"$((prev_offset + 1))" "$HELPDESK_LOG" >"$slice_file" 2>/dev/null
    start_line=$(grep -n -E 'Starting connect|Starting new connection' "$slice_file" | tail -1)
    done_line=$(grep -n -E 'Connection was successfully established|Site is not responding|User cancelled the connection|Disconnect initiated by user' "$slice_file" | tail -1)
    new_state=$(decide_state "$prev_state" "$slice_file")
    rm -f "$slice_file"

    echo "Most recent connect-start line in the new bytes: ${start_line:-<none>}"
    echo "Most recent completion/terminal line in the new bytes: ${done_line:-<none>}"
    echo
    if [ -f "$SAVED_ROUTES_FILE" ]; then
        echo "Routes currently lifted: YES ($SAVED_ROUTES_FILE)"
    else
        echo "Routes currently lifted: NO"
    fi
    echo
    case "$new_state" in
        STARTED) echo "DECISION: would lift the personal VPN's routes (a corporate-VPN connect looks to be in progress)." ;;
        IDLE)    echo "DECISION: no action -- no corporate-VPN connect currently in progress." ;;
    esac
    echo "(offset/state files NOT written; nothing lifted, deleted, or restored -- this is a preview only.)"
    exit 0
fi

# --- live path (WatchPaths / StartInterval invocation) ---
mkdir -p "$STATE_DIR"
if ! acquire_lock; then
    log "lock held by an active instance ($LOCK_DIR); exiting without action"
    exit 0
fi
LOCK_HELD=1
trap 'cleanup_and_exit' EXIT
trap 'cleanup_and_exit; exit 130' INT
trap 'cleanup_and_exit; exit 143' TERM

if run_safety_net_check; then
    run_decision_cycle
else
    log "safety-net acted this invocation; skipping the normal decision cycle until the next trigger"
fi

exit 0
