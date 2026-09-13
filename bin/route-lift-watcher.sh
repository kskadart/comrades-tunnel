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
# Trigger mode (LIFT_TRIGGER / --trigger): "connect-start" (default) fires
# on the connect-start line itself, as described above -- reliable, but
# keeps routes lifted for the ~15-35s Check Point spends on ClientHello,
# topology download, and the firewall-policy step before the expensive
# route-conflict scan even begins (see README's measured timeline).
# "pre-scan" instead waits for the last marker before that scan, "no need
# executing firewall step" in the same helpdesk.log, and only counts it if
# a connect-start was seen earlier with no completion since -- so an
# isolated, unrelated occurrence of that line can never fire it. This
# shrinks the disruption window to roughly the scan's own duration, but is
# a tighter race: if this watcher is slow to react, Check Point may start
# the scan before routes are actually lifted, and the connect is then just
# as slow as if this watcher did not exist (a missed optimisation, not a
# breakage -- see README). decide_state() below tracks a third, transient
# CONNECTING state for "pre-scan" between the two markers; --self-test
# exercises both modes.
#
# Route save/normalise/delete/restore/verify logic is shared with
# cp-connect.sh via lib-routes.sh (see that file's header for the exact
# global-variable contract); this script sets the same globals cp-connect.sh
# does before calling into it. It also shares that file's compute_keep_set,
# which excludes routes to configured LLM-API-style endpoints
# (config/example/keep-routes-for.txt) from both the save and the delete
# step, so an already-open connection to one of them is never disrupted by
# a lift at all -- see that file and the README for why, and the fail-safe
# rule if the keep-set cannot be computed.
#
# Every completed cycle logs how long the routes were actually gone
# (seconds from when they were saved -- immediately before deletion began
# -- to when the restore was verified, via the saved-routes file's own
# mtime and age_seconds()); the same figure for the most recent cycle is
# persisted under STATE_DIR and shown by --status, since that is the
# number that determines whether a long-lived streaming connection through
# the personal VPN survived the stall (see README).
#
# Pause switch (--pause [MINUTES] / --resume): for a long-running job not
# covered by the keep-routes list above, a human can suppress the normal
# lift decision for a bounded time. This is a plain file, PAUSE_FILE,
# holding an absolute expiry (epoch seconds); pause_state() below reads it
# and never writes it, so a missing/corrupt/expired file always reads as
# "not paused" -- there is no code path that can manufacture an indefinite
# pause. --pause with no MINUTES defaults to 60, capped at 480 (8h); the
# expiry is always printed by --pause and by --status. A pause only
# suppresses run_decision_cycle's own lift/restore ACTION (see the top of
# that check inside the function) -- it still advances the offset/state
# files every cycle, specifically so that once the pause expires this
# resumes from "now" instead of folding a whole pause window's backlog
# into one slice (a burst of catch-up decisions); and it never touches
# run_safety_net_check, which restores any already-lifted routes
# regardless of a pause (see that function's own comment) -- leaving the
# personal VPN's routes lifted is never acceptable, paused or not. While
# paused, an automatic corporate-VPN reconnect is simply not sped up: it
# is just as slow as if this watcher were not installed.
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
#     than were saved (plus kept) -- this is what self-heals a crash
#     between delete and restore, independent of the trap above (which
#     only fires for the process that actually did the deleting), and
#     independent of a pause (see above).
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
#     helpdesk.log unreadable, PERSONAL_TUNNEL_PREFIX unset, or a
#     configured keep-set that cannot be computed -- log why and do
#     nothing, never guess.
#
# Usage: route-lift-watcher.sh [--config DIR] [--timeout N]
#                               [--trigger connect-start|pre-scan]
#                               [--dry-run] [--status] [--self-test]
#                               [--pause [MINUTES]] [--resume]
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
TRIGGER_FLAG=""
DRY_RUN=0
STATUS=0
SELF_TEST=0
PAUSE_FLAG=0
PAUSE_MINUTES=""
RESUME_FLAG=0

PLIST_LABEL="dev.comrades-tunnel.route-lift"
LOG_FILE="/var/log/comrades-tunnel-route-lift.log"
HELPDESK_LOG_DEFAULT="/Library/Application Support/Checkpoint/Endpoint Connect/helpdesk.log"
PAUSE_DEFAULT_MINUTES=60
PAUSE_MAX_MINUTES=480   # 8h -- a pause must always auto-expire, never be indefinite

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
        --trigger)
            TRIGGER_FLAG=$2
            shift 2
            ;;
        --trigger=*)
            TRIGGER_FLAG=${1#--trigger=}
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
        --pause)
            PAUSE_FLAG=1
            case "${2:-}" in
                ''|-*) ;;              # no value, or the next token is another flag
                *[!0-9]*) ;;           # not a plain integer -- leave it for normal parsing
                *) PAUSE_MINUTES=$2; shift ;;
            esac
            shift
            ;;
        --pause=*)
            PAUSE_FLAG=1
            PAUSE_MINUTES=${1#--pause=}
            shift
            ;;
        --resume)
            RESUME_FLAG=1
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--timeout N] [--trigger connect-start|pre-scan] [--dry-run] [--status] [--self-test] [--pause [MINUTES]] [--resume]" >&2
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
    0)
        echo "ERROR: --timeout must be greater than 0, got '$TIMEOUT_FLAG'" >&2
        exit 2
        ;;
esac

case "$TRIGGER_FLAG" in
    ''|connect-start|pre-scan) ;;
    *)
        echo "ERROR: --trigger must be connect-start or pre-scan, got '$TRIGGER_FLAG'" >&2
        exit 2
        ;;
esac

if [ "$PAUSE_FLAG" = 1 ]; then
    [ -z "$PAUSE_MINUTES" ] && PAUSE_MINUTES=$PAUSE_DEFAULT_MINUTES
    case "$PAUSE_MINUTES" in
        ''|*[!0-9]*)
            echo "ERROR: --pause minutes must be a positive integer, got '$PAUSE_MINUTES'" >&2
            exit 2
            ;;
    esac
    if [ "$PAUSE_MINUTES" -le 0 ]; then
        echo "ERROR: --pause minutes must be a positive integer, got '$PAUSE_MINUTES'" >&2
        exit 2
    fi
    if [ "$PAUSE_MINUTES" -gt "$PAUSE_MAX_MINUTES" ]; then
        echo "NOTE: --pause $PAUSE_MINUTES exceeds the ${PAUSE_MAX_MINUTES}-minute (8h) cap; using $PAUSE_MAX_MINUTES." >&2
        PAUSE_MINUTES=$PAUSE_MAX_MINUTES
    fi
fi

# decide_state INITIAL FILE TRIGGER -- given the current persisted INITIAL
# state ("STARTED", "CONNECTING", or "IDLE") and a FILE containing zero or
# more new log lines (either the newly-appended slice of helpdesk.log, or a
# whole synthetic excerpt for --self-test), replay every matching line in
# FILE, in order, folding it into a running state, and return the result.
# TRIGGER selects which event actually means "start lifting":
#   connect-start (default) -- a connect-start line ("Starting connect" or
#     "Starting new connection") sets STARTED directly, exactly as before
#     LIFT_TRIGGER existed; the narrower "no need executing firewall step"
#     marker is never consulted.
#   pre-scan -- a connect-start line sets the transient CONNECTING state
#     (seen, not yet lifting); only "no need executing firewall step",
#     seen *while* CONNECTING, promotes it to STARTED. That marker seen
#     from IDLE (no connect-start first) is an unrelated occurrence and is
#     ignored -- this is the gating the header/README promise: pre-scan
#     can never fire without a connect-start first.
# Either way, a completion/terminal line (successful connect, "Site is not
# responding", user-cancelled, user-disconnected) always sets IDLE,
# regardless of TRIGGER. If FILE matches nothing at all, INITIAL is
# returned unchanged -- this is why "Interface change", "Trying to
# reconnect", "Reconnect finished successfully", and "Policy changed,
# restarting connection" never affect the result: they match no pattern
# here in any mode.
decide_state() {
    initial=$1
    file=$2
    trigger=${3:-connect-start}
    state=$initial
    # "Site is not responding" alone can also appear as a transient
    # tunnel-drop message while a connection is otherwise still active/in
    # progress, not only as part of the real terminal IKE failure -- ending
    # the window (IDLE) on the bare phrase risks restoring the personal
    # VPN's routes mid-reconnect. Only the compound IKE-failure form (as
    # observed live, both fragments on the same helpdesk.log line) is
    # treated as terminal.
    matched=$(grep -n -E 'Starting connect|Starting new connection|no need executing firewall step|Connection was successfully established|IKE connection failed.*Site is not responding|User cancelled the connection|Disconnect initiated by user' "$file" 2>/dev/null)
    if [ -z "$matched" ]; then
        printf '%s\n' "$state"
        return 0
    fi
    oldifs=$IFS
    IFS='
'
    set -f   # a log line containing a glob metacharacter must never be pathname-expanded
    for line in $matched; do
        case "$line" in
            *'no need executing firewall step'*)
                [ "$state" = "CONNECTING" ] && state=STARTED
                ;;
            *'Starting connect'*|*'Starting new connection'*)
                if [ "$trigger" = "pre-scan" ]; then
                    state=CONNECTING
                else
                    state=STARTED
                fi
                ;;
            *)
                state=IDLE
                ;;
        esac
    done
    set +f
    IFS=$oldifs
    printf '%s\n' "$state"
}

# pause_state FILE -- print 0 if FILE is absent, empty, non-numeric, or its
# recorded expiry (absolute epoch seconds) is not in the future; otherwise
# print that expiry. Never writes FILE. A pause can only ever collapse back
# to "not paused" here -- there is no path that manufactures an indefinite
# one.
pause_state() {
    pfile=$1
    [ -f "$pfile" ] || { echo 0; return 0; }
    expiry=$(cat "$pfile" 2>/dev/null)
    case "$expiry" in
        ''|*[!0-9]*) echo 0; return 0 ;;
    esac
    now=$(date +%s)
    if [ "$expiry" -gt "$now" ]; then
        echo "$expiry"
    else
        echo 0
    fi
}

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
    if ! { printf '%s\n' "$line" >>"$LOG_FILE"; } 2>/dev/null; then
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

# resolve_offset CUR_SIZE [DRY] -- read OFFSET_FILE/OFFSET_INODE_FILE
# against the current HELPDESK_LOG (whose size the caller has already read
# as CUR_SIZE) and print "OFFSET SKIP_CYCLE REASON":
#   - OFFSET_FILE missing entirely (this watcher has never processed this
#     log before -- a fresh install, or STATE_DIR wiped): OFFSET is
#     CUR_SIZE and SKIP_CYCLE is 1, REASON is "first_run" -- never replay a
#     log's entire pre-existing history as if it just happened now (a
#     "Starting new connection" from days ago must not be mistaken for one
#     happening this tick).
#   - the persisted offset now exceeds CUR_SIZE (truncation): OFFSET is 0,
#     SKIP_CYCLE 0, REASON "truncated".
#   - HELPDESK_LOG's inode differs from the one last recorded (a
#     rename-based rotation -- old file renamed away, new empty-or-partial
#     file created at the same path): OFFSET is 0, SKIP_CYCLE 0, REASON
#     "inode_changed". This catches a rotation the size check alone would
#     miss whenever the new file already happens to be at least as large as
#     the old persisted offset.
#   - otherwise: OFFSET is the persisted offset unchanged, SKIP_CYCLE 0,
#     REASON "none".
# With DRY=1 (used only by the --dry-run preview), nothing is written or
# logged -- this is a preview, and must touch nothing on disk.
resolve_offset() {
    cur_size=$1
    dry=${2:-0}
    had_offset_file=0
    [ -f "$OFFSET_FILE" ] && had_offset_file=1
    prev_offset=$(cat "$OFFSET_FILE" 2>/dev/null)
    case "$prev_offset" in ''|*[!0-9]*) prev_offset=0 ;; esac
    prev_inode=$(cat "$OFFSET_INODE_FILE" 2>/dev/null)
    case "$prev_inode" in ''|*[!0-9]*) prev_inode=0 ;; esac
    cur_inode=$(stat -f '%i' "$HELPDESK_LOG" 2>/dev/null)
    case "$cur_inode" in ''|*[!0-9]*) cur_inode=0 ;; esac
    [ "$dry" = 1 ] || echo "$cur_inode" >"$OFFSET_INODE_FILE" 2>/dev/null

    if [ "$had_offset_file" = 0 ]; then
        [ "$dry" = 1 ] || log "no persisted offset for $HELPDESK_LOG yet (first run against this log); seeding at the current size ($cur_size bytes) and taking no action this cycle"
        printf '%s %s %s\n' "$cur_size" 1 first_run
        return 0
    fi
    if [ "$prev_offset" -gt "$cur_size" ] 2>/dev/null; then
        [ "$dry" = 1 ] || log "helpdesk.log appears to have been truncated/rotated (offset $prev_offset > size $cur_size); resetting offset to 0"
        printf '%s %s %s\n' 0 0 truncated
        return 0
    fi
    if [ "$cur_inode" != 0 ] && [ "$prev_inode" != 0 ] && [ "$cur_inode" != "$prev_inode" ]; then
        [ "$dry" = 1 ] || log "helpdesk.log's inode changed ($prev_inode -> $cur_inode; a rename-based rotation) -- resetting offset to 0"
        printf '%s %s %s\n' 0 0 inode_changed
        return 0
    fi
    printf '%s %s %s\n' "$prev_offset" 0 none
}

# do_restore -- restore_saved_routes + verify_restore (from lib-routes.sh),
# then clear SAVED_ROUTES_FILE/KEPT_ROUTES_FILE only if both succeeded. See
# the header comment above for why this differs from cp-connect.sh (which
# always leaves the file in place): here, file presence must mean "still
# lifted". On success also logs and persists (LAST_LIFT_FILE, read by
# --status) how long the routes were actually gone: SAVED_ROUTES_FILE's own
# mtime is set by save_amnezia_routes immediately before do_lift deletes
# anything, so age_seconds() here is a fair (very slightly conservative)
# measure of the delete-to-verified-restore window.
do_restore() {
    RESTORE_DONE=1
    log "restoring saved routes from $SAVED_ROUTES_FILE"
    RESTORE_HAD_FAILURES=0
    RESTORE_VERIFY_FAILED=0
    restore_saved_routes
    verify_restore
    if [ "$RESTORE_HAD_FAILURES" = 0 ] && [ "$RESTORE_VERIFY_FAILED" = 0 ]; then
        lifted_seconds=$(age_seconds "$SAVED_ROUTES_FILE")
        rm -f "$SAVED_ROUTES_FILE" "$KEPT_ROUTES_FILE"
        log "restore verified; cleared $SAVED_ROUTES_FILE"
        log "lift duration: routes were unavailable for ${lifted_seconds:-unknown}s (from save/delete to verified restore)"
        printf '%s\n' "${lifted_seconds:-unknown}" >"$LAST_LIFT_FILE" 2>/dev/null
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
        rm -f "$LOCK_DIR/pid" 2>/dev/null
        rmdir "$LOCK_DIR" 2>/dev/null
        LOCK_HELD=0
    fi
}

cleanup_and_exit() {
    restore_if_needed
    release_lock_if_held
}

# acquire_lock -- mkdir-based single-instance lock, POSIX, no bashisms.
# Returns 0 holding the lock, 1 if another live instance holds it.
#
# A lock's true owner is the pid recorded in it, not its age: a normal
# lift+wait cycle can legitimately run for a good while longer than TIMEOUT
# (do_lift itself takes a few seconds, then wait_for_completion_then_restore
# polls for up to TIMEOUT more on top of that) -- an age-only rule can break
# a lock the first instance still legitimately holds, and race it while it
# is mid-restore (a second instance's safety net could then rm the saved
# file the first instance's own trap still needs). Break a lock only when
# its recorded pid is provably dead (`kill -0` fails); fall back to the old
# age rule only when the lock predates this fix and has no pid file at all.
acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ >"$LOCK_DIR/pid" 2>/dev/null
        return 0
    fi
    lock_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    case "$lock_pid" in
        ''|*[!0-9]*)
            lock_age=$(age_seconds "$LOCK_DIR")
            if [ -n "$lock_age" ] && [ "$lock_age" -gt "$TIMEOUT" ]; then
                log "WARNING: breaking stale lock at $LOCK_DIR (no pid recorded, age ${lock_age}s > timeout ${TIMEOUT}s) -- presumed to belong to a dead/pre-fix process"
                rm -f "$LOCK_DIR/pid" 2>/dev/null
                rmdir "$LOCK_DIR" 2>/dev/null
                if mkdir "$LOCK_DIR" 2>/dev/null; then
                    echo $$ >"$LOCK_DIR/pid" 2>/dev/null
                    return 0
                fi
            fi
            ;;
        *)
            if kill -0 "$lock_pid" 2>/dev/null; then
                return 1   # owner is alive -- never break this lock, regardless of age
            fi
            log "WARNING: breaking stale lock at $LOCK_DIR (owner pid $lock_pid is dead)"
            rm -f "$LOCK_DIR/pid" 2>/dev/null
            rmdir "$LOCK_DIR" 2>/dev/null
            if mkdir "$LOCK_DIR" 2>/dev/null; then
                echo $$ >"$LOCK_DIR/pid" 2>/dev/null
                return 0
            fi
            ;;
    esac
    return 1
}

# do_lift -- enumerate routes on the personal VPN's utun, save them, verify
# the saved file is non-empty and its line count matches the enumeration
# taken just before saving, then run compute_keep_set (lib-routes.sh) to
# exclude any configured keep-routes-for.txt entries from that saved file
# before ever deleting anything. Never deletes anything it has not first
# verified it saved, and never deletes anything at all if the keep-set
# could not be computed (fail-safe -- see compute_keep_set's own comment
# and the README).
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

    cks_err="$STATE_DIR/.compute-keep-set-stderr.$$"
    if compute_keep_set "$SAVED_ROUTES_FILE" 2>"$cks_err"; then
        cks_rc=0
    else
        cks_rc=1
    fi
    if [ -s "$cks_err" ]; then
        while IFS= read -r kline; do log "$kline"; done <"$cks_err"
    fi
    rm -f "$cks_err"
    if [ "$cks_rc" -ne 0 ]; then
        log "ERROR: keep-set could not be computed from $KEEP_ROUTES_FILE (see above); fail-safe -- NOT lifting any routes this cycle"
        rm -f "$SAVED_ROUTES_FILE" "$KEPT_ROUTES_FILE"
        return 1
    fi
    kept_lines=$(wc -l <"$KEPT_ROUTES_FILE" 2>/dev/null | tr -d ' ')
    [ -z "$kept_lines" ] && kept_lines=0
    if [ "$kept_lines" -gt 0 ]; then
        log "keeping $kept_lines route(s) from $personal_utun per $KEEP_ROUTES_FILE:"
        while IFS= read -r kline; do log "  kept: $kline"; done <"$KEPT_ROUTES_FILE"
    fi

    to_delete=$(wc -l <"$SAVED_ROUTES_FILE" 2>/dev/null | tr -d ' ')
    log "saved $saved_lines routes from $personal_utun to $SAVED_ROUTES_FILE (verified against $enumerated enumerated; $kept_lines kept, $to_delete to delete); deleting them now"
    delete_amnezia_routes "$personal_utun" | while IFS= read -r dline; do log "$dline"; done
    log "lifted (deleted) $to_delete routes from $personal_utun"
    return 0
}

# wait_for_completion_then_restore -- poll helpdesk.log every 2s, up to
# TIMEOUT seconds, advancing the same offset/state files the main decision
# cycle uses, until a completion/terminal line is seen or the timeout
# elapses; then restore unconditionally either way.
wait_for_completion_then_restore() {
    start_ts=$(date +%s)
    while :; do
        # Defense in depth alongside acquire_lock's pid check: keep the
        # lock directory's own mtime fresh for the whole time this instance
        # legitimately holds it, in case LOCK_DIR/pid is ever missing (e.g.
        # a lock from before that fix) and a peer instance falls back to
        # the age-only rule.
        [ "${LOCK_HELD:-0}" = 1 ] && touch "${LOCK_DIR:-}" 2>/dev/null
        cur_size=$(wc -c <"$HELPDESK_LOG" 2>/dev/null | tr -d ' ')
        if [ -n "$cur_size" ]; then
            set -- $(resolve_offset "$cur_size")
            prev_offset=$1
            skip_cycle=$2
            if [ "$skip_cycle" = 1 ]; then
                echo "$cur_size" >"$OFFSET_FILE"
            elif [ "$cur_size" -gt "$prev_offset" ]; then
                slice_file="$STATE_DIR/.slice.$$"
                tail -c +"$((prev_offset + 1))" "$HELPDESK_LOG" >"$slice_file" 2>/dev/null
                prev_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
                case "$prev_state" in STARTED|IDLE|CONNECTING) ;; *) prev_state=STARTED ;; esac
                new_state=$(decide_state "$prev_state" "$slice_file" "$TRIGGER")
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
            # Must happen BEFORE do_restore: leaving WATCH_STATE_FILE at
            # STARTED here means the next tick, over an unchanged log,
            # replays STARTED forever -- do_lift fires again every single
            # tick even though the routes were already lifted-and-restored
            # once. Writing IDLE now is what actually ends this cycle.
            echo IDLE >"$WATCH_STATE_FILE"
            do_restore
            return 0
        fi
        sleep 2
    done
}

# run_safety_net_check -- the independent backstop meant to run on every
# StartInterval tick (which, in this design, is just a normal invocation of
# this script -- see header). Returns 1 (and has already restored) if it
# decided a real restore was needed and ran one; 0 otherwise, including
# every "nothing to check" / "not old enough yet" / "utun missing" case,
# and the case where the saved-routes marker is stale but the routes are
# demonstrably already back (cleared, but nothing was restored -- see
# below), so the normal decision cycle is safe to run in the same tick.
#
# Deliberately independent of the pause switch (--pause/PAUSE_FILE, see
# pause_state() and the top of run_decision_cycle's action check): a pause
# only ever suppresses starting a *new* lift, never restoring one that
# already happened. This function does not read PAUSE_FILE at all, so a
# pause can never leave routes lifted past TIMEOUT.
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
    kept_count=0
    [ -f "$KEPT_ROUTES_FILE" ] && kept_count=$(wc -l <"$KEPT_ROUTES_FILE" 2>/dev/null | tr -d ' ')
    [ -z "$kept_count" ] && kept_count=0
    expected_count=$((saved_count + kept_count))
    now_count=$(routes_on_iface "$personal_utun")
    if [ "$now_count" -lt "$expected_count" ] 2>/dev/null; then
        log "SAFETY-NET: saved-routes file is ${saved_age}s old (> ${TIMEOUT}s) and $personal_utun has $now_count/$expected_count routes ($saved_count saved + $kept_count kept) -- restoring unconditionally"
        do_restore
        return 1
    fi
    if [ "$now_count" -ge "$expected_count" ] 2>/dev/null; then
        # The "still lifted" marker is stale, but $personal_utun already
        # has every route it should -- normal restore succeeded and this
        # is a leftover marker (e.g. a crash between restore succeeding and
        # the cleanup that follows it), or nothing was ever actually
        # missing. Clear it instead of leaving it to wedge the daemon
        # forever: every future tick would otherwise re-run a full,
        # permanently-failing restore attempt against routes that are
        # already there.
        log "SAFETY-NET: saved-routes file is ${saved_age}s old (> ${TIMEOUT}s) but $personal_utun already has $now_count/$expected_count routes ($saved_count saved + $kept_count kept) -- routes are demonstrably back; clearing the stale marker"
        rm -f "$SAVED_ROUTES_FILE" "$KEPT_ROUTES_FILE"
        return 0
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
    mkdir -p "$STATE_DIR"
    set -- $(resolve_offset "$cur_size")
    prev_offset=$1
    skip_cycle=$2
    if [ "$skip_cycle" = 1 ]; then
        echo "$cur_size" >"$OFFSET_FILE"
        return 0
    fi
    prev_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
    case "$prev_state" in STARTED|IDLE|CONNECTING) ;; *) prev_state=IDLE ;; esac

    slice_file="$STATE_DIR/.slice.$$"
    tail -c +"$((prev_offset + 1))" "$HELPDESK_LOG" >"$slice_file" 2>/dev/null
    new_state=$(decide_state "$prev_state" "$slice_file" "$TRIGGER")
    rm -f "$slice_file"

    echo "$cur_size" >"$OFFSET_FILE"
    echo "$new_state" >"$WATCH_STATE_FILE"

    # A pause suppresses only the lift/restore ACTION below -- the offset
    # and state files above are still advanced every cycle, specifically so
    # that once the pause expires this resumes from "now" instead of
    # folding a whole pause window's backlog into one slice (a burst of
    # catch-up decisions). run_safety_net_check (called by our caller
    # before this function ever runs) is entirely separate from this check
    # and always runs regardless of pause -- see its own comment.
    pause_expiry=$(pause_state "$PAUSE_FILE")
    if [ "$pause_expiry" != 0 ]; then
        paused_until=$(date -r "$pause_expiry" '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)
        log "paused until ${paused_until:-$pause_expiry} ($PAUSE_FILE); recorded state ($new_state) but taking no lift/restore action"
        return 0
    fi

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
        CONNECTING)
            if [ "$already_lifted" = 1 ]; then
                log "connect-start observed while routes were already lifted; continuing to wait for completion"
                wait_for_completion_then_restore
            else
                log "connect-start seen (pre-scan trigger); waiting for the pre-scan marker before lifting"
            fi
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

# run_self_test: exercise decide_state against a fixed table of synthetic
# helpdesk.log excerpts (both LIFT_TRIGGER modes), pause_state() against
# future/past/missing expiries, the pause switch's effect (and non-effect
# on the offset/state bookkeeping) inside run_decision_cycle, the
# independence of run_safety_net_check from an active pause, and
# keep-routes.py's own --self-test. PASS/FAIL per case; non-zero exit on
# any failure. Independent of any config directory or the real log/state
# dir -- everything here uses its own temp files.
run_self_test() {
    fail=0
    tmpfile=$(mktemp) || { echo "FAIL  could not create a temp file for self-test" >&2; return 1; }
    trap 'rm -f "$tmpfile"' EXIT

    test_case() {
        desc=$1
        initial=$2
        content=$3
        expected=$4
        trigger=${5:-connect-start}
        printf '%s' "$content" >"$tmpfile"
        actual=$(decide_state "$initial" "$tmpfile" "$trigger")
        if [ "$actual" = "$expected" ]; then
            echo "PASS  [$trigger] $desc -> $actual"
        else
            echo "FAIL  [$trigger] $desc -> $actual (expected $expected)"
            fail=1
        fi
    }

    # --- connect-start trigger (default): the original six cases ---
    test_case "fresh 'Starting new connection', no completion yet (trigger)" "IDLE" \
"[11 Sep 14:47:38] Starting new connection (0x9)
" "STARTED" connect-start

    test_case "same, followed by 'Connection was successfully established' (no trigger)" "IDLE" \
"[11 Sep 14:47:38] Starting new connection (0x9)
[11 Sep 14:47:52] Connection was successfully established (0x9)
" "IDLE" connect-start

    test_case "'Interface change'/'Reconnect finished successfully' pair alone (no trigger)" "IDLE" \
"[11 Sep  1:50:59] Interface change - location is OUT, trying to reconnect
[11 Sep  1:51:00] Reconnect finished successfully (0x9)
" "IDLE" connect-start

    test_case "'Policy changed, restarting connection' alone (no trigger)" "IDLE" \
"[10 Sep 11:28:39] Policy changed, restarting connection (0x9)
" "IDLE" connect-start

    test_case "connect-start followed by the IKE-failure form of 'Site is not responding' (terminal, no trigger)" "IDLE" \
"[11 Sep  0:58:11] Starting connect...
[11 Sep  1:00:57] IKE connection failed, error code=-1000. Reason: Site is not responding.
" "IDLE" connect-start

    # Finding 15: a BARE "Site is not responding" (no "IKE connection
    # failed" prefix) is a transient tunnel-drop message, not the terminal
    # form -- it must never end the window (state must stay STARTED here,
    # i.e. this line matches nothing at all).
    test_case "[finding 15] bare 'Site is not responding' WITHOUT the IKE-failure prefix does not end the window" "STARTED" \
"[11 Sep  1:05:00] Site is not responding
" "STARTED" connect-start

    test_case "empty/unchanged tail (no trigger)" "IDLE" "" "IDLE" connect-start

    # --- pre-scan trigger: the narrower window (see README) ---
    test_case "connect-start then pre-scan marker (trigger)" "IDLE" \
"[11 Sep 11:23:28] Starting new connection (0x9)
[11 Sep 11:23:44] no need executing firewall step
" "STARTED" pre-scan

    test_case "pre-scan marker with NO preceding connect-start (no trigger -- unrelated occurrence)" "IDLE" \
"[11 Sep 11:23:44] no need executing firewall step
" "IDLE" pre-scan

    test_case "connect-start alone, no pre-scan marker yet (no trigger under pre-scan -- still waiting)" "IDLE" \
"[11 Sep 11:23:28] Starting new connection (0x9)
" "CONNECTING" pre-scan

    test_case "same connect-start-alone input, but under connect-start trigger (trigger)" "IDLE" \
"[11 Sep 11:23:28] Starting new connection (0x9)
" "STARTED" connect-start

    # --- pause switch: pause_state() is a pure function of the pause
    # file's content and the current time; it never writes the file.
    pause_tmp=$(mktemp -d) || { echo "FAIL  could not create a temp dir for pause self-test" >&2; fail=1; pause_tmp=""; }
    if [ -n "$pause_tmp" ]; then
        future_file="$pause_tmp/future"
        past_file="$pause_tmp/past"
        echo $(( $(date +%s) + 3600 )) >"$future_file"
        echo $(( $(date +%s) - 10 )) >"$past_file"

        result=$(pause_state "$future_file")
        if [ "$result" != 0 ]; then
            echo "PASS  pause_state: future expiry -> active (expiry=$result)"
        else
            echo "FAIL  pause_state: future expiry -> $result (expected a nonzero epoch)"
            fail=1
        fi

        result=$(pause_state "$past_file")
        if [ "$result" = 0 ]; then
            echo "PASS  pause_state: past expiry -> not paused (treated as expired)"
        else
            echo "FAIL  pause_state: past expiry -> $result (expected 0 / not paused)"
            fail=1
        fi

        result=$(pause_state "$pause_tmp/does-not-exist")
        if [ "$result" = 0 ]; then
            echo "PASS  pause_state: missing file -> not paused"
        else
            echo "FAIL  pause_state: missing file -> $result (expected 0)"
            fail=1
        fi

        # Integration: a future pause must stop run_decision_cycle's own
        # lift/restore action even though the log alone says a connect just
        # started (decide_state would return STARTED) -- but it must still
        # advance the offset/state bookkeeping (see the comment at the top
        # of that check inside run_decision_cycle). PERSONAL_TUNNEL_PREFIX
        # below is TEST-NET-3 (RFC 5737), guaranteed not to match any real
        # utun, so even if this bug existed and do_lift ran for real, it
        # would stop at its own "no personal VPN utun found" fail-safe
        # without ever touching a route.
        cycle_dir="$pause_tmp/cycle"
        mkdir -p "$cycle_dir"
        STATE_DIR="$cycle_dir"
        SAVED_ROUTES_FILE="$cycle_dir/saved-routes.txt"
        KEPT_ROUTES_FILE="$cycle_dir/kept-routes.txt"
        OFFSET_FILE="$cycle_dir/offset"
        OFFSET_INODE_FILE="$cycle_dir/offset-inode"
        WATCH_STATE_FILE="$cycle_dir/state"
        LOG_FILE="$cycle_dir/log"
        LAST_LIFT_FILE="$cycle_dir/last-lift"
        PAUSE_FILE="$future_file"
        HELPDESK_LOG="$cycle_dir/helpdesk.log"
        PERSONAL_TUNNEL_PREFIX="203.0.113."
        KEEP_ROUTES_FILE="$cycle_dir/keep-routes-for.txt"
        TIMEOUT=240
        DRY_RUN=0
        TRIGGER=connect-start
        printf '%s\n' "[11 Sep 10:00:00] Starting new connection (0x9)" >"$HELPDESK_LOG"
        # Seed the offset state as though this log has already been watched
        # from byte 0 (not a first-ever run -- see finding 13/resolve_offset,
        # which deliberately skips all action on a genuinely first-ever run,
        # a scenario this particular test is not exercising).
        echo 0 >"$OFFSET_FILE"
        stat -f '%i' "$HELPDESK_LOG" >"$OFFSET_INODE_FILE" 2>/dev/null

        run_decision_cycle
        cycle_log=$(cat "$LOG_FILE" 2>/dev/null)
        watch_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
        case "$cycle_log" in
            *paused*)
                if [ "$watch_state" = "STARTED" ] && [ ! -f "$SAVED_ROUTES_FILE" ]; then
                    echo "PASS  paused (future expiry): connect-start logged but no lift attempted, state still advanced to STARTED"
                else
                    saved_exists=no
                    [ -f "$SAVED_ROUTES_FILE" ] && saved_exists=yes
                    echo "FAIL  paused (future expiry): unexpected watch_state='$watch_state' saved_routes_exists=$saved_exists"
                    fail=1
                fi
                ;;
            *)
                echo "FAIL  paused (future expiry): run_decision_cycle did not log a paused message; log was: $cycle_log"
                fail=1
                ;;
        esac

        # Safety net independence: an active pause must not change the
        # decision run_safety_net_check reaches for an old saved-routes
        # file. PERSONAL_TUNNEL_PREFIX above never matches a real utun, so
        # this stops at "cannot verify or restore" without ever touching a
        # route -- compare that outcome with and without a pause file
        # present alongside the same saved-routes file.
        net_dir="$pause_tmp/net"
        mkdir -p "$net_dir"
        STATE_DIR="$net_dir"
        SAVED_ROUTES_FILE="$net_dir/saved-routes.txt"
        KEPT_ROUTES_FILE="$net_dir/kept-routes.txt"
        LOG_FILE="$net_dir/log"
        printf '203.0.113.5/32 utun9\n' >"$SAVED_ROUTES_FILE"
        touch -t 202001010000 "$SAVED_ROUTES_FILE"
        TIMEOUT=0

        PAUSE_FILE="$net_dir/paused-until"
        rm -f "$PAUSE_FILE" "$LOG_FILE"
        run_safety_net_check
        rc_nopause=$?
        log_nopause=$(cat "$LOG_FILE" 2>/dev/null)

        echo $(( $(date +%s) + 3600 )) >"$PAUSE_FILE"
        rm -f "$LOG_FILE"
        run_safety_net_check
        rc_paused=$?
        log_paused=$(cat "$LOG_FILE" 2>/dev/null)

        if [ "$rc_nopause" = "$rc_paused" ] && [ "$log_nopause" = "$log_paused" ] && \
           printf '%s' "$log_paused" | grep -q "cannot verify or restore"; then
            echo "PASS  safety net with a saved-routes file present reaches the same restore-path decision whether or not a pause is active"
        else
            echo "FAIL  safety net pause independence: rc_nopause=$rc_nopause rc_paused=$rc_paused log_nopause='$log_nopause' log_paused='$log_paused'"
            fail=1
        fi

        rm -rf "$pause_tmp"
    fi

    # --- Finding 1: restore_saved_routes must never replay the utun name
    # recorded in SAVED_ROUTES_FILE -- it must re-detect the CURRENTLY live
    # personal-VPN interface and use that name for every entry, and must
    # refuse outright (never guess) when no such interface is present.
    # Subshell so the sudo/detect_utun_by_prefix overrides below never
    # leak, and so no real `route add` is ever invoked.
    if (
        f1_dir=$(mktemp -d) || exit 1
        trap 'rm -rf "$f1_dir"' EXIT
        f1_calls="$f1_dir/sudo-calls"
        : >"$f1_calls"
        sudo() { printf '%s\n' "$*" >>"$f1_calls"; return 0; }

        SAVED_ROUTES_FILE="$f1_dir/saved.txt"
        KEPT_ROUTES_FILE="$f1_dir/kept.txt"
        PERSONAL_TUNNEL_PREFIX="203.0.113."
        RESTORE_HAD_FAILURES=0
        RESTORE_VERIFY_FAILED=0
        printf '10.9.9.0/24 utun_stale_name\n' >"$SAVED_ROUTES_FILE"
        f1_fail=0

        # (a) the live interface differs from the saved name -- the saved
        # name must never appear in what gets executed.
        detect_utun_by_prefix() { echo "utun_live_name"; }
        restore_saved_routes >/dev/null
        if grep -q -- '-interface utun_live_name' "$f1_calls" && ! grep -q 'utun_stale_name' "$f1_calls"; then
            echo "PASS  [finding 1] restore_saved_routes replays onto the LIVE-detected utun, never the one saved"
        else
            echo "FAIL  [finding 1] sudo calls: $(cat "$f1_calls")"
            f1_fail=1
        fi

        # (b) no personal-VPN utun present at all -- must refuse, not guess.
        # Called directly (output redirected to a file, not captured via
        # "$(...)") so RESTORE_HAD_FAILURES -- set as a plain global inside
        # restore_saved_routes -- is visible here afterward; "$(...)" would
        # fork its own subshell and lose that write.
        : >"$f1_calls"
        RESTORE_HAD_FAILURES=0
        detect_utun_by_prefix() { return 1; }
        restore_saved_routes >"$f1_dir/out" 2>&1
        out=$(cat "$f1_dir/out")
        if [ ! -s "$f1_calls" ] && [ "$RESTORE_HAD_FAILURES" = 1 ] && printf '%s' "$out" | grep -q 'refusing to restore'; then
            echo "PASS  [finding 1] restore_saved_routes refuses (no route add attempted) when no live personal-VPN utun is present"
        else
            echo "FAIL  [finding 1] refusal case: RESTORE_HAD_FAILURES=$RESTORE_HAD_FAILURES sudo_calls='$(cat "$f1_calls")' out='$out'"
            f1_fail=1
        fi
        exit "$f1_fail"
    ); then
        :
    else
        fail=1
    fi

    # --- Finding 2: wait_for_completion_then_restore's timeout branch must
    # write IDLE to WATCH_STATE_FILE, or an unchanged log at the next tick
    # replays STARTED forever and do_lift fires on every tick (a permanent
    # re-lift loop). Subshell so the sudo/detect_utun_by_prefix/
    # routes_on_iface overrides below never leak -- SAVED_ROUTES_FILE etc.
    # here are throwaway temp files, never a real route or utun.
    if (
        f2_dir=$(mktemp -d) || exit 1
        trap 'rm -rf "$f2_dir"' EXIT
        detect_utun_by_prefix() { echo "utun42"; }
        routes_on_iface() { echo 1; }
        sudo() { return 0; }

        STATE_DIR="$f2_dir"
        SAVED_ROUTES_FILE="$f2_dir/saved-routes.txt"
        KEPT_ROUTES_FILE="$f2_dir/kept-routes.txt"
        OFFSET_FILE="$f2_dir/offset"
        OFFSET_INODE_FILE="$f2_dir/offset-inode"
        WATCH_STATE_FILE="$f2_dir/state"
        LOG_FILE="$f2_dir/log"
        LAST_LIFT_FILE="$f2_dir/last-lift"
        PAUSE_FILE="$f2_dir/paused-until"
        HELPDESK_LOG="$f2_dir/helpdesk.log"
        PERSONAL_TUNNEL_PREFIX="203.0.113."
        KEEP_ROUTES_FILE="$f2_dir/keep-routes-for.txt"
        TIMEOUT=0
        DRY_RUN=0
        TRIGGER=connect-start
        RESTORE_DONE=0
        f2_fail=0

        printf '%s\n' "[11 Sep 10:00:00] Starting new connection (0x9)" >"$HELPDESK_LOG"
        echo 0 >"$OFFSET_FILE"
        echo STARTED >"$WATCH_STATE_FILE"
        printf '10.77.0.0/24 utun42\n' >"$SAVED_ROUTES_FILE"

        wait_for_completion_then_restore >/dev/null

        watch_after=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
        if [ "$watch_after" = "IDLE" ] && [ ! -f "$SAVED_ROUTES_FILE" ]; then
            echo "PASS  [finding 2] timeout branch clears WATCH_STATE_FILE to IDLE and completes the restore"
        else
            saved_exists=no; [ -f "$SAVED_ROUTES_FILE" ] && saved_exists=yes
            echo "FAIL  [finding 2] timeout branch left state='$watch_after' saved_file_exists=$saved_exists"
            f2_fail=1
        fi

        # Second decision cycle, same (unchanged) log: must NOT lift again.
        rm -f "$LOG_FILE"
        run_decision_cycle >/dev/null
        if [ -f "$SAVED_ROUTES_FILE" ] || grep -q 'saved .* routes from' "$LOG_FILE" 2>/dev/null; then
            echo "FAIL  [finding 2] second decision cycle over an unchanged log lifted again"
            f2_fail=1
        else
            echo "PASS  [finding 2] second decision cycle over an unchanged log takes no lift action"
        fi
        exit "$f2_fail"
    ); then
        :
    else
        fail=1
    fi

    # --- Finding 3: acquire_lock must key off pid liveness, not just age.
    f3_dir=$(mktemp -d) || { echo "FAIL  [finding 3] could not create temp dir" >&2; fail=1; f3_dir=""; }
    if [ -n "$f3_dir" ]; then
        LOG_FILE="$f3_dir/log"
        TIMEOUT=0   # any age at all would look "stale" under the old age-only rule

        # A lock owned by a live process (this shell's own pid is alive)
        # must never be broken, no matter how old it looks.
        alive_lock="$f3_dir/lock-alive"
        mkdir "$alive_lock"
        echo $$ >"$alive_lock/pid"
        touch -t 202001010000 "$alive_lock"
        LOCK_DIR="$alive_lock"
        if acquire_lock; then
            echo "FAIL  [finding 3] acquire_lock broke a lock owned by a live pid ($$)"
            fail=1
        else
            echo "PASS  [finding 3] acquire_lock leaves a live-owned lock alone regardless of age"
        fi

        # A lock naming a pid that is certainly dead (spawned and already
        # waited on) must be broken and re-acquired even though a FRESH
        # mkdir (age 0) would have passed the old age-only check.
        ( exit 0 ) &
        dead_pid=$!
        wait "$dead_pid" 2>/dev/null
        dead_lock="$f3_dir/lock-dead"
        mkdir "$dead_lock"
        echo "$dead_pid" >"$dead_lock/pid"
        LOCK_DIR="$dead_lock"
        if acquire_lock && [ -f "$LOCK_DIR/pid" ] && [ "$(cat "$LOCK_DIR/pid")" = "$$" ]; then
            echo "PASS  [finding 3] acquire_lock breaks and re-acquires a lock whose owner pid is dead"
        else
            echo "FAIL  [finding 3] acquire_lock did not break/re-acquire a dead-pid lock"
            fail=1
        fi
        LOCK_HELD=1
        release_lock_if_held
        rm -rf "$f3_dir"
    fi

    # --- Finding 5(ii): run_safety_net_check must clear a stale
    # saved-routes marker once the personal VPN's routes are demonstrably
    # already back (now_count >= expected_count), instead of leaving the
    # "still lifted" marker in place forever (which would otherwise re-run
    # a full, permanently-failing restore attempt on every future tick).
    # Subshell so the detect_utun_by_prefix/routes_on_iface/sudo overrides
    # never leak.
    if (
        f5b_dir=$(mktemp -d) || exit 1
        trap 'rm -rf "$f5b_dir"' EXIT
        detect_utun_by_prefix() { echo "utun42"; }
        routes_on_iface() { echo 1; }   # "already back": matches expected_count below

        SAVED_ROUTES_FILE="$f5b_dir/saved.txt"
        KEPT_ROUTES_FILE="$f5b_dir/kept.txt"
        LOG_FILE="$f5b_dir/log"
        PERSONAL_TUNNEL_PREFIX="203.0.113."
        TIMEOUT=0
        f5b_fail=0

        printf '10.9.9.0/24 utun42\n' >"$SAVED_ROUTES_FILE"
        touch -t 202001010000 "$SAVED_ROUTES_FILE"

        run_safety_net_check
        rc=$?
        if [ "$rc" = 0 ] && [ ! -f "$SAVED_ROUTES_FILE" ] && grep -q 'demonstrably back' "$LOG_FILE" 2>/dev/null; then
            echo "PASS  [finding 5ii] run_safety_net_check clears a stale marker once routes are already back"
        else
            saved_exists=no; [ -f "$SAVED_ROUTES_FILE" ] && saved_exists=yes
            echo "FAIL  [finding 5ii] rc=$rc saved_exists=$saved_exists log=$(cat "$LOG_FILE" 2>/dev/null)"
            f5b_fail=1
        fi

        # Contrast: when routes are genuinely NOT back yet, the existing
        # restore path must still fire (unaffected by this fix).
        sudo() { return 0; }
        routes_on_iface() { echo 0; }
        printf '10.9.9.0/24 utun42\n' >"$SAVED_ROUTES_FILE"
        touch -t 202001010000 "$SAVED_ROUTES_FILE"
        rm -f "$LOG_FILE"
        run_safety_net_check
        rc2=$?
        if [ "$rc2" = 1 ] && grep -q 'restoring unconditionally' "$LOG_FILE" 2>/dev/null; then
            echo "PASS  [finding 5ii] run_safety_net_check still restores when routes are genuinely not back yet"
        else
            echo "FAIL  [finding 5ii] contrast case rc=$rc2 log=$(cat "$LOG_FILE" 2>/dev/null)"
            f5b_fail=1
        fi
        exit "$f5b_fail"
    ); then
        :
    else
        fail=1
    fi

    # --- Finding 13: resolve_offset must seed (not replay) on a first-ever
    # run, and must detect a rename-based rotation via inode change even
    # when the new file's size does not shrink below the old offset.
    f13_dir=$(mktemp -d) || { echo "FAIL  [finding 13] could not create temp dir" >&2; fail=1; f13_dir=""; }
    if [ -n "$f13_dir" ]; then
        HELPDESK_LOG="$f13_dir/helpdesk.log"
        OFFSET_FILE="$f13_dir/offset"
        OFFSET_INODE_FILE="$f13_dir/offset-inode"
        LOG_FILE="$f13_dir/log"

        # (a) first run ever: no OFFSET_FILE at all -- must seed at the
        # current size and signal "skip this cycle", never "replay from 0".
        printf 'line one\nline two\n' >"$HELPDESK_LOG"
        cur_size=$(wc -c <"$HELPDESK_LOG" | tr -d ' ')
        set -- $(resolve_offset "$cur_size")
        off=$1; skip=$2; reason=$3
        if [ "$off" = "$cur_size" ] && [ "$skip" = 1 ] && [ "$reason" = "first_run" ]; then
            echo "PASS  [finding 13] resolve_offset seeds at the current size and skips the first cycle when OFFSET_FILE is missing"
        else
            echo "FAIL  [finding 13] first-run result: off=$off skip=$skip reason=$reason (expected off=$cur_size skip=1 reason=first_run)"
            fail=1
        fi
        echo "$cur_size" >"$OFFSET_FILE"

        # (b) subsequent, unchanged call: no rotation, offset carried
        # forward unchanged, cycle not skipped.
        set -- $(resolve_offset "$cur_size")
        off=$1; skip=$2; reason=$3
        if [ "$off" = "$cur_size" ] && [ "$skip" = 0 ] && [ "$reason" = "none" ]; then
            echo "PASS  [finding 13] resolve_offset is a no-op once the offset is already seeded and nothing changed"
        else
            echo "FAIL  [finding 13] steady-state result: off=$off skip=$skip reason=$reason"
            fail=1
        fi

        # (c) rename-based rotation: a NEW file appears at the same path
        # with a DIFFERENT inode, and its size is already >= the old
        # persisted offset -- the case a size-only heuristic would miss.
        rm -f "$HELPDESK_LOG"
        printf 'brand new file, already bigger than before\n' >"$HELPDESK_LOG"
        new_size=$(wc -c <"$HELPDESK_LOG" | tr -d ' ')
        if [ "$new_size" -lt "$cur_size" ]; then
            echo "FAIL  [finding 13] test fixture invalid: new file ($new_size bytes) is not >= old offset ($cur_size bytes)" >&2
            fail=1
        else
            set -- $(resolve_offset "$new_size")
            off=$1; skip=$2; reason=$3
            if [ "$off" = 0 ] && [ "$reason" = "inode_changed" ]; then
                echo "PASS  [finding 13] resolve_offset detects a rename-based rotation via inode change even though size did not shrink"
            else
                echo "FAIL  [finding 13] rotation result: off=$off skip=$skip reason=$reason"
                fail=1
            fi
        fi
        rm -rf "$f13_dir"
    fi

    # --- Finding 14: compute_keep_set must invoke /usr/bin/python3
    # directly, never a PATH-resolved "python3" that could be shadowed
    # (e.g. by a user-installed python, or, in the LaunchDaemon's minimal
    # PATH, by something unexpected). Subshell so the fake PATH entry
    # never leaks.
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

    # --- Finding 16: reject --timeout 0 (meaningless -- every wait/lock
    # check here treats a 0 timeout as "already timed out"/"immediately
    # stale").
    f16_out=$("$0" --timeout 0 2>&1)
    f16_rc=$?
    if [ "$f16_rc" -ne 0 ] && printf '%s' "$f16_out" | grep -qi 'timeout'; then
        echo "PASS  [finding 16] --timeout 0 is rejected"
    else
        echo "FAIL  [finding 16] --timeout 0 -> rc=$f16_rc out='$f16_out' (expected a rejection)"
        fail=1
    fi

    # --- Finding 16: log() must not leak the shell's own "cannot open"
    # diagnostic to stderr when LOG_FILE is unwritable -- only the intended
    # fallback line.
    f16log_dir=$(mktemp -d) || { echo "FAIL  [finding 16] could not create temp dir" >&2; fail=1; f16log_dir=""; }
    if [ -n "$f16log_dir" ]; then
        DRY_RUN=0
        LOG_FILE="$f16log_dir/does-not-exist/nested/unwritable.log"
        log_err=$(log "self-test message" 2>&1)
        if printf '%s' "$log_err" | grep -q "self-test message" && \
           ! printf '%s' "$log_err" | grep -qi "no such file\|cannot open\|: .*\.log:"; then
            echo "PASS  [finding 16] log() falls back to stderr without leaking a shell redirection error"
        else
            echo "FAIL  [finding 16] log() stderr: $log_err"
            fail=1
        fi
        rm -rf "$f16log_dir"
    fi

    # --- keep-routes: containment/fail-safe unit tests live in
    # keep-routes.py itself (native language for CIDR arithmetic); fold its
    # result into ours so one --self-test command covers everything.
    if [ -x /usr/bin/python3 ]; then
        kr_out=$(/usr/bin/python3 "$SCRIPT_DIR/keep-routes.py" --self-test)
        kr_rc=$?
        printf '%s\n' "$kr_out"
        [ "$kr_rc" -ne 0 ] && fail=1
    else
        echo "FAIL  keep-routes.py --self-test: /usr/bin/python3 not available to run it" >&2
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

# --- config resolution (same dual-mode convention as dns-guard.sh: an
# installed conf file by default, or --config DIR to read a repo config dir
# directly without installing anything) ---
if [ -n "$CONFIG_DIR" ]; then
    # A relative --config is resolved against the CWD first (unchanged
    # behaviour), falling back to REPO_ROOT so it also works from any other
    # directory -- see resolve_config_dir in lib-routes.sh.
    CONFIG_DIR=$(resolve_config_dir "$REPO_ROOT" "$CONFIG_DIR")
    TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
    if [ ! -f "$TUNNELS_FILE" ]; then
        echo "ERROR: $TUNNELS_FILE not found (see config/example/tunnels.txt)" >&2
        exit 2
    fi
    PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)
    TRIGGER=$(get_tunnel_prefix LIFT_TRIGGER)
    TIMEOUT=240
    HELPDESK_LOG="$HELPDESK_LOG_DEFAULT"
    STATE_DIR="$REPO_ROOT/build/route-lift-state"
    KEEP_ROUTES_FILE="$CONFIG_DIR/keep-routes-for.txt"
else
    if [ ! -f "$CONF_FILE" ]; then
        echo "ERROR: $CONF_FILE not found (use --config DIR to read a repo config dir instead)" >&2
        exit 2
    fi
    PERSONAL_TUNNEL_PREFIX=$(grep '^PERSONAL_TUNNEL_PREFIX=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    TRIGGER=$(grep '^LIFT_TRIGGER=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    TIMEOUT=$(grep '^TIMEOUT=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    HELPDESK_LOG=$(grep '^HELPDESK_LOG=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    STATE_DIR=$(grep '^STATE_DIR=' "$CONF_FILE" | tail -1 | cut -d= -f2-)
    [ -z "$TIMEOUT" ] && TIMEOUT=240
    [ -z "$HELPDESK_LOG" ] && HELPDESK_LOG="$HELPDESK_LOG_DEFAULT"
    KEEP_ROUTES_FILE="$SCRIPT_DIR/keep-routes-for.txt"
fi
[ -z "$TRIGGER" ] && TRIGGER=connect-start
[ -n "$TRIGGER_FLAG" ] && TRIGGER=$TRIGGER_FLAG
case "$TRIGGER" in
    connect-start|pre-scan) ;;
    *)
        echo "ERROR: invalid LIFT_TRIGGER/--trigger '$TRIGGER' (expected connect-start or pre-scan)" >&2
        exit 2
        ;;
esac
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
OFFSET_INODE_FILE="$STATE_DIR/offset-inode"
WATCH_STATE_FILE="$STATE_DIR/state"
LOCK_DIR="$STATE_DIR/lock"
PAUSE_FILE="$STATE_DIR/paused-until"
LAST_LIFT_FILE="$STATE_DIR/last-lift-duration"
KEEP_ROUTES_SCRIPT="$SCRIPT_DIR/keep-routes.py"
KEPT_ROUTES_FILE="$STATE_DIR/route-lift-kept-routes.txt"

RESTORE_HAD_FAILURES=0
RESTORE_VERIFY_FAILED=0
RESTORE_DONE=0
LOCK_HELD=0

# --- --pause / --resume: state-file operations only. Whether these need
# sudo depends entirely on where STATE_DIR lives: under --config DIR it is
# REPO_ROOT/build/route-lift-state (user-owned, no sudo); against the
# installed conf it is the root:wheel, mode-755 directory
# install-route-lift-watcher.sh creates, so a normal user cannot write
# PAUSE_FILE there -- see the README and the Makefile's route-lift-pause/
# route-lift-resume targets, which use sudo for exactly that reason. ---
if [ "$PAUSE_FLAG" = 1 ]; then
    if ! mkdir -p "$STATE_DIR" 2>/dev/null; then
        echo "ERROR: cannot create $STATE_DIR (needs sudo? see README)" >&2
        exit 1
    fi
    expiry=$(( $(date +%s) + PAUSE_MINUTES * 60 ))
    if ! echo "$expiry" >"$PAUSE_FILE" 2>/dev/null; then
        echo "ERROR: cannot write $PAUSE_FILE (needs sudo? see README)" >&2
        exit 1
    fi
    human=$(date -r "$expiry" '+%Y-%m-%d %H:%M:%S%z' 2>/dev/null)
    echo "Paused: routes will not be lifted for an automatic corporate-VPN reconnect until ${human:-$expiry} (${PAUSE_MINUTES}m from now)."
    echo "Corporate VPN connects will be slow again while paused (2-3.5 minutes) -- see README."
    echo "The safety net still restores any already-lifted routes regardless of this pause."
    echo "Resume early with: $0${CONFIG_DIR:+ --config \"$CONFIG_DIR\"} --resume"
    exit 0
fi

if [ "$RESUME_FLAG" = 1 ]; then
    if [ -f "$PAUSE_FILE" ]; then
        rm -f "$PAUSE_FILE"
        echo "Resumed: the watcher will act on the next corporate-VPN reconnect again."
    else
        echo "Not paused ($PAUSE_FILE does not exist); nothing to resume."
    fi
    exit 0
fi

# --- --status ---
if [ "$STATUS" = 1 ]; then
    echo "=== route-lift-watcher status ==="
    echo "Config: ${CONFIG_DIR:-$CONF_FILE}"
    echo "Trigger: $TRIGGER"
    echo "State dir: $STATE_DIR"
    if [ -f "$SAVED_ROUTES_FILE" ]; then
        age=$(age_seconds "$SAVED_ROUTES_FILE")
        lines=$(wc -l <"$SAVED_ROUTES_FILE" 2>/dev/null | tr -d ' ')
        echo "Routes lifted: YES"
        echo "Saved-routes file: $SAVED_ROUTES_FILE (age: ${age:-unknown}s, $lines routes)"
        if [ -f "$KEPT_ROUTES_FILE" ]; then
            kept=$(wc -l <"$KEPT_ROUTES_FILE" 2>/dev/null | tr -d ' ')
            echo "Routes kept (per $KEEP_ROUTES_FILE): $kept"
        fi
    else
        echo "Routes lifted: NO"
        echo "Saved-routes file: none ($SAVED_ROUTES_FILE)"
    fi
    if [ -f "$LAST_LIFT_FILE" ]; then
        last_lift=$(cat "$LAST_LIFT_FILE" 2>/dev/null)
        echo "Last completed lift: routes were unavailable for ${last_lift:-unknown}s"
    else
        echo "Last completed lift: none recorded yet"
    fi
    pause_expiry=$(pause_state "$PAUSE_FILE")
    if [ "$pause_expiry" != 0 ]; then
        paused_until=$(date -r "$pause_expiry" '+%Y-%m-%d %H:%M:%S%z' 2>/dev/null)
        echo "Paused: YES, until ${paused_until:-$pause_expiry}"
    else
        echo "Paused: NO"
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
    echo "Trigger: $TRIGGER"
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
    set -- $(resolve_offset "$cur_size" 1)
    prev_offset=$1
    skip_cycle=$2
    reason=$3
    prev_state=$(cat "$WATCH_STATE_FILE" 2>/dev/null)
    case "$prev_state" in STARTED|IDLE|CONNECTING) ;; *) prev_state=IDLE ;; esac

    echo "Persisted offset: $prev_offset   Current file size: $cur_size bytes   New bytes: $((cur_size - prev_offset))"
    case "$reason" in
        first_run) echo "NOTE: no persisted offset yet for $HELPDESK_LOG -- a live run would seed the offset at the current size and take NO action this cycle (never replay the log's entire history)." ;;
        truncated) echo "NOTE: persisted offset exceeded the file size -- log truncation/rotation detected, would reset offset to 0" ;;
        inode_changed) echo "NOTE: $HELPDESK_LOG's inode differs from the last one seen -- a rename-based rotation, would reset offset to 0" ;;
    esac
    echo "Persisted state: $prev_state"

    slice_file=$(mktemp)
    tail -c +"$((prev_offset + 1))" "$HELPDESK_LOG" >"$slice_file" 2>/dev/null
    start_line=$(grep -n -E 'Starting connect|Starting new connection' "$slice_file" | tail -1)
    prescan_line=$(grep -n -E 'no need executing firewall step' "$slice_file" | tail -1)
    done_line=$(grep -n -E 'Connection was successfully established|Site is not responding|User cancelled the connection|Disconnect initiated by user' "$slice_file" | tail -1)
    new_state=$(decide_state "$prev_state" "$slice_file" "$TRIGGER")
    rm -f "$slice_file"

    echo "Most recent connect-start line in the new bytes: ${start_line:-<none>}"
    if [ "$TRIGGER" = "pre-scan" ]; then
        echo "Most recent pre-scan marker ('no need executing firewall step') in the new bytes: ${prescan_line:-<none>}"
    fi
    echo "Most recent completion/terminal line in the new bytes: ${done_line:-<none>}"
    echo
    if [ -f "$SAVED_ROUTES_FILE" ]; then
        echo "Routes currently lifted: YES ($SAVED_ROUTES_FILE)"
    else
        echo "Routes currently lifted: NO"
    fi
    pause_expiry=$(pause_state "$PAUSE_FILE")
    if [ "$pause_expiry" != 0 ]; then
        paused_until=$(date -r "$pause_expiry" '+%Y-%m-%d %H:%M:%S%z' 2>/dev/null)
        echo "Paused: YES, until ${paused_until:-$pause_expiry} -- a live run would take no lift/restore action regardless of the decision below"
    fi
    echo
    case "$new_state" in
        STARTED) echo "DECISION: would lift the personal VPN's routes (a corporate-VPN connect looks to be in progress, trigger=$TRIGGER)." ;;
        CONNECTING) echo "DECISION: no action yet -- a connect-start was seen but the pre-scan marker has not (trigger=pre-scan); would keep waiting." ;;
        IDLE)    echo "DECISION: no action -- no corporate-VPN connect currently in progress." ;;
    esac

    echo
    echo "Keep-routes preview ($KEEP_ROUTES_FILE, resolving for real -- read-only, touches nothing):"
    kr_preview_utun=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
    if [ -z "$kr_preview_utun" ]; then
        echo "  (no personal VPN utun found; cannot preview)"
    else
        # Use throwaway temp files instead of the real STATE_DIR/
        # KEPT_ROUTES_FILE paths -- a dry-run must not even create
        # STATE_DIR, which may not exist yet.
        kr_preview_file=$(mktemp)
        KEPT_ROUTES_FILE=$(mktemp)
        netstat -rn -f inet 2>/dev/null | awk -v i="$kr_preview_utun" '$NF==i {print $1, $2}' |
        while read -r dest gw; do
            [ -z "$dest" ] && continue
            echo "$(normalize_dest "$dest") $gw"
        done >"$kr_preview_file"
        if compute_keep_set "$kr_preview_file"; then
            if [ -s "$KEPT_ROUTES_FILE" ]; then
                echo "  would keep $(wc -l <"$KEPT_ROUTES_FILE" | tr -d ' ') route(s):"
                while IFS= read -r kline; do echo "    kept: $kline"; done <"$KEPT_ROUTES_FILE"
            else
                echo "  would keep 0 routes (no active entries, or none matched)"
            fi
        else
            echo "  a live lift would REFUSE this cycle -- keep-set could not be computed (see above)"
        fi
        rm -f "$kr_preview_file" "$KEPT_ROUTES_FILE"
    fi

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
