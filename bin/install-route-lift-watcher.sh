#!/bin/sh
# Install bin/route-lift-watcher.sh as a root LaunchDaemon that automatically
# lifts the personal AmneziaVPN's routes while the corporate Check Point VPN
# performs a full reconnect, then restores them. See bin/route-lift-watcher.sh
# for the full design and safety rationale.
#
# Modelled directly on install-dns-guard.sh: same root-owned install
# directory, same assert_safe_path ancestor checks, same dry-run-by-default
# behaviour, and the same reasoning for why the daemon script must be copied
# to a root-owned path rather than run in place from this repo checkout (a
# LaunchDaemon runs as root at RunAtLoad/StartInterval/WatchPaths, and its
# ProgramArguments points at a fixed path on disk -- if that path were inside
# the user's home directory, anything able to write there as that user could
# have its content executed as root the next time the daemon fires). The
# installer verifies the ancestor chain with assert_safe_path instead of
# assuming it: --dry-run reports, --apply hard-refuses.
#
# Renders:
#   /Library/Application Support/comrades-tunnel/route-lift-watcher.sh
#       (copy of bin/route-lift-watcher.sh)
#   /Library/Application Support/comrades-tunnel/lib-routes.sh
#       (copy of bin/lib-routes.sh, sourced by the copy above)
#   /Library/Application Support/comrades-tunnel/keep-routes.py
#       (copy of bin/keep-routes.py, invoked by lib-routes.sh's
#       compute_keep_set -- see that function and README)
#   /Library/Application Support/comrades-tunnel/keep-routes-for.txt
#       (copy of DIR/keep-routes-for.txt, if present -- optional; its
#       absence just means the keep-routes feature is unused)
#   /Library/Application Support/comrades-tunnel/route-lift.conf
#       (KEY=VALUE, PERSONAL_TUNNEL_PREFIX and LIFT_TRIGGER from
#       DIR/tunnels.txt plus fixed TIMEOUT/HELPDESK_LOG/STATE_DIR)
#   /Library/LaunchDaemons/dev.comrades-tunnel.route-lift.plist
#       (WatchPaths on helpdesk.log, StartInterval for the safety net,
#       RunAtLoad false)
#
# Default action is --dry-run: prints each rendered file and a diff against
# whatever is currently installed (or "would create"), and validates the
# rendered plist with `plutil -lint`. Nothing is written or executed.
# --apply performs the install with sudo and (re)loads the daemon.
# --uninstall stops the daemon and removes the installed files.
#
# Usage: install-route-lift-watcher.sh [--config DIR] [--dry-run|--apply|--uninstall|--self-test]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

CONFIG_DIR="$REPO_ROOT/local"
ACTION="dry-run"
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
            ACTION="dry-run"
            shift
            ;;
        --apply)
            ACTION="apply"
            shift
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--dry-run|--apply|--uninstall|--self-test]" >&2
            exit 2
            ;;
    esac
done

# saved_routes_blocks_uninstall MARKER -- true (0) if MARKER exists (the
# personal VPN's routes may currently be lifted and --uninstall must
# refuse), false (1) otherwise. Factored out so --self-test can exercise
# the decision without sudo or any real system path -- see finding 4 in
# the review this fixes.
saved_routes_blocks_uninstall() {
    [ -f "$1" ]
}

# safe_install SRC DST -- install SRC as DST atomically: copy next to DST,
# then rename over it, so a reader (a LaunchDaemon that could fire mid-
# install) never observes a partially-written file.
safe_install() {
    sudo cp "$1" "$2.new" && sudo mv "$2.new" "$2"
}

run_self_test() {
    fail=0
    t=$(mktemp -d) || { echo "FAIL  could not create a temp dir" >&2; return 1; }
    trap 'rm -rf "$t"' EXIT

    if saved_routes_blocks_uninstall "$t/does-not-exist"; then
        echo "FAIL  [finding 4] saved_routes_blocks_uninstall said yes for a marker that does not exist"
        fail=1
    else
        echo "PASS  [finding 4] saved_routes_blocks_uninstall says no when no saved-routes marker exists"
    fi

    printf '10.9.9.0/24 utun9\n' >"$t/marker"
    if saved_routes_blocks_uninstall "$t/marker"; then
        echo "PASS  [finding 4] saved_routes_blocks_uninstall says yes when a saved-routes marker is present (routes may be lifted)"
    else
        echo "FAIL  [finding 4] saved_routes_blocks_uninstall said no for an existing marker"
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

LIB_DIR="/Library/Application Support/comrades-tunnel"
WATCHER_SRC="$SCRIPT_DIR/route-lift-watcher.sh"
WATCHER_DST="$LIB_DIR/route-lift-watcher.sh"
LIBROUTES_SRC="$SCRIPT_DIR/lib-routes.sh"
LIBROUTES_DST="$LIB_DIR/lib-routes.sh"
KEEPROUTES_SRC="$SCRIPT_DIR/keep-routes.py"
KEEPROUTES_DST="$LIB_DIR/keep-routes.py"
KEEPFILE_SRC=""   # set once CONFIG_DIR is known, below
KEEPFILE_DST="$LIB_DIR/keep-routes-for.txt"
CONF_DST="$LIB_DIR/route-lift.conf"
PLIST_LABEL="dev.comrades-tunnel.route-lift"
PLIST_DST="/Library/LaunchDaemons/$PLIST_LABEL.plist"
LOG_FILE="/var/log/comrades-tunnel-route-lift.log"
HELPDESK_LOG="/Library/Application Support/Checkpoint/Endpoint Connect/helpdesk.log"
STATE_DIR="$LIB_DIR/route-lift-state"
# Same filename route-lift-watcher.sh's own SAVED_ROUTES_FILE resolves to
# under this installed STATE_DIR -- its presence means the personal VPN's
# routes may currently be lifted (see the --uninstall guard below).
SAVED_ROUTES_MARKER="$STATE_DIR/route-lift-saved-routes.txt"
NEWSYSLOG_DST="/etc/newsyslog.d/comrades-tunnel-route-lift.conf"
TIMEOUT=240
SAFETY_NET_INTERVAL=60
EXIT_TIMEOUT=300   # generous: a real restore can take a few seconds; never let launchd SIGKILL it mid-write (finding 4)

# Verify that <path> and every already-existing ancestor up to / is fully
# root-owned with neither group-write nor other-write permission. Directory
# write permission lets the owning user rename/delete any entry inside,
# regardless of that entry's own ownership, so a user-writable ancestor lets a
# non-root user replace exactly what the root daemon executes -- escalation to
# root. In --dry-run this reports one line per component; in --apply it
# hard-refuses (exit 1) before any sudo write. Identical to install-dns-guard.sh's
# copy of this function.
assert_safe_path() {
    p=$1
    while :; do
        if [ -e "$p" ] || [ "$p" = "/" ]; then
            owner=$(stat -f '%Su' "$p")
            mode=$(stat -f '%Sp' "$p")
            gwrite=$(printf '%s' "$mode" | cut -c6)   # group "write"
            owrite=$(printf '%s' "$mode" | cut -c9)   # other "write"
            if [ "$owner" = "root" ] && [ "$gwrite" != "w" ] && [ "$owrite" != "w" ]; then
                [ "$ACTION" != "apply" ] && echo "ok:      $p ($owner $mode)"
            elif [ "$ACTION" = "apply" ]; then
                echo "UNSAFE: $p ($owner $mode)" >&2
                echo "Refusing to install: a user-writable ancestor ($p) lets a non-root user replace what the root daemon executes." >&2
                exit 1
            else
                echo "UNSAFE: $p ($owner $mode)"
            fi
        fi
        [ "$p" = "/" ] && break
        p=$(dirname "$p")
    done
}

if [ "$ACTION" = "uninstall" ]; then
    if saved_routes_blocks_uninstall "$SAVED_ROUTES_MARKER"; then
        echo "ERROR: $SAVED_ROUTES_MARKER exists -- the personal VPN's routes may currently be lifted." >&2
        echo "Uninstalling now would delete the only record of what to restore, and launchd's bootout" >&2
        echo "can SIGKILL a restore already in progress before it finishes. Run the installed watcher" >&2
        echo "once first (a normal invocation restores), confirm with --status that routes are back," >&2
        echo "then re-run --uninstall:" >&2
        echo "  sudo sh \"$WATCHER_DST\"" >&2
        echo "  sh \"$WATCHER_DST\" --status" >&2
        exit 1
    fi
    echo "Uninstalling $PLIST_LABEL"
    sudo launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
    for f in "$PLIST_DST" "$WATCHER_DST" "$LIBROUTES_DST" "$KEEPROUTES_DST" "$KEEPFILE_DST" "$CONF_DST" "$NEWSYSLOG_DST"; do
        if [ -e "$f" ]; then
            sudo rm -f "$f"
            echo "Removed: $f"
        else
            echo "Already absent: $f"
        fi
    done
    if [ -d "$STATE_DIR" ]; then
        sudo rm -rf "$STATE_DIR"
        echo "Removed: $STATE_DIR"
    else
        echo "Already absent: $STATE_DIR"
    fi
    exit 0
fi

if [ ! -f "$WATCHER_SRC" ]; then
    echo "ERROR: $WATCHER_SRC not found" >&2
    exit 1
fi
if [ ! -f "$LIBROUTES_SRC" ]; then
    echo "ERROR: $LIBROUTES_SRC not found" >&2
    exit 1
fi
if [ ! -f "$KEEPROUTES_SRC" ]; then
    echo "ERROR: $KEEPROUTES_SRC not found" >&2
    exit 1
fi

# Reuse resolve_config_dir/get_tunnel_prefix from lib-routes.sh instead of
# re-implementing the same grep/cut parsing here. A relative --config is
# resolved against the CWD first (unchanged behaviour), falling back to
# REPO_ROOT so it also works from any other directory.
. "$LIBROUTES_SRC"
CONFIG_DIR=$(resolve_config_dir "$REPO_ROOT" "$CONFIG_DIR")

TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
if [ ! -f "$TUNNELS_FILE" ]; then
    echo "ERROR: $TUNNELS_FILE not found (see config/example/tunnels.txt)" >&2
    exit 1
fi
KEEPFILE_SRC="$CONFIG_DIR/keep-routes-for.txt"

PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)
if [ -z "$PERSONAL_TUNNEL_PREFIX" ]; then
    echo "ERROR: PERSONAL_TUNNEL_PREFIX not set in $TUNNELS_FILE" >&2
    exit 1
fi
LIFT_TRIGGER=$(get_tunnel_prefix LIFT_TRIGGER)
case "$LIFT_TRIGGER" in
    connect-start|pre-scan) ;;
    '') LIFT_TRIGGER=connect-start ;;
    *)
        echo "ERROR: invalid LIFT_TRIGGER '$LIFT_TRIGGER' in $TUNNELS_FILE (expected connect-start or pre-scan)" >&2
        exit 1
        ;;
esac

echo "Checking path safety:"
assert_safe_path "$LIB_DIR"
assert_safe_path "$(dirname "$PLIST_DST")"
assert_safe_path "$(dirname "$LOG_FILE")"
assert_safe_path "$(dirname "$NEWSYSLOG_DST")"

TMP_CONF=$(mktemp)
TMP_PLIST=$(mktemp)
TMP_NEWSYSLOG=$(mktemp)
trap 'rm -f "$TMP_CONF" "$TMP_PLIST" "$TMP_NEWSYSLOG"' EXIT

cat >"$TMP_CONF" <<EOF
PERSONAL_TUNNEL_PREFIX=$PERSONAL_TUNNEL_PREFIX
LIFT_TRIGGER=$LIFT_TRIGGER
TIMEOUT=$TIMEOUT
HELPDESK_LOG=$HELPDESK_LOG
STATE_DIR=$STATE_DIR
EOF

# ProgramArguments runs the installed script directly (shebang + chmod 755
# below), not "/bin/sh <script>", so macOS lists the daemon under "Allow in
# the Background" as "route-lift-watcher.sh" instead of an anonymous "sh" --
# see the same comment in install-dns-guard.sh.
cat >"$TMP_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$PLIST_LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$WATCHER_DST</string>
	</array>
	<key>WatchPaths</key>
	<array>
		<string>$HELPDESK_LOG</string>
	</array>
	<key>StartInterval</key>
	<integer>$SAFETY_NET_INTERVAL</integer>
	<key>RunAtLoad</key>
	<false/>
	<key>ThrottleInterval</key>
	<integer>2</integer>
	<key>ExitTimeOut</key>
	<integer>$EXIT_TIMEOUT</integer>
	<key>StandardOutPath</key>
	<string>$LOG_FILE</string>
	<key>StandardErrorPath</key>
	<string>$LOG_FILE</string>
</dict>
</plist>
EOF

# newsyslog.d entry: this daemon's log() always appends and never rotates
# itself (see route-lift-watcher.sh), so without this it grows forever.
cat >"$TMP_NEWSYSLOG" <<EOF
# logfilename                              [owner:group]  mode count size(KB) when  flags
$LOG_FILE	root:wheel	644	7	1000	*	J
EOF

echo "Config dir: $CONFIG_DIR"
if [ "$ACTION" = "apply" ]; then
    echo "Mode: --apply (will write with sudo and (re)load the daemon)"
else
    echo "Mode: --dry-run (no changes will be made)"
fi
echo

echo "=== $PLIST_DST ==="
plutil -lint "$TMP_PLIST" && echo "plutil -lint: OK"
echo "--- rendered content ---"
cat "$TMP_PLIST"
if [ -f "$PLIST_DST" ]; then
    if diff -u "$PLIST_DST" "$TMP_PLIST"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($PLIST_DST -> rendered) ---"
    fi
else
    echo "--- installed file: none, would create $PLIST_DST ---"
fi
echo

echo "=== $CONF_DST ==="
echo "--- rendered content ---"
cat "$TMP_CONF"
if [ -f "$CONF_DST" ]; then
    if diff -u "$CONF_DST" "$TMP_CONF"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($CONF_DST -> rendered) ---"
    fi
else
    echo "--- installed file: none, would create $CONF_DST ---"
fi
echo

echo "=== $WATCHER_DST ==="
if [ -f "$WATCHER_DST" ]; then
    if diff -u "$WATCHER_DST" "$WATCHER_SRC"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($WATCHER_DST -> $WATCHER_SRC) ---"
    fi
else
    echo "--- installed file: none, would create $WATCHER_DST (copy of $WATCHER_SRC) ---"
fi
echo

echo "=== $LIBROUTES_DST ==="
if [ -f "$LIBROUTES_DST" ]; then
    if diff -u "$LIBROUTES_DST" "$LIBROUTES_SRC"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($LIBROUTES_DST -> $LIBROUTES_SRC) ---"
    fi
else
    echo "--- installed file: none, would create $LIBROUTES_DST (copy of $LIBROUTES_SRC) ---"
fi
echo

echo "=== $KEEPROUTES_DST ==="
if [ -f "$KEEPROUTES_DST" ]; then
    if diff -u "$KEEPROUTES_DST" "$KEEPROUTES_SRC"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($KEEPROUTES_DST -> $KEEPROUTES_SRC) ---"
    fi
else
    echo "--- installed file: none, would create $KEEPROUTES_DST (copy of $KEEPROUTES_SRC) ---"
fi
echo

echo "=== $KEEPFILE_DST ==="
if [ -f "$KEEPFILE_SRC" ]; then
    if [ -f "$KEEPFILE_DST" ]; then
        if diff -u "$KEEPFILE_DST" "$KEEPFILE_SRC"; then
            echo "--- diff against installed file: none (up to date) ---"
        else
            echo "--- diff against installed file above ($KEEPFILE_DST -> $KEEPFILE_SRC) ---"
        fi
    else
        echo "--- installed file: none, would create $KEEPFILE_DST (copy of $KEEPFILE_SRC) ---"
    fi
else
    echo "--- $KEEPFILE_SRC not found; the keep-routes feature will be inactive (no routes protected during a lift) ---"
fi
echo

echo "=== $NEWSYSLOG_DST ==="
echo "--- rendered content ---"
cat "$TMP_NEWSYSLOG"
if [ -f "$NEWSYSLOG_DST" ]; then
    if diff -u "$NEWSYSLOG_DST" "$TMP_NEWSYSLOG"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($NEWSYSLOG_DST -> rendered) ---"
    fi
else
    echo "--- installed file: none, would create $NEWSYSLOG_DST ---"
fi
echo

if [ "$ACTION" = "dry-run" ]; then
    echo "dry-run: no changes made. Re-run with --apply (sudo) to install."
    exit 0
fi

# NO SUDO IS RUN ABOVE THIS LINE. Everything past this point (--apply only)
# requires sudo -- never run it from an automated/non-interactive context
# that isn't explicitly the human operator invoking --apply themselves.
sudo mkdir -p "$LIB_DIR" "$STATE_DIR"
safe_install "$WATCHER_SRC" "$WATCHER_DST"
safe_install "$LIBROUTES_SRC" "$LIBROUTES_DST"
safe_install "$KEEPROUTES_SRC" "$KEEPROUTES_DST"
safe_install "$TMP_CONF" "$CONF_DST"
safe_install "$TMP_PLIST" "$PLIST_DST"
safe_install "$TMP_NEWSYSLOG" "$NEWSYSLOG_DST"
if [ -f "$KEEPFILE_SRC" ]; then
    safe_install "$KEEPFILE_SRC" "$KEEPFILE_DST"
fi

sudo chown root:wheel "$WATCHER_DST" "$LIBROUTES_DST" "$KEEPROUTES_DST" "$CONF_DST" "$PLIST_DST" "$NEWSYSLOG_DST" "$STATE_DIR"
sudo chmod 755 "$WATCHER_DST" "$LIBROUTES_DST" "$KEEPROUTES_DST"
sudo chmod 644 "$CONF_DST" "$PLIST_DST" "$NEWSYSLOG_DST"
sudo chmod 755 "$STATE_DIR"
if [ -f "$KEEPFILE_DST" ]; then
    sudo chown root:wheel "$KEEPFILE_DST"
    sudo chmod 644 "$KEEPFILE_DST"
fi

sudo launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST_DST"

echo "--- launchctl print system/$PLIST_LABEL ---"
sudo launchctl print "system/$PLIST_LABEL" | head -5

echo "Installed and loaded $PLIST_LABEL (RunAtLoad is false; it will first run on the next helpdesk.log change or StartInterval tick)."
