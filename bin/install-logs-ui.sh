#!/bin/sh
# Install bin/logs-ui.py as a per-user LaunchAgent that serves the local,
# read-only logs/state web UI (see that script's own header for what it
# serves and its safety properties -- 127.0.0.1 only, GET-only, no writes).
#
# Modelled on install-split-health.sh: a GUI LaunchAgent (gui/$(id -u)), not
# a LaunchDaemon (system), and -- same as that script -- ProgramArguments
# points straight at the file in this repo checkout instead of copying it
# to a separate "trusted" location first. That copy step matters for
# install-dns-guard.sh/install-route-lift-watcher.sh because those install
# root-owned LaunchDaemons that would otherwise execute a file a non-root
# user could overwrite -- a real privilege boundary. Here there is none:
# logs-ui.py needs no privilege at all (it only shells out to ifconfig/
# netstat/launchctl and reads local/*.txt, the split-health state dir and
# the three log files -- all read-only), it binds to 127.0.0.1 only, and a
# GUI LaunchAgent already runs with exactly the invoking user's own
# privileges against that same user's own repo checkout. Copying it
# elsewhere would add nothing.
#
# Renders only:
#   ~/Library/LaunchAgents/dev.comrades-tunnel.logs-ui.plist
#
# Default action is --dry-run: prints the rendered plist, validates it with
# `plutil -lint`, and diffs it against whatever is currently installed (or
# says "would create"). Nothing is written or loaded. --apply writes the
# plist and loads it with `launchctl bootstrap gui/$(id -u)`. --uninstall
# unloads it (`launchctl bootout`) and removes the plist. No sudo anywhere.
#
# Usage: install-logs-ui.sh [--port PORT] [--dry-run|--apply|--uninstall]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

PORT=8765
ACTION="dry-run"

while [ $# -gt 0 ]; do
    case "$1" in
        --port)
            PORT=$2
            shift 2
            ;;
        --port=*)
            PORT=${1#--port=}
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
        *)
            echo "Usage: $0 [--port PORT] [--dry-run|--apply|--uninstall]" >&2
            exit 2
            ;;
    esac
done

SCRIPT_SRC="$SCRIPT_DIR/logs-ui.py"
PLIST_LABEL="dev.comrades-tunnel.logs-ui"
PLIST_DST="$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
LAUNCHD_LOG="$HOME/Library/Logs/comrades-tunnel-logs-ui.launchd.log"

case "$PORT" in
    ''|*[!0-9]*)
        echo "ERROR: --port must be a positive integer, got '$PORT'" >&2
        exit 2
        ;;
esac

if [ "$ACTION" = "uninstall" ]; then
    echo "Uninstalling $PLIST_LABEL"
    launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
    if [ -e "$PLIST_DST" ]; then
        rm -f "$PLIST_DST"
        echo "Removed: $PLIST_DST"
    else
        echo "Already absent: $PLIST_DST"
    fi
    exit 0
fi

if [ ! -f "$SCRIPT_SRC" ]; then
    echo "ERROR: $SCRIPT_SRC not found" >&2
    exit 1
fi

PYTHON3=$(command -v python3 || true)
if [ -z "$PYTHON3" ]; then
    echo "ERROR: python3 not found on PATH -- cannot render an absolute ProgramArguments entry for it" >&2
    exit 1
fi

TMP_PLIST=$(mktemp)
trap 'rm -f "$TMP_PLIST"' EXIT

cat >"$TMP_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$PLIST_LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$PYTHON3</string>
		<string>$SCRIPT_SRC</string>
		<string>--port</string>
		<string>$PORT</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>$LAUNCHD_LOG</string>
	<key>StandardErrorPath</key>
	<string>$LAUNCHD_LOG</string>
</dict>
</plist>
EOF

echo "Script: $SCRIPT_SRC"
echo "Python: $PYTHON3"
echo "Port: $PORT (bind host is always 127.0.0.1, hardcoded in logs-ui.py)"
if [ "$ACTION" = "apply" ]; then
    echo "Mode: --apply (will write $PLIST_DST and load it for gui/$(id -u); no sudo)"
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

if [ "$ACTION" = "dry-run" ]; then
    echo "dry-run: no changes made. Re-run with --apply to install (no sudo needed)."
    exit 0
fi

# NO CHANGES ABOVE THIS LINE. Everything past this point (--apply only)
# actually writes/loads the LaunchAgent.
mkdir -p "$HOME/Library/LaunchAgents"
cp "$TMP_PLIST" "$PLIST_DST"
launchctl bootout "gui/$(id -u)/$PLIST_LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"

echo "--- launchctl print gui/$(id -u)/$PLIST_LABEL ---"
launchctl print "gui/$(id -u)/$PLIST_LABEL" | head -5

echo "Installed and loaded $PLIST_LABEL. Open http://127.0.0.1:$PORT/ in your browser."
