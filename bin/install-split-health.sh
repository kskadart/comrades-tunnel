#!/bin/sh
# Install bin/split-health.sh as a per-user LaunchAgent that periodically
# checks the dual-VPN split-tunnel routing and pings Telegram on a state
# change (see bin/split-health.sh's own header for the checks and the
# no-spam notification policy).
#
# Unlike install-dns-guard.sh / install-route-lift-watcher.sh, this renders
# a LaunchAgent (gui/$(id -u)), not a LaunchDaemon (system), and does NOT
# copy anything to a root-owned path first -- two reasons that is safe here,
# where it would not be for the root daemons:
#   - The check itself needs no privilege (read-only route/DNS/ifconfig
#     inspection) and must read the Telegram token/chat id from the
#     invoking user's own login Keychain -- only a process running IN that
#     user's GUI session can do that; a root LaunchDaemon cannot unlock a
#     user's Keychain.
#   - A LaunchAgent in gui/$(id -u) already runs with exactly the invoking
#     user's own privileges, reading a script from that same user's own
#     repo checkout. There is no privilege boundary crossed by pointing
#     ProgramArguments at the file in place (unlike a root LaunchDaemon
#     executing a file a non-root user could overwrite), so copying it to a
#     separate "trusted" location would add nothing here.
#
# Renders only:
#   ~/Library/LaunchAgents/dev.comrades-tunnel.split-health.plist
#
# Default action is --dry-run: prints the rendered plist, validates it with
# `plutil -lint`, and diffs it against whatever is currently installed (or
# says "would create"). Nothing is written or loaded. --apply writes the
# plist and loads it with `launchctl bootstrap gui/$(id -u)`. --uninstall
# unloads it (`launchctl bootout`) and removes the plist. No sudo anywhere.
#
# Usage: install-split-health.sh [--config DIR] [--interval MINUTES] [--dry-run|--apply|--uninstall]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

CONFIG_DIR="$REPO_ROOT/local"
INTERVAL=10
ACTION="dry-run"

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
        --interval)
            INTERVAL=$2
            shift 2
            ;;
        --interval=*)
            INTERVAL=${1#--interval=}
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
            echo "Usage: $0 [--config DIR] [--interval MINUTES] [--dry-run|--apply|--uninstall]" >&2
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
ABS_CONFIG_DIR=$(resolve_config_dir "$REPO_ROOT" "$CONFIG_DIR")

SCRIPT_SRC="$SCRIPT_DIR/split-health.sh"
PLIST_LABEL="dev.comrades-tunnel.split-health"
PLIST_DST="$HOME/Library/LaunchAgents/$PLIST_LABEL.plist"
LAUNCHD_LOG="$HOME/Library/Logs/comrades-tunnel-split-health.launchd.log"

case "$INTERVAL" in
    ''|*[!0-9]*)
        echo "ERROR: --interval must be a positive integer number of minutes, got '$INTERVAL'" >&2
        exit 2
        ;;
esac
INTERVAL_SECONDS=$((INTERVAL * 60))

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
if [ ! -d "$ABS_CONFIG_DIR" ]; then
    echo "ERROR: config dir $ABS_CONFIG_DIR not found" >&2
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
		<string>/bin/sh</string>
		<string>$SCRIPT_SRC</string>
		<string>--config</string>
		<string>$ABS_CONFIG_DIR</string>
	</array>
	<key>StartInterval</key>
	<integer>$INTERVAL_SECONDS</integer>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>$LAUNCHD_LOG</string>
	<key>StandardErrorPath</key>
	<string>$LAUNCHD_LOG</string>
</dict>
</plist>
EOF

echo "Config dir: $ABS_CONFIG_DIR"
echo "Interval: every ${INTERVAL} minute(s) (${INTERVAL_SECONDS}s) plus RunAtLoad"
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

echo "Installed and loaded $PLIST_LABEL. First check runs immediately (RunAtLoad), then every ${INTERVAL} minute(s)."
