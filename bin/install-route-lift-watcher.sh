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
#   /Library/Application Support/comrades-tunnel/route-lift.conf
#       (KEY=VALUE, PERSONAL_TUNNEL_PREFIX from DIR/tunnels.txt plus fixed
#       TIMEOUT/HELPDESK_LOG/STATE_DIR)
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
# Usage: install-route-lift-watcher.sh [--config DIR] [--dry-run|--apply|--uninstall]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

CONFIG_DIR="$REPO_ROOT/local"
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
            echo "Usage: $0 [--config DIR] [--dry-run|--apply|--uninstall]" >&2
            exit 2
            ;;
    esac
done

LIB_DIR="/Library/Application Support/comrades-tunnel"
WATCHER_SRC="$SCRIPT_DIR/route-lift-watcher.sh"
WATCHER_DST="$LIB_DIR/route-lift-watcher.sh"
LIBROUTES_SRC="$SCRIPT_DIR/lib-routes.sh"
LIBROUTES_DST="$LIB_DIR/lib-routes.sh"
CONF_DST="$LIB_DIR/route-lift.conf"
PLIST_LABEL="dev.comrades-tunnel.route-lift"
PLIST_DST="/Library/LaunchDaemons/$PLIST_LABEL.plist"
LOG_FILE="/var/log/comrades-tunnel-route-lift.log"
HELPDESK_LOG="/Library/Application Support/Checkpoint/Endpoint Connect/helpdesk.log"
STATE_DIR="$LIB_DIR/route-lift-state"
TIMEOUT=240
SAFETY_NET_INTERVAL=60

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
    echo "Uninstalling $PLIST_LABEL"
    sudo launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
    for f in "$PLIST_DST" "$WATCHER_DST" "$LIBROUTES_DST" "$CONF_DST"; do
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

TUNNELS_FILE="$CONFIG_DIR/tunnels.txt"
if [ ! -f "$TUNNELS_FILE" ]; then
    echo "ERROR: $TUNNELS_FILE not found (see config/example/tunnels.txt)" >&2
    exit 1
fi

# Reuse get_tunnel_prefix from lib-routes.sh instead of re-implementing the
# same grep/cut parsing here.
. "$LIBROUTES_SRC"
PERSONAL_TUNNEL_PREFIX=$(get_tunnel_prefix PERSONAL_TUNNEL_PREFIX)
if [ -z "$PERSONAL_TUNNEL_PREFIX" ]; then
    echo "ERROR: PERSONAL_TUNNEL_PREFIX not set in $TUNNELS_FILE" >&2
    exit 1
fi

echo "Checking path safety:"
assert_safe_path "$LIB_DIR"
assert_safe_path "$(dirname "$PLIST_DST")"
assert_safe_path "$(dirname "$LOG_FILE")"

TMP_CONF=$(mktemp)
TMP_PLIST=$(mktemp)
trap 'rm -f "$TMP_CONF" "$TMP_PLIST"' EXIT

cat >"$TMP_CONF" <<EOF
PERSONAL_TUNNEL_PREFIX=$PERSONAL_TUNNEL_PREFIX
TIMEOUT=$TIMEOUT
HELPDESK_LOG=$HELPDESK_LOG
STATE_DIR=$STATE_DIR
EOF

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
	<key>StandardOutPath</key>
	<string>$LOG_FILE</string>
	<key>StandardErrorPath</key>
	<string>$LOG_FILE</string>
</dict>
</plist>
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

if [ "$ACTION" = "dry-run" ]; then
    echo "dry-run: no changes made. Re-run with --apply (sudo) to install."
    exit 0
fi

# NO SUDO IS RUN ABOVE THIS LINE. Everything past this point (--apply only)
# requires sudo -- never run it from an automated/non-interactive context
# that isn't explicitly the human operator invoking --apply themselves.
sudo mkdir -p "$LIB_DIR" "$STATE_DIR"
sudo cp "$WATCHER_SRC" "$WATCHER_DST"
sudo cp "$LIBROUTES_SRC" "$LIBROUTES_DST"
sudo cp "$TMP_CONF" "$CONF_DST"
sudo cp "$TMP_PLIST" "$PLIST_DST"

sudo chown root:wheel "$WATCHER_DST" "$LIBROUTES_DST" "$CONF_DST" "$PLIST_DST" "$STATE_DIR"
sudo chmod 755 "$WATCHER_DST" "$LIBROUTES_DST"
sudo chmod 644 "$CONF_DST" "$PLIST_DST"
sudo chmod 755 "$STATE_DIR"

sudo launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST_DST"

echo "--- launchctl print system/$PLIST_LABEL ---"
sudo launchctl print "system/$PLIST_LABEL" | head -5

echo "Installed and loaded $PLIST_LABEL (RunAtLoad is false; it will first run on the next helpdesk.log change or StartInterval tick)."
