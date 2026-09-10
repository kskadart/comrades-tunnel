#!/bin/sh
# Install bin/dns-guard.sh as a root LaunchDaemon that reverts the corporate
# VPN client's rewrite of the primary network service's DNS servers.
#
# The daemon script and its conf are copied to a root-owned location under
# /usr/local/lib/comrades-tunnel/ instead of being run in place from this
# repo checkout, because a LaunchDaemon runs as root (at RunAtLoad and on
# every matching WatchPaths event) and its ProgramArguments points at a
# fixed path on disk: if that path were inside the user's home directory,
# anything able to write there as that user -- a bug in an unrelated tool,
# a compromised dependency, malware -- could rewrite the script and have it
# executed as root the next time the daemon fires. Copying it to a
# root-owned path with 755/644 permissions at --apply time closes that
# privilege-escalation route; only root can change what the daemon runs.
#
# Renders:
#   /usr/local/lib/comrades-tunnel/dns-guard.sh    (copy of bin/dns-guard.sh)
#   /usr/local/lib/comrades-tunnel/dns-guard.conf  (KEY=VALUE, from
#                                                    DIR/dns-guard.txt +
#                                                    DIR/corp-dns.txt)
#   /Library/LaunchDaemons/dev.comrades-tunnel.dns-guard.plist
#
# Default action is --dry-run: prints each rendered file and a diff against
# whatever is currently installed (or "would create"), and validates the
# rendered plist with `plutil -lint`. Nothing is written or executed.
# --apply performs the install with sudo and (re)loads the daemon.
# --uninstall stops the daemon and removes the three installed files.
#
# Usage: install-dns-guard.sh [--config DIR] [--dry-run|--apply|--uninstall]

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

LIB_DIR="/usr/local/lib/comrades-tunnel"
GUARD_SCRIPT_SRC="$SCRIPT_DIR/dns-guard.sh"
GUARD_SCRIPT_DST="$LIB_DIR/dns-guard.sh"
GUARD_CONF_DST="$LIB_DIR/dns-guard.conf"
PLIST_LABEL="dev.comrades-tunnel.dns-guard"
PLIST_DST="/Library/LaunchDaemons/$PLIST_LABEL.plist"
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

if [ "$ACTION" = "uninstall" ]; then
    echo "Uninstalling $PLIST_LABEL"
    sudo launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
    sudo rm -f "$PLIST_DST" "$GUARD_SCRIPT_DST" "$GUARD_CONF_DST"
    echo "Removed: $PLIST_DST"
    echo "Removed: $GUARD_SCRIPT_DST"
    echo "Removed: $GUARD_CONF_DST"
    exit 0
fi

if [ ! -f "$GUARD_SCRIPT_SRC" ]; then
    echo "ERROR: $GUARD_SCRIPT_SRC not found" >&2
    exit 1
fi

DNS_GUARD_TXT="$CONFIG_DIR/dns-guard.txt"
CORP_DNS_TXT="$CONFIG_DIR/corp-dns.txt"
if [ ! -f "$DNS_GUARD_TXT" ]; then
    echo "ERROR: $DNS_GUARD_TXT not found" >&2
    exit 1
fi
if [ ! -f "$CORP_DNS_TXT" ]; then
    echo "ERROR: $CORP_DNS_TXT not found" >&2
    exit 1
fi

SERVERS=$(grep '^SERVERS=' "$DNS_GUARD_TXT" | tail -1 | cut -d= -f2-)
MODE=$(grep '^MODE=' "$DNS_GUARD_TXT" | tail -1 | cut -d= -f2-)
CORP_DNS=$(normalize_list "$(read_lines "$CORP_DNS_TXT" | tr '\n' ' ')")
SERVERS=$(normalize_list "$SERVERS")
MODE=$(normalize_list "$MODE")

if [ -z "$SERVERS" ]; then
    echo "ERROR: SERVERS not set in $DNS_GUARD_TXT" >&2
    exit 1
fi
if [ -z "$MODE" ]; then
    MODE="corp-only"
fi

TMP_CONF=$(mktemp)
TMP_PLIST=$(mktemp)
trap 'rm -f "$TMP_CONF" "$TMP_PLIST"' EXIT

cat >"$TMP_CONF" <<EOF
SERVERS=$SERVERS
MODE=$MODE
CORP_DNS=$CORP_DNS
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
		<string>$GUARD_SCRIPT_DST</string>
	</array>
	<key>WatchPaths</key>
	<array>
		<string>/Library/Preferences/SystemConfiguration/preferences.plist</string>
		<string>/private/var/run/resolv.conf</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>3</integer>
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

echo "=== $GUARD_CONF_DST ==="
echo "--- rendered content ---"
cat "$TMP_CONF"
if [ -f "$GUARD_CONF_DST" ]; then
    if diff -u "$GUARD_CONF_DST" "$TMP_CONF"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($GUARD_CONF_DST -> rendered) ---"
    fi
else
    echo "--- installed file: none, would create $GUARD_CONF_DST ---"
fi
echo

echo "=== $GUARD_SCRIPT_DST ==="
if [ -f "$GUARD_SCRIPT_DST" ]; then
    if diff -u "$GUARD_SCRIPT_DST" "$GUARD_SCRIPT_SRC"; then
        echo "--- diff against installed file: none (up to date) ---"
    else
        echo "--- diff against installed file above ($GUARD_SCRIPT_DST -> $GUARD_SCRIPT_SRC) ---"
    fi
else
    echo "--- installed file: none, would create $GUARD_SCRIPT_DST (copy of $GUARD_SCRIPT_SRC) ---"
fi
echo

if [ "$ACTION" = "dry-run" ]; then
    echo "dry-run: no changes made. Re-run with --apply (sudo) to install."
    exit 0
fi

# NO SUDO IS RUN ABOVE THIS LINE. Everything past this point (--apply only)
# requires sudo -- never run it from an automated/non-interactive context
# that isn't explicitly the human operator invoking --apply themselves.
sudo mkdir -p "$LIB_DIR"
sudo cp "$GUARD_SCRIPT_SRC" "$GUARD_SCRIPT_DST"
sudo cp "$TMP_CONF" "$GUARD_CONF_DST"
sudo cp "$TMP_PLIST" "$PLIST_DST"

sudo chown root:wheel "$GUARD_SCRIPT_DST" "$GUARD_CONF_DST" "$PLIST_DST"
sudo chmod 755 "$GUARD_SCRIPT_DST"
sudo chmod 644 "$GUARD_CONF_DST" "$PLIST_DST"

sudo launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST_DST"

echo "--- launchctl print system/$PLIST_LABEL ---"
sudo launchctl print "system/$PLIST_LABEL" | head -5

echo "--- running the guard once ---"
sudo "$GUARD_SCRIPT_DST"

echo "Installed and started $PLIST_LABEL."
