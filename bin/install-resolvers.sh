#!/bin/sh
# Render /etc/resolver/<domain> files for split-horizon corporate DNS.
#
# For each domain in corp-domains.txt, writes one "nameserver <ip>" line per
# entry of corp-dns.txt (in order) into /etc/resolver/<domain>.
#
# Default mode is --dry-run: prints the rendered content and a diff against
# whatever already exists (or "would create" if it doesn't exist yet).
# --apply writes the files with sudo. Idempotent: running twice with --apply
# produces no further changes.
#
# Usage: install-resolvers.sh [--config DIR] [--apply]

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

CONFIG_DIR="$REPO_ROOT/local"
APPLY=0

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
        --apply)
            APPLY=1
            shift
            ;;
        --dry-run)
            APPLY=0
            shift
            ;;
        *)
            echo "Usage: $0 [--config DIR] [--apply|--dry-run]" >&2
            exit 2
            ;;
    esac
done

DOMAINS_FILE="$CONFIG_DIR/corp-domains.txt"
DNS_FILE="$CONFIG_DIR/corp-dns.txt"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "ERROR: $DOMAINS_FILE not found" >&2
    exit 1
fi
if [ ! -f "$DNS_FILE" ]; then
    echo "ERROR: $DNS_FILE not found" >&2
    exit 1
fi

# Strip comments/blank lines from a config file.
read_lines() {
    sed -e 's/#.*$//' "$1" | sed -e 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$'
}

DNS_IPS=$(read_lines "$DNS_FILE")
if [ -z "$DNS_IPS" ]; then
    echo "ERROR: no nameservers found in $DNS_FILE" >&2
    exit 1
fi

DOMAINS=$(read_lines "$DOMAINS_FILE")
if [ -z "$DOMAINS" ]; then
    echo "ERROR: no domains found in $DOMAINS_FILE" >&2
    exit 1
fi

TMP_RENDERED=$(mktemp)
trap 'rm -f "$TMP_RENDERED"' EXIT

echo "Config dir: $CONFIG_DIR"
if [ "$APPLY" = 1 ]; then
    echo "Mode: --apply (will write with sudo)"
else
    echo "Mode: --dry-run (no changes will be made)"
fi
echo

STATUS=0

for domain in $DOMAINS; do
    TARGET="/etc/resolver/$domain"

    : > "$TMP_RENDERED"
    for ip in $DNS_IPS; do
        echo "nameserver $ip" >> "$TMP_RENDERED"
    done

    echo "=== $TARGET ==="
    echo "--- rendered content ---"
    cat "$TMP_RENDERED"

    if [ -f "$TARGET" ]; then
        if diff -u "$TARGET" "$TMP_RENDERED" >/tmp/.install-resolvers.diff.$$ 2>&1; then
            echo "--- diff against existing file: none (up to date) ---"
        else
            echo "--- diff against existing file ($TARGET -> rendered) ---"
            cat /tmp/.install-resolvers.diff.$$
            STATUS=1
        fi
        rm -f /tmp/.install-resolvers.diff.$$
    else
        echo "--- existing file: none, would create $TARGET ---"
        STATUS=1
    fi

    if [ "$APPLY" = 1 ]; then
        sudo mkdir -p /etc/resolver
        sudo cp "$TMP_RENDERED" "$TARGET"
        sudo chmod 644 "$TARGET"
        echo "--- applied: $TARGET written ---"
    fi
    echo
done

if [ "$APPLY" = 0 ]; then
    if [ "$STATUS" = 0 ]; then
        echo "dry-run: all resolver files match the rendered config, no differences."
    else
        echo "dry-run: some resolver files would change (see diffs above)."
    fi
    exit "$STATUS"
fi

exit 0
