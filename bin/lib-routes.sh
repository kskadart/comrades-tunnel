#!/bin/sh
# Shared route-manipulation helpers, sourced by bin/cp-connect.sh and
# bin/route-lift-watcher.sh. Not executable on its own -- it only defines
# functions.
#
# This is a straight extraction of the route save/normalise/delete/restore/
# verify logic that used to live in cp-connect.sh (see git history), moved
# here so route-lift-watcher.sh can reuse it instead of duplicating it. The
# functions still read/write the same global variables cp-connect.sh always
# set for them (that is how POSIX sh shares state between a script and a
# function library with no namespacing) -- any caller sourcing this file
# must set, before calling a function below:
#   DRY_RUN                 0 or 1 -- gates every mutating command
#   SAVED_ROUTES_FILE       path to the save/restore data file
#   BUILD_DIR               directory save_amnezia_routes will mkdir -p and
#                            write SAVED_ROUTES_FILE under
#   PERSONAL_TUNNEL_PREFIX  inet prefix of the personal VPN's utun (used by
#                            verify_restore/detect_utun_by_prefix)
#   RESTORE_HAD_FAILURES    initialise to 0; set to 1 by restore_saved_routes
#                            on any failed `route add`
#   RESTORE_VERIFY_FAILED   initialise to 0; set to 1 by verify_restore on a
#                            post-restore route-count mismatch
#   KEEP_ROUTES_FILE        path to the keep-routes-for.txt config (see
#                            config/example/keep-routes-for.txt); may not
#                            exist -- that means the feature is unused
#   KEEP_ROUTES_SCRIPT      path to keep-routes.py, which does the actual
#                            DNS resolution and CIDR containment check for
#                            compute_keep_set() below
#   KEPT_ROUTES_FILE        path compute_keep_set() writes its result to
#                            (truncated first on every call); read back by
#                            verify_restore() to size-check the restore
#                            correctly when some routes were never deleted
#   SCRIPT_DIR              directory this file lives in; both callers set
#                            it before sourcing this file. Only used by
#                            manual_restore_hint() to embed a live
#                            re-detection command (see that function).
#
# The data file itself is read back with `read` and passed to `route` as
# literal, quoted arguments only -- never sourced or eval'd, same discipline
# dns-guard.sh uses for its own config files.

# Never sudo when already root (e.g. a LaunchDaemon, which already runs as
# root): an extra sudo is unnecessary and, on a locked-down root PATH,
# possibly missing. Computed once at source time.
if [ "$(id -u)" = 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# detect_utun_by_prefix PREFIX -- print the first utunN whose inet address
# starts with PREFIX, never hardcoding a specific utun number.
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

# Total route count exactly as `netstat -rn -f inet | wc -l` -- matches the
# metric used to verify nothing changed, so before/during/after are directly
# comparable to that command.
route_count() {
    netstat -rn -f inet 2>/dev/null | wc -l | tr -d ' '
}

# routes_on_iface IFACE -- number of routes in the live table whose Netif is
# IFACE. Factored out of verify_restore so route-lift-watcher.sh's safety net
# (which needs the same count, for a different utun at a different time) does
# not duplicate the awk pipeline.
#
# Note on the `$NF==i` predicate used here and everywhere else in this file:
# `netstat -rn -f inet` rows have 4 fields (Destination Gateway Flags Netif)
# or, for link-layer/ARP-style entries, 5 (with a trailing Expire value) --
# see route_count()'s own field-count comment. For a 5-field row, $NF is
# that Expire value (a number, or "!"), never an interface name, so such a
# row can never spuriously match an iface filter here regardless of its
# actual Netif -- it just never matches at all (fails closed: excluded, not
# mis-attributed to the wrong interface). utun (VPN tunnel) interfaces do
# not have ARP/link-layer entries in practice, so this has not been
# observed to exclude anything real, but the predicate's own safety does
# not depend on that -- it is structurally unable to select a foreign
# interface's row.
routes_on_iface() {
    iface=$1
    netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i' | wc -l | tr -d ' '
}

# get_tunnel_prefix KEY -- return the VALUE of "KEY=" in $TUNNELS_FILE (the
# caller must set TUNNELS_FILE first). Same grep/cut parsing as
# bin/check-split.sh; never sourced/eval'd.
get_tunnel_prefix() {
    key=$1
    grep "^${key}=" "$TUNNELS_FILE" 2>/dev/null | head -1 | cut -d= -f2-
}

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
            # No explicit "/len" -- netstat only omits it when the mask
            # equals the classful default for the octet count shown (e.g.
            # "5.32" for 5.32.0.0/13's classful stand-in, "128.204.80" for
            # a /20). A full 4-octet form is an unambiguous host address
            # and passes through unchanged; 2/3-octet forms must be
            # expanded here -- ipaddress.ip_network() in keep-routes.py
            # rejects a bare "104.16" or "192.168.50" outright (not a
            # partial-address guess it is willing to make), so leaving them
            # unexpanded made a provider route in this form silently never
            # matchable by the keep-routes feature.
            oldifs=$IFS
            IFS=.
            set -- $dest
            IFS=$oldifs
            case $# in
                2) printf '%s.%s.0.0/16\n' "$1" "$2" ;;
                3) printf '%s.%s.%s.0/24\n' "$1" "$2" "$3" ;;
                *) echo "$dest" ;;   # 4 octets (a full host address) -- unchanged
            esac
            ;;
        *)
            echo "${dest}.0.0.0/8"
            ;;
    esac
}

# manual_restore_hint -- print the command(s) that restore SAVED_ROUTES_FILE
# by hand. Printed up front (before anything is deleted) and reprinted by
# restore_saved_routes/verify_restore on any failure, so it must stay a
# single source of truth for that command.
#
# Deliberately does NOT embed a specific "utunN" gateway name: utun numbers
# are not stable across sessions (a reconnect can renumber the personal
# VPN's tunnel), so a one-liner baked with today's name could restore ~2,200
# routes onto tomorrow's *wrong* utun if run later. Instead it re-detects
# the live interface, inline, at the moment the hint is actually run --
# the same detect_utun_by_prefix() logic, reimplemented without depending
# on this repo checkout still being at $SCRIPT_DIR (the hint may be copied
# out and run somewhere else, e.g. after a reboot or a repo move).
manual_restore_hint() {
    echo "  Manual restore -- re-detects the CURRENT personal-VPN utun (never reuse a name from a previous run):"
    echo "    live_utun=\$(for i in \$(ifconfig -l | tr ' ' '\\n' | grep '^utun'); do case \"\$(ifconfig \"\$i\" 2>/dev/null | awk '/inet /{print \$2}')\" in ${PERSONAL_TUNNEL_PREFIX}*) echo \"\$i\"; break;; esac; done); [ -n \"\$live_utun\" ] || { echo 'no personal VPN utun found (prefix $PERSONAL_TUNNEL_PREFIX)' >&2; exit 1; }; while read -r dest gw; do case \"\$gw\" in utun*) sudo route -n -q add -net \"\$dest\" -interface \"\$live_utun\";; *) sudo route -n -q add -net \"\$dest\" \"\$gw\";; esac; done < \"$SAVED_ROUTES_FILE\""
}

# save_amnezia_routes IFACE -- write "destination gateway" pairs for every
# route whose Netif is IFACE to SAVED_ROUTES_FILE, normalising each
# destination out of netstat's compact notation (see normalize_dest) so the
# file on disk -- and the manual one-liner printed from it -- are
# unambiguous.
#
# Only rows whose Gateway is the interface itself (an "-interface"-style
# route, e.g. AmneziaVPN's own site routes) are saved. A row on this same
# Netif whose Gateway is a literal address instead -- observed live as
# exactly one row, where destination == gateway == the tunnel's own inet
# address (the kernel's own point-to-point host route for the interface,
# flag UH) -- is the kernel's, not Amnezia's: it was never installed by a
# `route add -interface` call, restoring it with one would just recreate
# what the kernel already owns, and deleting/re-adding it needlessly is
# also why it used to be the one route a lift could never cleanly restore
# (see the README/review this fixes). "default" is never saved either
# (delete_amnezia_routes already refuses to touch it, so saving it would
# only make the saved/expected counts dishonest -- see verify_restore).
save_amnezia_routes() {
    iface=$1
    mkdir -p "$BUILD_DIR"
    : >"$SAVED_ROUTES_FILE"
    netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1, $2}' |
    while read -r dest gw; do
        [ -z "$dest" ] && continue
        [ "$dest" = "default" ] && continue
        case "$gw" in
            utun*) ;;
            *) continue ;;
        esac
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
        netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1, $2}' |
        while read -r dest gw; do
            [ -z "$dest" ] && continue
            [ "$dest" = "default" ] && continue   # never touch the default route
            case "$gw" in
                utun*) ;;
                *) continue ;;   # the kernel's own routes on this interface -- see save_amnezia_routes; never saved, so a live run never deletes them either
            esac
            ndest=$(normalize_dest "$dest")
            # A dry-run keep-set preview (see compute_keep_set) writes here
            # for real before this runs -- skip anything it decided to
            # keep, so the preview does not claim it "would delete" a route
            # that a live run would actually leave alone.
            if [ -n "${KEPT_ROUTES_FILE:-}" ] && [ -f "$KEPT_ROUTES_FILE" ] &&
               awk -v d="$ndest" '$1==d{f=1} END{exit !f}' "$KEPT_ROUTES_FILE"; then
                continue
            fi
            echo "  would run: sudo route -n -q delete -net \"$ndest\""
        done
        return 0
    fi
    del_ok=0
    del_fail=0
    del_skip=0
    del_fail_detail=""
    fail_cap=10
    while read -r dest _gw; do
        [ -z "$dest" ] && continue
        [ "$dest" = "default" ] && continue   # never touch the default route
        # Re-confirm the route's CURRENT interface is still the one it was
        # saved from: something may have re-pointed this destination since
        # save_amnezia_routes ran (a flap, a race with something else
        # touching the table) -- deleting it here would then delete a route
        # that now belongs to a different interface, purely by coincidence
        # of destination.
        cur_iface=$(route -n get -net "$dest" 2>/dev/null | awk '/interface:/{print $2}')
        if [ "$cur_iface" != "$iface" ]; then
            del_skip=$((del_skip + 1))
            continue
        fi
        err=$($SUDO route -n -q delete -net "$dest" 2>&1 >/dev/null)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            del_ok=$((del_ok + 1))
        else
            del_fail=$((del_fail + 1))
            if [ "$del_fail" -le "$fail_cap" ]; then
                del_fail_detail="${del_fail_detail}    $SUDO route -n -q delete -net \"$dest\"  ->  ${err:-(no output, exit $rc)}\n"
            fi
        fi
    done <"$SAVED_ROUTES_FILE"
    echo "Deleted routes from $iface: $del_ok succeeded, $del_fail failed, $del_skip skipped (interface changed since save)."
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
# again, and sets RESTORE_HAD_FAILURES so the caller can exit non-zero even
# if everything else finished. In --dry-run, SAVED_ROUTES_FILE was never
# written (nothing is written to disk in dry-run), so the preview is
# computed from the live table for the personal utun detected at startup
# instead -- the caller must set AMNEZIA_UTUN_START for that preview.
restore_saved_routes() {
    if [ "$DRY_RUN" = 1 ]; then
        if [ -z "$AMNEZIA_UTUN_START" ]; then
            echo "  (dry-run: no personal-VPN utun currently present to preview restore commands for)"
            return 0
        fi
        netstat -rn -f inet 2>/dev/null | awk -v i="$AMNEZIA_UTUN_START" '$NF==i {print $1, $2}' |
        while read -r dest gw; do
            [ -z "$dest" ] && continue
            [ "$dest" = "default" ] && continue
            case "$gw" in
                "$AMNEZIA_UTUN_START") ;;   # Amnezia's own routes -- see save_amnezia_routes
                *) continue ;;              # the kernel's own routes on this interface -- never saved, so never restored
            esac
            ndest=$(normalize_dest "$dest")
            # Mirror what a live run's SAVED_ROUTES_FILE would actually
            # hold: a route never deleted in the first place (per the
            # keep-set, if one is configured -- see compute_keep_set) has
            # nothing to restore either.
            if [ -n "${KEPT_ROUTES_FILE:-}" ] && [ -f "$KEPT_ROUTES_FILE" ] &&
               awk -v d="$ndest" '$1==d{f=1} END{exit !f}' "$KEPT_ROUTES_FILE"; then
                continue
            fi
            echo "  would run: sudo route -n -q add -net \"$ndest\" -interface \"$gw\""
        done
        return 0
    fi
    if [ ! -f "$SAVED_ROUTES_FILE" ]; then
        echo "  (no saved-routes file at $SAVED_ROUTES_FILE, nothing to restore)"
        return 0
    fi
    # utun numbers are not stable across sessions (a reconnect can renumber
    # the personal VPN's tunnel) -- NEVER replay the gateway name recorded
    # in SAVED_ROUTES_FILE as-is, since it may now name a different tunnel
    # (or nothing at all). Re-detect the live interface once, up front, and
    # use that name for every interface-route entry below; refuse outright
    # if it is not present -- leaving routes lifted and saying so loudly is
    # far better than guessing and installing ~2,200 personal routes onto
    # whatever now happens to hold that old utun number.
    live_utun=$(detect_utun_by_prefix "$PERSONAL_TUNNEL_PREFIX")
    if [ -z "$live_utun" ]; then
        echo
        echo "ERROR: the personal VPN interface (prefix $PERSONAL_TUNNEL_PREFIX) is not present -- refusing to restore $SAVED_ROUTES_FILE onto a guessed/stale utun name." >&2
        echo "Reconnect AmneziaVPN, then restore by hand once the tunnel is back:" >&2
        manual_restore_hint >&2
        RESTORE_HAD_FAILURES=1
        return 1
    fi
    restore_ok=0
    restore_fail=0
    restore_fail_detail=""
    fail_cap=10
    while read -r dest gw; do
        [ -z "$dest" ] && continue
        case "$gw" in
            utun*)
                cmd="$SUDO route -n -q add -net \"$dest\" -interface \"$live_utun\""
                err=$($SUDO route -n -q add -net "$dest" -interface "$live_utun" 2>&1 >/dev/null)
                ;;
            *)
                cmd="$SUDO route -n -q add -net \"$dest\" \"$gw\""
                err=$($SUDO route -n -q add -net "$dest" "$gw" 2>&1 >/dev/null)
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
#
# Routes named in KEPT_ROUTES_FILE (see compute_keep_set) were never
# deleted in the first place, so they are still on the interface the whole
# time -- the expected post-restore count is saved+kept, not just saved.
# KEPT_ROUTES_FILE is optional (unset or absent means kept=0, i.e. the
# exact pre-keep-routes behaviour) so this is a no-op for any caller not
# using that feature.
verify_restore() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ ! -f "$SAVED_ROUTES_FILE" ] && return 0   # nothing was saved this run
    saved_count=$(wc -l <"$SAVED_ROUTES_FILE" | tr -d ' ')
    kept_count=0
    if [ -n "${KEPT_ROUTES_FILE:-}" ] && [ -f "$KEPT_ROUTES_FILE" ]; then
        kept_count=$(wc -l <"$KEPT_ROUTES_FILE" | tr -d ' ')
    fi
    expected_count=$((saved_count + kept_count))
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
    now_count=$(routes_on_iface "$utun_now")
    if [ "$now_count" != "$expected_count" ]; then
        echo
        echo "ERROR: route count mismatch after restore: expected $expected_count ($saved_count restored + $kept_count kept), now $now_count routes point at $utun_now." >&2
        echo "Saved routes are in $SAVED_ROUTES_FILE -- to restore by hand:" >&2
        manual_restore_hint >&2
        RESTORE_VERIFY_FAILED=1
        return 1
    fi
    echo "Verified: $now_count/$expected_count routes are back on $utun_now ($saved_count restored + $kept_count kept)."
    return 0
}

# compute_keep_set ROUTES_FILE -- given ROUTES_FILE already containing
# normalised "dest gateway" pairs for the personal VPN's utun (as written
# by save_amnezia_routes, or a throwaway preview file for a --dry-run),
# determine which of those routes must survive a lift per KEEP_ROUTES_FILE
# (see config/example/keep-routes-for.txt) using KEEP_ROUTES_SCRIPT
# (bin/keep-routes.py -- POSIX sh has no sane way to do DNS resolution plus
# CIDR containment). On success (0): ROUTES_FILE is rewritten in place with
# the kept lines removed, so callers can go on to save/delete/preview
# exactly as before, just on a smaller set; KEPT_ROUTES_FILE (truncated
# first) ends up holding one "dest gateway entry detail" line per kept
# route, empty if the feature is unused or nothing matched.
#
# Returns 1 -- and leaves ROUTES_FILE untouched -- only when
# KEEP_ROUTES_FILE has active entries but none of them could be resolved
# or parsed at all (no python3, or every single lookup failed). The caller
# MUST then treat this exactly like any other "cannot verify it's safe to
# proceed" case and lift nothing this cycle: proceeding without a keep-set
# would silently delete the very routes this feature exists to protect. A
# domain that individually fails to resolve while others succeed is only a
# warning (printed to stderr by keep-routes.py) and does not reach this
# path -- see that script's own compute() for the exact rule.
compute_keep_set() {
    routes_file=$1
    : >"$KEPT_ROUTES_FILE"

    active_entries=0
    if [ -n "${KEEP_ROUTES_FILE:-}" ] && [ -f "$KEEP_ROUTES_FILE" ]; then
        active_entries=$(grep -v -E '^[[:space:]]*(#|$)' "$KEEP_ROUTES_FILE" 2>/dev/null | grep -c .)
        [ -z "$active_entries" ] && active_entries=0
    fi
    if [ "$active_entries" -eq 0 ] 2>/dev/null; then
        return 0   # feature unused (missing/empty file) -- empty keep-set, not a failure
    fi

    # Pinned to the absolute system path, never a PATH-resolved "python3":
    # this runs unattended as root under the installed LaunchDaemon, whose
    # PATH is minimal/unspecified -- resolving by name would either find
    # nothing or, worse, whatever a non-root user's PATH happened to expose.
    if [ ! -x /usr/bin/python3 ]; then
        echo "FATAL: $KEEP_ROUTES_FILE has $active_entries active entries but /usr/bin/python3 is not available to compute the keep-set." >&2
        return 1
    fi

    kept_out=$(mktemp) || { echo "FATAL: could not create a temp file to compute the keep-set" >&2; return 1; }
    err_out=$(mktemp) || { rm -f "$kept_out"; echo "FATAL: could not create a temp file to compute the keep-set" >&2; return 1; }
    /usr/bin/python3 "$KEEP_ROUTES_SCRIPT" compute "$KEEP_ROUTES_FILE" "$routes_file" >"$kept_out" 2>"$err_out"
    rc=$?
    if [ -s "$err_out" ]; then
        while IFS= read -r eline; do echo "$eline" >&2; done <"$err_out"
    fi
    rm -f "$err_out"
    if [ "$rc" -ne 0 ]; then
        rm -f "$kept_out"
        return 1
    fi
    mv "$kept_out" "$KEPT_ROUTES_FILE"

    if [ -s "$KEPT_ROUTES_FILE" ]; then
        tmp_filtered=$(mktemp) || { echo "FATAL: could not create a temp file to filter kept routes" >&2; return 1; }
        # NR==FNR reads KEPT_ROUTES_FILE (col 1 = dest, tab-separated) into
        # "kept"; the second pass over routes_file (col 1 = dest,
        # space-separated) drops any line whose destination is in that set.
        # awk's default field splitter treats runs of tabs/spaces alike, so
        # $1 is correct either way without setting FS explicitly.
        awk 'NR==FNR{kept[$1]=1; next} !($1 in kept)' "$KEPT_ROUTES_FILE" "$routes_file" >"$tmp_filtered"
        mv "$tmp_filtered" "$routes_file"
    fi
    return 0
}
