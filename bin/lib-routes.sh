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
#
# The data file itself is read back with `read` and passed to `route` as
# literal, quoted arguments only -- never sourced or eval'd, same discipline
# dns-guard.sh uses for its own config files.

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
            echo "$dest"
            ;;
        *)
            echo "${dest}.0.0.0/8"
            ;;
    esac
}

# manual_restore_hint -- print the one-liner that restores SAVED_ROUTES_FILE
# by hand. Printed up front (before anything is deleted) and reprinted by
# restore_saved_routes/verify_restore on any failure, so it must stay a
# single source of truth for that command.
manual_restore_hint() {
    echo "  while read -r dest gw; do case \"\$gw\" in utun*) sudo route -n -q add -net \"\$dest\" -interface \"\$gw\";; *) sudo route -n -q add -net \"\$dest\" \"\$gw\";; esac; done < $SAVED_ROUTES_FILE"
}

# save_amnezia_routes IFACE -- write "destination gateway" pairs for every
# route whose Netif is IFACE to SAVED_ROUTES_FILE, normalising each
# destination out of netstat's compact notation (see normalize_dest) so the
# file on disk -- and the manual one-liner printed from it -- are
# unambiguous.
save_amnezia_routes() {
    iface=$1
    mkdir -p "$BUILD_DIR"
    : >"$SAVED_ROUTES_FILE"
    netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1, $2}' |
    while read -r dest gw; do
        [ -z "$dest" ] && continue
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
        netstat -rn -f inet 2>/dev/null | awk -v i="$iface" '$NF==i {print $1}' |
        while read -r dest; do
            [ "$dest" = "default" ] && continue   # never touch the default route
            ndest=$(normalize_dest "$dest")
            echo "  would run: sudo route -n -q delete -net \"$ndest\""
        done
        return 0
    fi
    del_ok=0
    del_fail=0
    del_fail_detail=""
    fail_cap=10
    while read -r dest _gw; do
        [ -z "$dest" ] && continue
        [ "$dest" = "default" ] && continue   # never touch the default route
        err=$(sudo route -n -q delete -net "$dest" 2>&1 >/dev/null)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            del_ok=$((del_ok + 1))
        else
            del_fail=$((del_fail + 1))
            if [ "$del_fail" -le "$fail_cap" ]; then
                del_fail_detail="${del_fail_detail}    sudo route -n -q delete -net \"$dest\"  ->  ${err:-(no output, exit $rc)}\n"
            fi
        fi
    done <"$SAVED_ROUTES_FILE"
    echo "Deleted routes from $iface: $del_ok succeeded, $del_fail failed."
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
            ndest=$(normalize_dest "$dest")
            case "$gw" in
                utun*) echo "  would run: sudo route -n -q add -net \"$ndest\" -interface \"$gw\"" ;;
                *) echo "  would run: sudo route -n -q add -net \"$ndest\" \"$gw\"" ;;
            esac
        done
        return 0
    fi
    if [ ! -f "$SAVED_ROUTES_FILE" ]; then
        echo "  (no saved-routes file at $SAVED_ROUTES_FILE, nothing to restore)"
        return 0
    fi
    restore_ok=0
    restore_fail=0
    restore_fail_detail=""
    fail_cap=10
    while read -r dest gw; do
        [ -z "$dest" ] && continue
        case "$gw" in
            utun*)
                cmd="sudo route -n -q add -net \"$dest\" -interface \"$gw\""
                err=$(sudo route -n -q add -net "$dest" -interface "$gw" 2>&1 >/dev/null)
                ;;
            *)
                cmd="sudo route -n -q add -net \"$dest\" \"$gw\""
                err=$(sudo route -n -q add -net "$dest" "$gw" 2>&1 >/dev/null)
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
verify_restore() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ ! -f "$SAVED_ROUTES_FILE" ] && return 0   # nothing was saved this run
    saved_count=$(wc -l <"$SAVED_ROUTES_FILE" | tr -d ' ')
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
    if [ "$now_count" != "$saved_count" ]; then
        echo
        echo "ERROR: route count mismatch after restore: saved $saved_count, now $now_count routes point at $utun_now." >&2
        echo "Saved routes are in $SAVED_ROUTES_FILE -- to restore by hand:" >&2
        manual_restore_hint >&2
        RESTORE_VERIFY_FAILED=1
        return 1
    fi
    echo "Verified: $now_count/$saved_count routes are back on $utun_now."
    return 0
}
