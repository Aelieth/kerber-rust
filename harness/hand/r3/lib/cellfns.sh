# cellfns.sh: the grading helpers the R3 cell calls and rec.sh does not define (sourced by cells/r3.sh after rec.sh). They are leg.sh's own definitions, copied byte for byte
# (harness/field/lib/leg.sh: tktcheck, countlast, tgtline): leg.sh needs LEG and baseline.env, so the cell cannot source it. In hold C the cell called countlast and tktcheck
# without any definition: bash printed 'command not found' (stdout.txt) and wrote no row, so five R3 rows never ran. hc.sh's source check (lib/undef-check.sh) now refuses to
# start the cell when a helper is missing, and checks after each cell that the rows exist.
# shellcheck shell=bash
tktcheck() {
    local l res=FAIL
    l=$(tgtline "$2")
    if [ "$LAST_RC" = 0 ] && [[ $l =~ $3 ]]; then res=PASS; fi
    _checkrow "$1" "$res" "$3" "$LAST_RC" "$l"
}

countlast() {
    local n res=FAIL
    n=$(grep -cE -- "$2" "$LAST_OUT" || true)
    if [ "$LAST_RC" = 0 ] && [ "$n" = "$3" ]; then res=PASS; fi
    _checkrow "$1" "$res" "$3 lines: $2" "$LAST_RC" "$n lines match"
}

tgtline() {
    TZ=UTC gawk -v rx="$1" '
        function t(d, h) { sub(/,$/, "", h); split(d, a, "/"); split(h, b, ":"); return mktime(a[3] " " a[1] " " a[2] " " b[1] " " b[2] " " b[3]) }
        !p && $5 ~ rx && $1 ~ /^[0-9][0-9]\// { s = t($1, $2); e = t($3, $4); r = s; p = $5; next }
        p && !done && /renew until/ { r = t($3, $4) }
        p && !done && /Flags:/ { f = $NF; done = 1 }
        END { if (p) printf "%s: %d s life, %d s renewable, flags %s\n", p, e - s, r - s, f; else print "no ticket matches " rx }
    ' "$LAST_OUT"
}
