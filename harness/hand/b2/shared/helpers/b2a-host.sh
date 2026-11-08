#!/bin/bash
# b2a-host.sh: the host-side functions of the b2-admin modules (pg7, pg6, bl, p16ae); sourced by mod/<pkg>.sh (the driver's helpers are already defined when a module is sourced).
# A kdc-side script is pushed with b2a_push_script and run with b2a_run_kdc; its output is the packages' own record format (CELL name / RC:n / output / CELL_END name) and b2a_split makes
# $OUT/<pkg>/<stage>-<cell>.txt of each cell.
b2a_push_common() {   # the library and the kdc.conf editor, on the kdc under $VMD/b2a/
    push kdc "$SCRIPTS/helpers/b2a-lib.sh" "$VMD/b2a/b2a-lib.sh" 644 || return 1
    push kdc "$SCRIPTS/helpers/b2a-kdcconf.py" "$VMD/b2a/b2a-kdcconf.py" 644 || return 1
}
b2a_push_script() {   # b2a_push_script FILE...: the common files and these helpers/ files (mode 755) on the kdc
    local f
    b2a_push_common || return 1
    for f in "$@"; do push kdc "$SCRIPTS/helpers/$f" "$VMD/b2a/$f" 755 || return 1; done
}
b2a_split() {   # b2a_split RUNFILE DIR PREFIX: each CELL name ... CELL_END name block of a run transcript -> DIR/PREFIX-name.txt (the lines between the markers)
    awk -v dir="$2" -v pre="$3" '
        /^CELL_END / { if (out != "") close(out); out = ""; next }
        /^CELL / { out = dir "/" pre "-" $2 ".txt"; printf "" > out; next }
        out != "" { print >> out }' "$1"
}
b2a_run_kdc() {   # b2a_run_kdc CELLNAME SCRIPT ARGS...: the pushed script on the kdc as root, stdin = the caller's; transcript and both log deltas -> $OUT/CELLNAME.txt
    local name=$1 script=$2; shift 2
    cell "$name" kdc "sudo bash $VMD/b2a/$script $*" kdc+kadmin
}
b2a_pw3() { b2_pw 1; b2_pw 2; b2_pw 3; }   # the three throwaway passwords, one per line
