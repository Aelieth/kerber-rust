#!/usr/bin/env bash
# harness/field/scenarios/kdb-writes.sh --leg mit|rust: kadmind's writes to the database against the KDC's lockout writes, on
# the leg's KDC as upgrade.sh left it on kdc, MIT kinit and kadmin from client2:
#   SW.lockout: swlock (policy swpol, maxfailure 10) fails kinit 3 times, kadmind changes swother twice, swlock fails
#               twice more, kadmind changes swother again: getprinc shows 5 failed attempts;
#   SW.undo: a cpw of swpw that its policy (swpol2, minlength 20) refuses leaves its keys; the next cpw -randkey
#            changes them.
# Graded on both legs, MIT's first.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kdb-writes.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE ADMIN
R=${REALM//./\\.}
KA="kadmin -p admin/admin@$REALM -q"
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "for p in swlock swother swpw; do sudo kadmin.local -q \"delprinc -force \$p\"; done; for p in swpol swpol2; do sudo kadmin.local -q \"delpol -force \$p\"; done; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kadm <check> <ERE> <query>: remote MIT kadmin as admin/admin from client2 (a refused query may exit non-zero; its
# text is what is graded).
kadm() { check "$1" "$2" runin client2 "admin/admin's password ($ADMIN)" "$KA '$3' 2>&1; true" < <(once "$ADMIN"); }
# fails <check> <n>: n kinits of swlock from client2 with a wrong password, each refused.
fails() {
    check "$1" "^refused: $2\$" run client2 "n=0; for i in \$(seq 1 $2); do echo 'not-the-password' | kinit -c MEMORY:sw swlock@$REALM > /dev/null 2>&1 || n=\$((n + 1)); done; echo \"refused: \$n\""
}

section "kdb-writes --leg $LEG: kadmind's writes beside the KDC's lockout writes on the $LEG KDC"
kdcis
resetvm client2
run kdc "for p in swlock swother swpw; do sudo kadmin.local -q \"delprinc -force \$p\" 2>&1 | grep -v '^Authenticating'; done; for p in swpol swpol2; do sudo kadmin.local -q \"delpol -force \$p\" 2>&1 | grep -v '^Authenticating'; done; true"
check setup.policies 'policy swpol2' run kdc "sudo kadmin.local -q 'addpol -maxfailure 10 swpol' 2>&1; sudo kadmin.local -q 'addpol -minlength 20 swpol2' 2>&1; sudo kadmin.local -q listpols | grep -E '^swpol2?\$' | sed 's/^/policy /'"
check setup.swlock "^Principal \"swlock@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc -policy swpol swlock' 2>&1" < <(twice "$ALICE")
check setup.swother "^Principal \"swother@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey swother' 2>&1"
check setup.swpw "^Principal \"swpw@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey -policy swpol2 swpw' 2>&1"

section "SW.lockout: swlock's failed attempts kept across kadmind's writes to swother (MIT and ours: 5)"
fails SW.lockout.fail-3 3
kadm SW.lockout.write-1 "^Key for \"swother@$R\" randomized\\.\$" "cpw -randkey swother"
kadm SW.lockout.write-2 "^Principal \"swother@$R\" modified\\.\$" "modprinc -maxlife 1h swother"
fails SW.lockout.fail-2 2
kadm SW.lockout.write-3 "^Principal \"swother@$R\" modified\\.\$" "modprinc -maxlife 2h swother"
check SW.lockout.count '^Failed password attempts: 5$' run kdc "sudo kadmin.local -q 'getprinc swlock' 2>&1 | grep -E '^(Failed password attempts|Policy)'"

section "SW.undo: a cpw swpol2 refuses leaves swpw's keys; the next cpw -randkey changes them (MIT and ours)"
run kdc "sudo kadmin.local -q 'getprinc swpw' 2>&1 | grep -m1 -E '^Key: vno '"
K0=$(sed -n 's/^Key: vno \([0-9][0-9]*\),.*/\1/p' "$LAST_OUT")
kadm SW.undo.refused 'Password is too short' "cpw -pw short-pw-1 swpw"
check SW.undo.kept "^Key: vno ${K0:-none}, " run kdc "sudo kadmin.local -q 'getprinc swpw' 2>&1 | grep -m1 -E '^Key: vno '"
kadm SW.undo.next "^Key for \"swpw@$R\" randomized\\.\$" "cpw -randkey swpw"
check SW.undo.changed "^Key: vno $(( ${K0:-0} + 1 )), " run kdc "sudo kadmin.local -q 'getprinc swpw' 2>&1 | grep -m1 -E '^Key: vno '"
finish
