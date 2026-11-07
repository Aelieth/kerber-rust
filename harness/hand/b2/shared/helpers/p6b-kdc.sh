#!/bin/bash
# p6b-kdc.sh STAGE SECTION: P6b's kdc-side steps, as root: `sudo bash p6b-kdc.sh mit|ours setup|cleanup`. (b2-client; module mod/p6b.sh; spec/p6b.md)
# stdin: three lines, the leg's throwaway passwords PW1 (the scratch principals' password) PW2 PW3 (unused here; the pipe the other modules use). Library: b2a-lib.sh (the b2-admin builder's, pushed beside this file).
# What it makes, per stage (and deletes at its end: the shell compares the realm database at the module boundary, and alice's key must not move):
#   p6bkp-c<1|2><m|r>   four principals without a policy, one per (client, tool): the kpasswd cell changes each one's password once. The recorded leg changed ALICE's password and set it back with `kadmin.local cpw`
#                       between the two tools (wrapper.txt `cpw_reset=0`); here alice never changes (the shell's realm row watches her key version number).
#   p6bsw               one principal for the kswitch cell: a second ticket cache in a DIR collection next to alice's.
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit|ours) ;; *) echo "p6b-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "P6B_ABORT no passwords on stdin"; exit 2; }
PRINCS="p6bkp-c1m p6bkp-c1r p6bkp-c2m p6bkp-c2r p6bsw"
case $SECTION in
setup)
    echo "== facts"
    sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmin.local /usr/sbin/kadmind 2>&1
    for n in $PRINCS; do b2a_kal "add-$n" "addprinc -pw $PW1 $n"; done
    ;;
cleanup)
    for n in $PRINCS; do b2a_kal "del-$n" "delprinc -force $n"; done
    b2a_kal getprinc-gone 'getprinc p6bsw'
    ;;
*) echo "p6b-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
