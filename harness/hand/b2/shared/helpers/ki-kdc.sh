#!/bin/bash
# ki-kdc.sh STAGE SECTION: KI's kdc-side steps, as root: `sudo bash ki-kdc.sh mit|ours setup|cleanup`. (lab-agent; module mod/ki.sh; VM-LEG.md)
# stdin: three lines, the leg's throwaway passwords PW1 (every principal's password) PW2 PW3 (unused here; the pipe the other modules use). Library: b2a-lib.sh (pushed beside this file).
# What it makes, per stage (and deletes at its end: the shell compares the realm database at the module boundary, and alice's key must not move):
#   kiuser                      the user of the kinit cells (K0-K5); never changes its password.
#   kiexp6m kiexp6r kiexp7m kiexp7r   REQUIRES_PWCHANGE (`modprinc +needchange`, the VM-LEG's step): one per (cell K6 / K7, tool m = MIT's kinit, r = ours), because the expired-password flow changes
#                               the password once and the VM-LEG's cells run it for each tool.
#   kinewmf kinewmd kinewrf kinewrd   the principals of kpasswd (K8): one per (profile f = noaddresses false / d = default, tool), each changed once.
#   kiwbm kiwbr                 the principals of K8b (the request's parts): one per tool, changed four times (the password goes between PW1 and PW2).
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit|ours) ;; *) echo "ki-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "KI_ABORT no passwords on stdin"; exit 2; }
EXPS="kiexp6m kiexp6r kiexp7m kiexp7r"
PRINCS="kiuser $EXPS kinewmf kinewmd kinewrf kinewrd kiwbm kiwbr"
case $SECTION in
setup)
    echo "== facts"
    sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmin.local /usr/sbin/kadmind 2>&1
    echo "global_ipv6: $(ip -o -6 addr show scope global | awk '{ print $2 ":" $4 }' | paste -sd' ' -)"
    for n in $PRINCS; do b2a_kal "add-$n" "addprinc -pw $PW1 $n"; done
    for n in $EXPS; do b2a_kal "needchange-$n" "modprinc +needchange $n"; done
    b2a_kal getprinc-kiexp6m 'getprinc kiexp6m'
    ;;
cleanup)
    for n in $PRINCS; do b2a_kal "del-$n" "delprinc -force $n"; done
    b2a_kal getprinc-gone 'getprinc kiuser'
    ;;
*) echo "ki-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
