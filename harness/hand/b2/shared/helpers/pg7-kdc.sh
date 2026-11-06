#!/bin/bash
# pg7-kdc.sh STAGE SECTION: PG7's cells (kadm5_hook) on the kdc VM, as root: `sudo bash pg7-kdc.sh mit|ours base|stanza-disable|stanza-only|stanza-off`.
# stdin: three lines, the leg's throwaway passwords PW1 PW2 PW3 (never printed, never on the host's command line). Principal names: m<cell> in the MIT stage, r<cell> in the ours stage.
# Source of the cells: {mit,rust}-cells.txt, *-stanza-*.txt, judge.txt (the commands themselves were not recorded; the shapes are):
#   base  : kadmin.local addprinc -pw / cpw -pw, MIT's kpasswd (the kdc's own /usr/bin/kpasswd, in BOTH stages: "kpasswd client stayed MIT", J0021), MIT's kinit
#   stanza: [plugins] kadm5_hook = { disable = nosuch } / { enable_only = nosuch } in kdc.conf (MIT reads kdc.conf ahead of krb5.conf; the ship build reads both: policy.rs:518), kadmin.service restarted,
#           then create / kpasswd / kinit (disable) and create / kinit (enable_only). MIT 1.22.2-4.fc43 faults in configure_interface (plugin.c:336, :340) at the first plugin load: kadmind
#           dumps core, kadmin.local exits 139.
#   off   : the stanza removed, kadmin.service restarted.   cleanup: the stage's principals deleted again.
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit) P=m ;; ours) P=r ;; *) echo "pg7-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "PG7_ABORT no passwords on stdin"; exit 2; }
cellset() {   # cellset C KPASSWD(yes|no): the cells of one stanza: create, (kpasswd), kinit
    local c=$1
    b2a_kal "$c-create" "addprinc -pw $PW1 $P$c"
    [ "$2" = yes ] && b2a_run_in "$PW1\n$PW3\n$PW3\n" "$c-kpasswd" kpasswd "$P$c"
    if [ "$2" = yes ]; then b2a_kinit "$c-kinit" "$P$c" "$PW3"; else b2a_kinit "$c-kinit" "$P$c" "$PW1"; fi
}
stanza() {   # stanza LABEL RELATION CELL KPASSWD
    local t0
    printf '[plugins]\n    kadm5_hook = {\n        %s\n    }\n' "$2" | b2a_conf append
    t0=$(date '+%Y-%m-%d %H:%M:%S')
    b2a_restart_kadmin "$1"
    sleep 3                                                    # the coredump's journal entry lands a moment after the unit fails
    echo "== journal: kadmin.service since $t0"
    journalctl -u kadmin.service --no-pager --since "$t0" 2>&1 | cut -c1-240
    echo "== end of journal"
    cellset "$3" "$4"
    sleep 3
    echo "== coredumps since $t0: the processes that dumped core and the faulting frames"
    journalctl --no-pager --since "$t0" -t systemd-coredump 2>&1 | grep -E 'dumped core|Stack trace|#[0-9] ' | cut -c1-200
    echo "== end of coredumps"
}
case $SECTION in
base)
    echo "== facts"
    sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmin.local /usr/sbin/kadmind /usr/bin/kpasswd 2>&1
    b2a_unit_state
    b2a_kal base-create "addprinc -pw $PW1 ${P}base"
    b2a_kal base-cpw "cpw -pw $PW2 ${P}base"
    b2a_run_in "$PW2\n$PW3\n$PW3\n" base-kpasswd kpasswd "${P}base"
    b2a_kinit base-kinit "${P}base" "$PW3"
    ;;
stanza-disable) stanza disable-nosuch 'disable = nosuch' dis yes ;;
stanza-only)    stanza enable-only-nosuch 'enable_only = nosuch' only no ;;
stanza-off)
    b2a_conf
    systemctl reset-failed kadmin > /dev/null 2>&1
    b2a_restart_kadmin off
    b2a_wait_kadmind && echo "KADMIND_LISTENING" || echo "KADMIND_NOT_LISTENING"
    ;;
cleanup)   # the principals this stage made, and nothing else: the realm database is as L1 found it (the shell compares at the module boundary; MIT's dis / only creates faulted: nothing to delete there)
    for n in base dis only; do b2a_kal "del-$n" "delprinc -force $P$n"; done
    ;;
*) echo "pg7-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
