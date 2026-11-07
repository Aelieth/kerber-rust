#!/bin/bash
# pg6-kdc.sh STAGE SECTION: PG6's cells (pwqual by name) on the kdc VM, as root: `sudo bash pg6-kdc.sh mit|ours setup|kadmin|kpasswd|stanza-disable|stanza-only|stanza-off`.
# stdin: three lines, the leg's throwaway passwords PW1 (the old password) PW2 (a good new one) PW3 (unused here). Principal names: m<stem> in the MIT stage, r<stem> in the ours stage.
# Source of the cells: {mit,rust}-kadmin.txt (13 cells; the commands are scripts/kadmin-local-gate.sh:308-336), {mit,rust}-kpasswd.txt (the kpasswd cells: MIT's
# /usr/bin/kpasswd on the kdc against kadmind, in both stages, "kpasswd client stayed MIT" J0020/J0022), *-stanza-*.txt (the [plugins] pwqual cells), mit-conf.txt / mit-dict.txt (dict_file
# = /var/kerberos/krb5kdc/dict.txt, a 3-line file; the gate's equivalent is zebra / correcthorse / apple). The commands were not recorded for the kpasswd and stanza halves: rewritten from outputs.
# kadmin/history: the lab's f4-mit realm lacks it as found; the kadm5 layer creates it lazily the first time a password under a policy is set (MIT's kadmind did, in B2 on the real lab: the shell's realm row went
# red). setup records whether it exists at the stage's start (HISTORY_AT_START, kept in $B2A_D/pg6-hist-<stage>), kadmin says whether it exists before and after the cell that makes it (cpw-princ: HISTORY_BEFORE_CPW_PRINC,
# HISTORY_AFTER_CPW_PRINC; MIT and ours alike), kpasswd at its end (HISTORY_AFTER_KPASSWD, with the getprinc cell of what was created),
# and cleanup deletes it when the stage created it (HISTORY_CREATED_BY_STAGE), after the principals and the policy, so that the realm is as found and the next stage starts without it. Nothing creates it here.
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit) P=m ;; ours) P=r ;; *) echo "pg6-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "PG6_ABORT no passwords on stdin"; exit 2; }
DICT=$B2A_KDCDIR/dict.txt
HIST=kadmin/history@$B2A_REALM
HISTMARK=$B2A_D/pg6-hist-$STAGE
CAP="$(printf '%s' "${P^^}")"                       # M or R: the upper-case prefix of a password equal to a principal name
kpw() {   # kpw CELL PRINC OLD NEW: MIT's kpasswd, the old and the new password (twice) on its stdin
    b2a_run_in "$3\n$4\n$4\n" "$1" kpasswd "$2"
}
hist() {   # hist: yes when kadmin/history exists in the realm database (a read: getprinc does not create it)
    if kadmin.local -q "getprinc $HIST" < /dev/null 2>&1 | grep -q "^Principal: $HIST\$"; then echo yes; else echo no; fi
}
case $SECTION in
setup)
    hist > "$HISTMARK"
    echo "HISTORY_AT_START $(cat "$HISTMARK")"
    echo "== facts"
    sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmin.local /usr/sbin/kadmind /usr/bin/kpasswd 2>&1
    printf 'zebra\ncorrecthorse\napple\n' > "$DICT"
    restorecon "$DICT" 2> /dev/null
    b2a_conf realm dict_file "$DICT"
    echo "DICT_CONF"
    echo "DICT_FILE:$(wc -l < "$DICT")"
    echo "DICT:$(grep -n '^[[:space:]]*dict_file' "$B2A_KDCDIR/kdc.conf")"
    b2a_restart_kadmin dict
    b2a_wait_kadmind && echo "KADMIND_LISTENING" || echo "KADMIND_NOT_LISTENING"
    b2a_kal addpol 'addpol pq'
    b2a_kal getpol 'getpol pq'
    ;;
kadmin)   # the gate's list (kadmin-local-gate.sh:308-336), cell by cell as the record has them
    b2a_kal empty-nopolicy "addprinc -pw \"\" ${P}empty"
    b2a_kal princ-component "addprinc -pw ${CAP}NAME -policy pq ${P}name"
    b2a_kal realm "addprinc -pw kerber.test -policy pq ${P}realm"
    b2a_kal nopolicy-name-ok "addprinc -pw ${P}free ${P}free"
    b2a_kal rejected-not-created "getprinc ${P}name"
    b2a_kal cpw-empty "cpw -pw \"\" ${P}free"
    b2a_kal modprinc-policy "modprinc -policy pq ${P}free"
    echo "HISTORY_BEFORE_CPW_PRINC $(hist)"
    b2a_kal cpw-princ "cpw -pw ${CAP}Free ${P}free"       # the cell that makes kadmin/history on both stages (probed cell by cell on 2026-10-13): a password change under the policy; the princ module refuses it, the history key was fetched first
    echo "HISTORY_AFTER_CPW_PRINC $(hist)"
    b2a_kal dict-word "addprinc -pw CorrectHorse -policy pq ${P}dict"
    b2a_kal dict-nopolicy-ok "addprinc -pw correcthorse ${P}dictnp"
    b2a_kal dict-substring-ok "addprinc -pw correcthorse1 -policy pq ${P}dictsub"
    echo "CELL getprinc-dictsub"
    kadmin.local -q "getprinc ${P}dictsub" 2>&1 | grep -E '^(Principal:|Password expiration date:|Policy:)'
    echo "CELL_END getprinc-dictsub"
    ;;
kpasswd)  # with the policy pq (min length 1, classes 1, history 1): ke kp kd ko; without a policy: ne nd np
    b2a_kal ke-create "addprinc -pw $PW1 -policy pq ${P}ke"
    kpw kpol-empty "${P}ke" "$PW1" ""
    b2a_kinit kpol-empty-still "${P}ke" "$PW1"
    b2a_kal kp-create "addprinc -pw $PW1 -policy pq ${P}kp"
    kpw kpol-princ "${P}kp" "$PW1" "${P}kp"                   # the new password is the principal's own name, 3 characters: MIT's kpasswd accepts a component of 3 to 5 (docs/mit-deviations.md:40)
    b2a_kinit kpol-princ-still "${P}kp" "$PW1"
    b2a_kal kd-create "addprinc -pw $PW1 -policy pq ${P}kd"
    kpw kpol-dict "${P}kd" "$PW1" "CorrectHorse"
    b2a_kinit kpol-dict-still "${P}kd" "$PW1"
    b2a_kal ko-create "addprinc -pw $PW1 -policy pq ${P}ko"
    kpw kpol-ok "${P}ko" "$PW1" "$PW2"
    b2a_kinit kpol-kinit "${P}ko" "$PW2"
    b2a_kal ne-create "addprinc -pw $PW1 ${P}ne"
    kpw knp-empty "${P}ne" "$PW1" ""
    b2a_kinit knp-empty-still "${P}ne" "$PW1"
    b2a_kal nd-create "addprinc -pw $PW1 ${P}nd"
    kpw knp-dict "${P}nd" "$PW1" "CorrectHorse"
    b2a_kinit knp-kinit "${P}nd" "CorrectHorse"
    b2a_kal np-create "addprinc -pw $PW1 ${P}np"
    kpw knp-princ "${P}np" "$PW1" "${P}np"
    b2a_kinit knp-princ-kinit "${P}np" "${P}np"
    echo "HISTORY_AFTER_KPASSWD $(hist)"
    echo "CELL getprinc-history"   # kadmin/history as created: its key lines (kvno, enctype: getprinc prints no key material) and its shape; the two time stamps are left out
    kadmin.local -q "getprinc $HIST" < /dev/null 2>&1 | grep -E '^(Principal:|Expiration date:|Password expiration date:|Maximum ticket life:|Maximum renewable life:|Failed password attempts:|Number of keys:|Key: vno|MKey: vno|Attributes:|Policy:)'
    echo "CELL_END getprinc-history"
    ;;
stanza-disable)
    printf '[plugins]\n    pwqual = {\n        disable = empty\n    }\n' | b2a_conf realm dict_file "$DICT" append
    b2a_restart_kadmin disable-empty
    b2a_kal empty-off "addprinc -pw \"\" ${P}emptyoff"            # no policy: under pq (min length 1) the floor would refuse the empty password whatever the module says
    ;;
stanza-only)
    printf '[plugins]\n    pwqual = {\n        enable_only = nosuch\n    }\n' | b2a_conf realm dict_file "$DICT" append
    b2a_restart_kadmin enable-only-nosuch
    b2a_kal only-empty "addprinc -pw \"\" ${P}onlye"              # no policy (the empty module never skips; the floor of pq would refuse an empty password)
    b2a_kal only-princ "addprinc -pw ${P}onlyp -policy pq ${P}onlyp"
    b2a_kal only-dict "addprinc -pw CorrectHorse -policy pq ${P}onlyd"
    ;;
stanza-off)
    b2a_conf
    rm -f "$DICT"
    b2a_restart_kadmin off
    b2a_wait_kadmind && echo "KADMIND_LISTENING" || echo "KADMIND_NOT_LISTENING"
    ;;
cleanup)   # the principals and the policy this stage made, and nothing else: the realm database is as L1 found it (the shell compares at the module boundary)
    for n in free dictnp dictsub ke kp kd ko ne nd np emptyoff onlye onlyp onlyd; do b2a_kal "del-$n" "delprinc -force $P$n"; done
    b2a_kal del-pq 'delpol -force pq'
    b2a_kal getpol-gone 'getpol pq'
    if [ "$(cat "$HISTMARK" 2> /dev/null)" = no ] && [ "$(hist)" = yes ]; then   # the stage made kadmin/history: it goes, with the principals that used it already deleted
        echo "HISTORY_CREATED_BY_STAGE"
        b2a_kal del-history "delprinc -force $HIST"
    fi
    echo "HISTORY_AT_END $(hist)"
    rm -f "$HISTMARK"
    ;;
*) echo "pg6-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
