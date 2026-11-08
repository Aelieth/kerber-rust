#!/bin/bash
# p15b-kdc.sh STAGE SECTION: P15b's kdc-side steps, as root: `sudo bash p15b-kdc.sh mit|ours setup|history|cleanup`. (b2-client; module mod/p15b.sh; spec/p15b.md)
# stdin: three lines, the leg's throwaway passwords PW1 (the principals' initial password) PW2 PW3 (unused here; the same pipe the other modules use). Library: b2a-lib.sh (the b2-admin builder's, pushed beside this file).
# What it makes, per stage (the stage deletes all of it again, the shell compares the realm database at the module boundary):
#   kdc.conf   dict_file = $KDCDIR/p15b.dict, a 3-word file (the recorded leg replaced the stock `dict_file = /usr/share/dict/words` by `p15b.dict`, "DICT 3 28": mit-setup.txt:1-12; the stock relation is
#              why a first attempt accepted the probe word on both realms), kadmind restarted. The words satisfy the policy's length and classes, so only the dictionary can refuse them.
#   policies   p15bq  -minlength 8 -minclasses 3 -history 2          (the recorded `qualhist`: lab/mit-setup.txt policy dump: min length 8, classes 3, 2 old keys kept, min life 0)
#              p15bl  the same with -minlife 1 hour                 (the recorded `quallife` had 5 minutes: 0 days 00:05:00; an hour cannot run out between the setup and the last client's cell)
#   principals p15bq-c<1|2><m|r> and p15bh-c<1|2><m|r> under p15bq, p15bl-c<1|2><m|r> under p15bl, initial password PW1: 12 principals, one per (client, tool, case group) like the recorded p15bq-c1m ... p15bl-m ... p15bh-r
# kadmin/history: the lab's f4-mit realm lacks it as found and the kadm5 layer makes it lazily at the first password change under a policy; setup records whether it exists at the stage's start (HISTORY_AT_START, kept in
# $B2A_D/p15b-hist-<stage>), `history` says whether it exists now (HISTORY_NOW) and prints its shape, cleanup deletes it when the stage made it (HISTORY_CREATED_BY_STAGE), after the principals and the policies.
# Part (A) (the KDC log texts): setup also makes the scratch principal p15ba (+requires_preauth, no policy, initial password PW1: the cells' wrong-password kinit must not touch alice's `Last failed authentication`,
# which P6L compares across the upgrade) and cleanup deletes it; `restart-kdc` restarts krb5kdc (RESTART_RC, the units, KDC_LISTENING) so that the caller's KDC log delta carries the startup lines; it changes nothing else.
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit|ours) ;; *) echo "p15b-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "P15B_ABORT no passwords on stdin"; exit 2; }
DICT=$B2A_KDCDIR/p15b.dict
HIST=kadmin/history@$B2A_REALM
HISTMARK=$B2A_D/p15b-hist-$STAGE
PRINCS="p15bq-c1m p15bq-c1r p15bq-c2m p15bq-c2r p15bh-c1m p15bh-c1r p15bh-c2m p15bh-c2r p15bl-c1m p15bl-c1r p15bl-c2m p15bl-c2r"
hist() {   # hist: yes when kadmin/history exists in the realm database (a read: getprinc does not create it)
    if kadmin.local -q "getprinc $HIST" < /dev/null 2>&1 | grep -q "^Principal: $HIST\$"; then echo yes; else echo no; fi
}
case $SECTION in
setup)
    hist > "$HISTMARK"
    echo "HISTORY_AT_START $(cat "$HISTMARK")"
    echo "== facts"
    sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmin.local /usr/sbin/kadmind /usr/bin/kpasswd 2>&1
    printf 'Alpha-Bravo-7\nCorrect-Horse-9\nZulu-Yankee-3\n' > "$DICT"
    restorecon "$DICT" 2> /dev/null
    b2a_conf realm dict_file "$DICT"
    echo "DICT_FILE:$(wc -l < "$DICT") BYTES:$(wc -c < "$DICT")"
    echo "DICT:$(grep -n '^[[:space:]]*dict_file' "$B2A_KDCDIR/kdc.conf")"
    b2a_restart_kadmin dict
    b2a_wait_kadmind && echo "KADMIND_LISTENING" || echo "KADMIND_NOT_LISTENING"
    b2a_kal addpol-q 'addpol -minlength 8 -minclasses 3 -history 2 p15bq'
    b2a_kal addpol-l 'addpol -minlife "1 hour" -minlength 8 -minclasses 3 -history 2 p15bl'
    b2a_kal getpol-q 'getpol p15bq'
    b2a_kal getpol-l 'getpol p15bl'
    for n in $PRINCS; do
        case $n in p15bl-*) pol=p15bl ;; *) pol=p15bq ;; esac
        b2a_kal "add-$n" "addprinc -pw $PW1 -policy $pol $n"
    done
    b2a_kal add-p15ba "addprinc +requires_preauth -pw $PW1 p15ba"
    ;;
history)   # after the cells: has the stage made kadmin/history (HISTORY_NOW), and its shape (no key material: getprinc prints versions and enctypes only)
    echo "HISTORY_NOW $(hist)"
    echo "CELL getprinc-history"
    kadmin.local -q "getprinc $HIST" < /dev/null 2>&1 | grep -E '^(Principal:|Number of keys:|Key: vno|MKey: vno|Attributes:|Policy:)'
    echo "CELL_END getprinc-history"
    ;;
cleanup)   # the principals and the policies this stage made, and nothing else; kdc.conf and kadmin as found
    for n in $PRINCS p15ba; do b2a_kal "del-$n" "delprinc -force $n"; done
    b2a_kal del-p15bq 'delpol -force p15bq'
    b2a_kal del-p15bl 'delpol -force p15bl'
    b2a_kal getpol-gone-q 'getpol p15bq'
    b2a_kal getpol-gone-l 'getpol p15bl'
    if [ "$(cat "$HISTMARK" 2> /dev/null)" = no ] && [ "$(hist)" = yes ]; then   # the stage made kadmin/history: it goes, after the principals that used it
        echo "HISTORY_CREATED_BY_STAGE"
        b2a_kal del-history "delprinc -force $HIST"
    fi
    echo "HISTORY_AT_END $(hist)"
    rm -f "$HISTMARK"
    b2a_conf
    rm -f "$DICT"
    echo "DICT_GONE:$([ -e "$DICT" ] && echo no || echo yes) DICT_CONF_AFTER:$(grep -n '^[[:space:]]*dict_file' "$B2A_KDCDIR/kdc.conf" | tr '\n' ' ')"
    b2a_restart_kadmin off
    b2a_wait_kadmind && echo "KADMIND_LISTENING" || echo "KADMIND_NOT_LISTENING"
    ;;
restart-kdc)   # (A) krb5kdc restarted, as the earlier leg did (R/LEG/lab/{mit,rust}/startup.txt, "restart=0"): the cell's KDC log delta (the caller records it) holds the stop and start lines. Nothing is changed:
    # the KDC runs again, with the same configuration, when the section ends (it waits until :88 answers on UDP and TCP).
    systemctl reset-failed krb5kdc > /dev/null 2>&1       # a unit that failed must not trip systemd's start limit
    systemctl restart krb5kdc > /dev/null 2>&1; echo "RESTART_RC:$?"
    b2a_unit_state
    i=0
    until { ss -H -lnt 'sport = :88' 2> /dev/null | grep -q . && ss -H -lnu 'sport = :88' 2> /dev/null | grep -q .; } || [ "$i" -ge 50 ]; do i=$((i + 1)); sleep 0.2; done
    if [ "$i" -lt 50 ]; then echo "KDC_LISTENING"; else echo "KDC_NOT_LISTENING"; fi
    ;;
*) echo "p15b-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
