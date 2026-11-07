#!/bin/bash
# ks-kdc.sh STAGE SECTION: KS's kdc-side steps, as root: `sudo bash ks-kdc.sh mit|ours setup|nochallenge|challenge|cleanup`. (lab-agent; module mod/ks.sh; VM-LEG.md)
# stdin: three lines, the leg's throwaway passwords PW1 (both principals' password) PW2 PW3 (unused here; the pipe the other modules use). Library: b2a-lib.sh, b2a-kdcconf.py (pushed beside this file).
# What it makes, per stage (and deletes at its end: the shell compares the realm database at the module boundary, and alice's key must not move):
#   ksuser   the user of the cells, +requires_preauth, password PW1 (a wrong password in a cell is the leg's PW3)
#   ksarm    the armor principal (+requires_preauth, PW1): the module makes the armor ticket cache with MIT's kinit, once per stage
# The two KDC states of the SPAKE cells (VM-LEG: "The lab KDC's SPAKE settings are Fedora's: spake_preauth_kdc_challenge = edwards25519 in kdc.conf"):
#   (as found)    the KDC offers its own SPAKE challenge in the first reply: a default client answers it at once, no support message, no round-one failure line
#   nochallenge   kdc.conf := the kept pristine file without spake_preauth_kdc_challenge (b2a-kdcconf.py defaults-del), krb5kdc restarted: the first reply carries no challenge, a client sends the SPAKE
#                 support message, the KDC answers with its challenge (the round-one `More preauthentication data is required` pair), the client answers that
#   challenge     kdc.conf := the pristine file again (byte for byte), krb5kdc restarted
# Each of the last two prints RESTART_RC, the unit states, KDC_LISTENING (:88 on UDP and TCP) and the number of spake_preauth_kdc_challenge lines now in kdc.conf (CHALLENGE_LINES).
set -u
STAGE=${1:?mit|ours}; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
case $STAGE in mit|ours) ;; *) echo "ks-kdc.sh: stage mit|ours" >&2; exit 2 ;; esac
IFS= read -r PW1; IFS= read -r PW2; IFS= read -r PW3
[ -n "$PW1" ] && [ -n "$PW2" ] && [ -n "$PW3" ] || { echo "KS_ABORT no passwords on stdin"; exit 2; }
PRINCS="ksuser ksarm"
challenge_lines() { grep -c '^[[:space:]]*spake_preauth_kdc_challenge' "$B2A_KDCDIR/kdc.conf" 2> /dev/null || true; }
kdc_restart() {   # krb5kdc restarted; the caller's KDC log delta holds the stop and start lines
    local i=0
    systemctl reset-failed krb5kdc > /dev/null 2>&1       # a unit that failed must not trip systemd's start limit
    systemctl restart krb5kdc > /dev/null 2>&1; echo "RESTART_RC:$?"
    b2a_unit_state
    until { ss -H -lnt 'sport = :88' 2> /dev/null | grep -q . && ss -H -lnu 'sport = :88' 2> /dev/null | grep -q .; } || [ "$i" -ge 50 ]; do i=$((i + 1)); sleep 0.2; done
    if [ "$i" -lt 50 ]; then echo "KDC_LISTENING"; else echo "KDC_NOT_LISTENING"; fi
    echo "CHALLENGE_LINES:$(challenge_lines)"
}
case $SECTION in
setup)
    echo "== facts"
    sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmin.local /usr/sbin/kadmind 2>&1
    echo "CHALLENGE_LINES:$(challenge_lines)"
    echo "CHALLENGE_CONF:$(grep -n '^[[:space:]]*spake_preauth_kdc_challenge' "$B2A_KDCDIR/kdc.conf" | tr '\n' ' ')"
    for n in $PRINCS; do b2a_kal "add-$n" "addprinc +requires_preauth -pw $PW1 $n"; done
    b2a_kal getprinc-ksuser 'getprinc ksuser'
    ;;
nochallenge)
    b2a_conf defaults-del spake_preauth_kdc_challenge
    kdc_restart
    ;;
challenge)
    b2a_conf
    kdc_restart
    ;;
cleanup)   # the principals this stage made, and nothing else; kdc.conf as found (restarted only when it was not)
    for n in $PRINCS; do b2a_kal "del-$n" "delprinc -force $n"; done
    b2a_kal getprinc-gone 'getprinc ksuser'
    if ! cmp -s "$B2A_KDCDIR/kdc.conf" "$B2A_D/kdc.conf.pristine"; then
        echo "CONF_WAS_NOT_PRISTINE"
        b2a_conf
        kdc_restart
    fi
    echo "CONF_PRISTINE:$(cmp -s "$B2A_KDCDIR/kdc.conf" "$B2A_D/kdc.conf.pristine" && echo yes || echo no)"
    ;;
*) echo "ks-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
