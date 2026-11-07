#!/bin/bash
# p8e-kdc.sh after: P8E's kdc-side aftermath of the P8 field check (the scratch-patched copy), as root: `sudo bash p8e-kdc.sh after`. No stdin is read.
# The field check puts back what it adds (its scratch principal p8-lock, policy p8-lockpol and directory /root/p8-check) and leaves krb5kdc and kadmin active when it ends normally. When it stops early (its
# `stop` lines: "the daemons did not stop", "the upgrade step failed with the daemons stopped", "the daemons did not start ...", or a timeout) it says how to put things back and leaves the units as they
# were then. This section says what it found and then puts back what is left, so that the next module starts from the realm and the units it expects: one fact per line, judged by the module.
#   UNITS_BEFORE krb5kdc=<is-active> kadmin=<is-active>      the units as the check left them
#   LEFT principal|policy|directory NAME                      each leftover found (nothing found: no LEFT line)
#   REMOVED NAME / REMOVE_FAILED NAME                        the put-back of each leftover
#   STARTED UNIT / START_FAILED UNIT                         a unit found down, reset-failed and started (krb5kdc first)
#   KADMIND_NOT_LISTENING                                    kadmind did not bind :749 within 10 s after the units were up
#   UNITS_AFTER krb5kdc=<is-active> kadmin=<is-active>       the units after the put-back
set -u
SECTION=${1:?section}
. "$(dirname "$0")/b2a-lib.sh"
P=p8-lock; POL=p8-lockpol; BAK=${B2A_P8_BAK:-/root/p8-check}
RLM=$B2A_REALM

units() { printf 'krb5kdc=%s kadmin=%s' "$(systemctl is-active krb5kdc 2>&1)" "$(systemctl is-active kadmin 2>&1)"; }
have_princ() { kadmin.local -q "getprinc $P@$RLM" < /dev/null 2>&1 | grep -q "^Principal: $P@$RLM\$"; }
have_pol() { kadmin.local -q "getpol $POL" < /dev/null 2>&1 | grep -q "^Policy: $POL\$"; }

case $SECTION in
after)
    echo "UNITS_BEFORE $(units)"
    if have_princ; then
        echo "LEFT principal $P@$RLM"
        kadmin.local -q "delprinc -force $P@$RLM" < /dev/null > /dev/null 2>&1
        if have_princ; then echo "REMOVE_FAILED $P@$RLM"; else echo "REMOVED $P@$RLM"; fi
    fi
    if have_pol; then
        echo "LEFT policy $POL"
        kadmin.local -q "delpol -force $POL" < /dev/null > /dev/null 2>&1
        if have_pol; then echo "REMOVE_FAILED $POL"; else echo "REMOVED $POL"; fi
    fi
    if [ -e "$BAK" ]; then
        echo "LEFT directory $BAK"
        rm -rf "$BAK"
        if [ -e "$BAK" ]; then echo "REMOVE_FAILED $BAK"; else echo "REMOVED $BAK"; fi
    fi
    for u in krb5kdc kadmin; do
        if [ "$(systemctl is-active "$u" 2>&1)" != active ]; then
            systemctl reset-failed "$u" > /dev/null 2>&1
            if timeout 60 systemctl start "$u" > /dev/null 2>&1; then echo "STARTED $u"; else echo "START_FAILED $u"; fi
        fi
    done
    b2a_wait_kadmind || echo "KADMIND_NOT_LISTENING"
    echo "UNITS_AFTER $(units)"
    ;;
*) echo "p8e-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
