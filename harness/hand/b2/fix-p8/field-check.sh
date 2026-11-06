#!/bin/sh
# P8 field check, for the kdc VM (Fedora 43, SELinux enforcing) with this release installed from
# docs/install.md (krb5kdc and kadmin active, realm KERBER.TEST). Run as the lab user, with
# admin/admin's password as the first line of stdin, never on a command line:
#   { cat ~/kerber-lab/secrets/rust-realm.admin-admin.password; cat field-check.sh; } |
#     harness/field/lab.sh ssh kdc -- 'IFS= read -r ADMIN_PW; export ADMIN_PW; exec sh -s'
#
# It records the KDC's lockout attributes as MIT's KDC keeps them: a policy of three failures, a
# random-key principal under it (its key in a scratch keytab, so no password exists), one success
# and three failed passwords through MIT's own kinit, the fourth attempt refused, the lock kept
# across `systemctl restart krb5kdc`, MIT's three getprinc lines from kadmin.local and from a
# remote kadmin (kadmind), the dump's three columns, and an unlock. Read-only checks: the KDC's
# writes leave the database byte for byte and principal.ok's age as they were and update
# principal.lockout in place (same inode); principal.lockout is krb5kdc_principal_t as matchpathcon
# says and restorecon -n relabels nothing; no AVC since the start (ausearch's own exit status,
# trusted only once a positive control has matched in the same window).
#
# A realm an earlier release made has no principal.lockout: the script then runs install.md's
# upgrade step for it, and only it: the daemons stopped (checked), an empty 0600 file owned as the
# database is, restorecon, the daemons started (checked). Nothing else in the realm changes. If
# that step fails, the script stops there and prints how to put things back; it does not start
# the daemons itself.
#
# What it adds it removes: the principal, the policy, the keytab and the ccache, each removal
# checked; the scratch directory is removed only once all of them are. The full dump it reads
# the three columns from is removed as soon as they are read. principal.lockout keeps the deleted
# principal's record marked, as any delete leaves it, and the update log keeps the admin changes,
# as any admin change leaves it. It refuses to start when the test principal, the policy, the
# scratch directory or an upgrade dump an earlier release's step may have left is there. The last
# line is PASS or FAIL.
set -u
R=KERBER.TEST
D=/var/kerberos/krb5kdc
DB=$D/principal
SIDE=$DB.lockout
P=p8-lock
POL=p8-lockpol
BAK=/root/p8-check
KT=$BAK/p8.keytab
CC=FILE:$BAK/p8.cc
DUMP=$BAK/p8.dump
KINIT=/usr/bin/kinit
KADMIN=/usr/bin/kadmin
KDCLOG=/var/log/krb5kdc.log
T0D=$(date +%x)
T0T=$(date +%T)
fail=0

bad() { printf 'FAIL: %s\n' "$*"; fail=1; }
stop() { printf 'FAIL: %s\n\nFAIL\n' "$*"; exit 1; }
run() {
    printf '\n[%s] $ %s\n' "$(date -u +%T)" "$*"
    out=$(sh -c "$*" 2>&1)
    rc=$?
    printf '%s\n[rc=%s]\n' "$out" "$rc"
    return "$rc"
}
# call FUNCTION: run one of this script's functions as run runs a command line.
call() {
    printf '\n[%s] $ %s\n' "$(date -u +%T)" "$*"
    out=$("$@" 2>&1)
    rc=$?
    printf '%s\n[rc=%s]\n' "$out" "$rc"
    return "$rc"
}
three() { sudo kadmin.local -q "getprinc $P@$R" 2>&1 | grep -E '^(Last successful|Last failed|Failed password)'; }
count() { three | sed -n 's/^Failed password attempts: //p'; }
good() { sudo env KRB5CCNAME="$CC" "$KINIT" -k -t "$KT" "$P@$R" 2>&1; }
wrong() { printf 'not-the-password\n' | sudo env KRB5CCNAME="$CC" "$KINIT" "$P@$R" 2>&1; }
ino() { sudo stat -c %i "$1"; }
age() { sudo stat -c %Y.%y "$1"; }
sum() { sudo sha256sum "$1" | cut -d' ' -f1; }
inactive() { ! systemctl is-active --quiet krb5kdc && ! systemctl is-active --quiet kadmin; }

printf '# field-check.sh (P8) on %s from %s %s\n' "$(hostname)" "$T0D" "$T0T"
run "getenforce; rpm -q selinux-policy-targeted krb5-workstation; systemctl is-active krb5kdc kadmin; sudo ls -laZ $D"
[ "$(getenforce)" = Enforcing ] || bad "SELinux is not enforcing"
[ -n "${ADMIN_PW:-}" ] || stop "no admin/admin password on stdin's first line"
sudo test -e "$BAK" && stop "$BAK exists (an earlier run's leftovers): check and remove it first"
sudo test -e "$DB.upgrade-dump" && stop "$DB.upgrade-dump exists (an earlier upgrade step's dump, which holds the realm's keys under the master key): check and remove it first"
sudo kadmin.local -q "getprinc $P@$R" 2>&1 | grep -q "^Principal: $P@$R" && stop "$P@$R exists: delete it first"
sudo kadmin.local -q "getpol $POL" 2>&1 | grep -q "^Policy: $POL" && stop "policy $POL exists: delete it first"

printf '\n==== principal.lockout\n'
if sudo test -e "$SIDE"; then
    printf 'principal.lockout is there\n'
else
    printf 'principal.lockout is not there: install.md "Upgrading kerber-rust" makes it, empty\n'
    run "sudo systemctl stop krb5kdc kadmin"
    if ! inactive; then
        run "systemctl is-active krb5kdc kadmin"
        stop "the daemons did not stop; nothing was changed. Start them again with: sudo systemctl start krb5kdc kadmin"
    fi
    if ! run "sudo install -m 0600 -o \"\$(sudo stat -c %u $DB)\" -g \"\$(sudo stat -c %g $DB)\" /dev/null $SIDE && sudo restorecon -v $SIDE"; then
        stop "the upgrade step failed with the daemons stopped; nothing else was changed. To put things back: sudo rm -f $SIDE; sudo systemctl start krb5kdc kadmin"
    fi
    run "sudo systemctl start krb5kdc kadmin && systemctl is-active krb5kdc kadmin" ||
        stop "the daemons did not start after the upgrade step; look at: journalctl -u krb5kdc -u kadmin. $SIDE was made; remove it to go back: sudo rm -f $SIDE"
fi
sudo mkdir -m 0700 "$BAK" || stop "cannot make $BAK"
run "sudo ls -lZ $SIDE; sudo matchpathcon $SIDE"
[ "$(sudo stat -c %C "$SIDE" 2>/dev/null | cut -d: -f3)" = krb5kdc_principal_t ] ||
    bad "principal.lockout is not krb5kdc_principal_t"
run "sudo matchpathcon -V $SIDE" || bad "matchpathcon -V principal.lockout"
[ "$(sudo stat -c '%a %U:%G' "$SIDE")" = "$(sudo stat -c '%a %U:%G' "$DB")" ] ||
    bad "principal.lockout is not owned and moded as the database is"

printf '\n==== a policy of three failures and a principal under it\n'
run "sudo kadmin.local -q 'addpol -maxfailure 3 -failurecountinterval 0 -lockoutduration 0 $POL'"
run "sudo kadmin.local -q 'addprinc -randkey +requires_preauth -policy $POL $P@$R'"
printf '%s' "$out" | grep -q created || bad "addprinc"
run "sudo kadmin.local -q 'ktadd -k $KT $P@$R'"
printf '%s' "$out" | grep -q 'added to keytab' || bad "ktadd"
call three
printf '%s' "$out" | grep -q '^Failed password attempts: 0' || bad "a new principal has no failures"

printf '\n==== the KDC records: one success, three failures, then refused\n'
db0=$(sum "$DB")
ok0=$(age "$DB.ok")
side0=$(ino "$SIDE")
call good
[ "$rc" = 0 ] || bad "the first kinit -k"
call three
printf '%s' "$out" | grep -q '^Last successful authentication: \[never\]' && bad "no last success recorded"
for i in 1 2 3; do
    call wrong
    printf '%s' "$out" | grep -q 'Password incorrect' || bad "failure $i: $out"
done
call three
[ "$(count)" = 3 ] || bad "three failures are not 3"
call good
printf '%s' "$out" | grep -q "credentials have been revoked" || bad "the fourth attempt was not refused"
run "sudo grep -c 'LOCKED_OUT: $P@$R' $KDCLOG"
[ "${out:-0}" -ge 1 ] 2>/dev/null || bad "no LOCKED_OUT line in $KDCLOG"
[ "$(sum "$DB")" = "$db0" ] || bad "the KDC's writes changed the database"
[ "$(age "$DB.ok")" = "$ok0" ] || bad "the KDC's writes moved the database's age"
[ "$(ino "$SIDE")" = "$side0" ] || bad "principal.lockout was replaced, not written in place"
printf 'ok: database %s and its age unchanged, principal.lockout inode %s unchanged\n' "$db0" "$side0"

printf '\n==== a restart keeps the lock\n'
run "sudo systemctl restart krb5kdc && systemctl is-active krb5kdc" || bad "krb5kdc did not restart"
call good
printf '%s' "$out" | grep -q "credentials have been revoked" || bad "the lock did not survive the restart"
call three
[ "$(count)" = 3 ] || bad "the count did not survive the restart"
printf '\n[%s] $ kadmin -p admin/admin -q "getprinc %s" (ADMIN_PW on stdin)\n' "$(date -u +%T)" "$P@$R"
remote=$(printf '%s\n' "$ADMIN_PW" | "$KADMIN" -p admin/admin -q "getprinc $P@$R" 2>&1 |
    grep -E '^(Last successful|Last failed|Failed password)')
printf '%s\n' "$remote"
[ "$remote" = "$(three)" ] || bad "kadmind's getprinc differs from kadmin.local's"
run "sudo kdb5_util dump $DUMP && sudo awk -F'\t' '\$1 == \"princ\" && \$7 == \"$P@$R\" {print \"dump: last_success=\" \$13 \" last_failed=\" \$14 \" fail_auth_count=\" \$15}' $DUMP"
printf '%s' "$out" | grep -q 'fail_auth_count=3' || bad "the dump does not carry the count"
run "sudo rm -f $DUMP $DUMP.dump_ok" || bad "the dump $DUMP (the realm's keys under the master key) could not be removed"

printf '\n==== an unlock\n'
run "sudo kadmin.local -q 'modprinc -unlock $P@$R'"
call three
[ "$(count)" = 0 ] || bad "the unlock did not clear the count"
call good
[ "$rc" = 0 ] || bad "kinit after the unlock"

printf '\n==== labels (read-only)\n'
run "sudo restorecon -Rnv $D"
if [ -z "$out" ]; then printf 'ok: restorecon -n would relabel nothing\n'; else bad "restorecon -n would relabel: $out"; fi
run "sudo matchpathcon -V $D/principal $SIDE $DB.ok $DB.kadm5.lock" || bad "matchpathcon -V"
# principal.ulog exists only with iprop, as MIT keeps it (ovsec_kadmd.c); label it only when it is there
if sudo test -e "$DB.ulog"; then run "sudo matchpathcon -V $DB.ulog" || bad "matchpathcon -V principal.ulog"; else printf 'ok: no principal.ulog (iprop off; MIT keeps none either)\n'; fi

printf '\n==== put back\n'
put_back=1
run "sudo kadmin.local -q 'delprinc -force $P@$R'"
printf '%s' "$out" | grep -q 'deleted' || { bad "delprinc $P@$R"; put_back=0; }
run "sudo kadmin.local -q 'delpol -force $POL'"
sudo kadmin.local -q "getpol $POL" 2>&1 | grep -q "^Policy: $POL" && { bad "delpol $POL"; put_back=0; }
if [ "$put_back" = 1 ]; then
    run "sudo rm -f $DUMP $DUMP.dump_ok $KT $BAK/p8.cc && sudo rmdir $BAK" || put_back=0
fi
run "systemctl is-active krb5kdc kadmin" || bad "a daemon is not active"
if [ "$put_back" = 1 ]; then
    printf 'ok: the principal, the policy and %s are gone\n' "$BAK"
else
    bad "not all was put back: $BAK stays as it is (p8.keytab holds the key of $P@$R, p8.cc its tickets; the realm dump was removed when read)"
fi

printf '\n==== AVC since %s %s\n' "$T0D" "$T0T"
# ausearch exits 1 when nothing matches, as it also does when it reads nothing at all (a non-tty
# stdin without --input-logs): a positive control has to match first, in the same window.
printf '$ sudo ausearch --input-logs -m USER_CMD -ts %s %s\n' "$T0D" "$T0T"
sudo ausearch --input-logs -m USER_CMD -ts "$T0D" "$T0T" >/dev/null 2>&1
ctl=$?
printf '[rc=%s] (positive control: this run'"'"'s sudo commands, same window)\n' "$ctl"
printf '$ sudo ausearch --input-logs -m AVC,USER_AVC -ts %s %s\n' "$T0D" "$T0T"
avc=$(sudo ausearch --input-logs -m AVC,USER_AVC -ts "$T0D" "$T0T" 2>&1)
arc=$?
printf '%s\n[rc=%s]\n' "$avc" "$arc"
if [ "$ctl" != 0 ]; then
    bad "the positive control matched nothing, so ausearch's answer cannot be trusted"
elif [ "$arc" = 1 ]; then
    printf 'ok: no AVC since the start\n'
elif [ "$arc" = 0 ]; then
    bad "AVC records since the start"
else
    bad "ausearch failed (rc $arc)"
fi

if [ "$fail" = 0 ]; then printf '\nPASS\n'; else printf '\nFAIL\n'; fi
