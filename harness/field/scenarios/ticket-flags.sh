#!/usr/bin/env bash
# harness/field/scenarios/ticket-flags.sh --leg mit|rust: the moving gates expire, flags, renew,
# postdate, policy and sha2, MIT's kinit and kadmin from client2 against the leg's KDC as upgrade.sh
# left it. Scratch principals only. kadmin/changepw's PWCHANGE_SERVICE flag is restored on the way out.
# MIT 1.22.2:
#   kdc_util.c validate_as_request: NAME_EXP 733-738, KEY_EXP 741-749, SERVICE_EXP 752-756,
#   REQUIRES_PWCHANGE 762-765, CANNOT_POSTDATE 769-774, CLIENT_REVOKED 778-780, DISALLOW_SVR 790-792.
#   kdc_util.c get_ticket_flags: INVALID on postdate 825-826, OK_AS_DELEGATE 832-834, proxiable 836-842,
#   forwardable 844-850.
#   tgs_policy.c: NON-RENEWABLE TICKET 108-109, TGT BASED 157-161, NO HW PREAUTH 174-177.
#   kdc_preauth.c return_pw_change / NEEDED_HW_PREAUTH 747-749.
#   lib/kadm5/srv/server_misc.c check_against_policy 81-100 (length, classes).
#   lib/kadm5/chpass_util.c KADM5_PASS_TOOSOON 213-228. History and lockout are kadm5 policy on kinit.
#   The policy dump and load of the history TL is not in this scenario.
#   sha2-gate.sh: MIT kinit/kvno with only etype 20. The session key and the ticket key
#   of krbtgt and of the host are both aes256-cts-hmac-sha384-192. Both legs are the two
#   KDCs. Our kinit is TF-2.
#   kvno uses the ccache (kvno.c krb5_get_credentials). The flag rows kinit into a
#   fresh ccache so the host ticket from the delegate row is not reused.
#   krbtgt requires preauth (install.sh default_principal_flags). A TGT without
#   that flag is "NO PREAUTH" (tgs_policy.c:181-182). The hw row clears it; renew
#   puts it back before kinit -R and kinit -v.
#   tflock's minlength is 10, so tfpol's password is 10 characters.
#   The field supported_enctypes are the sha1 pair. tfsha and the host get an
#   etype-20 key. krbtgt is not re-keyed: session_enctypes allows etype 20
#   (kdc_util.c:1054-1076) and cleanup deletes the attribute. The TGT ticket
#   key stays the long-term sha1 key.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: ticket-flags.sh --leg mit|rust" >&2; exit 1 ;;
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
H="host/tfhost.${REALM,,}"
KA="kadmin -p admin/admin@$REALM -q"
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo kadmin.local -q 'delstr krbtgt/$REALM session_enctypes' >/dev/null 2>&1; sudo kadmin.local -q 'modprinc +password_changing_service kadmin/changepw' >/dev/null 2>&1; for p in tfuser tfpol tfclass tfhist tfdur tfint tfmin tfsha $H; do sudo kadmin.local -q \"delprinc -force \$p\" >/dev/null 2>&1; done; for p in tflock tfclass5 tfhistn tfdurpol tfintpol tflife; do sudo kadmin.local -q \"delpol -force \$p\" >/dev/null 2>&1; done; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'rm -rf ~/tf; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kadm <check> <ERE> <query>: MIT kadmin from client2. A refusal is still rc 0 here; the text is graded.
kadm() { check "$1" "$2" runin client2 "admin/admin's password ($ADMIN)" "$KA '$3' 2>&1; true" < <(once "$ADMIN"); }
# kin <check> <ERE> <cc> <princ> <what> [kinit args...]: password on stdin, then klist -f.
kin() {
    local name=$1 expect=$2 cc=$3 princ=$4 what=$5
    shift 5
    check "$name" "$expect" runin client2 "$what" "kinit $* -c FILE:\$HOME/tf/$cc.cc $princ@$REALM && klist -f -c FILE:\$HOME/tf/$cc.cc"
}
# kbad <check> <ERE> <cc> <princ> <what> [kinit args...]: the refusal text. rc is forced 0.
kbad() {
    local name=$1 expect=$2 cc=$3 princ=$4 what=$5
    shift 5
    check "$name" "$expect" runin client2 "$what" "kinit $* -c FILE:\$HOME/tf/$cc.cc $princ > \$HOME/tf/k.out 2>&1; echo kinit_rc:\$?; cat \$HOME/tf/k.out; true"
}
# knot <check> <cc> <princ>: a wrong password that must not be a lockout. rc is forced 0.
knot() {
    local name=$1 cc=$2 princ=$3
    check "$name" 'locked:no' runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/$cc.cc $princ@$REALM > \$HOME/tf/k.out 2>&1; if grep -qiE 'revoked|CLIENT_REVOKED' \$HOME/tf/k.out; then echo locked:yes; else echo locked:no; fi; cat \$HOME/tf/k.out; true" < <(printf '%s\n' 'not-the-password')
}
# klist_times <file>: start, end, and renew-until of the krbtgt line in a klist -f record.
klist_times() {
    awk '
        /krbtgt\// && $0 !~ /Flags/ { print $1, $2; print $3, $4 }
        /renew until / {
            line = $0
            sub(/.*renew until /, "", line)
            sub(/,.*/, "", line)
            gsub(/^ +| +$/, "", line)
            print line
        }
    ' "$1"
}

section "ticket-flags --leg $LEG: expire, flags, renew, postdate, policy, sha2 on the $LEG KDC"
kdcis
resetvm client2
run client2 "rm -rf ~/tf; mkdir -m 0700 ~/tf"
run kdc "for p in tfuser tfpol tfclass tfhist tfdur tfint tfmin tfsha $H; do sudo kadmin.local -q \"delprinc -force \$p\" >/dev/null 2>&1; done; for p in tflock tfclass5 tfhistn tfdurpol tfintpol tflife; do sudo kadmin.local -q \"delpol -force \$p\" >/dev/null 2>&1; done; true"
check setup.tfuser "^Principal \"tfuser@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc tfuser' 2>&1" < <(twice "$ALICE")
check setup.tfhost "^Principal \"$H@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey $H' 2>&1"

section "TF.expire principal expiry is NAME_EXP (kdc_util.c validate_as_request)"
kadm TF.expire.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" tfuser'
kbad TF.expire.kinit "Client's entry in database has expired" u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.expire.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -expire never tfuser'

section "TF.expire password expiry is KEY_EXP unless the server is PWCHANGE_SERVICE"
kadm TF.pw.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -pwexpire "Jan 1, 2020 00:00:00 UTC" tfuser'
kadm TF.pw.strip '^Principal "kadmin/changepw@'"$R"'" modified\.$' 'modprinc -password_changing_service kadmin/changepw'
kbad TF.pw.kinit "Password has expired" u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.pw.restore '^Principal "kadmin/changepw@'"$R"'" modified\.$' 'modprinc +password_changing_service kadmin/changepw'
kin TF.pw.changepw 'kadmin/changepw@'"$R" cpw tfuser "alice's password ($ALICE)" -S "kadmin/changepw@$REALM" < <(once "$ALICE")
kadm TF.pw.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -pwexpire never tfuser'

section "TF.expire both dates: NAME_EXP wins over KEY_EXP"
kadm TF.both.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" -pwexpire "Jan 1, 2020 00:00:00 UTC" tfuser'
kbad TF.both.kinit "Client's entry in database has expired" u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.both.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -expire never -pwexpire never tfuser'

section "TF.expire a live principal still gets a TGT"
kin TF.live '^Default principal: tfuser@'"$R"'$' u tfuser "alice's password ($ALICE)" < <(once "$ALICE")

section "TF.expire TGS kvno still succeeds after password expiry; the next AS is KEY_EXP"
kadm TF.tgs.pw "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -pwexpire "Jan 1, 2020 00:00:00 UTC" tfuser'
check TF.tgs.pw.kvno "^$H@$R: kvno = [0-9]+\$" run client2 "klist -c FILE:\$HOME/tf/u.cc >/dev/null && kvno -c FILE:\$HOME/tf/u.cc $H"
kadm TF.tgs.pw.strip '^Principal "kadmin/changepw@'"$R"'" modified\.$' 'modprinc -password_changing_service kadmin/changepw'
kbad TF.tgs.pw.as "Password has expired" u2 tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.tgs.pw.restore '^Principal "kadmin/changepw@'"$R"'" modified\.$' 'modprinc +password_changing_service kadmin/changepw'
kadm TF.tgs.pw.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -pwexpire never tfuser'

section "TF.expire TGS kvno still succeeds after account expiry; the next AS is NAME_EXP"
kin TF.tgs.acct.kinit '^Default principal: tfuser@'"$R"'$' u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.tgs.acct.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" tfuser'
check TF.tgs.acct.kvno "^$H@$R: kvno = [0-9]+\$" run client2 "kvno -c FILE:\$HOME/tf/u.cc $H"
kbad TF.tgs.acct.as "Client's entry in database has expired" u3 tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.tgs.acct.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -expire never tfuser'

section "TF.expire an expired server is SERVICE_EXP"
kin TF.svc.kinit '^Default principal: tfuser@'"$R"'$' u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.svc.set "^Principal \"$H@$R\" modified\\.\$" "modprinc -expire \"Jan 1, 2020 00:00:00 UTC\" $H"
check TF.svc.kvno "Server's entry in database has expired" run client2 "kvno -c FILE:\$HOME/tf/u.cc $H 2>&1; true"
kadm TF.svc.clear "^Principal \"$H@$R\" modified\\.\$" "modprinc -expire never $H"

section "TF.expire +needchange is KEY_EXP; changepw still issues"
check TF.need.set 'REQUIRES_PWCHANGE' run kdc "sudo kadmin.local -q 'modprinc +needchange tfuser' 2>&1; sudo kadmin.local -q 'getprinc tfuser' 2>&1"
kadm TF.need.strip '^Principal "kadmin/changepw@'"$R"'" modified\.$' 'modprinc -password_changing_service kadmin/changepw'
kbad TF.need.kinit "Password has expired" u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.need.restore '^Principal "kadmin/changepw@'"$R"'" modified\.$' 'modprinc +password_changing_service kadmin/changepw'
kin TF.need.changepw 'kadmin/changepw@'"$R" need tfuser "alice's password ($ALICE)" -S "kadmin/changepw@$REALM" < <(once "$ALICE")
kadm TF.need.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -needchange tfuser'

section "TF.expire a password that expires in two days still issues, with the warning"
WARN_DATE=$(run client2 "date -u -d '+2 days' '+%b %d, %Y %H:%M:%S UTC'" >/dev/null; tail -n 1 "$LAST_OUT")
kadm TF.warn.set "^Principal \"tfuser@$R\" modified\\.\$" "modprinc -pwexpire \"$WARN_DATE\" tfuser"
kin TF.warn.kinit 'Your password will expire' u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.warn.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -pwexpire never tfuser'

section "TF.flags DISALLOW_ALL_TIX is CLIENT_REVOKED"
kadm TF.flags.revoke.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -allow_tix tfuser'
kbad TF.flags.revoke "Client's credentials have been revoked" u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
kadm TF.flags.revoke.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc +allow_tix tfuser'

section "TF.flags DISALLOW_FORWARDABLE strips F (get_ticket_flags)"
check TF.flags.fwd.set 'DISALLOW_FORWARDABLE' run kdc "sudo kadmin.local -q 'modprinc -allow_forwardable tfuser' 2>&1; sudo kadmin.local -q 'getprinc tfuser' 2>&1"
kin TF.flags.fwd.kinit '^Default principal: tfuser@'"$R"'$' u tfuser "alice's password ($ALICE)" -f < <(once "$ALICE")
checklast TF.flags.fwd.bits 'Flags: [^F]*$'
kadm TF.flags.fwd.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc +allow_forwardable tfuser'
kin TF.flags.fwd.allow 'Flags:.*F' u tfuser "alice's password ($ALICE)" -f < <(once "$ALICE")

section "TF.flags DISALLOW_PROXIABLE strips P"
kadm TF.flags.prox.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -allow_proxiable tfuser'
kin TF.flags.prox.kinit '^Default principal: tfuser@'"$R"'$' u tfuser "alice's password ($ALICE)" -p < <(once "$ALICE")
checklast TF.flags.prox.bits 'Flags: [^P]*$'
kadm TF.flags.prox.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc +allow_proxiable tfuser'
kin TF.flags.prox.allow 'Flags:.*P' u tfuser "alice's password ($ALICE)" -p < <(once "$ALICE")

section "TF.flags OK_AS_DELEGATE sets O on the service ticket"
check TF.flags.deleg.set 'OK_AS_DELEGATE' run kdc "sudo kadmin.local -q 'modprinc +ok_as_delegate $H' 2>&1; sudo kadmin.local -q 'getprinc $H' 2>&1"
kin TF.flags.deleg.kinit '^Default principal: tfuser@'"$R"'$' u tfuser "alice's password ($ALICE)" < <(once "$ALICE")
check TF.flags.deleg.kvno "^$H@$R: kvno = [0-9]+\$" run client2 "kvno -c FILE:\$HOME/tf/u.cc $H && klist -f -c FILE:\$HOME/tf/u.cc"
checklast TF.flags.deleg.bits 'Flags:.*O'
kadm TF.flags.deleg.clear "^Principal \"$H@$R\" modified\\.\$" "modprinc -ok_as_delegate $H"

section "TF.flags DISALLOW_SVR is user2user or policy"
kadm TF.flags.svr.set "^Principal \"$H@$R\" modified\\.\$" "modprinc -allow_svr $H"
kin TF.flags.svr.kinit '^Default principal: tfuser@'"$R"'$' svr tfuser "alice's password ($ALICE)" < <(once "$ALICE")
check TF.flags.svr.kvno "Server principal valid for user2user only" run client2 "kvno -c FILE:\$HOME/tf/svr.cc $H 2>&1; true"
kadm TF.flags.svr.clear "^Principal \"$H@$R\" modified\\.\$" "modprinc +allow_svr $H"

section "TF.flags DISALLOW_TGT_BASED is POLICY (tgs_policy.c TGT BASED NOT ALLOWED)"
kadm TF.flags.tgt.set "^Principal \"$H@$R\" modified\\.\$" "modprinc -allow_tgs_req $H"
kin TF.flags.tgt.kinit '^Default principal: tfuser@'"$R"'$' tgs tfuser "alice's password ($ALICE)" < <(once "$ALICE")
check TF.flags.tgt.kvno "KDC policy rejects request" run client2 "kvno -c FILE:\$HOME/tf/tgs.cc $H 2>&1; true"
kadm TF.flags.tgt.clear "^Principal \"$H@$R\" modified\\.\$" "modprinc +allow_tgs_req $H"

section "TF.flags REQUIRES_HW_AUTH asks for more preauth and issues nothing (kdc_preauth.c)"
check TF.flags.hw.set 'REQUIRES_HW_AUTH' run kdc "sudo kadmin.local -q 'modprinc +requires_hwauth -requires_preauth tfuser' 2>&1; sudo kadmin.local -q 'getprinc tfuser' 2>&1"
check TF.flags.hw.kinit 'Additional pre-authentication required' runin client2 "alice's password ($ALICE)" "KRB5_TRACE=/dev/stderr kinit -c FILE:\$HOME/tf/hw.cc tfuser@$REALM > \$HOME/tf/k.out 2>&1; echo kinit_rc:\$?; cat \$HOME/tf/k.out; klist -s -c FILE:\$HOME/tf/hw.cc; echo klist_s:\$?; true" < <(once "$ALICE")
kadm TF.flags.hw.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -requires_hwauth tfuser'
kadm TF.flags.hw.preauth "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc +requires_preauth tfuser'

section "TF.renew four-term renewable life, then kinit -R keeps renew-until (tgs_policy.c)"
check TF.renew.life 'Maximum renewable life: [^0]' run kdc "sudo kadmin.local -q 'getprinc krbtgt/$REALM' 2>&1 | grep -F 'Maximum renewable life:'; sudo kadmin.local -q 'getprinc tfuser' 2>&1 | grep -F 'Maximum renewable life:'"
kadm TF.renew.user "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -maxrenewlife "7 days" tfuser'
kin TF.renew.kinit 'Flags:.*R' u tfuser "alice's password ($ALICE)" -r 7d -l 10h < <(once "$ALICE")
klist_times "$LAST_OUT" > "$STATE/renew1.txt"
START1=$(sed -n '1p' "$STATE/renew1.txt")
END1=$(sed -n '2p' "$STATE/renew1.txt")
REN1=$(sed -n '3p' "$STATE/renew1.txt")
if S_UNIX=$(date -d "$START1" +%s) && R_UNIX=$(date -d "$REN1" +%s); then
    printf 'renew_delta: %s\n' "$((R_UNIX - S_UNIX))" > "$STATE/renewdelta.txt"
else
    printf 'renew_delta: missing\n' > "$STATE/renewdelta.txt"
fi
check TF.renew.delta '^renew_delta: (59[0-9]{4}|6[01][0-9]{4})$' host "cat $(printf '%q' "$STATE/renewdelta.txt")"
sleep 2
check TF.renew.again rc run client2 "kinit -R -c FILE:\$HOME/tf/u.cc && klist -f -c FILE:\$HOME/tf/u.cc"
klist_times "$LAST_OUT" > "$STATE/renew2.txt"
END2=$(sed -n '2p' "$STATE/renew2.txt")
REN2=$(sed -n '3p' "$STATE/renew2.txt")
{
    if [ -n "$REN1" ] && [ "$REN1" = "$REN2" ]; then printf 'same_renew: yes\n'; else printf 'same_renew: no\n'; fi
    if [ -n "$END1" ] && [ -n "$END2" ] && [ "$END1" != "$END2" ]; then printf 'end_moved: yes\n'; else printf 'end_moved: no\n'; fi
} > "$STATE/renewcmp.txt"
check TF.renew.until '^same_renew: yes$' host "cat $(printf '%q' "$STATE/renewcmp.txt")"
checklast TF.renew.moved '^end_moved: yes$'

section "TF.renew DISALLOW_RENEWABLE strips R; a second kinit -R is BADOPTION"
kadm TF.renew.strip.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -allow_renewable tfuser'
check TF.renew.strip rc run client2 "kinit -R -c FILE:\$HOME/tf/u.cc && klist -f -c FILE:\$HOME/tf/u.cc"
checklast TF.renew.strip.bits 'Flags: [^R]*$'
check TF.renew.strip.again "KDC can't fulfill requested option" run client2 "kinit -R -c FILE:\$HOME/tf/u.cc 2>&1; true"
kadm TF.renew.strip.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc +allow_renewable tfuser'

section "TF.postdate kinit -s is INVALID, kvno is not yet valid, kinit -v then works"
START=$(run client2 "date -u -d '+20 seconds' '+%Y%m%d%H%M%S'" >/dev/null; tail -n 1 "$LAST_OUT")
kin TF.post.kinit 'Flags:.*i' u tfuser "alice's password ($ALICE)" -s "$START" < <(once "$ALICE")
check TF.post.nyv 'Ticket not yet valid' run client2 "kvno -c FILE:\$HOME/tf/u.cc $H 2>&1; true"
sleep 25
check TF.post.validate rc run client2 "kinit -v -c FILE:\$HOME/tf/u.cc && kvno -c FILE:\$HOME/tf/u.cc $H && klist -f -c FILE:\$HOME/tf/u.cc"
checklast TF.post.valid.bits 'Flags: [^i]*$'

section "TF.postdate DISALLOW_POSTDATED is CANNOT_POSTDATE"
kadm TF.post.deny.set "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc -allow_postdated tfuser'
START2=$(run client2 "date -u -d '+1 minute' '+%Y%m%d%H%M%S'" >/dev/null; tail -n 1 "$LAST_OUT")
kbad TF.post.deny "Ticket is ineligible for postdating" pd tfuser "alice's password ($ALICE)" -s "$START2" < <(once "$ALICE")
kadm TF.post.deny.clear "^Principal \"tfuser@$R\" modified\\.\$" 'modprinc +allow_postdated tfuser'

section "TF.policy length, classes, history, lockout (server_misc.c, chpass_util.c)"
check TF.pol.add '^Policy: tflock$' run kdc "sudo kadmin.local -q 'addpol -minlength 8 -minclasses 2 -history 1 -maxfailure 2 tflock' 2>&1; sudo kadmin.local -q 'getpol tflock' 2>&1"
check TF.pol.mod 'Minimum password length: 10' run kdc "sudo kadmin.local -q 'modpol -minlength 10 tflock' 2>&1; sudo kadmin.local -q 'getpol tflock' 2>&1"
check setup.tfpol "^Principal \"tfpol@$R\" created\\.\$" runin kdc "Tf-pol-000, twice" "sudo kadmin.local -q 'addprinc +requires_preauth -policy tflock tfpol' 2>&1" < <(printf '%s\n%s\n' 'Tf-pol-000' 'Tf-pol-000')
kadm TF.pol.short "Password is too short" 'cpw -pw ab tfpol'
kadm TF.pol.reuse "Cannot reuse password" 'cpw -pw Tf-pol-000 tfpol'
check TF.pol.fail1 rc=1 runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/pol.cc tfpol@$REALM" < <(printf '%s\n' 'not-the-password')
kin TF.pol.reset '^Default principal: tfpol@'"$R"'$' pol tfpol "Tf-pol-000" < <(printf '%s\n' 'Tf-pol-000')
knot TF.pol.fail2 pol tfpol
check TF.pol.fail3 'kinit_rc:' runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/pol.cc tfpol@$REALM > \$HOME/tf/k.out 2>&1; echo kinit_rc:\$?; cat \$HOME/tf/k.out; true" < <(printf '%s\n' 'not-the-password')
check TF.pol.locked "Client's credentials have been revoked" runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/pol.cc tfpol@$REALM 2>&1; true" < <(printf '%s\n' 'not-the-password')

section "TF.policy minclasses 5"
check TF.class.add '^Policy: tfclass5$' run kdc "sudo kadmin.local -q 'addpol -minlength 8 -minclasses 5 tfclass5' 2>&1; sudo kadmin.local -q 'getpol tfclass5' 2>&1"
check setup.tfclass "^Principal \"tfclass@$R\" created\\.\$" runin kdc "Aa1!aaa , twice" "sudo kadmin.local -q 'addprinc -policy tfclass5 tfclass' 2>&1" < <(printf '%s\n%s\n' 'Aa1!aaa ' 'Aa1!aaa ')
kadm TF.class.four 'enough character classes' 'cpw -pw Aa1!aaaa tfclass'
check TF.class.five 'Password for .* changed' runin kdc "Aa1!aaB and a space, twice" "sudo kadmin.local -q 'cpw tfclass' 2>&1" < <(printf '%s\n%s\n' 'Aa1!aaB ' 'Aa1!aaB ')

section "TF.policy minimum life refuses a self-service change (chpass_util.c PASS_TOOSOON)"
check TF.life.add 'Minimum password life:' run kdc "sudo kadmin.local -q 'addpol -minlife 1day -minlength 8 tflife' 2>&1; sudo kadmin.local -q 'getpol tflife' 2>&1"
check setup.tfmin "^Principal \"tfmin@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc -policy tflife tfmin' 2>&1" < <(twice "$ALICE")
kin TF.life.kinit '^Default principal: tfmin@'"$R"'$' min tfmin "alice's password ($ALICE)" < <(once "$ALICE")
check TF.life.soon 'changed too recently' runin client2 "old password ($ALICE), then Tf-life-2 twice" "kpasswd tfmin@$REALM 2>&1; true" < <({ once "$ALICE"; printf '%s\n%s\n' 'Tf-life-2' 'Tf-life-2'; })

section "TF.policy lockout duration and failure-count interval"
check TF.dur.add 'lockout duration: 0 days 00:00:03' run kdc "sudo kadmin.local -q 'addpol -minlength 8 -minclasses 1 -maxfailure 1 -lockoutduration 3s -failurecountinterval 0s tfdurpol' 2>&1; sudo kadmin.local -q 'getpol tfdurpol' 2>&1"
check setup.tfdur "^Principal \"tfdur@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc +requires_preauth -policy tfdurpol tfdur' 2>&1" < <(twice "$ALICE")
check TF.dur.fail rc=1 runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/dur.cc tfdur@$REALM" < <(printf '%s\n' 'not-the-password')
check TF.dur.locked "Client's credentials have been revoked" runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/dur.cc tfdur@$REALM 2>&1; true" < <(printf '%s\n' 'not-the-password')
sleep 4
kin TF.dur.open '^Default principal: tfdur@'"$R"'$' dur tfdur "alice's password ($ALICE)" < <(once "$ALICE")
check TF.int.add 'failure count reset interval: 0 days 00:00:02' run kdc "sudo kadmin.local -q 'addpol -minlength 8 -minclasses 1 -maxfailure 2 -lockoutduration 0s -failurecountinterval 2s tfintpol' 2>&1; sudo kadmin.local -q 'getpol tfintpol' 2>&1"
check setup.tfint "^Principal \"tfint@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc +requires_preauth -policy tfintpol tfint' 2>&1" < <(twice "$ALICE")
check TF.int.fail1 rc=1 runin client2 "a wrong password" "kinit -c FILE:\$HOME/tf/int.cc tfint@$REALM" < <(printf '%s\n' 'not-the-password')
sleep 3
knot TF.int.fail2 int tfint
kin TF.int.open '^Default principal: tfint@'"$R"'$' int tfint "alice's password ($ALICE)" < <(once "$ALICE")

section "TF.policy history depth 2 keeps the current password inside N"
check TF.hist.add '^Policy: tfhistn$' run kdc "sudo kadmin.local -q 'addpol -minlength 8 -minclasses 2 -history 2 tfhistn' 2>&1; sudo kadmin.local -q 'getpol tfhistn' 2>&1"
check setup.tfhist "^Principal \"tfhist@$R\" created\\.\$" runin kdc "Hist-pw0, twice" "sudo kadmin.local -q 'addprinc -policy tfhistn tfhist' 2>&1" < <(printf '%s\n%s\n' 'Hist-pw0' 'Hist-pw0')
kadm TF.hist.1 'changed' 'cpw -pw Hist-pw1 tfhist'
kadm TF.hist.2 'changed' 'cpw -pw Hist-pw2 tfhist'
kadm TF.hist.reject "Cannot reuse password" 'cpw -pw Hist-pw1 tfhist'
kadm TF.hist.allow 'changed' 'cpw -pw Hist-pw0 tfhist'

section "TF.sha2 MIT kinit and kvno with only etype 20 (sha2-gate.sh, this leg's KDC)"
check TF.sha2.sess 'Attribute set for principal' run kdc "sudo kadmin.local -q 'setstr krbtgt/$REALM session_enctypes \"aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\"' 2>&1"
check TF.sha2.hostkey 'Key for .* randomized' run kdc "sudo kadmin.local -q 'cpw -randkey -keepold -e aes256-cts-hmac-sha384-192:normal $H' 2>&1"
check TF.sha2.key 'session_enctypes: aes256-cts-hmac-sha384-192' run kdc "sudo kadmin.local -q 'getstrs krbtgt/$REALM' 2>&1"
check TF.sha2.hostprinc 'Key: vno [0-9]+, aes256-cts-hmac-sha384-192' run kdc "sudo kadmin.local -q 'getprinc $H' 2>&1"
check TF.sha2.conf rc run client2 "awk 'BEGIN{ins=0} /^\\[libdefaults\\]/{print; print \"    default_tkt_enctypes = aes256-cts-hmac-sha384-192\"; print \"    default_tgs_enctypes = aes256-cts-hmac-sha384-192\"; ins=1; next} ins && /^\\[/ {ins=0} ins && /default_tkt_enctypes|default_tgs_enctypes/ {next} {print}' /etc/krb5.conf > \$HOME/tf/sha2.conf"
check setup.tfsha "^Principal \"tfsha@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc -e aes256-cts-hmac-sha384-192:normal tfsha' 2>&1" < <(twice "$ALICE")
check TF.sha2.kinit rc runin client2 "alice's password ($ALICE)" "KRB5_CONFIG=\$HOME/tf/sha2.conf kinit -c FILE:\$HOME/tf/sha.cc tfsha@$REALM && KRB5_CONFIG=\$HOME/tf/sha2.conf kvno -c FILE:\$HOME/tf/sha.cc $H && KRB5_CONFIG=\$HOME/tf/sha2.conf klist -e -c FILE:\$HOME/tf/sha.cc" < <(once "$ALICE")
awk '
    function emit(tag,    s, a) {
        if (getline <= 0) return
        s = $0
        sub(/.*tkt\): */, "", s)
        split(s, a, ",")
        gsub(/ /, "", a[1])
        gsub(/ /, "", a[2])
        print "sha2", tag, "skey=" a[1], "tkt=" a[2]
    }
    index($0, "krbtgt/") && $0 !~ /Etype/ { emit("krbtgt"); next }
    index($0, "host/tfhost") && $0 !~ /Etype/ { emit("host"); next }
' "$LAST_OUT" > "$STATE/sha2.txt"
check TF.sha2.krbtgt '^sha2 krbtgt skey=aes256-cts-hmac-sha384-192 tkt=aes256-cts-hmac-sha1-96$' host "cat $(printf '%q' "$STATE/sha2.txt")"
checklast TF.sha2.host '^sha2 host skey=aes256-cts-hmac-sha384-192 tkt=aes256-cts-hmac-sha384-192$'

finish
