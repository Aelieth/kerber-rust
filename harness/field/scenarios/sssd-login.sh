#!/usr/bin/env bash
# harness/field/scenarios/sssd-login.sh --leg mit|rust: R2's login proofs on client1, headless, against the leg's KDC
# as upgrade.sh left it on kdc (hand records f-R2-mit, MIT, and f-R2, rust). client1's baseline is the kit-joined
# Kinoite client (SSSD 2.12 and krb5_child, the kit's sssd.conf: FILE:/tmp/krb5cc_%U, renewal on). Logins run on a pty
# (lib/ptydrive.py: the passwords come on stdin, never argv):
#   PROOF 2b: pamtester login (authenticate, open_session): FILE:/tmp/krb5cc_10001 alice's, user_tmp_t, FRIA, 24 h,
#     renewable 7 d;
#   PROOF 3, the renewal's shape at an sssd restart (not the 60 s interval wait): with alice's maxlife lowered to
#     15 min, the restarted SSSD renews the live TGT at once: FRIAT, 24 h again, renew-until and authtime kept;
#   PROOF 4: passwd through SSSD and kpasswd: the new password logs in, the old one is refused; restored the same way;
#   PROOF 5a: -allow_tix: the login is refused, the KDC's CLIENT LOCKED OUT, kinit's "credentials have been revoked";
#   PROOF 5b: lldap_disabled: Kerberos still issues the TGT, SSSD's access filter denies the account;
#   PROOF 6: the kit's own --validate as alice: "[OK] Validation passed (core checks)."
# Every realm and directory change is undone, also on an early exit. Never SDDM or other GUI, never the kit join.
# Recorded, not graded (sssd-login.expect): the cache's size. Run by run.sh (REC_DIR, TMPDIR, FIELD_SHA).
# vms: client1 services kdc
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: sssd-login.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE ALICE_TEMP ADMIN
T0=$(date +%s)
R=${REALM//./\\.}
I3='etypes \{rep=aes256-cts-hmac-sha1-96\(18\), tkt=aes256-cts-hmac-sha1-96\(18\), ses=aes256-cts-hmac-sha1-96\(18\)\}'
E2='\(2 etypes \{aes256-cts-hmac-sha1-96\(18\), aes128-cts-hmac-sha1-96\(17\)\}\) 192\.168\.177\.21: '
PT="\$HOME/field/ptydrive.py"
PAM="$PT --secrets 1 --timeout 60 --rule Password:=0 -- sudo pamtester -v login alice"
PW="$PT --secrets 2 --timeout 120 --rule 'Current Password:=0' --rule '(Retype|Reenter) new password:=1' --rule 'New password:=1' --rule 'Password:=0' -- su --pty - alice -c 'passwd; echo passwd-rc=\$?'"
KA="kadmin -p admin/admin@$REALM -q"
KINIT="printf '%s\n' \"\$(cat)\" | env KRB5CCNAME=MEMORY:f4 kinit alice@$REALM"
CHANGED=''
member() { printf 'ADMIN_PW=%q\nACTION=%q\nMUSER=alice\nMGROUP=lldap_disabled\n' "$(< "$SECRETS/$LAB_SECRET_LLDAP_ADMIN")" "$1"; cat "$FIELD_LIB/lldap-membership.sh"; }
# cleanup: what CHANGED still names is undone (the scenario's own restores clear it), then client1's scratch.
cleanup() {
    case $CHANGED in *maxlife* | *tix*) timeout -k 5 60 "$LAB" ssh kdc -- "sudo kadmin.local -q 'modprinc -maxlife \"1 day\" +allow_tix alice'" < /dev/null > /dev/null 2>&1 ;; esac
    case $CHANGED in *pw*) once "$ADMIN" "$ALICE" "$ALICE" | timeout -k 5 60 "$LAB" ssh client1 -- "$KA 'cpw alice'" > /dev/null 2>&1 ;; esac
    case $CHANGED in *member*) member remove | timeout -k 5 60 "$LAB" ssh services -- 'bash -s' > /dev/null 2>&1 ;; esac
    timeout -k 5 60 "$LAB" ssh client1 -- 'rm -rf ~/field; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kadm <check> <query>: remote MIT kadmin as admin/admin from client1, as R2 ran it (check: "modified" said).
kadm() { check "$1" "^Principal \"alice@$R\" modified\\.\$" runin client1 "admin/admin's password ($ADMIN)" "$KA '$2'" < <(once "$ADMIN"); }

section "sssd-login --leg $LEG: R2's login proofs on client1, headless (pamtester, su and passwd on a pty), against the $LEG KDC"
section "1. kdc as upgrade.sh left it; services and client1 at the leg's baseline; client1 as the kit boots it"
kdcis
resetvm services client1
servicesready
check boot.client1 "^Default principal: host/client1\\.kerber\\.test@$R\$" run client1 "systemctl is-active sssd; id alice; sudo klist -c FILE:/tmp/krb5cc_0; sha256sum /var/opt/kit/network/klldap-client-setup.sh; sudo sha256sum /etc/sssd/sssd.conf /etc/krb5.conf; rpm -q sssd sssd-krb5 pamtester krb5-workstation"
checklast boot.sssd '^active$'
checklast boot.alice '^uid=10001\(alice\) gid=10001\(alice\) groups=10001\(alice\),20001\(lldap_sudohost\)$'
check boot.ptydrive '^staged$' hostin "lib/ptydrive.py" "$LABQ ssh client1 -- 'install -d -m 0700 ~/field && cat > ~/field/ptydrive.py && chmod 0700 ~/field/ptydrive.py && echo staged'" < "$FIELD_LIB/ptydrive.py"

section "2. R2 PROOF 2b: pamtester login through SSSD: alice's FILE cache, its owner, label and ticket"
kdcmark login
check login.session '^pamtester: sucessfully opened a session$' runin client1 "alice's password ($ALICE)" "$PAM authenticate open_session; echo \"pamtester rc=\$?\"" < <(once "$ALICE")
checklast login.auth '^pamtester: successfully authenticated$'
check login.ccache '^-rw-------\. 1 alice alice [a-z_]+:object_r:user_tmp_t:s0 [0-9]+ .* /tmp/krb5cc_10001$' run client1 "sudo ls -lZ /tmp/krb5cc_10001; sudo klist -f -c FILE:/tmp/krb5cc_10001; sudo journalctl --since -3min --no-pager -o cat | grep -E 'pam_sss\\(login' | tail -n 3"
observelast obs.ccache.bytes 'user_tmp_t:s0 [0-9]+'
checklast login.pam_sss 'pam_sss\(login:auth\): authentication success; .*user=alice$'
tktcheck login.tgt '^krbtgt/' ': 86(399|400) s life, 60(4799|4800) s renewable, flags FRIA$'
TILL0=$(awk '/renew until/ { sub(/,$/, "", $4); print $3, $4; exit }' "$LAST_OUT")
kdcsince login "192\\.168\\.177\\.21: .*alice@$R"
checklast log.login.preauth "AS_REQ ${E2}NEEDED_PREAUTH: alice@$R for krbtgt/$R@$R, Additional pre-authentication required\$"
checklast log.login.issue "AS_REQ ${E2}ISSUE: authtime [0-9]+, $I3, alice@$R for krbtgt/$R@$R\$"
AUTH=$(grep -E "AS_REQ .*ISSUE: authtime [0-9]+, .*alice@$R for krbtgt/" "$LAST_OUT" | tail -n 1 | sed -E 's/.*ISSUE: authtime ([0-9]+),.*/\1/')

section "3. R2 PROOF 3, the renewal's shape at an sssd restart: alice's maxlife 15 min (test-only), sssd restarted"
kdcmark renew
CHANGED="$CHANGED maxlife"
kadm renew.maxlife 'modprinc -maxlife "15 minutes" alice'
check renew.restart '^renewed: FRIAT$' run client1 "sudo systemctl restart sssd; for i in \$(seq 1 30); do sleep 2; f=\$(sudo klist -f -c FILE:/tmp/krb5cc_10001 | awk '/renew until/ { print \$NF; exit }'); [ \"\$f\" = FRIAT ] && break; done; echo \"after \$((i * 2)) s\"; sudo klist -f -c FILE:/tmp/krb5cc_10001; echo \"renewed: \$f\""
tktcheck renew.tgt '^krbtgt/' ': 86(399|400) s life, [0-9]+ s renewable, flags FRIAT$'
TILL1=$(awk '/renew until/ { sub(/,$/, "", $4); print $3, $4; exit }' "$LAST_OUT")
res=FAIL; if [ -n "$TILL0" ] && [ "$TILL0" = "$TILL1" ]; then res=PASS; fi
_checkrow renew.till "$res" "renew-until kept" "$LAST_RC" "login: $TILL0 renewed: $TILL1"
kdcsince renew "192\\.168\\.177\\.21: .*alice@$R"
checklast log.renew "TGS_REQ ${E2}ISSUE: authtime ${AUTH:-none}, $I3, alice@$R for krbtgt/$R@$R\$"
kadm renew.restore 'modprinc -maxlife "1 day" alice'
if [ "$LAST_RC" = 0 ]; then CHANGED=${CHANGED/ maxlife/}; fi

section "4. R2 PROOF 4: passwd as alice through pam_sss, krb5_child and kpasswd; the new password logs in, the old one is refused; restored"
kdcmark chpw
CHANGED="$CHANGED pw"
check chpw.passwd '^passwd: password updated successfully$' runin client1 "alice's password ($ALICE), then $ALICE_TEMP" "$PW" < <(once "$ALICE" "$ALICE_TEMP")
checklast chpw.rc '^passwd-rc=0'
check chpw.new '^pamtester: successfully authenticated$' runin client1 "$ALICE_TEMP (the new one)" "$PAM authenticate; echo \"pamtester rc=\$?\"" < <(once "$ALICE_TEMP")
check chpw.old '^pamtester: Authentication failure$' runin client1 "$ALICE (the old one)" "$PAM authenticate; echo \"pamtester rc=\$?\"" < <(once "$ALICE")
kdcsince chpw "chpw|192\\.168\\.177\\.21: .*alice@$R"
checklast log.chpw "chpw request from 192\\.168\\.177\\.21 for alice@$R: success\$"
checklast log.oldpw "AS_REQ ${E2}PREAUTH_FAILED: alice@$R for krbtgt/$R@$R"
check chpw.restore '^passwd: password updated successfully$' runin client1 "$ALICE_TEMP, then $ALICE" "$PW" < <(once "$ALICE_TEMP" "$ALICE")
check chpw.restored '^kinit rc=0$' runin client1 "$ALICE (restored)" "$KINIT > /dev/null; echo \"kinit rc=\$?\"" < <(once "$ALICE")
if grep -qx 'kinit rc=0' "$LAST_OUT"; then CHANGED=${CHANGED/ pw/}; fi

section "5. R2 PROOF 5a: -allow_tix on the KDC refuses the login before any preauth; +allow_tix restores it"
kdcmark revoke
CHANGED="$CHANGED tix"
kadm revoke.set 'modprinc -allow_tix alice'
check revoke.attr '^Attributes: DISALLOW_ALL_TIX REQUIRES_PRE_AUTH$' runin client1 "admin/admin's password ($ADMIN)" "$KA 'getprinc alice' | grep -E '^(Attributes|Policy)'" < <(once "$ADMIN")
check revoke.pamtester '^pamtester: Authentication failure$' runin client1 "alice's password ($ALICE)" "$PAM authenticate; echo \"pamtester rc=\$?\"" < <(once "$ALICE")
check revoke.kinit "^kinit: Client's credentials have been revoked while getting initial credentials\$" runin client1 "alice's password ($ALICE)" "$KINIT 2>&1; echo \"kinit rc=\$?\"" < <(once "$ALICE")
check revoke.pam_sss 'pam_sss\(login:auth\): received for user alice: 6 \(Permission denied\)$' run client1 "sudo journalctl --since -2min --no-pager -o cat | grep -E 'pam_sss\\(login:auth\\)' | tail -n 4"
kdcsince revoke "192\\.168\\.177\\.21: .*alice@$R"
checklast log.revoked "AS_REQ ${E2}CLIENT LOCKED OUT: alice@$R for krbtgt/$R@$R, Client's credentials have been revoked\$"
kadm revoke.unset 'modprinc +allow_tix alice'
check revoke.restored '^pamtester: successfully authenticated$' runin client1 "alice's password ($ALICE)" "$PAM authenticate; echo \"pamtester rc=\$?\"" < <(once "$ALICE")
if [ "$LAST_RC" = 0 ] && grep -qx 'pamtester: successfully authenticated' "$LAST_OUT"; then CHANGED=${CHANGED/ tix/}; fi

section "6. R2 PROOF 5b: alice into lldap_disabled (lldap's API on services): the TGT is issued, SSSD's access filter denies; removed: allowed"
CHANGED="$CHANGED member"
check disabled.add '^add alice <-> lldap_disabled \(group id [0-9]+\): ok$' hostin "lldap's admin password ($LAB_SECRET_LLDAP_ADMIN), then lib/lldap-membership.sh" "$LABQ ssh services -- 'bash -s'" < <(member add)
check disabled.acct '^pamtester: Permission denied$' runin client1 "alice's password ($ALICE)" "$PAM authenticate acct_mgmt; echo \"pamtester rc=\$?\"" < <(once "$ALICE")
checklast disabled.auth '^pamtester: successfully authenticated$'
check disabled.pam_sss 'pam_sss\(login:account\): Access denied for user alice: 6 \(Permission denied\)$' run client1 "sudo journalctl --since -2min --no-pager -o cat | grep -E 'pam_sss\\(login:account\\)' | tail -n 2"
check disabled.remove '^remove alice <-> lldap_disabled \(group id [0-9]+\): ok$' hostin "lldap's admin password ($LAB_SECRET_LLDAP_ADMIN), then lib/lldap-membership.sh" "$LABQ ssh services -- 'bash -s'" < <(member remove)
if [ "$LAST_RC" = 0 ]; then CHANGED=${CHANGED/ member/}; fi
check disabled.restored '^pamtester: account management done\.$' runin client1 "alice's password ($ALICE)" "$PAM authenticate acct_mgmt; echo \"pamtester rc=\$?\"" < <(once "$ALICE")

section "7. R2 PROOF 6: the kit's own --validate, as alice on a pty (sudo asks for her password)"
check validate.ok '^\[OK\] Validation passed \(core checks\)\.$' runin client1 "alice's password ($ALICE)" "$PT --secrets 1 --max 4 --timeout 300 --rule '\\[sudo\\] password for alice:=0' --rule 'Password:=0' -- su --pty - alice -c 'cd /var/opt/kit/network && ./klldap-client-setup.sh --validate; echo kit-rc=\$?'" < <(once "$ALICE")
checklast validate.rc '^kit-rc=0'

section "8. the final state: alice as the baseline had her; client1's evidence"
check final.maxlife '^Maximum ticket life: 1 day 00:00:00$' runin client1 "admin/admin's password ($ADMIN)" "$KA 'getprinc alice' | grep -E '^(Maximum|Attributes|Policy|Key: vno)'" < <(once "$ADMIN")
checklast final.maxrenewlife '^Maximum renewable life: 7 days 00:00:00$'
checklast final.attributes '^Attributes: REQUIRES_PRE_AUTH$'
checklast final.policy '^Policy: \[none\]$'
_checkrow final.restored "$([ -z "${CHANGED// /}" ] && echo PASS || echo FAIL)" "every change undone" 0 "left: ${CHANGED:-none}"
MIN=$(( ($(date +%s) - T0) / 60 + 2 ))
host "COLLECT_MINUTES=$MIN $LABQ collect client1 $(printf '%q' "$REC_DIR/collect") /etc/krb5.conf /etc/pam.d/system-auth /var/log/sssd/krb5_child.log /var/log/sssd/sssd_kerber.log"
if [ -f "$REC_DIR/collect/client1/journal.txt" ]; then _redact < "$REC_DIR/collect/client1/journal.txt" > "$STATE/j" && mv "$STATE/j" "$REC_DIR/collect/client1/journal.txt"; fi
finish
