#!/usr/bin/env bash
# harness/field/scenarios/ad-trust.sh --leg mit|rust: the real AD DC (TEST-SERVER, AD.KERBER.TEST, a two-way trust
# with KERBER.TEST) against the leg's KDC as upgrade.sh left it on kdc; the RA hand legs of FULL-r2 as a field cell:
#   RA0: the DC's clock and state, the trust principals made the admin way, Test A (AD to us) and Test B (us to AD);
#   kinit -E of kbruser's UPN at the DC: MIT's, then in the rust leg ours, each first AS-REQ through
#   scripts/lib/kdc-req-proxy.py on client2 and compared request by request;
#   SB.ad-user-in (RA1): kbruser@AD.KERBER.TEST logs into client2's sshd with gssapi-with-mic;
#   SB.ad-user-out (RA2): KERBER.TEST users at the DC's SMB and LDAP: bob refused, user and alice (#1) served;
#   SB.ad-spnego (RA3): the DC as the SPNEGO client of Apache on kdc's LAN address (#2-#4), with -Credential
#   and with -UseDefaultCredentials (#7, a scheduled task).
# The DC changes (#1-#4 and #7, lib/ad.sh) are undone in the same run, also on an early exit, and a run starts only
# from lib/ad/baseline.txt (after undoing a killed run's leftovers). Run it as `harness/field/run.sh ad-trust`.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: ad-trust.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset KUSER ALICE BOB
R=${REALM//./\\.}
AR='AD\.KERBER\.TEST'
I3='etypes \{rep=aes256-cts-hmac-sha1-96\(18\), tkt=aes256-cts-hmac-sha1-96\(18\), ses=aes256-cts-hmac-sha1-96\(18\)\}'
RAENV="export KRB5_CONFIG=\$HOME/ra/krb5.conf"
SMB="smbclient -k //test-server.ad.kerber.test/SYSVOL -c ls; echo \"smbclient rc=\$?\""
LDAP="ldapsearch -Y GSSAPI -H ldap://test-server.ad.kerber.test -b DC=ad,DC=kerber,DC=test '(sAMAccountName=kbruser)' cn; echo \"ldapsearch rc=\$?\""
WHO="ldapwhoami -Y GSSAPI -H ldap://test-server.ad.kerber.test 2>&1; true"
SSHK="-o PreferredAuthentications=gssapi-with-mic -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=\$HOME/ra/known_hosts"
KDC_LAN=''
# shellcheck source=../lib/ad.sh
. "$FIELD_LIB/ad.sh"
cleanup() {
    adundo
    # shellcheck disable=SC2016 # the pid file is client2's
    timeout -k 5 60 "$LAB" ssh client2 -- '[ -f ~/ra/px.pid ] && kill "$(cat ~/ra/px.pid)"; rm -rf ~/ra; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# stopif <check ERE> <why>: when such a check failed, the rest is not run.
stopif() {
    if awk -F'\t' -v rx="$1" '$2 == "FAIL" && $1 ~ rx' "$CHECKS" | grep -q .; then
        note "$2: the rest of the scenario is not run"
        finish
        exit $?
    fi
}

section "ad-trust --leg $LEG: the real AD DC (TEST-SERVER, AD.KERBER.TEST) against the $LEG KDC"
section "RA0. the DC: its clock and its state (a killed run's leftovers are undone, nothing else is touched)"
dcskew
adbaseline
observelast obs.dc.kbruser 'info account: kbruser [^ ]+ locked=[A-Za-z]+ neverexpires=[A-Za-z]+'
stopif '^dc\.(skew|baseline)$' "the DC is unreachable, its clock is off or its state is not lib/ad/baseline.txt"

section "RA0. kdc as upgrade.sh left it; client2 at the leg's baseline, with the AD realm in a copy of krb5.conf"
kdcis
resetvm client2
ktcheck client2 /etc/krb5.keytab client2
check kdc.lan '^[0-9]+(\.[0-9]+){3}$' host "$LABQ ip kdc lan"
KDC_LAN=$(grep -m1 -E '^[0-9]+(\.[0-9]+){3}$' "$LAST_OUT")
check client2.adconf '^> +\.ad\.kerber\.test = AD\.KERBER\.TEST$' run client2 'mkdir -p ~/ra && awk '"'"'/^\[domain_realm\]/ && !d { print "    AD.KERBER.TEST = {"; print "        kdc = 10.10.38.38"; print "    }"; print ""; print; print "    .ad.kerber.test = AD.KERBER.TEST"; print "    ad.kerber.test = AD.KERBER.TEST"; d = 1; next } { print }'"'"' /etc/krb5.conf > ~/ra/krb5.conf; diff /etc/krb5.conf ~/ra/krb5.conf; true'
check client2.resolve '^10\.10\.38\.38 +test-server\.ad\.kerber\.test$' run client2 'getent hosts test-server.ad.kerber.test'

section "RA0. the trust principals, the admin way (kadmin.local on kdc; AD_TRUST_PASSWORD twice on stdin; the trust's enctypes 24)"
run kdc "for p in krbtgt/AD.KERBER.TEST@KERBER.TEST krbtgt/KERBER.TEST@AD.KERBER.TEST; do sudo kadmin.local -q \"delprinc -force \$p\" 2>&1 | grep -v '^Authenticating'; done; true"
ADD='sudo kadmin.local -q "addprinc -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal'
check trust.out '^Principal "krbtgt/AD\.KERBER\.TEST@KERBER\.TEST" created\.$' runin kdc "AD_TRUST_PASSWORD, twice" "$ADD krbtgt/AD.KERBER.TEST@KERBER.TEST\" 2>&1" < <(adtwice AD_TRUST_PASSWORD)
check trust.in '^Principal "krbtgt/KERBER\.TEST@AD\.KERBER\.TEST" created\.$' runin kdc "AD_TRUST_PASSWORD, twice" "$ADD krbtgt/KERBER.TEST@AD.KERBER.TEST\" 2>&1" < <(adtwice AD_TRUST_PASSWORD)
run kdc 'sudo kadmin.local -q "getprinc krbtgt/AD.KERBER.TEST@KERBER.TEST"; sudo kadmin.local -q "getprinc krbtgt/KERBER.TEST@AD.KERBER.TEST"'
countlast trust.keys '^Key: vno 1, aes(256|128)-cts-hmac-sha1-96$' 4

section "RA0. Test A (AD to us): kbruser@AD.KERBER.TEST from the DC, then svc/setup@KERBER.TEST through AD's referral"
kdcmark ra0
check testA.kinit '^Default principal: kbruser@AD\.KERBER\.TEST$' runin client2 "AD_KBRUSER_PASSWORD" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/kbruser.cc; kinit kbruser@AD.KERBER.TEST && klist -e" < <(adonce AD_KBRUSER_PASSWORD)
stopif '^testA\.kinit$' "the DC refuses kbruser's sign-in, so no Windows leg runs"
check testA.kvno "^svc/setup@$R: kvno = [0-9]+\$" run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/kbruser.cc; KRB5_TRACE=/dev/stderr kvno svc/setup@$REALM 2>&1"
checklast testA.referral "Received TGT for service realm: krbtgt/$R@$AR\$"
kdcsince ra0 "kbruser@$AR"
checklast testA.kdc-issue "TGS_REQ .* 192\\.168\\.177\\.22: ISSUE: authtime [0-9]+, $I3, kbruser@$AR for svc/setup@$R\$"

section "RA0. kinit -E kbruser@ad.kerber.test, the UPN as one enterprise component (kinit.c:418, get_in_tkt.c:921-930): MIT's, then in the rust leg ours, each first AS-REQ through kdc-req-proxy.py on client2"
EK=
if [ "$LEG" = rust ]; then
    b=kerber-rust-${FIELD_SHA:0:12}/target/release/krb5-kinit
    check ent.ours.build '^[0-9a-f]{64}$' run kdc "sha256sum < ~/$b | cut -c1-64"
    h=$(grep -m1 -oE '^[0-9a-f]{64}$' "$LAST_OUT")
    check ent.ours.copy "^client2: ~/ra/kinit ${h:-none}\$" host "$LABQ ssh kdc -- 'cat ~/$b' | $LABQ ssh client2 -- 'cat > ~/ra/kinit && chmod 0755 ~/ra/kinit && echo \"client2: ~/ra/kinit \$(sha256sum < ~/ra/kinit | cut -c1-64)\"'"
    [ -n "$h" ] && grep -q "^client2: ~/ra/kinit $h\$" "$LAST_OUT" && EK="\$HOME/ra/kinit"
fi
check ent.px.copy '^self-test ok$' hostin "scripts/lib/kdc-req-proxy.py" "$LABQ ssh client2 -- 'cat > ~/ra/kdc-req-proxy.py && python3 ~/ra/kdc-req-proxy.py --self-test | tail -n 1'" < "$HERE/../../../scripts/lib/kdc-req-proxy.py"
check ent.px.conf '^ +kdc = 127\.0\.0\.1:1891$' run client2 "sed 's/^\\( *kdc = \\)10\\.10\\.38\\.38\$/\\1127.0.0.1:1891/' ~/ra/krb5.conf > ~/ra/px.conf && grep -E '^ +kdc = 127' ~/ra/px.conf"
check ent.px.up '^proxy: listening on 127\.0\.0\.1:1891$' run client2 "setsid python3 -u ~/ra/kdc-req-proxy.py 1891 10.10.38.38 88 ~/ra/px.jsonl > /dev/null 2> ~/ra/px.err < /dev/null & echo \$! > ~/ra/px.pid; sleep 1; ss -Hltn 'sport = :1891' | grep -q . && echo 'proxy: listening on 127.0.0.1:1891'"
for k in mit ${EK:+ours}; do
    kin=kinit
    [ "$k" = ours ] && kin=$EK
    run client2 ": > ~/ra/px.jsonl"
    check "ent.kinit.$k" '^Default principal: kbruser\\@ad\.kerber\.test@AD\.KERBER\.TEST$' runin client2 "AD_KBRUSER_PASSWORD" "export KRB5_CONFIG=\$HOME/ra/px.conf KRB5CCNAME=FILE:\$HOME/ra/ent-$k.cc; $kin -E kbruser@ad.kerber.test > /dev/null && klist" < <(adonce AD_KBRUSER_PASSWORD)
    run client2 "cp ~/ra/px.jsonl ~/ra/ent-$k.jsonl; jq -c 'select(.kind == \"req\") | [.msg_type, .cname, .cname_nt, .kdc_options, .padata]' ~/ra/ent-$k.jsonl"
done
check ent.req.mit '^first AS-REQ: kbruser@ad\.kerber\.test, name type 10, no canonicalize$' run client2 "jq -rs '[.[] | select(.kind == \"req\")][0] | \"first AS-REQ: \\(.cname), name type \\(.cname_nt), \\(if any(.kdc_options[]; . == \"canonicalize\") then \"canonicalize\" else \"no canonicalize\" end)\"' ~/ra/ent-mit.jsonl"
[ -n "$EK" ] && check ent.req.same '^FLOW_ad_kinit_e_equal$' run client2 "python3 ~/ra/kdc-req-proxy.py --compare ~/ra/ent-mit.jsonl ~/ra/ent-ours.jsonl ad_kinit_e"
run client2 "kill \$(cat ~/ra/px.pid) && rm -f ~/ra/px.pid; cat ~/ra/px.err"

section "RA0. Test B (us to AD): user@KERBER.TEST to cifs/test-server; AD refuses while our referral TGT carries a PAC, then +no_auth_data_required"
check testB.kinit "^Default principal: user@$R\$" runin client2 "user@$REALM's password ($KUSER)" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/user.cc; kinit user@$REALM && klist -e" < <(once "$KUSER")
check testB.refused "^kvno: .* while getting credentials for cifs/test-server\\.ad\\.kerber\\.test@$AR\$" run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/user.cc; KRB5_TRACE=/dev/stderr kvno cifs/test-server.ad.kerber.test@AD.KERBER.TEST 2>&1; true"
observelast obs.testB.ad-error '(KDC policy rejects request|Generic error \(see e-text\))'
check testB.modprinc '^Attributes: REQUIRES_PRE_AUTH NO_AUTH_DATA_REQUIRED$' run kdc 'sudo kadmin.local -q "modprinc +no_auth_data_required krbtgt/AD.KERBER.TEST@KERBER.TEST"; sudo kadmin.local -q "getprinc krbtgt/AD.KERBER.TEST@KERBER.TEST" | grep -E "^(Attributes|Key)"'
check testB.kvno '^cifs/test-server\.ad\.kerber\.test@AD\.KERBER\.TEST: kvno = [0-9]+$' runin client2 "user@$REALM's password ($KUSER)" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/user2.cc; kinit user@$REALM > /dev/null && kvno cifs/test-server.ad.kerber.test@AD.KERBER.TEST" < <(once "$KUSER")

section "SB.ad-user-in (RA1): kbruser@AD.KERBER.TEST logs into client2's sshd (gssapi-with-mic) as the local kbruser"
check in.sshd '^gssapiauthentication yes$' run client2 'printf "%s\n" "GSSAPIAuthentication yes" "GSSAPICleanupCredentials yes" "GSSAPIStrictAcceptorCheck no" | sudo install -m 0600 /dev/stdin /etc/ssh/sshd_config.d/49-kerber-ad-gssapi.conf && sudo sshd -t && sudo systemctl reload sshd && sudo sshd -T | grep -E "^gssapi(authentication|strictacceptorcheck)"'
# The local account joins whichever local groups sshd's AllowGroups names (rust-ssh's kit allows "admins" only).
check in.k5login '^kbruser@AD\.KERBER\.TEST$' run client2 "id kbruser > /dev/null 2>&1 || sudo useradd -m kbruser; for g in \$(sudo sshd -T | sed -n 's/^allowgroups //p'); do getent group \"\$g\" > /dev/null && sudo usermod -aG \"\$g\" kbruser; done; id kbruser; echo kbruser@AD.KERBER.TEST | sudo install -m 0644 -o kbruser -g kbruser /dev/stdin /home/kbruser/.k5login && sudo cat /home/kbruser/.k5login"
S1=$(date +%s)
kdcmark in
check in.kinit '^Default principal: kbruser@AD\.KERBER\.TEST$' runin client2 "AD_KBRUSER_PASSWORD" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/kbruser.cc; kdestroy 2> /dev/null; kinit kbruser@AD.KERBER.TEST && klist" < <(adonce AD_KBRUSER_PASSWORD)
check in.ssh '^Authenticated to client2\.kerber\.test \(.*\) using "gssapi-with-mic"\.$' run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/kbruser.cc; ssh -v -K $SSHK kbruser@client2.kerber.test 'echo REMOTE: \$(id); klist' 2> \$HOME/ra/ssh.debug; echo \"ssh rc=\$?\"; grep -E 'Authenticated to|Delegating' \$HOME/ra/ssh.debug"
checklast in.id '^REMOTE: uid=[0-9]+\(kbruser\) gid=[0-9]+\(kbruser\) '
checklast in.delegated '^debug1: Delegating credentials$'
checklast in.far-principal '^Default principal: kbruser@AD\.KERBER\.TEST$'
S2=$(date +%s)
check in.sshd-journal "^.* Accepted gssapi-with-mic for kbruser from .* ssh2: kbruser@$AR\$" run client2 "sudo journalctl -u sshd --since \"$(date -u -d "@$S1" '+%F %T')\" --no-pager -o short-precise | grep -v 'from 192.168.177.1 '"
checklast in.authorized "^.* Authorized to kbruser, krb5 principal kbruser@$AR \\(krb5_kuserok\\)\$"
kdcsince in "kbruser@$AR"
checklast in.kdc-issue "TGS_REQ .* 192\\.168\\.177\\.22: ISSUE: authtime [0-9]+, $I3, kbruser@$AR for host/client2\\.kerber\\.test@$R\$"
dcwin in "$S1" "$S2"
checklast in.dc-4769 '^[0-9T:.Z-]+  4769  user=kbruser@AD\.KERBER\.TEST  domain=AD\.KERBER\.TEST  service=KERBER\.TEST  status=0x0  tktEnc=0x12 '

section "SB.ad-user-out (RA2): KERBER.TEST users at the DC's SYSVOL share and LDAP; alice is mapped (#1) for this cell only"
U1=$(date +%s)
kdcmark out
check out.bob-kinit "^Default principal: bob@$R\$" runin client2 "bob@$REALM's password ($BOB)" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/bob.cc; kinit bob@$REALM && klist" < <(once "$BOB")
check out.bob-smb '^session setup failed: NT_STATUS_ACCESS_DENIED$' run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/bob.cc; $SMB"
check out.bob-ldap '^text: 000004DC: LdapErr: DSID-0C090D5C, comment: In order to perform this opera$' run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/bob.cc; $LDAP"
check out.user-smb '^  ad\.kerber\.test +Dr +0 ' runin client2 "user@$REALM's password ($KUSER)" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/user3.cc; kinit user@$REALM > /dev/null && $SMB" < <(once "$KUSER")
check out.user-ldap '^cn: kbruser$' run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/user3.cc; $LDAP; $WHO"
checklast out.user-whoami '^u:ADKERBER\\kbruser$'
kdcsince out "user@$R"
checklast out.referral-issue "TGS_REQ .* 192\\.168\\.177\\.22: ISSUE: authtime [0-9]+, $I3, user@$R for krbtgt/$AR@$R\$"
adapply 1 apply1
check out.alice-smb '^  ad\.kerber\.test +Dr +0 ' runin client2 "alice@$REALM's password ($ALICE)" "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/alice.cc; kinit alice@$REALM > /dev/null && $SMB" < <(once "$ALICE")
check out.alice-ldap '^cn: kbruser$' run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/alice.cc; $LDAP; $WHO"
checklast out.alice-whoami '^u:ADKERBER\\kbruser$'
adundo
U2=$(date +%s)
dcwin out "$U1" "$U2"
checklast out.dc-4769-user '  4769  user=user@KERBER\.TEST  domain=KERBER\.TEST  service=TEST-SERVER\$  status=0x0  tktEnc=0x12 '
checklast out.dc-4769-alice '  4769  user=alice@KERBER\.TEST  domain=KERBER\.TEST  service=TEST-SERVER\$  status=0x0  tktEnc=0x12 '

section "SB.ad-spnego (RA3): the DC (ADKERBER\\krbadmin) as the SPNEGO client of Apache mod_auth_gssapi on kdc, over kdc's LAN address (#2-#4)"
runin kdc "lib/ad/ra3-gssapi.conf" 'sudo install -m 0644 /dev/stdin /etc/httpd/conf.d/ra3-gssapi.conf' < "$FIELD_LIB/ad/ra3-gssapi.conf"
runin kdc "lib/ad/whoami.cgi" 'sudo install -m 0755 /dev/stdin /var/www/cgi-bin/whoami' < "$FIELD_LIB/ad/whoami.cgi"
check spnego.httpd '^Syntax OK$' run kdc 'sudo restorecon /etc/httpd/conf.d/ra3-gssapi.conf /var/www/cgi-bin/whoami; sudo apachectl configtest 2>&1 && sudo systemctl restart httpd && systemctl is-active httpd'
check spnego.curl "^REMOTE_USER=user@$R\$" run client2 "$RAENV; export KRB5CCNAME=FILE:\$HOME/ra/user3.cc; curl -sS --negotiate -u : http://kdc.kerber.test/cgi-bin/whoami; curl -sS -o /dev/null -D - http://kdc.kerber.test/cgi-bin/whoami | grep -iE '^(HTTP|www-authenticate)'"
checklast spnego.unauth-401 '^HTTP/1\.1 401 Unauthorized'
checklast spnego.www-auth '^WWW-Authenticate: Negotiate'
adapply 234 apply234 KDC_LAN="$KDC_LAN" TAG="${FIELD_RUN##*/}-$LEG"
L=${KDC_LAN//./\\.}
check spnego.dc-resolves "^kdc\\.kerber\\.test -> $L\$" dc tnc
checklast spnego.dc-tcp88 "^tcp 88 : TcpTestSucceeded=True RemoteAddress=$L "
checklast spnego.dc-tcp80 "^tcp 80 : TcpTestSucceeded=True RemoteAddress=$L "
T3=$(date +%s)
kdcmark spnego
run kdc "sudo sh -c 'wc -l < /var/log/httpd/ra3_access.log 2> /dev/null || echo 0'"
AM=$(grep -m1 -E '^[0-9]+$' "$LAST_OUT" || echo 0)
capstart kdc spnego 'host 10.10.38.38'
check spnego.cred '^REMOTE_USER=krbadmin@AD\.KERBER\.TEST$' dc iwr
checklast spnego.cred-200 '^HTTP 200$'
checklast spnego.cred-negotiate '^AUTH_TYPE=Negotiate$'
printf '7\n' >> "$ADLOG"
check spnego.default '^REMOTE_USER=krbadmin@AD\.KERBER\.TEST$' dc task
checklast spnego.default-200 '^HTTP 200$'
checklast spnego.task-removed 'task still present: False +output file still present: False$'
capstop kdc spnego
T4=$(date +%s)
adundo
run kdc "sudo tail -n +$((AM + 1)) /var/log/httpd/ra3_access.log"
checklast spnego.apache-200 "^10\\.10\\.38\\.38 - krbadmin@$AR \\[.*\\] \"GET /cgi-bin/whoami HTTP/1\\.1\" 200 "
kdcsince spnego "krbadmin@$AR"
checklast spnego.kdc-issue "TGS_REQ .* 10\\.10\\.38\\.38: ISSUE: authtime [0-9]+, $I3, krbadmin@$AR for HTTP/kdc\\.kerber\\.test@$R\$"
check spnego.reply-lan "^$L\$" host "tshark -r $(printf '%q' "$REC_DIR/pcap/spnego.pcap") -Y 'kerberos.msg_type == 13' -T fields -e ip.src 2> /dev/null | sort -u"
observe obs.spnego.fragments 'fragments: [0-9]+' host "printf 'fragments: %s\\n' \"\$(tshark -r $(printf '%q' "$REC_DIR/pcap/spnego.pcap") -Y 'ip.flags.mf == 1 || ip.frag_offset > 0' 2> /dev/null | wc -l)\""
dcwin spnego "$T3" "$T4"
checklast spnego.dc-4769 '^[0-9T:.Z-]+  4769  user=krbadmin@AD\.KERBER\.TEST  domain=AD\.KERBER\.TEST  service=KERBER\.TEST  status=0x0  tktEnc=0x12 '

section "the end: the DC as the run found it"
adundo
adrestored
finish
