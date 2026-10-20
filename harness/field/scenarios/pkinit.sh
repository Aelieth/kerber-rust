#!/usr/bin/env bash
# harness/field/scenarios/pkinit.sh --leg mit|rust: PKINIT as the leg's KDC (as upgrade.sh left it on kdc) serves it
# from kdc.conf, seen from client2's MIT kinit, kdc.conf restored after. The certificates are the lab's (L6), P-256:
# on kdc $PK_KDC_DIR holds cacert.pem, kdc.pem and kdc.key (SAN krbtgt/REALM@REALM, EKU id-pkinit-KPKdc), and
# kdc-rsa.pem, kdc-rsa.key and rsa-cacert.pem (an RSA 2048 KDC identity and its CA); on client2 $PK_CLIENT_DIR holds
# cacert.pem, alice.pem and alice.key, alice-wrongsan.pem and .key (a SAN naming another principal), and
# alice-unknownca.pem and .key with their issuer unknown-cacert.pem (a CA the KDC does not trust), and
# alice-rsa.pem and .key with rsa-cacert.pem (an RSA 2048 client certificate and its CA). Keys are never printed: only certificates' public fields are read. kdc carries
# them in the snapshot its leg's upgrade started from; client2 is reset to $PK_SNAPSHOT_CLIENT2 when that is set
# (field.env), else used as it stands. alice is made +requires_preauth for the cells (the lab's principals are not,
# and MIT's kinit tries PKINIT only when the KDC asks for preauthentication), and restored after.
#   PK.7a: no pkinit_identity: the KDC starts and logs "preauth pkinit failed to initialize: PKINIT initialization
#          failed: No pkinit_identity supplied for realm REALM"; alice's certificate kinit is not offered PKINIT;
#   PK.1:  [kdcdefaults] pkinit_identity and pkinit_anchors: no such line, and alice's certificate kinit gets a TGT,
#          the KDC logging "PKINIT: freshness token received from alice@REALM" (MIT's kinit sends the token it got);
#   PK.san: client2's alice-wrongsan.pem (a SAN naming another principal) is refused: "preauth (pkinit) verify
#          failure: Client name mismatch" in the KDC log (75);
#   PK.ca: client2's alice-unknownca.pem, issued by unknown-cacert.pem, which client2 trusts and the KDC does not:
#          "Failed to verify received certificate (depth 0): unable to get local issuer certificate" (70);
#   PK.refuse: with alice's password on stdin, a refusal that carries e-data goes on to the password and a TGT
#          (alice-unknownca's 70, and the <SUBJECT>( rule's 24 in PK.dbmatch); alice-wrongsan's 75 carries none and
#          ends with rc 1; each refusal's code as the kinit's trace gives it;
#   PK.rsacert: client2's alice-rsa.pem (an RSA 2048 key, issued by rsa-cacert.pem, which kdc's pkinit_anchors and
#          client2 both trust) gets a TGT, from MIT's kinit and, in the rust leg, ours (it signs with the RSA key);
#   PK.dbmatch: alice's pkinit_cert_match rule decides her alice.pem kinit: "<KU>digitalSignature" and "<SAN>^alice@"
#          match and get a TGT; "&&<KU>digitalSignature<SAN>^bob@" misses: "preauth (pkinit) verify failure:
#          Certificate mismatch" (66); "<SUBJECT>(" does not compile (regcomp's REG_EPAREN, 8, which the KDC reports
#          as an errno): "preauth (pkinit) verify failure: Exec format error" (24);
#   PK.6:  kinit -n with client2's anchors: a WELLKNOWN/ANONYMOUS ticket (the principal is made for the cell);
#   PK.fast: with that anonymous ticket as FAST armor (-T), alice's certificate kinit runs pkinit inside the armored
#          request: a TGT, the trace's pkinit, FAST-encoding and FAST reply key lines;
#   PK.anchors: a profile whose second pkinit_anchors value is the KDC's CA: alice's certificate kinit gets a TGT;
#          an anchors file with no certificate: the reply does not verify (the trace's line and module 17's 70), and
#          the password is taken (stdin), which cannot open a PKINIT reply;
#   PK.kpasswd: with pkinit_identities and pkinit_anchors in a profile of its own, alice's kpasswd gets its
#          kadmin/changepw ticket by pkinit (the trace's module line) and stops at the new password (stdin empty);
#          in the rust leg kdc's build of krb5-kpasswd runs from client2's ~/pk/kpasswd too;
#   PK.7b: pkinit_identity names a file that is not there: the line ends "Cannot read certificate file '<file>':
#          (null)", OpenSSL 3 giving no reason for a system error;
#   PK.7c: the realm's pkinit_identity wins over [kdcdefaults]' missing one: alice's certificate kinit gets a TGT;
#   PK.eku: when client2 also holds alice-noeku.pem and alice-noeku.key (alice's SAN, no extended key usage), its
#          kinit is refused (77, "Inconsistent key purpose" in the KDC's verify-failure line), and with
#          pkinit_eku_checking = none it gets a TGT;
#   PK.dir: a DIR: identity holding both, as NAME.crt and NAME.key links: with pkinit_cert_match = <EKU>pkinit (a
#          profile ahead of /etc/krb5.conf in KRB5_CONFIG) kinit chooses alice's certificate and gets a TGT (the
#          no-EKU one would be refused with 77); with no rule it chooses neither (rc 1); each kinit's trace gives
#          MIT's matching lines (the rule, then 2 certs checked and 1 match; with no rule, 2 certs where one must be),
#          ours the same lines as MIT's;
#   PK.fallback: an identity file that is not there fails the PKINIT mechanism, and kinit goes on to alice's
#          password on stdin and gets a TGT; with no password it fails (rc 1, the text observed);
#   PK.twoid: a second X509_user_identity is refused before any request: "kinit: Preauth module pkinit:
#          X509_user_identity can not be given twice", then " while setting 'X509_user_identity'='<value>'" (rc 1);
#   PK.rsakdc: the RSA KDC identity (kdc-rsa.pem, kdc-rsa.key): the KDC signs its reply with the RSA key, and
#          alice's certificate kinit, trusting both CAs, verifies it (the trace's line) and gets a TGT, MIT's and ours;
#   PK.rsabig: made on kdc for the cell by scripts/lib/pkinit-rsa-certs.sh, an RSA CA, a KDC identity with an
#          8192-bit key and alice's certificate with a 3-prime key, alice's piped to client2: her kinit gets a TGT,
#          each kinit's time observed (ms, the AS exchange with both signatures);
#   PK.ec224, PK.ec384, PK.ec521, PK.k256: made on kdc by scripts/lib/pkinit-ec-certs.sh, a CA, a KDC identity and
#          alice's certificate, each with a P-224 key, then P-384, P-521 and secp256k1, alice's piped to client2:
#          her kinit gets a TGT;
#   PK.dh: the KDC's realm has pkinit_dh_min_bits = 4096 and client2's kinit 2048 (~/pk/dh.conf first): the KDC
#          refuses its 2048-bit DH with 65 and its groups, and kinit tries again with P-384 and gets a TGT;
#   PK.dh1024: client2's kinit at pkinit_dh_min_bits = 1024 (~/pk/dh1024.conf first): the KDC's realm at 1024
#          takes its 1024-bit DH for a TGT; at the default 2048 it is 65, and kinit tries again with P-256;
# Graded on both legs, MIT's first. In the rust leg the client cells run twice: MIT's kinit, then ours, kdc's
# build of krb5-kinit piped to client2's ~/pk/kinit (no host file) and run by path, so MIT's stays the one on PATH.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: pkinit.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
R=${REALM//./\\.}
KC=/var/kerberos/krb5kdc/kdc.conf
D=${PK_KDC_DIR:-/var/kerberos/krb5kdc/pkinit}
C=${PK_CLIENT_DIR:-/home/lab/pkinit}
BIG=/var/kerberos/krb5kdc/pkbig
EC=/var/kerberos/krb5kdc/pkec
legset ALICE
ANON=0
PREAUTH=0
DBMATCH=0
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "[ -e $KC.pk ] && sudo mv $KC.pk $KC && sudo systemctl restart krb5kdc; [ $ANON = 1 ] && sudo kadmin.local -q 'delprinc -force WELLKNOWN/ANONYMOUS'; [ $PREAUTH = 1 ] && sudo kadmin.local -q 'modprinc -requires_preauth alice'; [ $DBMATCH = 1 ] && sudo kadmin.local -q 'delstr alice pkinit_cert_match'; sudo rm -rf $BIG $EC; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'rm -rf ~/pk; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# pkkdc <check> <text appended to kdc.conf>: the saved kdc.conf plus that text, the KDC restarted, and the log
# marked before the restart, so the startup lines are the ones after the mark.
pkkdc() {
    kdcmark "$1"
    check "$1" '^krb5kdc: active, 88 listening$' run kdc "sudo cp -p $KC.pk $KC && printf '%b' '$2' | sudo tee -a $KC > /dev/null && sudo systemctl restart krb5kdc && for i in \$(seq 1 40); do ss -Hlun 'sport = :88' | grep -q . && break; sleep 0.25; done; sudo tail -n 8 $KC; echo \"krb5kdc: \$(systemctl is-active krb5kdc), 88 \$(ss -Hlun 'sport = :88' | grep -q . && echo listening)\""
}
# certkinit <check> <ERE> [<identity>]: alice's kinit from client2 with a certificate of hers (alice, or the name
# given) and client2's anchors, stdin empty (no password to fall back on), then the ticket cache listed.
certkinit() {
    local id=${3:-alice}
    check "$1" "$2" run client2 "mkdir -p ~/pk && kdestroy -c FILE:\$HOME/pk/a.cc 2> /dev/null; kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=FILE:$C/$id.pem,$C/$id.key -c FILE:\$HOME/pk/a.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/a.cc 2>&1 | grep -E '^Default principal|krbtgt/'"
}
# pwkinit <check> <kinit> <identity> <ERE for the rc line> <code>: <identity>'s certificate kinit, trusting client2's two
# CAs, alice's password on stdin; the KDC's refusal in the trace is <code> (the com_err code, from -1765328384).
pwkinit() {
    check "$1" "$4" runin client2 "alice's password ($ALICE)" "mkdir -p ~/pk && kdestroy -c FILE:\$HOME/pk/p.cc 2> /dev/null; rm -f \$HOME/pk/p.trace; KRB5_TRACE=\$HOME/pk/p.trace $2 -X X509_anchors=FILE:$C/cacert.pem -X X509_anchors=FILE:$C/unknown-cacert.pem -X X509_user_identity=FILE:$C/$3.pem,$C/$3.key -c FILE:\$HOME/pk/p.cc alice > \$HOME/pk/p.out 2>&1; echo \"kinit rc=\$?\"; grep -E 'kinit: ' \$HOME/pk/p.out; klist -c FILE:\$HOME/pk/p.cc 2>&1 | grep -E '^Default principal'; grep -oE 'Received error from KDC: -?[0-9]+' \$HOME/pk/p.trace | sort -u" < <(once "$ALICE")
    checklast "$1.code" "^Received error from KDC: $(($5 - 1765328384))\$"
}

section "pkinit --leg $LEG: PKINIT as the $LEG KDC serves it from kdc.conf, MIT kinit from client2"
kdcis
if [ -n "${PK_SNAPSHOT_CLIENT2:-}" ]; then
    check reset.client2 rc host "$LABQ reset client2 $PK_SNAPSHOT_CLIENT2"
    waitsync client2
fi
check l6.kdc '^kdc: krb5-pkinit, CA and KDC P-256, RSA KDC identity$' run kdc "rpm -q krb5-pkinit > /dev/null && for f in cacert.pem kdc.pem kdc-rsa.pem rsa-cacert.pem; do sudo openssl x509 -in $D/\$f -noout -subject; done && sudo test -r $D/kdc.key && sudo test -r $D/kdc-rsa.key && sudo openssl x509 -in $D/kdc.pem -noout -text | grep -qE 'ASN1 OID: prime256v1' && sudo openssl x509 -in $D/kdc-rsa.pem -noout -text | grep -qE 'Public Key Algorithm: rsaEncryption' && echo 'kdc: krb5-pkinit, CA and KDC P-256, RSA KDC identity'"
check l6.client2 '^client2: krb5-pkinit, alice P-256$' run client2 "rpm -q krb5-pkinit > /dev/null && for f in alice alice-wrongsan alice-unknownca unknown-cacert alice-rsa rsa-cacert; do openssl x509 -in $C/\$f.pem -noout -subject || exit 1; done && test -r $C/alice.key && test -r $C/alice-wrongsan.key && test -r $C/alice-unknownca.key && test -r $C/alice-rsa.key && openssl x509 -in $C/alice.pem -noout -text | grep -qE 'ASN1 OID: prime256v1' && echo 'client2: krb5-pkinit, alice P-256'"
OURS=
OURSPW=
if [ "$LEG" = rust ]; then
    B=kerber-rust-${FIELD_SHA:0:12}/target/release/krb5-kinit
    check ours.build '^[0-9a-f]{64}$' run kdc "sha256sum < ~/$B | cut -c1-64"
    H=$(grep -m1 -oE '^[0-9a-f]{64}$' "$LAST_OUT")
    check ours.copy "^client2: ~/pk/kinit ${H:-none}\$" host "$LABQ ssh kdc -- 'cat ~/$B' | $LABQ ssh client2 -- 'install -d ~/pk && cat > ~/pk/kinit && chmod 0755 ~/pk/kinit && echo \"client2: ~/pk/kinit \$(sha256sum < ~/pk/kinit | cut -c1-64)\"'"
    [ -n "$H" ] && grep -q "^client2: ~/pk/kinit $H\$" "$LAST_OUT" && OURS="\$HOME/pk/kinit"
    B=kerber-rust-${FIELD_SHA:0:12}/target/release/krb5-kpasswd
    check ours.kpasswd.build '^[0-9a-f]{64}$' run kdc "sha256sum < ~/$B | cut -c1-64"
    H=$(grep -m1 -oE '^[0-9a-f]{64}$' "$LAST_OUT")
    check ours.kpasswd.copy "^client2: ~/pk/kpasswd ${H:-none}\$" host "$LABQ ssh kdc -- 'cat ~/$B' | $LABQ ssh client2 -- 'install -d ~/pk && cat > ~/pk/kpasswd && chmod 0755 ~/pk/kpasswd && echo \"client2: ~/pk/kpasswd \$(sha256sum < ~/pk/kpasswd | cut -c1-64)\"'"
    [ -n "$H" ] && grep -q "^client2: ~/pk/kpasswd $H\$" "$LAST_OUT" && OURSPW="\$HOME/pk/kpasswd"
fi
check kdc.conf.saved '^no pkinit_identity$' run kdc "sudo cp -p $KC $KC.pk && ! sudo grep -qE '^[[:space:]]*pkinit_identity' $KC && echo 'no pkinit_identity'"
run kdc "sudo kadmin.local -q 'getprinc WELLKNOWN/ANONYMOUS' 2>&1 | grep -E '^Principal|does not exist'"
if grep -q 'does not exist' "$LAST_OUT"; then
    ANON=1
    check setup.anonymous "^Principal \"WELLKNOWN/ANONYMOUS@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey WELLKNOWN/ANONYMOUS' 2>&1"
fi
run kdc "sudo kadmin.local -q 'getprinc alice' 2>&1 | grep -E '^Attributes:'"
if ! grep -q 'REQUIRES_PRE_AUTH' "$LAST_OUT"; then
    PREAUTH=1
    check setup.alice.preauth "^Principal \"alice@$R\" modified\\.\$" run kdc "sudo kadmin.local -q 'modprinc +requires_preauth alice' 2>&1"
fi

section "PK.7a no pkinit_identity: the KDC starts without PKINIT and says why (MIT and ours)"
pkkdc PK.7a.kdc ''
kdcsince PK.7a.kdc 'preauth pkinit'
checklast PK.7a.line "preauth pkinit failed to initialize: PKINIT initialization failed: No pkinit_identity supplied for realm $R\$"
certkinit PK.7a.kinit '^kinit rc=1$'
observelast obs.PK.7a.kinit 'kinit: .*'

section "PK.1 [kdcdefaults] pkinit_identity and pkinit_anchors: alice's certificate gets a TGT (MIT and ours)"
pkkdc PK.1.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n"
kdcsince PK.1.kdc 'preauth pkinit'
countlast PK.1.no-line 'preauth pkinit failed' 0
certkinit PK.1.kinit '^kinit rc=0$'
checklast PK.1.tgt "^Default principal: alice@$R\$"
kdcsince PK.1.kdc 'PKINIT: '
checklast PK.1.fresh "PKINIT: freshness token received from alice@$R\$"
kdcmark PK.1.as
certkinit PK.1.again '^kinit rc=0$'
kdcsince PK.1.as 'AS_REQ'
observelast obs.PK.1.as_req 'AS_REQ .*'

section "PK.san alice's certificate with another principal's SAN: refused, Client name mismatch (MIT and ours)"
kdcmark PK.san.as
certkinit PK.san.kinit '^kinit rc=1$' alice-wrongsan
observelast obs.PK.san.kinit 'kinit: .*'
kdcsince PK.san.as 'verify failure'
checklast PK.san.line 'preauth \(pkinit\) verify failure: Client name mismatch$'

section "PK.ca alice's certificate from a CA the KDC does not trust: 70 (MIT and ours)"
kdcmark PK.ca.as
check PK.ca.kinit '^kinit rc=1$' run client2 "mkdir -p ~/pk && kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_anchors=FILE:$C/unknown-cacert.pem -X X509_user_identity=FILE:$C/alice-unknownca.pem,$C/alice-unknownca.key -c FILE:\$HOME/pk/u.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\""
observelast obs.PK.ca.kinit 'kinit: .*'
kdcsince PK.ca.as 'verify failure'
checklast PK.ca.line 'preauth \(pkinit\) verify failure: Failed to verify received certificate \(depth 0\): unable to get local issuer certificate$'

section "PK.refuse a refused certificate with alice's password: 70 goes on to the password, 75 stops (MIT and ours)"
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    pwkinit "PK.refuse.ca.$k" "$kinit" alice-unknownca '^kinit rc=0$' 70
    checklast "PK.refuse.ca.$k.tgt" "^Default principal: alice@$R\$"
    pwkinit "PK.refuse.san.$k" "$kinit" alice-wrongsan '^kinit rc=1$' 75
    observelast "obs.PK.refuse.san.$k" 'kinit: .*'
done

section "PK.rsacert alice's RSA certificate from the RSA CA both trust: a TGT (MIT and ours)"
pkkdc PK.rsacert.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n    pkinit_anchors = FILE:$D/rsa-cacert.pem\n"
check PK.rsacert.kinit '^kinit rc=0$' run client2 "mkdir -p ~/pk && kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_anchors=FILE:$C/rsa-cacert.pem -X X509_user_identity=FILE:$C/alice-rsa.pem,$C/alice-rsa.key -c FILE:\$HOME/pk/r.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/r.cc 2>&1 | grep -E '^Default principal'"
checklast PK.rsacert.tgt "^Default principal: alice@$R\$"
if [ -n "${OURS:-}" ]; then
    check PK.rsacert.ours '^kinit rc=0$' run client2 "kdestroy -c FILE:\$HOME/pk/r.cc 2> /dev/null; $OURS -X X509_anchors=FILE:$C/cacert.pem -X X509_anchors=FILE:$C/rsa-cacert.pem -X X509_user_identity=FILE:$C/alice-rsa.pem,$C/alice-rsa.key -c FILE:\$HOME/pk/r.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/r.cc 2>&1 | grep -E '^Default principal'"
    checklast PK.rsacert.ours.tgt "^Default principal: alice@$R\$"
fi
pkkdc PK.rsacert.back "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n"

section "PK.dbmatch alice's pkinit_cert_match rule decides her certificate kinit (MIT and ours)"
# dbmatch <check> <rule> <ERE for the kinit line> [<ERE for the KDC's verify-failure line>]
dbmatch() {
    check "$1.set" '^Attribute set' run kdc "sudo kadmin.local -q 'setstr alice pkinit_cert_match \"$2\"' 2>&1 | sed 's/^Attribute set for principal.*/Attribute set/'"
    kdcmark "$1.as"
    certkinit "$1.kinit" "$3"
    if [ -n "${4:-}" ]; then
        kdcsince "$1.as" 'verify failure'
        checklast "$1.line" "$4"
    fi
}
DBMATCH=1
dbmatch PK.dbmatch.ku '<KU>digitalSignature' '^kinit rc=0$'
dbmatch PK.dbmatch.san '<SAN>^alice@' '^kinit rc=0$'
dbmatch PK.dbmatch.miss '&&<KU>digitalSignature<SAN>^bob@' '^kinit rc=1$' 'preauth \(pkinit\) verify failure: Certificate mismatch$'
dbmatch PK.dbmatch.bad '<SUBJECT>(' '^kinit rc=1$' 'preauth \(pkinit\) verify failure: Exec format error$'
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    pwkinit "PK.refuse.rule.$k" "$kinit" alice '^kinit rc=0$' 24
    checklast "PK.refuse.rule.$k.tgt" "^Default principal: alice@$R\$"
done
run kdc "sudo kadmin.local -q 'delstr alice pkinit_cert_match' 2>&1"
DBMATCH=0

section "PK.6 kinit -n with client2's anchors: an anonymous ticket (MIT and ours)"
check PK.6.kinit '^Default principal: WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS$' run client2 "mkdir -p ~/pk && kinit -n -X X509_anchors=FILE:$C/cacert.pem -c FILE:\$HOME/pk/n.cc < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/n.cc 2>&1 | grep -E '^Default principal|krbtgt/'"
checklast PK.6.rc '^kinit rc=0$'

section "PK.fast PKINIT inside FAST: an anonymous armor ticket, then alice's certificate under -T (MIT and ours)"
check PK.fast.armor '^armor rc=0$' run client2 "mkdir -p ~/pk && kinit -n -X X509_anchors=FILE:$C/cacert.pem -c FILE:\$HOME/pk/armor.cc < /dev/null > /dev/null 2>&1; echo \"armor rc=\$?\""
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    check "PK.fast.$k" '^kinit rc=0$' run client2 "kdestroy -c FILE:\$HOME/pk/fast.cc 2> /dev/null; rm -f \$HOME/pk/fast.trace; KRB5_TRACE=\$HOME/pk/fast.trace $kinit -T FILE:\$HOME/pk/armor.cc -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=FILE:$C/alice.pem,$C/alice.key -c FILE:\$HOME/pk/fast.cc alice < /dev/null > /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/fast.cc 2>&1 | grep -E '^Default principal'; grep -oE 'Preauth module pkinit \\(16\\) \\(real\\) returned: 0/Success|Encoding request body and padata into FAST request|FAST reply key' \$HOME/pk/fast.trace | sort -u"
    checklast "PK.fast.$k.tgt" "^Default principal: alice@$R\$"
    checklast "PK.fast.$k.pkinit" '^Preauth module pkinit \(16\) \(real\) returned: 0/Success$'
    checklast "PK.fast.$k.armored" '^Encoding request body and padata into FAST request$'
    checklast "PK.fast.$k.reply" '^FAST reply key$'
done

section "PK.kpasswd pkinit_identities and pkinit_anchors in a profile: kpasswd's kadmin/changepw ticket by PKINIT (MIT and ours)"
check PK.kpasswd.conf '^    pkinit_anchors = FILE:' run client2 "mkdir -p ~/pk && printf '[libdefaults]\n    pkinit_identities = FILE:%s/alice.pem,%s/alice.key\n    pkinit_anchors = FILE:%s/cacert.pem\n' $C $C $C > ~/pk/kp.conf && cat ~/pk/kp.conf"
for k in mit ${OURSPW:+ours}; do
    kpw=kpasswd
    [ "$k" = ours ] && kpw=$OURSPW
    check "PK.kpasswd.$k" '^kpasswd rc=1$' run client2 "rm -f \$HOME/pk/kp.trace; KRB5CCNAME=FILE:\$HOME/pk/none.cc KRB5_CONFIG=\$HOME/pk/kp.conf:/etc/krb5.conf KRB5_TRACE=\$HOME/pk/kp.trace $kpw alice < /dev/null > \$HOME/pk/kp.out 2>&1; echo \"kpasswd rc=\$?\"; grep -oE 'Cannot read password while reading password' \$HOME/pk/kp.out; grep -oE 'Setting initial creds service to kadmin/changepw|Preauth module pkinit \\(16\\) \\(real\\) returned: [^ ]+|Decrypted AS reply' \$HOME/pk/kp.trace | sort -u"
    checklast "PK.kpasswd.$k.service" '^Setting initial creds service to kadmin/changepw$'
    checklast "PK.kpasswd.$k.pkinit" '^Preauth module pkinit \(16\) \(real\) returned: 0/Success$'
    checklast "PK.kpasswd.$k.ticket" '^Decrypted AS reply$'
    checklast "PK.kpasswd.$k.newpw" '^Cannot read password while reading password$'
done

section "PK.anchors every pkinit_anchors value, and an anchors file with no certificate (MIT and ours)"
check PK.anchors.conf '^    pkinit_anchors = FILE:.*/cacert\.pem$' run client2 "mkdir -p ~/pk && : > ~/pk/empty.pem && printf '[libdefaults]\n    pkinit_identities = FILE:%s/alice.pem,%s/alice.key\n    pkinit_anchors = FILE:%s/unknown-cacert.pem\n    pkinit_anchors = FILE:%s/cacert.pem\n' $C $C $C $C > ~/pk/an.conf && printf '[libdefaults]\n    pkinit_identities = FILE:%s/alice.pem,%s/alice.key\n    pkinit_anchors = FILE:%s/pk/empty.pem\n' $C $C \$HOME > ~/pk/an0.conf && cat ~/pk/an.conf"
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    check "PK.anchors.second.$k" '^kinit rc=0$' run client2 "kdestroy -c FILE:\$HOME/pk/an.cc 2> /dev/null; KRB5_CONFIG=\$HOME/pk/an.conf:/etc/krb5.conf $kinit -c FILE:\$HOME/pk/an.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/an.cc 2>&1 | grep -E '^Default principal'"
    checklast "PK.anchors.second.$k.tgt" "^Default principal: alice@$R\$"
    check "PK.anchors.empty.$k" '^kinit rc=1$' runin client2 "alice's password ($ALICE)" "kdestroy -c FILE:\$HOME/pk/an.cc 2> /dev/null; rm -f \$HOME/pk/an.trace; KRB5_CONFIG=\$HOME/pk/an0.conf:/etc/krb5.conf KRB5_TRACE=\$HOME/pk/an.trace $kinit -c FILE:\$HOME/pk/an.cc alice > \$HOME/pk/an.out 2>&1; echo \"kinit rc=\$?\"; grep -E 'kinit: ' \$HOME/pk/an.out; grep -oE 'PKINIT client could not verify DH reply|Preauth module pkinit \\(17\\) \\(real\\) returned: -?[0-9]+|Getting AS key' \$HOME/pk/an.trace | sort -u" < <(once "$ALICE")
    checklast "PK.anchors.empty.$k.verify" '^PKINIT client could not verify DH reply$'
    checklast "PK.anchors.empty.$k.module" '^Preauth module pkinit \(17\) \(real\) returned: -1765328314$'
    checklast "PK.anchors.empty.$k.password" '^Getting AS key$'
    observelast "obs.PK.anchors.empty.$k" 'kinit: .*'
done

section "PK.7b pkinit_identity names a file that is not there: MIT's line (MIT and ours)"
pkkdc PK.7b.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:/nonexistent/kdc.pem\n    pkinit_anchors = FILE:$D/cacert.pem\n"
kdcsince PK.7b.kdc 'preauth pkinit'
checklast PK.7b.line "preauth pkinit failed to initialize: PKINIT initialization failed: Cannot read certificate file '/nonexistent/kdc\\.pem': \\(null\\)\$"

section "PK.7c the realm's pkinit_identity wins over [kdcdefaults]' (MIT and ours)"
pkkdc PK.7c.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:/nonexistent/kdc.pem\n    pkinit_anchors = FILE:$D/cacert.pem\n\n[realms]\n    $REALM = {\n        pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    }\n"
kdcsince PK.7c.kdc 'preauth pkinit'
countlast PK.7c.no-line 'preauth pkinit failed' 0
certkinit PK.7c.kinit '^kinit rc=0$'

run client2 "test -r $C/alice-noeku.pem && test -r $C/alice-noeku.key && echo 'alice-noeku present'; true"
if grep -q 'alice-noeku present' "$LAST_OUT"; then
    section "PK.eku alice's certificate without the client EKU: 77, and a TGT with pkinit_eku_checking = none (MIT and ours)"
    pkkdc PK.eku.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n"
    kdcmark PK.eku.as
    certkinit PK.eku.kinit '^kinit rc=1$' alice-noeku
    observelast obs.PK.eku.kinit 'kinit: .*'
    kdcsince PK.eku.as 'verify failure'
    checklast PK.eku.line 'preauth \(pkinit\) verify failure: Inconsistent key purpose$'
    pkkdc PK.eku.none.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n    pkinit_eku_checking = none\n"
    certkinit PK.eku.none '^kinit rc=0$' alice-noeku

    section "PK.dir a DIR: identity holding alice's certificate and her no-EKU one: <EKU>pkinit picks hers (MIT's kinit, then ours)"
    pkkdc PK.dir.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n"
    check PK.dir.setup '^dir: alice-noeku\.crt alice-noeku\.key alice\.crt alice\.key$' run client2 "rm -rf ~/pk/dir && mkdir -p ~/pk/dir && for n in alice alice-noeku; do ln -s $C/\$n.pem ~/pk/dir/\$n.crt && ln -s $C/\$n.key ~/pk/dir/\$n.key || exit 1; done && printf '[libdefaults]\n    pkinit_cert_match = <EKU>pkinit\n' > ~/pk/match.conf && echo \"dir: \$(ls ~/pk/dir | LC_ALL=C sort | paste -sd' ' -)\""
    # dirkinit <check> <kinit> [match]: alice's kinit with the DIR: identity, the <EKU>pkinit profile first when asked;
    # the trace's certificate-matching lines after, kept for the comparison
    dirkinit() {
        local env='' rc=1
        [ -n "${3:-}" ] && env="KRB5_CONFIG=\$HOME/pk/match.conf:/etc/krb5.conf " rc=0
        check "$1" "^kinit rc=$rc\$" run client2 "kdestroy -c FILE:\$HOME/pk/d.cc 2> /dev/null; rm -f \$HOME/pk/d.trace; ${env}KRB5_TRACE=\$HOME/pk/d.trace $2 -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=DIR:\$HOME/pk/dir -c FILE:\$HOME/pk/d.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/d.cc 2>&1 | grep -E '^Default principal'; grep -oE 'PKINIT (client matching rule|client ignoring invalid rule|matched|didn.t match|client checked|no matching certificate|error: There are) .*' \$HOME/pk/d.trace"
        grep -E '^PKINIT ' "$LAST_OUT" > "$STATE/$1.lines"
        if [ -n "${3:-}" ]; then
            checklast "$1.tgt" "^Default principal: alice@$R\$"
            checklast "$1.rule" "^PKINIT client matching rule '<EKU>pkinit' against certificates\$"
            checklast "$1.checked" '^PKINIT client checked 2 certs, found 1 matches$'
        else
            observelast "obs.$1" 'kinit: .*'
            checklast "$1.default" '^PKINIT error: There are 2 certs, but there must be exactly one\.$'
        fi
    }
    for k in mit ${OURS:+ours}; do
        kinit=kinit
        [ "$k" = ours ] && kinit=$OURS
        dirkinit "PK.dir.rule.$k" "$kinit" match
        dirkinit "PK.dir.norule.$k" "$kinit"
    done
    if [ -n "${OURS:-}" ]; then
        rule=$(printf '%q ' "$STATE/PK.dir.rule.mit.lines" "$STATE/PK.dir.rule.ours.lines")
        norule=$(printf '%q ' "$STATE/PK.dir.norule.mit.lines" "$STATE/PK.dir.norule.ours.lines")
        check PK.dir.lines '^matching lines: as MIT.s$' host "diff $rule && diff $norule && echo \"matching lines: as MIT's\""
    fi
else
    note "client2 holds no alice-noeku certificate: the PK.eku and PK.dir cells are not run"
fi

section "PK.fallback an identity that does not load: kinit goes on to the password; PK.twoid a second identity is refused (MIT's kinit, then ours)"
pkkdc PK.fallback.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n"
# fbkinit <check> <kinit> [nopw]: alice's kinit naming a certificate file that is not there, her password on stdin
# (with nopw, none)
fbkinit() {
    local cmd="mkdir -p ~/pk && kdestroy -c FILE:\$HOME/pk/f.cc 2> /dev/null; $2 -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=FILE:/nonexistent -c FILE:\$HOME/pk/f.cc alice"
    if [ -z "${3:-}" ]; then
        check "$1" '^kinit rc=0$' runin client2 "alice's password ($ALICE)" "$cmd > /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/f.cc 2>&1 | grep -E '^Default principal'" < <(once "$ALICE")
        checklast "$1.tgt" "^Default principal: alice@$R\$"
    else
        check "$1" '^kinit rc=1$' run client2 "$cmd < /dev/null 2>&1; echo \"kinit rc=\$?\""
        observelast "obs.$1" 'kinit: .*'
    fi
}
# twoid <check> <kinit>: two X509_user_identity options
twoid() {
    check "$1" '^kinit rc=1$' run client2 "$2 -X X509_user_identity=FILE:$C/alice.pem,$C/alice.key -X X509_user_identity=FILE:/nonexistent -c FILE:\$HOME/pk/t.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\""
    checklast "$1.text" '^kinit: Preauth module pkinit: X509_user_identity can not be given twice$'
    checklast "$1.while" "^ while setting 'X509_user_identity'='FILE:/nonexistent'\$"
}
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    fbkinit "PK.fallback.$k" "$kinit"
    fbkinit "PK.fallback.nopw.$k" "$kinit" nopw
    twoid "PK.twoid.$k" "$kinit"
done

section "PK.rsakdc an RSA KDC identity: alice's certificate kinit gets a TGT (MIT and ours)"
pkkdc PK.rsakdc.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc-rsa.pem,$D/kdc-rsa.key\n    pkinit_anchors = FILE:$D/cacert.pem\n    pkinit_anchors = FILE:$D/rsa-cacert.pem\n"
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    check "PK.rsakdc.$k" '^kinit rc=0$' run client2 "mkdir -p ~/pk && kdestroy -c FILE:\$HOME/pk/k.cc 2> /dev/null; rm -f \$HOME/pk/k.trace; KRB5_TRACE=\$HOME/pk/k.trace $kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_anchors=FILE:$C/rsa-cacert.pem -X X509_user_identity=FILE:$C/alice.pem,$C/alice.key -c FILE:\$HOME/pk/k.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/k.cc 2>&1 | grep -E '^Default principal'; grep -oE 'PKINIT client (verified|could not verify) DH reply' \$HOME/pk/k.trace"
    checklast "PK.rsakdc.$k.tgt" "^Default principal: alice@$R\$"
    checklast "PK.rsakdc.$k.verified" '^PKINIT client verified DH reply$'
done

section "PK.rsabig an 8192-bit RSA KDC key and alice's 3-prime RSA key, made for the cell: a TGT, timed (MIT and ours)"
check PK.rsabig.make "^rsa certs in $BIG\$" runin kdc "scripts/lib/pkinit-rsa-certs.sh" "sudo sh -s -- $BIG $REALM alice 8192 3" < "$HERE/../../../scripts/lib/pkinit-rsa-certs.sh"
check PK.rsabig.copy '^client2: 3 files$' host "$LABQ ssh kdc -- 'sudo tar -C $BIG -cf - ca.pem client.pem client.key' | $LABQ ssh client2 -- 'install -d -m 0700 ~/pk/big && tar -C ~/pk/big -xf - && echo \"client2: \$(ls ~/pk/big | wc -l) files\"'"
pkkdc PK.rsabig.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$BIG/kdc.pem,$BIG/kdc.key\n    pkinit_anchors = FILE:$BIG/ca.pem\n"
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    check "PK.rsabig.$k" '^kinit rc=0 ms=[0-9]+$' run client2 "kdestroy -c FILE:\$HOME/pk/b.cc 2> /dev/null; t=\$(date +%s%N); $kinit -X X509_anchors=FILE:\$HOME/pk/big/ca.pem -X X509_user_identity=FILE:\$HOME/pk/big/client.pem,\$HOME/pk/big/client.key -c FILE:\$HOME/pk/b.cc alice < /dev/null 2>&1; echo \"kinit rc=\$? ms=\$(( (\$(date +%s%N) - t) / 1000000 ))\"; klist -c FILE:\$HOME/pk/b.cc 2>&1 | grep -E '^Default principal'"
    checklast "PK.rsabig.$k.tgt" "^Default principal: alice@$R\$"
    observelast "obs.PK.rsabig.$k.ms" 'ms=[0-9]+'
done

section "PK.ec224, PK.ec384, PK.ec521, PK.k256 the KDC's and alice's keys on P-224, then P-384, P-521 and secp256k1, made for the cells: a TGT (MIT and ours)"
for curve in P-224 P-384 P-521 secp256k1; do
    n=ec${curve#P-}
    [ "$curve" = secp256k1 ] && n=k256
    check "PK.$n.make" "^ec certs in $EC/$n\$" runin kdc "scripts/lib/pkinit-ec-certs.sh" "sudo sh -s -- $EC/$n $REALM alice $curve" < "$HERE/../../../scripts/lib/pkinit-ec-certs.sh"
    check "PK.$n.copy" '^client2: 3 files$' host "$LABQ ssh kdc -- 'sudo tar -C $EC/$n -cf - ca.pem client.pem client.key' | $LABQ ssh client2 -- 'install -d -m 0700 ~/pk/$n && tar -C ~/pk/$n -xf - && echo \"client2: \$(ls ~/pk/$n | wc -l) files\"'"
    pkkdc "PK.$n.kdc" "\n[kdcdefaults]\n    pkinit_identity = FILE:$EC/$n/kdc.pem,$EC/$n/kdc.key\n    pkinit_anchors = FILE:$EC/$n/ca.pem\n"
    for k in mit ${OURS:+ours}; do
        kinit=kinit
        [ "$k" = ours ] && kinit=$OURS
        check "PK.$n.$k" '^kinit rc=0$' run client2 "kdestroy -c FILE:\$HOME/pk/e.cc 2> /dev/null; $kinit -X X509_anchors=FILE:\$HOME/pk/$n/ca.pem -X X509_user_identity=FILE:\$HOME/pk/$n/client.pem,\$HOME/pk/$n/client.key -c FILE:\$HOME/pk/e.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/e.cc 2>&1 | grep -E '^Default principal'"
        checklast "PK.$n.$k.tgt" "^Default principal: alice@$R\$"
    done
done

section "PK.dh the KDC's pkinit_dh_min_bits = 4096: kinit's 2048-bit DH gets 65 and the KDC's groups, and kinit tries again with P-384 for a TGT (MIT and ours)"
pkkdc PK.dh.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n\n[realms]\n    $REALM = {\n        pkinit_dh_min_bits = 4096\n    }\n"
check PK.dh.conf '^    pkinit_dh_min_bits = 2048$' run client2 "mkdir -p ~/pk && printf '[libdefaults]\\n    pkinit_dh_min_bits = 2048\\n' > ~/pk/dh.conf && cat ~/pk/dh.conf"
for k in mit ${OURS:+ours}; do
    kinit=kinit
    [ "$k" = ours ] && kinit=$OURS
    check "PK.dh.$k" '^kinit rc=0$' run client2 "kdestroy -c FILE:\$HOME/pk/dh.cc 2> /dev/null; rm -f \$HOME/pk/dh.trace; KRB5_CONFIG=\$HOME/pk/dh.conf:/etc/krb5.conf KRB5_TRACE=\$HOME/pk/dh.trace $kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=FILE:$C/alice.pem,$C/alice.key -c FILE:\$HOME/pk/dh.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/dh.cc 2>&1 | grep -E '^Default principal'; grep -oE 'PKINIT using [^ ]+( DH)? key exchange group|Key parameters not accepted|Preauth tryagain input types \\(16\\): .*|PKINIT accepting KDC key exchange group preference .*|PKINIT client trying again with KDC-provided parameters|Preauth module pkinit \\(16\\) tryagain returned: .*' \$HOME/pk/dh.trace"
    checklast "PK.dh.$k.tgt" "^Default principal: alice@$R\$"
    checklast "PK.dh.$k.first" '^PKINIT using 2048-bit DH key exchange group$'
    checklast "PK.dh.$k.refused" '^Key parameters not accepted$'
    checklast "PK.dh.$k.input" '^Preauth tryagain input types \(16\): 109, PA-FX-COOKIE \(133\)$'
    checklast "PK.dh.$k.chosen" '^PKINIT accepting KDC key exchange group preference P-384$'
    checklast "PK.dh.$k.again" '^PKINIT client trying again with KDC-provided parameters$'
    checklast "PK.dh.$k.second" '^PKINIT using P-384 key exchange group$'
    checklast "PK.dh.$k.tryagain" '^Preauth module pkinit \(16\) tryagain returned: 0/Success$'
done

section "PK.dh1024 kinit at pkinit_dh_min_bits = 1024: the KDC's floor of 1024 takes its 1024-bit DH, and the default 2048 refuses it with 65, then P-256 (MIT and ours)"
check PK.dh1024.conf '^    pkinit_dh_min_bits = 1024$' run client2 "mkdir -p ~/pk && printf '[libdefaults]\\n    pkinit_dh_min_bits = 1024\\n' > ~/pk/dh1024.conf && cat ~/pk/dh1024.conf"
for floor in 1024 2048; do
    realm="\n[realms]\n    $REALM = {\n        pkinit_dh_min_bits = 1024\n    }\n"
    [ "$floor" = 2048 ] && realm=
    pkkdc "PK.dh1024.kdc$floor.kdc" "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n$realm"
    for k in mit ${OURS:+ours}; do
        kinit=kinit
        [ "$k" = ours ] && kinit=$OURS
        n=PK.dh1024.kdc$floor.$k
        check "$n" '^kinit rc=0$' run client2 "kdestroy -c FILE:\$HOME/pk/dh.cc 2> /dev/null; rm -f \$HOME/pk/dh.trace; KRB5_CONFIG=\$HOME/pk/dh1024.conf:/etc/krb5.conf KRB5_TRACE=\$HOME/pk/dh.trace $kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=FILE:$C/alice.pem,$C/alice.key -c FILE:\$HOME/pk/dh.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/dh.cc 2>&1 | grep -E '^Default principal'; grep -oE 'PKINIT using [^ ]+( DH)? key exchange group|Key parameters not accepted|PKINIT accepting KDC key exchange group preference .*' \$HOME/pk/dh.trace"
        checklast "$n.tgt" "^Default principal: alice@$R\$"
        checklast "$n.first" '^PKINIT using 1024-bit DH key exchange group$'
        if [ "$floor" = 1024 ]; then
            countlast "$n.taken" 'Key parameters not accepted' 0
        else
            checklast "$n.refused" '^Key parameters not accepted$'
            checklast "$n.chosen" '^PKINIT accepting KDC key exchange group preference P-256$'
            checklast "$n.second" '^PKINIT using P-256 key exchange group$'
        fi
    done
done

section "kdc.conf restored"
check kdc.conf.restored '^restored, krb5kdc active$' run kdc "sudo mv $KC.pk $KC && sudo systemctl restart krb5kdc && systemctl is-active krb5kdc > /dev/null && ! sudo grep -qE '^[[:space:]]*pkinit_identity' $KC && echo 'restored, krb5kdc active'"
if [ "$PREAUTH" = 1 ]; then
    check restore.alice.preauth "^Principal \"alice@$R\" modified\\.\$" run kdc "sudo kadmin.local -q 'modprinc -requires_preauth alice' 2>&1"
    PREAUTH=0
fi
finish
