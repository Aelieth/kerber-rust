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
#   PK.rsacert: client2's alice-rsa.pem (an RSA 2048 key, issued by rsa-cacert.pem, which kdc's pkinit_anchors and
#          client2 both trust) gets a TGT;
#   obs.PK.dbmatch (INFO): with alice's pkinit_cert_match set to "<KU>digitalSignature", which alice.pem matches,
#          MIT issues a TGT and kerber-rust refuses with 66 (its matcher is not ported; documented);
#   PK.6:  kinit -n with client2's anchors: a WELLKNOWN/ANONYMOUS ticket (the principal is made for the cell);
#   PK.7b: pkinit_identity names a file that is not there: the line ends "Cannot read certificate file '<file>':
#          (null)", OpenSSL 3 giving no reason for a system error;
#   PK.7c: the realm's pkinit_identity wins over [kdcdefaults]' missing one: alice's certificate kinit gets a TGT;
#   PK.eku: when client2 also holds alice-noeku.pem and alice-noeku.key (alice's SAN, no extended key usage), its
#          kinit is refused (77, "Inconsistent key purpose" in the KDC's verify-failure line), and with
#          pkinit_eku_checking = none it gets a TGT;
#   obs.PK.rsa: the RSA KDC identity's startup line (INFO): MIT serves with it; kerber-rust's KDC identity is P-256
#          only, so its line is the documented "Cannot use key file ...: only P-256 EC keys are supported".
# Graded on both legs, MIT's first.
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
ANON=0
PREAUTH=0
DBMATCH=0
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "[ -e $KC.pk ] && sudo mv $KC.pk $KC && sudo systemctl restart krb5kdc; [ $ANON = 1 ] && sudo kadmin.local -q 'delprinc -force WELLKNOWN/ANONYMOUS'; [ $PREAUTH = 1 ] && sudo kadmin.local -q 'modprinc -requires_preauth alice'; [ $DBMATCH = 1 ] && sudo kadmin.local -q 'delstr alice pkinit_cert_match'; true" < /dev/null > /dev/null 2>&1
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

section "pkinit --leg $LEG: PKINIT as the $LEG KDC serves it from kdc.conf, MIT kinit from client2"
kdcis
if [ -n "${PK_SNAPSHOT_CLIENT2:-}" ]; then
    check reset.client2 rc host "$LABQ reset client2 $PK_SNAPSHOT_CLIENT2"
    waitsync client2
fi
check l6.kdc '^kdc: krb5-pkinit, CA and KDC P-256, RSA KDC identity$' run kdc "rpm -q krb5-pkinit > /dev/null && for f in cacert.pem kdc.pem kdc-rsa.pem rsa-cacert.pem; do sudo openssl x509 -in $D/\$f -noout -subject; done && sudo test -r $D/kdc.key && sudo test -r $D/kdc-rsa.key && sudo openssl x509 -in $D/kdc.pem -noout -text | grep -qE 'ASN1 OID: prime256v1' && sudo openssl x509 -in $D/kdc-rsa.pem -noout -text | grep -qE 'Public Key Algorithm: rsaEncryption' && echo 'kdc: krb5-pkinit, CA and KDC P-256, RSA KDC identity'"
check l6.client2 '^client2: krb5-pkinit, alice P-256$' run client2 "rpm -q krb5-pkinit > /dev/null && for f in alice alice-wrongsan alice-unknownca unknown-cacert alice-rsa rsa-cacert; do openssl x509 -in $C/\$f.pem -noout -subject || exit 1; done && test -r $C/alice.key && test -r $C/alice-wrongsan.key && test -r $C/alice-unknownca.key && test -r $C/alice-rsa.key && openssl x509 -in $C/alice.pem -noout -text | grep -qE 'ASN1 OID: prime256v1' && echo 'client2: krb5-pkinit, alice P-256'"
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

section "PK.rsacert alice's RSA certificate from the RSA CA both trust: a TGT (MIT and ours)"
pkkdc PK.rsacert.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n    pkinit_anchors = FILE:$D/rsa-cacert.pem\n"
check PK.rsacert.kinit '^kinit rc=0$' run client2 "mkdir -p ~/pk && kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_anchors=FILE:$C/rsa-cacert.pem -X X509_user_identity=FILE:$C/alice-rsa.pem,$C/alice-rsa.key -c FILE:\$HOME/pk/r.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/r.cc 2>&1 | grep -E '^Default principal'"
checklast PK.rsacert.tgt "^Default principal: alice@$R\$"
pkkdc PK.rsacert.back "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc.pem,$D/kdc.key\n    pkinit_anchors = FILE:$D/cacert.pem\n"

section "obs.PK.dbmatch alice's pkinit_cert_match: MIT matches it, kerber-rust refuses with 66 (INFO)"
run kdc "sudo kadmin.local -q 'setstr alice pkinit_cert_match \"<KU>digitalSignature\"' 2>&1"
DBMATCH=1
kdcmark PK.dbmatch.as
run client2 "mkdir -p ~/pk && kinit -X X509_anchors=FILE:$C/cacert.pem -X X509_user_identity=FILE:$C/alice.pem,$C/alice.key -c FILE:\$HOME/pk/d.cc alice < /dev/null 2>&1; echo \"kinit rc=\$?\""
observelast obs.PK.dbmatch.kinit 'kinit rc=[0-9]+'
kdcsince PK.dbmatch.as 'verify failure'
observelast obs.PK.dbmatch.line 'verify failure: .*'
run kdc "sudo kadmin.local -q 'delstr alice pkinit_cert_match' 2>&1"
DBMATCH=0

section "PK.6 kinit -n with client2's anchors: an anonymous ticket (MIT and ours)"
check PK.6.kinit '^Default principal: WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS$' run client2 "mkdir -p ~/pk && kinit -n -X X509_anchors=FILE:$C/cacert.pem -c FILE:\$HOME/pk/n.cc < /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/pk/n.cc 2>&1 | grep -E '^Default principal|krbtgt/'"
checklast PK.6.rc '^kinit rc=0$'

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
else
    note "client2 holds no alice-noeku certificate: the PK.eku cells are not run"
fi

section "obs.PK.rsa an RSA KDC identity: MIT serves with it; kerber-rust's KDC identity is P-256 only (INFO)"
pkkdc PK.rsa.kdc "\n[kdcdefaults]\n    pkinit_identity = FILE:$D/kdc-rsa.pem,$D/kdc-rsa.key\n    pkinit_anchors = FILE:$D/cacert.pem\n    pkinit_anchors = FILE:$D/rsa-cacert.pem\n"
kdcsince PK.rsa.kdc 'preauth pkinit'
observelast obs.PK.rsa.line 'preauth pkinit .*'

section "kdc.conf restored"
check kdc.conf.restored '^restored, krb5kdc active$' run kdc "sudo mv $KC.pk $KC && sudo systemctl restart krb5kdc && systemctl is-active krb5kdc > /dev/null && ! sudo grep -qE '^[[:space:]]*pkinit_identity' $KC && echo 'restored, krb5kdc active'"
if [ "$PREAUTH" = 1 ]; then
    check restore.alice.preauth "^Principal \"alice@$R\" modified\\.\$" run kdc "sudo kadmin.local -q 'modprinc -requires_preauth alice' 2>&1"
    PREAUTH=0
fi
finish
