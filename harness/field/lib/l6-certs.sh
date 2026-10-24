# harness/field/lib/l6-certs.sh <dir> <realm>: the lab's PKINIT certificates (L6), made on kdc as root through
# `sh -s --`. In <dir>, the KDC's: cacert.pem (a P-256 CA), kdc.pem and kdc.key (P-256, id-pkinit-san
# krbtgt/<realm>@<realm>, EKU id-pkinit-KPKdc), and rsa-cacert.pem, kdc-rsa.pem and kdc-rsa.key (the same on RSA 2048).
# In <dir>/client2, client2's, for the caller to pipe there: both CAs, unknown-cacert.pem (a P-256 CA the KDC does
# not trust) and alice's identities, each a .pem and a .key: alice (P-256, id-pkinit-san alice@<realm>, EKU
# id-pkinit-KPClientAuth), alice-wrongsan (bob's SAN), alice-noeku (no EKU), alice-unknownca (from
# unknown-cacert.pem) and alice-rsa (RSA 2048, from rsa-cacert.pem). A set that is all there and verifies is kept;
# otherwise the whole set is made anew, and no CA key is kept. Keys are unencrypted PKCS#8 and never printed.
# Prints "l6 certs in <dir>: made" (or "kept").
# shellcheck shell=sh
set -eu
D=$1 REALM=$2
command -v openssl > /dev/null 2>&1 || { echo "l6-certs.sh: openssl is not installed" >&2; exit 1; }
umask 077

# pair <ca> <cert> <key>: <cert> verifies against <ca> alone, and <key> is its key.
pair() {
    openssl verify -CAfile "$1" "$2" > /dev/null 2>&1 &&
        [ "$(openssl x509 -in "$2" -noout -pubkey 2> /dev/null)" = "$(openssl pkey -in "$3" -pubout 2> /dev/null)" ]
}

# is <cert> <ERE>: <cert>'s text has a line matching <ERE> (its key's curve or algorithm).
is() { openssl x509 -in "$1" -noout -text 2> /dev/null | grep -qE "$2"; }

# whole: every file there; client2's CAs the KDC's; each identity from its CA, and alice-unknownca not from the KDC's.
whole() (
    cd "$D/client2" 2> /dev/null || exit 1
    cmp -s cacert.pem ../cacert.pem && cmp -s rsa-cacert.pem ../rsa-cacert.pem &&
        pair cacert.pem ../kdc.pem ../kdc.key && pair rsa-cacert.pem ../kdc-rsa.pem ../kdc-rsa.key &&
        pair cacert.pem alice.pem alice.key && pair cacert.pem alice-wrongsan.pem alice-wrongsan.key &&
        pair cacert.pem alice-noeku.pem alice-noeku.key && pair rsa-cacert.pem alice-rsa.pem alice-rsa.key &&
        pair unknown-cacert.pem alice-unknownca.pem alice-unknownca.key &&
        ! openssl verify -CAfile cacert.pem alice-unknownca.pem > /dev/null 2>&1 &&
        is ../kdc.pem 'ASN1 OID: prime256v1' && is alice.pem 'ASN1 OID: prime256v1' &&
        is ../kdc-rsa.pem 'Public Key Algorithm: rsaEncryption' && is alice-rsa.pem 'Public Key Algorithm: rsaEncryption'
)

ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2> /dev/null; }
rsa() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2> /dev/null; }
# ca <key> <cert> <name>: a self-signed CA.
ca() { openssl req -new -x509 -key "$1" -out "$2" -subj "/CN=$3" -days 3650; }
# leaf <key> <cert> <name> <ca> <ca key> <section>: a certificate from <ca> with ext.cnf's <section>.
leaf() {
    openssl req -new -key "$1" -out req.pem -subj "/CN=$3"
    openssl x509 -req -in req.pem -CA "$4" -CAkey "$5" -CAcreateserial -out "$2" -days 3650 \
        -extfile ext.cnf -extensions "$6" 2> /dev/null
}

# mint: the whole set anew, in a scratch directory under <dir> (so the files keep its SELinux type), then in place.
mint() {
    W=$D/.l6-mint
    rm -rf "$W" "$D/client2"
    for f in cacert.pem kdc.pem kdc.key rsa-cacert.pem kdc-rsa.pem kdc-rsa.key; do rm -f "$D/$f"; done
    mkdir -p "$W"
    cd "$W"
    cat > ext.cnf <<EOF
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_name
[kdc_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:kdc_seq
[kdc_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_strings
[kdc_strings]
princ1=GeneralString:krbtgt
princ2=GeneralString:$REALM
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:alice_name
[noeku_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:alice_name
[wrongsan_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:bob_name
[alice_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:alice_seq
[alice_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:alice_strings
[alice_strings]
princ1=GeneralString:alice
[bob_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:bob_seq
[bob_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:bob_strings
[bob_strings]
princ1=GeneralString:bob
EOF
    ec ca.key
    ca ca.key cacert.pem "$REALM PKINIT CA"
    rsa rsa-ca.key
    ca rsa-ca.key rsa-cacert.pem "$REALM PKINIT RSA CA"
    ec unknown-ca.key
    ca unknown-ca.key unknown-cacert.pem "Unknown PKINIT CA"
    ec kdc.key
    leaf kdc.key kdc.pem "$REALM KDC" cacert.pem ca.key kdc_cert
    rsa kdc-rsa.key
    leaf kdc-rsa.key kdc-rsa.pem "$REALM KDC RSA" rsa-cacert.pem rsa-ca.key kdc_cert
    for n in alice alice-wrongsan alice-noeku alice-unknownca; do ec "$n.key"; done
    leaf alice.key alice.pem alice cacert.pem ca.key client_cert
    leaf alice-wrongsan.key alice-wrongsan.pem alice cacert.pem ca.key wrongsan_cert
    leaf alice-noeku.key alice-noeku.pem alice cacert.pem ca.key noeku_cert
    leaf alice-unknownca.key alice-unknownca.pem alice unknown-cacert.pem unknown-ca.key client_cert
    rsa alice-rsa.key
    leaf alice-rsa.key alice-rsa.pem alice rsa-cacert.pem rsa-ca.key client_cert
    mkdir "$D/client2"
    cp cacert.pem rsa-cacert.pem unknown-cacert.pem alice*.pem alice*.key "$D/client2/"
    mv cacert.pem kdc.pem kdc.key rsa-cacert.pem kdc-rsa.pem kdc-rsa.key "$D/"
    cd "$D"
    rm -rf "$W"
    chmod 0644 ./*.pem client2/*.pem
}

mkdir -p "$D"
if whole; then
    state=kept
else
    mint
    whole || { echo "l6-certs.sh: the set made in $D does not verify" >&2; exit 1; }
    state=made
fi
echo "l6 certs in $D: $state"
