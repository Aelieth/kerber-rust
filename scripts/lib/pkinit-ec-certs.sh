# scripts/lib/pkinit-ec-certs.sh <dir> <realm> <client> <curve>: as pkinit-rsa-certs.sh, with EC keys on <curve> (P-224,
# P-384, P-521 or secp256k1, OpenSSL's names) for the CA, the KDC and the client, each in PKCS#8; prints "ec certs in <dir>".
# shellcheck shell=sh
set -eu
D=$1 REALM=$2 CLIENT=$3 CURVE=$4
mkdir -p "$D"
cd "$D"
cat > ext.cnf <<EOF
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:$REALM
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name
[princ_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:principal_seq
[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals
[principals]
princ1=GeneralString:$CLIENT
EOF
key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVE" -out "$1" 2> /dev/null; }
key ca.key
openssl req -new -x509 -key ca.key -out ca.pem -subj "/CN=EC $CURVE test CA" -days 2
key kdc.key
openssl req -new -key kdc.key -out kdc.req -subj "/CN=$REALM KDC"
openssl x509 -req -in kdc.req -CA ca.pem -CAkey ca.key -CAcreateserial -out kdc.pem -days 2 \
    -extfile ext.cnf -extensions kdc_cert 2> /dev/null
key client.key
openssl req -new -key client.key -out client.req -subj "/CN=$CLIENT"
openssl x509 -req -in client.req -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 2 \
    -extfile ext.cnf -extensions client_cert 2> /dev/null
openssl x509 -in client.pem -noout -text | grep -qE "(NIST CURVE|ASN1 OID): $CURVE$"
echo "ec certs in $D"
