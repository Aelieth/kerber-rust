# scripts/lib/pkinit-rsa-certs.sh <dir> <realm> <client> [<kdc bits> [<client primes>]]: run in a gate's container or on
# a lab VM through `sh -s --`. An RSA 2048 CA and, issued by it as MIT's doc/admin/pkinit.rst makes them, a KDC
# certificate for krbtgt/<realm> (key in PKCS#8, 2048 bits unless given) and a client certificate for <client>@<realm>
# (a 2048-bit key in PKCS#1, of two primes unless given); prints "rsa certs in <dir>".
# shellcheck shell=sh
set -eu
D=$1 REALM=$2 CLIENT=$3 KDCBITS=${4:-2048} PRIMES=${5:-2}
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
openssl genrsa -out ca.key 2048 2> /dev/null
openssl req -new -x509 -key ca.key -out ca.pem -subj "/CN=RSA test CA" -days 2
openssl genrsa -out kdc.key "$KDCBITS" 2> /dev/null
openssl req -new -key kdc.key -out kdc.req -subj "/CN=$REALM KDC"
openssl x509 -req -in kdc.req -CA ca.pem -CAkey ca.key -CAcreateserial -out kdc.pem -days 2 \
    -extfile ext.cnf -extensions kdc_cert 2> /dev/null
openssl genrsa -traditional -primes "$PRIMES" -out client.key 2048 2> /dev/null
openssl req -new -key client.key -out client.req -subj "/CN=$CLIENT"
openssl x509 -req -in client.req -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 2 \
    -extfile ext.cnf -extensions client_cert 2> /dev/null
grep -q 'BEGIN RSA PRIVATE KEY' client.key
grep -q 'BEGIN PRIVATE KEY' kdc.key
echo "rsa certs in $D"
