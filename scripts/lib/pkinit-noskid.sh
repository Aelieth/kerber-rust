#!/bin/sh
# CA with no SKID, and a client cert whose AKID is a raw key id. Prints the dir.
# shellcheck shell=sh
set -eu
D=${1:-/tmp/noskid}
mkdir -p "$D"
cd "$D"
cat > ext.cnf << 'EOF'
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:KERBER.TEST
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:KERBER.TEST
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=DER:30:06:80:04:DE:AD:BE:EF
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name
[princ_name]
realm=EXP:0,GeneralString:KERBER.TEST
principal_name=EXP:1,SEQUENCE:principal_seq
[principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:principals
[principals]
princ1=GeneralString:user
EOF
cat > ca.cnf << 'EOF'
[req]
distinguished_name = dn
x509_extensions = ca_ext
prompt = no
[dn]
CN = No SKID CA
[ca_ext]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=none
authorityKeyIdentifier=none
EOF
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -key ca.key -out ca.pem -days 2 -config ca.cnf 2>/dev/null
openssl genrsa -out kdc.key 2048 2>/dev/null
openssl req -new -key kdc.key -out kdc.req -subj "/CN=KERBER.TEST KDC" 2>/dev/null
openssl x509 -req -in kdc.req -CA ca.pem -CAkey ca.key -CAcreateserial -out kdc.pem -days 2 \
    -extfile ext.cnf -extensions kdc_cert 2>/dev/null
openssl genrsa -traditional -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.req -subj "/CN=user" 2>/dev/null
openssl x509 -req -in client.req -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt -days 2 \
    -extfile ext.cnf -extensions client_cert 2>/dev/null
cat client.crt client.key > client.pem
cat kdc.pem kdc.key > kdc-id.pem
openssl x509 -in ca.pem -noout -text | grep -q 'Subject Key Identifier' && exit 1
openssl x509 -in client.crt -noout -text | grep -q 'DE:AD:BE:EF'
echo "noskid certs in $D"
