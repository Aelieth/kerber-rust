# scripts/lib/pkinit-kdc-certs.sh <dir> <realm> <client> <host>: as pkinit-ec-certs.sh on P-256, with four KDC
# certificates that MIT's verify_kdc_san and verify_kdc_eku tell apart: othersan (id-pkinit-san krbtgt/OTHER.TEST),
# dns (dNSName <host>, EKU id-pkinit-KPKdc), dns_serverauth (EKU serverAuth) and dns_noku (no digitalSignature KU);
# prints "kdc certs in <dir>".
# shellcheck shell=sh
set -eu
D=$1 REALM=$2 CLIENT=$3 HOST=$4
mkdir -p "$D"
cd "$D"
cat > ext.cnf <<EOF
[othersan]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:other_name
[dns]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectAltName=DNS:$HOST
[dns_serverauth]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HOST
[dns_noku]
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectAltName=DNS:$HOST
[client]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:client_name
[other_name]
realm=EXP:0,GeneralString:OTHER.TEST
principal_name=EXP:1,SEQUENCE:other_seq
[other_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:other_parts
[other_parts]
p1=GeneralString:krbtgt
p2=GeneralString:OTHER.TEST
[client_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:client_seq
[client_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:client_parts
[client_parts]
p1=GeneralString:$CLIENT
EOF
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2> /dev/null; }
key ca.key
openssl req -new -x509 -key ca.key -out ca.pem -subj "/CN=KDC certificate test CA" -days 2
for v in othersan dns dns_serverauth dns_noku client; do
    key "$v.key"
    openssl req -new -key "$v.key" -out "$v.req" -subj "/CN=$v"
    openssl x509 -req -in "$v.req" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$v.pem" -days 2 \
        -extfile ext.cnf -extensions "$v" 2> /dev/null
done
openssl x509 -in dns_serverauth.pem -noout -ext extendedKeyUsage | grep -q 'TLS Web Server Authentication'
echo "kdc certs in $D"
