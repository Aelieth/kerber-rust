#!/usr/bin/env bash
# MIT 1.22.2 kadmin against Rust kadmind (GSS-RPC 749):
# addprinc, cpw, getprinc, listprincs, modprinc, cpw -randkey, ktadd,
# ktadd -norandkey, purgekeys, setstr/getstrs, delprinc.
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-gate"
NAME_MIT="kerber-rust-kadmin-mit"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kadmin-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kadmin-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *e
extract/admin@KERBER.TEST *e
EOF'

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadmin-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kadmin
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'
echo "==== MIT kadmin addprinc extra ===="
ADD="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra' 2>&1 || true)"
echo "$ADD"
echo "==== kadmind log ===="
docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true
echo "==== kdc log (tail) ===="
docker exec "$NAME" tail -20 /tmp/kdc.log 2>/dev/null || true
echo "==== kinit extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-secret\n" | kinit extra@KERBER.TEST' || true
echo "==== kdc log after extra kinit ===="
docker exec "$NAME" grep -E 'reload store|persist |CLIENT|saved store|error' /tmp/kdc.log | tail -30 || true
docker exec "$NAME" ls -l /tmp/principal /tmp/stash 2>/dev/null || true
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin cpw extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw extra-rotated extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin getprinc extra ===="
GET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$GET"
echo "$GET" | grep -q 'Principal: extra@KERBER.TEST'
echo "$GET" | grep -q 'Number of keys: 4'
echo "$GET" | grep -qE 'Key: vno 2,'
PWDCHG="$(echo "$GET" | grep '^Last password change:')"
echo "$PWDCHG"
echo "$PWDCHG" | grep -v '\[never\]'
MODLINE="$(echo "$GET" | grep '^Last modified:')"
echo "$MODLINE"
echo "$MODLINE" | grep -v '1970'

echo "==== MIT kadmin cpw -keepold ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q \
    'addprinc -pw keep-secret keepoldu'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q \
    'cpw -keepold -pw keep-rotated keepoldu'
GETK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc keepoldu' 2>&1 || true)"
echo "$GETK"
echo "$GETK" | grep -qE 'Key: vno 1,'
echo "$GETK" | grep -qE 'Key: vno 2,'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "keep-rotated\n" | kinit keepoldu@KERBER.TEST'

echo "==== MIT kadmin setstr/getstrs extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'setstr extra note hello-g3d'
STRS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getstrs extra' 2>&1 || true)"
echo "$STRS"
echo "$STRS" | grep -q 'note: hello-g3d'

echo "==== MIT kadmin lockdown_keys ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw lock-secret lockee'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc +lockdown_keys lockee'
GETL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc lockee' 2>&1 || true)"
echo "$GETL"
echo "$GETL" | grep -qi LOCKDOWN
CPWL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw lock-rotated lockee' 2>&1 || true)"
echo "$CPWL"
if echo "$CPWL" | grep -qi 'changed'; then
    echo "lockdown cpw rewrote keys: $CPWL" >&2
    exit 1
fi
echo "$CPWL" | grep -F 'change-password'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "lock-secret\n" | kinit lockee@KERBER.TEST'
KTL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/lockee-norand.keytab lockee' 2>&1 || true)"
echo "$KTL"
if echo "$KTL" | grep -qi 'added to keytab'; then
    echo "lockdown ktadd -norandkey leaked keys: $KTL" >&2
    exit 1
fi
CHR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/lockee.keytab lockee' 2>&1 || true)"
echo "$CHR"
if docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/lockee.keytab lockee@KERBER.TEST 2>"$SCRATCH/lockee-kinit.err"; then
    echo "lockdown ktadd leaked keys for kinit -k" >&2
    exit 1
fi

echo "==== MIT kadmin purgekeys ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addpol -history 2 g3bhist'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw purge-secret -policy g3bhist purgee'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw purge-rotated purgee'
GETP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc purgee' 2>&1 || true)"
echo "$GETP"
echo "$GETP" | grep -qE 'Key: vno 2,'
if echo "$GETP" | grep -qE 'Key: vno 1,'; then
    echo "getprinc listed password-history kvno 1: $GETP" >&2
    exit 1
fi
PURGE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'purgekeys purgee' 2>&1 || true)"
echo "$PURGE"
echo "$PURGE" | grep -qi purged
if echo "$PURGE" | grep -qiE 'while purging|Operation failed|unknown procedure'; then
    echo "purgekeys failed: $PURGE" >&2
    exit 1
fi
GETP2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc purgee' 2>&1 || true)"
echo "$GETP2"
echo "$GETP2" | grep -qE 'Key: vno 2,'
if echo "$GETP2" | grep -qE 'Key: vno 1,'; then
    echo "purgekeys left kvno 1: $GETP2" >&2
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "purge-rotated\n" | kinit purgee@KERBER.TEST'
KLISTP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTP"
echo "$KLISTP" | grep -q 'purgee@KERBER.TEST'

echo "==== MIT kadmin listprincs ===="
LIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs' 2>&1 || true)"
echo "$LIST"
echo "$LIST" | grep -q 'extra@KERBER.TEST'
echo "$LIST" | grep -q 'user@KERBER.TEST'

echo "==== MIT kadmin modprinc +requires_preauth extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc +requires_preauth extra'
GET2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$GET2"
echo "$GET2" | grep -q 'REQUIRES_PRE_AUTH'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'
KLIST3="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST3"
echo "$KLIST3" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin cpw -randkey extra + ktadd + kinit -k ===="
PWD_BEFORE="$(echo "$GET2" | grep '^Last password change:')"
MOD_BEFORE="$(echo "$GET2" | grep '^Last modified:')"
sleep 1
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -randkey extra'
GETR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$GETR"
PWDR="$(echo "$GETR" | grep '^Last password change:')"
MODR="$(echo "$GETR" | grep '^Last modified:')"
echo "$PWDR"
echo "$MODR"
echo "$PWDR" | grep -v '\[never\]'
echo "$MODR" | grep -v '1970'
if [ "$PWDR" = "$PWD_BEFORE" ]; then
    echo "Last password change did not move after cpw -randkey: $PWDR" >&2
    exit 1
fi
if [ "$MODR" = "$MOD_BEFORE" ]; then
    echo "Last modified did not move after cpw -randkey: $MODR" >&2
    exit 1
fi
if docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'; then
    echo "old password still worked after chrand" >&2
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/extra.keytab extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/extra.keytab extra@KERBER.TEST
KLIST4="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST4"
echo "$KLIST4" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin ktadd -norandkey extra + kinit -k ===="
KTN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/extra-norand.keytab extra' 2>&1 || true)"
echo "$KTN"
echo "$KTN" | grep -qi 'added to keytab'
if echo "$KTN" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "ktadd -norandkey failed: $KTN" >&2
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/extra-norand.keytab extra@KERBER.TEST
KLISTN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTN"
echo "$KLISTN" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin renprinc (randkey; default-salt password kinit is not required) ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -randkey renamefrom'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'renprinc -force renamefrom renameto'
RENGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc renameto' 2>&1 || true)"
echo "$RENGET"
echo "$RENGET" | grep -q 'Principal: renameto@KERBER.TEST'
RENOLD="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc renamefrom' 2>&1 || true)"
echo "$RENOLD"
echo "$RENOLD" | grep -qiE 'does not exist|not found|UNK_PRINC'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/renameto.keytab renameto'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/renameto.keytab renameto@KERBER.TEST
KLISTR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTR"
echo "$KLISTR" | grep -q 'renameto@KERBER.TEST'

echo "==== getprinc krbtgt LOCKDOWN_KEYS ===="
TGTGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$TGTGET"
echo "$TGTGET" | grep -F 'LOCKDOWN_KEYS'

echo "==== ktadd -norandkey krbtgt is extract-keys ===="
KTGT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/krbtgt.keytab krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$KTGT"
echo "$KTGT" | grep -F 'extract-keys'
if echo "$KTGT" | grep -qi 'added to keytab'; then
    echo "ktadd -norandkey leaked krbtgt keys: $KTGT" >&2
    exit 1
fi

echo "==== ktadd -norandkey kadmin/changepw is extract-keys ===="
KTCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw' 2>&1 || true)"
echo "$KTCPW"
echo "$KTCPW" | grep -F 'extract-keys'

echo "==== delprinc kadmin/changepw is delete privilege ===="
DELCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force kadmin/changepw' 2>&1 || true)"
echo "$DELCPW"
echo "$DELCPW" | grep -F "delete'' privilege"
GETCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw' 2>&1 || true)"
echo "$GETCPW" | grep -q 'Principal: kadmin/changepw@KERBER.TEST'

echo "==== modprinc -lockdown_keys kadmin/changepw is modify privilege ===="
MODCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc -lockdown_keys kadmin/changepw' 2>&1 || true)"
echo "$MODCPW"
echo "$MODCPW" | grep -F "modify'' privilege"
GETCPW2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw' 2>&1 || true)"
echo "$GETCPW2" | grep -F 'LOCKDOWN_KEYS'

echo "==== renprinc kadmin/changepw is delete privilege ===="
RENCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'renprinc -force kadmin/changepw kadmin/changepw2' 2>&1 || true)"
echo "$RENCPW"
echo "$RENCPW" | grep -F "delete'' privilege"

echo "==== extract/admin ktadd -norandkey extra control ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extract-secret extract/admin'
EXTKT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p extract/admin@KERBER.TEST -w extract-secret -q 'ktadd -norandkey -k /tmp/extra-extract.keytab extra' 2>&1 || true)"
echo "$EXTKT"
if echo "$EXTKT" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "extract/admin ktadd -norandkey extra failed: $EXTKT" >&2
    exit 1
fi

echo "==== MIT kadmin delprinc extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force extra'
DELGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$DELGET"
echo "$DELGET" | grep -qiE 'does not exist|not found|UNK_PRINC'

echo "==== MIT kadmind lockdown cells ===="
docker run -d --name "$NAME_MIT" "$IMAGE" >/dev/null
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME_MIT" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    docker logs "$NAME_MIT" >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT harness did not become ready"'
    exit 1
fi
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw extract-secret extract/admin'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw adminpassword admin/admin'
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *e" "extract/admin@KERBER.TEST *e" > /var/kerberos/krb5kdc/kadm5.acl'
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
sleep 0.4
docker exec -d "$NAME_MIT" kadmind
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen"'
    exit 1
fi
MITTGT="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc krbtgt/KERBER.TEST')"
echo "$MITTGT"
echo "$MITTGT" | grep -F 'LOCKDOWN_KEYS'
MITCTL="$(docker exec "$NAME_MIT" kadmin -p extract/admin -w extract-secret -q 'ktadd -norandkey -k /tmp/c.keytab user' 2>&1 || true)"
echo "$MITCTL"
if echo "$MITCTL" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "MIT extract/admin ktadd user failed: $MITCTL" >&2
    exit 1
fi
MITKTGT="$(docker exec "$NAME_MIT" kadmin -p extract/admin -w extract-secret -q 'ktadd -norandkey -k /tmp/krbtgt.keytab krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$MITKTGT"
echo "$MITKTGT" | grep -F 'extract-keys'
MITKTCPW="$(docker exec "$NAME_MIT" kadmin -p extract/admin -w extract-secret -q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw' 2>&1 || true)"
echo "$MITKTCPW"
echo "$MITKTCPW" | grep -F 'extract-keys'
MITDEL="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'delprinc -force kadmin/changepw' 2>&1 || true)"
echo "$MITDEL"
echo "$MITDEL" | grep -F "delete'' privilege"
MITMOD="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'modprinc -lockdown_keys kadmin/changepw' 2>&1 || true)"
echo "$MITMOD"
echo "$MITMOD" | grep -F "modify'' privilege"
MITREN="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'renprinc -force kadmin/changepw kadmin/changepw2' 2>&1 || true)"
echo "$MITREN"
echo "$MITREN" | grep -F "delete'' privilege"

log "kadmin.gate" "ok" ',"principal":"extra@KERBER.TEST","op":"addprinc+cpw+get+list+mod+chrand+norandkey+lockdown+purgekeys+setstr+renprinc+del"'
exit 0

