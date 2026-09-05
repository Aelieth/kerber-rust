#!/usr/bin/env bash
# MIT 1.22.2 kadmin against Rust kadmind (GSS-RPC 749):
# addprinc, cpw, getprinc, listprincs, modprinc, cpw -randkey, ktadd,
# ktadd -norandkey, purgekeys, setstr/getstrs, delprinc.
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

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

compile_kadm5_changepw() {
    local ctn=$1
    docker cp "$ROOT/scripts/kadm5-changepw-rpc.c" "$ctn":/tmp/kadm5-changepw-rpc.c
    if ! docker exec "$ctn" cc -o /tmp/kadm5-changepw-rpc /tmp/kadm5-changepw-rpc.c \
        -lkadm5clnt_mit -lgssrpc -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err 2>"$SCRATCH/kadm5-cc.err"
    then
        if ! docker exec "$ctn" cc -o /tmp/kadm5-changepw-rpc /tmp/kadm5-changepw-rpc.c \
            -lkadm5clnt -lgssrpc -lgssapi_krb5 -lkrb5 -lcom_err 2>>"$SCRATCH/kadm5-cc.err"
        then
            cat "$SCRATCH/kadm5-cc.err" >&2 || true
            docker exec "$ctn" cat /tmp/kadm5-cc.err >&2 || true
            log "kadmin.gate" "error" ',"error":"kadm5-changepw-rpc compile failed"'
            exit 1
        fi
    fi
}

kadm5_changepw_list() {
    local ctn=$1 client=$2 pass=$3
    docker exec -e KRB5_CONFIG="${4:-/etc/krb5.conf}" "$ctn" \
        /tmp/kadm5-changepw-rpc "$client" "$pass" KERBER.TEST listprincs
}

kadm5_list_service() {
    local ctn=$1 client=$2 pass=$3 svc=$4
    docker exec -e KRB5_CONFIG="${5:-/etc/krb5.conf}" "$ctn" \
        /tmp/kadm5-changepw-rpc --service "$svc" "$client" "$pass" KERBER.TEST listprincs
}

kadmind_auth_too_weak() {
    local ctn=$1
    docker exec "$ctn" python3 -c '
import socket, struct
s = socket.create_connection(("127.0.0.1", 749), 2)
xid, call, rpcvers, prog, vers, proc = 0x12345678, 0, 2, 2112, 2, 99
body = struct.pack(">10I", xid, call, rpcvers, prog, vers, proc, 0, 0, 0, 0)
s.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
hdr = s.recv(4)
assert len(hdr) == 4, hdr
n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
data = b""
while len(data) < n:
    chunk = s.recv(n - len(data))
    assert chunk, "eof"
    data += chunk
# xid, REPLY, DENIED, AUTH_ERROR, AUTH_TOOWEAK
got = struct.unpack(">5I", data[:20])
print("rpc=" + ",".join(str(x) for x in got))
assert got == (xid, 1, 1, 1, 5), got
'
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
norename@KERBER.TEST acilm
scoped@KERBER.TEST ad *@KERBER.TEST
restricted@KERBER.TEST a *@KERBER.TEST -clearpolicy
nodel@KERBER.TEST *D
ro@KERBER.TEST i
rolist@KERBER.TEST l
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

echo "==== Rust kadmind AUTH_NONE is AUTH_TOOWEAK ===="
kadmind_auth_too_weak "$NAME"

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

echo "==== knob search: stock kadmin never selects kadmin/changepw ===="
HELP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" kadmin --help 2>&1 || true)"
echo "$HELP"
if echo "$HELP" | grep -qi changepw; then
    echo "kadmin --help mentioned changepw (CLI has no CHANGEPW_SERVICE flag)" >&2
    exit 1
fi
KADMIN_TRACE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs' 2>&1 || true)"
echo "$KADMIN_TRACE"
echo "$KADMIN_TRACE" | grep -F 'Setting initial creds service to kadmin/admin'
if echo "$KADMIN_TRACE" | grep -F 'Setting initial creds service to kadmin/changepw'; then
    echo "stock kadmin selected kadmin/changepw as GSS service" >&2
    exit 1
fi
echo "kadmin.c:418-421 svcname = ADMIN_SERVICE or NULL; client_init.c:411 NULL -> kadmin/admin"

echo "==== crafted RPC listprincs over kadmin/changepw vs Rust kadmind ===="
compile_kadm5_changepw "$NAME"
CPW_LIST="$(kadm5_changepw_list "$NAME" admin@KERBER.TEST adminpassword /tmp/kadmin-krb5.conf 2>&1 || true)"
echo "$CPW_LIST"
echo "$CPW_LIST" | grep -F 'init_code=0'
echo "$CPW_LIST" | grep -F 'list_code=43787564'
echo "$CPW_LIST" | grep -F $'Operation requires ``list\'\' privilege'
if echo "$CPW_LIST" | grep -q 'list_count=' && echo "$CPW_LIST" | grep -qv 'list_count=0'; then
    if echo "$CPW_LIST" | grep -q 'list_code=0'; then
        echo "changepw listprincs succeeded: $CPW_LIST" >&2
        exit 1
    fi
fi
echo "==== kiprop service on kadm5 is AUTH_TOOWEAK ===="
KIPROP_LIST="$(kadm5_list_service "$NAME" admin@KERBER.TEST adminpassword kiprop/testhost.kerber.test /tmp/kadmin-krb5.conf 2>&1 || true)"
echo "$KIPROP_LIST"
echo "$KIPROP_LIST" | grep -F 'init_code=43787566'
echo "$KIPROP_LIST" | grep -F 'GSS-API (or Kerberos) error'
if echo "$KIPROP_LIST" | grep -q 'init_code=0'; then
    echo "kiprop service init succeeded: $KIPROP_LIST" >&2
    exit 1
fi
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

echo "==== ACL without d renprinc krbtgt is AUTH_INSUFFICIENT ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw norename-secret norename'
for run in 1 2; do
    echo "---- Rust norename krbtgt $run ----"
    RENACL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
        "$NAME" kadmin -p norename@KERBER.TEST -w norename-secret -q 'renprinc -force krbtgt/KERBER.TEST x' 2>&1 || true)"
    echo "$RENACL"
    echo "$RENACL" | grep -F 'Insufficient authorization for operation'
done
GETTGT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$GETTGT" | grep -F 'Principal: krbtgt/KERBER.TEST@KERBER.TEST'

echo "==== purgekeys krbtgt is protect-keys (Rust stricter) ===="
PURGE_TGT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'purgekeys krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$PURGE_TGT"
echo "$PURGE_TGT" | grep -F 'locked down'
if echo "$PURGE_TGT" | grep -qi 'Old keys for principal'; then
    echo "purgekeys cleared locked-down krbtgt keys: $PURGE_TGT" >&2
    exit 1
fi

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

echo "==== ACL target pattern scoped addprinc user2 / svc/x ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw scoped-secret scoped'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw restricted-secret restricted'
ADD_U2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'addprinc -pw x user2' 2>&1 || true)"
echo "$ADD_U2"
echo "$ADD_U2" | grep -F 'Principal "user2@KERBER.TEST" created.'
ADD_SVC="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'addprinc -pw x svc/x' 2>&1 || true)"
echo "$ADD_SVC"
echo "$ADD_SVC" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "svc/x@KERBER.TEST".'
if echo "$ADD_SVC" | grep -q 'Principal "svc/x@KERBER.TEST" created.'; then
    echo "scoped addprinc svc/x succeeded (ACL target ignored)" >&2
    exit 1
fi
REN_SVC="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'renprinc -force user2 svc/y' 2>&1 || true)"
echo "$REN_SVC"
echo "$REN_SVC" | grep -F 'Insufficient authorization for operation'
REN_U3="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'renprinc -force user2 user3' 2>&1 || true)"
echo "$REN_U3"
echo "$REN_U3" | grep -qiE 'renamed to "user3@KERBER.TEST"|Principal "user2@KERBER.TEST" renamed'
ADD_U9="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p restricted@KERBER.TEST -w restricted-secret -q 'addprinc -pw x -policy short8 user9' 2>&1 || true)"
echo "$ADD_U9"
echo "$ADD_U9" | grep -F 'Principal "user9@KERBER.TEST" created.'
GET_U9="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user9' 2>&1 || true)"
echo "$GET_U9"
echo "$GET_U9" | grep -F 'Policy: [none]'

echo "==== ACL uppercase *D revokes delete ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw nodel-secret nodel'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw victim-secret victim'
DEL_NODEL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p nodel@KERBER.TEST -w nodel-secret -q 'delprinc -force victim' 2>&1 || true)"
echo "$DEL_NODEL"
echo "$DEL_NODEL" | grep -F $'delete_principal: Operation requires ``delete\'\' privilege while deleting principal "victim@KERBER.TEST"'
if echo "$DEL_NODEL" | grep -qiE 'Principal "victim@KERBER.TEST" deleted|deleted.'; then
    echo "nodel *D granted delete: $DEL_NODEL" >&2
    exit 1
fi
GET_V="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc victim' 2>&1 || true)"
echo "$GET_V"
echo "$GET_V" | grep -F 'Principal: victim'

echo "==== ACL list vs inquire ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw ro-secret ro'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw rolist-secret rolist'
LIST_I="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p ro@KERBER.TEST -w ro-secret -q 'listprincs' 2>&1 || true)"
echo "$LIST_I"
echo "$LIST_I" | grep -F $'get_principals: Operation requires ``list\'\' privilege while retrieving list.'
if echo "$LIST_I" | grep -q 'user@KERBER.TEST'; then
    echo "ro i listed principals: $LIST_I" >&2
    exit 1
fi
LIST_L="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p rolist@KERBER.TEST -w rolist-secret -q 'listprincs' 2>&1 || true)"
echo "$LIST_L"
echo "$LIST_L" | grep -F 'user@KERBER.TEST'
ADDPOL_D="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p ro@KERBER.TEST -w ro-secret -q 'addpol pol-ro' 2>&1 || true)"
echo "$ADDPOL_D"
echo "$ADDPOL_D" | grep -F $'add_policy: Operation requires ``add\'\' privilege while creating policy "pol-ro".'
SELFGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user@KERBER.TEST -w userpassword -q 'getprinc user' 2>&1 || true)"
echo "$SELFGET"
echo "$SELFGET" | grep -F 'Principal: user@KERBER.TEST'

echo "==== MIT kadmin delprinc extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force extra'
DELGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$DELGET"
echo "$DELGET" | grep -qiE 'does not exist|not found|UNK_PRINC'

echo "==== ACL file without admin@ is not replaced ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
sleep 0.4
docker exec "$NAME" sh -c 'printf "%s\n" "scoped@KERBER.TEST ad *@KERBER.TEST" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-noadmin.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-noadmin.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-noadmin.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen after admin-less ACL"'
    exit 1
fi
NOADMIN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user' 2>&1 || true)"
echo "$NOADMIN"
echo "$NOADMIN" | grep -F $'get_principal: Operation requires ``get\'\' privilege while retrieving "user@KERBER.TEST".'
if echo "$NOADMIN" | grep -q 'Principal: user'; then
    echo "admin-less ACL granted admin getprinc: $NOADMIN" >&2
    exit 1
fi

echo "==== ACL unknown op letter refuses to start ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
sleep 0.4
docker exec "$NAME" sh -c 'printf "%s\n" "bad@KERBER.TEST aZ" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-badacl.log 2>&1'
sleep 1
BADLOG="$(docker exec "$NAME" cat /tmp/kadmind-badacl.log 2>/dev/null || true)"
echo "$BADLOG"
echo "$BADLOG" | grep -F "Unrecognized ACL operation"
if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-badacl.log 2>/dev/null; then
    echo "kadmind started on unknown op letter" >&2
    exit 1
fi

echo "==== default ACL path missing refuses start ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
sleep 0.4
docker exec "$NAME" sh -c '
python3 - <<PY
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
p.write_text("".join(ln for ln in p.read_text().splitlines(True) if "acl_file" not in ln))
PY
mv /tmp/kadm5.acl /tmp/kadm5.acl.bak 2>/dev/null || true
'
set +e
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c 'timeout 3 /tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-noacl.log 2>&1'
set -e
NOACL="$(docker exec "$NAME" cat /tmp/kadmind-noacl.log 2>/dev/null || true)"
echo "$NOACL"
echo "$NOACL" | grep -F 'Cannot open /tmp/kadm5.acl: No such file or directory while initializing ACL file, aborting'
if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-noacl.log 2>/dev/null; then
    echo "kadmind started with no ACL file" >&2
    exit 1
fi

echo "==== default ACL path present loads ===="
docker exec "$NAME" sh -c 'mv /tmp/kadm5.acl.bak /tmp/kadm5.acl'
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST *" "kiprop/*@KERBER.TEST p" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-defaultacl.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-defaultacl.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-defaultacl.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen on default ACL path"'
    exit 1
fi
GETPRIVS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprivs' 2>&1 || true)"
echo "$GETPRIVS"
echo "$GETPRIVS" | grep -qiE 'GET|ADD|MODIFY|DELETE'

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
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw norename-secret norename'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw scoped-secret scoped'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw restricted-secret restricted'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw nodel-secret nodel'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw victim-secret victim'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw ro-secret ro'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw rolist-secret rolist'
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *e" "admin@KERBER.TEST *e" "extract/admin@KERBER.TEST *e" "norename@KERBER.TEST acilm" "scoped@KERBER.TEST ad *@KERBER.TEST" "restricted@KERBER.TEST a *@KERBER.TEST -clearpolicy" "nodel@KERBER.TEST *D" "ro@KERBER.TEST i" "rolist@KERBER.TEST l" > /var/kerberos/krb5kdc/kadm5.acl'
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
echo "==== MIT kadmind AUTH_NONE is AUTH_TOOWEAK ===="
kadmind_auth_too_weak "$NAME_MIT"

echo "==== crafted RPC listprincs over kadmin/changepw vs MIT kadmind ===="
compile_kadm5_changepw "$NAME_MIT"
MIT_CPW_LIST="$(kadm5_changepw_list "$NAME_MIT" admin/admin adminpassword /etc/krb5.conf 2>&1 || true)"
echo "$MIT_CPW_LIST"
echo "$MIT_CPW_LIST" | grep -F 'init_code=0'
echo "$MIT_CPW_LIST" | grep -F 'list_code=43787564'
echo "$MIT_CPW_LIST" | grep -F $'Operation requires ``list\'\' privilege'
if echo "$MIT_CPW_LIST" | grep -q 'list_code=0'; then
    echo "MIT changepw listprincs succeeded: $MIT_CPW_LIST" >&2
    exit 1
fi
echo "==== MIT kiprop service on kadm5 is AUTH_TOOWEAK ===="
MIT_KIPROP_LIST="$(kadm5_list_service "$NAME_MIT" admin/admin adminpassword kiprop/testhost.kerber.test /etc/krb5.conf 2>&1 || true)"
echo "$MIT_KIPROP_LIST"
echo "$MIT_KIPROP_LIST" | grep -F 'init_code=43787560'
echo "$MIT_KIPROP_LIST" | grep -F 'Required KADM5 principal missing'
if echo "$MIT_KIPROP_LIST" | grep -q 'init_code=0'; then
    echo "MIT kiprop service init succeeded: $MIT_KIPROP_LIST" >&2
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

echo "==== MIT ACL without d renprinc krbtgt is AUTH_INSUFFICIENT ===="
for run in 1 2; do
    echo "---- MIT norename krbtgt $run ----"
    MITRENACL="$(docker exec "$NAME_MIT" kadmin -p norename -w norename-secret -q 'renprinc -force krbtgt/KERBER.TEST x' 2>&1 || true)"
    echo "$MITRENACL"
    echo "$MITRENACL" | grep -F 'Insufficient authorization for operation'
done
MITGETTGT="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc krbtgt/KERBER.TEST')"
echo "$MITGETTGT" | grep -F 'Principal: krbtgt/KERBER.TEST@KERBER.TEST'

echo "==== MIT ACL target pattern scoped addprinc user2 / svc/x ===="
MIT_U2="$(docker exec "$NAME_MIT" kadmin -p scoped -w scoped-secret -q 'addprinc -pw x user2' 2>&1 || true)"
echo "$MIT_U2"
echo "$MIT_U2" | grep -F 'Principal "user2@KERBER.TEST" created.'
MIT_SVC="$(docker exec "$NAME_MIT" kadmin -p scoped -w scoped-secret -q 'addprinc -pw x svc/x' 2>&1 || true)"
echo "$MIT_SVC"
echo "$MIT_SVC" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "svc/x@KERBER.TEST".'
MIT_REN_SVC="$(docker exec "$NAME_MIT" kadmin -p scoped -w scoped-secret -q 'renprinc -force user2 svc/y' 2>&1 || true)"
echo "$MIT_REN_SVC"
echo "$MIT_REN_SVC" | grep -F 'Insufficient authorization for operation'
MIT_REN_U3="$(docker exec "$NAME_MIT" kadmin -p scoped -w scoped-secret -q 'renprinc -force user2 user3' 2>&1 || true)"
echo "$MIT_REN_U3"
echo "$MIT_REN_U3" | grep -F 'Principal "user2@KERBER.TEST" renamed to "user3@KERBER.TEST".'
MIT_U9="$(docker exec "$NAME_MIT" kadmin -p restricted -w restricted-secret -q 'addprinc -pw x -policy short8 user9' 2>&1 || true)"
echo "$MIT_U9"
echo "$MIT_U9" | grep -F 'Principal "user9@KERBER.TEST" created.'
MIT_GET_U9="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc user9')"
echo "$MIT_GET_U9"
echo "$MIT_GET_U9" | grep -F 'Policy: [none]'

echo "==== MIT ACL uppercase *D revokes delete ===="
MIT_NODEL="$(docker exec "$NAME_MIT" kadmin -p nodel -w nodel-secret -q 'delprinc -force victim' 2>&1 || true)"
echo "$MIT_NODEL"
echo "$MIT_NODEL" | grep -F $'delete_principal: Operation requires ``delete\'\' privilege while deleting principal "victim@KERBER.TEST"'
if echo "$MIT_NODEL" | grep -qiE 'Principal "victim@KERBER.TEST" deleted'; then
    echo "MIT nodel *D granted delete: $MIT_NODEL" >&2
    exit 1
fi
MIT_GET_V="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc victim')"
echo "$MIT_GET_V"
echo "$MIT_GET_V" | grep -F 'Principal: victim@KERBER.TEST'

echo "==== MIT ACL list vs inquire ===="
MIT_LIST_I="$(docker exec "$NAME_MIT" kadmin -p ro -w ro-secret -q 'listprincs' 2>&1 || true)"
echo "$MIT_LIST_I"
echo "$MIT_LIST_I" | grep -F $'get_principals: Operation requires ``list\'\' privilege while retrieving list.'
MIT_LIST_L="$(docker exec "$NAME_MIT" kadmin -p rolist -w rolist-secret -q 'listprincs' 2>&1 || true)"
echo "$MIT_LIST_L"
echo "$MIT_LIST_L" | grep -F 'user@KERBER.TEST'
MIT_ADDPOL="$(docker exec "$NAME_MIT" kadmin -p ro -w ro-secret -q 'addpol pol-ro' 2>&1 || true)"
echo "$MIT_ADDPOL"
echo "$MIT_ADDPOL" | grep -F $'add_policy: Operation requires ``add\'\' privilege while creating policy "pol-ro".'
MIT_SELFGET="$(docker exec "$NAME_MIT" kadmin -p user -w userpassword -q 'getprinc user' 2>&1 || true)"
echo "$MIT_SELFGET"
echo "$MIT_SELFGET" | grep -F 'Principal: user@KERBER.TEST'

echo "==== MIT purgekeys krbtgt succeeds (no lockdown check) ===="
MITPURGE="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'purgekeys krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$MITPURGE"
echo "$MITPURGE" | grep -F 'Old keys for principal'
if echo "$MITPURGE" | grep -qiE 'locked down|PROTECT_KEYS'; then
    echo "MIT purgekeys refused krbtgt: $MITPURGE" >&2
    exit 1
fi

echo "==== MIT ACL file without admin is not replaced ===="
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
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "scoped@KERBER.TEST ad *@KERBER.TEST" > /var/kerberos/krb5kdc/kadm5.acl'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-noadmin.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-noadmin.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen after admin-less ACL"'
    exit 1
fi
MIT_NOADMIN="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'getprinc user' 2>&1 || true)"
echo "$MIT_NOADMIN"
echo "$MIT_NOADMIN" | grep -F $'get_principal: Operation requires ``get\'\' privilege while retrieving "user@KERBER.TEST".'
if echo "$MIT_NOADMIN" | grep -q 'Principal: user'; then
    echo "MIT admin-less ACL granted admin/admin getprinc: $MIT_NOADMIN" >&2
    exit 1
fi

echo "==== MIT ACL unknown op letter refuses to start ===="
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
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "bad@KERBER.TEST aZ" > /var/kerberos/krb5kdc/kadm5.acl'
set +e
docker exec "$NAME_MIT" sh -c 'timeout 3 kadmind -nofork >/tmp/kadmind-badacl.log 2>&1'
set -e
MIT_BAD="$(docker exec "$NAME_MIT" cat /tmp/kadmind-badacl.log 2>/dev/null || true)"
echo "$MIT_BAD"
echo "$MIT_BAD" | grep -F "Unrecognized ACL operation 'Z' in bad@KERBER.TEST aZ"
echo "$MIT_BAD" | grep -F "while initializing ACL file, aborting"
if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
    echo "MIT kadmind started on unknown op letter" >&2
    exit 1
fi

echo "==== MIT default ACL path missing refuses start ===="
docker exec "$NAME_MIT" sh -c '
python3 - <<PY
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
p.write_text("".join(ln for ln in p.read_text().splitlines(True) if "acl_file" not in ln))
PY
mv /var/kerberos/krb5kdc/kadm5.acl /tmp/kadm5.acl.bak 2>/dev/null || true
rm -f /var/krb5kdc/kadm5.acl
'
set +e
docker exec "$NAME_MIT" sh -c 'timeout 3 kadmind -nofork >/tmp/kadmind-noacl.log 2>&1'
set -e
MIT_NOACL="$(docker exec "$NAME_MIT" cat /tmp/kadmind-noacl.log 2>/dev/null || true)"
echo "$MIT_NOACL"
echo "$MIT_NOACL" | grep -F 'Cannot open /var/krb5kdc/kadm5.acl: No such file or directory while initializing ACL file, aborting'
if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
    echo "MIT kadmind started with no ACL file" >&2
    exit 1
fi

echo "==== MIT default ACL path present loads ===="
docker exec "$NAME_MIT" sh -c '
mkdir -p /var/krb5kdc
printf "%s\n" "admin@KERBER.TEST *" "kiprop/*@KERBER.TEST p" > /var/krb5kdc/kadm5.acl
'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-defaultacl.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-defaultacl.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen on default ACL path"'
    exit 1
fi
MIT_GETPRIVS="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'getprivs' 2>&1 || true)"
echo "$MIT_GETPRIVS"
echo "$MIT_GETPRIVS" | grep -qiE 'GET|ADD|MODIFY|DELETE'

log "kadmin.gate" "ok" ',"principal":"extra@KERBER.TEST","op":"addprinc+cpw+get+list+mod+chrand+norandkey+lockdown+purgekeys+setstr+renprinc+del"'
exit 0

