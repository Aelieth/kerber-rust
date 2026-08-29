#!/usr/bin/env bash
# MIT 1.22.2 modprinc +flag vs Rust KDC: DISALLOW_* / OK_AS_DELEGATE /
# REQUIRES_HW_AUTH / NO_AUTH_DATA_REQUIRED / PWCHANGE_SERVICE already in
# expire-gate. Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-flags-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-flags-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"flags-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "flags.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/flags-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "flags.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/flags-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_MASTER_PASSWORD=masterpassword \
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
    log "flags.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
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
    log "flags.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/flags-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_flags
    forwardable = true
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

kinit_try() {
    docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
        "$NAME" sh -c "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== DISALLOW_ALL_TIX client still CLIENT_REVOKED ===="
kadmin_q 'addprinc -pw flag-secret flaguser'
kadmin_q 'modprinc -allow_tix flaguser'
REV="$(kinit_try 'printf "flag-secret\n" | kinit flaguser@KERBER.TEST')"
echo "$REV"
echo "$REV" | grep -qiE "credentials have been revoked|CLIENT_REVOKED"
kadmin_q 'modprinc +allow_tix flaguser'

echo "==== DISALLOW_FORWARDABLE strips F ===="
kadmin_q 'modprinc -allow_forwardable flaguser'
GET="$(kadmin_q 'getprinc flaguser')"
echo "$GET"
echo "$GET" | grep -q 'DISALLOW_FORWARDABLE'
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" sh -c 'printf "flag-secret\n" | kinit flaguser@KERBER.TEST'
FLAGS="$(docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" klist -f)"
echo "$FLAGS"
echo "$FLAGS" | grep -q 'flaguser@KERBER.TEST'
FLAGBITS="$(echo "$FLAGS" | awk '/Flags:/{print $2}' | tail -1)"
echo "flagbits=$FLAGBITS"
echo "$FLAGBITS" | grep -qv F
kadmin_q 'modprinc +allow_forwardable flaguser'

echo "==== OK_AS_DELEGATE sets O on kvno host ===="
kadmin_q 'modprinc +ok_as_delegate host/testhost.kerber.test'
GETH="$(kadmin_q 'getprinc host/testhost.kerber.test')"
echo "$GETH"
echo "$GETH" | grep -q 'OK_AS_DELEGATE'
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test
OFLAGS="$(docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" klist -f)"
echo "$OFLAGS"
OHOST="$(echo "$OFLAGS" | awk '/host\/testhost.kerber.test/{p=1} p && /Flags:/{print $2; exit}')"
echo "host_flagbits=$OHOST"
echo "$OHOST" | grep -q O

echo "==== DISALLOW_SVR: kvno MUST_USE_USER2USER ===="
kadmin_q 'modprinc -allow_svr host/testhost.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" sh -c 'printf "flag-secret\n" | kinit flaguser@KERBER.TEST'
SVR="$(docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test 2>&1 || true)"
echo "$SVR"
echo "$SVR" | grep -qiE "user2user|MUST_USE_USER2USER|KDC policy|cannot accommodate"
kadmin_q 'modprinc +allow_svr host/testhost.kerber.test'

echo "==== DISALLOW_TGT_BASED: kvno POLICY ===="
kadmin_q 'modprinc -allow_tgs_req host/testhost.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" sh -c 'printf "flag-secret\n" | kinit flaguser@KERBER.TEST'
TGT="$(docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test 2>&1 || true)"
echo "$TGT"
echo "$TGT" | grep -qiE "KDC policy rejects|POLICY"
kadmin_q 'modprinc +allow_tgs_req host/testhost.kerber.test'

echo "==== REQUIRES_HW_AUTH: kinit PREAUTH_FAILED ===="
kadmin_q 'modprinc +requires_hwauth flaguser'
HW="$(kinit_try 'printf "flag-secret\n" | kinit flaguser@KERBER.TEST')"
echo "$HW"
echo "$HW" | grep -qiE "Password incorrect|preauthentication failed|PREAUTH_FAILED|Generic error"
if echo "$HW" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "REQUIRES_HW_AUTH principal obtained a ticket" >&2
    exit 1
fi
kadmin_q 'modprinc -requires_hwauth flaguser'

echo "==== unexpired flaguser still kinit ===="
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf \
    "$NAME" sh -c 'printf "flag-secret\n" | kinit flaguser@KERBER.TEST'
OKL="$(docker exec -e KRB5_CONFIG=/tmp/flags-krb5.conf "$NAME" klist)"
echo "$OKL"
echo "$OKL" | grep -q 'flaguser@KERBER.TEST'

log "flags.gate" "ok" ',"disallow_all_tix":true,"disallow_forwardable":true,"ok_as_delegate":true,"disallow_svr":true,"disallow_tgt_based":true,"requires_hw_auth":true'
exit 0
