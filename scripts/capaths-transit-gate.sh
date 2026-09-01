#!/usr/bin/env bash
# Three Rust KDCs A.TEST → B.TEST → C.TEST; MIT kvno is the oracle.
# Isolation: throwaway container only. Host /etc/krb5.conf is not touched.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-capaths-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
XR_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"capaths-transit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "capaths.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker exec "$NAME" chmod +x /tmp/krb5-kdc

docker exec "$NAME" sh -c 'cat >/tmp/client-capaths.conf <<EOF
[libdefaults]
    default_realm = A.TEST
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    forwardable = true
[realms]
    A.TEST = {
        kdc = 127.0.0.1:88
    }
    B.TEST = {
        kdc = 127.0.0.1:89
    }
    C.TEST = {
        kdc = 127.0.0.1:90
    }
[domain_realm]
    .a.test = A.TEST
    .b.test = B.TEST
    .c.test = C.TEST
[capaths]
    A.TEST = {
        C.TEST = B.TEST
        B.TEST = .
    }
    C.TEST = {
        A.TEST = B.TEST
    }
EOF
cat >/tmp/kdc-c-allow.conf <<EOF
[libdefaults]
    default_realm = C.TEST
    dns_lookup_kdc = false
[capaths]
    A.TEST = {
        C.TEST = B.TEST
    }
EOF
cat >/tmp/kdc-c-deny.conf <<EOF
[libdefaults]
    default_realm = C.TEST
    dns_lookup_kdc = false
EOF'

start_ab() {
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=A.TEST \
        -e KRB5_TEST_FOREIGN_REALM=B.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.a.test \
        "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc-a.log 2>&1'
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=B.TEST \
        -e KRB5_TEST_FOREIGN_REALM=A.TEST,C.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.b.test \
        "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:89 >/tmp/kdc-b.log 2>&1'
}

start_c() {
    local conf="$1"
    local log="$2"
    docker exec \
        -e KRB5_CONFIG="$conf" \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=C.TEST \
        -e KRB5_TEST_FOREIGN_REALM=B.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.c.test \
        "$NAME" sh -c "/tmp/krb5-kdc --test-realm 127.0.0.1:90 >$log 2>&1 & echo \$! >/tmp/kdc-c.pid"
}

wait_listen() {
    local log="$1"
    local i
    for i in $(seq 1 80); do
        if docker exec "$NAME" grep -q '^listening ' "$log" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

start_ab
start_c /tmp/kdc-c-allow.conf /tmp/kdc-c-allow.log
wait_listen /tmp/kdc-a.log
wait_listen /tmp/kdc-b.log
wait_listen /tmp/kdc-c-allow.log
echo "==== KDC A ===="
docker exec "$NAME" cat /tmp/kdc-a.log 2>/dev/null || true
echo "==== KDC B ===="
docker exec "$NAME" cat /tmp/kdc-b.log 2>/dev/null || true
echo "==== KDC C allow ===="
docker exec "$NAME" cat /tmp/kdc-c-allow.log 2>/dev/null || true

echo "==== MIT kinit A.TEST + kvno host/svc.c.test@C.TEST (permitted) ===="
set +e
KINIT="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@A.TEST' 2>&1)"
rc=$?
set -e
echo "$KINIT"
if [ "$rc" -ne 0 ]; then
    log "capaths.gate" "error" ',"error":"mit kinit A.TEST failed","rc":'"$rc"
    exit 1
fi
set +e
KVNO="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno host/svc.c.test@C.TEST 2>&1)"
rc=$?
set -e
echo "$KVNO"
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist 2>/dev/null || true)"
echo "$KLIST"
if [ "$rc" -ne 0 ]; then
    log "capaths.gate" "error" ',"error":"permitted path kvno failed","rc":'"$rc"
    exit 1
fi
echo "$KVNO" | grep -q 'host/svc.c.test@C.TEST: kvno ='
echo "$KLIST" | grep -q 'user@A.TEST'
echo "$KLIST" | grep -q 'krbtgt/B.TEST'
echo "$KLIST" | grep -q 'krbtgt/C.TEST'
echo "$KLIST" | grep -q 'host/svc.c.test'

echo "==== restart C without capaths (rejected path) ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
sleep 1
start_c /tmp/kdc-c-deny.conf /tmp/kdc-c-deny.log
if ! wait_listen /tmp/kdc-c-deny.log; then
    echo "==== KDC C deny (did not listen) ===="
    docker exec "$NAME" cat /tmp/kdc-c-deny.log 2>/dev/null || true
    docker exec "$NAME" cat /tmp/kdc-c.pid 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"deny KDC C did not listen"'
    exit 1
fi
echo "==== KDC C deny ===="
docker exec "$NAME" cat /tmp/kdc-c-deny.log 2>/dev/null || true

docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@A.TEST' >/dev/null
set +e
DENY="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno host/svc.c.test@C.TEST 2>&1)"
drc=$?
set -e
echo "$DENY"
test "$drc" -ne 0
echo "$DENY" | grep -q 'KDC policy rejects transited path'

log "capaths.gate" "ok" ',"path":"A.TEST>B.TEST>C.TEST","permitted":true,"rejected":true'
exit 0
