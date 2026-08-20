#!/usr/bin/env bash
# Two Rust KDCs + MIT kvno chase: KERBER.TEST -> OTHER.TEST host ticket.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-xr-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
XR_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"cross-realm-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "xr.gate" "error" ',"error":"docker not available"'
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

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_REALM=KERBER.TEST \
    -e KRB5_TEST_FOREIGN_REALM=OTHER.TEST \
    -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc-a.log 2>&1'

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_REALM=OTHER.TEST \
    -e KRB5_TEST_FOREIGN_REALM=KERBER.TEST \
    -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:89 >/tmp/kdc-b.log 2>&1'

ok_a=0
ok_b=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-a.log 2>/dev/null; then
        ok_a=1
    fi
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-b.log 2>/dev/null; then
        ok_b=1
    fi
    if [ "$ok_a" -eq 1 ] && [ "$ok_b" -eq 1 ]; then
        break
    fi
    sleep 0.25
done
echo "==== KDC A ===="
docker exec "$NAME" cat /tmp/kdc-a.log 2>/dev/null || true
echo "==== KDC B ===="
docker exec "$NAME" cat /tmp/kdc-b.log 2>/dev/null || true
if [ "$ok_a" -ne 1 ] || [ "$ok_b" -ne 1 ]; then
    log "xr.gate" "error" ',"error":"two-realm KDCs did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    forwardable = true

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:88
    }
    OTHER.TEST = {
        kdc = 127.0.0.1:89
    }
[domain_realm]
    .kerber.test = KERBER.TEST
    .other.test = OTHER.TEST
EOF'

echo "==== MIT kinit home realm ===="
set +e
KINIT="$(docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' 2>&1)"
rc=$?
set -e
echo "$KINIT"
if [ "$rc" -ne 0 ]; then
    log "xr.gate" "error" ',"error":"mit kinit home realm failed","rc":'"$rc"
    exit 1
fi
echo "==== MIT kvno host/svc.other.test@OTHER.TEST ===="
set +e
KVNO="$(docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno host/svc.other.test@OTHER.TEST 2>&1)"
rc=$?
set -e
echo "$KVNO"
KLIST="$(docker exec "$NAME" klist 2>/dev/null || true)"
echo "$KLIST"
if [ "$rc" -ne 0 ]; then
    echo "==== KDC A after kvno ===="
    docker exec "$NAME" cat /tmp/kdc-a.log 2>/dev/null || true
    echo "==== KDC B after kvno ===="
    docker exec "$NAME" cat /tmp/kdc-b.log 2>/dev/null || true
    log "xr.gate" "error" ',"error":"mit kvno cross-realm failed","rc":'"$rc"
    exit 1
fi
echo "$KVNO" | grep -q 'host/svc.other.test@OTHER.TEST: kvno ='
echo "$KLIST" | grep -q 'user@KERBER.TEST'
echo "$KLIST" | grep -q 'krbtgt/OTHER.TEST'
echo "$KLIST" | grep -q 'host/svc.other.test'
log "xr.gate" "ok" ',"home":"KERBER.TEST","foreign":"OTHER.TEST","service":"host/svc.other.test"'
exit 0
