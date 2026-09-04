#!/usr/bin/env bash
# MIT 1.22.2 kinit + kvno against a Rust KDC serving MemoryStore
# (db_library=memory seeded from --test-realm dump).
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-store-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-store-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"store-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "store.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/store-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "store.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/store-unavailable.log"
    exit 2
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
    -e KRB5_KDC_DB_LIBRARY=memory \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    if docker exec "$NAME" grep -qiE 'bind failed|privilege drop:|not found|glibc' /tmp/kdc.log 2>/dev/null; then
        if ! docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
            break
        fi
    fi
    sleep 0.25
done

echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true

if [ "$ok" -ne 1 ]; then
    log "store.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

if ! docker exec "$NAME" grep -q '^backend memory' /tmp/kdc.log; then
    log "store.gate" "error" ',"error":"KDC did not serve MemoryStore (missing backend memory)"'
    exit 1
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac

if [ "$PORT" != 88 ]; then
    docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1/kdc = 127.0.0.1:${PORT}/' /etc/krb5.conf"
fi

echo "==== MIT kinit (memory backend) ===="
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    log "store.gate" "error" ',"error":"MIT kinit failed"'
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLIST1="$(docker exec "$NAME" klist)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'user@KERBER.TEST'

echo "==== MIT kvno host/testhost.kerber.test ===="
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" kvno host/testhost.kerber.test; then
    log "store.gate" "error" ',"error":"MIT kvno failed"'
    docker exec "$NAME" klist || true
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLIST2="$(docker exec "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'host/testhost.kerber.test'

log "store.gate" "ok" ',"backend":"memory","principal":"user@KERBER.TEST","service":"host/testhost.kerber.test"'
exit 0
