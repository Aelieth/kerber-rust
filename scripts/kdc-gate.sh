#!/usr/bin/env bash
# Production-gate: MIT 1.22.2 kinit + kvno against the Rust KDC.
# Copies the Rust binary into a client-only MIT image so UDP stays on 127.0.0.1
# (host Docker publish of port 88 is unreliable).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-mit-client"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kdc-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kdc.gate" "error" ',"error":"docker not available"'
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

if ! docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc; then
    log "kdc.gate" "error" ',"error":"docker cp krb5-kdc failed"'
    exit 1
fi
docker exec "$NAME" chmod +x /tmp/krb5-kdc

# Bind 88 inside the container (root). Fall back to 8888 via the binary.
docker exec -d "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 30); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    # Binary may have failed to exec (glibc).
    if docker exec "$NAME" sh -c 'test -s /tmp/kdc.log' 2>/dev/null; then
        if docker exec "$NAME" grep -qiE 'not found|glibc|error|bind failed' /tmp/kdc.log 2>/dev/null; then
            break
        fi
    fi
    sleep 0.2
done

echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true

if [ "$ok" -ne 1 ]; then
    log "kdc.gate" "error" ',"error":"rust KDC did not listen inside MIT client container"'
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

echo "==== MIT kinit ===="
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    log "kdc.gate" "error" ',"error":"MIT kinit failed"'
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLIST1="$(docker exec "$NAME" klist)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'user@KERBER.TEST'
echo "$KLIST1" | grep -Ei 'Flags:|flags:' || echo "$KLIST1" | grep -q krbtgt

echo "==== MIT kvno host/testhost.kerber.test ===="
if ! docker exec "$NAME" kvno host/testhost.kerber.test; then
    log "kdc.gate" "error" ',"error":"MIT kvno failed"'
    docker exec "$NAME" klist || true
    exit 1
fi
KLIST2="$(docker exec "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'user@KERBER.TEST'
echo "$KLIST2" | grep -q 'host/testhost.kerber.test'

log "kdc.gate" "ok" ",\"principal\":\"user@KERBER.TEST\",\"service\":\"host/testhost.kerber.test\""
