#!/usr/bin/env bash
# Rust krb5-kpasswd against MIT kadmind (TCP 464). New password kinit; old fails.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kpasswd-mit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rust-kpasswd-mit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kpasswd.mit.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-admin --bin krb5-kpasswd

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "kpasswd.mit.gate" "error" ',"error":"harness did not become ready"'
    exit 1
fi

docker exec -d "$NAME" kadmind
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',464),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kpasswd.mit.gate" "error" ',"error":"MIT kadmind 464 did not listen"'
    exit 1
fi

docker cp target/debug/krb5-kpasswd "$NAME":/tmp/krb5-kpasswd
docker exec "$NAME" chmod +x /tmp/krb5-kpasswd

echo "==== Rust kpasswd vs MIT kadmind ===="
docker exec -e KRB5_PASSWORD=userpassword -e KRB5_NEW_PASSWORD=mit-rust-pw \
    "$NAME" /tmp/krb5-kpasswd 127.0.0.1 user@KERBER.TEST
docker exec "$NAME" sh -c 'printf "mit-rust-pw\n" | kinit user@KERBER.TEST'
KLIST="$(docker exec "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
set +e
docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
old=$?
set -e
if [ "$old" -eq 0 ]; then
    log "kpasswd.mit.gate" "error" ',"error":"old password still works"'
    exit 1
fi
log "kpasswd.mit.gate" "ok" ',"principal":"user@KERBER.TEST","oracle":"mit-kadmind"'
exit 0
