#!/usr/bin/env bash
# Rust kinit --fast vs MIT 1.22.2 KDC. Armor TGT from a prior enc-ts kinit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-fast-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rust-kinit-fast-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "fast.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-client --bin krb5-kinit

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
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        log "fast.client.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "fast.client.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc >/tmp/mit-kdc.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

echo "==== armor TGT (enc-ts) ===="
docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/krb5cc_armor user@KERBER.TEST

echo "==== Rust kinit --fast --armor-ccache ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    echo "==== MIT kdc TRACE ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast failed","rc":'"$rc"
    exit 1
fi
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
TRACE="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE" >&2
    log "fast.client.gate" "error" ',"error":"kinit succeeded without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE" | grep -F 'Decrypted AP-REQ'

echo "==== FAST immediate AS-REP (no +requires_preauth) ===="
docker exec "$NAME" sh -c "kadmin.local -q 'addprinc -pw userpassword nopreauth' >/tmp/g9-nopreauth-add.out 2>&1" || true
docker exec "$NAME" sh -c "kadmin.local -q 'modprinc -requires_preauth nopreauth' >/tmp/g9-nopreauth-mod.out 2>&1"
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT2="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast_np nopreauth@KERBER.TEST 2>&1)"
rc2=$?
set -e
echo "$OUT2"
if [ "$rc2" -ne 0 ]; then
    echo "==== MIT kdc TRACE (nopreauth) ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    docker exec "$NAME" cat /tmp/g9-nopreauth-add.out 2>/dev/null || true
    docker exec "$NAME" cat /tmp/g9-nopreauth-mod.out 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast nopreauth failed","rc":'"$rc2"
    exit 1
fi
KLIST2="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast_np 2>/dev/null || true)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'nopreauth@KERBER.TEST'
TRACE2="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE2" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE2" >&2
    log "fast.client.gate" "error" ',"error":"nopreauth FAST without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE2" | grep -F 'Decrypted AP-REQ'
log "fast.client.gate" "ok" ',"mode":"rust-kinit","pa_type":136,"principal":"user@KERBER.TEST","nopreauth":true'
exit 0
