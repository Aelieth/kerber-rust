#!/usr/bin/env bash
# Out-of-process MIT libgssapi_krb5 wrap/unwrap against krb5-gss-accept.
# Copies the Rust acceptor into the MIT 1.22.2 image (same pattern as kdc-gate).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-gss-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"gss-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "gss.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-gss --bin krb5-gss-accept

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Wait for MIT KDC + kinit in the entrypoint.
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        log "gss.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "gss.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

docker cp target/debug/krb5-gss-accept "$NAME":/tmp/krb5-gss-accept
docker exec "$NAME" chmod +x /tmp/krb5-gss-accept

kadmin_local() {
    docker exec \
        -e KRB5_CONFIG=/etc/krb5.conf \
        -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
        "$NAME" kadmin.local -q "$1"
}

echo "==== kadmin.local listprincs ===="
kadmin_local "listprincs" || true
# Old images swallowed ktadd; ensure the host principal and keytab exist.
kadmin_local "addprinc -randkey host/testhost.kerber.test" || true
kadmin_local "ktadd -k /etc/krb5kdc/testhost.keytab host/testhost.kerber.test"
if ! docker exec "$NAME" test -s /etc/krb5kdc/testhost.keytab; then
    log "gss.gate" "error" ',"error":"testhost.keytab missing after ktadd"'
    exit 1
fi

docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept.log 2>&1'
sleep 0.5

if ! docker exec "$NAME" grep -q 'listening' /tmp/gss-accept.log 2>/dev/null; then
    echo "==== gss-accept log ===="
    docker exec "$NAME" cat /tmp/gss-accept.log 2>/dev/null || true
    log "gss.gate" "error" ',"error":"gss-accept did not listen"'
    exit 1
fi

echo "==== MIT libgssapi_krb5 initiator ===="
MSG="hello-from-mit-gss"
docker cp "$ROOT/scripts/gss-mit-client.c" "$NAME":/tmp/gss-mit-client.c
if ! docker exec "$NAME" cc -o /tmp/gss-mit-client /tmp/gss-mit-client.c -lgssapi_krb5 -lkrb5; then
    log "gss.gate" "error" ',"error":"cc gss-mit-client failed"'
    docker exec "$NAME" cat /tmp/gss-cc.log 2>/dev/null || true
    exit 1
fi
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4444

echo "==== gss-accept log ===="
ACCEPT="$(docker exec "$NAME" cat /tmp/gss-accept.log 2>/dev/null || true)"
echo "$ACCEPT"
echo "$ACCEPT" | grep -q 'gss-accept unwrap ok'
echo "$ACCEPT" | grep -q "$MSG"

log "gss.gate" "ok" ",\"acceptor\":\"krb5-gss\",\"initiator\":\"mit-libgssapi\""
