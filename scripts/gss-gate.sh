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

cargo build -p krb5-gss --bin krb5-gss-accept --bin krb5-gss-init

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
docker cp target/debug/krb5-gss-init "$NAME":/tmp/krb5-gss-init
docker exec "$NAME" chmod +x /tmp/krb5-gss-accept /tmp/krb5-gss-init

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

echo "==== MIT libgssapi_krb5 initiator with GSS_C_DELEG_FLAG ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept-deleg.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-accept-deleg.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-accept-deleg.log >&2 || true
    log "gss.gate" "error" ',"error":"gss-accept did not listen for deleg"'
    exit 1
}
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4444 deleg
DELEG_LOG="$(docker exec "$NAME" cat /tmp/gss-accept-deleg.log 2>/dev/null || true)"
echo "$DELEG_LOG"
echo "$DELEG_LOG" | grep -q 'gss-accept unwrap ok'
echo "$DELEG_LOG" | grep -q 'gss-accept delegated=user@KERBER.TEST'

echo "==== compile MIT acceptor helper ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker cp "$ROOT/scripts/gss-mit-server.c" "$NAME":/tmp/gss-mit-server.c
if ! docker exec "$NAME" cc -o /tmp/gss-mit-server /tmp/gss-mit-server.c -lgssapi_krb5 -lkrb5; then
    log "gss.gate" "error" ',"error":"cc gss-mit-server failed"'
    exit 1
fi
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    kvno host/testhost.kerber.test@KERBER.TEST

echo "==== Rust initiator (no deleg) vs MIT acceptor ===="
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    "$NAME" sh -c '/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4446 >/tmp/gss-mit-server-plain.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-mit-server-plain.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-mit-server-plain.log >&2 || true
    log "gss.gate" "error" ',"error":"mit-gss-server plain did not listen"'
    exit 1
}
if ! docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/krb5-gss-init --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
    --ip 127.0.0.1 --port 4446; then
    echo "==== mit-gss-server-plain.log ===="
    docker exec "$NAME" cat /tmp/gss-mit-server-plain.log 2>/dev/null || true
    log "gss.gate" "error" ',"error":"rust gss-init plain failed"'
    exit 1
fi
PLAIN_ACC="$(docker exec "$NAME" cat /tmp/gss-mit-server-plain.log 2>/dev/null || true)"
echo "$PLAIN_ACC"
echo "$PLAIN_ACC" | grep -q 'mit-gss unwrap ok hello-from-rust-gss'

echo "==== Rust initiator GSS_C_DELEG_FLAG vs MIT acceptor ===="
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    -e KRB5_TRACE=/tmp/gss-mit-trace \
    "$NAME" sh -c '/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4445 >/tmp/gss-mit-server.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-mit-server.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-mit-server.log >&2 || true
    log "gss.gate" "error" ',"error":"mit-gss-server did not listen"'
    exit 1
}
if ! docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/krb5-gss-init --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
    --ip 127.0.0.1 --port 4445 --deleg; then
    echo "==== mit-gss-server.log ===="
    docker exec "$NAME" cat /tmp/gss-mit-server.log 2>/dev/null || true
    echo "==== mit-gss-trace ===="
    docker exec "$NAME" cat /tmp/gss-mit-trace 2>/dev/null || true
    log "gss.gate" "error" ',"error":"rust gss-init failed"'
    exit 1
fi
MIT_ACC="$(docker exec "$NAME" cat /tmp/gss-mit-server.log 2>/dev/null || true)"
echo "$MIT_ACC"
echo "$MIT_ACC" | grep -q 'mit-gss unwrap ok hello-from-rust-gss'
echo "$MIT_ACC" | grep -q 'mit-gss delegated=user@KERBER.TEST'

echo "==== MIT SPNEGO initiator vs Rust acceptor ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept-spnego.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-accept-spnego.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-accept-spnego.log >&2 || true
    log "gss.gate" "error" ',"error":"gss-accept did not listen for spnego"'
    exit 1
}
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4444 spnego
SPNEGO_LOG="$(docker exec "$NAME" cat /tmp/gss-accept-spnego.log 2>/dev/null || true)"
echo "$SPNEGO_LOG"
echo "$SPNEGO_LOG" | grep -q 'gss-accept unwrap ok'
echo "$SPNEGO_LOG" | grep -q "$MSG"
echo "$SPNEGO_LOG" | grep -q 'gss-accept spnego mic ok'
echo "$SPNEGO_LOG" | grep -q 'gss-accept spnego peer mic ok'

log "gss.gate" "ok" ",\"acceptor\":\"krb5-gss\",\"initiator\":\"mit-libgssapi\",\"deleg\":\"both\",\"spnego\":\"ok\""
