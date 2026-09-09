#!/usr/bin/env bash
# Out-of-process MIT libgssapi_krb5 wrap/unwrap against krb5-gss-accept.
# Copies the Rust acceptor into the MIT 1.22.2 image (same pattern as kdc-gate).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

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

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-gss-accept" "$NAME":/tmp/krb5-gss-accept
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-gss-init" "$NAME":/tmp/krb5-gss-init
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
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness -e GSS_DUMP_TOKEN=/tmp/gss-apreq "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4444

echo "==== gss-accept log ===="
ACCEPT="$(docker exec "$NAME" cat /tmp/gss-accept.log 2>/dev/null || true)"
echo "$ACCEPT"
echo "$ACCEPT" | grep -q 'gss-accept unwrap ok'
echo "$ACCEPT" | grep -q "$MSG"

echo "==== replayed AP-REQ vs Rust acceptor ===="
docker exec "$NAME" python3 -c 'import socket,struct; tok=open("/tmp/gss-apreq","rb").read(); s=socket.create_connection(("127.0.0.1",4444),5); s.sendall(struct.pack(">I", len(tok))+tok); s.close()'
ok=0
REPLAY_LOG=""
for _ in $(seq 1 20); do
    REPLAY_LOG="$(docker exec "$NAME" cat /tmp/gss-accept.log 2>/dev/null || true)"
    if echo "$REPLAY_LOG" | grep -qiE '34|replay'; then
        ok=1
        break
    fi
    sleep 0.15
done
echo "$REPLAY_LOG"
[ "$ok" = 1 ] || {
    log "gss.gate" "error" ',"error":"replayed AP-REQ did not log 34/replay"'
    exit 1
}
echo "$REPLAY_LOG" | grep -q 'accept_sec_context: KRB-ERROR 34: authenticator replay'
CLIENTN="$(echo "$REPLAY_LOG" | grep -c 'gss-accept client=' || true)"
if [ "$CLIENTN" -ne 1 ]; then
    echo "expected one gss-accept client= line, got $CLIENTN" >&2
    exit 1
fi

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
RUST_DELEG_FLAGS="$(echo "$DELEG_LOG" | sed -n 's/.*gss-accept inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
echo "rust_acceptor_deleg_flags=$RUST_DELEG_FLAGS"
[ $((${RUST_DELEG_FLAGS:-0} & 1)) -ne 0 ] || {
    log "gss.gate" "error" ',"error":"Rust acceptor stored a delegation without GSS_C_DELEG_FLAG"'
    exit 1
}

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
MIT_DELEG_FLAGS="$(echo "$MIT_ACC" | sed -n 's/.*mit-gss inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
echo "mit_acceptor_deleg_flags=$MIT_DELEG_FLAGS"
[ $((${MIT_DELEG_FLAGS:-0} & 1)) -ne 0 ] || {
    log "gss.gate" "error" ',"error":"MIT acceptor deleg flag not set (unexpected)"'
    exit 1
}

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

echo "==== MIT wrap_iov vs Rust unwrap_iov ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept-iov.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-accept-iov.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-accept-iov.log >&2 || true
    log "gss.gate" "error" ',"error":"gss-accept did not listen for iov"'
    exit 1
}
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4444 iov
IOV_LOG="$(docker exec "$NAME" cat /tmp/gss-accept-iov.log 2>/dev/null || true)"
echo "$IOV_LOG"
echo "$IOV_LOG" | grep -q 'gss-accept unwrap ok'
echo "$IOV_LOG" | grep -q "$MSG"
echo "$IOV_LOG" | grep -q 'gss-accept import ok'
echo "$IOV_LOG" | grep -q 'gss-accept inquire flags='
IOV_LIFE="$(echo "$IOV_LOG" | sed -n 's/.*gss-accept inquire flags=\([0-9]*\) lifetime=\([0-9]*\).*/\2/p' | head -1)"
IOV_FLAGS="$(echo "$IOV_LOG" | sed -n 's/.*gss-accept inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
[ "${IOV_LIFE:-0}" -gt 0 ]
# MUTUAL|CONF|INTEG|TRANS
[ $((${IOV_FLAGS:-0} & 306)) -eq 306 ]

echo "==== MIT wrap_iov SIGN_ONLY vs Rust unwrap_iov ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 --assoc rpc-hdr >/tmp/gss-accept-sign.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-accept-sign.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-accept-sign.log >&2 || true
    log "gss.gate" "error" ',"error":"gss-accept did not listen for sign"'
    exit 1
}
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4444 sign
SIGN_LOG="$(docker exec "$NAME" cat /tmp/gss-accept-sign.log 2>/dev/null || true)"
echo "$SIGN_LOG"
echo "$SIGN_LOG" | grep -q 'gss-accept unwrap ok'
echo "$SIGN_LOG" | grep -q "$MSG"

echo "==== replayed AP-REQ vs MIT acceptor ===="
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
sleep 0.2
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    "$NAME" sh -c 'stdbuf -oL -eL /tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4448 >/tmp/gss-mit-replay.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-mit-replay.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-mit-replay.log >&2 || true
    log "gss.gate" "error" ',"error":"mit-gss-server replay did not listen"'
    exit 1
}
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness -e GSS_DUMP_TOKEN=/tmp/gss-apreq-mit "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host "$MSG" 127.0.0.1 4448
MIT1="$(docker exec "$NAME" cat /tmp/gss-mit-replay.log 2>/dev/null || true)"
echo "$MIT1"
echo "$MIT1" | grep -q 'mit-gss unwrap ok'
REPLAY_PY="$(docker exec "$NAME" python3 -c '
import socket, struct, sys
tok = open("/tmp/gss-apreq-mit", "rb").read()
s = socket.create_connection(("127.0.0.1", 4448), 5)
s.settimeout(5)
s.sendall(struct.pack(">I", len(tok)) + tok)
hdr = b""
while len(hdr) < 4:
    chunk = s.recv(4 - len(hdr))
    if not chunk:
        sys.exit("replay: no length prefix")
    hdr += chunk
n = struct.unpack(">I", hdr)[0]
body = b""
while len(body) < n:
    chunk = s.recv(n - len(body))
    if not chunk:
        break
    body += chunk
print("replay_token_len=%d" % len(body))
idx = body.find(b"\xa6\x03\x02\x01")
if idx < 0:
    sys.exit("replay: no KRB-ERROR error-code")
code = body[idx + 4]
print("krb_error_code=%d" % code)
s.close()
if code != 34:
    sys.exit("replay: error-code %d != 34" % code)
')"
echo "$REPLAY_PY"
echo "$REPLAY_PY" | grep -q 'krb_error_code=34'
ok=0
MIT2=""
for _ in $(seq 1 20); do
    MIT2="$(docker exec "$NAME" cat /tmp/gss-mit-replay.log 2>/dev/null || true)"
    if echo "$MIT2" | grep -q 'accept_sec_context:' && echo "$MIT2" | grep -q 'Request is a replay'; then
        ok=1
        break
    fi
    sleep 0.15
done
echo "$MIT2"
[ "$ok" = 1 ] || {
    log "gss.gate" "error" ',"error":"MIT replay did not log accept_sec_context Request is a replay"'
    exit 1
}

docker cp "$ROOT/scripts/gss-mit-client.c" "$NAME":/tmp/gss-mit-client.c
if ! docker exec "$NAME" cc -o /tmp/gss-mit-client /tmp/gss-mit-client.c -lgssapi_krb5 -lkrb5; then
    log "gss.gate" "error" ',"error":"cc gss-mit-client dce rebuild failed"'
    exit 1
fi
docker cp "$ROOT/scripts/gss-mit-server.c" "$NAME":/tmp/gss-mit-server.c
if ! docker exec "$NAME" cc -o /tmp/gss-mit-server /tmp/gss-mit-server.c -lgssapi_krb5 -lkrb5; then
    log "gss.gate" "error" ',"error":"cc gss-mit-server dce rebuild failed"'
    exit 1
fi

echo "==== MIT DCE wrap_iov vs Rust unwrap ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept-dce.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-accept-dce.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-accept-dce.log >&2 || true
    log "gss.gate" "error" ',"error":"gss-accept did not listen for dce"'
    exit 1
}
MIT_GSS_CLIENT=/tmp/gss-mit-client
RUST_GSS_ACCEPT=/tmp/krb5-gss-accept
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$MIT_GSS_CLIENT" testhost.kerber.test host "$MSG" 127.0.0.1 4444 dce
DCE_LOG="$(docker exec "$NAME" cat /tmp/gss-accept-dce.log 2>/dev/null || true)"
echo "$DCE_LOG"
echo "$DCE_LOG" | grep -q 'gss-accept dce ok'
echo "$DCE_LOG" | grep -q "gss-accept plaintext=$MSG"
echo "$DCE_LOG" | grep -q "gss-accept unwrap ok bytes=${#MSG}"

echo "==== MIT DCE wrap_iov vs MIT unwrap ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    "$NAME" sh -c '/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4450 >/tmp/gss-mit-server-dce.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q 'listening' /tmp/gss-mit-server-dce.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.15
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/gss-mit-server-dce.log >&2 || true
    log "gss.gate" "error" ',"error":"mit-gss-server dce did not listen"'
    exit 1
}
MIT_GSS_CLIENT=/tmp/gss-mit-client
MIT_GSS_SERVER=/tmp/gss-mit-server
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$MIT_GSS_CLIENT" testhost.kerber.test host "$MSG" 127.0.0.1 4450 dce
MIT_DCE="$(docker exec "$NAME" cat /tmp/gss-mit-server-dce.log 2>/dev/null || true)"
echo "$MIT_DCE"
echo "$MIT_DCE" | grep -q "mit-gss unwrap ok $MSG"
echo "$MIT_DCE" | grep -q "mit-gss unwrap bytes=${#MSG}"

gss_mutate_cell() {
    local kind=$1
    local rust_pat=$2
    local mit_pat=$3
    echo "==== Rust initiator mutate $kind vs Rust acceptor ===="
    docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
    docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
    sleep 0.2
    docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept-mut.log 2>&1'
    ok=0
    for _ in $(seq 1 20); do
        if docker exec "$NAME" grep -q 'listening' /tmp/gss-accept-mut.log 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.15
    done
    [ "$ok" = 1 ] || {
        docker exec "$NAME" cat /tmp/gss-accept-mut.log >&2 || true
        log "gss.gate" "error" ",\"error\":\"gss-accept did not listen for mutate $kind\""
        exit 1
    }
    RUST_GSS_INIT=/tmp/krb5-gss-init
    RUST_GSS_ACCEPT=/tmp/krb5-gss-accept
    docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
        "$RUST_GSS_INIT" --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
        --ip 127.0.0.1 --port 4444 --mutate "$kind"
    MUT_LOG="$(docker exec "$NAME" cat /tmp/gss-accept-mut.log 2>/dev/null || true)"
    echo "$MUT_LOG"
    echo "$MUT_LOG" | grep -q "$rust_pat" || {
        log "gss.gate" "error" ",\"error\":\"rust mutate $kind did not reject\""
        exit 1
    }
    echo "==== Rust initiator mutate $kind vs MIT acceptor ===="
    docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
    docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
    sleep 0.2
    docker exec -d \
        -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
        "$NAME" sh -c "/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4451 >/tmp/gss-mit-mut.log 2>&1"
    ok=0
    for _ in $(seq 1 20); do
        if docker exec "$NAME" grep -q 'listening' /tmp/gss-mit-mut.log 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.15
    done
    [ "$ok" = 1 ] || {
        docker exec "$NAME" cat /tmp/gss-mit-mut.log >&2 || true
        log "gss.gate" "error" ",\"error\":\"mit-gss-server mutate $kind did not listen\""
        exit 1
    }
    RUST_GSS_INIT=/tmp/krb5-gss-init
    MIT_GSS_SERVER=/tmp/gss-mit-server
    docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
        "$RUST_GSS_INIT" --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
        --ip 127.0.0.1 --port 4451 --mutate "$kind" || true
    ok=0
    MIT_MUT=""
    for _ in $(seq 1 20); do
        MIT_MUT="$(docker exec "$NAME" cat /tmp/gss-mit-mut.log 2>/dev/null || true)"
        if echo "$MIT_MUT" | grep -q "$mit_pat"; then
            ok=1
            break
        fi
        sleep 0.15
    done
    echo "$MIT_MUT"
    [ "$ok" = 1 ] || {
        log "gss.gate" "error" ",\"error\":\"mit mutate $kind did not reject\""
        exit 1
    }
}

# MIT gss_display_status texts settled live in the mutation cells below.
gss_mutate_cell direction 'unwrap: gss integrity' 'invalid Message Integrity Check'
gss_mutate_cell filler 'unwrap: gss truncated' 'Invalid token was supplied'
gss_mutate_cell ec 'unwrap: gss truncated' 'Invalid token was supplied'

gss_listen() {
    local log=$1
    local what=$2
    ok=0
    for _ in $(seq 1 20); do
        if docker exec "$NAME" grep -q 'listening' "$log" 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.15
    done
    [ "$ok" = 1 ] || {
        docker exec "$NAME" cat "$log" >&2 || true
        log "gss.gate" "error" ",\"error\":\"$what did not listen\""
        exit 1
    }
}

echo "==== Rust initiator no-checksum vs Rust acceptor ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 --accept-only >/tmp/gss-accept-nc.log 2>&1'
gss_listen /tmp/gss-accept-nc.log "gss-accept no-checksum"
RUST_GSS_INIT=/tmp/krb5-gss-init
RUST_GSS_ACCEPT=/tmp/krb5-gss-accept
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$RUST_GSS_INIT" --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
    --ip 127.0.0.1 --port 4444 --no-checksum --accept-only
RUST_NC="$(docker exec "$NAME" cat /tmp/gss-accept-nc.log 2>/dev/null || true)"
echo "$RUST_NC"
echo "$RUST_NC" | grep -q 'gss-accept ap-rep=none' || {
    log "gss.gate" "error" ',"error":"rust no-checksum still sent AP-REP"'
    exit 1
}
RUST_NC_FLAGS="$(echo "$RUST_NC" | sed -n 's/.*gss-accept inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
[ $((${RUST_NC_FLAGS:-1} & 2)) -eq 0 ]
[ $((${RUST_NC_FLAGS:-1} & 2048)) -eq 0 ]

echo "==== Rust initiator no-checksum vs MIT acceptor ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    -e GSS_ACCEPT_ONLY=1 \
    "$NAME" sh -c '/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4452 >/tmp/gss-mit-nc.log 2>&1'
gss_listen /tmp/gss-mit-nc.log "mit-gss-server no-checksum"
RUST_GSS_INIT=/tmp/krb5-gss-init
MIT_GSS_SERVER=/tmp/gss-mit-server
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$RUST_GSS_INIT" --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
    --ip 127.0.0.1 --port 4452 --no-checksum --accept-only
MIT_NC="$(docker exec "$NAME" cat /tmp/gss-mit-nc.log 2>/dev/null || true)"
echo "$MIT_NC"
echo "$MIT_NC" | grep -q 'mit-gss ap-rep=none' || {
    log "gss.gate" "error" ',"error":"mit no-checksum still sent AP-REP"'
    exit 1
}
MIT_NC_FLAGS="$(echo "$MIT_NC" | sed -n 's/.*mit-gss inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
[ $((${MIT_NC_FLAGS:-1} & 2)) -eq 0 ]
[ $((${MIT_NC_FLAGS:-1} & 2048)) -eq 0 ]

echo "==== MIT initiator no CB vs Rust acceptor with CB ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 --channel-bindings acceptor-bind >/tmp/gss-accept-cb.log 2>&1'
gss_listen /tmp/gss-accept-cb.log "gss-accept cb"
MIT_GSS_CLIENT=/tmp/gss-mit-client
RUST_GSS_ACCEPT=/tmp/krb5-gss-accept
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$MIT_GSS_CLIENT" testhost.kerber.test host "$MSG" 127.0.0.1 4444
RUST_CB="$(docker exec "$NAME" cat /tmp/gss-accept-cb.log 2>/dev/null || true)"
echo "$RUST_CB"
echo "$RUST_CB" | grep -q 'gss-accept unwrap ok' || {
    log "gss.gate" "error" ',"error":"rust acceptor CB rejected initiator without CB"'
    exit 1
}
RUST_CB_FLAGS="$(echo "$RUST_CB" | sed -n 's/.*gss-accept inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
[ $((${RUST_CB_FLAGS:-2048} & 2048)) -eq 0 ]

echo "==== Rust initiator no CB vs MIT acceptor with CB ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    -e GSS_CHANNEL_BINDINGS=acceptor-bind \
    "$NAME" sh -c '/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4453 >/tmp/gss-mit-cb.log 2>&1'
gss_listen /tmp/gss-mit-cb.log "mit-gss-server cb"
RUST_GSS_INIT=/tmp/krb5-gss-init
MIT_GSS_SERVER=/tmp/gss-mit-server
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$RUST_GSS_INIT" --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
    --ip 127.0.0.1 --port 4453
MIT_CB="$(docker exec "$NAME" cat /tmp/gss-mit-cb.log 2>/dev/null || true)"
echo "$MIT_CB"
echo "$MIT_CB" | grep -q 'mit-gss unwrap ok hello-from-rust-gss' || {
    log "gss.gate" "error" ',"error":"mit acceptor CB rejected initiator without CB"'
    exit 1
}
MIT_CB_FLAGS="$(echo "$MIT_CB" | sed -n 's/.*mit-gss inquire flags=\([0-9]*\) lifetime=.*/\1/p' | head -1)"
[ $((${MIT_CB_FLAGS:-2048} & 2048)) -eq 0 ]

echo "==== MIT initiator CB mismatch vs Rust acceptor ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /etc/krb5kdc/testhost.keytab --listen 127.0.0.1:4444 --channel-bindings tls-b >/tmp/gss-accept-cbm.log 2>&1'
gss_listen /tmp/gss-accept-cbm.log "gss-accept cb mismatch"
MIT_GSS_CLIENT=/tmp/gss-mit-client
RUST_GSS_ACCEPT=/tmp/krb5-gss-accept
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness -e GSS_CHANNEL_BINDINGS=tls-a "$NAME" \
    "$MIT_GSS_CLIENT" testhost.kerber.test host "$MSG" 127.0.0.1 4444 || true
RUST_CBM="$(docker exec "$NAME" cat /tmp/gss-accept-cbm.log 2>/dev/null || true)"
echo "$RUST_CBM"
echo "$RUST_CBM" | grep -q 'gss channel bindings' || {
    log "gss.gate" "error" ',"error":"rust acceptor CB mismatch did not reject"'
    exit 1
}

echo "==== Rust initiator CB mismatch vs MIT acceptor ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-gss-accept) 2>/dev/null || true'
docker exec "$NAME" sh -c 'kill $(pidof gss-mit-server) 2>/dev/null || true'
sleep 0.2
docker exec -d \
    -e KRB5_KTNAME=/etc/krb5kdc/testhost.keytab \
    -e GSS_CHANNEL_BINDINGS=tls-b \
    "$NAME" sh -c '/tmp/gss-mit-server /etc/krb5kdc/testhost.keytab 127.0.0.1 4454 >/tmp/gss-mit-cbm.log 2>&1'
gss_listen /tmp/gss-mit-cbm.log "mit-gss-server cb mismatch"
RUST_GSS_INIT=/tmp/krb5-gss-init
MIT_GSS_SERVER=/tmp/gss-mit-server
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness "$NAME" \
    "$RUST_GSS_INIT" --ccache /tmp/krb5cc_harness --host testhost.kerber.test \
    --ip 127.0.0.1 --port 4454 --channel-bindings tls-a || true
ok=0
MIT_CBM=""
for _ in $(seq 1 20); do
    MIT_CBM="$(docker exec "$NAME" cat /tmp/gss-mit-cbm.log 2>/dev/null || true)"
    if echo "$MIT_CBM" | grep -q 'Incorrect channel bindings were supplied'; then
        ok=1
        break
    fi
    sleep 0.15
done
echo "$MIT_CBM"
[ "$ok" = 1 ] || {
    log "gss.gate" "error" ',"error":"mit acceptor CB mismatch did not reject"'
    exit 1
}

log "gss.gate" "ok" ",\"acceptor\":\"krb5-gss\",\"initiator\":\"mit-libgssapi\",\"deleg\":\"both\",\"spnego\":\"ok\",\"iov\":\"ok\",\"replay\":\"ok\",\"dce\":\"ok\",\"process_checksum\":\"ok\""
