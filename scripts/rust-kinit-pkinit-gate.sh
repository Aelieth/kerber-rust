#!/usr/bin/env bash
# Rust kinit --pkinit vs MIT 1.22.2 KDC (pkinit.so + KDC cert). MIT klist must
# name user@KERBER.TEST. Fails if pkinit.so is missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-pkinit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rust-kinit-pkinit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "pkinit.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc
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
        log "pkinit.client.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "pkinit.client.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

PLUGIN="$(docker exec "$NAME" sh -c 'find /usr -name pkinit.so 2>/dev/null | head -1' || true)"
if [ -z "$PLUGIN" ]; then
    echo "MIT pkinit plugin not present (image built without OpenSSL PKINIT)"
    log "pkinit.client.gate" "error" ',"error":"pkinit.so absent"'
    exit 1
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc-export
docker exec "$NAME" chmod +x /tmp/krb5-kdc-export
docker exec "$NAME" mkdir -p /tmp/pkinit
docker exec \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME" sh -c '
        /tmp/krb5-kdc-export --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:18888 >/tmp/pkinit-export.log 2>&1 &
        ep=$!
        okpem=0
        for _ in $(seq 1 200); do
            if [ -s /tmp/pkinit/kdc.pem ]; then
                okpem=1
                break
            fi
            sleep 0.1
        done
        kill "$ep" 2>/dev/null || true
        wait "$ep" 2>/dev/null || true
        if [ "$okpem" != 1 ]; then
            echo "pkinit export timed out" >&2
            cat /tmp/pkinit-export.log >&2 || true
            exit 1
        fi
    '
if ! docker exec "$NAME" test -s /tmp/pkinit/kdc.pem; then
    log "pkinit.client.gate" "error" ',"error":"pkinit export timed out"'
    docker exec "$NAME" cat /tmp/pkinit-export.log >&2 || true
    exit 1
fi
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/ca.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN EC PRIVATE KEY' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/kdc.pem
docker exec "$NAME" grep -q 'BEGIN EC PRIVATE KEY' /tmp/pkinit/kdc.pem

docker exec "$NAME" sh -c 'grep -q pkinit_identity /etc/krb5kdc/kdc.conf || sed -i "/\[kdcdefaults\]/a\\    pkinit_identity = FILE:/tmp/pkinit/kdc.pem\\n    pkinit_anchors = FILE:/tmp/pkinit/ca.pem\\n    pkinit_dh_min_bits = P-256" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" kadmin.local -q 'modprinc +requires_preauth user'

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
    log "pkinit.client.gate" "error" ',"error":"MIT krb5kdc did not listen after PKINIT config"'
    exit 1
fi

docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

echo "==== Rust kinit --pkinit vs MIT KDC ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT="$(docker exec -e KRB5_PASSWORD= "$NAME" \
    /tmp/krb5-kinit --pkinit FILE:/tmp/pkinit/user.pem --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/krb5cc_pkinit user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    echo "==== MIT kdc log ===="
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    echo "==== MIT kdc TRACE ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    echo "==== export log ===="
    docker exec "$NAME" cat /tmp/pkinit-export.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"rust kinit --pkinit failed","rc":'"$rc"
    exit 1
fi
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_pkinit 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
TRACE="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE$OUT" | grep -Eqi 'PKINIT|pa[_ ]?type[[:space:]]*16|padata type 16|PA-PK-AS|client.pkinit'; then
    log "pkinit.client.gate" "error" ',"error":"kinit succeeded without PKINIT evidence"'
    exit 1
fi
log "pkinit.client.gate" "ok" ',"mode":"rust-kinit","pa_type":16,"principal":"user@KERBER.TEST","mit_plugin":"present"'

echo "==== negative: MIT KDC identity is a client cert (rogue KDC) ===="
docker exec "$NAME" sh -c 'grep -q pkinit_identity /etc/krb5kdc/kdc.conf && sed -i "s|pkinit_identity = FILE:/tmp/pkinit/kdc.pem|pkinit_identity = FILE:/tmp/pkinit/user.pem|" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc-rogue.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc >/tmp/mit-kdc-rogue.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    echo "MIT krb5kdc did not listen with client-cert identity"
    docker exec "$NAME" cat /tmp/mit-kdc-rogue.log >&2 || true
    log "pkinit.client.gate" "error" ',"error":"MIT krb5kdc did not listen with client-cert identity"'
    exit 1
fi
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc-rogue.trace' || true
set +e
ROGUE="$(docker exec -e KRB5_PASSWORD= "$NAME" \
    /tmp/krb5-kinit --pkinit FILE:/tmp/pkinit/user.pem --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/krb5cc_pkinit_rogue user@KERBER.TEST 2>&1)"
rrc=$?
set -e
echo "$ROGUE"
if [ "$rrc" -eq 0 ]; then
    echo "==== MIT kdc rogue log ===="
    docker exec "$NAME" cat /tmp/mit-kdc-rogue.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"rust kinit accepted client-cert KDC CMS"'
    exit 1
fi
if ! echo "$ROGUE" | grep -q 'pkinit kdc eku'; then
    echo "$ROGUE" >&2
    log "pkinit.client.gate" "error" ',"error":"rogue KDC refused without pkinit kdc eku","rc":'"$rrc"
    exit 1
fi
log "pkinit.client.gate" "ok" ',"mode":"rust-kinit-rogue","refused":"client-cert-kdc","rc":'"$rrc"
exit 0
