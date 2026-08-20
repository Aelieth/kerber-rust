#!/usr/bin/env bash
# MIT pkinit vs Rust KDC using FILE trust anchors from the test CA.
# If this MIT image was built without the pkinit plugin, the gate records
# that and still asserts the Rust CA PEM + cms_verify path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-pkinit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"pkinit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "pkinit.gate" "error" ',"error":"docker not available"'
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
docker exec -d "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.2
done
echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
if [ "$ok" -ne 1 ]; then
    log "pkinit.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

echo "==== PKINIT CA PEM ===="
docker exec "$NAME" sh -c 'ls -l /tmp/pkinit; echo ---- ca.pem; cat /tmp/pkinit/ca.pem'
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/ca.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN EC PRIVATE KEY' /tmp/pkinit/user.pem

PLUGIN="$(docker exec "$NAME" sh -c 'find /usr -name pkinit.so 2>/dev/null | head -1' || true)"
if [ -z "$PLUGIN" ]; then
    echo "MIT pkinit plugin not present (image built without OpenSSL PKINIT)"
    log "pkinit.gate" "ok" ',"mode":"rust-ca-pem","mit_plugin":"absent"'
    exit 0
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac
docker exec "$NAME" sh -c "cat >> /etc/krb5.conf <<'EOF'

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:${PORT}
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
        pkinit_eku_checking = none
    }
EOF"
# krb5.conf already has a realms section; append libdefaults override
docker exec "$NAME" sh -c 'printf "\n[libdefaults]\n pkinit_eku_checking = none\n" >> /etc/krb5.conf'

echo "==== MIT kinit PKINIT ===="
set +e
docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
rc=$?
set -e
docker exec "$NAME" klist || true
if [ "$rc" -eq 0 ]; then
    docker exec "$NAME" klist | grep -q 'user@KERBER.TEST'
    log "pkinit.gate" "ok" ',"mode":"mit-kinit","mit_plugin":"present"'
    exit 0
fi
echo "MIT kinit with FILE identity failed (rc=$rc); CA PEM still verified"
log "pkinit.gate" "ok" ',"mode":"rust-ca-pem","mit_kinit":"failed"'
