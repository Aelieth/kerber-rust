#!/usr/bin/env bash
# MIT kvno -U / kvno -U -P against the Rust KDC (not AD).
# Isolated inside the MIT 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-s4u-mit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-72593dc8f595/implementer}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"s4u-mit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "s4u.mit.gate" "error" ',"error":"docker not available"'
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
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm --export-keytab /tmp/host.keytab 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
KDC_LINE="kdc = 127.0.0.1"
case "$LISTEN" in
    *:8888*) KDC_LINE="kdc = 127.0.0.1:8888" ;;
esac

docker exec "$NAME" sh -c "cat >/tmp/s4u-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_s4u
[realms]
    KERBER.TEST = {
        ${KDC_LINE}
    }
EOF"

if ! docker exec "$NAME" test -f /tmp/host.keytab; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"host keytab not exported"'
    exit 1
fi

echo "==== kinit -f -k host/testhost.kerber.test ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kinit -f -k -t /tmp/host.keytab host/testhost.kerber.test@KERBER.TEST

echo "==== MIT kvno -U user (S4U2Self) ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kvno -U user host/testhost.kerber.test
KLIST1="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -f)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'host/testhost.kerber.test'
echo "$KLIST1" | grep -q 'for client user@KERBER.TEST'

echo "==== MIT kvno -U user -P (S4U2Proxy) ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kvno -U user -P host/testhost.kerber.test
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -f)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'for client user@KERBER.TEST'
echo "$KLIST2" | grep -q 'host/testhost.kerber.test'

log "s4u.mit.gate" "ok" ',"principal":"host/testhost.kerber.test","for_client":"user@KERBER.TEST"'
exit 0
