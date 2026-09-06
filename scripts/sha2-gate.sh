#!/usr/bin/env bash
# Live MIT 1.22.2 kinit/kvno forcing aes256-cts-hmac-sha384-192 (RFC 8009 etype 20)
# against the Rust KDC. Hard-fails without Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-sha2-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"sha2-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "sha2.gate" "error" ',"error":"docker not available"'
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
docker exec "$NAME" mkdir -p /tmp/traces
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
if [ "$ok" -ne 1 ]; then
    log "sha2.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac

if [ "$PORT" != 88 ]; then
    docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1/kdc = 127.0.0.1:${PORT}/' /etc/krb5-sha2.conf /etc/krb5.conf"
fi

echo "==== MIT kinit aes256-cts-hmac-sha384-192 ===="
set +e
TRACE="$(docker exec -e KRB5_CONFIG=/etc/krb5-sha2.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' 2>&1)"
rc=$?
set -e
echo "$TRACE"
if [ "$rc" -ne 0 ]; then
    echo "==== rust KDC log after kinit ===="
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    log "sha2.gate" "error" ',"error":"mit kinit sha2 failed","rc":'"$rc"
    exit 1
fi

echo "==== MIT kvno host/testhost.kerber.test ===="
set +e
KVNO="$(docker exec -e KRB5_CONFIG=/etc/krb5-sha2.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno host/testhost.kerber.test 2>&1)"
krc=$?
set -e
echo "$KVNO"
if [ "$krc" -ne 0 ]; then
    log "sha2.gate" "error" ',"error":"mit kvno sha2 failed"'
    exit 1
fi

KLIST="$(docker exec -e KRB5_CONFIG=/etc/krb5-sha2.conf "$NAME" klist -e 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
echo "$KLIST" | grep -q 'krbtgt/KERBER.TEST'
echo "$KLIST" | grep -q 'host/testhost.kerber.test'

# MIT `klist -e` prints one `Etype (skey, tkt):` line after each principal.
# The session key must be RFC 8009 etype 20 (SHA-2 negotiated end to end).
# The ticket key is the KDC's first current key (MIT `get_first_current_key`);
# the `--test-realm` store mints the compiled default aes256-sha1-96 first
# (osconf.hin:109), so the ticket key is etype 18. Honouring the harness
# kdc.conf `supported_enctypes` order is a separate absent behaviour, and
# cross-kdc-gate proves the MIT/Rust ticket-key parity on a shared dump.
assert_klist_sha2() {
    local princ="$1"
    local pair skey tkt
    pair="$(printf '%s\n' "$KLIST" | awk -v p="$princ" '
        index($0, p) && $0 !~ /Etype/ { getline; print; exit }
    ')"
    echo "==== klist -e $princ ===="
    echo "$pair"
    skey="$(echo "$pair" | sed -n 's/.*tkt): *\([^,]*\),.*/\1/p' | tr -d ' ')"
    tkt="$(echo "$pair" | sed -n 's/.*tkt): *[^,]*, *\(.*\)/\1/p' | tr -d ' ')"
    if [ "$skey" != "aes256-cts-hmac-sha384-192" ]; then
        log "sha2.gate" "error" ",\"error\":\"$princ session key must be aes256-cts-hmac-sha384-192\",\"got\":\"$skey\""
        exit 1
    fi
    if [ "$tkt" != "aes256-cts-hmac-sha1-96" ]; then
        log "sha2.gate" "error" ",\"error\":\"$princ ticket key must be the first current key aes256-cts-hmac-sha1-96\",\"got\":\"$tkt\""
        exit 1
    fi
}
assert_klist_sha2 'krbtgt/KERBER.TEST'
assert_klist_sha2 'host/testhost.kerber.test'

log "sha2.gate" "ok" ',"skey":"aes256-cts-hmac-sha384-192","principal":"user@KERBER.TEST","tkt":"aes256-cts-hmac-sha1-96"'
exit 0
