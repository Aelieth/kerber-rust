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
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-s4u-mit-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"s4u-mit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "s4u.mit.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-client --bin krb5-kvno

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kvno "$NAME":/tmp/krb5-kvno
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kvno

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_LOCKED_USER=lock-secret \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    -e KRB5_TEST_OK_TO_AUTH_AS_DELEGATE=1 \
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

echo "==== user TGT + S4U2Self to host (mismatch, expect 36) ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
MM_BEFORE="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kdc.log' | tr -d ' ')"
KDC_HOST="127.0.0.1"
case "$LISTEN" in
    *:8888*) KDC_HOST="127.0.0.1:8888" ;;
esac
set +e
MISMATCH="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_s4u \
    "$NAME" /tmp/krb5-kvno -U admin "$KDC_HOST" host/testhost.kerber.test@KERBER.TEST 2>&1)"
MM_RC=$?
set -e
echo "$MISMATCH"
echo "mismatch_rc=$MM_RC"
echo "$MISMATCH" | grep -qiE "Ticket/authenticator don't match|BADMATCH|INVALID_S4U2SELF"
echo "$MM_RC" | grep -qx 1
MM_NEW="$(docker exec "$NAME" sh -c "tail -n +$((MM_BEFORE + 1)) /tmp/kdc.log")"
echo "$MM_NEW" | grep -q 'INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH'
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true

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
HOSTF="$(echo "$KLIST1" | sed -n 's/.*for client user@KERBER.TEST, Flags: //p')"
echo "s4u_flags_with_ok_to_auth=$HOSTF"
test -n "$HOSTF"
echo "$HOSTF" | grep -q F

echo "==== MIT kvno -U user -P (S4U2Proxy) ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kvno -U user -P host/testhost.kerber.test
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -f)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'for client user@KERBER.TEST'
echo "$KLIST2" | grep -q 'host/testhost.kerber.test'

echo "==== MIT kvno -U nosuch (C_PRINCIPAL_UNKNOWN) ===="
set +e
NOSUCH="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kvno -U nosuch host/testhost.kerber.test 2>&1)"
set -e
echo "$NOSUCH"
echo "$NOSUCH" | grep -qiE "not found in Kerberos database|C_PRINCIPAL_UNKNOWN"

echo "==== MIT kvno -U locked (CLIENT_REVOKED) ===="
set +e
LOCKED="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kvno -U locked host/testhost.kerber.test 2>&1)"
set -e
echo "$LOCKED"
echo "$LOCKED" | grep -qiE "credentials have been revoked|CLIENT_REVOKED"

echo "==== without ok_to_auth_as_delegate clears F on S4U2Self ===="
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
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
    log "s4u.mit.gate" "error" ',"error":"kdc did not listen (ok_to_auth)"'
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
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kinit -f -k -t /tmp/host.keytab host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kvno -U user host/testhost.kerber.test
KLISTF="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -f)"
echo "$KLISTF"
HOSTF2="$(echo "$KLISTF" | sed -n 's/.*for client user@KERBER.TEST, Flags: //p')"
echo "s4u_flags_without_ok_to_auth=$HOSTF2"
test -n "$HOSTF2"
echo "$HOSTF2" | grep -qv F

log "s4u.mit.gate" "ok" ',"principal":"host/testhost.kerber.test","for_client":"user@KERBER.TEST"'
exit 0
