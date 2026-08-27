#!/usr/bin/env bash
# MIT kpasswd (RFC 3244) against Rust kadmind UDP 464 + kadmin/changepw.
# Isolated inside the MIT 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kpasswd-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kpasswd-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kpasswd-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kpasswd.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'

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
    log "kpasswd.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^kpasswd ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "kpasswd.gate" "error" ',"error":"kpasswd 464 did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kpasswd-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kpasswd
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
        kpasswd_server = 127.0.0.1
    }
EOF'

echo "==== MIT kpasswd once ===="
set +e
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\nkpasswd-one\nkpasswd-one\n" | kpasswd user@KERBER.TEST'
kp1=$?
set -e
if [ "$kp1" -ne 0 ]; then
    echo "==== kadmind.log ===="
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    echo "==== kdc.log ===="
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kpasswd.gate" "error" ',"error":"kpasswd once failed"'
    exit 1
fi
echo "==== kinit kpasswd-one ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-one\n" | kinit user@KERBER.TEST'
KLIST1="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" klist)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'user@KERBER.TEST'

echo "==== old password must fail ===="
set +e
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
old_rc=$?
set -e
if [ "$old_rc" -eq 0 ]; then
    log "kpasswd.gate" "error" ',"error":"old password still kinit-able"'
    exit 1
fi

echo "==== MIT kpasswd twice ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-one\nkpasswd-two\nkpasswd-two\n" | kpasswd user@KERBER.TEST'
echo "==== kinit kpasswd-two ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-two\n" | kinit user@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'user@KERBER.TEST'

log "kpasswd.gate" "ok" ',"principal":"user@KERBER.TEST","op":"kpasswd+kinit"'
exit 0
