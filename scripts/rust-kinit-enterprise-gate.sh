#!/usr/bin/env bash
# NT-ENTERPRISE both directions: MIT kinit -E vs Rust KDC, and Rust kinit -E vs MIT KDC.
# klist default principal must be the canonical user@KERBER.TEST.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rust-kinit-enterprise-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

assert_canonical() {
    local klist="$1"
    echo "$klist"
    echo "$klist" | grep -q 'Default principal: user@KERBER.TEST'
    if echo "$klist" | grep -q 'Default principal: user@KERBER.TEST@KERBER.TEST'; then
        log "enterprise.gate" "error" ',"error":"enterprise string leaked as cname"'
        exit 1
    fi
    echo "$klist" | grep -q 'user@KERBER.TEST'
}

if ! command -v docker >/dev/null 2>&1; then
    log "enterprise.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-client --bin krb5-kinit
cargo build -p krb5-kdc --bin krb5-kdc

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

# --- Rust kinit -E vs MIT KDC ---
NAME="kerber-rust-kinit-enterprise-mit"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
cleanup_mit() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup_mit EXIT

ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        log "enterprise.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "enterprise.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

echo "==== Rust kinit -E vs MIT KDC ===="
set +e
OUT="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -E -c /tmp/krb5cc_ent user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "enterprise.gate" "error" ',"error":"rust kinit -E vs MIT failed","rc":'"$rc"
    exit 1
fi
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_ent 2>/dev/null || true)"
assert_canonical "$KLIST"
echo "==== Rust kinit -E mixed-case UPN vs MIT KDC (must fail) ===="
set +e
OUT="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -E -c /tmp/krb5cc_ent_lc user@kerber.test 2>&1)"
rc=$?
set -e
echo "$OUT"
test "$rc" -ne 0
echo "$OUT" | grep -Eqi 'CLIENT_NOT_FOUND|C_PRINCIPAL_UNKNOWN|not found'
cleanup_mit
trap - EXIT

# --- MIT kinit -E vs Rust KDC ---
NAME="kerber-rust-kinit-enterprise-kdc"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup_kdc() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup_kdc EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker exec "$NAME" chmod +x /tmp/krb5-kdc
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
if [ "$ok" -ne 1 ]; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "enterprise.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi
LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac
docker exec "$NAME" sh -c "cat >> /etc/krb5.conf <<EOF

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:${PORT}
    }
EOF"

echo "==== MIT kinit -E vs Rust KDC ===="
set +e
docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "%s\n" userpassword | kinit -E user@KERBER.TEST'
rc=$?
set -e
KLIST="$(docker exec "$NAME" klist 2>/dev/null || true)"
if [ "$rc" -ne 0 ]; then
    echo "==== rust KDC log ===="
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    echo "$KLIST"
    log "enterprise.gate" "error" ',"error":"mit kinit -E vs rust failed","rc":'"$rc"
    exit 1
fi
assert_canonical "$KLIST"
echo "==== MIT kinit -E mixed-case UPN vs Rust KDC (must fail) ===="
set +e
MIXOUT="$(docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "%s\n" userpassword | kinit -E user@kerber.test' 2>&1)"
rc=$?
set -e
echo "$MIXOUT"
test "$rc" -ne 0
echo "$MIXOUT" | grep -Eqi 'Client not found|not found|C_PRINCIPAL_UNKNOWN'
log "enterprise.gate" "ok" ',"mode":"both","principal":"user@KERBER.TEST","mixed_case":"refused"'
exit 0
