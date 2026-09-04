#!/usr/bin/env bash
# MIT 1.22.2 kadmin getprivs vs Rust kadmind: limited ACL actor is not 0x3F.
# Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-getprivs-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-getprivs-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"getprivs-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "getprivs.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/getprivs-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "getprivs.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/getprivs-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *
limited@KERBER.TEST i
EOF'

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_MASTER_PASSWORD=masterpassword \
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
    log "getprivs.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "getprivs.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/getprivs-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_getprivs
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/getprivs-krb5.conf \
        "$NAME" kadmin -p "$1" -w "$2" -q "$3" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/getprivs-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== admin getprivs is full ===="
ADMINP="$(kadmin_q admin@KERBER.TEST adminpassword getprivs)"
echo "$ADMINP"
echo "$ADMINP" | grep -qiE 'INQUIRE|GET'
echo "$ADMINP" | grep -qi ADD
echo "$ADMINP" | grep -qi MODIFY

echo "==== addprinc limited ===="
ADD="$(kadmin_q admin@KERBER.TEST adminpassword 'addprinc -pw limited-secret limited')"
echo "$ADD"

echo "==== limited getprivs is all bits like MIT ~0 ===="
docker exec -e KRB5_CONFIG=/tmp/getprivs-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/getprivs-krb5.conf \
    "$NAME" sh -c 'printf "limited-secret\n" | kinit limited@KERBER.TEST'
LIMP="$(kadmin_q limited@KERBER.TEST limited-secret getprivs)"
echo "$LIMP"
echo "$LIMP" | grep -qiE 'INQUIRE|GET'
echo "$LIMP" | grep -qi ADD
echo "$LIMP" | grep -qi MODIFY

echo "==== limited cpw -randkey is AUTH_CHANGEPW ===="
RAND="$(kadmin_q limited@KERBER.TEST limited-secret 'cpw -randkey user')"
echo "$RAND"
echo "$RAND" | grep -qi 'change-password'
if echo "$RAND" | grep -qi "Operation requires \`\`get'' privilege"; then
    echo "chrand ACL denial was AUTH_GET, want AUTH_CHANGEPW: $RAND" >&2
    exit 1
fi
if echo "$RAND" | grep -qiE 'randomized|changed'; then
    echo "limited randkey succeeded: $RAND" >&2
    exit 1
fi

log "getprivs.gate" "ok" ',"admin_full":true,"limited_getprivs_all_ones":true,"limited_chrand_auth_changepw":true'
exit 0
