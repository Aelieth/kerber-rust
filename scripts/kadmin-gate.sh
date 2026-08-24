#!/usr/bin/env bash
# MIT 1.22.2 kadmin addprinc + cpw against Rust kadmind (GSS-RPC 749).
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kadmin-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
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
    log "kadmin.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
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
    log "kadmin.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadmin-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kadmin
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'
echo "==== MIT kadmin addprinc extra ===="
ADD="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra' 2>&1 || true)"
echo "$ADD"
echo "==== kadmind log ===="
docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true
echo "==== kdc log (tail) ===="
docker exec "$NAME" tail -20 /tmp/kdc.log 2>/dev/null || true
echo "==== kinit extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-secret\n" | kinit extra@KERBER.TEST' || true
echo "==== kdc log after extra kinit ===="
docker exec "$NAME" grep -E 'reload store|persist |CLIENT|saved store|error' /tmp/kdc.log | tail -30 || true
docker exec "$NAME" ls -l /tmp/principal /tmp/stash 2>/dev/null || true
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin cpw extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw extra-rotated extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'extra@KERBER.TEST'

log "kadmin.gate" "ok" ',"principal":"extra@KERBER.TEST","op":"addprinc+cpw"'
exit 0

