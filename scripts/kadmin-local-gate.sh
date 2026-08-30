#!/usr/bin/env bash
# Rust kadmin.local mutates the dump; MIT kadmin getprinc/listprincs is the oracle.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-local-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kadmin-local-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.local.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind --bin krb5-kadmin-local

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker cp target/debug/krb5-kadmin-local "$NAME":/tmp/krb5-kadmin-local
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind /tmp/krb5-kadmin-local

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
    log "kadmin.local.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

echo "==== Rust kadmin.local addprinc/listprincs/getprinc ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=extra-local \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc extra2'
LIST="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'listprincs')"
echo "$LIST"
echo "$LIST" | grep -q 'extra2@KERBER.TEST'
GET="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc extra2')"
echo "$GET"
echo "$GET" | grep -q 'Principal: extra2@KERBER.TEST'

echo "==== Rust kadmin.local addprinc host/slashhost ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=slash-local \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc host/slashhost'
SLASH="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc host/slashhost')"
echo "$SLASH"
echo "$SLASH" | grep -q 'Principal: host/slashhost@KERBER.TEST'

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *e
EOF'

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen"'
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

echo "==== MIT kadmin getprinc/listprincs extra2 ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'
MITGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra2')"
echo "$MITGET"
echo "$MITGET" | grep -q 'extra2@KERBER.TEST'
MITLIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs extra2*')"
echo "$MITLIST"
echo "$MITLIST" | grep -q 'extra2@KERBER.TEST'

echo "==== MIT kadmin getprinc host/slashhost ===="
MITSLASH="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc host/slashhost')"
echo "$MITSLASH"
echo "$MITSLASH" | grep -q 'Principal: host/slashhost@KERBER.TEST'
echo "$MITSLASH" | grep -qi 'does not exist' && {
    log "kadmin.local.gate" "error" ',"error":"MIT did not find host/slashhost as two components"'
    exit 1
}
log "kadmin.local.gate" "ok" ',"principal":"extra2@KERBER.TEST,host/slashhost@KERBER.TEST"'
exit 0
