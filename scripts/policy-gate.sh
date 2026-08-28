#!/usr/bin/env bash
# MIT 1.22.2 kadmin policy verbs against Rust kadmind, then MIT kinit lockout.
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-policy-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-policy-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"policy-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "policy.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/policy-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "policy.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/policy-unavailable.log"
    exit 2
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
    log "policy.gate" "error" ',"error":"kdc did not listen"'
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
    log "policy.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/policy-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_policy
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== MIT kadmin addpol lockme ===="
ADD="$(kadmin_q 'addpol -minlength 8 -minclasses 2 -maxfailure 1 lockme')"
echo "$ADD"

echo "==== MIT kadmin getpol lockme ===="
GET="$(kadmin_q 'getpol lockme')"
echo "$GET"
echo "$GET" | grep -q 'Policy: lockme'
echo "$GET" | grep -q 'Minimum password length: 8'
echo "$GET" | grep -qiE 'Maximum password failures.*1|failures before lockout: 1'

echo "==== MIT kadmin listpols ===="
LIST="$(kadmin_q 'listpols')"
echo "$LIST"
echo "$LIST" | grep -q 'lockme'

echo "==== MIT kadmin modpol -minlength 10 lockme ===="
kadmin_q 'modpol -minlength 10 lockme' >/dev/null
GET2="$(kadmin_q 'getpol lockme')"
echo "$GET2"
echo "$GET2" | grep -q 'Minimum password length: 10'
echo "$GET2" | grep -qiE 'Maximum password failures.*1|failures before lockout: 1'

echo "==== MIT kadmin addprinc -policy lockme lockuser ===="
ADDPR="$(kadmin_q 'addprinc -policy lockme -pw lock-secret lockuser')"
echo "$ADDPR"
GETPR="$(kadmin_q 'getprinc lockuser')"
echo "$GETPR"
echo "$GETPR" | grep -q 'Principal: lockuser@KERBER.TEST'
echo "$GETPR" | grep -q 'Policy: lockme'

echo "==== MIT kinit lockuser wrong then lockout ===="
WRONG="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit lockuser@KERBER.TEST' 2>&1 || true)"
echo "$WRONG"
LOCKED="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "lock-secret\n" | kinit lockuser@KERBER.TEST' 2>&1 || true)"
echo "$LOCKED"
echo "$LOCKED" | grep -qiE 'revoked|CLIENT_REVOKED'

echo "==== MIT kadmin delpol lockme ===="
kadmin_q 'delpol -force lockme' >/dev/null
DELGET="$(kadmin_q 'getpol lockme')"
echo "$DELGET"
echo "$DELGET" | grep -qiE 'does not exist|not found|UNK|unknown policy'

log "policy.gate" "ok" ',"policy":"lockme","op":"addpol+getpol+listpols+modpol+lockout+delpol"'
exit 0
