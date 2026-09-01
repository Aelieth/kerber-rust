#!/usr/bin/env bash
# Three-hop A.TEST → B.TEST → C.TEST. MIT 1.22.2 KDCs are the transited-field
# oracle; MIT kvno is the client. Isolation: throwaway container only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-capaths-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
XR_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
XR_PW="xrpassword"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"capaths-transit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "capaths.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract

docker exec -i "$NAME" bash -s <<'CONF'
set -euo pipefail
cat >/tmp/client-capaths.conf <<EOF
[libdefaults]
    default_realm = A.TEST
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_capaths
[realms]
    A.TEST = {
        kdc = 127.0.0.1:88
    }
    B.TEST = {
        kdc = 127.0.0.1:89
    }
    C.TEST = {
        kdc = 127.0.0.1:90
    }
[domain_realm]
    .a.test = A.TEST
    .b.test = B.TEST
    .c.test = C.TEST
[capaths]
    A.TEST = {
        C.TEST = B.TEST
        B.TEST = .
    }
    C.TEST = {
        A.TEST = B.TEST
    }
EOF
write_kdc_conf() {
    local realm="$1" port="$2" db="$3"
    cat >"/tmp/kdc-${realm%%.*}.conf" <<EOF
[kdcdefaults]
    kdc_ports = ${port}
    kdc_tcp_ports = ${port}
[realms]
    ${realm} = {
        database_name = ${db}/principal
        key_stash_file = ${db}/.k5.${realm}
        acl_file = /var/kerberos/krb5kdc/kadm5.acl
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }
EOF
}
mkdir -p /tmp/db-a /tmp/db-b /tmp/db-c
write_kdc_conf A.TEST 88 /tmp/db-a
write_kdc_conf B.TEST 89 /tmp/db-b
write_kdc_conf C.TEST 90 /tmp/db-c
cat >/tmp/kdc-c-allow.conf <<EOF
[libdefaults]
    default_realm = C.TEST
    dns_lookup_kdc = false
[capaths]
    A.TEST = {
        C.TEST = B.TEST
    }
EOF
cat >/tmp/kdc-c-deny.conf <<EOF
[libdefaults]
    default_realm = C.TEST
    dns_lookup_kdc = false
EOF
CONF

setup_mit_realm() {
    local realm="$1" profile="$2"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_KDC_PROFILE="$profile" \
        "$NAME" kdb5_util -r "$realm" create -s -P masterpassword >/dev/null
}

echo "==== MIT kdb5_util A/B/C ===="
setup_mit_realm A.TEST /tmp/kdc-A.conf
setup_mit_realm B.TEST /tmp/kdc-B.conf
setup_mit_realm C.TEST /tmp/kdc-C.conf

docker exec -i -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" bash -s <<EOF
set -euo pipefail
kad() {
    local profile="\$1"
    local realm="\$2"
    shift 2
    KRB5_KDC_PROFILE="\$profile" kadmin.local -r "\$realm" -q "\$*"
}
kad /tmp/kdc-A.conf A.TEST "addprinc -pw userpassword user"
kad /tmp/kdc-A.conf A.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/B.TEST@A.TEST"
kad /tmp/kdc-B.conf B.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/B.TEST@A.TEST"
kad /tmp/kdc-B.conf B.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/C.TEST@B.TEST"
kad /tmp/kdc-C.conf C.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/C.TEST@B.TEST"
kad /tmp/kdc-C.conf C.TEST "addprinc -randkey host/svc.c.test"
kad /tmp/kdc-C.conf C.TEST "ktadd -k /tmp/mit-c.host.kt host/svc.c.test"
EOF

start_mit() {
    local realm="$1" profile="$2" log="$3" pidf="$4"
    docker exec \
        -e KRB5_CONFIG=/tmp/client-capaths.conf \
        -e KRB5_KDC_PROFILE="$profile" \
        "$NAME" sh -c "krb5kdc -n -r ${realm} >${log} 2>&1 & echo \$! >${pidf}"
}

wait_port() {
    local port="$1"
    local i
    for i in $(seq 1 80); do
        if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',${port}),0.3)" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

echo "==== MIT krb5kdc A/B/C ===="
start_mit A.TEST /tmp/kdc-A.conf /tmp/mit-a.log /tmp/mit-a.pid
start_mit B.TEST /tmp/kdc-B.conf /tmp/mit-b.log /tmp/mit-b.pid
start_mit C.TEST /tmp/kdc-C.conf /tmp/mit-c.log /tmp/mit-c.pid
wait_port 88
wait_port 89
wait_port 90 || {
    echo "==== MIT KDC logs ===="
    docker exec "$NAME" sh -c 'cat /tmp/mit-a.log /tmp/mit-b.log /tmp/mit-c.log' || true
    log "capaths.gate" "error" ',"error":"MIT KDCs did not listen"'
    exit 1
}

chase() {
    local cc="$1"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        sh -c "printf 'userpassword\n' | kinit -c ${cc} user@A.TEST"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
        kvno -c "$cc" host/svc.c.test@C.TEST
}

echo "==== MIT kvno vs MIT KDCs (permitted) ===="
set +e
MIT_CHASE="$(chase /tmp/krb5cc_mit 2>&1)"
mit_rc=$?
set -e
echo "$MIT_CHASE"
if [ "$mit_rc" -ne 0 ]; then
    docker exec "$NAME" sh -c 'cat /tmp/mit-a.log /tmp/mit-b.log /tmp/mit-c.log' || true
    log "capaths.gate" "error" ',"error":"MIT KDC 3-hop kvno failed","rc":'"$mit_rc"
    exit 1
fi
echo "$MIT_CHASE" | grep -q 'host/svc.c.test@C.TEST: kvno ='
MIT_FLAGS="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -f -c /tmp/krb5cc_mit)"
echo "$MIT_FLAGS"
echo "$MIT_FLAGS" | awk '/host\/svc.c.test/{p=1;next} p&&/Flags:/{print;exit}' | grep -q T
MIT_DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/mit-c.host.kt --ccache /tmp/krb5cc_mit --print-transited)"
echo "$MIT_DUMP"
echo "$MIT_DUMP" | grep -q '^transited_policy_checked=1$'
MIT_TR_TYPE="$(echo "$MIT_DUMP" | sed -n 's/^transited_tr_type=//p')"
MIT_TR_CONTENTS="$(echo "$MIT_DUMP" | sed -n 's/^transited_contents=//p')"

echo "==== stop MIT KDCs ===="
docker exec "$NAME" sh -c 'kill -9 $(cat /tmp/mit-a.pid /tmp/mit-b.pid /tmp/mit-c.pid 2>/dev/null) 2>/dev/null || true'
for _ in $(seq 1 20); do
    if docker exec "$NAME" python3 -c "
import socket
for p in (88, 89, 90):
    try:
        s = socket.create_connection(('127.0.0.1', p), 0.15)
        s.close()
        raise SystemExit(0)
    except OSError:
        pass
raise SystemExit(1)
" 2>/dev/null; then
        sleep 0.25
        continue
    fi
    break
done

start_ab() {
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=A.TEST \
        -e KRB5_TEST_FOREIGN_REALM=B.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.a.test \
        "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc-a.log 2>&1'
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=B.TEST \
        -e KRB5_TEST_FOREIGN_REALM=A.TEST,C.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.b.test \
        "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:89 >/tmp/kdc-b.log 2>&1'
}

start_c() {
    local conf="$1"
    local log="$2"
    docker exec \
        -e KRB5_CONFIG="$conf" \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=C.TEST \
        -e KRB5_TEST_FOREIGN_REALM=B.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.c.test \
        -e KRB5_EXPORT_KEYTAB=/tmp/rust-c.host.kt \
        "$NAME" sh -c "/tmp/krb5-kdc --test-realm 127.0.0.1:90 >$log 2>&1 & echo \$! >/tmp/kdc-c.pid"
}

wait_listen() {
    local log="$1"
    local i
    for i in $(seq 1 80); do
        if docker exec "$NAME" grep -q '^listening ' "$log" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

start_ab
start_c /tmp/kdc-c-allow.conf /tmp/kdc-c-allow.log
wait_listen /tmp/kdc-a.log
wait_listen /tmp/kdc-b.log
wait_listen /tmp/kdc-c-allow.log
echo "==== KDC A ===="
docker exec "$NAME" cat /tmp/kdc-a.log 2>/dev/null || true
echo "==== KDC B ===="
docker exec "$NAME" cat /tmp/kdc-b.log 2>/dev/null || true
echo "==== KDC C allow ===="
docker exec "$NAME" cat /tmp/kdc-c-allow.log 2>/dev/null || true

echo "==== MIT kvno vs Rust KDCs (permitted) ===="
set +e
RUST_CHASE="$(chase /tmp/krb5cc_rust 2>&1)"
rc=$?
set -e
echo "$RUST_CHASE"
if [ "$rc" -ne 0 ]; then
    log "capaths.gate" "error" ',"error":"permitted path kvno failed","rc":'"$rc"
    exit 1
fi
echo "$RUST_CHASE" | grep -q 'host/svc.c.test@C.TEST: kvno ='
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -f -c /tmp/krb5cc_rust 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@A.TEST'
echo "$KLIST" | grep -q 'krbtgt/B.TEST'
echo "$KLIST" | grep -q 'krbtgt/C.TEST'
echo "$KLIST" | grep -q 'host/svc.c.test'
echo "$KLIST" | awk '/host\/svc.c.test/{p=1;next} p&&/Flags:/{print;exit}' | grep -q T
RUST_DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/rust-c.host.kt --ccache /tmp/krb5cc_rust --print-transited)"
echo "$RUST_DUMP"
echo "$RUST_DUMP" | grep -q '^transited_policy_checked=1$'
RUST_TR_TYPE="$(echo "$RUST_DUMP" | sed -n 's/^transited_tr_type=//p')"
RUST_TR_CONTENTS="$(echo "$RUST_DUMP" | sed -n 's/^transited_contents=//p')"

echo "==== MIT vs Rust transited field ===="
echo "mit  tr_type=${MIT_TR_TYPE} contents=${MIT_TR_CONTENTS}"
echo "rust tr_type=${RUST_TR_TYPE} contents=${RUST_TR_CONTENTS}"
test "$MIT_TR_TYPE" = "$RUST_TR_TYPE"
test "$MIT_TR_CONTENTS" = "$RUST_TR_CONTENTS"

echo "==== restart C without capaths (rejected path) ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
sleep 1
start_c /tmp/kdc-c-deny.conf /tmp/kdc-c-deny.log
if ! wait_listen /tmp/kdc-c-deny.log; then
    echo "==== KDC C deny (did not listen) ===="
    docker exec "$NAME" cat /tmp/kdc-c-deny.log 2>/dev/null || true
    docker exec "$NAME" cat /tmp/kdc-c.pid 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"deny KDC C did not listen"'
    exit 1
fi
echo "==== KDC C deny ===="
docker exec "$NAME" cat /tmp/kdc-c-deny.log 2>/dev/null || true

docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_deny user@A.TEST" >/dev/null
set +e
DENY="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno -c /tmp/krb5cc_deny host/svc.c.test@C.TEST 2>&1)"
drc=$?
set -e
echo "$DENY"
test "$drc" -ne 0
echo "$DENY" | grep -q 'KDC policy rejects transited path'

log "capaths.gate" "ok" \
    ",\"path\":\"A.TEST>B.TEST>C.TEST\",\"permitted\":true,\"rejected\":true,\"transited_tr_type\":${MIT_TR_TYPE},\"transited_contents\":\"${MIT_TR_CONTENTS}\",\"transited_policy_checked\":true"
exit 0
