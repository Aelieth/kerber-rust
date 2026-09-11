#!/usr/bin/env bash
# MIT kvno -U / kvno -U -P against the Rust KDC (not AD). The mismatch
# cell also runs against the image's MIT KDC. Isolated inside the MIT
# 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-s4u-mit-gate"
MITNAME="${NAME}-oracle"
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

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract -p krb5-client --bin krb5-kvno

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" "$MITNAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker rm -f "$MITNAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        log "s4u.mit.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    log "s4u.mit.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

# The mismatch cell uses -U admin; the entrypoint only adds `user`.
docker exec "$NAME" kadmin.local -q "addprinc -randkey admin" >/dev/null
docker exec "$NAME" kadmin.local -q "addprinc -pw expirepw -pwexpire 19900101000000 expired" >/dev/null

docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"MIT kdc did not listen"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kvno" "$NAME":/tmp/krb5-kvno
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-pac-extract" "$NAME":/tmp/krb5-pac-extract
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kvno /tmp/krb5-pac-extract

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_LOCKED_USER=lock-secret \
    -e KRB5_TEST_PW_EXPIRED_USER=expirepw \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    -e KRB5_TEST_OK_TO_AUTH_AS_DELEGATE=1 \
    -e KRB5_TEST_S4U_TO=host/testhost.kerber.test -e KRB5_TEST_S4U_FROM=host/testhost.kerber.test@KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-keytab /tmp/host.keytab 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

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

docker exec "$NAME" sh -c 'cat >/tmp/s4u-mit.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_s4u_mit
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF
cat >/tmp/s4u-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_s4u
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
EOF'

if ! docker exec "$NAME" test -f /tmp/host.keytab; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"host keytab not exported"'
    exit 1
fi

expect_s4u_host_mismatch() {
    local label="$1"
    local conf="$2"
    local kdc_host="$3"
    local klog="$4"
    local cc="$5"
    echo "==== ${label}: user TGT + S4U2Self to host (mismatch, expect 36) ===="
    docker exec -e KRB5_CONFIG="$conf" \
        "$NAME" sh -c "printf 'userpassword\n' | kinit -c ${cc} user@KERBER.TEST"
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME="FILE:${cc}" \
        "$NAME" /tmp/krb5-kvno -U admin "$kdc_host" host/testhost.kerber.test@KERBER.TEST 2>&1)"
    rc=$?
    set -e
    echo "$out"
    echo "${label}_mismatch_rc=$rc"
    echo "$out" | grep -qiE "Ticket/authenticator don't match|BADMATCH|INVALID_S4U2SELF"
    echo "$rc" | grep -qx 1
    local new
    new="$(docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}")"
    echo "$new"
    echo "$new" | grep -q 'INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH'
    docker exec -e KRB5_CONFIG="$conf" "$NAME" kdestroy -c "$cc" >/dev/null 2>&1 || true
}

expect_s4u_host_mismatch "mit_kdc" /tmp/s4u-mit.conf 127.0.0.1 /tmp/mit-kdc.log /tmp/krb5cc_s4u_mit
expect_s4u_host_mismatch "rust_kdc" /tmp/s4u-krb5.conf 127.0.0.1:8888 /tmp/kdc.log /tmp/krb5cc_s4u

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

echo "==== without ok_to_auth_as_delegate keeps F (no allowed_to_delegate targets) ===="
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker exec "$NAME" chmod +x /tmp/krb5-kdc
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_PW_EXPIRED_USER=expirepw \
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
echo "$HOSTF2" | grep -q F

echo "==== MIT kvno -U expired (pw expired; S4U still issues) ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kvno -U expired host/testhost.kerber.test
KLISTE="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -f)"
echo "$KLISTE"
echo "$KLISTE" | grep -q 'for client expired@KERBER.TEST'

echo "==== PA-S4U-X509-USER 130+129 on the wire (padata proxy) ===="
docker cp "$ROOT/scripts/lib/kdc-padata-proxy.py" "$NAME":/tmp/kdc-padata-proxy.py
PROXY_TO=88
case "$LISTEN" in
    *:8888*) PROXY_TO=8888 ;;
esac
docker exec -d "$NAME" python3 /tmp/kdc-padata-proxy.py 1892 127.0.0.1 "$PROXY_TO" /tmp/s4u-padata.txt
sleep 0.3
docker exec "$NAME" sh -c "sed 's/${KDC_LINE}/kdc = 127.0.0.1:1892/' /tmp/s4u-krb5.conf | sed '/forwardable = true/a\\    udp_preference_limit = 10000' > /tmp/s4u-proxy.conf"
docker exec -e KRB5_CONFIG=/tmp/s4u-proxy.conf \
    "$NAME" kinit -f -k -t /tmp/host.keytab host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-proxy.conf \
    "$NAME" kvno -U user host/testhost.kerber.test
PADATA="$(docker exec "$NAME" cat /tmp/s4u-padata.txt)"
echo "$PADATA"
echo "$PADATA" | grep -E 'req#[0-9]+ msg_type=12 padata=\[' | grep -q '130'
echo "$PADATA" | grep -E 'req#[0-9]+ msg_type=12 padata=\[' | grep -q '129'
echo "$PADATA" | grep -E 'rep#[0-9]+ tag=0x6d' | grep -q '0x6d'

echo "==== MIT KDC db2: keep F, expired user, reply 130 ===="
docker rm -f "$MITNAME" >/dev/null 2>&1 || true
docker run -d --name "$MITNAME" "$IMAGE" >/dev/null
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$MITNAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        log "s4u.mit.gate" "error" ',"error":"MIT oracle harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    log "s4u.mit.gate" "error" ',"error":"MIT oracle harness did not become ready"'
    docker logs "$MITNAME" >&2 || true
    exit 1
fi
docker exec "$MITNAME" kadmin.local -q "addprinc -pw expirepw expired"
EXPOUT="$(docker exec "$MITNAME" kadmin.local -q "modprinc -pwexpire 1/1/1990 expired")"
echo "$EXPOUT"
echo "$EXPOUT" | grep -qi 'invalid date' && exit 1
GETEXP="$(docker exec "$MITNAME" kadmin.local -q "getprinc expired")"
echo "$GETEXP"
echo "$GETEXP" | grep -i 'Password expiration date' | grep -qv never
docker exec "$MITNAME" sh -c 'cat >/tmp/s4u-mit-oracle.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    udp_preference_limit = 10000
    default_ccache_name = FILE:/tmp/krb5cc_s4u_mit_oracle
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF'
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kinit -f -k -t /etc/krb5kdc/testhost.keytab host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kvno -U user host/testhost.kerber.test
KLISTM="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf "$MITNAME" klist -f)"
echo "$KLISTM"
HOSTFM="$(echo "$KLISTM" | sed -n 's/.*for client user@KERBER.TEST.*Flags: //p')"
echo "s4u_flags_mit_db2_without_ok_to_auth=$HOSTFM"
test -n "$HOSTFM"
echo "$HOSTFM" | grep -q F
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kvno -U expired host/testhost.kerber.test
KLISTME="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf "$MITNAME" klist -f)"
echo "$KLISTME"
echo "$KLISTME" | grep -q 'for client expired@KERBER.TEST'
docker cp "$ROOT/scripts/lib/kdc-padata-proxy.py" "$MITNAME":/tmp/kdc-padata-proxy.py
docker exec -d "$MITNAME" python3 /tmp/kdc-padata-proxy.py 1892 127.0.0.1 88 /tmp/s4u-mit-padata.txt
sleep 0.3
docker exec "$MITNAME" sh -c "sed 's/kdc = 127.0.0.1/kdc = 127.0.0.1:1892/' /tmp/s4u-mit-oracle.conf > /tmp/s4u-mit-proxy.conf"
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-proxy.conf \
    "$MITNAME" kinit -f -k -t /etc/krb5kdc/testhost.keytab host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-proxy.conf \
    "$MITNAME" kvno -U user host/testhost.kerber.test
MPADATA="$(docker exec "$MITNAME" cat /tmp/s4u-mit-padata.txt)"
echo "$MPADATA"
echo "$MPADATA" | grep -E 'req#[0-9]+ msg_type=12 padata=\[' | grep -q '130'
echo "$MPADATA" | grep -E 'req#[0-9]+ msg_type=12 padata=\[' | grep -q '129'
echo "$MPADATA" | grep -E 'rep#[0-9]+ tag=0x6d' | grep -q '0x6d'

echo "==== MIT kvno -U user -P krbtgt (TGS-target POLICY 12) rust ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kinit -f -k -t /tmp/host.keytab host/testhost.kerber.test@KERBER.TEST
set +e
TGST_RUST="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kvno -U user -P krbtgt/KERBER.TEST 2>&1)"
set -e
echo "$TGST_RUST"
echo "$TGST_RUST" | grep -qiE "KDC policy rejects request|NOT_ALLOWED_TO_DELEGATE"

echo "==== MIT kvno -U user -P krbtgt (TGS-target POLICY 12) mit ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kinit -f -k -t /etc/krb5kdc/testhost.keytab host/testhost.kerber.test@KERBER.TEST
set +e
TGST_MIT="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kvno -U user -P krbtgt/KERBER.TEST 2>&1)"
set -e
echo "$TGST_MIT"
echo "$TGST_MIT" | grep -qiE "KDC policy rejects request|NOT_ALLOWED_TO_DELEGATE"
echo "MIT_s4u2proxy_tgs_target"

echo "==== MIT kvno --u2u happy rust ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_u2u_user user@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kinit -k -t /tmp/host.keytab -c /tmp/krb5cc_u2u_host host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_u2u_user \
    "$NAME" kvno --u2u FILE:/tmp/krb5cc_u2u_host host/testhost.kerber.test
U2U_RUST="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" klist -c /tmp/krb5cc_u2u_user)"
echo "$U2U_RUST"
echo "$U2U_RUST" | grep -q 'host/testhost.kerber.test'

echo "==== MIT kvno --u2u happy mit ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_u2u_user user@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kinit -k -t /etc/krb5kdc/testhost.keytab -c /tmp/krb5cc_u2u_host \
    host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_u2u_user \
    "$MITNAME" kvno --u2u FILE:/tmp/krb5cc_u2u_host host/testhost.kerber.test
U2U_MIT="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" klist -c /tmp/krb5cc_u2u_user)"
echo "$U2U_MIT"
echo "$U2U_MIT" | grep -q 'host/testhost.kerber.test'
echo "MIT_u2u_happy"

echo "==== MIT kvno --u2u -allow_dup_skey rust ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true'
sleep 0.3
docker exec "$NAME" sh -c 'sed -i "s/kdc = 127.0.0.1.*/kdc = 127.0.0.1:8888/" /tmp/s4u-krb5.conf'
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_DISALLOW_DUP_SKEY=1 \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-keytab /tmp/host.keytab 127.0.0.1:8888 >/tmp/kdc-dup.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-dup.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc-dup.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"kdc did not listen (dup_skey)"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_u2u_dup user@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" kinit -k -t /tmp/host.keytab -c /tmp/krb5cc_u2u_dup_host \
    host/testhost.kerber.test@KERBER.TEST
set +e
U2U_DUP_RUST="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_u2u_dup \
    "$NAME" kvno --u2u FILE:/tmp/krb5cc_u2u_dup_host host/testhost.kerber.test 2>&1)"
set -e
echo "$U2U_DUP_RUST"
echo "$U2U_DUP_RUST" | grep -qiE "KDC policy rejects request|DUP_SKEY DISALLOWED"

echo "==== MIT kvno --u2u -allow_dup_skey mit ===="
docker exec "$MITNAME" kadmin.local -q "modprinc -allow_dup_skey host/testhost.kerber.test"
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_u2u_dup user@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kinit -k -t /etc/krb5kdc/testhost.keytab -c /tmp/krb5cc_u2u_dup_host \
    host/testhost.kerber.test@KERBER.TEST
set +e
U2U_DUP_MIT="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_u2u_dup \
    "$MITNAME" kvno --u2u FILE:/tmp/krb5cc_u2u_dup_host host/testhost.kerber.test 2>&1)"
set -e
echo "$U2U_DUP_MIT"
echo "$U2U_DUP_MIT" | grep -qiE "KDC policy rejects request|DUP_SKEY DISALLOWED"

echo "==== MIT kinit -a then kvno via 127.0.0.1 rust ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_addr -a user@KERBER.TEST'
KLIST_AR="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -a -n -c /tmp/krb5cc_addr)"
echo "$KLIST_AR"
echo "$KLIST_AR" | grep -qE 'Addresses: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
set +e
KVNO_AR="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_addr \
    "$NAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$KVNO_AR"
echo "$KVNO_AR" | grep -qiE "Incorrect net address|BADADDR|KRB5KRB_AP_ERR_BADADDR"

echo "==== MIT kinit -a then kvno via 127.0.0.1 mit ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_addr -a user@KERBER.TEST'
KLIST_AM="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf "$MITNAME" klist -a -n -c /tmp/krb5cc_addr)"
echo "$KLIST_AM"
echo "$KLIST_AM" | grep -qE 'Addresses: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
set +e
KVNO_AM="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_addr \
    "$MITNAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$KVNO_AM"
echo "$KVNO_AM" | grep -qiE "Incorrect net address|BADADDR|KRB5KRB_AP_ERR_BADADDR"

echo "==== MIT kinit -a + kvno via bridge rust ===="
BRIDGE="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_DISALLOW_DUP_SKEY=1 \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-keytab /tmp/host.keytab 0.0.0.0:8888 >/tmp/kdc-bridge.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-bridge.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc-bridge.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"kdc did not listen on 0.0.0.0"'
    exit 1
fi
docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1.*/kdc = ${BRIDGE}:8888/' /tmp/s4u-krb5.conf"
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_addrb -a user@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_addrb \
    "$NAME" kvno host/testhost.kerber.test
KLIST_BR="$(docker exec -e KRB5_CONFIG=/tmp/s4u-krb5.conf "$NAME" klist -a -n -c /tmp/krb5cc_addrb)"
echo "$KLIST_BR"
echo "$KLIST_BR" | grep -q 'host/testhost.kerber.test'
echo "$KLIST_BR" | grep -qE 'Addresses: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

echo "==== MIT kinit -a + kvno via bridge mit ===="
MBRIDGE="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$MITNAME")"
docker exec "$MITNAME" sh -c "sed -i 's/kdc = 127.0.0.1.*/kdc = ${MBRIDGE}/' /tmp/s4u-mit-oracle.conf"
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_addrb -a user@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_addrb \
    "$MITNAME" kvno host/testhost.kerber.test
KLIST_BM="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf "$MITNAME" klist -a -n -c /tmp/krb5cc_addrb)"
echo "$KLIST_BM"
echo "$KLIST_BM" | grep -q 'host/testhost.kerber.test'
echo "$KLIST_BM" | grep -qE 'Addresses: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
echo "MIT_kinit_a_both_legs"

echo "==== MIT test-KDB kvno -U user -P (classic S4U2Proxy happy) ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-pac-extract" "$NAME":/tmp/krb5-pac-extract
docker exec "$NAME" chmod +x /tmp/krb5-pac-extract
docker exec "$NAME" sh -c 'cat >/tmp/test-kdc.conf <<EOF
[kdcdefaults]
    kdc_listen = 127.0.0.1:8890
    kdc_tcp_listen = 127.0.0.1:8890
[realms]
    KERBER.TEST = {
        database_module = test
    }
[dbmodules]
    test = {
        db_library = test
        princs = {
            krbtgt/KERBER.TEST = {
                keys = aes256-cts
            }
            user = {
                keys = aes256-cts
            }
            host/testhost.kerber.test = {
                flags = +ok-to-auth-as-delegate
                keys = aes256-cts
            }
            host/rbcd.kerber.test = {
                keys = aes256-cts
            }
        }
        delegation = {
            host/testhost.kerber.test = host/testhost.kerber.test
        }
        rbcd = {
            host/rbcd.kerber.test@KERBER.TEST = host/testhost.kerber.test@KERBER.TEST
        }
    }
[logging]
    kdc = FILE:/tmp/mit-test.log
EOF
cat >/tmp/test-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_testkdb
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8890
    }
[dbmodules]
    db_module_dir = /usr/lib/krb5/plugins/kdb
EOF'
docker exec -e KRB5_CONFIG=/tmp/test-krb5.conf -e KRB5_KDC_PROFILE=/tmp/test-kdc.conf \
    "$NAME" kadmin.local -r KERBER.TEST -q \
    'ktadd -norandkey -k /tmp/test-host.kt host/testhost.kerber.test'
docker exec -d -e KRB5_CONFIG=/tmp/test-krb5.conf -e KRB5_KDC_PROFILE=/tmp/test-kdc.conf \
    "$NAME" sh -c 'krb5kdc -n -P /tmp/mit-test.pid >/tmp/mit-test-stdout.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',8890),0.2)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-test.log >&2 || true
    docker exec "$NAME" cat /tmp/mit-test-stdout.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"MIT test-KDB kdc did not listen"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/test-krb5.conf \
    "$NAME" kinit -f -k -t /tmp/test-host.kt -c /tmp/krb5cc_mit_testkdb \
    host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/test-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_mit_testkdb \
    "$NAME" kvno -U user -P host/testhost.kerber.test
MIT_TK="$(docker exec -e KRB5_CONFIG=/tmp/test-krb5.conf \
    "$NAME" klist -f -c /tmp/krb5cc_mit_testkdb)"
echo "$MIT_TK"
echo "$MIT_TK" | grep -q 'for client user@KERBER.TEST'
MIT_TF="$(echo "$MIT_TK" | sed -n 's/.*for client user@KERBER.TEST, Flags: //p' | tail -1)"
echo "s4u2proxy_flags_mit_testkdb=$MIT_TF"
test -n "$MIT_TF"
echo "$MIT_TF" | grep -q F
MIT_PAC="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/test-host.kt \
    --ccache /tmp/krb5cc_mit_testkdb --last --print-types --print-delegation)"
echo "$MIT_PAC"
echo "$MIT_PAC" | grep -q 'pac_types='
echo "$MIT_PAC" | grep -qE 'pac_types=.*\b11\b'
echo "$MIT_PAC" | grep -q 'proxy_target=host/testhost.kerber.test'
echo "$MIT_PAC" | grep -q 'transited_services=host/testhost.kerber.test@KERBER.TEST'

echo "==== Rust kvno -U user -P (classic S4U2Proxy happy) ===="
docker exec "$NAME" sh -c 'for p in /proc/[0-9]*; do comm=$(cat "$p/comm" 2>/dev/null) || continue; [ "$comm" = krb5-kdc ] || continue; kill -9 "${p#/proc/}" 2>/dev/null || true; done'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',8888),0.15)" 2>/dev/null; then
        sleep 0.2
        continue
    fi
    ok=1
    break
done
[ "$ok" = 1 ]
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host-r18.keytab \
    -e KRB5_EXPORT_KEYTAB_EXTRA=/tmp/host-rbcd.keytab \
    -e KRB5_TEST_OK_TO_AUTH_AS_DELEGATE=1 \
    -e KRB5_TEST_S4U_TO=host/testhost.kerber.test \
    -e KRB5_TEST_EXTRA_HOST=rbcd.kerber.test \
    -e KRB5_TEST_S4U_FROM=host/testhost.kerber.test@KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-keytab /tmp/host-r18.keytab 127.0.0.1:8888 >/tmp/kdc-r18.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-r18.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc-r18.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"Rust KDC for S4U2Proxy happy did not listen"'
    exit 1
fi
docker exec "$NAME" sh -c 'cat >/tmp/s4u-r18.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_r18
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
EOF'
docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf \
    "$NAME" kinit -f -k -t /tmp/host-r18.keytab -c /tmp/krb5cc_rust_s4u2p \
    host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_rust_s4u2p \
    "$NAME" kvno -U user -P host/testhost.kerber.test
RUST_TK="$(docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf \
    "$NAME" klist -f -c /tmp/krb5cc_rust_s4u2p)"
echo "$RUST_TK"
echo "$RUST_TK" | grep -q 'for client user@KERBER.TEST'
RUST_TF="$(echo "$RUST_TK" | sed -n 's/.*for client user@KERBER.TEST, Flags: //p' | tail -1)"
echo "s4u2proxy_flags_rust=$RUST_TF"
test -n "$RUST_TF"
echo "$RUST_TF" | grep -q F
RUST_PAC="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/host-r18.keytab \
    --ccache /tmp/krb5cc_rust_s4u2p --last --print-types --print-delegation)"
echo "$RUST_PAC"
echo "$RUST_PAC" | grep -q 'pac_types='
echo "$RUST_PAC" | grep -qE 'pac_types=.*\b11\b'
echo "$RUST_PAC" | grep -q 'proxy_target=host/testhost.kerber.test'
echo "$RUST_PAC" | grep -q 'transited_services=host/testhost.kerber.test@KERBER.TEST'
echo "MIT_testkdb_s4u2proxy_happy"

echo "==== MIT test-KDB kvno -U user -P (RBCD) ===="
docker exec -e KRB5_CONFIG=/tmp/test-krb5.conf -e KRB5_KDC_PROFILE=/tmp/test-kdc.conf \
    "$NAME" kadmin.local -r KERBER.TEST -q \
    'ktadd -norandkey -k /tmp/test-rbcd.kt host/rbcd.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/test-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_mit_testkdb \
    "$NAME" kvno -U user -P host/rbcd.kerber.test
MIT_RBCD="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/test-rbcd.kt \
    --ccache /tmp/krb5cc_mit_testkdb --last --print-types --print-delegation)"
echo "$MIT_RBCD"
echo "$MIT_RBCD" | grep -qE 'pac_types=.*\b11\b'
echo "$MIT_RBCD" | grep -q 'proxy_target=host/rbcd.kerber.test'
echo "$MIT_RBCD" | grep -q 'transited_services=host/testhost.kerber.test@KERBER.TEST'

echo "==== Rust kvno -U user -P (RBCD) ===="
docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_rust_s4u2p \
    "$NAME" kvno -U user -P host/rbcd.kerber.test
RUST_RBCD="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/host-rbcd.keytab \
    --ccache /tmp/krb5cc_rust_s4u2p --last --print-types --print-delegation)"
echo "$RUST_RBCD"
echo "$RUST_RBCD" | grep -qE 'pac_types=.*\b11\b'
echo "$RUST_RBCD" | grep -q 'proxy_target=host/rbcd.kerber.test'
echo "$RUST_RBCD" | grep -q 'transited_services=host/testhost.kerber.test@KERBER.TEST'
echo "MIT_testkdb_s4u2proxy_rbcd"
echo "explicit_rbcd_grant=host/testhost.kerber.test@KERBER.TEST"

echo "==== MIT db2 kvno -U user -P (no delegation hook) ===="
docker exec "$MITNAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d "$MITNAME" sh -c 'krb5kdc -n >/tmp/mit-db2-r22.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$MITNAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$MITNAME" cat /tmp/mit-db2-r22.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"MIT db2 kdc did not listen (r22)"'
    exit 1
fi
n="$(docker exec "$MITNAME" sh -c "wc -l < /tmp/mit-db2-r22.log" | tr -d '[:space:]')"
docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    "$MITNAME" kinit -f -k -t /etc/krb5kdc/testhost.keytab -c /tmp/krb5cc_r22_db2 \
    host/testhost.kerber.test@KERBER.TEST
set +e
DB2_P="$(docker exec -e KRB5_CONFIG=/tmp/s4u-mit-oracle.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_r22_db2 \
    "$MITNAME" kvno -U user -P host/testhost.kerber.test 2>&1)"
DB2_RC=$?
set -e
echo "$DB2_P"
echo "mit_db2_s4u2proxy_nogrant_rc=$DB2_RC"
echo "$DB2_RC" | grep -qx 1
echo "$DB2_P" | grep -qiE "KDC can't fulfill requested option"
DB2_LOG="$(docker exec "$MITNAME" sh -c "tail -n +$((n + 1)) /tmp/mit-db2-r22.log")"
echo "$DB2_LOG"
echo "$DB2_LOG" | grep -q 'UNSUPPORTED_S4U2PROXY_REQUEST'

echo "==== Rust kvno -U user -P (fresh host, no S4U knobs) ===="
docker exec "$NAME" sh -c 'for p in /proc/[0-9]*; do comm=$(cat "$p/comm" 2>/dev/null) || continue; [ "$comm" = krb5-kdc ] || continue; kill -9 "${p#/proc/}" 2>/dev/null || true; done'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',8888),0.15)" 2>/dev/null; then
        sleep 0.2
        continue
    fi
    ok=1
    break
done
[ "$ok" = 1 ]
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host-r22.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-keytab /tmp/host-r22.keytab 127.0.0.1:8888 >/tmp/kdc-r22-nogrant.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-r22-nogrant.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc-r22-nogrant.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"Rust KDC for R22 no-grant did not listen"'
    exit 1
fi
n="$(docker exec "$NAME" sh -c "wc -l < /tmp/kdc-r22-nogrant.log" | tr -d '[:space:]')"
docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf \
    "$NAME" kinit -f -k -t /tmp/host-r22.keytab -c /tmp/krb5cc_r22_rust \
    host/testhost.kerber.test@KERBER.TEST
set +e
RUST_P="$(docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_r22_rust \
    "$NAME" kvno -U user -P host/testhost.kerber.test 2>&1)"
RUST_RC=$?
set -e
echo "$RUST_P"
echo "rust_s4u2proxy_nogrant_rc=$RUST_RC"
echo "$RUST_RC" | grep -qx 1
echo "$RUST_P" | grep -qiE "KDC can't fulfill requested option"
RUST_LOG="$(docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/kdc-r22-nogrant.log")"
echo "$RUST_LOG"
echo "$RUST_LOG" | grep -q '"e_text":"NOT_ALLOWED_TO_DELEGATE"'
echo "mit_db2_e_text=UNSUPPORTED_S4U2PROXY_REQUEST rust_e_text=NOT_ALLOWED_TO_DELEGATE"
echo "MIT_db2_s4u2proxy_nogrant"

echo "==== MIT test-KDB kvno -U user -P host/rbcd (rbcd block removed) ===="
docker exec "$NAME" sh -c 'cat >/tmp/test-norbcd-kdc.conf <<EOF
[kdcdefaults]
    kdc_listen = 127.0.0.1:8891
    kdc_tcp_listen = 127.0.0.1:8891
[realms]
    KERBER.TEST = {
        database_module = test
    }
[dbmodules]
    test = {
        db_library = test
        princs = {
            krbtgt/KERBER.TEST = {
                keys = aes256-cts
            }
            user = {
                keys = aes256-cts
            }
            host/testhost.kerber.test = {
                flags = +ok-to-auth-as-delegate
                keys = aes256-cts
            }
            host/rbcd.kerber.test = {
                keys = aes256-cts
            }
        }
        delegation = {
            host/testhost.kerber.test = host/testhost.kerber.test
        }
    }
[logging]
    kdc = FILE:/tmp/mit-norbcd.log
EOF
cat >/tmp/test-norbcd-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_norbcd
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8891
    }
[dbmodules]
    db_module_dir = /usr/lib/krb5/plugins/kdb
EOF'
docker exec -d -e KRB5_CONFIG=/tmp/test-norbcd-krb5.conf \
    -e KRB5_KDC_PROFILE=/tmp/test-norbcd-kdc.conf \
    "$NAME" sh -c 'krb5kdc -n -P /tmp/mit-norbcd.pid >/tmp/mit-norbcd-stdout.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',8891),0.2)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-norbcd.log >&2 || true
    docker exec "$NAME" cat /tmp/mit-norbcd-stdout.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"MIT test-KDB no-rbcd kdc did not listen"'
    exit 1
fi
n="$(docker exec "$NAME" sh -c "wc -l < /tmp/mit-norbcd.log" | tr -d '[:space:]')"
docker exec -e KRB5_CONFIG=/tmp/test-norbcd-krb5.conf \
    "$NAME" kinit -f -k -t /tmp/test-host.kt -c /tmp/krb5cc_mit_norbcd \
    host/testhost.kerber.test@KERBER.TEST
set +e
NORBCD="$(docker exec -e KRB5_CONFIG=/tmp/test-norbcd-krb5.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_mit_norbcd \
    "$NAME" kvno -U user -P host/rbcd.kerber.test 2>&1)"
NORBCD_RC=$?
set -e
echo "$NORBCD"
echo "mit_testkdb_rbcd_deny_rc=$NORBCD_RC"
echo "$NORBCD_RC" | grep -qx 1
echo "$NORBCD" | grep -qiE "KDC can't fulfill requested option"
NORBCD_LOG="$(docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/mit-norbcd.log")"
echo "$NORBCD_LOG"
echo "$NORBCD_LOG" | grep -q 'NOT_ALLOWED_TO_DELEGATE'

echo "==== Rust kvno -U user -P host/rbcd (extra host, no S4U_FROM) ===="
docker exec "$NAME" sh -c 'for p in /proc/[0-9]*; do comm=$(cat "$p/comm" 2>/dev/null) || continue; [ "$comm" = krb5-kdc ] || continue; kill -9 "${p#/proc/}" 2>/dev/null || true; done'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',8888),0.15)" 2>/dev/null; then
        sleep 0.2
        continue
    fi
    ok=1
    break
done
[ "$ok" = 1 ]
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host-r22b.keytab \
    -e KRB5_EXPORT_KEYTAB_EXTRA=/tmp/host-r22b-rbcd.keytab \
    -e KRB5_TEST_EXTRA_HOST=rbcd.kerber.test \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-keytab /tmp/host-r22b.keytab 127.0.0.1:8888 >/tmp/kdc-r22-norbcd.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-r22-norbcd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc-r22-norbcd.log >&2 || true
    log "s4u.mit.gate" "error" ',"error":"Rust KDC for R22 rbcd-deny did not listen"'
    exit 1
fi
n="$(docker exec "$NAME" sh -c "wc -l < /tmp/kdc-r22-norbcd.log" | tr -d '[:space:]')"
docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf \
    "$NAME" kinit -f -k -t /tmp/host-r22b.keytab -c /tmp/krb5cc_r22_norbcd \
    host/testhost.kerber.test@KERBER.TEST
set +e
RUST_NORBCD="$(docker exec -e KRB5_CONFIG=/tmp/s4u-r18.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_r22_norbcd \
    "$NAME" kvno -U user -P host/rbcd.kerber.test 2>&1)"
RUST_NORBCD_RC=$?
set -e
echo "$RUST_NORBCD"
echo "rust_rbcd_deny_rc=$RUST_NORBCD_RC"
echo "$RUST_NORBCD_RC" | grep -qx 1
echo "$RUST_NORBCD" | grep -qiE "KDC can't fulfill requested option"
RUST_NORBCD_LOG="$(docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/kdc-r22-norbcd.log")"
echo "$RUST_NORBCD_LOG"
echo "$RUST_NORBCD_LOG" | grep -q '"e_text":"NOT_ALLOWED_TO_DELEGATE"'
echo "MIT_testkdb_s4u2proxy_rbcd_deny"

log "s4u.mit.gate" "ok" ',"principal":"host/testhost.kerber.test","for_client":"user@KERBER.TEST"'
exit 0
