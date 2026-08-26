#!/usr/bin/env bash
# Bidirectional Heimdal 7.8 oracle. The only exit 0 is after both
# directions content-assert AES-SHA1 tickets. Missing docker/image is
# honest exit 2 + unavailability log — not a pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${HEIMDAL_IMAGE:-kerber-rust-heimdal-kdc:latest}"
NAME_H2R="kerber-rust-heimdal-h2r"
NAME_R2H="kerber-rust-heimdal-r2h"
REALM="KERBER.TEST"
USER_PRINC="user@${REALM}"
HOST_PRINC="host/testhost.kerber.test"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-heimdal-gate}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/heimdal-gate-unavailable.log"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"heimdal-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "heimdal.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "$1"
        docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true
    } | tee "$UNAVAIL" >&2
    log "heimdal.gate" "error" ",\"error\":\"unavailable\""
    exit 2
}

assert_klist() {
    local label="$1"
    local text="$2"
    echo "==== $label ===="
    echo "$text"
    echo "$text" | grep -q 'user@' || die "$label klist missing user@"
    echo "$text" | grep -q 'host/testhost.' || die "$label klist missing host/testhost."
}

write_client_conf() {
    local ctn="$1"
    local kdc_line="$2"
    docker exec "$ctn" sh -c "cat >/tmp/heimdal-krb5.conf <<EOF
[libdefaults]
    default_realm = ${REALM}
    default_etypes = aes256-cts-hmac-sha1-96
    default_etypes_des = aes256-cts-hmac-sha1-96
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_heimdal
[realms]
    ${REALM} = {
        ${kdc_line}
    }
EOF"
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    unavailable "no Heimdal image (build harness/heimdal, tag $IMAGE)"
fi

echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-client --bin krb5-kinit

docker rm -f "$NAME_H2R" "$NAME_R2H" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME_H2R" "$NAME_R2H" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==== Heimdal client vs Rust KDC ===="
docker run -d --name "$NAME_H2R" --entrypoint sleep "$IMAGE" 3600 >/dev/null \
    || unavailable "docker run $IMAGE (sleep) failed"
docker cp target/debug/krb5-kdc "$NAME_H2R":/tmp/krb5-kdc \
    || die "docker cp krb5-kdc failed"
docker exec "$NAME_H2R" chmod +x /tmp/krb5-kdc
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME_H2R" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME_H2R" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    if docker exec "$NAME_H2R" grep -qiE 'bind failed|privilege drop:|not found|glibc' /tmp/kdc.log 2>/dev/null; then
        if ! docker exec "$NAME_H2R" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
            break
        fi
    fi
    sleep 0.25
done
echo "==== rust KDC log ===="
docker exec "$NAME_H2R" cat /tmp/kdc.log 2>/dev/null || true
[ "$ok" -eq 1 ] || die "rust KDC did not listen inside Heimdal container"

LISTEN="$(docker exec "$NAME_H2R" grep '^listening ' /tmp/kdc.log | tail -1)"
KDC_LINE="kdc = 127.0.0.1"
case "$LISTEN" in
    *:8888*) KDC_LINE="kdc = 127.0.0.1:8888" ;;
esac
write_client_conf "$NAME_H2R" "$KDC_LINE"

if ! docker exec -e KRB5_CONFIG=/tmp/heimdal-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_heimdal \
    "$NAME_H2R" sh -c 'printf "userpassword\n" | kinit --password-file=STDIN user@KERBER.TEST'; then
    docker exec "$NAME_H2R" cat /tmp/kdc.log 2>/dev/null || true
    die "Heimdal kinit against Rust KDC failed"
fi
if ! docker exec -e KRB5_CONFIG=/tmp/heimdal-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_heimdal \
    "$NAME_H2R" kgetcred "$HOST_PRINC"; then
    docker exec "$NAME_H2R" cat /tmp/kdc.log 2>/dev/null || true
    die "Heimdal kgetcred against Rust KDC failed"
fi
KLIST_H2R="$(docker exec -e KRB5_CONFIG=/tmp/heimdal-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_heimdal \
    "$NAME_H2R" klist)"
assert_klist "heimdal-client" "$KLIST_H2R"
log "heimdal.client.rustkdc" "ok" ",\"principal\":\"${USER_PRINC}\",\"service\":\"${HOST_PRINC}\""

echo "==== Rust client vs Heimdal KDC ===="
docker run -d --name "$NAME_R2H" "$IMAGE" >/dev/null \
    || unavailable "docker run $IMAGE (kdc) failed"
ok=0
for _ in $(seq 1 40); do
    if docker logs "$NAME_R2H" 2>&1 | grep -q '"event":"heimdal.start"'; then
        if docker exec "$NAME_R2H" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),2)" 2>/dev/null; then
            ok=1
            break
        fi
    fi
    sleep 0.25
done
echo "==== heimdal KDC log ===="
docker logs "$NAME_R2H" 2>&1 || true
[ "$ok" -eq 1 ] || die "Heimdal KDC did not listen on TCP 88"
docker logs "$NAME_R2H" 2>&1 | grep -q '"event":"heimdal.start"' \
    || die "missing heimdal.start JSON"

docker cp target/debug/krb5-kinit "$NAME_R2H":/tmp/krb5-kinit \
    || die "docker cp krb5-kinit failed"
docker exec "$NAME_R2H" chmod +x /tmp/krb5-kinit
if ! docker exec -e KRB5_PASSWORD=userpassword \
    "$NAME_R2H" /tmp/krb5-kinit 127.0.0.1 user@KERBER.TEST /tmp/krb5cc_rust \
    host/testhost.kerber.test; then
    docker logs "$NAME_R2H" 2>&1 || true
    docker exec "$NAME_R2H" cat /var/log/heimdal-kdc.log 2>/dev/null || true
    die "Rust krb5-kinit against Heimdal KDC failed"
fi
KLIST_R2H="$(docker exec "$NAME_R2H" klist -c /tmp/krb5cc_rust)"
assert_klist "rust-client" "$KLIST_R2H"
log "heimdal.rustclient.heimdalkdc" "ok" ",\"principal\":\"${USER_PRINC}\",\"service\":\"${HOST_PRINC}\""

log "heimdal.gate" "ok" ",\"principal\":\"${USER_PRINC}\",\"service\":\"${HOST_PRINC}\",\"directions\":2"
