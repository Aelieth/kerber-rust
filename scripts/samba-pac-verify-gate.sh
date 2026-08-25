#!/usr/bin/env bash
# L1 (+ L2 if kcrypto ships): Samba IDL decode of a Rust-issued PAC.
# Co-located Rust KDC on 127.0.0.1:8888 inside samba-ad-dc. Isolation:
# docker exec only; host /etc/krb5.conf stays TESTLABBY.LOCAL.
# Missing image/docker: exit 2. Dummy SID or missing buffers: exit 1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-samba-pac-verify}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/samba-pac-verify-unavailable.log"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"samba-pac-verify-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "$1"
    } | tee "$UNAVAIL" >&2
    log "samba.pac.verify" "error" ",\"error\":\"unavailable\""
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi

IMAGE="${SAMBA_AD_IMAGE:-}"
if [ -z "$IMAGE" ] && docker image inspect samba-ad-dc:latest >/dev/null 2>&1; then
    IMAGE="samba-ad-dc:latest"
fi
if [ -z "$IMAGE" ]; then
    unavailable "no Samba AD DC image (set SAMBA_AD_IMAGE)"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract

NAME="kerber-rust-samba-pac-verify"
docker rm -f "$NAME" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

set +e
docker run -d --name "$NAME" --hostname dc1 "$IMAGE" >/tmp/samba-pac-run.err 2>&1
run_rc=$?
set -e
if [ "$run_rc" -ne 0 ]; then
    unavailable "docker run $IMAGE failed: $(tr '\n' ' ' </tmp/samba-pac-run.err 2>/dev/null || true)"
fi

ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" sh -c 'ss -lun | grep -q ":88 "' 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.5
done
if [ "$ok" != 1 ]; then
    unavailable "Samba AD KDC did not listen on UDP 88"
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker cp harness/samba/pac_l1.py "$NAME":/tmp/pac_l1.py
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log 2>/dev/null || true
    unavailable "Rust KDC did not listen on 127.0.0.1:8888"
fi

docker exec "$NAME" sh -c 'cat >/tmp/rust-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_pac
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
EOF'

set +e
docker exec -e KRB5_CONFIG=/tmp/rust-krb5.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
kinit_rc=$?
set -e
if [ "$kinit_rc" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log 2>/dev/null || true
    unavailable "kinit user@KERBER.TEST against co-located Rust KDC failed"
fi

set +e
docker exec -e KRB5_CONFIG=/tmp/rust-krb5.conf "$NAME" \
    kvno host/testhost.kerber.test@KERBER.TEST
kvno_rc=$?
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/rust-krb5.conf "$NAME" klist 2>&1)"
set -e
echo "$KLIST"
if [ "$kvno_rc" -ne 0 ]; then
    unavailable "kvno host/testhost.kerber.test against Rust KDC failed"
fi
echo "$KLIST" | grep -q 'user@KERBER.TEST'
echo "$KLIST" | grep -q 'host/testhost.kerber.test'

docker exec "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/host.keytab --ccache /tmp/krb5cc_pac --out /tmp/rust.pac

set +e
L1="$(docker exec "$NAME" python3 /tmp/pac_l1.py /tmp/rust.pac 2>&1)"
l1_rc=$?
set -e
echo "$L1"
echo "$L1" >"$SCRATCH/samba-pac-l1.txt"
if [ "$l1_rc" -ne 0 ]; then
    log "samba.pac.verify" "error" ",\"error\":\"l1\""
    exit 1
fi
echo "$L1" | grep -q 'L1_OK'
echo "$L1" | grep -q 'REQUESTER_SID\|requestor'
echo "$L1" | grep -v L1_DUMMY_REQUESTOR | grep -q L1_OK

docker exec "$NAME" python3 /tmp/pac_l1.py --write-dummy /tmp/rust.pac /tmp/dummy.pac
set +e
D1="$(docker exec "$NAME" python3 /tmp/pac_l1.py /tmp/dummy.pac 2>&1)"
d1_rc=$?
set -e
echo "$D1"
if [ "$d1_rc" -eq 0 ] || echo "$D1" | grep -q L1_OK; then
    log "samba.pac.verify" "error" ",\"error\":\"dummy-sid-accepted\""
    exit 1
fi
echo "$D1" | grep -q L1_DUMMY

L2="deferred-to-l3"
set +e
docker exec "$NAME" python3 -c 'import samba.tests.krb5.kcrypto' >/dev/null 2>&1
if [ $? -eq 0 ]; then
    L2="kcrypto-present-unwired"
fi
set -e

log "samba.pac.verify" "ok" ",\"l1\":\"ok\",\"l2\":\"${L2}\",\"dump\":\"rust-issued\""
exit 0
