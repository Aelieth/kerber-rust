#!/usr/bin/env bash
# L2: Samba kcrypto validates Rust PAC checksums 6/7/16/19.
# Isolation: docker exec; host /etc/krb5.conf stays TESTLABBY.LOCAL.
# Missing image/kcrypto: exit 2. Mismatch or corrupt-MAC pass: exit 1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-samba-pac-l2}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/samba-pac-l2-unavailable.log"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"samba-pac-l2-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "$1"
    } | tee "$UNAVAIL" >&2
    log "samba.pac.l2" "error" ",\"error\":\"unavailable\""
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

NAME="kerber-rust-samba-pac-l2"
docker rm -f "$NAME" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

set +e
docker run -d --name "$NAME" --hostname dc1 "$IMAGE" >/tmp/samba-pac-l2-run.err 2>&1
run_rc=$?
set -e
if [ "$run_rc" -ne 0 ]; then
    unavailable "docker run failed: $(tr '\n' ' ' </tmp/samba-pac-l2-run.err 2>/dev/null || true)"
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
    unavailable "Samba KDC did not listen on UDP 88"
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker cp harness/samba/pac_l2.py "$NAME":/tmp/pac_l2.py
docker cp harness/samba/kcrypto.py "$NAME":/tmp/kcrypto.py
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract
set +e
docker exec "$NAME" python3 -c 'import sys; sys.path.insert(0,"/tmp"); import kcrypto' >/dev/null 2>&1
kcrypto_rc=$?
set -e
if [ "$kcrypto_rc" -ne 0 ]; then
    unavailable "kcrypto.py (Samba AES checksum) not importable; need python3-cryptography"
fi

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    -e KRB5_EXPORT_KRBTGT_KEYTAB=/tmp/krbtgt.keytab \
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
    unavailable "Rust KDC did not listen on 8888"
fi
if ! docker exec "$NAME" test -f /tmp/krbtgt.keytab; then
    unavailable "krbtgt keytab not exported"
fi

docker exec "$NAME" sh -c 'cat >/tmp/rust-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_l2
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
    unavailable "kinit user@KERBER.TEST failed"
fi
set +e
docker exec -e KRB5_CONFIG=/tmp/rust-krb5.conf "$NAME" \
    kvno host/testhost.kerber.test@KERBER.TEST
kvno_rc=$?
set -e
if [ "$kvno_rc" -ne 0 ]; then
    unavailable "kvno host/testhost.kerber.test failed"
fi

docker exec "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/host.keytab --krbtgt-keytab /tmp/krbtgt.keytab \
    --ccache /tmp/krb5cc_l2 --out /tmp/rust.pac \
    --enc-tkt-out /tmp/rust.enc_tkt --keys-out /tmp/rust.keys

set +e
L2="$(docker exec "$NAME" python3 /tmp/pac_l2.py /tmp/rust.pac /tmp/rust.enc_tkt /tmp/rust.keys 2>&1)"
l2_rc=$?
set -e
echo "$L2"
if [ "$l2_rc" -ne 0 ] || ! echo "$L2" | grep -q L2_OK; then
    log "samba.pac.l2" "error" ",\"error\":\"mismatch\""
    exit 1
fi

docker exec "$NAME" python3 -c '
import struct, sys
p = open("/tmp/rust.pac", "rb").read()
n, _ver = struct.unpack_from("<II", p)
b = bytearray(p)
found = False
for i in range(n):
    typ, size, off = struct.unpack_from("<IIQ", p, 8 + i * 16)
    if typ == 6 and size > 4:
        b[off + 4] ^= 0xFF
        found = True
        break
if not found:
    sys.exit("no PAC type-6 MAC")
open("/tmp/rust.pac.bad", "wb").write(b)
'
set +e
BAD="$(docker exec "$NAME" python3 /tmp/pac_l2.py /tmp/rust.pac.bad /tmp/rust.enc_tkt /tmp/rust.keys 2>&1)"
bad_rc=$?
set -e
echo "$BAD"
if [ "$bad_rc" -eq 0 ] || echo "$BAD" | grep -q L2_OK; then
    log "samba.pac.l2" "error" ",\"error\":\"corrupt-mac-passed\""
    exit 1
fi
if echo "$BAD" | grep -q L2_MISSING; then
    log "samba.pac.l2" "error" ",\"error\":\"corrupt-mac-missing\""
    exit 1
fi
echo "$BAD" | grep -q L2_MISMATCH

log "samba.pac.l2" "ok" ",\"l2\":\"ok\",\"corrupt\":\"fail\""
exit 0
