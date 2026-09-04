#!/usr/bin/env bash
# MIT kinit -T (FAST armor) + kvno against the Rust KDC.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-mit-fast-kdc-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"mit-fast-kdc-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "fast.kdc.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-forge-tgt

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-forge-tgt "$NAME":/tmp/krb5-forge-tgt
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-forge-tgt
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
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
    log "fast.kdc.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

echo "==== MIT armor TGT against Rust KDC ===="
if ! docker exec -e KRB5_TRACE=/tmp/armor.trace "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_armor user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "fast.kdc.gate" "error" ',"error":"MIT armor kinit failed"'
    exit 1
fi

echo "==== MIT kinit -T FAST against Rust KDC ===="
docker exec "$NAME" sh -c 'cat /dev/null >/tmp/fast.trace'
if ! docker exec -e KRB5_TRACE=/tmp/fast.trace "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor -c /tmp/krb5cc_fast user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/fast.trace >&2 || true
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "fast.kdc.gate" "error" ',"error":"MIT kinit -T failed"'
    exit 1
fi
TRACE="$(docker exec "$NAME" cat /tmp/fast.trace)"
echo "$TRACE"
if ! echo "$TRACE" | grep -E 'Upgrading to FAST due to presence of PA_FX_FAST|Using FAST due to armor ccache negotiation result'; then
    echo "$TRACE" >&2
    log "fast.kdc.gate" "error" ',"error":"kinit -T did not use FAST"'
    exit 1
fi
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

echo "==== MIT kvno under FAST ccache ===="
if ! docker exec -e KRB5_TRACE=/tmp/kvno.trace "$NAME" \
    kvno -c /tmp/krb5cc_fast host/testhost.kerber.test; then
    docker exec "$NAME" cat /tmp/kvno.trace >&2 || true
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "fast.kdc.gate" "error" ',"error":"MIT kvno under FAST failed"'
    exit 1
fi
KLIST2="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'host/testhost.kerber.test'
KDCLOG="$(docker exec "$NAME" cat /tmp/kdc.log)"
echo "$KDCLOG" | tail -40
FASTN="$(echo "$KDCLOG" | grep -c 'fast::KrbFastResponse' || true)"
echo "KrbFastResponse count=$FASTN"
if [ "$FASTN" -lt 2 ]; then
    echo "$KDCLOG" >&2
    echo "$TRACE" >&2
    log "fast.kdc.gate" "error" ',"error":"Rust KDC log lacked two FAST KrbFastResponse (AS+TGS)"'
    exit 1
fi

echo "==== Rust KDC: forged-realm FAST TGS is PROCESS_TGS ===="
if ! docker exec "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor -c /tmp/krb5cc_fast_tgs user@KERBER.TEST'; then
    log "fast.kdc.gate" "error" ',"error":"kinit -T for FAST TGS forge failed"'
    exit 1
fi
docker exec "$NAME" /tmp/krb5-forge-tgt \
    --ccache /tmp/krb5cc_fast_tgs --out /tmp/krb5cc_fast_forged \
    --claim-realm FORGED.EXAMPLE --tgt krbtgt/KERBER.TEST --keep-cipher
TGS_BEFORE="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kdc.log' | tr -d '[:space:]')"
set +e
TGSF="$(docker exec -e KRB5_TRACE=/tmp/tgs-forge.trace "$NAME" \
    kvno -c /tmp/krb5cc_fast_forged host/testhost.kerber.test 2>&1)"
TGSF_RC=$?
set -e
echo "$TGSF"
if [ "$TGSF_RC" -eq 0 ]; then
    echo "forged-realm FAST TGS must not kvno" >&2
    exit 1
fi
echo "$TGSF" | grep -F 'kvno: Server host/testhost.kerber.test@KERBER.TEST not found in Kerberos database while getting credentials for host/testhost.kerber.test@KERBER.TEST'
TRACEF="$(docker exec "$NAME" cat /tmp/tgs-forge.trace)"
echo "$TRACEF"
echo "$TRACEF" | grep -F 'Encoding request body and padata into FAST request'
TGSNEW="$(docker exec "$NAME" sh -c "tail -n +$((TGS_BEFORE + 1)) /tmp/kdc.log")"
echo "$TGSNEW"
echo "$TGSNEW" | grep -q '"code":7,"e_text":"PROCESS_TGS"'

echo "==== Rust KDC: forged-realm FAST armor is NOT_US ===="
docker exec "$NAME" /tmp/krb5-forge-tgt \
    --ccache /tmp/krb5cc_armor --out /tmp/krb5cc_armor_forged \
    --claim-realm FORGED.EXAMPLE --tgt krbtgt/KERBER.TEST --keep-cipher
MM_BEFORE="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kdc.log' | tr -d '[:space:]')"
set +e
FORGED="$(docker exec -e KRB5_TRACE=/tmp/forged.trace "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor_forged -c /tmp/krb5cc_forged user@KERBER.TEST' 2>&1)"
FORGED_RC=$?
set -e
echo "$FORGED"
if [ "$FORGED_RC" -eq 0 ]; then
    echo "forged-realm armor must not kinit" >&2
    exit 1
fi
echo "$FORGED" | grep -q "The ticket isn't for us"
MM_NEW="$(docker exec "$NAME" sh -c "tail -n +$((MM_BEFORE + 1)) /tmp/kdc.log")"
echo "$MM_NEW"
echo "$MM_NEW" | grep -q '"code":35,"e_text":"FIND_FAST"'
echo "$MM_NEW" | grep -q '"detail":"FAST armor TGT"'

echo "==== MIT KDC: forged-realm FAST armor is NOT_US ===="
MITNAME="${NAME}-mit"
docker rm -f "$MITNAME" >/dev/null 2>&1 || true
docker run -d --name "$MITNAME" "$IMAGE" >/dev/null
mit_cleanup() { docker rm -f "$MITNAME" >/dev/null 2>&1 || true; }
trap 'cleanup; mit_cleanup' EXIT
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$MITNAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    docker logs "$MITNAME" >&2 || true
    log "fast.kdc.gate" "error" ',"error":"MIT harness did not become ready"'
    exit 1
fi
docker exec "$MITNAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d "$MITNAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$MITNAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$MITNAME" cat /tmp/mit-kdc.log >&2 || true
    log "fast.kdc.gate" "error" ',"error":"MIT kdc did not listen"'
    exit 1
fi
docker cp target/debug/krb5-forge-tgt "$MITNAME":/tmp/krb5-forge-tgt
docker exec "$MITNAME" chmod +x /tmp/krb5-forge-tgt
docker exec "$MITNAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_armor user@KERBER.TEST'
if ! docker exec -e KRB5_TRACE=/tmp/mit-fast.trace "$MITNAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor -c /tmp/krb5cc_fast user@KERBER.TEST'; then
    docker exec "$MITNAME" cat /tmp/mit-fast.trace >&2 || true
    log "fast.kdc.gate" "error" ',"error":"MIT kinit -T against MIT KDC failed"'
    exit 1
fi
echo "==== MIT KDC: forged-realm FAST TGS is PROCESS_TGS ===="
docker exec "$MITNAME" /tmp/krb5-forge-tgt \
    --ccache /tmp/krb5cc_fast --out /tmp/krb5cc_fast_forged \
    --claim-realm FORGED.EXAMPLE --tgt krbtgt/KERBER.TEST --keep-cipher
n_tgs="$(docker exec "$MITNAME" sh -c 'wc -l < /tmp/mit-kdc.log' | tr -d '[:space:]')"
set +e
MITTGS="$(docker exec -e KRB5_TRACE=/tmp/mit-tgs-forge.trace "$MITNAME" \
    kvno -c /tmp/krb5cc_fast_forged host/testhost.kerber.test 2>&1)"
MITTGS_RC=$?
set -e
echo "$MITTGS"
if [ "$MITTGS_RC" -eq 0 ]; then
    echo "MIT forged-realm FAST TGS must not kvno" >&2
    exit 1
fi
echo "$MITTGS" | grep -F 'kvno: Server host/testhost.kerber.test@KERBER.TEST not found in Kerberos database while getting credentials for host/testhost.kerber.test@KERBER.TEST'
MITTRACE="$(docker exec "$MITNAME" cat /tmp/mit-tgs-forge.trace)"
echo "$MITTRACE"
echo "$MITTRACE" | grep -F 'Encoding request body and padata into FAST request'
MITTGSLOG="$(docker exec "$MITNAME" sh -c "tail -n +$((n_tgs + 1)) /tmp/mit-kdc.log")"
echo "$MITTGSLOG"
echo "$MITTGSLOG" | grep -q 'PROCESS_TGS'
echo "$MITTGSLOG" | grep -F "UNKNOWN SERVER: server='krbtgt/KERBER.TEST@FORGED.EXAMPLE'"

docker exec "$MITNAME" /tmp/krb5-forge-tgt \
    --ccache /tmp/krb5cc_armor --out /tmp/krb5cc_armor_forged \
    --claim-realm FORGED.EXAMPLE --tgt krbtgt/KERBER.TEST --keep-cipher
n="$(docker exec "$MITNAME" sh -c 'wc -l < /tmp/mit-kdc.log' | tr -d '[:space:]')"
set +e
MITF="$(docker exec "$MITNAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor_forged -c /tmp/krb5cc_forged user@KERBER.TEST' 2>&1)"
MITF_RC=$?
set -e
echo "$MITF"
if [ "$MITF_RC" -eq 0 ]; then
    echo "MIT forged-realm armor must not kinit" >&2
    exit 1
fi
echo "$MITF" | grep -q "The ticket isn't for us"
MITASLOG="$(docker exec "$MITNAME" sh -c "tail -n +$((n + 1)) /tmp/mit-kdc.log")"
echo "$MITASLOG"
echo "$MITASLOG" | grep -qE 'FIND_FAST: .*while handling ap-request armor'

log "fast.kdc.gate" "ok" ',"principal":"user@KERBER.TEST","mode":"mit-kinit-T"'
exit 0
