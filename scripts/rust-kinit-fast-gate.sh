#!/usr/bin/env bash
# Rust kinit --fast vs MIT 1.22.2 KDC. Armor TGT from a prior enc-ts kinit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-fast-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rust-kinit-fast-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

assert_no_error_log() {
    if echo "$1" | grep -qF '"level":"ERROR"'; then
        echo "$1" >&2
        log "fast.client.gate" "error" ',"error":"happy-path ERROR log"'
        exit 1
    fi
}

if ! command -v docker >/dev/null 2>&1; then
    log "fast.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-client --bin krb5-kinit
cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
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
        log "fast.client.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "fast.client.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

echo "==== armor TGT (enc-ts) ===="
set +e
ARMOR="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/krb5cc_armor user@KERBER.TEST 2>&1)"
arc=$?
set -e
echo "$ARMOR"
if [ "$arc" -ne 0 ]; then
    log "fast.client.gate" "error" ',"error":"rust kinit armor failed","rc":'"$arc"
    exit 1
fi
assert_no_error_log "$ARMOR"

echo "==== Rust kinit --fast --armor-ccache ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    echo "==== MIT kdc TRACE ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast failed","rc":'"$rc"
    exit 1
fi
assert_no_error_log "$OUT"
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
# write_out_ccache: fast_avail is recorded because the KDC echoed PA-FX-FAST
# inside the FAST reply; user needs no preauth here, so like MIT no pa_type
# entry is written (save_selected_preauth_type returns on KRB5_PADATA_NONE).
echo "==== Rust kinit --fast recorded fast_avail (and no pa_type without preauth) like write_out_ccache ===="
KLISTC="$(docker exec "$NAME" klist -C -c /tmp/krb5cc_fast 2>/dev/null || true)"
echo "$KLISTC"
echo "$KLISTC" | grep -F 'config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes'
if echo "$KLISTC" | grep -q 'config: pa_type('; then
    echo "pa_type recorded without a selected preauth type" >&2
    exit 1
fi
TRACE="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE" >&2
    log "fast.client.gate" "error" ',"error":"kinit succeeded without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE" | grep -F 'Decrypted AP-REQ'

echo "==== FAST immediate AS-REP (no +requires_preauth) ===="
docker exec "$NAME" sh -c "kadmin.local -q 'addprinc -pw userpassword nopreauth' >/tmp/g9-nopreauth-add.out 2>&1" || true
docker exec "$NAME" sh -c "kadmin.local -q 'modprinc -requires_preauth nopreauth' >/tmp/g9-nopreauth-mod.out 2>&1"
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT2="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast_np nopreauth@KERBER.TEST 2>&1)"
rc2=$?
set -e
echo "$OUT2"
if [ "$rc2" -ne 0 ]; then
    echo "==== MIT kdc TRACE (nopreauth) ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    docker exec "$NAME" cat /tmp/g9-nopreauth-add.out 2>/dev/null || true
    docker exec "$NAME" cat /tmp/g9-nopreauth-mod.out 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast nopreauth failed","rc":'"$rc2"
    exit 1
fi
assert_no_error_log "$OUT2"
KLIST2="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast_np 2>/dev/null || true)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'nopreauth@KERBER.TEST'
TRACE2="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE2" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE2" >&2
    log "fast.client.gate" "error" ',"error":"nopreauth FAST without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE2" | grep -F 'Decrypted AP-REQ'
if ! echo "$TRACE2" | grep -F 'Decrypted AP-REQ' | grep -F 'aes256-sha2'; then
    echo "$TRACE2" >&2
    log "fast.client.gate" "error" ',"error":"nopreauth FAST AP-REQ was not aes256-sha2"'
    exit 1
fi
KLIST2E="$(docker exec "$NAME" klist -e -c /tmp/krb5cc_fast_np 2>/dev/null || true)"
echo "$KLIST2E"
echo "$KLIST2E" | grep -F 'aes256-cts-hmac-sha384-192'

echo "==== Rust kinit --fast -S host (TGS strengthen-key) ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT3="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast_tgs -S host/testhost.kerber.test user@KERBER.TEST 2>&1)"
rc3=$?
set -e
echo "$OUT3"
if [ "$rc3" -ne 0 ]; then
    echo "==== MIT kdc TRACE (FAST TGS) ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast -S failed","rc":'"$rc3"
    exit 1
fi
assert_no_error_log "$OUT3"
KLIST3="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast_tgs 2>/dev/null || true)"
echo "$KLIST3"
echo "$KLIST3" | grep -q 'host/testhost.kerber.test'
MIT_TRACE=/tmp/mit-kdc.trace; TRACE3="$(docker exec "$NAME" cat "$MIT_TRACE" 2>/dev/null || true)"
if ! echo "$TRACE3" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE3" >&2
    log "fast.client.gate" "error" ',"error":"FAST TGS without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE3" | grep -F 'Decrypted AP-REQ'

echo "==== require_auth encrypted_challenge: FAST issued, password 12 both legs ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "$ROOT/harness/client-krb5.conf" "$NAME":/tmp/mit-krb5.conf
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb
docker exec "$NAME" sh -c "sed 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:8888/' /tmp/mit-krb5.conf > /tmp/rust-krb5.conf && sed -i 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:88/' /tmp/mit-krb5.conf"
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
t = p.read_text()
if "encrypted_challenge_indicator" not in t:
    t = t.replace("supported_enctypes", "        encrypted_challenge_indicator = encrypted_challenge\n        supported_enctypes", 1)
    p.write_text(t)
Path("/tmp/rust-kdc.conf").write_text("""[realms]
    KERBER.TEST = {
        encrypted_challenge_indicator = encrypted_challenge
    }
""")
'
docker exec "$NAME" kadmin.local -q 'modprinc +requires_preauth user'
docker exec "$NAME" kadmin.local -q 'setstr host/testhost.kerber.test require_auth encrypted_challenge'
docker exec "$NAME" kdb5_util dump /tmp/ec-ind.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"MIT krb5kdc did not listen after EC indicator"'
    exit 1
fi
LOAD_EC="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/ec-ind.dump)"
echo "$LOAD_EC"
echo "$LOAD_EC" | grep -q 'ok load version=7' || {
    log "fast.client.gate" "error" ',"error":"rust kdb load after EC indicator failed"'
    exit 1
}
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_PROFILE=/tmp/rust-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"rust kdc did not listen after EC indicator"'
    exit 1
fi
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/mit-krb5.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -c /tmp/ec-armor.cc user@KERBER.TEST'; then
    log "fast.client.gate" "error" ',"error":"MIT armor kinit for EC cell failed"'
    exit 1
fi
ec_fast_kvno() {
    local side=$1
    local conf="/tmp/${side}-krb5.conf"
    docker exec "$NAME" rm -f /tmp/ec-fast.cc
    if ! docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit -T /tmp/ec-armor.cc -c /tmp/ec-fast.cc user@KERBER.TEST'; then
        echo "==== $side FAST kinit failed ===="
        docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
        docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"MIT kinit -T via $side KDC failed\""
        exit 1
    fi
    KLISTC="$(docker exec "$NAME" klist -C -c /tmp/ec-fast.cc 2>/dev/null || true)"
    echo "$KLISTC"
    echo "$KLISTC" | grep -q 'pa_type.*= 138' || {
        log "fast.client.gate" "error" ",\"error\":\"$side FAST kinit missing pa_type 138\""
        exit 1
    }
    set +e
    got="$(docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/ec-fast.cc "$NAME" \
        kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$side ec_kvno=$got"
    echo "$got" | grep -q 'host/testhost.kerber.test@KERBER.TEST: kvno =' || {
        docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
        docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"$side kvno after EC TGT + require_auth failed\""
        exit 1
    }
}
ec_fast_kvno mit
ec_fast_kvno rust
docker exec "$NAME" sh -c ': >/tmp/mit-kdc.log; : >/tmp/rust-kdc.log'
ec_pw_kvno() {
    local side=$1
    local conf="/tmp/${side}-krb5.conf"
    local logf
    if [ "$side" = mit ]; then
        logf=/tmp/mit-kdc.log
    else
        logf=/tmp/rust-kdc.log
    fi
    docker exec -e KRB5_CONFIG="$conf" "$NAME" kdestroy -A >/dev/null 2>&1 || true
    if ! docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit -c /tmp/ec-pw.cc user@KERBER.TEST'; then
        log "fast.client.gate" "error" ",\"error\":\"$side password kinit for EC negative failed\""
        exit 1
    fi
    set +e
    got="$(docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/ec-pw.cc "$NAME" \
        kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$side pw_kvno=$got"
    echo "$got" | grep -q 'KDC policy rejects request' || {
        log "fast.client.gate" "error" ",\"error\":\"$side password kvno missing KDC policy rejects request\""
        exit 1
    }
    docker exec "$NAME" grep -q 'HIGHER_AUTHENTICATION_REQUIRED' "$logf" || {
        docker exec "$NAME" cat "$logf" >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"$side KDC log missing HIGHER_AUTHENTICATION_REQUIRED\""
        exit 1
    }
}
ec_pw_kvno mit
ec_pw_kvno rust

log "fast.client.gate" "ok" ',"mode":"rust-kinit","pa_type":136,"principal":"user@KERBER.TEST","nopreauth":true,"etype":20,"tgs_strengthen":true,"mit_tgs_strengthen":true,"ec_require_auth":"issued+12"'
exit 0
