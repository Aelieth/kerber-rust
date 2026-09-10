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

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-forge-tgt" "$NAME":/tmp/krb5-forge-tgt
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

# W1-J L3a/L3b: the plain kinit advertises PA-REQ-ENC-PA-REP; the Rust KDC
# echoes a valid enc-pa-rep checksum plus PA-FX-FAST, so MIT's
# krb5int_fast_verify_nego traces "FAST negotiation: available". A bad checksum
# would instead be KRB5_KDCREP_MODIFIED; a missing PA-FX-FAST, "unavailable".
echo "==== MIT plain kinit negotiated FAST availability from the Rust KDC ===="
MIT_ARMOR_TRACE="$(docker exec "$NAME" cat /tmp/armor.trace)"
if ! echo "$MIT_ARMOR_TRACE" | grep -F 'FAST negotiation: available'; then
    echo "$MIT_ARMOR_TRACE" >&2
    log "fast.kdc.gate" "error" ',"error":"plain kinit did not negotiate FAST availability"'
    exit 1
fi

# MIT write_out_ccache: the negotiated availability and the selected preauth
# type are ccache config entries keyed by the TGT's server (klist -C shows them).
echo "==== MIT plain kinit recorded fast_avail and pa_type against the Rust KDC ===="
ARMOR_CONF="$(docker exec "$NAME" klist -C -c /tmp/krb5cc_armor)"
echo "$ARMOR_CONF"
echo "$ARMOR_CONF" | grep -F 'config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes'
echo "$ARMOR_CONF" | grep -F 'config: pa_type(krbtgt/KERBER.TEST@KERBER.TEST) = 2'

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

echo "==== Rust KDC: FAST-error outer e_data shape via kdc-padata-proxy ===="
docker cp "$ROOT/scripts/lib/kdc-padata-proxy.py" "$NAME":/tmp/kdc-padata-proxy.py
docker exec "$NAME" rm -f /tmp/fast-err-rust.txt
docker exec -d "$NAME" python3 /tmp/kdc-padata-proxy.py 1891 127.0.0.1 88 /tmp/fast-err-rust.txt
sleep 0.4
docker exec "$NAME" sh -c "cat > /tmp/krb5-fast-proxy.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    udp_preference_limit = 4096
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:1891
    }
EOF"
set +e
docker exec -e KRB5_CONFIG=/tmp/krb5-fast-proxy.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor_forged -c /tmp/krb5cc_forged2 user@KERBER.TEST' >/dev/null 2>&1
set -e
RUST_FAST_ERR="$(docker exec "$NAME" cat /tmp/fast-err-rust.txt 2>/dev/null || true)"
echo "$RUST_FAST_ERR"
echo "$RUST_FAST_ERR" | grep -E 'rep#[0-9]+ error_code=35 e_data_encoding=none e_data_types=\[]' || {
    echo "rust FAST-error proxy line missing: $RUST_FAST_ERR" >&2
    exit 1
}
RUST_SHAPE="$(echo "$RUST_FAST_ERR" | grep -E 'rep#[0-9]+ error_code=' | head -1 | sed -E 's/^rep#[0-9]+ //')"

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
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-forge-tgt" "$MITNAME":/tmp/krb5-forge-tgt
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

echo "==== MIT KDC: FAST-error outer e_data shape via kdc-padata-proxy ===="
docker cp "$ROOT/scripts/lib/kdc-padata-proxy.py" "$MITNAME":/tmp/kdc-padata-proxy.py
docker exec "$MITNAME" rm -f /tmp/fast-err-mit.txt
docker exec -d "$MITNAME" python3 /tmp/kdc-padata-proxy.py 1891 127.0.0.1 88 /tmp/fast-err-mit.txt
sleep 0.4
docker exec "$MITNAME" sh -c "cat > /tmp/krb5-fast-proxy.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    udp_preference_limit = 4096
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:1891
    }
EOF"
set +e
docker exec -e KRB5_CONFIG=/tmp/krb5-fast-proxy.conf "$MITNAME" \
    sh -c 'printf "userpassword\n" | kinit -T /tmp/krb5cc_armor_forged -c /tmp/krb5cc_forged2 user@KERBER.TEST' >/dev/null 2>&1
set -e
MIT_FAST_ERR="$(docker exec "$MITNAME" cat /tmp/fast-err-mit.txt 2>/dev/null || true)"
echo "$MIT_FAST_ERR"
echo "$MIT_FAST_ERR" | grep -E 'rep#[0-9]+ error_code=35 e_data_encoding=none e_data_types=\[]' || {
    echo "MIT FAST-error proxy line missing: $MIT_FAST_ERR" >&2
    exit 1
}
MIT_SHAPE="$(echo "$MIT_FAST_ERR" | grep -E 'rep#[0-9]+ error_code=' | head -1 | sed -E 's/^rep#[0-9]+ //')"
echo "rust_fast_err_shape=$RUST_SHAPE"
echo "mit_fast_err_shape=$MIT_SHAPE"
if [ "$RUST_SHAPE" != "$MIT_SHAPE" ]; then
    echo "FAST-error outer e_data shape differs rust vs MIT" >&2
    exit 1
fi

echo "==== Rust KDC: FAST wrong-password and unknown-server outer shapes ===="
docker exec "$NAME" sh -c ':> /tmp/fast-err-rust.txt'
set +e
RUST_BADPW="$(docker exec -e KRB5_CONFIG=/tmp/krb5-fast-proxy.conf "$NAME" \
    sh -c 'printf "wrongpassword\n" | kinit -T /tmp/krb5cc_armor -c /tmp/krb5cc_bad user@KERBER.TEST' 2>&1)"
set -e
echo "$RUST_BADPW"
echo "$RUST_BADPW" | grep -q 'Password incorrect while getting initial credentials' || {
    echo "rust FAST wrong-password client text missing: $RUST_BADPW" >&2
    exit 1
}
RUST_BADPW_PROXY="$(docker exec "$NAME" cat /tmp/fast-err-rust.txt 2>/dev/null || true)"
echo "$RUST_BADPW_PROXY"
echo "$RUST_BADPW_PROXY" | grep -q '136' || {
    echo "rust FAST wrong-password proxy missing 136: $RUST_BADPW_PROXY" >&2
    exit 1
}
echo "$RUST_BADPW_PROXY" | grep -E 'rep#[0-9]+ error_code=25 e_data_encoding=method e_data_types=\[136\]' || {
    echo "rust FAST wrong-password missing 25 method [136]: $RUST_BADPW_PROXY" >&2
    exit 1
}
echo "$RUST_BADPW_PROXY" | grep -E 'rep#[0-9]+ error_code=24 e_data_encoding=method e_data_types=\[136\]' || {
    echo "rust FAST wrong-password missing 24 method [136]: $RUST_BADPW_PROXY" >&2
    exit 1
}
RUST_BADPW_SHAPE="$(echo "$RUST_BADPW_PROXY" | grep -E 'rep#[0-9]+ (error_code=|tag=)' | sed -E 's/^rep#[0-9]+ //' | sort -u || true)"

docker exec "$NAME" sh -c ':> /tmp/fast-err-rust.txt'
set +e
RUST_NOSUCH="$(docker exec -e KRB5_CONFIG=/tmp/krb5-fast-proxy.conf "$NAME" \
    kvno -c /tmp/krb5cc_fast nosuch/service 2>&1)"
set -e
echo "$RUST_NOSUCH"
echo "$RUST_NOSUCH" | grep -F 'Server nosuch/service@KERBER.TEST not found in Kerberos database' || {
    echo "rust FAST unknown-server client text missing: $RUST_NOSUCH" >&2
    exit 1
}
RUST_NOSUCH_PROXY="$(docker exec "$NAME" cat /tmp/fast-err-rust.txt 2>/dev/null || true)"
echo "$RUST_NOSUCH_PROXY"
echo "$RUST_NOSUCH_PROXY" | grep -E 'rep#[0-9]+ error_code=7 e_data_encoding=method e_data_types=\[136\]' || {
    echo "rust FAST unknown-server proxy line missing: $RUST_NOSUCH_PROXY" >&2
    exit 1
}
RUST_NOSUCH_SHAPE="$(echo "$RUST_NOSUCH_PROXY" | grep -E 'rep#[0-9]+ error_code=' | sed -E 's/^rep#[0-9]+ //' | sort -u)"

echo "==== MIT KDC: FAST wrong-password and unknown-server outer shapes ===="
# Harness user has empty Attributes; Rust --test-realm user has REQUIRES_PRE_AUTH.
# Align the flag so both legs emit 25 then 24 method [136], not an AS-REP 0x6b.
docker exec "$MITNAME" kadmin.local -q 'modprinc +requires_preauth user'
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
    echo "MIT kdc did not listen after +requires_preauth" >&2
    exit 1
fi
docker exec "$MITNAME" sh -c ':> /tmp/fast-err-mit.txt'
set +e
MIT_BADPW="$(docker exec -e KRB5_CONFIG=/tmp/krb5-fast-proxy.conf "$MITNAME" \
    sh -c 'printf "wrongpassword\n" | kinit -T /tmp/krb5cc_armor -c /tmp/krb5cc_bad user@KERBER.TEST' 2>&1)"
set -e
echo "$MIT_BADPW"
echo "$MIT_BADPW" | grep -q 'Password incorrect while getting initial credentials' || {
    echo "MIT FAST wrong-password client text missing: $MIT_BADPW" >&2
    exit 1
}
MIT_BADPW_PROXY="$(docker exec "$MITNAME" cat /tmp/fast-err-mit.txt 2>/dev/null || true)"
echo "$MIT_BADPW_PROXY"
echo "$MIT_BADPW_PROXY" | grep -q '136' || {
    echo "MIT FAST wrong-password proxy missing 136: $MIT_BADPW_PROXY" >&2
    exit 1
}
echo "$MIT_BADPW_PROXY" | grep -E 'rep#[0-9]+ error_code=25 e_data_encoding=method e_data_types=\[136\]' || {
    echo "MIT FAST wrong-password missing 25 method [136]: $MIT_BADPW_PROXY" >&2
    exit 1
}
echo "$MIT_BADPW_PROXY" | grep -E 'rep#[0-9]+ error_code=24 e_data_encoding=method e_data_types=\[136\]' || {
    echo "MIT FAST wrong-password missing 24 method [136]: $MIT_BADPW_PROXY" >&2
    exit 1
}
MIT_BADPW_SHAPE="$(echo "$MIT_BADPW_PROXY" | grep -E 'rep#[0-9]+ (error_code=|tag=)' | sed -E 's/^rep#[0-9]+ //' | sort -u || true)"
echo "rust_fast_badpw_shape=$RUST_BADPW_SHAPE"
echo "mit_fast_badpw_shape=$MIT_BADPW_SHAPE"
if [ "$RUST_BADPW_SHAPE" != "$MIT_BADPW_SHAPE" ]; then
    echo "FAST wrong-password outer shape differs rust vs MIT" >&2
    exit 1
fi

docker exec "$MITNAME" sh -c ':> /tmp/fast-err-mit.txt'
set +e
MIT_NOSUCH="$(docker exec -e KRB5_CONFIG=/tmp/krb5-fast-proxy.conf "$MITNAME" \
    kvno -c /tmp/krb5cc_fast nosuch/service 2>&1)"
set -e
echo "$MIT_NOSUCH"
echo "$MIT_NOSUCH" | grep -F 'Server nosuch/service@KERBER.TEST not found in Kerberos database' || {
    echo "MIT FAST unknown-server client text missing: $MIT_NOSUCH" >&2
    exit 1
}
MIT_NOSUCH_PROXY="$(docker exec "$MITNAME" cat /tmp/fast-err-mit.txt 2>/dev/null || true)"
echo "$MIT_NOSUCH_PROXY"
echo "$MIT_NOSUCH_PROXY" | grep -E 'rep#[0-9]+ error_code=7 e_data_encoding=method e_data_types=\[136\]' || {
    echo "MIT FAST unknown-server proxy line missing: $MIT_NOSUCH_PROXY" >&2
    exit 1
}
MIT_NOSUCH_SHAPE="$(echo "$MIT_NOSUCH_PROXY" | grep -E 'rep#[0-9]+ error_code=' | sed -E 's/^rep#[0-9]+ //' | sort -u)"
echo "rust_fast_nosuch_shape=$RUST_NOSUCH_SHAPE"
echo "mit_fast_nosuch_shape=$MIT_NOSUCH_SHAPE"
if [ "$RUST_NOSUCH_SHAPE" != "$MIT_NOSUCH_SHAPE" ]; then
    echo "FAST unknown-server outer shape differs rust vs MIT" >&2
    exit 1
fi

log "fast.kdc.gate" "ok" ',"principal":"user@KERBER.TEST","mode":"mit-kinit-T"'
exit 0
