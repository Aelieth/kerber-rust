#!/usr/bin/env bash
# MIT pkinit vs Rust KDC using FILE trust anchors from the test CA.
# Fails if MIT pkinit.so is missing or MIT kinit PKINIT does not succeed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-pkinit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"pkinit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "pkinit.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb -p krb5-admin --bin krb5-kadmin-local

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kadmin-local
docker exec "$NAME" sh -c 'cat > /tmp/rust-kdc.conf <<EOF
[realms]
    KERBER.TEST = {
        pkinit_indicator = pkinit
    }
EOF'
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/tmp/rust-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
if [ "$ok" -ne 1 ]; then
    log "pkinit.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

echo "==== PKINIT CA PEM ===="
docker exec "$NAME" sh -c 'ls -l /tmp/pkinit; echo ---- ca.pem; cat /tmp/pkinit/ca.pem'
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/ca.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN EC PRIVATE KEY' /tmp/pkinit/user.pem

PLUGIN="$(docker exec "$NAME" sh -c 'find /usr -name pkinit.so 2>/dev/null | head -1' || true)"
if [ -z "$PLUGIN" ]; then
    echo "MIT pkinit plugin not present (image built without OpenSSL PKINIT)"
    log "pkinit.gate" "error" ',"error":"pkinit.so absent"'
    exit 1
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac
docker exec "$NAME" sh -c "cat >> /etc/krb5.conf <<EOF

[libdefaults]
    pkinit_eku_checking = none
    pkinit_kdc_hostname = kerber.test
    pkinit_dh_min_bits = 3072

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:${PORT}
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
        pkinit_eku_checking = none
        pkinit_kdc_hostname = kerber.test
    }
EOF"

echo "==== MIT kinit PKINIT ===="
set +e
docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
rc=$?
set -e
docker exec "$NAME" klist || true
if [ "$rc" -eq 0 ]; then
    docker exec "$NAME" klist | grep -q 'user@KERBER.TEST'
    echo "==== KDC PKINIT KDF ===="
    docker exec "$NAME" grep -E 'rfc8636|kdf|pkinit' /tmp/kdc.log || true
    docker exec "$NAME" grep -q 'rfc8636 sha256 kdf' /tmp/kdc.log
    echo "==== negative: MIT kinit with SAN≠cname ===="
    docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/other.pem
    set +e
    docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
        kinit -X X509_user_identity=FILE:/tmp/pkinit/other.pem user@KERBER.TEST
    nrc=$?
    set -e
    if [ "$nrc" -eq 0 ]; then
        echo "MIT kinit with other.pem SAN must not issue user@KERBER.TEST"
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"SAN mismatch accepted"'
        exit 1
    fi
    KDCLOG="$(docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true)"
    if ! echo "$KDCLOG" | grep -q 'pkinit client san'; then
        echo "$KDCLOG" >&2
        log "pkinit.gate" "error" ',"error":"SAN mismatch refused without pkinit client san"'
        exit 1
    fi
    echo "$KDCLOG" | grep 'pkinit client san'

    echo "==== rust_kdc unsupported group P-384 → 65 TYPED-DATA shape (MIT accepts P-384 — item 17) ===="
    rust_kdc_pkinit_dh1024() {
        local proxy=1888
        docker cp "$ROOT/scripts/lib/kdc-error-proxy.py" "$NAME":/tmp/kdc-error-proxy.py
        docker cp "$ROOT/scripts/lib/openssl-seclevel0.cnf" "$NAME":/tmp/openssl-seclevel0.cnf
        docker exec "$NAME" rm -f /tmp/pkinit-65.txt
        docker exec -d "$NAME" python3 /tmp/kdc-error-proxy.py "$proxy" 127.0.0.1 "$PORT" /tmp/pkinit-65.txt
        sleep 0.4
        docker exec "$NAME" sh -c "cat > /tmp/krb5-dh1024.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    preferred_preauth_types = 16
    pkinit_eku_checking = none
    pkinit_kdc_hostname = kerber.test
    pkinit_dh_min_bits = P-384
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:${proxy}
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
        pkinit_eku_checking = none
        pkinit_kdc_hostname = kerber.test
        pkinit_dh_min_bits = P-384
    }
EOF"
        set +e
        docker exec \
            -e KRB5_CONFIG=/tmp/krb5-dh1024.conf \
            -e OPENSSL_CONF=/tmp/openssl-seclevel0.cnf \
            -e KRB5_TRACE=/dev/stderr \
            "$NAME" timeout 20 kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
        set -e
        local out
        out="$(docker exec "$NAME" cat /tmp/pkinit-65.txt 2>/dev/null || true)"
        echo "$out"
        echo "$out" | grep -F 'error_code=65' || {
            echo "rust_kdc PKINIT DH-min P-384 did not return protocol 65: $out" >&2
            exit 1
        }
        echo "$out" | grep -F 'e_data_encoding=typed' || {
            echo "rust_kdc PKINIT 65 e_data is not TYPED-DATA: $out" >&2
            exit 1
        }
        echo "$out" | grep -F '109' | grep -q '133' || {
            echo "rust_kdc PKINIT 65 missing TD-DH-PARAMETERS 109 or FX-COOKIE 133: $out" >&2
            exit 1
        }
    }
    rust_kdc_pkinit_dh1024

    echo "==== require_auth pkinit: PKINIT kvno issued, password kvno 12 ===="
    SETSTR="$(docker exec \
        -e KRB5_KDC_DB=/tmp/rust.db \
        -e KRB5_KDC_STASH=/tmp/rust.stash \
        "$NAME" /tmp/krb5-kdb setstr host/testhost.kerber.test require_auth pkinit)"
    echo "$SETSTR"
    echo "$SETSTR" | grep -q 'ok setstr' || {
        log "pkinit.gate" "error" ',"error":"krb5-kdb setstr require_auth failed"'
        exit 1
    }
    docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
    set +e
    docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
        kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
    pkrc=$?
    set -e
    if [ "$pkrc" -ne 0 ]; then
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"MIT kinit PKINIT after require_auth failed","rc":'"$pkrc"
        exit 1
    fi
    set +e
    PKKV="$(docker exec "$NAME" kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$PKKV"
    echo "$PKKV" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1' || {
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"kvno after PKINIT TGT + require_auth pkinit failed"'
        exit 1
    }
    docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
    docker exec "$NAME" sh -c ': >/tmp/kdc.log'
    set +e
    docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
    pwrc=$?
    set -e
    if [ "$pwrc" -ne 0 ]; then
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"password kinit after require_auth pkinit failed","rc":'"$pwrc"
        exit 1
    fi
    set +e
    PWKC="$(docker exec "$NAME" kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$PWKC"
    echo "$PWKC" | grep -q 'KDC policy rejects request' || {
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"password kvno after require_auth pkinit missing KDC policy rejects request"'
        exit 1
    }
    docker exec "$NAME" grep -q 'HIGHER_AUTHENTICATION_REQUIRED' /tmp/kdc.log || {
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"rust KDC log missing HIGHER_AUTHENTICATION_REQUIRED"'
        exit 1
    }

    echo "==== PKINIT TGT has no H; +requires_hwauth host is NO HW PREAUTH ===="
    HWMOD="$(docker exec \
        -e KRB5_KDC_DB=/tmp/rust.db \
        -e KRB5_KDC_STASH=/tmp/rust.stash \
        "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +requires_hwauth host/testhost.kerber.test')"
    echo "$HWMOD"
    docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
    set +e
    docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
        kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
    hwrc=$?
    set -e
    if [ "$hwrc" -ne 0 ]; then
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"MIT kinit PKINIT after +requires_hwauth failed","rc":'"$hwrc"
        exit 1
    fi
    HWL="$(docker exec "$NAME" klist -f)"
    echo "$HWL"
    HBITS="$(echo "$HWL" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
    echo "hbits=$HBITS"
    echo "$HBITS" | grep -qv H || {
        log "pkinit.gate" "error" ',"error":"rust PKINIT TGT has H"'
        exit 1
    }
    docker exec "$NAME" sh -c ': >/tmp/kdc.log'
    set +e
    HWKC="$(docker exec "$NAME" kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$HWKC"
    echo "$HWKC" | grep -qiE 'Generic error|KDC policy rejects request|NO HW PREAUTH' || {
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"kvno after PKINIT TGT +requires_hwauth host did not fail"'
        exit 1
    }
    docker exec "$NAME" grep -q 'NO HW PREAUTH' /tmp/kdc.log || {
        docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
        log "pkinit.gate" "error" ',"error":"rust KDC log missing NO HW PREAUTH"'
        exit 1
    }

    log "pkinit.gate" "ok" ',"mode":"mit-kinit","kdf":"rfc8636-sha256","mit_plugin":"present","san_mismatch":"refused","dh_typed":"typed+cookie","pkinit_require_auth":"issued+12","pkinit_h":false,"no_hw_preauth":60'
    exit 0
fi
echo "MIT kinit with FILE identity failed (rc=$rc)"
echo "==== rust KDC log after kinit ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
log "pkinit.gate" "error" ',"error":"mit kinit pkinit failed","rc":'"$rc"
exit 1
