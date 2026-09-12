#!/usr/bin/env bash
# Rust kinit --pkinit vs MIT 1.22.2 KDC (pkinit.so + KDC cert). MIT klist must
# name user@KERBER.TEST. Fails if pkinit.so is missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-pkinit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rust-kinit-pkinit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

assert_no_error_log() {
    if echo "$1" | grep -qF '"level":"ERROR"'; then
        echo "$1" >&2
        log "pkinit.client.gate" "error" ',"error":"happy-path ERROR log"'
        exit 1
    fi
}

if ! command -v docker >/dev/null 2>&1; then
    log "pkinit.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc
cargo build -p krb5-client --bin krb5-kinit

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
        log "pkinit.client.gate" "error" ',"error":"harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "pkinit.client.gate" "error" ',"error":"harness did not become ready"'
    docker logs "$NAME" >&2 || true
    exit 1
fi

PLUGIN="$(docker exec "$NAME" sh -c 'find /usr -name pkinit.so 2>/dev/null | head -1' || true)"
if [ -z "$PLUGIN" ]; then
    echo "MIT pkinit plugin not present (image built without OpenSSL PKINIT)"
    log "pkinit.client.gate" "error" ',"error":"pkinit.so absent"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc-export
docker exec "$NAME" chmod +x /tmp/krb5-kdc-export
docker exec "$NAME" mkdir -p /tmp/pkinit
docker exec \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME" sh -c '
        /tmp/krb5-kdc-export --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:18888 >/tmp/pkinit-export.log 2>&1 &
        ep=$!
        okpem=0
        for _ in $(seq 1 200); do
            if [ -s /tmp/pkinit/kdc.pem ]; then
                okpem=1
                break
            fi
            sleep 0.1
        done
        kill "$ep" 2>/dev/null || true
        wait "$ep" 2>/dev/null || true
        if [ "$okpem" != 1 ]; then
            echo "pkinit export timed out" >&2
            cat /tmp/pkinit-export.log >&2 || true
            exit 1
        fi
    '
if ! docker exec "$NAME" test -s /tmp/pkinit/kdc.pem; then
    log "pkinit.client.gate" "error" ',"error":"pkinit export timed out"'
    docker exec "$NAME" cat /tmp/pkinit-export.log >&2 || true
    exit 1
fi
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/ca.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN EC PRIVATE KEY' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/kdc.pem
docker exec "$NAME" grep -q 'BEGIN EC PRIVATE KEY' /tmp/pkinit/kdc.pem

docker exec "$NAME" sh -c 'grep -q pkinit_identity /etc/krb5kdc/kdc.conf || sed -i "/\[kdcdefaults\]/a\\    pkinit_identity = FILE:/tmp/pkinit/kdc.pem\\n    pkinit_anchors = FILE:/tmp/pkinit/ca.pem\\n    pkinit_dh_min_bits = P-256" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
t = p.read_text()
if "pkinit_indicator" not in t:
    t = t.replace("supported_enctypes", "        pkinit_indicator = pkinit\n        supported_enctypes", 1)
    p.write_text(t)
'
docker exec "$NAME" kadmin.local -q 'modprinc +requires_preauth user'
docker exec "$NAME" sh -c 'grep -q pkinit_anchors /etc/krb5.conf || cat >> /etc/krb5.conf <<EOF

[libdefaults]
    pkinit_eku_checking = none
    pkinit_kdc_hostname = kerber.test
    pkinit_dh_min_bits = 3072

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
        pkinit_eku_checking = none
        pkinit_kdc_hostname = kerber.test
    }
EOF'

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
    log "pkinit.client.gate" "error" ',"error":"MIT krb5kdc did not listen after PKINIT config"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

echo "==== Rust kinit --pkinit vs MIT KDC ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT="$(docker exec -e KRB5_PASSWORD= "$NAME" \
    /tmp/krb5-kinit --pkinit FILE:/tmp/pkinit/user.pem --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/krb5cc_pkinit user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    echo "==== MIT kdc log ===="
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    echo "==== MIT kdc TRACE ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    echo "==== export log ===="
    docker exec "$NAME" cat /tmp/pkinit-export.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"rust kinit --pkinit failed","rc":'"$rc"
    exit 1
fi
assert_no_error_log "$OUT"
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_pkinit 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
TRACE="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE$OUT" | grep -Eqi 'PKINIT|pa[_ ]?type[[:space:]]*16|padata type 16|PA-PK-AS|client.pkinit'; then
    log "pkinit.client.gate" "error" ',"error":"kinit succeeded without PKINIT evidence"'
    exit 1
fi
log "pkinit.client.gate" "ok" ',"mode":"rust-kinit","pa_type":16,"principal":"user@KERBER.TEST","mit_plugin":"present"'

echo "==== mit_kdc MIT kinit pkinit_dh_min_bits=2048 TYPED-DATA + cookie ===="
mit_kdc_pkinit_dh1024() {
    local proxy=1888
    docker cp "$ROOT/scripts/lib/kdc-error-proxy.py" "$NAME":/tmp/kdc-error-proxy.py
    docker cp "$ROOT/scripts/lib/openssl-seclevel0.cnf" "$NAME":/tmp/openssl-seclevel0.cnf
    docker exec "$NAME" rm -f /tmp/pkinit-65.txt
    docker exec -d "$NAME" python3 /tmp/kdc-error-proxy.py "$proxy" 127.0.0.1 88 /tmp/pkinit-65.txt
    sleep 0.4
    docker exec "$NAME" sh -c "cat > /tmp/krb5-dh1024.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    preferred_preauth_types = 16
    pkinit_eku_checking = none
    pkinit_kdc_hostname = kerber.test
    pkinit_dh_min_bits = 2048
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:${proxy}
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
        pkinit_eku_checking = none
        pkinit_kdc_hostname = kerber.test
        pkinit_dh_min_bits = 2048
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
        echo "mit_kdc PKINIT DH-min 2048 did not return protocol 65: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'e_data_encoding=typed' || {
        echo "mit_kdc PKINIT 65 e_data is not TYPED-DATA: $out" >&2
        exit 1
    }
    echo "$out" | grep -F '109' | grep -q '133' || {
        echo "mit_kdc PKINIT 65 missing TD-DH-PARAMETERS 109 or FX-COOKIE 133: $out" >&2
        exit 1
    }
}
mit_kdc_pkinit_dh1024

echo "==== require_auth pkinit: MIT kinit PKINIT kvno issued, password kvno 12 ===="
docker exec "$NAME" kadmin.local -q 'setstr host/testhost.kerber.test require_auth pkinit'
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
set +e
docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
mpk=$?
set -e
if [ "$mpk" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT kinit PKINIT after require_auth failed","rc":'"$mpk"
    exit 1
fi
set +e
MPKKV="$(docker exec "$NAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$MPKKV"
echo "$MPKKV" | grep -q 'host/testhost.kerber.test@KERBER.TEST: kvno =' || {
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT kvno after PKINIT TGT + require_auth pkinit failed"'
    exit 1
}
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec "$NAME" sh -c ': >/tmp/mit-kdc.log'
set +e
docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
mpw=$?
set -e
if [ "$mpw" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT password kinit after require_auth pkinit failed","rc":'"$mpw"
    exit 1
fi
set +e
MPWKV="$(docker exec "$NAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$MPWKV"
echo "$MPWKV" | grep -q 'KDC policy rejects request' || {
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT password kvno after require_auth pkinit missing KDC policy rejects request"'
    exit 1
}
docker exec "$NAME" grep -q 'HIGHER_AUTHENTICATION_REQUIRED' /tmp/mit-kdc.log || {
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT KDC log missing HIGHER_AUTHENTICATION_REQUIRED"'
    exit 1
}

echo "==== PKINIT TGT has no H; +requires_hwauth host is NO HW PREAUTH ===="
docker exec "$NAME" kadmin.local -q 'delstr host/testhost.kerber.test require_auth' || true
docker exec "$NAME" kadmin.local -q 'modprinc +requires_hwauth host/testhost.kerber.test'
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
set +e
docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    kinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem user@KERBER.TEST
mhw=$?
set -e
if [ "$mhw" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT kinit PKINIT after +requires_hwauth failed","rc":'"$mhw"
    exit 1
fi
MHWL="$(docker exec "$NAME" klist -f)"
echo "$MHWL"
MHBITS="$(echo "$MHWL" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "hbits=$MHBITS"
echo "$MHBITS" | grep -qv H || {
    log "pkinit.client.gate" "error" ',"error":"MIT PKINIT TGT has H"'
    exit 1
}
docker exec "$NAME" sh -c ': >/tmp/mit-kdc.log'
set +e
MHWKV="$(docker exec "$NAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$MHWKV"
echo "$MHWKV" | grep -qiE 'Generic error|KDC policy rejects request|NO HW PREAUTH' || {
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT kvno after PKINIT TGT +requires_hwauth host did not fail"'
    exit 1
}
docker exec "$NAME" grep -q 'NO HW PREAUTH' /tmp/mit-kdc.log || {
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT KDC log missing NO HW PREAUTH"'
    exit 1
}

echo "==== negative: MIT KDC identity is a client cert (rogue KDC) ===="
docker exec "$NAME" sh -c 'grep -q pkinit_identity /etc/krb5kdc/kdc.conf && sed -i "s|pkinit_identity = FILE:/tmp/pkinit/kdc.pem|pkinit_identity = FILE:/tmp/pkinit/user.pem|" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc-rogue.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc-rogue.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    echo "MIT krb5kdc did not listen with client-cert identity"
    docker exec "$NAME" cat /tmp/mit-kdc-rogue.log >&2 || true
    log "pkinit.client.gate" "error" ',"error":"MIT krb5kdc did not listen with client-cert identity"'
    exit 1
fi
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc-rogue.trace' || true
set +e
ROGUE="$(docker exec -e KRB5_PASSWORD= "$NAME" \
    /tmp/krb5-kinit --pkinit FILE:/tmp/pkinit/user.pem --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/krb5cc_pkinit_rogue user@KERBER.TEST 2>&1)"
rrc=$?
set -e
echo "$ROGUE"
if [ "$rrc" -eq 0 ]; then
    echo "==== MIT kdc rogue log ===="
    docker exec "$NAME" cat /tmp/mit-kdc-rogue.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"rust kinit accepted client-cert KDC CMS"'
    exit 1
fi
if ! echo "$ROGUE" | grep -q 'pkinit kdc eku'; then
    echo "$ROGUE" >&2
    log "pkinit.client.gate" "error" ',"error":"rogue KDC refused without pkinit kdc eku","rc":'"$rrc"
    exit 1
fi
log "pkinit.client.gate" "ok" ',"mode":"rust-kinit-rogue","refused":"client-cert-kdc","rc":'"$rrc"

echo "==== restore KDC identity; anonymous PKINIT + restrict_anon ===="
docker exec "$NAME" sh -c 'grep -q pkinit_identity /etc/krb5kdc/kdc.conf && sed -i "s|pkinit_identity = FILE:/tmp/pkinit/user.pem|pkinit_identity = FILE:/tmp/pkinit/kdc.pem|" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
t = p.read_text()
if "restrict_anonymous_to_tgt" not in t:
    t = t.replace("[kdcdefaults]", "[kdcdefaults]\n    restrict_anonymous_to_tgt = true", 1)
    p.write_text(t)
'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey WELLKNOWN/ANONYMOUS@KERBER.TEST'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey host/anonrestrict.kerber.test'
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc-anon.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc-anon.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc-anon.log >&2 || true
    log "pkinit.client.gate" "error" ',"error":"MIT krb5kdc did not listen after restrict_anon"'
    exit 1
fi
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
set +e
ANONOUT="$(docker exec -e KRB5_PASSWORD= "$NAME" \
    /tmp/krb5-kinit -n --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/krb5cc_anon 2>&1)"
anonrc=$?
set -e
echo "$ANONOUT"
if [ "$anonrc" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc-anon.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"rust kinit -n vs MIT KDC failed","rc":'"$anonrc"
    exit 1
fi
assert_no_error_log "$ANONOUT"
ANONL="$(docker exec "$NAME" klist -c /tmp/krb5cc_anon 2>/dev/null || true)"
echo "$ANONL"
echo "$ANONL" | grep -q 'WELLKNOWN/ANONYMOUS' || {
    log "pkinit.client.gate" "error" ',"error":"klist after rust kinit -n missing WELLKNOWN/ANONYMOUS"'
    exit 1
}
echo "$ANONL" | grep -q 'WELLKNOWN:ANONYMOUS' || {
    log "pkinit.client.gate" "error" ',"error":"klist after rust kinit -n missing WELLKNOWN:ANONYMOUS"'
    exit 1
}
set +e
ANONKV="$(docker exec "$NAME" kvno -c /tmp/krb5cc_anon host/anonrestrict.kerber.test 2>&1)"
set -e
echo "$ANONKV"
echo "$ANONKV" | grep -q 'KDC policy rejects request' || {
    docker exec "$NAME" cat /tmp/mit-kdc-anon.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"kvno after rust kinit -n missing KDC policy rejects request"'
    exit 1
}
docker exec "$NAME" grep -q 'ANONYMOUS NOT ALLOWED' /tmp/mit-kdc-anon.log || {
    docker exec "$NAME" cat /tmp/mit-kdc-anon.log 2>/dev/null || true
    log "pkinit.client.gate" "error" ',"error":"MIT KDC log missing ANONYMOUS NOT ALLOWED"'
    exit 1
}
log "pkinit.client.gate" "ok" ',"mode":"rust-kinit-anon","principal":"WELLKNOWN/ANONYMOUS","restrict_anon":12'
exit 0
