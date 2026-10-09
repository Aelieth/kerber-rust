#!/usr/bin/env bash
# MIT kinit SPAKE vs Rust KDC. Fails unless MIT obtains a TGT via PA-SPAKE (151): P-256 through
# support and a challenge, then edwards25519 through Fedora's optimistic challenge.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-spake-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "spake.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

shell_container

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker exec "$NAME" chmod +x /tmp/krb5-kdc
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

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
    log "spake.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac

PROXY=1888
docker cp "$ROOT/scripts/lib/kdc-error-proxy.py" "$NAME":/tmp/kdc-error-proxy.py
wait_bound_free_in "$NAME" "$PROXY" udp || die "stale proxy still bound :$PROXY"
docker exec -d "$NAME" python3 /tmp/kdc-error-proxy.py "$PROXY" 127.0.0.1 "$PORT" /tmp/spake-91.txt
wait_udp_in "$NAME" "$PROXY" || die "proxy $PROXY did not listen"

docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:${PROXY}/' /etc/krb5.conf"
docker exec "$NAME" sh -c "cat >> /etc/krb5.conf <<EOF

[libdefaults]
    preferred_preauth_types = 151
    spake_preauth_groups = P-256
EOF"

echo "==== MIT kinit SPAKE ===="
set +e
TRACE="$(docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' 2>&1)"
rc=$?
set -e
echo "$TRACE"
KLIST="$(docker exec "$NAME" klist 2>/dev/null || true)"
echo "$KLIST"
if [ "$rc" -ne 0 ]; then
    echo "==== rust KDC log after kinit ===="
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    log "spake.gate" "error" ',"error":"mit kinit spake failed","rc":'"$rc"
    exit 1
fi
echo "$KLIST" | grep -q 'user@KERBER.TEST'
if ! echo "$TRACE" | grep -qF 'Preauth module spake (151) (real) returned: 0/Success'; then
    log "spake.gate" "error" ',"error":"kinit succeeded without pa_type 151"'
    exit 1
fi
if ! echo "$TRACE" | grep -Eq 'group[[:space:]]*2|group=2|SPAKE challenge with group 2'; then
    log "spake.gate" "error" ',"error":"kinit succeeded without SPAKE group 2"'
    exit 1
fi
SPAKE91="$(docker exec "$NAME" cat /tmp/spake-91.txt 2>/dev/null || true)"
echo "==== SPAKE 91 e_text (MIT kinit vs Rust KDC) ===="
echo "$SPAKE91"
echo "$SPAKE91" | grep -F 'error_code=91'
echo "$SPAKE91" | grep -F 'e_text=PREAUTH_FAILED'
if echo "$SPAKE91" | grep -F 'e_text=SPAKE challenge'; then
    echo "SPAKE 91 e_text was prose SPAKE challenge" >&2
    exit 1
fi
require_log "$NAME" /tmp/kdc.log '"code":91,"e_text":"PREAUTH_FAILED"' 'SPAKE 91 PREAUTH_FAILED in /tmp/kdc.log'
KDCLOG="$(docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true)"
echo "$KDCLOG" | grep -F '"code":91,"e_text":"PREAUTH_FAILED"'

# Fedora's settings: krb5.conf permits edwards25519 and kdc.conf sets spake_preauth_kdc_challenge =
# edwards25519. MIT 1.22.2's KDC then sends an edwards25519 challenge with PREAUTH_REQUIRED, and a
# stock kinit with its default group answers it in its second request. The Rust KDC must too.
echo "==== MIT kinit, default groups, vs Rust KDC with Fedora's SPAKE settings ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5-kdc || die "rust KDC did not stop"
docker exec "$NAME" sh -c "cat >/tmp/spake-ed25519-kdc.conf <<'EOF'
[libdefaults]
    spake_preauth_groups = edwards25519
[kdcdefaults]
    spake_preauth_kdc_challenge = edwards25519
EOF
: >/tmp/kdc.log"
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_PROFILE=/tmp/spake-ed25519-kdc.conf \
    "$NAME" sh -c "/tmp/krb5-kdc --test-realm 127.0.0.1:$PORT >/tmp/kdc.log 2>&1"
require_listen "$NAME" /tmp/kdc.log "rust KDC (edwards25519)"
ED_PROXY=1891
docker cp "$ROOT/scripts/lib/kdc-padata-proxy.py" "$NAME":/tmp/kdc-padata-proxy.py
wait_bound_free_in "$NAME" "$ED_PROXY" udp || die "stale proxy still bound :$ED_PROXY"
docker exec -d "$NAME" python3 /tmp/kdc-padata-proxy.py "$ED_PROXY" 127.0.0.1 "$PORT" /tmp/spake-ed25519-wire.txt
wait_udp_in "$NAME" "$ED_PROXY" || die "proxy $ED_PROXY did not listen"
docker exec "$NAME" sh -c "cat >/tmp/spake-default-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:$ED_PROXY
    }
EOF"
set +e
EDTRACE="$(docker exec -e KRB5_TRACE=/dev/stderr -e KRB5_CONFIG=/tmp/spake-default-krb5.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -c /tmp/krb5cc_ed25519 user@KERBER.TEST' 2>&1)"
rc=$?
set -e
echo "$EDTRACE"
[ "$rc" -eq 0 ] || die "MIT kinit (default groups) vs Rust KDC failed, rc $rc"
echo "$EDTRACE" | grep -F 'SPAKE challenge received with group 1' || die "no edwards25519 challenge"
echo "$EDTRACE" | grep -F 'Preauth module spake (151) (real) returned: 0/Success' || die "edwards25519 SPAKE did not complete"
WIRE="$(docker exec "$NAME" cat /tmp/spake-ed25519-wire.txt)"
echo "$WIRE"
echo "$WIRE" | grep -F 'rep#1 error_code=25 e_data_encoding=method e_data_types=[136, 19, 151, 2, 133]' \
    || die "PREAUTH_REQUIRED e-data is not MIT's {136, 19, 151, 2, 133}"
echo "$WIRE" | grep -F 'req#2 msg_type=10 padata=[133, 151, 150, 149]' || die "the response request is not {133, 151, 150, 149}"
echo "$WIRE" | grep -E 'rep#2 tag=0x6b' | grep -F 'padata=[19]' || die "the AS-REP after SPAKE is not MIT's {19}"
docker exec "$NAME" klist -C -c /tmp/krb5cc_ed25519 | grep -F 'config: pa_type(krbtgt/KERBER.TEST@KERBER.TEST) = 151' \
    || die "edwards25519 kinit did not record pa_type 151"
log "spake.gate" "ok" ',"mode":"mit-kinit","pa_type":151,"group":2,"principal":"user@KERBER.TEST","e_text":"PREAUTH_FAILED"'
exit 0
