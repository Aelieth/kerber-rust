#!/usr/bin/env bash
# Rust kinit --spake vs MIT 1.22.2 KDC (P-256). MIT klist must name user@KERBER.TEST.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kinit

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-spake-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

assert_no_error_log() {
    if echo "$1" | grep -qF '"level":"ERROR"'; then
        echo "$1" >&2
        log "spake.client.gate" "error" ',"error":"happy-path ERROR log"'
        exit 1
    fi
}

if ! command -v docker >/dev/null 2>&1; then
    log "spake.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

stock_mit_kdc
mit_live_guard

docker exec "$NAME" sh -c 'grep -q spake_preauth_groups /etc/krb5kdc/kdc.conf || sed -i "/\[kdcdefaults\]/a\\    spake_preauth_groups = P-256" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" sh -c 'grep -q spake_preauth_groups /etc/krb5.conf || sed -i "/\[libdefaults\]/a\\    spake_preauth_groups = P-256\n    preferred_preauth_types = 151" /etc/krb5.conf'
docker exec "$NAME" kadmin.local -q 'modprinc +requires_preauth user'
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5kdc || true
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc >/tmp/mit-kdc.log 2>&1'
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
    log "spake.client.gate" "error" ',"error":"MIT krb5kdc did not listen after SPAKE config"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

PROXY=1888
docker cp "$ROOT/scripts/lib/kdc-error-proxy.py" "$NAME":/tmp/kdc-error-proxy.py
docker exec -d "$NAME" python3 /tmp/kdc-error-proxy.py "$PROXY" 127.0.0.1 88 /tmp/spake-91.txt
wait_udp_in "$NAME" "$PROXY" || die "proxy $PROXY did not listen"
docker exec "$NAME" sh -c "cat >/tmp/spake-proxy-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    preferred_preauth_types = 151
    spake_preauth_groups = P-256
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:${PROXY}
    }
EOF"

echo "==== Rust kinit --spake vs MIT KDC ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT="$(docker exec -e KRB5_PASSWORD=userpassword -e KRB5_CONFIG=/tmp/spake-proxy-krb5.conf "$NAME" \
    /tmp/krb5-kinit --spake -c /tmp/krb5cc_spake user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    echo "==== MIT kdc log ===="
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null || true
    echo "==== MIT kdc TRACE ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "spake.client.gate" "error" ',"error":"rust kinit --spake failed","rc":'"$rc"
    exit 1
fi
assert_no_error_log "$OUT"
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_spake 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
echo "==== Rust kinit recorded fast_avail and pa_type (SPAKE) like write_out_ccache ===="
KLISTC="$(docker exec "$NAME" klist -C -c /tmp/krb5cc_spake 2>/dev/null || true)"
echo "$KLISTC"
echo "$KLISTC" | grep -F 'config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes'
echo "$KLISTC" | grep -F 'config: pa_type(krbtgt/KERBER.TEST@KERBER.TEST) = 151'
TRACE="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE" | grep -Eq 'SPAKE response received|SPAKE derived K'; then
    echo "$TRACE" >&2
    log "spake.client.gate" "error" ',"error":"kinit succeeded without SPAKE completion TRACE"'
    exit 1
fi
echo "$TRACE" | grep -E 'SPAKE response received|SPAKE derived K'
SPAKE91="$(docker exec "$NAME" cat /tmp/spake-91.txt 2>/dev/null || true)"
echo "==== SPAKE 91 e_text (Rust kinit vs MIT KDC) ===="
echo "$SPAKE91"
echo "$SPAKE91" | grep -F 'error_code=91'
echo "$SPAKE91" | grep -F 'e_text=PREAUTH_FAILED'
log "spake.client.gate" "ok" ',"mode":"rust-kinit","pa_type":151,"group":2,"principal":"user@KERBER.TEST","e_text":"PREAUTH_FAILED"'
exit 0
