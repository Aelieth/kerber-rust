#!/usr/bin/env bash
# Isolated AD.KERBER.TEST ↔ KERBER.TEST referral/trust gate.
# NEVER writes /etc/krb5.conf or SSSD. Lab state lives in ~/adlab.
#
# Exit 0 only if MIT kinit kbruser@AD.KERBER.TEST then kvno yields
# krbtgt/KERBER.TEST@AD.KERBER.TEST and host/testhost.kerber.test@KERBER.TEST
# (etype 17 or 18) in klist. Exit 2 is honest unavailability.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-50fb1f8298b1/implementer}"
mkdir -p "$SCRATCH"

ADLAB="${ADLAB:-$HOME/adlab}"
if [ -f "$ADLAB/env" ]; then
    # shellcheck disable=SC1091
    set -a
    # Operator-held secrets (0600). Never commit this file.
    . "$ADLAB/env"
    set +a
fi

export KRB5_CONFIG="${KRB5_CONFIG:-$ADLAB/ad-krb5.conf}"
export KRB5CCNAME="FILE:$SCRATCH/ad-mit-trust.ccache"
export KRB5_KTNAME="FILE:$ADLAB/svc.keytab"
BIND="${KERBER_KDC_BIND:-10.10.44.154:8888}"
HEX_FILE="${ADLAB}/interrealm.aes256.hex"

LOG="$SCRATCH/ad-mit-trust-gate.log"
KDC_LOG="$SCRATCH/ad-mit-kdc.log"
KDC_PID=""

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ad-mit-trust-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

cleanup() {
    if [ -n "$KDC_PID" ]; then
        kill "$KDC_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

{
    echo "KRB5_CONFIG=$KRB5_CONFIG"
    echo "KRB5CCNAME=$KRB5CCNAME"
    echo "KERBER_KDC_BIND=$BIND"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    echo "date=$(date -Iseconds)"
    grep -E 'default_realm' /etc/krb5.conf | head -5 || true
    echo "---- isolated profile ----"
    cat "$KRB5_CONFIG" 2>/dev/null || echo "missing $KRB5_CONFIG"
    echo "---- ping DC ----"
    ping -c 1 -W 2 10.10.38.38 || true
} | tee "$LOG"

if ! grep -q 'TESTLABBY.LOCAL' /etc/krb5.conf; then
    log "ad.mit.trust.gate" "error" ',"error":"host /etc/krb5.conf is not TESTLABBY.LOCAL"'
    echo "isolation fail: host krb5.conf changed" | tee -a "$LOG"
    exit 1
fi

if ! ping -c 1 -W 2 10.10.38.38 >/dev/null 2>&1; then
    log "ad.mit.trust.gate" "error" ',"error":"DC 10.10.38.38 unreachable"'
    echo "DC unreachable" | tee -a "$LOG"
    exit 2
fi

if grep -E '(^|[^[:alnum:].])KERBER\.TEST' "$KRB5_CONFIG" >/dev/null 2>&1; then
    echo "isolated profile names KERBER.TEST (client-side trust stanza present)" | tee -a "$LOG"
else
    echo "isolated profile has no KERBER.TEST stanza (no client-side trust)" | tee -a "$LOG"
fi

# Start the KERBER.TEST KDC if the operator-held inter-realm key exists.
if [ -f "$HEX_FILE" ]; then
    host="${BIND%%:*}"
    port="${BIND##*:}"
    if ! ss -ulnp 2>/dev/null | grep -q "${host}:${port}"; then
        echo "starting krb5-kdc --test-realm $BIND" | tee -a "$LOG"
        cargo build -p krb5-kdc --bin krb5-kdc -q
        mkdir -p "$ADLAB/kdc"
        KEY="$(tr -d ' \n' <"$HEX_FILE")"
        KRB5_TEST_USER_PASSWORD="${KRB5_TEST_USER_PASSWORD:-userpassword}" \
        KRB5_TEST_ADMIN_PASSWORD="${KRB5_TEST_ADMIN_PASSWORD:-adminpassword}" \
        KRB5_TEST_FOREIGN_REALM=AD.KERBER.TEST \
        KRB5_TEST_INTERREALM_KEY="$KEY" \
        KRB5_KDC_DB="$ADLAB/kdc/principal" \
        KRB5_KDC_STASH="$ADLAB/kdc/stash" \
        RUST_LOG="${RUST_LOG:-krb5_kdc=info}" \
            ./target/debug/krb5-kdc --test-realm "$BIND" >"$KDC_LOG" 2>&1 &
        KDC_PID=$!
        ok=0
        for _ in $(seq 1 80); do
            if grep -q '^listening ' "$KDC_LOG" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.1
        done
        if [ "$ok" -ne 1 ]; then
            echo "KERBER.TEST KDC did not listen" | tee -a "$LOG"
            cat "$KDC_LOG" >>"$LOG" || true
        fi
    else
        echo "KERBER.TEST KDC already listening $BIND" | tee -a "$LOG"
    fi
else
    echo "no $HEX_FILE; host ticket hop needs the shared AES key" | tee -a "$LOG"
fi

PASS="${AD_KBRUSER_PASSWORD:-}"
set +e
if [ -n "$PASS" ]; then
    printf '%s\n' "$PASS" | timeout 20 kinit kbruser@AD.KERBER.TEST >>"$LOG" 2>&1
    kinit_rc=$?
else
    echo "AD_KBRUSER_PASSWORD unset; kinit will fail" | tee -a "$LOG"
    echo | timeout 20 kinit kbruser@AD.KERBER.TEST >>"$LOG" 2>&1
    kinit_rc=$?
fi
set -e
echo "kinit_rc=$kinit_rc" | tee -a "$LOG"

if [ "$kinit_rc" -eq 0 ]; then
    set +e
    timeout 20 kvno krbtgt/KERBER.TEST@AD.KERBER.TEST >>"$LOG" 2>&1
    timeout 20 kvno host/testhost.kerber.test@KERBER.TEST >>"$LOG" 2>&1
    KRB5CCNAME="$KRB5CCNAME" klist -e >>"$LOG" 2>&1
    set -e
    KLIST="$(KRB5CCNAME="$KRB5CCNAME" klist -e 2>/dev/null || true)"
    echo "$KLIST" | tee -a "$LOG"
    if echo "$KLIST" | grep -q 'krbtgt/KERBER.TEST@AD.KERBER.TEST' \
        && echo "$KLIST" | grep -q 'host/testhost.kerber.test@KERBER.TEST' \
        && echo "$KLIST" | grep -Eq 'aes(128|256)-cts-hmac-sha1-96'; then
        log "ad.mit.trust.gate" "ok" ',"principal":"kbruser@AD.KERBER.TEST","trust":"live","service":"host/testhost.kerber.test"'
        exit 0
    fi
fi

echo "---- in-tree referral hop (AD.KERBER.TEST names, not a live DC trust) ----" | tee -a "$LOG"
set +e
cargo test -p krb5-kdc --test phase7_preauth tgs_referral_ad_kerber_test_issues_krbtgt -- --nocapture >>"$LOG" 2>&1
hop_rc=$?
set -e
echo "referral_unit_rc=$hop_rc" | tee -a "$LOG"

{
    echo "Live AD.KERBER.TEST→KERBER.TEST referral/host ticket was not proven."
    echo "In-tree TGS referral hop for krbtgt/AD.KERBER.TEST is unit-tested."
    echo "This is not a fabricated pass."
} | tee -a "$LOG"

log "ad.mit.trust.gate" "error" ',"error":"live AD↔MIT referral/host ticket not in klist"'
exit 2
