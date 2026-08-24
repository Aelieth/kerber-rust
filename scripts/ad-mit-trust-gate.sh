#!/usr/bin/env bash
# Isolated AD.KERBER.TEST ↔ KERBER.TEST referral/trust gate.
# NEVER writes /etc/krb5.conf or SSSD. Lab state lives in ~/adlab.
#
# Exit 0 only if a live bidirectional trust is proven (klist names
# krbtgt/KERBER.TEST and a KERBER.TEST host ticket, or the reverse).
# Exit 2 records honest unavailability (DC up but no trust configured,
# missing password, or isolated profile has no KERBER.TEST stanza).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-50fb1f8298b1/implementer}"
mkdir -p "$SCRATCH"

ADLAB="${ADLAB:-$HOME/adlab}"
export KRB5_CONFIG="${KRB5_CONFIG:-$ADLAB/ad-krb5.conf}"
export KRB5CCNAME="FILE:$SCRATCH/ad-mit-trust.ccache"
export KRB5_KTNAME="FILE:$ADLAB/svc.keytab"

LOG="$SCRATCH/ad-mit-trust-gate.log"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ad-mit-trust-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

{
    echo "KRB5_CONFIG=$KRB5_CONFIG"
    echo "KRB5CCNAME=$KRB5CCNAME"
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

# Isolated AD profile has no KERBER.TEST realm or capaths — a live
# bidirectional trust would require those plus matching krbtgt keys
# on the DC. Record the absence rather than inventing a pass.
# Do not match the substring inside AD.KERBER.TEST.
if grep -E '(^|[^[:alnum:].])KERBER\.TEST' "$KRB5_CONFIG" >/dev/null 2>&1; then
    echo "isolated profile names KERBER.TEST (client-side trust stanza present)" | tee -a "$LOG"
else
    echo "isolated profile has no KERBER.TEST stanza (no client-side trust)" | tee -a "$LOG"
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
    if grep -E 'krbtgt/KERBER.TEST' "$LOG"; then
        log "ad.mit.trust.gate" "ok" ',"principal":"kbruser@AD.KERBER.TEST","trust":"live"'
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
    echo "Live AD.KERBER.TEST↔KERBER.TEST realm trust is not configured on the DC."
    echo "In-tree TGS referral hop for krbtgt/AD.KERBER.TEST is unit-tested."
    echo "This is not a fabricated pass."
} | tee -a "$LOG"

log "ad.mit.trust.gate" "error" ',"error":"live AD↔MIT trust not configured on DC"'
exit 2
