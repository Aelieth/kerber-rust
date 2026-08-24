#!/usr/bin/env bash
# Isolated Windows Server 2022 AS/TGS against AD.KERBER.TEST.
# NEVER writes /etc/krb5.conf or SSSD. Lab state lives in ~/adlab.
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
    . "$ADLAB/env"
    set +a
fi
export KRB5_CONFIG="${KRB5_CONFIG:-$ADLAB/ad-krb5.conf}"
export KRB5CCNAME="FILE:$SCRATCH/ad-windows.ccache"
export KRB5_KTNAME="FILE:$ADLAB/svc.keytab"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ad-windows-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

{
    echo "KRB5_CONFIG=$KRB5_CONFIG"
    echo "KRB5CCNAME=$KRB5CCNAME"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    ping -c 1 -W 2 10.10.38.38 || true
} | tee "$SCRATCH/ad-windows-gate.log"

if ! ping -c 1 -W 2 10.10.38.38 >/dev/null 2>&1; then
    log "ad.windows.gate" "error" ',"error":"DC 10.10.38.38 unreachable"'
    cp "$SCRATCH/ad-windows-gate.log" "$SCRATCH/ad-windows-unreachable.log"
    exit 2
fi

if [ ! -f "$KRB5_CONFIG" ]; then
    log "ad.windows.gate" "error" ',"error":"missing isolated ad-krb5.conf"'
    echo "missing $KRB5_CONFIG" >>"$SCRATCH/ad-windows-gate.log"
    exit 2
fi

PASS="${AD_KBRUSER_PASSWORD:-}"
set +e
if [ -n "$PASS" ]; then
    printf '%s\n' "$PASS" | timeout 20 kinit kbruser@AD.KERBER.TEST >>"$SCRATCH/ad-windows-gate.log" 2>&1
    kinit_rc=$?
else
    echo | timeout 20 kinit kbruser@AD.KERBER.TEST >>"$SCRATCH/ad-windows-gate.log" 2>&1
    kinit_rc=$?
fi
set -e

if [ "$kinit_rc" -ne 0 ] || ! grep -q "kbruser@AD.KERBER.TEST" <<<"$(KRB5CCNAME="$KRB5CCNAME" klist 2>/dev/null || true)"; then
    log "ad.windows.gate" "error" ',"error":"kinit failed (need AD_KBRUSER_PASSWORD or unexpired ccache)"'
    echo "kinit_rc=$kinit_rc" >>"$SCRATCH/ad-windows-gate.log"
    exit 2
fi

kvno host/svc.ad.kerber.test >>"$SCRATCH/ad-windows-gate.log" 2>&1
klist -e >>"$SCRATCH/ad-windows-gate.log" 2>&1
if ! grep -E "aes(128|256)-cts-hmac-sha1-96" "$SCRATCH/ad-windows-gate.log"; then
    log "ad.windows.gate" "error" ',"error":"etype 17/18 not in klist"'
    exit 1
fi
log "ad.windows.gate" "ok" ',"principal":"kbruser@AD.KERBER.TEST"'
exit 0
