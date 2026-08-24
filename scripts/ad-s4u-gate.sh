#!/usr/bin/env bash
# Isolated S4U2Self + S4U2Proxy against AD.KERBER.TEST (DC 10.10.38.38).
# NEVER writes /etc/krb5.conf or SSSD. Uses ~/adlab keytab + isolated profile.
#
# Exit 0 only if klist names host/svc.ad.kerber.test for client
# kbruser@AD.KERBER.TEST (aes256) after both kvno -U and kvno -U -P.
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
export KRB5CCNAME="FILE:$SCRATCH/ad-s4u.ccache"
export KRB5_KTNAME="FILE:$ADLAB/svc.keytab"
LOG="$SCRATCH/ad-s4u-gate.log"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ad-s4u-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

{
    echo "KRB5_CONFIG=$KRB5_CONFIG"
    echo "KRB5CCNAME=$KRB5CCNAME"
    echo "KRB5_KTNAME=$KRB5_KTNAME"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    echo "date=$(date -Iseconds)"
    grep default_realm /etc/krb5.conf | head -2 || true
    ping -c 1 -W 2 10.10.38.38 || true
} | tee "$LOG"

if ! grep -q 'TESTLABBY.LOCAL' /etc/krb5.conf; then
    log "ad.s4u.gate" "error" ',"error":"host /etc/krb5.conf is not TESTLABBY.LOCAL"'
    exit 1
fi
if ! ping -c 1 -W 2 10.10.38.38 >/dev/null 2>&1; then
    log "ad.s4u.gate" "error" ',"error":"DC unreachable"'
    exit 2
fi

rm -f "$SCRATCH/ad-s4u.ccache"
set +e
timeout 20 kinit -f -k host/svc.ad.kerber.test@AD.KERBER.TEST >>"$LOG" 2>&1
kinit_rc=$?
set -e
echo "kinit_rc=$kinit_rc" | tee -a "$LOG"
if [ "$kinit_rc" -ne 0 ]; then
    log "ad.s4u.gate" "error" ',"error":"kinit -k host/svc failed"'
    exit 1
fi

set +e
timeout 20 kvno -U kbruser host/svc.ad.kerber.test >>"$LOG" 2>&1
self_rc=$?
KRB5CCNAME="$KRB5CCNAME" klist -f -e >>"$LOG" 2>&1
set -e
echo "s4u2self_rc=$self_rc" | tee -a "$LOG"

set +e
timeout 20 kvno -U kbruser -P host/svc.ad.kerber.test >>"$LOG" 2>&1
proxy_rc=$?
KLIST="$(KRB5CCNAME="$KRB5CCNAME" klist -f -e 2>/dev/null || true)"
echo "$KLIST" >>"$LOG"
set -e
echo "s4u2proxy_rc=$proxy_rc" | tee -a "$LOG"
echo "$KLIST"

if [ "$self_rc" -eq 0 ] && [ "$proxy_rc" -eq 0 ] \
    && echo "$KLIST" | grep -q 'host/svc.ad.kerber.test@AD.KERBER.TEST' \
    && echo "$KLIST" | grep -q 'for client kbruser@AD.KERBER.TEST' \
    && echo "$KLIST" | grep -Eq 'aes(128|256)-cts-hmac-sha1-96'; then
    log "ad.s4u.gate" "ok" ',"service":"host/svc.ad.kerber.test","impersonate":"kbruser@AD.KERBER.TEST"'
    exit 0
fi

log "ad.s4u.gate" "error" ',"error":"S4U2Self/S4U2Proxy not in klist"'
exit 1
