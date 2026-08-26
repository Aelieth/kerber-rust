#!/usr/bin/env bash
# Live Samba AD S4U2Self + S4U2Proxy: kvno -U kbruser and kvno -U kbruser -P.
# Isolated: docker exec; never writes host /etc/krb5.conf.
# Missing docker/image: exit 2. This is not the torn-down Windows DC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-1b3488ffd6ae/implementer}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/ad-s4u-unavailable.log"
LOG="$SCRATCH/ad-s4u-gate.log"

REALM="${SAMBA_AD_REALM:-AD.KERBER.TEST}"
IMPERSONATE="${SAMBA_AD_USER:-kbruser}"
SVC="${SAMBA_AD_SVC:-host/svc.ad.kerber.test}"
SELF="${SAMBA_AD_SELF:-kbrsvc}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ad-s4u-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "oracle=samba-ad-dc (not Windows)"
        echo "$1"
    } | tee "$UNAVAIL" | tee -a "$LOG" >&2
    log "ad.s4u.gate" "error" ",\"error\":\"unavailable\""
    exit 2
}

{
    echo "KRB5_CONFIG=in-container"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    echo "oracle=samba-ad-dc realm=$REALM impersonate=$IMPERSONATE svc=$SVC"
    grep default_realm /etc/krb5.conf 2>/dev/null | head -2 || true
} | tee "$LOG"

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi

IMAGE="${SAMBA_AD_IMAGE:-}"
if [ -z "$IMAGE" ] && docker image inspect samba-ad-dc:latest >/dev/null 2>&1; then
    IMAGE="samba-ad-dc:latest"
fi
if [ -z "$IMAGE" ]; then
    unavailable "no Samba AD DC image (set SAMBA_AD_IMAGE)"
fi

NAME="kerber-rust-ad-s4u-gate"
docker rm -f "$NAME" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

set +e
docker run -d --name "$NAME" --hostname dc1 "$IMAGE" >/tmp/ad-s4u-run.err 2>&1
run_rc=$?
set -e
if [ "$run_rc" -ne 0 ]; then
    unavailable "docker run $IMAGE failed: $(tr '\n' ' ' </tmp/ad-s4u-run.err 2>/dev/null || true)"
fi

ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" sh -c 'ss -lun | grep -q ":88 "' 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.5
done
if [ "$ok" != 1 ]; then
    docker logs "$NAME" >>"$UNAVAIL" 2>&1 || true
    unavailable "Samba AD KDC did not listen on UDP 88"
fi

docker exec "$NAME" sh -c "cat >/tmp/samba-krb5.conf <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_ad_s4u
    default_keytab_name = FILE:/tmp/svc.keytab
[realms]
    ${REALM} = {
        kdc = 127.0.0.1
    }
EOF"

set +e
docker exec "$NAME" samba-tool domain exportkeytab /tmp/svc.keytab \
    --principal="${SELF}" >>"$LOG" 2>&1
kt_rc=$?
set -e
if [ "$kt_rc" -ne 0 ] || ! docker exec "$NAME" test -s /tmp/svc.keytab; then
    unavailable "samba-tool domain exportkeytab failed"
fi

set +e
docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf -e KRB5_KTNAME=/tmp/svc.keytab \
    "$NAME" kinit -f -k "${SELF}@${REALM}" >>"$LOG" 2>&1
kinit_rc=$?
set -e
echo "kinit_rc=$kinit_rc" | tee -a "$LOG"
if [ "$kinit_rc" -ne 0 ]; then
    docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" klist -k /tmp/svc.keytab >>"$LOG" 2>&1 || true
    unavailable "kinit -k ${SELF}@${REALM} failed"
fi

# Samba: S4U2Self target is the account (kbrsvc). host/svc is an SPN, not
# a client principal (Windows used a computer account of that name).
set +e
docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf -e KRB5_KTNAME=/tmp/svc.keytab \
    "$NAME" kvno -U "$IMPERSONATE" "$SELF" >>"$LOG" 2>&1
self_rc=$?
set -e
echo "s4u2self_rc=$self_rc" | tee -a "$LOG"

set +e
docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf -e KRB5_KTNAME=/tmp/svc.keytab \
    "$NAME" kvno -U "$IMPERSONATE" -P "$SVC" >>"$LOG" 2>&1
proxy_rc=$?
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" klist -f -e 2>/dev/null || true)"
echo "$KLIST" >>"$LOG"
set -e
echo "s4u2proxy_rc=$proxy_rc" | tee -a "$LOG"
echo "$KLIST"

if [ "$self_rc" -eq 0 ] && [ "$proxy_rc" -eq 0 ] \
    && echo "$KLIST" | grep -q "${SVC}@${REALM}" \
    && echo "$KLIST" | grep -q "for client ${IMPERSONATE}@${REALM}" \
    && echo "$KLIST" | grep -Eq 'aes(128|256)-cts-hmac-sha1-96'; then
    log "ad.s4u.gate" "ok" ",\"service\":\"${SVC}\",\"impersonate\":\"${IMPERSONATE}@${REALM}\",\"oracle\":\"samba\""
    exit 0
fi

echo "S4U2Self/S4U2Proxy not in klist (Samba, not Windows)" | tee -a "$LOG"
log "ad.s4u.gate" "error" ',"error":"S4U2Self/S4U2Proxy not in klist"'
exit 1
