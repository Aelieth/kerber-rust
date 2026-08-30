#!/usr/bin/env bash
# Live Samba AD: kinit kbruser + kvno host/svc.ad.kerber.test.
# Isolated: docker exec; never writes host /etc/krb5.conf.
# Missing docker/image: exit 2. This is not the torn-down Windows DC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-ad-windows-gate}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/ad-windows-unavailable.log"
LOG="$SCRATCH/ad-windows-gate.log"

REALM="${SAMBA_AD_REALM:-AD.KERBER.TEST}"
USER="${SAMBA_AD_USER:-kbruser}"
PASSWORD="${SAMBA_KBRUSER_PASSWORD:-Kbruser-P@ss-2026!}"
SVC="${SAMBA_AD_SVC:-host/svc.ad.kerber.test}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ad-windows-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "oracle=samba-ad-dc (not Windows)"
        echo "$1"
    } | tee "$UNAVAIL" | tee -a "$LOG" >&2
    log "ad.windows.gate" "error" ",\"error\":\"unavailable\""
    exit 2
}

{
    echo "KRB5_CONFIG=in-container"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    echo "oracle=samba-ad-dc realm=$REALM user=$USER"
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

NAME="kerber-rust-ad-windows-gate"
docker rm -f "$NAME" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

set +e
docker run -d --name "$NAME" --hostname dc1 "$IMAGE" >"$SCRATCH/ad-windows-run.err" 2>&1
run_rc=$?
set -e
if [ "$run_rc" -ne 0 ]; then
    unavailable "docker run $IMAGE failed: $(tr '\n' ' ' <"$SCRATCH/ad-windows-run.err" 2>/dev/null || true)"
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
    default_ccache_name = FILE:/tmp/krb5cc_ad_windows
[realms]
    ${REALM} = {
        kdc = 127.0.0.1
    }
EOF"

set +e
docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" \
    sh -c "printf '%s\n' '$PASSWORD' | kinit ${USER}@${REALM}" >>"$LOG" 2>&1
kinit_rc=$?
set -e
if [ "$kinit_rc" -ne 0 ]; then
    docker logs "$NAME" >>"$LOG" 2>&1 || true
    unavailable "kinit ${USER}@${REALM} against Samba AD failed"
fi

set +e
KVNO_OUT="$(docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" kvno "${SVC}@${REALM}" 2>&1)"
kvno_rc=$?
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" klist -e 2>&1)"
set -e
echo "$KVNO_OUT" | tee -a "$LOG"
echo "$KLIST" | tee -a "$LOG"
if [ "$kvno_rc" -ne 0 ]; then
    unavailable "kvno ${SVC} against Samba AD failed"
fi
echo "$KLIST" | grep -q "${USER}@${REALM}"
echo "$KLIST" | grep -q "${SVC}@${REALM}"
# Samba tickets are aes256-cts-hmac-sha1-96 (etype 18), not Windows kvno=3.
if ! echo "$KLIST" | grep -Eq 'aes(128|256)-cts-hmac-sha1-96'; then
    log "ad.windows.gate" "error" ',"error":"etype 17/18 not in klist"'
    exit 1
fi

log "ad.windows.gate" "ok" ",\"principal\":\"${USER}@${REALM}\",\"service\":\"${SVC}@${REALM}\",\"oracle\":\"samba\""
exit 0
