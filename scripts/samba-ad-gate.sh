#!/usr/bin/env bash
# Content-asserting Samba 4 AD DC gate. Isolated Kerberos env only.
# The only exit 0 is after a live Samba/AD kinit + kvno with klist content.
# Missing docker, image, or KDC: exit 2 + unavailability log (heimdal/sspi honesty).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-samba-ad-gate}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/samba-ad-gate-unavailable.log"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"samba-ad-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "$1"
        docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true
    } | tee "$UNAVAIL" >&2
    log "samba.ad.gate" "error" ",\"error\":\"unavailable\""
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi

IMAGE="${SAMBA_AD_IMAGE:-}"
if [ -z "$IMAGE" ]; then
    if docker image inspect samba-ad-dc:latest >/dev/null 2>&1; then
        IMAGE="samba-ad-dc:latest"
    fi
fi

if [ -z "$IMAGE" ]; then
    unavailable "no Samba AD DC image (set SAMBA_AD_IMAGE)"
fi

NAME="kerber-rust-samba-ad-gate"
docker rm -f "$NAME" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

set +e
docker run -d --name "$NAME" --hostname dc1 "$IMAGE" >/tmp/samba-ad-run.err 2>&1
run_rc=$?
set -e
if [ "$run_rc" -ne 0 ]; then
    unavailable "docker run $IMAGE failed: $(tr '\n' ' ' </tmp/samba-ad-run.err 2>/dev/null || true)"
fi

ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" sh -c 'command -v ss >/dev/null && ss -lun | grep -q ":88 "' 2>/dev/null; then
        ok=1
        break
    fi
    if docker exec "$NAME" sh -c 'netstat -uln 2>/dev/null | grep -q ":88 "' 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.5
done
if [ "$ok" != 1 ]; then
    docker logs "$NAME" >>"$UNAVAIL" 2>&1 || true
    unavailable "Samba AD KDC did not listen on UDP 88"
fi

REALM="${SAMBA_AD_REALM:-}"
USER="${SAMBA_AD_USER:-Administrator}"
PASSWORD="${SAMBA_AD_PASSWORD:-Samba-Admin-Kerber-2026!}"
if [ -z "$REALM" ] || [ -z "$PASSWORD" ]; then
    docker logs "$NAME" >>"$UNAVAIL" 2>&1 || true
    unavailable "Samba KDC listening but SAMBA_AD_REALM unset; refusing exit 0 without kinit"
fi

docker exec "$NAME" sh -c "cat >/tmp/samba-krb5.conf <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_samba_gate
[realms]
    ${REALM} = {
        kdc = 127.0.0.1
    }
EOF"

set +e
docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" \
    sh -c "printf '%s\n' '$PASSWORD' | kinit ${USER}@${REALM}"
kinit_rc=$?
set -e
if [ "$kinit_rc" -ne 0 ]; then
    docker logs "$NAME" >>"$UNAVAIL" 2>&1 || true
    unavailable "kinit ${USER}@${REALM} against Samba AD failed"
fi

set +e
KVNO_OUT="$(docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" kvno "krbtgt/${REALM}@${REALM}" 2>&1)"
kvno_rc=$?
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/samba-krb5.conf "$NAME" klist 2>&1)"
set -e
echo "$KVNO_OUT"
echo "$KLIST"
if [ "$kvno_rc" -ne 0 ]; then
    unavailable "kvno against Samba AD failed"
fi
echo "$KLIST" | grep -q "${USER}@${REALM}"
echo "$KLIST" | grep -q "krbtgt/${REALM}@${REALM}"

log "samba.ad.gate" "ok" ",\"principal\":\"${USER}@${REALM}\",\"image\":\"${IMAGE}\""
exit 0
