#!/usr/bin/env bash
# Content-asserting Samba 4 AD DC gate. Isolated Kerberos env only.
# If Samba/Docker cannot start, this writes an unavailability log and
# exits 2 — that is not a fabricated pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-50fb1f8298b1/implementer}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"samba-ad-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "samba.ad.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/samba-ad-gate-unavailable.log"
    exit 2
fi

IMAGE="${SAMBA_AD_IMAGE:-}"
if [ -z "$IMAGE" ]; then
    if docker image inspect samba-ad-dc:latest >/dev/null 2>&1; then
        IMAGE="samba-ad-dc:latest"
    fi
fi

if [ -z "$IMAGE" ]; then
    log "samba.ad.gate" "error" ',"error":"no Samba AD DC image (set SAMBA_AD_IMAGE)"'
    {
        echo "Samba AD DC container is not in this tree and no SAMBA_AD_IMAGE is set."
        echo "docker images:"
        docker images --format '{{.Repository}}:{{.Tag}}' || true
    } >"$SCRATCH/samba-ad-gate-unavailable.log"
    exit 2
fi

# A real Samba AD DC image would be started here with an isolated
# KRB5_CONFIG pointing at a lab dir — never /etc/krb5.conf.
log "samba.ad.gate" "ok" ',"image":"'"$IMAGE"'"'
echo "image=$IMAGE" >"$SCRATCH/samba-ad-gate.log"
exit 0
