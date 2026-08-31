#!/usr/bin/env bash
# SSSD krb5_child renew of a Rust-KDC FILE cache. Honest exit 2 until a
# digest-pinned Fedora image with sssd-kcm can run here.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-sssd-renew}"
mkdir -p "$SCRATCH"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"sssd-renew-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

IMAGE="${SSSD_FEDORA_IMAGE:-}"
if [ -z "$IMAGE" ]; then
    echo "SSSD Fedora image not configured (SSSD_FEDORA_IMAGE)" | tee "$SCRATCH/sssd-renew-unavailable.log"
    log "sssd.renew.gate" "unavailable" ',"error":"no Fedora sssd image"'
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "docker not available" | tee "$SCRATCH/sssd-renew-unavailable.log"
    log "sssd.renew.gate" "unavailable" ',"error":"docker not available"'
    exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    if ! docker pull "$IMAGE" >/dev/null 2>&1; then
        echo "cannot pull $IMAGE" | tee "$SCRATCH/sssd-renew-unavailable.log"
        log "sssd.renew.gate" "unavailable" ',"error":"fedora image pull failed"'
        exit 2
    fi
fi
echo "sssd-kcm oracle not wired (G8b records unavailability until G8c)" | tee "$SCRATCH/sssd-renew-unavailable.log"
log "sssd.renew.gate" "unavailable" ',"error":"sssd-kcm not vendored"'
exit 2
