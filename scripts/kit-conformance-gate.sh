#!/usr/bin/env bash
# 2×2 {MIT client, Rust client} × {MIT KDC, Rust KDC}. Kit twin via
# KIT_TWIN; honest exit 2 if absent. Diffs are within-column only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kit-conformance}"
mkdir -p "$SCRATCH"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID TZ=UTC LC_ALL=C
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kit-conformance-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

TWIN="${KIT_TWIN:-}"
if [ -z "$TWIN" ] || [ ! -e "$TWIN" ]; then
    echo "kit twin absent (set KIT_TWIN to a sanitized twin)" | tee "$SCRATCH/kit-conformance-unavailable.log"
    log "kit.conformance.gate" "unavailable" ',"error":"KIT_TWIN absent"'
    exit 2
fi
DIGEST="$(sha256sum "$TWIN" | awk '{print $1}')"
echo "kit_twin_digest=$DIGEST"
log "kit.conformance.gate" "error" ',"error":"twin present but 2x2 not vendored","digest":"'"$DIGEST"'"'
exit 2
