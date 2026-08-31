#!/usr/bin/env bash
# gssproxy Encrypted/Credentials/v1@X-GSSPROXY must survive Rust kvno/klist/kdestroy.
# Honest exit 2 until a Fedora/gssproxy oracle can run.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-gssproxy}"
mkdir -p "$SCRATCH"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"gssproxy-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if [ -z "${GSSPROXY_ORACLE:-}" ]; then
    echo "gssproxy oracle not configured (GSSPROXY_ORACLE)" | tee "$SCRATCH/gssproxy-unavailable.log"
    log "gssproxy.gate" "unavailable" ',"error":"no gssproxy oracle"'
    exit 2
fi
echo "gssproxy oracle path set but not vendored" | tee "$SCRATCH/gssproxy-unavailable.log"
log "gssproxy.gate" "unavailable" ',"error":"gssproxy not vendored"'
exit 2
