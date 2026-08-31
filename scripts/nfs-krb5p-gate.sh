#!/usr/bin/env bash
# NFS sec=krb5i + krb5p (AES-SHA1 and SHA-2). Manual until nfs-klldap-host is vendored.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-nfs-krb5p}"
mkdir -p "$SCRATCH"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"nfs-krb5p-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

echo "nfs-krb5p-gate is manual until nfs-klldap-host is vendored" | tee "$SCRATCH/nfs-krb5p-gate.log"
log "nfs.krb5p.gate" "unavailable" ',"error":"manual until vendored"'
exit 2
