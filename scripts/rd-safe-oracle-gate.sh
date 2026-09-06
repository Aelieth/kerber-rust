#!/usr/bin/env bash
# MIT 1.22.2 krb5_rd_safe over a non-canonical KRB-SAFE-BODY and seq ≥ 2^31.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-rd-safe-oracle"
MIT_LIBS="-lkrb5 -lk5crypto -lcom_err"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rd-safe-oracle-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "rd.safe.oracle" "error" ',"error":"docker not available"'
    exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "rd.safe.oracle" "error" ',"error":"MIT image unavailable"'
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 180 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp "$ROOT/scripts/rd-safe-oracle.c" "$NAME":/tmp/rd-safe-oracle.c
docker exec "$NAME" sh -c "gcc -O1 -o /tmp/rd-safe-oracle /tmp/rd-safe-oracle.c $MIT_LIBS"
OUT="$(docker exec "$NAME" /tmp/rd-safe-oracle)"
printf '%s\n' "$OUT"
printf '%s\n' "$OUT" | grep -q 'SAFE_CANON_OK'
printf '%s\n' "$OUT" | grep -q 'SAFE_NONCANON_BODY_OK'
printf '%s\n' "$OUT" | grep -q 'SAFE_SEQ_2_31_OK'
log "rd.safe.oracle" "ok" ',"canon":"SAFE_CANON_OK","noncanon":"SAFE_NONCANON_BODY_OK","seq":"SAFE_SEQ_2_31_OK"'
exit 0
