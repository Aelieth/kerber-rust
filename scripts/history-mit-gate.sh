#!/usr/bin/env bash
# MIT 1.22.2 kadmin.local history-window oracle on a MIT KDB (no kadmind).
# Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-history-mit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-history-mit-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"history-mit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "history.mit" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/history-mit-unavailable.log"
    exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT" || true
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "history.mit" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/history-mit-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword >/dev/null

klocal() {
    docker exec "$NAME" kadmin.local -q "$1" 2>&1 || true
}

echo "==== MIT kadmin.local history=1 A→B→A ===="
klocal 'addpol -minlength 8 -minclasses 2 -history 1 h1' >/dev/null
klocal 'addprinc -policy h1 -pw Hist-pw0 u1' >/dev/null
CUR="$(klocal 'cpw -pw Hist-pw0 u1')"
echo "$CUR"
echo "$CUR" | grep -qi 'reuse' || {
    log "history.mit" "error" ',"error":"history=1 must reject current A"'
    exit 1
}
klocal 'cpw -pw Hist-pw1 u1' >/dev/null
A1="$(klocal 'cpw -pw Hist-pw0 u1')"
echo "$A1"
echo "$A1" | grep -qi 'password .* changed' || {
    log "history.mit" "error" ',"error":"MIT history=1 must allow A→B→A"'
    exit 1
}

echo "==== MIT kadmin.local history=2 A→B→C then B reject A allow ===="
klocal 'addpol -minlength 8 -minclasses 2 -history 2 h2' >/dev/null
klocal 'addprinc -policy h2 -pw Hist-pw0 u2' >/dev/null
klocal 'cpw -pw Hist-pw1 u2' >/dev/null
klocal 'cpw -pw Hist-pw2 u2' >/dev/null
B="$(klocal 'cpw -pw Hist-pw1 u2')"
echo "$B"
echo "$B" | grep -qi 'reuse' || {
    log "history.mit" "error" ',"error":"MIT history=2 must reject B after A→B→C"'
    exit 1
}
A="$(klocal 'cpw -pw Hist-pw0 u2')"
echo "$A"
echo "$A" | grep -qi 'password .* changed' || {
    log "history.mit" "error" ',"error":"MIT history=2 must allow N-boundary A"'
    exit 1
}

log "history.mit" "ok" ',"h1":"A-B-A","h2":"reject-B-allow-A"'
exit 0
