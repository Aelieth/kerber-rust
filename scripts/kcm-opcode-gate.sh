#!/usr/bin/env bash
# Live-pin F43/F42 sssd-kcm opcodes against a running daemon (R10).
# Honest exit 2 if docker or the digest-pinned image is missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kcm-opcode}"
mkdir -p "$SCRATCH"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kcm-opcode-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

F43_DIGEST="sha256:96b2a05f8ce3111e10c236abe8055b01500880d95ee7c2f92fa30847fdbb667b"
F42_DIGEST="sha256:e78cd1a688cd079c23864f289a89a49a3f4ad66d817864e325e1d058310ee95c"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not available" | tee "$SCRATCH/kcm-opcode-unavailable.log"
    log "kcm.opcode.gate" "unavailable" ',"error":"docker not available"'
    exit 2
fi

probe_one() {
    local tag="$1" fedora="$2" digest="$3" out="$4"
    local image="kerber-rust-sssd-kcm:${tag}"
    local name="kerber-rust-kcm-${tag}-$$"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        docker build -f harness/kcm/Dockerfile --build-arg "FEDORA_DIGEST=${digest}" \
            -t "$image" "$ROOT"
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" "$image" >/dev/null
    local i
    for i in $(seq 1 50); do
        if docker exec "$name" test -S /run/.heim_org.h5l.kcm-socket; then
            break
        fi
        sleep 0.2
    done
    if ! docker exec "$name" test -S /run/.heim_org.h5l.kcm-socket; then
        docker logs "$name" >&2 || true
        docker rm -f "$name" >/dev/null 2>&1 || true
        echo "sssd-kcm socket never appeared ($tag)" >&2
        return 1
    fi
    local krb5 kcm
    krb5="$(docker exec "$name" rpm -q krb5-libs)"
    kcm="$(docker exec "$name" rpm -q sssd-kcm)"
    docker cp "$ROOT/harness/kcm/probe-opcodes.py" "$name":/usr/local/bin/kcm-probe-opcodes.py
    docker exec -e "KCM_FEDORA=$fedora" -e "KCM_DIGEST=$digest" \
        -e "KCM_KRB5_NVR=$krb5" -e "KCM_SSSD_NVR=$kcm" \
        "$name" python3 /usr/local/bin/kcm-probe-opcodes.py | tee "$out"
    docker rm -f "$name" >/dev/null 2>&1 || true
    grep -qx 'GET_CRED_LIST=ok' "$out"
    grep -qx 'RETRIEVE=KRB5_FCC_INTERNAL' "$out"
    grep -qx 'REPLACE=KRB5_FCC_INTERNAL' "$out"
}

probe_one f43 43 "$F43_DIGEST" "$SCRATCH/sssd-kcm-opcodes-f43.log"
probe_one f42 42 "$F42_DIGEST" "$SCRATCH/sssd-kcm-opcodes-f42.log"
log "kcm.opcode.gate" "ok" ''
echo "kcm-opcode-gate ok"
