# Shared gate preamble. Source after `cd "$ROOT"` and after provenance.sh.
# shellcheck shell=bash
# Provides: log, die, unavailable, register_cleanup, wait_port, wait_listen,
# wait_gone, wait_log, need_image, need_bins, shell_container, kdc_start,
# kdc_restart, mit_kdc_restart, stock_mit_kdc. One EXIT trap writes
# gate_wall_s= and runs registered cleanups. Does not replace provenance's ERR.

GATE_COMMON_SOURCED=1
GATE_NAME="${GATE_NAME:-$(basename "${BASH_SOURCE[1]:-${0}}" .sh)}"
COMPONENT="${COMPONENT:-$GATE_NAME}"
IMAGE="${IMAGE:-kerber-rust-mit-kdc:1.22.2}"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-${TMPDIR:-/tmp}/kerber-${GATE_NAME}}"
mkdir -p "$SCRATCH"
_GATE_START="${_GATE_START:-$(date +%s)}"
_CLEANUP_FNS=()

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"%s","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$COMPONENT" "$2" "${3:-}"
}

die() {
    log "${COMPONENT}.gate" "error" ",\"error\":\"$1\""
    echo "$1" >&2
    exit 1
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "$1"
    } | tee "$SCRATCH/${GATE_NAME}-unavailable.log" >&2
    log "${COMPONENT}.gate" "error" ",\"error\":\"unavailable\""
    exit 2
}

register_cleanup() {
    _CLEANUP_FNS+=("$1")
}

_gate_common_exit() {
    local rc=$?
    local now
    now=$(date +%s)
    echo "gate_wall_s=$((now - _GATE_START))"
    local fn
    for fn in "${_CLEANUP_FNS[@]}"; do
        eval "$fn" || true
    done
    return "$rc"
}
trap '_gate_common_exit' EXIT

wait_port() {
    local host="${1:-127.0.0.1}" port="${2:-88}" n="${3:-80}"
    local i
    for i in $(seq 1 "$n"); do
        if python3 - "$host" "$port" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(0.2)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
        then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_listen() {
    local ctn=$1 logfile=$2 n="${3:-80}"
    local i
    for i in $(seq 1 "$n"); do
        if docker exec "$ctn" grep -q '^listening ' "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    docker exec "$ctn" cat "$logfile" >&2 || true
    return 1
}

wait_gone() {
    local host="${1:-127.0.0.1}" port="${2:-88}" n="${3:-80}"
    local i
    for i in $(seq 1 "$n"); do
        if ! wait_port "$host" "$port" 1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_log() {
    local ctn=$1 logfile=$2 pattern=$3 n="${4:-80}"
    local i
    for i in $(seq 1 "$n"); do
        if docker exec "$ctn" grep -qE "$pattern" "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

need_image() {
    if ! command -v docker >/dev/null 2>&1; then
        unavailable "docker not available"
    fi
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        return 0
    fi
    if [ "${KERBER_SKIP_MIT_BUILD:-}" = 1 ]; then
        unavailable "MIT image $IMAGE missing"
    fi
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
    docker image inspect "$IMAGE" >/dev/null 2>&1 || unavailable "MIT image $IMAGE missing after build"
}

need_bins() {
    local bin missing=0
    local dest="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
    for bin in "$@"; do
        if [ ! -x "$dest/$bin" ] && [ ! -x "$dest/examples/$bin" ]; then
            missing=1
            break
        fi
    done
    if [ "$missing" = 0 ]; then
        return 0
    fi
    if [ "${KERBER_NEED_BINS_STRICT:-}" = 1 ]; then
        die "bins missing ($*); run scripts/lib/build-bins.sh"
    fi
    "$ROOT/scripts/lib/build-bins.sh"
}

shell_container() {
    local keep="${1:-3600}"
    if [ -n "${KERBER_SHELL:-}" ]; then
        NAME="${KERBER_SHELL}"
        return 0
    fi
    NAME="${NAME:-kerber-rust-${GATE_NAME}}"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" "$keep" >/dev/null
    register_cleanup "docker rm -f '$NAME' >/dev/null 2>&1 || true"
}

kdc_start() {
    local addr="${1:-127.0.0.1:88}"
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD="${KRB5_TEST_USER_PASSWORD:-userpassword}" \
        -e KRB5_TEST_ADMIN_PASSWORD="${KRB5_TEST_ADMIN_PASSWORD:-adminpassword}" \
        -e KRB5_MASTER_PASSWORD="${KRB5_MASTER_PASSWORD:-masterpassword}" \
        -e KRB5_KDC_DB="${KRB5_KDC_DB:-/tmp/principal}" \
        -e KRB5_KDC_STASH="${KRB5_KDC_STASH:-/tmp/stash}" \
        "$NAME" sh -c "/tmp/krb5-kdc --test-realm $addr >/tmp/kdc.log 2>&1"
    wait_listen "$NAME" /tmp/kdc.log || die "kdc did not listen"
}

kdc_restart() {
    docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true' || true
    wait_gone 127.0.0.1 88 40 || true
    kdc_start "$@"
}

mit_kdc_restart() {
    local ctn="${1:-$NAME}"
    docker exec "$ctn" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true' || true
    sleep 0.1 # proto: krb5kdc pid reuse
    docker exec -d "$ctn" krb5kdc
    local i
    for i in $(seq 1 80); do
        if docker exec "$ctn" sh -c 'pidof krb5kdc >/dev/null' 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    die "mit krb5kdc did not restart"
}

stock_mit_kdc() {
    local n="${1:-kerber-rust-mit-kdc}"
    if [ "${KERBER_LIVE:-}" = 1 ] && docker inspect "$n" >/dev/null 2>&1; then
        NAME="$n"
        return 0
    fi
    docker rm -f "$n" >/dev/null 2>&1 || true
    docker run -d --name "$n" \
        -p 88:88/tcp -p 88:88/udp \
        -e "CORRELATION_ID=${CORRELATION_ID}" \
        "$IMAGE"
    NAME="$n"
    register_cleanup "docker rm -f '$n' >/dev/null 2>&1 || true"
    local i
    for i in $(seq 1 90); do
        if docker logs "$n" 2>&1 | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
            return 0
        fi
        sleep 0.1
    done
    die "stock MIT KDC did not become ready"
}
