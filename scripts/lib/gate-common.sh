# Shared gate preamble. Source after `cd "$ROOT"` and after provenance.sh.
# shellcheck shell=bash
# Provides: log, die, unavailable, register_cleanup, wait_port, wait_listen,
# wait_gone, wait_log, wait_port_in, wait_udp_in, wait_tcp_bound_in, wait_gone_in, wait_pid_gone, need_image,
# need_bins, shell_container, kdc_start, kdc_restart, mit_kdc_restart,
# stock_mit_kdc. One EXIT trap writes gate_wall_s= and runs registered
# cleanups. Does not replace provenance's ERR. Host wait_port/wait_gone need a
# published port; wait_port_in/wait_gone_in probe inside $NAME.

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

# In-container TCP connect. Group-B shell containers do not publish KDC ports
# to the host, so wait_port (host-side) cannot see them.
wait_port_in() {
    local ctn="${1:-$NAME}" port="${2:-88}" n="${3:-80}"
    local i
    for i in $(seq 1 "$n"); do
        if docker exec "$ctn" python3 -c "import socket; socket.create_connection(('127.0.0.1', int('$port')), 0.2)" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Ready = the listen port is already bound inside the container.
# Use wait_tcp_bound_in (not wait_port_in) for single-accept TCP proxies:
# a connect probe would steal the only accept().
wait_bound_in() {
    local ctn="${1:-$NAME}" port="${2:-88}" n="${3:-80}" kind="${4:-udp}"
    local sock i
    case "$kind" in
        tcp) sock="socket.SOCK_STREAM" ;;
        udp) sock="socket.SOCK_DGRAM" ;;
        *) return 1 ;;
    esac
    for i in $(seq 1 "$n"); do
        if docker exec "$ctn" python3 -c "import socket,sys
s=socket.socket(socket.AF_INET, $sock)
try:
    s.bind(('127.0.0.1', int('$port')))
    sys.exit(1)
except OSError:
    sys.exit(0)
finally:
    s.close()" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_udp_in() { wait_bound_in "${1:-$NAME}" "${2:-88}" "${3:-80}" udp; }
wait_tcp_bound_in() { wait_bound_in "${1:-$NAME}" "${2:-88}" "${3:-80}" tcp; }

wait_gone_in() {
    local ctn="${1:-$NAME}" port="${2:-88}" n="${3:-80}"
    local i
    for i in $(seq 1 "$n"); do
        if ! wait_port_in "$ctn" "$port" 1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_pid_gone() {
    local ctn="${1:-$NAME}" proc="$2" n="${3:-40}"
    local i
    [ -n "$proc" ] || return 1
    for i in $(seq 1 "$n"); do
        if ! docker exec "$ctn" sh -c "pidof '$proc' >/dev/null" 2>/dev/null; then
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
    for bin in "$@"; do
        if [ ! -x "$dest/$bin" ] && [ ! -x "$dest/examples/$bin" ]; then
            die "bins missing after build-bins.sh: $bin"
        fi
    done
}

shell_container() {
    local keep="${1:-3600}"
    local host="${2:-}"
    if [ -n "${KERBER_SHELL:-}" ]; then
        NAME="${KERBER_SHELL}"
        docker inspect "$NAME" >/dev/null 2>&1 || die "KERBER_SHELL=$NAME is not running"
        docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc krb5-kadmind krb5kdc kadmind) 2>/dev/null || true' || true
        wait_pid_gone "$NAME" krb5-kdc || true
        wait_pid_gone "$NAME" krb5-kadmind || true
        wait_gone_in "$NAME" 88 || true
        wait_gone_in "$NAME" 749 || true
        return 0
    fi
    NAME="${NAME:-kerber-rust-${GATE_NAME}}"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [ -n "$host" ]; then
        docker run -d --name "$NAME" --hostname "$host" --entrypoint sleep "$IMAGE" "$keep" >/dev/null
    else
        docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" "$keep" >/dev/null
    fi
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
    local n="${1:-${KERBER_MIT_NAME:-kerber-rust-mit-kdc}}"
    local logs i
    if [ "${KERBER_LIVE:-}" = 1 ]; then
        n="${KERBER_MIT_NAME:-kerber-rust-mit-kdc}"
        docker inspect "$n" >/dev/null 2>&1 || die "KERBER_LIVE=1 but $n is not running"
        NAME="$n"
        return 0
    fi
    docker rm -f "$n" >/dev/null 2>&1 || true
    docker run -d --name "$n" \
        -e "CORRELATION_ID=${CORRELATION_ID}" \
        "$IMAGE" >/dev/null
    NAME="$n"
    if [ "${KERBER_STOCK_KEEP:-}" != 1 ]; then
        register_cleanup "docker rm -f '$n' >/dev/null 2>&1 || true"
    fi
    for i in $(seq 1 90); do
        logs="$(docker logs "$n" 2>&1 || true)"
        if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
            return 0
        fi
        if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
            echo "$logs" >&2
            die "stock MIT KDC harness kinit failed"
        fi
        sleep 0.1
    done
    docker logs "$n" >&2 || true
    die "stock MIT KDC did not become ready"
}

# Snapshot stock conf+KDB once; restore after a mutating gate when KERBER_LIVE=1.
mit_conf_snapshot() {
    local ctn="${1:-$NAME}"
    docker exec "$ctn" sh -c '
        [ -f /tmp/kerber-stock-kdc.conf ] || cp -a /etc/krb5kdc/kdc.conf /tmp/kerber-stock-kdc.conf
        [ -f /tmp/kerber-stock-krb5.conf ] || cp -a /etc/krb5.conf /tmp/kerber-stock-krb5.conf
        [ -f /tmp/kerber-stock.dump ] || kdb5_util dump /tmp/kerber-stock.dump >/dev/null 2>&1 || true
    '
}

mit_conf_restore() {
    local ctn="${1:-$NAME}"
    docker exec "$ctn" sh -c '
        [ -f /tmp/kerber-stock-kdc.conf ] && cp /tmp/kerber-stock-kdc.conf /etc/krb5kdc/kdc.conf
        [ -f /tmp/kerber-stock-krb5.conf ] && cp /tmp/kerber-stock-krb5.conf /etc/krb5.conf
        if [ -f /tmp/kerber-stock.dump ]; then
            kdb5_util load /tmp/kerber-stock.dump >/dev/null 2>&1 || true
        fi
        kill $(pidof krb5kdc) 2>/dev/null || true
        kill $(pidof kadmind) 2>/dev/null || true
        kill $(pidof krb5-kdc) 2>/dev/null || true
    ' || true
    wait_pid_gone "$ctn" krb5kdc || true
    wait_pid_gone "$ctn" kadmind || true
    docker exec -d "$ctn" krb5kdc || true
    local i
    for i in $(seq 1 40); do
        if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 0
}

# Mutating Group-A gates restore stock conf+KDB when attaching to a shared MIT KDC.
mit_live_guard() {
    if [ "${KERBER_LIVE:-}" = 1 ]; then
        mit_conf_snapshot "$NAME"
        register_cleanup "mit_conf_restore '$NAME'"
    fi
}
