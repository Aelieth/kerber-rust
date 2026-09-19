# Shared gate preamble. Source after `cd "$ROOT"` and after provenance.sh.
# shellcheck shell=bash
# Provides: log, die, unavailable, register_cleanup, wait_port, wait_listen,
# wait_gone, wait_log, require_listen, require_log, require_port_in,
# retry_until,
# wait_port_in, wait_udp_in, wait_tcp_bound_in, wait_gone_in, wait_pid_gone, need_image,
# need_bins, shell_container, kdc_start, kdc_restart, mit_kdc_restart,
# stock_mit_kdc. One EXIT trap writes gate_wall_s= and runs registered
# cleanups. Does not replace provenance's ERR. Host wait_port/wait_gone need a
# published port; wait_port_in/wait_gone_in probe inside $NAME.

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
    if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
        echo "log: expected 2-3 args, got $# ($*)" >&2
        return 1
    fi
    printf '{"event":"%s","correlation_id":"%s","component":"%s","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$COMPONENT" "${2:-}" "${3:-}"
}

# Actions annotation for die (::error) and unavailable (::notice).
# Names the first frame outside scripts/lib/ so a require_* failure
# points at the gate line, not gate-common.sh.
_gate_annotate() {
    local level=$1 msg=$2
    local i src rel line
    src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
    line="${BASH_LINENO[0]:-0}"
    for ((i = 1; i < ${#BASH_SOURCE[@]}; i++)); do
        src="${BASH_SOURCE[$i]}"
        rel="${src#"$PWD"/}"
        rel="${rel#./}"
        case "$rel" in
            scripts/lib/*) continue ;;
        esac
        case "$src" in
            */scripts/lib/*) continue ;;
        esac
        line="${BASH_LINENO[$((i - 1))]:-0}"
        break
    done
    [ -n "${GITHUB_ACTIONS:-}" ] || return 0
    src=${src#"$PWD"/}
    src=${src#./}
    local title=
    case "${src##*/}" in
        probe-gate.sh|*-probe.sh) title=',title=fixture' ;;
    esac
    if [ "$level" = notice ]; then
        printf '::notice file=%s,line=%s%s::%s: %s\n' "$src" "$line" "$title" "${src##*/}" "$msg"
        return 0
    fi
    printf '::error file=%s,line=%s%s::%s: %s\n' "$src" "$line" "$title" "${src##*/}" "$msg"
}

die() {
    _gate_annotate error "$1"
    log "${COMPONENT}.gate" "error" ",\"error\":\"$1\""
    echo "$1" >&2
    exit 1
}

# Product capture has no path policy (S2-R R1). Gates must not point
# KERBER_CAPTURE_DIR or TRACE_DST at the golden home.
refuse_golden_capture_dir() {
    local d="${1:-}"
    [ -z "$d" ] && return 0
    local norm="${d//\\//}"
    case "/$norm/" in
        */tests/traces/*) die "KERBER_CAPTURE_DIR refuses tests/traces: $d" ;;
    esac
}

unavailable() {
    _gate_annotate notice "$1"
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
    local host="${1:-127.0.0.1}" port="${2:-88}" n="${3:-200}"
    for _ in $(seq 1 "$n"); do
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
    local ctn=$1 logfile=$2 n="${3:-200}"
    for _ in $(seq 1 "$n"); do
        if docker exec "$ctn" grep -q '^listening ' "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    docker exec "$ctn" cat "$logfile" >&2 || true
    return 1
}

wait_gone() {
    local host="${1:-127.0.0.1}" port="${2:-88}" n="${3:-100}"
    for _ in $(seq 1 "$n"); do
        if ! wait_port "$host" "$port" 1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_log() {
    local ctn=$1 logfile=$2 pattern=$3 n="${4:-200}"
    for _ in $(seq 1 "$n"); do
        if docker exec "$ctn" grep -qE "$pattern" "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Bounded readiness. Hard-cap the poll, then die naming what never appeared.
# Privilege/not-found/glibc abort early. bind failed does not: the
# `:88 || :8888` fallback start logs it while krb5-kdc is still alive.
require_listen() {
    local ctn=$1 logfile=$2 what=$3 n="${4:-200}"
    for _ in $(seq 1 "$n"); do
        if docker exec "$ctn" grep -q '^listening ' "$logfile" 2>/dev/null; then
            return 0
        fi
        if docker exec "$ctn" grep -qiE 'privilege drop:|not found|glibc' "$logfile" 2>/dev/null; then
            if ! docker exec "$ctn" grep -q '^listening ' "$logfile" 2>/dev/null; then
                docker exec "$ctn" cat "$logfile" >&2 || true
                die "$what never appeared (kdc start failed)"
            fi
        fi
        if docker exec "$ctn" grep -qi 'bind failed' "$logfile" 2>/dev/null; then
            if docker exec "$ctn" sh -c "pidof krb5-kdc >/dev/null" 2>/dev/null; then
                sleep 0.1
                continue
            fi
        fi
        sleep 0.1
    done
    docker exec "$ctn" cat "$logfile" >&2 || true
    die "$what never appeared"
}

require_log() {
    local ctn=$1 logfile=$2 pattern=$3 what=$4 n="${5:-200}"
    if wait_log "$ctn" "$logfile" "$pattern" "$n"; then
        return 0
    fi
    docker exec "$ctn" cat "$logfile" >&2 || true
    die "$what never appeared"
}

require_port_in() {
    local ctn=$1 port=$2 what=$3 n="${4:-200}"
    if wait_port_in "$ctn" "$port" "$n"; then
        return 0
    fi
    die "$what never appeared"
}

# Wait ≡ assertion: retry the assertion command itself. Default 20 s.
retry_until() {
    local n=$1 what=$2
    shift 2
    for _ in $(seq 1 "$n"); do
        if "$@"; then
            return 0
        fi
        sleep 0.1
    done
    die "$what never appeared"
}

# In-container TCP connect. Group-B shell containers do not publish KDC ports
# to the host, so wait_port (host-side) cannot see them.
wait_port_in() {
    local ctn="${1:-$NAME}" port="${2:-88}" n="${3:-200}"
    for _ in $(seq 1 "$n"); do
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
    local sock
    case "$kind" in
        tcp) sock="socket.SOCK_STREAM" ;;
        udp) sock="socket.SOCK_DGRAM" ;;
        *) return 1 ;;
    esac
    for _ in $(seq 1 "$n"); do
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

# Fail if the port is already bound (stale listener). Callers snapshot
# this before starting a daemon, then wait_bound_in after.
wait_bound_free_in() {
    ! wait_bound_in "${1:-$NAME}" "${2:-88}" 1 "${3:-udp}"
}

wait_udp_in() { wait_bound_in "${1:-$NAME}" "${2:-88}" "${3:-80}" udp; }
wait_tcp_bound_in() { wait_bound_in "${1:-$NAME}" "${2:-88}" "${3:-80}" tcp; }

# The MIT image has `kill` but not `pkill`/`pgrep`. Scan /proc for *-proxy.py.
# Skip this scanner's pid (its cmdline contains the needle) and SIGKILL leftovers.
kill_proxy_py_in() {
    docker exec "${1:-$NAME}" python3 -c '
import os, signal, time, sys
self = os.getpid()
killed = []
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    pid = int(name)
    if pid == self:
        continue
    try:
        cmd = open("/proc/%s/cmdline" % name, "rb").read().replace(b"\x00", b" ").decode("ascii", "replace")
    except Exception:
        continue
    if "-proxy.py" not in cmd:
        continue
    try:
        os.kill(pid, signal.SIGTERM)
        killed.append(pid)
    except OSError:
        pass
time.sleep(0.05)
live = []
for pid in killed:
    try:
        os.kill(pid, 0)
        live.append(pid)
    except OSError:
        pass
for pid in live:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
time.sleep(0.05)
for name in os.listdir("/proc"):
    if not name.isdigit() or int(name) == self:
        continue
    try:
        cmd = open("/proc/%s/cmdline" % name, "rb").read().replace(b"\x00", b" ").decode("ascii", "replace")
    except Exception:
        continue
    if "-proxy.py" in cmd:
        sys.exit(1)
' >/dev/null 2>&1 || return 1
    return 0
}

wait_gone_in() {
    # Port is gone when UDP bind succeeds (no leftover UDP proxy) AND TCP
    # connect fails. A TCP-only probe cannot see kdc-error-proxy.py.
    local ctn="${1:-$NAME}" port="${2:-88}" n="${3:-100}"
    for _ in $(seq 1 "$n"); do
        if wait_bound_free_in "$ctn" "$port" udp && ! wait_port_in "$ctn" "$port" 1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Kill Samba task[kdc] workers and wait for a *new* task[kdc] pid.
# UDP :88 never unbinds (the parent holds it); wait_udp_in 88 is vacuous.
samba_kdc_respawn_in() {
    local ctn="${1:?}"
    docker exec "$ctn" python3 -c '
import os, signal, time
self = os.getpid()
pids = []
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    pid = int(name)
    if pid == self:
        continue
    try:
        cmd = open("/proc/%s/cmdline" % name, "rb").read().replace(b"\x00", b" ").decode("ascii", "replace")
    except Exception:
        continue
    if "task[kdc]" not in cmd:
        continue
    pids.append(pid)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
deadline = time.time() + 8
while time.time() < deadline:
    live = []
    for pid in pids:
        try:
            os.kill(pid, 0)
            live.append(pid)
        except OSError:
            pass
    if not live:
        break
    if time.time() > deadline - 4:
        for pid in live:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    time.sleep(0.1)
else:
    raise SystemExit(1)
old = set(pids)
deadline = time.time() + 8
found = False
while time.time() < deadline:
    now = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == self:
            continue
        try:
            cmd = open("/proc/%s/cmdline" % name, "rb").read().replace(b"\x00", b" ").decode("ascii", "replace")
        except Exception:
            continue
        if "task[kdc]" not in cmd:
            continue
        now.append(pid)
    # Old pids are dead (loop above). A live task[kdc] is a respawn even
    # if the kernel reused a pid from `old`.
    if now:
        found = True
        break
    time.sleep(0.1)
if not found:
    raise SystemExit(1)
' >/dev/null 2>&1 || return 1
    return 0
}

wait_pid_gone() {
    local ctn="${1:-$NAME}" proc="$2" n="${3:-40}"
    [ -n "$proc" ] || return 1
    for _ in $(seq 1 "$n"); do
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
    log "need_bins" "ok" ",\"msg\":\"need_bins: building missing bins ($*) (KERBER_NEED_BINS_STRICT unset)\""
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
        [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ] \
            || die "KERBER_SHELL=$NAME is not running"
        # One exec: kill leftovers, wipe KDB, restore stock conf, wait
        # pids+ports inside the container (host-side wait_gone_in is 10
        # docker execs per attach and dominated the harness wall).
        docker exec "$NAME" sh -c "$(cat <<'EOS'
            kill $(pidof krb5-kdc krb5-kadmind krb5kdc kadmind kpropd) 2>/dev/null || true
            pkill -f -- '-proxy.py' >/dev/null 2>&1 || true
            kdb5_util destroy -f >/dev/null 2>&1 || true
            find /tmp -mindepth 1 -maxdepth 1 \
                ! -name 'krb5-*' ! -name 'ccache-probe' ! -name 'build' \
                -exec rm -rf {} +
            mkdir -p /tmp/build
            rm -f /var/krb5kdc/principal* /var/kerberos/krb5kdc/principal* \
                /var/krb5kdc/.k5.* /var/kerberos/krb5kdc/.k5.* \
                /etc/krb5kdc/principal*
            if [ -f /etc/krb5.conf.kerber-stock ]; then
                cp -a /etc/krb5.conf.kerber-stock /etc/krb5.conf
            fi
            if [ -f /etc/krb5kdc/kdc.conf.kerber-stock ]; then
                cp -a /etc/krb5kdc/kdc.conf.kerber-stock /etc/krb5kdc/kdc.conf
            fi
            i=0
            while [ "$i" -lt 20 ]; do
                pidof krb5-kdc krb5kdc krb5-kadmind kadmind kpropd >/dev/null 2>&1 || break
                i=$((i + 1))
                sleep 0.05
            done
            python3 -c "
import socket, time
ports = (88, 89, 90, 91, 464, 749, 1888, 1891, 1892, 2121)
deadline = time.time() + 2
while time.time() < deadline:
    busy = False
    for p in ports:
        s = socket.socket()
        s.settimeout(0.05)
        try:
            s.connect(('127.0.0.1', p))
            busy = True
        except Exception:
            pass
        s.close()
        if busy:
            break
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(('127.0.0.1', p))
        except OSError:
            busy = True
        u.close()
        if busy:
            break
    if not busy:
        break
    time.sleep(0.05)
"
EOS
        )" || true
        kill_proxy_py_in "$NAME"
        wait_gone_in "$NAME" 1888 40 || die "proxy still bound :1888 after attach-reset"
        wait_gone_in "$NAME" 1891 20 || die "proxy still bound :1891 after attach-reset"
        wait_gone_in "$NAME" 1892 20 || die "proxy still bound :1892 after attach-reset"
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

# Uncalled (kdc-gate inlines the start). Held for S6.
kdc_start() {
    local addr="${1:-127.0.0.1:88}"
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD="${KRB5_TEST_USER_PASSWORD:-userpassword}" \
        -e KRB5_TEST_ADMIN_PASSWORD="${KRB5_TEST_ADMIN_PASSWORD:-adminpassword}" \
        -e KRB5_MASTER_PASSWORD="${KRB5_MASTER_PASSWORD:-masterpassword}" \
        -e KRB5_KDC_DB="${KRB5_KDC_DB:-/tmp/principal}" \
        -e KRB5_KDC_STASH="${KRB5_KDC_STASH:-/tmp/stash}" \
        "$NAME" sh -c "/tmp/krb5-kdc --test-realm $addr >/tmp/kdc.log 2>&1"
    require_listen "$NAME" /tmp/kdc.log "rust KDC listening in /tmp/kdc.log"
}

# Uncalled. Held for S6.
kdc_restart() {
    docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true' || true
    wait_gone 127.0.0.1 88 40 || true
    kdc_start "$@"
}

# Uncalled. Held for S6.
mit_kdc_restart() {
    local ctn="${1:-$NAME}"
    docker exec "$ctn" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true' || true
    sleep 0.1 # proto: krb5kdc pid reuse
    docker exec -d "$ctn" krb5kdc
    for _ in $(seq 1 80); do
        if docker exec "$ctn" sh -c 'pidof krb5kdc >/dev/null' 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    die "mit krb5kdc did not restart"
}

# Shared-job attach (KERBER_LIVE=1): the boot-stock-mit.sh step may
# return while the container is still coming up, or the container may
# die between steps. Run 649 (b3471f0, mit-extra-2): boot 4 s, flows
# gate 6 s, no product annotation — the old LIVE path died on one
# inspect or returned without waiting for :88.
_stock_mit_running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]
}

_stock_mit_ready() {
    local n=$1 logs
    if wait_port_in "$n" 88 1; then
        return 0
    fi
    logs="$(docker logs "$n" 2>&1 || true)"
    echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'
}

_stock_mit_warn_dead() {
    local n=$1
    log "stock.mit" "warn" ",\"container\":\"$n\",\"warning\":\"dead shared container; starting a replacement\""
    echo "stock_mit_kdc: dead shared container $n; starting a replacement" >&2
    [ -z "${GITHUB_ACTIONS:-}" ] || printf '::warning::dead shared MIT container %s; starting a replacement\n' "$n"
}

stock_mit_kdc() {
    local n="${1:-${KERBER_MIT_NAME:-kerber-rust-mit-kdc}}"
    local logs replaced=0
    if [ "${KERBER_LIVE:-}" = 1 ]; then
        n="${KERBER_MIT_NAME:-kerber-rust-mit-kdc}"
        NAME="$n"
        for _ in $(seq 1 "${KERBER_STOCK_LIVE_N:-200}"); do
            if _stock_mit_running "$n" && _stock_mit_ready "$n"; then
                return 0
            fi
            if _stock_mit_running "$n"; then
                logs="$(docker logs "$n" 2>&1 || true)"
                if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
                    echo "$logs" >&2
                    die "stock MIT KDC harness kinit failed"
                fi
            fi
            sleep 0.1
        done
        if _stock_mit_running "$n"; then
            docker logs "$n" >&2 || true
            die "KERBER_LIVE=1 but $n never became ready"
        fi
        # Still dead: start a stock instance and keep it for later steps.
        _stock_mit_warn_dead "$n"
        KERBER_STOCK_KEEP=1
        replaced=1
    fi
    docker rm -f "$n" >/dev/null 2>&1 || true
    docker run -d --name "$n" \
        -e "CORRELATION_ID=${CORRELATION_ID}" \
        "$IMAGE" >/dev/null
    NAME="$n"
    if [ "${KERBER_STOCK_KEEP:-}" != 1 ]; then
        register_cleanup "docker rm -f '$n' >/dev/null 2>&1 || true"
    fi
    for _ in $(seq 1 90); do
        logs="$(docker logs "$n" 2>&1 || true)"
        if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
            if [ "$replaced" = 1 ]; then
                mit_conf_snapshot "$n"
            fi
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
        pkill -f -- '-proxy.py' >/dev/null 2>&1 || true
    ' || true
    kill_proxy_py_in "$ctn" || true
    wait_gone_in "$ctn" 1888 40 || die "proxy still bound :1888 after mit_conf_restore"
    wait_gone_in "$ctn" 1891 20 || die "proxy still bound :1891 after mit_conf_restore"
    wait_gone_in "$ctn" 1892 20 || die "proxy still bound :1892 after mit_conf_restore"
    wait_gone_in "$ctn" 1893 20 || die "proxy still bound :1893 after mit_conf_restore"
    wait_gone_in "$ctn" 1894 20 || die "proxy still bound :1894 after mit_conf_restore"
    wait_pid_gone "$ctn" krb5kdc || true
    wait_pid_gone "$ctn" kadmind || true
    docker exec -d "$ctn" krb5kdc || true
    for _ in $(seq 1 40); do
        if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    die "krb5kdc did not come back after mit_conf_restore"
}

# Mutating Group-A gates restore stock conf+KDB when attaching to a shared MIT KDC.
mit_live_guard() {
    if [ "${KERBER_LIVE:-}" = 1 ]; then
        mit_conf_snapshot "$NAME"
        register_cleanup "mit_conf_restore '$NAME'"
    fi
}
