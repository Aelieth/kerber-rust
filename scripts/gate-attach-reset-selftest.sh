#!/usr/bin/env bash
# X3: attach-reset kills leftover /tmp/*-proxy.py and wait_bound_in
# refuses a port that was already bound. Needs docker + a shell container.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/gate-common.sh"

if ! command -v docker >/dev/null 2>&1; then
    echo "skip: no docker"
    exit 0
fi
IMAGE="${IMAGE:-kerber-rust-mit-kdc:1.22.2}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "skip: no $IMAGE"
    exit 0
fi

OWN=0
if [ -z "${KERBER_SHELL:-}" ]; then
    NAME="kerber-rust-attach-selftest-$$"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 120 >/dev/null
    KERBER_SHELL="$NAME"
    OWN=1
    trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
fi
NAME="$KERBER_SHELL"

# Stray UDP proxy named *-proxy.py so attach-reset's pkill matches.
docker exec "$NAME" sh -c 'cat > /tmp/stray-proxy.py <<'"'"'PY'"'"'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 1888))
time.sleep(30)
PY'
docker exec -d "$NAME" python3 /tmp/stray-proxy.py
sleep 0.3
if wait_bound_free_in "$NAME" 1888 udp; then
    echo "wait_bound_free_in must fail on a pre-bound port" >&2
    exit 1
fi

# Attach-reset must kill the stray and leave 1888 free (UDP, not just TCP).
KERBER_SHELL="$NAME" shell_container
wait_gone_in "$NAME" 1888 40 || {
    echo "attach-reset left :1888 bound" >&2
    exit 1
}
if ! wait_bound_free_in "$NAME" 1888 udp; then
    echo "attach-reset left a UDP listener on :1888" >&2
    exit 1
fi
echo "attach-reset proxy self-test ok"
