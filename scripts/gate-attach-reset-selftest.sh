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

# Stray UDP proxy on 1888 inside the shared container.
docker exec -d "$NAME" python3 -c "
import socket, time
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 1888))
time.sleep(30)
" >/dev/null
sleep 0.3
wait_bound_in "$NAME" 1888 5 udp && {
    echo "wait_bound_in must fail on a pre-bound port" >&2
    exit 1
}

# Attach-reset must kill the stray and leave 1888 free.
KERBER_SHELL="$NAME" shell_container
wait_gone_in "$NAME" 1888 40 || {
    echo "attach-reset left :1888 bound" >&2
    exit 1
}
echo "attach-reset proxy self-test ok"
