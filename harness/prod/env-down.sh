#!/usr/bin/env bash
# Tear down the C1 multi-host prod realm (containers + network). Idempotent.
# Pass --all to also remove any Samba oracle containers/networks left running.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$HERE/limits.env"

echo "[env-down] removing prod nodes"
docker rm -f kerber-rust-prod-kdc1 kerber-rust-prod-kdc2 kerber-rust-prod-client >/dev/null 2>&1 || true

if [ "${1:-}" = "--all" ]; then
    echo "[env-down] --all: removing Samba oracle containers + realtrust network"
    docker ps -a --format '{{.Names}}' | grep -E '^kerber-rust-samba' \
        | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network rm kerber-rust-realtrust >/dev/null 2>&1 || true
fi

docker network rm "$KERBER_PROD_NET" >/dev/null 2>&1 || true
echo "[env-down] done"
docker ps -a --format '{{.Names}}' | grep -E '^kerber-rust-' | sed 's/^/    still up: /' || echo "    (no kerber-rust containers remain)"
