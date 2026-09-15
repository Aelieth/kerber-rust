#!/usr/bin/env bash
# Job preamble: one stock MIT KDC. Subsequent steps set KERBER_LIVE=1.
# Does not remove the container on EXIT (the job cleanup step does).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_image
export KERBER_STOCK_KEEP=1
NAME="${KERBER_MIT_NAME:-kerber-rust-mit-kdc}"
stock_mit_kdc "$NAME"
mit_conf_snapshot "$NAME"
echo "KERBER_LIVE=1" >>"${GITHUB_ENV:-/dev/null}"
echo "KERBER_MIT_NAME=$NAME" >>"${GITHUB_ENV:-/dev/null}"
log "boot.stock-mit" "ok" ",\"name\":\"$NAME\""
