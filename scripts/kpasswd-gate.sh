#!/usr/bin/env bash
# Local wrapper: rust then MIT kpasswd legs (CI runs them as separate steps).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
export KERBER_KPASSWD_KEEP=1
export KERBER_SCRATCH="${KERBER_SCRATCH:-${TMPDIR:-/tmp}/kerber-kpasswd-gate}"
mkdir -p "$KERBER_SCRATCH"
./scripts/kpasswd-rust-gate.sh
./scripts/kpasswd-mit-gate.sh
