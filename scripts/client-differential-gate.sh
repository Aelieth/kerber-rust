#!/usr/bin/env bash
# Local wrapper: 11 FLOW_* then CLI/gss/Z (CI runs them as separate steps).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
export KERBER_CLIENT_DIFF_KEEP=1
export KERBER_SCRATCH="${KERBER_SCRATCH:-${TMPDIR:-/tmp}/kerber-client-diff-gate}"
mkdir -p "$KERBER_SCRATCH"
./scripts/client-differential-flows-gate.sh
./scripts/client-differential-cli-gate.sh
