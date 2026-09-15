#!/usr/bin/env bash
# Local/checkpoint wrapper: rust, rust-acl, mit, both; same containers.
# CI runs the four scripts as separate harness steps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
export KERBER_KADMIN_KEEP=1
export KERBER_SCRATCH="${KERBER_SCRATCH:-${TMPDIR:-/tmp}/kerber-kadmin-gate}"
mkdir -p "$KERBER_SCRATCH"
register_cleanup 'docker rm -f kerber-rust-kadmin-gate kerber-rust-kadmin-mit >/dev/null 2>&1 || true'
./scripts/kadmin-rust-gate.sh
./scripts/kadmin-rust-acl-gate.sh
./scripts/kadmin-mit-gate.sh
./scripts/kadmin-both-gate.sh
log "kadmin.gate" "ok" ',"legs":"rust+rust-acl+mit+both"'
