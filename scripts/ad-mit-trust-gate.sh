#!/usr/bin/env bash
# Retired Windows-DC one-shot. Cross-realm is samba-realtrust-gate.sh
# (two Samba DCs + samba-tool domain trust create). Does not claim a Windows DC.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
exec "$ROOT/scripts/samba-realtrust-gate.sh" "$@"
