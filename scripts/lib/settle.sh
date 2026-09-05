#!/usr/bin/env bash
# Capture a live settle: provenance, echoed command, verbatim output.
# Usage: scripts/lib/settle.sh <name> -- <command…>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

if [ "$#" -lt 3 ] || [ "$2" != "--" ]; then
    echo "usage: $0 <name> -- <command…>" >&2
    exit 2
fi
name=$1
shift 2
echo "==== settle $name ===="
echo "cmd=$*"
exec "$@"
