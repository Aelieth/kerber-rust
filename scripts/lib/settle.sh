#!/usr/bin/env bash
# Capture a live settle: provenance, echoed command, verbatim output.
# Usage: scripts/lib/settle.sh <name> -- <command…>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [ "$#" -lt 3 ] || [ "$2" != "--" ]; then
    echo "usage: $0 <name> -- <command…>" >&2
    exit 2
fi
name=$1
shift 2

base=$(basename -- "$1")
if [ "$base" = "grep" ] || [ "$base" = "egrep" ] || [ "$base" = "fgrep" ]; then
    for a in "$@"; do
        if [ -f "$a" ]; then
            echo "settle.sh: grep of a file is not a live settle" >&2
            exit 2
        fi
    done
fi

# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
echo "==== settle $name ===="
echo "cmd=$*"
set -o pipefail
if [ -n "${KERBER_SCRATCH:-}" ]; then
    mkdir -p "$KERBER_SCRATCH"
    "$@" 2>&1 | tee "$KERBER_SCRATCH/settle-${name}.log"
else
    "$@" 2>&1 | tee
fi
