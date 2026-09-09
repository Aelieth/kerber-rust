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

readers='grep|egrep|fgrep|rg|zgrep|sed|cat|awk|head|tail'
base=$(basename -- "$1")
case "$base" in
    grep|egrep|fgrep|rg|zgrep|sed|cat|awk|head|tail)
        for a in "$@"; do
            case "$a" in
                -*) continue ;;
                */*|*.log|*.txt|*.json|*.md|*.c|*.h|*.y|*.rs|*.sh|*.py) ;;
                *) [ -f "$a" ] || continue ;;
            esac
            echo "settle.sh: $base of a file is not a live settle ($a)" >&2
            exit 2
        done
        ;;
    bash|sh|dash|zsh|ksh)
        if [ "${2:-}" = "-c" ] && printf '%s' "${3:-}" | grep -Eq "(^|[^[:alnum:]_/.-])($readers)([[:space:]]|$)"; then
            echo "settle.sh: $base -c with a file reader is not a live settle" >&2
            exit 2
        fi
        ;;
esac

# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
# R2-T8: a settle must describe committed code, so refuse a dirty tree (working/
# is already excluded from provenance.sh's dirty check). KERBER_SETTLE_ALLOW_DIRTY
# overrides it for the ci-policy self-test, which runs on the dev tree; the
# override is stamped into the artefact so claim-audit / evidence-check see it.
if [ "${dirty:-yes}" != no ]; then
    if [ "${KERBER_SETTLE_ALLOW_DIRTY:-}" != 1 ]; then
        echo "settle.sh: refusing to settle a dirty tree (dirty=${dirty:-yes}); set KERBER_SETTLE_ALLOW_DIRTY=1 to override" >&2
        exit 1
    fi
    echo "override=KERBER_SETTLE_ALLOW_DIRTY"
fi
echo "==== settle $name ===="
echo "cmd=$*"
set -o pipefail
if [ -n "${KERBER_SCRATCH:-}" ]; then
    mkdir -p "$KERBER_SCRATCH"
    "$@" 2>&1 | tee "$KERBER_SCRATCH/settle-${name}.log"
else
    "$@" 2>&1 | tee
fi
