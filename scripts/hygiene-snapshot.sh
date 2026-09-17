#!/usr/bin/env bash
# Record a W2/W3 hygiene snapshot: tests, gate cells, oracles, time, quality.
# Usage: scripts/hygiene-snapshot.sh [--root DIR] [--skip-nextest] [--quality] OUTDIR
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CALLER_PWD="$PWD"
cd "$ROOT"
SKIP_NEXTEST=0
QUALITY=0
SRC_ROOT="$ROOT"
OUT=""
# Relative --root and OUTDIR resolve against the caller's directory, not the
# tree this script lives in (a snapshot may be taken by a copy of the tooling).
while [ $# -gt 0 ]; do
    case "$1" in
        --root) SRC_ROOT="$(cd "$CALLER_PWD" && cd "$2" && pwd)"; shift 2 ;;
        --skip-nextest) SKIP_NEXTEST=1; shift ;;
        --quality) QUALITY=1; shift ;;
        --) shift; break ;;
        -*) echo "usage: $0 [--root DIR] [--skip-nextest] [--quality] OUTDIR" >&2; exit 2 ;;
        *) OUT="$1"; shift; break ;;
    esac
done
if [ -z "${OUT:-}" ]; then
    echo "usage: $0 [--root DIR] [--skip-nextest] [--quality] OUTDIR" >&2
    exit 2
fi
case "$OUT" in /*) ;; *) OUT="$CALLER_PWD/$OUT" ;; esac
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# provenance.sh scratches under KERBER_SCRATCH, never host /tmp.
export KERBER_SCRATCH="${KERBER_SCRATCH:-$OUT/scratch}"
mkdir -p "$KERBER_SCRATCH"

# Stamp. Snapshots are tooling artefacts: allow a missing MIT image.
if [ -f "$SRC_ROOT/scripts/lib/provenance.sh" ]; then
    (
        cd "$SRC_ROOT"
        # shellcheck disable=SC1091
        KERBER_NO_IMAGE="${KERBER_NO_IMAGE:-1}" . "$SRC_ROOT/scripts/lib/provenance.sh"
    ) >"$OUT/provenance.txt" 2>&1 || true
fi

args=(--root "$SRC_ROOT" --out "$OUT")
if [ "$SKIP_NEXTEST" = 1 ]; then
    args+=(--skip-nextest)
fi
if [ "$QUALITY" = 1 ]; then
    args+=(--quality)
fi
python3 "$ROOT/scripts/lib/hygiene_inventory.py" "${args[@]}"
echo "hygiene-snapshot: wrote $OUT"
