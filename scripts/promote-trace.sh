#!/usr/bin/env bash
# Copy one captured PDU into tests/traces/ and append a README provenance row.
# Captures stay under $KERBER_SCRATCH/traces; this is the only write into the
# golden home. Dest must already be on the .gitignore allow-list.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
    echo "usage: scripts/promote-trace.sh <src> <dest-name> <tag> <origin>" >&2
    echo "  dest-name is a golden under tests/traces/ (e.g. mit-as-req.der)" >&2
    exit 2
}

[ "$#" -eq 4 ] || usage
src=$1
dest=$2
tag=$3
origin=$4

case "$dest" in
    mit-as-req.der | mit-as-req-preauth.der | mit-krb-error-preauth.der | \
    mit-as-rep.der | mit-tgs-req.der | mit-tgs-rep.der | pac-kbruser.ndr | \
    ccache-mit-addr-u2u.bin | kdb/mit-dump-v7.txt | kdb/mit-dump-v6.txt | \
    kdb/getprinc-pauser.txt | kdb/mit-dump-v7-history.txt) ;;
    *)
        echo "promote-trace: $dest is not a tracked golden (update .gitignore + README)" >&2
        exit 2
        ;;
esac

if [ ! -f "$src" ]; then
    echo "promote-trace: missing src $src" >&2
    exit 2
fi

dest_path="$ROOT/tests/traces/$dest"
mkdir -p "$(dirname "$dest_path")"
cp -f "$src" "$dest_path"

readme="$ROOT/tests/traces/README.md"
row="| \`$dest\` | \`$tag\` | $origin |"
python3 - "$readme" "$row" "$dest" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
row = sys.argv[2]
dest = sys.argv[3]
text = path.read_text(encoding="utf-8")
if f"| `{dest}` |" in text:
    sys.exit(0)
lines = text.splitlines(keepends=True)
last = -1
for i, ln in enumerate(lines):
    if ln.startswith("| `"):
        last = i
if last < 0:
    sys.exit("promote-trace: no provenance table in README")
lines.insert(last + 1, row + "\n")
path.write_text("".join(lines), encoding="utf-8")
PY

echo "promote-trace: wrote tests/traces/$dest"
