#!/usr/bin/env bash
# Set the workspace version and move it into every committed Cargo.lock (fuzz/, the T-7
# harness and any later one), so `--locked` builds pass. vendor/'s locks are upstream's.
set -euo pipefail
[[ $# -eq 1 && $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || {
    echo "usage: $0 VERSION" >&2
    exit 2
}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
sed -i "/^\[workspace\.package\]/,/^\[/ s/^version = \".*\"/version = \"$1\"/" Cargo.toml
grep -qx "version = \"$1\"" Cargo.toml || { echo "Cargo.toml: version not set" >&2; exit 1; }
git ls-files '*Cargo.lock' | grep -v '^vendor/' | while read -r lock; do
    (cd "$(dirname "$lock")" && cargo update -w --offline)
done
