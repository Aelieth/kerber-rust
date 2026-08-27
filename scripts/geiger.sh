#!/usr/bin/env bash
# Per-crate cargo-geiger. The workspace root is a virtual manifest, so each
# product library is scanned with --manifest-path, not `cargo geiger -p`.
# Product crates must be 0-unsafe / forbid-unsafe. Dependency unsafe is
# archived when GEIGER_DEPS_OUT is set; it is not a numeric gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CRATES=(
    krb5-log
    krb5-crypto
    krb5-types
    krb5-asn1
    krb5-config
    krb5-protocol
    krb5-client
    krb5-kdc
    krb5-gss
    krb5-admin
)

die() {
    echo "geiger: $*" >&2
    exit 1
}

if ! command -v cargo-geiger >/dev/null 2>&1; then
    die "cargo-geiger not installed"
fi

# Language-level unsafe in product sources (not rustdoc backticks).
if grep -RInE --include='*.rs' \
    '(^|[^[:alnum:]_`])unsafe[[:space:]]*(fn|impl|trait|\{|\()' \
    crates/krb5-*/src crates/krb5-*/tests crates/krb5-*/examples \
    2>/dev/null; then
    die "product source contains language-level unsafe"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
jsons=()

for crate in "${CRATES[@]}"; do
    manifest="$ROOT/crates/${crate}/Cargo.toml"
    [[ -f "$manifest" ]] || die "missing ${manifest}"
    json="$tmp/${crate}.json"
    if ! cargo geiger --manifest-path "$manifest" --forbid-only \
        --output-format Json --locked --color never \
        >"$json" 2>"$tmp/${crate}.err"; then
        cat "$tmp/${crate}.err" >&2
        die "cargo geiger failed for ${crate}"
    fi
    python3 - "$crate" "$json" <<'PY'
import json
import sys

name, path = sys.argv[1], sys.argv[2]
data = json.load(open(path, encoding="utf-8"))
found = False
for entry in data.get("packages") or []:
    ident = (entry.get("package") or {}).get("id") or {}
    if ident.get("name") != name:
        continue
    found = True
    if not entry.get("forbids_unsafe"):
        print(f"{name}: geiger forbids_unsafe=false", file=sys.stderr)
        sys.exit(1)
    print(f"{name}: forbid-unsafe ok")
    break
if not found:
    print(f"{name}: not in geiger report", file=sys.stderr)
    sys.exit(1)
PY
    jsons+=("$json")
done

if [[ -n "${GEIGER_DEPS_OUT:-}" ]]; then
    python3 - "$GEIGER_DEPS_OUT" "${jsons[@]}" <<'PY'
import json
import sys

out = sys.argv[1]
seen = {}
for path in sys.argv[2:]:
    data = json.load(open(path, encoding="utf-8"))
    for entry in data.get("packages") or []:
        ident = (entry.get("package") or {}).get("id") or {}
        name = ident.get("name") or ""
        if name.startswith("krb5-"):
            continue
        if entry.get("forbids_unsafe"):
            continue
        ver = ident.get("version") or ""
        seen[f"{name} {ver}"] = True
with open(out, "w", encoding="utf-8") as f:
    for line in sorted(seen):
        f.write(line + "\n")
print(f"geiger: archived {len(seen)} dependency crates without forbid(unsafe)")
PY
fi

echo "geiger: ${#CRATES[@]} product crates 0-unsafe / forbid-unsafe"
