#!/usr/bin/env bash
# The provenance lib's ERR trap must annotate a silent `set -e` death with the
# gate file and line, and stay quiet for deliberate failures. Runs in the
# `audit` job; no container needed (KERBER_NO_IMAGE=1 stamps without one).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d "${KERBER_SCRATCH:-${TMPDIR:-/tmp}}/gate-err-trap.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/scripts"
cat >"$TMP/scripts/probe-gate.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
cd "$KERBER_ROOT"
# shellcheck disable=SC1091
. "$KERBER_ROOT/scripts/lib/provenance.sh" >/dev/null
f() { return 3; }
false || true
set +e
false
set -e
if false; then :; fi
X="$(false)" || true
case "$1" in
    silent) f ;;
    capture) Y="$(false)" ;;
    explicit) echo '{"event":"probe","outcome":"error"}'; exit 1 ;;
esac
echo "reached the end"
PROBE
chmod +x "$TMP/scripts/probe-gate.sh"
run() {
    (cd "$TMP" && KERBER_ROOT="$ROOT" KERBER_NO_IMAGE=1 bash ./scripts/probe-gate.sh "$1" 2>&1) || true
}
OUT="$(run silent)"
echo "$OUT"
# The line is the call site; the command text is the innermost one (bash's BASH_COMMAND).
echo "$OUT" | grep -qF '::error file=scripts/probe-gate.sh,line=14::probe-gate.sh: exit 3 at line 14: '
OUT="$(run capture)"
echo "$OUT"
echo "$OUT" | grep -qF '::error file=scripts/probe-gate.sh,line=15::probe-gate.sh: exit 1 at line 15: '
OUT="$(run explicit)"
echo "$OUT"
if echo "$OUT" | grep -q '::error'; then
    echo "an explicit exit must not be annotated" >&2
    exit 1
fi
echo "$OUT" | grep -qF '"outcome":"error"'
echo "gate-err-trap-selftest: ok"
