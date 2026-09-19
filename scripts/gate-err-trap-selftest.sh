#!/usr/bin/env bash
# The provenance lib's ERR trap must annotate a silent `set -e` death with the
# gate file and line, and stay quiet for deliberate failures. Runs in the
# `test` job; no container needed (KERBER_NO_IMAGE=1 stamps without one).
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
echo "$OUT" | grep -qF '::error file=scripts/probe-gate.sh,line=13,title=fixture::probe-gate.sh: exit 3 at line 13: '
OUT="$(run capture)"
echo "$OUT"
echo "$OUT" | grep -qF '::error file=scripts/probe-gate.sh,line=14,title=fixture::probe-gate.sh: exit 1 at line 14: '
OUT="$(run explicit)"
echo "$OUT"
if echo "$OUT" | grep -q '::error'; then
    echo "an explicit exit must not be annotated" >&2
    exit 1
fi
echo "$OUT" | grep -qF '"outcome":"error"'

# die / unavailable are plain exits (no ERR trap). Under GITHUB_ACTIONS they
# must still print a file:line annotation (run 649 had none).
cat >"$TMP/scripts/die-probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
cd "$KERBER_ROOT"
. "$KERBER_ROOT/scripts/lib/provenance.sh" >/dev/null
. "$KERBER_ROOT/scripts/lib/gate-common.sh"
die "forced failure"
PROBE
cat >"$TMP/scripts/unavail-probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
cd "$KERBER_ROOT"
. "$KERBER_ROOT/scripts/lib/provenance.sh" >/dev/null
. "$KERBER_ROOT/scripts/lib/gate-common.sh"
unavailable "forced unavailable"
PROBE
chmod +x "$TMP/scripts/die-probe.sh" "$TMP/scripts/unavail-probe.sh"
run_die() {
    (
        cd "$TMP" || exit 1
        export KERBER_ROOT="$ROOT" KERBER_NO_IMAGE=1 KERBER_SCRATCH="$TMP/scratch"
        if [ -n "${1-}" ]; then
            export GITHUB_ACTIONS="$1"
        else
            unset GITHUB_ACTIONS
        fi
        bash ./scripts/die-probe.sh 2>&1
    ) || true
}
OUT="$(run_die 1)"
echo "$OUT"
echo "$OUT" | grep -qF '::error file=scripts/die-probe.sh,line=6,title=fixture::die-probe.sh: forced failure'
OUT="$(run_die)"
if echo "$OUT" | grep -q '::error'; then
    echo "die must not annotate without GITHUB_ACTIONS" >&2
    exit 1
fi
OUT="$(
    cd "$TMP" && KERBER_ROOT="$ROOT" KERBER_NO_IMAGE=1 \
        KERBER_SCRATCH="$TMP/scratch" GITHUB_ACTIONS=1 \
        bash ./scripts/unavail-probe.sh 2>&1 || true
)"
echo "$OUT"
echo "$OUT" | grep -qF '::error file=scripts/unavail-probe.sh,line=6,title=fixture::unavail-probe.sh: forced unavailable'
echo "gate-err-trap-selftest: ok"
