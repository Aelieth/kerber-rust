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
echo "$OUT" | grep -qF '::notice file=scripts/unavail-probe.sh,line=6,title=fixture::unavail-probe.sh: forced unavailable'

# require_listen must not die on bind failed while krb5-kdc is still
# alive (the :88 || :8888 fallback). A stub docker logs bind failed for
# two polls, then listening 127.0.0.1:8888, and pidof krb5-kdc succeeds.
mkdir -p "$TMP/fakebin"
printf '0\n' >"$TMP/rl-poll"
cat >"$TMP/fakebin/docker" <<'FAKE'
#!/usr/bin/env bash
# Minimal docker exec stub for require_listen.
shift
shift
pollf="${KERBER_RL_POLL:?}"
n="$(cat "$pollf")"
case "${1:-}" in
    grep)
        pat="${3:-}"
        case "$pat" in
            '^listening '*)
                n=$((n + 1))
                echo "$n" >"$pollf"
                [ "$n" -ge 3 ]
                ;;
            'bind failed')
                [ "$n" -lt 3 ]
                ;;
            privilege*|*'bind failed'*)
                exit 1
                ;;
            *)
                exit 1
                ;;
        esac
        ;;
    sh)
        # pidof krb5-kdc — process still alive during the fallback.
        exit 0
        ;;
    cat)
        echo 'bind failed: 127.0.0.1:88'
        echo 'listening 127.0.0.1:8888'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
FAKE
chmod +x "$TMP/fakebin/docker"
cat >"$TMP/scripts/listen-probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
cd "$KERBER_ROOT"
. "$KERBER_ROOT/scripts/lib/provenance.sh" >/dev/null
. "$KERBER_ROOT/scripts/lib/gate-common.sh"
require_listen fake /tmp/kdc.log "rust KDC listening in /tmp/kdc.log" 20
echo "require_listen fallback ok"
PROBE
chmod +x "$TMP/scripts/listen-probe.sh"
OUT="$(
    cd "$TMP" && KERBER_ROOT="$ROOT" KERBER_NO_IMAGE=1 \
        KERBER_SCRATCH="$TMP/scratch" KERBER_RL_POLL="$TMP/rl-poll" \
        PATH="$TMP/fakebin:$PATH" \
        bash ./scripts/listen-probe.sh 2>&1
)"
echo "$OUT"
echo "$OUT" | grep -qF 'require_listen fallback ok'
if echo "$OUT" | grep -q 'never appeared'; then
    echo "require_listen died on bind failed while krb5-kdc was alive" >&2
    exit 1
fi

# require_log's die must annotate the gate line, not gate-common.sh.
printf '0\n' >"$TMP/rl-poll"
cat >"$TMP/fakebin/docker" <<'FAKE'
#!/usr/bin/env bash
exit 1
FAKE
chmod +x "$TMP/fakebin/docker"
cat >"$TMP/scripts/require-log-probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
cd "$KERBER_ROOT"
. "$KERBER_ROOT/scripts/lib/provenance.sh" >/dev/null
. "$KERBER_ROOT/scripts/lib/gate-common.sh"
require_log fake /tmp/x.log 'never-pattern' "never-line" 3
echo "require_log should have died"
PROBE
chmod +x "$TMP/scripts/require-log-probe.sh"
OUT="$(
    cd "$TMP" && KERBER_ROOT="$ROOT" KERBER_NO_IMAGE=1 \
        KERBER_SCRATCH="$TMP/scratch" GITHUB_ACTIONS=1 \
        PATH="$TMP/fakebin:$PATH" \
        bash ./scripts/require-log-probe.sh 2>&1 || true
)"
echo "$OUT"
echo "$OUT" | grep -qF '::error file=scripts/require-log-probe.sh,line=6,title=fixture::require-log-probe.sh: never-line never appeared'
if echo "$OUT" | grep -q 'gate-common.sh'; then
    echo "require_log annotated gate-common.sh instead of the gate" >&2
    exit 1
fi

# stock_mit_kdc: dead shared container warns and snapshots; green attach is quiet.
cat >"$TMP/fakebin/docker" <<'FAKE'
#!/usr/bin/env bash
cmd=$1
shift || true
case "$cmd" in
    inspect)
        if [ -f "${KERBER_STOCK_RUNNING:-}" ]; then echo true; else echo false; fi
        ;;
    logs)
        echo '{"event":"harness.kinit","correlation_id":"x","outcome":"ok"}'
        ;;
    rm|run)
        echo "$cmd" >>"${KERBER_STOCK_MARK:?}"
        echo cid
        ;;
    exec)
        case "$*" in
            *kerber-stock*) echo snapshot >>"${KERBER_STOCK_MARK:?}" ;;
        esac
        ;;
    *)
        exit 1
        ;;
esac
FAKE
chmod +x "$TMP/fakebin/docker"
cat >"$TMP/scripts/stock-probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
cd "$KERBER_ROOT"
. "$KERBER_ROOT/scripts/lib/provenance.sh" >/dev/null
. "$KERBER_ROOT/scripts/lib/gate-common.sh"
stock_mit_kdc
echo "stock_mit_kdc ok"
PROBE
chmod +x "$TMP/scripts/stock-probe.sh"
run_stock() {
    local mark=$1 running=${2:-}
    : >"$mark"
    (
        cd "$TMP" || exit 1
        export KERBER_ROOT="$ROOT" KERBER_NO_IMAGE=1 KERBER_SCRATCH="$TMP/scratch"
        export KERBER_LIVE=1 KERBER_MIT_NAME=fake-mit KERBER_STOCK_LIVE_N=1
        export KERBER_STOCK_MARK="$mark" GITHUB_ACTIONS=1
        export PATH="$TMP/fakebin:$PATH"
        if [ -n "$running" ]; then
            export KERBER_STOCK_RUNNING="$running"
        else
            unset KERBER_STOCK_RUNNING
        fi
        bash ./scripts/stock-probe.sh 2>&1
    ) || true
}
MARK="$TMP/stock.mark"
OUT="$(run_stock "$MARK")"
echo "$OUT"
echo "$OUT" | grep -qF '::warning::dead shared MIT container fake-mit; starting a replacement'
echo "$OUT" | grep -qF '"event":"stock.mit"'
echo "$OUT" | grep -qF 'stock_mit_kdc ok'
grep -q '^run$' "$MARK"
grep -q '^snapshot$' "$MARK"
: >"$MARK"
touch "$TMP/stock.running"
OUT="$(run_stock "$MARK" "$TMP/stock.running")"
echo "$OUT"
echo "$OUT" | grep -qF 'stock_mit_kdc ok'
if echo "$OUT" | grep -q '::warning'; then
    echo "healthy LIVE attach must not warn" >&2
    exit 1
fi
if [ -s "$MARK" ]; then
    echo "healthy LIVE attach must not replace the container: $(cat "$MARK")" >&2
    exit 1
fi
echo "gate-err-trap-selftest: ok"
