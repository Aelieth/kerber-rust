#!/usr/bin/env bash
# Rebuild a historical SHA in a KERBER_SCRATCH worktree and run a gate or
# command against those binaries. Provenance header is printed first.
# Usage: scripts/red-at-sha.sh <base-sha> <gate-script-or-command> [args]
#        scripts/red-at-sha.sh --overlay-probe <base-sha> <rel-path>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

PROBE=0
if [ "${1:-}" = "--overlay-probe" ]; then
    PROBE=1
    shift
fi

if [ "$#" -lt 2 ]; then
    echo "usage: $0 [--overlay-probe] <base-sha> <gate-script-or-command> [args]" >&2
    exit 2
fi
if [ -z "${KERBER_SCRATCH:-}" ]; then
    echo "KERBER_SCRATCH is required" >&2
    exit 2
fi
case "$KERBER_SCRATCH" in
    /*) ;;
    *)
        echo "KERBER_SCRATCH must be an absolute path" >&2
        exit 2
        ;;
esac

BASE="$(git rev-parse --verify "$1^{commit}")"
shift
CMD=("$@")
WT="$KERBER_SCRATCH/red-at-${BASE:0:12}"
TARGET="$KERBER_SCRATCH/red-target-${BASE:0:12}"
mkdir -p "$KERBER_SCRATCH"
git worktree remove --force "$WT" 2>/dev/null || true
rm -rf "$WT"
git worktree add --detach "$WT" "$BASE"
cleanup() {
    cd "$ROOT" || true
    git worktree remove --force "$WT" 2>/dev/null || true
    git worktree prune || true
}
trap cleanup EXIT

# HEAD probes/helpers overlay the base-SHA tree so docker cp from $ROOT
# inside the gate (resolved from $0 in the worktree) is current. Gate
# scripts must land before write-tree so tree_sha describes what ran.
mkdir -p "$WT/scripts/lib"
if compgen -G "$ROOT/scripts/lib/*.sh" >/dev/null; then
    cp "$ROOT/scripts/lib/"*.sh "$WT/scripts/lib/"
fi
if compgen -G "$ROOT/scripts/lib/*.py" >/dev/null; then
    cp "$ROOT/scripts/lib/"*.py "$WT/scripts/lib/"
fi
if compgen -G "$ROOT/scripts/"*.sh >/dev/null; then
    cp "$ROOT/scripts/"*.sh "$WT/scripts/"
fi
if compgen -G "$ROOT/scripts/*.c" >/dev/null; then
    cp "$ROOT/scripts/"*.c "$WT/scripts/"
fi
if compgen -G "$ROOT/scripts/*.py" >/dev/null; then
    cp "$ROOT/scripts/"*.py "$WT/scripts/"
fi
if [ -d "$ROOT/harness" ]; then
    rm -rf "$WT/harness"
    cp -a "$ROOT/harness" "$WT/harness"
fi
git -C "$WT" add -A >/dev/null
TREE="$(git -C "$WT" write-tree)"

if [ "$PROBE" = 1 ]; then
    rel="${CMD[0]}"
    src_blob="$(git -C "$ROOT" hash-object "$ROOT/$rel")"
    tree_blob="$(git -C "$WT" rev-parse "$TREE:$rel")"
    echo "==== red-at-sha provenance ===="
    echo "base_sha=$BASE"
    echo "tree_sha=$TREE"
    echo "command=--overlay-probe $rel"
    echo "src_blob=$src_blob"
    echo "tree_blob=$tree_blob"
    if [ "$src_blob" = "$tree_blob" ]; then
        echo "overlay_match=yes"
    else
        echo "overlay_match=no"
    fi
    exit 0
fi

echo "==== red-at-sha provenance ===="
echo "base_sha=$BASE"
echo "tree_sha=$TREE"
echo "command=${CMD[*]}"
echo "worktree=$WT"
echo "CARGO_TARGET_DIR=$TARGET"
echo "==== probe sha256 ===="
if [ -f "$WT/scripts/kpasswd-tgs-client.c" ]; then
    sha256sum "$WT/scripts/kpasswd-tgs-client.c"
fi
if [ -f "$WT/scripts/lib/analyze-kdc-slo.py" ]; then
    sha256sum "$WT/scripts/lib/analyze-kdc-slo.py"
fi
if [ -f "$WT/harness/kadm5.acl" ]; then
    sha256sum "$WT/harness/kadm5.acl"
fi
if [ -f "$ROOT/${CMD[0]}" ]; then
    sha256sum "$ROOT/${CMD[0]}"
fi

export CARGO_TARGET_DIR="$TARGET"
BUILD_LOG="$KERBER_SCRATCH/red-at-${BASE:0:12}-build.log"
(
    cd "$WT"
    cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-forge-tgt \
        -p krb5-admin --bin krb5-kadmind --bin krb5-kpasswd \
        -p krb5-client --bin krb5-kinit 2>&1 | tee "$BUILD_LOG"
) || {
    echo "red-at-sha: cargo build failed at $BASE" >&2
    echo "gate_rc=1"
    exit 1
}
grep -E 'Compiling|Finished' "$BUILD_LOG" || true
echo "==== binary sha256 ===="
for b in krb5-kdc krb5-kadmind krb5-kpasswd krb5-kinit krb5-forge-tgt; do
    f="$TARGET/debug/$b"
    if [ -f "$f" ]; then
        sha256sum "$f"
    fi
done

run_from_wt() {
    local script="$1"
    shift
    if [ -f "$ROOT/$script" ]; then
        mkdir -p "$(dirname "$WT/$script")"
        cp "$ROOT/$script" "$WT/$script"
    fi
    rm -rf "$WT/target"
    ln -sfn "$TARGET" "$WT/target"
    cd "$WT"
    export CARGO_TARGET_DIR="$TARGET"
    bash "$script" "$@"
}

set +e
if [ "${CMD[0]}" = "scripts/kpasswd-gate.sh" ] \
    || [ "${CMD[0]}" = "scripts/kadmin-gate.sh" ] \
    || [[ "${CMD[0]}" == scripts/*-gate.sh ]]; then
    run_from_wt "${CMD[@]}"
    rc=$?
elif [ "${CMD[0]}" = "cargo" ]; then
    cd "$WT"
    export CARGO_TARGET_DIR="$TARGET"
    cargo "${CMD[@]:1}"
    rc=$?
else
    cd "$WT"
    export CARGO_TARGET_DIR="$TARGET"
    "${CMD[@]}"
    rc=$?
fi
set -e
echo "gate_rc=$rc"
exit "$rc"
