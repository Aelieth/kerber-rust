#!/usr/bin/env bash
# Rebuild a historical SHA in a KERBER_SCRATCH worktree and run a gate or
# command against those binaries. Provenance header is printed first.
# Usage: scripts/red-at-sha.sh <base-sha> <gate-script-or-command> [args]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <base-sha> <gate-script-or-command> [args]" >&2
    exit 2
fi
if [ -z "${KERBER_SCRATCH:-}" ]; then
    echo "KERBER_SCRATCH is required" >&2
    exit 2
fi

BASE="$(git rev-parse --verify "$1^{commit}")"
shift
CMD=("$1")
shift
WT="$KERBER_SCRATCH/red-at-${BASE:0:12}"
TARGET="$KERBER_SCRATCH/red-target-${BASE:0:12}"
mkdir -p "$KERBER_SCRATCH"
git worktree remove --force "$WT" 2>/dev/null || true
rm -rf "$WT"
git worktree add --detach "$WT" "$BASE"

echo "==== red-at-sha provenance ===="
echo "base_sha=$BASE"
echo "worktree=$WT"
echo "CARGO_TARGET_DIR=$TARGET"

export CARGO_TARGET_DIR="$TARGET"
BUILD_LOG="$KERBER_SCRATCH/red-at-${BASE:0:12}-build.log"
(
    cd "$WT"
    cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-forge-tgt \
        -p krb5-admin --bin krb5-kadmind --bin krb5-kpasswd \
        -p krb5-client --bin krb5-kinit 2>&1 | tee "$BUILD_LOG"
) || {
    echo "red-at-sha: cargo build failed at $BASE" >&2
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

if [ "${CMD[0]}" = "scripts/kpasswd-gate.sh" ] \
    || [ "${CMD[0]}" = "scripts/kadmin-gate.sh" ] \
    || [[ "${CMD[0]}" == scripts/*-gate.sh ]]; then
    run_from_wt "${CMD[0]}" "$@"
elif [ "${CMD[0]}" = "cargo" ]; then
    cd "$WT"
    export CARGO_TARGET_DIR="$TARGET"
    cargo "$@"
else
    cd "$WT"
    export CARGO_TARGET_DIR="$TARGET"
    "${CMD[@]}" "$@"
fi
