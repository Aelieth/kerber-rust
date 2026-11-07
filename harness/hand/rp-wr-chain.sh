#!/bin/bash
# WR on the build under test. MIT first. Ours runs only after a clean MIT end.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
REC=$HAND_REC/$PHASEC_SHA/wr
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
require_files "$HDIR/rp-wr-mit.sh" "$HDIR/rp-wr-ours.sh"
exec 9>&-
DIR=$REC
mkdir -p "$DIR"
echo "==== $(date -u +%Y-%m-%dT%H:%M:%SZ) WR MIT ===="
stdbuf -oL bash "$HDIR/rp-wr-mit.sh" "$PHASEC_SHA" > "$DIR/mit.log" 2>&1
mrc=$?
echo "MIT_RC:$mrc"
if [ "$mrc" -ne 0 ] || grep -q '^FAIL ' "$DIR/mit.log"; then
    echo "CHAIN_FAIL mit"
    echo "WR_CHAIN_END"
    exit 2
fi
grep -q 'WR_MIT_END' "$DIR/mit.log" || { echo "CHAIN_FAIL mit-no-end"; echo "WR_CHAIN_END"; exit 2; }
echo "==== $(date -u +%Y-%m-%dT%H:%M:%SZ) WR ours ===="
stdbuf -oL bash "$HDIR/rp-wr-ours.sh" "$PHASEC_SHA" > "$DIR/ours.log" 2>&1
orc=$?
echo "OURS_RC:$orc"
if [ "$orc" -ne 0 ] || grep -q '^FAIL ' "$DIR/ours.log"; then
    echo "CHAIN_FAIL ours"
    echo "WR_CHAIN_END"
    exit 2
fi
grep -q 'WR_OURS_END' "$DIR/ours.log" || { echo "CHAIN_FAIL ours-no-end"; echo "WR_CHAIN_END"; exit 2; }
echo "WR_CHAIN_END"
exit 0
