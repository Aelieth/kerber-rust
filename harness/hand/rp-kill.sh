#!/bin/bash
# Upgrade + kill-loop: profile kill-loop, leg rust
# (upgrade is inside that profile; kdc2 is the replica). Does not start the lab by itself.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/kill-loop
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
[ "$got" = "$PHASEC_SHA" ] || { echo "KILL_STOP head"; exit 2; }
cd "$WT" || exit 2
make field PROFILE=kill-loop LEG=rust REF="$PHASEC_SHA"
echo "KILL_RC:$?"
