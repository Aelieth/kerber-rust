#!/bin/bash
# REP: the rust record is the weekly profile with
# scenarios upgrade then replica. A lone replica has nothing to stream
# (replica.sh: upgrade leaves the build on kdc).
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
FIELD=$WT/harness/field
REC=$HAND_REC/$PHASEC_SHA/rep
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
[ "$got" = "$PHASEC_SHA" ] || { echo "REP_STOP head"; exit 2; }
cd "$FIELD" || exit 2
./run.sh --profile weekly --only upgrade,replica --ref "$PHASEC_SHA" --leg both
echo "REP_RC:$?"
