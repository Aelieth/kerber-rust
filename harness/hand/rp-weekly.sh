#!/bin/bash
# Weekly, both legs. The field harness writes its own run directory.
# This copy does not bring a VM up by itself. make field does the preflight.
# Records: the harness run dir, and a tee of this driver under $HAND_REC/$SHA/weekly.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/weekly
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
[ "$got" = "$PHASEC_SHA" ] || { echo "WEEKLY_STOP head"; exit 2; }
cd "$WT" || exit 2
make field PROFILE=weekly LEG=both REF="$PHASEC_SHA"
echo "WEEKLY_RC:$?"
