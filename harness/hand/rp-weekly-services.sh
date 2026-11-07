#!/bin/bash
# Upgrade then services, both legs.
# Same as rp-weekly.sh. The field harness writes its own run directory.
# ONLY=upgrade,services. A leg without upgrade runs against whatever kdc holds.
# This copy does not bring a VM up by itself. make field does the preflight.
# Records: the harness run dir, and this driver's pid under $HAND_REC/<sha>/services.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/services
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
[ "$got" = "$PHASEC_SHA" ] || { echo "WEEKLY_STOP head"; exit 2; }
require_bins "$WT/harness/field/run.sh"
require_files "$WT/Makefile" "$WT/harness/field/lab.sh"
cd "$WT" || exit 2
make field PROFILE=weekly LEG=both REF="$PHASEC_SHA" ONLY=upgrade,services
echo "WEEKLY_RC:$?"
