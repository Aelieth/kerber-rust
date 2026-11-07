#!/bin/bash
# Nightly N, both legs. Same as rp-weekly.sh.
# The field harness writes its own run directory.
# This copy does not bring a VM up by itself. make field does the preflight.
# Records: the harness run dir, and this driver's pid under $HAND_REC/<sha>/nightly-$N.
set -u
PHASEC_SHA=${1:?phasec sha}
N=${2:?night 1-7}
case "$N" in
    1|2|3|4|5|6|7) ;;
    *) echo "NIGHTLY_STOP night"; exit 2 ;;
esac
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/nightly-$N
[ -e "$REC" ] && { echo "NIGHTLY_STOP exists $REC"; exit 2; }
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
[ "$got" = "$PHASEC_SHA" ] || { echo "NIGHTLY_STOP head"; exit 2; }
require_bins "$WT/harness/field/run.sh"
require_files "$WT/Makefile" "$WT/harness/field/lab.sh"
cd "$WT" || exit 2
make field PROFILE=nightly LEG=both REF="$PHASEC_SHA"
echo "NIGHTLY_RC:$?"
