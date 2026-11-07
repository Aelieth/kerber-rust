#!/bin/bash
# Ticket-flags, then klldap-swap. Ticket-flags includes upgrade because
# kdcis needs the KDC that leg's upgrade left. klldap resets to f44-docker first.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
FIELD=$WT/harness/field
REC=$HAND_REC/$PHASEC_SHA/tf
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
[ "$got" = "$PHASEC_SHA" ] || { echo "TF_STOP head"; exit 2; }
require_bins "$FIELD/run.sh"
require_files "$FIELD/lab.sh"
cd "$FIELD" || exit 2
stdbuf -oL ./run.sh --profile weekly --only upgrade,ticket-flags --ref "$PHASEC_SHA" --leg both > "$REC/ticket-flags.log" 2>&1
echo "TF_RC:$?" | tee -a "$REC/ticket-flags.log"
bash "$FIELD/lab.sh" reset klldap f44-docker
rc=$?
echo "RESET_RC:$rc"
[ "$rc" = 0 ] || { echo "TF_STOP reset klldap"; exit 2; }
stdbuf -oL ./run.sh --profile weekly --only klldap-swap --ref "$PHASEC_SHA" --leg both > "$REC/klldap-swap.log" 2>&1
echo "KL_RC:$?" | tee -a "$REC/klldap-swap.log"
