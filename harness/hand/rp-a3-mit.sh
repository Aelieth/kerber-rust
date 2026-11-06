#!/bin/bash
# Cell A3, MIT leg. Time systemctl stop kadmin and keep the closing lines.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/al-a3
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
mkdir -p "$REC"
echo "REC:$REC"
lab() { bash "$LAB" "$@"; }
echo "==== reset MIT ===="
lab reset kdc f4-mit-f44
echo "RESET_KDC:$?"
lab ssh kdc -- 'systemctl is-active kadmin; ss -ltn | grep -q ":749 " && echo PORT_749 || echo NO_749'
echo "==== stop ===="
stop_cmd=$(cat << 'EOS'
s=$(date +%s%N); sudo systemctl stop kadmin; rc=$?; e=$(date +%s%N); echo "STOP_RC:$rc"; echo "STOP_MS:$(( (e-s)/1000000 ))"
EOS
)
lab ssh kdc -- "$stop_cmd"
echo "==== journal ===="
lab ssh kdc -- "sudo journalctl -u kadmin --no-pager -n 30 | grep -E 'signal to request exit|shutting down|finished|exiting|Got signal' || true"
echo "==== kadmind.log ===="
lab ssh kdc -- "sudo tail -n 40 /var/log/kadmind.log | grep -E 'signal to request exit|shutting down|finished|exiting|Got signal' || true"
echo "A3_MIT_END"
exit 0
