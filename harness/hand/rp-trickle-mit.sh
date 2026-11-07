#!/bin/bash
# KDC trickler, MIT leg. Field realm. Prints rc and elapsed only.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/al-trickle
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
mkdir -p "$REC"
echo "REC:$REC"
lab() { bash "$LAB" "$@"; }
HERE=$(dirname "$LAB")
if command -v virsh >/dev/null 2>&1; then
    vsh() { virsh -c qemu:///system "$@"; }
else
    vsh() { (cd "$HERE" && distrobox-host-exec virsh -c qemu:///system "$@"); }
fi
now=$(vsh snapshot-current kerber-kdc --name 2>/dev/null || true)
active=$(lab ssh kdc -- 'systemctl is-active kadmin' 2>/dev/null || true)
if [ "$now" = "f4-mit-f44" ] && [ "$active" = "active" ]; then
    echo "RESET_SKIPPED"
else
    echo "==== reset MIT ===="
    echo "RESET_WHY snapshot=$now kadmin=$active"
    lab reset kdc f4-mit-f44
    echo "RESET_KDC:$?"
fi
lab ssh kdc -- 'systemctl is-active kadmin; ss -ltn | grep -q ":749 " && echo PORT_749 || echo NO_749'
lab ssh kdc -- 'rm -rf /var/tmp/al3 && mkdir -p /var/tmp/al3 && chmod 700 /var/tmp/al3'
lab ssh kdc -- 'cat > /var/tmp/al3/trickle.py && chmod 700 /var/tmp/al3/trickle.py' < "$HDIR/lib/al3-trickle.py"
lab ssh kdc -- 'cat > /var/tmp/al3/guest.py && chmod 700 /var/tmp/al3/guest.py' < "$HDIR/lib/rp-trickle-guest.py"
lab ssh kdc -- 'cat > /var/tmp/al3/admin.pw && chmod 600 /var/tmp/al3/admin.pw' < "$LAB_HOME/secrets/mit-realm.admin-admin.password"
lab ssh kdc -- 'cat > /var/tmp/al3/bob.pw && chmod 600 /var/tmp/al3/bob.pw' < "$LAB_HOME/secrets/mit-realm.bob.password"
echo "==== trickle ===="
start_cmd=$(cat << 'EOS'
nohup python3 /var/tmp/al3/guest.py trickle > /var/tmp/al3/trickle.out 2>&1 & echo $! > /var/tmp/al3/trickle.pid; echo TRICKLE_PID:$(cat /var/tmp/al3/trickle.pid)
EOS
)
lab ssh kdc -- "$start_cmd"
sleep 2
lab ssh kdc -- 'python3 /var/tmp/al3/guest.py getprinc' &
GPID=$!
lab ssh kdc -- 'python3 /var/tmp/al3/guest.py kpasswd' &
KPID=$!
wait "$GPID" || true
wait "$KPID" || true
echo "==== trickle out ===="
wait_cmd=$(cat << 'EOS'
while kill -0 "$(cat /var/tmp/al3/trickle.pid)" 2>/dev/null; do sleep 1; done; cat /var/tmp/al3/trickle.out
EOS
)
lab ssh kdc -- "$wait_cmd"
lab ssh kdc -- 'rm -rf /var/tmp/al3'
echo "TRICKLE_MIT_END"
exit 0
