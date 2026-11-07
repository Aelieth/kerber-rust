#!/bin/bash
# Power-loss cell, MIT leg only.
# 1 kill control, then 20 virsh-destroy cycles. Does not reset kdc at the end.
# Does not reset klldap. Named snapshot f4-mit-f44 only.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/plw-mit
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
exec 9>&-
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
lab() { bash "$LAB" "$@"; }
# ssh reads the caller's stdin. The cycle loop's stdin is the delay list.
labn() { bash "$LAB" "$@" </dev/null; }
require_files "$LAB"
if command -v virsh >/dev/null 2>&1; then
    vsh() { virsh -q -c qemu:///system "$@"; }
elif command -v distrobox-host-exec >/dev/null 2>&1; then
    vsh() { (cd "$HERE" && distrobox-host-exec virsh -q -c qemu:///system "$@"); }
else
    echo "NO_VIRSH"
    exit 1
fi
mkdir -p "$REC/cycles"
echo $$ > "$REC/driver.pid"
echo "PLW_START $(TZ=America/Chicago date '+%H:%M:%S')"
echo "COMMIT:$PHASEC_SHA"
echo "SEED:20261031"

cache_of() {
    local dom="$1"
    vsh dumpxml "$dom" | awk '
        /<driver / && /cache=/ {
            if (match($0, /cache='"'"'[^'"'"']+'"'"'/)) {
                s = substr($0, RSTART, RLENGTH)
                gsub(/cache='"'"'|'"'"'/, "", s)
                print s
            }
        }'
}
ck=$(cache_of kerber-kdc | sort -u | tr '\n' ',' )
c2=$(cache_of kerber-kdc2 | sort -u | tr '\n' ',' )
echo "CACHE kdc ${ck:-absent}"
echo "CACHE kdc2 ${c2:-absent}"
if printf '%s %s\n' "$ck" "$c2" | grep -q unsafe; then
    echo "CACHE_UNSAFE"
    exit 1
fi

echo "==== reset ===="
lab reset kdc f4-mit-f44
echo "RESET_KDC:$?"
lab reset kdc2 f4-mit-f44
echo "RESET_KDC2:$?"
lab up kdc2
echo "UP_KDC2:$?"

# iprop on, units disabled so the next boot does not open the DB, kpropd up, serials equal.
lab ssh kdc -- 'sudo bash -s' << 'EOS'
set -u
KC=/var/kerberos/krb5kdc/kdc.conf
ACL=/var/kerberos/krb5kdc/kadm5.acl
W=/var/tmp/plw
sudo mkdir -p "$W"
if ! sudo grep -q plw-iprop "$KC"; then
    printf '\n# plw-iprop\n[realms]\n    KERBER.TEST = {\n        iprop_enable = true\n        iprop_port = 754\n    }\n' | sudo tee -a "$KC" >/dev/null
fi
if ! sudo grep -q '^kiprop/kdc2' "$ACL"; then
    echo 'kiprop/kdc2.kerber.test@KERBER.TEST p' | sudo tee -a "$ACL" >/dev/null
fi
sudo kadmin.local -q 'getprinc kiprop/kdc.kerber.test' 2>/dev/null | grep -q '^Principal:' \
    || sudo kadmin.local -q 'addprinc -randkey kiprop/kdc.kerber.test' >/dev/null
sudo kadmin.local -q 'getprinc host/kdc2.kerber.test' 2>/dev/null | grep -q '^Principal:' \
    || sudo kadmin.local -q 'addprinc -randkey host/kdc2.kerber.test' >/dev/null
sudo kadmin.local -q 'getprinc kiprop/kdc2.kerber.test' 2>/dev/null | grep -q '^Principal:' \
    || sudo kadmin.local -q 'addprinc -randkey kiprop/kdc2.kerber.test' >/dev/null
sudo kadmin.local -q 'ktadd -k /var/tmp/plw/kdc2.keytab host/kdc2.kerber.test kiprop/kdc2.kerber.test' >/dev/null
# replica.sh: MIT kadmind's full-resync kprop reads host/kdc from /etc/krb5.keytab.
# f4-mit-f44 has neither that principal nor that keytab. Without them kpropd
# stays on "Still waiting for full resync" and the serials never meet.
sudo kadmin.local -q 'getprinc host/kdc.kerber.test' 2>/dev/null | grep -q '^Principal:' \
    || sudo kadmin.local -q 'addprinc -randkey host/kdc.kerber.test' >/dev/null
sudo kadmin.local -q 'ktadd -k /etc/krb5.keytab -norandkey host/kdc.kerber.test' >/dev/null
sudo restorecon /etc/krb5.keytab
if sudo klist -k /etc/krb5.keytab | grep -q 'host/kdc.kerber.test@'; then
    echo HOST_KEYTAB
else
    echo HOST_KEYTAB_MISSING
    exit 1
fi
sudo systemctl disable krb5kdc kadmin
sudo systemctl restart krb5kdc kadmin
echo "UNITS $(systemctl is-enabled krb5kdc) $(systemctl is-active krb5kdc) $(systemctl is-enabled kadmin) $(systemctl is-active kadmin)"
EOS
primary_rc=$?
echo "PRIMARY_RC:$primary_rc"
if [ "$primary_rc" != 0 ]; then
    echo PRIMARY_FAIL
    exit 1
fi

lab ssh kdc -- 'sudo cat /var/kerberos/krb5kdc/.k5.KERBER.TEST' | lab ssh kdc2 -- 'sudo install -m 0600 /dev/stdin /var/kerberos/krb5kdc/.k5.KERBER.TEST && sudo restorecon /var/kerberos/krb5kdc/.k5.KERBER.TEST && echo STASH_COPIED'
lab ssh kdc -- 'sudo cat /var/tmp/plw/kdc2.keytab' | lab ssh kdc2 -- 'sudo install -m 0600 /dev/stdin /etc/krb5.keytab && sudo restorecon /etc/krb5.keytab && echo KEYTAB_COPIED'

lab ssh kdc2 -- 'sudo bash -s' << 'EOS'
set -u
W=/var/tmp/plw
sudo mkdir -p "$W"
sudo tee /var/kerberos/krb5kdc/kdc.conf >/dev/null << 'EOF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    KERBER.TEST = {
        iprop_enable = true
        iprop_port = 754
        iprop_replica_poll = 10s
    }
EOF
sudo tee /etc/krb5.conf >/dev/null << 'EOF'
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false

[realms]
    KERBER.TEST = {
        kdc = kdc.kerber.test
        admin_server = kdc.kerber.test
    }
EOF
echo 'host/kdc.kerber.test@KERBER.TEST' | sudo tee /var/kerberos/krb5kdc/kpropd.acl >/dev/null
sudo install -m 0644 -o "$(id -un)" /dev/null "$W/kpropd.log"
sudo pkill -x kpropd || true
cd / && sudo setsid -f /usr/sbin/kpropd -d -D -A kdc.kerber.test -s /etc/krb5.keytab >> "$W/kpropd.log" 2>&1 < /dev/null
for i in $(seq 1 40); do
    ss -Hltn 'sport = :754' | grep -q . && break
    sleep 0.25
done
ss -Hltn 'sport = :754' | grep -q . && echo KPROPD_LISTEN
EOS
echo "REPLICA_RC:$?"

# Wait until both logs share a last serial, or 60 s.
matched=0
for _ in $(seq 1 60); do
    a=$(labn ssh kdc -- 'sudo kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
    b=$(labn ssh kdc2 -- 'sudo kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
    echo "SERIAL kdc=$a kdc2=$b"
    if [ -n "${a:-}" ] && [ "$a" = "$b" ] && [ "$a" != "None" ]; then
        echo SERIAL_MATCH
        matched=1
        break
    fi
    sleep 2
done
if [ "$matched" != 1 ]; then
    echo "SERIAL_FAIL"
    labn ssh kdc2 -- 'sudo tail -n 60 /var/tmp/plw/kpropd.log' || true
    exit 1
fi

wait_ssh() {
    for _ in $(seq 1 60); do
        if labn ssh kdc -- 'echo SSH_UP' 2>/dev/null | grep -q SSH_UP; then
            return 0
        fi
        sleep 2
    done
    echo "SSH_FAIL"
    return 1
}

dump_state() {
    local cyc="$1"
    local dir="$REC/cycles/$cyc"
    mkdir -p "$dir"
    labn ssh kdc -- 'systemctl is-active krb5kdc; systemctl is-active kadmin; echo ----; sudo kproplog -h; echo ----; sudo kproplog | grep -E "principal|Update serial|Update operation|Update principal"' > "$dir/kdc-kprop.txt" || true
    labn ssh kdc -- 'sudo kadmin.local -q listprincs' > "$dir/kdc-princs.txt" || echo LIST_FAIL > "$dir/kdc-princs.txt"
    labn ssh kdc2 -- 'sudo kproplog -h; echo ----; sudo kadmin.local -q listprincs' > "$dir/kdc2.txt" || true
    if [ -f /var/tmp/plw/kpropd.log ]; then
        :
    fi
    labn ssh kdc2 -- 'sudo tail -n 40 /var/tmp/plw/kpropd.log' > "$dir/kpropd.txt" || true
}

start_daemons() {
    start_cmd=$(cat << 'EOS'
sudo systemctl start krb5kdc kadmin; echo STARTED $(systemctl is-active krb5kdc) $(systemctl is-active kadmin)
EOS
)
    labn ssh kdc -- "$start_cmd"
}

# Kill control. SIGKILL of kadmin.local. No virsh.
echo "==== kill control ===="
lab ssh kdc -- 'sudo bash -c "stdbuf -oL kadmin.local -q \"addprinc -randkey plwK-1\" | tee /var/tmp/plw/kill-ack"' > "$REC/cycles/kill.ack" || true
# The one-shot above finishes the op. Drive a loop and kill it.
kill_loop_cmd=$(cat << 'EOS'
sudo bash -c "i=2; while true; do i=\$((i+1)); kadmin.local -q \"addprinc -randkey plwK-\$i\" && echo ACK \$i; done"
EOS
)
lab ssh kdc -- "$kill_loop_cmd" > "$REC/kill.ack" 2>"$REC/kill.err" &
wpid=$!
ok=0
for _ in $(seq 1 50); do
    if grep -q '^ACK ' "$REC/kill.ack"; then ok=1; break; fi
    sleep 0.2
done
echo "KILL_ACK:$ok"
# pkill -x kadmin.local leaves the guest loop running, so the dump
# races the next op. One signal stops the loop and the op in flight.
# The [K] keeps this command from matching itself.
gone=$(lab ssh kdc -- 'sudo pkill -KILL -f "plw[K]-"; sleep 0.2; pgrep -f "plw[K]-" || echo WRITER_GONE')
printf '%s\n' "$gone"
if ! printf '%s\n' "$gone" | grep -q '^WRITER_GONE$'; then
    echo "WRITER_STILL"
    kill "$wpid" 2>/dev/null || true
    exit 1
fi
kill "$wpid" 2>/dev/null || true
wait "$wpid" 2>/dev/null || true
dump_state kill
echo "KILL_DUMPED"

# Power cycles.
python3 - << 'PY' > "$REC/delays.txt"
import random
r = random.Random(20261031)
for i in range(1, 21):
    print(r.randint(50, 400))
PY
cyc=0
while read -r delay; do
    # ssh and lab.sh's own wait_ssh read stdin. The delay file stays on this
    # loop; everything inside the cut runs with stdin closed.
    {
    cyc=$((cyc + 1))
    echo "==== cycle $cyc delay ${delay}ms ===="
    mkdir -p "$REC/cycles/$cyc"
    : > "$REC/cycles/$cyc/ack"
    labn ssh kdc -- "sudo bash -c 'i=0; while true; do i=\$((i+1)); if kadmin.local -q \"addprinc -randkey plw${cyc}-\$i\" | grep -q created; then echo ACK \$i plw${cyc}-\$i; else echo NAK \$i; fi; done'" > "$REC/cycles/$cyc/ack" 2>"$REC/cycles/$cyc/ack.err" &
    wpid=$!
    got=0
    for _ in $(seq 1 80); do
        if grep -q '^ACK ' "$REC/cycles/$cyc/ack"; then got=1; break; fi
        sleep 0.1
    done
    echo "ACK:$got"
    if [ "$got" != 1 ]; then
        echo "NO_ACK $cyc"
        kill "$wpid" 2>/dev/null || true
        exit 1
    fi
    python3 -c "import time; time.sleep(${delay}/1000.0)"
    vsh destroy kerber-kdc || true
    wait "$wpid" 2>/dev/null || true
    echo "DESTROYED $cyc"
    lab up kdc
    echo "UP:$?"
    if ! wait_ssh; then
        echo "BOOT_FAIL $cyc"
        exit 1
    fi
    dump_state "$cyc"
    # The next open is what resets an Unstable log. Record that header.
    start_daemons
    # kpropd's kadm5 client backs off 4s, 8s, 16s, 32s if it tries before
    # krb5kdc and kadmind are listening. Wait for both ports first.
    wait_cmd=$(cat << 'EOS'
for i in $(seq 1 40); do ss -Hltn "sport = :88" | grep -q . && ss -Hltn "sport = :754" | grep -q . && break; sleep 0.25; done; if ss -Hltn "sport = :754" | grep -q .; then echo KADMIND_UP; else echo KADMIND_DOWN; fi
EOS
)
    kad=$(labn ssh kdc -- "$wait_cmd")
    echo "$kad $cyc"
    if ! printf '%s\n' "$kad" | grep -q KADMIND_UP; then
        echo "KADMIND_DOWN $cyc"
        exit 1
    fi
    labn ssh kdc -- 'sudo kproplog -h' > "$REC/cycles/$cyc/post-open.txt" || true
    # A kpropd blocked in iprop_get_updates across the cut waits up to
    # an hour. That is MIT's kadm5 timeout, not a finding. Restart it every
    # cycle so a stuck poll does not become replica-miss. Record the tail first.
    labn ssh kdc2 -- 'sudo tail -n 20 /var/tmp/plw/kpropd.log' > "$REC/cycles/$cyc/kpropd-before.txt" || true
    # An in-flight poll (Send-Q > 0, or no socket) retransmits and
    # recovers on RST. Stuck is an acked call: Send-Q 0 on an ESTAB to :754.
    labn ssh kdc2 -- 'ss -Htn state established "( dport = :754 )"' > "$REC/cycles/$cyc/kpropd-ss.txt" || true
    poll=$(python3 - "$REC/cycles/$cyc" << 'PY'
import sys
from pathlib import Path
d = Path(sys.argv[1])
last = ""
for line in (d / "kpropd-before.txt").read_text(errors="replace").splitlines():
    if line.strip():
        last = line.strip()
calling = last.startswith("Calling iprop_get_updates_1")
sendq = []
for line in (d / "kpropd-ss.txt").read_text(errors="replace").splitlines():
    nums = [int(p) for p in line.split() if p.isdigit()]
    if len(nums) >= 2:
        sendq.append(nums[1])
if not calling:
    print("NOT_STUCK")
elif not sendq or any(q > 0 for q in sendq):
    print("IN_FLIGHT")
else:
    print("STUCK")
PY
)
    echo "$poll $cyc"
    # Stable-behind heal, scoped to this cycle's writes.
    # Cycle 1 is plw1-* only. Later cycles are plw<c>-* plus plw<c-1>-z.
    # A plain restart resumes from kdc2's serial. kproplog -R asks for a full resync.
    if miss=$(python3 - "$REC/cycles/$cyc" << 'PY'
import sys
from pathlib import Path
d = Path(sys.argv[1])
cyc = int(d.name)
text = (d / "kdc-kprop.txt").read_text(errors="replace")
princs = (d / "kdc-princs.txt").read_text(errors="replace")
state = None
names = set()
for line in text.splitlines():
    s = line.strip()
    if s.startswith("Log state") and state is None:
        state = s.split(":", 1)[1].strip()
    if s.startswith("Update principal"):
        names.add(s.split(":", 1)[1].strip().split("@", 1)[0])
db = set()
for line in princs.splitlines():
    line = line.strip()
    if line.startswith("plw") and "@" in line and " " not in line:
        db.add(line.split("@", 1)[0])

def in_scope(name):
    if name.startswith("plw%d-" % cyc):
        return True
    if cyc >= 2 and name == "plw%d-z" % (cyc - 1):
        return True
    return False

missing = sorted(p for p in db if in_scope(p) and p not in names)
if state == "Stable" and missing:
    print(" ".join(missing))
    sys.exit(0)
sys.exit(1)
PY
    ); then
        echo "HEAL $cyc $miss"
        labn ssh kdc2 -- 'sudo kproplog -R' > "$REC/cycles/$cyc/kproplog-R.txt" || true
    else
        echo "NO_HEAL $cyc"
    fi
    mark=$(labn ssh kdc2 -- 'sudo wc -c < /var/tmp/plw/kpropd.log' | tr -d '[:space:]')
    # setsid has to run in an already-root shell. `sudo setsid -f` dies with the ssh session.
    labn ssh kdc2 -- 'sudo bash -c "pkill -x kpropd || true; sleep 0.3; cd / && setsid -f /usr/sbin/kpropd -d -D -A kdc.kerber.test -s /etc/krb5.keytab >> /var/tmp/plw/kpropd.log 2>&1 < /dev/null; echo RESTARTED"'
    init_ok=0
    for _ in $(seq 1 30); do
        if labn ssh kdc2 -- "sudo tail -c +$((mark + 1)) /var/tmp/plw/kpropd.log" | grep -q 'kadm5 initialization succeeded'; then
            init_ok=1
            break
        fi
        sleep 1
    done
    echo "KPROP_INIT $cyc $init_ok"
    if [ "$init_ok" != 1 ]; then
        echo "KPROP_INIT_FAIL $cyc"
        exit 1
    fi
    labn ssh kdc -- "sudo kadmin.local -q 'addprinc -randkey plw${cyc}-z'" > "$REC/cycles/$cyc/extra" || true
    # iprop_replica_poll is 10s. The paper allows 30s for the sets to meet.
    matched_s=0
    for _ in $(seq 1 15); do
        sa=$(labn ssh kdc -- 'sudo kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
        sb=$(labn ssh kdc2 -- 'sudo kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
        echo "POSTSERIAL $cyc kdc=$sa kdc2=$sb"
        if [ -n "${sa:-}" ] && [ "$sa" = "$sb" ] && [ "$sa" != "None" ]; then
            matched_s=1
            break
        fi
        sleep 2
    done
    echo "POSTSERIAL_MATCH $cyc $matched_s"
    labn ssh kdc -- 'sudo kadmin.local -q listprincs' > "$REC/cycles/$cyc/kdc-after-princs.txt" || true
    labn ssh kdc2 -- 'sudo tail -n 40 /var/tmp/plw/kpropd.log; echo ----; sudo kadmin.local -q listprincs' > "$REC/cycles/$cyc/after.txt" || true
    echo "CYCLE_DONE $cyc"
    } < /dev/null
done < "$REC/delays.txt"
if [ "$cyc" != 20 ]; then
    echo "CYCLE_SHORT $cyc"
    exit 1
fi

echo "==== cleanup ===="
lab ssh kdc -- 'sudo bash -s' << 'EOS'
set -u
sudo kadmin.local -q listprincs | awk '/^plw/{print}' | while read -r p; do
    sudo kadmin.local -q "delprinc -force $p" >/dev/null || true
done
sudo sed -i '/^# plw-iprop$/,$d' /var/kerberos/krb5kdc/kdc.conf
sudo sed -i '/^kiprop\/kdc2/d' /var/kerberos/krb5kdc/kadm5.acl
sudo systemctl enable krb5kdc kadmin
echo "ENABLED $(systemctl is-enabled krb5kdc) $(systemctl is-enabled kadmin)"
if sudo grep -q plw-iprop /var/kerberos/krb5kdc/kdc.conf; then echo STANZA_LEFT; else echo STANZA_GONE; fi
left=$(sudo kadmin.local -q listprincs | grep -c '^plw' || true)
echo "PLW_LEFT $left"
EOS
lab ssh kdc2 -- 'sudo pkill -x kpropd || true; echo KPROPD_STOPPED'
lab reset kdc2 f4-mit-f44
echo "RESET_KDC2_END:$?"
lab down kdc2
echo "DOWN_KDC2:$?"
echo "PLW_END $(TZ=America/Chicago date '+%H:%M:%S')"
