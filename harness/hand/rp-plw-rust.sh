#!/bin/bash
# Power-loss cell, ours: kdc keeps the build its upgrade left; kdc2 is rust-replica-f44.
# Kill control: writer stop, then the stable-or-consistent check.
# Does not reset kdc. Does not reset klldap.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/plw-rust
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

echo "==== install ===="
# This leg drives kadmind and kadmin.local as well as krb5kdc.
# Hash all four against the build. Any miss stops before a power cut.
install_ok=1
while read -r bin built; do
    [ -n "${bin:-}" ] || continue
    want=$(labn ssh kdc -- "sha256sum ~/kerber-rust-${PHASEC_SHA:0:12}/target/release/$built" | awk '{print $1}')
    got=$(labn ssh kdc -- "sha256sum /usr/sbin/$bin" | awk '{print $1}')
    echo "KDC_SHA $bin build=$want install=$got"
    if [ -z "${want:-}" ] || [ "$want" != "$got" ]; then
        install_ok=0
    fi
done << 'EOF'
krb5kdc krb5-kdc
kadmind krb5-kadmind
kadmin.local krb5-kadmin-local
kdb5_util krb5-kdb
EOF
if [ "$install_ok" != 1 ]; then
    echo "INSTALL_MISMATCH"
    exit 1
fi
echo "==== reset kdc2 ===="
lab reset kdc2 rust-replica-f44
reset_rc=$?
echo "RESET_KDC2:$reset_rc"
if [ "$reset_rc" != 0 ]; then
    exit 1
fi
# replica.sh's four programs, from the build upgrade left on kdc. MIT kproplog
# reads this port's ulog; the upgraded kdc no longer has /usr/sbin/kproplog.
stream_log=$REC/stream.out
stream_cmd=$(cat << 'EOS'
rm -rf ~/rep-bin && mkdir ~/rep-bin && tar -x -C ~/rep-bin && n=0; for p in krb5-kdc:krb5kdc krb5-kpropd:kpropd krb5-kdb:kdb5_util krb5-kadmin-local:kadmin.local; do sudo install -m 0755 ~/rep-bin/${p%%:*} /usr/sbin/${p#*:} && n=$((n+1)); done; sudo restorecon /usr/sbin/krb5kdc /usr/sbin/kpropd /usr/sbin/kdb5_util /usr/sbin/kadmin.local; echo STREAMED $n
EOS
)
lab ssh kdc -- "tar -C ~/kerber-rust-${PHASEC_SHA:0:12}/target/release -c krb5-kdc krb5-kpropd krb5-kdb krb5-kadmin-local" \
    | lab ssh kdc2 -- "$stream_cmd" \
    > "$stream_log"
stream_rc=("${PIPESTATUS[@]}")
cat "$stream_log"
echo "STREAM_RC:${stream_rc[0]:-}:${stream_rc[1]:-}"
if [ "${stream_rc[0]:-1}" != 0 ] || [ "${stream_rc[1]:-1}" != 0 ] || ! grep -qx 'STREAMED 4' "$stream_log"; then
    echo "STREAM_FAIL"
    exit 1
fi
# MIT's kproplog, unpacked on kdc2 from Fedora's krb5-server rpm and never installed (as replica.sh does).
lab ssh kdc2 -- 'mkdir -p ~/plw-bin && cd ~/plw-bin && { rpm -q cpio > /dev/null || sudo dnf -y -q install cpio > /dev/null 2>&1; } && rm -rf krb5-server-*.rpm usr && dnf download -q krb5-server > /dev/null 2>&1 && rpm2cpio krb5-server-*.rpm | cpio -id --quiet "*/kproplog" && install -m 0755 usr/*/kproplog kproplog'
lab ssh kdc2 -- 'cat ~/plw-bin/kproplog' | lab ssh kdc -- 'mkdir -p ~/plw-bin && cat > ~/plw-bin/kproplog && chmod 755 ~/plw-bin/kproplog'
for vm in kdc kdc2; do
    if ! labn ssh "$vm" -- 'test -x /home/lab/plw-bin/kproplog && ! ldd /home/lab/plw-bin/kproplog | grep -q "not found"'; then
        echo "KPROPLOG_BAD $vm"
        exit 1
    fi
    echo "KPROPLOG_OK $vm"
done
# Hash kdc2's four before its daemons start.
kdc2_ok=1
while read -r bin built; do
    [ -n "${bin:-}" ] || continue
    want=$(labn ssh kdc -- "sha256sum ~/kerber-rust-${PHASEC_SHA:0:12}/target/release/$built" | awk '{print $1}')
    got=$(labn ssh kdc2 -- "sha256sum /usr/sbin/$bin" | awk '{print $1}')
    echo "KDC2_SHA $bin build=$want install=$got"
    if [ -z "${want:-}" ] || [ "$want" != "$got" ]; then
        kdc2_ok=0
    fi
done << 'EOF'
krb5kdc krb5-kdc
kpropd krb5-kpropd
kdb5_util krb5-kdb
kadmin.local krb5-kadmin-local
EOF
if [ "$kdc2_ok" != 1 ]; then
    echo "INSTALL_MISMATCH"
    exit 1
fi
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
sync
EOS
primary_rc=$?
echo "PRIMARY_RC:$primary_rc"
if [ "$primary_rc" != 0 ]; then
    echo PRIMARY_FAIL
    exit 1
fi
# The running krb5kdc and kadmind, after the unit restart.
proc_out=$(lab ssh kdc -- "sudo B=/home/lab/kerber-rust-${PHASEC_SHA:0:12}/target/release bash -s" << 'EOS'
set -u
B=${B:?}
for spec in krb5kdc:krb5-kdc kadmin:krb5-kadmind; do
    unit=${spec%%:*}
    built=${spec#*:}
    pid=$(systemctl show -p MainPID --value "$unit")
    if [ -z "${pid:-}" ] || [ "$pid" = 0 ] || [ ! -e "/proc/$pid/exe" ]; then
        echo "PROC_FAIL $unit"
        continue
    fi
    sha=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
    want=$(sha256sum "$B/$built" | awk '{print $1}')
    exe=$(readlink -f "/proc/$pid/exe" || true)
    echo "PROC $unit pid=$pid exe=$exe sha=$sha build=$want"
    if [ -z "$sha" ] || [ "$sha" != "$want" ]; then
        echo "PROC_MISMATCH $unit"
    fi
done
EOS
)
printf '%s\n' "$proc_out"
if ! printf '%s\n' "$proc_out" | grep -q '^PROC krb5kdc ' \
    || ! printf '%s\n' "$proc_out" | grep -q '^PROC kadmin ' \
    || printf '%s\n' "$proc_out" | grep -q -E 'PROC_FAIL|PROC_MISMATCH'; then
    echo "INSTALL_MISMATCH"
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
sync
EOS
echo "REPLICA_RC:$?"

# Wait until both logs share a last serial, or 60 s.
matched=0
for _ in $(seq 1 60); do
    a=$(labn ssh kdc -- 'sudo /home/lab/plw-bin/kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
    b=$(labn ssh kdc2 -- 'sudo /home/lab/plw-bin/kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
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
    labn ssh kdc -- 'systemctl is-active krb5kdc; systemctl is-active kadmin; echo ----; sudo /home/lab/plw-bin/kproplog -h; echo ----; sudo /home/lab/plw-bin/kproplog | grep -E "principal|Update serial|Update operation|Update principal"' > "$dir/kdc-kprop.txt" || true
    labn ssh kdc -- 'sudo kadmin.local -q listprincs' > "$dir/kdc-princs.txt" || echo LIST_FAIL > "$dir/kdc-princs.txt"
    labn ssh kdc2 -- 'sudo /home/lab/plw-bin/kproplog -h; echo ----; sudo kadmin.local -q listprincs' > "$dir/kdc2.txt" || true
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
# Unstable, or Stable and consistent over plwK-*. Behind or ahead stops.
python3 - "$REC/cycles/kill" << 'PY'
import sys
from pathlib import Path
d = Path(sys.argv[1])
text = (d / "kdc-kprop.txt").read_text(errors="replace")
princs = (d / "kdc-princs.txt").read_text(errors="replace")
state = None
names = set()
ops = []
cur = None
for line in text.splitlines():
    s = line.strip()
    if s.startswith("Log state") and state is None:
        state = s.split(":", 1)[1].strip()
    elif s.startswith("Update operation"):
        cur = s.split(":", 1)[1].strip()
    elif s.startswith("Update principal"):
        name = s.split(":", 1)[1].strip().split("@", 1)[0]
        names.add(name)
        ops.append((cur, name))
db = set()
bad = "LIST_FAIL" in princs or "Cannot open" in princs
for line in princs.splitlines():
    line = line.strip()
    if line.startswith("plwK-") and "@" in line and " " not in line:
        db.add(line.split("@", 1)[0])
plw_names = {n for n in names if n.startswith("plwK-")}
behind = sorted(p for p in db if p not in names)
ahead = sorted(n for op, n in ops if op == "Add" and n.startswith("plwK-") and n not in db)
if bad or state is None:
    print("KILL_MISS db")
    sys.exit(1)
if state == "Unstable":
    print("KILL_PASS unstable")
    sys.exit(0)
if state == "Stable" and not behind and not ahead:
    print("KILL_PASS stable-consistent")
    sys.exit(0)
print("KILL_MISS state=%s behind=%s ahead=%s" % (state, ",".join(behind), ",".join(ahead)))
sys.exit(1)
PY
kill_rc=$?
if [ "$kill_rc" != 0 ]; then
    exit 1
fi
# An Unstable kill must reset on the next open.
if python3 - "$REC/cycles/kill/kdc-kprop.txt" << 'PY'
import sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
state = None
for line in text.splitlines():
    s = line.strip()
    if s.startswith("Log state"):
        state = s.split(":", 1)[1].strip()
        break
sys.exit(0 if state == "Unstable" else 1)
PY
then
    labn ssh kdc -- 'sudo kadmin.local -q listprincs >/dev/null; sudo /home/lab/plw-bin/kproplog -h' > "$REC/cycles/kill/post-open.txt" || true
    if ! python3 - "$REC/cycles/kill" << 'PY'
import sys
from pathlib import Path
d = Path(sys.argv[1])
def hdr(text):
    out = {}
    for line in text.splitlines():
        s = line.strip()
        for key in ("Log state", "Last serial #"):
            if s.startswith(key) and key not in out:
                out[key] = s.split(":", 1)[1].strip()
    return out
before = hdr((d / "kdc-kprop.txt").read_text(errors="replace"))
after = hdr((d / "post-open.txt").read_text(errors="replace"))
print("KILL_RESET before=%s/%s after=%s/%s" % (before.get("Log state"), before.get("Last serial #"), after.get("Log state"), after.get("Last serial #")))
same = after.get("Log state") == "Unstable" and after.get("Last serial #") == before.get("Last serial #")
sys.exit(1 if same or after.get("Log state") is None else 0)
PY
    then
        echo "KILL_RESET_FAIL"
        exit 1
    fi
fi

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
    labn ssh kdc -- 'sudo /home/lab/plw-bin/kproplog -h' > "$REC/cycles/$cyc/post-open.txt" || true
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
    heal=0
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
        heal=1
        echo "HEAL $cyc $miss"
        echo "DUMP_BEFORE $cyc"
        labn ssh kdc -- 'stat -c "%y %s %n" /var/kerberos/krb5kdc/replica_datatrans /var/kerberos/krb5kdc/replica_datatrans.dump_ok 2>&1 || true; echo ----; sudo head -n 1 /var/kerberos/krb5kdc/replica_datatrans 2>/dev/null || echo DUMP_ABSENT'
        labn ssh kdc2 -- 'sudo /home/lab/plw-bin/kproplog -R' > "$REC/cycles/$cyc/kproplog-R.txt" || true
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
        sa=$(labn ssh kdc -- 'sudo /home/lab/plw-bin/kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
        sb=$(labn ssh kdc2 -- 'sudo /home/lab/plw-bin/kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
        echo "POSTSERIAL $cyc kdc=$sa kdc2=$sb"
        if [ -n "${sa:-}" ] && [ "$sa" = "$sb" ] && [ "$sa" != "None" ]; then
            matched_s=1
            break
        fi
        sleep 2
    done
    echo "POSTSERIAL_MATCH $cyc $matched_s"
    if [ "$heal" = 1 ]; then
        echo "DUMP_AFTER $cyc"
        labn ssh kdc -- 'stat -c "%y %s %n" /var/kerberos/krb5kdc/replica_datatrans /var/kerberos/krb5kdc/replica_datatrans.dump_ok 2>&1 || true; echo ----; sudo head -n 1 /var/kerberos/krb5kdc/replica_datatrans 2>/dev/null || echo DUMP_ABSENT'
    fi
    refuse=$(labn ssh kdc -- 'if sudo sh -c "cat /var/log/kadmind.log-* /var/log/kadmind.log.* /var/log/kadmind.log 2>/dev/null" | grep -F -q "more recent than"; then echo REFUSED; else echo NONE; fi')
    echo "DUMP_REFUSE $cyc $refuse"
    if [ "$refuse" != NONE ]; then
        echo "CYCLE_STOP dump-ok $cyc"
        exit 1
    fi
    if [ "$heal" = 1 ] && [ "$matched_s" != 1 ]; then
        echo "CYCLE_STOP step-A-serial $cyc"
        exit 1
    fi
    labn ssh kdc -- 'sudo kadmin.local -q listprincs' > "$REC/cycles/$cyc/kdc-after-princs.txt" || true
    labn ssh kdc2 -- 'sudo tail -n 40 /var/tmp/plw/kpropd.log; echo ----; sudo kadmin.local -q listprincs' > "$REC/cycles/$cyc/after.txt" || true
    # step B. Step A may share a still-current dump, which cannot carry
    # a principal that never reached the log. If one of those is still missing
    # on kdc2, delete the pair so the next full resync dumps the DB fresh.
    if [ "$heal" = 1 ] && [ -n "${miss:-}" ]; then
        k2body=$(awk 'f{print} /^----$/{f=1}' "$REC/cycles/$cyc/after.txt")
        still=""
        for name in $miss; do
            if ! printf '%s\n' "$k2body" | grep -qx "${name}@KERBER.TEST"; then
                still="$still $name"
            fi
        done
        still=${still# }
        if [ -n "$still" ]; then
            echo "HEAL_B $cyc $still"
            gone=$(labn ssh kdc -- 'sudo rm -f /var/kerberos/krb5kdc/replica_datatrans /var/kerberos/krb5kdc/replica_datatrans.dump_ok; if [ -e /var/kerberos/krb5kdc/replica_datatrans ] || [ -e /var/kerberos/krb5kdc/replica_datatrans.dump_ok ]; then echo DUMP_LEFT; else echo DUMP_GONE; fi')
            echo "DUMP_B_REMOVE $cyc $gone"
            if ! printf '%s\n' "$gone" | grep -qx DUMP_GONE; then
                echo "CYCLE_STOP step-B-remove $cyc"
                exit 1
            fi
            labn ssh kdc2 -- 'sudo /home/lab/plw-bin/kproplog -R' > "$REC/cycles/$cyc/kproplog-R-b.txt" || true
            mark=$(labn ssh kdc2 -- 'sudo wc -c < /var/tmp/plw/kpropd.log' | tr -d '[:space:]')
            labn ssh kdc2 -- 'sudo bash -c "pkill -x kpropd || true; sleep 0.3; cd / && setsid -f /usr/sbin/kpropd -d -D -A kdc.kerber.test -s /etc/krb5.keytab >> /var/tmp/plw/kpropd.log 2>&1 < /dev/null; echo RESTARTED"'
            init_ok=0
            for _ in $(seq 1 30); do
                if labn ssh kdc2 -- "sudo tail -c +$((mark + 1)) /var/tmp/plw/kpropd.log" | grep -q 'kadm5 initialization succeeded'; then
                    init_ok=1
                    break
                fi
                sleep 1
            done
            echo "KPROP_INIT_B $cyc $init_ok"
            if [ "$init_ok" != 1 ]; then
                echo "KPROP_INIT_FAIL $cyc"
                exit 1
            fi
            matched_b=0
            for _ in $(seq 1 15); do
                sa=$(labn ssh kdc -- 'sudo /home/lab/plw-bin/kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
                sb=$(labn ssh kdc2 -- 'sudo /home/lab/plw-bin/kproplog -h' | awk -F: '/Last serial/{gsub(/ /,"",$2); print $2}')
                echo "POSTSERIAL_B $cyc kdc=$sa kdc2=$sb"
                if [ -n "${sa:-}" ] && [ "$sa" = "$sb" ] && [ "$sa" != "None" ]; then
                    matched_b=1
                    break
                fi
                sleep 2
            done
            echo "POSTSERIAL_B_MATCH $cyc $matched_b"
            echo "DUMP_B_AFTER $cyc"
            labn ssh kdc -- 'stat -c "%y %s %n" /var/kerberos/krb5kdc/replica_datatrans /var/kerberos/krb5kdc/replica_datatrans.dump_ok 2>&1 || true; echo ----; sudo head -n 1 /var/kerberos/krb5kdc/replica_datatrans 2>/dev/null || echo DUMP_ABSENT'
            if [ "$matched_b" != 1 ]; then
                echo "CYCLE_STOP step-B-serial $cyc"
                exit 1
            fi
            labn ssh kdc -- 'sudo kadmin.local -q listprincs' > "$REC/cycles/$cyc/kdc-after-princs.txt" || true
            labn ssh kdc2 -- 'sudo tail -n 80 /var/tmp/plw/kpropd.log; echo ----; sudo kadmin.local -q listprincs' > "$REC/cycles/$cyc/after.txt" || true
            k2body=$(awk 'f{print} /^----$/{f=1}' "$REC/cycles/$cyc/after.txt")
            left=""
            for name in $still; do
                if ! printf '%s\n' "$k2body" | grep -qx "${name}@KERBER.TEST"; then
                    left="$left $name"
                fi
            done
            left=${left# }
            if [ -n "$left" ]; then
                echo "CYCLE_STOP replica-miss-fresh $cyc $left"
                exit 1
            fi
            echo "HEAL_B_OK $cyc"
        else
            echo "HEAL_B_SKIP $cyc"
        fi
    fi
    # Stop the leg on a class MIT did not show, and on replica-miss after a
    # consistent or unstable-reset cycle. Stable-behind is allowed. A set
    # gap outside this cycle's writes is recorded and is not replica-miss.
    if ! python3 - "$REC/cycles/$cyc" "$cyc" << 'PY'
import sys
from pathlib import Path
d = Path(sys.argv[1])
cyc = int(sys.argv[2])
text = (d / "kdc-kprop.txt").read_text(errors="replace")
princs = (d / "kdc-princs.txt").read_text(errors="replace")
state = None
nent = None
ops = []
cur = None
names = set()
for line in text.splitlines():
    s = line.strip()
    if s.startswith("Log state") and state is None:
        state = s.split(":", 1)[1].strip()
    elif s.startswith("Number of entries") and nent is None:
        nent = int(s.split(":", 1)[1].strip())
    elif s.startswith("Update operation"):
        cur = s.split(":", 1)[1].strip()
    elif s.startswith("Update principal"):
        name = s.split(":", 1)[1].strip().split("@", 1)[0]
        names.add(name)
        ops.append((cur, name))
if "LIST_FAIL" in princs or "Cannot open" in princs:
    print("CYCLE_STOP %d db-missing" % cyc)
    sys.exit(1)
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

behind = sorted(p for p in db if in_scope(p) and p not in names)
ahead = sorted(n for op, n in ops if op == "Add" and in_scope(n) and n not in db)
if state is not None and (state == "Corrupt" or state.startswith("Unknown")):
    print("CYCLE_STOP %d corrupt" % cyc)
    sys.exit(1)
if state == "Stable" and ahead and (nent is None or nent < 1000):
    print("CYCLE_STOP %d log-ahead %s" % (cyc, ",".join(ahead)))
    sys.exit(1)
cls = "other"
if state == "Unstable":
    cls = "unstable-reset"
elif state == "Stable" and behind:
    cls = "stable-behind"
elif state == "Stable" and not ahead:
    cls = "consistent"
after = (d / "kdc-after-princs.txt").read_text(errors="replace") if (d / "kdc-after-princs.txt").exists() else ""
k2txt = (d / "after.txt").read_text(errors="replace") if (d / "after.txt").exists() else ""
k2body = k2txt.split("----", 1)[1] if "----" in k2txt else k2txt
def plw(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("plw") and "@" in line and " " not in line:
            out.add(line.split("@", 1)[0])
    return out
a, b = plw(after), plw(k2body)
only_a = sorted(p for p in (a - b) if in_scope(p))
only_b = sorted(p for p in (b - a) if in_scope(p))
gap = sorted((a - b) | (b - a))
if gap and not (only_a or only_b):
    print("SET_GAP %d %s" % (cyc, ",".join(gap)))
if cls in ("consistent", "unstable-reset", "stable-behind") and (only_a or only_b):
    print("CYCLE_STOP %d replica-miss %s %s" % (cyc, ",".join(only_a), ",".join(only_b)))
    sys.exit(1)
print("CYCLE_CLASS %d %s" % (cyc, cls))
sys.exit(0)
PY
    then
        echo "CYCLE_STOP_EXIT $cyc"
        exit 1
    fi
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
lab reset kdc2 rust-replica-f44
echo "RESET_KDC2_END:$?"
lab down kdc2
echo "DOWN_KDC2:$?"
echo "PLW_END $(TZ=America/Chicago date '+%H:%M:%S')"
