#!/bin/bash
# 3j FZ driver.
# A raw TGS-REQ for krbtgt/é from client2, through the tree's raw-tgs.py,
# using a TGT from MIT /usr/bin/kinit. MIT first on f4-mit-f44, then the
# 3i upgrade of 806c20f1. The same client request runs on both legs.
#
# Pass:
#   FZ_MIT: result=error, kdc-code 7, component-hex c3a9, both kinits rc 0.
#   FZ_OURS: the same code 7, a follow-up kinit rc 0, krb5kdc still active
#   and listening on 88, and no new "request panic isolated" line.
#   FZ_CODE_EQ: both kdc-codes are 7.
# A MIT code other than 7 stops before the upgrade. The outputs stay in the log.
#
# Client2 is reset to f4-mit-f44 for MIT kinit and restored to its start
# snapshot. No snapshot is created or deleted. No lab down. The alice
# password is copied to client2 for kinit and removed there before the
# grade. It is not printed.
set -u
umask 077
exec 9>&-
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
PHASEC_SHA=${1:?phasec sha}
SHA=$PHASEC_SHA
RAW=$HDIR/lib/raw-tgs.py
ALICE_PW=$LAB_HOME/secrets/mit-realm.alice.password
export REC
REC=$HAND_REC/$PHASEC_SHA/hand-fz
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
export SEC
LOG=$REC/driver.log
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
MIT_SNAP=f4-mit-f44
EXPECT_KDC=rust-field-p12-f44
EXPECT_C2=rust-ssh-f44
touched=0
start_kdc=
start_c2=
lab() { bash "$LAB" "$@"; }
stop() { echo "FZ_STOP $*"; exit 2; }
lock_on() {
    exec 8>>"$LAB_HOME/state/lab.lock"
    flock -n 8 || { echo LOCK_BUSY; exit 1; }
}
lock_off() {
    flock -u 8 2>/dev/null || true
    exec 8>&-
}
snap_current() {
    local dom=$1
    if command -v virsh >/dev/null 2>&1; then
        virsh -q -c qemu:///system snapshot-current "$dom" --name
    else
        (cd "$HERE" && distrobox-host-exec virsh -q -c qemu:///system snapshot-current "$dom" --name)
    fi
}
reset_vm() {
    local name=$1
    local snap=$2
    local rc
    lock_off
    lab reset "$name" "$snap"
    rc=$?
    lock_on
    echo "RESET:$name:$snap:$rc"
    [ "$rc" = 0 ] || stop "reset $name"
}
cleanup() {
    if [ "$touched" != 1 ]; then
        return
    fi
    echo "==== cleanup ===="
rcmd=$(cat << 'EOS'
rm -rf /var/tmp/fz "$HOME/fz"
EOS
)
    lab ssh client2 -- "$rcmd" || true
    lab ssh kdc -- 'sudo -n rm -rf /var/tmp/fz /var/tmp/fz-mark /var/kerberos/krb5kdc/mit-realm.dump' || true
    if [ -n "$start_kdc" ]; then
        lock_off
        lab reset kdc "$start_kdc" || true
        echo "RESTORE_KDC:$?"
    else
        echo "RESTORE_KDC:no-start-snap"
    fi
    if [ -n "$start_c2" ]; then
        lock_off
        lab reset client2 "$start_c2" || true
        echo "RESTORE_CLIENT2:$?"
    else
        echo "RESTORE_CLIENT2:no-start-snap"
    fi
    lock_off
    python3 - << 'PY'
import os
from pathlib import Path
rec = Path(os.environ["REC"])
log = rec / "driver.log"
text = log.read_text(errors="replace") if log.exists() else ""
hit = 0
for p in Path(os.environ["SEC"]).glob("secret-*"):
    if p.is_file():
        for line in p.read_text(errors="replace").splitlines():
            if line and line in text:
                hit += 1
        p.unlink()
print(f"SECRET_SCAN_HITS:{hit}")
PY
}
trap 'cleanup; rm -rf "$SEC"' EXIT
mkdir -p "$REC"
echo "REC:hand-fz-$(date -u +%Y%m%dT%H%M%SZ)"
echo "TREE:$(git -C "$WT" rev-parse HEAD)"
echo "TREE_ID:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
require_files "$LAB" "$RAW" "$ALICE_PW"
echo "RAW_SHA:$(sha256sum "$RAW" | awk 'NR==1 {print $1}')"
install -m 600 "$ALICE_PW" "$SEC/secret-alice"
echo "ALICE_PW:client2-only"
lock_on
touched=1
start_kdc=$(snap_current kerber-kdc | tr -d '\r')
start_c2=$(snap_current kerber-client2 | tr -d '\r')
echo "START_KDC:$start_kdc"
echo "START_CLIENT2:$start_c2"
[ "$start_kdc" = "$EXPECT_KDC" ] || stop "kdc snap is $start_kdc"
[ "$start_c2" = "$EXPECT_C2" ] || stop "client2 snap is $start_c2"
echo "==== mit reset ===="
reset_vm kdc "$MIT_SNAP"
reset_vm client2 "$MIT_SNAP"
rcmd=$(cat << 'EOS'
rpm -q krb5-server; test -x /usr/sbin/krb5kdc && echo KDC_BIN:yes || echo KDC_BIN:no; test -f "$HOME/.cargo/env" && echo CARGO_ENV:yes || echo CARGO_ENV:no
EOS
)
lab ssh kdc -- "$rcmd"
lab ssh client2 -- 'rpm -q krb5-workstation python3; test -x /usr/bin/kinit && echo KINIT_BIN:yes || echo KINIT_BIN:no; test -e /usr/lib64/libkrb5.so.3 && echo LIBKRB5:yes || echo LIBKRB5:no'
echo "==== prereq ===="
prereq=$(lab ssh kdc -- 'rpm -q make >/dev/null 2>&1 || sudo -n dnf install -y make; echo PREREQ_INSTALL:$?; rpm -q make' | tr -d '\r')
printf '%s\n' "$prereq"
printf '%s\n' "$prereq" | grep -q '^PREREQ_INSTALL:0$' || stop "prereq install"
printf '%s\n' "$prereq" | grep -q '^make-' || stop "make missing"

kdc_marks() {
    local when=$1
    lab ssh kdc -- 'sudo -n bash -s' "$when" << 'EOS'
set +e
when=$1
if [ -f /var/log/krb5kdc.log ]; then
    n=$(grep -cF "request panic isolated" /var/log/krb5kdc.log || true)
else
    n=0
    echo "PANIC_LOG:missing"
fi
echo "PANIC_${when}:$n"
if [ "$when" = "BEFORE" ]; then
    date -u '+%Y-%m-%d %H:%M:%S' > /var/tmp/fz-mark
    echo "MARK:$(cat /var/tmp/fz-mark)"
fi
if [ "$when" = "AFTER" ] && [ -f /var/tmp/fz-mark ]; then
    mark=$(cat /var/tmp/fz-mark)
    j=$(journalctl -u krb5kdc --since "$mark" --no-pager -o cat | grep -cF "request panic isolated" || true)
    echo "PANIC_JOURNAL:$j"
fi
echo "UNIT_${when}:$(systemctl is-active krb5kdc)"
if ss -lnt | grep -q ':88 ' || ss -lnu | grep -q ':88 '; then
    echo "PORT88_${when}:up"
else
    echo "PORT88_${when}:down"
fi
EOS
}

run_cell() {
    local tag=$1
    local rc
    echo "==== cell $tag ===="
rcmd=$(cat << 'EOS'
rm -rf /var/tmp/fz "$HOME/fz" && mkdir -p /var/tmp/fz "$HOME/fz" && chmod 700 /var/tmp/fz "$HOME/fz"
EOS
)
    lab ssh client2 -- "$rcmd"
    lab ssh client2 -- 'cat > /var/tmp/fz/raw-tgs.py && chmod 700 /var/tmp/fz/raw-tgs.py' < "$RAW"
    lab ssh client2 -- 'cat > /var/tmp/fz/pw && chmod 600 /var/tmp/fz/pw' < "$SEC/secret-alice"
    lab ssh client2 -- 'sha256sum /var/tmp/fz/raw-tgs.py'
    before=$(kdc_marks BEFORE | tr -d '\r')
    printf '%s\n' "$before" | tee "$REC/cell-$tag.txt"
    set +e
    timeout 180 bash "$LAB" ssh client2 -- 'bash -s' << 'EOS' | tee -a "$REC/cell-$tag.txt"
set +e
echo "KINIT_PATH:$(readlink -f /usr/bin/kinit 2>/dev/null || echo missing)"
sha256sum /usr/bin/kinit 2>/dev/null | awk '{print "KINIT_SHA:" $1}'
python3 -c 'import ctypes; ctypes.CDLL("libkrb5.so.3"); print("LIBKRB5:yes")' || echo "LIBKRB5:no"
rm -f "$HOME/fz/tkt" "$HOME/fz/follow"
/usr/bin/kinit -c "FILE:$HOME/fz/tkt" alice < /var/tmp/fz/pw
echo "KINIT_RC:$?"
python3 /var/tmp/fz/raw-tgs.py -c "FILE:$HOME/fz/tkt" -r KERBER.TEST
echo "RAW_RC:$?"
/usr/bin/kinit -c "FILE:$HOME/fz/follow" alice < /var/tmp/fz/pw
echo "KINIT_AFTER_RC:$?"
rm -f /var/tmp/fz/pw "$HOME/fz/tkt" "$HOME/fz/follow"
echo "PW_REMOVED"
EOS
    rc=${PIPESTATUS[0]}
    set +e
    echo "CELL_RC:$tag:$rc" | tee -a "$REC/cell-$tag.txt"
    [ "$rc" = 0 ] || stop "$tag cell timeout"
    after=$(kdc_marks AFTER | tr -d '\r')
    printf '%s\n' "$after" | tee -a "$REC/cell-$tag.txt"
    grep -q '^component-hex=c3a9$' "$REC/cell-$tag.txt" || stop "$tag component"
    grep -q '^RAW_RC:0$' "$REC/cell-$tag.txt" || stop "$tag raw setup"
    grep -q '^KINIT_RC:0$' "$REC/cell-$tag.txt" || stop "$tag kinit"
    grep -q '^PW_REMOVED$' "$REC/cell-$tag.txt" || stop "$tag pw left"
}

run_cell mit
grep -q '^kdc-code=7$' "$REC/cell-mit.txt" || stop "MIT kdc-code"
grep -q '^result=error$' "$REC/cell-mit.txt" || stop "MIT result"

echo "==== dump ===="
dump_out=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
systemctl stop krb5kdc kadmin
/usr/sbin/kdb5_util dump /var/kerberos/krb5kdc/mit-realm.dump
echo "DUMP_RC:$?"
EOS
)
printf '%s\n' "$dump_out"
printf '%s\n' "$dump_out" | grep -q '^DUMP_RC:0$' || stop "MIT dump failed"
echo "==== upgrade ===="
rcmd=$(cat << 'EOS'
test -f "$HOME/.cargo/env" && echo CARGO_ENV:yes || echo CARGO_ENV:no
EOS
)
cargo_line=$(lab ssh kdc -- "$rcmd" | tr -d '\r')
echo "$cargo_line"
tar=$REC/src.tar
git -C "$WT" archive --format=tar --prefix=fz-src/ "$SHA" > "$tar"
echo "ARCHIVE_RC:$?"
lab ssh kdc -- 'rm -rf ~/fz-src && mkdir -p ~/fz-src && tar -x -C ~' < "$tar"
echo "UPLOAD_RC:$?"
if printf '%s\n' "$cargo_line" | grep -q 'CARGO_ENV:yes'; then
    echo "INSTALL_METHOD:guest-cargo"
    lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/fz-src && make build'"
    brc=$?
    echo "BUILD_RC:$brc"
    [ "$brc" = 0 ] || stop "build failed"
else
    echo "INSTALL_METHOD:host-target-rp"
    dirty=$(git -C "$WT" status --porcelain --untracked-files=no | wc -l | tr -d ' ')
    echo "TREE_DIRTY:$dirty"
    [ "$dirty" = 0 ] || stop "worktree dirty"
    make -C "$WT" build CARGO_TARGET_DIR="$WT/target-rp"
    brc=$?
    echo "HOST_BUILD_RC:$brc"
    [ "$brc" = 0 ] || stop "host build failed"
    bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
    tar -C "$WT/target-rp" -cf "$REC/target.tar" release
    lab ssh kdc -- 'rm -rf ~/fz-src/target && mkdir -p ~/fz-src/target && tar -x -C ~/fz-src/target' < "$REC/target.tar"
    echo "TARGET_UPLOAD_RC:$?"
fi
inst=$(lab ssh kdc -- "bash -lc 'set +e; sudo -n systemctl stop krb5kdc kadmin; sudo -n dnf remove -y --no-autoremove krb5-server; echo REMOVE_RC:\$?; rpm -q krb5-server libkadm5; echo RPM_AFTER_REMOVE; for f in /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl /etc/sysconfig/krb5kdc /etc/sysconfig/kadmin /etc/sysconfig/kprop /etc/logrotate.d/krb5kdc /etc/logrotate.d/kadmind; do if [ -e \$f.rpmsave ]; then sudo -n mv \$f.rpmsave \$f; echo RPSAVE:\$f; fi; done; cd \$HOME/fz-src && sudo -n /usr/bin/make install PREFIX=/usr CARGO_TARGET_DIR=\$HOME/fz-src/target; echo INSTALL_RC:\$?'" | tr -d '\r')
printf '%s\n' "$inst"
printf '%s\n' "$inst" | grep -q '^INSTALL_RC:0$' || stop "install failed"
load_out=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
cd /var/kerberos/krb5kdc
mkdir -p mit-db2
mv -f principal principal.kadm5 mit-db2/ 2>/dev/null || true
if [ -e principal.ulog ]; then mv -f principal.ulog mit-db2/; fi
/usr/sbin/kdb5_util load /var/kerberos/krb5kdc/mit-realm.dump
echo "LOAD_RC:$?"
if [ -e /var/kerberos/krb5kdc/kpropd.acl ]; then
    rm -f /var/kerberos/krb5kdc/kpropd.acl
    echo "KPROPD_ACL_CLEARED"
fi
restorecon -Rv /var/kerberos/krb5kdc >/tmp/fz-restorecon.out 2>&1
echo "RESTORECON_RC:$?"
systemctl enable --now krb5kdc kadmin
echo "START_RC:$?"
EOS
)
printf '%s\n' "$load_out"
printf '%s\n' "$load_out" | grep -q '^LOAD_RC:0$' || stop "load failed"
printf '%s\n' "$load_out" | grep -q '^START_RC:0$' || stop "kdc start"
listen=$(lab ssh kdc -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN; exit 1' | tr -d '\r')
printf '%s\n' "$listen"
printf '%s\n' "$listen" | grep -q '^PORT_UP$' || stop "ours ports"
proc=$(lab ssh kdc -- 'sudo python3 -' << 'PY'
import hashlib, os, pathlib
def hx(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
for name in ("krb5kdc", "kadmind"):
    disk = f"/usr/sbin/{name}"
    if not os.path.exists(disk):
        print(f"PROC {name} NO_DISK")
        continue
    dh = hx(disk)
    pids = os.popen(f"pgrep -x {name}").read().split()
    if not pids:
        print(f"PROC {name} NOT_RUNNING disk={dh}")
        continue
    eh = hx(f"/proc/{pids[0]}/exe")
    print(f"PROC {name} pid={pids[0]} exe={eh} disk={dh} match={str(eh==dh).lower()}")
PY
)
printf '%s\n' "$proc"
printf '%s\n' "$proc" | grep -q 'PROC krb5kdc .* match=true' || stop "kdc proc"
printf '%s\n' "$proc" | grep -q 'PROC kadmind .* match=true' || stop "kadmin proc"
run_cell ours
echo "==== grade ===="
python3 - "$REC" << 'PY'
import sys
from pathlib import Path
rec = Path(sys.argv[1])

def body(tag):
    p = rec / f"cell-{tag}.txt"
    return p.read_text(errors="replace") if p.exists() else ""

def one(text, key):
    prefix = key + "="
    colon = key + ":"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
        if line.startswith(colon):
            return line[len(colon):]
    return "missing"

def show(tag, text):
    code = one(text, "kdc-code")
    result = one(text, "result")
    hx = one(text, "component-hex")
    k1 = one(text, "KINIT_RC")
    k2 = one(text, "KINIT_AFTER_RC")
    raw = one(text, "RAW_RC")
    before = one(text, "PANIC_BEFORE")
    after = one(text, "PANIC_AFTER")
    journal = one(text, "PANIC_JOURNAL")
    unit = one(text, "UNIT_AFTER")
    port = one(text, "PORT88_AFTER")
    print(
        f"{tag} code={code} result={result} hex={hx} "
        f"kinit={k1} kinit_after={k2} raw={raw} "
        f"panic_before={before} panic_after={after} panic_journal={journal} "
        f"unit={unit} port={port}"
    )
    return code, result, hx, k1, k2, raw, before, after, journal, unit, port

def client_ok(code, result, hx, k1, k2, raw):
    return code == "7" and result == "error" and hx == "c3a9" and k1 == "0" and k2 == "0" and raw == "0"

mit = show("MIT", body("mit"))
ours = show("OURS", body("ours"))
mit_ok = client_ok(*mit[:6])
ours_client = client_ok(*ours[:6])
panic_ok = ours[6] != "missing" and ours[6] == ours[7] and ours[8] == "0"
up_ok = ours[9] == "active" and ours[10] == "up"
print("FZ_MIT:" + ("yes" if mit_ok else "no"))
print("FZ_OURS:" + ("yes" if ours_client and panic_ok and up_ok else "no"))
print("FZ_CODE_EQ:" + ("yes" if mit[0] == "7" and ours[0] == "7" else "no"))
print("FZ_PANIC:" + ("yes" if panic_ok else "no"))
print("FZ_KDC_UP:" + ("yes" if up_ok and ours[4] == "0" else "no"))
PY
echo "FZ_END"
