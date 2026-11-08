#!/bin/bash
# SR driver: the secrets scan of a kadmind core.
# MIT kadmind first on f4-mit-f44, then the host-target-rp upgrade, then ours.
# A kpasswd change and a remote kadmin cpw, each to a fresh password, then gcore kadmind.
# The core is scanned on the VM. Only counts leave. The core is deleted on the VM.
# Pass: each ours count is <= the MIT count, and the realm-name control is non-zero on both.
# Client2 is not reset. No snapshot is created or deleted.
set -u
umask 077
exec 9>&-
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
SETPW=$WT/harness/field/lib/setpw.py
PHASEC_SHA=${1:?phasec sha}
SHA=$PHASEC_SHA
export REC
REC=$HAND_REC/$PHASEC_SHA/hand-sr
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
export SEC
LOG=$REC/driver.log
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
ADMIN_PW=$LAB_HOME/secrets/mit-realm.admin-admin.password
MIT_SNAP=f4-mit-f44
touched=0
start_snap=
lab() { bash "$LAB" "$@"; }
stop() { echo "SR_STOP $*"; exit 2; }
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
reset_kdc() {
    local name=$1 rc
    lock_off
    lab reset kdc "$name"
    rc=$?
    lock_on
    echo "RESET:$name:$rc"
    [ "$rc" = 0 ] || stop "reset $name"
}
cleanup() {
    if [ "$touched" != 1 ]; then
        return
    fi
    echo "==== cleanup ===="
    lab ssh kdc -- 'sudo rm -f /tmp/sr1core.*; sudo kadmin.local -q "delprinc -force sruser" >/dev/null 2>&1 || true; sudo rm -rf /var/tmp/sr' || true
    lab ssh client2 -- 'rm -rf ~/sr1 /var/tmp/sr' || true
    if [ -n "$start_snap" ]; then
        lock_off
        lab reset kdc "$start_snap" || true
        echo "RESTORE_KDC:$?"
    else
        echo "RESTORE_KDC:no-start-snap"
    fi
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
echo "REC:hand-sr-$(date -u +%Y%m%dT%H%M%SZ)"
echo "TREE:$(git -C "$WT" rev-parse HEAD)"
require_files "$LAB" "$SETPW" "$ADMIN_PW"
cp "$ADMIN_PW" "$SEC/secret-admin"
chmod 600 "$SEC/secret-admin"
start_snap=$(snap_current kerber-kdc | tr -d '\r')
echo "START_SNAP:$start_snap"
[ -n "$start_snap" ] || stop "no start snapshot"
lock_on
touched=1
echo "==== mit reset ===="
reset_kdc "$MIT_SNAP"
lab ssh kdc -- 'rpm -q krb5-server krb5-workstation; systemctl is-active krb5kdc; systemctl is-active kadmin'
lab ssh client2 -- 'rpm -q krb5-workstation; test -x /usr/bin/kinit && echo KINIT:yes || echo KINIT:no; test -x /usr/bin/kadmin && echo KADMIN:yes || echo KADMIN:no; python3 -c "import ctypes; ctypes.CDLL(\"libkrb5.so.3\"); print(\"LIBKRB5:yes\")"'
echo "==== prereq ===="
prereq=$(lab ssh kdc -- 'rpm -q make gdb >/dev/null 2>&1 || sudo -n dnf install -y make gdb; echo PREREQ_INSTALL:$?; rpm -q make gdb' | tr -d '\r')
printf '%s\n' "$prereq"
printf '%s\n' "$prereq" | grep -q '^PREREQ_INSTALL:0$' || stop "prereq install"
printf '%s\n' "$prereq" | grep -q '^make-' || stop "make missing"
printf '%s\n' "$prereq" | grep -q '^gdb-' || stop "gdb missing"

draw() {
    local dest=$1
    python3 -c 'import secrets; print(secrets.token_urlsafe(18))' > "$dest"
    chmod 600 "$dest"
    [ -s "$dest" ] || stop "no secret drawn"
}

cell() {
    local tag=$1
    echo "==== cell $tag ===="
    draw "$SEC/secret-${tag}-pw1"
    draw "$SEC/secret-${tag}-pw2"
    lab ssh kdc -- 'sudo rm -rf /var/tmp/sr && sudo mkdir -p /var/tmp/sr && sudo chown lab:lab /var/tmp/sr && sudo chmod 700 /var/tmp/sr'
    lab ssh client2 -- 'rm -rf ~/sr1 /var/tmp/sr && mkdir -p -m 0700 ~/sr1 /var/tmp/sr'
    lab ssh client2 -- 'cat > ~/sr1/setpw.py && chmod 700 ~/sr1/setpw.py' < "$SETPW"
    lab ssh client2 -- 'cat > /var/tmp/sr/admin-pw && chmod 600 /var/tmp/sr/admin-pw' < "$ADMIN_PW"
    lab ssh client2 -- 'cat > /var/tmp/sr/pw1 && chmod 600 /var/tmp/sr/pw1' < "$SEC/secret-${tag}-pw1"
    lab ssh client2 -- 'cat > /var/tmp/sr/pw2 && chmod 600 /var/tmp/sr/pw2' < "$SEC/secret-${tag}-pw2"
    setup=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
/usr/sbin/kadmin.local -q "delprinc -force sruser" </dev/null >/tmp/sr-del.out 2>&1
echo "DEL_RC:$?"
/usr/sbin/kadmin.local -q "addprinc -randkey sruser" </dev/null >/tmp/sr-add.out 2>&1
echo "ADD_RC:$?"
grep -F 'created.' /tmp/sr-add.out && echo ADD_CREATED:yes || echo ADD_CREATED:no
rm -f /tmp/sr-del.out /tmp/sr-add.out
EOS
)
    printf '%s\n' "$setup"
    printf '%s\n' "$setup" | grep -q '^ADD_CREATED:yes$' || stop "$tag addprinc"
    chg=$(lab ssh client2 -- 'bash -s' << 'EOS'
set +e
admin=$(cat /var/tmp/sr/admin-pw)
pw1=$(cat /var/tmp/sr/pw1)
pw2=$(cat /var/tmp/sr/pw2)
kinit -S kadmin/changepw -c "FILE:$HOME/sr1/admin.cc" admin/admin@KERBER.TEST <<EOF
$admin
EOF
echo "KINIT_CPW:$?"
python3 "$HOME/sr1/setpw.py" -c "FILE:$HOME/sr1/admin.cc" -t sruser@KERBER.TEST kdc.kerber.test <<EOF
$pw1
EOF
echo "SETPW_RC:$?"
kadmin -p admin/admin@KERBER.TEST -r KERBER.TEST -q 'cpw sruser' <<EOF
$admin
$pw2
$pw2
EOF
echo "CPW_RC:$?"
rm -f "$HOME/sr1/admin.cc" /var/tmp/sr/admin-pw /var/tmp/sr/pw1 /var/tmp/sr/pw2
EOS
)
    printf '%s\n' "$chg"
    printf '%s\n' "$chg" | grep -q '^KINIT_CPW:0$' || stop "$tag kinit changepw"
    printf '%s\n' "$chg" | grep -q '^result: 0 (Success)$' || stop "$tag kpasswd"
    printf '%s\n' "$chg" | grep -q 'changed\.' || stop "$tag kadmin cpw"
    core=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
p=$(pgrep -x kadmind | head -1)
echo "KADMIND_PID:$p"
[ -n "$p" ] || { echo CORE:none; exit 1; }
rm -f /tmp/sr1core.*
gcore -o /tmp/sr1core "$p" >/tmp/sr-gcore.out 2>&1
echo "GCORE_RC:$?"
f=$(ls /tmp/sr1core.* 2>/dev/null | head -1)
if [ -n "$f" ] && [ -s "$f" ]; then echo "CORE_BYTES:$(stat -c %s "$f")"; else echo CORE_BYTES:0; fi
rm -f /tmp/sr-gcore.out
EOS
)
    printf '%s\n' "$core"
    printf '%s\n' "$core" | grep -q '^CORE_BYTES:0$' && stop "$tag core empty"
    printf '%s\n' "$core" | grep -q '^GCORE_RC:0$' || stop "$tag gcore"
    kpw=$(lab ssh kdc -- 'sudo grep -o -a -F -f - /tmp/sr1core.* | wc -l' < "$SEC/secret-${tag}-pw1" | tr -d ' \r')
    cpw=$(lab ssh kdc -- 'sudo grep -o -a -F -f - /tmp/sr1core.* | wc -l' < "$SEC/secret-${tag}-pw2" | tr -d ' \r')
    ctl=$(lab ssh kdc -- 'sudo grep -o -a -F -- KERBER.TEST /tmp/sr1core.* | wc -l' | tr -d ' \r')
    lab ssh kdc -- 'sudo rm -f /tmp/sr1core.*'
    echo "SR_KPW:$tag:$kpw"
    echo "SR_CPW:$tag:$cpw"
    echo "SR_CONTROL:$tag:$ctl"
    printf 'kpw=%s\ncpw=%s\ncontrol=%s\n' "$kpw" "$cpw" "$ctl" > "$REC/count-$tag"
    [ "$ctl" -ge 1 ] 2>/dev/null || stop "$tag control"
    lab ssh kdc -- 'sudo -n kadmin.local -q "delprinc -force sruser" </dev/null >/dev/null 2>&1 || true'
    lab ssh client2 -- 'rm -rf ~/sr1 /var/tmp/sr'
}

cell mit
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
git -C "$WT" archive --format=tar --prefix=sr-src/ "$SHA" > "$tar"
echo "ARCHIVE_RC:$?"
lab ssh kdc -- 'rm -rf ~/sr-src && mkdir -p ~/sr-src && tar -x -C ~' < "$tar"
echo "UPLOAD_RC:$?"
if printf '%s\n' "$cargo_line" | grep -q 'CARGO_ENV:yes'; then
    echo "INSTALL_METHOD:guest-cargo"
    lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/sr-src && make build'"
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
    lab ssh kdc -- 'rm -rf ~/sr-src/target && mkdir -p ~/sr-src/target && tar -x -C ~/sr-src/target' < "$REC/target.tar"
    echo "TARGET_UPLOAD_RC:$?"
fi
inst=$(lab ssh kdc -- "bash -lc 'set +e; sudo -n systemctl stop krb5kdc kadmin; sudo -n dnf remove -y --no-autoremove krb5-server; echo REMOVE_RC:\$?; rpm -q krb5-server libkadm5; echo RPM_AFTER_REMOVE; for f in /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl /etc/sysconfig/krb5kdc /etc/sysconfig/kadmin /etc/sysconfig/kprop /etc/logrotate.d/krb5kdc /etc/logrotate.d/kadmind; do if [ -e \$f.rpmsave ]; then sudo -n mv \$f.rpmsave \$f; echo RPSAVE:\$f; fi; done; cd \$HOME/sr-src && sudo -n /usr/bin/make install PREFIX=/usr CARGO_TARGET_DIR=\$HOME/sr-src/target; echo INSTALL_RC:\$?'" | tr -d '\r')
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
restorecon -Rv /var/kerberos/krb5kdc >/tmp/sr-restorecon.out 2>&1
echo "RESTORECON_RC:$?"
systemctl enable --now krb5kdc kadmin
echo "START_RC:$?"
EOS
)
printf '%s\n' "$load_out"
printf '%s\n' "$load_out" | grep -q '^LOAD_RC:0$' || stop "load failed"
lab ssh kdc -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN; exit 1'
echo "OURS_LISTEN:$?"
lab ssh kdc -- 'sudo python3 -' << 'PY'
import hashlib, os, pathlib
def hx(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
for name in ("krb5kdc", "kadmind"):
    pids = os.popen(f"pgrep -x {name}").read().split()
    disk = f"/usr/sbin/{name}"
    dh = hx(disk)
    if not pids:
        print(f"PROC {name} NOT_RUNNING disk={dh}")
        continue
    eh = hx(f"/proc/{pids[0]}/exe")
    print(f"PROC {name} pid={pids[0]} exe={eh} disk={dh} match={str(eh==dh).lower()}")
PY
cell ours
echo "==== grade ===="
mit_kpw=$(sed -n 's/^kpw=//p' "$REC/count-mit")
mit_cpw=$(sed -n 's/^cpw=//p' "$REC/count-mit")
ours_kpw=$(sed -n 's/^kpw=//p' "$REC/count-ours")
ours_cpw=$(sed -n 's/^cpw=//p' "$REC/count-ours")
echo "SR_COMPARE kpasswd $ours_kpw/$mit_kpw cpw $ours_cpw/$mit_cpw"
[ -n "$mit_kpw" ] && [ -n "$ours_kpw" ] && [ "$ours_kpw" -le "$mit_kpw" ] && echo SR_KPW_LE:yes || echo SR_KPW_LE:no
[ -n "$mit_cpw" ] && [ -n "$ours_cpw" ] && [ "$ours_cpw" -le "$mit_cpw" ] && echo SR_CPW_LE:yes || echo SR_CPW_LE:no
echo "SR_QUERY_DONE"
exit 0
