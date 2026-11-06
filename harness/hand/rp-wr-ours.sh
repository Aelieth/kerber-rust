#!/bin/bash
# WR, ours leg. Fresh rust-field-p12-f44.
# A failed read keeps the disk. Does not touch klldap.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
export REC
REC=$HAND_REC/$PHASEC_SHA/wr-ours
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
LOG=$REC/driver.log
export SEC
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")  # outside the record
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
TAR=$REC/wr-tree.tar
CO=kerber-rust-${PHASEC_SHA:0:12}
mkdir -p "$REC"
echo "REC:$REC"
lab() { bash "$LAB" "$@"; }
[ "$(git -C "$WT" rev-parse HEAD)" = "$PHASEC_SHA" ] || { echo "WT not at the build under test"; echo "WR_OURS_END"; exit 2; }
fail=0
note_fail() { echo "FAIL $*"; fail=1; }
python3 - << 'PY'
import os, pathlib, secrets
d = pathlib.Path(os.environ["SEC"])
d.mkdir(mode=0o700, exist_ok=True)
for name in ("wrcpw", "wrcpw-new", "wrk", "wrk-new", "wrpw", "wrpw-new", "wradd", "wrremote"):
    p = d / name
    p.write_text(secrets.token_hex(12) + "\n")
    p.chmod(0o600)
print("PW_READY")
PY
cleanup_pw() {
    python3 - << 'PY'
import os
from pathlib import Path
log = Path(os.environ["REC"]) / "driver.log"
text = log.read_text(errors="replace") if log.exists() else ""
hit = 0
root = Path(os.environ["SEC"])
if root.exists():
    for p in root.iterdir():
        for line in p.read_text(errors="replace").splitlines():
            if line and line in text:
                hit += 1
        p.unlink()
    root.rmdir()
print(f"SECRET_SCAN_HITS:{hit}")
PY
    rm -rf "$SEC"
    lab ssh kdc -- 'rm -rf /var/tmp/wr /var/tmp/wr.dump' >/dev/null 2>&1 || true
    lab ssh client2 -- 'rm -rf /var/tmp/wr' >/dev/null 2>&1 || true
}
trap cleanup_pw EXIT
echo "==== reset ===="
lab reset kdc rust-field-p12-f44
echo "RESET_KDC:$?"
lab reset client2 rust-ssh-f44
echo "RESET_C2:$?"
exec 8>>"$LAB_HOME/state/lab.lock"
flock -n 8 || { echo LOCK_BUSY; echo "WR_OURS_END"; exit 1; }
stage_host() {
    local host="$1"
    lab ssh "$host" -- 'rm -rf /var/tmp/wr && mkdir -p /var/tmp/wr && chmod 700 /var/tmp/wr'
    lab ssh "$host" -- 'cat > /var/tmp/wr/wr.py && chmod 700 /var/tmp/wr/wr.py' < "$HDIR/lib/wr.py"
}
stage_host kdc
stage_host client2
lab ssh kdc -- 'cat > /var/tmp/wr/alice && chmod 600 /var/tmp/wr/alice' < "$LAB_HOME/secrets/rust-realm.alice.password"
lab ssh kdc -- 'cat > /var/tmp/wr/bob && chmod 600 /var/tmp/wr/bob' < "$LAB_HOME/secrets/rust-realm.bob.password"
lab ssh client2 -- 'cat > /var/tmp/wr/alice && chmod 600 /var/tmp/wr/alice' < "$LAB_HOME/secrets/rust-realm.alice.password"
lab ssh client2 -- 'cat > /var/tmp/wr/bob && chmod 600 /var/tmp/wr/bob' < "$LAB_HOME/secrets/rust-realm.bob.password"
lab ssh client2 -- 'cat > /var/tmp/wr/admin && chmod 600 /var/tmp/wr/admin' < "$LAB_HOME/secrets/rust-realm.admin-admin.password"
for name in wrcpw wrcpw-new wrk wrk-new wrpw wrpw-new wradd wrremote; do
    lab ssh kdc -- "cat > /var/tmp/wr/$name && chmod 600 /var/tmp/wr/$name" < "$SEC/$name"
    lab ssh client2 -- "cat > /var/tmp/wr/$name && chmod 600 /var/tmp/wr/$name" < "$SEC/$name"
done
proc_line() {
    echo "==== proc ${1:-} ===="
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
}
kinit_c() {
    local who="$1" pw="$2" cc="$3" line
    line=$(lab ssh client2 -- "python3 /var/tmp/wr/wr.py kinit $who /var/tmp/wr/$pw FILE:/var/tmp/wr/$cc" | tr -d '\r')
    echo "$line"
    printf '%s\n' "$line"
}
expect_ok() {
    local line="$1" tag="$2"
    printf '%s\n' "$line" | grep -q ' rc=0 ' || note_fail "$tag $line"
}
echo "==== upgrade ===="
echo "COMMIT:$PHASEC_SHA"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
if [ ! -f "$TAR" ]; then
    git -C "$WT" archive --format=tar --prefix="${CO}/" "$PHASEC_SHA" > "$TAR"
fi
lab ssh kdc -- "rm -rf ~/$CO && mkdir -p ~/$CO && tar -x -C ~" < "$TAR"
echo "UPLOAD_RC:$?"
lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/$CO && make build'"
echo "BUILD_RC:$?"
inst=$(lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/$CO && sudo -n systemctl stop krb5kdc kadmin && sudo -n make install PREFIX=/usr CARGO_TARGET_DIR=\$HOME/$CO/target; echo INSTALL_RC:\$?'" | tr -d '\r')
printf '%s\n' "$inst" | grep -E 'still running|^INSTALL_RC:'
printf '%s\n' "$inst" | grep -q '^INSTALL_RC:0$' || { echo INSTALL_FAIL; echo "WR_OURS_END"; exit 1; }
lab ssh kdc -- 'sudo -n restorecon -Rv /var/kerberos/krb5kdc >/tmp/restorecon.out; echo RESTORECON_RC:$?; sudo -n systemctl start krb5kdc kadmin; echo START_RC:$?'
lab ssh kdc -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo LISTEN; exit 0; fi; sleep 1; done; echo DOWN; exit 1'
echo "BEGIN_BEFORE:$(lab ssh kdc -- 'sudo grep -c "^begin$" /var/kerberos/krb5kdc/principal || true' | tr -d '\r' | awk 'NF{p=$0} END{print p}')"
echo "==== WR.1 ===="
proc_line WR.1
k_alice=$(kinit_c alice alice cc-alice)
echo "$k_alice"
expect_ok "$k_alice" WR.1-alice
k_bob=$(kinit_c bob bob cc-bob)
echo "$k_bob"
expect_ok "$k_bob" WR.1-bob
echo "BASE_LIFE:$(lab ssh kdc -- 'python3 /var/tmp/wr/wr.py getlife bob' | tr -d '\r')"
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py add wrcpw /var/tmp/wr/wrcpw'
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py add wrk /var/tmp/wr/wrk'
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py add wrpw /var/tmp/wr/wrpw'
for who in wrcpw wrk wrpw; do
    line=$(kinit_c "$who" "$who" "cc-$who")
    echo "$line"
    expect_ok "$line" "WR.1-$who"
done
if [ "$fail" -ne 0 ]; then echo "WR_OURS_END"; exit 2; fi
echo "==== WR.2 ===="
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py add wradd /var/tmp/wr/wradd'
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py addrand wrdel'
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py delete wrdel'
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py cpw wrcpw /var/tmp/wr/wrcpw-new'
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py life bob 2h'
echo "==== WR.3 ===="
lab ssh client2 -- 'python3 /var/tmp/wr/wr.py remote cpw wrk /var/tmp/wr/wrk-new /var/tmp/wr/admin'
lab ssh client2 -- 'python3 /var/tmp/wr/wr.py remote add wrremote /var/tmp/wr/wrremote /var/tmp/wr/admin'
lab ssh client2 -- 'python3 /var/tmp/wr/wr.py kpasswd wrpw /var/tmp/wr/wrpw /var/tmp/wr/wrpw-new'
echo "BEGIN_AFTER_WRITES:$(lab ssh kdc -- 'sudo grep -c "^begin$" /var/kerberos/krb5kdc/principal || true' | tr -d '\r' | awk 'NF{p=$0} END{print p}')"
echo "DECRYPT_COUNT:$(lab ssh kdc -- 'sudo grep -c "stash master key did not decrypt dump key_data" /var/log/krb5kdc.log 2>/dev/null || true' | tr -d '\r' | awk 'NF{p=$0} END{print p+0}')"
echo "==== WR.4 ===="
check_read() {
    local tag="$1" line
    line=$(kinit_c alice alice cc-alice)
    echo "$tag $line"; expect_ok "$line" "$tag-alice"
    line=$(kinit_c bob bob cc-bob)
    echo "$tag $line"; expect_ok "$line" "$tag-bob"
    line=$(kinit_c wradd wradd cc-wradd)
    echo "$tag $line"; expect_ok "$line" "$tag-wradd"
    line=$(kinit_c wrremote wrremote cc-wrremote)
    echo "$tag $line"; expect_ok "$line" "$tag-wrremote"
    line=$(kinit_c wrcpw wrcpw-new cc-wrcpw)
    echo "$tag $line"; expect_ok "$line" "$tag-wrcpw-new"
    line=$(kinit_c wrk wrk-new cc-wrk)
    echo "$tag $line"; expect_ok "$line" "$tag-wrk-new"
    line=$(kinit_c wrpw wrpw-new cc-wrpw)
    echo "$tag $line"; expect_ok "$line" "$tag-wrpw-new"
    line=$(kinit_c wrcpw wrcpw cc-wrcpw-old)
    echo "$tag $line"
    printf '%s\n' "$line" | grep -q 'Password incorrect' || note_fail "$tag-old $line"
    line=$(kinit_c wrdel wrpw cc-wrdel)
    echo "$tag $line"
    printf '%s\n' "$line" | grep -q 'not found' || note_fail "$tag-wrdel $line"
    echo "$tag $(lab ssh kdc -- 'python3 /var/tmp/wr/wr.py getlife bob' | tr -d '\r')"
}
check_read WR.4
echo "LIFE_LINE:$(lab ssh kdc -- 'python3 /var/tmp/wr/wr.py getlife bob' | tr -d '\r')"
if [ "$fail" -ne 0 ]; then echo DISK_KEPT; echo "WR_OURS_END"; exit 2; fi
echo "==== WR.5 ===="
lab ssh kdc -- 'sudo systemctl restart krb5kdc kadmin; echo RESTART_RC:$?'
proc_line WR.5
check_read WR.5
if [ "$fail" -ne 0 ]; then echo DISK_KEPT; echo "WR_OURS_END"; exit 2; fi
echo "==== WR.6 ===="
lab ssh kdc -- 'sudo systemctl stop krb5kdc kadmin; echo STOP_RC:$?'
lab ssh kdc -- 'sudo timeout 60 kdb5_util dump /var/tmp/wr.dump >/tmp/wr-dump.out 2>/tmp/wr-dump.err; echo DUMP_RC:$?; sudo wc -c /var/tmp/wr.dump'
lab ssh kdc -- 'sudo timeout 60 kdb5_util load /var/tmp/wr.dump >/tmp/wr-load.out 2>/tmp/wr-load.err; echo LOAD_RC:$?'
lab ssh kdc -- 'sudo restorecon -R /var/kerberos/krb5kdc >/dev/null; sudo systemctl start krb5kdc kadmin; echo START_RC:$?; sudo rm -f /var/tmp/wr.dump /tmp/wr-dump.out /tmp/wr-dump.err /tmp/wr-load.out /tmp/wr-load.err'
echo "BEGIN_AFTER_LOAD:$(lab ssh kdc -- 'sudo grep -c "^begin$" /var/kerberos/krb5kdc/principal || true' | tr -d '\r' | awk 'NF{p=$0} END{print p}')"
proc_line WR.6
check_read WR.6
if [ "$fail" -ne 0 ]; then echo DISK_KEPT; echo "WR_OURS_END"; exit 2; fi
echo "==== cleanup ===="
lab ssh kdc -- 'python3 /var/tmp/wr/wr.py delete wradd; python3 /var/tmp/wr/wr.py delete wrremote; python3 /var/tmp/wr/wr.py delete wrcpw; python3 /var/tmp/wr/wr.py delete wrk; python3 /var/tmp/wr/wr.py delete wrpw; python3 /var/tmp/wr/wr.py life bob 1day'
echo "CLEAN_LIFE:$(lab ssh kdc -- 'python3 /var/tmp/wr/wr.py getlife bob' | tr -d '\r')"
echo "WR_OURS_END"
exit 0
