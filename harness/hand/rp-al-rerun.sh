#!/bin/bash
# A2, A3, trickle on one build. Both daemons restarted by the upgrade blocks.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
export SEC
REC=$HAND_REC/$PHASEC_SHA/al-rerun
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
TAR=$REC/tree.tar
CO=kerber-rust-${PHASEC_SHA:0:12}
SECRET=$LAB_HOME/secrets/rust-realm.bob.password
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")  # outside the record
mkdir -p "$REC" "$SEC"
chmod 700 "$SEC"
echo "REC:$REC"
lab() { bash "$LAB" "$@"; }
cleanup_pw() {
    lab ssh kdc -- 'rm -rf /var/tmp/decrypt /var/tmp/al3' >/dev/null 2>&1 || true
    lab ssh client2 -- 'rm -rf /var/tmp/decrypt' >/dev/null 2>&1 || true
    rm -f "$SEC/rp-al-newpw"
    rm -rf "$SEC"
}
trap cleanup_pw EXIT
echo "==== reset ===="
lab reset kdc rust-field-p12-f44
echo "RESET_KDC:$?"
lab reset client2 rust-ssh-f44
echo "RESET_C2:$?"
exec 8>>"$LAB_HOME/state/lab.lock"
flock -n 8 || { echo LOCK_BUSY; echo "AL_RERUN_END"; exit 1; }
echo "==== upload build upgrade ===="
git -C "$WT" archive --format=tar "$PHASEC_SHA" > "$TAR"
lab ssh kdc -- "rm -rf ~/$CO && mkdir -p ~/$CO && tar -x -C ~/$CO" < "$TAR"
echo "UPLOAD_RC:$?"
lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/$CO && make build'"
echo "BUILD_RC:$?"
inst=$(lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/$CO && sudo -n systemctl stop krb5kdc kadmin && sudo -n make install PREFIX=/usr CARGO_TARGET_DIR=\$HOME/$CO/target; echo INSTALL_RC:\$?'" | tr -d '\r')
printf '%s\n' "$inst" | grep -E 'still running|^installed |^INSTALL_RC:'
printf '%s\n' "$inst" | grep -q '^INSTALL_RC:0$' || { echo INSTALL_FAIL; echo "AL_RERUN_END"; exit 1; }
lab ssh kdc -- "bash -lc 'set -o pipefail
DB=/var/kerberos/krb5kdc/principal
sudo -n restorecon -Rv /var/kerberos/krb5kdc >/tmp/restorecon.out
echo RESTORECON_RC:\$?
for f in \"\$DB.ok\" \"\$DB.kadm5.lock\" \"\$DB.lockout\"; do
  if sudo -n test ! -e \"\$f\"; then echo CREATED; else echo EXISTS; fi
done
sudo -n systemctl start krb5kdc kadmin
echo START_RC:\$?
'"
lab ssh kdc -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo LISTEN; exit 0; fi; sleep 1; done; echo DOWN; exit 1'
echo "HOST:kdc TREE:$PHASEC_SHA write-tree:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
lab ssh kdc -- 'sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind /usr/sbin/kadmin.local'
kp_cmd=$(cat << 'EOS'
sha256sum "$(command -v kpasswd)"
EOS
)
lab ssh client2 -- "$kp_cmd"
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
proc_line install
kadmin_q() {
    lab ssh kdc -- "sudo kadmin.local -q $(printf '%q' "$1")"
}
echo "==== A2 ===="
kadmin_q "delpol -force dictpol" >/dev/null || true
kadmin_q "addpol dictpol"
echo "ADDPOL_RC:$?"
kadmin_q "modprinc -policy dictpol bob"
echo "MODPRINC_RC:$?"
kadmin_q "getprinc bob" | grep -E '^(Principal:|Policy:)' || true
dict=$(lab ssh kdc -- "sudo awk -F= '/dict_file/ && \$0 !~ /^[[:space:]]*#/ {gsub(/[[:space:]\"]/,\"\",\$2); print \$2; exit}' /var/kerberos/krb5kdc/kdc.conf" | tr -d '\r' | awk 'NF{p=$0} END{print p}')
echo "DICT:${dict:-missing}"
if [ -z "${dict:-}" ]; then
    echo "NO_DICT"
    echo "AL_RERUN_END"
    exit 1
fi
word=$(lab ssh kdc -- "sudo awk 'NF && \$1 !~ /^#/ { print; exit }' $(printf '%q' "$dict")" | tr -d '\r\n')
echo "WORD_LEN:${#word}"
old=$(tr -d '\r\n' < "$SECRET")
out=$(timeout 90 bash "$LAB" ssh client2 -- /usr/bin/kpasswd bob <<EOF
$old
$word
$word
EOF
)
rc=$?
echo "KPASSWD_RC:$rc"
OLD="$old" WORD="$word" python3 -c '
import os, sys
text = sys.stdin.read()
old = os.environ.get("OLD", "")
word = os.environ.get("WORD", "")
if old:
    text = text.replace(old, "[REDACTED]")
if word:
    text = text.replace(word, "[REDACTED]")
for line in text.splitlines():
    low = line.lower()
    if "key:" in low or "session key" in low:
        continue
    print(line[:200])
' <<<"$out"
if printf '%s\n' "$out" | grep -q 'Password changed'; then
    echo "CHANGED:1"
else
    echo "CHANGED:0"
fi
kadmin_q "modprinc -clearpolicy bob" >/dev/null || true
kadmin_q "delpol -force dictpol" >/dev/null || true
kadmin_q "getprinc bob" | grep -E '^(Principal:|Policy:)' || true
unset old word out
proc_line a2
echo "==== A3 ===="
stop_cmd=$(cat << 'EOS'
s=$(date +%s%N); sudo systemctl stop kadmin; rc=$?; e=$(date +%s%N); echo "STOP_RC:$rc"; echo "STOP_MS:$(( (e-s)/1000000 ))"
EOS
)
lab ssh kdc -- "$stop_cmd"
lab ssh kdc -- "sudo journalctl -u kadmin --no-pager -n 30 --since '2 min ago' | grep -E 'finished, exiting|Got signal|closing down|Stopped|Deactivated' || true"
lab ssh kdc -- "sudo tail -n 15 /var/log/kadmind.log | grep -E 'finished, exiting|Got signal|closing down' || true"
proc_line a3-stopped
echo "==== start kadmin for trickle ===="
lab ssh kdc -- 'sudo systemctl start kadmin; echo START_KADMIN:$?'
lab ssh kdc -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if systemctl is-active --quiet kadmin && ss -ltn | grep -q ":749 "; then echo LISTEN; exit 0; fi; sleep 1; done; echo DOWN; exit 1'
proc_line trickle
echo "==== trickle ===="
lab ssh kdc -- 'rm -rf /var/tmp/al3 && mkdir -p /var/tmp/al3 && chmod 700 /var/tmp/al3'
lab ssh kdc -- 'cat > /var/tmp/al3/trickle.py && chmod 700 /var/tmp/al3/trickle.py' < "$HDIR/lib/al3-trickle.py"
lab ssh kdc -- 'cat > /var/tmp/al3/guest.py && chmod 700 /var/tmp/al3/guest.py' < "$HDIR/lib/rp-trickle-guest.py"
lab ssh kdc -- 'cat > /var/tmp/al3/admin.pw && chmod 600 /var/tmp/al3/admin.pw' < "$LAB_HOME/secrets/rust-realm.admin-admin.password"
lab ssh kdc -- 'cat > /var/tmp/al3/bob.pw && chmod 600 /var/tmp/al3/bob.pw' < "$SECRET"
python3 - << 'PY'
import os, pathlib, secrets
p = pathlib.Path(os.environ["SEC"] + "/rp-al-newpw")
p.write_text(secrets.token_hex(16) + "\n")
p.chmod(0o600)
print("NEWPW_READY")
PY
lab ssh kdc -- 'cat > /var/tmp/al3/bob-new.pw && chmod 600 /var/tmp/al3/bob-new.pw' < "$SEC/rp-al-newpw"
trickle_cmd=$(cat << 'EOS'
nohup python3 /var/tmp/al3/trickle.py > /var/tmp/al3/trickle.out 2>&1 & echo $! > /var/tmp/al3/trickle.pid; echo TRICKLE_PID:$(cat /var/tmp/al3/trickle.pid)
EOS
)
lab ssh kdc -- "$trickle_cmd"
sleep 2
lab ssh kdc -- 'python3 /var/tmp/al3/guest.py getprinc'
lab ssh kdc -- 'python3 /var/tmp/al3/guest.py kpasswd'
trickle_wait=$(cat << 'EOS'
while kill -0 "$(cat /var/tmp/al3/trickle.pid)" 2>/dev/null; do sleep 1; done; cat /var/tmp/al3/trickle.out
EOS
)
lab ssh kdc -- "$trickle_wait"
proc_line after-trickle
echo "==== kinit after chpw ===="
lab ssh kdc -- 'cat > /var/tmp/al3/kinit.py && chmod 700 /var/tmp/al3/kinit.py' < "$HDIR/lib/rp-decrypt-guest.py"
lab ssh kdc -- 'cat > /var/tmp/al3/alice.pw && chmod 600 /var/tmp/al3/alice.pw' < "$LAB_HOME/secrets/rust-realm.alice.password"
lab ssh kdc -- 'python3 /var/tmp/al3/kinit.py alice /var/tmp/al3/alice.pw; python3 /var/tmp/al3/kinit.py bob /var/tmp/al3/bob-new.pw'
lab ssh kdc -- 'sudo kdestroy -c /tmp/krb5cc_0 2>/dev/null || true; kdestroy 2>/dev/null || true' >/dev/null || true
echo "AL_RERUN_END"
exit 0
