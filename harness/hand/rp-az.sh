#!/bin/bash
# 3d AZ. MIT first, then the doc upgrade at cb557f18, then embed cells 2-4 on klldap.
# A mismatched cell exits without resetting that disk. Passwords stay in 0600 files.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC FIELD_LAB_NET
WT=$HAND_WT
export REC
REC=$HAND_REC/$PHASEC_SHA/az
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
export SEC
exec 9>&-
echo $$ > "$REC/driver.pid"
LAB=$WT/harness/field/lab.sh
CO=kerber-rust-${PHASEC_SHA:0:12}
TAR=$REC/az-tree.tar
mkdir -p "$REC"
echo "REC:$REC"
echo "COMMIT:$PHASEC_SHA"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
lab() { bash "$LAB" "$@"; }
stop() { echo "AZ_STOP $*"; echo "AZ_END"; exit 2; }
[ "$(git -C "$WT" rev-parse HEAD)" = "$PHASEC_SHA" ] || stop "WT not at the build under test"

python3 - << 'PY'
import os, pathlib, secrets
d = pathlib.Path(os.environ["SEC"]) / "azpw"
d.mkdir(mode=0o700, exist_ok=True)
p = d / "pw"
p.write_text(secrets.token_hex(16))
p.chmod(0o600)
print("PW_READY")
PY
PW=$SEC/azpw/pw

cleanup() {
    python3 - << 'PY'
import os
from pathlib import Path
log = Path(os.environ["REC"]) / "driver.log"
text = log.read_text(errors="replace") if log.exists() else ""
hit = 0
root = Path(os.environ["SEC"]) / "azpw"
if root.exists():
    for p in root.iterdir():
        for line in p.read_text(errors="replace").splitlines():
            if line and line in text:
                hit += 1
print(f"SECRET_SCAN_HITS:{hit}")
PY
    lab reset klldap f44-docker
    echo "RESTORE_KLLDAP:$?"
    lab down klldap || true
    lab reset client2 rust-ssh-f44
    echo "RESTORE_C2:$?"
    lab down client2 || true
}
trap 'cleanup; rm -rf "$SEC"' EXIT

stage_kdc() {
    lab ssh kdc -- 'rm -rf /var/tmp/az && mkdir -p /var/tmp/az && chmod 700 /var/tmp/az'
    lab ssh kdc -- 'cat > /var/tmp/az/pw && chmod 600 /var/tmp/az/pw' < "$PW"
    lab ssh kdc -- 'cat > /var/tmp/az/az-kdc.py && chmod 700 /var/tmp/az/az-kdc.py' < "$HDIR/lib/az-kdc.py"
    lab ssh kdc -- 'cat > /var/tmp/az/az-cells.py && chmod 700 /var/tmp/az/az-cells.py' < "$HDIR/lib/az-cells.py"
}
stage_client() {
    lab ssh client2 -- 'rm -rf ~/field/az && mkdir -p ~/field/az && chmod 700 ~/field/az'
    lab ssh client2 -- 'cat > ~/field/az/pw && chmod 600 ~/field/az/pw' < "$PW"
    lab ssh client2 -- 'cat > ~/field/az/az-client.py && chmod 700 ~/field/az/az-client.py' < "$HDIR/lib/az-client.py"
    lab ssh client2 -- 'cat > ~/field/az/az-cells.py && chmod 700 ~/field/az/az-cells.py' < "$HDIR/lib/az-cells.py"
}
client_probe() {
    lab ssh client2 -- "python3 ~/field/az/$1 $2" < "$PW"
}
klog() {
    local since="$1"
    lab ssh kdc -- "sudo -n python3 - $since" << 'PY'
import pathlib, subprocess, sys
since = sys.argv[1]
pw_path = pathlib.Path("/var/tmp/az/pw")
pw = pw_path.read_text().strip() if pw_path.exists() else ""
chunks = []
log = pathlib.Path("/var/log/kadmind.log")
if log.exists():
    chunks.append(log.read_text(errors="replace")[-5000:])
j = subprocess.run(
    ["journalctl", "-u", "kadmin", "--since", "@" + since, "-o", "cat", "--no-pager"],
    capture_output=True, text=True,
)
chunks.append(j.stdout or "")
n = 0
for line in "".join(chunks).splitlines():
    if pw and pw in line:
        continue
    low = line.lower()
    if line.startswith("Key:") or "session key" in low:
        continue
    if any(s in low for s in ("privilege", "denied", "unauthorized", "operation requires", "auth_")):
        print("KLOG", line.strip()[:220])
        n += 1
print(f"KLOG_N:{n}")
PY
}
need() {
    local blob="$1" needle="$2" tag="$3"
    printf '%s\n' "$blob" | grep -F -q -- "$needle" || stop "$tag missing"
}
proc_line() {
    echo "==== proc $1 ===="
    lab ssh kdc -- 'sudo -n python3 -' << 'PY'
import hashlib, os, pathlib
def hx(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
for name in ("krb5kdc", "kadmind"):
    pids = os.popen("pgrep -x " + name).read().split()
    disk = "/usr/sbin/" + name
    dh = hx(disk)
    if not pids:
        print(f"PROC {name} NOT_RUNNING disk={dh}")
        continue
    eh = hx("/proc/" + pids[0] + "/exe")
    print(f"PROC {name} pid={pids[0]} exe={eh} disk={dh} match={str(eh==dh).lower()}")
PY
}

echo "==== MIT reset ===="
lab reset kdc f4-mit-f44
echo "RESET_KDC:$?"
lab reset client2 mit-kit-fc44
echo "RESET_C2:$?"
stage_kdc
stage_client
echo "==== MIT bins ===="
lab ssh kdc -- 'sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind /usr/sbin/kadmin.local'
lab ssh client2 -- 'sha256sum /usr/bin/kadmin'

echo "==== MIT cell 1 ===="
lab ssh kdc -- 'sudo -n cp -a /var/kerberos/krb5kdc/kdc.conf /var/tmp/az/kdc.conf.orig && sudo -n chmod 644 /var/tmp/az/kdc.conf.orig'
out=$(lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-kdc.py setup' < "$PW")
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q 'kadmin_restart_rc 0' || stop "MIT cell1 setup"
since=$(lab ssh kdc -- 'date +%s' | tr -d '\r')
c1=$(client_probe az-client.py cell1)
printf '%s\n' "$c1"
need "$c1" 'while creating "x@KERBER.TEST"' "MIT cell1 add"
need "$c1" 'Password for "helper@KERBER.TEST" changed.' "MIT cell1 cpw"
klog "$since"
printf '%s\n' "$c1" > "$REC/mit-cell1.txt"

echo "==== MIT cell 5 and acl ===="
lab reset kdc f4-mit-f44
echo "RESET_KDC_CELL5:$?"
stage_kdc
out=$(lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-cells.py setup' < "$PW")
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q 'kadmin_restart_rc 0' || stop "MIT cell5 setup"
printf '%s\n' "$out" | grep -q 'setup_alias aliased' || stop "MIT alias"
since=$(lab ssh kdc -- 'date +%s' | tr -d '\r')
c5=$(lab ssh client2 -- 'python3 ~/field/az/az-cells.py cell5' < "$PW")
printf '%s\n' "$c5"
need "$c5" 'while changing password for "ua@KERBER.TEST"' "MIT cell5"
klog "$since"
printf '%s\n' "$c5" > "$REC/mit-cell5.txt"
since=$(lab ssh kdc -- 'date +%s' | tr -d '\r')
cr=$(lab ssh client2 -- 'python3 ~/field/az/az-cells.py restrict' < "$PW")
printf '%s\n' "$cr"
need "$cr" 'add_changed yes' "MIT restrict create"
gl=$(lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-cells.py cleanup')
printf '%s\n' "$gl"
need "$gl" 'Maximum ticket life: 0 days 01:00:00' "MIT restrict life"
need "$gl" 'Attributes: REQUIRES_PRE_AUTH' "MIT restrict attr"
klog "$since"
printf '%s\n' "$cr" > "$REC/mit-restrict.txt"
printf '%s\n' "$gl" > "$REC/mit-getprinc.txt"

echo "==== ours reset and upgrade ===="
lab reset kdc rust-field-p12-f44
echo "RESET_OURS:$?"
stage_kdc
if [ ! -f "$TAR" ]; then
    git -C "$WT" archive --format=tar --prefix="${CO}/" "$PHASEC_SHA" > "$TAR"
fi
lab ssh kdc -- "rm -rf ~/$CO && mkdir -p ~/$CO && tar -x -C ~" < "$TAR"
echo "UPLOAD_RC:$?"
lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/$CO && make build'"
echo "BUILD_RC:$?"
inst=$(lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/$CO && sudo -n systemctl stop krb5kdc kadmin && sudo -n make install PREFIX=/usr CARGO_TARGET_DIR=\$HOME/$CO/target; echo INSTALL_RC:\$?'" | tr -d '\r')
printf '%s\n' "$inst" | grep -E 'still running|^INSTALL_RC:'
printf '%s\n' "$inst" | grep -q '^INSTALL_RC:0$' || stop "ours install"
lab ssh kdc -- 'sudo -n restorecon -Rv /var/kerberos/krb5kdc >/tmp/restorecon.out; echo RESTORECON_RC:$?; sudo -n systemctl start krb5kdc kadmin; echo START_RC:$?'
lab ssh kdc -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo LISTEN; exit 0; fi; sleep 1; done; echo DOWN; exit 1'
echo "LISTEN_RC:$?"
procs=$(proc_line after-upgrade)
printf '%s\n' "$procs"
printf '%s\n' "$procs" | grep -q 'PROC krb5kdc .* match=true' || stop "krb5kdc proc"
printf '%s\n' "$procs" | grep -q 'PROC kadmind .* match=true' || stop "kadmind proc"
lab ssh kdc -- 'sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind /usr/sbin/kadmin.local /usr/sbin/kdb5_util /usr/sbin/kprop /usr/sbin/kpropd'

echo "==== ours cell 1 ===="
lab ssh kdc -- 'sudo -n cp -a /var/kerberos/krb5kdc/kdc.conf /var/tmp/az/kdc.conf.orig && sudo -n chmod 644 /var/tmp/az/kdc.conf.orig'
lab ssh kdc -- 'sudo -n cp -a /var/kerberos/krb5kdc/kadm5.acl /var/tmp/az/acl.stock && sudo -n chmod 644 /var/tmp/az/acl.stock'
out=$(lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-kdc.py setup' < "$PW")
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q 'kadmin_restart_rc 0' || stop "ours cell1 setup"
since=$(lab ssh kdc -- 'date +%s' | tr -d '\r')
c1=$(client_probe az-client.py cell1)
printf '%s\n' "$c1"
need "$c1" 'while creating "x@KERBER.TEST"' "ours cell1 add"
need "$c1" 'Password for "helper@KERBER.TEST" changed.' "ours cell1 cpw"
klog "$since"
printf '%s\n' "$c1" > "$REC/ours-cell1.txt"
proc_line cell1
lab ssh kdc -- 'sudo -n tar -C /var/kerberos/krb5kdc -cf - principal principal.ok principal.lockout principal.kadm5.lock .k5.KERBER.TEST kadm5.acl' > "$SEC/az-db.tar"
chmod 600 "$SEC/az-db.tar"
lab ssh kdc -- 'sudo -n cat /var/tmp/az/kdc.conf.orig' > "$SEC/az-kdc.conf.orig"
chmod 600 "$SEC/az-kdc.conf.orig"

echo "==== ours cell 5 and acl ===="
lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-kdc.py plugins default restart'
lab ssh kdc -- 'sudo -n cp -a /var/tmp/az/acl.stock /var/kerberos/krb5kdc/kadm5.acl && sudo -n rm -f /var/kerberos/krb5kdc/kadm5.acl.az-bak'
out=$(lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-cells.py setup' < "$PW")
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q 'setup_alias aliased' || stop "ours alias"
since=$(lab ssh kdc -- 'date +%s' | tr -d '\r')
c5=$(lab ssh client2 -- 'python3 ~/field/az/az-cells.py cell5' < "$PW")
printf '%s\n' "$c5"
need "$c5" 'while changing password for "ua@KERBER.TEST"' "ours cell5"
klog "$since"
printf '%s\n' "$c5" > "$REC/ours-cell5.txt"
since=$(lab ssh kdc -- 'date +%s' | tr -d '\r')
cr=$(lab ssh client2 -- 'python3 ~/field/az/az-cells.py restrict' < "$PW")
printf '%s\n' "$cr"
need "$cr" 'add_changed yes' "ours restrict create"
gl=$(lab ssh kdc -- 'sudo -n python3 /var/tmp/az/az-cells.py cleanup')
printf '%s\n' "$gl"
need "$gl" 'Maximum ticket life: 0 days 01:00:00' "ours restrict life"
need "$gl" 'Attributes: REQUIRES_PRE_AUTH' "ours restrict attr"
klog "$since"
proc_line cell5
printf '%s\n' "$gl" > "$REC/ours-getprinc.txt"

echo "==== klldap embed ===="
lab reset klldap f44-base
echo "RESET_KLLDAP:$?"
lab ssh klldap -- 'rm -rf /var/tmp/az && mkdir -p /var/tmp/az && chmod 700 /var/tmp/az'
lab ssh klldap -- 'cat > /var/tmp/az/krb5-embed-realm && chmod 755 /var/tmp/az/krb5-embed-realm' < "$WT/target-rp/release/krb5-embed-realm"
lab ssh klldap -- 'sudo -n install -m 755 /var/tmp/az/krb5-embed-realm /usr/local/bin/krb5-embed-realm && sha256sum /usr/local/bin/krb5-embed-realm'
lab ssh klldap -- 'sudo -n mkdir -p /var/kerberos/krb5kdc && sudo -n tar -C /var/kerberos/krb5kdc -xf - && sudo -n chmod 600 /var/kerberos/krb5kdc/principal.kadm5.lock' < "$SEC/az-db.tar"
lab ssh klldap -- 'sudo -n tee /var/kerberos/krb5kdc/kdc.conf >/dev/null && sudo -n chmod 600 /var/kerberos/krb5kdc/kdc.conf' < "$SEC/az-kdc.conf.orig"
lab ssh klldap -- 'cat > /var/tmp/az/krb5.conf && chmod 644 /var/tmp/az/krb5.conf' << EOF
[libdefaults]
    default_realm = KERBER.TEST
[realms]
    KERBER.TEST = {
        kdc = $FIELD_LAB_NET.30
        admin_server = $FIELD_LAB_NET.30
        kpasswd_server = $FIELD_LAB_NET.30
    }
EOF
lab ssh klldap -- 'grep -c "^    default_realm = KERBER.TEST$" /var/tmp/az/krb5.conf'
lab ssh klldap -- 'sha256sum /var/tmp/az/krb5.conf'
lab ssh klldap -- 'cat > /var/tmp/az/az-kdc.py && chmod 700 /var/tmp/az/az-kdc.py' < "$HDIR/lib/az-kdc.py"
lab ssh client2 -- 'cat > ~/field/az/krb5.conf' << EOF
[libdefaults]
    default_realm = KERBER.TEST
[realms]
    KERBER.TEST = {
        kdc = $FIELD_LAB_NET.30
        admin_server = $FIELD_LAB_NET.30
        kpasswd_server = $FIELD_LAB_NET.30
    }
EOF
embed_up() {
    local mode="$1"
    lab ssh klldap -- "sudo -n python3 /var/tmp/az/az-kdc.py plugins $mode"
rcmd=$(cat << 'EOS'
sudo -n bash -c "if [ -s /var/tmp/az/embed.pid ]; then kill \$(cat /var/tmp/az/embed.pid) 2>/dev/null || true; sleep 1; fi; rm -f /var/tmp/az/embed.log /var/tmp/az/embed.pid"
EOS
)
    lab ssh klldap -- "$rcmd"
    lab ssh klldap -- 'sudo -n bash -c "KRB5_KDC_PROFILE=/var/kerberos/krb5kdc/kdc.conf KRB5_CONFIG=/var/tmp/az/krb5.conf nohup /usr/local/bin/krb5-embed-realm >/var/tmp/az/embed.log 2>&1 & echo \$! > /var/tmp/az/embed.pid"'
    lab ssh klldap -- 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if grep -q serving /var/tmp/az/embed.log 2>/dev/null; then echo EMBED_UP; exit 0; fi; sleep 1; done; echo EMBED_DOWN; tail -n 20 /var/tmp/az/embed.log; exit 1'
}
embed_log() {
    lab ssh klldap -- 'sudo -n python3 -' << 'PY'
import pathlib
pw_path = pathlib.Path("/var/tmp/az/pw")
pw = pw_path.read_text().strip() if pw_path.exists() else ""
log = pathlib.Path("/var/tmp/az/embed.log")
n = 0
if log.exists():
    for line in log.read_text(errors="replace").splitlines()[-40:]:
        if pw and pw in line:
            continue
        low = line.lower()
        if line.startswith("Key:") or "session key" in low:
            continue
        if any(s in low for s in ("privilege", "denied", "unauthorized", "serving", "error", "auth")):
            print("ELOG", line.strip()[:220])
            n += 1
print(f"ELOG_N:{n}")
PY
}
lab ssh klldap -- 'sudo -n systemctl stop krb5kdc kadmin 2>/dev/null || true; echo STOPPED'
echo "==== cell 2 ===="
embed_up default || stop "embed cell2"
rcmd=$(cat << 'EOS'
KRB5_CONFIG=$HOME/field/az/krb5.conf python3 ~/field/az/az-client.py cell2
EOS
)
c2=$(lab ssh client2 -- "$rcmd" < "$PW")
printf '%s\n' "$c2"
need "$c2" 'Principal: guest-a@KERBER.TEST' "cell2 guest"
need "$c2" 'while retrieving "other@KERBER.TEST"' "cell2 other"
embed_log
printf '%s\n' "$c2" > "$REC/cell2.txt"
echo "==== cell 3 bouncer ===="
embed_up default || stop "embed cell3"
rcmd=$(cat << 'EOS'
KRB5_CONFIG=$HOME/field/az/krb5.conf python3 ~/field/az/az-client.py cell3
EOS
)
c3=$(lab ssh client2 -- "$rcmd" < "$PW")
printf '%s\n' "$c3"
need "$c3" 'while modifying "deny-x@KERBER.TEST"' "cell3 deny"
embed_log
echo "==== cell 3 disable ===="
embed_up nobounce || stop "embed cell3 off"
rcmd=$(cat << 'EOS'
KRB5_CONFIG=$HOME/field/az/krb5.conf python3 ~/field/az/az-client.py cell3
EOS
)
c3b=$(lab ssh client2 -- "$rcmd" < "$PW")
printf '%s\n' "$c3b"
need "$c3b" 'Principal "deny-x@KERBER.TEST" modified.' "cell3 allow"
embed_log
printf '%s\n' "$c3" > "$REC/cell3.txt"
printf '%s\n' "$c3b" > "$REC/cell3b.txt"
echo "==== cell 4 ===="
embed_up bouncer-self || stop "embed cell4"
rcmd=$(cat << 'EOS'
KRB5_CONFIG=$HOME/field/az/krb5.conf python3 ~/field/az/az-client.py cell4
EOS
)
c4=$(lab ssh client2 -- "$rcmd" < "$PW")
printf '%s\n' "$c4"
need "$c4" 'while retrieving "anyone@KERBER.TEST"' "cell4"
embed_log
printf '%s\n' "$c4" > "$REC/cell4.txt"
rcmd=$(cat << 'EOS'
sudo -n bash -c "if [ -s /var/tmp/az/embed.pid ]; then kill \$(cat /var/tmp/az/embed.pid) 2>/dev/null || true; fi"
EOS
)
lab ssh klldap -- "$rcmd"
sha256sum "$WT/target-rp/release/krb5-embed-realm"
echo "CELL6: not run. MIT makes kadmin/* DISALLOW_TGT_BASED, so no stock MIT client reaches kadmind cross-realm."
echo "AZ_PASS"
echo "AZ_END"
