#!/bin/bash
# A4 and A5 on klldap. Does not reset or shut down kdc.
# A4 is SS cells 1-4. A5 is the embed trickle. MIT first.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC FIELD_LAB_NET
WT=$HAND_WT
export REC SEC
REC=$HAND_REC/$PHASEC_SHA/al-a45
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
BIN=${HAND_SHIP:-$WT/target-rp/release}/krb5-embed-realm
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")  # outside the record
mkdir -p "$REC" "$SEC"
chmod 700 "$SEC"
echo "REC:$REC"
echo "TREE:$PHASEC_SHA write-tree:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
echo "BIN_DIR:$(dirname "$BIN")"
lab() { bash "$LAB" "$@"; }
if [ ! -x "$BIN" ]; then
    echo "MISSING_BIN"
    echo "AL_A45_END"
    exit 1
fi
sha256sum "$BIN"
python3 - << 'PY'
import os, pathlib, secrets
d = pathlib.Path(os.environ["SEC"])
for name in ("ss3-pw1", "ss3-pw2", "ss3-pw3", "ss3-bob"):
    p = d / name
    p.write_text(secrets.token_hex(12) + "\n")
    p.chmod(0o600)
master = secrets.token_hex(12)
p = d / "ss3-master"
p.write_text(master + "\n" + master + "\n")
p.chmod(0o600)
print("PW_FILES_READY")
PY
cleanup_pw() {
    flock -u 8 2>/dev/null || true
    exec 8>&-
    python3 - << 'PY'
import os
from pathlib import Path
log = Path(os.environ["REC"]) / "driver.log"
text = log.read_text(errors="replace") if log.exists() else ""
hit = 0
for name in ("ss3-pw1", "ss3-pw2", "ss3-pw3", "ss3-bob", "ss3-master"):
    p = Path(os.environ["SEC"]) / name
    if not p.exists():
        continue
    for line in p.read_text(errors="replace").splitlines():
        if line and line in text:
            hit += 1
    p.unlink()
print(f"SECRET_SCAN_HITS:{hit}")
PY
    rm -f "$SEC/ss3-admin.keytab"
    rm -rf "$SEC"
    lab ssh client2 -- 'rm -rf /var/tmp/ss3 /var/tmp/al3' >/dev/null 2>&1 || true
    lab ssh klldap -- 'rm -rf /var/tmp/ss3 /var/tmp/al3' >/dev/null 2>&1 || true
    lab reset klldap f44-docker
    echo "RESTORE_KLLDAP:$?"
    lab down klldap || true
    lab reset client2 rust-ssh-f44
    echo "RESTORE_C2:$?"
    lab down client2 || true
}
trap cleanup_pw EXIT
echo "==== reset klldap client2 ===="
lab reset klldap f44-base
echo "RESET_KLLDAP:$?"
lab reset client2 mit-kit-fc44
echo "RESET_C2:$?"
exec 8>>"$LAB_HOME/state/lab.lock"
flock -n 8 || { echo LOCK_BUSY; echo "AL_A45_END"; exit 1; }
if ! lab ssh klldap -- 'rpm -q krb5-server >/dev/null'; then
    lab ssh klldap -- 'sudo dnf install -y krb5-server krb5-workstation'
    echo "DNF_K:$?"
fi
if ! lab ssh client2 -- 'command -v kpasswd >/dev/null && command -v kadmin >/dev/null'; then
    lab ssh client2 -- 'sudo dnf install -y krb5-workstation'
    echo "DNF_C:$?"
fi
lab ssh klldap -- 'rpm -q krb5-server; sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind'
write_profiles() {
    local root="$1"
    lab ssh klldap -- "sudo mkdir -p '$root' && sudo tee '$root/kdc.conf' >/dev/null" <<EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    EMBED.KERBER.TEST = {
        database_name = $root/principal
        key_stash_file = $root/.k5.EMBED.KERBER.TEST
        acl_file = $root/kadm5.acl
        admin_keytab = $root/kadm5.keytab
        kadmind_port = 749
        kpasswd_port = 464
        master_key_type = aes256-cts-hmac-sha1-96
        max_life = 1d 0h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
    }
EOF
    lab ssh klldap -- "sudo tee '$root/kadm5.acl' >/dev/null" <<'EOF'
admin/admin@EMBED.KERBER.TEST *
EOF
    lab ssh klldap -- "sudo tee '$root/krb5.conf' >/dev/null" <<'EOF'
[libdefaults]
    default_realm = EMBED.KERBER.TEST
    dns_lookup_kdc = false
    rdns = false

[realms]
    EMBED.KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
        kpasswd_server = 127.0.0.1
    }
EOF
}
lab ssh client2 -- 'rm -rf /var/tmp/ss3 && mkdir -p /var/tmp/ss3 && chmod 700 /var/tmp/ss3'
lab ssh client2 -- 'cat > /var/tmp/ss3/embed.conf && chmod 644 /var/tmp/ss3/embed.conf' <<EOF
[libdefaults]
    default_realm = EMBED.KERBER.TEST
    dns_lookup_kdc = false
    rdns = false

[realms]
    EMBED.KERBER.TEST = {
        kdc = $FIELD_LAB_NET.30
        admin_server = $FIELD_LAB_NET.30
        kpasswd_server = $FIELD_LAB_NET.30
    }
EOF
lab ssh client2 -- 'cat > /var/tmp/ss3/client.py && chmod 700 /var/tmp/ss3/client.py' < "$HDIR/lib/ss3-client.py"
for name in pw1 pw2 pw3; do
    lab ssh client2 -- "cat > /var/tmp/ss3/$name && chmod 600 /var/tmp/ss3/$name" < "$SEC/ss3-$name"
done
lab ssh klldap -- 'rm -rf /var/tmp/ss3 && mkdir -p /var/tmp/ss3'
lab ssh klldap -- 'cat > /var/tmp/ss3/master && chmod 600 /var/tmp/ss3/master' < "$SEC/ss3-master"
lab ssh klldap -- 'sudo systemctl disable --now krb5kdc kadmin 2>/dev/null || true; sudo systemctl mask krb5kdc kadmin 2>/dev/null || true; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; echo STOPPED'
lab ssh klldap -- 'sudo rm -rf /var/kerberos/embed-mit /var/kerberos/embed-ours'
write_profiles /var/kerberos/embed-mit
write_profiles /var/kerberos/embed-ours
echo "==== MIT create ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/embed-mit/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-mit/krb5.conf
/usr/sbin/kdb5_util -r EMBED.KERBER.TEST create -s < /var/tmp/ss3/master
echo "CREATE_RC:$?"
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'addprinc -randkey admin/admin'
echo "ADDADMIN_RC:$?"
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'ktadd -k /var/kerberos/embed-mit/admin.keytab -norandkey admin/admin' | awk '/^Entry for principal/{print}'
echo "KTADD_ADMIN_RC:${PIPESTATUS[0]}"
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'ktadd -k /var/kerberos/embed-mit/kadm5.keytab -norandkey kadmin/admin' | awk '/^Entry for principal/{print}'
echo "KTADD_KADMIN_RC:${PIPESTATUS[0]}"
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'ktadd -k /var/kerberos/embed-mit/kadm5.keytab -norandkey kadmin/changepw' | awk '/^Entry for principal/{print}'
echo "KTADD_CPW_RC:${PIPESTATUS[0]}"
EOS
echo "==== MIT serve ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/embed-mit/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-mit/krb5.conf
nohup /usr/sbin/krb5kdc -n >/var/tmp/ss3-mit-kdc.log 2>&1 &
echo $! > /var/tmp/ss3-mit-kdc.pid
nohup /usr/sbin/kadmind -nofork >/var/tmp/ss3-mit-kadm.log 2>&1 &
echo $! > /var/tmp/ss3-mit-kadm.pid
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -uln | grep -q ':88' && ss -ltn | grep -q ':749'; then
        echo MIT_LISTEN
        exit 0
    fi
    sleep 1
done
echo MIT_DOWN
exit 1
EOS
echo "MIT_SERVE:$?"
lab ssh klldap -- 'sudo python3 -' << 'PY'
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
lab ssh klldap -- 'sudo cat /var/kerberos/embed-mit/admin.keytab' > "$SEC/ss3-admin.keytab"
chmod 600 "$SEC/ss3-admin.keytab"
lab ssh client2 -- 'cat > /var/tmp/ss3/admin.keytab && chmod 600 /var/tmp/ss3/admin.keytab' < "$SEC/ss3-admin.keytab"
echo "==== MIT A4 ===="
for c in 1 2 3 4; do
    echo "==== MIT cell $c ===="
    lab ssh client2 -- "python3 /var/tmp/ss3/client.py $c"
done
echo "==== MIT A5 ===="
lab ssh client2 -- 'cat > /var/tmp/ss3/bob && chmod 600 /var/tmp/ss3/bob' < "$SEC/ss3-bob"
lab ssh client2 -- 'python3 -' << 'PY'
import os, subprocess
from pathlib import Path
pw = Path("/var/tmp/ss3/bob").read_text().strip()
env = os.environ.copy()
env["KRB5_CONFIG"] = "/var/tmp/ss3/embed.conf"
got = subprocess.run(["/usr/bin/kadmin","-k","-t","/var/tmp/ss3/admin.keytab","-p","admin/admin@EMBED.KERBER.TEST","-r","EMBED.KERBER.TEST","-q", f"addprinc -pw {pw} bob"], env=env, capture_output=True, text=True)
print(f"ADD_BOB rc={got.returncode}")
PY
lab ssh klldap -- 'rm -rf /var/tmp/al3 && mkdir -p /var/tmp/al3 && chmod 700 /var/tmp/al3'
lab ssh klldap -- 'cat > /var/tmp/al3/trickle.py && chmod 700 /var/tmp/al3/trickle.py' < "$HDIR/lib/al3-trickle.py"
lab ssh client2 -- 'rm -rf /var/tmp/al3 && mkdir -p /var/tmp/al3 && chmod 700 /var/tmp/al3'
lab ssh client2 -- 'cat > /var/tmp/al3/bob.pw && chmod 600 /var/tmp/al3/bob.pw' < "$SEC/ss3-bob"
lab ssh client2 -- 'cat > /var/tmp/al3/bob-new.pw && chmod 600 /var/tmp/al3/bob-new.pw' < "$SEC/ss3-pw1"
lab ssh client2 -- 'cat > /var/tmp/al3/guest.py && chmod 700 /var/tmp/al3/guest.py' < "$HDIR/lib/rp-trickle-guest.py"
trickle_cmd=$(cat << 'EOS'
nohup python3 /var/tmp/al3/trickle.py > /var/tmp/al3/trickle.out 2>&1 & echo $! > /var/tmp/al3/trickle.pid; echo TRICKLE_PID:$(cat /var/tmp/al3/trickle.pid)
EOS
)
trickle_wait=$(cat << 'EOS'
while kill -0 "$(cat /var/tmp/al3/trickle.pid)" 2>/dev/null; do sleep 1; done; cat /var/tmp/al3/trickle.out
EOS
)
lab ssh klldap -- "$trickle_cmd"
sleep 2
lab ssh client2 -- 'KRB5_CONFIG=/var/tmp/ss3/embed.conf python3 /var/tmp/al3/guest.py kpasswd'
lab ssh klldap -- "$trickle_wait"
stop_cmd=$(cat << 'EOS'
sudo kill "$(cat /var/tmp/ss3-mit-kdc.pid)" "$(cat /var/tmp/ss3-mit-kadm.pid)" 2>/dev/null || true; sleep 1; echo MIT_STOPPED
EOS
)
lab ssh klldap -- "$stop_cmd"
echo "==== ours serve ===="
lab ssh klldap -- 'cat > /var/tmp/ss3/krb5-embed-realm && chmod 755 /var/tmp/ss3/krb5-embed-realm' < "$BIN"
lab ssh klldap -- 'sha256sum /var/tmp/ss3/krb5-embed-realm'
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/embed-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-ours/krb5.conf
nohup /var/tmp/ss3/krb5-embed-realm >/var/tmp/ss3-embed.log 2>&1 &
echo $! > /var/tmp/ss3-embed.pid
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q 'serving EMBED.KERBER.TEST' /var/tmp/ss3-embed.log && ss -ltn | grep -q ':88' && ss -ltn | grep -q ':749'; then
        echo OURS_LISTEN
        exit 0
    fi
    sleep 1
done
echo OURS_DOWN
exit 1
EOS
echo "OURS_SERVE:$?"
lab ssh klldap -- 'sudo python3 -' << 'PY'
import hashlib, pathlib
pid = pathlib.Path("/var/tmp/ss3-embed.pid").read_text().strip()
exe = pathlib.Path(f"/proc/{pid}/exe").read_bytes()
disk = pathlib.Path("/var/tmp/ss3/krb5-embed-realm").read_bytes()
import hashlib as h
eh = h.sha256(exe).hexdigest()
dh = h.sha256(disk).hexdigest()
print(f"PROC embed pid={pid} exe={eh} disk={dh} match={str(eh==dh).lower()}")
PY
lab ssh klldap -- 'sudo cat /var/kerberos/embed-ours/admin.keytab' > "$SEC/ss3-admin.keytab"
chmod 600 "$SEC/ss3-admin.keytab"
lab ssh client2 -- 'cat > /var/tmp/ss3/admin.keytab && chmod 600 /var/tmp/ss3/admin.keytab' < "$SEC/ss3-admin.keytab"
echo "==== ours A4 ===="
for c in 1 2 3 4; do
    echo "==== ours cell $c ===="
    lab ssh client2 -- "python3 /var/tmp/ss3/client.py $c"
done
echo "==== ours A5 ===="
lab ssh client2 -- 'python3 -' << 'PY'
import os, subprocess, time
from pathlib import Path
pw = Path("/var/tmp/ss3/bob").read_text().strip()
env = os.environ.copy()
env["KRB5_CONFIG"] = "/var/tmp/ss3/embed.conf"
got = subprocess.run(["/usr/bin/kadmin","-k","-t","/var/tmp/ss3/admin.keytab","-p","admin/admin@EMBED.KERBER.TEST","-r","EMBED.KERBER.TEST","-q", f"addprinc -pw {pw} bob"], env=env, capture_output=True, text=True)
print(f"ADD_BOB rc={got.returncode}")
PY
lab ssh klldap -- 'rm -rf /var/tmp/al3 && mkdir -p /var/tmp/al3'
lab ssh klldap -- 'cat > /var/tmp/al3/trickle.py && chmod 700 /var/tmp/al3/trickle.py' < "$HDIR/lib/al3-trickle.py"
lab ssh klldap -- "$trickle_cmd"
sleep 2
lab ssh client2 -- 'python3 -' << 'PY'
import os, subprocess, time
env = os.environ.copy()
env["KRB5_CONFIG"] = "/var/tmp/ss3/embed.conf"
t0 = time.time()
try:
    got = subprocess.run(["/usr/bin/kadmin","-k","-t","/var/tmp/ss3/admin.keytab","-p","admin/admin@EMBED.KERBER.TEST","-r","EMBED.KERBER.TEST","-q","getprinc bob"], env=env, capture_output=True, text=True, timeout=55)
    rc = got.returncode
except subprocess.TimeoutExpired:
    rc = 124
print(f"GETPRINC rc={rc} elapsed={time.time()-t0:.1f}")
PY
lab ssh client2 -- 'KRB5_CONFIG=/var/tmp/ss3/embed.conf python3 /var/tmp/al3/guest.py kpasswd'
lab ssh klldap -- "$trickle_wait"
echo "AL_A45_END"
exit 0
