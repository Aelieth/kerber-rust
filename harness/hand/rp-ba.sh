#!/bin/bash
# BA. MIT first on klldap. Does not reset kdc.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC FIELD_LAB_NET
WT=$HAND_WT
export SEC
REC=$HAND_REC/$PHASEC_SHA/ba
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
BIN=${HAND_SHIP:-$WT/target-rp/release}/krb5-embed-realm
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")  # outside the record
mkdir -p "$REC" "$SEC"
chmod 700 "$SEC"
echo "REC:$REC"
echo "COMMIT:$(git -C "$WT" rev-parse HEAD)"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
lab() { bash "$LAB" "$@"; }
sha256sum "$BIN"
cleanup_pw() {
    exec 8>&- || true
    rm -f "$SEC/ba-master" "$SEC/ba-mit.keytab" "$SEC/ba-ours.keytab"
    rm -rf "$SEC"
    lab ssh client2 -- 'rm -rf /var/tmp/ba' >/dev/null 2>&1 || true
    lab ssh klldap -- 'sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; sudo pkill -9 krb5-embed-realm || true; rm -rf /var/tmp/ba' >/dev/null 2>&1 || true
    lab reset klldap f44-docker
    echo "RESTORE_KLLDAP:$?"
    lab down klldap || true
    lab reset client2 rust-ssh-f44
    echo "RESTORE_C2:$?"
    lab down client2 || true
}
trap cleanup_pw EXIT
python3 - << 'PY'
import os, pathlib, secrets
p = pathlib.Path(os.environ["SEC"] + "/ba-master")
master = secrets.token_hex(12)
p.write_text(master + "\n" + master + "\n")
p.chmod(0o600)
print("MASTER_READY")
PY
echo "==== reset ===="
lab reset klldap f44-base
echo "RESET_KLLDAP:$?"
lab reset client2 mit-kit-fc44
echo "RESET_C2:$?"
exec 8>>"$LAB_HOME/state/lab.lock"
flock -n 8 || { echo LOCK_BUSY; echo "BA_END"; exit 1; }
if ! lab ssh klldap -- 'rpm -q krb5-server >/dev/null'; then
    lab ssh klldap -- 'sudo dnf install -y krb5-server krb5-workstation'
    echo "DNF_K:$?"
fi
if ! lab ssh client2 -- 'command -v kinit >/dev/null && command -v kadmin >/dev/null'; then
    lab ssh client2 -- 'sudo dnf install -y krb5-workstation'
    echo "DNF_C:$?"
fi
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
    }
EOF
}
lab ssh client2 -- 'rm -rf /var/tmp/ba && mkdir -p /var/tmp/ba && chmod 700 /var/tmp/ba'
lab ssh client2 -- 'cat > /var/tmp/ba/embed.conf && chmod 644 /var/tmp/ba/embed.conf' <<EOF
[libdefaults]
    default_realm = EMBED.KERBER.TEST
    dns_lookup_kdc = false
    rdns = false

[realms]
    EMBED.KERBER.TEST = {
        kdc = $FIELD_LAB_NET.30
        admin_server = $FIELD_LAB_NET.30
    }
EOF
# The existing client reads ~/field/embed.conf. Point it there.
lab ssh client2 -- 'rm -rf ~/field && mkdir -p ~/field && cp /var/tmp/ba/embed.conf ~/field/embed.conf'
lab ssh client2 -- 'cat > /var/tmp/ba/client.py && chmod 700 /var/tmp/ba/client.py' < "$HDIR/lib/ba2-client.py"
lab ssh klldap -- 'rm -rf /var/tmp/ba && mkdir -p /var/tmp/ba && chmod 700 /var/tmp/ba'
lab ssh klldap -- 'cat > /var/tmp/ba/master && chmod 600 /var/tmp/ba/master' < "$SEC/ba-master"
lab ssh klldap -- 'sudo systemctl disable --now krb5kdc kadmin 2>/dev/null || true; sudo systemctl mask krb5kdc kadmin 2>/dev/null || true; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; echo STOPPED'
lab ssh klldap -- 'sudo rm -rf /var/kerberos/embed-mit /var/kerberos/embed-ours /var/kerberos/embed-crash'
write_profiles /var/kerberos/embed-mit
write_profiles /var/kerberos/embed-ours
write_profiles /var/kerberos/embed-crash
echo "==== MIT create ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/embed-mit/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-mit/krb5.conf
/usr/sbin/kdb5_util -r EMBED.KERBER.TEST create -s < /var/tmp/ba/master
echo "CREATE_RC:$?"
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'addprinc -randkey admin/admin'
echo "ADDADMIN_RC:$?"
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'ktadd -norandkey -k /var/kerberos/embed-mit/admin.keytab admin/admin' | awk '/^Entry for principal/{print}'
echo "KTADD_RC:${PIPESTATUS[0]}"
EOS
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
export KRB5_KDC_PROFILE=/var/kerberos/embed-mit/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-mit/krb5.conf
nohup /usr/sbin/krb5kdc -n >/var/tmp/ba/mit-kdc.log 2>&1 &
echo $! > /var/tmp/ba/mit-kdc.pid
nohup /usr/sbin/kadmind -nofork >/var/tmp/ba/mit-kadm.log 2>&1 &
echo $! > /var/tmp/ba/mit-kadm.pid
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -uln | grep -q ':88' && ss -ltn | grep -q ':749'; then echo MIT_LISTEN; exit 0; fi
    sleep 1
done
echo MIT_DOWN
exit 1
EOS
echo "MIT_SERVE:$?"
lab ssh klldap -- 'sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind'
lab ssh klldap -- 'sudo cat /var/kerberos/embed-mit/admin.keytab' > "$SEC/ba-mit.keytab"
chmod 600 "$SEC/ba-mit.keytab"
lab ssh client2 -- 'cat > /var/tmp/ba/mit.keytab && chmod 600 /var/tmp/ba/mit.keytab' < "$SEC/ba-mit.keytab"
echo "==== MIT cells ===="
lab ssh client2 -- 'python3 /var/tmp/ba/client.py getprinc /var/tmp/ba/mit.keytab' | tee "$REC/mit-getprinc.txt"
lab ssh client2 -- 'python3 /var/tmp/ba/client.py kinit /var/tmp/ba/mit.keytab'
lab ssh client2 -- 'python3 /var/tmp/ba/client.py addprinc /var/tmp/ba/mit.keytab'
stop_cmd=$(cat << 'EOS'
sudo kill "$(cat /var/tmp/ba/mit-kdc.pid)" "$(cat /var/tmp/ba/mit-kadm.pid)" 2>/dev/null || true; sleep 1; echo MIT_STOPPED
EOS
)
lab ssh klldap -- "$stop_cmd"
echo "==== ours bootstrap ===="
lab ssh klldap -- 'cat > /var/tmp/ba/krb5-embed-realm && chmod 755 /var/tmp/ba/krb5-embed-realm' < "$BIN"
lab ssh klldap -- 'sha256sum /var/tmp/ba/krb5-embed-realm'
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/embed-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-ours/krb5.conf
/var/tmp/ba/krb5-embed-realm --bootstrap-only > /var/tmp/ba/boot1.log 2>&1
echo "BOOT1_RC:$?"
grep -E 'created |serving ' /var/tmp/ba/boot1.log | head -5
EOS
lab ssh klldap -- 'sudo cat /var/kerberos/embed-ours/admin.keytab' > "$SEC/ba-ours.keytab"
chmod 600 "$SEC/ba-ours.keytab"
lab ssh client2 -- 'cat > /var/tmp/ba/ours.keytab && chmod 600 /var/tmp/ba/ours.keytab' < "$SEC/ba-ours.keytab"
# Serve so client2 can talk to it.
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
export KRB5_KDC_PROFILE=/var/kerberos/embed-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-ours/krb5.conf
nohup /var/tmp/ba/krb5-embed-realm >/var/tmp/ba/serve.log 2>&1 &
echo $! > /var/tmp/ba/serve.pid
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -ltn | grep -q ':88 ' && ss -ltn | grep -q ':749 '; then echo OURS_LISTEN; exit 0; fi
    sleep 1
done
echo OURS_DOWN
exit 1
EOS
echo "OURS_SERVE:$?"
lab ssh klldap -- 'sudo python3 -' << 'PY'
import hashlib, pathlib
pid = pathlib.Path("/var/tmp/ba/serve.pid").read_text().strip()
exe = hashlib.sha256(pathlib.Path(f"/proc/{pid}/exe").read_bytes()).hexdigest()
disk = hashlib.sha256(pathlib.Path("/var/tmp/ba/krb5-embed-realm").read_bytes()).hexdigest()
print(f"PROC embed pid={pid} exe={exe} disk={disk} match={str(exe==disk).lower()}")
PY
echo "==== ours cells ===="
lab ssh client2 -- 'python3 /var/tmp/ba/client.py getprinc /var/tmp/ba/ours.keytab' | tee "$REC/ours-getprinc.txt"
lab ssh client2 -- 'python3 /var/tmp/ba/client.py kinit /var/tmp/ba/ours.keytab'
lab ssh client2 -- 'python3 /var/tmp/ba/client.py addprinc /var/tmp/ba/ours.keytab'
python3 - << PY
from pathlib import Path
def rows(path):
    skip = ("Last ", "Modifier:", "Expiration", "Password expiration", "Number of failed", "Number of keys:")
    out = []
    for line in Path(path).read_text(errors="replace").splitlines():
        body = line.split(" ", 2)[-1] if line.startswith("getprinc ") else line
        if any(body.startswith(s) or s in body for s in skip):
            continue
        out.append(line)
    return out
mit = rows(Path("$REC/mit-getprinc.txt"))
ours = rows(Path("$REC/ours-getprinc.txt"))
print("FIELD_ROWS", len(mit), len(ours))
if mit == ours:
    print("FIELDS_EQUAL")
else:
    print("FIELDS_DIFFER")
    for line in mit:
        if line not in ours:
            print("MIT_ONLY", line[:180])
    for line in ours:
        if line not in mit:
            print("OURS_ONLY", line[:180])
PY
echo "==== cell 4 restarts ===="
kill_cmd=$(cat << 'EOS'
sudo kill "$(cat /var/tmp/ba/serve.pid)" 2>/dev/null || true; sleep 1
EOS
)
lab ssh klldap -- "$kill_cmd"
for n in 2 3; do
    lab ssh klldap -- "sudo -n bash -s" <<EOS
export KRB5_KDC_PROFILE=/var/kerberos/embed-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-ours/krb5.conf
/var/tmp/ba/krb5-embed-realm --bootstrap-only > /var/tmp/ba/boot$n.log 2>&1
echo BOOT${n}_RC:\$?
grep created /var/tmp/ba/boot$n.log | head -3
EOS
done
echo "==== cell 4 server up ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
export KRB5_KDC_PROFILE=/var/kerberos/embed-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-ours/krb5.conf
if ! ss -ltn | grep -q ':88 '; then
  nohup /var/tmp/ba/krb5-embed-realm >/var/tmp/ba/serve2.log 2>&1 &
  echo $! > /var/tmp/ba/serve.pid
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ss -ltn | grep -q ':88 ' && ss -ltn | grep -q ':749 '; then echo OURS_LISTEN; exit 0; fi
  sleep 1
done
echo OURS_DOWN
exit 1
EOS
echo "CELL4_SERVE:$?"
lab ssh client2 -- 'python3 /var/tmp/ba/client.py getprinc /var/tmp/ba/ours.keytab' | tee "$REC/ours-getprinc2.txt"
lab ssh client2 -- 'python3 /var/tmp/ba/client.py kinit /var/tmp/ba/ours.keytab'
python3 - << PY
from pathlib import Path
rec = Path("$REC")
def kv(path):
    return [ln for ln in Path(path).read_text(errors="replace").splitlines() if " keys kvno " in ln]
a, b = kv(rec/"ours-getprinc.txt"), kv(rec/"ours-getprinc2.txt")
print("KVNO_SAME" if a == b else "KVNO_CHANGED")
for ln in a:
    if ln not in b:
        print("KVNO_BEFORE", ln[:160])
for ln in b:
    if ln not in a:
        print("KVNO_AFTER", ln[:160])
PY
echo "==== cell 5 ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
ok=0
bad=0
export KRB5_KDC_PROFILE=/var/kerberos/embed-crash/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-crash/krb5.conf
for i in $(seq 1 50); do
    /var/tmp/ba/krb5-embed-realm >/var/tmp/ba/crash-start.log 2>&1 &
    pid=$!
    python3 -c 'import random,time; time.sleep(random.uniform(0.01,0.2))'
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if timeout 30 /var/tmp/ba/krb5-embed-realm --bootstrap-only >/var/tmp/ba/crash-open.log 2>&1; then
        ok=$((ok + 1))
    else
        bad=$((bad + 1))
        echo "CRASH_FAIL_AT:$i"
    fi
done
echo "CRASH_OK:$ok"
echo "CRASH_BAD:$bad"
if [ -f /var/kerberos/embed-crash/principal ]; then echo DB_PRESENT:1; else echo DB_PRESENT:0; fi
tail -n 2 /var/tmp/ba/crash-open.log
EOS
echo "BA_END"
exit 0
