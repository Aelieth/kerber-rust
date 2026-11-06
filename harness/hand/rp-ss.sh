#!/usr/bin/env bash
# Embed realm cells 1, 2, 3, 6, 4, 7. MIT first, then the release example. Cell 5 not run.
# Cell 1's reload-store clause is not graded. The director has not picked it.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC FIELD_LAB_NET
WT=$HAND_WT
export REC SEC
REC=$HAND_REC/$PHASEC_SHA/ss
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
exec 9>&-
LAB=$WT/harness/field/lab.sh
REF=$PHASEC_SHA
LOG=$REC/driver.log
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")  # outside the record
mkdir -p "$SEC"
chmod 700 "$SEC"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
echo "==== $(date -u +%FT%TZ) ss3 pid $$ ===="
lab() { ( cd "$LAB_HOME" && bash "$LAB" "$@" ); }
if command -v virsh >/dev/null 2>&1; then
    vsh() { virsh -c qemu:///system "$@"; }
else
    vsh() { (cd "$LAB_HOME" && distrobox-host-exec virsh -c qemu:///system "$@"); }
fi
got=$(git -C "$WT" rev-parse HEAD)
tree=$(git -C "$WT" rev-parse 'HEAD^{tree}')
echo "REF: $got"
echo "write-tree: $tree"
if [ "$got" != "$REF" ]; then
    echo "FINAL: SS3_ABORT"
    exit 1
fi
BIN=${HAND_SHIP:-$WT/target-rp/release}/krb5-embed-realm
if [ ! -x "$BIN" ]; then
    echo "MISSING embed"
    echo "FINAL: SS3_ABORT"
    exit 1
fi
sha256sum "$BIN"
python3 - <<'PY'
import os, pathlib, secrets
d = pathlib.Path(os.environ["SEC"])
for name in ("pw1", "pw2", "pw3"):
    p = d / f"ss3-{name}"
    p.write_text(secrets.token_hex(12) + "\n")
    p.chmod(0o600)
master = secrets.token_hex(12)
p = d / "ss3-master"
p.write_text(master + "\n" + master + "\n")
p.chmod(0o600)
print("PW_FILES_READY")
PY
restore() {
    python3 - <<'PY'
import os
from pathlib import Path
log = Path(os.environ["REC"]) / "driver.log"
text = log.read_text(errors="replace") if log.exists() else ""
hit = 0
for name in ("ss3-pw1", "ss3-pw2", "ss3-pw3", "ss3-master"):
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
    lab ssh klldap -- 'sudo pkill -TERM -f /var/tmp/ss3/krb5-embed-realm || true; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true' || true
    lab ssh client2 -- 'rm -rf /var/tmp/ss3' || true
    echo "==== restore ===="
    lab down klldap client2
    echo "DOWN_RC:$?"
    lab reset klldap f44-docker
    echo "RESET_KLLDAP_RC:$?"
    lab down klldap
    echo "DOWN_KLLDAP_RC:$?"
    lab reset client2 rust-ssh-f44
    echo "RESET_CLIENT2_RC:$?"
    lab down client2
    echo "DOWN_CLIENT2_RC:$?"
    cd "$LAB_HOME" || return
    for d in kerber-klldap kerber-client2 kerber-kdc kerber-kdc2; do
        printf '%s: ' "$d"
        vsh domstate "$d"
        printf '%s snap: ' "$d"
        vsh snapshot-current "$d" --name
    done
}
echo "==== up ===="
lab reset klldap f44-docker
echo "RESET_KLLDAP_UP:$?"
lab reset client2 mit-nfs-shares-fc44
echo "RESET_CLIENT2_UP:$?"
lab up klldap client2
echo "UP_RC:$?"
trap restore EXIT
lab ssh klldap -- 'sha256sum /etc/krb5.conf; rpm -q krb5-server || true'
lab ssh client2 -- 'sha256sum /etc/krb5.conf; command -v kinit; command -v kadmin; command -v kpasswd'
if ! lab ssh klldap -- 'rpm -q krb5-server >/dev/null'; then
    lab ssh klldap -- 'sudo dnf install -y krb5-server krb5-workstation'
    echo "DNF_RC:$?"
fi
lab ssh klldap -- 'rpm -q krb5-server krb5-workstation; command -v kinit'
if ! lab ssh client2 -- 'command -v kpasswd >/dev/null && command -v kadmin >/dev/null'; then
    lab ssh client2 -- 'sudo dnf install -y krb5-workstation'
    echo "DNF_CLIENT_RC:$?"
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
/usr/sbin/kadmin.local -r EMBED.KERBER.TEST -q 'ktadd -k /var/kerberos/embed-mit/admin.keytab -norandkey admin/admin' | awk '/^Entry for principal/{print} /^Principal /{print}'
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
EOS
lab ssh klldap -- 'sudo cat /var/kerberos/embed-mit/admin.keytab' > "$SEC/ss3-admin.keytab"
chmod 600 "$SEC/ss3-admin.keytab"
lab ssh client2 -- 'cat > /var/tmp/ss3/admin.keytab && chmod 600 /var/tmp/ss3/admin.keytab' < "$SEC/ss3-admin.keytab"
echo "==== MIT cells ===="
for c in 1 2 3 6 4; do
    echo "==== MIT cell $c ===="
    lab ssh client2 -- "python3 /var/tmp/ss3/client.py $c"
done
echo "==== MIT list before restart ===="
lab ssh client2 -- 'python3 /var/tmp/ss3/client.py 7'
echo "==== MIT restart ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
kill "$(cat /var/tmp/ss3-mit-kdc.pid)" "$(cat /var/tmp/ss3-mit-kadm.pid)" 2>/dev/null || true
sleep 1
export KRB5_KDC_PROFILE=/var/kerberos/embed-mit/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-mit/krb5.conf
nohup /usr/sbin/krb5kdc -n >/var/tmp/ss3-mit-kdc.log 2>&1 &
echo $! > /var/tmp/ss3-mit-kdc.pid
nohup /usr/sbin/kadmind -nofork >/var/tmp/ss3-mit-kadm.log 2>&1 &
echo $! > /var/tmp/ss3-mit-kadm.pid
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ss -uln | grep -q ':88' && ss -ltn | grep -q ':749'; then
        echo MIT_RESTART_LISTEN
        exit 0
    fi
    sleep 1
done
echo MIT_RESTART_DOWN
EOS
echo "==== MIT cell 7 ===="
lab ssh client2 -- 'python3 /var/tmp/ss3/client.py 7'
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
EOS
lab ssh klldap -- 'sudo cat /var/kerberos/embed-ours/admin.keytab' > "$SEC/ss3-admin.keytab"
chmod 600 "$SEC/ss3-admin.keytab"
lab ssh client2 -- 'cat > /var/tmp/ss3/admin.keytab && chmod 600 /var/tmp/ss3/admin.keytab' < "$SEC/ss3-admin.keytab"
echo "==== ours cells ===="
for c in 1 2 3 6 4; do
    echo "==== ours cell $c ===="
    lab ssh client2 -- "python3 /var/tmp/ss3/client.py $c"
done
echo "==== ours reload count at info ===="
reload_cmd=$(cat << 'EOS'
n=$(sudo grep -a -c "reload store" /var/tmp/ss3-embed.log || true); echo RELOAD_INFO_COUNT:$n
EOS
)
lab ssh klldap -- "$reload_cmd"
echo "==== ours list before restart ===="
lab ssh client2 -- 'python3 /var/tmp/ss3/client.py 7'
echo "==== ours restart ===="
lab ssh klldap -- 'sudo -n bash -s' <<'EOS'
set +e
pid=$(cat /var/tmp/ss3-embed.pid)
kill -TERM "$pid" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo OURS_SIGTERM_GONE
        break
    fi
    sleep 1
done
if kill -0 "$pid" 2>/dev/null; then
    echo OURS_SIGTERM_STUCK
    kill -9 "$pid" 2>/dev/null || true
fi
export KRB5_KDC_PROFILE=/var/kerberos/embed-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/embed-ours/krb5.conf
: > /var/tmp/ss3-embed.log
nohup /var/tmp/ss3/krb5-embed-realm >/var/tmp/ss3-embed.log 2>&1 &
echo $! > /var/tmp/ss3-embed.pid
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q 'serving EMBED.KERBER.TEST' /var/tmp/ss3-embed.log && ss -ltn | grep -q ':88'; then
        echo OURS_RESTART_LISTEN
        exit 0
    fi
    sleep 1
done
echo OURS_RESTART_DOWN
EOS
echo "==== ours cell 7 ===="
lab ssh client2 -- 'python3 /var/tmp/ss3/client.py 7'
echo "==== conf sha after ===="
lab ssh klldap -- 'sha256sum /etc/krb5.conf'
lab ssh client2 -- 'sha256sum /etc/krb5.conf'
echo "FINAL: SS3_DONE"
