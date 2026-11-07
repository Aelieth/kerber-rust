#!/bin/bash
# 3h SC driver.
# MIT first on kdc snapshot f4-mit-f44, then the install.md upgrade of that same disk,
# then the ours leg. Client2 is not reset. No snapshot is created or deleted.
# Cleanup returns kdc to the snapshot that was current at start.
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
export REC
REC=$HAND_REC/$PHASEC_SHA/hand-sc
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
export SEC
LOG=$REC/driver.log
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
PAC=$WT/target-pac/release/krb5-pac-extract
BIN=${HAND_SHIP:-$WT/target-rp/release}/krb5-embed-realm
MIT_SNAP=f4-mit-f44
TL_SRC=$HDIR/lib/sc1-tl.c
ADMIN_PW=$LAB_HOME/secrets/mit-realm.admin-admin.password
touched=0
start_snap=
lab() { bash "$LAB" "$@"; }
stop() { echo "SC_STOP $*"; exit 2; }
require_bins "$BIN"
require_files "$LAB" "$TL_SRC" "$ADMIN_PW"
scrub() {
    python3 -c 'import sys,re; t=sys.stdin.read(); sys.stdout.write(re.sub(r"(?<!\S)[0-9a-fA-F]{32,}(?!\S)","[redacted-hex]",t))'
}
lock_on() {
    exec 8>>"$LAB_HOME/state/lab.lock"
    flock -n 8 || { echo LOCK_BUSY; exit 1; }
}
lock_off() {
    flock -u 8 2>/dev/null || true
    exec 8>&-
}
snap_current() {
    if command -v virsh >/dev/null 2>&1; then
        virsh -q -c qemu:///system snapshot-current kerber-kdc --name
    else
        (cd "$HERE" && distrobox-host-exec virsh -q -c qemu:///system snapshot-current kerber-kdc --name)
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
    lab ssh kdc -- 'cat /var/tmp/sc/pw 2>/dev/null || true' > "$SEC/secret-pw" || true
    lab ssh kdc -- 'sudo cat /var/tmp/sc/admin-pw 2>/dev/null || true' > "$SEC/secret-admin" || true
    lab ssh client2 -- 'cat /var/tmp/sc/pw 2>/dev/null || true' > "$SEC/secret-pw-c2" || true
    chmod 600 "$SEC/secret-pw" "$SEC/secret-pw-c2" 2>/dev/null || true
    lab ssh kdc -- 'sudo rm -rf /var/tmp/sc' || true
    lab ssh client2 -- 'rm -rf /var/tmp/sc /tmp/sc-cc' || true
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
    echo "SC_END"
}
trap 'cleanup; rm -rf "$SEC"' EXIT
mkdir -p "$REC"
echo "REC:hand-sc-$(date -u +%Y%m%dT%H%M%SZ)"
echo "TREE:$SHA"
echo "==== pac extract preflight ===="
cargo build --release --locked --manifest-path "$WT/Cargo.toml" -p krb5-tools --bin krb5-pac-extract --features krb5-kdc/test-hooks,krb5-admin/test-hooks,krb5-client/test-hooks --target-dir "$WT/target-pac"
pbrc=$?
echo "PAC_BUILD_RC:$pbrc"
[ "$pbrc" = 0 ] || stop "pac build"
pac_sha=$(sha256sum "$PAC" | awk 'NR==1 {print $1}')
echo "PAC_SHA:$pac_sha"
echo "PAC_TREE:$(git -C "$WT" rev-parse HEAD)"
echo "PAC_FEATURES:krb5-kdc/test-hooks,krb5-admin/test-hooks,krb5-client/test-hooks"
lock_on
touched=1
start_snap=$(snap_current | tr -d '\r')
echo "START_SNAP:$start_snap"
[ -n "$start_snap" ] || stop "no start snapshot"
echo "==== mit reset ===="
reset_kdc "$MIT_SNAP"
rcmd=$(cat << 'EOS'
rpm -q krb5-server krb5-workstation; test -f "$HOME/.cargo/env" && echo CARGO_ENV:yes || echo CARGO_ENV:no; test -x /usr/sbin/kadmin.local && echo KADMIN_LOCAL:yes || echo KADMIN_LOCAL:no
EOS
)
lab ssh kdc -- "$rcmd"
rcmd=$(cat << 'EOS'
rpm -q krb5-workstation; test -x /usr/bin/kinit && echo KINIT:yes || echo KINIT:no; awk -F= "/default_realm/ {gsub(/ /,\"\",\$2); print \"REALM:\" \$2; exit}" /etc/krb5.conf
EOS
)
lab ssh client2 -- "$rcmd"
lab ssh kdc -- 'sudo rm -rf /var/tmp/sc && sudo mkdir -p /var/tmp/sc && sudo chown lab:lab /var/tmp/sc && sudo chmod 700 /var/tmp/sc'
lab ssh kdc -- 'python3 -' << 'PY'
import pathlib, secrets
root = pathlib.Path("/var/tmp/sc")
pw = secrets.token_hex(8)
path = root / "pw"
path.write_text(pw + "\n")
path.chmod(0o600)
print("PW_READY", path.stat().st_size)
PY
lab ssh kdc -- 'cat /var/tmp/sc/pw' > "$SEC/secret-pw"
chmod 600 "$SEC/secret-pw"
lab ssh client2 -- 'mkdir -p /var/tmp/sc && chmod 700 /var/tmp/sc && cat > /var/tmp/sc/pw && chmod 600 /var/tmp/sc/pw' < "$SEC/secret-pw"
echo "PW_COPIED"
# Each cell's remote script reads /var/tmp/sc/pw. The logged tag is not the query,
# so the password stays out of the driver log.
mit_setup=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
q() {
    tag=$1
    shift
    echo "CMD:$tag"
    out=$(/usr/sbin/kadmin.local -q "$*" </dev/null 2>&1)
    rc=$?
    printf '%s\n' "$out"
    echo "RC:$tag:$rc"
    need=
    case "$tag" in
        scalice|scaliceo|scbob|host|carol|carolo|dave|daveo|svc|listed|unlisted) need='created\.' ;;
        ren) need='renamed' ;;
        kvno|flag) need='modified\.' ;;
        cpw) need='randomized\.' ;;
        get-host|get-krbtgt) need='Key: vno' ;;
        kt) need='added to keytab' ;;
        getpol) need='^Policy:' ;;
        pol5|pol7) need= ;;
        *) echo "SETUP_MISS:$tag"; exit 1 ;;
    esac
    if [ -n "${need:-}" ]; then
        printf '%s\n' "$out" | grep -Eq "$need" || { echo "SETUP_MISS:$tag"; exit 1; }
    else
        printf '%s\n' "$out" | grep -q 'kadmin.local:' && { echo "SETUP_MISS:$tag"; exit 1; }
    fi
    [ "$rc" = 0 ] || { echo "SETUP_MISS:$tag"; exit 1; }
}
absent() {
    name=$1
    if printf '%s\n' "$list" | grep -qx "${name}@KERBER.TEST"; then
        echo "SETUP_MISS:exists:$name"
        exit 1
    fi
}
echo "LISTPRINCS:mit"
list=$(/usr/sbin/kadmin.local -q "listprincs" </dev/null 2>&1)
printf '%s\n' "$list"
absent scalice
absent scalice2
absent scbob
absent host/x
absent carol
absent dave
q scalice "addprinc -pw $pw scalice"
q ren "renprinc -force scalice scalice2"
q scbob "addprinc -e aes256-cts:norealm -pw $pw scbob"
q host "addprinc -randkey host/x"
q kvno "modprinc -kvno 65535 host/x"
q cpw "cpw -randkey host/x"
q get-host "getprinc host/x"
q get-krbtgt "getprinc krbtgt/KERBER.TEST"
q pol5 "addpol -maxfailure 10 -failurecountinterval 0 sc5"
q carol "addprinc -pw $pw -policy sc5 carol"
q pol7 "addpol -maxfailure 2 -failurecountinterval 15seconds -lockoutduration 0 sc7"
q dave "addprinc -pw $pw -policy sc7 dave"
q getpol "getpol sc7"
EOS
)
setup_rc=$?
printf '%s\n' "$mit_setup" | scrub
printf '%s\n' "$mit_setup" | grep -q 'SETUP_MISS:' && stop "MIT setup miss"
[ "$setup_rc" = 0 ] || stop "MIT setup rc $setup_rc"
echo "==== mit restart ===="
lab ssh kdc -- 'sudo systemctl restart krb5kdc kadmin; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN; exit 1'
echo "MIT_RESTART:$?"
echo "==== mit kinit ===="
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
try() {
    name=$1
    expect=$2
    rm -f /tmp/sc-cc
    if [ "$expect" = good ]; then use=$pw; else use=wrong-password; fi
    KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit "$name@KERBER.TEST" <<EOF
$use
EOF
    echo "KINIT:$name:$expect:$?"
    rm -f /tmp/sc-cc
}
try scalice2 good
try scbob good
try carol bad
try carol bad
try carol bad
EOS
echo "==== mit cell3 kvno ===="
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit scalice2@KERBER.TEST <<EOF
$pw
EOF
echo "KINIT:scalice2:kvno:$?"
KRB5CCNAME=/tmp/sc-cc /usr/bin/kvno host/x@KERBER.TEST
echo "KVNO_RC:$?"
rm -f /tmp/sc-cc
EOS
echo "==== mit cell5 restart ===="
lab ssh kdc -- 'sudo systemctl restart krb5kdc kadmin; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ss -ltn | grep -q ":88 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN'
lab ssh kdc -- 'sudo -n kadmin.local -q "getprinc carol" </dev/null' | scrub
echo "==== mit cell7 ===="
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
try() {
    name=$1
    rm -f /tmp/sc-cc
    KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit "$name@KERBER.TEST" <<EOF
wrong-password
EOF
    echo "KINIT:$name:bad:$?"
    rm -f /tmp/sc-cc
}
try dave
try dave
try dave
EOS
sleep 20
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
try() {
    name=$1
    rm -f /tmp/sc-cc
    KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit "$name@KERBER.TEST" <<EOF
$pw
EOF
    rc=$?
    echo "KINIT:$name:after-wait:$rc"
    if [ "$rc" != 0 ]; then echo "EXPECT_NONZERO:$name:pass"; else echo "EXPECT_NONZERO:$name:fail"; fi
    rm -f /tmp/sc-cc
}
try dave
EOS
lab ssh kdc -- 'sudo -n kadmin.local -q "modprinc -unlock dave" </dev/null; echo UNLOCK_RC:$?'
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit dave@KERBER.TEST <<EOF
$pw
EOF
echo "KINIT:dave:after-unlock:$?"
rm -f /tmp/sc-cc
EOS
echo "==== cell 4 compile ===="
lab ssh kdc -- 'command -v gcc >/dev/null || sudo -n dnf install -y gcc krb5-devel'
lab ssh kdc -- 'cat > /var/tmp/sc/sc1-tl.c && gcc -O2 -o /var/tmp/sc/sc1-tl /var/tmp/sc/sc1-tl.c -lkadm5clnt_mit -lkrb5 && echo TL_COMPILE_OK' < "$TL_SRC"
echo "TL_COMPILE_RC:$?"
lab ssh kdc -- 'sudo tee /var/tmp/sc/admin-pw >/dev/null && sudo chmod 600 /var/tmp/sc/admin-pw' < "$ADMIN_PW"
echo "==== cell 4 mit ===="
lab ssh kdc -- 'sudo -n bash -s' << 'EOS' | tee "$REC/tl-mit.txt"
set +e
run() {
    echo "PRINC:$1 MASK:$2"
    /var/tmp/sc/sc1-tl "$1" "$2"
    echo "TL_RC:$1:$2:$?"
}
run krbtgt/KERBER.TEST@KERBER.TEST tl
run krbtgt/KERBER.TEST@KERBER.TEST notl
run scbob@KERBER.TEST tl
run scbob@KERBER.TEST notl
run host/x@KERBER.TEST tl
run host/x@KERBER.TEST notl
EOS
echo "==== dump ===="
dump_out=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
systemctl stop krb5kdc kadmin
/usr/sbin/kdb5_util dump /var/kerberos/krb5kdc/mit-realm.dump
echo "DUMP_RC:$?"
if [ -f /var/kerberos/krb5kdc/mit-realm.dump ]; then echo "DUMP_LINES:$(wc -l < /var/kerberos/krb5kdc/mit-realm.dump)"; else echo "DUMP_LINES:absent"; fi
EOS
)
printf '%s\n' "$dump_out"
printf '%s\n' "$dump_out" | grep -q '^DUMP_RC:0$' || stop "MIT dump failed"
echo "==== cargo preflight ===="
rcmd=$(cat << 'EOS'
test -f "$HOME/.cargo/env" && echo CARGO_ENV:yes || echo CARGO_ENV:no
EOS
)
cargo_line=$(lab ssh kdc -- "$rcmd" | tr -d '\r')
echo "$cargo_line"
echo "==== upgrade ===="
tar=$REC/src.tar
git -C "$WT" archive --format=tar --prefix=sc-src/ "$SHA" > "$tar"
echo "ARCHIVE_RC:$?"
lab ssh kdc -- 'rm -rf ~/sc-src && mkdir -p ~/sc-src && tar -x -C ~' < "$tar"
echo "UPLOAD_RC:$?"
if printf '%s\n' "$cargo_line" | grep -q 'CARGO_ENV:yes'; then
    echo "INSTALL_METHOD:guest-cargo"
    lab ssh kdc -- "bash -lc 'set -o pipefail; . \"\$HOME/.cargo/env\"; cd \$HOME/sc-src && make build'"
    brc=$?
    echo "BUILD_RC:$brc"
    [ "$brc" = 0 ] || stop "build failed"
else
    # Weekly upgrade.sh builds on the guest. This disk has no cargo env, so the
    # same make build runs on the host into target-rp. The guest only installs.
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
    lab ssh kdc -- 'rm -rf ~/sc-src/target && mkdir -p ~/sc-src/target && tar -x -C ~/sc-src/target' < "$REC/target.tar"
    echo "TARGET_UPLOAD_RC:$?"
fi
inst=$(lab ssh kdc -- "bash -lc 'set +e; sudo -n systemctl stop krb5kdc kadmin; sudo -n dnf remove -y --no-autoremove krb5-server; echo REMOVE_RC:\$?; rpm -q krb5-server libkadm5 krb5-devel krb5-libs; echo RPM_AFTER_REMOVE; for f in /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl /etc/sysconfig/krb5kdc /etc/sysconfig/kadmin /etc/sysconfig/kprop /etc/logrotate.d/krb5kdc /etc/logrotate.d/kadmind; do if [ -e \$f.rpmsave ]; then sudo -n mv \$f.rpmsave \$f; echo RPSAVE:\$f; fi; done; cd \$HOME/sc-src && sudo -n make install PREFIX=/usr CARGO_TARGET_DIR=\$HOME/sc-src/target; echo INSTALL_RC:\$?'" | tr -d '\r')
printf '%s\n' "$inst" | scrub
printf '%s\n' "$inst" | grep -q '^INSTALL_RC:0$' || stop "install failed"
load_out=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
cd /var/kerberos/krb5kdc
mkdir -p mit-db2
mv -f principal principal.kadm5 mit-db2/
if [ -e principal.ulog ]; then mv -f principal.ulog mit-db2/; fi
/usr/sbin/kdb5_util load /var/kerberos/krb5kdc/mit-realm.dump
echo "LOAD_RC:$?"
restorecon -Rv /var/kerberos/krb5kdc >/tmp/sc-restorecon.out 2>&1
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
echo "==== cell 2 kinit scbob ===="
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit scbob@KERBER.TEST <<EOF
$pw
EOF
echo "KINIT:scbob:migrated:$?"
rm -f /tmp/sc-cc
EOS
echo "==== ours cells ===="
ours_setup=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
q() {
    tag=$1
    shift
    echo "CMD:$tag"
    out=$(/usr/sbin/kadmin.local -q "$*" </dev/null 2>&1)
    rc=$?
    printf '%s\n' "$out"
    echo "RC:$tag:$rc"
    need=
    case "$tag" in
        scalice|scaliceo|scbob|host|carol|carolo|dave|daveo|svc|listed|unlisted) need='created\.' ;;
        ren) need='renamed' ;;
        kvno|flag) need='modified\.' ;;
        cpw) need='randomized\.' ;;
        get-host|get-krbtgt) need='Key: vno' ;;
        kt) need='added to keytab' ;;
        getpol) need='^Policy:' ;;
        pol5|pol7) need= ;;
        *) echo "SETUP_MISS:$tag"; exit 1 ;;
    esac
    if [ -n "${need:-}" ]; then
        printf '%s\n' "$out" | grep -Eq "$need" || { echo "SETUP_MISS:$tag"; exit 1; }
    else
        printf '%s\n' "$out" | grep -q 'kadmin.local:' && { echo "SETUP_MISS:$tag"; exit 1; }
    fi
    [ "$rc" = 0 ] || { echo "SETUP_MISS:$tag"; exit 1; }
}
absent() {
    name=$1
    if printf '%s\n' "$list" | grep -qx "${name}@KERBER.TEST"; then
        echo "SETUP_MISS:exists:$name"
        exit 1
    fi
}
echo "LISTPRINCS:ours"
list=$(/usr/sbin/kadmin.local -q "listprincs" </dev/null 2>&1)
printf '%s\n' "$list"
absent scaliceo
absent scaliceo2
absent host/y
absent carolo
absent daveo
if printf '%s\n' "$list" | grep -qx 'scbob@KERBER.TEST'; then echo LIST_HAS:scbob; else echo SETUP_MISS:missing:scbob; exit 1; fi
q scaliceo "addprinc -pw $pw scaliceo"
q ren "renprinc -force scaliceo scaliceo2"
q host "addprinc -randkey host/y"
q kvno "modprinc -kvno 65535 host/y"
q cpw "cpw -randkey host/y"
q get-host "getprinc host/y"
q get-krbtgt "getprinc krbtgt/KERBER.TEST"
q pol5 "addpol -maxfailure 10 -failurecountinterval 0 sc5o"
q carol "addprinc -pw $pw -policy sc5o carolo"
q pol7 "addpol -maxfailure 2 -failurecountinterval 15seconds -lockoutduration 0 sc7o"
q dave "addprinc -pw $pw -policy sc7o daveo"
q getpol "getpol sc7o"
EOS
)
setup_rc=$?
printf '%s\n' "$ours_setup" | scrub
printf '%s\n' "$ours_setup" | grep -q 'SETUP_MISS:' && stop "ours setup miss"
[ "$setup_rc" = 0 ] || stop "ours setup rc $setup_rc"
lab ssh kdc -- 'sudo systemctl restart krb5kdc kadmin; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN'
echo "OURS_RESTART:$?"
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
try() {
    name=$1
    expect=$2
    rm -f /tmp/sc-cc
    if [ "$expect" = good ]; then use=$pw; else use=wrong-password; fi
    KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit "$name@KERBER.TEST" <<EOF
$use
EOF
    echo "KINIT:$name:$expect:$?"
    rm -f /tmp/sc-cc
}
try scaliceo2 good
try carolo bad
try carolo bad
try carolo bad
EOS
echo "==== ours cell3 kvno ===="
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit scaliceo2@KERBER.TEST <<EOF
$pw
EOF
echo "KINIT:scaliceo2:kvno:$?"
KRB5CCNAME=/tmp/sc-cc /usr/bin/kvno host/y@KERBER.TEST
echo "KVNO_RC:$?"
rm -f /tmp/sc-cc
EOS
lab ssh kdc -- 'sudo systemctl restart krb5kdc kadmin; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ss -ltn | grep -q ":88 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN'
lab ssh kdc -- 'sudo -n kadmin.local -q "getprinc carolo" </dev/null' | scrub
echo "==== ours cell7 ===="
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
try() {
    name=$1
    rm -f /tmp/sc-cc
    KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit "$name@KERBER.TEST" <<EOF
wrong-password
EOF
    echo "KINIT:$name:bad:$?"
    rm -f /tmp/sc-cc
}
try daveo
try daveo
try daveo
EOS
sleep 20
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit daveo@KERBER.TEST <<EOF
$pw
EOF
rc=$?
echo "KINIT:daveo:after-wait:$rc"
if [ "$rc" != 0 ]; then echo "EXPECT_NONZERO:daveo:pass"; else echo "EXPECT_NONZERO:daveo:fail"; fi
rm -f /tmp/sc-cc
EOS
lab ssh kdc -- 'sudo -n kadmin.local -q "modprinc -unlock daveo" </dev/null; echo UNLOCK_RC:$?'
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit daveo@KERBER.TEST <<EOF
$pw
EOF
echo "KINIT:daveo:after-unlock:$?"
rm -f /tmp/sc-cc
EOS
echo "==== cell 4 ours ===="
lab ssh kdc -- 'sudo -n bash -s' << 'EOS' | tee "$REC/tl-ours.txt"
set +e
run() {
    echo "PRINC:$1 MASK:$2"
    /var/tmp/sc/sc1-tl "$1" "$2"
    echo "TL_RC:$1:$2:$?"
}
run krbtgt/KERBER.TEST@KERBER.TEST tl
run krbtgt/KERBER.TEST@KERBER.TEST notl
run scbob@KERBER.TEST tl
run scbob@KERBER.TEST notl
run host/y@KERBER.TEST tl
run host/y@KERBER.TEST notl
EOS
python3 - "$REC/tl-mit.txt" "$REC/tl-ours.txt" << 'PY'
import sys
from pathlib import Path

def blocks(text):
    cur = None
    out = {}
    for line in text.splitlines():
        if line.startswith("PRINC:") and " MASK:" in line:
            princ, mask = line.split(" MASK:")
            cur = (princ.split(":", 1)[1].split("@", 1)[0], mask)
            out[cur] = []
            continue
        if cur is not None and (line.startswith("n_tl ") or line.startswith("tl type ")):
            if line.startswith("tl type "):
                parts = line.split()
                out[cur].append("type " + parts[2])
            else:
                out[cur].append(line)
    return out

mit = blocks(Path(sys.argv[1]).read_text(errors="replace"))
ours = blocks(Path(sys.argv[2]).read_text(errors="replace"))
pairs = [
    ("krbtgt", "krbtgt/KERBER.TEST", "krbtgt/KERBER.TEST"),
    ("bob", "scbob", "scbob"),
    ("fresh", "host/x", "host/y"),
]
for mask in ("tl", "notl"):
    for label, left, right in pairs:
        a = mit.get((left, mask), [])
        b = ours.get((right, mask), [])
        same = bool(a) and a == b
        print(f"SC_CELL4_{label}_{mask}_{'SAME' if same else 'DIFF'}")
        print("LEFT")
        print("\n".join(a))
        print("RIGHT")
        print("\n".join(b))
PY
echo "==== s4u ===="
s4u_setup=$(lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
q() {
    tag=$1
    shift
    echo "CMD:$tag"
    out=$(/usr/sbin/kadmin.local -q "$*" </dev/null 2>&1)
    rc=$?
    printf '%s\n' "$out"
    echo "RC:$tag:$rc"
    need=
    case "$tag" in
        scalice|scaliceo|scbob|host|carol|carolo|dave|daveo|svc|listed|unlisted) need='created\.' ;;
        ren) need='renamed' ;;
        kvno|flag) need='modified\.' ;;
        cpw) need='randomized\.' ;;
        get-host|get-krbtgt) need='Key: vno' ;;
        kt) need='added to keytab' ;;
        getpol) need='^Policy:' ;;
        pol5|pol7) need= ;;
        *) echo "SETUP_MISS:$tag"; exit 1 ;;
    esac
    if [ -n "${need:-}" ]; then
        printf '%s\n' "$out" | grep -Eq "$need" || { echo "SETUP_MISS:$tag"; exit 1; }
    else
        printf '%s\n' "$out" | grep -q 'kadmin.local:' && { echo "SETUP_MISS:$tag"; exit 1; }
    fi
    [ "$rc" = 0 ] || { echo "SETUP_MISS:$tag"; exit 1; }
}
absent() {
    name=$1
    if printf '%s\n' "$list" | grep -qx "${name}@KERBER.TEST"; then
        echo "SETUP_MISS:exists:$name"
        exit 1
    fi
}
echo "LISTPRINCS:s4u"
list=$(/usr/sbin/kadmin.local -q "listprincs" </dev/null 2>&1)
printf '%s\n' "$list"
absent host/scsvc
absent host/listed
absent host/unlisted
q svc "addprinc -randkey host/scsvc"
q flag "modprinc +ok_to_auth_as_delegate host/scsvc"
q listed "addprinc -randkey host/listed"
q unlisted "addprinc -randkey host/unlisted"
q kt "ktadd -k /var/tmp/sc/svc.kt host/scsvc"
chmod 600 /var/tmp/sc/svc.kt || true
systemctl stop krb5kdc kadmin
echo "S4U_STOPPED:$?"
EOS
)
setup_rc=$?
printf '%s\n' "$s4u_setup"
printf '%s\n' "$s4u_setup" | grep -q 'SETUP_MISS:' && stop "s4u setup miss"
[ "$setup_rc" = 0 ] || stop "s4u setup rc $setup_rc"
lab ssh kdc -- 'cat > /var/tmp/sc/krb5-embed-realm && chmod 755 /var/tmp/sc/krb5-embed-realm' < "$BIN"
lab ssh kdc -- 'sudo -n env KRB5_KDC_PROFILE=/var/kerberos/krb5kdc/kdc.conf KRB5_CONFIG=/etc/krb5.conf /var/tmp/sc/krb5-embed-realm --allow-to-delegate host/scsvc host/listed; echo ALLOW_RC:$?'
rcmd=$(cat << 'EOS'
sudo restorecon -Rv /var/kerberos/krb5kdc > /tmp/sc-s4u-restorecon.out 2>&1; echo RESTORECON_RC:$?; echo RESTORECON_LINES:$(wc -l < /tmp/sc-s4u-restorecon.out)
EOS
)
lab ssh kdc -- "$rcmd"
lab ssh kdc -- 'sudo systemctl start krb5kdc kadmin; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ss -ltn | grep -q ":88 " && ss -ltn | grep -q ":749 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN'
lab ssh kdc -- 'sudo cat /var/tmp/sc/svc.kt' > "$SEC/secret-svc"
chmod 600 "$SEC/secret-svc"
lab ssh client2 -- 'cat > /var/tmp/sc/svc.kt && chmod 600 /var/tmp/sc/svc.kt' < "$SEC/secret-svc"
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit -k -t /var/tmp/sc/svc.kt host/scsvc@KERBER.TEST
echo "KINIT:scsvc:$?"
KRB5CCNAME=/tmp/sc-cc /usr/bin/kvno -U scaliceo2 -P host/listed
echo "S4U_LISTED_RC:$?"
unlisted=$(KRB5CCNAME=/tmp/sc-cc /usr/bin/kvno -U scaliceo2 -P host/unlisted 2>&1)
echo "S4U_UNLISTED_RC:$?"
printf '%s\n' "$unlisted"
printf '%s\n' "$unlisted" | grep -q "KDC can't fulfill requested option" && echo S4U_UNLISTED:REFUSED || echo S4U_UNLISTED:OTHER
rm -f /tmp/sc-cc
EOS
lab ssh kdc -- 'sudo systemctl restart krb5kdc kadmin; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ss -ltn | grep -q ":88 "; then echo PORT_UP; exit 0; fi; sleep 1; done; echo PORT_DOWN'
lab ssh client2 -- 'bash -s' << 'EOS'
set +e
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit -k -t /var/tmp/sc/svc.kt host/scsvc@KERBER.TEST
echo "KINIT:scsvc:after-restart:$?"
KRB5CCNAME=/tmp/sc-cc /usr/bin/kvno -U scaliceo2 -P host/listed
echo "S4U_LISTED_AFTER_RC:$?"
rm -f /tmp/sc-cc
EOS
rm -f "$SEC/secret-svc"
echo "==== cell 6 rid ===="
lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
conf=/var/kerberos/krb5kdc/kdc.conf
if grep -q domain_sid "$conf"; then echo SID_ALREADY; else
    python3 - << 'PY'
from pathlib import Path
p = Path("/var/kerberos/krb5kdc/kdc.conf")
text = p.read_text()
needle = "        kadmind_port"
line = "        domain_sid = S-1-5-21-4242424242-4242424242-4242424243\n"
if needle in text:
    text = text.replace(needle, line + needle, 1)
else:
    text = text.replace("KERBER.TEST = {", "KERBER.TEST = {\n" + line, 1)
p.write_text(text)
print("SID_INSERTED")
PY
fi
grep -n domain_sid "$conf"
pw=$(cat /var/tmp/sc/pw)
/usr/sbin/kadmin.local -q "addprinc -randkey host/sc" </dev/null
echo "HOST_RC:$?"
/usr/sbin/kadmin.local -q "ktadd -k /var/tmp/sc/host.kt host/sc" </dev/null
echo "KTADD_RC:$?"
chmod 600 /var/tmp/sc/host.kt
/usr/sbin/kadmin.local -q "addprinc -pw $pw riduser" </dev/null
echo "RID1_ADD_RC:$?"
systemctl restart krb5kdc kadmin
echo "SID_RESTART:$?"
EOS
    lab ssh kdc -- 'sudo cat /var/tmp/sc/host.kt' > "$SEC/secret-kt"
    chmod 600 "$SEC/secret-kt"
    lab ssh client2 -- 'cat > /var/tmp/sc/host.kt && chmod 600 /var/tmp/sc/host.kt' < "$SEC/secret-kt"
    lab ssh client2 -- 'cat > /var/tmp/sc/krb5-pac-extract && chmod 755 /var/tmp/sc/krb5-pac-extract' < "$PAC"
    rid_once() {
        local tag=$1
        lab ssh client2 -- 'bash -s' "$tag" << 'EOS'
set +e
tag=$1
pw=$(cat /var/tmp/sc/pw)
rm -f /tmp/sc-cc
KRB5CCNAME=/tmp/sc-cc /usr/bin/kinit riduser@KERBER.TEST <<EOF
$pw
EOF
echo "KINIT:rid:$tag:$?"
KRB5CCNAME=/tmp/sc-cc /usr/bin/kvno host/sc@KERBER.TEST
echo "KVNO:$tag:$?"
/var/tmp/sc/krb5-pac-extract --keytab /var/tmp/sc/host.kt --ccache /tmp/sc-cc --out /var/tmp/sc/pac --print-rid
echo "EXTRACT:$tag:$?"
rm -f /tmp/sc-cc
EOS
    }
    rid_once first
    lab ssh kdc -- 'sudo -n bash -s' << 'EOS'
set +e
pw=$(cat /var/tmp/sc/pw)
/usr/sbin/kadmin.local -q "delprinc -force riduser" </dev/null
echo "DEL_RC:$?"
systemctl restart krb5kdc kadmin
echo "RID_RESTART:$?"
/usr/sbin/kadmin.local -q "addprinc -pw $pw riduser" </dev/null
echo "RID2_ADD_RC:$?"
EOS
rid_once second
rm -f "$SEC/secret-kt"
echo "SC_QUERY_DONE"
exit 0
