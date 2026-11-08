#!/bin/bash
# 3l BD driver, with BD_WARN.
# mitd3 only. MIT 1.22.2 under /opt/mit-1.22.2 (Fedora's MIT has no des3).
# MIT KDC transcript first, then ours on the same dump. Four client legs,
# the cell D3M.parity.spake-des3-prog:
#   leg1  MIT kinit  / MIT KDC
#   leg3  our kinit  / MIT KDC
#   leg2  MIT kinit  / our KDC
#   leg4  our kinit  / our KDC
# Principal d3spake is created des3-only on the MIT database, then dumped.
# d3aes is aes256-only, for the banner check, and is on that same dump.
# Both passwords are generated on the guest and are not printed.
#
# Pass, per des3 leg, matching the bd-legs3 transcript:
#   kinit rc 0, one SPAKE support, one group-1 challenge, one SPAKE response,
#   ENCTS_MODULE_COUNT 0, an ISSUE line whose reply etype is des3-cbc-sha1,
#   and a krbtgt ticket. Legs 1 and 3 also need the MIT KDC challenge line.
# BD_WARN: the deprecated-enctype banner is on all four des3 legs, and the
# text after argv[0] is the same. One aes256 kinit per client on the MIT
# KDC prints no banner. A banner difference is a finding.
#
# mitd3 must start shut off on pre-bd-l7. It is reset to that snapshot and
# shut off there again. No snapshot is created or deleted. Other VMs are
# not reset and not shut down. Booting mitd3 stops if configured RAM of the
# running kerber VMs plus mitd3 would pass 32 GiB.
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
REC=$HAND_REC/$PHASEC_SHA/hand-bd
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
MIT_SNAP=pre-bd-l7
CAP_MIB=$((32 * 1024))
MITD3_MIB=4096
touched=0
lab() { bash "$LAB" "$@"; }
stop() { echo "BD_STOP $*"; exit 2; }
require_files "$LAB"
lock_on() {
    exec 8>>"$LAB_HOME/state/lab.lock"
    flock -n 8 || { echo LOCK_BUSY; exit 1; }
}
lock_off() {
    flock -u 8 2>/dev/null || true
    exec 8>&-
}
vsh() {
    if command -v virsh >/dev/null 2>&1; then
        virsh -q -c qemu:///system "$@"
    else
        (cd "$HERE" && distrobox-host-exec virsh -q -c qemu:///system "$@")
    fi
}
domstate() { vsh domstate "$1" 2>/dev/null || echo missing; }
snap_current() { vsh snapshot-current "$1" --name 2>/dev/null || echo missing; }
cleanup() {
    if [ "$touched" != 1 ]; then
        return
    fi
    touched=0
    echo "==== cleanup ===="
    lock_off
    lab reset mitd3 "$MIT_SNAP" || true
    echo "RESTORE_MIT:$?"
    lab down mitd3 || true
    echo "DOWN_MIT:$?"
}
trap cleanup EXIT

echo "==== bd driver ===="
echo "TREE $(git -C "$WT" rev-parse HEAD)"
[ "$(git -C "$WT" rev-parse HEAD)" = "$SHA" ] || stop "tree is not $SHA"
if [ -n "$(git -C "$WT" status --porcelain --untracked-files=no)" ]; then
    stop "worktree dirty"
fi
mkdir -p "$REC"
chmod 700 "$REC"

echo "==== ship bins ===="
REL=${HAND_SHIP:-$WT/target-rp/release}
SHIP=$HAND_REC/$PHASEC_SHA/step1/ship.sha256
for b in krb5-kdc krb5-kdb krb5-kinit; do
    [ -x "$REL/$b" ] || stop "missing $b"
    got=$(sha256sum "$REL/$b" | awk '{print $1}')
    echo "BIN_SHA $b $got"
    want=$(awk -v n="$b" '$2 == n { print $1 }' "$SHIP")
    [ -n "$want" ] && [ "$got" = "$want" ] || stop "ship hash $b"
done
tar -C "$REL" -cf "$REC/bins.tar" krb5-kdc krb5-kdb krb5-kinit
echo "BINS_TAR $(sha256sum "$REC/bins.tar" | awk '{print $1}')"

cat > "$REC/bd-leg-filter.py" << 'PY'
"""Print one BD leg. Drops key-material lines. No long-hex brace quantifier."""
import sys

label = sys.argv[1]
root = sys.argv[2]


def scrub(line):
    low = line.lower()
    return any(
        s in low
        for s in (
            "session key",
            "subkey",
            "reply key",
            "as key",
            "encrypted timestamp",
            "algorithm result",
            "transcript",
            "pubkey",
        )
    )


def show(line):
    out = []
    buf = []

    def flush():
        if not buf:
            return
        word = "".join(buf)
        hexish = all(c in "0123456789abcdefABCDEF" for c in word)
        has_letter = any(c in "abcdefABCDEF" for c in word)
        if len(word) >= 8 and hexish and has_letter:
            out.append("redacted")
        else:
            out.append(word)
        buf.clear()

    for ch in line:
        if ch in "0123456789abcdefABCDEF":
            buf.append(ch)
        else:
            flush()
            out.append(ch)
    flush()
    return "".join(out)


def lines(name):
    try:
        return open(root + "/" + name, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []


print("==== %s ====" % label)
for line in lines(label + ".kinit"):
    line = line.rstrip()
    if line.startswith("Key:"):
        continue
    if not scrub(line):
        print("OUT " + show(line))
support = challenge = response = encts = 0
for n, line in enumerate(lines(label + ".trace"), 1):
    line = line.rstrip()
    if "SPAKE challenge received" in line:
        challenge += 1
        g = "?"
        mark = "group "
        i = line.find(mark)
        if i >= 0:
            g = line[i + len(mark):].split()[0]
        print("TRACE %d SPAKE challenge received with group %s" % (n, g))
        continue
    if scrub(line) or line.startswith("Key:"):
        continue
    if (
        "SPAKE" in line
        or "Preauth" in line
        or "error" in line.lower()
        or "failed" in line.lower()
        or "Getting initial" in line
        or "Sending" in line
    ):
        print("TRACE %d %s" % (n, show(line)))
    if "SPAKE support" in line:
        support += 1
    if "Sending SPAKE response" in line:
        response += 1
    if "encrypted_timestamp" in line and "returned" in line:
        encts += 1
print("SUPPORT_COUNT %d" % support)
print("CHALLENGE_COUNT %d" % challenge)
print("RESPONSE_COUNT %d" % response)
print("ENCTS_MODULE_COUNT %d" % encts)
shown = 0
for line in lines(label + ".kdc"):
    low = line.lower()
    if line.startswith("Key:"):
        continue
    if "spake" in low or "preauth" in low or "issue:" in low or "error" in low:
        print("KDC " + show(line.rstrip())[:400])
        shown += 1
        if shown == 30:
            break
print("KDC_SHOWN %d" % shown)
kdc_ch = 0
for n, line in enumerate(lines(label + ".kdctrace"), 1):
    line = line.rstrip()
    if "Sending SPAKE challenge" in line or "SPAKE support message received" in line:
        if "Sending SPAKE challenge" in line:
            kdc_ch += 1
        g = "?"
        mark = "group "
        i = line.find(mark)
        if i >= 0:
            g = line[i + len(mark):].split()[0]
        kind = "challenge" if "challenge" in line else "support"
        print("KDCTRACE %d SPAKE %s group %s" % (n, kind, g))
        continue
    if scrub(line) or line.startswith("Key:"):
        continue
    if "SPAKE" in line or "error" in line.lower():
        print("KDCTRACE %d %s" % (n, show(line)))
print("KDC_CHALLENGE_COUNT %d" % kdc_ch)
for line in lines(label + ".klist"):
    if line.startswith("Key:"):
        continue
    print("KLIST " + show(line.rstrip()))
PY

cat > "$REC/bd-guest.sh" << 'GUEST'
#!/usr/bin/env bash
# Four BD legs on mitd3. Password stays in this shell. Raw traces stay here.
set -u
MIT=/opt/mit-1.22.2
ROOT=/var/tmp/bd
BINS=/var/tmp/bd/bins
echo "DATE $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ ! -x "$MIT/sbin/krb5kdc" ] || [ ! -x "$MIT/bin/kinit" ] || [ ! -x "$MIT/sbin/kadmin.local" ] || [ ! -x "$MIT/sbin/kdb5_util" ]; then
    echo "ORACLE_BAD bins"
    exit 2
fi
ver=$("$MIT/bin/krb5-config" --version 2>&1 | head -1)
echo "KDC_VERSION $ver"
case $ver in
    *1.22.2*) echo ORACLE_OK ;;
    *) echo ORACLE_BAD version; exit 2 ;;
esac
for b in krb5-kdc krb5-kdb krb5-kinit; do
    if [ ! -x "$BINS/$b" ]; then
        echo "BIN_MISSING $b"
        exit 2
    fi
    echo "BIN_SHA $b $(sha256sum "$BINS/$b" | awk '{print $1}')"
done
src_kdc=""
src_krb=""
for f in "$MIT/var/krb5kdc/kdc.conf" "$MIT/etc/krb5kdc/kdc.conf" /etc/krb5kdc/kdc.conf; do
    if [ -f "$f" ]; then src_kdc=$f; break; fi
done
for f in "$MIT/etc/krb5.conf" /etc/krb5.conf; do
    if [ -f "$f" ]; then src_krb=$f; break; fi
done
echo "SRC_KDC ${src_kdc:-none}"
echo "SRC_KRB ${src_krb:-none}"
if [ -z "$src_kdc" ] || [ -z "$src_krb" ]; then
    echo "CONF_MISSING"
    exit 2
fi
python3 - "$src_kdc" "$src_krb" "$ROOT" << 'PY'
import sys
src_kdc, src_krb, root = sys.argv[1:4]
kdc = open(src_kdc, encoding="utf-8", errors="replace").read()
krb = open(src_krb, encoding="utf-8", errors="replace").read()
if "D3.TEST = {" not in kdc and "D3.TEST ={" not in kdc:
    sys.exit("NO_D3_REALM")
needle = "D3.TEST = {" if "D3.TEST = {" in kdc else "D3.TEST ={"
if "spake_preauth_groups" in kdc:
    sys.exit("SPAKE_ALREADY_SET")
line = "\n        spake_preauth_groups = edwards25519 P-256"
kdc_body = kdc.replace(needle, needle + line, 1)

def with_log(text, path):
    if "[logging]" not in text:
        return text + "\n[logging]\n    kdc = FILE:%s\n" % path
    return text.replace("[logging]", "[logging]\n    kdc = FILE:%s" % path, 1)

open(root + "/kdc-mit.conf", "w", encoding="utf-8").write(with_log(kdc_body, root + "/mit.kdc"))
open(root + "/kdc-our.conf", "w", encoding="utf-8").write(with_log(kdc_body, root + "/our.kdc"))
extra = (
    "    allow_weak_crypto = true\n"
    "    permitted_enctypes = des3-cbc-sha1 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
)
def insert_lib(text, more):
    if "[libdefaults]" not in text:
        return "[libdefaults]\n" + more + text
    return text.replace("[libdefaults]", "[libdefaults]\n" + more, 1)
kdc_krb = insert_lib(krb, extra + "    spake_preauth_groups = edwards25519 P-256\n")
client = insert_lib(krb, extra + "    spake_preauth_groups = edwards25519\n    dns_lookup_kdc = false\n    rdns = false\n")
open(root + "/krb5-kdc.conf", "w", encoding="utf-8").write(kdc_krb)
open(root + "/krb5-client.conf", "w", encoding="utf-8").write(client)
print("CONF_WRITTEN")
PY
echo "PY_RC $?"
if [ ! -f "$ROOT/krb5-kdc.conf" ]; then
    echo "CONF_FAILED"
    exit 2
fi
grep -q 'spake_preauth_groups = edwards25519 P-256' "$ROOT/krb5-kdc.conf" || { echo "KDC_LIB_SPAKE_MISSING"; exit 2; }
echo "DEFAULT_REALM $(grep default_realm "$ROOT/krb5-client.conf" | head -1)"
sudo systemctl stop krb5kdc 2>/dev/null || true
sudo pkill -x krb5kdc || true
sudo pkill -x krb5-kdc || true
sleep 1
pw=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
pw_aes=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
export KRB5_CONFIG=$ROOT/krb5-kdc.conf
export KRB5_KDC_PROFILE=$ROOT/kdc-mit.conf
sudo --preserve-env=KRB5_CONFIG,KRB5_KDC_PROFILE "$MIT/sbin/kadmin.local" -r D3.TEST -q "addprinc -pw ${pw} -e des3-cbc-sha1:normal +requires_preauth d3spake" > "$ROOT/kadmin-d3spake.out" 2>&1
echo "ADDPRINC_RC d3spake $?"
sudo --preserve-env=KRB5_CONFIG,KRB5_KDC_PROFILE "$MIT/sbin/kadmin.local" -r D3.TEST -q "addprinc -pw ${pw_aes} -e aes256-cts-hmac-sha1-96:normal +requires_preauth d3aes" > "$ROOT/kadmin-d3aes.out" 2>&1
echo "ADDPRINC_RC d3aes $?"
python3 - "$ROOT" "$pw" "$pw_aes" << 'PY'
import sys
root, pw, pw_aes = sys.argv[1], sys.argv[2], sys.argv[3]
for name in ("d3spake", "d3aes"):
    for line in open(root + "/kadmin-" + name + ".out", encoding="utf-8", errors="replace"):
        if (pw and pw in line) or (pw_aes and pw_aes in line):
            print("KADMIN redacted")
        elif line.startswith("Key:"):
            continue
        else:
            print("KADMIN " + line.rstrip())
PY
show_princ() {
    name=$1
    sudo --preserve-env=KRB5_CONFIG,KRB5_KDC_PROFILE "$MIT/sbin/kadmin.local" -r D3.TEST -q "getprinc $name" > "$ROOT/getprinc-$name.out" 2>&1
    python3 - "$ROOT/getprinc-$name.out" "$name" << 'PY'
import sys
path, name = sys.argv[1], sys.argv[2]
for line in open(path, encoding="utf-8", errors="replace"):
    line = line.rstrip()
    if line.startswith("Key:"):
        parts = [p.strip() for p in line.split(",")]
        vno = parts[0].split()[-1] if parts else "?"
        etype = parts[1] if len(parts) > 1 else "?"
        print("PRINC %s kvno %s etype %s" % (name, vno, etype))
    elif line.startswith("Principal:") or line.startswith("Number of keys:"):
        print("PRINC %s %s" % (name, line))
PY
}
show_princ d3spake
show_princ d3aes

start_kdc() {
    tag=$1
    bin=$2
    shift 2
    : > "$ROOT/${tag}.kdc"
    : > "$ROOT/${tag}.kdctrace"
    chmod 644 "$ROOT/${tag}.kdc" "$ROOT/${tag}.kdctrace"
    export KRB5_KDC_PROFILE=$ROOT/kdc-${tag}.conf
    export KRB5_TRACE=$ROOT/${tag}.kdctrace
    sudo --preserve-env=KRB5_CONFIG,KRB5_KDC_PROFILE,KRB5_TRACE setsid nohup "$bin" -n "$@" -r D3.TEST > "$ROOT/${tag}.stdout" 2>&1 < /dev/null &
    echo "KDC_PID $tag $!"
    i=0
    while [ "$i" -lt 15 ]; do
        if grep -q 'commencing operation' "$ROOT/${tag}.kdc" 2>/dev/null; then
            echo "KDC_UP $tag"
            sudo chmod a+r "$ROOT/${tag}.kdc" "$ROOT/${tag}.kdctrace" 2>/dev/null || true
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    echo "KDC_NOT_UP $tag"
    sudo chmod a+r "$ROOT/${tag}.stdout" 2>/dev/null || true
    return 1
}

run_kinit() {
    label=$1
    bin=$2
    tag=$3
    princ=$4
    pass=$5
    rm -f "$ROOT/${label}.trace" "$ROOT/${label}.cc"
    : > "$ROOT/${label}.trace"
    printf '%s\n' "$pass" | timeout 25 env KRB5_CONFIG=$ROOT/krb5-client.conf KRB5_TRACE=$ROOT/${label}.trace KRB5CCNAME=FILE:$ROOT/${label}.cc "$bin" "$princ" > "$ROOT/${label}.kinit" 2>&1
    echo "KINIT_RC $label $?"
    if [ -x "$MIT/bin/klist" ]; then
        "$MIT/bin/klist" -e -c "FILE:$ROOT/${label}.cc" > "$ROOT/${label}.klist" 2>&1 || true
    fi
    cp -f "$ROOT/${tag}.kdc" "$ROOT/${label}.kdc" 2>/dev/null || true
    cp -f "$ROOT/${tag}.kdctrace" "$ROOT/${label}.kdctrace" 2>/dev/null || true
    python3 /var/tmp/bd/bd-leg-filter.py "$label" "$ROOT"
}

echo "==== phase mit-kdc ===="
start_kdc mit "$MIT/sbin/krb5kdc" || echo "MIT_KDC_FAILED"
echo "==== LEG1 mit-kinit mit-kdc ===="
run_kinit leg1 "$MIT/bin/kinit" mit d3spake@D3.TEST "$pw"
echo "==== LEG3 our-kinit mit-kdc ===="
run_kinit leg3 "$BINS/krb5-kinit" mit d3spake@D3.TEST "$pw"
echo "==== AES mit-kinit mit-kdc ===="
run_kinit aes-mit "$MIT/bin/kinit" mit d3aes@D3.TEST "$pw_aes"
echo "==== AES our-kinit mit-kdc ===="
run_kinit aes-ours "$BINS/krb5-kinit" mit d3aes@D3.TEST "$pw_aes"
echo "==== dump ===="
sudo --preserve-env=KRB5_CONFIG,KRB5_KDC_PROFILE "$MIT/sbin/kdb5_util" -r D3.TEST dump "$ROOT/mit.dump" > "$ROOT/dump.out" 2>&1
echo "DUMP_RC $?"
sudo chmod a+r "$ROOT/mit.dump" "$ROOT/dump.out" 2>/dev/null || true
echo "DUMP_BYTES $(wc -c < "$ROOT/mit.dump" 2>/dev/null || echo 0)"
sudo pkill -x krb5kdc || true
sleep 1
echo "==== load ===="
mkdir -p "$ROOT/ours"
export KRB5_KDC_PROFILE=$ROOT/kdc-our.conf
sudo --preserve-env=KRB5_CONFIG,KRB5_KDC_PROFILE "$BINS/krb5-kdb" -r D3.TEST -d "$ROOT/ours/principal" -sf "$MIT/var/krb5kdc/.k5.D3.TEST" load "$ROOT/mit.dump" > "$ROOT/load.out" 2>&1
echo "LOAD_RC $?"
python3 - "$ROOT/load.out" << 'PY'
import sys
def show(line):
    out, buf = [], []
    def flush():
        if not buf:
            return
        word = "".join(buf)
        hexish = all(c in "0123456789abcdefABCDEF" for c in word)
        letter = any(c in "abcdefABCDEF" for c in word)
        out.append("redacted" if len(word) >= 8 and hexish and letter else word)
        buf.clear()
    for ch in line:
        if ch in "0123456789abcdefABCDEF":
            buf.append(ch)
        else:
            flush()
            out.append(ch)
    flush()
    return "".join(out)
for line in open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()[:30]:
    if line.startswith("Key:"):
        continue
    print("LOAD " + show(line))
PY
echo "==== phase our-kdc ===="
start_kdc our "$BINS/krb5-kdc" -d "$ROOT/ours/principal" || echo "OUR_KDC_FAILED"
echo "==== LEG2 mit-kinit our-kdc ===="
run_kinit leg2 "$MIT/bin/kinit" our d3spake@D3.TEST "$pw"
echo "==== LEG4 our-kinit our-kdc ===="
run_kinit leg4 "$BINS/krb5-kinit" our d3spake@D3.TEST "$pw"
unset pw
unset pw_aes
sudo pkill -x krb5kdc || true
sudo pkill -x krb5-kdc || true
rm -f "$ROOT/leg1.cc" "$ROOT/leg2.cc" "$ROOT/leg3.cc" "$ROOT/leg4.cc" "$ROOT/aes-mit.cc" "$ROOT/aes-ours.cc" "$ROOT/mit.dump"
echo "FINAL_GUEST"
GUEST
chmod 700 "$REC/bd-guest.sh" "$REC/bd-leg-filter.py"

echo "==== lab gate ===="
lock_on
mit_st=$(domstate kerber-mitd3)
mit_snap=$(snap_current kerber-mitd3)
echo "MITD3 $mit_st $mit_snap"
[ "$mit_st" = "shut off" ] || stop "mitd3 not shut off"
[ "$mit_snap" = "$MIT_SNAP" ] || stop "mitd3 snap is $mit_snap"
vsh snapshot-info kerber-mitd3 --snapshotname "$MIT_SNAP" >/dev/null 2>&1 || stop "snapshot $MIT_SNAP missing"
sum=$MITD3_MIB
for name in kdc services client1 client2 klldap win kdc2 ub26 deb13 rocky10; do
    st=$(domstate "kerber-$name")
    echo "VM $name $st $(snap_current "kerber-$name")"
    if [ "$st" = running ]; then
        kb=$(vsh dominfo "kerber-$name" | awk '/Max memory:/ { print $3 }')
        case $kb in
            ''|*[!0-9]*) stop "no memory for $name" ;;
        esac
        mib=$((kb / 1024))
        echo "VM_MIB $name $mib"
        sum=$((sum + mib))
    fi
done
echo "RAM_SUM_MIB $sum CAP_MIB $CAP_MIB"
[ "$sum" -le "$CAP_MIB" ] || stop "ram $sum over $CAP_MIB"
touched=1
lock_off
lab reset mitd3 "$MIT_SNAP"
reset_rc=$?
echo "RESET_MIT:$reset_rc"
lock_on
[ "$reset_rc" = 0 ] || stop "reset mitd3"
if ! lab ssh mitd3 -- 'test -d /opt/mit-1.22.2'; then
    stop "mitd3 has no oracle after reset"
fi
echo "ORACLE_DIR_PRESENT"
lab ssh mitd3 -- 'rm -rf /var/tmp/bd && mkdir -p /var/tmp/bd/bins && chmod 700 /var/tmp/bd'
lab ssh mitd3 -- 'tar -C /var/tmp/bd/bins -xf - && chmod 755 /var/tmp/bd/bins/krb5-kdc /var/tmp/bd/bins/krb5-kdb /var/tmp/bd/bins/krb5-kinit' < "$REC/bins.tar"
echo "COPY_RC:$?"
lab ssh mitd3 -- 'cat > /var/tmp/bd/bd-leg-filter.py' < "$REC/bd-leg-filter.py"
lab ssh mitd3 -- 'bash -s' < "$REC/bd-guest.sh" | tee "$REC/guest.out"
echo "GUEST_RC:${PIPESTATUS[0]}"

python3 - "$REC/guest.out" << 'GRADEPY'
import sys
path = sys.argv[1]
lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
text = "\n".join(lines)
print("BD_ORACLE:%s" % ("yes" if "ORACLE_OK" in text else "no"))
princ_key = any(l.startswith("PRINC d3spake Number of keys: 1") for l in lines)
princ_et = any(l.startswith("PRINC d3spake kvno 1 etype") and "des3-cbc-sha1" in l for l in lines)
print("BD_PRINC:%s" % ("yes" if princ_key and princ_et else "no"))
aes_key = any(l.startswith("PRINC d3aes Number of keys: 1") for l in lines)
aes_et = any(
    l.startswith("PRINC d3aes kvno 1 etype") and "aes256-cts-hmac-sha1-96" in l and "des3" not in l
    for l in lines
)
print("BD_AESPRINC:%s" % ("yes" if aes_key and aes_et else "no"))
dump = any(l == "DUMP_RC 0" for l in lines)
load = any(l == "LOAD_RC 0" for l in lines)
print("BD_DUMP:%s" % ("yes" if dump else "no"))
print("BD_LOAD:%s" % ("yes" if load else "no"))

def section(label):
    start = "==== %s ====" % label
    try:
        i = lines.index(start)
    except ValueError:
        return []
    out = []
    for line in lines[i + 1:]:
        if line.startswith("==== ") and line.endswith(" ===="):
            break
        out.append(line)
    return out

def rc_of(label):
    last = None
    prefix = "KINIT_RC %s " % label
    for line in lines:
        if line.startswith(prefix):
            last = line.split()[-1]
    return last

need_kdc = {"leg1": True, "leg3": True, "leg2": False, "leg4": False}
ok_all = dump and load and princ_key and princ_et and "ORACLE_OK" in text
for label in ("leg1", "leg2", "leg3", "leg4"):
    sec = section(label)
    body = "\n".join(sec)
    counts = {}
    for key in ("SUPPORT_COUNT", "CHALLENGE_COUNT", "RESPONSE_COUNT", "ENCTS_MODULE_COUNT", "KDC_CHALLENGE_COUNT"):
        counts[key] = None
        for line in sec:
            if line.startswith(key + " "):
                counts[key] = line.split()[-1]
    group = "SPAKE challenge received with group 1" in body
    issue = any("ISSUE:" in line and "rep=DEPRECATED:des3-cbc-sha1" in line and "d3spake@D3.TEST" in line for line in sec)
    ticket = any("krbtgt/D3.TEST@D3.TEST" in line for line in sec)
    kdc_ok = True
    if need_kdc[label]:
        kdc_ok = counts["KDC_CHALLENGE_COUNT"] not in (None, "0")
    ok = (
        rc_of(label) == "0"
        and counts["SUPPORT_COUNT"] == "1"
        and counts["CHALLENGE_COUNT"] == "1"
        and counts["RESPONSE_COUNT"] == "1"
        and counts["ENCTS_MODULE_COUNT"] == "0"
        and group
        and issue
        and ticket
        and kdc_ok
    )
    print("BD_%s:%s" % (label.upper(), "yes" if ok else "no"))
    if not ok:
        ok_all = False
        print(
            "BD_%s_DETAIL rc=%s support=%s challenge=%s response=%s encts=%s group1=%s issue=%s ticket=%s kdc_challenge=%s"
            % (
                label.upper(),
                rc_of(label),
                counts["SUPPORT_COUNT"],
                counts["CHALLENGE_COUNT"],
                counts["RESPONSE_COUNT"],
                counts["ENCTS_MODULE_COUNT"],
                "yes" if group else "no",
                "yes" if issue else "no",
                "yes" if ticket else "no",
                counts["KDC_CHALLENGE_COUNT"],
            )
        )

def banner_body(line):
    s = line[4:] if line.startswith("OUT ") else line
    for name in ("krb5-kinit", "kinit"):
        prefix = name + ": "
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return s

def banners(label):
    found = []
    for line in section(label):
        if "deprecated and will be disabled" in line:
            found.append(banner_body(line))
    return found

des3_b = [banners(label) for label in ("leg1", "leg2", "leg3", "leg4")]
one_each = all(len(b) == 1 for b in des3_b)
bodies = [b[0] for b in des3_b if len(b) == 1]
same = one_each and len(set(bodies)) == 1
aes_quiet = (
    banners("aes-mit") == []
    and banners("aes-ours") == []
    and rc_of("aes-mit") == "0"
    and rc_of("aes-ours") == "0"
)
warn_ok = same and aes_quiet and aes_key and aes_et
print("BD_WARN:%s" % ("yes" if warn_ok else "no"))
if warn_ok:
    print("BD_WARN_TEXT %s" % bodies[0])
else:
    ok_all = False
    print(
        "BD_WARN_DETAIL counts=%s texts=%s aes_banners=%s,%s aes_rc=%s,%s"
        % (
            [len(b) for b in des3_b],
            bodies,
            len(banners("aes-mit")),
            len(banners("aes-ours")),
            rc_of("aes-mit"),
            rc_of("aes-ours"),
        )
    )
print("BD_ALL:%s" % ("yes" if ok_all else "no"))
GRADEPY

echo "==== secret scan ===="
python3 - "$REC/guest.out" << 'PY'
import sys
bad = 0
for i, line in enumerate(open(sys.argv[1], encoding="utf-8", errors="replace"), 1):
    if line.startswith("Key:") or "\nKey:" in line:
        bad += 1
print("SECRET_SCAN_HITS:%d" % bad)
PY
echo "BD_END"
