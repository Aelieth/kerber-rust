#!/bin/bash
# 3g TR on 806c20f1. The seven changes.
# Cell 1: MIT kadmin.local addprinc -randkey on f4-mit, then getprinc.
# Cell 2 is graded by rp-tr-cell2.sh, not by this driver. The embed realm
# setup below stays, because cell 3 runs on that pair.
# Cell 3: both legs on that pair, MIT krb5kdc first, then krb5-embed-realm,
# one at a time on the profile's KDC port.
# The key file, the master password, and the client password stay on the
# guest and are not printed.
set -u
umask 077
exec 9>&-
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
LAB=$WT/harness/field/lab.sh
PHASEC_SHA=${1:?phasec sha}
SHA=$PHASEC_SHA
TREE=$(git -C "$WT" rev-parse 'HEAD^{tree}')
REL=${HAND_SHIP:-$WT/target-rp/release}
BIN=$REL/krb5-embed-realm
export REC
REC=$HAND_REC/$PHASEC_SHA/hand-tr
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
export SEC
LOG=$REC/driver.log
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
kdc_touched=0
kl_touched=0
kdc_port=88
lab() { bash "$LAB" "$@"; }
stop() { echo "TR_STOP $*"; exit 2; }
[ "$(git -C "$WT" rev-parse HEAD)" = "$SHA" ] || stop "WT not at the build under test"
[ "$(git -C "$WT" rev-parse 'HEAD^{tree}')" = "$TREE" ] || stop "tree is not HEAD's"
require_bins "$BIN"
require_files "$LAB" "$HDIR/lib/cc-one.c"
mkdir -p "$REC"
echo "REC:hand-tr-$(date -u +%Y%m%dT%H%M%SZ)"
bin_sha=$(sha256sum "$BIN" | awk 'NR==1 {print $1}')
echo "EMBED_PROVENANCE sha=$bin_sha commit=$SHA tree=$TREE"
echo "EMBED_BIN:$BIN"
stat -c 'EMBED_MTIME:%y' "$BIN"
lock_on() {
    exec 8>>"$LAB_HOME/state/lab.lock"
    flock -n 8 || { echo LOCK_BUSY; exit 1; }
}
lock_off() {
    flock -u 8 2>/dev/null || true
    exec 8>&-
}
redact_log() {
    lab ssh klldap -- "sudo -n python3 - '$1'" << 'PY'
import pathlib, sys
log_path = pathlib.Path(sys.argv[1])
secrets = []
root = pathlib.Path("/var/tmp/tr")
for name in ("master", "key", "client-pw"):
    p = root / name
    if p.is_file():
        for line in p.read_text(errors="replace").splitlines():
            if line:
                secrets.append(line)
secrets.sort(key=len, reverse=True)
text = log_path.read_text(errors="replace") if log_path.is_file() else "LOG_ABSENT\n"
for secret in secrets:
    text = text.replace(secret, "[redacted]")
sys.stdout.write(text)
if text and not text.endswith("\n"):
    sys.stdout.write("\n")
PY
}
need0() {
    local tag="$1" rc="$2" guest_log="$3"
    echo "${tag}:${rc}"
    if [ "$rc" != 0 ]; then
        echo "==== ${tag} log ===="
        redact_log "$guest_log"
        stop "${tag} ${rc}"
    fi
}
cleanup() {
    if [ "$kdc_touched" != 1 ] && [ "$kl_touched" != 1 ]; then
        return
    fi
    echo "==== cleanup ===="
    if [ "$kl_touched" = 1 ]; then
        lab ssh klldap -- 'cat /var/tmp/tr/master 2>/dev/null || true' > "$SEC/secret-master"
        lab ssh klldap -- 'cat /var/tmp/tr/key 2>/dev/null || true' > "$SEC/secret-key"
        lab ssh klldap -- 'cat /var/tmp/tr/client-pw 2>/dev/null || true' > "$SEC/secret-client"
        chmod 600 "$SEC/secret-master" "$SEC/secret-key" "$SEC/secret-client" || true
        lab ssh klldap -- 'sudo pkill -9 -x krb5-embed-real || true; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; sudo rm -rf /var/kerberos/tr-mit /var/kerberos/tr-ours /var/tmp/tr' || true
        lock_off
        lab reset klldap f44-docker || true
        echo "RESTORE_KLLDAP:$?"
    fi
    if [ "$kdc_touched" = 1 ]; then
        lock_off
        lab reset kdc rust-field-p12-f44 || true
        echo "RESTORE_KDC:$?"
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
    echo "TR_END"
}
trap 'cleanup; rm -rf "$SEC"' EXIT
echo "==== cell 1 MIT kdc ===="
kdc_touched=1
lab reset kdc f4-mit-f44
echo "RESET_MIT:$?"
lock_on
echo "==== rpm kdc ===="
lab ssh kdc -- 'rpm -q krb5-server krb5-workstation; if [ -x /usr/sbin/kadmin.local ]; then echo BIN_OK:/usr/sbin/kadmin.local; else echo BIN_MISSING:/usr/sbin/kadmin.local; fi' | tee "$REC/kdc-bins.txt"
if grep -q '^BIN_MISSING:' "$REC/kdc-bins.txt"; then
    stop "kdc kadmin.local missing"
fi
lab ssh kdc -- 'sudo cat /var/kerberos/krb5kdc/kdc.conf' > "$REC/f4-mit-kdc.conf"
python3 - "$REC/f4-mit-kdc.conf" "$REC/tr-mit-kdc.conf" "$REC/tr-ours-kdc.conf" << 'PYCONF'
import sys
from pathlib import Path
src, mit_out, ours_out = sys.argv[1:]
text = Path(src).read_text(errors="replace")

def join_cont(raw):
    out, buf = [], ""
    for line in raw.splitlines():
        if buf:
            line = buf + " " + line.lstrip()
            buf = ""
        if line.rstrip().endswith("\\"):
            buf = line.rstrip()[:-1]
            continue
        out.append(line)
    if buf:
        out.append(buf)
    return out

def strip_comment(line):
    if line.lstrip().startswith("#"):
        return ""
    if " #" in line:
        return line.split(" #", 1)[0]
    return line

PATH_KEYS = {
    "database_name", "key_stash_file", "acl_file", "admin_keytab", "dict_file",
    "iprop_logfile", "pkinit_identity", "pkinit_anchors", "pkinit_pool",
    "pkinit_revoke", "pkinit_dh_param", "pkinit_kdc_ocsp", "pkinit_mapping_file",
}

def relations_of(body):
    kept, dropped = [], []
    for raw in body:
        line = strip_comment(raw).strip().rstrip(",")
        if not line or line in ("{", "}"):
            continue
        if "=" not in line:
            print(f"SKIPPED_BARE:{line}")
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key.lower() in PATH_KEYS or "/" in value:
            dropped.append(key)
        else:
            kept.append((key, value))
    return kept, dropped

def flat_section(lines, header):
    want = header.lower()
    in_section = False
    body = []
    for raw in lines:
        line = strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            if in_section:
                break
            in_section = line.lower() == want
            continue
        if in_section:
            body.append(line)
    return body

lines = join_cont(text)
realm_lines = []
in_realms = False
in_body = False
depth = 0
for raw in lines:
    line = strip_comment(raw).strip()
    if not line:
        continue
    if not in_body:
        if line.startswith("[") and line.endswith("]"):
            in_realms = line.lower() == "[realms]"
            continue
        if in_realms and line.upper().startswith("KERBER.TEST") and "{" in line:
            in_body = True
            depth = line.count("{") - line.count("}")
            rest = line.split("{", 1)[1].strip()
            if rest:
                realm_lines.append(rest)
            if depth <= 0:
                break
            continue
    else:
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            chunk = line.rsplit("}", 1)[0].strip()
            if chunk:
                realm_lines.append(chunk)
            break
        realm_lines.append(line)

kept, dropped = relations_of(realm_lines)
defaults = relations_of(flat_section(lines, "[kdcdefaults]"))[0]
for key in dropped:
    print(f"DROPPED_PATH:{key}")
if not text.strip() or text.lstrip().startswith("sudo:") or not kept:
    print("STANZA_EMPTY")
    raise SystemExit(2)
print("COPIED_STANZA_BEGIN")
for key, value in kept:
    print(f"    {key} = {value}")
print("COPIED_STANZA_END")

def last(pairs, key, fallback):
    found = fallback
    for k, v in pairs:
        if k.lower() == key:
            found = v.split(",")[0].split()[0]
    return found

port = last(kept, "kdc_ports", last(defaults, "kdc_ports", "88"))
tcp = last(kept, "kdc_tcp_ports", last(defaults, "kdc_tcp_ports", port))
print(f"PROFILE_KDC_PORT:{port}")
print(f"PROFILE_KDC_TCP_PORT:{tcp}")
keys = {k.lower() for k, _ in kept}
extra = []
if "kadmind_port" not in keys:
    extra.append(("kadmind_port", "749"))
    print("PROFILE_PORT_DEFAULT:kadmind_port=749")
if "kpasswd_port" not in keys:
    extra.append(("kpasswd_port", "464"))
    print("PROFILE_PORT_DEFAULT:kpasswd_port=464")

def write_conf(path, root):
    rows = [
        ("database_name", f"{root}/principal"),
        ("key_stash_file", f"{root}/.k5.KERBER.TEST"),
        ("acl_file", f"{root}/kadm5.acl"),
        ("admin_keytab", f"{root}/admin.keytab"),
    ]
    rows.extend(kept)
    rows.extend(extra)
    body = [
        "[kdcdefaults]",
        f"    kdc_ports = {port}",
        f"    kdc_tcp_ports = {tcp}",
        "",
        "[realms]",
        "    KERBER.TEST = {",
    ]
    for key, value in rows:
        body.append(f"        {key} = {value}")
    body.append("    }")
    body.append("")
    Path(path).write_text("\n".join(body))

write_conf(mit_out, "/var/kerberos/tr-mit")
write_conf(ours_out, "/var/kerberos/tr-ours")
PYCONF
parse_rc=$?
if [ "$parse_rc" != 0 ]; then
    stop "copied stanza empty"
fi
kdc_port=$(awk -F= '/^    kdc_ports / {gsub(/ /, "", $2); print $2; exit}' "$REC/tr-mit-kdc.conf")
kadm_port=$(awk -F= '/kadmind_port/ {gsub(/ /, "", $2); print $2; exit}' "$REC/tr-mit-kdc.conf")
[ -n "$kdc_port" ] || stop "kdc_ports missing"
[ -n "$kadm_port" ] || kadm_port=749
echo "PROFILE_KDC_PORT:${kdc_port}"
echo "GENERATED_PROFILE_BEGIN"
cat "$REC/tr-mit-kdc.conf"
echo "GENERATED_PROFILE_END"
lab ssh kdc -- 'sudo kadmin.local -q "addprinc -randkey krbtgt/OTHER.TEST"; echo ADD_RC:$?'
lab ssh kdc -- 'sudo kadmin.local -q "getprinc krbtgt/OTHER.TEST"' | tee "$REC/cell1-getprinc.txt"
python3 - "$REC/cell1-getprinc.txt" > "$REC/cell1-fields.txt" << 'PY'
import sys
from pathlib import Path
keep = ("maximum ticket life", "maximum renewable life", "attributes", "number of keys", "key:", "expiration date")
out = []
for line in Path(sys.argv[1]).read_text(errors="replace").splitlines():
    low = line.strip().lower()
    if not low.startswith(keep):
        continue
    if any(len(tok) >= 32 and all(c in "0123456789abcdefABCDEF" for c in tok) for tok in line.split()):
        continue
    out.append(line.strip())
print("\n".join(out))
PY
cat "$REC/cell1-fields.txt"
lock_off
lab reset kdc rust-field-p12-f44
echo "RESET_BACK:$?"
lock_on
echo "==== cell 2 embed on klldap ===="
kl_touched=1
echo "==== rpm klldap ===="
klldap_bins() {
rcmd=$(cat << 'EOS'
rpm -q krb5-server krb5-workstation; for c in /usr/sbin/kadmin.local /usr/sbin/kdb5_util /usr/sbin/krb5kdc /usr/bin/kadmin /usr/bin/kinit /usr/bin/kvno /usr/bin/klist; do if [ -x "$c" ]; then echo "BIN_OK:$c"; else echo "BIN_MISSING:$c"; fi; done
EOS
)
    lab ssh klldap -- "$rcmd"
}
klldap_bins | tee "$REC/klldap-bins.txt"
if grep -q '^BIN_MISSING:' "$REC/klldap-bins.txt"; then
    echo "==== klldap mit packages ===="
    lab ssh klldap -- 'sudo -n dnf install -y krb5-server krb5-workstation; echo KLLDAP_DNF:$?' | tee "$REC/klldap-dnf.txt"
    grep -q '^KLLDAP_DNF:0$' "$REC/klldap-dnf.txt" || stop "klldap dnf"
    klldap_bins | tee "$REC/klldap-bins.txt"
fi
if grep -q '^BIN_MISSING:' "$REC/klldap-bins.txt"; then
    stop "klldap mit binary missing"
fi
lab ssh klldap -- 'sudo systemctl stop krb5kdc kadmin 2>/dev/null || true; sudo systemctl mask krb5kdc kadmin 2>/dev/null || true; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; sudo pkill -9 -x krb5-embed-real || true; echo SERVICES_HELD'
lab ssh klldap -- 'sudo rm -rf /var/tmp/tr /var/kerberos/tr-mit /var/kerberos/tr-ours && sudo mkdir -p /var/tmp/tr /var/kerberos/tr-mit /var/kerberos/tr-ours && sudo chown lab:lab /var/tmp/tr && sudo chmod 700 /var/tmp/tr'
lab ssh klldap -- 'python3 -' << 'PY'
import pathlib, secrets
root = pathlib.Path("/var/tmp/tr")
pw = secrets.token_hex(16)
master = root / "master"
key = root / "key"
client = root / "client-pw"
master.write_text(pw + "\n" + pw + "\n")
master.chmod(0o600)
key.write_text(secrets.token_hex(32) + "\n")
key.chmod(0o600)
client.write_text(secrets.token_hex(16) + "\n")
client.chmod(0o600)
print("SECRETS_READY", master.stat().st_size, key.stat().st_size, client.stat().st_size)
PY
lab ssh klldap -- 'cat > /var/tmp/tr/krb5-embed-realm && chmod 755 /var/tmp/tr/krb5-embed-realm' < "$BIN"
lab ssh klldap -- 'cat > /var/tmp/tr/cc-one.c && chmod 644 /var/tmp/tr/cc-one.c' < "$HDIR/lib/cc-one.c"
if [ -x "$REL/krb5-kvno" ]; then
    lab ssh klldap -- 'cat > /var/tmp/tr/krb5-kvno && chmod 755 /var/tmp/tr/krb5-kvno' < "$REL/krb5-kvno"
    echo "A4_KVNO_PUSHED target-rp"
else
    echo "A4_KVNO_OURS_ABSENT target-rp/release/krb5-kvno"
fi
lab ssh klldap -- 'sha256sum /var/tmp/tr/krb5-embed-realm'
install_side() {
    local root="$1" conf="$2"
    lab ssh klldap -- "sudo tee '$root/kdc.conf' >/dev/null" < "$conf"
    lab ssh klldap -- "sudo tee '$root/kadm5.acl' >/dev/null" << 'EOF'
admin/admin@KERBER.TEST *
EOF
    lab ssh klldap -- "sudo tee '$root/krb5.conf' >/dev/null" << 'EOF'
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    rdns = false

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF
}
install_side /var/kerberos/tr-mit "$REC/tr-mit-kdc.conf"
install_side /var/kerberos/tr-ours "$REC/tr-ours-kdc.conf"
create_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/tr-mit/kdc.conf
export KRB5_CONFIG=/var/kerberos/tr-mit/krb5.conf
/usr/sbin/kdb5_util -r KERBER.TEST create -s < /var/tmp/tr/master > /var/tmp/tr/create.txt 2>&1
echo "CREATE_RC:$?"
rc=0
/usr/sbin/kadmin.local -r KERBER.TEST -q 'addprinc -randkey -e aes256-cts-hmac-sha1-96:normal krbtgt/OTHER.TEST' > /var/tmp/tr/add.txt 2>&1 || rc=$?
/usr/sbin/kadmin.local -r KERBER.TEST -q 'addprinc -randkey -e aes256-cts-hmac-sha1-96:normal krbtgt/KERBER.TEST@OTHER.TEST' >> /var/tmp/tr/add.txt 2>&1 || rc=$?
echo "SCRATCH_ADD_RC:$rc"
EOS
) || stop "ssh tr-mit create failed"
printf '%s\n' "$create_out"
crc=$(printf '%s\n' "$create_out" | awk -F: '$1=="CREATE_RC" {v=$2} END {print v}')
arc=$(printf '%s\n' "$create_out" | awk -F: '$1=="SCRATCH_ADD_RC" {v=$2} END {print v}')
[ -n "$crc" ] || stop "no CREATE_RC"
[ -n "$arc" ] || stop "no SCRATCH_ADD_RC"
need0 CREATE_RC "$crc" /var/tmp/tr/create.txt
need0 SCRATCH_ADD_RC "$arc" /var/tmp/tr/add.txt
boot_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
export KRB5_KDC_PROFILE=/var/kerberos/tr-ours/kdc.conf
export KRB5_CONFIG=/var/kerberos/tr-ours/krb5.conf
/var/tmp/tr/krb5-embed-realm --bootstrap-only > /var/tmp/tr/boot.log 2>&1
echo "BOOT_RC:$?"
/var/tmp/tr/krb5-embed-realm --create-trust OTHER.TEST --key-file /var/tmp/tr/key > /var/tmp/tr/trust.log 2>&1
echo "TRUST_RC:$?"
EOS
) || stop "ssh tr-ours boot failed"
printf '%s\n' "$boot_out"
brc=$(printf '%s\n' "$boot_out" | awk -F: '$1=="BOOT_RC" {v=$2} END {print v}')
trc=$(printf '%s\n' "$boot_out" | awk -F: '$1=="TRUST_RC" {v=$2} END {print v}')
[ -n "$brc" ] || stop "no BOOT_RC"
[ -n "$trc" ] || stop "no TRUST_RC"
need0 BOOT_RC "$brc" /var/tmp/tr/boot.log
need0 TRUST_RC "$trc" /var/tmp/tr/trust.log
# Cell 2's ours-vs-mit getprinc rows are not this driver. rp-tr-cell2.sh grades
# them. TR_SANITY stays: cell 1's fields against tr-mit's outbound, key lines
# dropped. The realm setup above stays. Cell 3 runs on that pair.
lab ssh klldap -- 'sudo -n bash -s' << 'EOS' | tee "$REC/cell2-getprinc.txt"
set +e
getp() {
    root=$1
    princ=$2
    echo "==== ${root} ${princ} ===="
    KRB5_KDC_PROFILE=$root/kdc.conf KRB5_CONFIG=$root/krb5.conf \
        /usr/sbin/kadmin.local -r KERBER.TEST -q "getprinc $princ"
}
getp /var/kerberos/tr-mit 'krbtgt/OTHER.TEST'
getp /var/kerberos/tr-mit 'krbtgt/KERBER.TEST@OTHER.TEST'
EOS
python3 - "$REC/cell1-fields.txt" "$REC/cell2-getprinc.txt" << 'PY'
import sys
from pathlib import Path
keep = ("maximum ticket life", "maximum renewable life", "attributes", "number of keys", "key:", "expiration date")

def fields(lines, drop_keys):
    out = []
    for line in lines:
        low = line.strip().lower()
        if not low.startswith(keep):
            continue
        if drop_keys and (low.startswith("key:") or low.startswith("number of keys")):
            continue
        if any(len(tok) >= 32 and all(c in "0123456789abcdefABCDEF" for c in tok) for tok in line.split()):
            continue
        out.append(line.strip())
    return out

def blocks(text):
    cur = None
    data = {}
    for line in text.splitlines():
        if line.startswith("==== ") and line.endswith(" ===="):
            cur = line[len("==== "):-len(" ====")]
            data[cur] = []
            continue
        if cur is not None:
            data[cur].append(line)
    return data

def show(title, a, b):
    print(title)
    print("LEFT")
    print("\n".join(a))
    print("RIGHT")
    print("\n".join(b))
    same = bool(a) and a == b
    print(f"{title}_{'SAME' if same else 'DIFF'}")
    return same

cell1 = [ln for ln in Path(sys.argv[1]).read_text(errors="replace").splitlines() if ln.strip()]
got = blocks(Path(sys.argv[2]).read_text(errors="replace"))
print("SANITY_DROPPED:key lines and number of keys")
show("TR_SANITY", fields(cell1, True), fields(got.get("/var/kerberos/tr-mit krbtgt/OTHER.TEST", []), True))
PY
echo "==== cell 3 ===="
echo "CELL3_REASON:the embed pair; this leg runs no AD trust pair"
add_client() {
    lab ssh klldap -- "sudo -n python3 - '$1'" << 'PY'
import pathlib, subprocess, sys
how = sys.argv[1]
pw = pathlib.Path("/var/tmp/tr/client-pw").read_text().strip()
if how == "mit":
    env = {
        "KRB5_KDC_PROFILE": "/var/kerberos/tr-mit/kdc.conf",
        "KRB5_CONFIG": "/var/kerberos/tr-mit/krb5.conf",
        "PATH": "/usr/sbin:/usr/bin:/bin",
    }
    cmd = ["/usr/sbin/kadmin.local", "-r", "KERBER.TEST", "-q", f"addprinc -pw {pw} trcell"]
else:
    env = {
        "KRB5_KDC_PROFILE": "/var/kerberos/tr-ours/kdc.conf",
        "KRB5_CONFIG": "/var/kerberos/tr-ours/krb5.conf",
        "PATH": "/usr/sbin:/usr/bin:/bin",
    }
    cmd = [
        "/usr/bin/kadmin", "-p", "admin/admin", "-k", "-t",
        "/var/kerberos/tr-ours/admin.keytab", "-r", "KERBER.TEST",
        "-q", f"addprinc -pw {pw} trcell",
    ]
proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
text = (proc.stdout or "") + (proc.stderr or "")
text = text.replace(pw, "[redacted]")
path = pathlib.Path("/var/tmp/tr") / f"add-client-{how}.txt"
path.write_text(text)
print(f"ADD_CLIENT_{how}_RC:{proc.returncode}")
PY
}
kinit_leg() {
    lab ssh klldap -- "sudo -n bash -s -- '$1' '$2'" << 'EOS'
set +e
tag=$1
conf=$2
export KRB5CCNAME=FILE:/var/tmp/tr/cc
export KRB5_CONFIG=$conf
export LC_ALL=C
rm -f /var/tmp/tr/cc
/usr/bin/kinit -r 7d trcell@KERBER.TEST < /var/tmp/tr/client-pw > /var/tmp/tr/kinit-$tag.txt 2>&1
echo "KINIT_${tag}_RC:$?"
/usr/bin/kvno krbtgt/OTHER.TEST@KERBER.TEST > /var/tmp/tr/kvno-$tag.txt 2>&1
echo "KVNO_${tag}_RC:$?"
/usr/bin/klist -f > /var/tmp/tr/klist-$tag.txt 2>&1
echo "KLIST_${tag}_RC:$?"
# A cache that holds only krbtgt/OTHER.TEST@KERBER.TEST, then kvno a third realm.
rm -f /var/tmp/tr/cc-only
if gcc -o /var/tmp/tr/cc-one /var/tmp/tr/cc-one.c -lkrb5 > /var/tmp/tr/cc-one-build-$tag.txt 2>&1; then
    /var/tmp/tr/cc-one FILE:/var/tmp/tr/cc FILE:/var/tmp/tr/cc-only trcell@KERBER.TEST krbtgt/OTHER.TEST@KERBER.TEST > /var/tmp/tr/cc-one-$tag.txt 2>&1
    echo "CC_ONE_RC:$?" >> /var/tmp/tr/cc-one-$tag.txt
else
    echo CC_ONE_NO_COMPILER > /var/tmp/tr/cc-one-$tag.txt
fi
cat > /var/tmp/tr/a4-third.conf << 'EOF'
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
[realms]
    KERBER.TEST = { kdc = 127.0.0.1:1 }
    OTHER.TEST = { kdc = 127.0.0.1:1 }
    THIRD.TEST = { kdc = 127.0.0.1:1 }
EOF
if grep -q '^CC_ONE_OK$' /var/tmp/tr/cc-one-$tag.txt; then
    KRB5_CONFIG=/var/tmp/tr/a4-third.conf KRB5CCNAME=FILE:/var/tmp/tr/cc-only /usr/bin/klist -e > /var/tmp/tr/a4-klist-$tag.txt 2>&1
    KRB5_CONFIG=/var/tmp/tr/a4-third.conf KRB5CCNAME=FILE:/var/tmp/tr/cc-only /usr/bin/kvno host/nosuch@THIRD.TEST > /var/tmp/tr/a4-kvno-mit-$tag.txt 2>&1
    echo "KVNO_MIT_RC:$?" >> /var/tmp/tr/a4-kvno-mit-$tag.txt
    if [ -x /var/tmp/tr/krb5-kvno ]; then
        KRB5_CONFIG=/var/tmp/tr/a4-third.conf KRB5CCNAME=FILE:/var/tmp/tr/cc-only /var/tmp/tr/krb5-kvno host/nosuch@THIRD.TEST > /var/tmp/tr/a4-kvno-ours-$tag.txt 2>&1
        echo "KVNO_OURS_RC:$?" >> /var/tmp/tr/a4-kvno-ours-$tag.txt
    else
        echo KVNO_OURS_ABSENT > /var/tmp/tr/a4-kvno-ours-$tag.txt
    fi
else
    echo A4_SKIPPED_NO_ONLY_CACHE > /var/tmp/tr/a4-klist-$tag.txt
    echo A4_SKIPPED_NO_ONLY_CACHE > /var/tmp/tr/a4-kvno-mit-$tag.txt
    echo A4_SKIPPED_NO_ONLY_CACHE > /var/tmp/tr/a4-kvno-ours-$tag.txt
fi
EOS
}
start_kdc() {
    lab ssh klldap -- "sudo -n bash -s -- '$1' '$kdc_port' '$3'" << EOS
set +e
tag=\$1
port=\$2
extra=\$3
if ss -H -lntu sport = :\$port | grep -q .; then
    echo PORT_BUSY
    ss -lntup sport = :\$port || true
    exit 0
fi
nohup $2 >/var/tmp/tr/\${tag}-serve.log 2>&1 &
echo \$! > /var/tmp/tr/\${tag}.pid
up=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -H -lntu sport = :\$port | grep -q .; then
        up=1
        break
    fi
    sleep 1
done
if [ "\$up" != 1 ]; then
    echo PORT_DOWN:\$tag
    exit 0
fi
if [ -n "\$extra" ]; then
    up=0
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if ss -H -lnt sport = :\$extra | grep -q .; then
            up=1
            break
        fi
        sleep 1
    done
    if [ "\$up" != 1 ]; then
        echo PORT_DOWN:\$tag-\$extra
        exit 0
    fi
fi
echo PORT_UP:\$tag
EOS
}
add_client mit
start_out=$(start_kdc mit "env KRB5_KDC_PROFILE=/var/kerberos/tr-mit/kdc.conf KRB5_CONFIG=/var/kerberos/tr-mit/krb5.conf /usr/sbin/krb5kdc -n" "")
printf '%s\n' "$start_out"
if printf '%s\n' "$start_out" | grep -q '^PORT_DOWN:'; then
    echo "==== mit serve log ===="
    redact_log /var/tmp/tr/mit-serve.log
fi
echo "==== a4 toolchain ===="
lab ssh klldap -- 'sudo -n dnf install -y gcc krb5-devel; echo A4_DNF:$?' | tee "$REC/a4-dnf.txt"
lab ssh klldap -- 'rpm -q gcc krb5-devel' | tee "$REC/a4-rpm.txt"
grep -q '^A4_DNF:0$' "$REC/a4-dnf.txt" || stop "a4 dnf"
grep -q '^gcc-' "$REC/a4-rpm.txt" || stop "a4 rpm gcc"
grep -q '^krb5-devel-' "$REC/a4-rpm.txt" || stop "a4 rpm krb5-devel"
kinit_leg mit /var/kerberos/tr-mit/krb5.conf
lab ssh klldap -- 'sudo pkill -9 krb5kdc || true'
if ! lab ssh klldap -- 'sudo test -f /var/kerberos/tr-ours/admin.keytab'; then
    echo "ADMIN_KEYTAB_MISSING"
    lab ssh klldap -- 'sudo ls -l /var/kerberos/tr-ours || true'
fi
start_out=$(start_kdc ours "env KRB5_KDC_PROFILE=/var/kerberos/tr-ours/kdc.conf KRB5_CONFIG=/var/kerberos/tr-ours/krb5.conf /var/tmp/tr/krb5-embed-realm" "$kadm_port")
printf '%s\n' "$start_out"
if printf '%s\n' "$start_out" | grep -q '^PORT_DOWN:'; then
    echo "==== ours serve log ===="
    redact_log /var/tmp/tr/ours-serve.log
fi
add_client ours
kinit_leg ours /var/kerberos/tr-ours/krb5.conf
# Each tool has its own file. A4_ROW FAIL fails the leg. Skip markers fail too.
: > "$REC/a4-verdict.txt"
a4_pull() {
    local tag=$1 name
    for name in cc-one cc-one-build klist kvno-mit kvno-ours; do
        case "$name" in
            cc-one) lab ssh klldap -- "cat /var/tmp/tr/cc-one-$tag.txt" ;;
            cc-one-build) lab ssh klldap -- "cat /var/tmp/tr/cc-one-build-$tag.txt" ;;
            klist) lab ssh klldap -- "cat /var/tmp/tr/a4-klist-$tag.txt" ;;
            kvno-mit) lab ssh klldap -- "cat /var/tmp/tr/a4-kvno-mit-$tag.txt" ;;
            kvno-ours) lab ssh klldap -- "cat /var/tmp/tr/a4-kvno-ours-$tag.txt" ;;
        esac > "$REC/a4-$tag-$name.txt" || echo "A4_PULL_MISSING $name" >> "$REC/a4-$tag-$name.txt"
    done
    python3 - "$tag" "$REC/a4-$tag-cc-one.txt" "$REC/a4-$tag-klist.txt" "$REC/a4-$tag-kvno-mit.txt" "$REC/a4-$tag-kvno-ours.txt" "$REC/a4-verdict.txt" << 'PY'
import sys
from pathlib import Path
tag = sys.argv[1]
paths = [Path(p) for p in sys.argv[2:6]]
verdict = Path(sys.argv[6])
files = [p.read_text(errors="replace") if p.is_file() else "" for p in paths]
cc, klist, mit, ours = files
lines = []
def row(name, ok, detail):
    lines.append("A4_ROW %s %s %s %s" % (tag, name, "PASS" if ok else "FAIL", detail))
if "CC_ONE_NO_COMPILER" in cc or "A4_PULL_MISSING" in cc:
    row("cc-one", False, "CC_ONE_NO_COMPILER" if "CC_ONE_NO_COMPILER" in cc else "A4_PULL_MISSING")
else:
    row("cc-one", "CC_ONE_OK" in cc, "only the cross TGT was copied")
if "A4_SKIPPED_NO_ONLY_CACHE" in klist or "A4_PULL_MISSING" in klist:
    row("only-cross", False, "A4_SKIPPED_NO_ONLY_CACHE" if "A4_SKIPPED_NO_ONLY_CACHE" in klist else "A4_PULL_MISSING")
else:
    ok = "krbtgt/OTHER.TEST@KERBER.TEST" in klist and "krbtgt/KERBER.TEST@KERBER.TEST" not in klist
    row("only-cross", ok, "klist has the cross TGT and not the local TGT")
if "A4_SKIPPED_NO_ONLY_CACHE" in mit or "A4_PULL_MISSING" in mit:
    row("mit-kvno", False, "A4_SKIPPED_NO_ONLY_CACHE" if "A4_SKIPPED_NO_ONLY_CACHE" in mit else "A4_PULL_MISSING")
else:
    row("mit-kvno", "KVNO_MIT_RC:1" in mit and "Matching credential not found" in mit, "MIT kvno rc 1, matching credential not found")
if "KVNO_OURS_ABSENT" in ours or "A4_SKIPPED_NO_ONLY_CACHE" in ours or "A4_PULL_MISSING" in ours:
    if "KVNO_OURS_ABSENT" in ours:
        why = "KVNO_OURS_ABSENT"
    elif "A4_SKIPPED_NO_ONLY_CACHE" in ours:
        why = "A4_SKIPPED_NO_ONLY_CACHE"
    else:
        why = "A4_PULL_MISSING"
    row("ours-kvno", False, why)
else:
    row("ours-kvno", "KVNO_OURS_RC:1" in ours and "Matching credential not found" in ours, "ours kvno rc 1, matching credential not found")
text = "\n".join(lines) + "\n"
sys.stdout.write(text)
with verdict.open("a") as handle:
    handle.write(text)
PY
}
a4_pull mit
a4_pull ours
python3 - "$REC/a4-verdict.txt" << 'PY'
import sys
from pathlib import Path
rows = [ln for ln in Path(sys.argv[1]).read_text(errors="replace").splitlines() if ln.startswith("A4_ROW ")]
fail = [ln for ln in rows if len(ln.split()) >= 4 and ln.split()[3] == "FAIL"]
pas = [ln for ln in rows if len(ln.split()) >= 4 and ln.split()[3] == "PASS"]
print("A4_SUMMARY pass=%d fail=%d" % (len(pas), len(fail)))
sys.exit(0 if len(rows) == 8 and not fail else 1)
PY
a4_rc=$?
lab ssh klldap -- 'sudo pkill -9 -x krb5-embed-real || true; sudo pkill -9 krb5kdc || true'
for tag in mit ours; do
    echo "==== klist $tag ===="
    lab ssh klldap -- "sudo cat /var/tmp/tr/klist-$tag.txt 2>/dev/null || echo KLIST_ABSENT" | tee "$REC/klist-$tag.txt"
    echo "==== kvno $tag ===="
    lab ssh klldap -- "sudo cat /var/tmp/tr/kvno-$tag.txt 2>/dev/null || true"
done
echo "==== cell 3 logs ===="
lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
for tag in mit ours; do
    python3 - "$tag" << 'PY'
import pathlib, sys
tag = sys.argv[1]
root = pathlib.Path("/var/tmp/tr")
secrets = []
for name in ("master", "key", "client-pw"):
    p = root / name
    if p.is_file():
        for line in p.read_text(errors="replace").splitlines():
            if line:
                secrets.append(line)
secrets.sort(key=len, reverse=True)
for name in (f"kinit-{tag}.txt", f"add-client-{tag}.txt"):
    path = root / name
    text = path.read_text(errors="replace") if path.is_file() else "LOG_ABSENT\n"
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    sys.stdout.write(f"---- {name} ----\n")
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
PY
done
EOS
python3 - "$REC/klist-mit.txt" "$REC/klist-ours.txt" << 'PY'
import datetime, re, sys
from pathlib import Path
TIME = r"\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}"
row_re = re.compile(rf"^({TIME})  ({TIME})  (\S+)\s*$")
renew_re = re.compile(rf"renew until ({TIME}), Flags: (\S+)")
LOCAL = "krbtgt/KERBER.TEST@KERBER.TEST"
CROSS = "krbtgt/OTHER.TEST@KERBER.TEST"

def parse_time(text):
    return datetime.datetime.strptime(text, "%m/%d/%y %H:%M:%S")

def row(lines, princ):
    for i, line in enumerate(lines):
        if princ not in line:
            continue
        m = row_re.match(line.strip())
        if not m or m.group(3) != princ:
            return ("PARSE_ERROR", line)
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if "renew until" in nxt and renew_re.search(nxt) is None:
            return ("PARSE_ERROR", nxt)
        if "Flags:" in nxt and re.search(r"Flags: (\S+)", nxt) is None:
            return ("PARSE_ERROR", nxt)
        try:
            start = parse_time(m.group(1))
        except ValueError:
            return ("PARSE_ERROR", line)
        renew = None
        flags = ""
        found = renew_re.search(nxt)
        if found:
            try:
                renew = parse_time(found.group(1))
            except ValueError:
                return ("PARSE_ERROR", nxt)
            flags = found.group(2)
        else:
            flag_only = re.search(r"Flags: (\S+)", nxt)
            if flag_only:
                flags = flag_only.group(1)
        return ("OK", start, renew, flags)
    return ("NO_TICKET",)

def leg(tag, lines):
    local = row(lines, LOCAL)
    cross = row(lines, CROSS)
    for kind, got in (("local", local), ("cross", cross)):
        if got[0] == "PARSE_ERROR":
            print("CELL3_PARSE_ERROR")
            print(f"CELL3_PARSE_LEG:{tag}")
            print(f"CELL3_PARSE_ROW:{kind}")
            print("CELL3_PARSE_RAW:" + got[1].strip())
            raise SystemExit(2)
    if local[0] != "OK" or cross[0] != "OK" or cross[2] is None or local[2] is None:
        print(f"CELL3_{tag}_RENEW_AFTER_START:no")
        print(f"CELL3_{tag}_SPAN_FROM_TGT:absent")
        print(f"CELL3_{tag}_CAPPED_AT_TGT:no")
        print(f"CELL3_{tag}_FLAGS:absent")
        return None
    later = "yes" if cross[2] > cross[1] else "no"
    span = int((cross[2] - local[1]).total_seconds())
    capped = "yes" if cross[2] == local[2] else "no"
    print(f"CELL3_{tag}_RENEW_AFTER_START:{later}")
    print(f"CELL3_{tag}_SPAN_FROM_TGT:{span}")
    print(f"CELL3_{tag}_CAPPED_AT_TGT:{capped}")
    print(f"CELL3_{tag}_FLAGS:{cross[3]}")
    return later, span, capped, cross[3]

def load(path):
    file = Path(path)
    if not file.is_file():
        return []
    return file.read_text(errors="replace").splitlines()

mit = leg("MIT", load(sys.argv[1]))
ours = leg("OURS", load(sys.argv[2]))
if mit and ours and mit[0] == "yes" and ours[0] == "yes" and mit[1:] == ours[1:]:
    print("CELL3_SAME")
else:
    print("CELL3_DIFF")
PY
cell3_rc=$?
if [ "$cell3_rc" != 0 ]; then
    stop "cell 3 parse"
fi
if [ "$a4_rc" != 0 ]; then
    stop "a4 rows"
fi
exit 0
