#!/bin/bash
# Cell 2 rerun, with reader (B). klldap only. Not 3h.
# (A) MIT kadmin -k against the serving embed.
# (B) ours' krb5-kdb dump, then MIT kdb5_util load of that export into tr-load.
# The raw principal file is not loaded.
set -u
umask 077
exec 9>&-
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
LAB=$WT/harness/field/lab.sh
PHASEC_SHA=${1:?phasec sha}
REL=${HAND_SHIP:-$WT/target-rp/release}
BIN=$REL/krb5-embed-realm
KDB=$REL/krb5-kdb
EXTRA=$HAND_REC/$PHASEC_SHA/step1/extra.sha256
export REC
SRC=$HAND_REC/$PHASEC_SHA/hand-tr
REC=$HAND_REC/$PHASEC_SHA/hand-tr-cell2
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
export SEC
LOG=$REC/driver.log
mkdir -p "$REC"
exec > >(tee -a "$LOG") 2>&1
touched=0
lab() { bash "$LAB" "$@"; }
stop() { echo "CELL2_STOP $*"; exit 2; }
require_bins "$BIN" "$KDB"
require_files "$LAB" "$EXTRA" "$SRC/tr-mit-kdc.conf" "$SRC/tr-ours-kdc.conf"
# The embed binary must be the one step 1 built for this sha.
EXPECT=$(awk '$1 == "EXTRA" && $2 == "krb5-embed-realm" { print $3 }' "$EXTRA")
got=$(sha256sum "$BIN" | awk 'NR==1 {print $1}')
[ -n "$EXPECT" ] && [ "$got" = "$EXPECT" ] || stop "embed sha is $got, step 1 has ${EXPECT:-none}"
kdb_sha=$(sha256sum "$KDB" | awk 'NR==1 {print $1}')
mkdir -p "$REC"
echo "REC:hand-tr-cell2-$(date -u +%Y%m%dT%H%M%SZ)"
echo "EMBED_SHA:$got"
echo "KDB_SHA:$kdb_sha"
echo "KDB_BIN:$KDB"
lock_on() {
    exec 8>>"$LAB_HOME/state/lab.lock"
    flock -n 8 || { echo LOCK_BUSY; exit 1; }
}
lock_off() {
    flock -u 8 2>/dev/null || true
    exec 8>&-
}
redact_guest() {
    lab ssh klldap -- "sudo -n python3 - '$1'" << 'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
root = pathlib.Path("/var/tmp/tr")
secrets = []
for name in ("master", "key"):
    p = root / name
    if p.is_file():
        secrets.extend([ln for ln in p.read_text(errors="replace").splitlines() if ln])
secrets.sort(key=len, reverse=True)
text = path.read_text(errors="replace") if path.is_file() else "LOG_ABSENT\n"
for secret in secrets:
    text = text.replace(secret, "[redacted]")
kept = []
for line in text.splitlines():
    bad = any(len(tok) >= 32 and all(c in "0123456789abcdefABCDEF" for c in tok) for tok in line.split())
    kept.append("[redacted-hex]" if bad else line)
sys.stdout.write("\n".join(kept))
if text and not text.endswith("\n"):
    sys.stdout.write("\n")
PY
}
cleanup() {
    if [ "$touched" != 1 ]; then
        return
    fi
    echo "==== cleanup ===="
    lab ssh klldap -- 'cat /var/tmp/tr/master 2>/dev/null || true' > "$SEC/secret-master"
    lab ssh klldap -- 'cat /var/tmp/tr/key 2>/dev/null || true' > "$SEC/secret-key"
    chmod 600 "$SEC/secret-master" "$SEC/secret-key" || true
rcmd=$(cat << 'EOS'
pid=$(sudo cat /var/tmp/tr/ours.pid 2>/dev/null || true); if [ -n "$pid" ]; then sudo kill "$pid" 2>/dev/null || true; sudo kill -9 "$pid" 2>/dev/null || true; fi; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; sudo rm -rf /var/kerberos/tr-mit /var/kerberos/tr-ours /var/kerberos/tr-load /var/tmp/tr
EOS
)
    lab ssh klldap -- "$rcmd" || true
    lock_off
    lab reset klldap f44-docker
    echo "RESTORE_KLLDAP:$?"
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
    echo "CELL2_END"
}
trap 'cleanup; rm -rf "$SEC"' EXIT
lock_on
touched=1
echo "==== rpm ===="
if ! lab ssh klldap -- 'test -x /usr/sbin/kadmin.local && test -x /usr/sbin/kdb5_util && test -x /usr/bin/kadmin'; then
    lab ssh klldap -- 'sudo -n dnf install -y krb5-server krb5-workstation'
fi
lab ssh klldap -- 'rpm -q krb5-server krb5-workstation'
echo "==== probe ===="
echo "PROBE_BEGIN"
lab ssh klldap -- 'sudo -n bash -s' <<< 'echo OUT; echo ERR >&2; /usr/sbin/kadmin.local -r NOPE -q x </dev/null; echo KADMIN_RC:$?' | tee "$REC/probe-tee.txt"
echo "PROBE_END"
lab ssh klldap -- 'sudo systemctl stop krb5kdc kadmin 2>/dev/null || true; sudo systemctl mask krb5kdc kadmin 2>/dev/null || true; sudo pkill -9 krb5kdc || true; sudo pkill -9 kadmind || true; echo SERVICES_HELD'
lab ssh klldap -- 'sudo rm -rf /var/tmp/tr /var/kerberos/tr-mit /var/kerberos/tr-ours /var/kerberos/tr-load && sudo mkdir -p /var/tmp/tr /var/kerberos/tr-mit /var/kerberos/tr-ours && sudo chown lab:lab /var/tmp/tr && sudo chmod 700 /var/tmp/tr'
lab ssh klldap -- 'python3 -' << 'PY'
import pathlib, secrets
root = pathlib.Path("/var/tmp/tr")
pw = secrets.token_hex(16)
master = root / "master"
key = root / "key"
master.write_text(pw + "\n" + pw + "\n")
master.chmod(0o600)
key.write_text(secrets.token_hex(32) + "\n")
key.chmod(0o600)
print("SECRETS_READY", master.stat().st_size, key.stat().st_size)
PY
lab ssh klldap -- 'cat > /var/tmp/tr/krb5-embed-realm && chmod 755 /var/tmp/tr/krb5-embed-realm' < "$BIN"
lab ssh klldap -- 'cat > /var/tmp/tr/krb5-kdb && chmod 755 /var/tmp/tr/krb5-kdb' < "$KDB"
lab ssh klldap -- 'sha256sum /var/tmp/tr/krb5-embed-realm /var/tmp/tr/krb5-kdb'
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
install_side /var/kerberos/tr-mit "$SRC/tr-mit-kdc.conf"
install_side /var/kerberos/tr-ours "$SRC/tr-ours-kdc.conf"
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
[ "$crc" = 0 ] || stop "CREATE_RC $crc"
[ "$arc" = 0 ] || stop "SCRATCH_ADD_RC $arc"
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
[ "$brc" = 0 ] || stop "BOOT_RC $brc"
[ "$trc" = 0 ] || stop "TRUST_RC $trc"
echo "==== export ===="
dump_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
env KRB5_KDC_PROFILE=/var/kerberos/tr-ours/kdc.conf KRB5_CONFIG=/var/kerberos/tr-ours/krb5.conf \
    /var/tmp/tr/krb5-kdb -r KERBER.TEST dump /var/tmp/tr/ours.dump \
    >/var/tmp/tr/o-dump 2>/var/tmp/tr/e-dump
echo "DUMP_RC:$?"
if [ -f /var/tmp/tr/ours.dump ]; then echo "DUMP_LINES:$(wc -l < /var/tmp/tr/ours.dump)"; else echo "DUMP_LINES:absent"; fi
EOS
) || stop "ssh dump failed"
printf '%s\n' "$dump_out"
drc=$(printf '%s\n' "$dump_out" | awk -F: '$1=="DUMP_RC" {v=$2} END {print v}')
echo "==== dump stderr ===="
redact_guest /var/tmp/tr/e-dump
if [ "$drc" != 0 ]; then
    stop "DUMP_RC $drc"
fi
echo "==== reader A ===="
start_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
if ss -H -lntu sport = :88 | grep -q .; then echo PORT_BUSY; ss -lntup sport = :88 || true; exit 0; fi
env KRB5_KDC_PROFILE=/var/kerberos/tr-ours/kdc.conf KRB5_CONFIG=/var/kerberos/tr-ours/krb5.conf \
    nohup /var/tmp/tr/krb5-embed-realm >/var/tmp/tr/ours-serve.log 2>&1 &
echo $! > /var/tmp/tr/ours.pid
up=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ss -H -lntu sport = :88 | grep -q . && ss -H -lnt sport = :749 | grep -q .; then up=1; break; fi
    sleep 1
done
if [ "$up" = 1 ]; then echo PORT_UP; else echo PORT_DOWN; fi
EOS
)
printf '%s\n' "$start_out"
if printf '%s\n' "$start_out" | grep -q '^PORT_BUSY$'; then
    stop "port 88 busy"
fi
if printf '%s\n' "$start_out" | grep -q '^PORT_DOWN$'; then
    echo "==== serve log ===="
    redact_guest /var/tmp/tr/ours-serve.log
    stop "embed port down"
fi
a_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
runq() {
    tag=$1
    q=$2
    env KRB5_CONFIG=/var/kerberos/tr-ours/krb5.conf KRB5_KDC_PROFILE=/var/kerberos/tr-ours/kdc.conf \
        /usr/bin/kadmin -p admin/admin -k -t /var/kerberos/tr-ours/admin.keytab -r KERBER.TEST -q "$q" \
        </dev/null >/var/tmp/tr/o-$tag 2>/var/tmp/tr/e-$tag
    echo "RC:$tag:$?"
}
runq a-out 'getprinc krbtgt/OTHER.TEST'
runq a-in 'getprinc krbtgt/KERBER.TEST@OTHER.TEST'
EOS
) || stop "ssh reader A failed"
printf '%s\n' "$a_out"
echo "==== A captured ===="
redact_guest /var/tmp/tr/e-a-out
redact_guest /var/tmp/tr/o-a-out
redact_guest /var/tmp/tr/e-a-in
redact_guest /var/tmp/tr/o-a-in
rcmd=$(cat << 'EOS'
pid=$(sudo cat /var/tmp/tr/ours.pid 2>/dev/null || true); if [ -n "$pid" ]; then sudo kill "$pid" 2>/dev/null || true; sleep 1; sudo kill -9 "$pid" 2>/dev/null || true; fi; echo EMBED_STOPPED
EOS
)
lab ssh klldap -- "$rcmd"
echo "==== reader B ===="
lab ssh klldap -- 'sudo mkdir -p /var/kerberos/tr-load && sudo cp -a /var/kerberos/tr-ours/.k5.KERBER.TEST /var/kerberos/tr-load/.k5.KERBER.TEST && sudo cp -a /var/kerberos/tr-ours/kadm5.acl /var/kerberos/tr-load/kadm5.acl && sudo cp -a /var/kerberos/tr-ours/krb5.conf /var/kerberos/tr-load/krb5.conf'
lab ssh klldap -- "sudo tee /var/kerberos/tr-load/kdc.conf >/dev/null" < <(sed 's#/var/kerberos/tr-ours#/var/kerberos/tr-load#g' "$SRC/tr-ours-kdc.conf")
load_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
env KRB5_KDC_PROFILE=/var/kerberos/tr-load/kdc.conf KRB5_CONFIG=/var/kerberos/tr-load/krb5.conf \
    /usr/sbin/kdb5_util -r KERBER.TEST load /var/tmp/tr/ours.dump \
    </dev/null >/var/tmp/tr/o-load 2>/var/tmp/tr/e-load
echo "LOAD_RC:$?"
EOS
) || stop "ssh load failed"
printf '%s\n' "$load_out"
lrc=$(printf '%s\n' "$load_out" | awk -F: '$1=="LOAD_RC" {v=$2} END {print v}')
echo "==== load stderr ===="
redact_guest /var/tmp/tr/e-load
echo "==== load stdout ===="
redact_guest /var/tmp/tr/o-load
if [ "$lrc" != 0 ]; then
    stop "LOAD_RC $lrc"
fi
b_out=$(lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
set +e
runq() {
    root=$1
    tag=$2
    q=$3
    env KRB5_KDC_PROFILE=$root/kdc.conf KRB5_CONFIG=$root/krb5.conf \
        /usr/sbin/kadmin.local -r KERBER.TEST -q "$q" \
        </dev/null >/var/tmp/tr/o-$tag 2>/var/tmp/tr/e-$tag
    echo "RC:$tag:$?"
}
runq /var/kerberos/tr-mit mit-out 'getprinc krbtgt/OTHER.TEST'
runq /var/kerberos/tr-mit mit-in 'getprinc krbtgt/KERBER.TEST@OTHER.TEST'
runq /var/kerberos/tr-load b-out 'getprinc krbtgt/OTHER.TEST'
runq /var/kerberos/tr-load b-in 'getprinc krbtgt/KERBER.TEST@OTHER.TEST'
EOS
) || stop "ssh reader B failed"
printf '%s\n' "$b_out"
echo "==== stderr ===="
lab ssh klldap -- 'sudo -n python3 -' << 'PY'
import pathlib, sys
root = pathlib.Path("/var/tmp/tr")
secrets = []
for name in ("master", "key"):
    p = root / name
    if p.is_file():
        secrets.extend([ln for ln in p.read_text(errors="replace").splitlines() if ln])
secrets.sort(key=len, reverse=True)

def clean(text):
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    kept = []
    for line in text.splitlines():
        bad = any(len(tok) >= 32 and all(c in "0123456789abcdefABCDEF" for c in tok) for tok in line.split())
        kept.append("[redacted-hex]" if bad else line)
    return "\n".join(kept)

for tag in ("a-out", "a-in", "mit-out", "mit-in", "b-out", "b-in"):
    err = root / f"e-{tag}"
    out = root / f"o-{tag}"
    et = err.read_text(errors="replace") if err.is_file() else "E_ABSENT\n"
    ot = out.read_text(errors="replace") if out.is_file() else "O_ABSENT\n"
    sys.stdout.write(f"---- e {tag} ----\n")
    sys.stdout.write(clean(et) + ("\n" if not et.endswith("\n") else ""))
    sys.stdout.write(f"---- o {tag} ----\n")
    sys.stdout.write(clean(ot) + ("\n" if not ot.endswith("\n") else ""))
print("OUTPUTS_DONE")
PY
# Pull the six stdout files. A 32-hex token is replaced. The rest of a key line stays.
lab ssh klldap -- 'sudo -n python3 -' > "$REC/bodies.txt" << 'PY'
import pathlib, re, sys
root = pathlib.Path("/var/tmp/tr")
secrets = []
for name in ("master", "key"):
    p = root / name
    if p.is_file():
        secrets.extend([ln for ln in p.read_text(errors="replace").splitlines() if ln])
secrets.sort(key=len, reverse=True)
hex_tok = re.compile(r"(?<!\S)[0-9a-fA-F]{32,}(?!\S)")

def clean(text):
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    return hex_tok.sub("[redacted-hex]", text)

for tag in ("mit-out", "mit-in", "a-out", "a-in", "b-out", "b-in"):
    out = root / f"o-{tag}"
    ot = out.read_text(errors="replace") if out.is_file() else ""
    sys.stdout.write(f"==== {tag} ====\n")
    sys.stdout.write(clean(ot))
    if ot and not ot.endswith("\n"):
        sys.stdout.write("\n")
PY
python3 - "$REC/bodies.txt" << 'PY'
import re, sys
from pathlib import Path
keep = ("maximum ticket life", "maximum renewable life", "attributes", "number of keys", "key:", "expiration date")
hex_tok = re.compile(r"(?<!\S)[0-9a-fA-F]{32,}(?!\S)")

def fields(lines):
    out = []
    for line in lines:
        low = line.strip().lower()
        if not low.startswith(keep):
            continue
        out.append(hex_tok.sub("[redacted-hex]", line.strip()))
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

got = blocks(Path(sys.argv[1]).read_text(errors="replace"))

def show(title, left, right):
    a, b = fields(got.get(left, [])), fields(got.get(right, []))
    print(title)
    print("LEFT")
    print("\n".join(a))
    print("RIGHT")
    print("\n".join(b))
    same = bool(a) and a == b
    print(f"{title}_{'SAME' if same else 'DIFF'}")

show("TR_CELL2_A_OUT", "mit-out", "a-out")
show("TR_CELL2_A_IN", "mit-in", "a-in")
show("TR_CELL2_B_OUT", "mit-out", "b-out")
show("TR_CELL2_B_IN", "mit-in", "b-in")
PY
echo "CELL2_QUERY_DONE"
exit 0
