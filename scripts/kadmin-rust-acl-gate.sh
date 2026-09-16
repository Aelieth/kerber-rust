#!/usr/bin/env bash
# Rust kadmind ACL-restart / policy cells of kadmin-gate. Attaches to the
# rust-gate container (KERBER_KADMIN_KEEP=1). KEEP-attach in CI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-glob-cells.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kadmin-gate}"
mkdir -p "$SCRATCH"
_snap_key() {
    printf '%s-%s\n' "$(git rev-parse HEAD)" \
        "$(git status --porcelain -- ':!working' | sha256sum | awk '{print $1}')"
}
save_rust_snap() {
    printf '%s\n' "$2" >"$SCRATCH/kadmin-rust-$1"
    _snap_key >"$SCRATCH/kadmin-rust-$1.key"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
    exit 1
fi
docker inspect "$NAME" >/dev/null 2>&1 || die "kadmin-rust-acl-gate needs rust container (run kadmin-rust-gate.sh with KERBER_KADMIN_KEEP=1 first)"

alias_cells "$NAME" /tmp/kadmin-krb5.conf admin@KERBER.TEST rust
glob_cells "$NAME" /tmp/kadmin-krb5.conf admin@KERBER.TEST rust "$SCRATCH/glob-rust.txt"

echo "==== ACL file without admin@ is not replaced ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 749 || true
docker exec "$NAME" sh -c 'printf "%s\n" "scoped@KERBER.TEST ad *@KERBER.TEST" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-noadmin.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-noadmin.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-noadmin.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen after admin-less ACL"'
    exit 1
fi
NOADMIN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user' 2>&1 || true)"
echo "$NOADMIN"
echo "$NOADMIN" | grep -F $'get_principal: Operation requires ``get\'\' privilege while retrieving "user@KERBER.TEST".'
if echo "$NOADMIN" | grep -q 'Principal: user'; then
    echo "admin-less ACL granted admin getprinc: $NOADMIN" >&2
    exit 1
fi

echo "==== ACL unknown op letter refuses to start ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 749 || true
docker exec "$NAME" sh -c 'printf "%s\n" "bad@KERBER.TEST aZ" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-badacl.log 2>&1'
wait_log "$NAME" /tmp/kadmind-badacl.log "Unrecognized ACL" || true
BADLOG="$(docker exec "$NAME" cat /tmp/kadmind-badacl.log 2>/dev/null || true)"
echo "$BADLOG"
echo "$BADLOG" | grep -F "Unrecognized ACL operation 'Z' in bad@KERBER.TEST aZ"
echo "$BADLOG" | grep -F "syntax error at line 1 <bad@KERBER...>"
echo "$BADLOG" | grep -F "while initializing ACL file, aborting"
if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-badacl.log 2>/dev/null; then
    echo "kadmind started on unknown op letter" >&2
    exit 1
fi

echo "==== ACL CRLF continuation refused ===="
docker exec "$NAME" python3 -c 'open("/tmp/kadm5.acl","wb").write(b"admin@KERBER.TEST \\\r\n a\n")'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-crlf.log 2>&1'
wait_log "$NAME" /tmp/kadmind-crlf.log "Unrecognized ACL" || true
CRLFLOG="$(docker exec "$NAME" cat /tmp/kadmind-crlf.log 2>/dev/null || true)"
echo "$CRLFLOG"
echo "$CRLFLOG" | grep -F "Unrecognized ACL operation"
if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-crlf.log 2>/dev/null; then
    echo "kadmind started on CRLF continuation ACL" >&2
    exit 1
fi

echo "==== default ACL path missing refuses start ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 749 || true
docker exec "$NAME" sh -c '
python3 - <<PY
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
p.write_text("".join(ln for ln in p.read_text().splitlines(True) if "acl_file" not in ln))
PY
mv /tmp/kadm5.acl /tmp/kadm5.acl.bak 2>/dev/null || true
'
set +e
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c 'timeout 3 /tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-noacl.log 2>&1'
set -e
NOACL="$(docker exec "$NAME" cat /tmp/kadmind-noacl.log 2>/dev/null || true)"
echo "$NOACL"
echo "$NOACL" | grep -F 'Cannot open /tmp/kadm5.acl: No such file or directory while initializing ACL file, aborting'
if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-noacl.log 2>/dev/null; then
    echo "kadmind started with no ACL file" >&2
    exit 1
fi

echo "==== default ACL path present loads ===="
docker exec "$NAME" sh -c 'mv /tmp/kadm5.acl.bak /tmp/kadm5.acl'
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST *" "kiprop/*@KERBER.TEST p" "keepoldset@KERBER.TEST s" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-defaultacl.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-defaultacl.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-defaultacl.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen on default ACL path"'
    exit 1
fi
GETPRIVS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprivs' 2>&1 || true)"
save_rust_snap GETPRIVS "$GETPRIVS"
echo "$GETPRIVS"
echo "$GETPRIVS" | grep -qiE 'GET|ADD|MODIFY|DELETE'

echo "==== getprinc user@OTHER.REALM is UNK_PRINC ===="
FOREIGN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user@OTHER.REALM' 2>&1 || true)"
echo "$FOREIGN"
echo "$FOREIGN" | grep -F 'Principal does not exist'
echo "==== addprinc user@OTHER.REALM creates ===="
ADDFOR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw x user@OTHER.REALM' 2>&1 || true)"
echo "$ADDFOR"
echo "$ADDFOR" | grep -F 'Principal "user@OTHER.REALM" created' || {
    echo "addprinc user@OTHER.REALM did not create: $ADDFOR" >&2
    exit 1
}
GETFOR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user@OTHER.REALM' 2>&1 || true)"
echo "$GETFOR"
echo "$GETFOR" | grep -F 'Principal: user@OTHER.REALM' || {
    echo "getprinc user@OTHER.REALM after create missed: $GETFOR" >&2
    exit 1
}
echo "==== denied addprinc user@OTHER.REALM is add privilege ===="
DENYFOR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w userpassword -q 'addprinc -pw x denied@OTHER.REALM' 2>&1 || true)"
echo "$DENYFOR"
echo "$DENYFOR" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "denied@OTHER.REALM".' || {
    echo "denied addprinc missed add privilege: $DENYFOR" >&2
    exit 1
}
if echo "$DENYFOR" | grep -q 'Principal "denied@OTHER.REALM" created'; then
    echo "denied addprinc created: $DENYFOR" >&2
    exit 1
fi
echo "==== unauthorised modprinc nosuch is UNK_PRINC ===="
MODNS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w userpassword -q 'modprinc +requires_preauth nosuch' 2>&1 || true)"
echo "$MODNS"
echo "$MODNS" | grep -F 'Principal does not exist'
if echo "$MODNS" | grep -qiE "requires \`\`modify'' privilege"; then
    echo "unauthorised modprinc nosuch was AUTH_MODIFY: $MODNS" >&2
    exit 1
fi
echo "==== unauthorised setstr nosuch is UNK_PRINC ===="
SETNS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w userpassword -q 'setstr nosuch a b' 2>&1 || true)"
echo "$SETNS"
echo "$SETNS" | grep -F 'Principal does not exist'
echo "==== unauthorised purgekeys nosuch is UNK_PRINC ===="
PURNS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w userpassword -q 'purgekeys nosuch' 2>&1 || true)"
echo "$PURNS"
echo "$PURNS" | grep -F 'Principal does not exist'

echo "==== unauthorised getprinc nosuch is UNK_PRINC ===="
NOSUCH="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w userpassword -q 'getprinc nosuch' 2>&1 || true)"
echo "$NOSUCH"
echo "$NOSUCH" | grep -F 'Principal does not exist'
if echo "$NOSUCH" | grep -qiE "requires \`\`get'' privilege"; then
    echo "unauthorised getprinc nosuch was AUTH_GET: $NOSUCH" >&2
    exit 1
fi

echo "==== policy min/max life getpol ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addpol -minlife 1h -maxlife 1d life'
GETPOL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getpol life' 2>&1 || true)"
save_rust_snap GETPOL "$GETPOL"
echo "$GETPOL"
echo "$GETPOL" | grep -F 'Minimum password life: 0 days 01:00:00'
echo "$GETPOL" | grep -F 'Maximum password life: 1 day 00:00:00'
echo "$GETPOL" | grep -F 'Minimum password length: 1'
echo "$GETPOL" | grep -F 'Minimum number of password character classes: 1'
echo "$GETPOL" | grep -F 'Number of old keys kept: 1'
echo "==== addpol name-only getpol floors 1/1/1 ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addpol floors1'
GETF="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getpol floors1' 2>&1 || true)"
save_rust_snap GETF "$GETF"
echo "$GETF"
echo "$GETF" | grep -F 'Minimum password length: 1'
echo "$GETF" | grep -F 'Minimum number of password character classes: 1'
echo "$GETF" | grep -F 'Number of old keys kept: 1'
echo "==== modpol -minlength 0 is BAD_LENGTH ===="
MOD0="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modpol -minlength 0 floors1' 2>&1 || true)"
echo "$MOD0"
echo "$MOD0" | grep -F 'Invalid password length' || {
    echo "modpol -minlength 0 missed BAD_LENGTH: $MOD0" >&2
    exit 1
}
echo "==== modpol minlife over maxlife is BAD_MIN_PASS_LIFE ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addpol -maxlife 1d max1d'
MODM="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modpol -minlife 2d max1d' 2>&1 || true)"
echo "$MODM"
echo "$MODM" | grep -F 'Password minimum life is greater than password maximum life' || {
    echo "modpol min>max missed BAD_MIN_PASS_LIFE: $MODM" >&2
    exit 1
}
echo "==== modprinc +0x1ffffffff truncates ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw hex-secret hexu' || true
HEXF="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc +0x1ffffffff hexu' 2>&1 || true)"
echo "$HEXF"
GETHEX="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc hexu' 2>&1 || true)"
echo "$GETHEX"
echo "$GETHEX" | grep -E 'Attributes:' | grep -F 'DISALLOW_ALL_TIX'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc -policy life user'
GETU="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user' 2>&1 || true)"
save_rust_snap GETU "$GETU"
echo "$GETU"
echo "$GETU" | grep -F 'Password expiration date:'
echo "$GETU" | grep -F 'Password expiration date:' | grep -qv '\[never\]'
echo "==== admin cpw new password then reuse ===="
CPWA="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw user-admin-new user' 2>&1 || true)"
echo "$CPWA"
echo "$CPWA" | grep -F 'Password for "user@KERBER.TEST" changed.'
GETU2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user' 2>&1 || true)"
echo "$GETU2" | grep -F 'Password expiration date:' | grep -v 2001 | grep -qv '\[never\]'
if echo "$CPWA" | grep -qiE 'minimum life|too soon|too recently|Cannot reuse'; then
    echo "admin cpw new password failed: $CPWA" >&2
    exit 1
fi
CPWR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw user-admin-new user' 2>&1 || true)"
echo "$CPWR"
echo "$CPWR" | grep -F 'Cannot reuse password' || {
    echo "admin cpw reuse missed: $CPWR" >&2
    exit 1
}
echo "==== self cpw min_life is PASS_TOOSOON after the admin cpw ===="
CPW1="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w user-admin-new -q 'cpw -pw user-new1 user' 2>&1 || true)"
echo "$CPW1"
echo "$CPW1" | grep -F "Current password's minimum life has not expired"
CPW2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user -w user-admin-new -q 'cpw -pw user-new2 user' 2>&1 || true)"
echo "$CPW2"
echo "$CPW2" | grep -F "Current password's minimum life has not expired"
echo "==== self keepold clamps to 5 ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw keep-0 keepoldself'
pw=keep-0
for i in 1 2 3 4 5 6; do
    nxt="keep-$i"
    KEEP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
        "$NAME" kadmin -p keepoldself -w "$pw" -q "cpw -keepold -pw $nxt keepoldself" 2>&1 || true)"
    echo "$KEEP"
    pw=$nxt
done
KEEPG="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc keepoldself' 2>&1 || true)"
echo "$KEEPG"
nkeys="$(echo "$KEEPG" | sed -n 's/^Key: vno \([0-9][0-9]*\).*/\1/p' | sort -u | wc -l | tr -d ' ')"
echo "keepold_kvnos=$nkeys"
if [ "$nkeys" != 5 ]; then
    echo "self keepold not 5: $nkeys $KEEPG" >&2
    exit 1
fi
echo "==== self cpw -randkey -keepold x6 and setkey -keepold x6 clamp to 5 kvnos ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw rand-0 keepoldrand'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw set-0 keepoldset'
RANDK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    /tmp/kadm5-changepw-rpc --service kadmin/admin keepoldrand rand-0 KERBER.TEST randkey-keepold 6 2>&1 || true)"
echo "$RANDK"
echo "$RANDK" | grep -F 'randkey-keepold[6]=0'
SETK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    /tmp/kadm5-changepw-rpc --service kadmin/admin keepoldset set-0 KERBER.TEST setkey-keepold 6 2>&1 || true)"
echo "$SETK"
echo "$SETK" | grep -F 'setkey-keepold[6]=0'
for p in keepoldrand keepoldset; do
    KG="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "getprinc $p" 2>&1 || true)"
    nk="$(echo "$KG" | sed -n 's/^Key: vno \([0-9][0-9]*\).*/\1/p' | sort -u | wc -l | tr -d ' ')"
    echo "${p}_kvnos=$nk"
    if [ "$nk" != 5 ]; then
        echo "$p keepold x6 not clamped to 5: $nk $KG" >&2
        exit 1
    fi
done
echo "==== create_policy ignores an unmasked pw_max_life (KADM5_PW_MIN_LIFE only) ===="
UNM="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    /tmp/kadm5-changepw-rpc --service kadmin/admin admin adminpassword KERBER.TEST addpol-minlife-unmasked-max nomax 2>&1 || true)"
echo "$UNM"
echo "$UNM" | grep -F 'addpol_code=0'
GETNM="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getpol nomax' 2>&1 || true)"
save_rust_snap GETNM "$GETNM"
echo "$GETNM"
echo "$GETNM" | grep -F 'Maximum password life: 0 days 00:00:00'
echo "$GETNM" | grep -F 'Minimum password life: 0 days 01:00:00'
echo "==== purgekeys locked-down target is allowed ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw lock-secret lockp' || true
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc +lockdown_keys lockp'
PURGE_L="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'purgekeys lockp' 2>&1 || true)"
echo "$PURGE_L"
if echo "$PURGE_L" | grep -qiE 'protect|lockdown|Operation requires'; then
    echo "purgekeys lockdown denied: $PURGE_L" >&2
    exit 1
fi

echo "==== addprinc foo\\/admin then ACL */admin denies ===="
ADDESC="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw slashsecret foo\/admin' 2>&1 || true)"
echo "$ADDESC"
echo "$ADDESC" | grep -F 'created'

echo "==== ACL -maxlife 12:34 loads ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 749 || true
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST * *@KERBER.TEST -maxlife 12:34" "kiprop/*@KERBER.TEST p" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-maxlife.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-maxlife.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-maxlife.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen with -maxlife 12:34"'
    exit 1
fi

echo "==== ACL -maxlife 42x loads as 42s ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 749 || true
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST * *@KERBER.TEST -maxlife 42x" "kiprop/*@KERBER.TEST p" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-42x.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-42x.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-42x.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen with -maxlife 42x"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw x life42' || true
LIFE42="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc life42' 2>&1 || true)"
echo "$LIFE42"
echo "$LIFE42" | grep -F 'Maximum ticket life: 0 days 00:00:42' || {
    echo "42x did not apply 42s max life: $LIFE42" >&2
    exit 1
}

echo "==== ACL -maxlife 3dd refuses ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 749 || true
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST * *@KERBER.TEST -maxlife 3dd" > /tmp/kadm5.acl'
set +e
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c 'timeout 3 /tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-3dd.log 2>&1'
set -e
BADDELTA="$(docker exec "$NAME" cat /tmp/kadmind-3dd.log 2>/dev/null || true)"
echo "$BADDELTA"
echo "$BADDELTA" | grep -F 'invalid restrictions: -maxlife 3dd'
echo "$BADDELTA" | grep -F 'syntax error at line 1 <admin@KERB...>'
echo "$BADDELTA" | grep -F 'while initializing ACL file, aborting'
if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-3dd.log 2>/dev/null; then
    echo "kadmind started with -maxlife 3dd" >&2
    exit 1
fi

echo "==== ACL */admin does not match foo\\/admin ===="
docker exec "$NAME" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-esc.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-esc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-esc.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen with */admin ACL"'
    exit 1
fi
ESCDENY="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p 'foo\/admin' -w slashsecret -q 'listprincs' 2>&1 || true)"
echo "$ESCDENY"
echo "$ESCDENY" | grep -F $'Operation requires ``list\'\' privilege'
if echo "$ESCDENY" | grep -q 'user@KERBER.TEST'; then
    echo "foo\\/admin matched */admin: $ESCDENY" >&2
    exit 1
fi
log "kadmin.gate" "ok" ',"leg":"rust-acl"'
exit 0
