#!/usr/bin/env bash
# MIT kadmind leg of kadmin-gate (GSS-RPC 749). KEEP-attach in CI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/kadmin-glob-cells.sh"
. "$ROOT/scripts/lib/kadmin-common.sh"
need_bins krb5-kdc krb5-kdb krb5-kadmind krb5-kadmin-local

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-gate"
NAME_MIT="kerber-rust-kadmin-mit"
KADMIND_PORT=749
MIT_IPROP_PORT=2121
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"
load_rust_snap() {
    local f="$SCRATCH/kadmin-rust-$1"
    local k="$f.key"
    [ -f "$f" ] || die "missing rust snapshot $1 (run kadmin-rust-gate.sh and kadmin-rust-acl-gate.sh first, KERBER_KADMIN_KEEP=1)"
    [ -f "$k" ] || die "missing rust snapshot key $1"
    [ "$(cat "$k")" = "$(_snap_key)" ] || die "stale rust snapshot $1 (tree/run mismatch)"
    cat "$f"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image
docker inspect "$NAME" >/dev/null 2>&1 || die "kadmin-mit-gate needs rust container (run kadmin-rust-gate.sh with KERBER_KADMIN_KEEP=1 first)"
HIST_GET="$(load_rust_snap HIST_GET)"
GETPRIVS="$(load_rust_snap GETPRIVS)"
GETPOL="$(load_rust_snap GETPOL)"
GETF="$(load_rust_snap GETF)"
GETU="$(load_rust_snap GETU)"
GETNM="$(load_rust_snap GETNM)"

echo "==== MIT kadmind lockdown cells ===="
docker rm -f "$NAME_MIT" >/dev/null 2>&1 || true
docker run -d --name "$NAME_MIT" "$IMAGE" >/dev/null
_kadmin_cleanup "docker rm -f '$NAME_MIT' >/dev/null 2>&1 || true"
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME_MIT" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    docker logs "$NAME_MIT" >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT harness did not become ready"'
    exit 1
fi
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw extract-secret extract/admin'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw adminpassword admin/admin'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw norename-secret norename'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw scoped-secret scoped'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw restricted-secret restricted'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw nodel-secret nodel'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw victim-secret victim'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw ro-secret ro'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw rolist-secret rolist'
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *e" "admin@KERBER.TEST *e" "extract/admin@KERBER.TEST *e" "norename@KERBER.TEST acilm" "scoped@KERBER.TEST ad *@KERBER.TEST" "restricted@KERBER.TEST a *@KERBER.TEST -clearpolicy" "nodel@KERBER.TEST *D" "ro@KERBER.TEST i" "rolist@KERBER.TEST l" "some_alias@KERBER.TEST a aliasname@KERBER.TEST" "some_alias@KERBER.TEST m user@KERBER.TEST" "restricted_alias@KERBER.TEST ai *@KERBER.TEST +requires_preauth" > /var/kerberos/krb5kdc/kadm5.acl'
echo "==== MIT backdate user last_pwd_change to 1000000000 (kdb5_util dump, edit tl-data 1, load) ===="
docker exec "$NAME_MIT" sh -c 'kdb5_util dump /tmp/bd.dump >/dev/null 2>&1'
docker exec -i "$NAME_MIT" python3 - <<'PY'
import struct
lines = open("/tmp/bd.dump").read().split("\n")
out = []
for l in lines:
    if l.startswith("princ") and "\tuser@KERBER.TEST\t" in l:
        f = l.split("\t")
        for i in range(15, len(f) - 2):
            if f[i] == "1" and f[i + 1] == "4" and len(f[i + 2]) == 8:
                f[i + 2] = struct.pack("<I", 1000000000).hex()
                break
        l = "\t".join(f)
    out.append(l)
open("/tmp/bd.dump", "w").write("\n".join(out))
PY
docker exec "$NAME_MIT" sh -c 'kdb5_util load /tmp/bd.dump >/dev/null 2>&1'
MIT_BD="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc user' 2>&1 || true)"
echo "$MIT_BD" | grep -F 'Last password change: Sun Sep 09 01:46:40 UTC 2001'
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME_MIT" 749 || die "MIT kadmind still bound :749 after kill"
docker exec "$NAME_MIT" sh -c 'cat >/tmp/mit-iprop-kdc.conf <<EOF
[kdcdefaults]
    kdc_ports = 88
[realms]
    KERBER.TEST = {
        database_name = /var/lib/krb5kdc/principal
        acl_file = /var/kerberos/krb5kdc/kadm5.acl
        key_stash_file = /var/lib/krb5kdc/.k5.KERBER.TEST
        kadmind_port = '"$KADMIND_PORT"'
        master_key_type = aes256-cts-hmac-sha384-192
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        iprop_enable = true
        iprop_port = '"$MIT_IPROP_PORT"'
        iprop_listen = 0.0.0.0:'"$MIT_IPROP_PORT"'
        iprop_master_ulogsize = 1000
    }
EOF'
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -randkey kiprop/testhost.kerber.test' 
docker exec -d -e KRB5_KDC_PROFILE=/tmp/mit-iprop-kdc.conf "$NAME_MIT" kadmind
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$KADMIND_PORT),0.3);t=socket.create_connection(('127.0.0.1',$MIT_IPROP_PORT),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen"'
    exit 1
fi
echo "==== MIT kadmind AUTH_NONE is AUTH_TOOWEAK ===="
kadmind_auth_too_weak "$NAME_MIT"
echo "==== MIT kadmind RPC PROG_UNAVAIL / PROG_MISMATCH / REPLY ===="
MIT_FRAMING="$(kadmind_rpc_framing "$NAME_MIT")"
echo "$MIT_FRAMING"
assert_k14_rpcsec "$MIT_FRAMING"

alias_cells "$NAME_MIT" /etc/krb5.conf admin/admin mit; glob_cells "$NAME_MIT" /etc/krb5.conf admin/admin mit "$SCRATCH/glob-mit.txt"

echo "==== crafted RPC listprincs over kadmin/changepw vs MIT kadmind ===="
compile_kadm5_changepw "$NAME_MIT"
MIT_CPW_LIST="$(kadm5_changepw_list "$NAME_MIT" admin/admin adminpassword /etc/krb5.conf 2>&1 || true)"
echo "$MIT_CPW_LIST"
echo "$MIT_CPW_LIST" | grep -F 'init_code=0'
echo "$MIT_CPW_LIST" | grep -F 'list_code=43787564'
echo "$MIT_CPW_LIST" | grep -F $'Operation requires ``list\'\' privilege'
if echo "$MIT_CPW_LIST" | grep -q 'list_code=0'; then
    echo "MIT changepw listprincs succeeded: $MIT_CPW_LIST" >&2
    exit 1
fi
echo "==== MIT kiprop service on kadm5 is AUTH_TOOWEAK (server) ===="
compile_kadm5_probe "$NAME_MIT"
MIT_KIPROP_PROBE="$(kadm5_probe "$NAME_MIT" admin/admin valid /etc/krb5.conf kiprop/testhost.kerber.test@KERBER.TEST 2>&1 || true)"
echo "$MIT_KIPROP_PROBE"
echo "$MIT_KIPROP_PROBE" | grep -F 'valid label=AUTH_TOOWEAK'
echo "==== MIT iprop program is also dispatched on kadmind_port once iprop_enable (process-wide svc registry): AUTH_NONE AUTH_TOOWEAK ===="
MIT_KADM_IPROP="$(kadmind_iprop_auth_gssapi "$NAME_MIT" "$KADMIND_PORT" 2>&1 || true)"
echo "$MIT_KADM_IPROP"
echo "$MIT_KADM_IPROP" | grep -F 'kadmin_on_iprop kind=init label=SUCCESS'
echo "$MIT_KADM_IPROP" | grep -F 'kadmin_on_iprop kind=data label=AUTH_FAILED'
echo "$MIT_KADM_IPROP" | grep -F 'kadmin_on_iprop kind=auth_none label=AUTH_TOOWEAK'
echo "==== MIT iprop program on iprop_port: AUTH_GSSAPI INIT SUCCESS, DATA no-context AUTH_FAILED, AUTH_NONE AUTH_TOOWEAK ===="
MIT_IPROP="$(kadmind_iprop_auth_gssapi "$NAME_MIT" "$MIT_IPROP_PORT" 2>&1 || true)"
echo "$MIT_IPROP"
echo "$MIT_IPROP" | grep -F 'kadmin_on_iprop kind=init label=SUCCESS'
echo "$MIT_IPROP" | grep -F 'kadmin_on_iprop kind=data label=AUTH_FAILED'
echo "$MIT_IPROP" | grep -F 'kadmin_on_iprop kind=auth_none label=AUTH_TOOWEAK'
echo "==== MIT iprop program: kiprop RPCSEC_GSS dispatched; kadmin acceptor and established AUTH_GSSAPI are AUTH_TOOWEAK ===="
MIT_IPROP_OK="$(kadm5_probe "$NAME_MIT" admin/admin iprop-valid /etc/krb5.conf kiprop/testhost.kerber.test@KERBER.TEST "$MIT_IPROP_PORT" 2>&1 || true)"
echo "$MIT_IPROP_OK"
echo "$MIT_IPROP_OK" | grep -F 'iprop-valid label=SUCCESS'
MIT_IPROP_ADM="$(kadm5_probe "$NAME_MIT" admin/admin iprop-valid /etc/krb5.conf kadmin/admin@KERBER.TEST "$MIT_IPROP_PORT" 2>&1 || true)"
echo "$MIT_IPROP_ADM"
echo "$MIT_IPROP_ADM" | grep -F 'iprop-valid label=AUTH_TOOWEAK'
MIT_IPROP_AG="$(kadm5_probe "$NAME_MIT" admin/admin iprop-auth-gssapi /etc/krb5.conf kadmin/admin@KERBER.TEST "$MIT_IPROP_PORT" 2>&1 || true)"
echo "$MIT_IPROP_AG"
echo "$MIT_IPROP_AG" | grep -F 'iprop-auth-gssapi label=AUTH_TOOWEAK'
echo "==== MIT RPCSEC_GSS integrity service listprincs ===="
compile_kadm5_integrity "$NAME_MIT"
MIT_INT_LIST="$(kadm5_integrity_list "$NAME_MIT" admin/admin adminpassword integrity /etc/krb5.conf 2>&1 || true)"
echo "$MIT_INT_LIST"
echo "$MIT_INT_LIST" | grep -F 'init_code=0'
echo "$MIT_INT_LIST" | grep -F 'svc=2'
echo "$MIT_INT_LIST" | grep -F 'clnt_stat=0'
echo "$MIT_INT_LIST" | grep -F 'list_code=0'
if echo "$MIT_INT_LIST" | grep -qE 'count=0$'; then
    echo "MIT integrity listprincs returned no principals" >&2
    exit 1
fi
echo "==== MIT RPCSEC_GSS integrity tampered checksum ===="
start_integ_tamper_proxy "$NAME_MIT"
wait_tcp_bound_in "$NAME_MIT" 1749 || die "MIT tamper proxy did not listen"
MIT_INT_TAMPER="$(kadm5_integrity_list "$NAME_MIT" admin/admin adminpassword integrity /etc/krb5.conf 1749 2>&1 || true)"
echo "$MIT_INT_TAMPER"
if echo "$MIT_INT_TAMPER" | grep -qF 'list_code=0'; then
    echo "MIT accepted tampered integrity checksum: $MIT_INT_TAMPER" >&2
    exit 1
fi
echo "$MIT_INT_TAMPER" | grep -E 'clnt_stat=11|garbage_args=1|accept_stat=4' || {
    echo "MIT tampered integrity checksum was not refused: $MIT_INT_TAMPER" >&2
    exit 1
}
echo "==== RPCSEC_GSS reject machine vs MIT kadmind ===="
rpcsec_reject_cells "$NAME_MIT" admin/admin /etc/krb5.conf
echo "==== MIT kadmin/history service on kadm5 ===="
# kadmin through kadmind (same as the rust HIST_BEFORE cell). kadmin.local
# against a live DB2 kadmind can print a lock error instead of UNK_PRINC.
MIT_HIST_BEFORE=""
for _ in $(seq 1 10); do
    MIT_HIST_BEFORE="$(mit_kadmin -e KRB5_CONFIG=/etc/krb5.conf \
        "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
    if echo "$MIT_HIST_BEFORE" | grep -qF 'Principal does not exist while retrieving "kadmin/history@KERBER.TEST".'; then
        break
    fi
    if echo "$MIT_HIST_BEFORE" | grep -qF 'Principal: kadmin/history@KERBER.TEST'; then
        break
    fi
    sleep 0.2
done
echo "$MIT_HIST_BEFORE"
echo "$MIT_HIST_BEFORE" | grep -F 'Principal does not exist while retrieving "kadmin/history@KERBER.TEST".' \
    || { echo "MIT kadmin/history before first policy chpass: $MIT_HIST_BEFORE" >&2; exit 1; }

kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addpol -minlength 8 -history 2 a8pol' 
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw a8-initial-secret -policy a8pol a8u' 
MIT_A8CPW="$(mit_kadmin_local "$NAME_MIT" -- -q 'cpw -pw sh a8u' 2>&1 || true)"
echo "$MIT_A8CPW"
echo "$MIT_A8CPW" | grep -F 'Password is too short while changing password for "a8u@KERBER.TEST".'
MIT_A8HIST="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$MIT_A8HIST" | grep -F 'Principal: kadmin/history@KERBER.TEST'
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addpol -history 2 g3bhist' 
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw hist-secret -policy g3bhist histee' 
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'cpw -pw hist-rotated histee' 
MIT_HIST_GET="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$MIT_HIST_GET"
echo "$MIT_HIST_GET" | grep -F 'Principal: kadmin/history@KERBER.TEST'
MIT_HIST_PROBE="$(kadm5_probe "$NAME_MIT" admin/admin valid /etc/krb5.conf kadmin/history@KERBER.TEST 2>&1 || true)"
echo "$MIT_HIST_PROBE"
echo "$MIT_HIST_PROBE" | grep -F 'valid label=AUTH_TOOWEAK'
echo "==== kadmin/history getprinc shape: Rust vs MIT (create_hist: max_life 64 s, no attributes, one key at kvno 2, no policy) ===="
# Last modified date is dropped so the Z1.1 rust/MIT getprinc byte-diff
# sees the modifier. History itself is created by kadmind RPC (`admin@`)
# on the Rust dump and by `kadmin.local` (`root/admin@`) on MIT — the
# modifier of `kadmin/history` is Z6.4's cell, not this shape check.
echo "$HIST_GET" | hist_shape | sed 's/^/rust: /'
echo "$MIT_HIST_GET" | hist_shape | sed 's/^/mit:  /'
diff <(echo "$HIST_GET" | hist_shape | grep -v '^Last modified:') \
     <(echo "$MIT_HIST_GET" | hist_shape | grep -v '^Last modified:')
echo "$HIST_GET" | grep -F 'Maximum ticket life: 0 days 00:01:04'
echo "$HIST_GET" | grep -F 'Key: vno 2, aes256-cts-hmac-sha384-192'
echo "==== MIT kadmin/admin is DISALLOW_TGT_BASED ===="
MIT_GETADM="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc kadmin/admin' 2>&1 || true)"
echo "$MIT_GETADM"
echo "$MIT_GETADM" | grep -E '^Attributes:' | grep -F 'DISALLOW_TGT_BASED'
MITTGT="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc krbtgt/KERBER.TEST')"
echo "$MITTGT"
echo "$MITTGT" | grep -F 'LOCKDOWN_KEYS'
MITCTL="$(mit_kadmin "$NAME_MIT" -- -p extract/admin -w extract-secret -q 'ktadd -norandkey -k /tmp/c.keytab user' 2>&1 || true)"
echo "$MITCTL"
if echo "$MITCTL" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "MIT extract/admin ktadd user failed: $MITCTL" >&2
    exit 1
fi
MITKTGT="$(mit_kadmin "$NAME_MIT" -- -p extract/admin -w extract-secret -q 'ktadd -norandkey -k /tmp/krbtgt.keytab krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$MITKTGT"
echo "$MITKTGT" | grep -F 'extract-keys'
MITKTCPW="$(mit_kadmin "$NAME_MIT" -- -p extract/admin -w extract-secret -q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw' 2>&1 || true)"
echo "$MITKTCPW"
echo "$MITKTCPW" | grep -F 'extract-keys'
MITDEL="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'delprinc -force kadmin/changepw' 2>&1 || true)"
echo "$MITDEL"
echo "$MITDEL" | grep -F "delete'' privilege"
MITMOD="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'modprinc -lockdown_keys kadmin/changepw' 2>&1 || true)"
echo "$MITMOD"
echo "$MITMOD" | grep -F "modify'' privilege"
MITREN="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'renprinc -force kadmin/changepw kadmin/changepw2' 2>&1 || true)"
echo "$MITREN"
echo "$MITREN" | grep -F "delete'' privilege"

echo "==== C1 kadm5 create over the MIT kadmind: -randkey (NULL passwd) is a random key, -pw \"\" is PASS_Q_TOOSHORT ===="
# svr_principal.c:369,463-470: kadmin addprinc -randkey sends a NULL passwd,
# the server skips passwd_check and keys with krb5_dbe_crk, so an
# empty-password kinit fails; pwqual_empty.c refuses -pw "" with
# KADM5_PASS_Q_TOOSHORT, which the remote kadmin prints as the et text.
MIT_RK="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'addprinc -randkey rkempty' 2>&1 || true)"
echo "$MIT_RK"
echo "$MIT_RK" | grep -F 'Principal "rkempty@KERBER.TEST" created.'
MIT_RK_KINIT="$(docker exec "$NAME_MIT" sh -c 'printf "\n" | kinit rkempty@KERBER.TEST' 2>&1 || true)"
echo "$MIT_RK_KINIT"
echo "$MIT_RK_KINIT" | grep -F 'kinit: Password incorrect while getting initial credentials'
MIT_RK_EMPTY="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'addprinc -pw "" rpcempty' 2>&1 || true)"
echo "$MIT_RK_EMPTY"
echo "$MIT_RK_EMPTY" | grep -F 'add_principal: Password is too short while creating "rpcempty@KERBER.TEST".'
echo "c1_kadm5_randkey_and_empty=mit-leg"

echo "==== MIT ACL without d renprinc krbtgt is AUTH_INSUFFICIENT ===="
for run in 1 2; do
    echo "---- MIT norename krbtgt $run ----"
    MITRENACL="$(mit_kadmin "$NAME_MIT" -- -p norename -w norename-secret -q 'renprinc -force krbtgt/KERBER.TEST x' 2>&1 || true)"
    echo "$MITRENACL"
    echo "$MITRENACL" | grep -F 'Insufficient authorization for operation'
done
MITGETTGT="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc krbtgt/KERBER.TEST')"
echo "$MITGETTGT" | grep -F 'Principal: krbtgt/KERBER.TEST@KERBER.TEST'

echo "==== MIT ACL target pattern scoped addprinc user2 / svc/x ===="
MIT_U2="$(mit_kadmin "$NAME_MIT" -- -p scoped -w scoped-secret -q 'addprinc -pw x user2' 2>&1 || true)"
echo "$MIT_U2"
echo "$MIT_U2" | grep -F 'Principal "user2@KERBER.TEST" created.'
MIT_SVC="$(mit_kadmin "$NAME_MIT" -- -p scoped -w scoped-secret -q 'addprinc -pw x svc/x' 2>&1 || true)"
echo "$MIT_SVC"
echo "$MIT_SVC" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "svc/x@KERBER.TEST".'
MIT_REN_SVC="$(mit_kadmin "$NAME_MIT" -- -p scoped -w scoped-secret -q 'renprinc -force user2 svc/y' 2>&1 || true)"
echo "$MIT_REN_SVC"
echo "$MIT_REN_SVC" | grep -F 'Insufficient authorization for operation'
MIT_REN_U3="$(mit_kadmin "$NAME_MIT" -- -p scoped -w scoped-secret -q 'renprinc -force user2 user3' 2>&1 || true)"
echo "$MIT_REN_U3"
echo "$MIT_REN_U3" | grep -F 'Principal "user2@KERBER.TEST" renamed to "user3@KERBER.TEST".'
MIT_U9="$(mit_kadmin "$NAME_MIT" -- -p restricted -w restricted-secret -q 'addprinc -pw x -policy short8 user9' 2>&1 || true)"
echo "$MIT_U9"
echo "$MIT_U9" | grep -F 'Principal "user9@KERBER.TEST" created.'
MIT_GET_U9="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc user9')"
echo "$MIT_GET_U9"
echo "$MIT_GET_U9" | grep -F 'Policy: [none]'

echo "==== MIT ACL uppercase *D revokes delete ===="
MIT_NODEL="$(mit_kadmin "$NAME_MIT" -- -p nodel -w nodel-secret -q 'delprinc -force victim' 2>&1 || true)"
echo "$MIT_NODEL"
echo "$MIT_NODEL" | grep -F $'delete_principal: Operation requires ``delete\'\' privilege while deleting principal "victim@KERBER.TEST"'
if echo "$MIT_NODEL" | grep -qiE 'Principal "victim@KERBER.TEST" deleted'; then
    echo "MIT nodel *D granted delete: $MIT_NODEL" >&2
    exit 1
fi
MIT_GET_V="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc victim')"
echo "$MIT_GET_V"
echo "$MIT_GET_V" | grep -F 'Principal: victim@KERBER.TEST'

echo "==== MIT ACL list vs inquire ===="
MIT_LIST_I="$(mit_kadmin "$NAME_MIT" -- -p ro -w ro-secret -q 'listprincs' 2>&1 || true)"
echo "$MIT_LIST_I"
echo "$MIT_LIST_I" | grep -F $'get_principals: Operation requires ``list\'\' privilege while retrieving list.'
MIT_LIST_L="$(mit_kadmin "$NAME_MIT" -- -p rolist -w rolist-secret -q 'listprincs' 2>&1 || true)"
echo "$MIT_LIST_L"
echo "$MIT_LIST_L" | grep -F 'user@KERBER.TEST'
MIT_ADDPOL="$(mit_kadmin "$NAME_MIT" -- -p ro -w ro-secret -q 'addpol pol-ro' 2>&1 || true)"
echo "$MIT_ADDPOL"
echo "$MIT_ADDPOL" | grep -F $'add_policy: Operation requires ``add\'\' privilege while creating policy "pol-ro".'
MIT_SELFGET="$(mit_kadmin "$NAME_MIT" -- -p user -w userpassword -q 'getprinc user' 2>&1 || true)"
echo "$MIT_SELFGET"
echo "$MIT_SELFGET" | grep -F 'Principal: user@KERBER.TEST'

echo "==== MIT purgekeys krbtgt succeeds (no lockdown check) ===="
MITPURGE="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'purgekeys krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$MITPURGE"
echo "$MITPURGE" | grep -F 'Old keys for principal'
if echo "$MITPURGE" | grep -qiE 'locked down|PROTECT_KEYS'; then
    echo "MIT purgekeys refused krbtgt: $MITPURGE" >&2
    exit 1
fi

echo "==== MIT ACL file without admin is not replaced ===="
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME_MIT" 749 || die "MIT kadmind still bound :749 after kill"
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "scoped@KERBER.TEST ad *@KERBER.TEST" > /var/kerberos/krb5kdc/kadm5.acl'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-noadmin.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-noadmin.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen after admin-less ACL"'
    exit 1
fi
MIT_NOADMIN="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'getprinc user' 2>&1 || true)"
echo "$MIT_NOADMIN"
echo "$MIT_NOADMIN" | grep -F $'get_principal: Operation requires ``get\'\' privilege while retrieving "user@KERBER.TEST".'
if echo "$MIT_NOADMIN" | grep -q 'Principal: user'; then
    echo "MIT admin-less ACL granted admin/admin getprinc: $MIT_NOADMIN" >&2
    exit 1
fi

echo "==== MIT ACL unknown op letter refuses to start ===="
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME_MIT" 749 || die "MIT kadmind still bound :749 after kill"
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "bad@KERBER.TEST aZ" > /var/kerberos/krb5kdc/kadm5.acl'
set +e
docker exec "$NAME_MIT" sh -c 'timeout 3 kadmind -nofork >/tmp/kadmind-badacl.log 2>&1'
set -e
MIT_BAD="$(docker exec "$NAME_MIT" cat /tmp/kadmind-badacl.log 2>/dev/null || true)"
echo "$MIT_BAD"
echo "$MIT_BAD" | grep -F "Unrecognized ACL operation 'Z' in bad@KERBER.TEST aZ"
echo "$MIT_BAD" | grep -F "syntax error at line 1 <bad@KERBER...>"
echo "$MIT_BAD" | grep -F "while initializing ACL file, aborting"
if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
    echo "MIT kadmind started on unknown op letter" >&2
    exit 1
fi

echo "==== MIT ACL CRLF continuation refused ===="
docker exec "$NAME_MIT" python3 -c 'open("/var/kerberos/krb5kdc/kadm5.acl","wb").write(b"admin@KERBER.TEST \\\r\n a\n")'
set +e
docker exec "$NAME_MIT" sh -c 'timeout 3 kadmind -nofork >/tmp/kadmind-crlf.log 2>&1'
set -e
MIT_CRLF="$(docker exec "$NAME_MIT" cat /tmp/kadmind-crlf.log 2>/dev/null || true)"
echo "$MIT_CRLF"
echo "$MIT_CRLF" | grep -F "Unrecognized ACL operation"
echo "$MIT_CRLF" | grep -F "while initializing ACL file, aborting"
if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
    echo "MIT kadmind started on CRLF continuation ACL" >&2
    exit 1
fi

echo "==== MIT default ACL path missing refuses start ===="
docker exec "$NAME_MIT" sh -c '
python3 - <<PY
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
p.write_text("".join(ln for ln in p.read_text().splitlines(True) if "acl_file" not in ln))
PY
mv /var/kerberos/krb5kdc/kadm5.acl /tmp/kadm5.acl.bak 2>/dev/null || true
rm -f /var/krb5kdc/kadm5.acl
'
set +e
docker exec "$NAME_MIT" sh -c 'timeout 3 kadmind -nofork >/tmp/kadmind-noacl.log 2>&1'
set -e
MIT_NOACL="$(docker exec "$NAME_MIT" cat /tmp/kadmind-noacl.log 2>/dev/null || true)"
echo "$MIT_NOACL"
echo "$MIT_NOACL" | grep -F 'Cannot open /var/krb5kdc/kadm5.acl: No such file or directory while initializing ACL file, aborting'
if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
    echo "MIT kadmind started with no ACL file" >&2
    exit 1
fi

echo "==== MIT default ACL path present loads ===="
docker exec "$NAME_MIT" sh -c '
mkdir -p /var/krb5kdc
printf "%s\n" "admin@KERBER.TEST *" "*/admin@KERBER.TEST *" "kiprop/*@KERBER.TEST p" "keepoldset@KERBER.TEST s" > /var/krb5kdc/kadm5.acl
'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-defaultacl.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-defaultacl.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen on default ACL path"'
    exit 1
fi
MIT_GETPRIVS="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'getprivs' 2>&1 || true)"
echo "$MIT_GETPRIVS"
echo "$MIT_GETPRIVS" | grep -qiE 'GET|ADD|MODIFY|DELETE'
RUST_PRIV="$(echo "$GETPRIVS" | grep -i 'current privileges' || true)"
MIT_PRIV="$(echo "$MIT_GETPRIVS" | grep -i 'current privileges' || true)"
echo "getprivs_rust=$RUST_PRIV"
echo "getprivs_mit=$MIT_PRIV"
if [ -z "$RUST_PRIV" ] || [ "$RUST_PRIV" != "$MIT_PRIV" ]; then
    echo "getprivs legs differ: rust=[$RUST_PRIV] mit=[$MIT_PRIV]" >&2
    exit 1
fi

echo "==== MIT getprinc user@OTHER.REALM is UNK_PRINC ===="
MIT_FOREIGN="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'getprinc user@OTHER.REALM' 2>&1 || true)"
echo "$MIT_FOREIGN"
echo "$MIT_FOREIGN" | grep -F 'Principal does not exist'
echo "==== MIT addprinc user@OTHER.REALM creates ===="
MIT_ADDFOR="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'addprinc -pw x user@OTHER.REALM' 2>&1 || true)"
echo "$MIT_ADDFOR"
echo "$MIT_ADDFOR" | grep -F 'Principal "user@OTHER.REALM" created' || {
    echo "MIT addprinc user@OTHER.REALM did not create: $MIT_ADDFOR" >&2
    exit 1
}
MIT_GETFOR="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'getprinc user@OTHER.REALM' 2>&1 || true)"
echo "$MIT_GETFOR"
echo "$MIT_GETFOR" | grep -F 'Principal: user@OTHER.REALM' || {
    echo "MIT getprinc user@OTHER.REALM after create missed: $MIT_GETFOR" >&2
    exit 1
}
echo "==== MIT denied addprinc user@OTHER.REALM is add privilege ===="
MIT_DENYFOR="$(mit_kadmin "$NAME_MIT" -- -p user -w userpassword -q 'addprinc -pw x denied@OTHER.REALM' 2>&1 || true)"
echo "$MIT_DENYFOR"
echo "$MIT_DENYFOR" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "denied@OTHER.REALM".' || {
    echo "MIT denied addprinc missed add privilege: $MIT_DENYFOR" >&2
    exit 1
}
if echo "$MIT_DENYFOR" | grep -q 'Principal "denied@OTHER.REALM" created'; then
    echo "MIT denied addprinc created: $MIT_DENYFOR" >&2
    exit 1
fi
echo "==== MIT unauthorised modprinc nosuch is UNK_PRINC ===="
MIT_MODNS="$(mit_kadmin "$NAME_MIT" -- -p user -w userpassword -q 'modprinc +requires_preauth nosuch' 2>&1 || true)"
echo "$MIT_MODNS"
echo "$MIT_MODNS" | grep -F 'Principal does not exist'

echo "==== MIT unauthorised setstr nosuch is UNK_PRINC ===="
MIT_SETNS="$(mit_kadmin "$NAME_MIT" -- -p user -w userpassword -q 'setstr nosuch a b' 2>&1 || true)"
echo "$MIT_SETNS"
echo "$MIT_SETNS" | grep -F 'Principal does not exist'
echo "==== MIT unauthorised purgekeys nosuch is UNK_PRINC ===="
MIT_PURNS="$(mit_kadmin "$NAME_MIT" -- -p user -w userpassword -q 'purgekeys nosuch' 2>&1 || true)"
echo "$MIT_PURNS"
echo "$MIT_PURNS" | grep -F 'Principal does not exist'

echo "==== MIT unauthorised getprinc nosuch is UNK_PRINC ===="
MIT_NOSUCH="$(mit_kadmin "$NAME_MIT" -- -p user -w userpassword -q 'getprinc nosuch' 2>&1 || true)"
echo "$MIT_NOSUCH"
echo "$MIT_NOSUCH" | grep -F 'Principal does not exist'
if echo "$MIT_NOSUCH" | grep -qiE "requires \`\`get'' privilege"; then
    echo "MIT unauthorised getprinc nosuch was AUTH_GET: $MIT_NOSUCH" >&2
    exit 1
fi

echo "==== MIT policy min/max life getpol ===="
kadmin_q_ok --next-asserts mit_kadmin_local "$NAME_MIT" -- -q 'addpol -minlife 1h -maxlife 1d life'
MIT_GETPOL="$(mit_kadmin_local "$NAME_MIT" -- -q 'getpol life' 2>&1 || true)"
echo "$MIT_GETPOL"
echo "$MIT_GETPOL" | grep -F 'Minimum password life: 0 days 01:00:00'
echo "$MIT_GETPOL" | grep -F 'Maximum password life: 1 day 00:00:00'
echo "$MIT_GETPOL" | grep -F 'Minimum password length: 1'
echo "$MIT_GETPOL" | grep -F 'Minimum number of password character classes: 1'
echo "$MIT_GETPOL" | grep -F 'Number of old keys kept: 1'
echo "==== MIT addpol name-only getpol floors 1/1/1 ===="
kadmin_q_ok --next-asserts mit_kadmin_local "$NAME_MIT" -- -q 'addpol floors1'
MIT_GETF="$(mit_kadmin_local "$NAME_MIT" -- -q 'getpol floors1' 2>&1 || true)"
echo "$MIT_GETF"
echo "$MIT_GETF" | grep -F 'Minimum password length: 1'
echo "$MIT_GETF" | grep -F 'Minimum number of password character classes: 1'
echo "$MIT_GETF" | grep -F 'Number of old keys kept: 1'
echo "==== getpol output is identical on both legs (life, floors1) ===="
diff <(echo "$GETPOL" | grep -v '^Authenticating') <(echo "$MIT_GETPOL" | grep -v -e '^Authenticating' -e 'No dictionary file')
diff <(echo "$GETF" | grep -v '^Authenticating') <(echo "$MIT_GETF" | grep -v -e '^Authenticating' -e 'No dictionary file')
echo "==== MIT modpol -minlength 0 is BAD_LENGTH ===="
MIT_MOD0="$(mit_kadmin_local "$NAME_MIT" -- -q 'modpol -minlength 0 floors1' 2>&1 || true)"
echo "$MIT_MOD0"
echo "$MIT_MOD0" | grep -F 'Invalid password length' || {
    echo "MIT modpol -minlength 0 missed BAD_LENGTH: $MIT_MOD0" >&2
    exit 1
}
echo "==== MIT modpol minlife over maxlife is BAD_MIN_PASS_LIFE ===="
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addpol -maxlife 1d max1d'
MIT_MODM="$(mit_kadmin_local "$NAME_MIT" -- -q 'modpol -minlife 2d max1d' 2>&1 || true)"
echo "$MIT_MODM"
echo "$MIT_MODM" | grep -F 'Password minimum life is greater than password maximum life' || {
    echo "MIT modpol min>max missed BAD_MIN_PASS_LIFE: $MIT_MODM" >&2
    exit 1
}
echo "==== MIT modprinc +0x1ffffffff truncates ===="
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw hex-secret hexu' 
MIT_HEXF="$(mit_kadmin_local "$NAME_MIT" -- -q 'modprinc +0x1ffffffff hexu' 2>&1 || true)"
echo "$MIT_HEXF"
echo "$MIT_HEXF" | grep -F 'Principal "hexu@KERBER.TEST" modified.'
MIT_GETHEX="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc hexu' 2>&1 || true)"
echo "$MIT_GETHEX"
echo "$MIT_GETHEX" | grep -E 'Attributes:' | grep -F 'DISALLOW_ALL_TIX'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'modprinc -policy life user'
MIT_GETU="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc user' 2>&1 || true)"
echo "$MIT_GETU"
echo "$MIT_GETU" | grep -F 'Password expiration date:'
echo "$MIT_GETU" | grep -F 'Password expiration date:' | grep -qv '\[never\]'
echo "==== backdated last_pwd_change + maxlife 1d: expiration identical on both legs ===="
echo "$GETU" | grep -F 'Last password change: Sun Sep 09 01:46:40 UTC 2001'
echo "$MIT_GETU" | grep -F 'Last password change: Sun Sep 09 01:46:40 UTC 2001'
diff <(echo "$GETU" | grep -F 'Password expiration date:') <(echo "$MIT_GETU" | grep -F 'Password expiration date:')
echo "$MIT_GETU" | grep -F 'Password expiration date: Mon Sep 10 01:46:40 UTC 2001'
echo "==== MIT admin cpw new password then reuse ===="
MIT_CPWA="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'cpw -pw user-admin-new user' 2>&1 || true)"
echo "$MIT_CPWA"
echo "$MIT_CPWA" | grep -F 'Password for "user@KERBER.TEST" changed.'
MIT_GETU2="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc user' 2>&1 || true)"
echo "$MIT_GETU2" | grep -F 'Password expiration date:' | grep -v 2001 | grep -qv '\[never\]'
if echo "$MIT_CPWA" | grep -qiE 'minimum life|too soon|too recently|Cannot reuse'; then
    echo "MIT admin cpw new password failed: $MIT_CPWA" >&2
    exit 1
fi
MIT_CPWR="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'cpw -pw user-admin-new user' 2>&1 || true)"
echo "$MIT_CPWR"
echo "$MIT_CPWR" | grep -F 'Cannot reuse password' || {
    echo "MIT admin cpw reuse missed: $MIT_CPWR" >&2
    exit 1
}
echo "==== MIT self cpw min_life is PASS_TOOSOON after the admin cpw ===="
MIT_CPW1="$(mit_kadmin "$NAME_MIT" -- -p user -w user-admin-new -q 'cpw -pw user-new1 user' 2>&1 || true)"
echo "$MIT_CPW1"
echo "$MIT_CPW1" | grep -F "Current password's minimum life has not expired"
MIT_CPW2="$(mit_kadmin "$NAME_MIT" -- -p user -w user-admin-new -q 'cpw -pw user-new2 user' 2>&1 || true)"
echo "$MIT_CPW2"
echo "$MIT_CPW2" | grep -F "Current password's minimum life has not expired"
echo "==== MIT self keepold clamps to 5 ===="
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw keep-0 keepoldself'
pw='keep-0'
for i in 1 2 3 4 5 6; do
    nxt="keep-$i"
    kadmin_q_ok mit_kadmin "$NAME_MIT" -- -p keepoldself -w "$pw" -q "cpw -keepold -pw $nxt keepoldself"
    pw=$nxt
done
MIT_KEEPG="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc keepoldself' 2>&1 || true)"
echo "$MIT_KEEPG"
nkeys="$(echo "$MIT_KEEPG" | sed -n 's/^Key: vno \([0-9][0-9]*\).*/\1/p' | sort -u | wc -l | tr -d ' ')"
echo "mit_keepold_kvnos=$nkeys"
if [ "$nkeys" != 5 ]; then
    echo "MIT self keepold not 5: $nkeys $MIT_KEEPG" >&2
    exit 1
fi
echo "==== MIT self cpw -randkey -keepold x6 and setkey -keepold x6 clamp to 5 kvnos ===="
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw rand-0 keepoldrand'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw set-0 keepoldset'
MIT_RANDK="$(docker exec "$NAME_MIT" /tmp/kadm5-changepw-rpc --service kadmin/admin keepoldrand rand-0 KERBER.TEST randkey-keepold 6 2>&1 || true)"
echo "$MIT_RANDK"
echo "$MIT_RANDK" | grep -F 'randkey-keepold[6]=0'
MIT_SETK="$(docker exec "$NAME_MIT" /tmp/kadm5-changepw-rpc --service kadmin/admin keepoldset set-0 KERBER.TEST setkey-keepold 6 2>&1 || true)"
echo "$MIT_SETK"
echo "$MIT_SETK" | grep -F 'setkey-keepold[6]=0'
MIT_RANDG="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc keepoldrand' 2>&1 || true)"
nk="$(echo "$MIT_RANDG" | sed -n 's/^Key: vno \([0-9][0-9]*\).*/\1/p' | sort -u | wc -l | tr -d ' ')"
echo "mit_keepoldrand_kvnos=$nk"
if [ "$nk" != 5 ]; then
    echo "MIT keepoldrand randkey keepold x6 not clamped to 5: $nk $MIT_RANDG" >&2
    exit 1
fi
echo "==== MIT 1.22.2 setkey keepold drops the old keys (svr_principal.c n_new_key_data); pinned as the deviation ===="
MIT_SETG="$(mit_kadmin_local "$NAME_MIT" -- -q 'getprinc keepoldset' 2>&1 || true)"
echo "$MIT_SETG"
nk="$(echo "$MIT_SETG" | sed -n 's/^Key: vno \([0-9][0-9]*\).*/\1/p' | sort -u | wc -l | tr -d ' ')"
echo "mit_keepoldset_kvnos=$nk"
if [ "$nk" != 1 ]; then
    echo "MIT setkey keepold x6 no longer drops old keys (deviation row is stale): $nk $MIT_SETG" >&2
    exit 1
fi
echo "$MIT_SETG" | grep -F 'Key: vno 7,'
echo "==== MIT create_policy ignores an unmasked pw_max_life (KADM5_PW_MIN_LIFE only) ===="
MIT_UNM="$(docker exec "$NAME_MIT" /tmp/kadm5-changepw-rpc --service kadmin/admin admin/admin adminpassword KERBER.TEST addpol-minlife-unmasked-max nomax 2>&1 || true)"
echo "$MIT_UNM"
echo "$MIT_UNM" | grep -F 'addpol_code=0'
MIT_GETNM="$(mit_kadmin_local "$NAME_MIT" -- -q 'getpol nomax' 2>&1 || true)"
echo "$MIT_GETNM"
diff <(echo "$GETNM" | grep -v '^Authenticating') <(echo "$MIT_GETNM" | grep -v -e '^Authenticating' -e 'No dictionary file')
echo "==== MIT purgekeys locked-down target is allowed ===="
kadmin_q_try mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw lock-secret lockp' 
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'modprinc +lockdown_keys lockp'
MIT_PURGE_L="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'purgekeys lockp' 2>&1 || true)"
echo "$MIT_PURGE_L"
if echo "$MIT_PURGE_L" | grep -qiE 'protect|lockdown|Operation requires'; then
    echo "MIT purgekeys lockdown denied: $MIT_PURGE_L" >&2
    exit 1
fi

echo "==== MIT addprinc foo\\/admin then ACL */admin denies ===="
MIT_ADDESC="$(mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw slashsecret foo\/admin' 2>&1 || true)"
echo "$MIT_ADDESC"
echo "$MIT_ADDESC" | grep -F 'created'

echo "==== MIT ACL -maxlife 12:34 loads ===="
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME_MIT" 749 || die "MIT kadmind still bound :749 after kill"
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "admin@KERBER.TEST * *@KERBER.TEST -maxlife 12:34" "*/admin@KERBER.TEST *" > /var/krb5kdc/kadm5.acl'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-maxlife.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-maxlife.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen with -maxlife 12:34"'
    exit 1
fi

echo "==== MIT ACL -maxlife 42x loads as 42s ===="
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME_MIT" 749 || die "MIT kadmind still bound :749 after kill"
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "admin@KERBER.TEST * *@KERBER.TEST -maxlife 42x" "*/admin@KERBER.TEST * *@KERBER.TEST -maxlife 42x" > /var/krb5kdc/kadm5.acl'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-42x.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-42x.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen with -maxlife 42x"'
    exit 1
fi
kadmin_q_try mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'addprinc -pw x life42' 
MIT_LIFE42="$(mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'getprinc life42' 2>&1 || true)"
echo "$MIT_LIFE42"
echo "$MIT_LIFE42" | grep -F 'Maximum ticket life: 0 days 00:00:42' || {
    echo "MIT 42x did not apply 42s max life: $MIT_LIFE42" >&2
    exit 1
}

echo "==== MIT ACL -maxlife 3dd refuses ===="
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME_MIT" 749 || die "MIT kadmind still bound :749 after kill"
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "admin@KERBER.TEST * *@KERBER.TEST -maxlife 3dd" > /var/krb5kdc/kadm5.acl'
set +e
docker exec "$NAME_MIT" sh -c 'timeout 3 kadmind -nofork >/tmp/kadmind-3dd.log 2>&1'
set -e
MIT_BADDELTA="$(docker exec "$NAME_MIT" cat /tmp/kadmind-3dd.log 2>/dev/null || true)"
echo "$MIT_BADDELTA"
echo "$MIT_BADDELTA" | grep -F 'invalid restrictions: -maxlife 3dd'
echo "$MIT_BADDELTA" | grep -F 'syntax error at line 1 <admin@KERB...>'
echo "$MIT_BADDELTA" | grep -F 'while initializing ACL file, aborting'
if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
    echo "MIT kadmind started with -maxlife 3dd" >&2
    exit 1
fi

echo "==== MIT ACL */admin does not match foo\\/admin ===="
docker exec "$NAME_MIT" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *" > /var/krb5kdc/kadm5.acl'
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind-esc.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_MIT" cat /tmp/kadmind-esc.log >&2 || true
    log "kadmin.gate" "error" ',"error":"MIT kadmind did not listen with */admin ACL"'
    exit 1
fi
MIT_ESCDENY="$(mit_kadmin "$NAME_MIT" -- -p 'foo\/admin' -w slashsecret -q 'listprincs' 2>&1 || true)"
echo "$MIT_ESCDENY"
echo "$MIT_ESCDENY" | grep -F $'Operation requires ``list\'\' privilege'
if echo "$MIT_ESCDENY" | grep -q 'user@KERBER.TEST'; then
    echo "MIT foo\\/admin matched */admin: $MIT_ESCDENY" >&2
    exit 1
fi

echo "==== MIT kadmin modprinc -unlock against Rust kadmind ===="
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
wait_gone_in "$NAME" 749 || die "kadmind still bound :749 after kill"
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST *" > /tmp/kadm5.acl'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-unlock.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-unlock.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-unlock.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen for unlock"'
    exit 1
fi
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addpol -maxfailure 1 -lockoutduration 0s -failurecountinterval 0s unlockpol'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw unlock-secret -policy unlockpol +requires_preauth unlocku'
docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME" sh -c 'printf "wrong-secret\n" | kinit unlocku@KERBER.TEST' >/dev/null 2>&1 || true
LOCKED="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME" sh -c 'printf "unlock-secret\n" | kinit unlocku@KERBER.TEST' 2>&1 || true)"
echo "$LOCKED"
echo "$LOCKED" | grep -qiE 'revoked|locked out|CLIENT_REVOKED' || {
    echo "unlocku was not locked after one failure: $LOCKED" >&2
    exit 1
}
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'modprinc -unlock unlocku'
docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME" sh -c 'printf "unlock-secret\n" | kinit unlocku@KERBER.TEST'
UNL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$UNL"
echo "$UNL" | grep -q 'unlocku@KERBER.TEST'
docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kdb dump /tmp/unlock.dump
docker exec "$NAME" grep unlocku /tmp/unlock.dump | grep -F $'\t1792\t' || {
    echo "Rust dump missing TL 1792 on unlocku" >&2
    docker exec "$NAME" grep unlocku /tmp/unlock.dump >&2 || true
    exit 1
}

echo "==== MIT kadmin modprinc -unlock against MIT kadmind ===="
# Same unknown-group pin as the rust unlock cell: a P-256-only MIT KDC
# plus an honest client is verify_support 24, which lockout.c counts.
docker exec "$NAME_MIT" sh -c 'cat >/tmp/kadmin-unlock-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    preferred_preauth_types = 2
    spake_preauth_groups = none
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addpol -maxfailure 1 -lockoutduration 0s -failurecountinterval 0s unlockpol'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'addprinc -pw unlock-secret -policy unlockpol +requires_preauth unlocku'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'getprinc unlocku'
MIT_WRONG="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME_MIT" sh -c 'printf "wrong-secret\n" | kinit unlocku@KERBER.TEST' 2>&1 || true)"
echo "$MIT_WRONG"
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -q 'getprinc unlocku'
MIT_LOCKED="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME_MIT" sh -c 'printf "unlock-secret\n" | kinit unlocku@KERBER.TEST' 2>&1 || true)"
echo "$MIT_LOCKED"
echo "$MIT_LOCKED" | grep -qiE 'revoked|locked out|CLIENT_REVOKED' || {
    echo "MIT unlocku was not locked after one failure: $MIT_LOCKED" >&2
    exit 1
}
kadmin_q_ok mit_kadmin "$NAME_MIT" -- -p admin/admin -w adminpassword -q 'modprinc -unlock unlocku'
docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME_MIT" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/kadmin-unlock-krb5.conf \
    "$NAME_MIT" sh -c 'printf "unlock-secret\n" | kinit unlocku@KERBER.TEST'
MIT_UNL="$(docker exec "$NAME_MIT" klist)"
echo "$MIT_UNL"
echo "$MIT_UNL" | grep -q 'unlocku@KERBER.TEST'
docker exec "$NAME_MIT" kdb5_util dump /tmp/unlock-mit.dump
docker exec "$NAME_MIT" grep unlocku /tmp/unlock-mit.dump | grep -F $'\t1792\t' || {
    echo "MIT dump missing TL 1792 on unlocku" >&2
    docker exec "$NAME_MIT" grep unlocku /tmp/unlock-mit.dump >&2 || true
    exit 1
}
log "kadmin.gate" "ok" ',"leg":"mit"'
exit 0
