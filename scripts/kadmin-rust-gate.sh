#!/usr/bin/env bash
# Rust kadmind leg of kadmin-gate (GSS-RPC 749). KEEP-attach in CI.
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
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"
rm -f "$SCRATCH"/kadmin-rust-*

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
_kadmin_cleanup "docker rm -f '$NAME' >/dev/null 2>&1 || true"

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kadmind /tmp/krb5-kadmin-local

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *e
extract/admin@KERBER.TEST *e
norename@KERBER.TEST acilm
scoped@KERBER.TEST ad *@KERBER.TEST
restricted@KERBER.TEST a *@KERBER.TEST -clearpolicy
nodel@KERBER.TEST *D
ro@KERBER.TEST i
rolist@KERBER.TEST l
some_alias@KERBER.TEST a aliasname@KERBER.TEST
some_alias@KERBER.TEST m user@KERBER.TEST
restricted_alias@KERBER.TEST ai *@KERBER.TEST +requires_preauth
EOF'

echo "==== backdate user last_pwd_change to 1000000000 before kadmind loads the store ===="
docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kdb setlastpwd user 1000000000
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "kadmin.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

# kadm5_line_count: the kadmind log's `kadm5: ` stderr lines.
kadm5_line_count() {
    docker exec "$NAME" grep -c '^kadm5: ' /tmp/kadmind.log || true
}
# kadm5_garbage_probe: one RPC record holding a single zero byte; the call does
# not decode, so kadmind prints `kadm5: rpc garbage args`.
kadm5_garbage_probe() {
    docker exec "$NAME" python3 -c '
import socket, struct
s = socket.create_connection(("127.0.0.1", 749), 2)
s.sendall(struct.pack(">I", 0x80000000 | 1) + b"\x00")
s.settimeout(2)
try:
    while s.recv(4096):
        pass
except OSError:
    pass
s.close()
'
}
# kadm5_wait_count N: wait until the log holds N `kadm5: ` lines.
kadm5_wait_count() {
    for _ in $(seq 1 40); do
        [ "$(kadm5_line_count)" -ge "$1" ] && return 0
        sleep 0.1
    done
    return 1
}

echo "==== D1 kadmind stderr names an RPC call that does not decode ===="
d1_before="$(kadm5_line_count)"
kadm5_garbage_probe
kadm5_wait_count $((d1_before + 1)) || die "D1 no kadm5: line after the garbage probe"
docker exec "$NAME" grep -F 'kadm5: rpc garbage args' /tmp/kadmind.log \
    || die "D1 kadmind stderr has no kadm5: rpc garbage args line"
echo "RUST_kadmind_stderr_garbage_args"

echo "==== D2 kadmind stays silent on an oversize record; the garbage probe is the sync point ===="
d2_before="$(kadm5_line_count)"
docker exec "$NAME" python3 -c '
import socket, struct
s = socket.create_connection(("127.0.0.1", 749), 2)
s.sendall(struct.pack(">I", 0x80000000 | ((1 << 20) + 1)))
s.settimeout(2)
try:
    while s.recv(4096):
        pass
except OSError:
    pass
s.close()
'
kadm5_garbage_probe
kadm5_wait_count $((d2_before + 1)) || die "D2 no kadm5: line after the sync probe"
sleep 0.2
d2_after="$(kadm5_line_count)"
echo "kadm5 lines: before=$d2_before after=$d2_after"
[ "$d2_after" -eq $((d2_before + 1)) ] \
    || die "D2 kadm5: lines rose by $((d2_after - d2_before)), want 1 (the sync probe only)"
if docker exec "$NAME" grep -F 'kadm5: rpc record' /tmp/kadmind.log; then
    die "D2 kadmind printed the oversize record error"
fi
echo "RUST_kadmind_stderr_silent_record"

echo "==== Rust kadmind AUTH_NONE is AUTH_TOOWEAK ===="
kadmind_auth_too_weak "$NAME"
echo "==== Rust kadmind RPC PROG_UNAVAIL / PROG_MISMATCH / REPLY ===="
RUST_FRAMING="$(kadmind_rpc_framing "$NAME")"
echo "$RUST_FRAMING"
assert_k14_rpcsec "$RUST_FRAMING"

docker exec "$NAME" sh -c 'cat >/tmp/kadmin-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kadmin
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'
# Enc-ts only for unlocku kinit: rust --test-realm advertises P-256 SPAKE;
# MIT client default edwards25519 is verify_support 24, and lockout.c
# increments on that 24, so maxfailure=1 would revoke before enc-ts.
# preferred_preauth_types = 2 only reorders hints; unknown groups → NOTSUPP.
docker exec "$NAME" sh -c 'cat >/tmp/kadmin-unlock-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kadmin
    preferred_preauth_types = 2
    spake_preauth_groups = none
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== knob search: stock kadmin never selects kadmin/changepw ===="
HELP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" kadmin --help 2>&1 || true)"
echo "$HELP"
if echo "$HELP" | grep -qi changepw; then
    echo "kadmin --help mentioned changepw (CLI has no CHANGEPW_SERVICE flag)" >&2
    exit 1
fi
KADMIN_TRACE="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'listprincs' 2>&1 || true)"
echo "$KADMIN_TRACE"
echo "$KADMIN_TRACE" | grep -F 'Setting initial creds service to kadmin/admin'
if echo "$KADMIN_TRACE" | grep -F 'Setting initial creds service to kadmin/changepw'; then
    echo "stock kadmin selected kadmin/changepw as GSS service" >&2
    exit 1
fi
echo "kadmin.c:418-421 svcname = ADMIN_SERVICE or NULL; client_init.c:411 NULL -> kadmin/admin"

echo "==== crafted RPC listprincs over kadmin/changepw vs Rust kadmind ===="
compile_kadm5_changepw "$NAME"
CPW_LIST="$(kadm5_changepw_list "$NAME" admin@KERBER.TEST adminpassword /tmp/kadmin-krb5.conf 2>&1 || true)"
echo "$CPW_LIST"
echo "$CPW_LIST" | grep -F 'init_code=0'
echo "$CPW_LIST" | grep -F 'list_code=43787564'
echo "$CPW_LIST" | grep -F $'Operation requires ``list\'\' privilege'
if echo "$CPW_LIST" | grep -q 'list_count=' && echo "$CPW_LIST" | grep -qv 'list_count=0'; then
    if echo "$CPW_LIST" | grep -q 'list_code=0'; then
        echo "changepw listprincs succeeded: $CPW_LIST" >&2
        exit 1
    fi
fi
echo "==== kiprop service on kadm5 is AUTH_TOOWEAK (server) ===="
compile_kadm5_probe "$NAME"
KIPROP_PROBE="$(kadm5_probe "$NAME" admin@KERBER.TEST valid /tmp/kadmin-krb5.conf kiprop/testhost.kerber.test@KERBER.TEST 2>&1 || true)"
echo "$KIPROP_PROBE"
echo "$KIPROP_PROBE" | grep -F 'valid label=AUTH_TOOWEAK'
echo "==== AUTH_GSSAPI INIT IPROP_PROG on kadmind 749 (kadmin-on-iprop) ===="
KADM_IPROP="$(kadmind_iprop_auth_gssapi "$NAME" 2>&1 || true)"
echo "$KADM_IPROP"
echo "$KADM_IPROP" | grep -F 'kadmin_on_iprop kind=init label=SUCCESS'
echo "$KADM_IPROP" | grep -F 'kadmin_on_iprop kind=data label=AUTH_FAILED'
echo "$KADM_IPROP" | grep -F 'kadmin_on_iprop kind=auth_none label=AUTH_TOOWEAK'
echo "==== iprop program vs Rust kadmind: kiprop RPCSEC_GSS dispatched; kadmin acceptor and established AUTH_GSSAPI are AUTH_TOOWEAK ===="
IPROP_OK="$(kadm5_probe "$NAME" admin@KERBER.TEST iprop-valid /tmp/kadmin-krb5.conf kiprop/testhost.kerber.test@KERBER.TEST "$KADMIND_PORT" 2>&1 || true)"
echo "$IPROP_OK"
echo "$IPROP_OK" | grep -F 'iprop-valid label=SUCCESS'
IPROP_ADM="$(kadm5_probe "$NAME" admin@KERBER.TEST iprop-valid /tmp/kadmin-krb5.conf kadmin/admin@KERBER.TEST "$KADMIND_PORT" 2>&1 || true)"
echo "$IPROP_ADM"
echo "$IPROP_ADM" | grep -F 'iprop-valid label=AUTH_TOOWEAK'
IPROP_AG="$(kadm5_probe "$NAME" admin@KERBER.TEST iprop-auth-gssapi /tmp/kadmin-krb5.conf kadmin/admin@KERBER.TEST "$KADMIND_PORT" 2>&1 || true)"
echo "$IPROP_AG"
echo "$IPROP_AG" | grep -F 'iprop-auth-gssapi label=AUTH_TOOWEAK'
echo "==== RPCSEC_GSS integrity service listprincs vs Rust kadmind ===="
compile_kadm5_integrity "$NAME"
INT_LIST="$(kadm5_integrity_list "$NAME" admin@KERBER.TEST adminpassword integrity /tmp/kadmin-krb5.conf 2>&1 || true)"
echo "$INT_LIST"
echo "$INT_LIST" | grep -F 'init_code=0'
echo "$INT_LIST" | grep -F 'svc=2'
echo "$INT_LIST" | grep -F 'clnt_stat=0'
echo "$INT_LIST" | grep -F 'list_code=0'
if echo "$INT_LIST" | grep -qE 'count=0$'; then
    echo "Rust integrity listprincs returned no principals" >&2
    exit 1
fi
echo "==== RPCSEC_GSS integrity tampered checksum vs Rust kadmind ===="
start_integ_tamper_proxy "$NAME"
wait_tcp_bound_in "$NAME" 1749 || die "tamper proxy did not listen"
INT_TAMPER="$(kadm5_integrity_list "$NAME" admin@KERBER.TEST adminpassword integrity /tmp/kadmin-krb5.conf 1749 2>&1 || true)"
echo "$INT_TAMPER"
if echo "$INT_TAMPER" | grep -qF 'list_code=0'; then
    echo "Rust accepted tampered integrity checksum: $INT_TAMPER" >&2
    exit 1
fi
echo "$INT_TAMPER" | grep -E 'clnt_stat=11|garbage_args=1|accept_stat=4' || {
    echo "Rust tampered integrity checksum was not refused: $INT_TAMPER" >&2
    exit 1
}
echo "==== RPCSEC_GSS reject machine vs Rust kadmind ===="
rpcsec_reject_cells "$NAME" admin@KERBER.TEST /tmp/kadmin-krb5.conf
echo "==== MIT kadmin addprinc extra ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra'
echo "==== kadmind log ===="
wait_log "$NAME" /tmp/kadmind.log "Request: kadm5_create_principal" || true
KADMIND_LOG="$(docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true)"
echo "$KADMIND_LOG"
# M4c: MIT log_done / log_unauth (server_stubs.c:403-459). The successful admin
# addprinc logs "Request: ... success" and the changepw listprincs denial logs
# "Unauthorized request: ...", each with client/service/addr. Settled live
# against a MIT kadmind; the log is kept outside the repository.
echo "$KADMIND_LOG" \
    | grep -F 'Request: kadm5_create_principal, extra@KERBER.TEST, success, client=admin@KERBER.TEST, service=kadmin/admin@KERBER.TEST, addr=' \
    || { echo "Rust kadmind did not log the create like MIT log_done" >&2; exit 1; }
echo "$KADMIND_LOG" \
    | grep -F 'Unauthorized request: kadm5_get_principals' \
    | grep -F 'client=admin@KERBER.TEST' | grep -F 'service=kadmin/changepw@KERBER.TEST' \
    || { echo "Rust kadmind did not log the denied list like MIT log_unauth" >&2; exit 1; }

echo "==== kdc log (tail) ===="
docker exec "$NAME" tail -20 /tmp/kdc.log 2>/dev/null || true
echo "==== kinit extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-secret\n" | kinit extra@KERBER.TEST' || true
echo "==== kdc log after extra kinit ===="
docker exec "$NAME" grep -E 'reload store|persist |CLIENT|saved store|error' /tmp/kdc.log | tail -30 || true
docker exec "$NAME" ls -l /tmp/principal /tmp/stash 2>/dev/null || true
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin cpw extra ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw extra-rotated extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin getprinc extra ===="
GET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$GET"
echo "$GET" | grep -q 'Principal: extra@KERBER.TEST'
echo "$GET" | grep -q 'Number of keys: 4'
echo "$GET" | grep -qE 'Key: vno 2,'
PWDCHG="$(echo "$GET" | grep '^Last password change:')"
echo "$PWDCHG"
echo "$PWDCHG" | grep -v '\[never\]'
MODLINE="$(echo "$GET" | grep '^Last modified:')"
echo "$MODLINE"
echo "$MODLINE" | grep -v '1970'

echo "==== MIT kadmin cpw -keepold ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q \
    'addprinc -pw keep-secret keepoldu'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q \
    'cpw -keepold -pw keep-rotated keepoldu'
GETK="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc keepoldu' 2>&1 || true)"
echo "$GETK"
echo "$GETK" | grep -qE 'Key: vno 1,'
echo "$GETK" | grep -qE 'Key: vno 2,'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "keep-rotated\n" | kinit keepoldu@KERBER.TEST'

echo "==== MIT kadmin setstr/getstrs extra ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'setstr extra note hello-g3d'
STRS="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getstrs extra' 2>&1 || true)"
echo "$STRS"
echo "$STRS" | grep -q 'note: hello-g3d'

echo "==== MIT kadmin lockdown_keys ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw lock-secret lockee'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'modprinc +lockdown_keys lockee'
GETL="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc lockee' 2>&1 || true)"
echo "$GETL"
echo "$GETL" | grep -qi LOCKDOWN
CPWL="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw lock-rotated lockee' 2>&1 || true)"
echo "$CPWL"
if echo "$CPWL" | grep -qi 'changed'; then
    echo "lockdown cpw rewrote keys: $CPWL" >&2
    exit 1
fi
echo "$CPWL" | grep -F 'change-password'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "lock-secret\n" | kinit lockee@KERBER.TEST'
KTL="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/lockee-norand.keytab lockee' 2>&1 || true)"
echo "$KTL"
if echo "$KTL" | grep -qi 'added to keytab'; then
    echo "lockdown ktadd -norandkey leaked keys: $KTL" >&2
    exit 1
fi
CHR="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/lockee.keytab lockee' 2>&1 || true)"
echo "$CHR"
if echo "$CHR" | grep -qi 'added to keytab'; then
    echo "lockdown ktadd leaked keys: $CHR" >&2
    exit 1
fi
if docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/lockee.keytab lockee@KERBER.TEST 2>"$SCRATCH/lockee-kinit.err"; then
    echo "lockdown ktadd leaked keys for kinit -k" >&2
    exit 1
fi

echo "==== kadmin/history does not exist before the first policy chpass (create_hist is lazy) ===="
HIST_BEFORE="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$HIST_BEFORE"
echo "$HIST_BEFORE" | grep -F 'Principal does not exist while retrieving "kadmin/history@KERBER.TEST".'

echo "==== a failed short-password cpw still creates kadmin/history (before passwd_check) ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addpol -minlength 8 -history 2 a8pol'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw a8-initial-secret -policy a8pol a8u'
A8CPW="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw sh a8u' 2>&1 || true)"
echo "$A8CPW"
echo "$A8CPW" | grep -F 'Password is too short while changing password for "a8u@KERBER.TEST".'
A8HIST="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$A8HIST" | grep -F 'Principal: kadmin/history@KERBER.TEST'

echo "==== MIT kadmin purgekeys ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addpol -history 2 g3bhist'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw purge-secret -policy g3bhist purgee'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw purge-rotated purgee'
GETP="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc purgee' 2>&1 || true)"
echo "$GETP"
echo "$GETP" | grep -qE 'Key: vno 2,'
if echo "$GETP" | grep -qE 'Key: vno 1,'; then
    echo "getprinc listed password-history kvno 1: $GETP" >&2
    exit 1
fi
PURGE="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'purgekeys purgee' 2>&1 || true)"
echo "$PURGE"
echo "$PURGE" | grep -qi purged
if echo "$PURGE" | grep -qiE 'while purging|Operation failed|unknown procedure'; then
    echo "purgekeys failed: $PURGE" >&2
    exit 1
fi
GETP2="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc purgee' 2>&1 || true)"
echo "$GETP2"
echo "$GETP2" | grep -qE 'Key: vno 2,'
if echo "$GETP2" | grep -qE 'Key: vno 1,'; then
    echo "purgekeys left kvno 1: $GETP2" >&2
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "purge-rotated\n" | kinit purgee@KERBER.TEST'
KLISTP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTP"
echo "$KLISTP" | grep -q 'purgee@KERBER.TEST'

echo "==== kadmin/history service on kadm5 (created by the purgee chpass like kdb_get_hist_key) ===="
HIST_GET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
save_rust_snap HIST_GET "$HIST_GET"
echo "$HIST_GET"
echo "$HIST_GET" | grep -F 'Principal: kadmin/history@KERBER.TEST'
HIST_PROBE="$(kadm5_probe "$NAME" admin@KERBER.TEST valid /tmp/kadmin-krb5.conf kadmin/history@KERBER.TEST 2>&1 || true)"
echo "$HIST_PROBE"
echo "$HIST_PROBE" | grep -F 'valid label=AUTH_TOOWEAK'

echo "==== MIT kadmin listprincs ===="
LIST="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'listprincs' 2>&1 || true)"
echo "$LIST"
echo "$LIST" | grep -q 'extra@KERBER.TEST'
echo "$LIST" | grep -q 'user@KERBER.TEST'

echo "==== MIT kadmin modprinc +requires_preauth extra ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'modprinc +requires_preauth extra'
GET2="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$GET2"
echo "$GET2" | grep -q 'REQUIRES_PRE_AUTH'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'
KLIST3="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST3"
echo "$KLIST3" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin cpw -randkey extra + ktadd + kinit -k ===="
PWD_BEFORE="$(echo "$GET2" | grep '^Last password change:')"
MOD_BEFORE="$(echo "$GET2" | grep '^Last modified:')"
sleep 1 # proto: last-password-change timestamp
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'cpw -randkey extra'
GETR="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$GETR"
PWDR="$(echo "$GETR" | grep '^Last password change:')"
MODR="$(echo "$GETR" | grep '^Last modified:')"
echo "$PWDR"
echo "$MODR"
echo "$PWDR" | grep -v '\[never\]'
echo "$MODR" | grep -v '1970'
if [ "$PWDR" = "$PWD_BEFORE" ]; then
    echo "Last password change did not move after cpw -randkey: $PWDR" >&2
    exit 1
fi
if [ "$MODR" = "$MOD_BEFORE" ]; then
    echo "Last modified did not move after cpw -randkey: $MODR" >&2
    exit 1
fi
if docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'; then
    echo "old password still worked after chrand" >&2
    exit 1
fi
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/extra.keytab extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/extra.keytab extra@KERBER.TEST
KLIST4="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST4"
echo "$KLIST4" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin ktadd -norandkey extra + kinit -k ===="
KTN="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/extra-norand.keytab extra' 2>&1 || true)"
echo "$KTN"
echo "$KTN" | grep -qi 'added to keytab'
if echo "$KTN" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "ktadd -norandkey failed: $KTN" >&2
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/extra-norand.keytab extra@KERBER.TEST
KLISTN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTN"
echo "$KLISTN" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin renprinc (randkey; default-salt password kinit is not required) ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -randkey renamefrom'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'renprinc -force renamefrom renameto'
RENGET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc renameto' 2>&1 || true)"
echo "$RENGET"
echo "$RENGET" | grep -q 'Principal: renameto@KERBER.TEST'
RENOLD="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc renamefrom' 2>&1 || true)"
echo "$RENOLD"
echo "$RENOLD" | grep -qiE 'does not exist|not found|UNK_PRINC'

echo "==== C1 kadm5 create over the Rust kadmind: -randkey (NULL passwd) is a random key, -pw \"\" is PASS_Q_TOOSHORT ===="
# Rust leg of the C1 cell; the MIT leg runs once the MIT kadmind is up.
RUST_RK="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -randkey rkempty' 2>&1 || true)"
echo "$RUST_RK"
echo "$RUST_RK" | grep -F 'Principal "rkempty@KERBER.TEST" created.'
RUST_RK_KINIT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "\n" | kinit rkempty@KERBER.TEST' 2>&1 || true)"
echo "$RUST_RK_KINIT"
echo "$RUST_RK_KINIT" | grep -F 'kinit: Password incorrect while getting initial credentials'
RUST_RK_EMPTY="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw "" rpcempty' 2>&1 || true)"
echo "$RUST_RK_EMPTY"
echo "$RUST_RK_EMPTY" | grep -F 'add_principal: Password is too short while creating "rpcempty@KERBER.TEST".'
RUST_RK_GET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc rpcempty' 2>&1 || true)"
echo "$RUST_RK_GET" | grep -F 'get_principal: Principal does not exist while retrieving "rpcempty@KERBER.TEST".'
echo "c1_kadm5_randkey_and_empty=rust-leg"
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/renameto.keytab renameto'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/renameto.keytab renameto@KERBER.TEST
KLISTR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTR"
echo "$KLISTR" | grep -q 'renameto@KERBER.TEST'

echo "==== getprinc krbtgt LOCKDOWN_KEYS ===="
TGTGET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$TGTGET"
echo "$TGTGET" | grep -F 'LOCKDOWN_KEYS'

echo "==== ktadd -norandkey krbtgt is extract-keys ===="
KTGT="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/krbtgt.keytab krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$KTGT"
echo "$KTGT" | grep -F 'extract-keys'
if echo "$KTGT" | grep -qi 'added to keytab'; then
    echo "ktadd -norandkey leaked krbtgt keys: $KTGT" >&2
    exit 1
fi

echo "==== ktadd -norandkey kadmin/changepw is extract-keys ===="
KTCPW="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw' 2>&1 || true)"
echo "$KTCPW"
echo "$KTCPW" | grep -F 'extract-keys'

echo "==== delprinc kadmin/changepw is delete privilege ===="
DELCPW="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force kadmin/changepw' 2>&1 || true)"
echo "$DELCPW"
echo "$DELCPW" | grep -F "delete'' privilege"
GETCPW="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw' 2>&1 || true)"
echo "$GETCPW" | grep -q 'Principal: kadmin/changepw@KERBER.TEST'
echo "==== kadmin/admin is DISALLOW_TGT_BASED (server_stubs.c CHANGEPW_SERVICE acceptor takes an initial ticket) ===="
GETADM="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/admin' 2>&1 || true)"
echo "$GETADM"
echo "$GETADM" | grep -E '^Attributes:' | grep -F 'DISALLOW_TGT_BASED'

echo "==== modprinc -lockdown_keys kadmin/changepw is modify privilege ===="
MODCPW="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'modprinc -lockdown_keys kadmin/changepw' 2>&1 || true)"
echo "$MODCPW"
echo "$MODCPW" | grep -F "modify'' privilege"
GETCPW2="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw' 2>&1 || true)"
echo "$GETCPW2" | grep -F 'LOCKDOWN_KEYS'

echo "==== renprinc kadmin/changepw is delete privilege ===="
RENCPW="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'renprinc -force kadmin/changepw kadmin/changepw2' 2>&1 || true)"
echo "$RENCPW"
echo "$RENCPW" | grep -F "delete'' privilege"

echo "==== ACL without d renprinc krbtgt is AUTH_INSUFFICIENT ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw norename-secret norename'
for run in 1 2; do
    echo "---- Rust norename krbtgt $run ----"
    RENACL="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
        "$NAME" -- -p norename@KERBER.TEST -w norename-secret -q 'renprinc -force krbtgt/KERBER.TEST x' 2>&1 || true)"
    echo "$RENACL"
    echo "$RENACL" | grep -F 'Insufficient authorization for operation'
done
GETTGT="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$GETTGT" | grep -F 'Principal: krbtgt/KERBER.TEST@KERBER.TEST'

echo "==== purgekeys krbtgt succeeds (no lockdown check) ===="
PURGE_TGT="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'purgekeys krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$PURGE_TGT"
echo "$PURGE_TGT" | grep -F 'Old keys for principal' || {
    echo "purgekeys krbtgt missed success: $PURGE_TGT" >&2
    exit 1
}
if echo "$PURGE_TGT" | grep -qiE 'locked down|PROTECT_KEYS'; then
    echo "purgekeys refused krbtgt: $PURGE_TGT" >&2
    exit 1
fi

echo "==== extract/admin ktadd -norandkey extra control ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extract-secret extract/admin'
EXTKT="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p extract/admin@KERBER.TEST -w extract-secret -q 'ktadd -norandkey -k /tmp/extra-extract.keytab extra' 2>&1 || true)"
echo "$EXTKT"
if echo "$EXTKT" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "extract/admin ktadd -norandkey extra failed: $EXTKT" >&2
    exit 1
fi

echo "==== ACL target pattern scoped addprinc user2 / svc/x ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw scoped-secret scoped'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw restricted-secret restricted'
ADD_U2="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p scoped@KERBER.TEST -w scoped-secret -q 'addprinc -pw x user2' 2>&1 || true)"
echo "$ADD_U2"
echo "$ADD_U2" | grep -F 'Principal "user2@KERBER.TEST" created.'
ADD_SVC="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p scoped@KERBER.TEST -w scoped-secret -q 'addprinc -pw x svc/x' 2>&1 || true)"
echo "$ADD_SVC"
echo "$ADD_SVC" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "svc/x@KERBER.TEST".'
if echo "$ADD_SVC" | grep -q 'Principal "svc/x@KERBER.TEST" created.'; then
    echo "scoped addprinc svc/x succeeded (ACL target ignored)" >&2
    exit 1
fi
REN_SVC="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p scoped@KERBER.TEST -w scoped-secret -q 'renprinc -force user2 svc/y' 2>&1 || true)"
echo "$REN_SVC"
echo "$REN_SVC" | grep -F 'Insufficient authorization for operation'
REN_U3="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p scoped@KERBER.TEST -w scoped-secret -q 'renprinc -force user2 user3' 2>&1 || true)"
echo "$REN_U3"
echo "$REN_U3" | grep -qiE 'renamed to "user3@KERBER.TEST"|Principal "user2@KERBER.TEST" renamed'
ADD_U9="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p restricted@KERBER.TEST -w restricted-secret -q 'addprinc -pw x -policy short8 user9' 2>&1 || true)"
echo "$ADD_U9"
echo "$ADD_U9" | grep -F 'Principal "user9@KERBER.TEST" created.'
GET_U9="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc user9' 2>&1 || true)"
echo "$GET_U9"
echo "$GET_U9" | grep -F 'Policy: [none]'

echo "==== ACL uppercase *D revokes delete ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw nodel-secret nodel'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw victim-secret victim'
DEL_NODEL="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p nodel@KERBER.TEST -w nodel-secret -q 'delprinc -force victim' 2>&1 || true)"
echo "$DEL_NODEL"
echo "$DEL_NODEL" | grep -F $'delete_principal: Operation requires ``delete\'\' privilege while deleting principal "victim@KERBER.TEST"'
if echo "$DEL_NODEL" | grep -qiE 'Principal "victim@KERBER.TEST" deleted|deleted.'; then
    echo "nodel *D granted delete: $DEL_NODEL" >&2
    exit 1
fi
GET_V="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc victim' 2>&1 || true)"
echo "$GET_V"
echo "$GET_V" | grep -F 'Principal: victim'

echo "==== ACL list vs inquire ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw ro-secret ro'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw rolist-secret rolist'
LIST_I="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p ro@KERBER.TEST -w ro-secret -q 'listprincs' 2>&1 || true)"
echo "$LIST_I"
echo "$LIST_I" | grep -F $'get_principals: Operation requires ``list\'\' privilege while retrieving list.'
if echo "$LIST_I" | grep -q 'user@KERBER.TEST'; then
    echo "ro i listed principals: $LIST_I" >&2
    exit 1
fi
LIST_L="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p rolist@KERBER.TEST -w rolist-secret -q 'listprincs' 2>&1 || true)"
echo "$LIST_L"
echo "$LIST_L" | grep -F 'user@KERBER.TEST'
ADDPOL_D="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p ro@KERBER.TEST -w ro-secret -q 'addpol pol-ro' 2>&1 || true)"
echo "$ADDPOL_D"
echo "$ADDPOL_D" | grep -F $'add_policy: Operation requires ``add\'\' privilege while creating policy "pol-ro".'
SELFGET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p user@KERBER.TEST -w userpassword -q 'getprinc user' 2>&1 || true)"
echo "$SELFGET"
echo "$SELFGET" | grep -F 'Principal: user@KERBER.TEST'

echo "==== MIT kadmin delprinc extra ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force extra'
DELGET="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$DELGET"
echo "$DELGET" | grep -qiE 'does not exist|not found|UNK_PRINC'

log "kadmin.gate" "ok" ',"leg":"rust"'
exit 0
