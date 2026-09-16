#!/usr/bin/env bash
# Rust kadmind leg of kadmin-gate (GSS-RPC 749). KEEP-attach in CI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-glob-cells.sh"
need_bins krb5-kdc krb5-kdb krb5-kadmind krb5-kadmin-local

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-gate"
NAME_MIT="kerber-rust-kadmin-mit"
KADMIND_PORT=749
MIT_IPROP_PORT=2121
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kadmin-gate}"
mkdir -p "$SCRATCH"
# mit-gate diffs these; KERBER_KADMIN_KEEP preserves containers, not shell vars.
_snap_key() {
    printf '%s-%s\n' "$(git rev-parse HEAD)" \
        "$(git status --porcelain -- ':!working' | sha256sum | awk '{print $1}')"
}
save_rust_snap() {
    printf '%s\n' "$2" >"$SCRATCH/kadmin-rust-$1"
    _snap_key >"$SCRATCH/kadmin-rust-$1.key"
}
rm -f "$SCRATCH"/kadmin-rust-*

_kadmin_cleanup() {
    if [ "${KERBER_KADMIN_KEEP:-}" = 1 ]; then
        return 0
    fi
    register_cleanup "$1"
}

compile_kadm5_changepw() {
    local ctn=$1
    docker cp "$ROOT/scripts/kadm5-changepw-rpc.c" "$ctn":/tmp/kadm5-changepw-rpc.c
    if ! docker exec "$ctn" cc -o /tmp/kadm5-changepw-rpc /tmp/kadm5-changepw-rpc.c \
        -lkadm5clnt_mit -lgssrpc -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err 2>"$SCRATCH/kadm5-cc.err"
    then
        if ! docker exec "$ctn" cc -o /tmp/kadm5-changepw-rpc /tmp/kadm5-changepw-rpc.c \
            -lkadm5clnt -lgssrpc -lgssapi_krb5 -lkrb5 -lcom_err 2>>"$SCRATCH/kadm5-cc.err"
        then
            cat "$SCRATCH/kadm5-cc.err" >&2 || true
            log "kadmin.gate" "error" ',"error":"kadm5-changepw-rpc compile failed"'
            exit 1
        fi
    fi
}

kadm5_changepw_list() {
    local ctn=$1 client=$2 pass=$3
    docker exec -e KRB5_CONFIG="${4:-/etc/krb5.conf}" "$ctn" \
        /tmp/kadm5-changepw-rpc "$client" "$pass" KERBER.TEST listprincs
}

kadm5_list_service() {
    local ctn=$1 client=$2 pass=$3 svc=$4
    docker exec -e KRB5_CONFIG="${5:-/etc/krb5.conf}" "$ctn" \
        /tmp/kadm5-changepw-rpc --service "$svc" "$client" "$pass" KERBER.TEST listprincs
}

compile_kadm5_integrity() {
    local ctn=$1
    docker cp "$ROOT/scripts/kadm5-integrity-rpc.c" "$ctn":/tmp/kadm5-integrity-rpc.c
    if ! docker exec "$ctn" cc -o /tmp/kadm5-integrity-rpc /tmp/kadm5-integrity-rpc.c \
        -lkadm5clnt_mit -lgssrpc -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err 2>"$SCRATCH/kadm5-int-cc.err"
    then
        cat "$SCRATCH/kadm5-int-cc.err" >&2 || true
        log "kadmin.gate" "error" ',"error":"kadm5-integrity-rpc compile failed"'
        exit 1
    fi
}

# kadmin/admin is DISALLOW_TGT_BASED, so kinit -S takes an initial service
# ticket the RPCSEC_GSS acceptor accepts.
kadm5_integrity_list() {
    local ctn=$1 client=$2 pass=$3 svc=$4 conf=${5:-/etc/krb5.conf} port=${6:-749}
    docker exec -e KRB5_CONFIG="$conf" "$ctn" sh -c \
        "printf '%s\n' '$pass' | kinit -S kadmin/admin@KERBER.TEST -c /tmp/int-cc '$client'" >/dev/null 2>&1 || true
    docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/int-cc "$ctn" \
        /tmp/kadm5-integrity-rpc 127.0.0.1 kadmin/admin@KERBER.TEST "$svc" "$port"
}

compile_kadm5_probe() {
    local ctn=$1
    docker cp "$ROOT/scripts/kadm5-rpc-probe.c" "$ctn":/tmp/kadm5-rpc-probe.c
    if ! docker exec "$ctn" cc -o /tmp/kadm5-rpc-probe /tmp/kadm5-rpc-probe.c \
        -lkadm5clnt_mit -lgssrpc -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err 2>"$SCRATCH/kadm5-probe-cc.err"
    then
        cat "$SCRATCH/kadm5-probe-cc.err" >&2 || true
        log "kadmin.gate" "error" ',"error":"kadm5-rpc-probe compile failed"'
        exit 1
    fi
}

kadm5_probe() {
    local ctn=$1 client=$2 mode=$3 conf=${4:-/etc/krb5.conf}
    local service=${5:-kadmin/admin@KERBER.TEST} port=${6:-749}
    docker exec -e KRB5_CONFIG="$conf" "$ctn" sh -c \
        "printf 'adminpassword\n' | kinit -S '$service' -c /tmp/probe-cc '$client'" >/dev/null 2>&1 || true
    docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/probe-cc "$ctn" \
        /tmp/kadm5-rpc-probe 127.0.0.1 "$service" "$mode" "$port"
}

# RPCSEC_GSS reject machine (svc_auth_gss.c): each malformed DATA call yields the
# same auth/accept status on MIT and Rust. gc_handle is not compared on either.
rpcsec_reject_cells() {
    local ctn=$1 client=$2 conf=$3 out
    compile_kadm5_probe "$ctn"
    out="$(kadm5_probe "$ctn" "$client" valid "$conf" 2>&1 || true)"
    echo "$out"
    echo "$out" | grep -F 'valid label=SUCCESS'
    out="$(kadm5_probe "$ctn" "$client" corrupt-verf "$conf" 2>&1 || true)"
    echo "$out"
    echo "$out" | grep -F 'corrupt-verf label=CREDPROBLEM'
    out="$(kadm5_probe "$ctn" "$client" maxseq "$conf" 2>&1 || true)"
    echo "$out"
    echo "$out" | grep -F 'maxseq label=CTXPROBLEM'
    out="$(kadm5_probe "$ctn" "$client" wrong-handle "$conf" 2>&1 || true)"
    echo "$out"
    echo "$out" | grep -F 'wrong-handle label=SUCCESS'
    out="$(kadm5_probe "$ctn" "$client" destroy-then-data "$conf" 2>&1 || true)"
    echo "$out"
    echo "$out" | grep -F 'destroy label=SUCCESS'
    echo "$out" | grep -F 'data-after-destroy label=CREDPROBLEM'
    out="$(kadm5_probe "$ctn" "$client" garbage-args "$conf" 2>&1 || true)"
    echo "$out"
    echo "$out" | grep -F 'garbage-args label=GARBAGE_ARGS'
}

start_integ_tamper_proxy() {
    local ctn=$1
    docker cp "$ROOT/scripts/integ-tamper-proxy.py" "$ctn":/tmp/integ-tamper-proxy.py
    docker exec -d "$ctn" python3 /tmp/integ-tamper-proxy.py
}

kadmind_auth_too_weak() {
    local ctn=$1
    docker exec "$ctn" python3 -c '
import socket, struct
s = socket.create_connection(("127.0.0.1", 749), 2)
xid, call, rpcvers, prog, vers, proc = 0x12345678, 0, 2, 2112, 2, 99
body = struct.pack(">10I", xid, call, rpcvers, prog, vers, proc, 0, 0, 0, 0)
s.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
hdr = s.recv(4)
assert len(hdr) == 4, hdr
n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
data = b""
while len(data) < n:
    chunk = s.recv(n - len(data))
    assert chunk, "eof"
    data += chunk
# xid, REPLY, DENIED, AUTH_ERROR, AUTH_TOOWEAK
got = struct.unpack(">5I", data[:20])
print("rpc=" + ",".join(str(x) for x in got))
assert got == (xid, 1, 1, 1, 5), got
'
}

kadmind_rpc_framing() {
    local ctn=$1
    docker exec "$ctn" python3 -c '
import select, socket, struct

def rec(body):
    return struct.pack(">I", 0x80000000 | len(body)) + body

def call(xid, prog, vers, proc, mtype=0, rpcvers=2):
    return struct.pack(">10I", xid, mtype, rpcvers, prog, vers, proc, 0, 0, 0, 0)

def exchange(pkt, timeout=2.0):
    s = socket.create_connection(("127.0.0.1", 749), 2)
    s.settimeout(timeout)
    s.sendall(rec(pkt))
    r, _, _ = select.select([s], [], [], timeout)
    if not r:
        print("timeout")
        return None
    hdr = s.recv(4)
    if not hdr:
        print("eof")
        return None
    n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk, "eof"
        data += chunk
    words = list(struct.unpack(">" + "I" * (len(data) // 4), data[: len(data) - (len(data) % 4)]))
    print("rpc=" + ",".join(str(x) for x in words[:8]))
    return words

xid = 0x11111111
got = exchange(call(xid, 99999, 1, 0))
assert got is not None and got[:6] == [xid, 1, 0, 0, 0, 1], got
xid = 0x22222222
got = exchange(call(xid, 2112, 99, 0))
assert got is not None and got[:8] == [xid, 1, 0, 0, 0, 2, 2, 2], got

s = socket.create_connection(("127.0.0.1", 749), 2)
s.settimeout(2.0)
s.sendall(rec(call(0x33333333, 2112, 2, 12, mtype=1)))
r, _, _ = select.select([s], [], [], 0.4)
assert not r, "REPLY-typed call must stay idle"
xid = 0x33333334
s.sendall(rec(call(xid, 2112, 2, 0)))
r, _, _ = select.select([s], [], [], 2.0)
assert r, "NULLPROC after REPLY on the same socket"
hdr = s.recv(4)
assert hdr, "eof after REPLY then NULLPROC"
n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
data = b""
while len(data) < n:
    chunk = s.recv(n - len(data))
    assert chunk, "eof"
    data += chunk
words = list(struct.unpack(">" + "I" * (len(data) // 4), data[: len(data) - (len(data) % 4)]))
print("rpc=" + ",".join(str(x) for x in words[:8]))
assert words[:5] == [xid, 1, 1, 1, 5], words
s.close()

def xdr_u32(n):
    return struct.pack(">I", n)

def xdr_opaque(b):
    pad = (4 - (len(b) % 4)) % 4
    return xdr_u32(len(b)) + b + b"\x00" * pad

def gss_call(xid, prog, vers, proc, gc_proc, gc_seq=0, gc_svc=3, handle=b"", token=None):
    cred = xdr_u32(1) + xdr_u32(gc_proc) + xdr_u32(gc_seq) + xdr_u32(gc_svc) + xdr_opaque(handle)
    body = struct.pack(">6I", xid, 0, 2, prog, vers, proc)
    body += xdr_u32(6) + xdr_opaque(cred)
    body += xdr_u32(0) + xdr_opaque(b"")
    if token is not None:
        body += xdr_opaque(token)
    return exchange(body)

cred = xdr_u32(99) + xdr_u32(1) + xdr_u32(0) + xdr_u32(3) + xdr_opaque(b"")
xid = 0x44444444
body = struct.pack(">6I", xid, 0, 2, 99999, 1, 0)
body += xdr_u32(6) + xdr_opaque(cred)
body += xdr_u32(0) + xdr_opaque(b"")
got = exchange(body)
assert got is not None and got[:5] == [xid, 1, 1, 1, 1], got
print("rpcsec_unknown_auth_error=ok")

got = gss_call(0x55555551, 2112, 2, 12, 1)
assert got is not None and got[:5] == [0x55555551, 1, 1, 1, 7], got
print("rpcsec_init_non_nullproc=AUTH_FAILED")

got = gss_call(0x55555552, 2112, 2, 12, 0)
assert got is not None and got[:5] == [0x55555552, 1, 1, 1, 13], got
print("rpcsec_data_no_context=CREDPROBLEM")

got = gss_call(0x55555553, 2112, 2, 0, 99)
assert got is not None and got[:5] == [0x55555553, 1, 1, 1, 2], got
print("rpcsec_unknown_gc_proc=AUTH_REJECTEDCRED")

got = gss_call(0x55555554, 2112, 2, 0, 1, token=b"\xff\x00")
assert got is not None and got[:5] == [0x55555554, 1, 1, 1, 2], got
print("rpcsec_init_garbage=AUTH_REJECTEDCRED")

got = gss_call(0x55555555, 2112, 2, 0, 3)
assert got is not None and got[:5] == [0x55555555, 1, 1, 1, 13], got
print("rpcsec_destroy_no_context=CREDPROBLEM")

print("framing=ok")
'
}

assert_k14_rpcsec() {
    local out=$1
    echo "$out" | grep -F 'rpcsec_unknown_auth_error=ok' || {
        echo "missing AUTH_BADCRED cell: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'rpcsec_init_non_nullproc=AUTH_FAILED' || {
        echo "missing INIT non-NULLPROC AUTH_FAILED: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'rpcsec_data_no_context=CREDPROBLEM' || {
        echo "missing DATA no-context CREDPROBLEM: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'rpcsec_unknown_gc_proc=AUTH_REJECTEDCRED' || {
        echo "missing unknown gc_proc AUTH_REJECTEDCRED: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'rpcsec_init_garbage=AUTH_REJECTEDCRED' || {
        echo "missing INIT garbage AUTH_REJECTEDCRED: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'rpcsec_destroy_no_context=CREDPROBLEM' || {
        echo "missing DESTROY no-context CREDPROBLEM: $out" >&2
        exit 1
    }
    echo "$out" | grep -F 'framing=ok' || {
        echo "missing framing=ok: $out" >&2
        exit 1
    }
}

kadmind_iprop_auth_gssapi() {
    local ctn=$1 port=${2:-749}
    docker exec -e IPROP_PORT="$port" "$ctn" python3 -c '
import os, socket, struct
port = int(os.environ.get("IPROP_PORT", "749"))

def xdr_u32(n):
    return struct.pack(">I", n)

def xdr_opaque(b):
    pad = (4 - (len(b) % 4)) % 4
    return xdr_u32(len(b)) + b + b"\x00" * pad

def classify(words):
    if len(words) >= 5 and words[1] == 1 and words[2] == 1:
        st = words[4]
        return {1: "AUTH_BADCRED", 5: "AUTH_TOOWEAK", 7: "AUTH_FAILED"}.get(st, "AUTH_%d" % st)
    if len(words) >= 6 and words[1] == 1 and words[2] == 0:
        st = words[5]
        return {0: "SUCCESS", 1: "PROG_UNAVAIL", 2: "PROG_MISMATCH"}.get(st, "ACCEPT_%d" % st)
    return "other"

def exchange(body):
    s = socket.create_connection(("127.0.0.1", port), 2)
    s.settimeout(2)
    s.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
    hdr = s.recv(4)
    if len(hdr) != 4:
        return []
    n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    nw = len(data) // 4
    return list(struct.unpack(">" + "I" * nw, data[: nw * 4])) if nw else []

def emit(kind, words):
    rpc = ",".join(str(x) for x in words[:8]) if words else "timeout_or_eof"
    print("rpc=" + rpc)
    print("kadmin_on_iprop kind=%s label=%s" % (kind, classify(words) if words else "eof"))

# AUTH_GSSAPI INIT, IPROP_PROG 100423 (auth-layer INIT; MIT 749 may SUCCESS).
xid = 0x41475353
cred = xdr_u32(2) + xdr_u32(1) + xdr_opaque(b"")
args = xdr_u32(2) + xdr_opaque(b"")
body = struct.pack(">6I", xid, 0, 2, 100423, 1, 1)
body += xdr_u32(300001) + xdr_opaque(cred)
body += xdr_u32(0) + xdr_opaque(b"")
body += args
emit("init", exchange(body))

# AUTH_GSSAPI DATA, IPROP_GET_UPDATES (flavor gate; no GSS context).
xid = 0x41475354
cred = xdr_u32(2) + xdr_u32(0) + xdr_opaque(b"")
body = struct.pack(">6I", xid, 0, 2, 100423, 1, 1)
body += xdr_u32(300001) + xdr_opaque(cred)
body += xdr_u32(0) + xdr_opaque(b"")
emit("data", exchange(body))

# AUTH_NONE IPROP: MIT kadmind 749 is PROG_UNAVAIL; Rust serves 100423 as AUTH_TOOWEAK.
xid = 0x11111111
body = struct.pack(">10I", xid, 0, 2, 100423, 1, 0, 0, 0, 0, 0)
emit("auth_none", exchange(body))
'
}

# Principal aliases on one leg, like MIT tests/t_alias.py + t_kadmin_acl.py
# (server_stubs.c:1727-1758, auth_acl.c:723-734, svr_principal.c:2051-2087,
# do_as_req.c:681-687, do_tgs_req.c:1029). Texts settled live in
# working/logs/audit-polish-0902/w1k/m3a-settle-mit-alias.log.
alias_cells() {
    local ctn=$1 conf=$2 admin=$3 leg=$4
    kq() {
        docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$1" -w "$2" -q "$3" 2>&1 || true
    }
    kadm() { kq "$admin" adminpassword "$1"; }
    kinit_alias() {
        docker exec -e KRB5_CONFIG="$conf" "$ctn" \
            sh -c "printf 'userpassword\n' | kinit -c /tmp/alias.cc $1" 2>&1 || true
    }
    klist_alias() { docker exec -e KRB5_CONFIG="$conf" "$ctn" klist -c /tmp/alias.cc 2>&1 || true; }
    kvno_alias() { docker exec -e KRB5_CONFIG="$conf" "$ctn" kvno -c /tmp/alias.cc "$@" 2>&1 || true; }
    local out get
    echo "==== $leg alias: actors ===="
    kadm 'addprinc -pw pw some_alias' | grep -F 'Principal "some_alias@KERBER.TEST" created.'
    kadm 'addprinc -pw pw restricted_alias' | grep -F 'Principal "restricted_alias@KERBER.TEST" created.'
    kadm 'addprinc -pw pw none' | grep -F 'Principal "none@KERBER.TEST" created.'

    echo "==== $leg alias: admin creates a1 -> user, getprinc resolves to the target ===="
    out="$(kadm 'alias a1 user')"
    echo "$out"
    echo "$out" | grep -F 'Principal "a1@KERBER.TEST" aliased to "user@KERBER.TEST".'
    get="$(kadm 'getprinc a1')"
    echo "$get"
    echo "$get" | grep -F 'Principal: user@KERBER.TEST'
    # getprinc through the alias returns the target's whole record verbatim.
    diff <(kadm 'getprinc a1' | grep -v -e '^Authenticating' -e 'No dictionary') \
         <(kadm 'getprinc user' | grep -v -e '^Authenticating' -e 'No dictionary')
    kadm 'listprincs' | grep -Fx 'a1@KERBER.TEST'

    echo "==== $leg alias: duplicate, addprinc over an alias, cross-realm target ===="
    out="$(kadm 'alias a1 user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Principal or policy already exists while aliasing principal "a1@KERBER.TEST" to "user@KERBER.TEST"'
    out="$(kadm 'addprinc -pw x a1')"
    echo "$out"
    echo "$out" | grep -F 'add_principal: Principal or policy already exists while creating "a1@KERBER.TEST".'
    out="$(kadm 'alias x y@OTHER.REALM')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Alias target must be within the same realm while aliasing principal "x@KERBER.TEST" to "y@OTHER.REALM"'
    kadm 'getprinc x' | grep -F 'get_principal: Principal does not exist while retrieving "x@KERBER.TEST".'

    echo "==== $leg alias: dangling target is legal and the name stays creatable ===="
    kadm 'alias xa1 nosuch' | grep -F 'Principal "xa1@KERBER.TEST" aliased to "nosuch@KERBER.TEST".'
    kadm 'getprinc xa1' | grep -F 'get_principal: Principal does not exist while retrieving "xa1@KERBER.TEST".'
    kadm 'addprinc -pw x xa1' | grep -F 'Principal "xa1@KERBER.TEST" created.'
    kadm 'getprinc xa1' | grep -F 'Principal: xa1@KERBER.TEST'

    echo "==== $leg alias: renprinc of an alias is unsupported; delprinc removes the stub only ===="
    out="$(kadm 'renprinc -force a1 b1')"
    echo "$out"
    echo "$out" | grep -F 'rename_principal: Operation unsupported on alias principal name while renaming principal "a1@KERBER.TEST" to "b1@KERBER.TEST"'
    kadm 'getprinc b1' | grep -F 'Principal does not exist'
    kadm 'alias tmpalias user' | grep -F 'aliased to "user@KERBER.TEST".'
    kadm 'delprinc -force tmpalias' | grep -F 'Principal "tmpalias@KERBER.TEST" deleted.'
    kadm 'getprinc tmpalias' | grep -F 'get_principal: Principal does not exist while retrieving "tmpalias@KERBER.TEST".'
    kadm 'getprinc user' | grep -F 'Principal: user@KERBER.TEST'

    echo "==== $leg alias: acl_addalias = add on the alias without restrictions AND modify on the target ===="
    kq some_alias pw 'alias aliasname user' | grep -F 'Principal "aliasname@KERBER.TEST" aliased to "user@KERBER.TEST".'
    out="$(kq some_alias pw 'alias other user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "other@KERBER.TEST" to "user@KERBER.TEST"'
    out="$(kq some_alias pw 'alias aliasname2 host/testhost.kerber.test')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "aliasname2@KERBER.TEST" to "host/testhost.kerber.test@KERBER.TEST"'
    out="$(kq restricted_alias pw 'alias r1 user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "r1@KERBER.TEST" to "user@KERBER.TEST"'
    out="$(kq none pw 'alias n1 user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "n1@KERBER.TEST" to "user@KERBER.TEST"'
    for denied in other aliasname2 r1 n1; do
        kadm "getprinc $denied" | grep -F "get_principal: Principal does not exist while retrieving \"$denied@KERBER.TEST\"."
    done

    echo "==== $leg alias: kinit keeps the requested name, -C canonicalizes, kvno keeps the requested sname ===="
    out="$(kinit_alias a1)"
    echo "$out"
    out="$(klist_alias)"
    echo "$out"
    echo "$out" | grep -F 'Default principal: a1@KERBER.TEST'
    echo "$out" | grep -F 'krbtgt/KERBER.TEST@KERBER.TEST'
    out="$(kvno_alias a1 aliasname)"
    echo "$out"
    echo "$out" | grep -E '^a1@KERBER.TEST: kvno = [0-9]+$'
    echo "$out" | grep -E '^aliasname@KERBER.TEST: kvno = [0-9]+$'
    klist_alias | grep -F ' a1@KERBER.TEST'
    out="$(kinit_alias '-C a1')"
    echo "$out"
    out="$(klist_alias)"
    echo "$out"
    echo "$out" | grep -F 'Default principal: user@KERBER.TEST'

    echo "==== $leg alias: chains resolve to depth 10; 11 and a self-alias are not found ===="
    local i
    for i in $(seq 2 11); do
        kadm "alias a$i a$((i - 1))" | grep -F "aliased to \"a$((i - 1))@KERBER.TEST\"."
    done
    kadm 'alias selfalias selfalias' | grep -F 'Principal "selfalias@KERBER.TEST" aliased to "selfalias@KERBER.TEST".'
    out="$(kvno_alias a10)"
    echo "$out"
    echo "$out" | grep -E '^a10@KERBER.TEST: kvno = [0-9]+$'
    out="$(kvno_alias a11)"
    echo "$out"
    echo "$out" | grep -F 'kvno: Server a11@KERBER.TEST not found in Kerberos database while getting credentials for a11@KERBER.TEST'
    out="$(kvno_alias selfalias)"
    echo "$out"
    echo "$out" | grep -F 'kvno: Server selfalias@KERBER.TEST not found in Kerberos database while getting credentials for selfalias@KERBER.TEST'
    out="$(kinit_alias a11)"
    echo "$out"
    echo "$out" | grep -F "kinit: Client 'a11@KERBER.TEST' not found in Kerberos database while getting initial credentials"
    kadm 'getprinc a10' | grep -F 'Principal: user@KERBER.TEST'
    kadm 'getprinc a11' | grep -F 'get_principal: Principal does not exist while retrieving "a11@KERBER.TEST".'
    docker exec "$ctn" rm -f /tmp/alias.cc
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
_kadmin_cleanup 'docker rm -f "$NAME" >/dev/null 2>&1 || true'

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
KADMIN_TRACE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs' 2>&1 || true)"
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
ADD="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra' 2>&1 || true)"
echo "$ADD"
echo "==== kadmind log ===="
wait_log "$NAME" /tmp/kadmind.log "Request: kadm5_create_principal" || true
KADMIND_LOG="$(docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true)"
echo "$KADMIND_LOG"
# M4c: MIT log_done / log_unauth (server_stubs.c:403-459). The successful admin
# addprinc logs "Request: ... success" and the changepw listprincs denial logs
# "Unauthorized request: ...", each with client/service/addr. Settled live in
# a live MIT kadmind settle (working/logs/audit-polish-0902/w1k/settle-m4c-kadmind-log.log).
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
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw extra-rotated extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "extra-rotated\n" | kinit extra@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin getprinc extra ===="
GET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
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
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q \
    'addprinc -pw keep-secret keepoldu'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q \
    'cpw -keepold -pw keep-rotated keepoldu'
GETK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc keepoldu' 2>&1 || true)"
echo "$GETK"
echo "$GETK" | grep -qE 'Key: vno 1,'
echo "$GETK" | grep -qE 'Key: vno 2,'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "keep-rotated\n" | kinit keepoldu@KERBER.TEST'

echo "==== MIT kadmin setstr/getstrs extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'setstr extra note hello-g3d'
STRS="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getstrs extra' 2>&1 || true)"
echo "$STRS"
echo "$STRS" | grep -q 'note: hello-g3d'

echo "==== MIT kadmin lockdown_keys ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw lock-secret lockee'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc +lockdown_keys lockee'
GETL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc lockee' 2>&1 || true)"
echo "$GETL"
echo "$GETL" | grep -qi LOCKDOWN
CPWL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw lock-rotated lockee' 2>&1 || true)"
echo "$CPWL"
if echo "$CPWL" | grep -qi 'changed'; then
    echo "lockdown cpw rewrote keys: $CPWL" >&2
    exit 1
fi
echo "$CPWL" | grep -F 'change-password'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "lock-secret\n" | kinit lockee@KERBER.TEST'
KTL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/lockee-norand.keytab lockee' 2>&1 || true)"
echo "$KTL"
if echo "$KTL" | grep -qi 'added to keytab'; then
    echo "lockdown ktadd -norandkey leaked keys: $KTL" >&2
    exit 1
fi
CHR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/lockee.keytab lockee' 2>&1 || true)"
echo "$CHR"
if docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/lockee.keytab lockee@KERBER.TEST 2>"$SCRATCH/lockee-kinit.err"; then
    echo "lockdown ktadd leaked keys for kinit -k" >&2
    exit 1
fi

echo "==== kadmin/history does not exist before the first policy chpass (create_hist is lazy) ===="
HIST_BEFORE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$HIST_BEFORE"
echo "$HIST_BEFORE" | grep -F 'Principal does not exist while retrieving "kadmin/history@KERBER.TEST".'

echo "==== a failed short-password cpw still creates kadmin/history (before passwd_check) ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addpol -minlength 8 -history 2 a8pol'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw a8-initial-secret -policy a8pol a8u'
A8CPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw sh a8u' 2>&1 || true)"
echo "$A8CPW"
echo "$A8CPW" | grep -F 'Password is too short while changing password for "a8u@KERBER.TEST".'
A8HIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$A8HIST" | grep -F 'Principal: kadmin/history@KERBER.TEST'

echo "==== MIT kadmin purgekeys ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addpol -history 2 g3bhist'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw purge-secret -policy g3bhist purgee'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw purge-rotated purgee'
GETP="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc purgee' 2>&1 || true)"
echo "$GETP"
echo "$GETP" | grep -qE 'Key: vno 2,'
if echo "$GETP" | grep -qE 'Key: vno 1,'; then
    echo "getprinc listed password-history kvno 1: $GETP" >&2
    exit 1
fi
PURGE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'purgekeys purgee' 2>&1 || true)"
echo "$PURGE"
echo "$PURGE" | grep -qi purged
if echo "$PURGE" | grep -qiE 'while purging|Operation failed|unknown procedure'; then
    echo "purgekeys failed: $PURGE" >&2
    exit 1
fi
GETP2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc purgee' 2>&1 || true)"
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
HIST_GET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/history' 2>&1 || true)"
save_rust_snap HIST_GET "$HIST_GET"
echo "$HIST_GET"
echo "$HIST_GET" | grep -F 'Principal: kadmin/history@KERBER.TEST'
HIST_PROBE="$(kadm5_probe "$NAME" admin@KERBER.TEST valid /tmp/kadmin-krb5.conf kadmin/history@KERBER.TEST 2>&1 || true)"
echo "$HIST_PROBE"
echo "$HIST_PROBE" | grep -F 'valid label=AUTH_TOOWEAK'

echo "==== MIT kadmin listprincs ===="
LIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs' 2>&1 || true)"
echo "$LIST"
echo "$LIST" | grep -q 'extra@KERBER.TEST'
echo "$LIST" | grep -q 'user@KERBER.TEST'

echo "==== MIT kadmin modprinc +requires_preauth extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc +requires_preauth extra'
GET2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
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
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -randkey extra'
GETR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
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
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/extra.keytab extra'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/extra.keytab extra@KERBER.TEST
KLIST4="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLIST4"
echo "$KLIST4" | grep -q 'extra@KERBER.TEST'

echo "==== MIT kadmin ktadd -norandkey extra + kinit -k ===="
KTN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/extra-norand.keytab extra' 2>&1 || true)"
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
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -randkey renamefrom'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'renprinc -force renamefrom renameto'
RENGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc renameto' 2>&1 || true)"
echo "$RENGET"
echo "$RENGET" | grep -q 'Principal: renameto@KERBER.TEST'
RENOLD="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc renamefrom' 2>&1 || true)"
echo "$RENOLD"
echo "$RENOLD" | grep -qiE 'does not exist|not found|UNK_PRINC'

echo "==== C1 kadm5 create over the Rust kadmind: -randkey (NULL passwd) is a random key, -pw \"\" is PASS_Q_TOOSHORT ===="
# Rust leg of the C1 cell; the MIT leg runs once the MIT kadmind is up.
RUST_RK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -randkey rkempty' 2>&1 || true)"
echo "$RUST_RK"
echo "$RUST_RK" | grep -F 'Principal "rkempty@KERBER.TEST" created.'
RUST_RK_KINIT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "\n" | kinit rkempty@KERBER.TEST' 2>&1 || true)"
echo "$RUST_RK_KINIT"
echo "$RUST_RK_KINIT" | grep -F 'kinit: Password incorrect while getting initial credentials'
RUST_RK_EMPTY="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw "" rpcempty' 2>&1 || true)"
echo "$RUST_RK_EMPTY"
echo "$RUST_RK_EMPTY" | grep -F 'add_principal: Password is too short while creating "rpcempty@KERBER.TEST".'
RUST_RK_GET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc rpcempty' 2>&1 || true)"
echo "$RUST_RK_GET" | grep -F 'get_principal: Principal does not exist while retrieving "rpcempty@KERBER.TEST".'
echo "c1_kadm5_randkey_and_empty=rust-leg"
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -k /tmp/renameto.keytab renameto'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/renameto.keytab renameto@KERBER.TEST
KLISTR="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$KLISTR"
echo "$KLISTR" | grep -q 'renameto@KERBER.TEST'

echo "==== getprinc krbtgt LOCKDOWN_KEYS ===="
TGTGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$TGTGET"
echo "$TGTGET" | grep -F 'LOCKDOWN_KEYS'

echo "==== ktadd -norandkey krbtgt is extract-keys ===="
KTGT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/krbtgt.keytab krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$KTGT"
echo "$KTGT" | grep -F 'extract-keys'
if echo "$KTGT" | grep -qi 'added to keytab'; then
    echo "ktadd -norandkey leaked krbtgt keys: $KTGT" >&2
    exit 1
fi

echo "==== ktadd -norandkey kadmin/changepw is extract-keys ===="
KTCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw' 2>&1 || true)"
echo "$KTCPW"
echo "$KTCPW" | grep -F 'extract-keys'

echo "==== delprinc kadmin/changepw is delete privilege ===="
DELCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force kadmin/changepw' 2>&1 || true)"
echo "$DELCPW"
echo "$DELCPW" | grep -F "delete'' privilege"
GETCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw' 2>&1 || true)"
echo "$GETCPW" | grep -q 'Principal: kadmin/changepw@KERBER.TEST'
echo "==== kadmin/admin is DISALLOW_TGT_BASED (server_stubs.c CHANGEPW_SERVICE acceptor takes an initial ticket) ===="
GETADM="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/admin' 2>&1 || true)"
echo "$GETADM"
echo "$GETADM" | grep -E '^Attributes:' | grep -F 'DISALLOW_TGT_BASED'

echo "==== modprinc -lockdown_keys kadmin/changepw is modify privilege ===="
MODCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'modprinc -lockdown_keys kadmin/changepw' 2>&1 || true)"
echo "$MODCPW"
echo "$MODCPW" | grep -F "modify'' privilege"
GETCPW2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw' 2>&1 || true)"
echo "$GETCPW2" | grep -F 'LOCKDOWN_KEYS'

echo "==== renprinc kadmin/changepw is delete privilege ===="
RENCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'renprinc -force kadmin/changepw kadmin/changepw2' 2>&1 || true)"
echo "$RENCPW"
echo "$RENCPW" | grep -F "delete'' privilege"

echo "==== ACL without d renprinc krbtgt is AUTH_INSUFFICIENT ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw norename-secret norename'
for run in 1 2; do
    echo "---- Rust norename krbtgt $run ----"
    RENACL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
        "$NAME" kadmin -p norename@KERBER.TEST -w norename-secret -q 'renprinc -force krbtgt/KERBER.TEST x' 2>&1 || true)"
    echo "$RENACL"
    echo "$RENACL" | grep -F 'Insufficient authorization for operation'
done
GETTGT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc krbtgt/KERBER.TEST' 2>&1 || true)"
echo "$GETTGT" | grep -F 'Principal: krbtgt/KERBER.TEST@KERBER.TEST'

echo "==== purgekeys krbtgt succeeds (no lockdown check) ===="
PURGE_TGT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'purgekeys krbtgt/KERBER.TEST' 2>&1 || true)"
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
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extract-secret extract/admin'
EXTKT="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p extract/admin@KERBER.TEST -w extract-secret -q 'ktadd -norandkey -k /tmp/extra-extract.keytab extra' 2>&1 || true)"
echo "$EXTKT"
if echo "$EXTKT" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "extract/admin ktadd -norandkey extra failed: $EXTKT" >&2
    exit 1
fi

echo "==== ACL target pattern scoped addprinc user2 / svc/x ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw scoped-secret scoped'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw restricted-secret restricted'
ADD_U2="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'addprinc -pw x user2' 2>&1 || true)"
echo "$ADD_U2"
echo "$ADD_U2" | grep -F 'Principal "user2@KERBER.TEST" created.'
ADD_SVC="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'addprinc -pw x svc/x' 2>&1 || true)"
echo "$ADD_SVC"
echo "$ADD_SVC" | grep -F $'add_principal: Operation requires ``add\'\' privilege while creating "svc/x@KERBER.TEST".'
if echo "$ADD_SVC" | grep -q 'Principal "svc/x@KERBER.TEST" created.'; then
    echo "scoped addprinc svc/x succeeded (ACL target ignored)" >&2
    exit 1
fi
REN_SVC="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'renprinc -force user2 svc/y' 2>&1 || true)"
echo "$REN_SVC"
echo "$REN_SVC" | grep -F 'Insufficient authorization for operation'
REN_U3="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p scoped@KERBER.TEST -w scoped-secret -q 'renprinc -force user2 user3' 2>&1 || true)"
echo "$REN_U3"
echo "$REN_U3" | grep -qiE 'renamed to "user3@KERBER.TEST"|Principal "user2@KERBER.TEST" renamed'
ADD_U9="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p restricted@KERBER.TEST -w restricted-secret -q 'addprinc -pw x -policy short8 user9' 2>&1 || true)"
echo "$ADD_U9"
echo "$ADD_U9" | grep -F 'Principal "user9@KERBER.TEST" created.'
GET_U9="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc user9' 2>&1 || true)"
echo "$GET_U9"
echo "$GET_U9" | grep -F 'Policy: [none]'

echo "==== ACL uppercase *D revokes delete ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw nodel-secret nodel'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw victim-secret victim'
DEL_NODEL="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p nodel@KERBER.TEST -w nodel-secret -q 'delprinc -force victim' 2>&1 || true)"
echo "$DEL_NODEL"
echo "$DEL_NODEL" | grep -F $'delete_principal: Operation requires ``delete\'\' privilege while deleting principal "victim@KERBER.TEST"'
if echo "$DEL_NODEL" | grep -qiE 'Principal "victim@KERBER.TEST" deleted|deleted.'; then
    echo "nodel *D granted delete: $DEL_NODEL" >&2
    exit 1
fi
GET_V="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc victim' 2>&1 || true)"
echo "$GET_V"
echo "$GET_V" | grep -F 'Principal: victim'

echo "==== ACL list vs inquire ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw ro-secret ro'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw rolist-secret rolist'
LIST_I="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p ro@KERBER.TEST -w ro-secret -q 'listprincs' 2>&1 || true)"
echo "$LIST_I"
echo "$LIST_I" | grep -F $'get_principals: Operation requires ``list\'\' privilege while retrieving list.'
if echo "$LIST_I" | grep -q 'user@KERBER.TEST'; then
    echo "ro i listed principals: $LIST_I" >&2
    exit 1
fi
LIST_L="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p rolist@KERBER.TEST -w rolist-secret -q 'listprincs' 2>&1 || true)"
echo "$LIST_L"
echo "$LIST_L" | grep -F 'user@KERBER.TEST'
ADDPOL_D="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p ro@KERBER.TEST -w ro-secret -q 'addpol pol-ro' 2>&1 || true)"
echo "$ADDPOL_D"
echo "$ADDPOL_D" | grep -F $'add_policy: Operation requires ``add\'\' privilege while creating policy "pol-ro".'
SELFGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p user@KERBER.TEST -w userpassword -q 'getprinc user' 2>&1 || true)"
echo "$SELFGET"
echo "$SELFGET" | grep -F 'Principal: user@KERBER.TEST'

echo "==== MIT kadmin delprinc extra ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'delprinc -force extra'
DELGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra' 2>&1 || true)"
echo "$DELGET"
echo "$DELGET" | grep -qiE 'does not exist|not found|UNK_PRINC'

log "kadmin.gate" "ok" ',"leg":"rust"'
exit 0
