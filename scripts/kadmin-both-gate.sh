#!/usr/bin/env bash
# Both-kadmind diff cells of kadmin-gate (GSS-RPC 749). KEEP-attach in CI.
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

if ! docker inspect "$NAME" >/dev/null 2>&1 || ! docker inspect "$NAME_MIT" >/dev/null 2>&1; then
    die "kadmin-both-gate needs rust+mit containers (run rust then mit with KERBER_KADMIN_KEEP=1)"
fi
register_cleanup 'docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true'
echo "==== kadm5 modify reserved TL type and nonzero failcount both kadminds ===="
kadm5_modify_validate() {
    local ctn=$1 client=$2 conf=$3 princ=$4
    local tl fc before after
    tl="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-tl-reserved "$princ" 2>&1 || true)"
    echo "$ctn tl: $tl"
    echo "$tl" | grep -q 'modify_code=43787567' || {
        echo "$ctn reserved TL did not return KADM5_BAD_TL_TYPE: $tl" >&2
        exit 1
    }
    before="$(echo "$tl" | sed -n 's/.*get_before_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    after="$(echo "$tl" | sed -n 's/.*get_after_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    [ -n "$before" ] && [ "$before" = "$after" ] || {
        echo "$ctn reserved TL changed max_life: $tl" >&2
        exit 1
    }
    fc="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-failcount "$princ" 2>&1 || true)"
    echo "$ctn failcount: $fc"
    echo "$fc" | grep -q 'modify_code=43787563' || {
        echo "$ctn failcount did not return KADM5_BAD_SERVER_PARAMS: $fc" >&2
        exit 1
    }
    before="$(echo "$fc" | sed -n 's/.*get_before_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    after="$(echo "$fc" | sed -n 's/.*get_after_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    [ -n "$before" ] && [ "$before" = "$after" ] || {
        echo "$ctn failcount changed max_life: $fc" >&2
        exit 1
    }
    local mask
    mask="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-policy-clr "$princ" 2>&1 || true)"
    echo "$ctn policy-clr: $mask"
    echo "$mask" | grep -q 'modify_code=43787534' || {
        echo "$ctn POLICY|POLICY_CLR did not return KADM5_BAD_MASK: $mask" >&2
        exit 1
    }
    before="$(echo "$mask" | sed -n 's/.*get_before_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    after="$(echo "$mask" | sed -n 's/.*get_after_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    [ -n "$before" ] && [ "$before" = "$after" ] || {
        echo "$ctn POLICY|POLICY_CLR changed max_life: $mask" >&2
        exit 1
    }
    local create
    create="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-failcount-mask "r9mask@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-failcount-mask: $create"
    echo "$create" | grep -q 'create_code=43787534' || {
        echo "$ctn create FAIL_AUTH_COUNT mask did not return KADM5_BAD_MASK: $create" >&2
        exit 1
    }
    local ctl ok
    ctl="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-tl-reserved "r9tlbad@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-tl-reserved: $ctl"
    echo "$ctl" | grep -q 'create_code=43787567' || {
        echo "$ctn create reserved TL did not return KADM5_BAD_TL_TYPE: $ctl" >&2
        exit 1
    }
    ok="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-tl-500 "r9tl500@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-tl-500: $ok"
    echo "$ok" | grep -q 'create_code=0' || {
        echo "$ctn create TL 500 did not succeed: $ok" >&2
        exit 1
    }
    echo "$ok" | grep -q 'tl_type=500' || {
        echo "$ctn create TL 500 missing on getprinc: $ok" >&2
        exit 1
    }
}
kadm5_modify_validate "$NAME" admin /tmp/kadmin-krb5.conf user@KERBER.TEST
kadm5_modify_validate "$NAME_MIT" admin/admin /etc/krb5.conf user@KERBER.TEST

echo "==== both kadminds reject -x db_args; ACL before mask; KEY_DATA mask ===="
kadm5_r12_restart_with_ro() {
    local ctn=$1 is_mit=$2
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" sh -c '
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
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec "$ctn" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *" "admin@KERBER.TEST *" "ro@KERBER.TEST i" > /var/krb5kdc/kadm5.acl'
        docker exec -d "$ctn" sh -c 'kadmind -nofork >/tmp/kadmind-r12.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-r12.log >&2 || true; echo "MIT kadmind did not listen for r12" >&2; exit 1; }
    else
        docker exec "$ctn" sh -c '
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
        wait_gone_in "$ctn" 749 || die "kadmind still bound :749 after kill"
        docker exec "$ctn" sh -c 'printf "%s\n" "admin@KERBER.TEST *" "ro@KERBER.TEST i" > /tmp/kadm5.acl'
        docker exec -d \
            -e KRB5_KDC_DB=/tmp/principal \
            -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_ACL_FILE=/tmp/kadm5.acl \
            "$ctn" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-r12.log 2>&1'
        local ok=0 i
        for i in $(seq 1 40); do
            if docker exec "$ctn" grep -q '^listening ' /tmp/kadmind-r12.log 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-r12.log >&2 || true; echo "Rust kadmind did not listen for r12" >&2; exit 1; }
    fi
}
kadm5_r12_db_args() {
    local ctn=$1 client=$2 conf=$3 is_mit=$4
    local kadm dumpcmd userline before after mod add getx ro kd
    kadm() { docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword -q "$1" 2>&1 || true; }
    before="$(kadm 'getprinc user' | grep -v -e '^Authenticating' -e 'No dictionary')"
    mod="$(kadm 'modprinc -x foo=bar user')"
    echo "$ctn modprinc -x: $mod"
    echo "$mod" | grep -F 'Invalid argument while modifying "user@KERBER.TEST"' || {
        echo "$ctn modprinc -x did not print Invalid argument: $mod" >&2
        exit 1
    }
    after="$(kadm 'getprinc user' | grep -v -e '^Authenticating' -e 'No dictionary')"
    [ "$before" = "$after" ] || {
        echo "$ctn getprinc user changed after modprinc -x" >&2
        printf '%s\n' "$before" "$after" >&2
        exit 1
    }
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" kdb5_util dump /tmp/r12.dump
    else
        docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_MASTER_PASSWORD=masterpassword \
            "$ctn" /tmp/krb5-kdb dump /tmp/r12.dump
    fi
    userline="$(docker exec "$ctn" grep -F $'\tuser@KERBER.TEST\t' /tmp/r12.dump || true)"
    echo "$ctn user dump: $userline"
    [ -n "$userline" ] || {
        echo "$ctn dump missing user@KERBER.TEST" >&2
        exit 1
    }
    echo "$userline" | grep -F $'\t32767\t' && {
        echo "$ctn dump still has TL 32767 on user" >&2
        exit 1
    }
    add="$(kadm 'addprinc -pw x -x foo=bar r12x')"
    echo "$ctn addprinc -x: $add"
    echo "$add" | grep -F 'Invalid argument while creating' || {
        echo "$ctn addprinc -x did not print Invalid argument: $add" >&2
        exit 1
    }
    getx="$(kadm 'getprinc r12x')"
    echo "$ctn getprinc r12x: $getx"
    echo "$getx" | grep -qiE 'does not exist|not found|UNK_PRINC|Unknown' || {
        echo "$ctn r12x exists after failed addprinc -x: $getx" >&2
        exit 1
    }
    ro="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin ro@KERBER.TEST ro-secret KERBER.TEST \
        modify-policy-clr user@KERBER.TEST 2>&1 || true)"
    echo "$ctn ro modify-policy-clr: $ro"
    echo "$ro" | grep -q 'modify_code=43787523' || {
        echo "$ctn ro POLICY|POLICY_CLR was not KADM5_AUTH_MODIFY: $ro" >&2
        exit 1
    }
    kd="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-key-data-mask "r12key@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-key-data-mask: $kd"
    echo "$kd" | grep -q 'create_code=43787534' || {
        echo "$ctn KEY_DATA mask did not return KADM5_BAD_MASK: $kd" >&2
        exit 1
    }
}
kadm5_r12_restart_with_ro "$NAME" rust
kadm5_r12_restart_with_ro "$NAME_MIT" mit
kadm5_r12_db_args "$NAME" admin /tmp/kadmin-krb5.conf rust
kadm5_r12_db_args "$NAME_MIT" admin/admin /etc/krb5.conf mit

echo "==== glob lists: Rust kadmind vs MIT kadmind ===="
diff "$SCRATCH/glob-rust.txt" "$SCRATCH/glob-mit.txt" || { echo "glob lists differ between the Rust kadmind and MIT kadmind" >&2; exit 1; }

echo "==== no-GET modify-raw: lookup before ACL and mask (both kadminds) ===="
kadm5_modify_raw() {
    local ctn=$1 client=$2 conf=$3
    local ro_ns adm_ns adm_user
    ro_ns="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin ro@KERBER.TEST ro-secret KERBER.TEST \
        modify-raw nosuch@KERBER.TEST maxlife 2>&1 || true)"
    echo "$ctn ro modify-raw nosuch maxlife: $ro_ns"
    echo "$ro_ns" | grep -q 'modify_code=43787532' || {
        echo "$ctn ro no-GET modify nosuch was not KADM5_UNK_PRINC: $ro_ns" >&2
        exit 1
    }
    adm_ns="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-raw nosuch@KERBER.TEST policyclr 2>&1 || true)"
    echo "$ctn admin modify-raw nosuch policyclr: $adm_ns"
    echo "$adm_ns" | grep -q 'modify_code=43787532' || {
        echo "$ctn admin no-GET policyclr nosuch was not KADM5_UNK_PRINC: $adm_ns" >&2
        exit 1
    }
    adm_user="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-raw user@KERBER.TEST policyclr 2>&1 || true)"
    echo "$ctn admin modify-raw user policyclr: $adm_user"
    echo "$adm_user" | grep -q 'modify_code=43787534' || {
        echo "$ctn admin no-GET policyclr user was not KADM5_BAD_MASK: $adm_user" >&2
        exit 1
    }
}
kadm5_modify_raw "$NAME" admin /tmp/kadmin-krb5.conf
kadm5_modify_raw "$NAME_MIT" admin/admin /etc/krb5.conf

echo "==== Z1.1 kadm5_create_principal_3 field application + impose_restrictions (both kadminds, MIT kadmin RPC) ===="
# svr_principal.c:376-420 applies every masked field of the request record;
# kadmin/server/auth.c:205-272 imposes the ACL line's restrictions on the
# request *before* the create/modify runs (server_stubs.c:478,519,630), so a
# `-policy P` restriction is enforced by P's floors, an in-mask 0 is kept, a
# value above the cap is lowered and a field absent from the mask takes the
# cap outright. Each leg restarts its kadmind with the same ACL lines (the
# `modprinc` actor needs `i`: MIT kadmin_modprinc gets the entry first,
# kadmin.c:1395-1401, and sends only the parsed args in the mask).
# The container's kdc.conf plus the two `params.*` stanzas a bare `addprinc`
# takes (`alt_prof.c:580-632`): `default_principal_flags` (over
# `KRB5_KDB_DEF_FLAGS` 0) and `default_principal_expiration`
# (`krb5_string_to_timestamp`, local time — the containers run UTC).
z11_profile() {
    docker exec "$1" sh -c '
python3 - <<PY
from pathlib import Path
src = Path("/etc/krb5kdc/kdc.conf").read_text().splitlines(True)
out = []
for ln in src:
    out.append(ln)
    if ln.strip().startswith("KERBER.TEST") and ln.rstrip().endswith("{"):
        out.append("        default_principal_flags = +disallow_svr\n")
        out.append("        default_principal_expiration = 20300102030405\n")
Path("/tmp/z11-kdc.conf").write_text("".join(out))
PY
grep -q default_principal_expiration /tmp/z11-kdc.conf'
}
z11_restart() {
    local ctn=$1 is_mit=$2
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" sh -c '
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
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec "$ctn" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *" "admin@KERBER.TEST *" \
            "z1pol@KERBER.TEST a *@KERBER.TEST -policy shortpol" \
            "z1rl@KERBER.TEST a *@KERBER.TEST -maxrenewlife 1d" \
            "z1ml@KERBER.TEST aim *@KERBER.TEST -maxlife 1h" > /var/krb5kdc/kadm5.acl'
        z11_profile "$ctn"
        docker exec -d -e KRB5_KDC_PROFILE=/tmp/z11-kdc.conf "$ctn" sh -c 'kadmind -nofork >/tmp/kadmind-z11.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-z11.log >&2 || true; echo "MIT kadmind did not listen for z11" >&2; exit 1; }
    else
        docker exec "$ctn" sh -c '
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
        wait_gone_in "$ctn" 749 || die "kadmind still bound :749 after kill"
        docker exec "$ctn" sh -c 'printf "%s\n" "admin@KERBER.TEST *" \
            "admin/admin@KERBER.TEST *" \
            "*/admin@KERBER.TEST *" \
            "z1pol@KERBER.TEST a *@KERBER.TEST -policy shortpol" \
            "z1rl@KERBER.TEST a *@KERBER.TEST -maxrenewlife 1d" \
            "z1ml@KERBER.TEST aim *@KERBER.TEST -maxlife 1h" > /tmp/kadm5.acl'
        z11_profile "$ctn"
        docker exec -d \
            -e KRB5_KDC_DB=/tmp/principal \
            -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_ACL_FILE=/tmp/kadm5.acl \
            -e KRB5_KDC_PROFILE=/tmp/z11-kdc.conf \
            "$ctn" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-z11.log 2>&1'
        local ok=0 i
        for i in $(seq 1 40); do
            if docker exec "$ctn" grep -q '^listening ' /tmp/kadmind-z11.log 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-z11.log >&2 || true; echo "Rust kadmind did not listen for z11" >&2; exit 1; }
    fi
}
z11_leg() {
    local ctn=$1 fixture=$2 client=$3 conf=$4 leg=$5
    local kadm out shape pwx
    kadm() {
        docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$1" -w "$2" -q "$3" 2>&1 \
            | grep -v -e '^Authenticating' -e 'No dictionary' -e 'No policy specified' || true
    }
    # Fixtures before the restart: the restricted actors, the two policies.
    # The rust dump has `admin@`, not `admin/admin@`; create the RPC actor
    # used after restart so Z6.4's modifier is `admin/admin@KERBER.TEST`
    # on both legs.
    kadm "$fixture" adminpassword 'addprinc -pw z1pol-secret z1pol' | grep -F 'Principal "z1pol@KERBER.TEST" created.'
    kadm "$fixture" adminpassword 'addprinc -pw z1rl-secret z1rl' | grep -F 'Principal "z1rl@KERBER.TEST" created.'
    kadm "$fixture" adminpassword 'addprinc -pw z1ml-secret z1ml' | grep -F 'Principal "z1ml@KERBER.TEST" created.'
    kadm "$fixture" adminpassword 'addpol -minlength 8 shortpol'
    kadm "$fixture" adminpassword 'addpol -maxlife 30d z1pw'
    if [ "$leg" = rust ]; then
        kadm "$fixture" adminpassword 'addprinc -pw adminpassword admin/admin' || true
    fi
    z11_restart "$ctn" "$leg"

    echo "---- $leg: every masked field lands (getprinc shape to $SCRATCH/z11-$leg.txt) ----"
    out="$(kadm "$client" adminpassword 'addprinc -pw x -maxlife 1h -maxrenewlife 0 -expire "2030-01-01 00:00:00 UTC" -pwexpire "2031-01-01 00:00:00 UTC" -kvno 7 +disallow_all_tix +requires_preauth z1u')"
    echo "$out"
    echo "$out" | grep -F 'Principal "z1u@KERBER.TEST" created.'
    shape="$(kadm "$client" adminpassword 'getprinc z1u')"
    echo "$shape"
    echo "$shape" | hist_shape > "$SCRATCH/z11-$leg.txt"
    echo "$shape" | grep -F 'Expiration date: Tue Jan 01 00:00:00 UTC 2030'
    echo "$shape" | grep -F 'Password expiration date: Wed Jan 01 00:00:00 UTC 2031'
    echo "$shape" | grep -F 'Maximum ticket life: 0 days 01:00:00'
    echo "$shape" | grep -F 'Maximum renewable life: 0 days 00:00:00'
    echo "$shape" | grep -E '^Attributes: DISALLOW_ALL_TIX REQUIRES_PRE_AUTH$'
    echo "$shape" | grep -E '^Key: vno 7, ' >/dev/null
    if echo "$shape" | grep -E '^Key: vno ' | grep -vq '^Key: vno 7, '; then
        echo "$leg: a key is not at kvno 7: $shape" >&2
        exit 1
    fi
    echo "$shape" | grep -E '^Last modified: .* \(admin/admin@KERBER.TEST\)$'

    echo "---- $leg: default_principal_flags / default_principal_expiration are params.flags / params.expiration for a bare addprinc ----"
    kadm "$client" adminpassword 'addprinc -pw x z1def' | grep -F 'Principal "z1def@KERBER.TEST" created.'
    out="$(kadm "$client" adminpassword 'getprinc z1def')"
    echo "$out"
    echo "$out" | grep -F 'Expiration date: Wed Jan 02 03:04:05 UTC 2030'
    echo "$out" | grep -E '^Attributes: DISALLOW_SVR$'

    echo "---- $leg: -policy with pw_max_life sets Password expiration date ----"
    kadm "$client" adminpassword 'addprinc -pw z1pwu-secret -policy z1pw z1pwu' | grep -F 'Principal "z1pwu@KERBER.TEST" created.'
    pwx="$(kadm "$client" adminpassword 'getprinc z1pwu' | grep -E '^Password expiration date: ')"
    echo "$pwx"
    if echo "$pwx" | grep -qF '[never]'; then
        echo "$leg: policy pw_max_life did not set the password expiration" >&2
        exit 1
    fi
    # now + 30d, to the day (the two legs run seconds apart).
    docker exec "$ctn" sh -c "date -u -d '+30 days' '+%a %b %d'" | grep -qF "$(echo "$pwx" | sed -E 's/^Password expiration date: ([A-Za-z]+ [A-Za-z]+ [0-9]+) .*/\1/')" || {
        echo "$leg: password expiration is not now + 30d: $pwx" >&2
        exit 1
    }

    echo "---- $leg: ACL -policy shortpol is enforced on addprinc (Password is too short; nothing created) ----"
    out="$(kadm z1pol z1pol-secret 'addprinc -pw abc z1short')"
    echo "$out"
    echo "$out" | grep -F 'add_principal: Password is too short while creating "z1short@KERBER.TEST".'
    out="$(kadm "$client" adminpassword 'getprinc z1short')"
    echo "$out"
    echo "$out" | grep -F 'get_principal: Principal does not exist while retrieving "z1short@KERBER.TEST".'
    out="$(kadm z1pol z1pol-secret 'addprinc -pw longenough z1long')"
    echo "$out"
    echo "$out" | grep -F 'Principal "z1long@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1long' | grep -E '^Policy: shortpol$'

    echo "---- $leg: ACL -maxrenewlife 1d keeps an in-mask 0 and lowers 30d ----"
    kadm z1rl z1rl-secret 'addprinc -pw x -maxrenewlife 0 z1r0' | grep -F 'Principal "z1r0@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1r0' | grep -F 'Maximum renewable life: 0 days 00:00:00'
    kadm z1rl z1rl-secret 'addprinc -pw x -maxrenewlife 30d z1r30' | grep -F 'Principal "z1r30@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1r30' | grep -F 'Maximum renewable life: 1 day 00:00:00'

    echo "---- $leg: ACL -maxlife 1h: a modify without -maxlife takes the cap (auth.c:259-263) ----"
    kadm z1ml z1ml-secret 'addprinc -pw x -maxlife 30m z1mu' | grep -F 'Principal "z1mu@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1mu' | grep -F 'Maximum ticket life: 0 days 00:30:00'
    kadm z1ml z1ml-secret 'modprinc +requires_preauth z1mu' | grep -F 'Principal "z1mu@KERBER.TEST" modified.'
    kadm "$client" adminpassword 'getprinc z1mu' | grep -F 'Maximum ticket life: 0 days 01:00:00'
}
z11_leg "$NAME" admin admin/admin /tmp/kadmin-krb5.conf rust
z11_leg "$NAME_MIT" admin/admin admin/admin /etc/krb5.conf mit
echo "---- Z1.1 getprinc z1u shape: Rust vs MIT ----"
sed 's/^/rust: /' "$SCRATCH/z11-rust.txt"
sed 's/^/mit:  /' "$SCRATCH/z11-mit.txt"
diff "$SCRATCH/z11-rust.txt" "$SCRATCH/z11-mit.txt" || { echo "Z1.1: getprinc z1u differs between the Rust kadmind and MIT kadmind" >&2; exit 1; }

# W1-Z Z1b.1: the AUTH_GSSAPI GSSAPI_INIT arg-version switch
# (svc_auth_gssapi.c:326-341) against both kadminds on 749 with a forged
# init (empty token): 1/2 → init_res.version 1, 3/4 echoed, 5 → AUTH_BADCRED.
echo "==== Z1b.1 AUTH_GSSAPI init-arg version switch (svc_auth_gssapi.c:326-341): Rust kadmind vs MIT kadmind ===="
z1b1_leg() {
    local ctn=$1 leg=$2 v out
    docker cp "$ROOT/scripts/lib/auth-gssapi-init-probe.py" "$ctn":/tmp/auth-gssapi-init-probe.py
    for v in 1 2 3 4 5 0; do
        out="$(docker exec "$ctn" python3 /tmp/auth-gssapi-init-probe.py 127.0.0.1:749 "$v")"
        echo "$leg: init-arg version $v -> $out"
        case $v in
            1|2) echo "$out" | grep -q '^accepted version=1 ' || { echo "$leg: version $v was not answered with init_res.version 1" >&2; exit 1; } ;;
            3|4) echo "$out" | grep -q "^accepted version=$v " || { echo "$leg: version $v was not echoed" >&2; exit 1; } ;;
            *)   echo "$out" | grep -q '^denied auth_stat=1 AUTH_BADCRED$' || { echo "$leg: version $v was not AUTH_BADCRED" >&2; exit 1; } ;;
        esac
    done
}
z1b1_leg "$NAME" rust
z1b1_leg "$NAME_MIT" mit

echo "==== Z6.5 RPC create honours ks_tuple (svr_principal.c:444-447) ===="
# MIT kadmin addprinc -randkey -e against both kadminds (still up after z11).
# Date-bearing lines are dropped; only Key: lines are compared.
z65_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -randkey -e aes128-cts-hmac-sha1-96:normal z65' 2>&1 \
        | grep -F 'Principal "z65@KERBER.TEST" created.'
    local keys
    keys="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getprinc z65' | grep '^Key:')"
    echo "$leg: $keys"
    echo "$keys" | grep -Fx 'Key: vno 1, aes128-cts-hmac-sha1-96' >/dev/null
    [ "$(echo "$keys" | grep -c '^Key:')" = 1 ] || {
        echo "$leg: z65 has more than the requested keysalt: $keys" >&2
        exit 1
    }
    echo "$keys" > "$SCRATCH/z65-$leg.txt"
}
z65_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z65_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z65-rust.txt" "$SCRATCH/z65-mit.txt" || {
    echo "Z6.5: getprinc z65 Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z6.6 params.max_life default is 24 h (alt_prof.c:574-575) ===="
# Stock kdc.conf writes max_life = 10h. Strip only that relation (not
# max_renewable_life) and restart both kadminds so an unmasked create
# takes MIT's 24 h default.
z66_profile() {
    # python must run *inside* the container (z11_profile): `docker exec`
    # without `-i` does not forward the host heredoc, so the file was never
    # written and rust kadmind exited on a missing KRB5_KDC_PROFILE.
    docker exec "$1" sh -c '
python3 - <<PY
from pathlib import Path
src = Path("/etc/krb5kdc/kdc.conf").read_text().splitlines(True)
out = []
for ln in src:
    key = ln.split("=", 1)[0].strip()
    if key == "max_life":
        continue
    out.append(ln)
Path("/tmp/z66-kdc.conf").write_text("".join(out))
PY
test -f /tmp/z66-kdc.conf
grep -q max_renewable_life /tmp/z66-kdc.conf
if grep -E "^[[:space:]]*max_life[[:space:]]*=" /tmp/z66-kdc.conf; then
    echo "z66-kdc.conf still has max_life" >&2
    exit 1
fi
'
}
z66_restart() {
    local ctn=$1 is_mit=$2
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" sh -c '
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
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec -d -e KRB5_KDC_PROFILE=/tmp/z66-kdc.conf "$ctn" sh -c 'kadmind -nofork >/tmp/kadmind-z66.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-z66.log >&2 || true; echo "MIT kadmind did not listen for z66" >&2; exit 1; }
    else
        docker exec "$ctn" sh -c '
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
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec -d \
            -e KRB5_KDC_DB=/tmp/principal \
            -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_ACL_FILE=/tmp/kadm5.acl \
            -e KRB5_KDC_PROFILE=/tmp/z66-kdc.conf \
            "$ctn" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-z66.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" sh -c 'echo ---- z66-kdc.conf ----; cat /tmp/z66-kdc.conf; echo ---- kadmind-z66.log ----; cat /tmp/kadmind-z66.log' >&2 || true; echo "Rust kadmind did not listen for z66" >&2; exit 1; }
    fi
}
z66_profile "$NAME"
z66_profile "$NAME_MIT"
z66_restart "$NAME" rust
z66_restart "$NAME_MIT" mit
z66_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -pw x z66' 2>&1 | grep -F 'Principal "z66@KERBER.TEST" created.'
    local life
    life="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getprinc z66' | grep '^Maximum ticket life:')"
    echo "$leg: $life"
    echo "$life" | grep -Fx 'Maximum ticket life: 1 day 00:00:00'
    echo "$life" > "$SCRATCH/z66-$leg.txt"
}
z66_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z66_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z66-rust.txt" "$SCRATCH/z66-mit.txt" || {
    echo "Z6.6: getprinc z66 Maximum ticket life differs between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z7.2 RPC chpass/randkey honour ks_tuple (svr_principal.c:1259,1425) ===="
z72_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -pw z72old z72c' 2>&1 \
        | grep -F 'Principal "z72c@KERBER.TEST" created.'
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'cpw -pw z72new -e aes128-cts-hmac-sha1-96:normal z72c' 2>&1 \
        | grep -F 'Password for "z72c@KERBER.TEST" changed.'
    local keys
    keys="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getprinc z72c' | grep '^Key:')"
    echo "$leg cpw -e: $keys"
    echo "$keys" | grep -Fx 'Key: vno 2, aes128-cts-hmac-sha1-96' >/dev/null
    [ "$(echo "$keys" | grep -c '^Key:')" = 1 ] || {
        echo "$leg: z72c has more than the requested keysalt: $keys" >&2
        exit 1
    }
    echo "$keys" > "$SCRATCH/z72c-$leg.txt"
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -randkey z72r' 2>&1 \
        | grep -F 'Principal "z72r@KERBER.TEST" created.'
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'cpw -randkey -e aes128-cts-hmac-sha1-96:normal z72r' 2>&1 \
        | grep -F 'Key for "z72r@KERBER.TEST" randomized.'
    keys="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getprinc z72r' | grep '^Key:')"
    echo "$leg cpw -randkey -e: $keys"
    echo "$keys" | grep -Fx 'Key: vno 2, aes128-cts-hmac-sha1-96' >/dev/null
    [ "$(echo "$keys" | grep -c '^Key:')" = 1 ] || {
        echo "$leg: z72r has more than the requested keysalt: $keys" >&2
        exit 1
    }
    echo "$keys" > "$SCRATCH/z72r-$leg.txt"
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addpol -allowedkeysalts aes256-cts:normal z72ks' >/dev/null
    local refuse
    refuse="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -policy z72ks -e aes128-cts:normal -pw ValidPass1 z72ksbad' 2>&1 || true)"
    echo "$leg refuse: $refuse"
    echo "$refuse" | grep -F 'Invalid key/salt tuples'
    echo "$refuse" > "$SCRATCH/z72ks-$leg.txt"
}
z72_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z72_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z72c-rust.txt" "$SCRATCH/z72c-mit.txt" || {
    echo "Z7.2: getprinc z72c Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
diff "$SCRATCH/z72r-rust.txt" "$SCRATCH/z72r-mit.txt" || {
    echo "Z7.2: getprinc z72r Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
diff "$SCRATCH/z72ks-rust.txt" "$SCRATCH/z72ks-mit.txt" || {
    echo "Z7.2: addprinc -policy -e refusal differs between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z8.3 bootstrap actors: kadmin/changepw kdb5_util@ (kadm5_create.c:100) ===="
# kadmin/changepw is never successfully modified in this gate (the
# lockdown_keys cell is a privilege denial), so both legs still show
# kadm5_create's kdb5_util@REALM. krbtgt is purgekeys'd earlier
# (admin@ on rust, admin/admin@ on MIT — fixture princstr); bootstrap
# db_creation@ is z8_bootstrap_mod.rs.
z83_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
R83="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kadmin -p admin/admin -w adminpassword -q 'getprinc kadmin/changepw')"
M83="$(docker exec -e KRB5_CONFIG=/etc/krb5.conf "$NAME_MIT" \
    kadmin -p admin/admin -w adminpassword -q 'getprinc kadmin/changepw')"
echo "$R83" | hist_shape | sed 's/^/rust kadmin\/changepw: /'
echo "$M83" | hist_shape | sed 's/^/mit kadmin\/changepw: /'
R83MOD="$(echo "$R83" | z83_mod)"
M83MOD="$(echo "$M83" | z83_mod)"
echo "rust kadmin/changepw modifier=$R83MOD"
echo "mit  kadmin/changepw modifier=$M83MOD"
[ "$R83MOD" = "kdb5_util@KERBER.TEST" ]
[ "$M83MOD" = "kdb5_util@KERBER.TEST" ]
[ "$R83MOD" = "$M83MOD" ]
R83T="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kadmin -p admin/admin -w adminpassword -q 'getprinc krbtgt/KERBER.TEST')"
M83T="$(docker exec -e KRB5_CONFIG=/etc/krb5.conf "$NAME_MIT" \
    kadmin -p admin/admin -w adminpassword -q 'getprinc krbtgt/KERBER.TEST')"
R83TMOD="$(echo "$R83T" | z83_mod)"
M83TMOD="$(echo "$M83T" | z83_mod)"
echo "rust krbtgt modifier=$R83TMOD (purgekeys caller)"
echo "mit  krbtgt modifier=$M83TMOD (purgekeys caller)"
[ "$R83TMOD" = "admin@KERBER.TEST" ]
[ "$M83TMOD" = "admin/admin@KERBER.TEST" ]
echo "MIT_z83_bootstrap_actors"
echo "RUST_z83_bootstrap_actors"

echo "==== Z8.4 addpol/modpol unknown keysalt matches MIT (string_to_keysalts skips) ===="
# Live MIT kadmin.local addpol -allowedkeysalts bogus:normal succeeds
# (str_conv.c:341-343 discards unrecognized; validate only rejects a tab).
z84_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    local add mod get
    add="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addpol -allowedkeysalts bogus:normal z8pol' 2>&1 || true)"
    echo "$leg addpol: $add"
    if echo "$add" | grep -qF 'Invalid key/salt tuples'; then
        echo "$leg: addpol bogus:normal was refused" >&2
        exit 1
    fi
    get="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getpol z8pol' | grep -E '^(Policy|Allowed key/salt)')"
    echo "$leg getpol: $get"
    echo "$get" | grep -F 'Policy: z8pol'
    echo "$get" | grep -F 'Allowed key/salt types: bogus:normal'
    echo "$get" > "$SCRATCH/z84get-$leg.txt"
    docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addpol z8mod' >/dev/null
    mod="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'modpol -allowedkeysalts bogus:normal z8mod' 2>&1 || true)"
    echo "$leg modpol: $mod"
    if echo "$mod" | grep -qF 'Invalid key/salt tuples'; then
        echo "$leg: modpol bogus:normal was refused" >&2
        exit 1
    fi
}
z84_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z84_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z84get-rust.txt" "$SCRATCH/z84get-mit.txt" || {
    echo "Z8.4: getpol z8pol differs between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z8.5 weak/deprecated -e on both kadminds (allow_weak_crypto = false) ===="
z85_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    local des3 rc4 keys
    des3="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -randkey -e des3-cbc-sha1:normal z8des3' 2>&1 || true)"
    rc4="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'addprinc -randkey -e arcfour-hmac:normal z8rc4' 2>&1 || true)"
    echo "$leg des3: $des3"
    echo "$leg rc4: $rc4"
    echo "$des3" | grep -F 'Principal "z8des3@KERBER.TEST" created.'
    echo "$rc4" | grep -F 'Principal "z8rc4@KERBER.TEST" created.'
    keys="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getprinc z8des3' | grep '^Key:')"
    echo "$leg des3 keys: $keys"
    echo "$keys" > "$SCRATCH/z85des3-$leg.txt"
    keys="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$client" -w adminpassword \
        -q 'getprinc z8rc4' | grep '^Key:')"
    echo "$leg rc4 keys: $keys"
    echo "$keys" > "$SCRATCH/z85rc4-$leg.txt"
}
z85_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z85_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z85des3-rust.txt" "$SCRATCH/z85des3-mit.txt" || {
    echo "Z8.5: getprinc z8des3 Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
diff "$SCRATCH/z85rc4-rust.txt" "$SCRATCH/z85rc4-mit.txt" || {
    echo "Z8.5: getprinc z8rc4 Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
echo "MIT_z85_des3_rc4_ks_tuple"
echo "RUST_z85_des3_rc4_ks_tuple"

echo "==== Z8 leftover: kadm5_create max_life (kadm5_create.c:54-55,207-213) ===="
z8life() {
    local ctn=$1 client=$2 conf=$3 princ=$4 want=$5
    local life
    life="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        kadmin -p "$client" -w adminpassword -q "getprinc $princ" \
        | grep '^Maximum ticket life:')"
    echo "$ctn $princ: $life"
    echo "$life" | grep -Fx "$want"
}
z8life "$NAME" admin/admin /tmp/kadmin-krb5.conf kadmin/admin \
    'Maximum ticket life: 0 days 03:00:00'
z8life "$NAME_MIT" admin/admin /etc/krb5.conf kadmin/admin \
    'Maximum ticket life: 0 days 03:00:00'
z8life "$NAME" admin/admin /tmp/kadmin-krb5.conf kadmin/changepw \
    'Maximum ticket life: 0 days 00:05:00'
z8life "$NAME_MIT" admin/admin /etc/krb5.conf kadmin/changepw \
    'Maximum ticket life: 0 days 00:05:00'
echo "MIT_z8_kadm5_create_max_life"
echo "RUST_z8_kadm5_create_max_life"

echo "==== Z8 leftover: setstr stamps current_caller (svr_principal.c:2022-2043) ===="
# RPC create stamps the kadmind caller; local setstr must restamp
# like kdb_put_entry (Z7.2 local princstr is root/admin@ both legs).
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kadmin -p admin/admin -w adminpassword -q 'addprinc -pw z8str-secret z8str' \
    | grep -F 'Principal "z8str@KERBER.TEST" created.'
docker exec -e KRB5_CONFIG=/etc/krb5.conf "$NAME_MIT" \
    kadmin -p admin/admin -w adminpassword -q 'addprinc -pw z8str-secret z8str' \
    | grep -F 'Principal "z8str@KERBER.TEST" created.'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -p root/admin -q 'setstr z8str note leftover'
docker exec "$NAME_MIT" kadmin.local -p root/admin -q 'setstr z8str note leftover'
z8str_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
RSTR="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -p root/admin -q 'getprinc z8str')"
MSTR="$(docker exec "$NAME_MIT" kadmin.local -p root/admin -q 'getprinc z8str')"
echo "$RSTR" | hist_shape | sed 's/^/rust z8str: /'
echo "$MSTR" | hist_shape | sed 's/^/mit  z8str: /'
RSTRMOD="$(echo "$RSTR" | z8str_mod)"
MSTRMOD="$(echo "$MSTR" | z8str_mod)"
echo "rust z8str modifier=$RSTRMOD"
echo "mit  z8str modifier=$MSTRMOD"
[ "$RSTRMOD" = "root/admin@KERBER.TEST" ]
[ "$MSTRMOD" = "root/admin@KERBER.TEST" ]
echo "MIT_z8_setstr_stamps_caller"
echo "RUST_z8_setstr_stamps_caller"

log "kadmin.gate" "ok" ',"principal":"extra@KERBER.TEST","op":"addprinc+cpw+get+list+mod+chrand+norandkey+lockdown+purgekeys+setstr+renprinc+del+alias"'
exit 0

