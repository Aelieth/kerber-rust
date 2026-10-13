#!/usr/bin/env bash
# The kadmin gates' shared helpers: the kadm5 probe builds, the RPCSEC_GSS and framing cells, the snapshot
# keys. Sourced after gate-common.sh by kadmin-{mit,rust,both}-gate.sh and kadmin-rust-acl-gate.sh; each
# function reads the gate's globals ($NAME, $ROOT, the conf paths) when it is called.
# shellcheck shell=bash

# MIT kadmin prints "Authenticating as principal ... with password." to stdout
# and the com_err sentence to stderr. Under 2>&1 the banner can land inside
# that sentence. This is the same sed -z as kadmin-local-gate.sh's mit_local:
# it removes the banner wherever it landed and rejoins the line.
strip_mit_kadmin_banner() {
    sed -z -e 's/Authenticating as principal [^\n]*with password\.\n//g'
}

_snap_key() {
    printf '%s\n' "${tree_sha:?}"
}

save_rust_snap() {
    printf '%s\n' "$2" >"$SCRATCH/kadmin-rust-$1"
    _snap_key >"$SCRATCH/kadmin-rust-$1.key"
}

_kadmin_cleanup() {
    if [ "${KERBER_KADMIN_KEEP:-}" = 1 ]; then
        return 0
    fi
    register_cleanup "$1"
}

compile_kadm5_changepw() {
    local ctn=$1
    docker cp "$ROOT/scripts/oracle/kadm5-changepw-rpc.c" "$ctn":/tmp/kadm5-changepw-rpc.c
    mit_oracle_cc "$ctn" /tmp/kadm5-changepw-rpc /tmp/kadm5-changepw-rpc.c kadm-client
}

kadm5_changepw_list() {
    local ctn=$1 client=$2 pass=$3
    docker exec -e KRB5_CONFIG="${4:-/etc/krb5.conf}" "$ctn" \
        /tmp/kadm5-changepw-rpc "$client" "$pass" KERBER.TEST listprincs
}

compile_kadm5_integrity() {
    local ctn=$1
    docker cp "$ROOT/scripts/oracle/kadm5-integrity-rpc.c" "$ctn":/tmp/kadm5-integrity-rpc.c
    mit_oracle_cc "$ctn" /tmp/kadm5-integrity-rpc /tmp/kadm5-integrity-rpc.c kadm-client
}

# kadmin/admin is DISALLOW_TGT_BASED, so kinit -S takes an initial service
# ticket the RPCSEC_GSS acceptor accepts.
kadm5_integrity_list() {
    local ctn=$1 client=$2 pass=$3 svc=$4 conf=${5:-/etc/krb5.conf} port=${6:-749}
    docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/int-cc "$ctn" sh -c \
        "printf '%s\n' '$pass' | kinit -S kadmin/admin@KERBER.TEST '$client' >/dev/null 2>&1; \
        exec /tmp/kadm5-integrity-rpc 127.0.0.1 kadmin/admin@KERBER.TEST '$svc' '$port'"
}

compile_kadm5_probe() {
    local ctn=$1
    # The gates build it again where a cell needs it; a container is made for one run, so what is there is this source's build.
    docker exec "$ctn" test -x /tmp/kadm5-rpc-probe && return 0
    docker cp "$ROOT/scripts/oracle/kadm5-rpc-probe.c" "$ctn":/tmp/kadm5-rpc-probe.c
    mit_oracle_cc "$ctn" /tmp/kadm5-rpc-probe /tmp/kadm5-rpc-probe.c kadm-client
}

# The ticket and the probe run in one shell of the container: a docker exec is about 0.1 s, and the gates make dozens of probes.
kadm5_probe() {
    local ctn=$1 client=$2 mode=$3 conf=${4:-/etc/krb5.conf}
    local service=${5:-kadmin/admin@KERBER.TEST} port=${6:-749}
    docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/probe-cc "$ctn" sh -c \
        "printf 'adminpassword\n' | kinit -S '$service' '$client' >/dev/null 2>&1; \
        exec /tmp/kadm5-rpc-probe 127.0.0.1 '$service' '$mode' '$port'"
}

# The acceptor names kadmind's two RPC programs are asked with, one probe each, and the label each answers. kadm5's
# check_rpcsec_auth (kadm_rpc_svc.c:333-337) is exact: two components, the realm, `kadmin`, not `history`. iprop's
# check_iprop_rpcsec_auth (ipropd_svc.c:513-514) is a strncmp over the component's own length, so MIT's iprop program
# also serves any prefix of `kiprop`; ours serves `kiprop` alone (docs/mit-deviations.md, docs/security.md).
# Columns: name, the kadm5 program's label, the iprop program's on MIT, the iprop program's on ours.
SERVICE_NAME_CELLS=(
    "kadmin/admin SUCCESS AUTH_TOOWEAK AUTH_TOOWEAK"
    "kadmin/changepw SUCCESS AUTH_TOOWEAK AUTH_TOOWEAK"
    "kadmin/history AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "kadmin/testhost.kerber.test SUCCESS AUTH_TOOWEAK AUTH_TOOWEAK"
    "kadmins/admin AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "kadmin AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "kadmin/testhost.kerber.test/x AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "host/testhost.kerber.test AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "kiprop/testhost.kerber.test AUTH_TOOWEAK SUCCESS SUCCESS"
    "k/testhost.kerber.test AUTH_TOOWEAK SUCCESS AUTH_TOOWEAK"
    "kip/testhost.kerber.test AUTH_TOOWEAK SUCCESS AUTH_TOOWEAK"
    "kipro/testhost.kerber.test AUTH_TOOWEAK SUCCESS AUTH_TOOWEAK"
    "kiprop2/testhost.kerber.test AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "K/testhost.kerber.test AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "/testhost.kerber.test AUTH_TOOWEAK SUCCESS AUTH_TOOWEAK"
    "kiprop AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
    "kiprop/testhost.kerber.test/x AUTH_TOOWEAK AUTH_TOOWEAK AUTH_TOOWEAK"
)

# A batch is run by one shell of the container (a docker exec is about 0.1 s, and the table is 34 probes): its output is a run of
# blocks, each headed by a line "@@ KEY". _probe_blocks reads that on stdin into PROBE_OUT[KEY], the block's lines, and prints
# whatever precedes the first header (the exec's own error), so the host judges the claims one at a time, a transcript line each.
declare -A PROBE_OUT=()
_probe_blocks() {
    local line key='' before=''
    PROBE_OUT=()
    while IFS= read -r line; do
        if [[ $line == '@@ '* ]]; then
            key=${line#@@ }
            PROBE_OUT["$key"]=
        elif [ -n "$key" ]; then
            PROBE_OUT["$key"]+=${PROBE_OUT["$key"]:+$'\n'}$line
        else
            before+=$line$'\n'
        fi
    done
    printf '%s' "$before"
}

# service_name_principals RUNNER [DOCKER-EXEC-OPTIONS...] CONTAINER -- [KADMIN-ARGS...]: one kadmin session, its queries on stdin
# (the runner takes -i and no -q), makes the principal of every name in the table; best-effort, as some exist.
service_name_principals() {
    local cell name
    for cell in "${SERVICE_NAME_CELLS[@]}"; do
        read -r name _ <<<"$cell"
        printf 'addprinc -randkey %s\n' "$name"
    done | kadmin_q_try "$@"
    echo
}

# service_name_cells LEG CTN CLIENT CONF IPROP_PORT: LEG is mit or rust. One shell in CTN takes every name's ticket at once (kinit -S,
# each into a cache of its own that was removed first, so a refused ticket is no probe of the name before it), then asks the kadm5
# program and the iprop program, a stream each (two connections at a time), with each ticket in turn.
service_name_cells() {
    local leg=$1 ctn=$2 client=$3 conf=$4 iprop_port=$5 cell name kadm5 mit ours want out all script
    local -a svcs=()
    IFS= read -r -d '' script <<'EOF' || true
client=$1 port=$2
shift 2
i=0
for svc in "$@"; do
    i=$((i + 1))
    rm -f "/tmp/probe-cc-$i"
    (printf 'adminpassword\n' | KRB5CCNAME="/tmp/probe-cc-$i" kinit -S "$svc" "$client" >/dev/null 2>&1) &
done
wait
(
    i=0
    for svc in "$@"; do
        i=$((i + 1))
        echo "@@ kadm5 $svc"
        KRB5CCNAME="/tmp/probe-cc-$i" /tmp/kadm5-rpc-probe 127.0.0.1 "$svc" valid 749 2>&1 </dev/null
    done
) >/tmp/probe-kadm5.out &
(
    i=0
    for svc in "$@"; do
        i=$((i + 1))
        echo "@@ iprop $svc"
        KRB5CCNAME="/tmp/probe-cc-$i" /tmp/kadm5-rpc-probe 127.0.0.1 "$svc" iprop-valid "$port" 2>&1 </dev/null
    done
) >/tmp/probe-iprop.out &
wait
cat /tmp/probe-kadm5.out /tmp/probe-iprop.out
EOF
    for cell in "${SERVICE_NAME_CELLS[@]}"; do
        read -r name _ <<<"$cell"
        svcs+=("$name@KERBER.TEST")
    done
    all="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" sh -c "$script" sh "$client" "$iprop_port" "${svcs[@]}" 2>&1 || true)"
    _probe_blocks <<<"$all"
    for cell in "${SERVICE_NAME_CELLS[@]}"; do
        read -r name kadm5 mit ours <<<"$cell"
        out="${PROBE_OUT["kadm5 $name@KERBER.TEST"]-}"
        echo "$leg kadm5 program, acceptor $name: $out"
        [[ $out == *"valid label=$kadm5"* ]] || die "$leg kadm5 program, acceptor $name: not $kadm5"
        want=$ours
        [ "$leg" = mit ] && want=$mit
        out="${PROBE_OUT["iprop $name@KERBER.TEST"]-}"
        echo "$leg iprop program, acceptor $name: $out"
        [[ $out == *"iprop-valid label=$want"* ]] || die "$leg iprop program, acceptor $name: not $want"
    done
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

# AUTH_NONE IPROP: PROG_UNAVAIL without iprop_enable (the program is not registered), AUTH_TOOWEAK with it.
xid = 0x11111111
body = struct.pack(">10I", xid, 0, 2, 100423, 1, 0, 0, 0, 0, 0)
emit("auth_none", exchange(body))
'
}
