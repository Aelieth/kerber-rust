#!/usr/bin/env bash
# The kpasswd gates' shared helpers: the raw kpasswd exchange and the pinned wire cells both legs run.
# Sourced after gate-common.sh by kpasswd-mit-gate.sh and kpasswd-rust-gate.sh; each function reads
# the gate's globals when it is called.
# shellcheck shell=bash

# Raw UDP kpasswd: vno 0x0002 / plen != len. MIT schpw.c:60-82 sets
# numresult then goto bailout; dispatch logs com_err and sends no datagram.
kpasswd_raw() {
    local ctn=$1 kind=$2
    docker exec "$ctn" python3 -c '
import socket, struct, sys

def tlv(data, i=0):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + l], i + l

def krb_error(der):
    _, inner, _ = tlv(der)
    _, seqb, _ = tlv(inner)
    i = 0
    fields = {}
    while i < len(seqb):
        t, v, i = tlv(seqb, i)
        n = t & 0x1F
        if t & 0x20 and v:
            _, inner2, _ = tlv(v)
            fields[n] = inner2
        else:
            fields[n] = v
    code = int.from_bytes(fields.get(6, b"\x00"), "big")
    return code, fields.get(11, b""), fields.get(12, b"")

kind = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
if kind == "vno":
    pkt = struct.pack(">HHH", 6, 2, 0)
elif kind == "len":
    pkt = struct.pack(">HHH", 99, 1, 0)
elif kind == "apreq":
    # schpw.c:89 uses `>=` so AP-REQ must leave at least one PRIV byte
    # or MIT goto bailout (no datagram). Junk AP-REQ then chpwfail.
    pkt = struct.pack(">HHH", 11, 1, 4) + b"junk" + b"x"
elif kind == "fill":
    pkt = struct.pack(">HHH", 10, 1, 4) + b"junk"
else:
    raise SystemExit("kind")
s.sendto(pkt, ("127.0.0.1", 464))
try:
    data, _ = s.recvfrom(4096)
except socket.timeout:
    print("timeout")
    raise SystemExit(2)
print("hex=" + data.hex())
print("ap_len=" + str(struct.unpack(">H", data[4:6])[0] if len(data) >= 6 else -1))
if len(data) >= 6 and struct.unpack(">H", data[4:6])[0] == 0:
    code, etext, edata = krb_error(data[6:])
    print("error_code=%d" % code)
    print("e_data_hex=" + edata.hex())
if b"\x00\x06Request contained unknown protocol version number 2" in data:
    print("result=6")
if b"\x00\x01Request length was inconsistent" in data:
    print("result=1")
if b"Failed reading application request" in data:
    print("result=3")
    print("text=autherror")
if b"Request contained unknown protocol version number 2" in data:
    print("text=unknown_version")
if b"Request length was inconsistent" in data:
    print("text=inconsistent_length")
' "$kind"
}

pin_kpasswd_apreq_retransmit() {
    local ctn=$1 label=$2 run OUT rc
    for run in 1 2; do
        echo "---- $label bad AP-REQ $run ----"
        set +e
        OUT="$(kpasswd_raw "$ctn" apreq)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 0 ]
        echo "$OUT" | grep -F 'ap_len=0'
        echo "$OUT" | grep -F 'result=3'
        echo "$OUT" | grep -F 'text=autherror'
        echo "$OUT" | grep -F 'error_code=60'
        echo "$OUT" | grep -F 'e_data_hex=00034661696c65642072656164696e67206170706c69636174696f6e2072657175657374'
    done
}

pin_kpasswd_fill_datagram() {
    local ctn=$1 label=$2 run OUT rc
    for run in 1 2; do
        echo "---- $label fill-datagram AP-REQ $run ----"
        set +e
        OUT="$(kpasswd_raw "$ctn" fill)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        if echo "$OUT" | grep -F 'hex='; then
            echo "$label framed a fill-the-datagram kpasswd AP-REQ" >&2
            exit 1
        fi
    done
}

# MIT schpw.c goto bailout; dispatch logs com_err and sends no framed reply.
pin_kpasswd_raw_rust() {
    local run nlog OUT rc
    for run in 1 2; do
        nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- Rust raw vno $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME" vno)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        if echo "$OUT" | grep -F 'hex='; then
            echo "Rust framed a malformed kpasswd datagram" >&2
            exit 1
        fi
        docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Requested protocol version not supported - while dispatching (udp)'
        nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- Rust raw len $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME" len)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        if echo "$OUT" | grep -F 'hex='; then
            echo "Rust framed a malformed kpasswd datagram" >&2
            exit 1
        fi
        docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Message stream modified - while dispatching (udp)'
    done
}

# MIT schpw.c goto bailout; dispatch logs com_err and sends no framed reply.
pin_kpasswd_raw_mit() {
    local run nlog OUT rc
    for run in 1 2; do
        nlog="$(docker exec "$NAME_MIT" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- MIT raw vno $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME_MIT" vno)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        docker exec "$NAME_MIT" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Requested protocol version not supported - while dispatching (udp)'
        nlog="$(docker exec "$NAME_MIT" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- MIT raw len $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME_MIT" len)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        docker exec "$NAME_MIT" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Message stream modified - while dispatching (udp)'
    done
}
