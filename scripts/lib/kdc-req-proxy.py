#!/usr/bin/env python3
"""UDP/TCP proxy that prints the request *shape* of every KDC-REQ it forwards.

usage:
  kdc-req-proxy.py <listen-port> <kdc-host> <kdc-port> [out.jsonl]
  kdc-req-proxy.py --compare <mit.jsonl> <rust.jsonl> <flow-name>
  kdc-req-proxy.py --self-test

Each forwarded request is one JSON object (JSONL). Compared fields are the
plan-w1b seed columns: padata types/order, KDCOptions bits, etype list,
addresses present, rtime/till class, nonce present, sname, and KRB-ERROR
e_data. Timestamps and nonce *values* are classified, never compared raw.
"""
from __future__ import annotations

import json
import select
import socket
import struct
import sys
import threading


KDC_FLAGS = (
    (0x40000000, "forwardable"),
    (0x20000000, "forwarded"),
    (0x10000000, "proxiable"),
    (0x08000000, "proxy"),
    (0x04000000, "allow_postdate"),
    (0x02000000, "postdated"),
    (0x00800000, "renewable"),
    (0x00200000, "reserved20"),
    (0x00020000, "cname_in_addl_tkt"),
    (0x00010000, "canonicalize"),
    (0x00008000, "request_anonymous"),
    (0x00000020, "disable_transited_check"),
    (0x00000010, "renewable_ok"),
    (0x00000008, "enc_tkt_in_skey"),
    (0x00000002, "renew"),
    (0x00000001, "validate"),
)

# Fields the seed gate dies on if they diverge (already-matching / structural).
CORE_FIELDS = ("msg_type", "sname", "nonce", "etype_nonempty")
# Fields recorded as ranked deviations when they differ.
SHAPE_FIELDS = (
    "padata",
    "kdc_options",
    "etypes",
    "addresses",
    "till",
    "rtime",
    "from",
    "cname",
    "cname_nt",
    "sname_nt",
    "addl_tickets",
    "enc_authdata",
)


def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    n = buf[i]
    if n < 0x80:
        return n, i + 1
    count = n & 0x7F
    if count == 0 or count > 4 or i + 1 + count > len(buf):
        raise ValueError("der length")
    val = 0
    for b in buf[i + 1 : i + 1 + count]:
        val = (val << 8) | b
    return val, i + 1 + count


def _tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    tag = buf[i]
    i += 1
    if tag & 0x1F == 0x1F:
        while buf[i] & 0x80:
            i += 1
        i += 1
    ln, i = _read_len(buf, i)
    return tag, buf[i : i + ln], i + ln


def _int(val: bytes) -> int:
    if not val:
        return 0
    n = 0
    for b in val:
        n = (n << 8) | b
    if val[0] & 0x80:
        n -= 1 << (8 * len(val))
    return n


def _unwrap(val: bytes, constructed: bool) -> bytes:
    if constructed and val:
        _, inner, _ = _tlv(val, 0)
        return inner
    return val


def _general_string(val: bytes) -> str:
    try:
        return val.decode("ascii")
    except UnicodeDecodeError:
        return val.decode("latin-1", "replace")


def _principal(val: bytes) -> tuple[str | None, int | None]:
    if val and val[0] == 0x30:
        _, seq, _ = _tlv(val, 0)
        val = seq
    i = 0
    parts: list[str] = []
    ntype = None
    while i < len(val):
        tag, inner, i = _tlv(val, i)
        if tag & 0xC0 != 0x80:
            continue
        num = tag & 0x1F
        inner = _unwrap(inner, bool(tag & 0x20))
        if num == 0:
            ntype = _int(inner)
        elif num == 1:
            if inner and inner[0] == 0x30:
                _, inner, _ = _tlv(inner, 0)
            j = 0
            while j < len(inner):
                _, s, j = _tlv(inner, j)
                parts.append(_general_string(s))
    if not parts:
        return None, ntype
    return "/".join(parts), ntype


def _time_class(val: bytes) -> str:
    if not val:
        return "absent"
    text = _general_string(val)
    if text.startswith("19700101"):
        return "zero"
    return "present"


def _bit_string_u32(val: bytes) -> int:
    if not val:
        return 0
    unused = val[0]
    bits = val[1:]
    if not bits:
        return 0
    n = 0
    for b in bits[:4]:
        n = (n << 8) | b
    n <<= 8 * max(0, 4 - len(bits))
    if unused and bits:
        n &= ~((1 << unused) - 1)
    return n


def _flag_names(opts: int) -> list[str]:
    names = [name for bit, name in KDC_FLAGS if opts & bit]
    leftover = opts
    for bit, _ in KDC_FLAGS:
        leftover &= ~bit
    if leftover:
        names.append(f"other=0x{leftover:08x}")
    return names


def _padata_types(inner: bytes) -> list[int]:
    types: list[int] = []
    j = 0
    while j < len(inner):
        _, pa, j = _tlv(inner, j)
        k = 0
        while k < len(pa):
            ptag, pval, k = _tlv(pa, k)
            if ptag == 0xA1:
                _, pt, _ = _tlv(pval, 0)
                types.append(_int(pt))
    return types


def parse_kdc_req_shape(pdu: bytes) -> dict | None:
    """Shape dict of an AS-REQ (0x6a) or TGS-REQ (0x6c), else None."""
    if not pdu or pdu[0] not in (0x6A, 0x6C):
        return None
    _, seq, _ = _tlv(pdu, 0)
    if seq and seq[0] == 0x30:
        _, seq, _ = _tlv(seq, 0)
    msg_type = 10 if pdu[0] == 0x6A else 12
    padata: list[int] = []
    body = None
    i = 0
    while i < len(seq):
        tag, val, i = _tlv(seq, i)
        if tag & 0xC0 != 0x80:
            continue
        num = tag & 0x1F
        inner = _unwrap(val, bool(tag & 0x20))
        if num == 2:
            msg_type = _int(inner)
        elif num == 3:
            padata = _padata_types(inner)
        elif num == 4:
            body = inner
            if body and body[0] == 0x30:
                _, body, _ = _tlv(body, 0)
    shape: dict = {
        "kind": "req",
        "msg_type": msg_type,
        "padata": padata,
        "kdc_options": [],
        "kdc_options_hex": "00000000",
        "cname": None,
        "cname_nt": None,
        "realm": None,
        "sname": None,
        "sname_nt": None,
        "from": "absent",
        "till": "absent",
        "rtime": "absent",
        "nonce": False,
        "etypes": [],
        "etype_nonempty": False,
        "addresses": False,
        "enc_authdata": False,
        "addl_tickets": False,
    }
    if body is None:
        return shape
    i = 0
    while i < len(body):
        tag, val, i = _tlv(body, i)
        if tag & 0xC0 != 0x80:
            continue
        num = tag & 0x1F
        inner = _unwrap(val, bool(tag & 0x20))
        if num == 0:
            opts = _bit_string_u32(inner)
            shape["kdc_options_hex"] = f"{opts:08x}"
            shape["kdc_options"] = _flag_names(opts)
        elif num == 1:
            name, ntype = _principal(inner)
            shape["cname"] = name
            shape["cname_nt"] = ntype
        elif num == 2:
            shape["realm"] = _general_string(inner)
        elif num == 3:
            name, ntype = _principal(inner)
            shape["sname"] = name
            shape["sname_nt"] = ntype
        elif num == 4:
            shape["from"] = _time_class(inner)
        elif num == 5:
            shape["till"] = _time_class(inner)
        elif num == 6:
            shape["rtime"] = _time_class(inner)
        elif num == 7:
            shape["nonce"] = True
        elif num == 8:
            etypes: list[int] = []
            j = 0
            seq = inner
            if seq and seq[0] == 0x30:
                _, seq, _ = _tlv(seq, 0)
            while j < len(seq):
                _, ev, j = _tlv(seq, j)
                etypes.append(_int(ev))
            shape["etypes"] = etypes
            shape["etype_nonempty"] = bool(etypes)
        elif num == 9:
            shape["addresses"] = bool(inner)
        elif num == 10:
            shape["enc_authdata"] = True
        elif num == 11:
            shape["addl_tickets"] = True
    return shape


def parse_error_shape(pdu: bytes) -> dict | None:
    if not pdu or pdu[0] != 0x7E:
        return None
    _, seq, _ = _tlv(pdu, 0)
    if seq and seq[0] == 0x30:
        _, seq, _ = _tlv(seq, 0)
    code = None
    etext = None
    types: list[int] = []
    enc = "none"
    i = 0
    while i < len(seq):
        tag, val, i = _tlv(seq, i)
        if tag & 0xC0 != 0x80:
            continue
        num = tag & 0x1F
        inner = _unwrap(val, bool(tag & 0x20))
        if num == 6:
            code = _int(inner)
        elif num == 11:
            etext = _general_string(inner)
        elif num == 12:
            enc, types = _edata_types(inner)
    return {
        "kind": "error",
        "error_code": code,
        "e_text": etext,
        "e_data_encoding": enc,
        "e_data_types": types,
    }


def _edata_types(edata: bytes) -> tuple[str, list[int]]:
    if not edata or edata[0] != 0x30:
        return "none", []
    _, body, _ = _tlv(edata, 0)
    types: list[int] = []
    enc = "unknown"
    j = 0
    while j < len(body):
        _, pa, j = _tlv(body, j)
        k = 0
        t = None
        while k < len(pa):
            ptag, pval, k = _tlv(pa, k)
            inner = _unwrap(pval, bool(ptag & 0x20))
            n = ptag & 0x1F
            if ptag & 0xC0 != 0x80:
                continue
            if n == 0:
                enc = "typed"
                t = _int(inner)
            elif n == 1 and enc != "typed":
                enc = "method"
                t = _int(inner)
        types.append(t if t is not None else -1)
    return enc, types


def parse_rep_shape(pdu: bytes) -> dict | None:
    if not pdu or pdu[0] not in (0x6B, 0x6D):
        return None
    _, seq, _ = _tlv(pdu, 0)
    if seq and seq[0] == 0x30:
        _, seq, _ = _tlv(seq, 0)
    padata: list[int] = []
    i = 0
    while i < len(seq):
        tag, val, i = _tlv(seq, i)
        if tag & 0xC0 != 0x80:
            continue
        if (tag & 0x1F) == 2:
            padata = _padata_types(_unwrap(val, bool(tag & 0x20)))
    return {
        "kind": "rep",
        "tag": pdu[0],
        "padata": padata,
        "len": len(pdu),
    }


def classify(pdu: bytes) -> dict:
    if not pdu:
        return {"kind": "empty"}
    for fn in (parse_kdc_req_shape, parse_error_shape, parse_rep_shape):
        got = fn(pdu)
        if got is not None:
            return got
    return {"kind": "other", "tag": pdu[0], "len": len(pdu)}


def load_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def reqs_only(rows: list[dict], msg_type: int | None = None) -> list[dict]:
    out = [r for r in rows if r.get("kind") == "req"]
    if msg_type is None:
        return out
    return [r for r in out if r.get("msg_type") == msg_type]


# kinit -R is a TGS RENEW; kvno* are TGS. Everything else is AS.
_TGS_FLOWS = frozenset({"renew", "kvno_plain", "kvno_s4u", "kvno_u2u"})


def expected_msg(flow: str) -> int:
    return 12 if flow in _TGS_FLOWS else 10


def compare_flows(mit: list[dict], rust: list[dict], flow: str) -> int:
    """Print field-by-field compare. Return 0 if CORE matches; 1 otherwise."""
    want = expected_msg(flow)
    mreq = reqs_only(mit, want)
    rreq = reqs_only(rust, want)
    mall = reqs_only(mit)
    rall = reqs_only(rust)
    if len(mall) != len(mreq) or len(rall) != len(rreq):
        print(
            f"FLOW_{flow} extra_reqs mit_all={len(mall)} rust_all={len(rall)} "
            f"compared_msg={want}"
        )
    print(f"FLOW_{flow} mit_reqs={len(mreq)} rust_reqs={len(rreq)}")
    if not mreq:
        print(f"FLOW_{flow} missing MIT request capture")
        raise SystemExit(1)
    if not rreq:
        print(f"FLOW_{flow} missing Rust request capture")
        raise SystemExit(1)
    n = min(len(mreq), len(rreq))
    if len(mreq) != len(rreq):
        print(f"FLOW_{flow}_req_count_differ mit={len(mreq)} rust={len(rreq)}")
    core_fail = 0
    deviations: list[str] = []
    for i in range(n):
        a, b = mreq[i], rreq[i]
        print(f"FLOW_{flow} req#{i + 1}")
        print(f"  MIT  {json.dumps(a, sort_keys=True)}")
        print(f"  RUST {json.dumps(b, sort_keys=True)}")
        for field in CORE_FIELDS:
            av, bv = a.get(field), b.get(field)
            if av != bv:
                print(f"  CORE_DIFF {field} mit={av!r} rust={bv!r}")
                core_fail += 1
            else:
                print(f"  CORE_MATCH {field}={av!r}")
        for field in SHAPE_FIELDS:
            av, bv = a.get(field), b.get(field)
            if av != bv:
                print(f"  SHAPE_DIFF {field} mit={av!r} rust={bv!r}")
                deviations.append(f"{flow}#{i + 1}.{field}")
            else:
                print(f"  SHAPE_MATCH {field}={av!r}")
    mer = [r for r in mit if r.get("kind") == "error"]
    rer = [r for r in rust if r.get("kind") == "error"]
    if mer or rer:
        print(f"FLOW_{flow} errors mit={len(mer)} rust={len(rer)}")
        if mer and rer:
            for field in ("error_code", "e_data_encoding", "e_data_types"):
                av, bv = mer[0].get(field), rer[0].get(field)
                if av != bv:
                    print(f"  SHAPE_DIFF error.{field} mit={av!r} rust={bv!r}")
                    deviations.append(f"{flow}.error.{field}")
                else:
                    print(f"  SHAPE_MATCH error.{field}={av!r}")
    if deviations:
        print(f"FLOW_{flow}_differ {','.join(deviations)}")
    else:
        print(f"FLOW_{flow}_equal")
    if core_fail:
        print(f"FLOW_{flow} CORE failures={core_fail}")
        raise SystemExit(1)
    return 0


def _emit(path: str | None, obj: dict) -> None:
    line = json.dumps(obj, sort_keys=True)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def _read_tcp_pdu(sock: socket.socket) -> bytes | None:
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    (n,) = struct.unpack("!I", hdr)
    if n == 0 or n > 1024 * 1024:
        return None
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _write_tcp_pdu(sock: socket.socket, pdu: bytes) -> None:
    sock.sendall(struct.pack("!I", len(pdu)) + pdu)


def _forward_udp(
    data: bytes, addr: tuple, kdc: tuple, srv: socket.socket, out: str | None, n: int
) -> None:
    shape = classify(data)
    shape["n"] = n
    shape["transport"] = "udp"
    _emit(out, shape)
    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd.settimeout(5.0)
    try:
        fwd.sendto(data, kdc)
        try:
            reply, _ = fwd.recvfrom(65535)
        except TimeoutError:
            _emit(out, {"kind": "timeout", "n": n, "transport": "udp"})
            return
        rshape = classify(reply)
        rshape["n"] = n
        rshape["transport"] = "udp"
        _emit(out, rshape)
        srv.sendto(reply, addr)
    finally:
        fwd.close()


def _forward_tcp(conn: socket.socket, kdc: tuple, out: str | None, n: int) -> None:
    try:
        data = _read_tcp_pdu(conn)
        if data is None:
            return
        shape = classify(data)
        shape["n"] = n
        shape["transport"] = "tcp"
        _emit(out, shape)
        fwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fwd.settimeout(8.0)
        try:
            fwd.connect(kdc)
            _write_tcp_pdu(fwd, data)
            reply = _read_tcp_pdu(fwd)
        except OSError:
            _emit(out, {"kind": "timeout", "n": n, "transport": "tcp"})
            return
        finally:
            fwd.close()
        if reply is None:
            _emit(out, {"kind": "timeout", "n": n, "transport": "tcp"})
            return
        rshape = classify(reply)
        rshape["n"] = n
        rshape["transport"] = "tcp"
        _emit(out, rshape)
        _write_tcp_pdu(conn, reply)
    finally:
        conn.close()


def serve(listen: int, kdc: tuple[str, int], out: str | None) -> int:
    if out:
        with open(out, "w", encoding="utf-8"):
            pass
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(("127.0.0.1", listen))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", listen))
    tcp.listen(8)
    n = 0
    lock = threading.Lock()
    try:
        while True:
            ready, _, _ = select.select([udp, tcp], [], [], 30.0)
            for s in ready:
                if s is udp:
                    data, addr = udp.recvfrom(65535)
                    with lock:
                        n += 1
                        cur = n
                    _forward_udp(data, addr, kdc, udp, out, cur)
                else:
                    conn, _ = tcp.accept()
                    with lock:
                        n += 1
                        cur = n
                    threading.Thread(
                        target=_forward_tcp, args=(conn, kdc, out, cur), daemon=True
                    ).start()
    finally:
        udp.close()
        tcp.close()


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def _tlv_enc(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(val)) + val


def _int_enc(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 8) // 8
    return n.to_bytes(length, "big")


def _self_test() -> int:
    opts = _tlv_enc(0x03, bytes([0, 0x50, 0x00, 0x00, 0x10]))
    cname = _tlv_enc(
        0x30,
        _tlv_enc(0xA0, _tlv_enc(0x02, _int_enc(1)))
        + _tlv_enc(0xA1, _tlv_enc(0x30, _tlv_enc(0x1B, b"user"))),
    )
    realm = b"KERBER.TEST"
    sname = _tlv_enc(
        0x30,
        _tlv_enc(0xA0, _tlv_enc(0x02, _int_enc(2)))
        + _tlv_enc(
            0xA1,
            _tlv_enc(
                0x30,
                _tlv_enc(0x1B, b"krbtgt") + _tlv_enc(0x1B, b"KERBER.TEST"),
            ),
        ),
    )
    body = (
        _tlv_enc(0xA0, opts)
        + _tlv_enc(0xA1, cname)
        + _tlv_enc(0xA2, _tlv_enc(0x1B, realm))
        + _tlv_enc(0xA3, sname)
        + _tlv_enc(0xA5, _tlv_enc(0x18, b"20260101120000Z"))
        + _tlv_enc(0xA7, _tlv_enc(0x02, _int_enc(1)))
        + _tlv_enc(0xA8, _tlv_enc(0x30, _tlv_enc(0x02, _int_enc(18))))
    )
    seq = (
        _tlv_enc(0xA1, _tlv_enc(0x02, _int_enc(5)))
        + _tlv_enc(0xA2, _tlv_enc(0x02, _int_enc(10)))
        + _tlv_enc(0xA4, _tlv_enc(0x30, body))
    )
    pdu = _tlv_enc(0x6A, _tlv_enc(0x30, seq))
    shape = parse_kdc_req_shape(pdu)
    assert shape is not None, "parse failed"
    assert shape["msg_type"] == 10, shape
    assert shape["sname"] == "krbtgt/KERBER.TEST", shape
    assert shape["sname_nt"] == 2, shape
    assert shape["cname"] == "user", shape
    assert shape["cname_nt"] == 1, shape
    assert shape["nonce"] is True, shape
    assert shape["etypes"] == [18], shape
    assert shape["etype_nonempty"] is True, shape
    assert shape["till"] == "present", shape
    assert "forwardable" in shape["kdc_options"], shape
    assert "renewable_ok" in shape["kdc_options"], shape
    mit = [shape]
    rust = [dict(shape)]
    compare_flows(mit, rust, "self")
    rust_bad = [dict(shape, sname="host/x (nt=1)")]
    try:
        compare_flows(mit, rust_bad, "self-bad")
    except SystemExit as e:
        assert e.code == 1
    else:
        raise AssertionError("CORE sname mismatch must fail")
    print("self-test ok")
    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        return _self_test()
    if len(sys.argv) >= 2 and sys.argv[1] == "--compare":
        if len(sys.argv) < 5:
            print("usage: kdc-req-proxy.py --compare mit.jsonl rust.jsonl flow", file=sys.stderr)
            return 2
        mit = load_jsonl(sys.argv[2])
        rust = load_jsonl(sys.argv[3])
        return compare_flows(mit, rust, sys.argv[4])
    if len(sys.argv) < 4:
        print(
            "usage: kdc-req-proxy.py listen-port kdc-host kdc-port [out.jsonl]",
            file=sys.stderr,
        )
        return 2
    listen = int(sys.argv[1])
    kdc = (sys.argv[2], int(sys.argv[3]))
    out = sys.argv[4] if len(sys.argv) > 4 else None
    return serve(listen, kdc, out)


if __name__ == "__main__":
    raise SystemExit(main())
