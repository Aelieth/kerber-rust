#!/usr/bin/env python3
"""UDP/TCP man-in-the-middle in front of a KDC that rewrites replies.

usage:
  kdc-rewrite-proxy.py <listen-port> <kdc-host> <kdc-port> <out-file> <mode> [arg]
  kdc-rewrite-proxy.py --self-test

modes:
  none                  forward untouched (request counting only)
  as-rep-cname <name>   every AS-REP (0x6b): the outer cname [4] becomes the
                        one-component NT-PRINCIPAL <name> — the FAST finished
                        client must win (fast.c:548-558)
  strip-fx-fast         every KRB-ERROR (0x7e): PA-FX-FAST (136) is removed
                        from the e_data padata sequence (an emptied sequence
                        stays as `30 00`) — the outer error must be fatal
                        (fast.c:445-458)

Every forwarded request appends `req#<n> transport=<udp|tcp> msg_type=<10|12>`
to <out-file>; every reply appends `rep#<n> kind=<as-rep|tgs-rep|error|other>
[error_code=<c>] rewritten=<yes|no>`. A KDC timeout is `rep#<n> timeout`.
The gate counts `req#` lines to prove a client sent no second request.
"""
from __future__ import annotations

import select
import socket
import struct
import sys
import threading

PA_FX_FAST = 136


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
    """(tag, value, next-index) of the TLV at `i` (single-byte tags only)."""
    tag = buf[i]
    i += 1
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tag")
    ln, i = _read_len(buf, i)
    if i + ln > len(buf):
        raise ValueError("der overrun")
    return tag, buf[i : i + ln], i + ln


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def _enc(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(val)) + val


def _int(val: bytes) -> int:
    n = 0
    for b in val:
        n = (n << 8) | b
    if val and val[0] & 0x80:
        n -= 1 << (8 * len(val))
    return n


def _int_enc(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 8) // 8
    return n.to_bytes(length, "big", signed=True)


def _fields(seq: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i < len(seq):
        tag, val, i = _tlv(seq, i)
        out.append((tag, val))
    return out


def _rebuild(app_tag: int, fields: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(_enc(t, v) for t, v in fields)
    return _enc(app_tag, _enc(0x30, body))


def principal_name(name: str) -> bytes:
    """PrincipalName { name-type [0] NT-PRINCIPAL(1), name-string [1] { name } }."""
    comps = _enc(0x30, _enc(0x1B, name.encode("ascii")))
    return _enc(0x30, _enc(0xA0, _enc(0x02, _int_enc(1))) + _enc(0xA1, comps))


def rewrite_as_rep_cname(pdu: bytes, name: str) -> tuple[bytes, bool]:
    """Replace the outer cname [4] of an AS-REP; anything else passes through."""
    if not pdu or pdu[0] != 0x6B:
        return pdu, False
    _, seq, _ = _tlv(pdu, 0)
    _, body, _ = _tlv(seq, 0)
    fields = _fields(body)
    out = []
    hit = False
    for tag, val in fields:
        if tag == 0xA4:
            out.append((0xA4, principal_name(name)))
            hit = True
        else:
            out.append((tag, val))
    return (_rebuild(0x6B, out), True) if hit else (pdu, False)


def _padata_type(pa: bytes) -> int | None:
    i = 0
    while i < len(pa):
        tag, val, i = _tlv(pa, i)
        if tag == 0xA1:
            _, t, _ = _tlv(val, 0)
            return _int(t)
    return None


def strip_fx_fast(pdu: bytes) -> tuple[bytes, bool]:
    """Drop PA-FX-FAST from a KRB-ERROR's e_data padata sequence."""
    if not pdu or pdu[0] != 0x7E:
        return pdu, False
    _, seq, _ = _tlv(pdu, 0)
    _, body, _ = _tlv(seq, 0)
    fields = _fields(body)
    out = []
    hit = False
    for tag, val in fields:
        if tag != 0xAC:
            out.append((tag, val))
            continue
        _, edata, _ = _tlv(val, 0)  # OCTET STRING
        if not edata or edata[0] != 0x30:
            out.append((tag, val))
            continue
        _, pas, _ = _tlv(edata, 0)
        kept = []
        j = 0
        while j < len(pas):
            ptag, pa, j = _tlv(pas, j)
            if _padata_type(pa) == PA_FX_FAST:
                hit = True
                continue
            kept.append(_enc(ptag, pa))
        out.append((0xAC, _enc(0x04, _enc(0x30, b"".join(kept)))))
    return (_rebuild(0x7E, out), True) if hit else (pdu, False)


def error_code(pdu: bytes) -> int | None:
    if not pdu or pdu[0] != 0x7E:
        return None
    _, seq, _ = _tlv(pdu, 0)
    _, body, _ = _tlv(seq, 0)
    for tag, val in _fields(body):
        if tag == 0xA6:
            _, c, _ = _tlv(val, 0)
            return _int(c)
    return None


def req_msg_type(pdu: bytes) -> int | None:
    if not pdu or pdu[0] not in (0x6A, 0x6C):
        return None
    _, seq, _ = _tlv(pdu, 0)
    _, body, _ = _tlv(seq, 0)
    for tag, val in _fields(body):
        if tag == 0xA2:
            _, t, _ = _tlv(val, 0)
            return _int(t)
    return None


class Rewriter:
    def __init__(self, mode: str, arg: str | None) -> None:
        if mode not in ("none", "as-rep-cname", "strip-fx-fast"):
            raise SystemExit(f"unknown mode {mode}")
        if mode == "as-rep-cname" and not arg:
            raise SystemExit("as-rep-cname needs a name")
        self.mode = mode
        self.arg = arg

    def apply(self, reply: bytes) -> tuple[bytes, bool]:
        try:
            if self.mode == "as-rep-cname":
                return rewrite_as_rep_cname(reply, self.arg or "")
            if self.mode == "strip-fx-fast":
                return strip_fx_fast(reply)
        except (ValueError, IndexError):
            return reply, False
        return reply, False


def _kind(reply: bytes) -> str:
    if not reply:
        return "empty"
    return {0x6B: "as-rep", 0x6D: "tgs-rep", 0x7E: "error"}.get(reply[0], "other")


class Log:
    def __init__(self, path: str) -> None:
        self.path = path
        self.lock = threading.Lock()
        with open(path, "w", encoding="ascii"):
            pass

    def line(self, s: str) -> None:
        with self.lock:
            sys.stdout.write(s + "\n")
            sys.stdout.flush()
            with open(self.path, "a", encoding="ascii") as f:
                f.write(s + "\n")


def _describe_reply(n: int, reply: bytes, rewritten: bool) -> str:
    kind = _kind(reply)
    extra = ""
    if kind == "error":
        try:
            extra = f" error_code={error_code(reply)}"
        except (ValueError, IndexError):
            extra = " error_code=?"
    return f"rep#{n} kind={kind}{extra} rewritten={'yes' if rewritten else 'no'}"


def _handle(data: bytes, kdc: tuple, rw: Rewriter, log: Log, n: int, transport: str) -> bytes | None:
    try:
        mt = req_msg_type(data)
    except (ValueError, IndexError):
        mt = None
    log.line(f"req#{n} transport={transport} msg_type={mt}")
    if transport == "udp":
        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd.settimeout(5.0)
        try:
            fwd.sendto(data, kdc)
            try:
                reply, _ = fwd.recvfrom(65535)
            except (TimeoutError, socket.timeout):
                log.line(f"rep#{n} timeout")
                return None
        finally:
            fwd.close()
    else:
        fwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fwd.settimeout(8.0)
        try:
            fwd.connect(kdc)
            _write_tcp_pdu(fwd, data)
            reply = _read_tcp_pdu(fwd)
        except OSError:
            reply = None
        finally:
            fwd.close()
        if reply is None:
            log.line(f"rep#{n} timeout")
            return None
    reply, rewritten = rw.apply(reply)
    log.line(_describe_reply(n, reply, rewritten))
    return reply


def _read_tcp_pdu(sock: socket.socket) -> bytes | None:
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    (ln,) = struct.unpack("!I", hdr)
    if ln == 0 or ln > 1024 * 1024:
        return None
    buf = b""
    while len(buf) < ln:
        chunk = sock.recv(ln - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _write_tcp_pdu(sock: socket.socket, pdu: bytes) -> None:
    sock.sendall(struct.pack("!I", len(pdu)) + pdu)


def _tcp_conn(conn: socket.socket, kdc: tuple, rw: Rewriter, log: Log, n: int) -> None:
    try:
        conn.settimeout(10.0)
        data = _read_tcp_pdu(conn)
        if data is None:
            return
        reply = _handle(data, kdc, rw, log, n, "tcp")
        if reply is not None:
            _write_tcp_pdu(conn, reply)
    except OSError:
        pass
    finally:
        conn.close()


def serve(listen: int, kdc: tuple[str, int], log: Log, rw: Rewriter) -> int:
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
                    reply = _handle(data, kdc, rw, log, cur, "udp")
                    if reply is not None:
                        udp.sendto(reply, addr)
                else:
                    conn, _ = tcp.accept()
                    with lock:
                        n += 1
                        cur = n
                    threading.Thread(
                        target=_tcp_conn, args=(conn, kdc, rw, log, cur), daemon=True
                    ).start()
    finally:
        udp.close()
        tcp.close()


def _self_test() -> int:
    # A minimal AS-REP: pvno, msg-type, crealm, cname, ticket (opaque), enc-part (opaque).
    cname = principal_name("user")
    fields = [
        (0xA0, _enc(0x02, _int_enc(5))),
        (0xA1, _enc(0x02, _int_enc(11))),
        (0xA3, _enc(0x1B, b"KERBER.TEST")),
        (0xA4, cname),
        (0xA5, _enc(0x61, _enc(0x30, b""))),
        (0xA6, _enc(0x30, b"")),
    ]
    rep = _rebuild(0x6B, fields)
    out, hit = rewrite_as_rep_cname(rep, "mitm")
    assert hit, "cname not rewritten"
    _, seq, _ = _tlv(out, 0)
    _, body, _ = _tlv(seq, 0)
    got = dict(_fields(body))
    assert got[0xA4] == principal_name("mitm"), "cname value"
    assert got[0xA3] == _enc(0x1B, b"KERBER.TEST"), "crealm kept"
    assert len(got) == 6, "field count"
    # A KRB-ERROR whose e_data is [PA-FX-FAST, PA-FX-COOKIE].
    def pa(t: int, v: bytes) -> bytes:
        return _enc(0x30, _enc(0xA1, _enc(0x02, _int_enc(t))) + _enc(0xA2, _enc(0x04, v)))

    edata = _enc(0x30, pa(PA_FX_FAST, b"\x01\x02") + pa(133, b"cookie"))
    efields = [
        (0xA0, _enc(0x02, _int_enc(5))),
        (0xA1, _enc(0x02, _int_enc(30))),
        (0xA6, _enc(0x02, _int_enc(25))),
        (0xAC, _enc(0x04, edata)),
    ]
    err = _rebuild(0x7E, efields)
    out, hit = strip_fx_fast(err)
    assert hit, "fx-fast not stripped"
    assert error_code(out) == 25
    _, seq, _ = _tlv(out, 0)
    _, body, _ = _tlv(seq, 0)
    got = dict(_fields(body))
    _, inner, _ = _tlv(got[0xAC], 0)
    _, pas, _ = _tlv(inner, 0)
    types = []
    j = 0
    while j < len(pas):
        _, p, j = _tlv(pas, j)
        types.append(_padata_type(p))
    assert types == [133], types
    # Only PA-FX-FAST → an empty sequence, e_data still present.
    err2 = _rebuild(0x7E, efields[:3] + [(0xAC, _enc(0x04, _enc(0x30, pa(PA_FX_FAST, b"x"))))])
    out2, hit2 = strip_fx_fast(err2)
    assert hit2
    _, seq, _ = _tlv(out2, 0)
    _, body, _ = _tlv(seq, 0)
    got = dict(_fields(body))
    assert got[0xAC] == _enc(0x04, _enc(0x30, b"")), got[0xAC].hex()
    # Pass-through: a TGS-REP and an error without e_data are untouched.
    assert rewrite_as_rep_cname(_rebuild(0x6D, fields), "mitm") == (_rebuild(0x6D, fields), False)
    assert strip_fx_fast(_rebuild(0x7E, efields[:3])) == (_rebuild(0x7E, efields[:3]), False)
    print("kdc-rewrite-proxy self-test ok")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return _self_test()
    if len(sys.argv) < 6:
        print(__doc__, file=sys.stderr)
        return 2
    listen = int(sys.argv[1])
    kdc = (sys.argv[2], int(sys.argv[3]))
    log = Log(sys.argv[4])
    rw = Rewriter(sys.argv[5], sys.argv[6] if len(sys.argv) > 6 else None)
    return serve(listen, kdc, log, rw)


if __name__ == "__main__":
    sys.exit(main())
