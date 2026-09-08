#!/usr/bin/env python3
"""UDP proxy that prints KRB-ERROR error-code, e-text, and e_data types.

usage: kdc-error-proxy.py <listen-port> <kdc-host> <kdc-port> [out-file]
"""
from __future__ import annotations

import socket
import sys


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


def _skip_value(buf: bytes, i: int) -> int:
    if i >= len(buf):
        raise ValueError("eof")
    tag = buf[i]
    i += 1
    if tag & 0x1F == 0x1F:
        while i < len(buf) and buf[i] & 0x80:
            i += 1
        i += 1
    ln, i = _read_len(buf, i)
    return i + ln


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
    n = 0
    for b in val:
        n = (n << 8) | b
    if val and val[0] & 0x80:
        n -= 1 << (8 * len(val))
    return n


def _unwrap(val: bytes, constructed: bool) -> bytes:
    if constructed and val:
        _, inner, _ = _tlv(val, 0)
        return inner
    return val


def parse_edata_types(edata: bytes) -> tuple[str, list[int]]:
    """Return (encoding, types) for METHOD-DATA [1]/[2] or TYPED-DATA [0]/[1]."""
    if not edata or edata[0] != 0x30:
        return "none", []
    _, seq, _ = _tlv(edata, 0)
    if not seq:
        return "empty", []
    types: list[int] = []
    enc = "unknown"
    i = 0
    while i < len(seq):
        _, pa, i = _tlv(seq, i)
        j = 0
        t = None
        while j < len(pa):
            ptag, pval, j = _tlv(pa, j)
            inner = _unwrap(pval, bool(ptag & 0x20))
            num = ptag & 0x1F
            if ptag & 0xC0 != 0x80:
                continue
            if num == 0:
                enc = "typed"
                t = _int(inner)
            elif num == 1 and enc != "typed":
                enc = "method"
                t = _int(inner)
        types.append(t if t is not None else -1)
    return enc, types


def parse_krb_error(pdu: bytes) -> tuple[int | None, str | None, str, list[int]]:
    if not pdu or pdu[0] != 0x7E:
        return None, None, "none", []
    ln, i = _read_len(pdu, 1)
    end = i + ln
    if end > len(pdu):
        end = len(pdu)
    if i >= end or pdu[i] != 0x30:
        return None, None, "none", []
    sln, i = _read_len(pdu, i + 1)
    seq_end = min(i + sln, end)
    code = None
    etext = None
    edata = None
    while i < seq_end:
        if i >= len(pdu):
            break
        tag = pdu[i]
        if tag & 0xC0 != 0x80:
            i = _skip_value(pdu, i)
            continue
        num = tag & 0x1F
        constructed = tag & 0x20
        i += 1
        vln, i = _read_len(pdu, i)
        val = pdu[i : i + vln]
        i += vln
        if constructed and val:
            inner = 1
            iln, inner = _read_len(val, 1)
            val = val[inner : inner + iln]
        if num == 6:
            code = _int(val)
        elif num == 11:
            try:
                etext = val.decode("ascii")
            except UnicodeDecodeError:
                etext = val.decode("latin-1", "replace")
        elif num == 12:
            edata = val
    enc, types = parse_edata_types(edata) if edata else ("none", [])
    return code, etext, enc, types


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: kdc-error-proxy.py listen-port kdc-host kdc-port [out]", file=sys.stderr)
        return 2
    listen = int(sys.argv[1])
    kdc_host = sys.argv[2]
    kdc_port = int(sys.argv[3])
    out_path = sys.argv[4] if len(sys.argv) > 4 else None
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen))
    srv.settimeout(30.0)
    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd.settimeout(5.0)
    if out_path:
        with open(out_path, "w", encoding="ascii"):
            pass
    while True:
        try:
            data, addr = srv.recvfrom(65535)
        except socket.timeout:
            continue
        fwd.sendto(data, (kdc_host, kdc_port))
        try:
            reply, _ = fwd.recvfrom(65535)
        except socket.timeout:
            continue
        if reply[:1] == b"\x7e":
            code, etext, enc, types = parse_krb_error(reply)
            line = (
                f"error_code={code}\ne_text={etext}\n"
                f"e_data_encoding={enc}\ne_data_types={types}\n"
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            if out_path:
                with open(out_path, "a", encoding="ascii") as f:
                    f.write(line)
        srv.sendto(reply, addr)


if __name__ == "__main__":
    raise SystemExit(main())
