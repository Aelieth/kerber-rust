#!/usr/bin/env python3
"""UDP proxy that prints the padata type list of every KDC-REQ it forwards.

usage: kdc-padata-proxy.py <listen-port> <kdc-host> <kdc-port> [out-file]

Each request line is `req#<n> msg_type=<10|12> padata=[<type>, ...]` in wire
order (an absent padata field prints `padata=[]`).
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


def _tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, value, next-index) for the TLV at `i`."""
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


def parse_kdc_req(pdu: bytes) -> tuple[int | None, list[int]]:
    """(msg-type, [padata-type…]) of an AS-REQ (0x6a) or TGS-REQ (0x6c)."""
    if not pdu or pdu[0] not in (0x6A, 0x6C):
        return None, []
    _, seq, _ = _tlv(pdu, 0)
    _, body, _ = _tlv(seq, 0)
    msg_type = None
    types: list[int] = []
    i = 0
    while i < len(body):
        tag, val, i = _tlv(body, i)
        if tag & 0xC0 != 0x80:
            continue
        num = tag & 0x1F
        _, inner, _ = _tlv(val, 0)
        if num == 2:
            msg_type = _int(inner)
        elif num == 3:
            j = 0
            while j < len(inner):
                _, pa, j = _tlv(inner, j)
                k = 0
                while k < len(pa):
                    ptag, pval, k = _tlv(pa, k)
                    if ptag == 0xA1:
                        _, pt, _ = _tlv(pval, 0)
                        types.append(_int(pt))
    return msg_type, types


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: kdc-padata-proxy.py listen-port kdc-host kdc-port [out]", file=sys.stderr)
        return 2
    listen = int(sys.argv[1])
    kdc = (sys.argv[2], int(sys.argv[3]))
    out_path = sys.argv[4] if len(sys.argv) > 4 else None
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen))
    srv.settimeout(30.0)
    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd.settimeout(5.0)
    n = 0
    while True:
        try:
            data, addr = srv.recvfrom(65535)
        except socket.timeout:
            continue
        n += 1
        msg_type, types = parse_kdc_req(data)
        line = f"req#{n} msg_type={msg_type} padata={types}\n"
        sys.stdout.write(line)
        sys.stdout.flush()
        if out_path:
            with open(out_path, "a", encoding="ascii") as f:
                f.write(line)
        fwd.sendto(data, kdc)
        try:
            reply, _ = fwd.recvfrom(65535)
        except socket.timeout:
            continue
        srv.sendto(reply, addr)


if __name__ == "__main__":
    raise SystemExit(main())
