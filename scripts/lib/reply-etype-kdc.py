#!/usr/bin/env python3
"""A UDP KDC that answers any request with one reply: `PORT ENC_ETYPE [INFO_ETYPE]` or `PORT s2k ITER`.

The first is an AS-REP for user@KERBER.TEST whose enc-part is ENC_ETYPE over zeros; with INFO_ETYPE its
padata is an ETYPE-INFO2 naming only that enctype. The second is a PREAUTH_REQUIRED offering encrypted
timestamp, with an ETYPE-INFO2 for aes256 whose s2kparams are ITER.
"""
import socket
import sys
import time


def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    elif n < 0x100:
        head = bytes([0x81, n])
    else:
        head = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + head + body


def ctx(n, body):
    return tlv(0xA0 | n, body)


def seq(*items):
    return tlv(0x30, b"".join(items))


def integer(v):
    return tlv(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big", signed=True))


def gstr(s):
    return tlv(0x1B, s.encode())


def princ(kind, *names):
    return seq(ctx(0, integer(kind)), ctx(1, seq(*(gstr(n) for n in names))))


def enc_data(etype, kvno=None):
    kv = ctx(1, integer(kvno)) if kvno is not None else b""
    return seq(ctx(0, integer(etype)), kv, ctx(2, tlv(0x04, bytes(64))))


def as_rep(enc_etype, info_etype):
    realm = "KERBER.TEST"
    ticket = tlv(0x61, seq(ctx(0, integer(5)), ctx(1, gstr(realm)),
                           ctx(2, princ(2, "krbtgt", realm)), ctx(3, enc_data(18, 1))))
    padata = b""
    if info_etype is not None:
        info = seq(seq(ctx(0, integer(info_etype))))
        padata = ctx(2, seq(seq(ctx(1, integer(19)), ctx(2, tlv(0x04, info)))))
    return tlv(0x6B, seq(ctx(0, integer(5)), ctx(1, integer(11)), padata, ctx(3, gstr(realm)),
                         ctx(4, princ(1, "user")), ctx(5, ticket), ctx(6, enc_data(enc_etype))))


def preauth_required(iterations):
    realm = "KERBER.TEST"
    info = seq(seq(ctx(0, integer(18)), ctx(1, gstr(realm + "user")),
                   ctx(2, tlv(0x04, iterations.to_bytes(4, "big")))))
    method = seq(seq(ctx(1, integer(2)), ctx(2, tlv(0x04, b""))),
                 seq(ctx(1, integer(19)), ctx(2, tlv(0x04, info))))
    now = tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime()).encode())
    return tlv(0x7E, seq(ctx(0, integer(5)), ctx(1, integer(30)), ctx(4, now), ctx(5, integer(0)),
                         ctx(6, integer(25)), ctx(9, gstr(realm)), ctx(10, princ(2, "krbtgt", realm)),
                         ctx(12, tlv(0x04, method))))


def main():
    if sys.argv[2] == "s2k":
        def make():
            return preauth_required(int(sys.argv[3]))
    else:
        reply = as_rep(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else None)

        def make():
            return reply
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", int(sys.argv[1])))
    print("listening", sys.argv[1], flush=True)
    while True:
        _, peer = s.recvfrom(65536)
        s.sendto(make(), peer)


main()
