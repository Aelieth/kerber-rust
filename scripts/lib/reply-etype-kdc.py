#!/usr/bin/env python3
"""A UDP KDC: `PORT ENC_ETYPE [INFO_ETYPE]`, `PORT s2k ITER` or `PORT nonce`.

The first answers any request with an AS-REP for user@KERBER.TEST whose enc-part is ENC_ETYPE over
zeros; with INFO_ETYPE its padata is an ETYPE-INFO2 naming only that enctype. The second answers with a
PREAUTH_REQUIRED offering encrypted timestamp, with an ETYPE-INFO2 for aes256 whose s2kparams are ITER.
The third prints each AS-REQ's nonce and padata types, and answers PREAUTH_REQUIRED (ITER 4096), or
PREAUTH_FAILED to a request carrying an encrypted timestamp.
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


def krb_error(code, edata=None):
    realm = "KERBER.TEST"
    now = tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime()).encode())
    extra = ctx(12, tlv(0x04, edata)) if edata is not None else b""
    return tlv(0x7E, seq(ctx(0, integer(5)), ctx(1, integer(30)), ctx(4, now), ctx(5, integer(0)),
                         ctx(6, integer(code)), ctx(9, gstr(realm)), ctx(10, princ(2, "krbtgt", realm)),
                         extra))


def preauth_required(iterations):
    info = seq(seq(ctx(0, integer(18)), ctx(1, gstr("KERBER.TESTuser")),
                   ctx(2, tlv(0x04, iterations.to_bytes(4, "big")))))
    method = seq(seq(ctx(1, integer(2)), ctx(2, tlv(0x04, b""))),
                 seq(ctx(1, integer(19)), ctx(2, tlv(0x04, info))))
    return krb_error(25, method)


def read_tlv(b, i):
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return tag, b[i:i + n], i + n


def fields(body):
    out, i = {}, 0
    while i < len(body):
        tag, val, i = read_tlv(body, i)
        out[tag] = val
    return out


def as_req_nonce(req):
    f = fields(read_tlv(read_tlv(req, 0)[1], 0)[1])
    types, pas, i = [], read_tlv(f.get(0xA3, b"\x30\x00"), 0)[1], 0
    while i < len(pas):
        _, pa, i = read_tlv(pas, i)
        types.append(int.from_bytes(read_tlv(fields(pa)[0xA1], 0)[1], "big", signed=True))
    body = fields(read_tlv(f[0xA4], 0)[1])
    return int.from_bytes(read_tlv(body[0xA7], 0)[1], "big"), types


def main():
    if sys.argv[2] == "s2k":
        def make(_):
            return preauth_required(int(sys.argv[3]))
    elif sys.argv[2] == "nonce":
        def make(req):
            nonce, types = as_req_nonce(req)
            print("nonce", nonce, "padata", types, flush=True)
            return krb_error(24) if 2 in types else preauth_required(4096)
    else:
        reply = as_rep(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else None)

        def make(_):
            return reply
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", int(sys.argv[1])))
    print("listening", sys.argv[1], flush=True)
    while True:
        req, peer = s.recvfrom(65536)
        s.sendto(make(req), peer)


main()
