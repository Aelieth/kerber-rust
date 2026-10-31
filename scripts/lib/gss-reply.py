#!/usr/bin/env python3
"""Send a GSS token to an acceptor (4-byte length prefix) and print its reply in one line.

usage: gss-reply.py <port> <token-file>

reply=none, or reply=krb5 tokid=XXXX [code= realm= sname= fields=] for a KRB-ERROR token, or
reply=spnego negstate=N mech=yes|no response=<the same for its mech token, or none>.
"""
import socket
import struct
import sys


def tlv(b, i):
    tag = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return tag, b[i:i + n], i + n


def fields(seq):
    out, i = {}, 0
    while i < len(seq):
        tag, val, i = tlv(seq, i)
        out[tag - 0xA0] = val
    return out


def krb5_token(tok):
    _, body, _ = tlv(tok, 0)
    _, _, i = tlv(body, 0)
    tokid = body[i:i + 2].hex()
    if tokid != "0300":
        return f"tokid={tokid}"
    _, err, _ = tlv(body[i + 2:], 0)
    _, seq, _ = tlv(err, 0)
    f = fields(seq)
    code = int.from_bytes(tlv(f[6], 0)[1], "big", signed=True)
    realm = tlv(f[9], 0)[1].decode()
    names = fields(tlv(f[10], 0)[1])[1]
    _, comps, j, parts = None, tlv(names, 0)[1], 0, []
    while j < len(comps):
        _, c, j = tlv(comps, j)
        parts.append(c.decode())
    present = ",".join(str(k) for k in sorted(f))
    return f"tokid=0300 code={code} realm={realm} sname={'/'.join(parts)} fields={present}"


def describe(tok):
    if not tok:
        return "reply=none"
    if tok[0] == 0x60:
        return "reply=krb5 " + krb5_token(tok)
    if tok[0] == 0xA1:
        _, inner, _ = tlv(tok, 0)
        f = fields(tlv(inner, 0)[1])
        state = int.from_bytes(tlv(f[0], 0)[1], "big") if 0 in f else -1
        resp = describe(tlv(f[2], 0)[1]) if 2 in f else "reply=none"
        mech = "yes" if 1 in f else "no"
        return f"reply=spnego negstate={state} mech={mech} response=({resp})"
    return f"reply=other first={tok[0]:02x}"


def main():
    port, path = int(sys.argv[1]), sys.argv[2]
    tok = open(path, "rb").read()
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    s.sendall(struct.pack(">I", len(tok)) + tok)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) >= 4 and len(data) >= 4 + struct.unpack(">I", data[:4])[0]:
                break
    except OSError:
        pass
    s.close()
    reply = data[4:4 + struct.unpack(">I", data[:4])[0]] if len(data) >= 4 else b""
    print(describe(reply))


main()
