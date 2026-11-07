#!/usr/bin/env python3
"""kdc-hostile.py <cell> <host> <realm> <client>: one hostile input at the KDC's listener (port 88), the same bytes on
both legs; prints one outcome line. MIT 1.22.2's answers (lib/apputils/net-server.c, kdc/dispatch.c) are the oracle.

  K1a  TCP length one past the 1 MiB - 4 cap      K1b  TCP length 0x7fffffff
  K2   TCP length with RFC 4120 7.2.2's high bit  K3   46 idle TCP connections, then a request on a 47th
  K4a  64 fixed pseudo-random bytes over UDP      K4b  an AS-REQ cut short, over UDP
  K5a  an AS-REQ with 20000 PA-DATA, over TCP     K5b  an AS-REQ whose body claims more than the frame holds
                                                     (its length octet is short-form, as alice's 115-byte body)
Outcome: `reply krb-error N` (the KRB-ERROR's error-code), `reply other`, `silence` (no reply in 3 s), `close` (the
stream ended with no reply) or `reset`, then for TCP `; then close`, `; then open` or `; then reset` after a reply;
`unreachable` when no connection or datagram could be made.
"""
import random
import socket
import struct
import sys

PORT = 88
CAP = 1024 * 1024 - 4


def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + head + body


def ctx(n, body):
    return tlv(0xA0 | n, body)


def integer(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def gstring(s):
    return tlv(0x1B, s.encode())


def principal(ntype, parts):
    return tlv(0x30, ctx(0, integer(ntype)) + ctx(1, tlv(0x30, b"".join(gstring(p) for p in parts))))


def as_req(realm, client, padata=()):
    body = tlv(0x30, ctx(0, tlv(0x03, b"\x00\x40\x00\x00\x10"))
               + ctx(1, principal(1, [client])) + ctx(2, gstring(realm))
               + ctx(3, principal(2, ["krbtgt", realm])) + ctx(5, tlv(0x18, b"20370913024805Z"))
               + ctx(7, integer(0x1F2E3D4C)) + ctx(8, tlv(0x30, integer(18) + integer(17))))
    pa = ctx(3, tlv(0x30, b"".join(padata))) if padata else b""
    return tlv(0x6A, tlv(0x30, ctx(1, integer(5)) + ctx(2, integer(10)) + pa + ctx(4, body)))


def error_code(msg):
    """The error-code [6] of a KRB-ERROR ([APPLICATION 30]), or None."""
    def walk(b):
        i, out = 0, []
        while i + 2 <= len(b):
            tag, n, i = b[i], b[i + 1], i + 2
            if n & 0x80:
                k = n & 0x7F
                n, i = int.from_bytes(b[i:i + k], "big"), i + k
            out.append((tag, b[i:i + n]))
            i += n
        return out
    top = walk(msg)
    if not top or top[0][0] != 0x7E:
        return None
    seq = walk(top[0][1])
    for tag, val in walk(seq[0][1]) if seq else []:
        if tag == 0xA6:
            inner = walk(val)
            if inner and inner[0][0] == 0x02:
                return int.from_bytes(inner[0][1], "big", signed=True)
    return None


def describe(reply):
    code = error_code(reply)
    return f"reply krb-error {code}" if code is not None else "reply other"


def tcp(host, payload, after_reply=True):
    """Send payload on a new stream; the outcome, and whether the server closed after its reply."""
    try:
        s = socket.create_connection((host, PORT), timeout=10)
    except OSError:
        return "unreachable"
    try:
        head = b""
        try:
            s.sendall(payload)
            s.settimeout(3)
            while len(head) < 4:
                chunk = s.recv(4 - len(head))
                if not chunk:
                    return "close"
                head += chunk
        except socket.timeout:
            return "silence"
        except OSError:
            return "reset"
        n = struct.unpack(">I", head)[0] & 0x7FFFFFFF
        body = b""
        try:
            while len(body) < n:
                chunk = s.recv(min(65536, n - len(body)))
                if not chunk:
                    break
                body += chunk
        except OSError:
            pass
        out = describe(body)
        if after_reply:
            try:
                out += "; then close" if not s.recv(1) else "; then data"
            except socket.timeout:
                out += "; then open"
            except OSError:
                out += "; then reset"
        return out
    finally:
        s.close()


def udp(host, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(payload, (socket.gethostbyname(host), PORT))
        return describe(s.recvfrom(65536)[0])
    except socket.timeout:
        return "silence"
    except OSError:
        return "unreachable"
    finally:
        s.close()


def framed(msg):
    return struct.pack(">I", len(msg)) + msg


def main():
    if len(sys.argv) != 5:
        print("usage: kdc-hostile.py <cell> <host> <realm> <client>", file=sys.stderr)
        return 2
    cell, host, realm, client = sys.argv[1:]
    if cell == "K1a":
        out = tcp(host, struct.pack(">I", CAP + 1))
    elif cell == "K1b":
        out = tcp(host, struct.pack(">I", 0x7FFFFFFF))
    elif cell == "K2":
        out = tcp(host, struct.pack(">I", 0x80000000))
    elif cell == "K3":
        idle, closed, refused = [], 0, 0
        for i in range(46):
            try:
                c = socket.create_connection((host, PORT), timeout=10)
            except OSError:
                refused += 1
                continue
            idle.append(c)
            if i % 2:
                try:
                    c.sendall(b"\x00")
                except OSError:
                    pass
        out = tcp(host, framed(as_req(realm, client)), after_reply=False)
        for c in idle:
            c.settimeout(0.5)
            try:
                closed += c.recv(1) == b""
            except socket.timeout:
                pass
            except OSError:
                closed += 1
            c.close()
        print(f"K3 idle connections the server closed: {closed}, refused: {refused}", file=sys.stderr)
    elif cell == "K4a":
        out = udp(host, random.Random(4).randbytes(64))
    elif cell == "K4b":
        out = udp(host, as_req(realm, client)[:-9])
    elif cell == "K5a":
        pa = [tlv(0x30, ctx(1, integer(150)) + ctx(2, tlv(0x04, b""))) for _ in range(20000)]
        out = tcp(host, framed(as_req(realm, client, pa)))
    elif cell == "K5b":
        msg = bytearray(as_req(realm, client))
        body = msg.index(b"\x30", msg.index(b"\xa4\x81") + 3 if b"\xa4\x81" in msg else msg.index(b"\xa4") + 2)
        msg[body + 1:body + 2] = b"\x82\x7f\xff"
        out = tcp(host, framed(bytes(msg)))
    else:
        print(f"kdc-hostile.py: unknown cell {cell}", file=sys.stderr)
        return 2
    print(f"{cell}: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
