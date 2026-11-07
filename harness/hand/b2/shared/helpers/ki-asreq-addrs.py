#!/usr/bin/env python3 -I
"""asreq-addrs.py CAP.pcap [PORT...]: the service and the address list of every AS-REQ in a classic pcap (tcpdump -w), in wire order.
No third-party modules. Reads Ethernet (1), Linux cooked v1 (113) and v2 (276), and raw IP (101/12) captures; IPv4 and IPv6; UDP and
TCP (one request per segment, TCP reassembly is not done: an AS-REQ that spans segments is skipped and counted).
Default ports: 88. Output, one line per AS-REQ:  <frame> <sname> addresses=<type>:<hex>,... | none"""
import struct, sys

def tlv(b, i):
    tag = b[i]; i += 1
    n = b[i]; i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big"); i += k
    return tag, i, i + n

def kids(b, s, e):
    i = s
    while i < e:
        t, cs, ce = tlv(b, i)
        yield t, cs, ce
        i = ce

def parse_as_req(b):
    if not b or b[0] != 0x6A:
        return None
    _, s, e = tlv(b, 0)
    _, s2, e2 = tlv(b, s)
    body = next(((cs, ce) for t, cs, ce in kids(b, s2, e2) if t == 0xA4), None)
    if body is None:
        return None
    _, bs, be = tlv(b, body[0])
    sname, addrs = [], None
    for t, cs, ce in kids(b, bs, be):
        if t == 0xA3:
            _, ss, se = tlv(b, cs)
            for t2, c2s, c2e in kids(b, ss, se):
                if t2 == 0xA1:
                    _, qs, qe = tlv(b, c2s)
                    sname = [b[x:y].decode() for _, x, y in kids(b, qs, qe)]
        if t == 0xA9:
            addrs = []
            _, as_, ae = tlv(b, cs)
            for t2, c2s, c2e in kids(b, as_, ae):
                typ = val = None
                for t3, c3s, c3e in kids(b, c2s, c2e):
                    _, vs, ve = tlv(b, c3s)
                    if t3 == 0xA0: typ = int.from_bytes(b[vs:ve], "big")
                    if t3 == 0xA1: val = b[vs:ve].hex()
                addrs.append(f"{typ}:{val}")
    return "/".join(sname), addrs

def main():
    path, ports = sys.argv[1], {int(p) for p in sys.argv[2:]} or {88}
    data = open(path, "rb").read()
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    link = struct.unpack(endian + "I", data[20:24])[0]
    off, frame, skipped = 24, 0, 0
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + caplen]; off += 16 + caplen; frame += 1
        if link == 1: ip = pkt[14:] if pkt[12:14] in (b"\x08\x00", b"\x86\xdd") else b""
        elif link == 113: ip = pkt[16:]
        elif link == 276: ip = pkt[20:]
        elif link in (101, 12): ip = pkt
        else: continue
        if not ip: continue
        ver = ip[0] >> 4
        if ver == 4:
            ihl = (ip[0] & 15) * 4; proto = ip[9]; l4 = ip[ihl:]
        elif ver == 6:
            proto = ip[6]; l4 = ip[40:]
        else: continue
        if proto == 17:
            sport, dport = struct.unpack(">HH", l4[:4]); payload = l4[8:]
        elif proto == 6:
            sport, dport = struct.unpack(">HH", l4[:4]); doff = (l4[12] >> 4) * 4; payload = l4[doff:]
            if len(payload) > 4 and int.from_bytes(payload[:4], "big") == len(payload) - 4: payload = payload[4:]
            elif payload: skipped += 1; continue
        else: continue
        if dport not in ports or not payload: continue
        try: got = parse_as_req(payload)
        except Exception: got = None
        if got:
            sname, addrs = got
            print(f"{frame} {sname} addresses={'none' if addrs is None else ','.join(addrs)}")
    if skipped: print(f"# {skipped} TCP segment(s) not read (no reassembly)", file=sys.stderr)
main()
