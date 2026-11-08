#!/usr/bin/env python3
"""ki-fmt.py sig|ports: host-side formatter for the KI module (stdlib only; lab-agent). Never reads a secret; the capture itself stays on the host.
  ki-fmt.py sig [NAMES KEEP-RX] < DECODER-OUTPUT   stdin: the lines of ki-asreq-addrs.py (`<frame> <sname> addresses=<type>:<hex>,...|none`, KI's decoder, byte for byte); stdout: one line per AS-REQ in
                                      wire order, `# asreq <sname> <ip,ip,...|none>` (type 2 as a dotted quad, type 24 as the compressed IPv6 form, anything else as type:hex), then
                                      `SIG <sname>=<list> > <sname>=<list> ...` with consecutive repeats collapsed (one login is two AS-REQs: without and with pre-authentication).
                                      NAMES is the output of `b2c-pcap.py summarize --names` of the same capture: when its AS-REQ lines are as many as the decoder's, an AS-REQ whose cname does not
                                      match KEEP-RX is another client's traffic and is left out (counted in a `# other` line); otherwise nothing is left out (`# names: count mismatch`).
  ki-fmt.py ports PCAP [PORT...]     stdout: `port <p> to=<n> from=<m> udp=<n> tcp=<n>` per port: the UDP and TCP packets with a payload to and from the port (default 464): kpasswd's request on the wire.
"""
import ipaddress
import re
import struct
import sys


def addr(item):
    typ, _, val = item.partition(":")
    try:
        raw = bytes.fromhex(val)
        if typ == "2" and len(raw) == 4:
            return str(ipaddress.IPv4Address(raw))
        if typ == "24" and len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
    except ValueError:
        pass
    return item


def sig(names_path=None, keep_rx=None):
    reqs = []
    for ln in sys.stdin:
        parts = ln.split()
        if len(parts) < 3 or not parts[2].startswith("addresses="):
            continue
        a = parts[2][len("addresses="):]
        reqs.append((parts[1], "none" if a == "none" else ",".join(addr(x) for x in a.split(","))))
    if names_path:
        cn = []
        for ln in open(names_path, errors="replace"):
            if ln.startswith("AS-REQ "):
                m = re.search(r" cname=(\S+)", ln)
                cn.append(m.group(1) if m else "-")
        if len(cn) == len(reqs):
            kept = [r for r, c in zip(reqs, cn) if re.search(keep_rx, c)]
            if len(kept) != len(reqs):
                print("# other: %d AS-REQ(s) of other clients left out (%s)" % (len(reqs) - len(kept), ",".join(sorted({c for c in cn if not re.search(keep_rx, c)}))))
            reqs = kept
        else:
            print("# names: count mismatch (%d names, %d requests): nothing left out" % (len(cn), len(reqs)))
    for sname, a in reqs:
        print("# asreq %s %s" % (sname, a))
    groups = []
    for r in reqs:
        if not groups or groups[-1] != r:
            groups.append(r)
    print("SIG " + (" > ".join("%s=%s" % g for g in groups) if groups else "none"))


def ports(path, wanted):
    data = open(path, "rb").read()
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    link = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    cnt = {p: [0, 0, 0, 0] for p in wanted}   # to, from, udp, tcp
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + caplen]
        off += 16 + caplen
        if link == 1:
            ip = pkt[14:] if pkt[12:14] in (b"\x08\x00", b"\x86\xdd") else b""
        elif link == 113:
            ip = pkt[16:]
        elif link == 276:
            ip = pkt[20:]
        elif link in (101, 12):
            ip = pkt
        else:
            continue
        if not ip:
            continue
        ver = ip[0] >> 4
        if ver == 4:
            l4 = ip[(ip[0] & 15) * 4:]
            proto = ip[9]
        elif ver == 6:
            l4 = ip[40:]
            proto = ip[6]
        else:
            continue
        if proto not in (6, 17) or len(l4) < 8:
            continue
        sport, dport = struct.unpack(">HH", l4[:4])
        if proto == 17:
            payload = l4[8:]
        else:
            payload = l4[(l4[12] >> 4) * 4:] if len(l4) >= 14 else b""
        if not payload:
            continue
        for p in wanted:
            if dport == p:
                cnt[p][0] += 1
                cnt[p][2 if proto == 17 else 3] += 1
            if sport == p:
                cnt[p][1] += 1
                cnt[p][2 if proto == 17 else 3] += 1
    for p in wanted:
        c = cnt[p]
        print("port %d to=%d from=%d udp=%d tcp=%d" % (p, c[0], c[1], c[2], c[3]))


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "sig":
        sig(*sys.argv[2:4]) if len(sys.argv) >= 4 else sig()
    elif len(sys.argv) >= 3 and sys.argv[1] == "ports":
        ports(sys.argv[2], [int(x) for x in sys.argv[3:]] or [464])
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)


main()
