#!/usr/bin/env python3
"""b2c-pcap.py summarize FILE.pcap [--ports 88] [--names]  |  b2c-pcap.py selftest

Host side, stdlib only. Reads a classic pcap (what `tcpdump -w` writes) taken on a KDC and prints ONE LINE PER KERBEROS MESSAGE, in capture order:
    AS-REQ client=192.0.2.21 padata=[]
    KRB-ERROR client=192.0.2.21 code=25 padata=[136,19,151,133]
    AS-REQ client=192.0.2.21 padata=[133,151]
    AS-REP client=192.0.2.21 padata=[19]
and a trailer of counts. The summary carries message kinds, error codes and the padata TYPE NUMBERS only: no cookie, ciphertext, name, nonce, time or port. This is
what the B2 records keep of a capture; the capture itself stays on the host.

--names (PG2 only; the default output is byte for byte what it was): each line also carries the CLIENT PRINCIPAL of its exchange, `cname=alice@KERBER.TEST`, right after client=:
    AS-REQ client=192.0.2.21 cname=alice@KERBER.TEST padata=[150,149]
    KRB-ERROR client=192.0.2.21 cname=alice@KERBER.TEST code=25 padata=[136,19,2,133]
    TGS-REQ client=192.0.2.21 cname=-
The name of an AS-REQ is the cname of its req-body; of an AS-REP or a KRB-ERROR its own cname when it has one, else the name of the request that came from the same client address and
port just before it (the exchange's); `-` when no name is known (a TGS-REQ carries none: the client's name is inside the encrypted ticket). The client ADDRESS alone does not tell the
cell's logins from other traffic of the same host (one lab client ran the cell's logins and its own NFS machinery from one address), the name does.

`flow FILE [--match RX] [--kdc-port 88]` (DN and KL): the DNS and KDC side of a capture taken on a CLIENT, one line per event in capture order with the seconds since the first event:
    T+0.000 DNS-Q udp to=192.0.2.22 id=63983 sport=55898 SRV _kerberos._udp.KERBER.TEST.
    T+0.001 DNS-R udp from=192.0.2.22 id=63983 rcode=0 an=1 flags=aa,rd,ra
    T+0.002 DNS-Q tcp to=... (a query over a TCP connection to port 53; the 2-byte length prefix may come in a segment of its own) / DNS-R tcp ...
    T+0.010 KDC udp dst=192.0.2.1:88 len=180 cname=alice@KERBER.TEST   (a datagram to the KDC port; the client's name when the message names one, `-` otherwise)
    T+1.011 KDC tcp-syn dst=192.0.2.10:88 cname=alice@KERBER.TEST  (a connection attempt: SYN without ACK; the name is that of the connection's first request, absent for a SYN nobody answered)
    T+1.012 KDC-R udp src=192.0.2.10:88 len=447      (a datagram from the KDC port); KDC-R tcp: the first payload segment of a connection's reply
--match: only DNS queries whose name matches the extended regular expression (case-insensitive), and their responses (the rest of the host's DNS chatter is left out). Trailer: `# N packets ...`.

Linktypes handled: 1 (Ethernet), 0 (null/loopback), 12 and 101 (raw IP), 113 (Linux cooked), 276 (Linux cooked v2). TCP payloads are Kerberos messages with the 4-byte length
prefix, reassembled per direction in capture order (duplicate segments dropped); UDP payloads are messages.
"""
import struct
import sys

NAMES = {0x6A: "AS-REQ", 0x6B: "AS-REP", 0x6C: "TGS-REQ", 0x6D: "TGS-REP", 0x6E: "AP-REQ", 0x6F: "AP-REP", 0x7E: "KRB-ERROR"}


def der(buf, off):
    """(tag, content_start, content_end) of the element at off; raises IndexError/ValueError when truncated."""
    tag = buf[off]
    off += 1
    ln = buf[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    end = off + ln
    if end > len(buf):
        raise ValueError("truncated")
    return tag, off, end


def children(buf, start, end):
    off = start
    while off < end:
        tag, s, e = der(buf, off)
        yield tag, s, e
        off = e


def int_value(buf, s, e):
    t, cs, ce = der(buf, s)
    if t != 0x02:
        raise ValueError("not an INTEGER")
    return int.from_bytes(buf[cs:ce], "big", signed=True)


def padata_types(buf, s, e):
    """The PA-DATA type numbers of a SEQUENCE OF PA-DATA whose [n] content spans s..e."""
    t, ss, se = der(buf, s)
    if t != 0x30:
        raise ValueError("not a SEQUENCE")
    types = []
    for pt, ps, pe in children(buf, ss, se):
        if pt != 0x30:
            raise ValueError("not a PA-DATA")
        for ft, fs, fe in children(buf, ps, pe):
            if ft == 0xA1:
                types.append(int_value(buf, fs, fe))
    return types


def _text(buf, s, e):
    """The text of the string element whose [n] content spans s..e; anything outside printable ASCII is shown as '?'."""
    _t, cs, ce = der(buf, s)
    return "".join(chr(b) if 0x21 <= b < 0x7F else "?" for b in buf[cs:ce])


def _principal(buf, s, e):
    """name/name/... of the PrincipalName whose [n] content spans s..e."""
    t, ss, se = der(buf, s)
    if t != 0x30:
        raise ValueError("not a SEQUENCE")
    for ft, fs, _fe in children(buf, ss, se):
        if ft == 0xA1:
            t2, s2, e2 = der(buf, fs)
            if t2 != 0x30:
                raise ValueError("not a SEQUENCE OF")
            return "/".join("".join(chr(b) if 0x21 <= b < 0x7F else "?" for b in buf[cs:ce]) for _t, cs, ce in children(buf, s2, e2))
    raise ValueError("no name-string")


def client_name(msg):
    """name@REALM the message itself names as its client: an AS-REQ's req-body cname and realm, an AS-REP's cname and crealm, a KRB-ERROR's cname and crealm when it has them;
    None when it names none (a TGS-REQ, a KRB-ERROR without a cname)."""
    try:
        tag, s, _e = der(msg, 0)
        t, ss, se = der(msg, s)
        if t != 0x30:
            return None
        fields = {ft: (fs, fe) for ft, fs, fe in children(msg, ss, se)}
        if tag == 0x6A:      # AS-REQ: req-body [4] { cname [1], realm [2] }
            if 0xA4 not in fields:
                return None
            _bt, bs, be = der(msg, fields[0xA4][0])
            body = {ft: (fs, fe) for ft, fs, fe in children(msg, bs, be)}
            nm, rl = body.get(0xA1), body.get(0xA2)
        elif tag == 0x6B:    # AS-REP: crealm [3], cname [4]
            nm, rl = fields.get(0xA4), fields.get(0xA3)
        elif tag == 0x7E:    # KRB-ERROR: crealm [7], cname [8]
            nm, rl = fields.get(0xA8), fields.get(0xA7)
        else:
            return None
        if nm is None:
            return None
        name = _principal(msg, *nm)
        return name + "@" + _text(msg, *rl) if rl is not None else name
    except (IndexError, ValueError, KeyError):
        return None


def describe(msg):
    """(kind, detail string) of one Kerberos message, or None when it is not one."""
    try:
        tag, s, e = der(msg, 0)
    except (IndexError, ValueError):
        return None
    kind = NAMES.get(tag)
    if kind is None:
        return "TAG-0x%02x" % tag, ""
    try:
        t, ss, se = der(msg, s)
        if t != 0x30:
            return kind, "undecoded"
        fields = {ft: (fs, fe) for ft, fs, fe in children(msg, ss, se)}
        if tag == 0x6A and 0xA3 in fields:
            return kind, "padata=%s" % padata_types(msg, *fields[0xA3]).__repr__().replace(" ", "")
        if tag == 0x6A:
            return kind, "padata=[]"
        if tag == 0x6B and 0xA2 in fields:
            return kind, "padata=%s" % padata_types(msg, *fields[0xA2]).__repr__().replace(" ", "")
        if tag == 0x6B:
            return kind, "padata=[]"
        if tag == 0x7E:
            code = int_value(msg, *fields[0xA6]) if 0xA6 in fields else -1
            out = "code=%d" % code
            if 0xAC in fields:
                try:
                    ot, os_, oe = der(msg, fields[0xAC][0])
                    if ot == 0x04:
                        out += " padata=%s" % padata_types(msg, os_, oe).__repr__().replace(" ", "")
                except (IndexError, ValueError):
                    out += " edata=unparsed"
            return kind, out
        return kind, ""
    except (IndexError, ValueError, KeyError):
        return kind, "undecoded"


def ip_payload(pkt, linktype):
    """(src, dst, proto, l4 bytes) of an IPv4/IPv6 packet inside a link frame, or None."""
    off = 0
    if linktype == 1:
        if len(pkt) < 14:
            return None
        et = struct.unpack(">H", pkt[12:14])[0]
        off = 14
        while et == 0x8100 and len(pkt) >= off + 4:
            et = struct.unpack(">H", pkt[off + 2:off + 4])[0]
            off += 4
    elif linktype == 113:
        if len(pkt) < 16:
            return None
        et = struct.unpack(">H", pkt[14:16])[0]
        off = 16
    elif linktype == 276:
        if len(pkt) < 20:
            return None
        et = struct.unpack(">H", pkt[0:2])[0]
        off = 20
    elif linktype == 0:
        if len(pkt) < 4:
            return None
        et = 0x0800 if pkt[0] in (2,) or pkt[3] in (2,) else 0x86DD
        off = 4
    elif linktype in (12, 101):
        et = 0x0800 if (pkt[0] >> 4) == 4 else 0x86DD
    else:
        return None
    if et == 0x0800 and len(pkt) >= off + 20:
        ihl = (pkt[off] & 0x0F) * 4
        total = struct.unpack(">H", pkt[off + 2:off + 4])[0]
        proto = pkt[off + 9]
        src = ".".join(str(b) for b in pkt[off + 12:off + 16])
        dst = ".".join(str(b) for b in pkt[off + 16:off + 20])
        end = off + total if 0 < total <= len(pkt) - off else len(pkt)
        return src, dst, proto, pkt[off + ihl:end]
    if et == 0x86DD and len(pkt) >= off + 40:
        proto = pkt[off + 6]
        src = ":".join("%x" % x for x in struct.unpack(">8H", pkt[off + 8:off + 24]))
        dst = ":".join("%x" % x for x in struct.unpack(">8H", pkt[off + 24:off + 40]))
        return src, dst, proto, pkt[off + 40:]
    return None


def summarize(path, ports, names=False):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return ["# empty capture"], 0
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise SystemExit("b2c-pcap.py: %s is not a classic pcap file" % path)
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    npk = 0
    streams = {}
    seen = set()
    out = []
    counts = {}
    asked = {}   # names mode: (client address, client port) -> the client name of the last request from there

    def emit(src, sport, dst, dport, msg):
        client = dst if sport in ports else src
        d = describe(msg)
        if d is None:
            return
        kind, detail = d
        counts[kind] = counts.get(kind, 0) + 1
        if not names:
            out.append(("%s client=%s %s" % (kind, client, detail)).rstrip())
            return
        endpoint = (client, dport if sport in ports else sport)
        who = client_name(msg)
        if sport in ports:   # a reply: its own name, else the name of the request it answers
            who = who or asked.get(endpoint)
        else:
            asked[endpoint] = who
        out.append(("%s client=%s cname=%s %s" % (kind, client, who or "-", detail)).rstrip())

    while off + 16 <= len(data):
        _ts_s, _ts_u, incl, _orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        npk += 1
        ip = ip_payload(pkt, linktype)
        if ip is None:
            continue
        src, dst, proto, l4 = ip
        if proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack(">HH", l4[:4])
            if sport in ports or dport in ports:
                emit(src, sport, dst, dport, l4[8:])
        elif proto == 6 and len(l4) >= 20:
            sport, dport, seq = struct.unpack(">HHI", l4[:8])
            doff = (l4[12] >> 4) * 4
            payload = l4[doff:]
            if not payload or not (sport in ports or dport in ports):
                continue
            key = (src, sport, dst, dport)
            if (key, seq, len(payload)) in seen:
                continue
            seen.add((key, seq, len(payload)))
            buf = streams.setdefault(key, bytearray())
            buf.extend(payload)
            while len(buf) >= 4:
                ln = struct.unpack(">I", bytes(buf[:4]))[0] & 0x7FFFFFFF
                if len(buf) < 4 + ln:
                    break
                emit(src, sport, dst, dport, bytes(buf[4:4 + ln]))
                del buf[:4 + ln]
    trailer = "# %d packets, linktype %d, %d Kerberos messages: %s" % (
        npk, linktype, len(out), ", ".join("%s %d" % (k, counts[k]) for k in sorted(counts)) or "none")
    return out + [trailer], len(out)


def dns_message(msg):
    """(id, flags, qname, qtype, ancount, rcode) of a DNS message, or None"""
    if len(msg) < 12:
        return None
    qid, flags, qd, an = struct.unpack(">HHHH", msg[:8])
    if qd < 1:
        return None
    labels = []
    off = 12
    try:
        while True:
            ln = msg[off]
            off += 1
            if ln == 0:
                break
            if ln & 0xC0:
                return None
            labels.append(msg[off:off + ln].decode("ascii", "replace"))
            off += ln
        qtype = struct.unpack(">H", msg[off:off + 2])[0]
    except (IndexError, struct.error):
        return None
    return qid, flags, ".".join(labels) + ".", qtype, an, flags & 0xF


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 256: "URI"}


def flow(path, match, kdc_port):
    import re
    rx = re.compile(match, re.I) if match else None
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return ["# empty capture"]
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise SystemExit("b2c-pcap.py: %s is not a classic pcap file" % path)
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    npk = 0
    events = []              # (time, text)
    pending = {}             # (client ip, client port, id) -> kept query name
    streams = {}
    seen = set()
    kdc_first = set()        # tcp reply streams that already produced a KDC-R line
    syn_at = {}              # (client ip, port, kdc ip, kdc port) -> index of its tcp-syn event
    named = set()            # connections whose SYN line already carries the client's name
    kbuf = {}                # the first bytes of a connection's request

    def dns_event(t, proto, src, sport, dst, dport, msg):
        d = dns_message(msg)
        if d is None:
            return
        qid, flags, qname, qtype, an, rcode = d
        if dport == 53 and not flags & 0x8000:
            if rx and not rx.search(qname):
                return
            pending[(src, sport, qid)] = qname
            events.append((t, "DNS-Q %s to=%s id=%d sport=%d %s %s" % (proto, dst, qid, sport, DNS_TYPES.get(qtype, str(qtype)), qname)))
        elif sport == 53 and flags & 0x8000:
            if (dst, dport, qid) not in pending:
                return
            fl = ",".join(n for bit, n in ((0x0400, "aa"), (0x0200, "tc"), (0x0100, "rd"), (0x0080, "ra")) if flags & bit)
            events.append((t, "DNS-R %s from=%s id=%d rcode=%d an=%d flags=%s" % (proto, src, qid, rcode, an, fl or "-")))

    while off + 16 <= len(data):
        ts_s, ts_f, incl, _orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        npk += 1
        t = ts_s + ts_f / (1e9 if nano else 1e6)
        ip = ip_payload(pkt, linktype)
        if ip is None:
            continue
        src, dst, proto, l4 = ip
        if proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack(">HH", l4[:4])
            payload = l4[8:]
            if dport == 53 or sport == 53:
                dns_event(t, "udp", src, sport, dst, dport, payload)
            elif dport == kdc_port:
                events.append((t, "KDC udp dst=%s:%d len=%d cname=%s" % (dst, dport, len(payload), client_name(payload) or "-")))
            elif sport == kdc_port:
                events.append((t, "KDC-R udp src=%s:%d len=%d" % (src, sport, len(payload))))
        elif proto == 6 and len(l4) >= 20:
            sport, dport, seq = struct.unpack(">HHI", l4[:8])
            doff = (l4[12] >> 4) * 4
            tflags = l4[13]
            payload = l4[doff:]
            if dport == kdc_port and tflags & 0x02 and not tflags & 0x10:
                if (src, sport, dst, dport, seq) not in seen:      # the kernel's own SYN retransmission (same port and sequence number) is not a new attempt
                    seen.add((src, sport, dst, dport, seq))
                    syn_at[(src, sport, dst, dport)] = len(events)
                    events.append((t, "KDC tcp-syn dst=%s:%d" % (dst, dport)))
            elif dport == kdc_port and payload and (src, sport, dst, dport) in syn_at and (src, sport, dst, dport) not in named:
                # the first request of a connection names its client: `cname=alice@KERBER.TEST` is added to the SYN line (a SYN that never got a reply stays without one)
                kb = kbuf.setdefault((src, sport, dst, dport), bytearray())
                kb.extend(payload)
                if len(kb) >= 4 and len(kb) >= 4 + (struct.unpack(">I", bytes(kb[:4]))[0] & 0x7FFFFFFF):
                    named.add((src, sport, dst, dport))
                    i = syn_at[(src, sport, dst, dport)]
                    events[i] = (events[i][0], events[i][1] + " cname=%s" % (client_name(bytes(kb[4:4 + (struct.unpack(">I", bytes(kb[:4]))[0] & 0x7FFFFFFF)])) or "-"))
            elif sport == kdc_port and payload and (src, dst, dport) not in kdc_first:
                kdc_first.add((src, dst, dport))
                events.append((t, "KDC-R tcp src=%s:%d" % (src, sport)))
            if (dport == 53 or sport == 53) and payload:
                key = (src, sport, dst, dport)
                if (key, seq, len(payload)) in seen:
                    continue
                seen.add((key, seq, len(payload)))
                buf = streams.setdefault(key, bytearray())
                buf.extend(payload)
                while len(buf) >= 2:
                    ln = struct.unpack(">H", bytes(buf[:2]))[0]
                    if len(buf) < 2 + ln:
                        break
                    dns_event(t, "tcp", src, sport, dst, dport, bytes(buf[2:2 + ln]))
                    del buf[:2 + ln]
    out = []
    if events:
        t0 = events[0][0]
        for t, text in events:
            out.append("T+%.3f %s" % (t - t0, text))
    out.append("# %d packets, linktype %d, %d events" % (npk, linktype, len(events)))
    return out


def selftest():
    def tlv(tag, body):
        n = len(body)
        if n < 128:
            return bytes([tag, n]) + body
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(nb)]) + nb + body

    def integer(v):
        b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
        return tlv(0x02, b)

    def padata(types):
        return tlv(0x30, b"".join(tlv(0x30, tlv(0xA1, integer(t)) + tlv(0xA2, tlv(0x04, b"x"))) for t in types))

    as_req0 = tlv(0x6A, tlv(0x30, tlv(0xA1, integer(5)) + tlv(0xA2, integer(10)) + tlv(0xA4, tlv(0x30, b""))))
    as_req1 = tlv(0x6A, tlv(0x30, tlv(0xA1, integer(5)) + tlv(0xA2, integer(10)) + tlv(0xA3, padata([133, 151])) + tlv(0xA4, tlv(0x30, b""))))
    err = tlv(0x7E, tlv(0x30, tlv(0xA0, integer(5)) + tlv(0xA6, integer(25)) + tlv(0xAC, tlv(0x04, padata([136, 19, 151, 133])))))
    as_rep = tlv(0x6B, tlv(0x30, tlv(0xA0, integer(5)) + tlv(0xA2, padata([19]))))

    def frame_eth_tcp(src, sport, dst, dport, seq, payload):
        tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + tcp
        return b"\x00" * 12 + b"\x08\x00" + ip

    frames = []
    c, k = "192.0.2.21", "192.0.2.10"
    frames.append(frame_eth_tcp(c, 40000, k, 88, 1, struct.pack(">I", len(as_req0)) + as_req0))
    frames.append(frame_eth_tcp(k, 88, c, 40000, 1, struct.pack(">I", len(err)) + err))
    frames.append(frame_eth_tcp(c, 40002, k, 88, 1, struct.pack(">I", len(as_req1)) + as_req1))
    frames.append(frame_eth_tcp(c, 40002, k, 88, 1, struct.pack(">I", len(as_req1)) + as_req1))   # a retransmission: dropped
    frames.append(frame_eth_tcp(k, 88, c, 40002, 1, struct.pack(">I", len(as_rep)) + as_rep))
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for fr in frames:
        pcap += struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="b2c-pcap-selftest-", dir=os.environ.get("TMPDIR") or None)
    os.write(fd, pcap)
    os.close(fd)
    try:
        lines, n = summarize(tmp, {88})
    finally:
        os.unlink(tmp)
    want = ["AS-REQ client=192.0.2.21 padata=[]",
            "KRB-ERROR client=192.0.2.21 code=25 padata=[136,19,151,133]",
            "AS-REQ client=192.0.2.21 padata=[133,151]",
            "AS-REP client=192.0.2.21 padata=[19]"]
    if lines[:4] != want or n != 4:
        sys.stderr.write("selftest FAILED:\n%s\n" % "\n".join(lines))
        return 1
    # --names: the client principal of each exchange. alice's AS exchange (the error carries no cname of its own: it takes the request's), another host's AS exchange whose AS-REP names
    # it itself, and a TGS exchange (the TGS-REQ names nobody; its error names the ticket's client)
    def principal(comps, realm):
        names = tlv(0x30, b"".join(tlv(0x1B, x.encode()) for x in comps))
        return tlv(0xA1, tlv(0x30, tlv(0xA0, integer(1)) + tlv(0xA1, names))), tlv(0xA2, tlv(0x1B, realm.encode()))

    def as_req_for(comps, realm, types):
        cn, rl = principal(comps, realm)
        pa = tlv(0xA3, padata(types)) if types else b""
        return tlv(0x6A, tlv(0x30, tlv(0xA1, integer(5)) + tlv(0xA2, integer(10)) + pa + tlv(0xA4, tlv(0x30, cn + rl))))

    def as_rep_for(comps, realm, types):
        cn, _rl = principal(comps, realm)
        return tlv(0x6B, tlv(0x30, tlv(0xA0, integer(5)) + tlv(0xA2, padata(types)) + tlv(0xA3, tlv(0x1B, realm.encode())) + tlv(0xA4, cn[2:])))   # cname is [4]
    tgs_req = tlv(0x6C, tlv(0x30, tlv(0xA1, integer(5)) + tlv(0xA2, integer(12)) + tlv(0xA4, tlv(0x30, b""))))
    cn_h, rl_h = principal(["host", "client1.kerber.test"], "KERBER.TEST")
    err7 = tlv(0x7E, tlv(0x30, tlv(0xA0, integer(5)) + tlv(0xA6, integer(7)) + tlv(0xA7, rl_h[2:]) + tlv(0xA8, cn_h[2:]) + tlv(0xAC, tlv(0x04, padata([136])))))
    frames = []
    ra = as_req_for(["alice"], "KERBER.TEST", [])
    rb = as_req_for(["alice"], "KERBER.TEST", [133, 2])
    rh = as_req_for(["host", "client1"], "KERBER.TEST", [])
    frames.append(frame_eth_tcp(c, 40000, k, 88, 1, struct.pack(">I", len(ra)) + ra))
    frames.append(frame_eth_tcp(k, 88, c, 40000, 1, struct.pack(">I", len(err)) + err))                       # no cname of its own
    frames.append(frame_eth_tcp(c, 40000, k, 88, 100, struct.pack(">I", len(rb)) + rb))                       # the same connection again
    frames.append(frame_eth_tcp(k, 88, c, 40000, 100, struct.pack(">I", len(as_rep_for(["alice"], "KERBER.TEST", [19]))) + as_rep_for(["alice"], "KERBER.TEST", [19])))
    frames.append(frame_eth_tcp(c, 40002, k, 88, 1, struct.pack(">I", len(rh)) + rh))
    hrep = as_rep_for(["host", "client1"], "KERBER.TEST", [19])
    frames.append(frame_eth_tcp(k, 88, c, 40002, 1, struct.pack(">I", len(hrep)) + hrep))
    frames.append(frame_eth_tcp(c, 40004, k, 88, 1, struct.pack(">I", len(tgs_req)) + tgs_req))
    frames.append(frame_eth_tcp(k, 88, c, 40004, 1, struct.pack(">I", len(err7)) + err7))
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for fr in frames:
        pcap += struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr
    fd, tmp = tempfile.mkstemp(prefix="b2c-pcap-selftest-", dir=os.environ.get("TMPDIR") or None)
    os.write(fd, pcap)
    os.close(fd)
    try:
        plain, _ = summarize(tmp, {88})
        named, nn = summarize(tmp, {88}, names=True)
    finally:
        os.unlink(tmp)
    want_named = ["AS-REQ client=192.0.2.21 cname=alice@KERBER.TEST padata=[]",
                  "KRB-ERROR client=192.0.2.21 cname=alice@KERBER.TEST code=25 padata=[136,19,151,133]",
                  "AS-REQ client=192.0.2.21 cname=alice@KERBER.TEST padata=[133,2]",
                  "AS-REP client=192.0.2.21 cname=alice@KERBER.TEST padata=[19]",
                  "AS-REQ client=192.0.2.21 cname=host/client1@KERBER.TEST padata=[]",
                  "AS-REP client=192.0.2.21 cname=host/client1@KERBER.TEST padata=[19]",
                  "TGS-REQ client=192.0.2.21 cname=-",
                  "KRB-ERROR client=192.0.2.21 cname=host/client1.kerber.test@KERBER.TEST code=7 padata=[136]"]
    want_plain = [x.replace(" cname=alice@KERBER.TEST", "").replace(" cname=host/client1@KERBER.TEST", "").replace(" cname=host/client1.kerber.test@KERBER.TEST", "").replace(" cname=-", "") for x in want_named]
    if named[:-1] != want_named or nn != 8 or plain[:-1] != want_plain:
        sys.stderr.write("selftest (names) FAILED:\n%s\n--- plain:\n%s\n" % ("\n".join(named), "\n".join(plain)))
        return 1
    print("b2c-pcap selftest ok: %s" % lines[-1])
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) >= 3 and argv[1] == "flow":
        a = argv[3:]
        print("\n".join(flow(argv[2], a[a.index("--match") + 1] if "--match" in a else None, int(a[a.index("--kdc-port") + 1]) if "--kdc-port" in a else 88)))
        return 0
    if len(argv) >= 3 and argv[1] == "summarize":
        ports = {88}
        if "--ports" in argv:
            ports = {int(p) for p in argv[argv.index("--ports") + 1].split(",")}
        lines, _ = summarize(argv[2], ports, names="--names" in argv)
        print("\n".join(lines))
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
