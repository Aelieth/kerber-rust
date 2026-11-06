#!/usr/bin/env python3
"""dn-stub.py serve --bind IP [--port 53] --zone FILE [--log FILE]  |  dn-stub.py probe IP NAME TYPE [--tcp] [--port 53]  |  dn-stub.py selftest

The DNS server of the B2 modules DN and KL (b2-client): stdlib only, UDP and TCP on IP:53, run as root by `sudo python3 -I dn-stub.py serve ...` on the DNS host (client2, or the kdc VM; never services),
instead of dnsmasq (no mirror, no package). It answers from a small zone file and nothing else; it is not a resolver and forwards nothing.

Zone file, one record per line (blank lines and # comments ignored; names are absolute, case-insensitive, a trailing dot is optional):
    SRV   _kerberos._udp.KERBER.TEST.  PRIORITY WEIGHT PORT TARGET        a service record (TARGET "." is the root target)
    A     kdc.kerber.test.             192.0.2.10                      an address record
    UDPTC _kerberos._udp.TC.TEST.                                          over UDP this name's answer is cut: TC bit set, no records (dnsmasq's answer to a name whose records do not fit 512 bytes)
    ROTATE                                                                 the records of a name with several are rotated by one on every query (dnsmasq's round robin: the recorded
                                                                           KL captures show the two _tcp SRV records in swapped order from one query to the next)
Behaviour, as the recorded dnsmasq (lab-b-r2.txt, lab.txt):
    - a name with records of the asked type: NOERROR, authoritative (AA), the records in the zone file's order, RA and the query's RD copied;
    - a name that is in the zone but has no record of the asked type, or a name not in the zone, or a type the zone never serves (AAAA, URI, TXT ...): REFUSED, no records (dnsmasq without upstream does this);
    - UDP: an answer longer than 512 bytes (no EDNS) is cut to the header with TC set; TCP: the whole answer, any number of queries per connection, the 2-byte length prefix read in as many pieces as they arrive;
    - EDNS: an OPT record in the query is ignored (none of the clients sends one).
--log FILE: one line per query, flushed: `T <seconds since start> <udp|tcp> <src ip>:<src port> id=<id> <TYPE> <name> -> <rcode> an=<n> [tc]`.
`probe` sends one query and prints `<name> <TYPE> bytes=<n> an=<n> tc=<bool> rcode=<n> id=<id>` (the cell's own check that the stub answers and that the client VM can reach it)."""
import os
import select
import socket
import struct
import sys
import threading
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "URI": 256}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
UDP_MAX = 512


def norm(name):
    return name.lower().rstrip(".")


def encode_name(name):
    out = b""
    name = name.rstrip(".")
    if name:
        for label in name.split("."):
            b = label.encode("ascii")
            out += bytes([len(b)]) + b
    return out + b"\x00"


def parse_name(msg, off):
    labels = []
    jumped = False
    end = off
    hops = 0
    while True:
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        off += 1
        if ln == 0:
            break
        labels.append(msg[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), (end if jumped else off)


class Zone:
    def __init__(self, path):
        self.srv = {}    # name -> [(prio, weight, port, target)]
        self.a = {}      # name -> [ip]
        self.udptc = set()
        self.rotate = False
        self.count = {}
        with open(path, encoding="utf-8") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                w = line.split()
                kind = w[0].upper()
                if kind == "SRV" and len(w) == 6:
                    self.srv.setdefault(norm(w[1]), []).append((int(w[2]), int(w[3]), int(w[4]), w[5]))
                elif kind == "A" and len(w) == 3:
                    self.a.setdefault(norm(w[1]), []).append(w[2])
                elif kind == "UDPTC" and len(w) == 2:
                    self.udptc.add(norm(w[1]))
                elif kind == "ROTATE" and len(w) == 1:
                    self.rotate = True
                else:
                    raise SystemExit("dn-stub.py: bad zone line: %s" % line)

    def names(self):
        return set(self.srv) | set(self.a)

    def answer(self, qname, qtype):
        """(rcode, [rdata bytes], type) for a query"""
        n = norm(qname)
        if qtype == TYPES["SRV"] and n in self.srv:
            return 0, self.order(n, qtype, [struct.pack(">HHH", p, wt, port) + encode_name(t) for p, wt, port, t in self.srv[n]]), qtype
        if qtype == TYPES["A"] and n in self.a:
            return 0, self.order(n, qtype, [socket.inet_aton(ip) for ip in self.a[n]]), qtype
        return 5, [], qtype

    def order(self, n, qtype, rdatas):
        if not self.rotate or len(rdatas) < 2:
            return rdatas
        k = self.count.get((n, qtype), 0)
        self.count[(n, qtype)] = k + 1
        k %= len(rdatas)
        return rdatas[k:] + rdatas[:k]


def build_response(zone, query, transport):
    """(response bytes, rcode, answer count, tc) for one query message"""
    if len(query) < 12:
        return None
    qid, flags, qd = struct.unpack(">HHH", query[:6])
    if flags & 0x8000 or qd != 1:
        return None
    try:
        qname, off = parse_name(query, 12)
        qtype, qclass = struct.unpack(">HH", query[off:off + 4])
    except (IndexError, ValueError, struct.error):
        return None
    question = query[12:off + 4]
    rcode, rdatas, rtype = zone.answer(qname, qtype)
    rd = flags & 0x0100
    hdr_flags = 0x8000 | (0x0400 if rcode == 0 else 0) | rd | 0x0080 | rcode        # QR, AA on an answer, RD copied, RA
    answers = b""
    for rd_ in rdatas:
        answers += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 0, len(rd_)) + rd_
    resp = struct.pack(">HHHHHH", qid, hdr_flags, 1, len(rdatas), 0, 0) + question + answers
    tc = False
    if transport == "udp" and (len(resp) > UDP_MAX or (rcode == 0 and norm(qname) in zone.udptc)):
        resp = struct.pack(">HHHHHH", qid, hdr_flags | 0x0200, 1, 0, 0, 0) + question
        tc = True
        return resp, rcode, 0, tc
    return resp, rcode, len(rdatas), tc


class Logger:
    def __init__(self, path):
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.f = open(path, "a", buffering=1) if path else None

    def write(self, transport, src, query, rcode, an, tc):
        if not self.f:
            return
        try:
            qid = struct.unpack(">H", query[:2])[0]
            qname, off = parse_name(query, 12)
            qtype = struct.unpack(">H", query[off:off + 2])[0]
        except (IndexError, ValueError, struct.error):
            return
        with self.lock:
            self.f.write("T %.3f %s %s:%d id=%d %s %s -> %d an=%d%s\n" % (time.time() - self.t0, transport, src[0], src[1], qid, TYPE_NAMES.get(qtype, str(qtype)), qname, rcode, an, " tc" if tc else ""))


def serve_udp(sock, zone, log):
    while True:
        data, src = sock.recvfrom(4096)
        r = build_response(zone, data, "udp")
        if r is None:
            continue
        sock.sendto(r[0], src)
        log.write("udp", src, data, r[1], r[2], r[3])


def read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve_conn(conn, src, zone, log):
    conn.settimeout(10)
    try:
        while True:
            hdr = read_exact(conn, 2)
            if hdr is None:
                return
            ln = struct.unpack(">H", hdr)[0]
            query = read_exact(conn, ln)
            if query is None:
                return
            r = build_response(zone, query, "tcp")
            if r is None:
                return
            conn.sendall(struct.pack(">H", len(r[0])) + r[0])
            log.write("tcp", src, query, r[1], r[2], r[3])
    except (OSError, socket.timeout):
        return
    finally:
        conn.close()


def serve_tcp(sock, zone, log):
    while True:
        conn, src = sock.accept()
        threading.Thread(target=serve_conn, args=(conn, src, zone, log), daemon=True).start()


def serve(bind, port, zonefile, logfile):
    zone = Zone(zonefile)
    log = Logger(logfile)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    u.bind((bind, port))
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind((bind, port))
    t.listen(16)
    print("dn-stub: serving %d names on %s:%d (udp+tcp), log %s" % (len(zone.names()), bind, port, logfile or "-"), flush=True)
    threading.Thread(target=serve_tcp, args=(t, zone, log), daemon=True).start()
    serve_udp(u, zone, log)


def query_message(name, qtype, qid=0x2b3c):
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", qtype, 1)


def probe(ip, name, tname, tcp=False, port=53, timeout=3):
    q = query_message(name, TYPES[tname.upper()])
    if tcp:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.sendall(struct.pack(">H", len(q)) + q)
        ln = struct.unpack(">H", read_exact(s, 2))[0]
        resp = read_exact(s, ln)
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (ip, port))
        resp = s.recv(65535)
        s.close()
    qid, flags, qd, an = struct.unpack(">HHHH", resp[:8])
    print("%s %s bytes=%d an=%d tc=%s rcode=%d id=%d" % (name, tname.upper(), len(resp), an, bool(flags & 0x0200), flags & 0xF, qid))
    return 0


def selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="dn-stub-selftest-", dir=os.environ.get("TMPDIR") or None)
    zf = os.path.join(d, "zone")
    with open(zf, "w") as f:
        f.write("SRV _kerberos._udp.KERBER.TEST. 0 0 88 .\nSRV _kerberos._tcp.KERBER.TEST. 0 0 88 192.0.2.1.\nSRV _kerberos._tcp.KERBER.TEST. 10 0 88 kdc.kerber.test.\n"
                "A kdc.kerber.test. 192.0.2.10\nA 192.0.2.1. 192.0.2.1\nUDPTC _kerberos._udp.TC.TEST.\nSRV _kerberos._udp.TC.TEST. 0 10 88 t1.tc.test.\n")
        for i in range(40):
            f.write("SRV _kerberos._tcp.BIG.TEST. 0 10 88 very-long-kdc-target-name-for-truncation-%02d.tc.kerber.test.\n" % i)
    zone = Zone(zf)
    ok = True

    def check(what, cond):
        nonlocal ok
        print("%s %s" % ("ok  " if cond else "BAD ", what))
        ok = ok and cond
    r = build_response(zone, query_message("_kerberos._tcp.kerber.test", TYPES["SRV"]), "udp")
    check("SRV tcp: 2 answers, NOERROR, AA", r[1] == 0 and r[2] == 2 and struct.unpack(">H", r[0][2:4])[0] & 0x0400)
    r = build_response(zone, query_message("kdc.kerber.test.", TYPES["AAAA"]), "udp")
    check("AAAA: REFUSED", r[1] == 5 and r[2] == 0)
    zone.rotate = True
    first = build_response(zone, query_message("_kerberos._tcp.kerber.test", TYPES["SRV"]), "udp")[0]
    second = build_response(zone, query_message("_kerberos._tcp.kerber.test", TYPES["SRV"]), "udp")[0]
    third = build_response(zone, query_message("_kerberos._tcp.kerber.test", TYPES["SRV"]), "udp")[0]
    check("ROTATE: the two records swap from one query to the next, and back", first != second and first == third)
    zone.rotate = False
    r = build_response(zone, query_message("_kerberos.KERBER.TEST.", TYPES["URI"]), "udp")
    check("URI: REFUSED", r[1] == 5)
    r = build_response(zone, query_message("nosuch.example.", TYPES["A"]), "udp")
    check("unknown name: REFUSED", r[1] == 5)
    r = build_response(zone, query_message("192.0.2.1.", TYPES["A"]), "udp")
    check("A of the dead target: 192.0.2.1", r[1] == 0 and r[0][-4:] == socket.inet_aton("192.0.2.1"))
    r = build_response(zone, query_message("_kerberos._udp.tc.test", TYPES["SRV"]), "udp")
    check("UDPTC over udp: TC, no answers", r[3] and r[2] == 0 and struct.unpack(">H", r[0][2:4])[0] & 0x0200)
    r = build_response(zone, query_message("_kerberos._udp.tc.test", TYPES["SRV"]), "tcp")
    check("UDPTC over tcp: the answer", (not r[3]) and r[2] == 1)
    r = build_response(zone, query_message("_kerberos._tcp.big.test", TYPES["SRV"]), "udp")
    check("40 SRV over udp: cut (over 512 bytes)", r[3] and r[2] == 0)
    r = build_response(zone, query_message("_kerberos._tcp.big.test", TYPES["SRV"]), "tcp")
    check("40 SRV over tcp: 40 answers", (not r[3]) and r[2] == 40)
    # live: udp and tcp, the length prefix in two pieces
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    th = threading.Thread(target=serve, args=("127.0.0.1", port, zf, os.path.join(d, "log")), daemon=True)
    th.start()
    time.sleep(0.5)
    q = query_message("_kerberos._tcp.big.test", TYPES["SRV"])
    c = socket.create_connection(("127.0.0.1", port), timeout=3)
    c.sendall(struct.pack(">H", len(q)))
    time.sleep(0.1)
    c.sendall(q)
    ln = struct.unpack(">H", read_exact(c, 2))[0]
    resp = read_exact(c, ln)
    c.close()
    check("live tcp, prefix and query in two writes: 40 answers", struct.unpack(">H", resp[6:8])[0] == 40)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, ("127.0.0.1", port))
    resp = s.recv(65535)
    check("live udp: truncated", struct.unpack(">H", resp[2:4])[0] & 0x0200 and struct.unpack(">H", resp[6:8])[0] == 0)
    time.sleep(0.2)
    logtext = open(os.path.join(d, "log")).read()
    check("log has the tcp and the udp query", " tcp " in logtext and " udp " in logtext and "-> 0 an=40" in logtext and "tc" in logtext)
    for fn in os.listdir(d):
        os.unlink(os.path.join(d, fn))
    os.rmdir(d)
    print("dn-stub selftest %s" % ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) >= 2 and argv[1] == "serve":
        a = argv[2:]
        bind = a[a.index("--bind") + 1] if "--bind" in a else None
        zonef = a[a.index("--zone") + 1] if "--zone" in a else None
        port = int(a[a.index("--port") + 1]) if "--port" in a else 53
        logf = a[a.index("--log") + 1] if "--log" in a else None
        if not bind or not zonef:
            sys.stderr.write(__doc__)
            return 2
        serve(bind, port, zonef, logf)
        return 0
    if len(argv) >= 5 and argv[1] == "probe":
        a = argv[5:]
        return probe(argv[2], argv[3], argv[4], tcp="--tcp" in a, port=int(a[a.index("--port") + 1]) if "--port" in a else 53)
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
