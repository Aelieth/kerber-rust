#!/usr/bin/env python3
"""kpwsend.py: reference sender for the RA r4 kpasswd (:464) cells. Stdlib only. Holds no key.

usage: kpwsend.py --proto udp|tcp --host H [--port 464] [--log /var/log/kadmind.log] [--timeout 1.0] FRAMES.tsv

FRAMES.tsv: `id<TAB>frame-hex` per line (`#` lines skipped): the whole RFC 3244 message, as MIT's
process_chpw_request reads it: [plen:2][vno:2][aplen:2][AP-REQ][KRB-PRIV]. Over TCP the 4-octet
length of Kerberos TCP framing is added here.

stdout, one line per frame: `id<TAB>proto<TAB>wire<TAB>log`
  wire = DROP:eof | DROP:timeout          no reply (MIT: process_chpw_request failed before chpwfail)
         ERR:<error-code>:<result>:<text> KRB-ERROR whose e-data is <result:2><text> (no AP-REP)
         REP                              AP-REP then a KRB-PRIV (its result code is encrypted)
  log  = `-` or the kadmind.log lines that appeared during the exchange, without time/host/pid
         (`(Level) message`), joined by ` | `
Nothing is compared here; a second run against the other daemon is compared by the caller.
"""
import argparse
import glob
import os
import re
import socket
import struct
import sys
import time

PREFIX = re.compile(r"^\w{3} [ \d]\d \d\d:\d\d:\d\d (?:\S+ )?[\w.-]+\[\d+\]\((\w+)\): (.*)$")
NOISE = re.compile(r"\(info\) closing down fd \d+$")


def tlv(b, i=0):
    """(tag, content, next) of the DER element at b[i]; one-octet tags only."""
    tag = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return tag, b[i:i + n], i + n


def krb_error_fields(b):
    """error-code and e-data of a KRB-ERROR (APPLICATION 30) or None."""
    tag, body, _ = tlv(b)
    if tag != 0x7E:
        return None
    _, seq, _ = tlv(body)
    out, i = {}, 0
    while i < len(seq):
        t, c, i = tlv(seq, i)
        out[t & 0x1F] = c
    code = None
    if 6 in out:
        _, v, _ = tlv(out[6])
        code = int.from_bytes(v, "big", signed=True)
    edata = None
    if 12 in out:
        _, edata, _ = tlv(out[12])
    return code, edata


def classify(rep):
    if len(rep) < 6:
        return "BAD:short"
    plen, ver, aplen = struct.unpack(">HHH", rep[:6])
    tag = "" if plen == len(rep) and ver == 1 else ":badhdr"
    if aplen == 0:
        f = krb_error_fields(rep[6:])
        if f is None or f[1] is None or len(f[1]) < 2:
            return "BAD:noerr" + tag
        res = int.from_bytes(f[1][:2], "big")
        return "ERR:%s:%d:%s%s" % (f[0], res, f[1][2:].decode("latin-1"), tag)
    return "REP" + tag


def exchange_udp(host, port, frame, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(frame, (host, port))
        return s.recvfrom(65535)[0], None
    except socket.timeout:
        return None, "timeout"
    except ConnectionRefusedError:
        return None, "refused"
    finally:
        s.close()


def exchange_tcp(host, port, frame, timeout):
    try:
        s = socket.create_connection((host, port), timeout)
    except OSError:
        return None, "refused"
    s.settimeout(timeout)
    try:
        s.sendall(struct.pack(">I", len(frame)) + frame)
        buf = b""
        while len(buf) < 4:
            d = s.recv(4 - len(buf))
            if not d:
                return None, "eof"
            buf += d
        want = struct.unpack(">I", buf)[0]
        body = b""
        while len(body) < want:
            d = s.recv(want - len(body))
            if not d:
                return None, "eof"
            body += d
        return body, None
    except socket.timeout:
        return None, "timeout"
    except ConnectionResetError:
        return None, "eof"
    finally:
        s.close()


def log_size(path):
    try:
        st = os.stat(path)
        return st.st_size, st.st_ino
    except OSError:
        return 0, 0


def log_since(path, mark):
    # Across logrotate's rename: the rotated file holding the marked inode from the mark, then the new file whole.
    size, ino = mark
    data = b""
    try:
        if ino and os.stat(path).st_ino != ino:
            for g in glob.glob(path + "-*") + glob.glob(path + ".*"):
                if os.stat(g).st_ino == ino:
                    with open(g, "rb") as f:
                        f.seek(size)
                        data = f.read()
                    break
            size = 0
        with open(path, "rb") as f:
            f.seek(size)
            data += f.read()
    except OSError:
        return []
    lines = data.decode("latin-1").splitlines()
    out = []
    for ln in lines:
        m = PREFIX.match(ln)
        out.append("(%s) %s" % (m.group(1), m.group(2)) if m else ln)
    return [x for x in out if not NOISE.search(x)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proto", choices=("udp", "tcp"), required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=464)
    ap.add_argument("--log", default="/var/log/kadmind.log")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("frames")
    a = ap.parse_args()
    ex = exchange_udp if a.proto == "udp" else exchange_tcp
    for line in open(a.frames):
        if line.startswith("#") or not line.strip():
            continue
        cid, hexframe = line.rstrip("\n").split("\t")[:2]
        before = log_size(a.log)
        rep, why = ex(a.host, a.port, bytes.fromhex(hexframe), a.timeout)
        time.sleep(0.05)
        wire = "DROP:" + why if rep is None else classify(rep)
        lines = log_since(a.log, before)
        print("%s\t%s\t%s\t%s" % (cid, a.proto, wire, " | ".join(lines) if lines else "-"))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
