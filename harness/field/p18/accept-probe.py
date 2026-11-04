#!/usr/bin/env python3
"""accept-probe.py: time a KDC's accept path with one pre-built AS-REQ.

    accept-probe.py [--host H] [--port P] [--out accept.csv]
                    [--keytab /srv/p18/seed/admin.keytab]

The request is an AS-REQ for admin/admin in P18.TEST, with no padata. Each sample
is one TCP connection: the clock starts at connect and stops when the reply
has arrived. One UDP sample is recorded first. Then 200 requests back to
back (idle), then 30 rounds of 50 requests at once with no write (idle-burst).
Then 30 rounds of one `kadmin cpw -randkey` on host/f00000.p18.test, one
request alone (post-write), and 50 requests at once (post-write-burst).

accept.csv columns: phase, burst, ms, reply. The reply is AS-REP, or
KRB-ERROR and its code. The graded number is the slowest alone post-write
request minus the idle median. The burst delta is informational. A
KRB-ERROR 6 ends the run. Point it at a KDC that is already listening.
"""

import argparse
import csv
import socket
import statistics
import subprocess
import sys
import threading
import time

REALM = "P18.TEST"
CLIENT = ("admin", "admin")
SERVICE = ("krbtgt", REALM)
WRITE_PRINC = "host/f00000.p18.test"
KDC_PORT = 18888
IDLE = 200
ROUNDS = 30
BURST = 50


def der_len(n):
    if n < 0x80:
        return bytes((n,))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def tlv(tag, content):
    return bytes((tag,)) + der_len(len(content)) + content


def der_int(value):
    if value < 0:
        raise ValueError(value)
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return tlv(0x02, raw)


def gstring(text):
    return tlv(0x1B, text.encode("ascii"))


def explicit(number, inner):
    return tlv(0xA0 | number, inner)


def principal(name_type, parts):
    name = explicit(0, der_int(name_type)) + explicit(1, tlv(0x30, b"".join(gstring(p) for p in parts)))
    return tlv(0x30, name)


def as_req(nonce):
    """AS-REQ, application 10, no padata. etype is aes256 (18)."""
    body = b"".join(
        (
            explicit(0, tlv(0x03, b"\x00\x00\x00\x00\x00")),
            explicit(1, principal(1, CLIENT)),
            explicit(2, gstring(REALM)),
            explicit(3, principal(2, SERVICE)),
            explicit(5, tlv(0x18, b"20991231235959Z")),
            explicit(7, der_int(nonce)),
            explicit(8, tlv(0x30, der_int(18))),
        )
    )
    seq = tlv(0x30, explicit(1, der_int(5)) + explicit(2, der_int(10)) + explicit(4, tlv(0x30, body)))
    return tlv(0x6A, seq)


def take(buf, at):
    tag = buf[at]
    n, i = buf[at + 1], at + 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i : i + k], "big")
        i += k
    return tag, buf[i : i + n], i + n


def reply_name(der):
    """AS-REP, or KRB-ERROR and its code, from the application tag."""
    try:
        tag, inner, end = take(der, 0)
    except (IndexError, ValueError):
        return "short"
    if end != len(der) or (tag & 0xC0) != 0x40:
        return "not-krb"
    app = tag & 0x1F
    if app == 11:
        return "AS-REP"
    if app != 30:
        return f"msg {app}"
    try:
        _, seq, _ = take(inner, 0)
        fields, i = {}, 0
        while i < len(seq):
            number, value, i = take(seq, i)
            fields[number & 0x1F] = value
        _, code, _ = take(fields[6], 0)
        return f"KRB-ERROR {int.from_bytes(code, 'big', signed=True)}"
    except (IndexError, KeyError, ValueError):
        return "KRB-ERROR ?"


def recv_all(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def once_tcp(host, port, nonce):
    der = as_req(nonce)
    frame = len(der).to_bytes(4, "big") + der
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(frame)
            hdr = recv_all(sock, 4)
            if len(hdr) != 4:
                return (time.perf_counter() - started) * 1000, "short"
            body = recv_all(sock, int.from_bytes(hdr, "big"))
    except (TimeoutError, OSError):
        return (time.perf_counter() - started) * 1000, "timeout"
    return (time.perf_counter() - started) * 1000, reply_name(body)


def once_udp(host, port, nonce):
    der = as_req(nonce)
    started = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(der, (host, port))
            body, _ = sock.recvfrom(65535)
    except (TimeoutError, OSError):
        return (time.perf_counter() - started) * 1000, "timeout"
    return (time.perf_counter() - started) * 1000, reply_name(body)


def cpw(keytab):
    cmd = [
        "/usr/bin/kadmin",
        "-k",
        "-t",
        keytab,
        "-p",
        f"admin/admin@{REALM}",
        "-r",
        REALM,
        "-q",
        f"cpw -randkey {WRITE_PRINC}",
    ]
    got = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if got.returncode != 0:
        err = (got.stderr or got.stdout).strip().splitlines()
        print(f"cpw: {err[0] if err else got.returncode}", file=sys.stderr)


def burst(host, port, phase, number, count, nonce0):
    gate = threading.Barrier(count)
    rows = [None] * count

    def go(i):
        gate.wait()
        ms, name = once_tcp(host, port, nonce0 + i)
        rows[i] = (phase, number, f"{ms:.3f}", name)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return rows


def run(host, port, keytab, out_path):
    rows = []
    ms, name = once_udp(host, port, 1)
    rows.append(("udp", 0, f"{ms:.3f}", name))
    for i in range(IDLE):
        ms, name = once_tcp(host, port, 1000 + i)
        rows.append(("idle", 0, f"{ms:.3f}", name))
    nonce = 100000
    for number in range(1, ROUNDS + 1):
        rows.extend(burst(host, port, "idle-burst", number, BURST, nonce))
        nonce += BURST
    for number in range(1, ROUNDS + 1):
        cpw(keytab)
        ms, name = once_tcp(host, port, nonce)
        nonce += 1
        rows.append(("post-write", number, f"{ms:.3f}", name))
        rows.extend(burst(host, port, "post-write-burst", number, BURST, nonce))
        nonce += BURST
    with open(out_path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("phase", "burst", "ms", "reply"))
        writer.writerows(rows)
    idle = [float(ms) for phase, _, ms, _ in rows if phase == "idle"]
    alone = [float(ms) for phase, _, ms, _ in rows if phase == "post-write"]
    idle_burst = [float(ms) for phase, _, ms, _ in rows if phase == "idle-burst"]
    wrote_burst = [float(ms) for phase, _, ms, _ in rows if phase == "post-write-burst"]
    stall = max(alone) - statistics.median(idle)
    delta = max(wrote_burst) - max(idle_burst)
    mark = "within 5 ms" if stall <= 5 else "over 5 ms"
    print(f"graded max stall {stall:.3f} ms, {mark}; informational burst delta {delta:.3f} ms")
    if any(reply == "KRB-ERROR 6" for *_, reply in rows):
        raise SystemExit("a reply was KRB-ERROR 6")


def self_check():
    der = as_req(7)
    tag, inner, end = take(der, 0)
    if tag != 0x6A or end != len(der):
        raise SystemExit("AS-REQ tag")
    _, seq, _ = take(inner, 0)
    if seq[0] != 0xA1:
        raise SystemExit("pvno")
    code = explicit(6, der_int(25))
    err = tlv(0x7E, tlv(0x30, explicit(1, der_int(30)) + code))
    if reply_name(err) != "KRB-ERROR 25":
        raise SystemExit(reply_name(err))
    if reply_name(der) != "msg 10":
        raise SystemExit(reply_name(der))
    print("ok")


def main(argv):
    if argv[1:2] == ["--self-check"]:
        self_check()
        return
    parser = argparse.ArgumentParser(description="Time KDC accept with one AS-REQ")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=KDC_PORT)
    parser.add_argument("--keytab", default="/srv/p18/seed/admin.keytab")
    parser.add_argument("--out", default="accept.csv")
    args = parser.parse_args(argv[1:])
    run(args.host, args.port, args.keytab, args.out)


if __name__ == "__main__":
    main(sys.argv)
