#!/usr/bin/env python3
"""RADIUS Accept/Reject responder for settling MIT krb5 1.22.2's OTP preauth (kerber-rust OTP1 settle).

Extends P16b-2's p16b2probe.py `cmd_radius` (a UNIX stream socket that only answered Access-Reject): this one
decodes the User-Password attribute and answers Access-Accept for the configured codes, Access-Reject for
anything else, and signs the Response Authenticator. Standard library only; run it inside the MIT image.

  radius_stub.py --unix PATH [--accept CODE]... [--secret S] [--respond MODE] [--delay SEC]
                 [--name NAME] [--log FILE] [--keep-socket] [--idle SEC]

  --unix PATH      UNIX stream socket to listen on (libkrad frames one RADIUS packet per message: the
                   header's 16-bit length). An existing file at PATH is replaced.
  --accept CODE    a decoded User-Password value that is answered Access-Accept (repeatable). With no
                   --accept every request is rejected.
  --secret S       the shared secret (default empty: MIT uses an empty secret on a UNIX socket, and
                   still applies RFC 2865 5.2 to User-Password with it).
  --respond MODE   normal (default: accept listed codes, reject the rest) | reject | accept | challenge
                   (Access-Challenge with State and Reply-Message) | silent (read, never answer).
  --delay SEC      sleep before answering (the whole loop blocks, like p16b2probe's stub).
  --name NAME      label in the log lines.
  --log FILE       append the log here (default stdout); every line is flushed.
  --keep-socket    on SIGTERM leave the socket file behind (a listener-less stale socket: ECONNREFUSED
                   for the next connect); the default removes it (ENOENT).
  --idle SEC       exit after SEC seconds with no event (default 900).

RFC 2865: User-Password (attr 2) is hidden as c(1) = p(1) XOR MD5(S + RA), c(i) = p(i) XOR MD5(S + c(i-1)),
16-octet blocks, the password padded with NULs; the Response Authenticator is
MD5(Code + ID + Length + RequestAuthenticator + Attributes + Secret). Log line shape:
  [t=SECONDS wall=EPOCH] NAME: event ...
"""
import argparse
import hashlib
import os
import select
import signal
import socket
import struct
import sys
import time

T0 = time.monotonic()
ATTR_NAMES = {
    1: "User-Name", 2: "User-Password", 4: "NAS-IP-Address", 5: "NAS-Port", 6: "Service-Type",
    18: "Reply-Message", 24: "State", 25: "Class", 32: "NAS-Identifier", 80: "Message-Authenticator",
}
CODE_NAMES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}
SERVICE_TYPES = {1: "Login", 2: "Framed", 8: "Authenticate-Only"}
LOG = sys.stdout
NAME = "radius-stub"


def say(msg):
    LOG.write(f"[t={time.monotonic() - T0:8.3f} wall={time.time():.3f}] {NAME}: {msg}\n")
    LOG.flush()


def decode_password(secret, req_auth, hidden):
    """RFC 2865 5.2 decoding; returns the padded plaintext (caller strips the NUL padding)."""
    out = b""
    prev = req_auth
    for i in range(0, len(hidden), 16):
        block = hidden[i:i + 16]
        pad = hashlib.md5(secret + prev).digest()
        out += bytes(a ^ b for a, b in zip(block, pad))
        prev = block
    return out


def parse_attrs(buf):
    attrs, off = [], 0
    while off + 2 <= len(buf):
        t, ln = buf[off], buf[off + 1]
        if ln < 2 or off + ln > len(buf):
            attrs.append((None, buf[off:]))
            break
        attrs.append((t, buf[off + 2:off + ln]))
        off += ln
    return attrs


def describe(t, v, secret, req_auth):
    name = ATTR_NAMES.get(t, f"attr{t}")
    if t == 2:
        plain = decode_password(secret, req_auth, v).rstrip(b"\0")
        shown = repr(plain) if len(plain) <= 48 else f"{len(plain)} octets {plain[:40]!r}..."
        return name, f"hidden {len(v)} octets, decoded {shown}", plain
    if t in (1, 32, 18):
        return name, repr(v), None
    if t == 6 and len(v) == 4:
        n = struct.unpack("!I", v)[0]
        return name, f"{n} ({SERVICE_TYPES.get(n, '?')})", None
    if t == 4 and len(v) == 4:
        return name, ".".join(str(b) for b in v), None
    return name, f"{len(v)} octets {v.hex()}", None


def respond(code, ident, req_auth, attrs, secret):
    body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    length = 20 + len(body)
    head = struct.pack("!BBH", code, ident, length)
    auth = hashlib.md5(head + req_auth + body + secret).digest()
    return head + auth + body


def handle(conn, args, secret, accept):
    """One request packet from conn; returns False when the peer closed."""
    hdr = b""
    while len(hdr) < 4:
        chunk = conn.recv(4 - len(hdr))
        if not chunk:
            return False
        hdr += chunk
    code, ident, length = struct.unpack("!BBH", hdr)
    rest = b""
    while len(rest) < length - 4:
        chunk = conn.recv(length - 4 - len(rest))
        if not chunk:
            say(f"peer closed in the middle of a {length}-octet packet")
            return False
        rest += chunk
    req_auth, attr_bytes = rest[:16], rest[16:]
    say(f"request: {CODE_NAMES.get(code, f'code {code}')} id={ident} length={length} "
        f"request-authenticator={req_auth.hex()}")
    password = None
    for t, v in parse_attrs(attr_bytes):
        if t is None:
            say(f"  malformed trailing attribute bytes {v.hex()}")
            continue
        name, text, plain = describe(t, v, secret, req_auth)
        say(f"  attr {t:3d} {name}: {text}")
        if t == 2:
            password = plain
    if code != 1:
        say("  not an Access-Request; ignored")
        return True
    mode = args.respond
    if mode == "normal":
        verdict = "accept" if password in accept else "reject"
    else:
        verdict = mode
    if args.delay:
        say(f"  answering in {args.delay} s")
        time.sleep(args.delay)
    if verdict == "silent":
        say("  verdict: silent (no reply sent)")
        return True
    if verdict == "accept":
        pkt = respond(2, ident, req_auth, [], secret)
    elif verdict == "challenge":
        pkt = respond(11, ident, req_auth, [(24, b"stub-state"), (18, b"stub challenge")], secret)
    else:
        pkt = respond(3, ident, req_auth, [], secret)
    conn.sendall(pkt)
    say(f"  verdict: {verdict} -> sent {CODE_NAMES[pkt[0]]} id={ident} length={len(pkt)} "
        f"response-authenticator={pkt[4:20].hex()}")
    return True


def main():
    global LOG, NAME
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unix", required=True)
    ap.add_argument("--accept", action="append", default=[])
    ap.add_argument("--secret", default="")
    ap.add_argument("--respond", default="normal", choices=["normal", "reject", "accept", "challenge", "silent"])
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--name", default="radius-stub")
    ap.add_argument("--log")
    ap.add_argument("--keep-socket", action="store_true")
    ap.add_argument("--idle", type=float, default=900.0)
    args = ap.parse_args()
    NAME = args.name
    if args.log:
        LOG = open(args.log, "a", buffering=1)
    secret = args.secret.encode()
    accept = {a.encode() for a in args.accept}

    def stop(signum, _frame):
        say(f"stopping on signal {signum}; socket file {'kept' if args.keep_socket else 'removed'}")
        if not args.keep_socket and os.path.exists(args.unix):
            os.remove(args.unix)
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if os.path.exists(args.unix):
        os.remove(args.unix)
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(args.unix)
    ls.listen(8)
    say(f"listening on {args.unix}; secret {'empty' if not secret else repr(args.secret)}; "
        f"respond={args.respond}; accepted codes {sorted(a.decode() for a in accept)}; delay={args.delay}")
    conns = [ls]
    while True:
        ready, _, _ = select.select(conns, [], [], args.idle)
        if not ready:
            say(f"idle {args.idle} s, exiting")
            return
        for c in ready:
            if c is ls:
                n, _ = ls.accept()
                conns.append(n)
                say("KDC connected")
                continue
            try:
                alive = handle(c, args, secret, accept)
            except OSError as e:
                say(f"connection error: {e}")
                alive = False
            if not alive:
                say("KDC closed its connection")
                conns.remove(c)
                c.close()


if __name__ == "__main__":
    main()
