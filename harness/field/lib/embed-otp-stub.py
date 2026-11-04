"""TOTP RADIUS stub for the OV-3 MIT leg. Logs the verdict and the user name only."""
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

STEP = 30


def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def decode_password(secret, req_auth, hidden):
    out = b""
    prev = req_auth
    for i in range(0, len(hidden), 16):
        block = hidden[i:i + 16]
        pad = hashlib.md5(secret + prev).digest()
        out += bytes(a ^ b for a, b in zip(block, pad))
        prev = block
    return out.rstrip(b"\0")


def parse_attrs(buf):
    attrs, off = [], 0
    while off + 2 <= len(buf):
        typ, ln = buf[off], buf[off + 1]
        if ln < 2 or off + ln > len(buf):
            break
        attrs.append((typ, buf[off + 2:off + ln]))
        off += ln
    return attrs


def respond(code, ident, req_auth, secret):
    length = 20
    head = struct.pack("!BBH", code, ident, length)
    auth = hashlib.md5(head + req_auth + secret).digest()
    return head + auth


def hotp(seed, counter):
    digest = hmac.new(seed, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    window = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{window % 1000000:06d}"


def load_secret(path):
    raw = open(path, "rb").read().splitlines()[0].strip()
    body = raw.rstrip(b"=")
    acc = bits = 0
    out = bytearray()
    for c in body:
        if 65 <= c <= 90:
            val = c - 65
        elif 97 <= c <= 122:
            val = c - 97
        elif 50 <= c <= 55:
            val = c - 50 + 26
        else:
            raise SystemExit("seed alphabet")
        acc = (acc << 5) | val
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
            acc &= (1 << bits) - 1
    return bytes(out)


def main():
    sock_path, pw_path, seed_path, state_path = sys.argv[1:5]
    seed = load_secret(seed_path)
    if os.path.exists(sock_path):
        os.remove(sock_path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    os.chmod(sock_path, 0o666)
    listener.listen(8)
    say("stub listening")
    last = {}
    if os.path.exists(state_path):
        for line in open(state_path, encoding="utf-8"):
            parts = line.split()
            if len(parts) == 2:
                last[parts[0]] = int(parts[1])
    while True:
        conn, _ = listener.accept()
        try:
            hdr = conn.recv(4)
            if len(hdr) < 4:
                continue
            code, ident, length = struct.unpack("!BBH", hdr)
            rest = b""
            while len(rest) < length - 4:
                chunk = conn.recv(length - 4 - len(rest))
                if not chunk:
                    break
                rest += chunk
            req_auth, attrs = rest[:16], rest[16:]
            user = b""
            token = b""
            for typ, val in parse_attrs(attrs):
                if typ == 1:
                    user = val
                elif typ == 2:
                    token = decode_password(b"", req_auth, val)
            verdict = "reject"
            passwords = {}
            for line in open(pw_path, "rb").read().splitlines():
                if b" " not in line:
                    continue
                name, pw = line.split(b" ", 1)
                passwords[name] = pw
            if code == 1 and len(token) > 6 and token[-6:].isdigit():
                name = user.decode("utf-8", "replace")
                password = passwords.get(user) or passwords.get(name.split("@", 1)[0].encode())
                code_text = token[-6:].decode()
                if password is not None and hmac.compare_digest(token[:-6], password):
                    now = int(time.time()) // STEP
                    matched = None
                    for step in (now, now - 1, now + 1):
                        if hmac.compare_digest(hotp(seed, step), code_text):
                            matched = step
                            break
                    name = user.decode("utf-8", "replace")
                    if matched is not None and matched > last.get(name, 0):
                        last[name] = matched
                        verdict = "accept"
                        tmp = state_path + ".tmp"
                        with open(tmp, "w", encoding="utf-8") as fh:
                            for key, val in last.items():
                                fh.write(f"{key} {val}\n")
                        os.chmod(tmp, 0o600)
                        os.replace(tmp, state_path)
            pkt = respond(2 if verdict == "accept" else 3, ident, req_auth, b"")
            conn.sendall(pkt)
            say(f"verdict {verdict} user {user.decode('utf-8', 'replace')}")
        finally:
            conn.close()


if __name__ == "__main__":
    main()
