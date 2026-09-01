#!/usr/bin/env python3
"""Probe a running sssd-kcm for RETRIEVE / GET_CRED_LIST / REPLACE.

Talks the MIT unix-socket KCM framing (cc_kcm.c): write is 4-byte length
plus payload; read is 4-byte length, 4-byte status, then that many bytes
which themselves start with a 4-byte status. Prints NVRs from the
environment and a yes/no per opcode. Exit 0 only when the socket answers.
"""
from __future__ import annotations

import os
import socket
import struct
import sys

SOCK = os.environ.get("KCM_SOCKET", "/run/.heim_org.h5l.kcm-socket")

KCM_OP_GEN_NEW = 3
KCM_OP_GET_DEFAULT_CACHE = 20
KCM_OP_RETRIEVE = 7
KCM_OP_GET_CRED_LIST = 13001
KCM_OP_REPLACE = 13002

# MIT com_err krb5 table (signed 32-bit on the wire).
CODES = {
    0: "ok",
    -1765328137: "KRB5_CC_NOSUPP",
    -1765328183: "KRB5_CC_IO",
    -1765328188: "KRB5_FCC_INTERNAL",
    -1765328189: "KRB5_FCC_NOFILE",
    -1765328242: "KRB5_CC_END",
    -1765328243: "KRB5_CC_NOTFOUND",
}


def _i32(u: int) -> int:
    return u - 0x100000000 if u >= 0x80000000 else u


def _code_name(c: int) -> str:
    return CODES.get(c, f"krb5_{c}")


def kcm_call(sock: socket.socket, payload: bytes) -> tuple[int, bytes]:
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    hdr = _readn(sock, 8)
    n, outer = struct.unpack(">II", hdr)
    outer_s = _i32(outer)
    if outer_s != 0:
        return outer_s, b""
    body = _readn(sock, n) if n else b""
    if len(body) < 4:
        return 0, body
    inner = _i32(struct.unpack(">I", body[:4])[0])
    return inner, body[4:]


def _readn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("kcm socket closed")
        buf += chunk
    return buf


def req(opcode: int, rest: bytes = b"") -> bytes:
    return bytes([2, 0]) + struct.pack(">H", opcode) + rest


def _data(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _princ(realm: str, *comps: str, ntype: int = 1) -> bytes:
    out = struct.pack(">iI", ntype, len(comps)) + _data(realm.encode())
    for c in comps:
        out += _data(c.encode())
    return out


def classify(code: int) -> str:
    if code == 0:
        return "yes"
    name = _code_name(code)
    if name in {"KRB5_CC_NOSUPP", "KRB5_FCC_INTERNAL"}:
        return "no"
    if name == "KRB5_CC_IO":
        return "unknown"
    # Implemented but empty/missing cache still counts as the opcode exists.
    if name in {"KRB5_FCC_NOFILE", "KRB5_CC_END", "KRB5_CC_NOTFOUND"}:
        return "yes"
    return f"other:{name}"


def main() -> int:
    nvr_krb5 = os.environ.get("KCM_KRB5_NVR", "")
    nvr_kcm = os.environ.get("KCM_SSSD_NVR", "")
    fedora = os.environ.get("KCM_FEDORA", "")
    digest = os.environ.get("KCM_DIGEST", "")
    print(f"fedora={fedora}")
    print(f"digest={digest}")
    print(f"krb5-libs={nvr_krb5}")
    print(f"sssd-kcm={nvr_kcm}")
    print(f"socket={SOCK}")
    if not os.path.exists(SOCK):
        print("error=kcm socket missing (daemon not listening)", file=sys.stderr)
        return 1
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(SOCK)
    code, body = kcm_call(s, req(KCM_OP_GET_DEFAULT_CACHE))
    print(f"GET_DEFAULT_CACHE code={code} name={_code_name(code)} body={body!r}")
    if code != 0:
        print("error=sssd-kcm not answering GET_DEFAULT_CACHE", file=sys.stderr)
        return 1
    code, nameb = kcm_call(s, req(KCM_OP_GEN_NEW))
    print(f"GEN_NEW code={code} name={_code_name(code)} body={nameb!r}")
    cname = nameb.split(b"\0", 1)[0] + b"\0" if code == 0 and nameb else b"0\0"
    princ = _princ("KERBER.TEST", "user")
    icode, _ = kcm_call(s, req(4, cname + princ))  # INITIALIZE
    print(f"INITIALIZE code={icode} name={_code_name(icode)}")
    probes = (
        ("RETRIEVE", KCM_OP_RETRIEVE, cname + struct.pack(">I", 1) + princ),
        ("GET_CRED_LIST", KCM_OP_GET_CRED_LIST, cname),
        (
            "REPLACE",
            KCM_OP_REPLACE,
            cname + struct.pack(">I", 0) + princ + struct.pack(">I", 0),
        ),
    )
    answers = {}
    for label, op, rest in probes:
        c, b = kcm_call(s, req(op, rest))
        ans = classify(c)
        answers[label] = ans
        print(f"{label} opcode={op} code={c} name={_code_name(c)} impl={ans} body_len={len(b)}")
    s.close()
    for label in ("RETRIEVE", "GET_CRED_LIST", "REPLACE"):
        print(f"{label}={answers[label]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
