#!/usr/bin/env python3
"""rpc-probe.py HOST PORT PROG VERS [options]: one ONC RPC call over TCP (RFC 5531), by default procedure 0 with
AUTH_NONE, and its answer on one line, `PROG/VERS on HOST:PORT: STATUS`: the accept_stat (SUCCESS, PROG_UNAVAIL,
PROG_MISMATCH, ...), the auth_stat of a refused call (AUTH_TOOWEAK, ...), RPC_MISMATCH, or why there is none (the
connection's error, closed without an answer, or no answer within --wait seconds).

  --proc N       the procedure (default 0)
  --flavor N     the credential's flavor (default 0, AUTH_NONE)
  --cred SPEC    the credential's body: len:N (N zero bytes), or unix[:name=N][:gids=N] (an authunix_parms with
                 a machine name of N bytes, default 4, and N groups, default 0)
  --verf-len N   an AUTH_NONE verifier of N zero bytes (default 0)
  --then         then, on the same connection, procedure 0 of 2112/2 under AUTH_NONE: `...: STATUS; then: STATUS`
  --wait S       seconds to wait for each answer (default 10)
"""
import argparse
import os
import socket
import struct

ACCEPT = ["SUCCESS", "PROG_UNAVAIL", "PROG_MISMATCH", "PROC_UNAVAIL", "GARBAGE_ARGS", "SYSTEM_ERR"]
AUTH = ["AUTH_OK", "AUTH_BADCRED", "AUTH_REJECTEDCRED", "AUTH_BADVERF", "AUTH_REJECTEDVERF", "AUTH_TOOWEAK",
        "AUTH_INVALIDRESP", "AUTH_FAILED"]


def opaque(b):
    return struct.pack(">I", len(b)) + b + b"\0" * (-len(b) % 4)


def cred_body(spec):
    if spec is None:
        return b""
    kind, *opts = spec.split(":")
    if kind == "len":
        return b"\0" * int(opts[0])
    args = dict(o.split("=", 1) for o in opts)
    name = b"h" * int(args.get("name", 4))
    gids = int(args.get("gids", 0))
    # authunix_parms: stamp, machine name, uid, gid, groups (svc_auth_unix.c)
    return struct.pack(">I", 0) + opaque(name) + struct.pack(">II", 1000, 1000) + struct.pack(
        f">I{gids}I", gids, *range(gids))


def call(prog, vers, proc, flavor, cred, verf_len):
    xid = int.from_bytes(os.urandom(4), "big")
    head = struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc)
    msg = head + struct.pack(">I", flavor) + opaque(cred) + struct.pack(">I", 0) + opaque(b"\0" * verf_len)
    return struct.pack(">I", 0x80000000 | len(msg)) + msg


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


def answer(s):
    body = b""
    try:
        while True:
            (mark,) = struct.unpack(">I", recv_exact(s, 4))
            body += recv_exact(s, mark & 0x7FFFFFFF)
            if mark & 0x80000000:
                break
    except socket.timeout:
        return "no answer"
    except (EOFError, OSError):
        return "closed without an answer"
    (rstat,) = struct.unpack(">I", body[8:12])
    if rstat == 0:
        (vlen,) = struct.unpack(">I", body[16:20])
        off = 20 + ((vlen + 3) & ~3)
        (astat,) = struct.unpack(">I", body[off:off + 4])
        return ACCEPT[astat] if astat < len(ACCEPT) else f"accept_stat {astat}"
    (reject,) = struct.unpack(">I", body[12:16])
    if reject == 0:
        return "RPC_MISMATCH"
    (auth,) = struct.unpack(">I", body[16:20])
    return AUTH[auth] if auth < len(AUTH) else f"auth_stat {auth}"


def main():
    p = argparse.ArgumentParser(add_help=False)
    for a in ("host", "port", "prog", "vers"):
        p.add_argument(a)
    p.add_argument("--proc", type=int, default=0)
    p.add_argument("--flavor", type=int, default=0)
    p.add_argument("--cred")
    p.add_argument("--verf-len", type=int, default=0)
    p.add_argument("--then", action="store_true")
    p.add_argument("--wait", type=float, default=10)
    o = p.parse_args()
    where = f"{o.prog}/{o.vers} on {o.host}:{o.port}"
    try:
        s = socket.create_connection((o.host, int(o.port)), timeout=10)
    except OSError as e:
        print(f"{where}: {e.strerror or e}")
        return
    with s:
        s.settimeout(o.wait)
        s.sendall(call(int(o.prog), int(o.vers), o.proc, o.flavor, cred_body(o.cred), o.verf_len))
        line = f"{where}: {answer(s)}"
        if o.then:
            try:
                s.sendall(call(2112, 2, 0, 0, b"", 0))
                line += f"; then: {answer(s)}"
            except OSError:
                line += "; then: closed without an answer"
    print(line)


if __name__ == "__main__":
    main()
