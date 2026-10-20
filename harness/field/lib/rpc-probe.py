#!/usr/bin/env python3
"""rpc-probe.py HOST PORT PROG VERS: one ONC RPC call over TCP (RFC 5531), procedure 0 with AUTH_NONE, and its answer
on one line, `PROG/VERS on HOST:PORT: STATUS`: the accept_stat (SUCCESS, PROG_UNAVAIL, PROG_MISMATCH, ...), the
auth_stat of a refused call (AUTH_TOOWEAK, ...), RPC_MISMATCH, or why there is none (the connection's error, or
closed without an answer)."""
import os
import socket
import struct
import sys

ACCEPT = ["SUCCESS", "PROG_UNAVAIL", "PROG_MISMATCH", "PROC_UNAVAIL", "GARBAGE_ARGS", "SYSTEM_ERR"]
AUTH = ["AUTH_OK", "AUTH_BADCRED", "AUTH_REJECTEDCRED", "AUTH_BADVERF", "AUTH_REJECTEDVERF", "AUTH_TOOWEAK",
        "AUTH_INVALIDRESP", "AUTH_FAILED"]


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


def main():
    host, port, prog, vers = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    where = f"{prog}/{vers} on {host}:{port}"
    xid = int.from_bytes(os.urandom(4), "big")
    # xid, CALL, RPC version 2, program, version, procedure 0, AUTH_NONE credential and verifier
    call = struct.pack(">IIIIIIIIII", xid, 0, 2, prog, vers, 0, 0, 0, 0, 0)
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        print(f"{where}: {e.strerror or e}")
        return
    body = b""
    with s:
        s.sendall(struct.pack(">I", 0x80000000 | len(call)) + call)
        try:
            while True:
                (mark,) = struct.unpack(">I", recv_exact(s, 4))
                body += recv_exact(s, mark & 0x7FFFFFFF)
                if mark & 0x80000000:
                    break
        except (EOFError, OSError):
            print(f"{where}: closed without an answer")
            return
    (rstat,) = struct.unpack(">I", body[8:12])
    if rstat == 0:
        (vlen,) = struct.unpack(">I", body[16:20])
        off = 20 + ((vlen + 3) & ~3)
        (astat,) = struct.unpack(">I", body[off:off + 4])
        name = ACCEPT[astat] if astat < len(ACCEPT) else f"accept_stat {astat}"
    else:
        (reject,) = struct.unpack(">I", body[12:16])
        if reject == 0:
            name = "RPC_MISMATCH"
        else:
            (auth,) = struct.unpack(">I", body[16:20])
            name = AUTH[auth] if auth < len(AUTH) else f"auth_stat {auth}"
    print(f"{where}: {name}")


main()
