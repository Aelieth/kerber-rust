#!/usr/bin/env python3
"""Forged AUTH_GSSAPI GSSAPI_INIT against a kadmind (W1-Z Z1b.1).

One ONC RPC CALL on program 2112 v2, proc 1 (AUTH_GSSAPI_INIT), credential
flavor 300001 (`auth_gssapi_creds` version 2, `auth_msg` TRUE, empty client
handle), verifier AUTH_NONE, and an `authgssapi_init_arg` of VERSION plus an
empty token. The token never verifies, which `svc_auth_gssapi.c:452-463`
still answers with an `authgssapi_init_res`; the arg-version switch at
`:326-341` runs before the token is looked at.

    auth-gssapi-init-probe.py HOST:PORT VERSION

Prints one line:

    accepted version=<init_res.version> major=<gss_major>
    denied auth_stat=<n> <AUTH_BADCRED|AUTH_TOOWEAK|AUTH_FAILED|AUTH_n>
    eof

Exit 0 whenever a reply (or EOF) was observed; the caller asserts the text.
"""

import socket
import struct
import sys

AUTH_STAT = {1: "AUTH_BADCRED", 2: "AUTH_REJECTEDCRED", 3: "AUTH_BADVERF",
             4: "AUTH_REJECTEDVERF", 5: "AUTH_TOOWEAK", 7: "AUTH_FAILED"}


def u32(n):
    return struct.pack(">I", n)


def opaque(b):
    return u32(len(b)) + b + b"\x00" * ((4 - len(b) % 4) % 4)


def init_call(xid, version):
    cred = u32(2) + u32(1) + opaque(b"")  # creds vers 2, auth_msg TRUE, no handle
    body = u32(xid) + u32(0) + u32(2) + u32(2112) + u32(2) + u32(1)
    body += u32(300001) + opaque(cred) + u32(0) + opaque(b"")
    body += u32(version) + opaque(b"")
    return body


def exchange(host, port, body):
    s = socket.create_connection((host, port), 3)
    s.settimeout(3)
    s.sendall(u32(0x80000000 | len(body)) + body)
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c:
            return None
        hdr += c
    n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
    data = b""
    while len(data) < n:
        c = s.recv(n - len(data))
        if not c:
            break
        data += c
    return data


def words(b):
    n = len(b) // 4
    return list(struct.unpack(">" + "I" * n, b[: n * 4])) if n else []


def main():
    host, port = sys.argv[1].rsplit(":", 1)
    version = int(sys.argv[2])
    data = exchange(host, int(port), init_call(0x5a1b, version))
    if not data:
        print("eof")
        return 0
    w = words(data)
    # xid, MSG_REPLY, reply_stat
    if len(w) >= 5 and w[1] == 1 and w[2] == 1 and w[3] == 1:
        print("denied auth_stat=%d %s" % (w[4], AUTH_STAT.get(w[4], "AUTH_%d" % w[4])))
        return 0
    if len(w) >= 6 and w[1] == 1 and w[2] == 0:
        # verf flavor, verf opaque, accept_stat, then init_res: version, handle…
        i = 16  # past xid, MSG_REPLY, MSG_ACCEPTED, verf flavor
        vlen = struct.unpack(">I", data[i:i + 4])[0]
        i += 4 + vlen + ((4 - vlen % 4) % 4)
        stat = struct.unpack(">I", data[i:i + 4])[0]
        i += 4
        if stat != 0:
            print("accept_stat=%d" % stat)
            return 0
        res_ver = struct.unpack(">I", data[i:i + 4])[0]
        i += 4
        hlen = struct.unpack(">I", data[i:i + 4])[0]
        i += 4 + hlen + ((4 - hlen % 4) % 4)
        major = struct.unpack(">I", data[i:i + 4])[0]
        print("accepted version=%d major=0x%x" % (res_ver, major))
        return 0
    print("other %s" % ",".join(str(x) for x in w[:8]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
