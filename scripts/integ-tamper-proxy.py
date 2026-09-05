#!/usr/bin/env python3
"""Listen 1749, forward to 749, XOR last args byte of RPCSEC DATA (integrity checksum)."""
import socket
import struct
import threading


def u32(b, i):
    return struct.unpack(">I", b[i : i + 4])[0], i + 4


def skip_op(b, i):
    n, i = u32(b, i)
    return i + n + ((4 - n % 4) % 4)


def flip_data_args(body):
    if len(body) < 40:
        return body
    flavor, _ = u32(body, 24)
    if flavor != 6:
        return body
    clen, _ = u32(body, 28)
    if clen < 8:
        return body
    gc_proc, _ = u32(body, 36)
    if gc_proc != 0:
        return body
    i = 32 + clen + ((4 - clen % 4) % 4)
    if i + 8 > len(body):
        return body
    i += 4
    i = skip_op(body, i)
    if i >= len(body):
        return body
    args = bytearray(body[i:])
    j = len(args) - 1
    while j > 0 and args[j] == 0:
        j -= 1
    args[j] ^= 0xFF
    return bytes(body[:i]) + bytes(args)


def rec(s):
    h = s.recv(4)
    if len(h) < 4:
        return None
    n = struct.unpack(">I", h)[0]
    last, n = n & 0x80000000, n & 0x7FFFFFFF
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            return None
        b += c
    return last, b


def send(s, last, b):
    n = len(b) | (0x80000000 if last else 0)
    s.sendall(struct.pack(">I", n) + b)


def pipe(src, dst, tamper):
    try:
        while True:
            r = rec(src)
            if r is None:
                break
            last, body = r
            if tamper:
                body = flip_data_args(body)
            send(dst, last, body)
    except OSError:
        pass


def main():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 1749))
    ls.listen(1)
    c, _ = ls.accept()
    u = socket.create_connection(("127.0.0.1", 749))
    threading.Thread(target=pipe, args=(c, u, True), daemon=True).start()
    pipe(u, c, False)


if __name__ == "__main__":
    main()
