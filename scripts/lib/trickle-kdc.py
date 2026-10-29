#!/usr/bin/env python3
"""A TCP server that answers any request with a bad reply: `PORT [trickle|badlen]`.

trickle: a long reply sent one byte a second. badlen: a kpasswd reply whose own length
field is one short of the frame.
"""
import socket
import struct
import sys
import time


def main():
    mode = sys.argv[2] if len(sys.argv) > 2 else "trickle"
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", int(sys.argv[1])))
    ls.listen(8)
    while True:
        c, _ = ls.accept()
        try:
            n = struct.unpack(">I", c.recv(4, socket.MSG_WAITALL))[0]
            c.recv(n, socket.MSG_WAITALL)
            if mode == "badlen":
                c.sendall(struct.pack(">I", 8) + struct.pack(">HHH", 7, 1, 0) + b"\x00\x00")
                continue
            c.sendall(struct.pack(">I", 600))
            for _ in range(600):
                time.sleep(1)
                c.sendall(b"\x00")
        except OSError:
            pass
        finally:
            c.close()


main()
