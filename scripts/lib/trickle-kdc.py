#!/usr/bin/env python3
"""A TCP server that answers any request with a long reply sent one byte a second: `PORT`."""
import socket
import struct
import sys
import time


def main():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", int(sys.argv[1])))
    ls.listen(8)
    while True:
        c, _ = ls.accept()
        try:
            n = struct.unpack(">I", c.recv(4, socket.MSG_WAITALL))[0]
            c.recv(n, socket.MSG_WAITALL)
            c.sendall(struct.pack(">I", 600))
            for _ in range(600):
                time.sleep(1)
                c.sendall(b"\x00")
        except OSError:
            pass
        finally:
            c.close()


main()
