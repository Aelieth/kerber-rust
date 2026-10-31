#!/usr/bin/env python3
"""FILE ccache v4 header KDC time offset (tag 1): `show PATH` | `set PATH SECONDS`."""
import struct
import sys


def tag1(b):
    assert b[:2] == b"\x05\x04", b[:4].hex()
    end = 4 + struct.unpack(">H", b[2:4])[0]
    i = 4
    while i < end:
        tag, ln = struct.unpack(">HH", b[i : i + 4])
        if tag == 1:
            return i + 4
        i += 4 + ln
    sys.exit("no time offset tag in the ccache header")


def main():
    mode, path = sys.argv[1], sys.argv[2]
    b = open(path, "rb").read()
    at = tag1(b)
    if mode == "show":
        print(struct.unpack(">ii", b[at : at + 8])[0])
    else:
        b = b[:at] + struct.pack(">ii", int(sys.argv[3]), 0) + b[at + 8 :]
        open(path, "wb").write(b)


main()
