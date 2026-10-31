#!/usr/bin/env python3
"""kt-records.py: keytab files as records, for client-tools.sh on client2. Never prints a key.

    kt-records.py unknown <out> <realm> <name>   a v2 keytab: <name>@<realm>, kvno 3, enctype 99, a zero key
    kt-records.py compare <a> <b>                the two files' versions and records, timestamps zeroed:
                                                 "records: N, the same but for the timestamps", else exit 1

The layout is MIT's (lib/krb5/keytab/kt_file.c): a 0x05 0x01 or 0x05 0x02 header, then each record's signed
length (a hole when negative); a v1 file is in host order, its component count includes the realm, and it has
no name type.
"""
import struct
import sys


def records(path):
    data = open(path, "rb").read()
    if len(data) < 2 or data[0] != 5 or data[1] not in (1, 2):
        sys.exit("%s: not a keytab (header %s)" % (path, data[:2].hex()))
    v1 = data[1] == 1
    o = "=" if v1 else ">"
    i, out = 2, []
    while i + 4 <= len(data):
        (n,) = struct.unpack(o + "i", data[i:i + 4])
        i += 4
        if n > 0:
            r = bytearray(data[i:i + n])
            (count,) = struct.unpack(o + "H", r[0:2])
            j = 2
            for _ in range(count + (0 if v1 else 1)):
                (size,) = struct.unpack(o + "H", r[j:j + 2])
                j += 2 + size
            if not v1:
                j += 4
            r[j:j + 4] = bytes(4)
            out.append(bytes(r))
        i += abs(n)
    return data[1], out


def unknown(path, realm, name):
    comps = [realm.encode(), name.encode()]
    rec = struct.pack(">H", len(comps) - 1) + b"".join(struct.pack(">H", len(c)) + c for c in comps)
    rec += struct.pack(">IIBHH", 1, 0, 3, 99, 16) + bytes(16)
    with open(path, "wb") as f:
        f.write(b"\x05\x02" + struct.pack(">i", len(rec)) + rec)
    print("%s: one entry, %s@%s, kvno 3, enctype 99" % (path, name, realm))


def compare(a, b):
    va, ra = records(a)
    vb, rb = records(b)
    if va == vb and ra == rb and ra:
        print("records: %d, the same but for the timestamps" % len(ra))
        return 0
    print("records differ: version %d / %d, %d / %d records, first differing record %s" % (
        va, vb, len(ra), len(rb), next((k for k, (x, y) in enumerate(zip(ra, rb)) if x != y), "none")))
    return 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["unknown"] and len(sys.argv) == 5:
        unknown(*sys.argv[2:])
    elif sys.argv[1:2] == ["compare"] and len(sys.argv) == 4:
        sys.exit(compare(*sys.argv[2:]))
    else:
        sys.exit(__doc__)
