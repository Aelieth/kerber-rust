#!/usr/bin/env python3
"""bulk-dump.py IN OUT [N]: IN, a kdb5_util dump, with N more principals (250 unless given), as OUT.

Each new principal is a copy of IN's `user@REALM` record (else its first record that is no K/M,
krbtgt or kadmin principal), renamed `bulkNNNN@REALM` with the record's name-length field made
the new name's. The header, IN's records and its policies stay as they are and in order; the new
records follow the last principal record. `OUT.dump_ok` is made after OUT, as kdb5_util dump makes it.

kprop sends a dump in KRB-PRIV blocks of up to 32768 bytes and chains one cipher state through them,
so a dump that fits in one block shows nothing of how that state is chained; this one is several
blocks long, and loads as any MIT dump does."""
import os
import sys

NEW_NAME = "bulk%04d"

SID_TL = "19201"


def drop_sid_tl(fields):
    """Drop every tl-data triple of type 19201 and lower n_tl_data. Other fields stay."""
    n = int(fields[3])
    start = 15
    end = start + 3 * n
    if end > len(fields):
        sys.stderr.write("bulk-dump: n_tl_data %s does not fit the record%s" % (n, chr(10)))
        raise SystemExit(1)
    kept = []
    dropped = 0
    i = start
    for _ in range(n):
        ty, ln, contents = fields[i], fields[i + 1], fields[i + 2]
        i += 3
        if ty == SID_TL:
            dropped += 1
        else:
            kept.extend((ty, ln, contents))
    if dropped == 0:
        return fields
    out = list(fields[:start]) + kept + list(fields[end:])
    out[3] = str(n - dropped)
    return out




def main() -> int:
    if len(sys.argv) not in (3, 4):
        sys.stderr.write(__doc__ + "\n")
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) == 4 else 250
    with open(src, encoding="utf-8") as f:
        lines = f.read().split("\n")
    princ = [i for i, l in enumerate(lines) if l.startswith("princ\t")]
    if not princ:
        sys.stderr.write("bulk-dump: no principal record in %s\n" % src)
        return 1

    def name_of(i: int) -> str:
        return lines[i].split("\t")[6]

    plain = [i for i in princ if not name_of(i).split("@")[0].startswith(("K/M", "krbtgt", "kadmin"))]
    users = [i for i in plain if name_of(i).startswith("user@")]
    pick = (users or plain or princ)[0]
    fields = lines[pick].split("\t")
    realm = fields[6].split("@", 1)[1]
    clones = []
    for n in range(1, count + 1):
        name = (NEW_NAME % n) + "@" + realm
        f = list(fields)
        f[2] = str(len(name))
        f[6] = name
        f = drop_sid_tl(f)
        clones.append("\t".join(f))
    last = princ[-1]
    out = lines[: last + 1] + clones + lines[last + 1 :]
    tmp = dst + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    os.replace(tmp, dst)
    with open(dst + ".dump_ok", "w", encoding="utf-8") as f:
        f.write("\0")
    return 0


sys.exit(main())
