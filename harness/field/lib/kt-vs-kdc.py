#!/usr/bin/env python3
"""kt-vs-kdc.py <klist -k -e output> <getprinc output>: a keytab's newest keys against the KDC's.

The first file is `klist -k -e <keytab>` (MIT's listing: `KVNO Principal (enctype)`), the second the
`kadmin.local -q "getprinc <principal>"` output for every principal the keytab names, one after another.
For each principal it compares the keytab's newest kvno and its enctypes with the KDC's `Key: vno N, <enctype>`
lines, and prints one line per principal, then a summary:

  host/client2@KERBER.TEST: keytab kvno 2 {aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96} = KDC kvno 2 {...}
  keytab-vs-kdc: 2 principals, all equal

Exit status 0 when every principal is equal, 1 when one differs or the KDC does not know it, 2 on bad input.
Only names and numbers are read: neither listing carries key material.
"""
import re
import sys

KT_LINE = re.compile(r"^\s*(\d+)\s+(\S+@\S+)\s+\(([^)]+)\)\s*$")
PRINC = re.compile(r"^Principal: (\S+)$")
KEY = re.compile(r"^Key: vno (\d+), (\S+)$")
MISSING = re.compile(r'while retrieving "([^"]+)"')


def keytab(path):
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = KT_LINE.match(line)
        if m:
            out.setdefault(m.group(2), {}).setdefault(int(m.group(1)), set()).add(m.group(3))
    return out


def kdc(path):
    out, missing, cur = {}, set(), None
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        m = PRINC.match(line)
        if m:
            cur = m.group(1)
            out[cur] = {}
            continue
        m = MISSING.search(line)
        if m:
            missing.add(m.group(1))
            continue
        m = KEY.match(line)
        if m and cur:
            out[cur].setdefault(int(m.group(1)), set()).add(m.group(2))
    return out, missing


def fmt(kv):
    vno = max(kv)
    return "kvno %d {%s}" % (vno, " ".join(sorted(kv[vno])))


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: kt-vs-kdc.py <klist -k -e output> <getprinc output>")
    kt = keytab(sys.argv[1])
    db, missing = kdc(sys.argv[2])
    if not kt:
        print("keytab-vs-kdc: the listing names no principal")
        return 2
    bad = 0
    for princ in sorted(kt):
        mine = fmt(kt[princ])
        if princ not in db or not db[princ]:
            why = "does not exist" if princ in missing else "no getprinc output"
            print("%s: keytab %s, KDC: %s" % (princ, mine, why))
            bad += 1
            continue
        theirs = fmt(db[princ])
        same = mine == theirs
        bad += 0 if same else 1
        print("%s: keytab %s %s KDC %s" % (princ, mine, "=" if same else "!=", theirs))
    n = len(kt)
    print("keytab-vs-kdc: %d principal%s, %s" % (n, "" if n == 1 else "s", "all equal" if bad == 0 else "%d differ" % bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
