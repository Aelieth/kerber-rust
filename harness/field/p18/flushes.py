#!/usr/bin/env python3
"""P18 flushes.py <prefix>...: per write call, the median flushes, directory flushes, renames and
file bytes from the per-call strace splits (results/strace/<tag>.csv, strace-split.py), and the
whole-workload syscall counts (results/strace/<tag>.count.txt)."""
import csv
import glob
import os
import re
import statistics
import sys

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "strace")
WRITES = {"CREATE(pw)", "CREATE(rand)", "MODIFY_PRINCIPAL", "CHPASS_PRINCIPAL", "CHRAND_PRINCIPAL3",
          "DELETE_PRINCIPAL"}
prefixes = sys.argv[1:] or ["F-"]
print("per write call, median over the session's 210 writes")
for p in sorted(glob.glob(os.path.join(RES, "*.csv"))):
    tag = os.path.basename(p)[:-4]
    if not any(tag.startswith(x) for x in prefixes):
        continue
    rows = [r for r in csv.DictReader(open(p)) if r.get("op") in WRITES]
    if not rows:
        continue
    keys = [k for k in rows[0] if k not in ("reply", "op")]
    med = {k: statistics.median(float(r[k]) for r in rows) for k in keys}
    print(f"  {tag:<24} n={len(rows):<4}" + " ".join(f"{k}={med[k]:g}" for k in keys))
print("whole workload (strace -f -c)")
for p in sorted(glob.glob(os.path.join(RES, "*.count.txt"))):
    tag = os.path.basename(p)[: -len(".count.txt")]
    if not any(tag.startswith(x) for x in prefixes):
        continue
    counts = {}
    for line in open(p):
        f = line.split()
        if len(f) >= 5 and re.fullmatch(r"[a-z_0-9]+", f[-1]) and f[3].isdigit():
            counts[f[-1]] = int(f[3])
    show = " ".join(f"{k}={counts.get(k, 0)}" for k in ("fsync", "fdatasync", "msync", "rename", "renameat",
                                                        "renameat2", "pwrite64", "lgetxattr"))
    print(f"  {tag:<24} {show}")
