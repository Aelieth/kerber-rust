#!/usr/bin/env python3
"""norm.py FILE: a lab cell's CLIENT-side transcript (up to '# end of cell output'), with what must differ between runs removed:
pids, epoch stamps, byte counts, ccache names, MEMORY ccache ids, the KDC's cookie bytes, the encrypted timestamp's time, ticket times.
What is left is the sequence of events the MIT client saw. Nothing else is normalized: whatever still differs is listed by parity.sh."""
import re
import sys

out = []
for line in open(sys.argv[1], errors="replace"):
    line = line.rstrip("\n")
    if line.startswith("# end of cell output"):
        break
    if line.startswith("# cell ") or line.startswith("# stdin") or line.startswith("# $"):
        continue
    line = re.sub(r"^\[\d+\] \d+\.\d+: ", "", line)
    line = re.sub(r"\(\d+ bytes\)", "(N bytes)", line)
    line = re.sub(r"/(mit|ours)-[A-Za-z0-9_.-]+\.cc", "/STAGE-CC", line)
    line = re.sub(r"/armor-(mit|ours)\.cc", "/STAGE-ARMOR", line)
    line = re.sub(r"MEMORY:\w+", "MEMORY:ID", line)
    line = re.sub(r"Received cookie: .*", "Received cookie: <opaque>", line)
    line = re.sub(r"\(for [0-9.]+\)", "(for T)", line)
    line = re.sub(r"\d\d/\d\d/\d{2,4} \d\d:\d\d:\d\d", "<time>", line)
    out.append(line)
print("\n".join(out))
