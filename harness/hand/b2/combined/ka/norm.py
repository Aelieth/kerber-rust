#!/usr/bin/env python3
"""norm.py MIT.txt OURS.txt: the two transcripts of one client's kadmin session with the dates masked; prints IDENTICAL, or a unified diff and
the count of differing lines. Exit 0 when identical, 1 when not."""
import difflib, re, sys
DATE = re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d+ \d\d:\d\d:\d\d \S+ \d{4}\b")
def norm(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace").read().splitlines():
        out.append(DATE.sub("<date>", line))
    return out
a, b = norm(sys.argv[1]), norm(sys.argv[2])
if a == b:
    print(f"IDENTICAL {len(a)} lines")
    sys.exit(0)
d = [l for l in difflib.unified_diff(a, b, "mit", "ours", lineterm="", n=1)]
print("\n".join(d))
print(f"DIFFERENT {sum(1 for l in d if l[:1] in '+-' and l[:3] not in ('+++', '---'))} lines")
sys.exit(1)
