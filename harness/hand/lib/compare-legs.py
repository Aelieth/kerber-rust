#!/usr/bin/env python3
"""compare-legs.py NEW.tsv PREFIX=BASELINE.tsv [PREFIX=BASELINE.tsv ...]: for each module prefix (a row-label prefix such as KI.) the rows of NEW against the same prefix's rows of the landed leg's results.tsv:
counts per status on both sides, and the labels whose status changed (PASS->FAIL is a REGRESSION, FAIL->PASS an improvement, INFO<->PASS/FAIL a kind change), the labels only in one side.
Run with python3 -I. Prints a report; exit 1 when a regression (a row PASS in the baseline and FAIL now) exists."""
import sys, collections, pathlib

def load(path, prefix):
    rows = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and p[0].startswith(prefix):
                rows[p[0]] = (p[1], p[2:] )
    return rows

def main(argv):
    new_path = argv[1]
    reg = 0
    for spec in argv[2:]:
        prefix, base_path = spec.split("=", 1)
        new, old = load(new_path, prefix), load(base_path, prefix)
        cn = collections.Counter(s for s, _ in new.values()); co = collections.Counter(s for s, _ in old.values())
        print("== %s   new %d rows (PASS %d / FAIL %d / INFO %d)   landed %d rows (PASS %d / FAIL %d / INFO %d)   [%s]" % (
            prefix, len(new), cn["PASS"], cn["FAIL"], cn["INFO"], len(old), co["PASS"], co["FAIL"], co["INFO"], base_path))
        regress, improve, kind = [], [], []
        for lab in sorted(set(new) & set(old)):
            a, b = old[lab][0], new[lab][0]
            if a == b:
                continue
            if a == "PASS" and b == "FAIL": regress.append(lab)
            elif a == "FAIL" and b == "PASS": improve.append(lab)
            else: kind.append((lab, a, b))
        only_new = sorted(set(new) - set(old)); only_old = sorted(set(old) - set(new))
        reds_new = sorted(l for l, (s, _) in new.items() if s == "FAIL"); reds_old = sorted(l for l, (s, _) in old.items() if s == "FAIL")
        print("   rows in both: %d; regressions (PASS -> FAIL): %d; improvements (FAIL -> PASS): %d; other status changes: %d; only in the new leg: %d; only in the landed leg: %d" % (
            len(set(new) & set(old)), len(regress), len(improve), len(kind), len(only_new), len(only_old)))
        expected = {}
        exp_path = pathlib.Path(__file__).with_name("expected-diff.txt")
        if exp_path.is_file():
            for line in exp_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line and not line.startswith("#"):
                    f = line.split("\t")
                    if f and f[0]:
                        expected[f[0]] = line
        exp_hits = [l for l in regress if l in expected]
        regress = [l for l in regress if l not in expected]
        for l in regress: print("   REGRESSION", l)
        for l in exp_hits: print("   EXPECTED_DIFF", expected[l])
        for lab, line in sorted(expected.items()):
            if lab not in exp_hits:
                print("   EXPECTED_DIFF", line)
        for l in improve: print("   improved  ", l)
        for l, a, b in kind: print("   changed   ", l, a, "->", b)
        for l in only_new[:60]: print("   only-new  ", l, new[l][0])
        if len(only_new) > 60: print("   only-new   ... %d more" % (len(only_new) - 60))
        for l in only_old[:60]: print("   only-old  ", l, old[l][0])
        if len(only_old) > 60: print("   only-old   ... %d more" % (len(only_old) - 60))
        print("   FAIL rows now: %s" % (", ".join(reds_new) if reds_new else "none"))
        print("   FAIL rows then: %s" % (", ".join(reds_old) if reds_old else "none"))
        reg += len(regress)
    return 1 if reg else 0

sys.exit(main(sys.argv))
