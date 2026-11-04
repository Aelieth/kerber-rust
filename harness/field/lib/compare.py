#!/usr/bin/env python3
import argparse
import sys


def load_checks(path):
    rows = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            observed = parts[4] if len(parts) > 4 else ""
            rows[parts[0]] = (parts[1], observed)
    return rows


def load_known(path):
    known = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4 and parts[0] and parts[2] and parts[3]:
                known[parts[0]] = (parts[2], parts[3])
    return known


def grade(mit, rust, known):
    rows = []
    bad = False
    # A name on only one leg is that leg's own check. NOT-RUN is a status the scenario recorded.
    names = sorted(set(mit) & set(rust))
    for name in names:
        mit_status, mit_obs = mit[name]
        rust_status, rust_obs = rust[name]
        if mit_status == "NOT-RUN" or rust_status == "NOT-RUN":
            kind = "NOT-RUN"
            bad = True
        elif name in known:
            kind = "KNOWN"
        elif mit_status == "FAIL":
            kind = "ORACLE-FAIL"
            bad = True
        elif rust_status == "FAIL" and mit_status == "PASS":
            kind = "REGRESSION"
            bad = True
        elif mit_status == "PASS" and rust_status == "PASS" and mit_obs != rust_obs:
            kind = "DIVERGED"
        elif mit_status != rust_status:
            kind = "DIVERGED"
        else:
            continue
        rows.append((name, kind, mit_status, rust_status))
    return rows, bad


def main(argv):
    parser = argparse.ArgumentParser(description="grade a rust field leg against MIT")
    parser.add_argument("--expect", required=True)
    parser.add_argument("--mit", required=True)
    parser.add_argument("--rust", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    rows, bad = grade(load_checks(args.mit), load_checks(args.rust), load_known(args.expect))
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("# check\tgrade\tmit\trust\n")
        for name, kind, mit_status, rust_status in rows:
            fh.write("%s\t%s\t%s\t%s\n" % (name, kind, mit_status, rust_status))
            print("%s\t%s" % (name, kind))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
