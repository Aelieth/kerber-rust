#!/usr/bin/env python3
"""P18 tables.py <tag-prefix>...: the README's tables from results/wire.csv and results/calls/.

For each run prefix (e.g. A-, B-) and each (leg, N, KENV), it pools every call of every repetition
(results/calls/<tag>.csv) and prints, per write op, the median and p90 over the pooled calls, the
ratio ours / MIT of the medians, and n. Sessions are grouped by tag: <run>-N<N>-<leg>[-<variant>]-<rep>.
"""
import csv
import os
import re
import statistics
import sys

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
OPS = ["CREATE(pw)", "CREATE(rand)", "MODIFY_PRINCIPAL", "CHPASS_PRINCIPAL", "CHRAND_PRINCIPAL3",
       "DELETE_PRINCIPAL", "GET_PRINCIPAL"]
SHORT = {"CREATE(pw)": "CREATE pw", "CREATE(rand)": "CREATE rand", "MODIFY_PRINCIPAL": "MODIFY",
         "CHPASS_PRINCIPAL": "CHPASS", "CHRAND_PRINCIPAL3": "CHRAND3", "DELETE_PRINCIPAL": "DELETE",
         "GET_PRINCIPAL": "GET"}


def p90(v):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(0.9 * (len(v) - 1))))]


def load(prefixes):
    groups = {}
    for name in sorted(os.listdir(os.path.join(RES, "calls"))):
        tag = name[:-4]
        if not any(tag.startswith(p) for p in prefixes):
            continue
        m = re.match(r"^(\w+)-N(\d+)-(\w+?)(?:-([\w.]+))?-(\d+)$", tag)
        if not m:
            continue
        run, n, leg, variant, _rep = m.groups()
        key = (run, int(n), leg, variant or "")
        with open(os.path.join(RES, "calls", name)) as f:
            for row in csv.DictReader(f):
                groups.setdefault(key, {}).setdefault(row["op"], []).append(float(row["call_to_reply_ms"]))
    return groups


def main():
    prefixes = sys.argv[1:] or ["A-"]
    g = load(prefixes)
    for run in sorted({k[0] for k in g}):
        print(f"### run {run}")
        for variant in sorted({k[3] for k in g if k[0] == run}):
            ns = sorted({k[1] for k in g if k[0] == run and k[3] == variant})
            legs = sorted({k[2] for k in g if k[0] == run and k[3] == variant})
            print(f"variant '{variant or 'none'}': legs {legs}")
            hdr = f"{'op':<12}{'N':>6}" + "".join(f"{l + ' med':>11}{l + ' p90':>10}{'n':>5}" for l in legs)
            if "mit" in legs and len(legs) > 1:
                hdr += "".join(f"{l + '/mit':>10}" for l in legs if l != "mit")
            print(hdr)
            for op in OPS:
                for n in ns:
                    line = f"{SHORT[op]:<12}{n:>6}"
                    meds = {}
                    for l in legs:
                        v = g.get((run, n, l, variant), {}).get(op, [])
                        if v:
                            meds[l] = statistics.median(v)
                            line += f"{meds[l]:>11.1f}{p90(v):>10.1f}{len(v):>5}"
                        else:
                            line += f"{'-':>11}{'-':>10}{'-':>5}"
                    if "mit" in meds:
                        line += "".join(f"{meds[l] / meds['mit']:>10.1f}" if l in meds else f"{'-':>10}"
                                        for l in legs if l != "mit")
                    print(line)
            print()




def pooled(prefixes):
    """Every write call (CREATE, MODIFY, CHPASS, CHRAND, DELETE) pooled per (run, N, leg, variant)."""
    g = load(prefixes)
    writes = ["CREATE(pw)", "CREATE(rand)", "MODIFY_PRINCIPAL", "CHPASS_PRINCIPAL", "CHRAND_PRINCIPAL3",
              "DELETE_PRINCIPAL"]
    print(f"{'run':<4}{'variant':<12}{'N':>6}{'leg':>6}{'writes':>8}{'median':>9}{'p90':>9}")
    for key in sorted(g, key=lambda k: (k[0], k[3], k[1], k[2])):
        v = [x for op in writes for x in g[key].get(op, [])]
        if v:
            print(f"{key[0]:<4}{key[3] or '-':<12}{key[1]:>6}{key[2]:>6}{len(v):>8}{statistics.median(v):>9.1f}{p90(v):>9.1f}")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--pooled"]:
        pooled(sys.argv[2:] or ["A-"])
    else:
        main()
