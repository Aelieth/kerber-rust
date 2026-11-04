#!/usr/bin/env python3
"""P18 analyze.py <session-dir>...: per-call times of one or more P18 sessions.

For each session (a copy of the VM's /srv/p18/out/<TAG>):
  - wire: tshark matches each kadm5 reply to its call by xid (`rpc.time`, call -> reply on the
    loopback capture). The first M CREATE_PRINCIPAL calls are `addprinc -pw`, the next M
    `addprinc -randkey` (the workload's order), shown as CREATE(pw) / CREATE(rand).
  - server log stamps: MIT's kadmind.log and ours carry 1 s stamps (MIT's format), so for each op
    they give the span from its first to its last request; ours also writes JSON on stdout with
    microsecond stamps, where each change is one `reload store` .. `saved store` pair.
  - probe lines (variant, P18_PROBE=1): the phase times of each change, by op.
Prints a block per session and appends rows to results/wire.csv (tag, leg, N, M, KENV, op, n,
median, p90, mean, min, max in ms).
"""
import csv
import datetime as dt
import json
import os
import re
import statistics
import subprocess
import sys

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
ORDER = ["INIT", "GET_POLICY", "CREATE(pw)", "CREATE(rand)", "MODIFY_PRINCIPAL", "CHPASS_PRINCIPAL",
         "CHRAND_PRINCIPAL3", "CHRAND_PRINCIPAL", "GET_PRINCIPAL", "DELETE_PRINCIPAL"]
WRITE_LOG = {"kadm5_create_principal": "CREATE", "kadm5_modify_principal": "MODIFY_PRINCIPAL",
             "kadm5_chpass_principal": "CHPASS_PRINCIPAL", "kadm5_randkey_principal": "CHRAND",
             "kadm5_delete_principal": "DELETE_PRINCIPAL"}


def q(vals):
    v = sorted(vals)
    n = len(v)
    p90 = v[min(n - 1, int(round(0.9 * (n - 1))))]
    return n, statistics.median(v), p90, statistics.fmean(v), v[0], v[-1]


def summary(d):
    meta = {}
    with open(os.path.join(d, "summary.txt")) as f:
        first = f.readline()
        for m in re.finditer(r"(\w+)=('[^']*'|\S+)", first):
            meta[m.group(1)] = m.group(2).strip("'")
        rest = f.read()
    m = re.search(r"workload done in ([0-9.]+) s", rest)
    meta["workload_s"] = float(m.group(1)) if m else float("nan")
    meta["probe"] = [ln.strip() for ln in rest.splitlines() if ln.startswith(("before:", "after:"))]
    meta["kadmin"] = next((ln.strip() for ln in rest.splitlines() if ln.startswith("kadmin:")), "")
    return meta


def wire(d, m):
    out = subprocess.run(
        ["tshark", "-r", os.path.join(d, "wire.pcap"), "-d", "tcp.port==18749,rpc", "-Y",
         "rpc.msgtyp == 1 && rpc.program == 2112", "-T", "fields", "-E", "separator=|",
         "-e", "rpc.time", "-e", "_ws.col.Info"],
        capture_output=True, text=True, check=True).stdout
    per = {}
    rows = []
    creates = 0
    for line in out.splitlines():
        t, info = line.split("|", 1)
        proc = info.split()[1]
        if proc == "CREATE_PRINCIPAL":
            proc = "CREATE(pw)" if creates < m else "CREATE(rand)"
            creates += 1
        per.setdefault(proc, []).append(float(t) * 1000)
        rows.append((len(rows) + 1, proc, f"{float(t) * 1000:.3f}"))
    os.makedirs(os.path.join(RESULTS, "calls"), exist_ok=True)
    with open(os.path.join(RESULTS, "calls", os.path.basename(d) + ".csv"), "w", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(["reply", "op", "call_to_reply_ms"])
        cw.writerows(rows)
    return per


def log_spans(d):
    """Per write op from kadmind.log: count, first and last stamp (1 s resolution)."""
    spans = {}
    p = os.path.join(d, "kadmind.log")
    if not os.path.exists(p):
        return spans
    for line in open(p, errors="replace"):
        m = re.match(r"(\w{3} \d{2} \d{2}:\d{2}:\d{2}) .*Request: (kadm5_\w+), ", line)
        if not m:
            continue
        op = m.group(2)
        ts = dt.datetime.strptime("2026 " + m.group(1), "%Y %b %d %H:%M:%S")
        s = spans.setdefault(op, [0, ts, ts])
        s[0] += 1
        s[2] = ts
    return spans


def json_changes(d):
    """Ours: each change's reload store -> saved store span (ms), labelled by kadmind.log's order."""
    p = os.path.join(d, "kadmind.stdout")
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return {}
    ops = []
    for line in open(os.path.join(d, "kadmind.log"), errors="replace"):
        m = re.search(r"Request: (kadm5_\w+), \S+, success", line)
        if m and m.group(1) in WRITE_LOG:
            ops.append(WRITE_LOG[m.group(1)])
    spans, start = [], None
    for line in open(p):
        try:
            j = json.loads(line)
        except ValueError:
            continue
        detail = j.get("fields", {}).get("detail")
        ts = dt.datetime.fromisoformat(j["timestamp"].replace("Z", "+00:00"))
        if detail == "reload store":
            start = ts
        elif detail == "saved store" and start is not None:
            spans.append((ts - start).total_seconds() * 1000)
            start = None
    per = {}
    for op, s in zip(ops, spans):
        per.setdefault(op, []).append(s)
    return per


def probes(d):
    """Variant with P18_PROBE: per change, the phase times (ms) by op (kadmind.log's order)."""
    p = os.path.join(d, "kadmind.stderr")
    if not os.path.exists(p):
        return None
    ops = []
    for line in open(os.path.join(d, "kadmind.log"), errors="replace"):
        m = re.search(r"Request: (kadm5_\w+), \S+, success", line)
        if m and m.group(1) in WRITE_LOG:
            ops.append(WRITE_LOG[m.group(1)])
    changes, cur = [], {}
    for line in open(p, errors="replace"):
        if not line.startswith("P18PROBE "):
            continue
        kind = line.split()[1]
        kv = dict(x.split("=", 1) for x in line.split()[2:] if "=" in x)
        if kind == "file":
            name = kv["name"]
            for k in ("create_us", "write_us", "fsync_us", "rename_us", "dirsync_us"):
                cur[f"{name}.{k}"] = int(kv[k])
            cur[f"{name}.bytes"] = int(kv["bytes"])
        elif kind == "change":
            for k, v in kv.items():
                if k.endswith("_us") or k == "princs":
                    cur[f"change.{k}"] = int(v)
            changes.append(cur)
            cur = {}
        else:
            for k, v in kv.items():
                if k.endswith("_us") or k.endswith("_bytes"):
                    cur[f"{kind}.{k}"] = int(v)
    if not changes:
        return None
    per = {}
    for op, c in zip(ops, changes):
        per.setdefault(op, []).append(c)
    return per


def main():
    os.makedirs(RESULTS, exist_ok=True)
    csv_path = os.path.join(RESULTS, "wire.csv")
    new = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as cf:
        w = csv.writer(cf)
        if new:
            w.writerow(["tag", "leg", "N", "M", "KENV", "op", "n", "median_ms", "p90_ms", "mean_ms",
                        "min_ms", "max_ms"])
        for d in sys.argv[1:]:
            d = d.rstrip("/")
            tag = os.path.basename(d)
            meta = summary(d)
            m = int(meta.get("M", 30))
            print(f"== {tag}: leg={meta.get('leg')} N={meta.get('N')} M={m} KENV='{meta.get('KENV', '')}' "
                  f"TRACE={meta.get('TRACE')} | workload {meta['workload_s']:.2f} s")
            print(f"   {meta['kadmin']}")
            for p in meta["probe"]:
                print(f"   {p}")
            per = wire(d, m)
            print(f"   {'wire call->reply (ms)':<22}{'n':>4}{'median':>9}{'p90':>9}{'mean':>9}{'min':>9}{'max':>9}")
            for op in ORDER + sorted(set(per) - set(ORDER)):
                if op not in per:
                    continue
                n, med, p90, mean, lo, hi = q(per[op])
                print(f"   {op:<22}{n:>4}{med:>9.2f}{p90:>9.2f}{mean:>9.2f}{lo:>9.2f}{hi:>9.2f}")
                w.writerow([tag, meta.get("leg"), meta.get("N"), m, meta.get("KENV", ""), op, n,
                            f"{med:.3f}", f"{p90:.3f}", f"{mean:.3f}", f"{lo:.3f}", f"{hi:.3f}"])
            spans = log_spans(d)
            if spans:
                parts = []
                for op, (n, a, b) in spans.items():
                    if op in ("kadm5_init", "kadm5_get_policy", "kadm5_get_principal"):
                        continue
                    parts.append(f"{op.replace('kadm5_', '')} {n} in {(b - a).total_seconds():.0f} s")
                print("   kadmind.log stamps (1 s): " + "; ".join(parts))
            js = json_changes(d)
            if js:
                parts = []
                for op, v in js.items():
                    n, med, p90, *_ = q(v)
                    parts.append(f"{op} n={n} med {med:.2f} p90 {p90:.2f}")
                print("   JSON stamps reload->saved (ms): " + "; ".join(parts))
            pr = probes(d)
            if pr:
                for op, cs in pr.items():
                    keys = sorted({k for c in cs for k in c})
                    med = {k: statistics.median([c.get(k, 0) for c in cs]) for k in keys}
                    show = " ".join(f"{k}={med[k] / 1000:.2f}" if k.endswith("_us") else f"{k}={med[k]:.0f}"
                                    for k in keys)
                    print(f"   probe medians {op} (n={len(cs)}; ms): {show}")
            print()


if __name__ == "__main__":
    main()
