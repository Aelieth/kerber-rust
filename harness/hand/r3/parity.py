#!/usr/bin/env python3
"""parity.py OUTDIR [CELL...]: MIT stage against ours stage, cell by cell, from the cells' checks.tsv (the RA-only re-run of hold C; CELL defaults to ra).

For each cell, the checks of <cell>-mit and <cell>-ours are paired by name:
  - the result (PASS / FAIL / INFO) of both;
  - the observed text of both, with the volatile parts (clock times, dates, pids, ports, sequence numbers, authtimes) masked;
  - a verdict: same, KNOWN (a divergence the records already explain, with its reason), or DIFFERS (unexplained: a finding to classify).
A check that passes on MIT and fails on ours is a REGRESSION candidate; one that fails on both is a cell or lab problem; one that fails on MIT only
is an oracle problem. Nothing here reads a secret: it reads the already-redacted checks.tsv files. Exit status 0 always (the verdicts are the output).
"""
import csv
import re
import sys
from pathlib import Path

# Divergences the 1.1 records already explain: (check-name regex, reason). The sizes differ because our tickets carry a PAC where MIT's db2 ones carry the
# short {10,16,6,7,19} set (L2-rust F2); RA-F2 is AD's error code for a PAC-carrying referral.
KNOWN = [
    (r"^r3\.3\.cache-bytes$", "size: the authorization data in our TGT differs from MIT's (decision 5: our PAC set); an INFO row"),
    (r"^r3\.4a\.trace-tgs-(req|rep)-bytes$", "size: the authorization data in the tickets differs between our KDC and MIT's (decision 5: our PAC set); an INFO row"),
    (r"^r3\.5\.far-cache-bytes$", "size: the delegated cache differs because the tickets' authorization data differs (decision 5); an INFO row"),
    (r"^r3\.cap\.", "wire facts: sizes carry the PAC; fragments/transport are asserted by the checks themselves"),
    (r"^ra\.0\.testA\.tgs-bytes$", "PAC: our request carrying AD's PAC-bearing referral is larger"),
    (r"^ra\.0\.testB1\.ad-error$", "RA-F2: AD refuses our PAC-carrying referral TGT with KDC_ERR_POLICY (12) where MIT's gets KRB_ERR_GENERIC (60)"),
    (r"^ra\.3\.(lan-fragments|dc-tgs-req-transport|reply-source-lan)$", "reply size/fragmentation: our reply carries the PAC (MIT 956 B, ours about 1.7 kB, fragmented on the LAN NIC)"),
    (r"^ra\.0\.kdc-log-testA$", "log line: etype set/authtime masked; equal text expected"),
    (r"^r3\.6b\.client2-avc-(list|count)$", "cumulative since the client's boot: the ours stage also holds the MIT stage's records (the same sshd_session_t permissive krb5cc create/setattr/write-open types)"),
]

MASKS = [
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "HH:MM:SS"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?\b"), "DATE"),
    (re.compile(r"\b\d{2}/\d{2}/\d{4}\b"), "DATE"),
    (re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d+\b"), "MON D"),
    (re.compile(r"\b\d{2}:\d{2}\b"), "HH:MM"),
    (re.compile(r"\bport \d+\b"), "port N"),
    (re.compile(r"\[\d+\]"), "[N]"),
    (re.compile(r"\bpid[= ]\d+\b"), "pid N"),
    (re.compile(r"\bauthtime \d+\b"), "authtime N"),
    (re.compile(r"\bseqnum \d+\b"), "seqnum N"),
    (re.compile(r"\b1[0-9]{9}(?:\.[0-9]+)?\b"), "EPOCH"),
    (re.compile(r"\b[0-9a-f]{12,}\b"), "HEX"),
    (re.compile(r"\bmarks: \d+ \d+\b"), "marks: N N"),                       # the length of the kdc's two logs: activity, not behaviour
    (re.compile(r"\bpackets \d+ bytes \d+\b"), "packets N bytes N"),          # nft counters
    (re.compile(r"(ip=::ffff:\d+\.\d+\.\d+\.\d+):\d+"), r"\1:PORT"),        # the client's source port in the DC's event lines
]


def mask(text: str) -> str:
    for rx, rep in MASKS:
        text = rx.sub(rep, text)
    return re.sub(r"\s+", " ", text).strip()


def load(path: Path):
    rows = {}
    order = []
    if not path.exists():
        return rows, order
    with path.open(newline="") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            name, result, expect, rc, observed = parts[:5]
            if name not in rows:
                order.append(name)
            rows[name] = (result, observed)
    return rows, order


def known_reason(name: str):
    for rx, why in KNOWN:
        if re.search(rx, name):
            return why
    return None


def compare(out: Path, cell: str):
    mit, mo = load(out / f"{cell}-mit" / "checks.tsv")
    ours, oo = load(out / f"{cell}-ours" / "checks.tsv")
    names = list(mo) + [n for n in oo if n not in mit]
    counts = {"same": 0, "known": 0, "differs": 0, "regression": 0, "both-fail": 0, "mit-only-fail": 0, "missing": 0}
    lines = []
    for n in names:
        a, b = mit.get(n), ours.get(n)
        if a is None or b is None:
            counts["missing"] += 1
            lines.append(f"MISSING     {n}: mit={a[0] if a else '-'} ours={b[0] if b else '-'}")
            continue
        (ra, oa), (rb, ob) = a, b
        ma, mb = mask(oa), mask(ob)
        why = known_reason(n)
        if ra == "PASS" and rb == "FAIL":
            counts["regression"] += 1
            lines.append(f"REGRESSION? {n}: MIT PASS, ours FAIL\n              mit : {oa[:160]}\n              ours: {ob[:160]}")
        elif ra == "FAIL" and rb == "FAIL":
            counts["both-fail"] += 1
            lines.append(f"BOTH-FAIL   {n}: {oa[:100]} | {ob[:100]}")
        elif ra == "FAIL" and rb == "PASS":
            counts["mit-only-fail"] += 1
            lines.append(f"MIT-FAIL    {n}: MIT FAIL ({oa[:100]}), ours PASS")
        elif ma == mb:
            counts["same"] += 1
        elif why:
            counts["known"] += 1
            lines.append(f"KNOWN       {n}: {why}\n              mit : {oa[:160]}\n              ours: {ob[:160]}")
        else:
            counts["differs"] += 1
            lines.append(f"DIFFERS     {n} ({ra}/{rb})\n              mit : {oa[:200]}\n              ours: {ob[:200]}")
    return counts, lines, len(mit), len(ours)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: parity.py OUTDIR [CELL...]")
    out = Path(sys.argv[1])
    cells = sys.argv[2:] or ["ra"]
    print("PARITY: the MIT stage against the ours stage (cells " + " and ".join(cells) + "); texts compared after masking times, dates, pids, ports, sequence numbers and authtimes")
    print("verdicts: same | KNOWN (explained by the records) | DIFFERS (unexplained) | REGRESSION? (MIT PASS, ours FAIL) | BOTH-FAIL | MIT-FAIL | MISSING")
    total = {}
    for stage in ("mit", "ours"):
        down = out / f"ra-{stage}" / "dc-down"
        if down.exists():
            print(f"\nra-{stage}: NOT RUN (the Windows side was unusable: {down.read_text().strip()}); see ra-{stage}/record.txt for the exact refusal")
    for cell in cells:
        counts, lines, nm, no = compare(out, cell)
        print(f"\n== {cell}: {nm} checks on MIT, {no} on ours")
        print("   " + ", ".join(f"{k}={v}" for k, v in counts.items()))
        for ln in lines:
            print(ln)
        for k, v in counts.items():
            total[k] = total.get(k, 0) + v
    print("\n== total: " + ", ".join(f"{k}={v}" for k, v in total.items()))


if __name__ == "__main__":
    main()
