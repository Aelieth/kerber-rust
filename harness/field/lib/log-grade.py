#!/usr/bin/env python3
"""log-grade.py <run dir>: the log grader over a field run's records (goal.txt's log analysis), MIT's leg first.

run.sh leaves, after each scenario's leg, <scenario>/<leg>/logs/: kdc's krb5kdc.log and kadmind.log, its Kerberos
units' journal since the scenario began (units.txt; ours' JSON events, `json = STDERR` from upgrade), and window
(start, end, kdc's UTC offset). A daemon log line counts for the scenario its time falls in. Checks, written to
<run>/log-grade/{checks.tsv,record.txt,result}:
  LG.records       each leg left daemon log lines;
  LG.panic         no panic in any raw line of ours' daemon logs or units' journal;
  LG.unread        no unmatched daemon line or unparsed JSON line of ours holds panic or an error level;
  LG.correlated    at least one kdc.issue event, each with a correlation_id (per line; docs/logging.md);
  LG.errors        every (Error) or worse line of ours matches, masked (addresses, principals, hex, numbers),
                   one of MIT's in the same scenario or an allow rule (log-grade.allow: prog<TAB>ERE<TAB>reason).
Exit 0 when every check passes, 1 otherwise, 2 on a usage error.
"""
import datetime
import json
import os
import re
import sys

LINE = re.compile(r"^(\w{3}) ([ \d]\d) (\d\d:\d\d:\d\d) \S+ ([\w.-]+)\[\d+\]\((\w+)\): (.*)$")
SEVERE = {"error", "critical", "alert", "emergency"}
SLACK = 60
HERE = os.path.dirname(os.path.abspath(__file__))


def windows(run, leg):
    """(log dir, start, end, tzinfo) for each scenario that left logs on this leg."""
    out = []
    for sc in sorted(os.listdir(run)):
        d = os.path.join(run, sc, leg, "logs")
        try:
            with open(os.path.join(d, "window")) as f:
                parts = f.read().split()
        except OSError:
            continue
        if len(parts) < 2 or not (parts[0].isdigit() and parts[1].isdigit()):
            continue
        off = parts[2] if len(parts) > 2 and re.fullmatch(r"[+-]\d{4}", parts[2]) else "+0000"
        mins = int(off[1:3]) * 60 + int(off[3:5])
        tz = datetime.timezone(datetime.timedelta(minutes=mins if off[0] == "+" else -mins))
        out.append((d, int(parts[0]), int(parts[1]), tz))
    return out


def stamp(mon, day, hms, year, tz, t0):
    """Epoch of the line's stamp, in the year nearest the window start."""
    best = None
    for y in (year, year - 1, year + 1):
        try:
            t = datetime.datetime.strptime(f"{y} {mon} {day.strip()} {hms}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        t = t.replace(tzinfo=tz).timestamp()
        if best is None or abs(t - t0) < abs(best - t0):
            best = t
    return best


def leg_lines(run, leg):
    """(rows, units, raws, loose): daemon rows (scenario, prog, level, message, raw) inside a window, once;
    units' (scenario, line)s; every raw daemon line; the daemon lines that match no log format."""
    seen, rows, units, raws, loose = set(), [], [], [], []
    for d, t0, t1, tz in windows(run, leg):
        sc = os.path.basename(os.path.dirname(os.path.dirname(d)))
        year = datetime.datetime.fromtimestamp(t0, datetime.timezone.utc).year
        for name in ("krb5kdc.log", "kadmind.log"):
            try:
                with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for raw in text.splitlines():
                raws.append(raw)
                g = LINE.match(raw)
                if not g:
                    if raw.strip():
                        loose.append(raw)
                    continue
                t = stamp(g.group(1), g.group(2), g.group(3), year, tz, t0)
                if raw in seen or t is None or not t0 - SLACK <= t <= t1 + SLACK:
                    continue
                seen.add(raw)
                rows.append((sc, g.group(4), g.group(5).lower(), g.group(6), raw))
        try:
            with open(os.path.join(d, "units.txt"), encoding="utf-8", errors="replace") as f:
                units += [(sc, raw.rstrip("\n")) for raw in f]
        except OSError:
            pass
    return rows, units, raws, loose


def json_events(units):
    """(scenario, event) for each JSON event in the units' journal lines; the lines that do not parse."""
    out, bad = [], []
    for sc, raw in units:
        i = raw.find("]: {")
        if i < 0:
            continue
        try:
            ev = json.loads(raw[i + 3:])
        except ValueError:
            ev = None
        if isinstance(ev, dict):
            out.append((sc, ev))
        else:
            bad.append(raw)
    return out, bad


def allow_rules():
    rules = []
    path = os.path.join(HERE, "log-grade.allow")
    if os.path.isfile(path):
        with open(path) as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    prog, ere, _reason = (line.rstrip("\n").split("\t") + ["", ""])[:3]
                    if not ere:
                        raise ValueError(f"{path}: empty ERE in rule: {line.rstrip()!r}")
                    rules.append((prog, re.compile(ere)))
    return rules


MASKS = [(re.compile(r"\S+@\S+"), "<P>"), (re.compile(r"\d+\.\d+\.\d+\.\d+(?:[.:]\d+)?"), "<A>"),
         (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<H>"), (re.compile(r"\d+"), "<N>")]
UNREAD = re.compile(r"panic|\b(?:error|critical|alert|emergency)\b", re.I)


def klass(prog, msg):
    for rx, tok in MASKS:
        msg = rx.sub(tok, msg)
    return prog, msg


def grade(run):
    rows, rec = [], []

    def row(name, ok, expect, observed):
        rows.append((name, "PASS" if ok else "FAIL", expect, "0", observed[:200]))

    def info(name, observed):
        rows.append((name, "INFO", "", "0", observed[:200]))

    (mit, _, _, _), (ours, units, raws, loose) = leg_lines(run, "mit"), leg_lines(run, "rust")
    row("LG.records", bool(mit) and bool(ours), "daemon log lines on both legs",
        f"mit {len(mit)} lines, rust {len(ours)} lines")
    mit_err = {(sc, klass(p, msg)) for sc, p, lvl, msg, _ in mit if lvl in SEVERE}
    info("LG.mit.errors", f"{len(mit_err)} distinct error classes on MIT's leg")
    rec += [f"MIT error: {sc}: {c[0]}: {c[1]}" for sc, c in sorted(mit_err)]

    events, bad = json_events(units)
    panics = [raw for raw in raws + [u for _, u in units] if re.search(r"panic", raw, re.I)]
    panics += [json.dumps(e) for _, e in events
               if e.get("event") == "kdc.transport" and not re.search(r"panic", json.dumps(e), re.I)]
    row("LG.panic", not panics, "no panic in ours' daemon logs, journal or JSON events", f"{len(panics)} panic lines")
    rec += [f"panic: {p}" for p in panics]

    info("LG.unmatched", f"{len(loose)} daemon log lines match no log format")
    info("LG.unparsed", f"{len(bad)} JSON journal lines do not parse")
    unread = [raw for raw in loose + bad if UNREAD.search(raw)]
    row("LG.unread", not unread, "no unmatched or unparsed line holds panic or an error level",
        f"{len(unread)} such lines")
    rec += [f"unread: {u}" for u in unread]

    issues = [(sc, e) for sc, e in events if e.get("event") == "kdc.issue" and e.get("outcome") in ("ok", "krb-error")]

    def cid(e):
        v = e.get("correlation_id") or (e.get("fields") or {}).get("correlation_id")
        return v if isinstance(v, str) and v and v != "none" else None

    bare = [e for _, e in issues if cid(e) is None]
    row("LG.correlated", issues and not bare, "kdc.issue events >= 1, each with a correlation_id",
        f"{len(issues)} kdc.issue, {len(bare)} without a correlation_id")
    rec += ["uncorrelated: " + json.dumps(e) for e in bare]
    for sc in sorted({s for s, *_ in ours} | {s for s, _ in units}):
        info(f"LG.issues.{sc}", f"{sum(1 for s, _ in issues if s == sc)} kdc.issue events")

    rules = allow_rules()
    unexplained = []
    for sc, p, lvl, msg, raw in ours:
        if lvl not in SEVERE or (sc, klass(p, msg)) in mit_err:
            continue
        if any((not rp or rp == p) and ere.search(msg) for rp, ere in rules):
            continue
        unexplained.append(raw)
    row("LG.errors", not unexplained, "each (Error) line of ours in MIT's leg (same scenario) or log-grade.allow",
        f"{len(unexplained)} unexplained of {sum(1 for _, _, lvl, _, _ in ours if lvl in SEVERE)}")
    rec += [f"unexplained: {u}" for u in unexplained]
    return rows, rec


def main():
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        print("usage: log-grade.py <run dir>", file=sys.stderr)
        return 2
    run = sys.argv[1]
    try:
        rows, rec = grade(run)
    except ValueError as e:
        print(f"log-grade: {e}", file=sys.stderr)
        return 2
    out = os.path.join(run, "log-grade")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "checks.tsv"), "w") as f:
        for r in rows:
            f.write("\t".join(r) + "\t\n")
    with open(os.path.join(out, "record.txt"), "w") as f:
        f.write("\n".join(rec) + ("\n" if rec else ""))
    n = {s: sum(1 for r in rows if r[1] == s) for s in ("PASS", "FAIL", "INFO")}
    result = "PASS" if n["FAIL"] == 0 and n["PASS"] > 0 else "FAIL"
    with open(os.path.join(out, "result"), "w") as f:
        f.write(f"{result} {n['PASS']} pass {n['FAIL']} fail {n['INFO']} info\n")
    for r in rows:
        print(f"{r[0]}: {r[1]} ({r[4]})")
    print(f"log-grade: {result}")
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
