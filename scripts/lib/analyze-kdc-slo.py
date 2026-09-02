#!/usr/bin/env python3
"""Aggregate KDC JSON logs: p99 duration_us, throughput, error rate, panics.

Gates and the --self-test fixture share this path. Do not reimplement
percentiles inside Rust tests.

Documented CI bounds (debug build, bounded wire load):
  p99 duration_us  <= 50000    (50 ms; catches a 10x regression vs lab ~9.4 ms)
  throughput       >= 8        (kdc.issue ok per KDC-clock second)
  error_rate       == 0
  panics           == 0
Throughput uses kdc.issue timestamps, else sum(duration_us). It does not
use Docker/`date +%s` wall time around MIT kinit. p99/throughput/window
undershoot is a warning when kdc_issue_err==0 and panics==0; error_rate
and panics stay hard-fail.
Stress p99/throughput/windows skip env-up + MIT-before (--warmup-log).
Stress additionally:
  second-window p99 <= first-window p99 * 2.5
Soak additionally:
  second-window p99 <= first-window p99 * 2.5
  RSS last <= first * 1.5 + 8 MiB
  RSS slope <= 0.05 MiB/s
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import sys
import tempfile
from datetime import datetime


def _parse_epoch(o: dict) -> float | None:
    ts = o.get("timestamp")
    if ts is None:
        ts = (o.get("fields") or {}).get("timestamp")
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def _kdc_elapsed_s(epochs: list[float | None], durs: list[float]) -> float | None:
    known = [e for e in epochs if e is not None]
    if len(known) >= 2:
        span = max(known) - min(known)
        if span > 0:
            return span
    if durs:
        return max(sum(durs) / 1_000_000.0, 1e-6)
    return None


def _soft_slo_issue(issue: str) -> bool:
    return issue.startswith("p99_us:") or issue.startswith("throughput:") or issue.startswith(
        "latency_degraded:"
    ) or issue in {"no_elapsed_for_throughput", "window_p99_missing"}


def percentile(xs: list[float], p: float) -> float | None:
    if not xs:
        return None
    ys = sorted(xs)
    if len(ys) == 1:
        return ys[0]
    k = max(0, min(len(ys) - 1, int(math.ceil(p / 100.0 * len(ys)) - 1)))
    return ys[k]


def parse_logs(paths: list[pathlib.Path]) -> dict:
    issues: list[str] = []
    n_json = 0
    n_issue_ok = 0
    n_issue_err = 0
    n_issue_krb_error = 0
    n_cid = 0
    panics = 0
    durations: list[tuple[float, float]] = []
    epochs: list[float | None] = []
    seq = 0.0
    for log_path in paths:
        if not log_path.is_file():
            issues.append(f"missing_log:{log_path}")
            continue
        for line in log_path.read_text(errors="replace").splitlines():
            if "panic" in line.lower():
                panics += 1
                issues.append("panic")
            if not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                issues.append("bad_json")
                continue
            n_json += 1
            fields = o.get("fields") or {}
            cid = fields.get("correlation_id") or o.get("correlation_id")
            if cid:
                n_cid += 1
            event = fields.get("event") or o.get("event")
            outcome = fields.get("outcome") or o.get("outcome")
            tkey = seq
            seq += 1.0
            if event == "kdc.issue":
                dur = fields.get("duration_us")
                if dur is None:
                    dur = o.get("duration_us")
                if outcome == "ok":
                    n_issue_ok += 1
                    if not cid or cid == "none":
                        issues.append("issue_without_correlation_id")
                    if dur is not None:
                        try:
                            durations.append((tkey, float(dur)))
                            epochs.append(_parse_epoch(o))
                        except (TypeError, ValueError):
                            issues.append("bad_duration_us")
                elif outcome == "krb-error":
                    n_issue_krb_error += 1
                elif outcome == "error":
                    n_issue_err += 1
    n_issue = n_issue_ok + n_issue_err
    error_rate = (n_issue_err / n_issue) if n_issue else 0.0
    durs = [d for _, d in durations]
    return {
        "n_json": n_json,
        "n_issue_ok": n_issue_ok,
        "n_issue_err": n_issue_err,
        "n_issue_krb_error": n_issue_krb_error,
        "n_cid": n_cid,
        "panics": panics,
        "error_rate": error_rate,
        "durations": durations,
        "epochs": epochs,
        "p50_us": percentile(durs, 50),
        "p99_us": percentile(durs, 99),
        "max_us": max(durs) if durs else None,
        "issues": issues,
    }


def parse_rss(path: pathlib.Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    samples: list[tuple[float, float]] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            samples.append((float(parts[0]), float(parts[1])))
        except ValueError:
            continue
    if not samples:
        return {"samples": 0}
    first = samples[0][1]
    last = samples[-1][1]
    peak = max(s[1] for s in samples)
    elapsed = samples[-1][0] - samples[0][0]
    extra = last - first
    slope = (extra / elapsed) if elapsed > 0 else None
    return {
        "samples": len(samples),
        "first_mib": first,
        "last_mib": last,
        "max_mib": peak,
        "growth": (last / first) if first > 0 else None,
        "elapsed_s": elapsed,
        "slope_mib_s": slope,
    }


def window_p99(durations: list[tuple[float, float]], nwindows: int) -> list[float | None]:
    if nwindows < 2 or len(durations) < nwindows:
        return []
    chunk = max(1, len(durations) // nwindows)
    out: list[float | None] = []
    for i in range(nwindows):
        sl = durations[i * chunk : (i + 1) * chunk] if i < nwindows - 1 else durations[i * chunk :]
        out.append(percentile([d for _, d in sl], 99))
    return out


def evaluate(args: argparse.Namespace, parsed: dict, rss: dict | None) -> dict:
    issues = list(parsed["issues"])
    skip = max(0, int(getattr(args, "skip_first_ok", 0) or 0))
    warmup_path = getattr(args, "warmup_log", None)
    if warmup_path:
        w = parse_logs([pathlib.Path(warmup_path)])
        skip = len(w["durations"])
        issues.extend(w["issues"])
    durations = parsed["durations"][skip:]
    epochs = (parsed.get("epochs") or [])[skip:]
    durs = [d for _, d in durations]
    n_ok = len(durs)
    p50 = percentile(durs, 50)
    p99 = percentile(durs, 99)
    max_us = max(durs) if durs else None
    elapsed = _kdc_elapsed_s(epochs, durs)
    throughput = (n_ok / elapsed) if elapsed and elapsed > 0 else None
    if args.p99_max_us is not None:
        if p99 is None:
            issues.append("no_duration_us")
        elif p99 > args.p99_max_us:
            issues.append(f"p99_us:{p99}>max:{args.p99_max_us}")
    if args.throughput_min is not None:
        if throughput is None:
            issues.append("no_elapsed_for_throughput")
        elif throughput < args.throughput_min:
            issues.append(f"throughput:{throughput:.3f}<min:{args.throughput_min}")
    if args.max_error_rate is not None and parsed["error_rate"] > args.max_error_rate + 1e-12:
        issues.append(f"error_rate:{parsed['error_rate']}>max:{args.max_error_rate}")
    if parsed["panics"] != 0:
        issues.append(f"panics:{parsed['panics']}")
    if args.min_issue_ok is not None and n_ok < args.min_issue_ok:
        issues.append(f"issue_ok:{n_ok}<min:{args.min_issue_ok}")
    windows = window_p99(durations, args.windows) if args.windows else []
    if args.windows >= 2 and args.degrade_factor is not None and len(windows) >= 2:
        first, last = windows[0], windows[-1]
        if first is None or last is None:
            issues.append("window_p99_missing")
        elif first > 0 and last > first * args.degrade_factor:
            issues.append(f"latency_degraded:{last}>{first}*{args.degrade_factor}")
    if rss is not None:
        if rss.get("samples", 0) < args.min_rss_samples:
            issues.append(f"rss_samples:{rss.get('samples', 0)}<min:{args.min_rss_samples}")
        else:
            first = rss.get("first_mib") or 0.0
            last = rss.get("last_mib") or 0.0
            cap = first * args.rss_max_growth + args.rss_max_extra_mib
            if last > cap:
                issues.append(f"rss_growth:{last}>{cap}")
            slope_max = getattr(args, "rss_max_slope_mib_s", None)
            slope = rss.get("slope_mib_s")
            if slope_max is not None and slope is not None and slope > slope_max:
                issues.append(f"rss_slope:{slope}>{slope_max}")
    warnings = [i for i in issues if _soft_slo_issue(i)]
    hard = [i for i in issues if not _soft_slo_issue(i)]
    outcome = "ok" if not hard else "error"
    return {
        "event": "kdc.slo",
        "json_lines": parsed["n_json"],
        "kdc_issue_ok": parsed["n_issue_ok"],
        "kdc_issue_err": parsed["n_issue_err"],
        "kdc_issue_krb_error": parsed.get("n_issue_krb_error", 0),
        "correlation_id_fields": parsed["n_cid"],
        "panics": parsed["panics"],
        "error_rate": parsed["error_rate"],
        "p50_us": p50,
        "p99_us": p99,
        "max_us": max_us,
        "elapsed_s": elapsed,
        "wall_elapsed_s": args.elapsed_s,
        "throughput": throughput,
        "skipped_ok": skip,
        "windows_p99_us": windows,
        "rss": rss,
        "issues": issues,
        "warnings": warnings,
        "outcome": outcome,
    }


def self_test() -> int:
    ok_lines = []
    for i in range(40):
        ok_lines.append(
            json.dumps(
                {
                    "timestamp": f"2026-01-01T00:00:{i:02d}Z",
                    "fields": {
                        "event": "kdc.issue",
                        "outcome": "ok",
                        "correlation_id": f"{i:032x}",
                        "duration_us": 1000 + i,
                    },
                }
            )
        )
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "ok.log"
        p.write_text("\n".join(ok_lines) + "\n")
        parsed = parse_logs([p])
        ns = argparse.Namespace(
            p99_max_us=500000,
            throughput_min=1.0,
            max_error_rate=0.0,
            min_issue_ok=10,
            elapsed_s=10.0,
            windows=0,
            degrade_factor=2.5,
            min_rss_samples=0,
            rss_max_growth=2.0,
            rss_max_extra_mib=20.0,
            rss_max_slope_mib_s=None,
            skip_first_ok=0,
            warmup_log=None,
        )
        rep = evaluate(ns, parsed, None)
        if rep["outcome"] != "ok":
            print("self-test ok-log failed", json.dumps(rep), file=sys.stderr)
            return 1
        breach = list(ok_lines)
        breach.append(
            json.dumps(
                {
                    "fields": {
                        "event": "kdc.issue",
                        "outcome": "ok",
                        "correlation_id": "ab",
                        "duration_us": 9_000_000,
                    }
                }
            )
        )
        b = pathlib.Path(td) / "breach.log"
        b.write_text("\n".join(breach) + "\n")
        parsed_b = parse_logs([b])
        ns.p99_max_us = 1000
        ns.throughput_min = None
        ns.min_issue_ok = 1
        rep_b = evaluate(ns, parsed_b, None)
        if rep_b["outcome"] != "ok" or not any(
            i.startswith("p99_us:") for i in (rep_b.get("warnings") or [])
        ):
            print("self-test p99-only should warn not fail", json.dumps(rep_b), file=sys.stderr)
            return 1
        err_log = pathlib.Path(td) / "err.log"
        err_log.write_text(
            json.dumps(
                {
                    "fields": {
                        "event": "kdc.issue",
                        "outcome": "error",
                        "correlation_id": "cd",
                        "duration_us": 10,
                    }
                }
            )
            + "\n"
        )
        parsed_e = parse_logs([err_log])
        ns.p99_max_us = None
        ns.max_error_rate = 0.0
        ns.min_issue_ok = 0
        rep_e = evaluate(ns, parsed_e, None)
        if rep_e["outcome"] != "error" or not any(
            i.startswith("error_rate:") for i in rep_e["issues"]
        ):
            print("self-test error-rate did not fail", json.dumps(rep_e), file=sys.stderr)
            return 1
        rss_path = pathlib.Path(td) / "rss-leak.tsv"
        rss_path.write_text(
            "# epoch_s rss_mib\n"
            "1000 8.0\n"
            "1005 8.8\n"
            "1010 9.6\n"
            "1015 10.4\n"
            "1020 11.2\n"
            "1025 12.0\n"
        )
        rss_leak = parse_rss(rss_path)
        ns.p99_max_us = 500000
        ns.max_error_rate = 1.0
        ns.min_issue_ok = 1
        ns.throughput_min = None
        ns.min_rss_samples = 5
        ns.rss_max_growth = 2.0
        ns.rss_max_extra_mib = 20.0
        ns.rss_max_slope_mib_s = 0.05
        rep_rss = evaluate(ns, parsed, rss_leak)
        if rep_rss["outcome"] != "error" or not any(
            i.startswith("rss_slope:") for i in rep_rss["issues"]
        ):
            print("self-test rss-slope did not fail", json.dumps(rep_rss), file=sys.stderr)
            return 1
        ns.rss_max_slope_mib_s = None
        rep_old = evaluate(ns, parsed, rss_leak)
        if rep_old["outcome"] != "ok":
            print("self-test rss old-floor should pass", json.dumps(rep_old), file=sys.stderr)
            return 1
        slow = json.dumps(
            {
                "fields": {
                    "event": "kdc.issue",
                    "outcome": "ok",
                    "correlation_id": "ee",
                    "duration_us": 200_000,
                }
            }
        )
        warm = pathlib.Path(td) / "warmup.log"
        full = pathlib.Path(td) / "warmed.log"
        warm.write_text(slow + "\n" + slow + "\n")
        full.write_text(slow + "\n" + slow + "\n" + "\n".join(ok_lines) + "\n")
        ns.p99_max_us = 50000
        ns.max_error_rate = 0.0
        ns.min_issue_ok = 10
        ns.min_rss_samples = 0
        ns.warmup_log = None
        ns.skip_first_ok = 0
        parsed_full = parse_logs([full])
        rep_cold = evaluate(ns, parsed_full, None)
        if not any(i.startswith("p99_us:") for i in (rep_cold.get("warnings") or [])):
            print("self-test cold p99 did not warn", json.dumps(rep_cold), file=sys.stderr)
            return 1
        ns.warmup_log = str(warm)
        rep_warm = evaluate(ns, parsed_full, None)
        if rep_warm["outcome"] != "ok" or rep_warm.get("skipped_ok") != 2:
            print("self-test warmup skip should pass", json.dumps(rep_warm), file=sys.stderr)
            return 1
        if any(i.startswith("p99_us:") for i in (rep_warm.get("warnings") or [])):
            print("self-test warmup still warned p99", json.dumps(rep_warm), file=sys.stderr)
            return 1
        tail = pathlib.Path(td) / "tail-spike.log"
        tail.write_text("\n".join(ok_lines) + "\n" + slow + "\n")
        ns.warmup_log = None
        ns.skip_first_ok = 0
        parsed_tail = parse_logs([tail])
        rep_tail = evaluate(ns, parsed_tail, None)
        if not any(i.startswith("p99_us:") for i in (rep_tail.get("warnings") or [])):
            print("self-test trailing spike did not warn", json.dumps(rep_tail), file=sys.stderr)
            return 1
        flake_lines = []
        for i in range(200):
            flake_lines.append(
                json.dumps(
                    {
                        "timestamp": f"2026-01-01T00:00:{i // 5:02d}.{i % 5 * 200:03d}Z",
                        "fields": {
                            "event": "kdc.issue",
                            "outcome": "ok",
                            "correlation_id": f"{i:032x}",
                            "duration_us": 5000,
                        },
                    }
                )
            )
        flake = pathlib.Path(td) / "g8b-flake.log"
        flake.write_text("\n".join(flake_lines) + "\n")
        ns.p99_max_us = 50000
        ns.throughput_min = 8.0
        ns.max_error_rate = 0.0
        ns.min_issue_ok = 16
        ns.elapsed_s = 40.0
        ns.windows = 2
        ns.degrade_factor = 2.5
        ns.warmup_log = None
        parsed_flake = parse_logs([flake])
        rep_flake = evaluate(ns, parsed_flake, None)
        if rep_flake["outcome"] != "ok" or parsed_flake["n_issue_err"] != 0:
            print("self-test wall-clock flake should pass", json.dumps(rep_flake), file=sys.stderr)
            return 1
        panic_log = pathlib.Path(td) / "panic.log"
        panic_log.write_text(
            "\n".join(ok_lines)
            + "\nthread 'kdc' panicked at src/issue.rs:1:1: boom\n"
        )
        ns.throughput_min = None
        ns.p99_max_us = 500000
        parsed_p = parse_logs([panic_log])
        rep_p = evaluate(ns, parsed_p, None)
        if rep_p["outcome"] != "error" or not any(i == "panic" for i in rep_p["issues"]):
            print("self-test panic did not fail", json.dumps(rep_p), file=sys.stderr)
            return 1
    print("self-test ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log", action="append", default=[], help="KDC JSON log path (repeatable)")
    ap.add_argument("--out", help="write report JSON here")
    ap.add_argument("--p99-max-us", type=float, default=None)
    ap.add_argument("--throughput-min", type=float, default=None)
    ap.add_argument("--max-error-rate", type=float, default=0.0)
    ap.add_argument("--min-issue-ok", type=int, default=1)
    ap.add_argument("--elapsed-s", type=float, default=None)
    ap.add_argument("--windows", type=int, default=0)
    ap.add_argument("--degrade-factor", type=float, default=2.5)
    ap.add_argument("--rss-series", default=None)
    ap.add_argument("--min-rss-samples", type=int, default=5)
    ap.add_argument("--rss-max-growth", type=float, default=2.0)
    ap.add_argument("--rss-max-extra-mib", type=float, default=20.0)
    ap.add_argument("--rss-max-slope-mib-s", type=float, default=None)
    ap.add_argument("--skip-first-ok", type=int, default=0)
    ap.add_argument("--warmup-log", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.log:
        print("need --log", file=sys.stderr)
        return 2
    parsed = parse_logs([pathlib.Path(p) for p in args.log])
    rss = parse_rss(pathlib.Path(args.rss_series) if args.rss_series else None)
    if args.elapsed_s is None and parsed["durations"]:
        args.elapsed_s = max(1.0, float(len(parsed["durations"])) / 10.0)
    rep = evaluate(args, parsed, rss)
    text = json.dumps(rep)
    print(text)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n")
    return 0 if rep["outcome"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
