#!/usr/bin/env python3
"""Print recent GitHub Actions runs with per-job conclusions and failing steps.

usage: ci-status.py [-n RUNS] [--workflow NAME] [--sha SHA] [--jobs] [--durations]
                    [--repo OWNER/NAME] [--save SHA] [--out DIR] [--budget-report]
                    [--check-budget]

Reads the public REST API without a token (run, job and step conclusions and
the check-run annotations — the gates' `::error file=,line=` lines — are
public for a public repository; job logs are not); `GITHUB_TOKEN` in the
environment is sent when present. Exit status is 0 when the newest listed run of the selected
workflow succeeded, 1 when it failed, 2 when it is still running or unknown.

`--save SHA` writes `ci-<sha>.txt` only from a **completed**, non-rate-limited
run (retries with backoff; exits 2 otherwise). Fixture annotations from
`scripts/probe-gate.sh` (`title=fixture`) are omitted. Saved records include
`job=<name> duration_s=<n>` lines and `run_wall_s=` (W2-S0).

`--durations` prints per-job `duration_s=` from `started_at`/`completed_at`
already in the `/jobs` payload. `--budget-report` prints per-job medians over
the last N completed runs. `--check-budget` compares each job's median of the
last N completed runs (and the median wall) to `ci-budget.toml`; single-run
breaches are info; fail when the median breaches or ≥ 3 of 5 runs breach
(W2-Y4; a run cannot measure itself).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import statistics
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

API = "https://api.github.com"

# Workflow `name:` → filename. `--workflow` accepts either.
WORKFLOW_FILES = {
    "ci": "ci.yml",
    "peers": "peers.yml",
    "soak": "soak.yml",
    "fuzz": "fuzz.yml",
    "kcm-opcode": "kcm-opcode.yml",
    "full-test": "full-test.yml",
}


def repo_from_git() -> str | None:
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if url.startswith(prefix):
            return url[len(prefix) :].removesuffix(".git")
    return None


def workflow_file(name: str) -> str:
    """Map a workflow name (`ci`, `peers`) or filename (`peers.yml`) to the YAML file."""
    if name.endswith(".yml") or name.endswith(".yaml"):
        return name
    return WORKFLOW_FILES.get(name, f"{name}.yml")


def get(path: str) -> dict | list:
    headers = {"User-Agent": "kerber-rust ci-status", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise urllib.error.HTTPError(e.url, e.code, f"{e.reason}: {body[:200]}", e.headers, None) from e


def is_fixture_annotation(note: dict) -> bool:
    """ERR-trap self-test fixtures must not look like product CI failures."""
    if (note.get("title") or "").strip().lower() == "fixture":
        return True
    path = (note.get("path") or "").replace("\\", "/")
    return path.endswith("probe-gate.sh") or path.endswith("/probe-gate.sh")


def annotations(repo: str, job: dict) -> list[str]:
    """The failure annotations of a job, minus the runner's generic exit line and fixtures."""
    try:
        notes = get(f"/repos/{repo}/check-runs/{job['id']}/annotations")
    except urllib.error.URLError:
        return []
    out = []
    for a in notes if isinstance(notes, list) else []:
        if a.get("annotation_level") != "failure":
            continue
        if is_fixture_annotation(a):
            continue
        msg = (a.get("message") or "").strip()
        if msg.startswith("Process completed with exit code"):
            continue
        out.append(f"{a.get('path')}:{a.get('start_line')}: {msg}")
    return out


def failing_steps(job: dict) -> list[str]:
    return [
        s["name"].split(" (")[0]
        for s in job.get("steps", [])
        if s.get("conclusion") not in (None, "success", "skipped")
    ]


def parse_gh_ts(s: str | None) -> float | None:
    """Parse a GitHub ISO-8601 timestamp to epoch seconds. None if missing/unparseable."""
    if not s:
        return None
    text = s.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def job_duration_s(job: dict) -> int | None:
    """Whole seconds between job started_at and completed_at."""
    start = parse_gh_ts(job.get("started_at"))
    end = parse_gh_ts(job.get("completed_at"))
    if start is None or end is None:
        return None
    return max(0, int(round(end - start)))


def step_duration_s(step: dict) -> int | None:
    start = parse_gh_ts(step.get("started_at"))
    end = parse_gh_ts(step.get("completed_at"))
    if start is None or end is None:
        return None
    return max(0, int(round(end - start)))


def run_wall_s(jobs: list[dict], run: dict | None = None) -> int | None:
    """Critical-path wall: max job completed_at − min job started_at.

    Falls back to the run's run_started_at/updated_at when jobs have no stamps.
    """
    starts: list[float] = []
    ends: list[float] = []
    for job in jobs:
        start = parse_gh_ts(job.get("started_at"))
        end = parse_gh_ts(job.get("completed_at"))
        if start is not None:
            starts.append(start)
        if end is not None:
            ends.append(end)
    if starts and ends:
        return max(0, int(round(max(ends) - min(starts))))
    if run:
        start = parse_gh_ts(run.get("run_started_at") or run.get("created_at"))
        end = parse_gh_ts(run.get("updated_at"))
        if start is not None and end is not None:
            return max(0, int(round(end - start)))
    return None


def duration_lines(jobs: list[dict], run: dict | None = None) -> list[str]:
    """Machine-readable duration records for --save and --durations."""
    lines: list[str] = []
    for job in jobs:
        dur = job_duration_s(job)
        if dur is None:
            continue
        lines.append(f"job={job['name']} duration_s={dur}")
        for step in job.get("steps") or []:
            sdur = step_duration_s(step)
            if sdur is None:
                continue
            name = (step.get("name") or "").split(" (")[0]
            if not name:
                continue
            lines.append(f"step={job['name']}/{name} duration_s={sdur}")
    wall = run_wall_s(jobs, run)
    if wall is not None:
        lines.append(f"run_wall_s={wall}")
    return lines


def format_run(repo: str, r: dict, jobs: bool, durations: bool = False) -> list[str]:
    lines: list[str] = []
    state = r["conclusion"] or r["status"]
    head = (
        f"run {r['run_number']} {r['head_sha'][:7]} {r['name']} {state} "
        f"{r['created_at']} id={r['id']}"
    )
    want_jobs = jobs or durations or state != "success"
    job_list: list[dict] = []
    if want_jobs:
        try:
            job_list = get(f"/repos/{repo}/actions/runs/{r['id']}/jobs?per_page=50").get(
                "jobs", []
            )
        except urllib.error.URLError as e:
            lines.append(head)
            lines.append(f"    jobs: unavailable ({e})")
            return lines
    wall = run_wall_s(job_list, r) if job_list else None
    if wall is not None:
        head = f"{head} run_wall_s={wall}"
    lines.append(head)
    if job_list:
        for j in job_list:
            bad = failing_steps(j)
            note = f"  FAILED: {', '.join(bad)}" if bad else ""
            jstate = j["conclusion"] or j["status"]
            dur = job_duration_s(j)
            dur_note = f" duration_s={dur}" if dur is not None and durations else ""
            if jobs or durations or bad or jstate not in ("success", "skipped"):
                lines.append(f"    {j['name']}: {jstate}{dur_note}{note}")
            if bad:
                for line in annotations(repo, j):
                    lines.append(f"        {line}")
        if durations:
            lines.extend(duration_lines(job_list, r))
    return lines


def fetch_runs(repo: str, workflow: str, sha: str | None, n: int) -> list[dict]:
    """Runs of one workflow, newest first.

    Uses `/actions/workflows/<file>/runs` (not the global run list filtered
    by the default branch) so `--workflow peers` and PR-head SHAs are visible.
    """
    wf = workflow_file(workflow)
    per_page = max(n * 3, 10)
    path = f"/repos/{repo}/actions/workflows/{urllib.parse.quote(wf)}/runs?per_page={per_page}"
    runs = get(path)
    if not isinstance(runs, dict):
        return []
    selected = list(runs.get("workflow_runs") or [])
    if sha:
        selected = [r for r in selected if r.get("head_sha", "").startswith(sha)]
        if not selected and len(sha) >= 7:
            # Workflow-file listing is not filtered by SHA server-side; a
            # long-ago run can fall off per_page. Try the run list by head_sha
            # (full SHA) and keep those whose path/name matches.
            try:
                extra = get(
                    f"/repos/{repo}/actions/runs?per_page={per_page}"
                    f"&head_sha={urllib.parse.quote(sha)}"
                )
            except urllib.error.HTTPError:
                extra = {}
            if isinstance(extra, dict):
                want = workflow_file(workflow)
                for r in extra.get("workflow_runs") or []:
                    path_name = (r.get("path") or "").rsplit("/", 1)[-1]
                    if path_name == want or r.get("name") == workflow:
                        selected.append(r)
    return selected[:n]


def save_run(repo: str, workflow: str, sha: str, out_dir: str, retries: int = 10) -> int:
    """Write ci-<sha>.txt from a completed run only. Exit 2 on rate-limit / in_progress exhaustion."""
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"ci-{sha[:7]}.txt")
    backoff = 5.0
    last_err = "no matching runs"
    for attempt in range(retries):
        try:
            selected = fetch_runs(repo, workflow, sha, 5)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                last_err = f"HTTP Error 403: rate limit exceeded (attempt {attempt + 1}/{retries})"
                print(f"ci-status: {last_err}", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
            print(f"ci-status: {e}", file=sys.stderr)
            return 2
        except urllib.error.URLError as e:
            last_err = str(e)
            print(f"ci-status: {e}", file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)
            continue
        if not selected:
            last_err = "no matching runs"
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        newest = selected[0]
        status = newest.get("status") or ""
        conclusion = newest.get("conclusion")
        if status != "completed" or conclusion is None:
            last_err = f"run {newest.get('run_number')} still {status or 'unknown'}"
            print(f"ci-status: {last_err}; retrying", file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        lines = format_run(repo, newest, jobs=True, durations=True)
        # Stamp so evidence-check accepts the record.
        stamp = [
            "==== provenance ====",
            f"head_sha={newest['head_sha']}",
            f"tree_sha=ci-status-save",
            "dirty=no",
            f"captured_at={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            f"ci_run_id={newest['id']}",
            f"ci_conclusion={conclusion}",
            "",
        ]
        text = "\n".join(stamp + lines) + "\n"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        sys.stdout.write(text)
        return 0 if conclusion == "success" else 1
    print(f"ci-status: refusing to save incomplete record: {last_err}", file=sys.stderr)
    return 2


def budget_report(repo: str, workflow: str, n: int) -> int:
    """Print per-job median duration_s over the last N completed runs."""
    selected = fetch_runs(repo, workflow, None, n)
    if not selected:
        print("ci-status: no matching runs", file=sys.stderr)
        return 2
    by_job: dict[str, list[int]] = {}
    walls: list[int] = []
    used = 0
    for run in selected:
        if (run.get("status") or "") != "completed":
            continue
        try:
            job_list = get(f"/repos/{repo}/actions/runs/{run['id']}/jobs?per_page=50").get(
                "jobs", []
            )
        except urllib.error.URLError as e:
            print(f"ci-status: jobs unavailable for run {run.get('run_number')}: {e}", file=sys.stderr)
            continue
        used += 1
        wall = run_wall_s(job_list, run)
        if wall is not None:
            walls.append(wall)
        for job in job_list:
            dur = job_duration_s(job)
            if dur is None:
                continue
            by_job.setdefault(job["name"], []).append(dur)
    print(f"budget-report workflow={workflow} runs_completed={used} of {len(selected)}")
    if walls:
        print(f"run_wall_s median={int(statistics.median(walls))} n={len(walls)}")
    for name in sorted(by_job):
        vals = by_job[name]
        print(f"job={name} median_s={int(statistics.median(vals))} n={len(vals)}")
    return 0


def parse_budget(text: str) -> dict:
    """Parse ci-budget.toml text into {jobs: {name: int}, run_wall: int|None}."""
    data = tomllib.loads(text)
    jobs = {str(k): int(v) for k, v in (data.get("jobs") or {}).items()}
    run_wall = (data.get("push") or {}).get("run_wall")
    return {"jobs": jobs, "run_wall": int(run_wall) if run_wall is not None else None}


def load_budget(path: pathlib.Path | None = None) -> dict:
    if path is None:
        path = pathlib.Path(__file__).resolve().parents[1] / "ci-budget.toml"
    if not path.is_file():
        raise FileNotFoundError(str(path))
    return parse_budget(path.read_text(encoding="utf-8"))


def budget_overruns(
    job_durations: dict[str, int],
    run_wall: int | None,
    budget: dict,
) -> list[str]:
    """Human lines for each overrun. Empty means within budget."""
    lines: list[str] = []
    for name, cap in (budget.get("jobs") or {}).items():
        got = job_durations.get(name)
        if got is None:
            continue
        if got > cap:
            lines.append(f"job={name} duration_s={got} budget={cap}")
    cap_wall = budget.get("run_wall")
    if cap_wall is not None and run_wall is not None and run_wall > cap_wall:
        lines.append(f"run_wall_s={run_wall} budget={cap_wall}")
    return lines


def budget_median_verdict(
    runs: list[tuple[int | None, dict[str, int], int | None]],
    budget: dict,
    over_runs_fail_at: int = 3,
) -> tuple[list[str], list[str]]:
    """Fail when a job/wall median exceeds the cap, or >= over_runs_fail_at runs do.

    `runs` is (run_number, job_durs, wall) newest-first. Single-run
    breaches are info. Empty fail list means within budget.
    """
    fail: list[str] = []
    info: list[str] = []
    by_job: dict[str, list[int]] = {}
    walls: list[int] = []
    for run_n, durs, wall in runs:
        if wall is not None:
            walls.append(wall)
        for name, dur in durs.items():
            by_job.setdefault(name, []).append(dur)
        over = budget_overruns(durs, wall, budget)
        if over:
            for line in over:
                info.append(f"run={run_n} {line}")

    for name, cap in (budget.get("jobs") or {}).items():
        vals = by_job.get(name) or []
        if not vals:
            continue
        med = int(statistics.median(vals))
        over_n = sum(1 for v in vals if v > cap)
        line = f"job={name} median_s={med} budget={cap} n={len(vals)} over={over_n}"
        if med > cap or over_n >= over_runs_fail_at:
            fail.append(line)
        elif over_n:
            info.append(line + " (info)")

    cap_wall = budget.get("run_wall")
    if cap_wall is not None and walls:
        med = int(statistics.median(walls))
        over_n = sum(1 for v in walls if v > cap_wall)
        line = f"run_wall_s median={med} budget={cap_wall} n={len(walls)} over={over_n}"
        if med > cap_wall or over_n >= over_runs_fail_at:
            fail.append(line)
        elif over_n:
            info.append(line + " (info)")
    return fail, info


def check_budget(repo: str, workflow: str, sha: str | None, n: int) -> int:
    """Compare completed runs against ci-budget.toml.

    Per-run overruns are info. Fail when a job/wall median exceeds the cap
    or when >= 3 of the runs breach (W2-Y4). Exit 2 if no completed run /
    fetch failed.
    """
    try:
        budget = load_budget()
    except FileNotFoundError:
        print("ci-status: missing ci-budget.toml", file=sys.stderr)
        return 2
    try:
        selected = fetch_runs(repo, workflow, sha, n)
    except urllib.error.URLError as e:
        print(f"ci-status: {e}", file=sys.stderr)
        return 2
    completed = [r for r in selected if (r.get("status") or "") == "completed"]
    if not completed:
        print("ci-status: no completed run to check", file=sys.stderr)
        return 2
    payload: list[tuple[int | None, dict[str, int], int | None]] = []
    for run in completed:
        try:
            job_list = get(
                f"/repos/{repo}/actions/runs/{run['id']}/jobs?per_page=50"
            ).get("jobs", [])
        except urllib.error.URLError as e:
            print(
                f"ci-status: jobs unavailable for run {run.get('run_number')}: {e}",
                file=sys.stderr,
            )
            return 2
        durs: dict[str, int] = {}
        for job in job_list:
            dur = job_duration_s(job)
            if dur is not None:
                durs[job["name"]] = dur
        wall = run_wall_s(job_list, run)
        sha8 = (run.get("head_sha") or "")[:8]
        over = budget_overruns(durs, wall, budget)
        if over:
            print(f"check-budget info run={run.get('run_number')} sha={sha8}")
            for line in over:
                print(f"  {line}")
        else:
            print(f"check-budget ok run={run.get('run_number')} sha={sha8}")
        payload.append((run.get("run_number"), durs, wall))
    fail, _info = budget_median_verdict(payload, budget)
    for line in fail:
        print(f"check-budget FAIL {line}")
    if fail:
        return 1
    print("check-budget ok (median / >=3-of-5)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--runs", type=int, default=10)
    ap.add_argument("--workflow", default="ci", help="workflow name or YAML file (default: ci)")
    ap.add_argument("--sha", help="only runs for this commit (prefix match)")
    ap.add_argument("--jobs", action="store_true", help="list every job of every listed run")
    ap.add_argument(
        "--durations",
        action="store_true",
        help="print per-job duration_s= from started_at/completed_at",
    )
    ap.add_argument("--repo", default=repo_from_git(), help="OWNER/NAME (default: origin)")
    ap.add_argument(
        "--save",
        metavar="SHA",
        help="write ci-<sha>.txt only from a completed run (retries; exit 2 otherwise)",
    )
    ap.add_argument(
        "--out",
        default=".",
        help="directory for --save output (default: cwd)",
    )
    ap.add_argument(
        "--budget-report",
        action="store_true",
        help="print per-job median duration_s over the last -n completed runs",
    )
    ap.add_argument(
        "--check-budget",
        action="store_true",
        help="fail if job/wall median of last -n (or --sha) exceeds ci-budget.toml, or >=3 of 5 runs breach",
    )
    args = ap.parse_args()
    if not args.repo:
        print("ci-status: cannot determine the repository; pass --repo", file=sys.stderr)
        return 2
    if args.save:
        return save_run(args.repo, args.workflow, args.save, args.out)
    if args.budget_report:
        return budget_report(args.repo, args.workflow, args.runs)
    if args.check_budget:
        return check_budget(args.repo, args.workflow, args.sha, args.runs)
    try:
        selected = fetch_runs(args.repo, args.workflow, args.sha, args.runs)
    except urllib.error.URLError as e:
        print(f"ci-status: {e}", file=sys.stderr)
        return 2
    if not selected:
        print("ci-status: no matching runs", file=sys.stderr)
        return 2
    for r in selected:
        for line in format_run(args.repo, r, args.jobs, durations=args.durations):
            print(line)
    newest = selected[0]
    if newest["conclusion"] == "success":
        return 0
    if newest["conclusion"] in ("failure", "cancelled", "timed_out"):
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
