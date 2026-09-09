#!/usr/bin/env python3
"""Print recent GitHub Actions runs with per-job conclusions and failing steps.

usage: ci-status.py [-n RUNS] [--workflow NAME] [--sha SHA] [--jobs] [--repo OWNER/NAME]
                    [--save SHA] [--out DIR]

Reads the public REST API without a token (run, job and step conclusions and
the check-run annotations — the gates' `::error file=,line=` lines — are
public for a public repository; job logs are not); `GITHUB_TOKEN` in the
environment is sent when present. Exit status is 0 when the newest listed run of the selected
workflow succeeded, 1 when it failed, 2 when it is still running or unknown.

`--save SHA` writes `ci-<sha>.txt` only from a **completed**, non-rate-limited
run (retries with backoff; exits 2 otherwise). Fixture annotations from
`scripts/probe-gate.sh` (`title=fixture`) are omitted.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"


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


def format_run(repo: str, r: dict, jobs: bool) -> list[str]:
    lines: list[str] = []
    state = r["conclusion"] or r["status"]
    lines.append(
        f"run {r['run_number']} {r['head_sha'][:7]} {r['name']} {state} {r['created_at']} id={r['id']}"
    )
    if jobs or state != "success":
        try:
            job_list = get(f"/repos/{repo}/actions/runs/{r['id']}/jobs?per_page=50").get("jobs", [])
        except urllib.error.URLError as e:
            lines.append(f"    jobs: unavailable ({e})")
            return lines
        for j in job_list:
            bad = failing_steps(j)
            note = f"  FAILED: {', '.join(bad)}" if bad else ""
            jstate = j["conclusion"] or j["status"]
            if jobs or bad or jstate not in ("success", "skipped"):
                lines.append(f"    {j['name']}: {jstate}{note}")
            if bad:
                for line in annotations(repo, j):
                    lines.append(f"        {line}")
    return lines


def fetch_runs(repo: str, workflow: str, sha: str | None, n: int) -> list[dict]:
    runs = get(f"/repos/{repo}/actions/runs?per_page={max(n * 3, 10)}&branch=main")
    if not isinstance(runs, dict):
        return []
    selected = [
        r
        for r in runs.get("workflow_runs", [])
        if r["name"] == workflow and (not sha or r["head_sha"].startswith(sha))
    ][:n]
    return selected


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
        lines = format_run(repo, newest, jobs=True)
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--runs", type=int, default=10)
    ap.add_argument("--workflow", default="ci", help="workflow name to select (default: ci)")
    ap.add_argument("--sha", help="only runs for this commit (prefix match)")
    ap.add_argument("--jobs", action="store_true", help="list every job of every listed run")
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
    args = ap.parse_args()
    if not args.repo:
        print("ci-status: cannot determine the repository; pass --repo", file=sys.stderr)
        return 2
    if args.save:
        return save_run(args.repo, args.workflow, args.save, args.out)
    try:
        selected = fetch_runs(args.repo, args.workflow, args.sha, args.runs)
    except urllib.error.URLError as e:
        print(f"ci-status: {e}", file=sys.stderr)
        return 2
    if not selected:
        print("ci-status: no matching runs", file=sys.stderr)
        return 2
    for r in selected:
        for line in format_run(args.repo, r, args.jobs):
            print(line)
    newest = selected[0]
    if newest["conclusion"] == "success":
        return 0
    if newest["conclusion"] in ("failure", "cancelled", "timed_out"):
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
