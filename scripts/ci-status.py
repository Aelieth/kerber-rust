#!/usr/bin/env python3
"""Print recent GitHub Actions runs with per-job conclusions and failing steps.

usage: ci-status.py [-n RUNS] [--workflow NAME] [--sha SHA] [--jobs] [--repo OWNER/NAME]

Reads the public REST API without a token (run, job and step conclusions and
the check-run annotations — the gates' `::error file=,line=` lines — are
public for a public repository; job logs are not); `GITHUB_TOKEN` in the
environment is sent when present. Exit status is 0 when the newest listed run of the selected
workflow succeeded, 1 when it failed, 2 when it is still running or unknown.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
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


def get(path: str) -> dict:
    headers = {"User-Agent": "kerber-rust ci-status", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def annotations(repo: str, job: dict) -> list[str]:
    """The failure annotations of a job, minus the runner's generic exit line."""
    try:
        notes = get(f"/repos/{repo}/check-runs/{job['id']}/annotations")
    except urllib.error.URLError:
        return []
    out = []
    for a in notes if isinstance(notes, list) else []:
        if a.get("annotation_level") != "failure":
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--runs", type=int, default=10)
    ap.add_argument("--workflow", default="ci", help="workflow name to select (default: ci)")
    ap.add_argument("--sha", help="only runs for this commit (prefix match)")
    ap.add_argument("--jobs", action="store_true", help="list every job of every listed run")
    ap.add_argument("--repo", default=repo_from_git(), help="OWNER/NAME (default: origin)")
    args = ap.parse_args()
    if not args.repo:
        print("ci-status: cannot determine the repository; pass --repo", file=sys.stderr)
        return 2
    try:
        runs = get(f"/repos/{args.repo}/actions/runs?per_page={max(args.runs * 3, 10)}&branch=main")
    except urllib.error.URLError as e:
        print(f"ci-status: {e}", file=sys.stderr)
        return 2
    selected = [
        r
        for r in runs.get("workflow_runs", [])
        if r["name"] == args.workflow and (not args.sha or r["head_sha"].startswith(args.sha))
    ][: args.runs]
    if not selected:
        print("ci-status: no matching runs", file=sys.stderr)
        return 2
    for r in selected:
        state = r["conclusion"] or r["status"]
        print(f"run {r['run_number']} {r['head_sha'][:7]} {r['name']} {state} {r['created_at']} id={r['id']}")
        if args.jobs or state != "success":
            jobs = get(f"/repos/{args.repo}/actions/runs/{r['id']}/jobs?per_page=50").get("jobs", [])
            for j in jobs:
                bad = failing_steps(j)
                note = f"  FAILED: {', '.join(bad)}" if bad else ""
                jstate = j["conclusion"] or j["status"]
                if args.jobs or bad or jstate not in ("success", "skipped"):
                    print(f"    {j['name']}: {jstate}{note}")
                if bad:
                    for line in annotations(args.repo, j):
                        print(f"        {line}")
    newest = selected[0]
    if newest["conclusion"] == "success":
        return 0
    if newest["conclusion"] in ("failure", "cancelled", "timed_out"):
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
