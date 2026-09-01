#!/usr/bin/env python3
"""Fail unless committed GitHub workflow YAML matches gate discipline.

Parses `.github/workflows/*.yml` (and `.config/nextest.toml`) rather than
a parallel copy of the job list. Job `continue-on-error` on the per-push
`ci` workflow is allowed only for stress/chaos/soak. Named deterministic
MIT extras must fail-red per SHA.
Samba PAC / realtrust / Heimdal must fail-red on a scheduled workflow.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
NEXTEST_TOML = ROOT / ".config" / "nextest.toml"

# Per-push jobs that may set continue-on-error: true. Everything else on
# the push/PR workflow is fail-red.
SOFT_PER_PUSH_JOBS = frozenset({"slo", "chaos", "soak"})

FAIL_RED_PER_PUSH = (
    "spake-gate.sh",
    "rust-kinit-spake-gate.sh",
    "mit-fast-kdc-gate.sh",
    "rust-kinit-fast-gate.sh",
    "rust-kinit-pkinit-gate.sh",
    "rust-kinit-enterprise-gate.sh",
    "sha2-gate.sh",
    "s4u-mit-gate.sh",
    "cross-realm-gate.sh",
    "capaths-transit-gate.sh",
    "ktutil-gate.sh",
    "kadmin-local-gate.sh",
    "rust-kpasswd-mit-gate.sh",
    "kcm-gate.sh",
    "config-include-gate.sh",
)

NIGHTLY_BLOCKING = (
    "samba-pac-verify-gate.sh",
    "samba-pac-l2-gate.sh",
    "samba-crossrealm-gate.sh",
    "samba-realtrust-gate.sh",
    "heimdal-gate.sh",
    "kcm-opcode-gate.sh",
)

TIMEOUT_JOBS = (
    "test",
    "harness",
    "mit-extra",
    "slo",
    "chaos",
    "soak",
    "mit-image",
)

SCRIPT_RE = re.compile(r"scripts/([A-Za-z0-9._-]+\.sh)")
JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.M)


class Job:
    def __init__(self, name: str, body: str) -> None:
        self.name = name
        self.body = body
        self.continue_on_error = _job_level_bool(body, "continue-on-error")
        timeout = _job_level_scalar(body, "timeout-minutes")
        self.timeout_minutes = int(timeout) if timeout and timeout.isdigit() else None
        self.scripts = tuple(SCRIPT_RE.findall(body))


class Workflow:
    def __init__(self, path: pathlib.Path, text: str) -> None:
        self.path = path
        self.text = text
        self.scheduled = bool(re.search(r"(?m)^\s+schedule:\s*$", text))
        self.per_push = bool(
            re.search(r"(?m)^(?:  )?(push|pull_request):", text)
        )
        jobs_m = re.search(r"(?m)^jobs:\s*$", text)
        if not jobs_m:
            self.jobs: dict[str, Job] = {}
            return
        rest = text[jobs_m.end() :]
        headers = list(JOB_HEADER_RE.finditer(rest))
        jobs: dict[str, Job] = {}
        for i, m in enumerate(headers):
            start = m.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(rest)
            jobs[m.group(1)] = Job(m.group(1), rest[start:end])
        self.jobs = jobs


def _job_level_scalar(body: str, key: str) -> str | None:
    m = re.search(rf"(?m)^    {re.escape(key)}:\s*(.+?)\s*$", body)
    return m.group(1).strip() if m else None


def _job_level_bool(body: str, key: str) -> bool:
    v = _job_level_scalar(body, key)
    return v in {"true", "True", "yes", "on"}


def _die(msg: str) -> None:
    print(f"ci-policy: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _scripts_in_jobs(jobs: dict[str, Job], script: str) -> list[Job]:
    return [j for j in jobs.values() if script in j.scripts]


def check_ci(wf: Workflow) -> None:
    if "ci.yml" not in wf.path.name:
        return
    if not wf.per_push:
        _die(f"{wf.path.name} is not a push/PR workflow")
    if wf.scheduled:
        _die(f"{wf.path.name} must not be scheduled; peers belong on a sibling")

    soft = {n for n, j in wf.jobs.items() if j.continue_on_error}
    extra = soft - SOFT_PER_PUSH_JOBS
    missing_soft = SOFT_PER_PUSH_JOBS - set(wf.jobs)
    if extra:
        _die(f"{wf.path.name} continue-on-error jobs not allowed: {sorted(extra)}")
    if missing_soft:
        _die(f"{wf.path.name} missing soft jobs {sorted(missing_soft)}")

    for name in TIMEOUT_JOBS:
        job = wf.jobs.get(name)
        if job is None:
            _die(f"{wf.path.name} missing job {name}")
        if not job.timeout_minutes:
            _die(f"{wf.path.name} job {name} has no timeout-minutes")

    for script in FAIL_RED_PER_PUSH:
        hits = _scripts_in_jobs(wf.jobs, script)
        if not hits:
            _die(f"{script} is not in {wf.path.name}")
        if all(j.continue_on_error for j in hits):
            _die(f"{script} only runs on continue-on-error jobs")

    for script in NIGHTLY_BLOCKING:
        if _scripts_in_jobs(wf.jobs, script):
            _die(f"{script} must not run on per-push {wf.path.name}")

    if "actions/cache" not in wf.text:
        _die(f"{wf.path.name} has no actions/cache")
    if "docker save" not in wf.text or "docker load" not in wf.text:
        _die(f"{wf.path.name} must docker save and docker load the MIT image")
    if "harness/Dockerfile" not in wf.text or "hashFiles" not in wf.text:
        _die(f"{wf.path.name} cache key must hashFiles harness/Dockerfile")
    if "nextest" in wf.text and "--profile ci" not in wf.text:
        _die(f"{wf.path.name} cargo nextest must use --profile ci")


def check_nightly(workflows: list[Workflow]) -> None:
    scheduled = [w for w in workflows if w.scheduled]
    for script in NIGHTLY_BLOCKING:
        hits: list[tuple[Workflow, Job]] = []
        for w in scheduled:
            for j in _scripts_in_jobs(w.jobs, script):
                hits.append((w, j))
        if not hits:
            _die(f"{script} is not on a scheduled workflow")
        if any(j.continue_on_error for _, j in hits):
            _die(f"{script} is continue-on-error on a scheduled workflow")
        if any(not j.timeout_minutes for _, j in hits):
            _die(f"{script} scheduled job has no timeout-minutes")


def check_nextest() -> None:
    if not NEXTEST_TOML.is_file():
        _die("missing .config/nextest.toml")
    text = NEXTEST_TOML.read_text()
    if "slow-timeout" not in text:
        _die(".config/nextest.toml has no slow-timeout")
    if "terminate-after" not in text:
        _die(".config/nextest.toml slow-timeout must terminate hangs")


def _self_test() -> None:
    snippet = """name: ci
on:
  push:
    branches: [main]
jobs:
  harness:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - run: ./scripts/spake-gate.sh
  slo:
    continue-on-error: true
    timeout-minutes: 30
    steps:
      - run: ./scripts/stress-gate.sh
"""
    wf = Workflow(pathlib.Path("ci.yml"), snippet)
    assert wf.per_push and not wf.scheduled
    assert not wf.jobs["harness"].continue_on_error
    assert wf.jobs["slo"].continue_on_error
    assert wf.jobs["harness"].timeout_minutes == 45
    assert "spake-gate.sh" in wf.jobs["harness"].scripts
    assert "stress-gate.sh" in wf.jobs["slo"].scripts


def main() -> None:
    _self_test()
    if not WORKFLOWS.is_dir():
        _die(f"missing {WORKFLOWS}")
    workflows = [
        Workflow(p, p.read_text())
        for p in sorted(WORKFLOWS.glob("*.yml"))
    ]
    if not workflows:
        _die("no workflow YAML")
    ci = [w for w in workflows if w.path.name == "ci.yml"]
    if len(ci) != 1:
        _die("expected .github/workflows/ci.yml")
    check_ci(ci[0])
    check_nightly(workflows)
    check_nextest()
    print("ci-policy: ok")


if __name__ == "__main__":
    main()
