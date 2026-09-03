#!/usr/bin/env python3
"""Fail unless committed GitHub workflow YAML matches gate discipline.

Parses `.github/workflows/*.yml` (and `.config/nextest.toml`) rather than
a parallel copy of the job list. Job `continue-on-error` on the per-push
`ci` workflow is allowed only for stress/chaos/soak. Named deterministic
MIT extras must fail-red per SHA.
Samba PAC / realtrust / Heimdal must fail-red on a scheduled workflow.

Gate discipline (docs/testing.md): red-at-HEAD artefacts live under
working/ which is gitignored, so CI cannot check them. This script
checks workflow YAML, gate-script structure, and the MIT parity
ledger `proof` column.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
NEXTEST_TOML = ROOT / ".config" / "nextest.toml"
GITIGNORE = ROOT / ".gitignore"
SCRIPTS = ROOT / "scripts"
LEDGER = ROOT / "docs" / "mit-parity-ledger.md"

DIFFSEND_CASES = frozenset(
    {
        "garbage-pdu",
        "unknown-cname",
        "etype-nosupp",
        "wrong-realm",
        "pauser-no-preauth",
        "skewed-timestamp",
        "unknown-sname",
        "as-success",
        "tgs-success",
        "tgs-not-a-tgt",
        "tgt-expired",
        "tgt-nyv",
    }
)
_LEDGER_GATE = re.compile(r"(?:scripts/)?([A-Za-z0-9._-]+-gate(?:\.sh)?)")
_LEDGER_DIFFSEND = re.compile(r"diffsend `([^`]+)`")

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
    "capaths-compress-gate.sh",
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
    "msrv",
    "audit",
)

FULL_RUN_SCHEDULED = (
    "cargo nextest run --workspace --release",
    "cargo test --workspace --locked",
)

DOCUMENTED_STUBS = frozenset(
    {
        "gss-sspi-gate.sh",
        "ad-mit-trust-gate.sh",
    }
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
    if "nextest run --workspace --release" in wf.text:
        _die(f"{wf.path.name} must not run nextest --release; that is full-test.yml")


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


_NEXTEST_RUN = re.compile(r"cargo\s+nextest\s+run[^\n]*")
_CARGO_TEST_WS = re.compile(r"cargo\s+test\s+--workspace")
_CARGO_TEST_ALL = re.compile(r"cargo\s+test\s+--all(?:\s|$)")
_IF_ONELINER = re.compile(
    r"^\s*(if|elif)\b.*;\s*then\b.*;\s*fi\b",
)
_IF_START = re.compile(r"^\s*(if|elif)\b")
_ELSE = re.compile(r"^\s*else\b")
_FI = re.compile(r"^\s*fi\b")
_ASSERT_IN_IF = re.compile(
    r"""(?x)
    \b(exit|die|return|break|continue)\b
    | log\s+\S+\s+error
    | (?:^|[\s;])[A-Za-z_][A-Za-z0-9_]*=
    """
)
_NOISE_ONLY = re.compile(r"^(?:echo|printf|true)\b|^:(?:\s|$)")
_QUOTED = re.compile(r"""('([^'\\]|\\.)*'|"([^"\\]|\\.)*")""")


def _fold_continuations(text: str) -> str:
    return re.sub(r"\\\n\s*", " ", text)


def _strip_quoted(s: str) -> str:
    return _QUOTED.sub(" ", s)


def _echo_only_body(body: str) -> bool:
    stmts = [
        ln.strip()
        for ln in body.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not stmts:
        return False
    if not all(_NOISE_ONLY.match(s) for s in stmts):
        return False
    stripped = _strip_quoted(body)
    if "|" in stripped:
        return False
    if re.search(r">(?!&2)", stripped.replace(">&2", "")):
        return False
    if _ASSERT_IN_IF.search(stripped):
        return False
    if re.search(r'log\s+\S+\s+"error"', body):
        return False
    return True


def informational_if_starts(text: str) -> list[int]:
    """Line numbers of if-chains whose every arm is only echo/printf/: /true.

    Nested `fi` is paired by depth so an inner `if` cannot pop the outer
    frame. Quoted strings are stripped before token matching.
    """
    hits: list[int] = []
    # frame: start_line, arms (completed), current arm lines
    stack: list[tuple[int, list[str], list[str]]] = []

    def _arm_echo(lines: list[str]) -> bool:
        return _echo_only_body("\n".join(lines))

    def _close_if(start: int, arms: list[str], current: list[str]) -> bool:
        blobs = list(arms)
        if current:
            blobs.append("\n".join(current))
        informational = bool(blobs) and all(_echo_only_body(b) for b in blobs)
        if informational:
            hits.append(start)
        if stack:
            stack[-1][2].append("echo x" if informational else "exit 1")
        return informational

    def _after_then(line: str) -> str:
        parts = re.split(r"\bthen\b", line, maxsplit=1)
        return parts[1].strip() if len(parts) == 2 else ""

    for i, raw in enumerate(text.splitlines(), 1):
        hash_at = None
        in_s = in_d = False
        for j, ch in enumerate(raw):
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == "#" and not in_s and not in_d:
                hash_at = j
                break
        line = (raw[:hash_at] if hash_at is not None else raw).rstrip()
        if not line.strip():
            continue
        if _IF_ONELINER.search(line):
            then_m = re.search(r";\s*then\b(.*?)(?:;\s*else\b(.*))?;\s*fi\b", line)
            if then_m:
                arms = [p for p in then_m.groups() if p is not None]
                if arms and all(_echo_only_body(p) for p in arms):
                    hits.append(i)
                    if stack:
                        stack[-1][2].append("echo x")
                elif stack:
                    stack[-1][2].append("exit 1")
            continue
        if re.match(r"^\s*elif\b", line):
            if stack:
                start, arms, cur = stack[-1]
                if cur:
                    arms.append("\n".join(cur))
                stack[-1] = (start, arms, [])
                extra = _after_then(line)
                if extra:
                    stack[-1][2].append(extra)
            continue
        if _IF_START.match(line):
            extra = _after_then(line)
            stack.append((i, [], [extra] if extra else []))
            continue
        if _ELSE.match(line):
            if stack:
                start, arms, cur = stack[-1]
                if cur:
                    arms.append("\n".join(cur))
                extra = re.split(r"\belse\b", line, maxsplit=1)
                rest = extra[1].strip() if len(extra) == 2 else ""
                stack[-1] = (start, arms, [rest] if rest else [])
            continue
        if _FI.match(line):
            if stack:
                start, arms, cur = stack.pop()
                _close_if(start, arms, cur)
            continue
        if stack:
            stack[-1][2].append(line)
    return hits


def check_nextest_profile(workflows: list[Workflow]) -> None:
    for wf in workflows:
        folded = _fold_continuations(wf.text)
        cmds = _NEXTEST_RUN.findall(folded)
        if "nextest" in folded and not cmds:
            _die(f"{wf.path.name} mentions nextest but has no cargo nextest run")
        for cmd in cmds:
            if "--profile ci" not in cmd:
                _die(f"{wf.path.name} cargo nextest run missing --profile ci")


def check_ci_nextest_split(wf: Workflow) -> None:
    if "ci.yml" not in wf.path.name:
        return
    job = wf.jobs.get("test")
    if job is None:
        _die(f"{wf.path.name} missing job test")
    if "--no-run" not in job.body:
        _die(f"{wf.path.name} test job must cargo nextest --no-run")
    if "junit.xml" not in job.body:
        _die(f"{wf.path.name} test job must produce nextest junit.xml")
    if "upload-artifact" not in job.body:
        _die(f"{wf.path.name} test job must upload-artifact the junit")


def check_ci_no_workspace_cargo_test(wf: Workflow) -> None:
    if "ci.yml" not in wf.path.name:
        return
    folded = _fold_continuations(wf.text)
    if _CARGO_TEST_WS.search(folded) or _CARGO_TEST_ALL.search(folded):
        _die(f"{wf.path.name} must not run cargo test --workspace/--all on per-push")


def check_all_timeouts(workflows: list[Workflow]) -> None:
    for wf in workflows:
        if not wf.jobs:
            _die(f"{wf.path.name} has no jobs")
        for name, job in wf.jobs.items():
            if not job.timeout_minutes:
                _die(f"{wf.path.name} job {name} has no timeout-minutes")


def check_full_run_scheduled(workflows: list[Workflow]) -> None:
    scheduled = [w for w in workflows if w.scheduled]
    for needle in FULL_RUN_SCHEDULED:
        hits: list[tuple[Workflow, Job]] = []
        for w in scheduled:
            for j in w.jobs.values():
                if needle in j.body:
                    hits.append((w, j))
        if not hits:
            _die(f"{needle!r} is not on a scheduled workflow")
        if any(j.continue_on_error for _, j in hits):
            _die(f"{needle!r} is continue-on-error on a scheduled workflow")


def check_gate_membership(workflows: list[Workflow]) -> None:
    mentioned: set[str] = set()
    for w in workflows:
        mentioned.update(SCRIPT_RE.findall(w.text))
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        name = path.name
        if name in mentioned or name in DOCUMENTED_STUBS:
            continue
        _die(f"{name} is not in any workflow and not in DOCUMENTED_STUBS")


def check_no_informational_gates() -> None:
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        hits = informational_if_starts(path.read_text())
        if hits:
            _die(f"{path.name} informational if at line {hits[0]}")


def _split_ledger_row(line: str) -> list[str]:
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", inner)]


def check_ledger_proof_column(text: str | None = None) -> None:
    """Proof cells may name existing diffsend cases / *-gate.sh or `proposed`."""
    if text is None:
        if not LEDGER.is_file():
            _die("missing docs/mit-parity-ledger.md")
        text = LEDGER.read_text()
    existing = {p.name for p in SCRIPTS.glob("*-gate.sh")}
    for i, line in enumerate(text.splitlines(), 1):
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7:
            continue
        proof = cols[6]
        proposed = bool(re.search(r"\bproposed\b", proof, re.I))
        for m in _LEDGER_DIFFSEND.finditer(proof):
            case = m.group(1)
            if case not in DIFFSEND_CASES and not proposed:
                _die(
                    f"docs/mit-parity-ledger.md:{i} proof names diffsend `{case}` "
                    "which is not a live case (use proposed)"
                )
        for m in _LEDGER_GATE.finditer(proof):
            name = m.group(1)
            if not name.endswith(".sh"):
                name = name + ".sh"
            if name not in existing and not proposed:
                _die(
                    f"docs/mit-parity-ledger.md:{i} proof names {name} "
                    "which is not in scripts/ (use proposed)"
                )


def check_working_gitignored() -> None:
    if not GITIGNORE.is_file():
        _die("missing .gitignore")
    text = GITIGNORE.read_text()
    if "/working" not in text and "working/" not in text:
        _die(".gitignore must ignore working/ (red-at-HEAD artefacts)")
    if "__pycache__/" not in text:
        _die(".gitignore must ignore __pycache__/")


def check_nextest() -> None:
    if not NEXTEST_TOML.is_file():
        _die("missing .config/nextest.toml")
    text = NEXTEST_TOML.read_text()
    if "slow-timeout" not in text:
        _die(".config/nextest.toml has no slow-timeout")
    if "terminate-after" not in text:
        _die(".config/nextest.toml slow-timeout must terminate hangs")


def _must_die(fn, *args) -> None:
    err = sys.stderr
    sys.stderr = open("/dev/null", "w", encoding="utf-8")
    try:
        fn(*args)
        died = False
    except SystemExit:
        died = True
    finally:
        sys.stderr.close()
        sys.stderr = err
    if not died:
        raise AssertionError(f"{fn.__name__} must fail closed")


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

    no_timeout = Workflow(
        pathlib.Path("notimeout.yml"),
        "name: fuzz\non:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )
    _must_die(check_all_timeouts, [no_timeout])

    sched = Workflow(
        pathlib.Path("full-test.yml"),
        "name: full-test\non:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  test-release:\n    timeout-minutes: 40\n    steps:\n      - run: cargo nextest run --workspace --release --profile ci\n  msrv-test:\n    timeout-minutes: 30\n    steps:\n      - run: cargo test --workspace --locked\n",
    )
    check_full_run_scheduled([sched])
    check_nextest_profile([sched])
    check_all_timeouts([sched])

    echo_if = 'if ! grep -F foo /tmp/x; then\n    echo "informational fallback"\nfi\n'
    if not informational_if_starts(echo_if):
        raise AssertionError("informational echo if must be a violation")
    ok_if = 'if ! grep -F foo /tmp/x; then\n    exit 1\nfi\n'
    if informational_if_starts(ok_if):
        raise AssertionError("if with exit must pass")
    gss_shape = 'if [ "$ok" != 1 ]; then\n    echo "settled live"\nfi\n'
    if not informational_if_starts(gss_shape):
        raise AssertionError("if [ ] echo-only must be a violation")
    quoted_return = 'if true; then\n    echo "return from helper"\nfi\n'
    if not informational_if_starts(quoted_return):
        raise AssertionError("return inside quotes must not excuse echo-only")
    else_echo = 'if true; then\n    :\nelse\n    echo only\nfi\n'
    if not informational_if_starts(else_echo):
        raise AssertionError("else echo-only must be a violation")
    nested = 'if true; then\n    if false; then\n        echo inner\n    fi\n    exit 1\nfi\n'
    nested_hits = informational_if_starts(nested)
    if not nested_hits:
        raise AssertionError("nested echo-only if must be a violation")
    if nested_hits[0] == 1:
        raise AssertionError("nested fi must not pop the outer if")
    colon_if = 'if true; then\n    :\nfi\n'
    if not informational_if_starts(colon_if):
        raise AssertionError("colon-only if must be a violation")
    oneliner = 'if [ "$ok" != 1 ]; then echo settled; fi\n'
    if not informational_if_starts(oneliner):
        raise AssertionError("one-liner echo-only must be a violation")

    missing_profile = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace\n",
    )
    _must_die(check_nextest_profile, [missing_profile])

    cargo_test = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, cargo_test)

    no_junit = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace --profile ci --no-run\n",
    )
    _must_die(check_ci_nextest_split, no_junit)

    no_norun = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace --profile ci\n      - uses: actions/upload-artifact@v4\n        with:\n          path: target/nextest/ci/junit.xml\n",
    )
    _must_die(check_ci_nextest_split, no_norun)

    no_upload = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace --profile ci --no-run\n      - run: echo junit.xml\n",
    )
    _must_die(check_ci_nextest_split, no_upload)

    mentions_nextest = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: echo nextest is great\n",
    )
    _must_die(check_nextest_profile, [mentions_nextest])

    cargo_test_all = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --all\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, cargo_test_all)

    ledger_ok = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname`; `scripts/expire-gate.sh` |\n"
        "| kdc_util.c:2 | x | y | z | w | absent | proposed: diffsend `no-such-case`; proposed kdc-lookaside-gate.sh |\n"
    )
    check_ledger_proof_column(ledger_ok)
    ledger_bad_case = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `no-such-case` |\n"
    )
    _must_die(check_ledger_proof_column, ledger_bad_case)
    ledger_bad_gate = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | kdc-lookaside-gate.sh |\n"
    )
    _must_die(check_ledger_proof_column, ledger_bad_gate)


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
    check_ci_nextest_split(ci[0])
    check_ci_no_workspace_cargo_test(ci[0])
    check_nightly(workflows)
    check_nextest()
    check_nextest_profile(workflows)
    check_all_timeouts(workflows)
    check_full_run_scheduled(workflows)
    check_gate_membership(workflows)
    check_no_informational_gates()
    check_working_gitignored()
    check_ledger_proof_column()
    print("ci-policy: ok")


if __name__ == "__main__":
    main()
