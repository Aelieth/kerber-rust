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
ledger `proof` column. `--checkpoint` adds the local-evidence rules the
checkpoint runner owns (W1-Z Z3.4: no cargo build tree under
`working/logs/`).
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import io
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
NEXTEST_TOML = ROOT / ".config" / "nextest.toml"
GITIGNORE = ROOT / ".gitignore"
SCRIPTS = ROOT / "scripts"

DIFFSEND_CASES = frozenset(
    {
        "garbage-pdu",
        "unknown-cname",
        "etype-nosupp",
        "as-session-enctype",
        "wrong-realm",
        "pauser-no-preauth",
        "as-needpreauth-hints-unpermitted",
        "skewed-timestamp",
        "unknown-sname",
        "as-success",
        "tgs-success",
        "tgs-not-a-tgt",
        "tgt-expired",
        "tgt-nyv",
        "tgt-nyv-no-starttime",
        "fast-armor-no-subkey",
        "armor-ap-req-as-pa-tgs-req",
        "tgs-ad-fx-armor-authenticator",
        "as-bad-msg-type",
        "as-bad-pvno",
        "tgs-bad-msg-type",
        "as-service-not-allowed",
        "tgs-ap-options",
        "tgs-header-kvno-zero",
        "as-hw-preauth",
        "as-spake-round1",
        "u2u-2nd-ticket-unknown-server",
        "u2u-2nd-ticket-bad-etype",
        "u2u-2nd-ticket-corrupt",
        "tgs-pac-client-mismatch",
        "tgs-pac-corrupt-before-sname",
        "tgs-pac-request-false",
        "tgs-from-pacless-tgt",
        "tgs-renew-service-ticket",
        "tgs-proxy-krbtgt",
        "tgs-canonicalize-renew",
        "tgs-expired-vs-unknown-sname",
        "s4u2self-no-pac",
        "s4u2self-pac-client-mismatch",
        "pa-s4u-x509-user-bad-checksum",
        "pa-s4u-x509-user-nonce",
        "pa-for-user-only",
        "pa-s4u-x509-user-empty",
        "pa-for-user-undecodable",
        "pa-s4u-x509-user",
        "s4u2proxy-no-2nd-tkt",
        "s4u2proxy-not-forwardable",
        "s4u2proxy-u2u-combo",
        "s4u2proxy-tgs-target",
        "s4u2proxy-no-header-pac",
        "s4u2proxy-header-pac",
        "s4u2proxy-no-stkt-pac",
        "s4u2proxy-evidence-mismatch",
        "s4u2proxy-local-stkt-pac",
        "u2u-no-2nd-tkt",
        "u2u-2nd-ticket-not-tgs",
        "u2u-2nd-ticket-mismatch",
        "u2u-2nd-ticket-bad-pac",
        "u2u-bad-etype",
        "u2u-success",
        "tgs-addr-mismatch",
        "tgs-forwarded-addresses",
        "u2u-2nd-ticket-foreign-realm",
        "s4u2self-renew-options",
        "pa-s4u-x509-user-truncated",
        "s4u2self-krbtgt-other",
        "tgs-locked-pac-mismatch",
        "u2u-dup-skey-tgt-based",
        "tgs-expired-addr-mismatch",
        "tgs-expired-badmatch",
        "u2u-2nd-ticket-kvno-miss",
        "u2u-2nd-ticket-disallow-svr",
        "s4u2self-cert-only",
        "tgs-forwarded-tgt-addresses",
        "as-needchange",
        "as-invalid-opts",
        "as-validate-before-preauth",
        "as-optimistic-encts-wrong-etype",
        "as-retransmit",
        "as-request-anonymous",
        "tgs-pac-server-cksum-wrong-enctype",
        "u2u-2nd-ticket-pac-wrong-enctype",
        "u2u-success-offered",
        "tgs-forwarded-on-non-f-tgt",
        "tgs-proxy-on-non-p-tgt",
        "tgs-postdate-on-non-postdatable",
        "tgs-postdated-is-invalid",
        "tgs-validate-invalid-non-renewable",
        "tgs-till-in-past",
        "tgs-service-expired-require-auth",
        "tgs-postdated-from",
        "tgs-no-preauth-flag",
        "tgs-hw-preauth-flag",
        "tgs-nyv-inside-skew",
        "tgs-body-authdata",
        "tgs-ad-mandatory-for-kdc",
        "tgs-body-authdata-kdc-issued-stripped",
        "tgs-body-authdata-subkey",
        "tgs-body-authdata-session-ku5",
        "tgs-tgt-and-or-kept",
        "tgs-truncated-cammac",
        "ec-outside-fast",
        "tgs-rbcd-pac-options",
        "tgs-renew-header-end-before-start",
        "as-anonymous-unsigned-authpack-named-client",
        "as-fast-hide-error-client",
        "tgs-fast-hide-client",
        "pkinit-stale-freshness",
        "tgs-referral-no-dot",
        "tgs-alternate-tgs-hierarchical",
        "tgs-renew-postdated-from",
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
    "client-differential-flows-gate.sh",
    "client-differential-cli-gate.sh",
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
    "kadmin-rust-gate.sh",
    "kadmin-rust-acl-gate.sh",
    "kadmin-mit-gate.sh",
    "kadmin-both-gate.sh",
    "kpasswd-rust-gate.sh",
    "kpasswd-mit-gate.sh",
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
    "harness-2",
    "mit-extra",
    "mit-extra-2",
    "slo",
    "chaos",
    "soak",
    "mit-image",
    "msrv",
    "audit",
    "doc",
)

GATE_WALL_MAX = 45
GATE_PROTO_SLEEP_MAX = 26.0
UNIT_SLEEP_MAX = 14
PLAN_JOB_CAPS = {
    "test": 300,
    "harness": 270,
    "mit-extra": 180,
}
PLAN_RUN_WALL_CAP = 360
BUDGET_REQUIRED_JOBS = (
    "test",
    "harness",
    "mit-extra",
    "doc",
    "msrv",
    "audit",
    "ledger-mit",
    "mit-image",
)
EXCEPTIONS_REL = "scripts/gate-wall-exceptions.txt"

FULL_RUN_SCHEDULED = (
    "cargo nextest run --workspace --release",
    "cargo test --workspace --locked",
)

DOCUMENTED_STUBS = frozenset(
    {
        "gss-sspi-gate.sh",
        "ad-mit-trust-gate.sh",
        "kadmin-gate.sh",  # local wrapper; CI runs rust+mit+both steps
        "kpasswd-gate.sh",  # local wrapper; CI runs rust+mit steps
        "client-differential-gate.sh",  # local wrapper; CI runs flows+cli steps
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
    if wf.path.name != "ci.yml":
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
_CARGO_TEST_WS_DOC = re.compile(r"cargo\s+test\s+--workspace\s+--doc\b")
_IF_ONELINER = re.compile(
    r"^\s*(if|elif)\b.*;\s*then\b.*;\s*fi\b",
)
_IF_START = re.compile(r"^\s*(if|elif)\b")
_ELSE = re.compile(r"^\s*else\b")
_FI = re.compile(r"^\s*fi\b")
_NOISE_ONLY = re.compile(r"^(?:echo|printf|true|cat|tee)\b|^:(?:\s|$)")
_ASSIGN_ONLY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_QUOTED = re.compile(r"""('([^'\\]|\\.)*'|"([^"\\]|\\.)*")""")
_ASSERT_CMDS = frozenset(
    {"exit", "die", "return", "break", "continue", "unavailable"}
)
_TEST_CMDS = frozenset({"[", "[[", "test", "grep", "egrep", "fgrep", "cmp"})
_NOISE_CMDS = frozenset({"echo", "printf", "true", "cat", "tee", ":"})
_REQUIRE_DIE = re.compile(r"KERBER_REQUIRE_")
_LOG_ERROR = re.compile(r"""log\s+\S+\s+(?:error|"error")""")
_LOG_SKIP = re.compile(r"""log\s+\S+\s+(?:skip|"skip")""")
_OR_TRUE = re.compile(r"\|\|\s*true\s*$")
_PIPE = re.compile(r"(?<!\|)\|(?!\|)")
_REDIR = re.compile(r"(?:\d*)(?:>>?|<)\s*(\S+)")
_TEE_FILE = re.compile(r"\btee(?:\s+-a)?\s+(\S+)")
_DOLLAR_PAREN = re.compile(r"\$\([^()]*\)")
_HEREDOC = re.compile(
    r"(?:cat\s+)?<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n.*?^\1\s*$",
    re.M | re.S,
)
_BRACE_GROUP = re.compile(r"\{([^{}]*)\}(?:\s*(?:>>?|\|(?!\|))\s*\S+)?")
_PAREN_GROUP = re.compile(r"(?<!\$)\(([^()]*)\)(?:\s*(?:>>?|\|(?!\|))\s*\S+)?")


def _flatten_arm(body: str) -> str:
    """Unwrap `{...}`, `(...)`, and heredocs so wrappers cannot hide echo-only."""
    body = _HEREDOC.sub("echo heredoc", body)
    prev = None
    while prev != body:
        prev = body
        body = _BRACE_GROUP.sub(lambda m: m.group(1), body)
        body = _PAREN_GROUP.sub(lambda m: m.group(1), body)
    return body


def _fold_continuations(text: str) -> str:
    return re.sub(r"\\\n\s*", " ", text)


def _code_without_comment(line: str) -> str:
    in_s = in_d = False
    for j, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            return line[:j].rstrip()
    return line.rstrip()


def _join_shell_continuations(text: str) -> str:
    """Join `\\`, `||`, and `&&` continuations; blank the swallowed lines."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        code = _code_without_comment(lines[i])
        if code.endswith("\\") or re.search(r"(?:\|\||&&)\s*$", code):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                nxt = lines[j].lstrip()
                if code.endswith("\\"):
                    lines[i] = code[:-1].rstrip() + " " + nxt
                else:
                    lines[i] = code + " " + nxt
                lines[j] = ""
                continue
        i += 1
    return "\n".join(lines)


def _strip_quoted(s: str) -> str:
    return _QUOTED.sub(" ", s)


def _split_semi(line: str) -> list[str]:
    """Split on `;` that are not inside quotes."""
    out: list[str] = []
    buf: list[str] = []
    in_s = in_d = False
    for ch in line:
        if ch == "'" and not in_d:
            in_s = not in_s
            buf.append(ch)
        elif ch == '"' and not in_s:
            in_d = not in_d
            buf.append(ch)
        elif ch == ";" and not in_s and not in_d:
            piece = "".join(buf).strip()
            if piece:
                out.append(piece)
            buf = []
        else:
            buf.append(ch)
    piece = "".join(buf).strip()
    if piece:
        out.append(piece)
    return out or ([line.strip()] if line.strip() else [])


def _written_paths(body: str) -> set[str]:
    found: set[str] = set()
    for rx in (_TEE_FILE, _REDIR):
        for m in rx.finditer(body):
            tok = m.group(1)
            found.add(tok)
            found.add(tok.strip("'\""))
    return found


def _cmd_word(stage: str) -> str:
    s = _DOLLAR_PAREN.sub(" ", stage.strip())
    while True:
        m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=\S*\s+", s)
        if not m:
            break
        s = s[m.end() :]
    s = _QUOTED.sub(lambda m: m.group(0) if "$" in m.group(0) else " ", s)
    s = re.sub(r"(?:\d*)(?:>>?|<)\s*\S+", " ", s)
    s = re.sub(r"\d*>&?\d+", " ", s)
    s = s.strip()
    if s.startswith("[["):
        return "[["
    if s.startswith("["):
        return "["
    return (s.split() or [""])[0]


_LOGICAL_OPS = ("||", "&&")
_REQUIRE_NAME = re.compile(r"KERBER_REQUIRE_([A-Z0-9_]+)")
_CASE_START = re.compile(r"^\s*case\b.*\bin\s*$")
_ESAC = re.compile(r"^\s*esac\b")
_CASE_ARM = re.compile(r"^\s*\(?[^()$]*\)\s*(.*)$")


def _split_logical(stmt: str) -> list[tuple[str, str]]:
    """`(op, part)` pieces split on `||` / `&&` outside quotes; the first op is empty."""
    parts: list[tuple[str, str]] = []
    buf: list[str] = []
    op = ""
    in_s = in_d = False
    i = 0
    while i < len(stmt):
        ch = stmt[i]
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d and stmt[i : i + 2] in _LOGICAL_OPS:
            parts.append((op, "".join(buf).strip()))
            buf = []
            op = stmt[i : i + 2]
            i += 2
            continue
        buf.append(ch)
        i += 1
    parts.append((op, "".join(buf).strip()))
    return [(o, x) for o, x in parts if x]


def _is_tautology(
    cmd: str, stage: str, written: set[str], noise_written: frozenset[str], stmt: str
) -> bool:
    if cmd in {"[", "[[", "test"}:
        for w in written:
            if w and w in stage and re.search(r"(?:^|[\s[])-[sfe]\b", stage):
                return True
        if "$" not in stage:
            return True
    if cmd == "cmp":
        args = [a for a in _QUOTED.sub(" ", stage).split()[1:] if not a.startswith("-")]
        if len(args) >= 2 and (args[0] == args[1] or args[:2] == ["/dev/null", "/dev/null"]):
            return True
    if cmd in {"grep", "egrep", "fgrep"}:
        echo = re.search(r"\becho\b(.*)\|\s*(?:e|f)?grep\b", stmt)
        if echo is not None and "$" not in echo.group(1):
            return True
        if any(w and w in stage for w in noise_written):
            return True
    return False


def _part_kind(part: str, written: set[str], noise_written: frozenset[str]) -> str:
    stages = [s.strip() for s in _PIPE.split(part) if s.strip()] or [part]
    kinds: list[str] = []
    for stage in stages:
        if not stage or _ASSIGN_ONLY.match(stage):
            continue
        cmd = _cmd_word(stage).rsplit("/", 1)[-1]
        if not cmd:
            continue
        if cmd == "log" or cmd.startswith("log_"):
            kinds.append("assert" if re.search(r"\berror\b", stage) else "noise")
        elif cmd in _ASSERT_CMDS:
            kinds.append("assert")
        elif cmd in _TEST_CMDS:
            taut = _is_tautology(cmd, stage, written, noise_written, part)
            kinds.append("noise" if taut else "assert")
        elif cmd in _NOISE_CMDS or _NOISE_ONLY.match(stage):
            kinds.append("noise")
        else:
            kinds.append("work")
    if "assert" in kinds:
        return "assert"
    if "work" in kinds:
        return "work"
    return "noise"


def _stmt_kind(stmt: str, written: set[str], noise_written: frozenset[str] = frozenset()) -> str:
    """`assert`, `work`, or `noise`; a test whose `||` branch does not assert is noise."""
    parts = _split_logical(stmt.strip())
    if not parts:
        return "noise"
    kinds = [_part_kind(x, written, noise_written) for _, x in parts]
    for i in range(1, len(parts)):
        if kinds[i - 1] != "assert":
            continue
        if parts[i][0] == "||":
            kinds[i - 1] = "assert" if kinds[i] == "assert" else "noise"
        elif kinds[i] != "assert":
            kinds[i - 1] = kinds[i]
    if "assert" in kinds:
        return "assert"
    if "work" in kinds:
        return "work"
    return "noise"


def _noise_written(stmts: list[str]) -> frozenset[str]:
    noise: set[str] = set()
    work: set[str] = set()
    for s in stmts:
        for _, part in _split_logical(s):
            targets = _written_paths(part)
            if not targets:
                continue
            cmd = _cmd_word(part).rsplit("/", 1)[-1]
            (noise if cmd in _NOISE_CMDS else work).update(targets)
    return frozenset(noise - work)


def _echo_only_body(body: str, script: str = "") -> bool:
    """True when the arm is an informational skip, not a real assert or work."""
    flat = _flatten_arm(body)
    if _LOG_SKIP.search(flat) and re.search(r"\bdie\b", script):
        low = flat.lower()
        if any(name.lower() in low for name in _REQUIRE_NAME.findall(script)):
            return False
    stmts: list[str] = []
    for ln in flat.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        stmts.extend(_split_semi(s))
    if not stmts:
        return False
    written = _written_paths(flat)
    noise_written = _noise_written(stmts)
    actionable = [s for s in stmts if not _ASSIGN_ONLY.match(s)]
    if not actionable:
        return False
    return all(_stmt_kind(s, written, noise_written) == "noise" for s in actionable)


def _case_informational_starts(text: str) -> list[int]:
    hits: list[int] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if not _CASE_START.match(lines[i]):
            i += 1
            continue
        start = i + 1
        depth = 1
        arms: list[list[str]] = []
        cur: list[str] | None = None
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if _CASE_START.match(line):
                depth += 1
            elif _ESAC.match(line):
                depth -= 1
                if depth == 0:
                    break
            elif depth == 1:
                m = _CASE_ARM.match(line)
                if cur is None and m:
                    cur = [m.group(1)] if m.group(1).strip() else []
                elif cur is not None:
                    cur.append(line)
                if cur is not None and line.rstrip().endswith(";;"):
                    cur[-1] = cur[-1].rstrip()[:-2]
                    arms.append(cur)
                    cur = None
            j += 1
        if cur:
            arms.append(cur)
        if any(_echo_only_body("\n".join(a), text) for a in arms if "\n".join(a).strip()):
            hits.append(start)
        i = j + 1
    return hits


def informational_if_starts(text: str) -> list[int]:
    """Line numbers of if-chains with any echo-only then/elif/else arm.

    Nested `fi` is paired by depth so an inner `if` cannot pop the outer
    frame. Each arm is tokenised: assignments, redirections, quotes and
    `$(…)` do not supply assertion words. An assertion is a command in
    {exit, die, return, break, continue, unavailable, log … error} or a
    test (`[`, `[[`, `test`, `grep`, `cmp`) whose `||` branch, if any,
    asserts, and that is not a self-tautology (a `grep` of a file the arm
    wrote with `echo` is one). `case` arms are walked like `if` arms.
    `log … skip` is accepted only when the arm names a `KERBER_REQUIRE_`
    requirement that a `die` in the same script enforces.
    """
    text = _join_shell_continuations(text)
    hits: list[int] = []
    # frame: start_line, arms (completed), current arm lines
    stack: list[tuple[int, list[str], list[str]]] = []

    def _close_if(start: int, arms: list[str], current: list[str]) -> bool:
        blobs = list(arms)
        if current:
            blobs.append("\n".join(current))
        any_echo = bool(blobs) and any(_echo_only_body(b, text) for b in blobs)
        all_echo = bool(blobs) and all(_echo_only_body(b, text) for b in blobs)
        if any_echo:
            hits.append(start)
        if stack:
            stack[-1][2].append("echo x" if all_echo else "exit 1")
        return any_echo

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
            flat = [
                m.group(1)
                for m in re.finditer(
                    r";\s*(?:then|elif\b.*?;\s*then|else)\b(.*?)(?=;\s*(?:elif\b|else\b|fi\b)|$)",
                    line,
                )
            ]
            if flat and any(_echo_only_body(p, text) for p in flat):
                hits.append(i)
                if stack:
                    stack[-1][2].append(
                        "echo x" if all(_echo_only_body(p, text) for p in flat) else "exit 1"
                    )
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
        if re.match(r"^\s*then\b", line) and stack:
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
    hits.extend(_case_informational_starts(text))
    return sorted(set(hits))


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
    if wf.path.name != "ci.yml":
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
    if wf.path.name != "ci.yml":
        return
    folded = _fold_continuations(wf.text)
    # `cargo test --workspace --doc` is the doctest runner (nextest never runs
    # doctests). Any other workspace `cargo test` re-runs the unit suite.
    allowed = _CARGO_TEST_WS_DOC.sub("", folded)
    if _CARGO_TEST_WS.search(allowed) or _CARGO_TEST_ALL.search(allowed):
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


def check_gate_membership(
    workflows: list[Workflow] | None = None,
    fail_red: tuple[str, ...] | None = None,
    stubs: frozenset[str] | None = None,
    gate_names: list[str] | None = None,
) -> None:
    """Every gate is in some workflow; every FAIL_RED_PER_PUSH gate is a per-push ci.yml step."""
    if workflows is None:
        workflows = [
            Workflow(p, p.read_text())
            for p in sorted(WORKFLOWS.glob("*.yml"))
        ]
    if fail_red is None:
        fail_red = FAIL_RED_PER_PUSH
    if stubs is None:
        stubs = DOCUMENTED_STUBS
    mentioned: set[str] = set()
    for w in workflows:
        mentioned.update(SCRIPT_RE.findall(w.text))
    if gate_names is None:
        gate_names = [p.name for p in sorted(SCRIPTS.glob("*-gate.sh"))]
    for name in gate_names:
        if name in mentioned or name in stubs:
            continue
        _die(f"{name} is not in any workflow and not in DOCUMENTED_STUBS")
    ci_wfs = [w for w in workflows if w.path.name == "ci.yml"]
    if not ci_wfs:
        _die("check_gate_membership needs ci.yml")
    ci = ci_wfs[0]
    for script in fail_red:
        hits = _scripts_in_jobs(ci.jobs, script)
        if not hits:
            _die(f"{script} is not a per-push ci.yml step")
        if all(j.continue_on_error for j in hits):
            _die(f"{script} only runs on continue-on-error ci.yml jobs")


def check_no_informational_gates() -> None:
    paths = list(SCRIPTS.glob("*-gate.sh")) + list((SCRIPTS / "lib").glob("*.sh"))
    for path in sorted(paths):
        hits = informational_if_starts(path.read_text())
        if hits:
            rel = path.relative_to(ROOT)
            _die(f"{rel} informational if at line {hits[0]}")


_PROVENANCE_SRC = re.compile(
    r"""\.\s+["']\$ROOT/scripts/lib/provenance\.sh["']"""
)
_HOST_TMP_REDIR = re.compile(
    r"(?:^|[\s;|&])(?:\d*)>>?\s*/tmp/"
    r"|(?:^|[\s;|&])(?:cp|tee|mv|mkdir|touch|install)\b[^\n;|&]*\s/tmp/"
    r"|\$\([^)]*>>?\s*/tmp/"
)
_HEREDOC_DELIM = re.compile(r"""(?<!<)<<(?!<)[-]?\s*['\"]?(\w+)['\"]?""")
_UNQUOTED_REDIR = re.compile(r"(?:^|[\s;|&])(?:\d*)>>?\s*$")
_UNQUOTED_CP = re.compile(
    r"(?:^|[\s;|&])(?:cp|tee|mv|mkdir|touch|install)\b"
)
_QUOTED_TMP = re.compile(r"""['\"]/tmp/""")
# `mktemp` / `mktemp -d` with no template and no -p/--tmpdir lands in host /tmp
# (W3-S1). A template or `-p DIR` follows the flags; a bare call hits a closer.
_BARE_MKTEMP = re.compile(r"(?<![\w-])mktemp\b(?:\s+-[a-zA-Z]+)*\s*(?=$|[)|&;>])")
_QUOTED_REDIR_TMP = re.compile(r""">>?\s*['\"]/tmp/""")


def _quoted_host_tmp(raw: str, unquoted: str) -> bool:
    """Host `>"/tmp/…"` or `cp x "/tmp/…"`; `>` inside a quote is not a host write."""
    if _UNQUOTED_REDIR.search(unquoted.rstrip()) and _QUOTED_REDIR_TMP.search(raw):
        return True
    return bool(_UNQUOTED_CP.search(unquoted) and _QUOTED_TMP.search(raw))


def check_gate_provenance(text: str | None = None, name: str = "gate.sh") -> None:
    """Every *-gate.sh and red-at-sha.sh must source the stamp helper."""
    if text is not None:
        if not _PROVENANCE_SRC.search(text):
            _die(f"{name} must source scripts/lib/provenance.sh")
        return
    missing: list[str] = []
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        if not _PROVENANCE_SRC.search(path.read_text()):
            missing.append(path.name)
    ras = SCRIPTS / "red-at-sha.sh"
    if ras.is_file() and not _PROVENANCE_SRC.search(ras.read_text()):
        missing.append(ras.name)
    if missing:
        _die(f"must source scripts/lib/provenance.sh: {missing}")


def check_docker_cp_cargo_target() -> None:
    """Gate docker cp must use ${CARGO_TARGET_DIR:-target}/debug (not a bare target/debug)."""
    bare: list[str] = []
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        text = path.read_text()
        if "docker cp target/debug/" in text:
            bare.append(path.name)
        if "docker cp" in text and "CARGO_TARGET_DIR:-target" not in text:
            # Some gates only docker cp fixtures; require the expansion when copying binaries.
            if re.search(r"docker cp .*krb5-|docker cp .*diffsend|docker cp .*examples/", text):
                bare.append(path.name)
    if bare:
        _die(
            "docker cp of cargo binaries must use "
            "${CARGO_TARGET_DIR:-target}/debug: "
            f"{sorted(set(bare))}"
        )


def _skip_dollar_arith(line: str, k: int) -> int:
    """Advance past `$((…))` starting at `$`. Returns `len(line)` if unclosed."""
    k += 3
    n = len(line)
    while k + 1 < n:
        if line[k] == ")" and line[k + 1] == ")":
            return k + 2
        k += 1
    return n


def _push_cmdsubst(in_sq: list[bool], in_dq: list[bool], in_ansi: list[bool]) -> None:
    in_sq.append(False)
    in_dq.append(False)
    in_ansi.append(False)


_DOCKER_CMD = re.compile(r"\bdocker\s+(?:exec|run)\b")
_DOCKER_HOST_OP = re.compile(r"(?:&&|\|\||;&|\|&|[;&|]|[0-9]*>>?)")


def _host_side_code(code: str) -> str:
    """Drop `docker exec`/`run` argv; keep host redirects, pipes, and later commands."""
    out: list[str] = []
    i = 0
    while i < len(code):
        m = _DOCKER_CMD.search(code, i)
        if not m:
            out.append(code[i:])
            break
        out.append(code[i : m.start()])
        op = _DOCKER_HOST_OP.search(code, m.end())
        if not op:
            break
        i = op.start()
    return "".join(out)


def host_tmp_write_lines(text: str) -> list[int]:
    """Host-level `>/tmp/` writes, skipping quotes, `$(…)`, and heredocs.

    A quoted closer (`EOF'`, `EOF"`) ends the heredoc. The delimiter is
    taken from the unquoted host-side text (`<<<` is not a heredoc).
    Quoted redirect targets are scanned. Quoted `sh -c '…'` payloads are
    stripped; a host redirect on the same docker line is not.
    """
    hits: list[int] = []
    in_sq = [False]
    in_dq = [False]
    in_ansi = [False]
    heredoc_end: str | None = None
    for i, line in enumerate(text.splitlines(), 1):
        if heredoc_end is not None:
            s = line.strip()
            if s == heredoc_end:
                heredoc_end = None
            elif s == heredoc_end + "'":
                heredoc_end = None
                in_sq[-1] = False
            elif s == heredoc_end + '"':
                heredoc_end = None
                in_dq[-1] = False
            continue
        started_quoted = in_sq[-1] or in_dq[-1] or in_ansi[-1]
        buf: list[str] = []
        k = 0
        n = len(line)
        while k < n:
            ch = line[k]
            if in_ansi[-1]:
                if ch == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ch == "'":
                    in_ansi[-1] = False
                k += 1
                continue
            if in_sq[-1]:
                if ch == "'":
                    in_sq[-1] = False
                k += 1
                continue
            if in_dq[-1]:
                if ch == "\\" and k + 1 < n:
                    k += 2
                    continue
                if ch == '"':
                    in_dq[-1] = False
                    k += 1
                    continue
                if ch == "$" and k + 1 < n and line[k + 1] == "(":
                    if k + 2 < n and line[k + 2] == "(":
                        k = _skip_dollar_arith(line, k)
                    else:
                        _push_cmdsubst(in_sq, in_dq, in_ansi)
                        k += 2
                    continue
                k += 1
                continue
            if ch == "\\" and k + 1 < n:
                buf.append(line[k + 1])
                k += 2
                continue
            if ch == "$" and k + 1 < n and line[k + 1] == "'":
                in_ansi[-1] = True
                k += 2
                continue
            if ch == "'":
                in_sq[-1] = True
                k += 1
                continue
            if ch == '"':
                in_dq[-1] = True
                k += 1
                continue
            if ch == "$" and k + 1 < n and line[k + 1] == "(":
                if k + 2 < n and line[k + 2] == "(":
                    k = _skip_dollar_arith(line, k)
                else:
                    _push_cmdsubst(in_sq, in_dq, in_ansi)
                    k += 2
                continue
            if ch == ")" and len(in_sq) > 1:
                in_sq.pop()
                in_dq.pop()
                in_ansi.pop()
                k += 1
                continue
            if ch == "#":
                break
            buf.append(ch)
            k += 1
        unquoted = "".join(buf)
        code = _host_side_code(unquoted)
        raw = line[:k]
        if not started_quoted and "<<" in unquoted:
            m = _HEREDOC_DELIM.search(raw)
            if m:
                heredoc_end = m.group(1)
        if "KERBER_SCRATCH:-" in code or "KERBER_SCRATCH:-" in raw:
            continue
        if _HOST_TMP_REDIR.search(code) or _quoted_host_tmp(raw, code):
            hits.append(i)
        elif "mktemp" in code and "TMPDIR=" not in code and _BARE_MKTEMP.search(raw):
            hits.append(i)
    return hits


def _blank_rust(src: str) -> str:
    """Blank comments and string/char bodies via `strip_noncode`. Same length."""
    try:
        blanked = _hygiene_inventory().strip_noncode(src)
    except Exception as exc:
        _die(f"isolate_test_krb5 strip_noncode failed: {exc}")
    if len(blanked) != len(src):
        _die("isolate_test_krb5 strip_noncode length mismatch")
    return blanked


def _attr_end(src: str, start: int) -> int | None:
    """Index after the `]` that closes `#[…]` at `start`, or None if unclosed."""
    if not src.startswith("#[", start):
        return None
    depth = 0
    i = start + 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _top_level_comma_args(inner: str) -> list[str]:
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    for c in inner:
        if c == "(":
            depth += 1
            buf.append(c)
        elif c == ")":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
    if buf:
        args.append("".join(buf).strip())
    return args


def _cfg_pred_is_test(pred: str) -> bool:
    compact = "".join(pred.split())
    if compact == "test":
        return True
    for head in ("all(", "any("):
        if compact.startswith(head) and compact.endswith(")"):
            inner = compact[len(head) : -1]
            if any(arg == "test" for arg in _top_level_comma_args(inner)):
                return True
    return False


def _cfg_attr_is_test(attr: str) -> bool:
    compact = "".join(attr.split())
    if not (compact.startswith("#[cfg(") and compact.endswith(")]")):
        return False
    return _cfg_pred_is_test(compact[len("#[cfg(") : -2])


def _cfg_test_ranges(src: str) -> list[tuple[int, int]]:
    """Byte ranges of cfg(test) items on blanked source.

    `#[cfg(test)]` matches anywhere on a line; `cfg(all|any(..., test, ...))`
    counts. Brace-match on the blanked text (no quote scanner). An unclosed
    item runs to EOF.
    """
    blanked = _blank_rust(src)
    ranges: list[tuple[int, int]] = []
    n = len(blanked)
    i = 0
    while True:
        j = blanked.find("#[cfg(", i)
        if j < 0:
            break
        end_attr = _attr_end(blanked, j)
        if end_attr is None:
            ranges.append((j, n))
            break
        if not _cfg_attr_is_test(blanked[j:end_attr]):
            i = end_attr
            continue
        k = end_attr
        while True:
            while k < n and blanked[k] in " \t\r\n":
                k += 1
            if k < n and blanked.startswith("#[", k):
                close = _attr_end(blanked, k)
                if close is None:
                    ranges.append((k, n))
                    return ranges
                k = close
                continue
            break
        if k >= n:
            ranges.append((end_attr, n))
            break
        p = k
        depth = 0
        end = n
        while p < n:
            c = blanked[p]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = p + 1
                    break
            elif c == ";" and depth == 0:
                end = p + 1
                break
            p += 1
        ranges.append((k, end))
        i = end
    return ranges


def _cfg_test_has_temp_dir(src: str) -> bool:
    """True if a host-/tmp call sits inside a cfg(test) item, not after one."""
    blanked = _blank_rust(src)
    for a, b in _cfg_test_ranges(src):
        if "temp_dir()" in blanked[a:b] or "/tmp/kerber-test-krb5" in src[a:b]:
            return True
    return False


def check_isolate_test_krb5(
    text: str | None = None,
    tests_text: str | None = "",
    src_files: dict[str, str] | None = None,
    root: pathlib.Path | None = None,
) -> None:
    """Unit-test isolate helper must not write host `/tmp`."""
    root_dir = pathlib.Path(root) if root is not None else ROOT
    if text is None:
        path = root_dir / "crates/krb5-config/src/testenv.rs"
        if not path.is_file():
            _die("missing crates/krb5-config/src/testenv.rs")
        text = path.read_text()
        tests_path = root_dir / "crates/krb5-config/src/tests.rs"
        if not tests_path.is_file():
            _die("missing crates/krb5-config/src/tests.rs")
        tests_text = tests_path.read_text()
        if src_files is None:
            src_dir = root_dir / "crates/krb5-config/src"
            src_files = {
                p.name: p.read_text()
                for p in sorted(src_dir.glob("*.rs"))
                if p.is_file()
            }
    if "fn isolate_test_krb5" not in text:
        _die("isolate_test_krb5 missing")
    blanked = _blank_rust(text)
    if "temp_dir()" in blanked or "/tmp/kerber-test-krb5" in text:
        _die("isolate_test_krb5 writes host /tmp")
    if tests_text:
        tests_blanked = _blank_rust(tests_text)
        if "temp_dir()" in tests_blanked:
            _die("cfg(test) writes host /tmp via temp_dir()")
    if src_files:
        for name, src in src_files.items():
            if name in ("tests.rs", "testenv.rs"):
                continue
            if _cfg_test_has_temp_dir(src):
                _die(f"{name} cfg(test) writes host /tmp via temp_dir()")


def check_no_host_tmp_writes(
    text: str | None = None,
    name: str = "gate.sh",
    files: dict[str, str] | None = None,
) -> None:
    """No host `/tmp/` writes (nor bare `mktemp`) in scripts/*.sh or scripts/lib outside KERBER_SCRATCH defaults."""
    if text is not None:
        hits = host_tmp_write_lines(text)
        if hits:
            _die(f"{name} host /tmp write at line {hits[0]}")
        return
    if files is None:
        files = {
            p.name: p.read_text()
            for p in sorted(SCRIPTS.glob("*.sh"))
        }
        lib = SCRIPTS / "lib"
        if lib.is_dir():
            for path in sorted(lib.glob("*.sh")):
                files[f"lib/{path.name}"] = path.read_text()
    for fname, body in files.items():
        hits = host_tmp_write_lines(body)
        if hits:
            _die(f"{fname} host /tmp write at line {hits[0]}")


def check_red_at_sha_target_trap(text: str | None = None) -> None:
    """W1-Z Z3.4: the cargo tree goes in the EXIT trap (kept only by
    KERBER_KEEP_RED_TARGET=1) and every run stamps `red-at-parent=1`."""
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text()
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    m = re.search(r"cleanup\(\)\s*\{(.*?)\n\}", code, re.S)
    if not m:
        _die("red-at-sha.sh has no cleanup() trap body")
    body = m.group(1)
    if 'rm -rf "$TARGET"' not in body:
        _die("red-at-sha.sh cleanup() must remove the red-target cargo tree (Z3.4)")
    if "KERBER_KEEP_RED_TARGET" not in body:
        _die("red-at-sha.sh cleanup() must keep the tree only under KERBER_KEEP_RED_TARGET=1")
    if "trap cleanup EXIT" not in code:
        _die("red-at-sha.sh must arm cleanup on EXIT")
    if 'echo "red-at-parent=1"' not in code:
        _die("red-at-sha.sh must stamp red-at-parent=1 in its provenance block")


_RED_TARGET_DIR = re.compile(r"^red-target-[0-9a-f]{6,}$")


def find_red_target_trees(root: pathlib.Path) -> list[pathlib.Path]:
    """`red-target-*` dirs and any cargo build tree (CACHEDIR.TAG + debug/) under root."""
    found: list[pathlib.Path] = []
    if not root.is_dir():
        return found
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        names = {e.name for e in entries}
        if _RED_TARGET_DIR.match(d.name) or ("CACHEDIR.TAG" in names and "debug" in names):
            found.append(d)
            continue  # do not descend into a build tree
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                stack.append(pathlib.Path(e.path))
    return sorted(found)


def check_no_red_target_trees(root: pathlib.Path | None = None) -> None:
    """W1-Z Z3.4 (checkpoint runner only — `working/` is gitignored, so CI never
    sees it): no rebuildable cargo tree may sit inside the evidence dirs."""
    root = ROOT / "working" / "logs" if root is None else root
    trees = find_red_target_trees(root)
    if trees:
        listing = "\n  ".join(str(t.relative_to(ROOT)) if t.is_relative_to(ROOT) else str(t) for t in trees)
        total = subprocess.run(
            ["du", "-sch", *map(str, trees)], capture_output=True, text=True, check=False
        ).stdout.strip().splitlines()
        size = total[-1].split("\t")[0] if total else "?"
        _die(
            f"{len(trees)} cargo build tree(s) under {root} ({size}); they are rebuildable "
            "scratch, the stamped unit-red-*.log keeps the rc and FAILED list — "
            "working/w1-sweep/plan-w1z-0913-1915.md Z5: find working/logs/w1-sweep -type d -name 'red-target-*' "
            f"-prune -exec rm -rf {{}} +\n  {listing}"
        )


def check_red_at_sha_overlay_order(text: str | None = None) -> None:
    """`scripts/*.sh` must be copied before `write-tree` so tree_sha includes the gate."""
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text()
    write = -1
    cp = -1
    offset = 0
    for line in text.splitlines(True):
        code = line.split("#", 1)[0]
        if write < 0 and "write-tree" in code:
            write = offset
        if cp < 0 and re.search(r'cp\s+"\$ROOT/scripts/"\*\.sh', code):
            cp = offset
        offset += len(line)
    if write < 0:
        _die("red-at-sha.sh has no write-tree")
    if cp < 0 or cp > write:
        _die("red-at-sha.sh must overlay scripts/*.sh before write-tree")


def _split_ledger_row(line: str) -> list[str]:
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", inner)]


_LEDGER_KEYS = ("A1", "A2", "A3", "A4", "A5", "B1")
_PARITY_FILE = re.compile(r"^(?P<key>[ab][1-9])-[a-z0-9][a-z0-9-]*\.md$")


def _ledger_rows(text: str) -> list[tuple[int, str, list[str]]]:
    """(line number, line, cells) of every ledger table row (seven or more cells, not a header)."""
    rows = []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.startswith("|") or "MIT file:line" in line or line.startswith("| ---"):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7 or cols[5] == "verdict":
            continue
        rows.append((i, line, cols))
    return rows


def ledger_sources(root: pathlib.Path | None = None) -> list[tuple[str, str, str | None]]:
    """The ledger as (repo path, text, section key) triples, in reading order.

    Split layout, once `docs/parity/` holds section files: `docs/parity/README.md` first (the
    header: counts, verdict tally, the live diffsend list; no rows; key None), then every
    `docs/parity/<a1..a5|b1>-*.md` in sorted order, keyed by its file name. Single layout
    otherwise: `docs/mit-parity-ledger.md`, key None (its `## A1` ... headings give the sections).
    Red: a split with no README, a section file whose name or first heading gives no section or
    the wrong one, two files for one section, rows in the README, and rows left in
    `docs/mit-parity-ledger.md` beside the split.
    """
    root = ROOT if root is None else root
    single = root / "docs" / "mit-parity-ledger.md"
    parity = root / "docs" / "parity"
    sections = sorted(p for p in parity.glob("*.md") if p.name != "README.md") if parity.is_dir() else []
    if not sections:
        if not single.is_file():
            _die("missing docs/mit-parity-ledger.md (or docs/parity/)")
        return [("docs/mit-parity-ledger.md", single.read_text(encoding="utf-8"), None)]
    readme = parity / "README.md"
    if not readme.is_file():
        _die("docs/parity/ has section files but no README.md (the ledger header)")
    head = readme.read_text(encoding="utf-8")
    if _ledger_rows(head):
        _die("docs/parity/README.md holds ledger rows; rows live in the section files")
    if single.is_file() and _ledger_rows(single.read_text(encoding="utf-8")):
        _die("docs/mit-parity-ledger.md still holds rows beside docs/parity/; it must be a pointer")
    out: list[tuple[str, str, str | None]] = [("docs/parity/README.md", head, None)]
    seen: dict[str, str] = {}
    for path in sections:
        m = _PARITY_FILE.match(path.name)
        key = m.group("key").upper() if m else None
        if key not in _LEDGER_KEYS:
            _die(f"docs/parity/{path.name} names no ledger section (want a1..a5 or b1)")
        if key in seen:
            _die(f"docs/parity/{path.name} and docs/parity/{seen[key]} both hold section {key}")
        seen[key] = path.name
        text = path.read_text(encoding="utf-8")
        first = next((line for line in text.splitlines() if line.startswith("# ")), "")
        if not re.match(rf"^# {key}\b", first):
            _die(f"docs/parity/{path.name}: first heading {first!r} does not name section {key}")
        out.append((f"docs/parity/{path.name}", text, key))
    return out


def check_ledger_layout(root: pathlib.Path | None = None) -> None:
    """The ledger's files are well formed (`ledger_sources`) and no row appears twice.

    A row is identified by its MIT cite and check cells, so a moved row left behind in its old file,
    or one row copied into two files, is red in either layout.
    """
    seen: dict[tuple[str, str], str] = {}
    for name, text, _key in ledger_sources(root):
        for i, _line, cols in _ledger_rows(text):
            ident = (cols[0], cols[1])
            if ident in seen:
                _die(f"{name}:{i} repeats the ledger row at {seen[ident]}")
            seen[ident] = f"{name}:{i}"


def check_ledger_proof_column(text: str | None = None, name: str = "docs/mit-parity-ledger.md") -> None:
    """Proof cells may name existing diffsend cases / *-gate.sh or `proposed`."""
    if text is None:
        for src_name, src_text, _key in ledger_sources():
            check_ledger_proof_column(src_text, src_name)
        return
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
        for clause in (c.strip() for c in proof.split(";") if c.strip()):
            proposed = bool(re.search(r"\bpropose(?:d)?\b", clause, re.I))
            for m in _LEDGER_DIFFSEND.finditer(clause):
                case = m.group(1)
                if case not in DIFFSEND_CASES and not proposed:
                    _die(
                        f"{name}:{i} proof names diffsend `{case}` "
                        "which is not a live case (use proposed)"
                    )
            for m in _LEDGER_GATE.finditer(clause):
                gate = m.group(1)
                if not gate.endswith(".sh"):
                    gate = gate + ".sh"
                if gate not in existing and not proposed:
                    _die(
                        f"{name}:{i} proof names {gate} "
                        "which is not in scripts/ (use proposed)"
                    )


_LEDGER_CASES_HDR = re.compile(
    r"The [\w-]+ live `diffsend` cases are ((?:`[^`]+`(?:,\s*)?)+)",
    re.S,
)


DIFFSEND_SRC = ROOT / "crates/krb5-tools/src/bin/diffsend.rs"


def diffsend_source_cases(src: str) -> set[str]:
    """Copy 1 of the case list: every `expect_*(&cfg, "name"` call and every
    `"case":"name"` literal the driver prints itself."""
    names = set(re.findall(r'expect_\w+\(\s*&cfg,\s*"([^"]+)"', src, re.S))
    names |= set(re.findall(r'"case":"([^"{]+)"', src))
    return names


def check_diffsend_cases(
    ledger: str | None = None, gate: str | None = None, src: str | None = None
) -> None:
    """The four copies of the diffsend case list agree: the driver's names
    (copy 1), DIFFSEND_CASES here, the ledger header, and the gate — which
    must grep every case and pin the same ratchet the driver's summary
    claims (W1-Z Z3.3)."""
    if ledger is None:
        ledger = ledger_sources()[0][1]
    gate_path = SCRIPTS / "differential-gate.sh"
    if gate is None:
        if not gate_path.is_file():
            _die("missing scripts/differential-gate.sh")
        gate = gate_path.read_text()
    if src is None:
        if not DIFFSEND_SRC.is_file():
            _die(f"missing {DIFFSEND_SRC.relative_to(ROOT)}")
        src = DIFFSEND_SRC.read_text()
    hdr = _LEDGER_CASES_HDR.search(ledger)
    if not hdr:
        _die("the ledger header (docs/parity/README.md or docs/mit-parity-ledger.md) missing live diffsend cases list")
    names = set(re.findall(r"`([^`]+)`", hdr.group(1)))
    if names != set(DIFFSEND_CASES):
        missing = sorted(DIFFSEND_CASES - names)
        extra = sorted(names - DIFFSEND_CASES)
        _die(
            f"DIFFSEND_CASES vs ledger header: missing {missing} extra {extra}"
        )
    src_names = diffsend_source_cases(src)
    if src_names != set(DIFFSEND_CASES):
        _die(
            "diffsend.rs case names vs DIFFSEND_CASES: "
            f"only in diffsend.rs {sorted(src_names - DIFFSEND_CASES)}; "
            f"only in DIFFSEND_CASES {sorted(DIFFSEND_CASES - src_names)}"
        )
    m = re.search(r"^DIFFSEND_RATCHET=(\d+)\s*$", gate, re.M)
    if not m:
        _die("scripts/differential-gate.sh missing DIFFSEND_RATCHET=N")
    n = int(m.group(1))
    if n != len(DIFFSEND_CASES):
        _die(
            f"scripts/differential-gate.sh DIFFSEND_RATCHET={n} != "
            f"DIFFSEND_CASES {len(DIFFSEND_CASES)}"
        )
    if '"case":"[^"]*","outcome":"ok"' not in gate or "$CASES_SEEN" not in gate:
        _die("scripts/differential-gate.sh must count the distinct emitted ok cases against the ratchet")
    claimed = re.search(r'"outcome":"ok","cases":(\d+)\}', src)
    if not claimed or int(claimed.group(1)) != n:
        _die(
            "diffsend.rs summary line claims "
            f"{claimed.group(1) if claimed else 'no'} cases; the gate ratchet is {n}"
        )
    grepped = set(re.findall(r'"case":"([^"]+)"', gate))
    ungrepped = sorted(DIFFSEND_CASES - grepped)
    if ungrepped:
        _die(f"scripts/differential-gate.sh asserts no line for diffsend case(s) {ungrepped}")


def _gate_unit_index():
    spec = importlib.util.spec_from_file_location(
        "gate_unit_index", SCRIPTS / "lib" / "gate_unit_index.py"
    )
    if spec is None or spec.loader is None:
        _die("cannot load scripts/lib/gate_unit_index.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CAPTURE_ENV_RE = re.compile(r"""(?:env::var(?:_os)?|option_env!)\(\s*"([^"]+)"\s*\)""")
_CAPTURE_ASSIGN_RE = re.compile(r"""KERBER_CAPTURE_DIR\s*[=:]\s*([^\s\\#'"]+|['"][^'"]+['"])""")


def _capture_product(text: str) -> str:
    i = text.find("#[cfg(test)]")
    return text if i < 0 else text[:i]


def _is_golden_capture_path(val: str) -> bool:
    norm = val.strip().strip("\"'").replace("\\", "/")
    parts = [p for p in norm.split("/") if p and p != "$ROOT"]
    return any(
        parts[i] == "tests" and parts[i + 1] == "traces" for i in range(len(parts) - 1)
    )


def check_capture_env_only(
    capture_text: str | None = None,
    common_text: str | None = None,
    script_texts: dict[str, str] | None = None,
) -> None:
    """capture.rs reads no env but KERBER_CAPTURE_DIR; no script sets it under tests/traces."""
    if capture_text is None:
        path = ROOT / "crates" / "krb5-protocol" / "src" / "capture.rs"
        if not path.is_file():
            _die("missing crates/krb5-protocol/src/capture.rs")
        capture_text = path.read_text(encoding="utf-8")
    product = _capture_product(capture_text)
    envs = set(_CAPTURE_ENV_RE.findall(product))
    if envs != {"KERBER_CAPTURE_DIR"}:
        _die(
            "capture.rs product must read only KERBER_CAPTURE_DIR, got "
            + ", ".join(sorted(envs) or ["<none>"])
        )
    if "KERBER_SCRATCH" in product or "CARGO_TARGET_DIR" in product:
        _die("capture.rs product must not name KERBER_SCRATCH or CARGO_TARGET_DIR")
    if common_text is None:
        common = SCRIPTS / "lib" / "gate-common.sh"
        if not common.is_file():
            _die("missing scripts/lib/gate-common.sh")
        common_text = common.read_text(encoding="utf-8")
    if "refuse_golden_capture_dir" not in common_text:
        _die("gate-common.sh must define refuse_golden_capture_dir")
    live_scan = script_texts is None
    if script_texts is None:
        script_texts = {}
        for p in sorted(SCRIPTS.glob("*.sh")) + sorted((SCRIPTS / "lib").glob("*.sh")):
            script_texts[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
        harness = ROOT / "harness"
        if harness.is_dir():
            for p in sorted(harness.rglob("*.sh")):
                script_texts[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
        wf = ROOT / ".github" / "workflows"
        if wf.is_dir():
            for p in sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))):
                script_texts[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
    if live_scan or any(rel in script_texts for rel in _REQUIRED_REFUSE_CALLERS):
        for rel in _REQUIRED_REFUSE_CALLERS:
            if not live_scan and rel not in script_texts:
                continue
            caller = script_texts.get(rel, "")
            if not _REFUSE_CALL_RE.search(caller):
                _die(f"{rel} must call refuse_golden_capture_dir")
    for name, text in script_texts.items():
        for m in _CAPTURE_ASSIGN_RE.finditer(text):
            if _is_golden_capture_path(m.group(1)):
                _die(f"{name} sets KERBER_CAPTURE_DIR under tests/traces")


def check_gate_unit_index(
    root: pathlib.Path | None = None,
    gate: str | None = None,
    doc: str | None = None,
) -> None:
    """Every differential-gate.sh status-word cell has a tagged unit twin."""
    mod = _gate_unit_index()
    root = pathlib.Path(root) if root is not None else ROOT
    if gate is None:
        path = SCRIPTS / "differential-gate.sh"
        if not path.is_file():
            _die("missing scripts/differential-gate.sh")
        gate = path.read_text(encoding="utf-8")
    if doc is None:
        doc_path = root / "docs" / "gate-unit-index.md"
        if not doc_path.is_file():
            _die("missing docs/gate-unit-index.md")
        doc = doc_path.read_text(encoding="utf-8")
    try:
        mod.verify(root, gate, doc)
    except mod.GateIndexError as e:
        _die(str(e))


_DOC_FILE_CITE_RE = re.compile(
    r"`((?:crates|scripts|docs|tests|harness|\.github|examples)/"
    r"[A-Za-z0-9_./+-]+\.[A-Za-z0-9]+)"
    r"(?::\d+(?:-\d+)?)?`"
)


def check_doc_file_cites(
    texts: dict[str, str] | None = None,
    root: pathlib.Path | None = None,
) -> None:
    """Every backticked crates/scripts/docs/tests/harness/.github/examples file path exists.

    The files read are `doc_files(root)` less the CHANGELOG (history keeps old paths).
    """
    root = pathlib.Path(root) if root is not None else ROOT
    if texts is None:
        texts = {
            str(path.relative_to(root)): path.read_text(encoding="utf-8") for path in doc_files(root)
        }
    missing: list[str] = []
    for doc, text in texts.items():
        if pathlib.Path(doc).name == "CHANGELOG.md":
            continue
        for m in _DOC_FILE_CITE_RE.finditer(text):
            rel = m.group(1)
            if any(ch in rel for ch in "*?{}<>"):
                continue
            if not (root / rel).exists():
                missing.append(f"{doc}: `{rel}`")
    if missing:
        _die("doc file cite(s) do not exist: " + "; ".join(missing[:8]))


def doc_files(root: pathlib.Path | None = None) -> list[pathlib.Path]:
    """The public docs: README.md, CONTRIBUTING.md, CHANGELOG.md, docs/**/*.md, and every README.md
    under examples/, harness/, scripts/ and tests/."""
    root = ROOT if root is None else root
    out = [root / rel for rel in ("README.md", "CONTRIBUTING.md", "CHANGELOG.md") if (root / rel).is_file()]
    if (root / "docs").is_dir():
        out += sorted((root / "docs").rglob("*.md"))
    for top in ("examples", "harness", "scripts", "tests"):
        if (root / top).is_dir():
            out += sorted((root / top).rglob("README.md"))
    return out


_MD_FENCE = re.compile(r"^(\s*)(```|~~~)")
_MD_LINK = re.compile(r"!?\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(\s*<?([^()\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_MD_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_MD_HTML_ANCHOR = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"")


def _md_prose_lines(text: str) -> list[tuple[int, str]]:
    """(line number, line) outside fenced code blocks, with inline code spans blanked."""
    out: list[tuple[int, str]] = []
    fence: str | None = None
    for i, line in enumerate(text.splitlines(), 1):
        m = _MD_FENCE.match(line)
        if m:
            if fence is None:
                fence = m.group(2)
            elif m.group(2) == fence:
                fence = None
            continue
        if fence is None:
            out.append((i, re.sub(r"(`+)(?:(?!\1).)+\1", lambda c: " " * len(c.group(0)), line)))
    return out


def github_slug(heading: str) -> str:
    """GitHub's heading anchor: the rendered text lowercased, every character that is not a
    letter, digit, space, hyphen or underscore dropped, and each space turned into a hyphen."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").strip().lower()
    return "".join(ch for ch in text if ch.isalnum() or ch in "-_ ").replace(" ", "-")


def md_anchors(text: str) -> set[str]:
    """Every anchor a Markdown file offers: its headings' slugs (a repeated slug takes -1, -2, ...)
    and explicit `<a name="..">` / `<a id="..">` targets."""
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    fence: str | None = None
    for line in text.splitlines():
        m = _MD_FENCE.match(line)
        if m:
            fence = m.group(2) if fence is None else (None if m.group(2) == fence else fence)
            continue
        if fence is not None:
            continue
        h = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if h:
            slug = github_slug(h.group(1))
            n = seen.get(slug, 0)
            anchors.add(slug if n == 0 else f"{slug}-{n}")
            seen[slug] = n + 1
        anchors.update(_MD_HTML_ANCHOR.findall(line))
    return anchors


def doc_link_violations(root: pathlib.Path | None = None) -> list[str]:
    """Relative links in `doc_files` whose file or `#anchor` does not exist."""
    root = ROOT if root is None else root
    bad: list[str] = []
    anchors_of: dict[pathlib.Path, set[str]] = {}
    for doc in doc_files(root):
        rel = doc.relative_to(root)
        text = doc.read_text(encoding="utf-8")
        for lineno, line in _md_prose_lines(text):
            for m in _MD_LINK.finditer(line):
                target = m.group(2)
                if _MD_SCHEME.match(target):
                    continue
                path_part, _, anchor = target.partition("#")
                dest = (doc.parent / path_part).resolve() if path_part else doc
                if not dest.exists():
                    bad.append(f"{rel}:{lineno}: {target} (no such file)")
                    continue
                if anchor and dest.suffix == ".md":
                    if dest not in anchors_of:
                        anchors_of[dest] = md_anchors(dest.read_text(encoding="utf-8"))
                    if anchor not in anchors_of[dest]:
                        bad.append(f"{rel}:{lineno}: {target} (no such anchor)")
    return bad


def check_doc_links(root: pathlib.Path | None = None) -> None:
    """Every relative link and anchor in the public docs resolves (GitHub slug rules)."""
    bad = doc_link_violations(root)
    if bad:
        _die(f"broken doc link(s) ({len(bad)}): " + "; ".join(bad[:8]))


_CHANGELOG_HEADING = re.compile(
    r"^### (?!Security|Added|Changed|Fixed|Tests and CI|Deprecated|Removed|How to)", re.M
)


def check_changelog_headings(text: str | None = None, *, allow: int | None = None) -> None:
    """CHANGELOG.md groups use the Keep-a-Changelog headings only (plus Tests and CI, How to).

    Advisory while `allow` equals the live count; hard at 0.
    """
    if text is None:
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    allow = CHANGELOG_HEADINGS_ALLOW if allow is None else allow
    n = len(_CHANGELOG_HEADING.findall(text))
    if n != allow:
        _die(f"CHANGELOG.md has {n} ### headings outside the Keep-a-Changelog set, allow {allow}")


def check_docs_size(
    root: pathlib.Path | None = None, *, allow: int | None = None, changelog_max: int | None = None
) -> None:
    """No docs/**/*.md is over DOCS_SIZE_LIMIT bytes, and CHANGELOG.md (history, exempt from that
    limit) is not over CHANGELOG_MAX_BYTES. Advisory while `allow` equals the live count."""
    root = ROOT if root is None else root
    allow = DOCS_SIZE_ALLOW if allow is None else allow
    changelog_max = CHANGELOG_MAX_BYTES if changelog_max is None else changelog_max
    over = [
        f"{p.relative_to(root)} {p.stat().st_size}"
        for p in sorted((root / "docs").rglob("*.md"))
        if p.stat().st_size > DOCS_SIZE_LIMIT
    ] if (root / "docs").is_dir() else []
    if len(over) != allow:
        _die(f"{len(over)} docs file(s) over {DOCS_SIZE_LIMIT} bytes, allow {allow}: " + "; ".join(over))
    log = root / "CHANGELOG.md"
    if log.is_file() and log.stat().st_size > changelog_max:
        _die(f"CHANGELOG.md is {log.stat().st_size} bytes, over its ceiling {changelog_max}")


WRAPPER_GATES = frozenset({"kadmin-gate.sh", "kpasswd-gate.sh", "client-differential-gate.sh"})
_GATE_ORACLES = frozenset({"MIT", "Samba", "Heimdal", "Windows", "none"})
_GATE_ROW = re.compile(r"^\|\s*`scripts/([A-Za-z0-9._-]+-gate\.sh)`\s*\|")


def gate_placements(workflows: list[Workflow] | None = None) -> dict[str, list[tuple[str, str]]]:
    """scripts/*-gate.sh -> [(`workflow:job`, lane)] read from .github/workflows.

    The lane is `nightly` for a workflow that only runs on a schedule, `soft` for a
    continue-on-error job, `skip2` for a step that runs the gate through `skip2` (exit 2 is
    green), and `fail-red` otherwise.
    """
    if workflows is None:
        workflows = [Workflow(p, p.read_text()) for p in sorted(WORKFLOWS.glob("*.yml"))]
    out: dict[str, list[tuple[str, str]]] = {}
    for w in workflows:
        for job in w.jobs.values():
            for script in job.scripts:
                if not script.endswith("-gate.sh"):
                    continue
                if w.scheduled and not w.per_push:
                    lane = "nightly"
                elif job.continue_on_error:
                    lane = "soft"
                elif re.search(rf"skip2 \./scripts/{re.escape(script)}\b", job.body):
                    lane = "skip2"
                else:
                    lane = "fail-red"
                place = (f"{w.path.stem}:{job.name}", lane)
                if place not in out.setdefault(script, []):
                    out[script].append(place)
    return out


def gate_doc_violations(
    text: str,
    gate_names: list[str],
    placements: dict[str, list[tuple[str, str]]],
    stubs: frozenset[str],
) -> list[str]:
    """docs/gates.md rows against the scripts and the workflows: one row per gate, the workflow
    column equal to the gates' placements (`stub` / `wrapper` for DOCUMENTED_STUBS), the lane
    column equal to their lanes, a known oracle, and a non-empty assertion."""
    bad: list[str] = []
    rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = _GATE_ROW.match(line)
        if not m:
            continue
        name = m.group(1)
        if name in rows:
            bad.append(f"{name}: two rows")
            continue
        rows[name] = _split_ledger_row(line)
    for name in gate_names:
        if name not in rows:
            bad.append(f"{name}: no row")
            continue
        cells = rows[name]
        if len(cells) != 5:
            bad.append(f"{name}: {len(cells)} cells, want 5 (gate, oracle, workflow, lane, asserts)")
            continue
        _gate, oracle, workflow, lane, asserts = cells
        if name in placements:
            want_wf = ", ".join(f"`{p}`" for p, _l in placements[name])
            want_lane = ", ".join(lane_ for _p, lane_ in placements[name])
        elif name in stubs:
            want_wf = "wrapper" if name in WRAPPER_GATES else "stub"
            want_lane = "—"
        else:
            want_wf, want_lane = "(in no workflow)", "—"
        if workflow != want_wf:
            bad.append(f"{name}: workflow {workflow!r}, want {want_wf!r}")
        if lane != want_lane:
            bad.append(f"{name}: lane {lane!r}, want {want_lane!r}")
        if oracle not in _GATE_ORACLES:
            bad.append(f"{name}: oracle {oracle!r} not in {sorted(_GATE_ORACLES)}")
        if not asserts.strip():
            bad.append(f"{name}: empty assertion cell")
    for name in sorted(set(rows) - set(gate_names)):
        bad.append(f"{name}: row for a gate that does not exist")
    return bad


def check_gate_documented(root: pathlib.Path | None = None, *, allow: int | None = None) -> None:
    """docs/gates.md has one true row per scripts/*-gate.sh (`gate_doc_violations`).

    Advisory while `allow` equals the live count; hard at 0.
    """
    root = ROOT if root is None else root
    allow = GATE_DOC_ALLOW if allow is None else allow
    doc = root / "docs" / "gates.md"
    text = doc.read_text(encoding="utf-8") if doc.is_file() else ""
    gate_names = [p.name for p in sorted((root / "scripts").glob("*-gate.sh"))]
    bad = gate_doc_violations(text, gate_names, gate_placements(), DOCUMENTED_STUBS)
    if len(bad) != allow:
        _die(f"docs/gates.md: {len(bad)} gate row problem(s), allow {allow}: " + "; ".join(bad[:8]))


def _dump_key_hexes(line: str) -> tuple[str, tuple[str, ...]] | None:
    """Name and every key_data slot-0 hex from a princ dump line, or None."""
    if not line.startswith("princ\t"):
        return None
    f = line.rstrip(";").split("\t")
    if len(f) < 16:
        return None
    try:
        n_tl = int(f[3])
        n_key = int(f[4])
    except ValueError:
        return None
    i = 15 + 3 * n_tl
    hexes: list[str] = []
    for _ in range(n_key):
        if i + 4 >= len(f):
            return None
        try:
            ver = int(f[i])
        except ValueError:
            return None
        # ver, kvno, then ver × (type, length, hex); slot 0 is the key.
        i += 2
        if i + 2 >= len(f):
            return None
        hexes.append(f[i + 2])
        i += 3 * ver
    if not hexes:
        return None
    return f[6], tuple(hexes)


def check_golden_dump_unique_keys(text: str | None = None) -> None:
    """Golden dump nosvr/hwuser key blobs are MIT-derived, not clones of user/pwprau."""
    if text is None:
        path = ROOT / "tests" / "traces" / "kdb" / "mit-dump-v7.txt"
        if not path.is_file():
            _die("missing tests/traces/kdb/mit-dump-v7.txt")
        text = path.read_text()
    keys: dict[str, tuple[str, ...]] = {}
    for line in text.splitlines():
        parsed = _dump_key_hexes(line)
        if parsed is None:
            continue
        name, hexes = parsed
        keys[name] = hexes
    for need in (
        "user@KERBER.TEST",
        "nosvr@KERBER.TEST",
        "hwuser@KERBER.TEST",
        "pwprau@KERBER.TEST",
    ):
        if need not in keys:
            _die(f"golden dump missing {need}")
    if keys["nosvr@KERBER.TEST"] == keys["user@KERBER.TEST"]:
        _die("nosvr keys clone user")
    if keys["hwuser@KERBER.TEST"] == keys["pwprau@KERBER.TEST"]:
        _die("hwuser keys clone pwprau")


_VERDICT_KEYS = (
    "stricter-documented",
    "exact",
    "deviation",
    "absent",
    "deferred",
)
_HEADER_EXACT = re.compile(
    r"exact\s+(\d+)\s*·\s*stricter-documented\s+(\d+)\s*·\s*deviation\s+(\d+)"
)
_HEADER_ABSENT = re.compile(r"absent\s+(\d+)\s*·\s*deferred\s+(\d+)")
_HEADER_TOTAL = re.compile(
    r"\*\*(\d+)\*\*\s*=\s*A1\s+(\d+)\s*\+\s*A2\s+(\d+)\s*\+\s*A3\s+(\d+)"
    r"(?:\s*\+\s*A4\s+(\d+))?(?:\s*\+\s*A5\s+(\d+))?(?:\s*\+\s*B1\s+(\d+))?"
)
_RUST_ANCHOR = re.compile(
    r"(?:`)?(?:(?P<crate>[A-Za-z0-9_-]+)/(?:src/)?)?(?P<file>[A-Za-z0-9_-]+\.rs)"
    r"\s+(?:`)?(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)(?:`)?"
    r"(?::(?P<symline>\d+))?"
)
_ITEM_DEF = re.compile(
    r"^(\s*)(?:pub(?:\([^)]+\))?\s+)*"
    r"(?:(?:(?:async|const|unsafe)\s+)+fn|fn|struct|enum|const|static)"
    r"\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_STATUS_QUOTE = re.compile(r"`([A-Z][A-Z0-9_][A-Z0-9_ /-]{1,})`")
_BARE_STATUS = re.compile(r"(?<![`\w])([A-Z][A-Z0-9]*_[A-Z0-9_]+)(?![`\w])")
_MIT_CITE = re.compile(r"\b[\w.-]+\.(?:c|h|y|et|x|hin)\b")
_MIT_NA = re.compile(r"^\s*(?:n/a|absent|—|-|RFC\s*\d)", re.I)
_PROOF_UNIT = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")
_PROOF_CASE = re.compile(r"`([a-z][a-z0-9]*(?:-[a-z0-9]+)+)`")
_PROOF_GATE = re.compile(r"\b([\w-]+-gate\.sh)\b")
_FN_NAMES: set[str] | None = None
_CASE_TEXT: str | None = None


def _status_tokens(text: str) -> list[str]:
    """Backticked ALL-CAPS status words plus bare `WORD_WORD` identifiers."""
    toks = _STATUS_QUOTE.findall(text)
    toks += _BARE_STATUS.findall(_STATUS_QUOTE.sub(" ", text))
    return toks


def _fn_names() -> set[str]:
    global _FN_NAMES
    if _FN_NAMES is None:
        names: set[str] = set()
        for src in (ROOT / "crates").rglob("*.rs"):
            names.update(re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", src.read_text(errors="replace")))
        _FN_NAMES = names
    return _FN_NAMES


def _case_text() -> str:
    global _CASE_TEXT
    if _CASE_TEXT is None:
        parts = [q.read_text(errors="replace") for q in (ROOT / "scripts").glob("*-gate.sh")]
        if DIFFSEND_SRC.is_file():
            parts.append(DIFFSEND_SRC.read_text(errors="replace"))
        _CASE_TEXT = "\n".join(parts)
    return _CASE_TEXT


def _proof_exists(proof: str) -> bool:
    if any(n in _fn_names() for n in _PROOF_UNIT.findall(proof)):
        return True
    if any((ROOT / "scripts" / g).is_file() for g in _PROOF_GATE.findall(proof)):
        return True
    return any(f'"{c}"' in _case_text() or f"'{c}'" in _case_text() for c in _PROOF_CASE.findall(proof))
_CRATE_ALIASES = {
    "kdc": "krb5-kdc",
    "admin": "krb5-admin",
    "gss": "krb5-gss",
    "types": "krb5-types",
    "protocol": "krb5-protocol",
    "crypto": "krb5-crypto",
    "client": "krb5-client",
    "asn1": "krb5-asn1",
    "log": "krb5-log",
    "config": "krb5-config",
}


def recount_ledger_sections(text: str) -> dict[str, int]:
    """Row counts under `## A1` ... `## A5` / `## B1` headings (the single-file layout)."""
    counts = {k: 0 for k in _LEDGER_KEYS}
    section: str | None = None
    for line in text.splitlines():
        m = re.match(r"^## (A1|A2|A3|A4|A5|B1)\b", line)
        if m:
            section = m.group(1)
            continue
        if re.match(r"^## ", line):
            section = None
            continue
        if section is None:
            continue
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7:
            continue
        if cols[5] == "verdict":
            continue
        counts[section] += 1
    return counts


def recount_ledger_verdicts(text: str) -> dict[str, int]:
    counts = {k: 0 for k in _VERDICT_KEYS}
    for line in text.splitlines():
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7:
            continue
        verdict = cols[5]
        if verdict == "verdict":
            continue
        for key in _VERDICT_KEYS:
            if (
                verdict == key
                or verdict.startswith(key + " ")
                or verdict.startswith(key + "(")
            ):
                counts[key] += 1
                break
    return counts


def check_ledger_tally(text: str | None = None, root: pathlib.Path | None = None) -> None:
    """Header verdict counts must equal a recount of the table cells, in total and per section.

    `text` is a single-file ledger (the fixtures); otherwise the layout `ledger_sources` finds is
    read, the header from its first file and the per-section counts from the section files.
    """
    sources = [("docs/mit-parity-ledger.md", text, None)] if text is not None else ledger_sources(root)
    hname, head, _key = sources[0]
    got = {k: 0 for k in _VERDICT_KEYS}
    for _name, body, _k in sources:
        for k, v in recount_ledger_verdicts(body).items():
            got[k] += v
    exact = _HEADER_EXACT.search(head)
    absent = _HEADER_ABSENT.search(head)
    if not exact or not absent:
        _die(f"{hname} missing verdict header tally")
    want = {
        "exact": int(exact.group(1)),
        "stricter-documented": int(exact.group(2)),
        "deviation": int(exact.group(3)),
        "absent": int(absent.group(1)),
        "deferred": int(absent.group(2)),
    }
    if got != want:
        _die(
            f"{hname} tally header "
            f"{want} != recount {got}"
        )
    total = _HEADER_TOTAL.search(head)
    if not total:
        _die(f"{hname} missing A1/A2/A3 total line")
    header_n = int(total.group(1))
    a1, a2, a3 = (int(total.group(i)) for i in (2, 3, 4))
    a4 = int(total.group(5) or 0)
    a5 = int(total.group(6) or 0)
    b1 = int(total.group(7) or 0)
    n = sum(got.values())
    parts = a1 + a2 + a3 + a4 + a5 + b1
    if header_n != n or header_n != parts:
        _die(
            f"{hname} total {header_n} "
            f"= A1 {a1} + A2 {a2} + A3 {a3} + A4 {a4} + A5 {a5} + B1 {b1} != recount {n}"
        )
    if all(key is None for _name, _body, key in sources):
        sec = recount_ledger_sections(head)
    else:
        sec = {k: 0 for k in _LEDGER_KEYS}
        for _name, body, key in sources:
            if key is not None:
                sec[key] += len(_ledger_rows(body))
    want_sec = {"A1": a1, "A2": a2, "A3": a3, "A4": a4, "A5": a5, "B1": b1}
    if sec != want_sec:
        _die(
            f"{hname} section split "
            f"header {want_sec} != recount {sec}"
        )


def _is_exact_verdict(verdict: str) -> bool:
    return (
        verdict == "exact"
        or verdict.startswith("exact ")
        or verdict.startswith("exact(")
    )


def _normalize_crate(name: str | None) -> str | None:
    if not name:
        return None
    return _CRATE_ALIASES.get(name, name)


def _src_index(
    crates: pathlib.Path | None = None,
) -> tuple[dict[str, dict[str, pathlib.Path]], dict[str, list[str]]]:
    """`crates/<crate>/src/**/*.rs` keyed by crate then basename.

    A `src/**` file its parent declares `#[cfg(test)] mod` is test scope
    (`kadm5/tests/policy.rs`): never a rust-site anchor, and no collision
    with the product file of the same basename (`kadm5/policy.rs`).
    """
    by_crate: dict[str, dict[str, pathlib.Path]] = {}
    by_base: dict[str, list[str]] = {}
    crates = ROOT / "crates" if crates is None else crates
    if not crates.is_dir():
        return by_crate, by_base
    inv = _hygiene_inventory()
    for crate_dir in sorted(crates.iterdir()):
        src = crate_dir / "src"
        if not crate_dir.is_dir() or not src.is_dir():
            continue
        crate = crate_dir.name
        src_test = {crate_dir / rel for rel in inv.cfg_test_files_in_pkg(crate_dir)}
        for p in src.rglob("*.rs"):
            if p in src_test:
                continue
            files = by_crate.setdefault(crate, {})
            prev = files.get(p.name)
            if prev is not None and prev != p:
                _die(f"duplicate {p.name} under crates/{crate}/src")
            files[p.name] = p
            if crate not in by_base.setdefault(p.name, []):
                by_base[p.name].append(crate)
    return by_crate, by_base


def _code_without_line_comment(line: str) -> str:
    out: list[str] = []
    in_str = False
    quote = ""
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c in "\"'":
            in_str = True
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _item_spans(path: pathlib.Path, symbol: str) -> list[tuple[int, int, str]]:
    """Every brace-matched definition of `symbol` in `path`, in file order."""
    lines = path.read_text(errors="replace").splitlines()
    starts = [i for i, line in enumerate(lines, 1) if (m := _ITEM_DEF.match(line)) and m.group(2) == symbol]
    return [_span_from(lines, s) for s in starts]


def _item_span(path: pathlib.Path, symbol: str) -> tuple[int, int, str] | None:
    spans = _item_spans(path, symbol)
    return spans[0] if len(spans) == 1 else None


def _span_from(lines: list[str], start: int) -> tuple[int, int, str]:
    depth = 0
    seen_brace = False
    end = start
    for i, line in enumerate(lines[start - 1 :], start):
        code = _code_without_line_comment(line)
        if not seen_brace and "{" not in code:
            if ";" in code:
                end = i
                break
            end = i
            continue
        for c in code:
            if c == "{":
                depth += 1
                seen_brace = True
            elif c == "}":
                depth -= 1
        end = i
        if seen_brace and depth <= 0:
            break
    body = "\n".join(lines[start - 1 : end])
    return start, end, body


def _resolve_src(
    crate: str | None,
    fname: str,
    by_crate: dict[str, dict[str, pathlib.Path]],
    by_base: dict[str, list[str]],
    where: str,
) -> pathlib.Path:
    crate_n = _normalize_crate(crate)
    if crate_n:
        files = by_crate.get(crate_n)
        if not files or fname not in files:
            _die(f"{where} {crate_n}/{fname} not under crates/{crate_n}/src")
        return files[fname]
    crates_for = by_base.get(fname) or []
    if not crates_for:
        _die(f"{where} {fname} not under crates/*/src")
    if len(crates_for) > 1:
        opts = ", ".join(f"{c}/{fname}" for c in sorted(crates_for))
        _die(f"{where} {fname} is ambiguous; qualify as {opts}")
    return by_crate[crates_for[0]][fname]


def check_ledger_anchors(text: str | None = None, name: str = "docs/mit-parity-ledger.md") -> None:
    """Every rust-site `file.rs symbol[:N]` resolves to one item; exact rows verify their claim.

    The MIT column must cite a MIT file (or say n/a / absent). An `exact` row's
    e_text status words (backticked, or bare `WORD_WORD` identifiers) must occur
    in the anchored item body; a row with no such word must name a proof unit,
    diffsend case or gate that exists. A symbol defined more than once in a file
    needs `:N` inside the intended definition.
    """
    checking_file = text is None
    sources = ledger_sources() if text is None else [(name, text, None)]
    by_crate, by_base = _src_index()
    n_quote = 0
    rows = [(src_name, i, cols) for src_name, body, _key in sources for i, _line, cols in _ledger_rows(body)]
    for src_name, i, cols in rows:
        site, etext = cols[3], cols[4]
        where = f"{src_name}:{i}"
        if not (_MIT_CITE.search(cols[0]) or _MIT_NA.match(cols[0])):
            _die(f"{where} MIT column names no MIT file: {cols[0].strip()}")
        bodies: list[str] = []
        saw_symbol = False
        for m in _RUST_ANCHOR.finditer(site):
            fname = m.group("file")
            symbol = m.group("symbol")
            lineno = m.group("symline")
            if not symbol:
                continue
            saw_symbol = True
            path = _resolve_src(m.group("crate"), fname, by_crate, by_base, where)
            spans = _item_spans(path, symbol)
            if not spans:
                _die(f"{where} {fname} {symbol} is not an item in {path}")
            if lineno:
                n = int(lineno)
                inside = [s for s in spans if s[0] <= n <= s[1]]
                if not inside:
                    ranges = ", ".join(f"{s[0]}-{s[1]}" for s in spans)
                    _die(f"{where} {fname}:{n} is not inside {symbol} ({ranges})")
                spans = inside
            if len(spans) > 1:
                starts = ", ".join(str(s[0]) for s in spans)
                _die(
                    f"{where} {fname} {symbol} is defined {len(spans)} times "
                    f"(lines {starts}); add :N inside the intended item"
                )
            bodies.append(spans[0][2])
        if _is_exact_verdict(cols[5]):
            if not saw_symbol:
                _die(f"{where} exact row has no rust-site anchor")
            joined = "\n".join(bodies)
            checked = 0
            for q in _status_tokens(etext):
                ident = re.sub(r"[^A-Z0-9]+", "_", q).strip("_")
                checked += 1
                if q not in joined and ident not in joined:
                    _die(f"{where} `{q}` not in rust-site item body")
            n_quote += checked
            if checked == 0 and not _proof_exists(cols[6]):
                _die(f"{where} exact row verifies nothing: no e_text status word, no existing proof unit or cell")
    if checking_file and n_quote == 0:
        _die("the ledger executed no quote checks")


_MIT_CITE_FILE = re.compile(r"\b([\w.-]+\.(?:c|h|y|et|x|hin))\b")
_MIT_IDENTS: dict[str, tuple[set[str], set[str], set[str]]] = {}


def _mit_index(src: pathlib.Path) -> tuple[set[str], set[str], set[str]]:
    """Basenames, identifiers and quoted status strings of a MIT source tree."""
    key = str(src)
    if key not in _MIT_IDENTS:
        names: set[str] = set()
        idents: set[str] = set()
        strings: set[str] = set()
        suffixes: set[str] = set()
        for f in src.rglob("*"):
            if f.suffix not in {".c", ".h", ".y", ".et", ".x", ".hin"} or not f.is_file():
                continue
            names.add(f.name)
            body = f.read_text(errors="replace")
            idents.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))
            strings.update(re.findall(r'"([A-Z][A-Z0-9 _/-]+)"', body))
        for ident in idents:
            parts = ident.split("_")
            suffixes.update("_".join(parts[k:]) for k in range(1, len(parts)))
        _MIT_IDENTS[key] = (names, idents | suffixes, strings)
    return _MIT_IDENTS[key]


def check_ledger_mit_cites(
    text: str | None = None, src: pathlib.Path | None = None, name: str = "docs/mit-parity-ledger.md"
) -> None:
    """Every MIT cite names a file of the tree; every MIT status word is an identifier there, a `_`-suffix of one, or a status string."""
    if src is None:
        env = os.environ.get("KERBER_MIT_SRC")
        if not env:
            # R2-T8: don't skip the MIT-anchor verification silently.
            print(
                "ci-policy: KERBER_MIT_SRC unset — skipping MIT-anchor "
                "verification (ledger-mit job sets it)",
                file=sys.stderr,
            )
            return
        src = pathlib.Path(env)
    if not src.is_dir():
        _die(f"KERBER_MIT_SRC {src} is not a directory")
    sources = ledger_sources() if text is None else [(name, text, None)]
    names, idents, strings = _mit_index(src)
    rows = [(src_name, i, cols) for src_name, body, _key in sources for i, _line, cols in _ledger_rows(body)]
    for src_name, i, cols in rows:
        where = f"{src_name}:{i}"
        for f in _MIT_CITE_FILE.findall(cols[0]):
            if f not in names:
                _die(f"{where} MIT cite {f} is not a file under {src}")
        for tok in _status_tokens(cols[2]):
            ident = re.sub(r"[^A-Z0-9]+", "_", tok).strip("_")
            if tok not in strings and ident not in idents and tok.strip() not in idents:
                _die(f"{where} MIT status `{tok}` is neither an identifier nor a status string in {src}")


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


def check_unit_evidence_helper() -> None:
    """R8: unit_green / unit_red_at exist; red refuses missing files; green refuses dirty."""
    path = SCRIPTS / "lib" / "unit-evidence.sh"
    if not path.is_file():
        _die("missing scripts/lib/unit-evidence.sh")
    text = path.read_text()
    if "unit_green" not in text or "unit_red_at" not in text:
        _die("unit-evidence.sh missing unit_green/unit_red_at")
    if "inject files required" not in text:
        _die("unit_red_at must refuse a command without inject files")
    if "--inject" not in text:
        _die("unit_red_at must pass --inject to red-at-sha.sh")
    if "KERBER_UNIT_ALLOW_DIRTY" not in text:
        _die("unit_green must honour KERBER_UNIT_ALLOW_DIRTY")
    if "red-at-parent=1" not in text:
        _die("unit_red_at must stamp red-at-parent=1")
    if "_unit_test_names" not in text:
        _die("unit_red_at must derive #[test] names from inject files")
    if '--test "$stem"' not in text and "--test \"$stem\"" not in text:
        # Accept either quoting style from the shell helper.
        if "--test" not in text or "stem=" not in text:
            _die("unit_red_at --all must run cargo test --test <stem> per inject file")
    if "IFS='|'" in text or 'IFS="|"' in text:
        _die("unit_red_at must not join test names with | for cargo test")
    if "refusing dirty tree" not in text:
        _die("unit_green must refuse a dirty tree without KERBER_UNIT_ALLOW_DIRTY")
    if "unit_green: missing Summary" not in text:
        _die("unit_green must fail unless a Summary … passed line is present")
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    env["ROOT"] = str(ROOT)
    r = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; unit_red_at',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("unit_red_at accepted missing args")
    r = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; unit_red_at HEAD k12 --all',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("unit_red_at accepted missing inject files")
    err = (r.stderr or b"") + (r.stdout or b"")
    if b"inject files required" not in err:
        _die("unit_red_at missing-files refusal did not mention inject files")
    r = subprocess.run(
        [
            "bash",
            str(SCRIPTS / "red-at-sha.sh"),
            "--inject",
            "--",
            "HEAD",
            "true",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("red-at-sha.sh --inject with no files was accepted")


def check_settle_helper() -> None:
    """K12/U7/R8: settle.sh tees, refuses readers, stamps override= when dirty bypassed."""
    path = SCRIPTS / "lib" / "settle.sh"
    if not path.is_file():
        _die("missing scripts/lib/settle.sh")
    text = path.read_text()
    if "tee" not in text:
        _die("settle.sh must tee command output")
    if "pipefail" not in text:
        _die("settle.sh must set pipefail around tee")
    if "of a file is not a live settle" not in text:
        _die("settle.sh must refuse readers of a file")
    if "override=KERBER_SETTLE_ALLOW_DIRTY" not in text:
        _die("settle.sh must stamp override=KERBER_SETTLE_ALLOW_DIRTY when dirty is bypassed")
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    # The dev tree is dirty while iterating; the self-test exercises settle.sh's
    # tee/refusal logic, not the R2-T8 dirty guard (checked before it in CI).
    env["KERBER_SETTLE_ALLOW_DIRTY"] = "1"
    existing = ROOT / "scripts" / "ci-policy.py"
    r = subprocess.run(
        [
            "bash",
            str(path),
            "k12-grep",
            "--",
            "grep",
            "-F",
            "ci-policy: ok",
            str(existing),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("settle.sh accepted grep of an existing file")
    err = (r.stderr or b"").decode("utf-8", "replace")
    if "grep of a file is not a live settle" not in err:
        _die("settle.sh grep refusal text missing")
    refusals = [
        (["bash", "-c", f"grep -F ok {existing}"], "bash -c grep"),
        (["rg", "ok", str(existing)], "rg of a file"),
        (["sed", "-n", "1p", str(existing)], "sed -n of a file"),
        (["grep", "-F", "ok", "/tmp/kerber-vanished-settle/gate.log"], "grep of a vanished path"),
    ]
    for cmd, what in refusals:
        r = subprocess.run(
            ["bash", str(path), "k12-reader", "--", *cmd],
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=False,
        )
        if r.returncode == 0:
            _die(f"settle.sh accepted {what}")
        if b"not a live settle" not in (r.stderr or b""):
            _die(f"settle.sh refusal text missing for {what}")
    r = subprocess.run(
        ["bash", str(path), "k12-live", "--", "bash", "-c", "printf live"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0 or b"live" not in (r.stdout or b""):
        _die("settle.sh refused a live bash -c command")
    out = (r.stdout or b"").decode("utf-8", "replace")
    if "dirty=yes" in out and "override=KERBER_SETTLE_ALLOW_DIRTY" not in out:
        _die("settle.sh dirty bypass must stamp override=KERBER_SETTLE_ALLOW_DIRTY")


def check_evidence_check_tool() -> None:
    """R8: evidence-check.py flags unstamped, wrong-SHA, and unlabeled dirty logs."""
    path = SCRIPTS / "evidence-check.py"
    if not path.is_file():
        _die("missing scripts/evidence-check.py")
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (root / "ok.log").write_text(
            "==== provenance ====\nhead_sha=abc1234deadbeef\ntree_sha=t1\ndirty=no\nok\n"
        )
        (root / "unstamped.log").write_text("no stamp\n")
        (root / "wrongsha.log").write_text(
            "head_sha=ffffffffffff\ntree_sha=t2\ndirty=no\n"
        )
        (root / "dirty.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t3\ndirty=yes\n"
        )
        (root / "dirty-red.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t4\ndirty=yes\nred-at-parent=1\n"
        )
        (root / "r13-unit-green.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t5\ndirty=no\n==== unit_green r13 ====\n"
        )
        (root / "r12-unit-green.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t6\ndirty=no\n"
            "     Summary [   0.100s] 11 tests run: 11 passed, 0 skipped\n"
        )
        (root / "ci-bad.txt").write_text("ci-status: HTTP Error 403: rate limit exceeded\n")
        # Z3.2/Z3.6: any scratch* directory is outside the contract (dev runs,
        # KERBER_SCRATCH output); a file merely named scratch* is not.
        for scratch in ("scratch", "scratch-dev", "scratch-pre2"):
            (root / scratch).mkdir()
            (root / scratch / "dirty-dev-run.log").write_text("head_sha=abc1234\ntree_sha=t\ndirty=yes\n")
        (root / "scratch-notes.log").write_text("no stamp\n")
        r = subprocess.run(
            [
                sys.executable,
                str(path),
                str(root),
                "--commits",
                "abc1234",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode == 0:
            _die("evidence-check.py passed a fixture tree with known bad artefacts")
        out = (r.stdout or "") + (r.stderr or "")
        for name in (
            "unstamped.log",
            "wrongsha.log",
            "dirty.log",
            "ci-bad.txt",
            "r13-unit-green.log",
        ):
            if name not in out:
                _die(f"evidence-check.py missed {name}: {out}")
        if "dirty.log: dirty=yes without" not in out:
            _die(f"evidence-check.py must name the dirty label rule: {out}")
        if "unit-green log missing Summary" not in out:
            _die(f"evidence-check.py must flag a header-only unit-green log: {out}")
        if any(ln.startswith("dirty-red.log:") for ln in out.splitlines()):
            _die("evidence-check.py flagged a dirty log that carries red-at-parent=")
        if any(ln.startswith("ok.log:") for ln in out.splitlines()):
            _die(f"evidence-check.py flagged a good log: {out}")
        if "dirty-dev-run.log" in out:
            _die(f"evidence-check.py must skip every scratch* directory: {out}")
        if "scratch-notes.log" not in out:
            _die("evidence-check.py must still check a file merely named scratch*")
        if any(ln.startswith("r12-unit-green.log:") for ln in out.splitlines()):
            _die(f"evidence-check.py flagged a unit-green log that has Summary: {out}")
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=False)


def check_ci_status_save() -> None:
    """R8: ci-status.py --save exists and filters fixture annotations.

    W2-S0: also durations, workflow-file fetch (not branch=main), budget-report.
    """
    path = SCRIPTS / "ci-status.py"
    if not path.is_file():
        _die("missing scripts/ci-status.py")
    text = path.read_text()
    if "--save" not in text:
        _die("ci-status.py must support --save")
    if "is_fixture_annotation" not in text:
        _die("ci-status.py must filter title=fixture annotations")
    if "probe-gate.sh" not in text:
        _die("ci-status.py must filter probe-gate.sh fixture annotations")
    if "403" not in text:
        _die("ci-status.py --save must handle HTTP 403 rate limits")
    if "--durations" not in text:
        _die("ci-status.py must support --durations")
    if "duration_s=" not in text:
        _die("ci-status.py must emit duration_s= records")
    if "run_wall_s=" not in text:
        _die("ci-status.py must emit run_wall_s=")
    if "--budget-report" not in text:
        _die("ci-status.py must support --budget-report")
    if "--check-budget" not in text:
        _die("ci-status.py must support --check-budget")
    if "budget_overruns" not in text:
        _die("ci-status.py must implement budget_overruns")
    if "budget_median_verdict" not in text:
        _die("ci-status.py must implement budget_median_verdict")
    if "over_runs_fail_at" not in text:
        _die("ci-status.py median verdict must take over_runs_fail_at")
    if ">= 3 of 5" not in text and ">=3-of-5" not in text:
        _die("ci-status.py --check-budget must document median / >=3-of-5")
    if "actions/workflows/" not in text:
        _die("ci-status.py must fetch /actions/workflows/<file>/runs")
    if "branch=main" in text:
        _die("ci-status.py must not pin fetch_runs to branch=main")
    if "keep_listing_run" not in text:
        _die("ci-status.py must filter listings to main pushes and the PR under test")
    if "dependabot[bot]" not in text:
        _die("ci-status.py must drop dependabot runs from listings and --check-budget")
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_status_r8", path)
    if spec is None or spec.loader is None:
        _die("ci-status.py load failed")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not mod.is_fixture_annotation({"title": "fixture", "path": "x.sh"}):
        _die("is_fixture_annotation must accept title=fixture")
    if not mod.is_fixture_annotation({"title": "", "path": "scripts/probe-gate.sh"}):
        _die("is_fixture_annotation must accept probe-gate.sh path")
    if not mod.is_fixture_annotation({"title": "", "path": "scripts/die-probe.sh"}):
        _die("is_fixture_annotation must accept *-probe.sh path")
    if mod.is_fixture_annotation({"title": "", "path": "scripts/kadmin-gate.sh"}):
        _die("is_fixture_annotation must not filter product gates")
    if mod.workflow_file("peers") != "peers.yml":
        _die("workflow_file must map peers -> peers.yml")
    if mod.job_duration_s(
        {"started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:01:05Z"}
    ) != 65:
        _die("job_duration_s must use started_at/completed_at")
    over = mod.budget_overruns(
        {"harness": 600, "test": 100},
        700,
        {"jobs": {"harness": 500, "test": 300}, "run_wall": 540},
    )
    if not any("harness" in ln for ln in over) or not any("run_wall" in ln for ln in over):
        _die(f"budget_overruns must flag harness and run_wall: {over}")
    if mod.budget_overruns(
        {"harness": 400, "test": 100},
        500,
        {"jobs": {"harness": 500, "test": 300}, "run_wall": 540},
    ):
        _die("budget_overruns must accept durations under budget")
    _y4_budget = {"jobs": {"mit-extra": 180, "test": 300}, "run_wall": 360}
    # 2 of 5 over, median under — info, not fail.
    _y4_green = [
        (625, {"mit-extra": 183, "test": 136}, 388),
        (624, {"mit-extra": 181, "test": 127}, 272),
        (623, {"mit-extra": 155, "test": 103}, 374),
        (622, {"mit-extra": 174, "test": 108}, 277),
        (613, {"mit-extra": 168, "test": 123}, 288),
    ]
    _fail, _info = mod.budget_median_verdict(_y4_green, _y4_budget)
    if _fail:
        _die(f"budget_median_verdict must pass 2-of-5 with median under cap: {_fail}")
    if not any("mit-extra" in ln for ln in _info):
        _die("budget_median_verdict must info single-run mit-extra breaches")
    # 3 of 5 over / median over — fail.
    _y4_red = [
        (621, {"mit-extra": 198, "test": 128}, 316),
        (619, {"mit-extra": 192, "test": 124}, 314),
        (616, {"mit-extra": 185, "test": 134}, 284),
        (615, {"mit-extra": 164, "test": 131}, 321),
        (613, {"mit-extra": 168, "test": 123}, 288),
    ]
    _fail, _info = mod.budget_median_verdict(_y4_red, _y4_budget)
    if not _fail:
        _die("budget_median_verdict must fail 3-of-5 / median over cap")
    if not any("mit-extra" in ln for ln in _fail):
        _die(f"budget_median_verdict 3-of-5 must name mit-extra: {_fail}")
    dep = {
        "event": "pull_request",
        "head_branch": "dependabot/cargo/foo",
        "actor": {"login": "dependabot[bot]"},
        "pull_requests": [{"number": 46}],
    }
    main_push = {
        "event": "push",
        "head_branch": "main",
        "actor": {"login": "Aelieth"},
        "pull_requests": [],
    }
    pr_run = {
        "event": "pull_request",
        "head_branch": "w3-hygiene-s3-0",
        "actor": {"login": "Aelieth"},
        "pull_requests": [{"number": 60}],
    }
    if mod.keep_listing_run(dep, pr=60):
        _die("keep_listing_run must drop a dependabot run")
    if not mod.keep_listing_run(main_push, pr=None):
        _die("keep_listing_run must keep a main push")
    if not mod.keep_listing_run(pr_run, pr=60):
        _die("keep_listing_run must keep the PR under test")
    if mod.keep_listing_run(pr_run, pr=54):
        _die("keep_listing_run must drop another PR")
    pr_empty = {
        "event": "pull_request",
        "head_branch": "w3-hygiene-s3-0",
        "actor": {"login": "Aelieth"},
        "pull_requests": [],
    }
    if not mod.keep_listing_run(pr_empty, pr=60, pr_head="w3-hygiene-s3-0"):
        _die("keep_listing_run must match head_branch when pull_requests is empty")
    if mod.keep_listing_run(pr_empty, pr=60, pr_head="other-branch"):
        _die("keep_listing_run must not match a different head_branch")
    if mod.keep_listing_run(pr_empty, pr=60):
        _die("keep_listing_run must not keep empty pull_requests without pr_head")


def check_makefile_matches_ci(mf: str | None = None, ci_text: str | None = None) -> None:
    """Makefile `safety` cargo order matches the ci.yml `test` job; doc is a sibling."""
    if mf is None:
        makefile = ROOT / "Makefile"
        if not makefile.is_file():
            _die("missing Makefile")
        mf = makefile.read_text()
    if ci_text is None:
        ci_path = WORKFLOWS / "ci.yml"
        if not ci_path.is_file():
            _die("missing .github/workflows/ci.yml")
        ci_text = ci_path.read_text()
    ci_wf = Workflow(pathlib.Path("ci.yml"), ci_text)
    test_job = ci_wf.jobs.get("test")
    doc_job = ci_wf.jobs.get("doc")
    if test_job is None:
        _die("ci.yml missing job test")
    if doc_job is None:
        _die("ci.yml missing job doc")
    if "safety:" not in mf:
        _die("Makefile missing safety target")
    needles = (
        "cargo fmt --all",
        "cargo clippy --workspace --all-targets --all-features",
        "cargo nextest run --workspace --profile ci",
        "python3 scripts/ci-policy.py",
    )
    for n in needles:
        if n not in mf:
            _die(f"Makefile safety missing {n!r}")
        if n not in test_job.body:
            _die(f"ci.yml test job missing {n!r}")
    if "cargo doc --workspace --no-deps" not in mf:
        _die("Makefile missing cargo doc --workspace --no-deps (make doc)")
    if "cargo doc --workspace --no-deps" in test_job.body:
        _die("ci.yml test job must not run cargo doc (that is the doc job)")
    if "cargo doc --workspace --no-deps" not in doc_job.body:
        _die("ci.yml doc job must cargo doc --workspace --no-deps")
    cargo = (
        "cargo fmt --all",
        "cargo clippy --workspace",
        "cargo nextest run --workspace --profile ci",
    )

    def _order(text: str, label: str) -> None:
        pos = [text.find(s) for s in cargo]
        if any(p < 0 for p in pos):
            _die(f"{label} missing a safety cargo step")
        if pos != sorted(pos):
            _die(f"{label} cargo order must be fmt, clippy, nextest")

    _order(mf, "Makefile")
    _order(test_job.body, "ci.yml test job")


MSRV = "1.95"
MSRV_JOBS = (("ci.yml", "msrv"), ("full-test.yml", "msrv-test"))
# The composite that installs the toolchain, lld and rust-cache (W3-S1). A job
# that `uses:` it has the rust-cache step, so the checks below read through it.
RUST_PREAMBLE = "./.github/actions/rust-preamble"
RUST_PREAMBLE_FILE = ROOT / ".github" / "actions" / "rust-preamble" / "action.yml"


def check_msrv_pinned(
    cargo_toml: str | None = None,
    fuzz_toml: str | None = None,
    toolchain_toml: str | None = None,
    wf_texts: dict[str, str] | None = None,
) -> None:
    """W3-S1: rust-version is MSRV in both manifests; rust-toolchain.toml tracks
    stable; each msrv job installs MSRV and pins it with RUSTUP_TOOLCHAIN (the
    toolchain file outranks `rustup default`, which is all the action sets)."""
    if cargo_toml is None:
        cargo_toml = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if fuzz_toml is None:
        fuzz_toml = (ROOT / "fuzz" / "Cargo.toml").read_text(encoding="utf-8")
    if toolchain_toml is None:
        p = ROOT / "rust-toolchain.toml"
        toolchain_toml = p.read_text(encoding="utf-8") if p.is_file() else ""
    if wf_texts is None:
        wf_texts = {
            name: (WORKFLOWS / name).read_text(encoding="utf-8")
            for name, _ in MSRV_JOBS
            if (WORKFLOWS / name).is_file()
        }
    rv = re.compile(r'(?m)^rust-version\s*=\s*"([^"]+)"')
    for label, text in (("Cargo.toml", cargo_toml), ("fuzz/Cargo.toml", fuzz_toml)):
        m = rv.search(text)
        if not m:
            _die(f"{label} has no rust-version")
        if m.group(1) != MSRV:
            _die(f"{label} rust-version {m.group(1)} != MSRV {MSRV}")
    if not re.search(r'(?m)^channel\s*=\s*"stable"', toolchain_toml):
        _die('rust-toolchain.toml must pin channel = "stable"')
    for name, job_name in MSRV_JOBS:
        text = wf_texts.get(name)
        if text is None:
            _die(f"missing workflow {name}")
        job = Workflow(pathlib.Path(name), text).jobs.get(job_name)
        if job is None:
            _die(f"{name} missing job {job_name}")
        # `@1.95` by tag, or SHA-pinned / the rust-preamble composite with
        # `toolchain: 1.95` (W3-S1 pins by SHA and shares the preamble).
        by_tag = re.search(r"dtolnay/rust-toolchain@" + re.escape(MSRV) + r"\b", job.body)
        installer = re.search(r"dtolnay/rust-toolchain@[0-9a-f]{40}\b", job.body) or (
            RUST_PREAMBLE in job.body
        )
        by_input = installer and re.search(
            r'(?m)^\s+toolchain:\s*"?' + re.escape(MSRV) + r'"?\s*$', job.body
        )
        if not (by_tag or by_input):
            _die(f"{name} job {job_name} must install dtolnay/rust-toolchain {MSRV}")
        if not re.search(r'(?m)^\s+RUSTUP_TOOLCHAIN:\s*"?' + re.escape(MSRV) + r'"?\s*$', job.body):
            _die(f"{name} job {job_name} must set RUSTUP_TOOLCHAIN: {MSRV}")
        if "cargo " not in job.body:
            _die(f"{name} job {job_name} runs no cargo step")


def check_rust_cache_shared_key(
    wf_texts: dict[str, str] | None = None, preamble: str | None = None
) -> None:
    """Every Swatinem/rust-cache step uses shared-key: kerber; cargo jobs have a
    cache, inline or through the rust-preamble composite (which must carry it)."""
    needle = "shared-key: kerber"
    if wf_texts is None:
        wf_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        }
    if preamble is None:
        preamble = RUST_PREAMBLE_FILE.read_text(encoding="utf-8") if RUST_PREAMBLE_FILE.is_file() else ""
    preamble_ok = "Swatinem/rust-cache" in preamble and needle in preamble
    for name, text in wf_texts.items():
        n_cache = text.count("Swatinem/rust-cache")
        n_key = text.count(needle)
        if n_cache and n_key != n_cache:
            _die(f"{name}: rust-cache steps must set shared-key: kerber ({n_key}/{n_cache})")
        wf = Workflow(pathlib.Path(name), text)
        for job_name, job in wf.jobs.items():
            if "cargo " not in job.body and "cargo\n" not in job.body:
                continue
            if RUST_PREAMBLE in job.body:
                if not preamble_ok:
                    _die(f"{RUST_PREAMBLE}/action.yml must run Swatinem/rust-cache with {needle}")
                continue
            if "Swatinem/rust-cache" not in job.body:
                _die(f"{name} job {job_name} runs cargo but has no rust-cache")
            if needle not in job.body:
                _die(f"{name} job {job_name} rust-cache missing shared-key: kerber")


CONCURRENCY_WORKFLOWS = ("ci.yml", "fuzz.yml")
_USES_PINNED = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
SHELLCHECK_CMD = "shellcheck -S style scripts/*.sh scripts/lib/*.sh harness/*.sh"


def check_workflow_hardening(
    wf_texts: dict[str, str] | None = None,
    action_texts: dict[str, str] | None = None,
    dependabot: str | None = None,
    shellcheckrc: str | None = None,
    shellcheck_pins: dict[str, str] | None = None,
) -> None:
    """W3-S1 CI shape: every workflow grants `contents: read` at the top;
    `concurrency` + `cancel-in-progress` on ci.yml and fuzz.yml only; every
    third-party `uses:` (workflows and composite actions) is a 40-hex SHA with
    the tag in a trailing comment; dependabot covers github-actions and cargo;
    ci.yml runs the fail-red shellcheck job over the three script globs with a
    `.shellcheckrc` that follows sources, on a ShellCheck it installs itself by
    version and sha256 (the runner's package differs by two minor versions and
    hundreds of notes), and the Makefile fallback image and the hygiene
    inventory's image name that same version."""
    if wf_texts is None:
        wf_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        }
    if action_texts is None:
        action_texts = {
            f"{p.parent.name}/{p.name}": p.read_text(encoding="utf-8")
            for p in sorted((ROOT / ".github" / "actions").glob("*/action.yml"))
        }
    if dependabot is None:
        p = ROOT / ".github" / "dependabot.yml"
        dependabot = p.read_text(encoding="utf-8") if p.is_file() else ""
    if shellcheckrc is None:
        p = ROOT / ".shellcheckrc"
        shellcheckrc = p.read_text(encoding="utf-8") if p.is_file() else ""
    for name, text in wf_texts.items():
        if not re.search(r"(?m)^permissions:\n  contents: read$", text):
            _die(f"{name} must grant top-level permissions: contents: read")
        has_conc = bool(re.search(r"(?m)^concurrency:\n(?:  .*\n)*  cancel-in-progress: true$", text))
        if has_conc != (name in CONCURRENCY_WORKFLOWS):
            want = "must" if name in CONCURRENCY_WORKFLOWS else "must not"
            _die(f"{name} {want} set concurrency with cancel-in-progress: true")
    for name, text in {**wf_texts, **action_texts}.items():
        for i, line in enumerate(text.splitlines(), 1):
            m = _USES_PINNED.match(line)
            if not m:
                continue
            ref, rest = m.group(1), m.group(2)
            if ref.startswith("./"):
                continue
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref) or not re.match(r"\s+#\s*\S", rest):
                _die(f"{name}:{i} uses: must be SHA-pinned with the tag in a comment: {ref}")
    for eco in ("github-actions", "cargo"):
        if f'package-ecosystem: "{eco}"' not in dependabot and f"package-ecosystem: {eco}" not in dependabot:
            _die(f".github/dependabot.yml must cover package-ecosystem {eco}")
    ci = wf_texts.get("ci.yml")
    if ci is None:
        _die("missing ci.yml")
    job = Workflow(pathlib.Path("ci.yml"), ci).jobs.get("shellcheck")
    if job is None or SHELLCHECK_CMD not in job.body:
        _die(f"ci.yml needs a shellcheck job running `{SHELLCHECK_CMD}`")
    if "external-sources=true" not in shellcheckrc:
        _die(".shellcheckrc must set external-sources=true")
    ver = re.search(r"(?m)^\s+SHELLCHECK_VERSION:\s*(v\d+\.\d+\.\d+)\s*$", job.body)
    if ver is None:
        _die("ci.yml shellcheck job must pin SHELLCHECK_VERSION: vX.Y.Z (the runner's package is not that version)")
    if not re.search(r"(?m)^\s+SHELLCHECK_SHA256:\s*[0-9a-f]{64}\s*$", job.body) or "sha256sum --check" not in job.body:
        _die("ci.yml shellcheck job must verify the release tarball with SHELLCHECK_SHA256 and sha256sum --check")
    if shellcheck_pins is None:
        shellcheck_pins = {
            "Makefile": (ROOT / "Makefile").read_text(encoding="utf-8"),
            "scripts/lib/hygiene_inventory.py": (ROOT / "scripts" / "lib" / "hygiene_inventory.py").read_text(encoding="utf-8"),
        }
    image = f"koalaman/shellcheck:{ver.group(1)}"
    for name, text in shellcheck_pins.items():
        if image not in text:
            _die(f"{name} must run the shellcheck image {image} (the version ci.yml installs)")


def check_prod_image_once(ci_text: str | None = None) -> None:
    """ci.yml builds harness/prod/Dockerfile exactly once (mit-image)."""
    if ci_text is None:
        ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    builds = ci_text.count("docker build -f harness/prod/Dockerfile")
    if builds != 1:
        _die(f"ci.yml must docker build harness/prod/Dockerfile exactly once, found {builds}")
    if "upload-artifact" in ci_text and "mit-kdc-image" in ci_text:
        _die("ci.yml must not upload-artifact the MIT tar (cache restore only)")
    wf = Workflow(pathlib.Path("ci.yml"), ci_text)
    mit = wf.jobs.get("mit-image")
    if mit is None or "harness/prod/Dockerfile" not in mit.body:
        _die("mit-image must build/save harness/prod/Dockerfile")
    if not re.search(r"hashFiles\([^)]*harness/prod/Dockerfile", ci_text):
        _die("cache key must hashFiles harness/prod/Dockerfile")


def check_build_profile(
    cargo: str | None = None,
    cfg: str | None = None,
    ci: str | None = None,
) -> None:
    """[profile.dev] line-tables-only + split-debuginfo; lld rustflags."""
    if cargo is None:
        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if 'debug = "line-tables-only"' not in cargo:
        _die('Cargo.toml [profile.dev] must set debug = "line-tables-only"')
    if 'split-debuginfo = "unpacked"' not in cargo:
        _die('Cargo.toml [profile.dev] must set split-debuginfo = "unpacked"')
    if cfg is None:
        cfg_path = ROOT / ".cargo" / "config.toml"
        if not cfg_path.is_file():
            _die("missing .cargo/config.toml")
        cfg = cfg_path.read_text(encoding="utf-8")
    if "fuse-ld=lld" not in cfg:
        _die(".cargo/config.toml must pass -fuse-ld=lld")
    if ci is None:
        # The lld step lives in the rust-preamble composite every cargo job uses.
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        if RUST_PREAMBLE_FILE.is_file():
            ci += RUST_PREAMBLE_FILE.read_text(encoding="utf-8")
    if "apt-get install" not in ci or " lld" not in ci:
        _die("ci.yml (or the rust-preamble composite) must apt-get install lld")


def check_env_read(
    wf_texts: dict[str, str] | None = None,
    corpus_blob: str | None = None,
) -> None:
    """Every env a workflow sets (except GitHub-provided) is read by a script or test."""
    allow = {
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_TOKEN",
        "GEIGER_DEPS_OUT",
        "KRB5_CONFIG",
        "KERBER_SCRATCH",
        "KERBER_SKIP_MIT_BUILD",
        "KERBER_REQUIRE_REAL_PCAP",
        "KERBER_REQUIRE_NETEM",
        "KERBER_SOAK_SECONDS",
        "SAMBA_AD_IMAGE",
        "SAMBA_AD_REALM",
        "SAMBA_AD_USER",
        "SAMBA_AD_PASSWORD",
        "SAMBA_KERBER_IMAGE",
        "CORRELATION_ID",
    }
    if corpus_blob is None:
        corpus: list[str] = []
        for path in sorted((ROOT / "scripts").rglob("*")):
            if path.suffix in {".sh", ".py", ".rs", ".c"} and path.is_file():
                corpus.append(path.read_text(encoding="utf-8", errors="replace"))
        for path in sorted((ROOT / "crates").rglob("*.rs")):
            corpus.append(path.read_text(encoding="utf-8", errors="replace"))
        blob = "\n".join(corpus)
    else:
        blob = corpus_blob
    if wf_texts is None:
        wf_items = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        }
    else:
        wf_items = wf_texts
    for wf_name, text in wf_items.items():
        in_env = False
        for line in text.splitlines():
            if re.match(r"^\s+env:\s*$", line):
                in_env = True
                continue
            if in_env:
                if re.match(r"^\s+\w", line) and not re.match(r"^\s+[A-Z0-9_]+:", line):
                    in_env = False
                    continue
                m = re.match(r"^\s+([A-Z][A-Z0-9_]+):\s", line)
                if not m:
                    if line.strip() and not line.strip().startswith("#"):
                        in_env = False
                    continue
                name = m.group(1)
                if name in allow:
                    continue
                if name not in blob:
                    _die(f"{wf_name} sets {name} but no script/test reads it")


def check_trace_dst(texts: dict[str, str] | None = None) -> None:
    """Gate captures must not default into tests/traces (S5)."""
    names = ("kdc-gate.sh", "client-gate.sh")
    if texts is None:
        texts = {}
        for name in names:
            path = SCRIPTS / name
            if not path.is_file():
                _die(f"missing scripts/{name}")
            texts[name] = path.read_text(encoding="utf-8")
    for name in names:
        text = texts.get(name, "")
        if 'KERBER_TRACE_DST:-$ROOT/tests/traces' in text:
            _die(f"{name} must not default TRACE_DST to tests/traces")
        if "KERBER_SCRATCH" not in text or "TRACE_DST" not in text:
            _die(f"{name} must default TRACE_DST under KERBER_SCRATCH")


GATE_COMMON_NEEDLES = (
    "log()",
    "die()",
    "unavailable()",
    "need_bins",
    "need_image",
    "gate_wall_s=",
    "wait_port_in",
    "require_listen",
    "require_log",
    "require_port_in",
    "retry_until",
    "wait_udp_in",
    "wait_tcp_bound_in",
    "wait_gone_in",
    "wait_pid_gone",
    "stock_mit_kdc",
    "shell_container",
    "mit_live_guard",
    "mit_conf_restore",
    "find /tmp -mindepth 1 -maxdepth 1",
    "! -name 'build'",
    "kdb5_util destroy",
    "krb5.conf.kerber-stock",
    "kill_proxy_py_in",
    "wait_bound_free_in",
    "samba_kdc_respawn_in",
)


def check_log_arity(common_text: str | None = None) -> None:
    """log() refuses a call that is not 2 or 3 args (W2-Y5)."""
    if common_text is None:
        path = SCRIPTS / "lib" / "gate-common.sh"
        if not path.is_file():
            _die("missing scripts/lib/gate-common.sh")
        common_text = path.read_text(encoding="utf-8")
    m = re.search(r"^log\(\) \{.*?\n\}", common_text, re.M | re.S)
    if not m:
        _die("gate-common.sh must define log()")
    body = m.group(0)
    if '"$#"' not in body:
        _die("log() must check $# arity")
    if "expected 2-3" not in body:
        _die("log() must refuse arity other than 2-3")


def check_autotests_registered(root: pathlib.Path | None = None) -> None:
    """Every tests/*.rs in an autotests=false crate has a [[test]] entry.

    `tests/common.rs` and `tests/common/**` are shared modules, not harnesses.
    """
    root = pathlib.Path(root) if root is not None else ROOT
    crates = root / "crates"
    if not crates.is_dir():
        _die("missing crates/")
    for toml in sorted(crates.glob("*/Cargo.toml")):
        text = toml.read_text(encoding="utf-8")
        if not re.search(r"(?m)^\s*autotests\s*=\s*false\s*$", text):
            continue
        tests_dir = toml.parent / "tests"
        if not tests_dir.is_dir():
            continue
        listed: set[str] = set()
        for m in re.finditer(r"(?ms)^\[\[test\]\]\s*(.*?)(?=\n\[|\Z)", text):
            block = m.group(1)
            path_m = re.search(r'(?m)^\s*path\s*=\s*"([^"]+)"', block)
            name_m = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
            if path_m:
                p = path_m.group(1)
                listed.add(p.removeprefix("tests/"))
            elif name_m:
                listed.add(f"{name_m.group(1)}.rs")
        orphans = []
        for p in tests_dir.rglob("*.rs"):
            rel = p.relative_to(tests_dir).as_posix()
            if rel == "common.rs" or rel.startswith("common/"):
                continue
            if rel not in listed:
                orphans.append(rel)
        if orphans:
            _die(
                f"{toml.parent.name}: autotests=false tests/*.rs missing [[test]]: "
                + ", ".join(sorted(orphans))
            )


_SELF_TEST_OK_RE = re.compile(r"self-test ok \((\d+) cases\)")
HYGIENE_DIFF_MIN_CASES = 36
HYGIENE_BODY_DIFF_MIN_CASES = 41
HYGIENE_FN_DIFF_MIN_CASES = 142
HYGIENE_INVENTORY_MIN_CASES = 8
PY_MOVE_CHECK_MIN_CASES = 18
# S4. A commit that changes a live hit count updates the matching
# constant in that commit. Hard means 0.
MIT_ANCHOR_ALLOW = 0
MIT_TRUTH_ALLOW = 0
PROCESS_TAG_ALLOW = 0
# S5 doc checks: advisory at the live count until the commit that clears each.
CHANGELOG_HEADINGS_ALLOW = 0
DOCS_SIZE_ALLOW = 0
GATE_DOC_ALLOW = 0
DOCS_SIZE_LIMIT = 60 * 1024
# The CHANGELOG at the S5 close (235,552 bytes) plus 9,000 bytes for S6's bullets: one per PR item
# across S6.1-S6.3, at most 25 at 360 bytes (the median bullet is 341); re-based only by a tool:
# commit at the start of a swath that adds bullets.
CHANGELOG_MAX_BYTES = 244552
_REFUSE_CALL_RE = re.compile(r"^\s*refuse_golden_capture_dir\s+\S", re.M)
_REQUIRED_REFUSE_CALLERS = (
    "scripts/lib/prod-realm-common.sh",
    "harness/prod/env-up.sh",
)


def _self_test_n_from_text(text: str) -> int | None:
    found = [int(x) for x in _SELF_TEST_OK_RE.findall(text)]
    return max(found) if found else None


def _self_test_fn_is_gutted(text: str, name: str = "_self_test") -> bool:
    """True when `name` exists and its body is effectively `return None`."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return bool(
            re.search(
                rf'def {re.escape(name)}\([^)]*\):\s*(?:"""[\s\S]*?"""\s*)?return None\b',
                text,
            )
        )
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != name:
            continue
        body = list(node.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(getattr(body[0], "value", None), ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if not body:
            return True
        if len(body) == 1 and isinstance(body[0], ast.Return):
            val = body[0].value
            return val is None or (isinstance(val, ast.Constant) and val.value is None)
        return False
    return False


def _require_self_test_n(blob: str, label: str, min_n: int) -> None:
    n = _self_test_n_from_text(blob)
    if n is None or n < min_n:
        _die(
            f"{label} --self-test must print self-test ok (N cases) with N>={min_n}, got {n!r}"
        )


def _gut_self_test_source(src: str, name: str = "_self_test") -> str:
    tree = ast.parse(src)
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != name:
            continue
        doc = ast.get_docstring(node)
        new_body: list[ast.stmt] = []
        if doc is not None:
            new_body.append(ast.Expr(value=ast.Constant(value=doc)))
        new_body.append(ast.Return(value=ast.Constant(value=None)))
        node.body = new_body
    return ast.unparse(tree)


def _run_script_self_test(
    path: pathlib.Path, label: str, min_n: int | None = None
) -> None:
    proc = subprocess.run(
        [sys.executable, str(path), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-400:]
        _die(f"{label} --self-test failed (rc={proc.returncode}): {tail}")
    if min_n is not None:
        _require_self_test_n((proc.stdout or "") + "\n" + (proc.stderr or ""), label, min_n)


def _gutted_self_test_must_not_count(
    path: pathlib.Path, src: str, label: str, min_n: int
) -> None:
    """A copy whose `_self_test` body is `return None` must not report N cases."""
    try:
        gutted = _gut_self_test_source(src)
    except SyntaxError:
        return
    with tempfile.TemporaryDirectory() as tmp:
        probe_root = pathlib.Path(tmp)
        dest = probe_root / "scripts" / path.name
        dest.parent.mkdir(parents=True)
        dest.write_text(gutted, encoding="utf-8")
        # Sibling imports resolve ROOT as parents[1] of scripts/*.py.
        # Copy them so a gutted file can start; a missing sibling made
        # the probe vacuous (import crash, no N, treated as green).
        for sib in (
            SCRIPTS / "hygiene-diff.py",
            SCRIPTS / "lib" / "hygiene_inventory.py",
        ):
            if sib.resolve() == path.resolve():
                continue
            target = probe_root / "scripts" / sib.relative_to(SCRIPTS)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sib, target)
        proc = subprocess.run(
            [sys.executable, str(dest), "--self-test"],
            cwd=probe_root,
            capture_output=True,
            text=True,
            check=False,
        )
        n = _self_test_n_from_text((proc.stdout or "") + "\n" + (proc.stderr or ""))
        if n is not None and n >= min_n:
            _die(f"{label} gutted _self_test still reports self-test ok ({n} cases)")


def check_hygiene_diff_self_test(text: str | None = None) -> None:
    """hygiene-diff.py --self-test is executed; a gutted `_self_test` is red."""
    path = SCRIPTS / "hygiene-diff.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/hygiene-diff.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "hygiene-diff.py", HYGIENE_DIFF_MIN_CASES)
        _gutted_self_test_must_not_count(
            path, text, "hygiene-diff.py", HYGIENE_DIFF_MIN_CASES
        )
    elif _self_test_n_from_text(text) is None or (
        _self_test_n_from_text(text) or 0
    ) < HYGIENE_DIFF_MIN_CASES:
        _die(
            "hygiene-diff.py must print self-test ok (N cases) with "
            f"N>={HYGIENE_DIFF_MIN_CASES}"
        )
    if _self_test_fn_is_gutted(text):
        _die("hygiene-diff.py _self_test must not be gutted to return None")
    if "def main" not in text:
        _die("hygiene-diff.py must define main()")
    if "def _self_test" not in text:
        _die("hygiene-diff.py must define _self_test")
    if text.count("_self_test()") < 2:
        _die("hygiene-diff.py must run _self_test on normal compare runs")
    if "redirect_stdout(sys.stderr)" not in text:
        _die("hygiene-diff.py must send compare-run _self_test to stderr")
    if "def load_duplicates_map" not in text or "merged:" not in text:
        _die("hygiene-diff.py must key --duplicates and require merged: for many-to-one")
    if "def load_renames_map" not in text:
        _die("hygiene-diff.py must key --renames")
    if "def _self_test_duplicates" not in text:
        _die("hygiene-diff.py must self-test keyed duplicates maps")


def check_hygiene_body_diff_self_test(text: str | None = None) -> None:
    """hygiene-body-diff.py --self-test is executed; a gutted `_self_test` is red."""
    path = SCRIPTS / "hygiene-body-diff.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/hygiene-body-diff.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "hygiene-body-diff.py", HYGIENE_BODY_DIFF_MIN_CASES)
        _gutted_self_test_must_not_count(
            path, text, "hygiene-body-diff.py", HYGIENE_BODY_DIFF_MIN_CASES
        )
        testing = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
        body_at = testing.find("hygiene-body-diff.py")
        fn_at = testing.find("hygiene-fn-diff.py")
        chunk = testing[body_at:fn_at] if body_at >= 0 and fn_at > body_at else ""
        if "literal" not in chunk:
            _die(
                "docs/testing.md must say hygiene-body-diff keeps string literals whole"
            )
    elif _self_test_n_from_text(text) is None or (
        _self_test_n_from_text(text) or 0
    ) < HYGIENE_BODY_DIFF_MIN_CASES:
        _die(
            "hygiene-body-diff.py must print self-test ok (N cases) with "
            f"N>={HYGIENE_BODY_DIFF_MIN_CASES}"
        )
    if _self_test_fn_is_gutted(text):
        _die("hygiene-body-diff.py _self_test must not be gutted to return None")
    if "def _self_test" not in text:
        _die("hygiene-body-diff.py must define _self_test")
    if text.count("_self_test()") < 2:
        _die("hygiene-body-diff.py must run _self_test on normal compare runs")
    if not re.search(r"assert_eq!\(\s*1,\s*2\s*\)", text):
        _die("hygiene-body-diff.py must self-test an assertion change (assert_eq!(1, 2))")
    if "user_as" not in text:
        _die("hygiene-body-diff.py must self-test a helper rename")
    if '"a  b"' not in text:
        _die("hygiene-body-diff.py must self-test whitespace inside an asserted string")
    if 'r"a\\n\\nb"' not in text:
        _die(
            "hygiene-body-diff.py must self-test a zero-length interior line of an asserted literal"
        )


def check_hygiene_fn_diff_self_test(text: str | None = None) -> None:
    """hygiene-fn-diff.py --self-test is executed; a gutted `_self_test` is red."""
    path = SCRIPTS / "hygiene-fn-diff.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/hygiene-fn-diff.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "hygiene-fn-diff.py", HYGIENE_FN_DIFF_MIN_CASES)
        _gutted_self_test_must_not_count(
            path, text, "hygiene-fn-diff.py", HYGIENE_FN_DIFF_MIN_CASES
        )
        testing = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
        dead_at = testing.find("`--dead`")
        diff_at = testing.find("hygiene-diff.py")
        fn_at = testing.find("hygiene-fn-diff.py")
        if dead_at < 0 or not (diff_at < dead_at < fn_at):
            _die("docs/testing.md must describe --dead on the hygiene-diff paragraph")
        for needle in (
            "byte-string",
            "line-anchored",
            "impl-header",
            "head:",
            "rustfmt_skip",
            "const-fold",
        ):
            if needle not in testing:
                _die(f"docs/testing.md must describe fn-diff {needle}")
    elif _self_test_n_from_text(text) is None or (
        _self_test_n_from_text(text) or 0
    ) < HYGIENE_FN_DIFF_MIN_CASES:
        _die(
            "hygiene-fn-diff.py must print self-test ok (N cases) with "
            f"N>={HYGIENE_FN_DIFF_MIN_CASES}"
        )
    if _self_test_fn_is_gutted(text):
        _die("hygiene-fn-diff.py _self_test must not be gutted to return None")
    if "def _self_test" not in text:
        _die("hygiene-fn-diff.py must define _self_test")
    if text.count("_self_test()") < 2:
        _die("hygiene-fn-diff.py must run _self_test on normal compare runs")
    if "x + 2" not in text:
        _die("hygiene-fn-diff.py must self-test a body edit")
    if "phase_b" not in text:
        _die("hygiene-fn-diff.py must self-test --split")
    if "pub(crate)" not in text:
        _die("hygiene-fn-diff.py must self-test a vis-only change")
    if "unused-accept fixture must be otherwise green" not in text:
        _die("hygiene-fn-diff.py must isolate unused --accept as its own case")


_PY_MOVE_KINDS = ("missing", "extra", "defined-twice", "changed", "unresolved", "future", "stray", "shim", "cycles")


def check_py_move_self_test(text: str | None = None) -> None:
    """py-move-check.py --self-test is executed; a gutted `_self_test` is red; every finding kind
    has a fixture, and a compare run self-tests first."""
    path = SCRIPTS / "py-move-check.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/py-move-check.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "py-move-check.py", PY_MOVE_CHECK_MIN_CASES)
        _gutted_self_test_must_not_count(path, text, "py-move-check.py", PY_MOVE_CHECK_MIN_CASES)
    elif (_self_test_n_from_text(text) or 0) < PY_MOVE_CHECK_MIN_CASES:
        _die(f"py-move-check.py must print self-test ok (N cases) with N>={PY_MOVE_CHECK_MIN_CASES}")
    if _self_test_fn_is_gutted(text):
        _die("py-move-check.py _self_test must not be gutted to return None")
    if "def _self_test" not in text or "def main" not in text:
        _die("py-move-check.py must define _self_test and main")
    if text.count("_self_test()") < 2 or "redirect_stdout(sys.stderr)" not in text:
        _die("py-move-check.py must run _self_test (to stderr) before a compare run")
    for kind in _PY_MOVE_KINDS:
        if f'"{kind}"),' not in text:
            _die(f"py-move-check.py must self-test the {kind} finding")


def check_hygiene_inventory_cfg_test() -> None:
    """Inventory classifies `#[cfg(test)] mod x;` as src-test."""
    path = SCRIPTS / "lib" / "hygiene_inventory.py"
    if not path.is_file():
        _die("missing scripts/lib/hygiene_inventory.py")
    _run_script_self_test(path, "hygiene_inventory.py", HYGIENE_INVENTORY_MIN_CASES)


# The two tools that load scripts/ci-policy.py as a module and read its attributes.
_POLICY_MODULE_CONSUMERS = (
    ("scripts/kdb-dump-gate.sh", ("ROOT", "_dump_key_hexes", "check_golden_dump_unique_keys")),
    (
        "scripts/lib/hygiene_inventory.py",
        ("DIFFSEND_CASES", "ledger_sources", "recount_ledger_verdicts", "_split_ledger_row"),
    ),
)
_POLICY_MODULE_PROBE = """import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location("ci_policy", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out = {"missing": [n for n in json.loads(sys.argv[2]) if not hasattr(mod, n)]}
if not out["missing"]:
    out["diffsend"] = sorted(mod.DIFFSEND_CASES)
    out["ledger"] = [name for name, _text, _key in mod.ledger_sources(mod.ROOT)]
print(json.dumps(out))
"""


def check_policy_module_attrs(path: pathlib.Path | None = None) -> None:
    """scripts/ci-policy.py, loaded as a module the way kdb-dump-gate.sh:36-40 loads it (`python3 -`
    from cwd=/, spec_from_file_location, no PYTHONPATH), has every name its two consumers read; its
    DIFFSEND_CASES is this policy's list (what hygiene_inventory's diffsend_cases reads) and its
    ledger_sources reads the docs/parity/ split, so a stub with the right names does not pass."""
    path = SCRIPTS / "ci-policy.py" if path is None else path
    names = [n for _consumer, group in _POLICY_MODULE_CONSUMERS for n in group]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    r = subprocess.run(
        [sys.executable, "-", str(path), json.dumps(names)],
        input=_POLICY_MODULE_PROBE,
        cwd="/",
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        tail = (r.stderr or r.stdout).strip().splitlines()[-1:]
        _die(f"{path.name} does not load as a module from cwd=/: {tail}")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    for consumer, group in _POLICY_MODULE_CONSUMERS:
        missing = [n for n in group if n in out["missing"]]
        if missing:
            _die(f"{path.name} loaded as a module lacks {', '.join(missing)}, which {consumer} reads")
    if out["diffsend"] != sorted(DIFFSEND_CASES):
        _die(
            f"{path.name} loaded as a module holds {len(out['diffsend'])} DIFFSEND_CASES, this policy "
            f"{len(DIFFSEND_CASES)}: hygiene_inventory.py's diffsend_cases would read the wrong list"
        )
    if not out["ledger"] or not all(n.startswith("docs/parity/") for n in out["ledger"]):
        _die(
            f"{path.name} loaded as a module: ledger_sources reads {out['ledger'][:2]}, not the "
            "docs/parity/ split that hygiene_inventory.py's ledger_rows needs"
        )


def check_gate_common_sourced(
    common_text: str | None = None,
    gate_texts: dict[str, str] | None = None,
) -> None:
    """Every gate sources gate-common.sh; no private log()/cleanup(); no cargo build."""
    if common_text is None:
        common = SCRIPTS / "lib" / "gate-common.sh"
        if not common.is_file():
            _die("missing scripts/lib/gate-common.sh")
        common_text = common.read_text(encoding="utf-8")
    for needle in GATE_COMMON_NEEDLES:
        if needle not in common_text:
            _die(f"gate-common.sh missing {needle}")
    if "pkill -f -- '-proxy.py'" in (common_text or "") and "kill_proxy_py_in" not in common_text:
        _die("gate-common.sh must pin kill_proxy_py_in, not only pkill")
    if "GITHUB_ACTIONS" not in common_text or "::error file=" not in common_text:
        _die("die must print ::error file=… when GITHUB_ACTIONS is set")
    if "::notice file=" not in common_text:
        _die("unavailable must print ::notice file=… when GITHUB_ACTIONS is set")
    if gate_texts is None:
        items = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*-gate.sh"))
        }
        live = True
    else:
        items = gate_texts
        live = False
    for name, text in items.items():
        if "scripts/lib/gate-common.sh" not in text:
            _die(f"{name} must source scripts/lib/gate-common.sh")
        if re.search(r"^log\(\)", text, re.M):
            _die(f"{name} still defines a private log()")
        if re.search(r"^cleanup\(\)", text, re.M):
            _die(f"{name} still defines a private cleanup()")
        check_gate_no_exit_trap(text, name)
        if name in ("kadmin-rust-gate.sh", "kadmin-rust-acl-gate.sh", "kadmin-mit-gate.sh", "kadmin-both-gate.sh") and "kadmin-glob-cells.sh" not in text:
            _die(f"{name} must source scripts/lib/kadmin-glob-cells.sh")
        if name in ("kadmin-rust-gate.sh", "kadmin-mit-gate.sh"):
            if re.search(r'wait_port_in\s+"\$NAME(_MIT)?"\s+1749', text):
                _die(f"{name} tamper proxy is single-accept; use wait_tcp_bound_in, not wait_port_in")
            if "wait_tcp_bound_in" not in text:
                _die(f"{name} must wait_tcp_bound_in for the integrity tamper proxy")
        check_kadmin_split_snaps(text, name)
        if name == "kcm-gate.sh":
            check_kcm_need_image(text)
            check_kcm_stop_before_run(text, name)
        if name == "prod-gate.sh":
            check_prod_gate_tcpdump_cleanup(text)
        if re.search(r"krb5kdc -n >/tmp/mit-kdc.log 2>&1 & cat", text):
            _die(f"{name} must wait_log for krb5kdc -n, not cat the log immediately")
    check_no_gate_cargo_build(items)
    idx = common_text.find("samba_kdc_respawn_in()")
    end = common_text.find("wait_pid_gone()", idx) if idx >= 0 else -1
    if idx >= 0 and end > idx and "wait_udp_in" in common_text[idx:end]:
        _die("samba_kdc_respawn_in must wait for a new task[kdc] pid, not wait_udp_in :88")
    if live:
        ci_yml = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        if "gate-attach-reset-selftest.sh" not in ci_yml:
            _die("ci.yml must run gate-attach-reset-selftest.sh")
        check_kadmin_glob_lib()
        check_s4_shared_boots()
        check_build_bins_examples()


def check_s4_shared_boots(ci_text: str | None = None) -> None:
    """harness and mit-extra boot one stock MIT KDC and one shell per job."""
    if ci_text is None:
        ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    if "boot-stock-mit.sh" not in ci_text:
        _die("ci.yml must run scripts/lib/boot-stock-mit.sh")
    if "boot-shell.sh" not in ci_text:
        _die("ci.yml must run scripts/lib/boot-shell.sh")
    if ci_text.count("boot-stock-mit.sh") < 4:
        _die("ci.yml must boot stock MIT in harness, harness-2, mit-extra, and mit-extra-2")
    if ci_text.count("boot-shell.sh") < 4:
        _die("ci.yml must boot a shared shell in harness, harness-2, mit-extra, and mit-extra-2")


def check_stock_boots_per_job(ci_text: str | None = None) -> None:
    """Plan name for the S4 shared-boot contract."""
    check_s4_shared_boots(ci_text)


def _hygiene_inventory():
    spec = importlib.util.spec_from_file_location(
        "hygiene_inventory", SCRIPTS / "lib" / "hygiene_inventory.py"
    )
    if spec is None or spec.loader is None:
        _die("cannot load scripts/lib/hygiene_inventory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def classify_gate_sleeps(text: str) -> list[tuple[str, float]]:
    inv = _hygiene_inventory()
    return [(kind, float(sec)) for _ln, sec, kind in inv.classify_sleeps(text)]


def check_sleep_classifiers_agree(text: str | None = None) -> None:
    """ci-policy and the snapshot must book the same kind for each sleep."""
    inv = _hygiene_inventory()

    def one(label: str, body: str) -> None:
        policy = classify_gate_sleeps(body)
        inventory = [(kind, float(sec)) for _ln, sec, kind in inv.classify_sleeps(body)]
        if policy != inventory:
            _die(f"sleep classifiers disagree in {label}: policy={policy} inventory={inventory}")

    if text is not None:
        one("fixture", text)
        return
    one(
        "self",
        "for _ in $(seq 1 10); do\n"
        "    sleep 0.1\n"
        "done\n"
        "sleep 0.1 # proto: krb5kdc pid reuse\n"
        + ("# pad\n" * 40)
        + "sleep 0.1 # proto: far from any loop\n",
    )
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        one(path.name, path.read_text(encoding="utf-8"))
    common = SCRIPTS / "lib" / "gate-common.sh"
    if common.is_file():
        one(common.name, common.read_text(encoding="utf-8"))


def check_gate_wall(
    exceptions_text: str | None = None,
    timings_text: str | None = None,
) -> None:
    """Checkpoint gate walls ≤ 45 s; exceptions file must be empty."""
    if exceptions_text is None:
        path = ROOT / EXCEPTIONS_REL
        if not path.is_file():
            _die(f"missing {EXCEPTIONS_REL}")
        exceptions_text = path.read_text(encoding="utf-8")
    for i, line in enumerate(exceptions_text.splitlines(), 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            _die(f"{EXCEPTIONS_REL}:{i} must be empty (no gate-wall exceptions)")
    texts: list[str] = []
    if timings_text is not None:
        texts = [timings_text]
    else:
        args = sys.argv[1:]
        if "--timings" in args:
            idx = args.index("--timings")
            if idx + 1 >= len(args):
                _die("--timings needs a path")
            tpath = pathlib.Path(args[idx + 1])
            if not tpath.is_file():
                _die(f"missing timings file {tpath}")
            texts = [tpath.read_text(encoding="utf-8")]
        elif "--checkpoint" in args:
            log_root = ROOT / "working" / "logs"
            texts = [
                p.read_text(encoding="utf-8")
                for p in log_root.rglob("timings.tsv")
                if p.is_file()
            ]
        else:
            return
    for text in texts:
        n_rows = 0
        n_rc0 = 0
        for i, line in enumerate(text.splitlines()):
            if i == 0 and line.startswith("gate"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            try:
                wall = int(parts[3])
                rc = int(parts[2])
            except ValueError:
                continue
            n_rows += 1
            if rc == 0:
                n_rc0 += 1
            if wall > GATE_WALL_MAX:
                _die(f"gate {parts[0]} wall_s={wall} exceeds {GATE_WALL_MAX}")
        if n_rows and n_rc0 == 0:
            _die("checkpoint timings have zero gate_rc=0 rows")


def check_sleep_ratchet(
    gate_texts: dict[str, str] | None = None,
    unit_sleep_count: int | None = None,
) -> None:
    """Gate proto sleeps ≤ GATE_PROTO_SLEEP_MAX all tagged; unit sleep( ≤ UNIT_SLEEP_MAX."""
    if gate_texts is None:
        gate_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*-gate.sh"))
        }
        common = SCRIPTS / "lib" / "gate-common.sh"
        if common.is_file():
            gate_texts[common.name] = common.read_text(encoding="utf-8")
    proto = 0.0
    for name, text in gate_texts.items():
        for kind, sec in classify_gate_sleeps(text):
            if kind == "padding":
                _die(f"{name} has an untagged padding sleep {sec}s")
            if kind == "proto":
                proto += sec
    if proto > GATE_PROTO_SLEEP_MAX:
        _die(f"proto sleeps sum {proto:.1f}s exceeds {GATE_PROTO_SLEEP_MAX}")
    if unit_sleep_count is None:
        n = 0
        for path in (ROOT / "crates").glob("*/tests/**/*.rs"):
            n += path.read_text(encoding="utf-8", errors="replace").count("sleep(")
        unit_sleep_count = n
    if unit_sleep_count > UNIT_SLEEP_MAX:
        _die(f"unit sleep( count {unit_sleep_count} exceeds {UNIT_SLEEP_MAX}")


def parse_budget_toml(text: str) -> dict:
    import tomllib

    data = tomllib.loads(text)
    jobs = {str(k): int(v) for k, v in (data.get("jobs") or {}).items()}
    run_wall = (data.get("push") or {}).get("run_wall")
    return {"jobs": jobs, "run_wall": int(run_wall) if run_wall is not None else None}


def check_ci_budgets(
    toml_text: str | None = None,
    status_text: str | None = None,
    wf_names: list[str] | None = None,
    ci_job_names: list[str] | None = None,
) -> None:
    """ci-budget.toml exists with required jobs; plan caps are maxima; every ci.yml job is budgeted."""
    live = toml_text is None
    if toml_text is None:
        path = ROOT / "ci-budget.toml"
        if not path.is_file():
            _die("missing ci-budget.toml")
        toml_text = path.read_text(encoding="utf-8")
    budget = parse_budget_toml(toml_text)
    for name in BUDGET_REQUIRED_JOBS:
        if name not in budget["jobs"]:
            _die(f"ci-budget.toml missing [jobs].{name}")
    if budget.get("run_wall") is None:
        _die("ci-budget.toml missing [push].run_wall")
    for name, cap in PLAN_JOB_CAPS.items():
        val = budget["jobs"].get(name)
        if val is not None and val > cap:
            _die(f"ci-budget.toml [jobs].{name}={val} exceeds plan cap {cap}")
    if budget["run_wall"] > PLAN_RUN_WALL_CAP:
        _die(
            f"ci-budget.toml [push].run_wall={budget['run_wall']} "
            f"exceeds plan cap {PLAN_RUN_WALL_CAP}"
        )
    if status_text is None:
        status_text = (SCRIPTS / "ci-status.py").read_text(encoding="utf-8")
    if "--check-budget" not in status_text:
        _die("ci-status.py must support --check-budget")
    if "budget_overruns" not in status_text:
        _die("ci-status.py must implement budget_overruns")
    if wf_names is None:
        wf_names = [p.name for p in sorted(WORKFLOWS.glob("*.yml"))]
    if "budget.yml" not in wf_names:
        _die("missing .github/workflows/budget.yml nightly job")
    if live and ci_job_names is None:
        ci_path = WORKFLOWS / "ci.yml"
        if ci_path.is_file():
            ci_job_names = list(Workflow(ci_path, ci_path.read_text()).jobs)
    if ci_job_names:
        for name in ci_job_names:
            if name not in budget["jobs"]:
                _die(f"ci-budget.toml missing [jobs].{name} (ci.yml job)")


def check_testing_doc_budgets(
    testing_text: str | None = None,
    contributing_text: str | None = None,
    toml_text: str | None = None,
) -> None:
    """docs/testing.md names the three tiers; numbers come from ci-budget.toml."""
    if testing_text is None:
        testing_text = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
    if contributing_text is None:
        contributing_text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    if toml_text is None:
        path = ROOT / "ci-budget.toml"
        if not path.is_file():
            _die("missing ci-budget.toml")
        toml_text = path.read_text(encoding="utf-8")
    for needle in ("Tier 1", "Tier 2", "Tier 3", "ci-budget.toml"):
        if needle not in testing_text:
            _die(f"docs/testing.md must name {needle}")
    budget = parse_budget_toml(toml_text)
    for name in BUDGET_REQUIRED_JOBS:
        if name not in testing_text:
            _die(f"docs/testing.md must mention job {name}")
    if "ci-budget.toml" not in contributing_text and "tier" not in contributing_text.lower():
        _die("CONTRIBUTING.md must mention the tier rule / ci-budget.toml")
    harness = str(budget["jobs"].get("harness", ""))
    if harness and harness not in testing_text:
        _die("docs/testing.md must quote the harness budget from ci-budget.toml")


def check_kadmin_glob_lib(text: str | None = None) -> None:
    """hist_shape lives in the sourced lib so both-gate can diff getprinc output."""
    if text is None:
        path = SCRIPTS / "lib" / "kadmin-glob-cells.sh"
        if not path.is_file():
            _die("missing scripts/lib/kadmin-glob-cells.sh")
        text = path.read_text(encoding="utf-8")
    if "hist_shape" not in text:
        _die("kadmin-glob-cells.sh must define hist_shape for rust/MIT getprinc diffs")
    if "alias_cells" not in text:
        _die("kadmin-glob-cells.sh must define alias_cells")


def check_kadmin_split_snaps(text: str, name: str) -> None:
    """KEEP preserves containers, not shell vars; rust snapshots must cross the process boundary."""
    if name == "kadmin-rust-gate.sh" and "save_rust_snap" not in text:
        _die("kadmin-rust-gate.sh must persist rust snapshots for mit-gate diffs")
    if name == "kadmin-rust-acl-gate.sh" and "save_rust_snap" not in text:
        _die("kadmin-rust-acl-gate.sh must persist rust snapshots for mit-gate diffs")
    if name == "kadmin-mit-gate.sh" and "load_rust_snap" not in text:
        _die("kadmin-mit-gate.sh must load rust snapshots (KEEP does not preserve shell vars)")
    if name == "kadmin-gate.sh":
        if "kadmin-rust-gate.sh" not in text or "kadmin-both-gate.sh" not in text:
            _die("kadmin-gate.sh must wrap rust+mit+both legs")
        if "kadmin-rust-acl-gate.sh" not in text:
            _die("kadmin-gate.sh must wrap rust-acl after rust")
        if "KERBER_SCRATCH" not in text:
            _die("kadmin-gate.sh must export KERBER_SCRATCH so rust/mit/both share snapshots")


def check_kcm_need_image(text: str, name: str = "kcm-gate.sh") -> None:
    """need_image inspects $IMAGE; the Fedora KCM tag is not the MIT image."""
    if re.search(r'^\s*IMAGE=.*sssd-kcm', text, re.M) and "need_image" in text:
        _die(f"{name} must not set IMAGE to sssd-kcm before need_image (KERBER_SKIP_MIT_BUILD)")
    if "KCM_IMAGE" not in text:
        _die(f"{name} must use KCM_IMAGE for the Fedora sssd-kcm tag")


def check_kcm_stop_before_run(text: str | None = None, name: str = "kcm-gate.sh") -> None:
    """kcm-gate registers stop-harness before run-harness so a failed boot still stops."""
    if text is None:
        path = SCRIPTS / "kcm-gate.sh"
        if not path.is_file():
            _die("missing scripts/kcm-gate.sh")
        text = path.read_text(encoding="utf-8")
    stop = text.find("stop-harness.sh")
    run = text.find("run-harness.sh")
    if run < 0:
        _die(f"{name} must call run-harness.sh")
    if stop < 0:
        _die(f"{name} must register stop-harness.sh")
    if stop > run:
        _die(f"{name} must register stop-harness before run-harness")


def check_prod_gate_tcpdump_cleanup(text: str | None = None) -> None:
    """Registered cleanup kills root tcpdump with sudo -n kill; KDC with plain kill."""
    if text is None:
        path = SCRIPTS / "prod-gate.sh"
        if not path.is_file():
            _die("missing scripts/prod-gate.sh")
        text = path.read_text(encoding="utf-8")
    # The cleanup is a quoted string or a named function; read the body either way.
    bodies = re.findall(r"register_cleanup\s+'([^']*)'", text)
    for fn in re.findall(r"^register_cleanup\s+([A-Za-z_]\w*)\s*$", text, re.M):
        m = re.search(rf"^{re.escape(fn)}\(\)\s*\{{\n(.*?)^\}}", text, re.M | re.S)
        if m:
            bodies.append(m.group(1))
    if not bodies:
        _die("prod-gate.sh must register_cleanup")
    joined = "\n".join(bodies)
    if "sudo -n kill" not in joined or "TCPDUMP_PID" not in joined:
        _die("prod-gate.sh cleanup must sudo -n kill TCPDUMP_PID")
    if re.search(r"kill \$KDC_PID \$TCPDUMP_PID", joined):
        _die("prod-gate.sh must not plain-kill the root tcpdump with the KDC")
    if "kill $KDC_PID" not in joined and 'kill "$KDC_PID"' not in joined:
        _die("prod-gate.sh cleanup must plain-kill KDC_PID")


def check_gate_no_exit_trap(text: str, name: str = "gate.sh") -> None:
    """Gates must not replace gate-common's EXIT trap (register_cleanup)."""
    if re.search(r"^\s*trap\b.*\bEXIT\b", text, re.M):
        _die(f"{name} must not set an EXIT trap (use register_cleanup)")


def check_build_bins_examples() -> None:
    """build-bins.sh must build krb5-tools and name the seven harness bins."""
    path = SCRIPTS / "lib" / "build-bins.sh"
    if not path.is_file():
        _die("missing scripts/lib/build-bins.sh")
    text = path.read_text(encoding="utf-8")
    if "krb5-tools" not in text:
        _die("build-bins.sh must build -p krb5-tools")
    for ex in (
        "kprop-expired-apreq",
        "ccache-probe",
        "loadgen",
        "krb5-vfy-increds",
        "krb5-forge-tgt",
        "krb5-pac-extract",
        "diffsend",
    ):
        if ex not in text:
            _die(f"build-bins.sh must name harness bin {ex}")


def check_gate_cargo_leftover(text: str, name: str = "gate.sh") -> None:
    """S2 converter residue: a cargo-build argument line with no cargo build."""
    if re.search(r"^\s+-p\s+krb5-", text, re.M):
        _die(f"{name} still has leftover cargo-build argument lines")


def check_need_bins_strict(
    ci_text: str | None = None,
    checkpoint_text: str | None = None,
    common_text: str | None = None,
    workflow_texts: dict[str, str] | None = None,
) -> None:
    """CI, checkpoint, and every gate-running workflow set STRICT=1 and build-bins."""
    if ci_text is None:
        ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    if "KERBER_NEED_BINS_STRICT" not in ci_text:
        _die("ci.yml must set KERBER_NEED_BINS_STRICT")
    if checkpoint_text is None:
        checkpoint_text = (SCRIPTS / "checkpoint.sh").read_text(encoding="utf-8")
    if "KERBER_NEED_BINS_STRICT=1" not in checkpoint_text:
        _die("checkpoint.sh must export KERBER_NEED_BINS_STRICT=1")
    if common_text is None:
        common_text = (SCRIPTS / "lib" / "gate-common.sh").read_text(encoding="utf-8")
    if "KERBER_NEED_BINS_STRICT" not in common_text:
        _die("need_bins must honour KERBER_NEED_BINS_STRICT")
    if "need_bins: building" not in common_text:
        _die("need_bins must log when it builds (lenient local path)")
    if workflow_texts is None:
        workflow_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(WORKFLOWS.glob("*.yml"))
        }
    for name, text in workflow_texts.items():
        if not re.search(r"scripts/[A-Za-z0-9._-]+-gate\.sh", text):
            continue
        if "build-bins.sh" not in text:
            _die(f"{name} runs a gate but has no build-bins.sh step")
        if 'KERBER_NEED_BINS_STRICT: "1"' not in text:
            _die(f'{name} runs a gate but lacks KERBER_NEED_BINS_STRICT: "1"')


def check_no_gate_cargo_build(gate_texts: dict[str, str] | None = None) -> None:
    """Named S6 rule: no scripts/*-gate.sh may run cargo build (use need_bins)."""
    if gate_texts is None:
        gate_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*-gate.sh"))
        }
    for name, text in gate_texts.items():
        if re.search(r"\bcargo\s+build\b", text):
            _die(f"{name} must not run cargo build (use need_bins)")
        check_gate_cargo_leftover(text, name)


PEER_CAPTURE_GATES = (
    "ad-s4u-gate.sh",
    "ad-windows-gate.sh",
    "samba-ad-gate.sh",
    "samba-crossrealm-gate.sh",
    "samba-pac-l2-gate.sh",
    "samba-pac-verify-gate.sh",
)


def _run_rc_adjacent_to_docker_run(text: str) -> bool:
    """`run_rc=$?` must follow `docker run` with no `register_cleanup` in between."""
    lines = text.splitlines()
    saw = False
    for i, line in enumerate(lines):
        if not re.search(r"\bdocker\s+run\b", line.split("#", 1)[0]):
            continue
        for j in range(i + 1, min(len(lines), i + 12)):
            code = lines[j].split("#", 1)[0]
            if re.search(r"\brun_rc=\$\?", code):
                saw = True
                between = "\n".join(lines[i + 1 : j])
                if "register_cleanup" in between:
                    return False
                break
    return saw


def check_peers_unavailable_convention(
    wrapper_text: str | None = None,
    peers_text: str | None = None,
    ad_text: str | None = None,
    nightly_texts: dict[str, str] | None = None,
    capture_texts: dict[str, str] | None = None,
) -> None:
    """peers.yml maps gate exit 2 to step success; live kinit/kvno failures are exit 1."""
    live = wrapper_text is None and peers_text is None and ad_text is None
    if wrapper_text is None:
        wrapper = SCRIPTS / "lib" / "run-peer-step.sh"
        if not wrapper.is_file():
            _die("missing scripts/lib/run-peer-step.sh")
        wrapper_text = wrapper.read_text(encoding="utf-8")
    if "[ \"$rc\" -eq 2 ]" not in wrapper_text and "[ \"$rc\" -eq 2 ]" not in wrapper_text.replace(" ", ""):
        if 'rc" -eq 2' not in wrapper_text:
            _die("run-peer-step.sh must treat exit 2 as unavailable (not a job failure)")
    if peers_text is None:
        peers_text = (WORKFLOWS / "peers.yml").read_text(encoding="utf-8")
    if "run-peer-step.sh" not in peers_text:
        _die("peers.yml must wrap peer gates with run-peer-step.sh")
    if ad_text is None:
        ad_text = (SCRIPTS / "samba-ad-gate.sh").read_text(encoding="utf-8")
    if 'unavailable "kinit' in ad_text:
        _die("samba-ad-gate.sh kinit failure against a listening KDC must exit 1, not unavailable")
    if "exit 1" not in ad_text:
        _die("samba-ad-gate.sh must exit 1 on live kinit/kvno failure")
    if live:
        nightly_texts = {}
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if Workflow(path, text).scheduled:
                nightly_texts[path.name] = text
        capture_texts = {
            name: (SCRIPTS / name).read_text(encoding="utf-8")
            for name in PEER_CAPTURE_GATES
            if (SCRIPTS / name).is_file()
        }
    if nightly_texts:
        for name, text in nightly_texts.items():
            if not re.search(r"scripts/[A-Za-z0-9._-]+-gate\.sh", text):
                continue
            if "kerber-rust-mit-kdc.tar" not in text and "KERBER_NO_IMAGE" not in text:
                _die(
                    f"{name} runs a gate but neither restores the MIT tar "
                    "nor sets KERBER_NO_IMAGE"
                )
        for name in ("peers.yml", "kcm-opcode.yml"):
            text = nightly_texts.get(name, "")
            if not text:
                continue
            if "kerber-rust-mit-kdc.tar" not in text:
                _die(f"{name} must restore kerber-rust-mit-kdc.tar (KERBER_NO_IMAGE is not a substitute)")
            if name == "kcm-opcode.yml" and "lld" not in text and RUST_PREAMBLE not in text:
                _die("kcm-opcode.yml must install lld (inline or via the rust-preamble composite)")
            if name == "kcm-opcode.yml" and "run-peer-step.sh" not in text:
                _die("kcm-opcode.yml must wrap the gate with run-peer-step.sh")
        if "peers.yml" in nightly_texts:
            pt = nightly_texts["peers.yml"]
            if "unavailable=" not in pt or "failed=" not in pt:
                _die("peers.yml must print unavailable=N failed=M")
    if capture_texts:
        for name, text in capture_texts.items():
            if not _run_rc_adjacent_to_docker_run(text):
                _die(f"{name} run_rc=$? must sit adjacent to docker run")


_SAMBA_GONE_88 = re.compile(r'wait_gone_in\s+"\$NAME(_A)?"\s+88')


def check_samba_kdc_respawn(
    cross_text: str | None = None,
    trust_text: str | None = None,
) -> None:
    """Samba PAC L3/realtrust respawn task[kdc] workers; UDP :88 stays bound."""
    if cross_text is None:
        path = SCRIPTS / "samba-crossrealm-gate.sh"
        if not path.is_file():
            _die("missing scripts/samba-crossrealm-gate.sh")
        cross_text = path.read_text(encoding="utf-8")
    if trust_text is None:
        path = SCRIPTS / "samba-realtrust-gate.sh"
        if not path.is_file():
            _die("missing scripts/samba-realtrust-gate.sh")
        trust_text = path.read_text(encoding="utf-8")
    for name, text in (
        ("samba-crossrealm-gate.sh", cross_text),
        ("samba-realtrust-gate.sh", trust_text),
    ):
        if "samba_kdc_respawn_in" not in text:
            _die(f"{name} must call samba_kdc_respawn_in after task[kdc] kill")
        if _SAMBA_GONE_88.search(text):
            _die(f"{name} must not wait_gone_in :88 (Samba keeps the port)")
        if "rebind :88" in text:
            _die(f"{name} Samba die must not say rebind :88 (UDP 88 stays bound)")


def check_red_at_sha_inject(text: str | None = None) -> None:
    """K12: --inject copies named HEAD files before write-tree."""
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text()
    if "--inject" not in text:
        _die("red-at-sha.sh must support --inject")
    if 'cp "$ROOT/$rel" "$WT/$rel"' not in text:
        _die("red-at-sha.sh --inject must copy HEAD files into the worktree")
    write = -1
    cp = -1
    offset = 0
    for line in text.splitlines(True):
        code = line.split("#", 1)[0]
        if write < 0 and "write-tree" in code:
            write = offset
        if cp < 0 and 'cp "$ROOT/$rel" "$WT/$rel"' in code:
            cp = offset
        offset += len(line)
    if write < 0 or cp < 0 or cp > write:
        _die("red-at-sha.sh must copy --inject files before write-tree")
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "0d58023^{commit}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    inj = "crates/krb5-types/tests/parse_name_deltat.rs"
    if probe.returncode != 0 or not (ROOT / inj).is_file():
        # R2-T3: a shallow CI checkout (fetch-depth 1) cannot see the historical
        # base, so the probe cannot run. Say so loudly rather than pass silently.
        print(
            "ci-policy: SKIP red-at-sha overlay-probe: base 0d58023 not fetched "
            "(shallow clone?) or fixture missing — set fetch-depth: 0",
            file=sys.stderr,
        )
        return
    scratch = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    env["KERBER_SCRATCH"] = str(scratch)
    try:
        r = subprocess.run(
            [
                "bash",
                str(SCRIPTS / "red-at-sha.sh"),
                "--overlay-probe",
                "--inject",
                inj,
                "--",
                "0d58023",
                inj,
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=False,
            text=True,
        )
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0:
            _die(f"red-at-sha --inject overlay-probe failed: {out[-500:]}")
        if "--inject" not in out:
            _die("red-at-sha --inject overlay-probe log missing --inject")
        if "overlay_match=yes" not in out:
            _die("red-at-sha --inject did not land HEAD file in write-tree")
        if "tree_sha=" not in out:
            _die("red-at-sha --inject overlay-probe missing tree_sha=")
    finally:
        subprocess.run(["rm", "-rf", str(scratch)], check=False)


def _claim_audit_module():
    spec = importlib.util.spec_from_file_location("claim_audit", SCRIPTS / "claim-audit.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/claim-audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scratch_root() -> pathlib.Path:
    base = pathlib.Path(os.environ.get("KERBER_SCRATCH") or ROOT / "target" / "ci-policy")
    base.mkdir(parents=True, exist_ok=True)
    return base


def check_index_check_scratch() -> None:
    """W1-Z Z3.2: index-check.py skips any `scratch*` component (`scratch/`,
    `scratch-pre/`, `scratch-diffsend2/`), flags an unnamed real file, and
    accepts a directory name as cover for the files under it."""
    spec = importlib.util.spec_from_file_location("index_check", SCRIPTS / "index-check.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/index-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (root / "INDEX.md").write_text("| `a.log` | named |\n| `sub/` | covered |\n")
        (root / "a.log").write_text("x")
        (root / "b.log").write_text("x")
        (root / "sub").mkdir()
        (root / "sub" / "c.log").write_text("x")
        for scratch in ("scratch", "scratch-pre", "scratch-diffsend2", "sub/scratch-red"):
            (root / scratch).mkdir()
            (root / scratch / "dump.jsonl").write_text("x")
        files, unnamed = mod.check(root)
        if files != 3 or unnamed != ["b.log"]:
            _die(f"index-check must count 3 files and flag only b.log: files={files} unnamed={unnamed}")
        if not mod.is_scratch(("z1", "scratch-pre", "cdiff", "x.jsonl")):
            _die("index-check is_scratch must match a scratch-* component")
        if mod.is_scratch(("z1", "logs", "settle-kdc-1.log")):
            _die("index-check is_scratch must not match an ordinary path")
        (root / "scratch-notes.log").write_text("x")
        files, unnamed = mod.check(root)
        if files != 4 or unnamed != ["b.log", "scratch-notes.log"]:
            _die(f"index-check must judge directories, not file names, as scratch: {unnamed}")
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=False)


def check_claim_audit() -> None:
    """Round 3: claim-audit.py fails a non-asserting line, a log-only bullet and a grep settle."""
    mod = _claim_audit_module()
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (root / "scripts").mkdir()
        pad = 'echo "---- pad ----"\n' * 4
        (root / "scripts" / "fx-gate.sh").write_text(
            'NAME="rust"\nNAME_MIT="mit"\n'
            + pad
            + 'echo "==== value ===="  # MIT omits NULL\nOUT="$(docker exec "$NAME" true)"\n'
            + "echo \"$OUT\" | grep -F 'value=1'\n"
            + pad
            + 'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            + "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
            + pad
            + 'echo "value=1 printed only"\n'
        )
        ev = root / "logs"
        ev.mkdir()
        stamp = "head_sha=0\ntree_sha=0\n"
        (ev / "good.log").write_text(stamp + "value=1\n")
        (ev / "settle-live.log").write_text(stamp + "dirty=no\n==== settle live ====\ncmd=docker exec x kinit user\nvalue=1\n")
        (ev / "settle-grep.log").write_text(stamp + "dirty=no\n==== settle grep ====\ncmd=grep -F value=1 /tmp/x.log\nvalue=1\n")
        (ev / "settle-run.log").write_text(stamp + "dirty=no\n==== settle run ====\ncmd=scripts/fx-gate.sh\nvalue=1\n")
        (ev / "settle-nobanner.log").write_text(stamp + "dirty=no\ncmd=docker exec x kinit user\nvalue=1\n")
        (ev / "settle-commit.log").write_text(stamp + "dirty=no\n==== settle commit ====\ncmd=docker exec c sh -c\ncommit value=1\n")
        (ev / "settle-dirty.log").write_text(
            stamp + "dirty=yes\n==== settle dirty ====\ncmd=docker exec x kinit user\nvalue=1\n"
        )
        (ev / "settle-override.log").write_text(
            stamp
            + "dirty=yes\noverride=KERBER_SETTLE_ALLOW_DIRTY\n==== settle ov ====\n"
            + "cmd=docker exec x kinit user\nvalue=1\n"
        )
        (ev / "unit-red.log").write_text(
            stamp + "dirty=yes\nred-at-parent=1\n==== unit_red_at ====\nvalue=1\n"
        )
        (root / "scripts" / "fx-policy.py").write_text(
            "def check():\n    if bad:\n        _die('value=1 wrong')\n\n\ndef _self_test():\n    _must_die(check, 'value=1')\n"
        )
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"

        def rows(bullet: str):
            return mod.audit_text(head + bullet, root, ev)

        def must_fail(bullet: str, why: str) -> None:
            bad = [r for r in rows(bullet) if r[1] != "ok"]
            if not bad:
                _die(f"claim-audit passed a bullet that {why}")

        good = "- **Both legs:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; live `good.log`.\n"
        if any(r[1] != "ok" for r in rows(good)):
            _die(f"claim-audit failed a valid bullet: {rows(good)}")
        must_fail(
            "- **Echo only:** `value=1` at `scripts/fx-gate.sh:20` / `:15`.\n",
            "names a non-asserting line",
        )
        must_fail("- **Log only:** `value=1` in `good.log`.\n", "names only a log")
        must_fail(
            "- **Grep settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-grep.log`.\n",
            "names a grep settle",
        )
        must_fail(
            "- **One leg:** `value=1` at `scripts/fx-gate.sh:9`.\n",
            "names a cell on one leg only",
        )
        must_fail(
            "- **Far window:** `value=1` at `scripts/fx-gate.sh:12` / `:15`.\n",
            "a reference three lines from an assertion",
        )
        live = "- **Live settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-live.log`.\n"
        if any(r[1] != "ok" for r in rows(live)):
            _die(f"claim-audit refused an oracle settle as the MIT leg: {rows(live)}")
        must_fail(
            "- **Dirty settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-dirty.log`.\n",
            "takes a dirty=yes oracle without a parent-red label",
        )
        must_fail(
            "- **Override settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-override.log`.\n",
            "takes an override= oracle without a parent-red label",
        )
        parent_red = (
            "- **Red at parent:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; Red at parent `unit-red.log`.\n"
        )
        if any(r[1] != "ok" for r in rows(parent_red)):
            _die(f"claim-audit refused a labelled parent-red dirty artefact: {rows(parent_red)}")
        must_fail(
            "- **Red at parent + dirty settle:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; "
            "Red at parent; `settle-dirty.log`.\n",
            "lets a parent-red label excuse a dirty settle",
        )
        must_fail(
            "- **Gate-run settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-run.log`.\n",
            "takes a Rust-side gate run as the MIT leg",
        )
        must_fail(
            "- **No-banner settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-nobanner.log`.\n",
            "takes a settle without the settle.sh banner",
        )
        must_fail(
            "- **Commit-not-oracle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-commit.log`.\n",
            "matches 'commit' as an oracle word",
        )
        must_fail(
            "- **Tooling without fixture:** `value=1` at `scripts/fx-policy.py:3`.\n",
            "names a tooling die site without its fixture",
        )
        tooling = "- **Tooling with fixture:** `value=1` at `scripts/fx-policy.py:3` / `:7`.\n"
        if any(r[1] != "ok" for r in rows(tooling)):
            _die(f"claim-audit refused a tooling claim with its fixture: {rows(tooling)}")
        # A fixture that asserts the die message counts, by that exact name.
        (root / "scripts" / "fx-msg-policy.py").write_text(
            "def check():\n    if bad:\n        _die('value=1 wrong')\n\n\n"
            "def _self_test():\n    _must_die_msg('value=1 wrong', check)\n"
        )
        msg_tooling = "- **Message fixture:** `value=1` at `scripts/fx-msg-policy.py:3` / `:7`.\n"
        if any(r[1] != "ok" for r in rows(msg_tooling)):
            _die(f"claim-audit refused a tooling claim with its _must_die_msg fixture: {rows(msg_tooling)}")
        no_fixture = "- **Message tooling alone:** `value=1` at `scripts/fx-msg-policy.py:3`.\n"
        if not any("tooling claim names no fixture line" in r[2] for r in rows(no_fixture)):
            _die(f"claim-audit must fail a tooling claim with no fixture call in its window: {rows(no_fixture)}")
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=False)


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


def _must_die_msg(needle: str, fn, *args, **kwargs) -> None:
    buf = io.StringIO()
    err = sys.stderr
    sys.stderr = buf
    try:
        fn(*args, **kwargs)
        died = False
    except SystemExit:
        died = True
    finally:
        sys.stderr = err
    text = buf.getvalue()
    name = getattr(fn, "__name__", "callable")
    if not died:
        raise AssertionError(f"{name} must fail closed")
    if needle not in text:
        raise AssertionError(f"{name} died without {needle!r}: {text!r}")


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
    mixed = 'if X; then\n    exit 1\nelif Y; then\n    echo only\nfi\n'
    if not informational_if_starts(mixed):
        raise AssertionError("mixed exit/echo chain must be a violation")
    echo_else_exit = 'if true; then\n    echo only\nelse\n    exit 0\nfi\n'
    if not informational_if_starts(echo_else_exit):
        raise AssertionError("echo then else exit must be a violation")
    multi = 'if [ "$a" = 1 ] ||\n   [ "$b" = 2 ]; then\n    echo hi\nfi\n'
    if not informational_if_starts(multi):
        raise AssertionError("multi-line condition echo-only must be a violation")
    helper_snip = 'if ! wait_ready; then\n    echo skip\nfi\n'
    if not informational_if_starts(helper_snip):
        raise AssertionError("helper-file echo-only snippet must be a violation")
    ok_mixed_no_echo = 'if X; then\n    exit 1\nelif Y; then\n    exit 2\nfi\n'
    if informational_if_starts(ok_mixed_no_echo):
        raise AssertionError("exit/exit chain must pass")
    oneliner_elif = (
        'if X; then exit 1; elif Y; then echo hi; elif Z; then exit 2; fi\n'
    )
    if informational_if_starts(oneliner_elif) != [1]:
        raise AssertionError("one-line ≥2-elif middle echo must be a hit")
    tee_echo = 'if true; then\n    echo skip | tee /tmp/x\nfi\n'
    if not informational_if_starts(tee_echo):
        raise AssertionError("echo | tee without assert must be a violation")
    redir_echo = 'if true; then\n    echo skip > /tmp/x\nfi\n'
    if not informational_if_starts(redir_echo):
        raise AssertionError("echo > file without assert must be a violation")
    assign_echo = 'if true; then\n    n=1\n    echo skip\nfi\n'
    if not informational_if_starts(assign_echo):
        raise AssertionError("assignment must not excuse echo-only")
    brace_echo = 'if true; then\n    { echo x; } > /tmp/x\nfi\n'
    if not informational_if_starts(brace_echo):
        raise AssertionError("{ echo; } redirect must be a violation")
    subshell_echo = 'if true; then\n    ( echo x ) > /tmp/x\nfi\n'
    if not informational_if_starts(subshell_echo):
        raise AssertionError("( echo ) redirect must be a violation")
    heredoc = 'if true; then\n    cat <<EOF > /tmp/x\nhi\nEOF\nfi\n'
    if not informational_if_starts(heredoc):
        raise AssertionError("heredoc arm must be a violation")
    cmp_ok = 'if true; then\n    cmp -s a b\nfi\n'
    if informational_if_starts(cmp_ok):
        raise AssertionError("cmp arm must assert")
    test_ok = 'if true; then\n    [ "$x" = 1 ]\nfi\n'
    if informational_if_starts(test_ok):
        raise AssertionError("[ ] arm must assert")
    unavail_ok = 'if true; then\n    unavailable "x"\nfi\n'
    if informational_if_starts(unavail_ok):
        raise AssertionError("unavailable arm must assert")
    for i, snippet in enumerate(
        (
            'if true; then\n    y=$( grep foo bar )\n    echo skip\nfi\n',
            'if true; then\n    echo see grep output\nfi\n',
            'if true; then\n    echo skip > test.log\nfi\n',
            'if true; then\n    echo run test suite\nfi\n',
            'if true; then\n    echo tcpdump unavailable\nfi\n',
            'if true; then\n    echo will exit later\nfi\n',
            'if true; then\n    ( exit 1 ) || true\n    echo skip\nfi\n',
            'if true; then\n    echo skip | grep -q skip\nfi\n',
            'if true; then\n    echo skip\n    test -n "x"\nfi\n',
            'if true; then\n    echo skip\n    cmp -s /dev/null /dev/null\nfi\n',
            'if true; then\n    echo skip | tee /tmp/x\n    [ -s /tmp/x ]\nfi\n',
        )
    ):
        if not informational_if_starts(snippet):
            raise AssertionError(f"counter-example {i} must be informational")
    for i, snippet in enumerate(
        (
            'if true; then\n    grep -q x f || { echo skip; }\nfi\n',
            'if true; then\n    grep -q x f || :\nfi\n',
            'if true; then\n    echo skip > "$OUT/x.log"\n    grep -q skip "$OUT/x.log"\nfi\n',
            'if true; then\n    /bin/echo skip\nfi\n',
            'if true; then\n    log_info "skipping"\nfi\n',
            'if true; then\n    [ -n "$x" ] && echo skip\nfi\n',
            'case "$x" in\n    *) echo skip ;;\nesac\n',
            'case "$x" in\n    a)\n        echo skip\n        ;;\n    *) die x ;;\nesac\n',
        )
    ):
        if not informational_if_starts(snippet):
            raise AssertionError(f"round-2 counter-example {i} must be informational")
    for i, snippet in enumerate(
        (
            'if true; then\n    grep -q x f || die x\nfi\n',
            'if true; then\n    [ -n "$x" ] && exit 1\nfi\n',
            'if true; then\n    docker exec c true > "$OUT/x.log"\n    grep -q ok "$OUT/x.log"\nfi\n',
            'if true; then\n    grep -q x f || { log "g" "error" x; exit 1; }\nfi\n',
            'case "$x" in\n    *) die x ;;\nesac\n',
        )
    ):
        if informational_if_starts(snippet):
            raise AssertionError(f"round-2 positive control {i} must assert")
    skip_scoped = (
        'if [ "${KERBER_REQUIRE_NETEM:-0}" = 1 ]; then\n'
        '    die "required"\n'
        "fi\n"
        "if true; then\n"
        '    log "g" "skip" "foo missing"\n'
        "fi\n"
    )
    if not informational_if_starts(skip_scoped):
        raise AssertionError("a skip that names no enforced requirement must be informational")
    skip_require = (
        'if [ "${KERBER_REQUIRE_NETEM:-0}" = 1 ]; then\n'
        '    die "required"\n'
        "fi\n"
        "if true; then\n"
        '    log "g" "skip" "netem"\n'
        "    echo hi\n"
        "fi\n"
    )
    if informational_if_starts(skip_require):
        raise AssertionError("log skip with REQUIRE die must pass")
    skip_bare = 'if true; then\n    log "g" "skip" "netem"\n    echo hi\nfi\n'
    if not informational_if_starts(skip_bare):
        raise AssertionError("log skip without REQUIRE die must be informational")

    class _Alarm(Exception):
        pass

    def _on_alarm(_signum, _frame) -> None:
        raise _Alarm

    three_or = (
        'if [ "$a" = 1 ] ||\n'
        '   [ "$b" = 2 ] ||\n'
        '   [ "$c" = 3 ]; then\n'
        " echo hi\n"
        "fi\n"
    )
    old = signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(5)
    try:
        three_hits = informational_if_starts(three_or)
    except _Alarm as exc:
        raise AssertionError("3-way || join hung") from exc
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    if three_hits != [1]:
        raise AssertionError(f"3-way || must be [1], got {three_hits}")
    joined = _join_shell_continuations("a &&\nb &&\nc\n")
    if "a && b && c" not in joined.replace("\n", " "):
        raise AssertionError(f"3-way && join failed: {joined!r}")

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
    doc_tests = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace --doc\n",
    )
    check_ci_no_workspace_cargo_test(doc_tests)
    doc_then_unit = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace --doc && cargo test --workspace\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, doc_then_unit)
    docs_word = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace --docs\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, docs_word)

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
    ledger_proposed_sibling = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | proposed: diffsend `no-such-case`; kdc-lookaside-gate.sh |\n"
    )
    _must_die(check_ledger_proof_column, ledger_proposed_sibling)
    cases_hdr = (
        "The thirty-three live `diffsend` cases are "
        + ", ".join(f"`{c}`" for c in sorted(DIFFSEND_CASES))
        + ".\n"
    )
    gate_n = (
        f"DIFFSEND_RATCHET={len(DIFFSEND_CASES)}\n"
        "CASES_SEEN=\"$(grep -o '\"case\":\"[^\"]*\",\"outcome\":\"ok\"' <<<\"$DIFF\" | sort -u | wc -l)\"\n"
        '[ "$CASES_SEEN" = "$DIFFSEND_RATCHET" ] || die "x"\n'
        + "".join(f"grep -q '\"case\":\"{c}\"' <<<\"$DIFF\" || die x\n" for c in sorted(DIFFSEND_CASES))
    )
    src_n = (
        "".join(f'expect_error(&cfg, "{c}", &req, 1)?;\n' for c in sorted(DIFFSEND_CASES))
        + f'println!(r#"{{{{"event":"diffsend","outcome":"ok","cases":{len(DIFFSEND_CASES)}}}}}"#);\n'
    )
    check_diffsend_cases(cases_hdr, gate_n, src_n)
    _must_die(check_diffsend_cases, "no header here", gate_n, src_n)
    _must_die(check_diffsend_cases, cases_hdr, 'echo "no cases pin"\n', src_n)
    gate_short = gate_n.replace(f"DIFFSEND_RATCHET={len(DIFFSEND_CASES)}", "DIFFSEND_RATCHET=29")
    _must_die(check_diffsend_cases, cases_hdr, gate_short, src_n)
    # Z3.3: the gate must count, not trust the literal; must grep every case;
    # the driver's names and its summary literal must match the ratchet.
    _must_die(check_diffsend_cases, cases_hdr, gate_n.replace("$CASES_SEEN", "$X"), src_n)
    _must_die(
        check_diffsend_cases, cases_hdr, gate_n.replace('"case":"garbage-pdu"', '"case":"gone"'), src_n
    )
    _must_die(check_diffsend_cases, cases_hdr, gate_n, src_n + 'expect_drop(&cfg, "stray-case", &req)?;\n')
    _must_die(
        check_diffsend_cases,
        cases_hdr,
        gate_n,
        src_n.replace(f'"cases":{len(DIFFSEND_CASES)}', '"cases":7'),
    )

    with tempfile.TemporaryDirectory() as tmp:
        troot = pathlib.Path(tmp)
        testdir = troot / "crates" / "demo" / "tests"
        testdir.mkdir(parents=True)
        (testdir / "twin.rs").write_text(
            "#[test]\n// oracle: differential-gate.sh unknown-sname\n"
            "fn as_unknown_sname_is_server_not_found() {}\n",
            encoding="utf-8",
        )
        gui = _gate_unit_index()
        cell_gate = (
            'grep -q \'"case":"unknown-sname","outcome":"ok","error_code":7,'
            '"e_text":"SERVER_NOT_FOUND"\' <<<"$DIFF"\n'
        )
        good_doc = gui.verify(troot, cell_gate, None)
        check_gate_unit_index(troot, cell_gate, good_doc)
        _must_die(check_gate_unit_index, troot, cell_gate, good_doc + "stale\n")
        _must_die(check_gate_unit_index, troot, cell_gate.replace("unknown-sname", "other-case"), good_doc)
        (testdir / "twin.rs").write_text(
            "#[test]\nfn other() {}\n"
            "// oracle: differential-gate.sh unknown-sname\n"
            "fn as_unknown_sname_is_server_not_found() {}\n",
            encoding="utf-8",
        )
        _must_die(check_gate_unit_index, troot, cell_gate, good_doc)
        (testdir / "twin.rs").write_text(
            "#[test]\nfn as_unknown_sname_is_server_not_found() {}\n",
            encoding="utf-8",
        )
        _must_die(check_gate_unit_index, troot, cell_gate, good_doc)

    check_doc_file_cites({"docs/testing.md": "see `crates/krb5-kdc/src/lib.rs`\n"}, ROOT)
    _must_die(
        check_doc_file_cites,
        {"docs/testing.md": "see `crates/krb5-kdc/tests/ad_pac.rs`\n"},
        ROOT,
    )
    # The S5 doc checks on a temp tree: links and anchors, recursive cites, the CHANGELOG
    # headings, the size limits, and docs/gates.md against the scripts and workflows.
    droot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (droot / "docs" / "sub").mkdir(parents=True)
        (droot / "docs" / "a.md").write_text("# A\n\n## Setup — first\n\n## Setup — first\n", encoding="utf-8")
        readme = droot / "README.md"
        readme.write_text(
            "See [a](docs/a.md), [setup](docs/a.md#setup--first), [again](docs/a.md#setup--first-1),\n"
            "[site](https://example.org/x) and `[code](nowhere.md)`.\n\n```\n[fenced](nowhere.md)\n```\n",
            encoding="utf-8",
        )
        if doc_link_violations(droot):
            _die(f"check_doc_links must accept files, slugs, repeats, URLs and code: {doc_link_violations(droot)}")
        readme.write_text("See [gone](docs/gone.md).\n", encoding="utf-8")
        _must_die_msg("docs/gone.md (no such file)", check_doc_links, droot)
        readme.write_text("See [bad](docs/a.md#setup).\n", encoding="utf-8")
        _must_die_msg("docs/a.md#setup (no such anchor)", check_doc_links, droot)
        readme.write_text("See [a](docs/a.md).\n", encoding="utf-8")
        (droot / "docs" / "sub" / "deep.md").write_text("see `docs/missing.md`\n", encoding="utf-8")
        _must_die_msg("docs/sub/deep.md: `docs/missing.md`", check_doc_file_cites, None, droot)
        (droot / "docs" / "sub" / "deep.md").write_text("see `docs/a.md`\n", encoding="utf-8")
        (droot / "CONTRIBUTING.md").write_text("see `scripts/none.sh`\n", encoding="utf-8")
        _must_die_msg("CONTRIBUTING.md: `scripts/none.sh`", check_doc_file_cites, None, droot)
        (droot / "CONTRIBUTING.md").write_text("see `docs/a.md`\n", encoding="utf-8")
        check_doc_file_cites(None, droot)
        log = "## [Unreleased]\n\n### Added\n\n### Tests and CI\n\n### How to add an entry\n\n### W3-S4 comments\n"
        check_changelog_headings(log, allow=1)
        _must_die_msg("1 ### headings outside", check_changelog_headings, log, allow=0)
        check_changelog_headings(log.replace("### W3-S4 comments\n", ""), allow=0)
        (droot / "docs" / "big.md").write_text("x" * (DOCS_SIZE_LIMIT + 1), encoding="utf-8")
        check_docs_size(droot, allow=1, changelog_max=10)
        _must_die_msg("1 docs file(s) over", check_docs_size, droot, allow=0, changelog_max=10)
        (droot / "docs" / "big.md").unlink()
        (droot / "CHANGELOG.md").write_text("y" * 11, encoding="utf-8")
        _must_die_msg("over its ceiling 10", check_docs_size, droot, allow=0, changelog_max=10)
        check_docs_size(droot, allow=0, changelog_max=11)
    finally:
        subprocess.run(["rm", "-rf", str(droot)], check=False)
    gates = ["a-gate.sh", "b-gate.sh", "s-gate.sh", "w-gate.sh"]
    places = {
        "a-gate.sh": [("ci:harness", "fail-red")],
        "b-gate.sh": [("ci:soak", "soft"), ("soak:soak", "nightly")],
    }
    stubs_fx = frozenset({"s-gate.sh", "w-gate.sh"})
    head = "| Gate | Oracle | Workflow | Lane | Asserts |\n| --- | --- | --- | --- | --- |\n"
    rows_ok = {
        "a": "| `scripts/a-gate.sh` | MIT | `ci:harness` | fail-red | the wire code |\n",
        "b": "| `scripts/b-gate.sh` | none | `ci:soak`, `soak:soak` | soft, nightly | no leak |\n",
        "s": "| `scripts/s-gate.sh` | Windows | stub | — | exits 2 |\n",
        "w": "| `scripts/w-gate.sh` | MIT | stub | — | runs a and b |\n",
    }
    good_doc = head + "".join(rows_ok.values())
    got = gate_doc_violations(good_doc, gates, places, stubs_fx)
    if got:
        _die(f"check_gate_documented must accept a true table: {got}")
    for label, doc, needle in (
        ("missing row", head + rows_ok["a"] + rows_ok["b"] + rows_ok["s"], "w-gate.sh: no row"),
        ("two rows", good_doc + rows_ok["a"], "a-gate.sh: two rows"),
        ("wrong workflow", good_doc.replace("`ci:harness` | fail-red", "`ci:harness-2` | fail-red"), "a-gate.sh: workflow"),
        ("wrong lane", good_doc.replace("soft, nightly", "fail-red"), "b-gate.sh: lane"),
        ("bad oracle", good_doc.replace("| MIT | `ci:harness`", "| Kerberos | `ci:harness`"), "a-gate.sh: oracle"),
        ("empty asserts", good_doc.replace("the wire code", " "), "a-gate.sh: empty assertion"),
        ("unknown gate", good_doc + "| `scripts/z-gate.sh` | MIT | stub | — | x |\n", "z-gate.sh: row for a gate"),
        ("cell count", good_doc.replace("| exits 2 |", "|"), "s-gate.sh: 4 cells"),
    ):
        if not any(needle in v for v in gate_doc_violations(doc, gates, places, stubs_fx)):
            _die(f"check_gate_documented must flag {label}")
    if gate_placements()["kdc-gate.sh"] != [("ci:harness", "fail-red")]:
        _die(f"gate_placements must read kdc-gate.sh as ci:harness fail-red: {gate_placements()['kdc-gate.sh']}")

    check_capture_env_only(
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"kdc-gate.sh": "KERBER_CAPTURE_DIR=/tmp/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_SCRATCH");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "log() {\n    :\n}\n",
        {},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"kdc-gate.sh": "KERBER_CAPTURE_DIR=$ROOT/tests/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"ci.yml": "KERBER_CAPTURE_DIR: $ROOT/tests/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var_os("KERBER_SCRATCH");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {},
    )
    check_capture_env_only(
        'pub fn capture_pdu() {\n    let _ = std::env::var_os("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"kdc-gate.sh": "KERBER_CAPTURE_DIR=/tmp/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"harness/prod/env-up.sh": "refuse_golden_capture_dir() {\n    :\n}\n"},
    )
    check_doc_file_cites({"CHANGELOG.md": "see `crates/missing/nope.rs`\n"}, ROOT)

    def _princ_line(name: str, *keyhexes: str) -> str:
        namelen = str(len(name))
        parts = [
            "princ",
            "38",
            namelen,
            "0",
            str(len(keyhexes)),
            "0",
            name,
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
        ]
        for keyhex in keyhexes:
            klen = str(len(keyhex) // 2)
            parts.extend(["1", "1", "17", klen, keyhex])
        parts.append("-1")
        return "\t".join(parts) + "\n"

    dump_unique = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "ba", "bb", "bc", "bd")
        + _princ_line("hwuser@KERBER.TEST", "ca", "cb", "cc", "cd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    check_golden_dump_unique_keys(dump_unique)
    dump_clone_user = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("hwuser@KERBER.TEST", "ca", "cb", "cc", "cd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    _must_die(check_golden_dump_unique_keys, dump_clone_user)
    dump_clone_hw = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "ba", "bb", "bc", "bd")
        + _princ_line("hwuser@KERBER.TEST", "da", "db", "dc", "dd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    _must_die(check_golden_dump_unique_keys, dump_clone_hw)
    dump_missing = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa")
        + _princ_line("nosvr@KERBER.TEST", "ba")
    )
    _must_die(check_golden_dump_unique_keys, dump_missing)
    ledger_tally_ok = (
        "Counts:\n"
        "**1** = A1 1 + A2 0 + A3 0.\n"
        "exact 1 · stricter-documented 0 · deviation 0 ·\n"
        "absent 0 · deferred 0.\n"
        "## A1 — tgs\n"
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
        "## A2 — as\n"
        "## A3 — fast\n"
    )
    check_ledger_tally(ledger_tally_ok)
    ledger_tally_bad = ledger_tally_ok.replace(
        "exact 1 · stricter-documented 0 · deviation 0 ·",
        "exact 49 · stricter-documented 0 · deviation 95 ·",
    )
    _must_die(check_ledger_tally, ledger_tally_bad)
    ledger_tally_no_total = (
        "Counts:\n"
        "exact 1 · stricter-documented 0 · deviation 0 ·\n"
        "absent 0 · deferred 0.\n"
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
    )
    _must_die(check_ledger_tally, ledger_tally_no_total)
    ledger_tally_ok_sections = (
        "Counts:\n"
        "**1** = A1 1 + A2 0 + A3 0.\n"
        "exact 1 · stricter-documented 0 · deviation 0 ·\n"
        "absent 0 · deferred 0.\n"
        "## A1 — tgs\n"
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
        "## A2 — as\n"
        "## A3 — fast\n"
    )
    check_ledger_tally(ledger_tally_ok_sections)
    ledger_tally_wrong_split = ledger_tally_ok_sections.replace(
        "**1** = A1 1 + A2 0 + A3 0.",
        "**1** = A1 0 + A2 1 + A3 0.",
    )
    _must_die(check_ledger_tally, ledger_tally_wrong_split)
    # The ledger in either layout: one file, or docs/parity/ with a README header and one file
    # per section keyed by its name. A row's identity is its MIT cite and check cells.
    lroot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (lroot / "docs").mkdir()
        single = lroot / "docs" / "mit-parity-ledger.md"
        single.write_text(ledger_tally_ok_sections, encoding="utf-8")
        check_ledger_layout(lroot)
        check_ledger_tally(root=lroot)
        table = (
            "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
        )
        row_a1 = "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
        row_b1 = "| gic_pwd.c:2 | v | y | z | w | deviation | proposed |\n"
        head = (
            "Counts:\n**2** = A1 1 + A2 0 + A3 0 + A4 0 + A5 0 + B1 1.\n"
            "exact 1 · stricter-documented 0 · deviation 1 ·\nabsent 0 · deferred 0.\n"
        )
        parity = lroot / "docs" / "parity"
        parity.mkdir()
        (parity / "a1-tgs.md").write_text("# A1 — tgs\n\n" + table + row_a1, encoding="utf-8")
        (parity / "b1-client.md").write_text("# B1 — client\n\n" + table + row_b1, encoding="utf-8")
        _must_die_msg("but no README.md", ledger_sources, lroot)
        (parity / "README.md").write_text(head, encoding="utf-8")
        _must_die_msg("still holds rows beside docs/parity/", ledger_sources, lroot)
        single.write_text("The ledger is under docs/parity/.\n", encoding="utf-8")
        check_ledger_layout(lroot)
        check_ledger_tally(root=lroot)
        if [k for _n, _t, k in ledger_sources(lroot)] != [None, "A1", "B1"]:
            _die("ledger_sources must read the README, then the section files in order")
        (parity / "b1-client.md").write_text(
            "# B1 — client\n\n" + table + row_b1 + row_a1, encoding="utf-8"
        )
        _must_die_msg("repeats the ledger row at docs/parity/a1-tgs.md:5", check_ledger_layout, lroot)
        (parity / "b1-client.md").write_text("# B1 — client\n\n" + table + row_b1, encoding="utf-8")
        (parity / "a2-as.md").write_text("# A1 — as\n\n" + table, encoding="utf-8")
        _must_die_msg("does not name section A2", ledger_sources, lroot)
        (parity / "a2-as.md").unlink()
        (parity / "c1-other.md").write_text("# C1 — other\n\n" + table, encoding="utf-8")
        _must_die_msg("names no ledger section", ledger_sources, lroot)
        (parity / "c1-other.md").unlink()
        (parity / "README.md").write_text(head.replace("A1 1 + A2 0", "A1 0 + A2 1"), encoding="utf-8")
        _must_die_msg("section split", check_ledger_tally, None, lroot)
    finally:
        subprocess.run(["rm", "-rf", str(lroot)], check=False)
    def _row(site: str, etext: str = "—", verdict: str = "exact", proof: str = "none") -> str:
        return (
            "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
            f"| kdc_util.c:1 | x | y | {site} | {etext} | {verdict} | {proof} |\n"
        )

    unit = "`udp_oversize_reply_is_response_too_big`"

    check_ledger_anchors(_row("none", verdict="absent"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", proof=unit))
    check_ledger_anchors(_row("krb5-kdc/listen.rs MAX_TCP_REQUEST", proof="`kdc-gate.sh:1`"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", proof="`as-success`"))
    check_ledger_anchors(
        _row("krb5-kdc/status.rs NEEDED_PREAUTH", "`NEEDED_PREAUTH`")
    )
    check_ledger_anchors(
        _row("krb5-kdc/preauth.rs armor_key_from_ap", "`NOT_US` / `TKT_NYV`")
    )
    _must_die(check_ledger_anchors, _row("missing.rs no_such_fn", "`PROCESS_TGS`"))
    fake_mit = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (fake_mit / "kdc").mkdir()
        (fake_mit / "kdc" / "kdc_util.c").write_text('int x = KRB_ERR_RESPONSE_TOO_BIG;\nstatus = "CLIENT KEY EXPIRED";\n')
        mit_row = _row("krb5-kdc/listen.rs handle_tcp", proof=unit).replace("| x | y |", "| x | `KRB_ERR_RESPONSE_TOO_BIG` `CLIENT KEY EXPIRED` |")
        check_ledger_mit_cites(mit_row, fake_mit)
        check_ledger_mit_cites(mit_row.replace("KRB_ERR_RESPONSE_TOO_BIG", "RESPONSE_TOO_BIG"), fake_mit)
        _must_die(check_ledger_mit_cites, mit_row.replace("KRB_ERR_RESPONSE_TOO_BIG", "RESPONSE_TOO_BI"), fake_mit)
        _must_die(check_ledger_mit_cites, mit_row.replace("CLIENT KEY EXPIRED", "CLIENT KEY EXPIRE"), fake_mit)
        _must_die(check_ledger_mit_cites, mit_row.replace("kdc_util.c:1", "no_such.c:1"), fake_mit)
    finally:
        subprocess.run(["rm", "-rf", str(fake_mit)], check=False)
    _must_die(check_ledger_anchors, _row("krb5-kdc/plugins.rs advertise", verdict="absent"))
    # Several impls define advertise. Pin a line inside one of them rather
    # than a fixed number, so a module-header shift does not move the pin
    # out of the item.
    advertise_spans = _item_spans(ROOT / "crates/krb5-kdc/src/plugins.rs", "advertise")
    advertise_at = next(s[0] for s in advertise_spans if s[1] - s[0] > 5)
    check_ledger_anchors(
        _row(f"krb5-kdc/plugins.rs advertise:{advertise_at}", verdict="absent")
    )
    _must_die(check_ledger_anchors, _row("krb5-kdc/plugins.rs advertise:1", verdict="absent"))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp", "no status word"))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp", proof="`no_such_unit_anywhere`"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", "no status word", proof=unit))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp", "NOT_A_REAL_STATUS 60"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", "FIELD_TOOLONG 52"))
    _must_die(
        check_ledger_anchors,
        _row("krb5-kdc/listen.rs handle_tcp", "`TKT_NYV`").replace("| kdc_util.c:1 |", "| issue.rs:1 |"),
    )
    check_ledger_anchors(
        _row("krb5-kdc/listen.rs handle_tcp", "x", "absent").replace("| kdc_util.c:1 |", "| n/a (harness) |")
    )
    _must_die(check_ledger_anchors, _row("issue.rs no_such_fn_at_all"))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp:1"))
    _must_die(check_ledger_anchors, _row("listen.rs handle_tcp"))
    _must_die(check_ledger_anchors, _row("lib.rs propagate", verdict="deviation"))
    _must_die(check_ledger_anchors, _row("none"))
    _must_die(
        check_ledger_anchors,
        _row("krb5-kdc/listen.rs handle_tcp", "`TKT_NYV`"),
    )
    handle_span = _item_span(ROOT / "crates/krb5-kdc/src/listen.rs", "handle_tcp")
    if handle_span is None or not handle_span[2].startswith("fn handle_tcp(") or not handle_span[2].rstrip().endswith("}") or handle_span[1] - handle_span[0] < 20:
        raise AssertionError(f"handle_tcp must resolve to a brace-matched fn body, got {handle_span}")
    max_span = _item_span(ROOT / "crates/krb5-kdc/src/listen.rs", "MAX_TCP_REQUEST")
    if max_span is None:
        raise AssertionError("MAX_TCP_REQUEST const must resolve")
    # a `#[cfg(test)] mod` child that shares a basename with a product file
    # (`kadm5/tests/policy.rs` next to `kadm5/policy.rs`): the index keeps the
    # product file only; without the cfg(test) the twin is a duplicate
    fake_crates = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        a = fake_crates / "x" / "src" / "a"
        (a / "tests").mkdir(parents=True)
        (fake_crates / "x" / "src" / "lib.rs").write_text("mod a;\n")
        (fake_crates / "x" / "src" / "a.rs").write_text("mod policy;\n#[cfg(test)]\nmod tests;\n")
        (a / "policy.rs").write_text("pub(super) fn policy_mask_err() {}\n")
        (a / "tests" / "mod.rs").write_text("mod policy;\n")
        (a / "tests" / "policy.rs").write_text("#[test]\nfn t() {}\n")
        by_crate, by_base = _src_index(fake_crates)
        if by_crate["x"].get("policy.rs") != a / "policy.rs" or by_base.get("policy.rs") != ["x"]:
            raise AssertionError("src index must keep the product policy.rs and skip its cfg(test) twin")
        if "mod.rs" in by_crate["x"]:
            raise AssertionError("src index must skip a cfg(test) tests/mod.rs")
        (fake_crates / "x" / "src" / "a.rs").write_text("mod policy;\nmod tests;\n")
        _must_die(_src_index, fake_crates)
    finally:
        subprocess.run(["rm", "-rf", str(fake_crates)], check=False)
    not_ci = Workflow(
        pathlib.Path("not-ci.yml"),
        "name: x\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: echo hi\n",
    )
    check_ci(not_ci)
    check_ci_nextest_split(not_ci)
    check_ci_no_workspace_cargo_test(not_ci)

    # R2-T2: red fixtures for check_ci's rules and check_nightly. The not_ci
    # call above returns at the ci.yml name guard and exercised none of the
    # _die rules; these (named ci.yml to pass that guard) do.
    def _ci(body: str) -> Workflow:
        return Workflow(pathlib.Path("ci.yml"), body)

    _soft = (
        "jobs:\n  slo:\n    continue-on-error: true\n"
        "  chaos:\n    continue-on-error: true\n"
        "  soak:\n    continue-on-error: true\n"
    )
    _must_die(check_ci, _ci("on:\n  workflow_dispatch:\n" + _soft))  # not push/PR
    _must_die(
        check_ci,
        _ci("on:\n  push:\n  schedule:\n    - cron: '0 0 * * *'\n" + _soft),
    )  # scheduled
    _must_die(
        check_ci,
        _ci("on:\n  push:\n" + _soft + "  rogue:\n    continue-on-error: true\n"),
    )  # extra continue-on-error job
    _must_die(
        check_ci,
        _ci("on:\n  push:\njobs:\n  test:\n    timeout-minutes: 30\n"),
    )  # missing the soft jobs
    _must_die(check_ci, _ci("on:\n  push:\n" + _soft))  # missing timeout job 'test'
    _must_die(check_nightly, [])  # no scheduled workflow runs a nightly-blocking gate

    _ci_push = Workflow(
        pathlib.Path("ci.yml"),
        "on:\n  push:\njobs:\n  harness:\n    timeout-minutes: 20\n"
        "    steps:\n      - run: ./scripts/kadmin-rust-gate.sh\n",
    )
    check_gate_membership(
        [_ci_push],
        ("kadmin-rust-gate.sh",),
        frozenset(),
        ["kadmin-rust-gate.sh"],
    )
    _ci_soft = Workflow(
        pathlib.Path("ci.yml"),
        "on:\n  push:\njobs:\n  soak:\n    continue-on-error: true\n"
        "    steps:\n      - run: ./scripts/kadmin-rust-gate.sh\n",
    )
    _must_die(
        check_gate_membership,
        [_ci_soft],
        ("kadmin-rust-gate.sh",),
        frozenset(),
        ["kadmin-rust-gate.sh"],
    )
    _ci_no_kadmin = Workflow(
        pathlib.Path("ci.yml"),
        "on:\n  push:\njobs:\n  harness:\n    timeout-minutes: 20\n"
        "    steps:\n      - run: ./scripts/spake-gate.sh\n",
    )
    _nightly_kadmin = Workflow(
        pathlib.Path("peers.yml"),
        "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  peers:\n"
        "    steps:\n      - run: ./scripts/kadmin-rust-gate.sh\n",
    )
    _must_die(
        check_gate_membership,
        [_ci_no_kadmin, _nightly_kadmin],
        ("kadmin-rust-gate.sh",),
        frozenset(),
        ["kadmin-rust-gate.sh"],
    )

    check_gate_provenance('. "$ROOT/scripts/lib/provenance.sh"\n', "ok-gate.sh")
    _must_die(check_gate_provenance, "#!/bin/bash\necho hi\n", "no-prov-gate.sh")
    check_no_case_whitelists(
        'compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt)?;\n'
        'if echo "$DIFF" | grep -q \'"whitelist"\'; then die "banned"; fi\n',
        "ok-diffsend.rs",
    )
    _must_die(
        check_no_case_whitelists,
        "let wl = Whitelist::default();\n",
        "wl-diffsend.rs",
    )
    _must_die(
        check_no_case_whitelists,
        'println!("whitelist:{:?}", ok.whitelisted);\n',
        "field-diffsend.rs",
    )
    _must_die(
        check_no_case_whitelists,
        "for c in skip_cases; do :; done\n",
        "skip-gate.sh",
    )
    check_no_host_tmp_writes(
        'SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-x-gate}"\n'
        "docker exec n sh -c 'cat >/tmp/in-container'\n",
        "ok-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cc -o x x.c 2>/tmp/kadm5-cc.err\n",
        "kadmin-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cp x /tmp/foo\n",
        "cp-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "tee /tmp/out.log\n",
        "tee-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "echo $(cat >/tmp/x)\n",
        "subshell-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "python3 -c '\nprint(1)\n'\necho x > /tmp/after-multiline\n",
        "multiline-quote-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "docker exec n sh -c 'cat >/tmp/in <<EOF\nbody\nEOF'\necho x > /tmp/after-heredoc\n",
        "quoted-heredoc-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        None,
        "lib",
        {"lib/gate-common.sh": "echo x > /tmp/host-out\n"},
    )
    _must_die(
        check_no_host_tmp_writes,
        "docker exec n sh -c 'true' >/tmp/host-out\n",
        "docker-host-redir-tmp-gate.sh",
    )
    check_gate_cargo_leftover("need_bins krb5-kdc krb5-kvno\n", "ok-bins-gate.sh")
    _must_die(
        check_gate_cargo_leftover,
        "    -p krb5-client --bin krb5-kvno\n",
        "leftover-cargo-gate.sh",
    )
    check_gate_no_exit_trap("register_cleanup 'docker rm -f \"$NAME\"'\n", "ok-trap-gate.sh")
    _must_die(
        check_gate_no_exit_trap,
        "trap 'cleanup; mit_cleanup' EXIT\n",
        "exit-trap-gate.sh",
    )
    _four_boots = (
        "boot-stock-mit.sh\nboot-shell.sh\n"
        "boot-stock-mit.sh\nboot-shell.sh\n"
        "boot-stock-mit.sh\nboot-shell.sh\n"
        "boot-stock-mit.sh\nboot-shell.sh\n"
    )
    check_s4_shared_boots(_four_boots)
    _must_die(check_s4_shared_boots, "boot-shell.sh\nboot-shell.sh\n")
    check_stock_boots_per_job(_four_boots)
    _must_die(check_stock_boots_per_job, "boot-stock-mit.sh\n")
    check_gate_wall("# empty\n", "gate\trun\tgate_rc\twall_s\nkdc-gate\trun1\t0\t12\n")
    _must_die(check_gate_wall, "kadmin-gate\n", "gate\trun\tgate_rc\twall_s\n")
    _must_die(
        check_gate_wall,
        "# empty\n",
        "gate\trun\tgate_rc\twall_s\nkdc-gate\trun1\t2\t1\n",
    )
    _must_die(
        check_gate_wall,
        "# empty\n",
        "gate\trun\tgate_rc\twall_s\nkpasswd-gate\trun1\t0\t46\n",
    )
    ok_sleep = "sleep 2 # proto: ticket age\n"
    check_sleep_ratchet({"renew-gate.sh": ok_sleep}, unit_sleep_count=5)
    long_poll = "for _ in $(seq 1 200); do\nsleep 0.1\ndone\n"
    check_sleep_ratchet({"kdc-gate.sh": long_poll}, unit_sleep_count=5)
    check_sleep_classifiers_agree()
    _must_die(
        check_sleep_ratchet,
        {"pad-gate.sh": "sleep 3\n"},
        5,
    )
    _must_die(
        check_sleep_ratchet,
        {"pad-gate.sh": "sleep 3 # leftover\n"},
        5,
    )
    _must_die(
        check_sleep_ratchet,
        {"renew-gate.sh": "sleep 40 # proto: ticket age\n"},
        5,
    )
    _must_die(check_sleep_ratchet, {"renew-gate.sh": ok_sleep}, 15)
    good_toml = (
        "[jobs]\n"
        "test = 300\nharness = 270\nmit-extra = 180\ndoc = 90\n"
        "msrv = 120\naudit = 240\nledger-mit = 60\nmit-image = 90\n"
        "[push]\nrun_wall = 360\n"
    )
    check_ci_budgets(
        good_toml,
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        "[jobs]\ntest = 300\n[push]\nrun_wall = 540\n",
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        good_toml,
        "no check flag\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        good_toml,
        "--check-budget\nbudget_overruns\n",
        ["ci.yml"],
    )
    _must_die(
        check_ci_budgets,
        (
            "[jobs]\n"
            "test = 300\nharness = 500\nmit-extra = 180\ndoc = 90\n"
            "msrv = 120\naudit = 240\nledger-mit = 60\nmit-image = 90\n"
            "[push]\nrun_wall = 360\n"
        ),
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        good_toml,
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
        ["harness-2"],
    )
    check_need_bins_strict(
        "KERBER_NEED_BINS_STRICT: \"1\"\n",
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
        {
            "peers.yml": (
                'scripts/samba-ad-gate.sh\nbuild-bins.sh\n'
                'KERBER_NEED_BINS_STRICT: "1"\n'
            )
        },
    )
    _must_die(
        check_need_bins_strict,
        'KERBER_NEED_BINS_STRICT: "1"\n',
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
        {"peers.yml": "scripts/samba-ad-gate.sh\n"},
    )
    _must_die(
        check_need_bins_strict,
        'KERBER_NEED_BINS_STRICT: "1"\n',
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
        {"peers.yml": "scripts/samba-ad-gate.sh\nbuild-bins.sh\n"},
    )
    _must_die(
        check_need_bins_strict,
        "no strict env\n",
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
    )
    _must_die(
        check_need_bins_strict,
        "KERBER_NEED_BINS_STRICT: \"1\"\n",
        "no export\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
    )
    _must_die(
        check_need_bins_strict,
        "KERBER_NEED_BINS_STRICT: \"1\"\n",
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\n",
    )
    good_docs = (
        "Tier 1 test harness mit-extra msrv audit ledger-mit mit-image doc "
        "ci-budget.toml 270\nTier 2 slo chaos soak\nTier 3 budget.yml\n"
    )
    check_testing_doc_budgets(good_docs, "see ci-budget.toml tier rule\n", good_toml)
    _must_die(
        check_testing_doc_budgets,
        "no tiers here\n",
        "see ci-budget.toml\n",
        good_toml,
    )
    dst_ok = 'TRACE_DST="${KERBER_TRACE_DST:-${KERBER_SCRATCH}/traces}"\n'
    check_trace_dst({"kdc-gate.sh": dst_ok, "client-gate.sh": dst_ok})
    _must_die(
        check_trace_dst,
        {
            "kdc-gate.sh": 'TRACE_DST="${KERBER_TRACE_DST:-$ROOT/tests/traces}"\n',
            "client-gate.sh": dst_ok,
        },
    )
    prod_ok = (
        "jobs:\n"
        "  mit-image:\n"
        "    steps:\n"
        "      - run: docker build -f harness/prod/Dockerfile -t prod .\n"
        "        hashFiles('harness/prod/Dockerfile')\n"
    )
    check_prod_image_once(prod_ok)
    _must_die(
        check_prod_image_once,
        "jobs:\n  mit-image:\n    steps:\n      - run: echo no prod\n",
    )
    _must_die(
        check_prod_image_once,
        "docker build -f harness/prod/Dockerfile\n"
        "docker build -f harness/prod/Dockerfile\n"
        "jobs:\n  mit-image:\n    steps:\n      - run: harness/prod/Dockerfile\n"
        "hashFiles('harness/prod/Dockerfile')\n",
    )
    check_build_profile(
        'debug = "line-tables-only"\nsplit-debuginfo = "unpacked"\n',
        "fuse-ld=lld\n",
        "apt-get install -y lld\n",
    )
    _must_die(
        check_build_profile,
        "debug = 2\nsplit-debuginfo = \"unpacked\"\n",
        "fuse-ld=lld\n",
        "apt-get install -y lld\n",
    )
    cache_ok = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: Swatinem/rust-cache@v2\n"
        "        with:\n"
        "          shared-key: kerber\n"
        "      - run: cargo nextest run\n"
    )
    check_rust_cache_shared_key({"ci.yml": cache_ok})
    sha = "c" * 40
    sc_pin = f"    env:\n      SHELLCHECK_VERSION: v0.11.0\n      SHELLCHECK_SHA256: {'8' * 64}\n"
    hard_ci = (
        "name: ci\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: g\n  cancel-in-progress: true\n\n"
        f"on:\n  push:\njobs:\n  shellcheck:\n{sc_pin}    steps:\n"
        f"      - uses: actions/checkout@{sha} # v5.1.0\n"
        '      - run: echo "$SHELLCHECK_SHA256  $f" | sha256sum --check\n'
        f"      - run: {SHELLCHECK_CMD}\n"
    )
    hard_soak = "name: soak\n\npermissions:\n  contents: read\n\non:\n  schedule:\njobs:\n  soak:\n    steps:\n      - uses: ./.github/actions/rust-preamble\n"
    hard_action = {"rust-preamble/action.yml": f"runs:\n  steps:\n    - uses: Swatinem/rust-cache@{sha} # v2.9.2\n"}
    hard_bot = 'updates:\n  - package-ecosystem: "github-actions"\n  - package-ecosystem: "cargo"\n'
    hard_pins = {"Makefile": "koalaman/shellcheck:v0.11.0 -S style\n", "hygiene_inventory.py": 'SHELLCHECK_IMAGE = "koalaman/shellcheck:v0.11.0"\n'}
    check_workflow_hardening({"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak.replace("permissions:\n  contents: read\n\n", "")}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak.replace("on:", "concurrency:\n  cancel-in-progress: true\non:")}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace("concurrency:\n  group: g\n  cancel-in-progress: true\n\n", ""), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(f"@{sha} # v5.1.0", "@v5"), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(" # v5.1.0", ""), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, {"rust-preamble/action.yml": "runs:\n  steps:\n    - uses: Swatinem/rust-cache@v2\n"}, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, 'updates:\n  - package-ecosystem: "cargo"\n', "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(SHELLCHECK_CMD, "shellcheck scripts/*.sh"), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, hard_bot, "disable=SC2329\n", hard_pins)
    # The shellcheck job on the runner's package (no version pin), an unverified tarball, a stale fallback image.
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(sc_pin, ""), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace("sha256sum --check", "tar -xJf"), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", {**hard_pins, "Makefile": "koalaman/shellcheck:stable -S style\n"})
    cache_via_preamble = cache_ok.replace(
        "      - uses: Swatinem/rust-cache@v2\n        with:\n          shared-key: kerber\n",
        "      - uses: ./.github/actions/rust-preamble\n",
    )
    preamble_ok = "steps:\n  - uses: Swatinem/rust-cache@" + "b" * 40 + " # v2\n    with:\n      shared-key: kerber\n"
    check_rust_cache_shared_key({"ci.yml": cache_via_preamble}, preamble_ok)
    _must_die(check_rust_cache_shared_key, {"ci.yml": cache_via_preamble}, "steps:\n  - run: true\n")
    msrv_wf = (
        "jobs:\n"
        "  {job}:\n"
        "    env:\n"
        '      RUSTUP_TOOLCHAIN: "1.95"\n'
        "    steps:\n"
        "      - uses: dtolnay/rust-toolchain@1.95\n"
        "      - run: cargo build --workspace --locked\n"
    )
    msrv_ok = {
        "ci.yml": msrv_wf.format(job="msrv"),
        "full-test.yml": msrv_wf.format(job="msrv-test"),
    }
    manifest_ok = '[package]\nrust-version = "1.95"\n'
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "stable"\n', msrv_ok)
    sha_pinned = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: dtolnay/rust-toolchain@" + "a" * 40 + " # stable\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "stable"\n', {"ci.yml": sha_pinned, "full-test.yml": msrv_ok["full-test.yml"]})
    via_preamble = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: ./.github/actions/rust-preamble\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "stable"\n', {"ci.yml": via_preamble, "full-test.yml": msrv_ok["full-test.yml"]})
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": via_preamble.replace('          toolchain: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": sha_pinned.replace('          toolchain: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
    )
    _must_die(check_msrv_pinned, '[package]\nrust-version = "1.90"\n', manifest_ok, 'channel = "stable"\n', msrv_ok)
    _must_die(check_msrv_pinned, manifest_ok, "[package]\n", 'channel = "stable"\n', msrv_ok)
    _must_die(check_msrv_pinned, manifest_ok, manifest_ok, 'channel = "1.95.0"\n', msrv_ok)
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": msrv_wf.format(job="msrv").replace('      RUSTUP_TOOLCHAIN: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": msrv_ok["ci.yml"], "full-test.yml": msrv_ok["full-test.yml"].replace("@1.95", "@stable")},
    )
    _must_die(
        check_rust_cache_shared_key,
        {
            "ci.yml": (
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - run: cargo nextest run\n"
            )
        },
    )
    mf_ok = (
        "safety: fmt clippy test policy\n"
        "cargo fmt --all\n"
        "cargo clippy --workspace --all-targets --all-features\n"
        "cargo nextest run --workspace --profile ci\n"
        "python3 scripts/ci-policy.py\n"
        "cargo doc --workspace --no-deps\n"
    )
    ci_ok = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: cargo fmt --all\n"
        "      - run: cargo clippy --workspace --all-targets --all-features\n"
        "      - run: cargo nextest run --workspace --profile ci\n"
        "      - run: python3 scripts/ci-policy.py\n"
        "  doc:\n"
        "    steps:\n"
        "      - run: cargo doc --workspace --no-deps\n"
    )
    check_makefile_matches_ci(mf_ok, ci_ok)
    _must_die(
        check_makefile_matches_ci,
        "safety:\ncargo fmt --all\n",
        ci_ok,
    )
    _must_die(
        check_makefile_matches_ci,
        mf_ok,
        "jobs:\n  test:\n    steps:\n      - run: cargo fmt --all\n"
        "      - run: cargo clippy --workspace --all-targets --all-features\n"
        "      - run: cargo nextest run --workspace --profile ci\n"
        "      - run: python3 scripts/ci-policy.py\n"
        "      - run: cargo doc --workspace --no-deps\n"
        "  doc:\n    steps:\n      - run: cargo doc --workspace --no-deps\n",
    )
    check_env_read(
        {"ci.yml": "  env:\n    KERBER_READ: 1\n"},
        "KERBER_READ is used here\n",
    )
    _must_die(
        check_env_read,
        {"ci.yml": "  env:\n    KERBER_UNREAD_XYZ: 1\n"},
        "no reader for that name\n",
    )
    check_peers_unavailable_convention(
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
    )
    _must_die(
        check_peers_unavailable_convention,
        "echo no rc check\n",
        "run-peer-step.sh\n",
        "exit 1\n",
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ]\n',
        "no wrapper\n",
        "exit 1\n",
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ]\n',
        "run-peer-step.sh\n",
        'unavailable "kinit failed"\nexit 1\n',
    )
    check_peers_unavailable_convention(
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "peers.yml": (
                "scripts/samba-ad-gate.sh\nkerber-rust-mit-kdc.tar\n"
                "unavailable=\nfailed=\n"
            ),
            "kcm-opcode.yml": (
                "scripts/kcm-opcode-gate.sh\nkerber-rust-mit-kdc.tar\n"
                "lld\nrun-peer-step.sh\n"
            ),
        },
        {"ad-s4u-gate.sh": "docker run -d --name n img\nrun_rc=$?\nregister_cleanup x\n"},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {"peers.yml": "scripts/samba-ad-gate.sh\n"},
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "peers.yml": (
                "scripts/samba-ad-gate.sh\nkerber-rust-mit-kdc.tar\n"
            )
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "kcm-opcode.yml": (
                "scripts/kcm-opcode-gate.sh\nkerber-rust-mit-kdc.tar\nlld\n"
            )
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "kcm-opcode.yml": (
                "scripts/kcm-opcode-gate.sh\nKERBER_NO_IMAGE\n"
                "lld\nrun-peer-step.sh\n"
            )
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "peers.yml": "scripts/samba-ad-gate.sh\nkerber-rust-mit-kdc.tar\nunavailable=\nfailed=\n",
            "kcm-opcode.yml": "scripts/kcm-opcode-gate.sh\nkerber-rust-mit-kdc.tar\nrun-peer-step.sh\n",
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {},
        {
            "ad-s4u-gate.sh": (
                "docker run -d --name n img\n"
                "register_cleanup x\n"
                "run_rc=$?\n"
            )
        },
    )
    check_samba_kdc_respawn(
        'samba_kdc_respawn_in "$NAME" || die x\n',
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        'wait_gone_in "$NAME" 88 || die x\n',
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        'samba_kdc_respawn_in "$NAME" || die x\n',
        'wait_gone_in "$NAME_A" 88 || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        "echo no helper\n",
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        'samba_kdc_respawn_in "$NAME" || die "Samba KDC did not rebind :88 after worker kill"\n',
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    common_ok = "\n".join(GATE_COMMON_NEEDLES) + "\nGITHUB_ACTIONS\n::error file=\n::notice file=\n"
    gate_ok = "scripts/lib/gate-common.sh\nneed_bins krb5-kdc\n"
    _must_die(check_gate_common_sourced, "\n".join(GATE_COMMON_NEEDLES) + "\n", {"ok-gate.sh": gate_ok})
    _must_die(
        check_gate_common_sourced,
        "\n".join(GATE_COMMON_NEEDLES) + "\nGITHUB_ACTIONS\n::error file=\n",
        {"ok-gate.sh": gate_ok},
    )
    check_log_arity(
        'log() {\n    if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then\n'
        '        echo "log: expected 2-3 args, got $#" >&2\n        return 1\n    fi\n}\n'
    )
    _must_die(check_log_arity, "log() {\n    printf '%s' \"$1\"\n}\n")
    check_hygiene_diff_self_test(
        "def load_duplicates_map():\n    return {'merged:'}\n"
        "def load_renames_map():\n    return {}\n"
        "def _self_test_duplicates():\n    pass\n"
        "def _self_test():\n    pass\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-diff: self-test ok (36 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
        "    return _compare()\n"
    )
    _must_die(
        check_hygiene_diff_self_test,
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n        return 0\n",
    )
    _must_die(
        check_hygiene_diff_self_test,
        "def _self_test():\n    pass\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    _self_test()\n    return _compare()\n",
    )
    _must_die(
        check_hygiene_diff_self_test,
        'def load_duplicates_map():\n    return {"merged:"}\n'
        "def load_renames_map():\n    return {}\n"
        "def _self_test_duplicates():\n    pass\n"
        "def _self_test():\n"
        '    """merged: load_duplicates_map load_renames_map _self_test_duplicates"""\n'
        "    return None\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-diff: self-test ok (36 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
        "    return _compare()\n",
    )
    check_hygiene_body_diff_self_test(
        'def _self_test():\n    assert_eq!(1, 2) vs user_as helper "a  b" r"a\\n\\nb"\n'
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-body-diff: self-test ok (41 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    _must_die(check_hygiene_body_diff_self_test, "def main():\n    return 0\n")
    _must_die(
        check_hygiene_body_diff_self_test,
        "def _self_test():\n    assert_eq! vs user_as helper\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    _must_die(
        check_hygiene_body_diff_self_test,
        "def _self_test():\n"
        '    """assert_eq!(1, 2) vs user_as helper "a  b" r"a\\n\\nb" """\n'
        "    return None\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-body-diff: self-test ok (32 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    check_hygiene_fn_diff_self_test(
        "def _self_test():\n    x + 2 phase_b pub(crate)\n"
        "    # unused-accept fixture must be otherwise green\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-fn-diff: self-test ok (142 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    _must_die(check_hygiene_fn_diff_self_test, "def main():\n    return 0\n")
    _must_die(
        check_hygiene_fn_diff_self_test,
        "def _self_test():\n    x + 2 phase_b pub(crate)\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    _must_die(
        check_hygiene_fn_diff_self_test,
        "def _self_test():\n"
        '    """x + 2 phase_b pub(crate)"""\n'
        "    return None\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-fn-diff: self-test ok (64 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    py_move_ok = (
        "def _self_test():\n    cases = [" + "".join(f'("x", {{}}, s, a, "{k}"),' for k in _PY_MOVE_KINDS) + "]\n"
        "def main(argv):\n    if argv == ['--self-test']:\n        _self_test()\n"
        "        print('py-move-check: self-test ok (18 cases)')\n"
        "        return 0\n    with contextlib.redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    check_py_move_self_test(py_move_ok)
    _must_die_msg("self-test ok (N cases)", check_py_move_self_test, py_move_ok.replace("(18 cases)", "(17 cases)"))
    _must_die_msg(
        "must not be gutted",
        check_py_move_self_test,
        'def _self_test():\n    """' + "".join(f'"{k}"),' for k in _PY_MOVE_KINDS) + '"""\n    return None\n'
        + py_move_ok[py_move_ok.index("def main(argv):"):],
    )
    _must_die_msg("before a compare run", check_py_move_self_test,
                  py_move_ok.replace("with contextlib.redirect_stdout(sys.stderr):\n        _self_test()\n", "pass\n"))
    _must_die_msg("the shim finding", check_py_move_self_test, py_move_ok.replace('"shim"),', '"other"),'))
    with tempfile.TemporaryDirectory() as tmp:
        demo = pathlib.Path(tmp) / "crates" / "demo"
        (demo / "tests" / "common").mkdir(parents=True)
        (demo / "tests" / "listed.rs").write_text("fn main() {}\n", encoding="utf-8")
        (demo / "tests" / "common" / "mod.rs").write_text("", encoding="utf-8")
        (demo / "Cargo.toml").write_text(
            "[package]\nname = \"demo\"\nautotests = false\n\n"
            "[[test]]\nname = \"listed\"\npath = \"tests/listed.rs\"\n",
            encoding="utf-8",
        )
        check_autotests_registered(pathlib.Path(tmp))
        (demo / "tests" / "orphan.rs").write_text("", encoding="utf-8")
        _must_die(check_autotests_registered, pathlib.Path(tmp))
    check_gate_common_sourced(common_ok, {"ok-gate.sh": gate_ok})
    _must_die(
        check_gate_common_sourced,
        common_ok.replace("wait_port_in", "no-wait"),
        {"ok-gate.sh": gate_ok},
    )
    _must_die(
        check_gate_common_sourced,
        common_ok,
        {"bad-gate.sh": "scripts/lib/gate-common.sh\ncargo build -p krb5-kdc\n"},
    )
    check_no_gate_cargo_build({"ok-gate.sh": "need_bins krb5-kdc\n"})
    _must_die(
        check_no_gate_cargo_build,
        {"bad-gate.sh": "cargo build -p krb5-kdc\n"},
    )
    _must_die(
        check_no_gate_cargo_build,
        {"leftover-gate.sh": "    -p krb5-client --bin krb5-kvno\n"},
    )
    check_kadmin_glob_lib("hist_shape() { cat; }\nalias_cells() { :; }\n")
    _must_die(check_kadmin_glob_lib, "glob_cells() { :; }\n")
    _must_die(check_kadmin_glob_lib, "hist_shape() { cat; }\n")
    check_kadmin_split_snaps("save_rust_snap HIST_GET\n", "kadmin-rust-gate.sh")
    _must_die(check_kadmin_split_snaps, "echo no snap\n", "kadmin-rust-gate.sh")
    check_kadmin_split_snaps("load_rust_snap HIST_GET\n", "kadmin-mit-gate.sh")
    _must_die(check_kadmin_split_snaps, "echo no load\n", "kadmin-mit-gate.sh")
    check_kadmin_split_snaps(
        "./scripts/kadmin-rust-gate.sh\n./scripts/kadmin-rust-acl-gate.sh\n"
        "./scripts/kadmin-both-gate.sh\nKERBER_SCRATCH=\n",
        "kadmin-gate.sh",
    )
    check_kadmin_split_snaps("save_rust_snap GETPRIVS\n", "kadmin-rust-acl-gate.sh")
    _must_die(check_kadmin_split_snaps, "echo no snap\n", "kadmin-rust-acl-gate.sh")
    _must_die(
        check_kadmin_split_snaps,
        "./scripts/kadmin-rust-gate.sh\n./scripts/kadmin-both-gate.sh\n",
        "kadmin-gate.sh",
    )
    _must_die(
        check_kadmin_split_snaps,
        "./scripts/kadmin-rust-gate.sh\nKERBER_SCRATCH=\n",
        "kadmin-gate.sh",
    )
    check_kcm_need_image(
        'KCM_IMAGE="${KCM_IMAGE:-kerber-rust-sssd-kcm:f43}"\nneed_image\n',
        "ok-kcm-gate.sh",
    )
    _must_die(
        check_kcm_need_image,
        'IMAGE="${KCM_IMAGE:-kerber-rust-sssd-kcm:f43}"\nneed_image\n',
        "bad-kcm-gate.sh",
    )
    check_kcm_stop_before_run(
        "register_cleanup './scripts/stop-harness.sh'\n./scripts/run-harness.sh\n",
        "ok-kcm-gate.sh",
    )
    _must_die(
        check_kcm_stop_before_run,
        "./scripts/run-harness.sh\nregister_cleanup './scripts/stop-harness.sh'\n",
        "bad-kcm-gate.sh",
    )
    check_prod_gate_tcpdump_cleanup(
        'register_cleanup \'kill $KDC_PID 2>/dev/null || true; '
        'if [ -n "$TCPDUMP_PID" ]; then sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || true; fi\'\n'
    )
    check_prod_gate_tcpdump_cleanup(
        "prod_cleanup() {\n"
        '    kill "$KDC_PID" 2>/dev/null || true\n'
        '    if [ -n "$TCPDUMP_PID" ]; then sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || true; fi\n'
        "}\nregister_cleanup prod_cleanup\n"
    )
    _must_die(
        check_prod_gate_tcpdump_cleanup,
        "register_cleanup 'kill $KDC_PID $TCPDUMP_PID 2>/dev/null || true'\n",
    )
    _must_die(
        check_prod_gate_tcpdump_cleanup,
        'prod_cleanup() {\n    kill "$KDC_PID" 2>/dev/null || true\n}\nregister_cleanup prod_cleanup\n',
    )
    _must_die(check_no_host_tmp_writes, 'tmp="$(mktemp -d)"\n', "bare-mktemp.sh")
    _must_die(check_no_host_tmp_writes, "t=$(mktemp)\n", "bare-mktemp-file.sh")
    check_no_host_tmp_writes(
        'TMP="$(mktemp -d "${KERBER_SCRATCH:-${TMPDIR:-/tmp}}/x.XXXXXX")"\n'
        'idx="$(mktemp "$dir/kerber-prov.XXXXXX")"\n'
        'd="$(mktemp -d -p "$SCRATCH")"\n'
        "docker exec n sh -c 'mktemp -d'\n",
        "ok-mktemp.sh",
    )
    check_no_host_tmp_writes(
        "docker exec n sh -c 'kill /tmp/krb5-kdc; : >/tmp/in-container'\n"
        "docker exec -d n \\\n"
        "    sh -c '/tmp/krb5-kdc >/tmp/kdc-r18.log 2>&1'\n",
        "ok-r18-kill-tmp-gate.sh",
    )
    _probe_dir = ROOT / "working" / "logs" / "w1-sweep" / "a2-r2-audit" / "scan-probe"
    for _probe_name in (
        "differential-gate.sh",
        "kadmin-gate.sh",
        "renew-gate.sh",
        "s4u-mit-gate.sh",
    ):
        _probe = _probe_dir / _probe_name
        if _probe.is_file():
            _must_die(check_no_host_tmp_writes, _probe.read_text(), _probe_name)
        _must_die(
            check_no_host_tmp_writes,
            (SCRIPTS / _probe_name).read_text()
            + f"\necho probe > /tmp/host-probe-{_probe_name}\n",
            f"probe-{_probe_name}",
        )
    _must_die(
        check_no_host_tmp_writes,
        "# ignore <<EOF in a comment\necho x > /tmp/after-comment-heredoc\n",
        "comment-heredoc-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cat <<<ignored\necho x > /tmp/after-herestring\n",
        "herestring-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        'echo >"/tmp/quoted-redir"\n',
        "quoted-redir-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        'cp x "/tmp/quoted-cp"\n',
        "quoted-cp-tmp-gate.sh",
    )
    check_no_host_tmp_writes(
        'echo "cat <<EOF"\necho ok\ncat <<<hello\n# <<EOF\n',
        "ok-quoted-and-comment-heredoc.sh",
    )
    # S3.4d: tokenise via strip_noncode, scan testenv.rs whole, cfg(test)
    # anywhere on the line including cfg(all|any(..., test, ...)). Missing
    # tests.rs dies on the production is_file() branch (a ROOT-like tree
    # under scratch, text=None).
    _isolate_ok = (
        "fn isolate_scratch_dir() -> PathBuf {\n    PathBuf::from(\"target\").join(\"test-krb5\")\n}\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
    )
    check_isolate_test_krb5(_isolate_ok)
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        "pub fn isolate_test_krb5() {\n"
        "    let path = std::env::temp_dir().join(\"kerber-test-krb5-1.conf\");\n"
        "}\n",
    )
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        "fn isolate_scratch_dir() -> PathBuf { PathBuf::from(\"target/test-krb5\") }\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
        "#[cfg(test)]\nmod tests {\n    fn f() { let _ = std::env::temp_dir(); }\n}\n",
    )
    # C1 / C2: a private helper after isolate_test_krb5 is still testenv.rs
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        _isolate_ok + "fn helper_dir() -> PathBuf {\n    std::env::temp_dir()\n}\n",
    )
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        _isolate_ok
        + "fn helper_dir() -> PathBuf {\n    PathBuf::from(\"/tmp/kerber-test-krb5\")\n}\n",
    )
    # product temp_dir() after a cfg(test) use is not a cfg(test) item
    # (sibling file: testenv.rs is scanned whole)
    check_isolate_test_krb5(
        _isolate_ok,
        src_files={
            "kdcconf.rs": (
                "#[cfg(test)]\nuse foo::bar;\n"
                "fn product() { let _ = std::env::temp_dir(); }\n"
            )
        },
    )
    # temp_dir() inside a string literal in a cfg(test) mod is not a call
    check_isolate_test_krb5(
        _isolate_ok,
        src_files={
            "kdcconf.rs": (
                "#[cfg(test)]\nmod t {\n"
                '    fn f() { let _ = "temp_dir()"; }\n'
                "}\n"
            )
        },
    )

    def _isolate_src_file(name: str, src: str) -> None:
        check_isolate_test_krb5(_isolate_ok, src_files={name: src})

    # U1: lifetime + &'static before the temp_dir() fn (quote scanner ate it)
    _must_die_msg(
        "u1.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u1.rs",
        "#[cfg(test)]\nmod t {\n"
        " fn a<'x>(v: &str) { let r: &'static str = \"k\"; }\n"
        " fn f(){ std::env::temp_dir(); }\n}\n",
    )
    # U3: // comment containing }
    _must_die_msg(
        "u3.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u3.rs",
        "#[cfg(test)]\nmod t {\n // closes } here\n fn f(){ std::env::temp_dir(); }\n}\n",
    )
    # U6: #[cfg(test)] after code on the same line
    _must_die_msg(
        "u6.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u6.rs",
        "fn p(){} #[cfg(test)] mod t { fn f(){ std::env::temp_dir(); } }\n",
    )
    # U4: cfg(all(test, …)) / cfg(any(test, …))
    _must_die_msg(
        "u4.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u4.rs",
        "#[cfg(all(test, unix))]\nmod t {\n fn f(){ std::env::temp_dir(); }\n}\n",
    )
    _must_die_msg(
        "u4any.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u4any.rs",
        "#[cfg(any(test, windows))]\nmod t {\n fn f(){ std::env::temp_dir(); }\n}\n",
    )

    def _isolate_missing_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        src = fake / "crates/krb5-config/src"
        src.mkdir(parents=True)
        (src / "testenv.rs").write_text(_isolate_ok)
        check_isolate_test_krb5(root=fake)

    def _isolate_tree_with_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        src = fake / "crates/krb5-config/src"
        src.mkdir(parents=True)
        (src / "testenv.rs").write_text(_isolate_ok)
        (src / "tests.rs").write_text("// no temp_dir\n")
        check_isolate_test_krb5(root=fake)

    def _isolate_tests_rs_temp_dir() -> None:
        check_isolate_test_krb5(
            _isolate_ok,
            tests_text="fn f() { let _ = std::env::temp_dir(); }\n",
        )

    def _isolate_src_cfg_test_temp_dir() -> None:
        check_isolate_test_krb5(
            _isolate_ok,
            src_files={
                "kdcconf.rs": (
                    "#[cfg(test)]\nmod tests {\n"
                    "    fn f() { let _ = std::env::temp_dir(); }\n"
                    "}\n"
                )
            },
        )

    _iso_src = inspect.getsource(check_isolate_test_krb5)
    _blank_src = inspect.getsource(_blank_rust)
    _range_src = inspect.getsource(_cfg_test_ranges)
    if "if not tests_path.is_file():" not in _iso_src:
        raise AssertionError("missing tests.rs must go through is_file()")
    if "tests_missing" in _iso_src:
        raise AssertionError("tests_missing short-circuit must stay gone")
    if "strip_noncode" not in _blank_src:
        raise AssertionError("must tokenise via strip_noncode")
    if "except" not in _blank_src:
        raise AssertionError("strip_noncode failure must die")
    if "in_str" in _iso_src or "in_str" in _range_src:
        raise AssertionError("hand-rolled string scanner must stay gone")
    if "isolate_scratch_dir" in _iso_src:
        raise AssertionError("testenv.rs must be scanned whole, not as an isolate chunk")
    _must_die_msg(
        "missing crates/krb5-config/src/tests.rs",
        _isolate_missing_tests,
    )
    _isolate_tree_with_tests()
    _must_die(_isolate_tests_rs_temp_dir)
    _must_die(_isolate_src_cfg_test_temp_dir)
    check_isolate_test_krb5()
    check_unit_evidence_helper()
    check_settle_helper()
    check_evidence_check_tool()
    check_ci_status_save()
    check_red_at_sha_inject()
    check_red_at_sha_overlay_order(
        'cp "$ROOT/scripts/"*.sh "$WT/scripts/"\nTREE="$(git write-tree)"\n'
    )
    _must_die(
        check_red_at_sha_overlay_order,
        'TREE="$(git write-tree)"\ncp "$ROOT/scripts/"*.sh "$WT/scripts/"\n',
    )
    _must_die(
        check_red_at_sha_inject,
        '--inject\nTREE="$(git write-tree)"\ncp "$ROOT/$rel" "$WT/$rel"\n',
    )
    check_red_at_sha_target_trap()
    _trap_ok = (
        'cleanup() {\n    rm -rf "$WT"\n    if [ "${KERBER_KEEP_RED_TARGET:-}" != "1" ]; then\n'
        '        rm -rf "$TARGET"\n    fi\n}\ntrap cleanup EXIT\necho "red-at-parent=1"\n'
    )
    check_red_at_sha_target_trap(_trap_ok)
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace('rm -rf "$TARGET"', "true"))
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace("KERBER_KEEP_RED_TARGET", "X"))
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace('echo "red-at-parent=1"', ""))
    _rt = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        check_no_red_target_trees(_rt)
        (_rt / "z9" / "scratch" / "red-target-0123456789ab" / "debug").mkdir(parents=True)
        _must_die(check_no_red_target_trees, _rt)
        subprocess.run(["rm", "-rf", str(_rt / "z9")], check=True)
        (_rt / "z9" / "scratch" / "tgt" / "debug").mkdir(parents=True)
        (_rt / "z9" / "scratch" / "tgt" / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55")
        _must_die(check_no_red_target_trees, _rt)
    finally:
        subprocess.run(["rm", "-rf", str(_rt)], check=False)
    check_index_check_scratch()

    env = os.environ.copy()
    env.update({"ROOT": str(ROOT), "KERBER_NO_IMAGE": "1"})
    dirty_refuse = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; dirty=yes; unit_guard_dirty',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )
    if dirty_refuse.returncode != 1:
        _die("unit_guard_dirty must refuse dirty=yes without KERBER_UNIT_ALLOW_DIRTY")
    dirty_allow = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; dirty=yes; '
            "KERBER_UNIT_ALLOW_DIRTY=1 unit_guard_dirty",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )
    if dirty_allow.returncode != 0 or "override=KERBER_UNIT_ALLOW_DIRTY" not in (
        dirty_allow.stdout or ""
    ):
        _die("unit_guard_dirty must stamp override=KERBER_UNIT_ALLOW_DIRTY when allowed")
    dirty_ok = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; dirty=no; unit_guard_dirty',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if dirty_ok.returncode != 0:
        _die("unit_guard_dirty must accept dirty=no")

    red_py = SCRIPTS / "lib" / "unit-red-check.py"
    if not red_py.is_file():
        _die("missing scripts/lib/unit-red-check.py")
    red_fail = subprocess.run(
        [sys.executable, str(red_py), "foo"],
        input="test foo ... FAILED\n",
        capture_output=True,
        check=False,
        text=True,
    )
    if red_fail.returncode != 0:
        _die("unit-red-check.py must accept all FAILED")
    red_pass = subprocess.run(
        [sys.executable, str(red_py), "foo"],
        input="test foo ... ok\n",
        capture_output=True,
        check=False,
        text=True,
    )
    if red_pass.returncode != 1 or "vacuous red" not in (red_pass.stderr or ""):
        _die("unit-red-check.py must reject a passed test")
    red_empty = subprocess.run(
        [sys.executable, str(red_py), "foo"],
        input="",
        capture_output=True,
        check=False,
        text=True,
    )
    if red_empty.returncode != 1:
        _die("unit-red-check.py must reject empty cargo output")

    hdr_mismatch = "The thirty-three live `diffsend` cases are `garbage-pdu`.\n"
    _must_die(check_diffsend_cases, hdr_mismatch, gate_n, src_n)

    spec = importlib.util.spec_from_file_location("ci_status_r14", SCRIPTS / "ci-status.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/ci-status.py")
    cistat = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cistat)
    cistat.time.sleep = lambda _s: None
    out_dir = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:

        def _inprog(*_a, **_k):
            return [
                {
                    "id": 1,
                    "run_number": 1,
                    "status": "in_progress",
                    "conclusion": None,
                    "head_sha": "abc1234deadbeef",
                }
            ]

        import io
        import urllib.error as _ue
        from email.message import Message

        def _quiet_save(*args, **kwargs):
            sink = io.StringIO()
            oldout, olderr = sys.stdout, sys.stderr
            try:
                sys.stdout = sink
                sys.stderr = sink
                return cistat.save_run(*args, **kwargs)
            finally:
                sys.stdout = oldout
                sys.stderr = olderr

        cistat.fetch_runs = _inprog
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=2)
        if rc != 2 or (out_dir / "ci-abc1234.txt").exists():
            _die("ci-status --save must exit 2 and write no file for in_progress")

        def _403(*_a, **_k):
            raise _ue.HTTPError(
                "https://api.github.com",
                403,
                "rate limit",
                Message(),
                io.BytesIO(b""),
            )

        cistat.fetch_runs = _403
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=3)
        if rc != 2 or (out_dir / "ci-abc1234.txt").exists():
            _die("ci-status --save must exit 2 and write no file after 403 ×N")

        def _done(*_a, **_k):
            return [
                {
                    "id": 9,
                    "run_number": 2,
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "abc1234deadbeef",
                }
            ]

        cistat.fetch_runs = _done
        cistat.format_run = lambda *_a, **_k: ["run ok"]
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=1)
        saved = out_dir / "ci-abc1234.txt"
        if rc != 0 or not saved.is_file() or "head_sha=" not in saved.read_text():
            _die("ci-status --save must exit 0 with head_sha= for a completed run")
    finally:
        subprocess.run(["rm", "-rf", str(out_dir)], check=False)

    camod = _claim_audit_module()
    croot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (croot / "scripts").mkdir()
        pad = 'echo "---- pad ----"\n' * 4
        (croot / "scripts" / "fx-gate.sh").write_text(
            'NAME="rust"\nNAME_MIT="mit"\n'
            + pad
            + 'echo "==== value ===="  # MIT omits NULL\nOUT="$(docker exec "$NAME" true)"\n'
            + "echo \"$OUT\" | grep -F 'value=1'\n"
            + pad
            + 'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            + "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
        )
        ev = croot / "logs"
        ev.mkdir()
        stamp = "head_sha=0\ntree_sha=0\n"
        (ev / "x-unit-red.log").write_text(stamp + "dirty=yes\nvalue=1\n")
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"
        bullet = (
            "- **Text excuse only:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; "
            "Red at parent `x-unit-red.log`.\n"
        )
        rows = camod.audit_text(head + bullet, croot, ev)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must not take a parent-red text excuse without red-at-parent=")
        (ev / "x-unit-red.log").write_text(
            stamp + "dirty=yes\nred-at-parent=1\nvalue=1\n"
        )
        rows = camod.audit_text(head + bullet, croot, ev)
        if any(r[1] != "ok" for r in rows):
            _die(f"claim-audit refused a dirty unit-red with red-at-parent=: {rows}")
    finally:
        subprocess.run(["rm", "-rf", str(croot)], check=False)

    # W1-Z Z3.1 freeze rule: a `Frozen-at: <sha>` summary resolves its cites at
    # that commit, so a later gate edit that drops the assertion does not
    # re-open the closed summary; the same bullet without the header is red.
    froot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (froot / "scripts").mkdir()
        gate = froot / "scripts" / "fx-gate.sh"
        asserting = (
            'NAME="rust"\nNAME_MIT="mit"\n'
            'OUT="$(docker exec "$NAME" true)"\n'
            "echo \"$OUT\" | grep -F 'value=1'\n"
            'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
        )
        gate.write_text(asserting)
        genv = {
            **os.environ,
            "GIT_AUTHOR_NAME": "fx",
            "GIT_AUTHOR_EMAIL": "fx@x",
            "GIT_COMMITTER_NAME": "fx",
            "GIT_COMMITTER_EMAIL": "fx@x",
        }
        for cmd in (
            ["git", "init", "-q"],
            ["git", "add", "-A"],
            ["git", "commit", "-q", "-m", "fx"],
        ):
            subprocess.run(cmd, cwd=froot, check=True, env=genv, capture_output=True)
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=froot, check=True, capture_output=True, text=True
        ).stdout.strip()
        gate.write_text(asserting.replace("grep -F 'value=1'", "cat"))
        fev = froot / "logs"
        fev.mkdir()
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"
        bullet = "- **Frozen cite:** `value=1` at `scripts/fx-gate.sh:4` / `:6`.\n"
        if camod.frozen_at(f"# T\n\nFrozen-at: `{sha[:12]}`\n\n" + head + bullet) != sha[:12]:
            _die("claim-audit frozen_at must read the `Frozen-at:` header")
        rows = camod.audit_text(head + bullet, froot, fev)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must read the working tree when no Frozen-at is given")
        rows = camod.audit_text(head + bullet, froot, fev, sha)
        if any(r[1] != "ok" for r in rows):
            _die(f"claim-audit must resolve a frozen cite at its sha: {rows}")
        rows = camod.audit_text(head + bullet, froot, fev, "0" * 40)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must fail a cite frozen at an unknown sha")
    finally:
        subprocess.run(["rm", "-rf", str(froot)], check=False)

    anchor_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        src = anchor_root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        tests_dir = anchor_root / "crates" / "demo" / "tests"
        tests_dir.mkdir(parents=True)
        good = src / "lib.rs"
        in_tests = tests_dir / "t.rs"
        in_tests.write_text("", encoding="utf-8")
        accepted = {
            "fn-anchor": "/// MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "line-comment": "// MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "inner-doc": "//! MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "block": "/* MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay */\n",
            "header-anchor": "/// MIT `krb5_get_init_creds_opt` (`krb5.hin:6839-6851`): the option block\n",
            "et-anchor": "/// MIT `KADM5_UNK_PRINC` (`kadm_err.et:54-54`): an unknown principal\n",
            "type-anchor": "/// MIT `struct extended_options` (`krb/gic_opt.c:19-32`): the option tail\n",
            "qualified-basename": "// MIT `init_realm` (`kdc/main.c:286-345`): the realm stanza wins\n",
            "mention": "/// MIT `KRB5_KDB_DISALLOW_TGT_BASED`.\n",
            "file-mention": "//! Context establishment (`init_sec_context.c`, `accept_sec_context.c`).\n",
            "file-and-mention": "/// MIT `pac.c` `MAX_BUFFERS`.\n",
            "bare-file-mention": "// The loop mirrors gic_pwd.c.\n",
            "anchor-and-mention": "/// MIT `f` (`a.c:1-2`): calls `g` in `b.c` first\n",
            "backtick-guarantee": "/// MIT `f` (`a.c:1-2`): `KDC_ERR_X` on a bad key\n",
        }
        for body in accepted.values():
            good.write_text(body, encoding="utf-8")
            check_mit_anchor_form(anchor_root, allow=0)
        good.write_text("", encoding="utf-8")
        in_tests.write_text(accepted["fn-anchor"], encoding="utf-8")
        check_mit_anchor_form(anchor_root, allow=0)
        in_tests.write_text("", encoding="utf-8")
        rejected = {
            "file-range-only": "/// (`do_as_req.c:10-20`)\n",
            "name-and-range": "/// MIT `krb5_rd_req` (`do_as_req.c:10-20`)\n",
            "file-point-only": "/// (`do_as_req.c:10`)\n",
            "bare-file": "/// MIT do_as_req.c:10 sets the flag\n",
            "name-and-point": "/// MIT `krb5_rd_req` (`do_as_req.c:10`)\n",
            "mit-backtick-point": "/// MIT `do_as_req.c:10` sets the flag\n",
            "prose-range": "// the check at do_tgs_req.c:10-20 runs first\n",
            "header-point": "// the rock (`kdc_util.h:422`)\n",
            "hin-range": "/// the option block (krb5.hin:6839-6851)\n",
            "et-point": "/// `kadm_err.et:54` names it\n",
            "multi-range": "/// (`server_stubs.c:478,519`)\n",
            "leftover-beside-anchor": "/// MIT `f` (`a.c:1-2`): checks first, see b.c:3\n",
            "two-anchors": "/// MIT `f` (`a.c:1-2`): x; MIT `g` (`b.c:3-4`): y\n",
            "no-guarantee": "/// MIT `f` (`a.c:1-2`):\n",
            "empty-guarantee": "/// MIT `f` (`a.c:1-2`): \n",
            "punct-guarantee": "/// MIT `stub_setup` (`server_stubs.c:296-301`): -638).\n",
            "paren-guarantee": "/// MIT `f` (`a.c:1-2`): (`g`,.\n",
            "same-check": "/// MIT `f` (`a.c:1-2`): same check.\n",
            "mit-guarantee": "/// MIT `f` (`a.c:1-2`): MIT.\n",
            "name-guarantee": "/// MIT `strdur` (`kadmin.c:118-138`): strdur.\n",
            "ambiguous-anchor": "// MIT `init_realm` (`main.c:286-345`): the realm stanza wins\n",
            "ambiguous-mention": "//! Principal names (`str_conv.c`).\n",
            "block-cite": "/* see do_as_req.c:10 */\n",
            "doc-block-cite": "/**\n * the check (`do_as_req.c:10-20`)\n */\n",
            "inner-doc-cite": "//! the check (`do_as_req.c:10-20`)\n",
            "line-comment-cite": "// the check (`do_as_req.c:10-20`)\n",
        }
        for shape, body in rejected.items():
            good.write_text(body, encoding="utf-8")
            _must_die_msg(
                "mit anchor lines 1 != allow 0",
                check_mit_anchor_form,
                anchor_root,
                allow=0,
            )
        good.write_text("", encoding="utf-8")
        in_tests.write_text(rejected["file-range-only"], encoding="utf-8")
        _must_die_msg(
            "mit anchor lines 1 != allow 0", check_mit_anchor_form, anchor_root, allow=0
        )
        check_mit_anchor_form(anchor_root, allow=1)
        _must_die_msg(
            "mit anchor lines 1 != allow 2",
            check_mit_anchor_form,
            anchor_root,
            allow=2,
        )
        # The shape names are part of the fixture, so a deleted shape is a
        # missing key, not a silent pass.
        if len(accepted) != 14 or len(rejected) != 26:
            _die("mit anchor fixtures dropped a shape")
    finally:
        subprocess.run(["rm", "-rf", str(anchor_root)], check=False)

    truth_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        fake = truth_root / "mit"
        for rel, text in {
            "lib/krb5/krb/gic_pwd.c": (
                "/* a file comment */\n\nstatic int\nhelper(int x)\n{\n    return callee(x);\n}\n\n"
                "/*\n * The password loop.\n */\nkrb5_error_code\n"
                "krb5_get_init_creds_password(int a)\n{\n    int r = helper(a);\n"
                "    if (isflagset(a, 1))\n        r = 1;\n    return r;\n}\n\n"
                "static const char *names[] = {\n    \"a\",\n};\n\nDEFFIELD(error_7, x, 7);\n"
            ),
            "include/k5-int.h": (
                "#define isflagset(flags, flag) \\\n    ((flags) & (flag))\n"
                "struct opt_tail {\n    int x;\n};\ntypedef struct {\n    int y;\n} opt_head;\n"
            ),
            "lib/kadm5/t_kadm5.c": "static void\nkinit(int x)\n{\n}\n",
            "kdc/main.c": "static void\ninit_realm(void)\n{\n}\n",
            "clients/ksu/main.c": "static void\ninit_realm(void)\n{\n}\n",
            "lib/kadm5/kadm_err.et": "error_table ovk\nerror_code KADM5_FAILURE, \"Operation failed\"\n",
            "kdc/fast_util.c": (
                "static krb5_error_code armor_ap_request\n(struct state *s)\n{\n"
                "    return 0;\n}\n"
            ),
            "include/k5-inline.h": (
                "/* Verify a key. */\nstatic inline int\nverify_key(int k)\n{\n    return k;\n}\n"
            ),
            "include/plugin.h": (
                "/* The handle method. */\ntypedef int\n(*handle_fn)(int context,\n"
                "                int flags);\n"
            ),
            "lib/kadm5/internal.h": (
                "typedef struct _handle_t {\n    int magic;\n} handle_rec, *handle_t;\n"
            ),
            "include/iprop.h": (
                "struct kdb_last_t {\n    int sno;\n};\ntypedef struct kdb_last_t kdb_last_t;\n"
            ),
            "lib/krb5/asn.1/asn1_k_encode.c": (
                "/*\n * SecureCookie ::= SEQUENCE {\n *     time INTEGER\n * }\n */\n"
                "DEFSEQTYPE(secure_cookie, krb5_secure_cookie, fields);\n"
            ),
        }.items():
            (fake / rel).parent.mkdir(parents=True, exist_ok=True)
            (fake / rel).write_text(text, encoding="utf-8")
        crate_src = truth_root / "crates" / "demo" / "src"
        crate_tests = truth_root / "crates" / "demo" / "tests"
        crate_src.mkdir(parents=True)
        crate_tests.mkdir(parents=True)

        def truth(body: str, in_tests: bool = False) -> int:
            (crate_src / "lib.rs").write_text("" if in_tests else body, encoding="utf-8")
            (crate_tests / "t.rs").write_text(body if in_tests else "", encoding="utf-8")
            return len(mit_anchor_truth_violations(truth_root, fake))

        holds = {
            "fn-body": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:14-18`): loops\n",
            "doc-block": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:9-19`): documented\n",
            "slack": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:6-19`): slack\n",
            "type": "// MIT `struct opt_tail` (`k5-int.h:3-5`): the tail\n",
            "typedef-tail": "// MIT `opt_head` (`k5-int.h:6-8`): the head\n",
            "header-macro": "// MIT `isflagset` (`k5-int.h:1-2`): tests a flag\n",
            "data": "// MIT `names` (`gic_pwd.c:21-23`): the table\n",
            "macro-gen": "// MIT `error_7` (`gic_pwd.c:25-25`): the field\n",
            "errcode": "// MIT `KADM5_FAILURE` (`kadm_err.et:2-2`): unspecified\n",
            "qualified": "// MIT `init_realm` (`kdc/main.c:2-4`): realm first\n",
            "mention": "//! Mirrors `gic_pwd.c` and `kdc/main.c`.\n",
            "split-declarator": "// MIT `armor_ap_request` (`fast_util.c:3-5`): armor first\n",
            "static-inline": "// MIT `verify_key` (`k5-inline.h:1-6`): the key check\n",
            "fn-pointer-typedef": "// MIT `handle_fn` (`plugin.h:1-4`): the method\n",
            "typedef-list-tail": "// MIT `handle_rec` (`internal.h:3-3`): the handle\n",
            "rpcgen-typedef": "// MIT `kdb_last_t` (`iprop.h:1-4`): the last entry\n",
            "asn1-comment": "// MIT `SecureCookie` (`asn1_k_encode.c:2-4`): the cookie\n",
        }
        for label, body in holds.items():
            if truth(body) != 0:
                _die(f"check_mit_anchor_truth must accept {label}: {mit_anchor_truth_violations(truth_root, fake)}")
        if truth("// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n", in_tests=True) != 0:
            _die("check_mit_anchor_truth must accept a test citing MIT test code")
        breaks = {
            "callee": "// MIT `callee` (`gic_pwd.c:6-6`): calls\n",
            "macro-slot": "// MIT `isflagset` (`gic_pwd.c:16-16`): tests\n",
            "wrong-fn": "// MIT `helper` (`gic_pwd.c:15-15`): helps\n",
            "lead-overhang": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:5-19`): early\n",
            "tail-overhang": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:14-20`): late\n",
            "test-from-src": "// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n",
            "ambiguous": "// MIT `init_realm` (`main.c:2-4`): realm first\n",
            "unknown-file": "// MIT `f` (`nosuch.c:1-2`): gone\n",
            "mention-unknown": "//! Mirrors `nosuch.c`.\n",
            "mention-ambiguous": "//! Mirrors `main.c`.\n",
        }
        for label, body in breaks.items():
            if truth(body) != 1:
                _die(f"check_mit_anchor_truth must flag {label} once: {mit_anchor_truth_violations(truth_root, fake)}")
        truth(breaks["callee"])
        check_mit_anchor_truth(truth_root, fake, allow=1)
        _must_die_msg("mit anchor truth 1 != allow 0", check_mit_anchor_truth, truth_root, fake, allow=0)
        _must_die_msg("_AMBIGUOUS_MIT_BASENAMES differs", _check_ambiguous_pin, fake)
        if len(holds) != 17 or len(breaks) != 10:
            _die("mit anchor truth fixtures dropped a case")
    finally:
        subprocess.run(["rm", "-rf", str(truth_root)], check=False)

    tag_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        src = tag_root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        good = src / "lib.rs"
        for body in (
            "// the parent principal stays\n",
            "/// the magic word `deadbeef` and `0x12345678`\n",
            "/// each item is checked; networking/ is not a path here\n",
            "/// a SHA-256 digest; B-frames; F-strings\n",
        ):
            good.write_text(body, encoding="utf-8")
            check_no_process_history(tag_root, allow=0)
        good.write_text('fn f() {\n    let s = "// R12 in a string";\n}\n', encoding="utf-8")
        check_no_process_history(tag_root, allow=0)
        tagged = {
            "R12": "// R12 left the suppression\n",
            "A-prime": "// A\u2032-3 item 14\n",
            "W0": "// W0e H7\n",
            "W1": "// W1-Z follow-up\n",
            "Round": "// Round 2\n",
            "parent": "// parent abcdef0\n",
            "R2-S3": "// limit (R2-S3).\n",
            "B3": "// referral (B3).\n",
            "Y0": "// the Y0 mismatch\n",
            "Z": "// before Z6.3 the wire code was 60\n",
            "sha": "//! the check landed in `59c363b`.\n",
            "parent-red": "//! the unit is (parent-red).\n",
            "compiles-at": "//! Compiles at the parent and fails there.\n",
            "item": "/// order stays item 15.\n",
            "S-section": "// Helpers moved here in S2.3.\n",
            "Z-leftover": "//! Z8 leftover: the stamp.\n",
            "B-F": "//! F4 hierarchical referral.\n",
            "the-parent": "//! at the parent `abcdef0` it fails.\n",
            "working": "//! see `working/logs/x.log`.\n",
        }
        for body in tagged.values():
            good.write_text(body, encoding="utf-8")
            _must_die_msg(
                "process-history lines 1 != allow 0",
                check_no_process_history,
                tag_root,
                allow=0,
            )
        good.write_text(tagged["B3"], encoding="utf-8")
        check_no_process_history(tag_root, allow=1)
        if len(tagged) != 19:
            _die("process-history fixtures dropped a tag")
    finally:
        subprocess.run(["rm", "-rf", str(tag_root)], check=False)

    # S6-14: the module-attribute consumers, each missing name and each shape red.
    check_policy_module_attrs()
    mod_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        full = {
            "ROOT": "import pathlib\nROOT = pathlib.Path('/nonexistent')\n",
            "_dump_key_hexes": "def _dump_key_hexes(line):\n    return None\n",
            "check_golden_dump_unique_keys": "def check_golden_dump_unique_keys():\n    pass\n",
            "DIFFSEND_CASES": f"DIFFSEND_CASES = frozenset({sorted(DIFFSEND_CASES)!r})\n",
            "ledger_sources": "def ledger_sources(root=None):\n    return [('docs/parity/README.md', '', None)]\n",
            "recount_ledger_verdicts": "def recount_ledger_verdicts(text):\n    return {}\n",
            "_split_ledger_row": "def _split_ledger_row(line):\n    return []\n",
        }
        fake = mod_root / "ci-policy.py"
        fake.write_text("".join(full.values()), encoding="utf-8")
        check_policy_module_attrs(fake)
        for gone, consumer in (("_dump_key_hexes", "kdb-dump-gate.sh"), ("ledger_sources", "hygiene_inventory.py")):
            fake.write_text("".join(v for k, v in full.items() if k != gone), encoding="utf-8")
            _must_die_msg(f"lacks {gone}, which scripts/", check_policy_module_attrs, fake)
            _must_die_msg(consumer, check_policy_module_attrs, fake)
        fake.write_text("".join(full.values()).replace(full["DIFFSEND_CASES"], "DIFFSEND_CASES = frozenset({'x'})\n"),
                        encoding="utf-8")
        _must_die_msg("holds 1 DIFFSEND_CASES", check_policy_module_attrs, fake)
        fake.write_text(
            "".join(full.values()).replace("docs/parity/README.md", "docs/mit-parity-ledger.md"), encoding="utf-8"
        )
        _must_die_msg("not the docs/parity/ split", check_policy_module_attrs, fake)
        fake.write_text("raise SystemExit('no import')\n", encoding="utf-8")
        _must_die_msg("does not load as a module from cwd=/", check_policy_module_attrs, fake)
    finally:
        subprocess.run(["rm", "-rf", str(mod_root)], check=False)


# W1-K M2b: after the differential oracle's whitelist mechanism is deleted, no
# case may be excused by name. Ban the mechanism identifiers from the diffsend
# driver and the gate scripts. The tokens are case-precise so a gate's runtime
# assertion that the output has no `"whitelist"` key is not itself flagged.
_CASE_WHITELIST = re.compile(r"\bWhitelist\b|whitelisted|whitelist_hits|skip_cases|known_diff")


def check_no_case_whitelists(text: str | None = None, name: str = "diffsend.rs") -> None:
    """Fail if a differential whitelist mechanism reappears."""

    def scan(txt: str, rel: str) -> None:
        for i, line in enumerate(txt.splitlines(), 1):
            m = _CASE_WHITELIST.search(line)
            if m:
                _die(f"{rel}:{i} banned differential whitelist token {m.group(0)!r} (M2b)")

    if text is not None:
        scan(text, name)
        return
    if DIFFSEND_SRC.is_file():
        scan(DIFFSEND_SRC.read_text(), str(DIFFSEND_SRC.relative_to(ROOT)))
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
    # R2-T7: the differential compare itself (diff.rs) and the shared gate
    # helpers are where a case-name whitelist would most plausibly reappear, so
    # scan them too, not only the driver and the top-level gates.
    for path in sorted((ROOT / "crates/krb5-protocol/src").glob("*.rs")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
    for path in sorted((SCRIPTS / "lib").glob("*.sh")):
        scan(path.read_text(), str(path.relative_to(ROOT)))


_ANCHOR_EXT = r"(?:c|hin|h|et|x|y)"
# The one anchor form (R1): MIT `symbol` (`path.ext:a-b`): guarantee. The
# symbol is a C function, or the type (`struct x`, `union x`, `enum x`),
# macro, table or error-table entry a non-function anchor names; the truth
# check (ledger-mit job) proves that the range lies inside that definition.
_ANCHOR_HEAD = re.compile(
    r"MIT `((?:(?:struct|union|enum) )?[A-Za-z_][A-Za-z0-9_]*)` "
    r"\(`([A-Za-z0-9_./+-]+\." + _ANCHOR_EXT + r"):(\d+)-(\d+)`\)"
)
# Any MIT line cite: a source path with a line number. Outside an anchor
# head it is the dodge the form forbids (a range that is not an anchor).
_LINE_CITE = re.compile(
    r"(?<![\w./+-])[A-Za-z0-9_+-][A-Za-z0-9_./+-]*\." + _ANCHOR_EXT + r":\d+"
)
# A MIT source path with or without a range; a rangeless mention is legal.
_FILE_TOKEN = re.compile(
    r"(?<![\w./+-])([A-Za-z_][A-Za-z0-9_./+-]*\." + _ANCHOR_EXT + r")(?![\w])"
)
# Basenames that name more than one file under the MIT 1.22.2 `src/` tree
# (.c .h .hin .et .x .y). A cite of one of them must carry a directory;
# check_mit_anchor_truth re-derives this set from KERBER_MIT_SRC.
_AMBIGUOUS_MIT_BASENAMES = frozenset(
    {
        "aes.c", "auth.h", "camellia.c", "client.c", "cmac.c", "common.c",
        "common.h", "copyright.h", "des3.c", "des_keys.c", "extern.h",
        "gss-client.c", "gss-misc.c", "gss-misc.h", "gss-server.c", "hmac.c",
        "init_ctx.c", "kdb_xdr.c", "kdf.c", "keytab.c", "localauth.c",
        "lockout.c", "main.c", "mit-sipb-copyright.h", "openssl.c", "parse.c",
        "pbkdf2.c", "prf.c", "rc4.c", "reminder.h", "replay.c", "resource.h",
        "server.c", "sha256.c", "str_conv.c", "t_prf.c", "util.h",
    }
)
_BAD_GUARANTEE_START = set(".,;:!?)(]}-\u2013\u2014\u2192")
_EMPTY_GUARANTEES = {"same check", "mit"}


def _anchor_line_problems(comment: str) -> list[str]:
    """Why one comment line breaks the R1 anchor form (empty when it does not)."""
    problems: list[str] = []
    heads = list(_ANCHOR_HEAD.finditer(comment))
    if len(heads) > 1:
        problems.append("two anchors on one line")
    for m in heads:
        tail = comment[m.end():]
        if not tail.startswith(": "):
            problems.append("anchor without a guarantee on its line")
            continue
        guarantee = tail[2:].strip()
        bare = guarantee.strip("` ").rstrip(".").strip("` ").lower()
        if not guarantee:
            problems.append("empty guarantee")
        elif guarantee[0] in _BAD_GUARANTEE_START:
            problems.append("guarantee starts with punctuation")
        elif bare in _EMPTY_GUARANTEES or bare == m.group(1).split()[-1].lower():
            problems.append("guarantee states nothing")
    if _LINE_CITE.search(_ANCHOR_HEAD.sub(" ", comment)):
        problems.append("line cite outside the anchor form")
    for f in _FILE_TOKEN.finditer(comment):
        path = f.group(1)
        if "/" not in path and path in _AMBIGUOUS_MIT_BASENAMES:
            problems.append(f"ambiguous basename {path} needs a directory")
    return problems


def _comment_lexer():
    spec = importlib.util.spec_from_file_location(
        "hygiene_fn_diff_comments", SCRIPTS / "hygiene-fn-diff.py"
    )
    if spec is None or spec.loader is None:
        _die("missing scripts/hygiene-fn-diff.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_COMMENT_LEXER = None


def _comment_lines(src: str) -> list[tuple[int, str]]:
    """Comment lines outside string literals: every `//`, `///` and `//!`
    line, and every line of a (nested) `/* */`, `/** */` or `/*! */` block."""
    global _COMMENT_LEXER
    if _COMMENT_LEXER is None:
        _COMMENT_LEXER = _comment_lexer()
    mod = _COMMENT_LEXER
    out: list[tuple[int, str]] = []
    i, n = 0, len(src)
    line = 1

    def bump(chunk: str) -> None:
        nonlocal line
        line += chunk.count("\n")

    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            if j < 0:
                j = n
            out.append((line, src[i:j]))
            i = j
            continue
        if src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k, part in enumerate(src[i:j].split("\n")):
                out.append((line + k, part))
            bump(src[i:j])
            i = j
            continue
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        end: int | None = None
        if c == "r" or (c == "b" and nxt == "r"):
            end = mod._scan_raw(src, i)
        if end is None and c == "b" and nxt == '"':
            end = mod._scan_quoted(src, i + 1)
        if end is None and c == '"':
            end = mod._scan_quoted(src, i)
        if end is None and c in "'b":
            end = mod._scan_char(src, i)
        if end is not None:
            bump(src[i:end])
            i = end
            continue
        if c == "\n":
            line += 1
        i += 1
    return out


def _rs_under(root: pathlib.Path, kinds: tuple[str, ...] | None) -> list[pathlib.Path]:
    crates = root / "crates"
    if not crates.is_dir():
        return []
    if kinds is None:
        return sorted(crates.rglob("*.rs"))
    out: list[pathlib.Path] = []
    for crate in sorted(p for p in crates.iterdir() if p.is_dir()):
        for kind in kinds:
            base = crate / kind
            if base.is_dir():
                out.extend(sorted(base.rglob("*.rs")))
    return out


_TEST_MIT_PATH = re.compile(r"(?:^|/)(?:t_[^/]*\.c|tests?/|unit-test/)")
_C_KEYWORDS = frozenset(
    "if for while switch return sizeof do else case typedef struct union enum".split()
)


def _mit_tree_root(src: pathlib.Path) -> pathlib.Path:
    """The MIT `src/` directory; KERBER_MIT_SRC may name the tree or its `src/`."""
    if (src / "src").is_dir() and not (src / "kdc").is_dir():
        return src / "src"
    return src


_MIT_FILES: dict[str, dict[str, list[str]]] = {}


def _mit_files(root: pathlib.Path) -> dict[str, list[str]]:
    """Basename → relative paths of every .c/.h/.hin/.et/.x/.y file under root."""
    key = str(root)
    if key not in _MIT_FILES:
        out: dict[str, list[str]] = {}
        for f in sorted(root.rglob("*")):
            if f.suffix in {".c", ".h", ".hin", ".et", ".x", ".y"} and f.is_file():
                out.setdefault(f.name, []).append(str(f.relative_to(root)))
        _MIT_FILES[key] = out
    return _MIT_FILES[key]


def _resolve_mit_path(files: dict[str, list[str]], cited: str) -> list[str]:
    base = cited.rsplit("/", 1)[-1]
    cands = files.get(base, [])
    if "/" in cited:
        cands = [c for c in cands if c == cited or c.endswith("/" + cited)]
    return cands


_MIT_LINES: dict[str, list[str]] = {}


def _mit_lines(path: pathlib.Path) -> list[str]:
    key = str(path)
    if key not in _MIT_LINES:
        _MIT_LINES[key] = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return _MIT_LINES[key]


# The resolution below is a port of the reference resolver
# `working/logs/w3-hygiene/s4-audit/resolve-anchors.py` (v3.2): a definition,
# never a usage; a definition starts at the comment block directly above
# its storage-class / return-type lines, with three more lines of slack.
# Keep the two in step; the audit runs the reference.
_ANCHOR_SLACK = 3


def _ref_lead_start(ls: list[str], i: int) -> int:
    """0-based start of the definition at line i: the storage-class / return-type
    lines above it and the comment block directly above those (where MIT
    documents a function and where an old cite may begin)."""
    j = i
    while (
        j > 0
        and ls[j - 1].strip()
        and not ls[j - 1].rstrip().endswith((";", "}", "{", "*/"))
        and not ls[j - 1].startswith("#")
    ):
        j -= 1
    if j > 0 and ls[j - 1].rstrip().endswith("*/"):
        k = j - 1
        while k > 0 and "/*" not in ls[k]:
            k -= 1
        if "/*" in ls[k]:
            j = k
    return j


def _ref_brace_end(ls: list[str], start: int) -> int:
    """0-based index of the first line at or after `start` that is `}` or `};` at column 0."""
    k = start
    while k < len(ls) and not re.match(r"^\}\s*;?\s*$", ls[k]):
        k += 1
    return k


def _ref_find_fn(ls: list[str], name: str) -> list[tuple[int, int]]:
    pat = re.compile(r"^(?:[A-Za-z_][\w \t*]*[ \t*])?" + re.escape(name) + r"\s*\(")
    split = re.compile(r"^(?:[A-Za-z_][\w \t*]*[ \t*])?" + re.escape(name) + r"\s*$")
    out: list[tuple[int, int]] = []
    for i, line in enumerate(ls):
        if not pat.match(line) and not (
            split.match(line) and i + 1 < len(ls) and ls[i + 1].lstrip().startswith("(")
        ):
            continue
        j, body = i, False
        while j < len(ls):
            if "{" in ls[j]:
                body = True
                break
            if ";" in ls[j]:
                break
            j += 1
        if not body:
            continue
        out.append((_ref_lead_start(ls, i) + 1, _ref_brace_end(ls, j) + 1))
    return out


def _ref_find_type(ls: list[str], name: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    head = re.compile(r"^(?:typedef\s+)?(?:struct|union|enum)\s+" + re.escape(name) + r"\b")
    tail = re.compile(r"^\}[^;]*\b" + re.escape(name) + r"\b[^;]*;")
    fnptr = re.compile(r"\(\s*\*\s*" + re.escape(name) + r"\s*\)\s*\(")
    same = re.compile(
        r"^typedef\s+(?:struct|union|enum)\s+" + re.escape(name) + r"\s+" + re.escape(name) + r"\s*;"
    )
    for i, line in enumerate(ls):
        if head.match(line):
            if "{" in line or (i + 1 < len(ls) and ls[i + 1].lstrip().startswith("{")):
                end = _ref_brace_end(ls, i)
                if end + 1 < len(ls) and same.match(ls[end + 1]):
                    end += 1  # rpcgen's `typedef struct X X;` right after the struct
                out.append((_ref_lead_start(ls, i) + 1, end + 1))
            else:
                out.append((_ref_lead_start(ls, i) + 1, i + 1))
        elif tail.match(line):
            j = i
            while j > 0 and not ls[j].startswith("typedef"):
                j -= 1
            out.append((_ref_lead_start(ls, j) + 1, i + 1))
        elif fnptr.search(line) and not line.lstrip().startswith(("*", "/*", "//")):
            j = i
            while j > 0 and j > i - 4 and not ls[j].startswith("typedef"):
                j -= 1
            k = i
            while k < len(ls) and ";" not in ls[k]:
                k += 1
            out.append((_ref_lead_start(ls, j) + 1, k + 1))
    return out


def _ref_find_data(ls: list[str], name: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    decl = re.compile(
        r"^[A-Za-z_][^;{}=()]*\b" + re.escape(name) + r"\b\s*(?:\[[^\]]*\]\s*)*\s*(?:=|;|,)"
    )
    for i, line in enumerate(ls):
        if not decl.match(line) or line.startswith(("return", "if", "else", "for", "while")):
            continue
        if "= {" in line or line.rstrip().endswith("=") or line.rstrip().endswith("{"):
            out.append((_ref_lead_start(ls, i) + 1, _ref_brace_end(ls, i) + 1))
        else:
            out.append((_ref_lead_start(ls, i) + 1, i + 1))
    return out


def _ref_find_macro_gen(ls: list[str], name: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    gen = re.compile(r"^[A-Z_][A-Z0-9_]*\(\s*" + re.escape(name) + r"\b")
    dfn = re.compile(r"^#\s*define\s+" + re.escape(name) + r"\b")
    for i, line in enumerate(ls):
        if gen.match(line):
            k = i
            while k < len(ls) and ")" not in ls[k]:
                k += 1
            out.append((i + 1, k + 1))
        elif dfn.match(line):
            k = i
            while k < len(ls) and ls[k].rstrip().endswith("\\"):
                k += 1
            out.append((i + 1, k + 1))
    return out


def _ref_find_asn1(ls: list[str], name: str) -> list[tuple[int, int]]:
    """An ASN.1 type defined by `NAME ::=` inside a comment block (MIT copies the
    module text above each DEF* group in asn1_k_encode.c): that comment block."""
    out: list[tuple[int, int]] = []
    pat = re.compile(r"(?:^|[\s*/])" + re.escape(name) + r"\s*::=")
    for i, line in enumerate(ls):
        if not pat.search(line):
            continue
        s = i
        while s > 0 and "/*" not in ls[s]:
            s -= 1
        e = i
        while e < len(ls) and "*/" not in ls[e]:
            e += 1
        out.append((s + 1, e + 1))
    return out


def _ref_find_hdr(ls: list[str], name: str) -> list[tuple[int, int]]:
    out = (
        _ref_find_macro_gen(ls, name)
        + _ref_find_type(ls, name)
        + _ref_find_fn(ls, name)
        + _ref_find_asn1(ls, name)
    )
    proto = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    etc = re.compile(
        r"^(?:error_code|ec|const|program|version|typedef|struct|union|enum|%token)\b.*\b"
        + re.escape(name)
        + r"\b"
    )
    for i, line in enumerate(ls):
        if proto.search(line) and not line.lstrip().startswith(("*", "/*", "//")):
            k = i
            while k < len(ls) and ";" not in ls[k] and "{" not in ls[k]:
                k += 1
            out.append((i + 1, k + 1))
        elif etc.match(line):
            out.append((i + 1, i + 1))
    return out


def _ref_contained(a: int, b: int, defs: list[tuple[int, int]]) -> bool:
    return any(a >= s - _ANCHOR_SLACK and b <= e and a <= b for s, e in defs)


def _anchor_resolves(lines: list[str], ext: str, symbol: str, a: int, b: int) -> bool:
    """The reference's verdict for one ranged anchor: some definition of the
    symbol's kind in this file contains the range."""
    typed = symbol.split(" ")[-1] if " " in symbol else None
    if ext == "c":
        if typed:
            tries = [_ref_find_type(lines, typed)]
        else:
            tries = [
                _ref_find_fn(lines, symbol),
                _ref_find_type(lines, symbol),
                _ref_find_data(lines, symbol),
                _ref_find_macro_gen(lines, symbol),
                _ref_find_asn1(lines, symbol),
            ]
    else:
        tries = [_ref_find_hdr(lines, typed or symbol)]
    return any(defs and _ref_contained(a, b, defs) for defs in tries)


def _enclosing_fn(lines: list[str], a: int) -> str | None:
    """Name of the column-0 C function whose definition holds line `a`, if any."""
    head = re.compile(r"^(?:[A-Za-z_][\w \t*]*[ \t*])?([A-Za-z_]\w*)\s*\(")
    for i in range(a - 1, -1, -1):
        if lines[i].startswith("}"):
            return None
        m = head.match(lines[i])
        if m and m.group(1) not in _C_KEYWORDS:
            spans = _ref_find_fn(lines, m.group(1))
            if any(s - _ANCHOR_SLACK <= a <= e for s, e in spans):
                return m.group(1)
            return None
    return None


def _is_rust_test_file(rel: pathlib.Path) -> bool:
    text = rel.as_posix()
    return "/tests/" in text or text.endswith("/tests.rs")


def mit_anchor_truth_violations(
    root: pathlib.Path | None = None, mit: pathlib.Path | None = None
) -> list[str]:
    """Anchors whose range is not inside the named MIT definition, and file
    mentions that do not name exactly one file of the MIT tree."""
    root = ROOT if root is None else root
    assert mit is not None
    files = _mit_files(mit)
    bad: list[str] = []
    for path in _rs_under(root, ("src", "tests")):
        rel = path.relative_to(root)
        is_test = _is_rust_test_file(rel)
        for lineno, comment in _comment_lines(path.read_text(encoding="utf-8")):
            where = f"{rel}:{lineno}"
            for m in _ANCHOR_HEAD.finditer(comment):
                symbol, cited = m.group(1), m.group(2)
                a, b = int(m.group(3)), int(m.group(4))
                cands = _resolve_mit_path(files, cited)
                if not cands:
                    bad.append(f"{where}: {cited} is not a file of the MIT tree")
                    continue
                if len(cands) > 1:
                    bad.append(f"{where}: {cited} is ambiguous ({', '.join(cands[:4])})")
                    continue
                ok_in = [
                    c for c in cands
                    if _anchor_resolves(_mit_lines(mit / c), c.rsplit(".", 1)[-1], symbol, a, b)
                ]
                if not ok_in:
                    lines = _mit_lines(mit / cands[0])
                    inside = _enclosing_fn(lines, a) if cands[0].endswith(".c") else None
                    why = f"range {a}-{b} is inside `{inside}`" if inside else f"range {a}-{b}"
                    bad.append(f"{where}: {why}, not inside a definition of `{symbol}` in {cands[0]}")
                    continue
                if _TEST_MIT_PATH.search(ok_in[0]) and not is_test:
                    bad.append(f"{where}: `{symbol}` is MIT test code ({ok_in[0]}) cited from src")
            rest = _ANCHOR_HEAD.sub(" ", comment)
            for f in _FILE_TOKEN.finditer(rest):
                cands = _resolve_mit_path(files, f.group(1))
                if not cands:
                    bad.append(f"{where}: {f.group(1)} is not a file of the MIT tree")
                elif len(cands) > 1:
                    bad.append(f"{where}: {f.group(1)} is ambiguous ({', '.join(cands[:4])})")
    return bad


def _check_ambiguous_pin(mit: pathlib.Path) -> None:
    files = _mit_files(mit)
    live = frozenset(n for n, paths in files.items() if len(paths) > 1)
    if live != _AMBIGUOUS_MIT_BASENAMES:
        _die(
            "_AMBIGUOUS_MIT_BASENAMES differs from the MIT tree: "
            f"missing {sorted(live - _AMBIGUOUS_MIT_BASENAMES)[:6]}, "
            f"extra {sorted(_AMBIGUOUS_MIT_BASENAMES - live)[:6]}"
        )


def check_mit_anchor_truth(
    root: pathlib.Path | None = None,
    src: pathlib.Path | None = None,
    *,
    allow: int | None = None,
) -> None:
    """Every anchor's range lies inside the named MIT definition (ledger-mit job).

    Lists every violation. Advisory while `allow` equals the live count.
    """
    if src is None:
        env = os.environ.get("KERBER_MIT_SRC")
        if not env:
            print(
                "ci-policy: KERBER_MIT_SRC unset — skipping check_mit_anchor_truth "
                "(ledger-mit job sets it)",
                file=sys.stderr,
            )
            return
        src = pathlib.Path(env)
    if not src.is_dir():
        _die(f"KERBER_MIT_SRC {src} is not a directory")
    mit = _mit_tree_root(src)
    if root is None:
        _check_ambiguous_pin(mit)
    if allow is None:
        allow = MIT_TRUTH_ALLOW
    bad = mit_anchor_truth_violations(ROOT if root is None else root, mit)
    if len(bad) != allow:
        for line in bad:
            print(f"ci-policy: anchor truth: {line}", file=sys.stderr)
        _die(f"mit anchor truth {len(bad)} != allow {allow}")


def mit_anchor_violations(root: pathlib.Path | None = None) -> list[str]:
    """Comment lines that break the R1 anchor form, one entry per line."""
    root = ROOT if root is None else root
    bad: list[str] = []
    for path in _rs_under(root, ("src", "tests")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(root)
        for lineno, comment in _comment_lines(text):
            problems = _anchor_line_problems(comment)
            if problems:
                bad.append(f"{rel}:{lineno}: {'; '.join(problems)}: {comment.strip()[:140]}")
    return bad


def check_mit_anchor_form(
    root: pathlib.Path | None = None, *, allow: int | None = None
) -> None:
    """Every MIT anchor in `//` / `///` / `//!` is the R1 one-line form.

    Advisory while `allow` equals the live count. Hard when `allow` is 0.
    """
    if allow is None:
        allow = MIT_ANCHOR_ALLOW
    bad = mit_anchor_violations(ROOT if root is None else root)
    if len(bad) != allow:
        sample = "; ".join(bad[:6])
        _die(
            f"mit anchor lines {len(bad)} != allow {allow}"
            + (f": {sample}" if sample else "")
        )


_PROCESS_TAG = re.compile(
    r"\bR[0-9]+\b"
    r"|A\u2032-[0-9]"
    r"|W0[a-f]"
    r"|W1-[A-Z]"
    r"|Round [0-9]"
    r"|parent [0-9a-f]{7}"
    r"|R[0-9]-[A-Z][0-9]+"
    r"|\bB3\b"
    r"|\bY0\b"
    r"|Z[0-9]b?\.[0-9]"
    # v2: what survived the first regex.
    r"|`(?=[0-9a-f]*[a-f])(?=[0-9a-f]*[0-9])[0-9a-f]{7,8}`"
    r"|parent-red"
    r"|Compiles at"
    r"|\bitem [0-9]+\b"
    r"|\bS[0-9]\.[0-9]"
    r"|\bZ[0-9] leftover"
    r"|\b[BF][0-9]\b"
    r"|the parent `"
    r"|(?<![\w/.-])working/"
)


def process_tag_violations(root: pathlib.Path | None = None) -> list[str]:
    """Process-history tags on `//` comments under `crates/`."""
    root = ROOT if root is None else root
    bad: list[str] = []
    for path in _rs_under(root, None):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(root)
        for lineno, comment in _comment_lines(text):
            if _PROCESS_TAG.search(comment):
                bad.append(f"{rel}:{lineno}:{comment.strip()[:160]}")
    return bad


def check_no_process_history(
    root: pathlib.Path | None = None, *, allow: int | None = None
) -> None:
    """No process-history tag in a `crates/` comment. Advisory until allow is 0."""
    if allow is None:
        allow = PROCESS_TAG_ALLOW
    bad = process_tag_violations(ROOT if root is None else root)
    if len(bad) != allow:
        sample = "; ".join(bad[:6])
        _die(
            f"process-history lines {len(bad)} != allow {allow}"
            + (f": {sample}" if sample else "")
        )


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
    check_no_case_whitelists()
    check_gate_provenance()
    check_docker_cp_cargo_target()
    check_no_host_tmp_writes()
    check_isolate_test_krb5()
    check_unit_evidence_helper()
    check_settle_helper()
    check_evidence_check_tool()
    check_ci_status_save()
    check_makefile_matches_ci()
    check_msrv_pinned()
    check_rust_cache_shared_key()
    check_workflow_hardening()
    check_prod_image_once()
    check_build_profile()
    check_env_read()
    check_peers_unavailable_convention()
    check_samba_kdc_respawn()
    check_log_arity()
    check_hygiene_diff_self_test()
    check_hygiene_body_diff_self_test()
    check_hygiene_fn_diff_self_test()
    check_py_move_self_test()
    check_hygiene_inventory_cfg_test()
    check_policy_module_attrs()
    check_autotests_registered()
    check_kcm_stop_before_run()
    check_prod_gate_tcpdump_cleanup()
    check_gate_common_sourced()
    check_no_gate_cargo_build()
    check_trace_dst()
    check_stock_boots_per_job()
    check_gate_wall()
    check_sleep_ratchet()
    check_sleep_classifiers_agree()
    check_ci_budgets()
    check_need_bins_strict()
    check_testing_doc_budgets()
    check_red_at_sha_inject()
    check_red_at_sha_overlay_order()
    check_red_at_sha_target_trap()
    if "--checkpoint" in sys.argv[1:]:
        # W1-Z Z3.4: the local evidence tree is gitignored, so only the
        # checkpoint runner (`ci-policy.py --checkpoint`) can see it.
        check_no_red_target_trees()
    check_working_gitignored()
    check_ledger_layout()
    check_ledger_proof_column()
    check_diffsend_cases()
    check_gate_unit_index()
    check_doc_file_cites()
    check_doc_links()
    check_changelog_headings()
    check_docs_size()
    check_gate_documented()
    check_capture_env_only()
    check_golden_dump_unique_keys()
    check_ledger_tally()
    check_ledger_anchors()
    check_ledger_mit_cites()
    check_claim_audit()
    check_mit_anchor_form()
    check_mit_anchor_truth()
    check_no_process_history()
    print("ci-policy: ok")


if __name__ == "__main__":
    main()
