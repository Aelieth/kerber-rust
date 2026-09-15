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

import importlib.util
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile

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
    "client-differential-gate.sh",
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
    "doc",
)

FULL_RUN_SCHEDULED = (
    "cargo nextest run --workspace --release",
    "cargo test --workspace --locked",
)

DOCUMENTED_STUBS = frozenset(
    {
        "gss-sspi-gate.sh",
        "ad-mit-trust-gate.sh",
        "kadmin-gate.sh",  # local wrapper; CI runs rust+mit+both steps
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
    return hits


def check_isolate_test_krb5(text: str | None = None) -> None:
    """Unit-test isolate helper must not write host `/tmp`."""
    if text is None:
        path = ROOT / "crates/krb5-config/src/lib.rs"
        if not path.is_file():
            _die("missing crates/krb5-config/src/lib.rs")
        text = path.read_text()
    if "fn isolate_test_krb5" not in text:
        _die("isolate_test_krb5 missing")
    start = text.find("fn isolate_scratch_dir")
    fn = text.find("pub fn isolate_test_krb5")
    if start < 0 or start > fn:
        start = fn
    if fn < 0:
        _die("isolate_test_krb5 missing")
    end = text.find("\npub fn ", fn + 1)
    chunk = text[start : end if end > 0 else None]
    if re.search(r"temp_dir\(\)|/tmp/kerber-test-krb5", chunk):
        _die("isolate_test_krb5 writes host /tmp")
    test_start = text.find("#[cfg(test)]")
    if test_start >= 0 and "temp_dir()" in text[test_start:]:
        _die("cfg(test) writes host /tmp via temp_dir()")


def check_no_host_tmp_writes(text: str | None = None, name: str = "gate.sh") -> None:
    """No host `/tmp/` writes in gate scripts outside KERBER_SCRATCH defaults."""
    if text is not None:
        hits = host_tmp_write_lines(text)
        if hits:
            _die(f"{name} host /tmp write at line {hits[0]}")
        return
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        hits = host_tmp_write_lines(path.read_text())
        if hits:
            _die(f"{path.name} host /tmp write at line {hits[0]}")


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
        for clause in (c.strip() for c in proof.split(";") if c.strip()):
            proposed = bool(re.search(r"\bpropose(?:d)?\b", clause, re.I))
            for m in _LEDGER_DIFFSEND.finditer(clause):
                case = m.group(1)
                if case not in DIFFSEND_CASES and not proposed:
                    _die(
                        f"docs/mit-parity-ledger.md:{i} proof names diffsend `{case}` "
                        "which is not a live case (use proposed)"
                    )
            for m in _LEDGER_GATE.finditer(clause):
                name = m.group(1)
                if not name.endswith(".sh"):
                    name = name + ".sh"
                if name not in existing and not proposed:
                    _die(
                        f"docs/mit-parity-ledger.md:{i} proof names {name} "
                        "which is not in scripts/ (use proposed)"
                    )


_LEDGER_CASES_HDR = re.compile(
    r"The [\w-]+ live `diffsend` cases are ((?:`[^`]+`(?:,\s*)?)+)",
    re.S,
)


DIFFSEND_SRC = ROOT / "crates/krb5-protocol/examples/diffsend.rs"


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
        if not LEDGER.is_file():
            _die("missing docs/mit-parity-ledger.md")
        ledger = LEDGER.read_text()
    gate_path = SCRIPTS / "differential-gate.sh"
    if gate is None:
        if not gate_path.is_file():
            _die("missing scripts/differential-gate.sh")
        gate = gate_path.read_text()
    if src is None:
        if not DIFFSEND_SRC.is_file():
            _die("missing crates/krb5-protocol/examples/diffsend.rs")
        src = DIFFSEND_SRC.read_text()
    hdr = _LEDGER_CASES_HDR.search(ledger)
    if not hdr:
        _die("docs/mit-parity-ledger.md missing live diffsend cases list")
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
    r"(?:\s*\+\s*A4\s+(\d+))?(?:\s*\+\s*B1\s+(\d+))?"
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
        diffsend = ROOT / "crates/krb5-protocol/examples/diffsend.rs"
        if diffsend.is_file():
            parts.append(diffsend.read_text(errors="replace"))
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
    """Row counts under `## A1` / `## A2` / `## A3` / `## A4` / `## B1` headings."""
    counts = {"A1": 0, "A2": 0, "A3": 0, "A4": 0, "B1": 0}
    section: str | None = None
    for line in text.splitlines():
        m = re.match(r"^## (A1|A2|A3|A4|B1)\b", line)
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


def check_ledger_tally(text: str | None = None) -> None:
    """Header verdict counts must equal a recount of the table cells."""
    if text is None:
        if not LEDGER.is_file():
            _die("missing docs/mit-parity-ledger.md")
        text = LEDGER.read_text()
    got = recount_ledger_verdicts(text)
    exact = _HEADER_EXACT.search(text)
    absent = _HEADER_ABSENT.search(text)
    if not exact or not absent:
        _die("docs/mit-parity-ledger.md missing verdict header tally")
    want = {
        "exact": int(exact.group(1)),
        "stricter-documented": int(exact.group(2)),
        "deviation": int(exact.group(3)),
        "absent": int(absent.group(1)),
        "deferred": int(absent.group(2)),
    }
    if got != want:
        _die(
            "docs/mit-parity-ledger.md tally header "
            f"{want} != recount {got}"
        )
    total = _HEADER_TOTAL.search(text)
    if not total:
        _die("docs/mit-parity-ledger.md missing A1/A2/A3 total line")
    header_n = int(total.group(1))
    a1, a2, a3 = (int(total.group(i)) for i in (2, 3, 4))
    a4 = int(total.group(5) or 0)
    b1 = int(total.group(6) or 0)
    n = sum(got.values())
    parts = a1 + a2 + a3 + a4 + b1
    if header_n != n or header_n != parts:
        _die(
            f"docs/mit-parity-ledger.md total {header_n} "
            f"= A1 {a1} + A2 {a2} + A3 {a3} + A4 {a4} + B1 {b1} != recount {n}"
        )
    sec = recount_ledger_sections(text)
    want_sec = {"A1": a1, "A2": a2, "A3": a3, "A4": a4, "B1": b1}
    if sec != want_sec:
        _die(
            f"docs/mit-parity-ledger.md section split "
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


def _src_index() -> tuple[dict[str, dict[str, pathlib.Path]], dict[str, list[str]]]:
    """`crates/<crate>/src/**/*.rs` keyed by crate then basename."""
    by_crate: dict[str, dict[str, pathlib.Path]] = {}
    by_base: dict[str, list[str]] = {}
    crates = ROOT / "crates"
    if not crates.is_dir():
        return by_crate, by_base
    for crate_dir in sorted(crates.iterdir()):
        src = crate_dir / "src"
        if not crate_dir.is_dir() or not src.is_dir():
            continue
        crate = crate_dir.name
        for p in src.rglob("*.rs"):
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


def check_ledger_anchors(text: str | None = None) -> None:
    """Every rust-site `file.rs symbol[:N]` resolves to one item; exact rows verify their claim.

    The MIT column must cite a MIT file (or say n/a / absent). An `exact` row's
    e_text status words (backticked, or bare `WORD_WORD` identifiers) must occur
    in the anchored item body; a row with no such word must name a proof unit,
    diffsend case or gate that exists. A symbol defined more than once in a file
    needs `:N` inside the intended definition.
    """
    checking_file = text is None
    if text is None:
        if not LEDGER.is_file():
            _die("missing docs/mit-parity-ledger.md")
        text = LEDGER.read_text()
    by_crate, by_base = _src_index()
    n_quote = 0
    for i, line in enumerate(text.splitlines(), 1):
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7 or cols[5] == "verdict":
            continue
        site, etext = cols[3], cols[4]
        where = f"docs/mit-parity-ledger.md:{i}"
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
        _die("docs/mit-parity-ledger.md executed no quote checks")


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


def check_ledger_mit_cites(text: str | None = None, src: pathlib.Path | None = None) -> None:
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
    if text is None:
        text = LEDGER.read_text()
    names, idents, strings = _mit_index(src)
    for i, line in enumerate(text.splitlines(), 1):
        if not line.startswith("|") or "MIT file:line" in line or line.startswith("| ---"):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7 or cols[5] == "verdict":
            continue
        where = f"docs/mit-parity-ledger.md:{i}"
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
    if "actions/workflows/" not in text:
        _die("ci-status.py must fetch /actions/workflows/<file>/runs")
    if "branch=main" in text:
        _die("ci-status.py must not pin fetch_runs to branch=main")
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
    if mod.is_fixture_annotation({"title": "", "path": "scripts/kadmin-gate.sh"}):
        _die("is_fixture_annotation must not filter product gates")
    if mod.workflow_file("peers") != "peers.yml":
        _die("workflow_file must map peers -> peers.yml")
    if mod.job_duration_s(
        {"started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:01:05Z"}
    ) != 65:
        _die("job_duration_s must use started_at/completed_at")


def check_makefile_matches_ci() -> None:
    """Makefile `safety` cargo order matches the ci.yml `test` job; doc is a sibling."""
    makefile = ROOT / "Makefile"
    if not makefile.is_file():
        _die("missing Makefile")
    mf = makefile.read_text()
    ci_path = WORKFLOWS / "ci.yml"
    if not ci_path.is_file():
        _die("missing .github/workflows/ci.yml")
    ci_wf = Workflow(ci_path, ci_path.read_text())
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


def check_rust_cache_shared_key() -> None:
    """Every Swatinem/rust-cache step uses shared-key: kerber; cargo jobs have a cache."""
    needle = "shared-key: kerber"
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        n_cache = text.count("Swatinem/rust-cache")
        n_key = text.count(needle)
        if n_cache and n_key != n_cache:
            _die(f"{path.name}: rust-cache steps must set shared-key: kerber ({n_key}/{n_cache})")
        wf = Workflow(path, text)
        for name, job in wf.jobs.items():
            if "cargo " not in job.body and "cargo\n" not in job.body:
                continue
            if "Swatinem/rust-cache" not in job.body:
                _die(f"{path.name} job {name} runs cargo but has no rust-cache")
            if needle not in job.body:
                _die(f"{path.name} job {name} rust-cache missing shared-key: kerber")


def check_prod_image_once() -> None:
    """ci.yml builds harness/prod/Dockerfile exactly once (mit-image)."""
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    n = ci.count("harness/prod/Dockerfile")
    builds = ci.count("docker build -f harness/prod/Dockerfile")
    if builds != 1:
        _die(f"ci.yml must docker build harness/prod/Dockerfile exactly once, found {builds}")
    if "upload-artifact" in ci and "mit-kdc-image" in ci:
        _die("ci.yml must not upload-artifact the MIT tar (cache restore only)")
    wf = Workflow(WORKFLOWS / "ci.yml", ci)
    mit = wf.jobs.get("mit-image")
    if mit is None or "harness/prod/Dockerfile" not in mit.body:
        _die("mit-image must build/save harness/prod/Dockerfile")
    if not re.search(r"hashFiles\([^)]*harness/prod/Dockerfile", ci):
        _die("cache key must hashFiles harness/prod/Dockerfile")


def check_build_profile() -> None:
    """[profile.dev] line-tables-only + split-debuginfo; lld rustflags."""
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if 'debug = "line-tables-only"' not in cargo:
        _die('Cargo.toml [profile.dev] must set debug = "line-tables-only"')
    if 'split-debuginfo = "unpacked"' not in cargo:
        _die('Cargo.toml [profile.dev] must set split-debuginfo = "unpacked"')
    cfg = ROOT / ".cargo" / "config.toml"
    if not cfg.is_file():
        _die("missing .cargo/config.toml")
    text = cfg.read_text(encoding="utf-8")
    if "fuse-ld=lld" not in text:
        _die(".cargo/config.toml must pass -fuse-ld=lld")
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    if "apt-get install" not in ci or " lld" not in ci:
        _die("ci.yml must apt-get install lld")


def check_env_read() -> None:
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
    env_re = re.compile(r"(?m)^\s{2,8}([A-Z][A-Z0-9_]+):\s")
    corpus: list[str] = []
    for path in sorted((ROOT / "scripts").rglob("*")):
        if path.suffix in {".sh", ".py", ".rs", ".c"} and path.is_file():
            corpus.append(path.read_text(encoding="utf-8", errors="replace"))
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        corpus.append(path.read_text(encoding="utf-8", errors="replace"))
    blob = "\n".join(corpus)
    for wf_path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = wf_path.read_text(encoding="utf-8")
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
                    _die(f"{wf_path.name} sets {name} but no script/test reads it")


def check_trace_dst() -> None:
    """Gate captures must not default into tests/traces (S5)."""
    for name in ("kdc-gate.sh", "client-gate.sh"):
        path = SCRIPTS / name
        text = path.read_text(encoding="utf-8")
        if 'KERBER_TRACE_DST:-$ROOT/tests/traces' in text:
            _die(f"{name} must not default TRACE_DST to tests/traces")
        if "KERBER_SCRATCH" not in text or "TRACE_DST" not in text:
            _die(f"{name} must default TRACE_DST under KERBER_SCRATCH")


def check_gate_common_sourced() -> None:
    """Every gate sources gate-common.sh; no private log()/cleanup(); no cargo build."""
    common = SCRIPTS / "lib" / "gate-common.sh"
    if not common.is_file():
        _die("missing scripts/lib/gate-common.sh")
    ctext = common.read_text(encoding="utf-8")
    for needle in (
        "log()",
        "die()",
        "unavailable()",
        "need_bins",
        "need_image",
        "gate_wall_s=",
        "wait_port_in",
        "wait_udp_in",
        "wait_tcp_bound_in",
        "wait_gone_in",
        "wait_pid_gone",
        "stock_mit_kdc",
        "shell_container",
        "mit_live_guard",
        "mit_conf_restore",
        "rm -rf /tmp/db-*",
        "kdb5_util destroy",
        "krb5.conf.kerber-stock",
    ):
        if needle not in ctext:
            _die(f"gate-common.sh missing {needle}")
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        text = path.read_text(encoding="utf-8")
        if "scripts/lib/gate-common.sh" not in text:
            _die(f"{path.name} must source scripts/lib/gate-common.sh")
        if re.search(r"^log\(\)", text, re.M):
            _die(f"{path.name} still defines a private log()")
        if re.search(r"^cleanup\(\)", text, re.M):
            _die(f"{path.name} still defines a private cleanup()")
        if re.search(r"\bcargo\s+build\b", text):
            _die(f"{path.name} must not run cargo build (use need_bins)")
        check_gate_cargo_leftover(text, path.name)
        check_gate_no_exit_trap(text, path.name)
        if path.name in ("kadmin-rust-gate.sh", "kadmin-rust-acl-gate.sh", "kadmin-mit-gate.sh", "kadmin-both-gate.sh") and "kadmin-glob-cells.sh" not in text:
            _die(f"{path.name} must source scripts/lib/kadmin-glob-cells.sh")
        if path.name in ("kadmin-rust-gate.sh", "kadmin-mit-gate.sh"):
            if re.search(r'wait_port_in\s+"\$NAME(_MIT)?"\s+1749', text):
                _die(f"{path.name} tamper proxy is single-accept; use wait_tcp_bound_in, not wait_port_in")
            if "wait_tcp_bound_in" not in text:
                _die(f"{path.name} must wait_tcp_bound_in for the integrity tamper proxy")
        check_kadmin_split_snaps(text, path.name)
        if path.name == "kcm-gate.sh":
            check_kcm_need_image(text)
        if re.search(r"krb5kdc -n >/tmp/mit-kdc.log 2>&1 & cat", text):
            _die(f"{path.name} must wait_log for krb5kdc -n, not cat the log immediately")
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
    if ci_text.count("boot-stock-mit.sh") < 2:
        _die("ci.yml must boot stock MIT in both harness and mit-extra")
    if ci_text.count("boot-shell.sh") < 2:
        _die("ci.yml must boot a shared shell in both harness and mit-extra")


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


def check_gate_no_exit_trap(text: str, name: str = "gate.sh") -> None:
    """Gates must not replace gate-common's EXIT trap (register_cleanup)."""
    if re.search(r"^\s*trap\b.*\bEXIT\b", text, re.M):
        _die(f"{name} must not set an EXIT trap (use register_cleanup)")


def check_build_bins_examples() -> None:
    """Job-level build-bins.sh must produce every example the gates docker-cp."""
    path = SCRIPTS / "lib" / "build-bins.sh"
    if not path.is_file():
        _die("missing scripts/lib/build-bins.sh")
    text = path.read_text(encoding="utf-8")
    for ex in ("ccache-probe", "diffsend", "kprop-expired-apreq", "loadgen"):
        if ex not in text:
            _die(f"build-bins.sh must build example {ex}")


def check_gate_cargo_leftover(text: str, name: str = "gate.sh") -> None:
    """S2 converter residue: a cargo-build argument line with no cargo build."""
    if re.search(r"^\s+-p\s+krb5-", text, re.M):
        _die(f"{name} still has leftover cargo-build argument lines")


def check_no_gate_cargo_build() -> None:
    check_gate_common_sourced()


def check_peers_unavailable_convention() -> None:
    """peers.yml maps gate exit 2 to step success; live kinit/kvno failures are exit 1."""
    wrapper = SCRIPTS / "lib" / "run-peer-step.sh"
    if not wrapper.is_file():
        _die("missing scripts/lib/run-peer-step.sh")
    wtext = wrapper.read_text(encoding="utf-8")
    if "[ \"$rc\" -eq 2 ]" not in wtext and "[ \"$rc\" -eq 2 ]" not in wtext.replace(" ", ""):
        if 'rc" -eq 2' not in wtext:
            _die("run-peer-step.sh must treat exit 2 as unavailable (not a job failure)")
    peers = (WORKFLOWS / "peers.yml").read_text(encoding="utf-8")
    if "run-peer-step.sh" not in peers:
        _die("peers.yml must wrap peer gates with run-peer-step.sh")
    ad = (SCRIPTS / "samba-ad-gate.sh").read_text(encoding="utf-8")
    if 'unavailable "kinit' in ad:
        _die("samba-ad-gate.sh kinit failure against a listening KDC must exit 1, not unavailable")
    if "exit 1" not in ad:
        _die("samba-ad-gate.sh must exit 1 on live kinit/kvno failure")


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
    inj = "crates/krb5-types/tests/k3_parse_deltat.rs"
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
    check_ledger_anchors(_row("krb5-kdc/plugins.rs advertise:129", verdict="absent"))
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
    check_s4_shared_boots(
        "boot-stock-mit.sh\nboot-shell.sh\nboot-stock-mit.sh\nboot-shell.sh\n"
    )
    _must_die(check_s4_shared_boots, "boot-shell.sh\nboot-shell.sh\n")
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
    # A'-3 R34: _must_die(check_isolate_test_krb5) unless a temp_dir() isolate helper is refused.
    check_isolate_test_krb5(
        "fn isolate_scratch_dir() -> PathBuf {\n    PathBuf::from(\"target\").join(\"test-krb5\")\n}\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
    )
    _must_die(
        check_isolate_test_krb5,
        "pub fn isolate_test_krb5() {\n"
        "    let path = std::env::temp_dir().join(\"kerber-test-krb5-1.conf\");\n"
        "}\n",
    )
    _must_die(
        check_isolate_test_krb5,
        "fn isolate_scratch_dir() -> PathBuf { PathBuf::from(\"target/test-krb5\") }\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
        "#[cfg(test)]\nmod tests {\n    fn f() { let _ = std::env::temp_dir(); }\n}\n",
    )
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
    diffsend = ROOT / "crates/krb5-protocol/examples/diffsend.rs"
    if diffsend.is_file():
        scan(diffsend.read_text(), "crates/krb5-protocol/examples/diffsend.rs")
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
    # R2-T7: the differential compare itself (diff.rs) and the shared gate
    # helpers are where a case-name whitelist would most plausibly reappear, so
    # scan them too, not only the driver and the top-level gates.
    for path in sorted((ROOT / "crates/krb5-protocol/src").glob("*.rs")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
    for path in sorted((SCRIPTS / "lib").glob("*.sh")):
        scan(path.read_text(), str(path.relative_to(ROOT)))


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
    check_rust_cache_shared_key()
    check_prod_image_once()
    check_build_profile()
    check_env_read()
    check_peers_unavailable_convention()
    check_gate_common_sourced()
    check_trace_dst()
    check_red_at_sha_inject()
    check_red_at_sha_overlay_order()
    check_red_at_sha_target_trap()
    if "--checkpoint" in sys.argv[1:]:
        # W1-Z Z3.4: the local evidence tree is gitignored, so only the
        # checkpoint runner (`ci-policy.py --checkpoint`) can see it.
        check_no_red_target_trees()
    check_working_gitignored()
    check_ledger_proof_column()
    check_diffsend_cases()
    check_golden_dump_unique_keys()
    check_ledger_tally()
    check_ledger_anchors()
    check_ledger_mit_cites()
    check_claim_audit()
    print("ci-policy: ok")


if __name__ == "__main__":
    main()
