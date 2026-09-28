"""Checks on `.github/workflows/*.yml`, the Makefile, nextest and the CI budgets."""

from __future__ import annotations

import pathlib
import re

from .common import GITIGNORE, NEXTEST_TOML, ROOT, SCRIPTS, WORKFLOWS, _die

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


def _scripts_in_jobs(jobs: dict[str, Job], script: str) -> list[Job]:
    return [j for j in jobs.values() if script in j.scripts]


def check_ci(wf: Workflow) -> None:
    """ci.yml runs per push and is not scheduled; only SOFT_PER_PUSH_JOBS are continue-on-error, and all
    exist; every TIMEOUT_JOBS job has timeout-minutes; each FAIL_RED_PER_PUSH gate runs on a job that is
    not continue-on-error, and no NIGHTLY_BLOCKING gate runs per push; the MIT image is cached
    (actions/cache keyed on hashFiles of harness/Dockerfile, docker save / load); nextest --release
    stays in full-test.yml."""
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
    """Each NIGHTLY_BLOCKING gate runs on a scheduled workflow, in a job that is not continue-on-error
    and has timeout-minutes."""
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


def _fold_continuations(text: str) -> str:
    return re.sub(r"\\\n\s*", " ", text)


def check_nextest_profile(workflows: list[Workflow]) -> None:
    """Every `cargo nextest run` in a workflow passes `--profile ci`, and a workflow that names nextest
    runs it."""
    for wf in workflows:
        folded = _fold_continuations(wf.text)
        cmds = _NEXTEST_RUN.findall(folded)
        if "nextest" in folded and not cmds:
            _die(f"{wf.path.name} mentions nextest but has no cargo nextest run")
        for cmd in cmds:
            if "--profile ci" not in cmd:
                _die(f"{wf.path.name} cargo nextest run missing --profile ci")


def check_ci_nextest_split(wf: Workflow) -> None:
    """ci.yml's test job builds with `cargo nextest --no-run` first, writes the nextest junit.xml and
    uploads it as an artifact."""
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
    """ci.yml runs no `cargo test --workspace` / `--all` but the doctest pass (`--doc`): the unit
    suite runs once, under nextest."""
    if wf.path.name != "ci.yml":
        return
    folded = _fold_continuations(wf.text)
    # `cargo test --workspace --doc` is the doctest runner (nextest never runs
    # doctests). Any other workspace `cargo test` re-runs the unit suite.
    allowed = _CARGO_TEST_WS_DOC.sub("", folded)
    if _CARGO_TEST_WS.search(allowed) or _CARGO_TEST_ALL.search(allowed):
        _die(f"{wf.path.name} must not run cargo test --workspace/--all on per-push")


def check_all_timeouts(workflows: list[Workflow]) -> None:
    """Every workflow has a job, and every job has timeout-minutes."""
    for wf in workflows:
        if not wf.jobs:
            _die(f"{wf.path.name} has no jobs")
        for name, job in wf.jobs.items():
            if not job.timeout_minutes:
                _die(f"{wf.path.name} job {name} has no timeout-minutes")


def check_full_run_scheduled(workflows: list[Workflow]) -> None:
    """Each FULL_RUN_SCHEDULED command runs on a scheduled workflow, in a job that is not
    continue-on-error."""
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


def check_working_gitignored() -> None:
    """.gitignore ignores working/ (the local evidence, never committed) and __pycache__/."""
    if not GITIGNORE.is_file():
        _die("missing .gitignore")
    text = GITIGNORE.read_text()
    if "/working" not in text and "working/" not in text:
        _die(".gitignore must ignore working/ (red-at-HEAD artefacts)")
    if "__pycache__/" not in text:
        _die(".gitignore must ignore __pycache__/")


def check_nextest() -> None:
    """.config/nextest.toml sets a slow-timeout with terminate-after, so a hung test ends the run."""
    if not NEXTEST_TOML.is_file():
        _die("missing .config/nextest.toml")
    text = NEXTEST_TOML.read_text()
    if "slow-timeout" not in text:
        _die(".config/nextest.toml has no slow-timeout")
    if "terminate-after" not in text:
        _die(".config/nextest.toml slow-timeout must terminate hangs")


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
