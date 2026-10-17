"""Checks on workflow timeouts and hardening, the Makefile, nextest and the MSRV pin."""

from __future__ import annotations

import pathlib
import re

from .common import GITIGNORE, NEXTEST_TOML, ROOT, WORKFLOWS, _die

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

def check_all_timeouts(workflows: list[Workflow]) -> None:
    """Every workflow has a job, and every job has timeout-minutes."""
    for wf in workflows:
        if not wf.jobs:
            _die(f"{wf.path.name} has no jobs")
        for name, job in wf.jobs.items():
            if not job.timeout_minutes:
                _die(f"{wf.path.name} job {name} has no timeout-minutes")


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
    preamble: str | None = None,
) -> None:
    """rust-version is MSRV in both manifests; rust-toolchain.toml pins one
    exact stable release (`X.Y.Z`, bumped by hand) and the rust-preamble's
    default toolchain installs that same release, so a new Rust release cannot
    change a build; each msrv job installs MSRV and pins it with
    RUSTUP_TOOLCHAIN (the toolchain file outranks `rustup default`, which is all
    the action sets)."""
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
    pin = re.search(r'(?m)^channel\s*=\s*"(\d+\.\d+\.\d+)"', toolchain_toml)
    if not pin:
        _die('rust-toolchain.toml must pin channel = "X.Y.Z" (an exact stable release)')
    if preamble is None:
        preamble = RUST_PREAMBLE_FILE.read_text(encoding="utf-8") if RUST_PREAMBLE_FILE.is_file() else ""
    default = re.search(r"(?ms)^  toolchain:\n(?:    .*\n)*?    default:\s*\"?([^\"\s]+)\"?\s*$", preamble)
    if not default or default.group(1) != pin.group(1):
        _die(
            f"rust-preamble's default toolchain {default.group(1) if default else None} != "
            f"rust-toolchain.toml channel {pin.group(1)}"
        )
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

CONCURRENCY_WORKFLOWS = ("ci.yml", "fuzz.yml")
_USES_PINNED = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
SHELLCHECK_CMD = (
    "shellcheck -S style scripts/*.sh scripts/lib/*.sh harness/*.sh harness/prod/*.sh dist/*.sh"
    " harness/field/*.sh harness/field/lib/*.sh harness/field/scenarios/*.sh"
)


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
    ci.yml runs the fail-red shellcheck job over SHELLCHECK_CMD's script globs
    (the field harness's included) with a `.shellcheckrc` that follows sources,
    on a ShellCheck it installs itself by
    version and sha256 (the runner's package differs by two minor versions and
    hundreds of notes), and the Makefile fallback image names that same version."""
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
        }
    image = f"koalaman/shellcheck:{ver.group(1)}"
    for name, text in shellcheck_pins.items():
        if image not in text:
            _die(f"{name} must run the shellcheck image {image} (the version ci.yml installs)")
