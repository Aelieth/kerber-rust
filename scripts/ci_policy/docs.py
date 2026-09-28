"""Checks on the public docs: file cites, links, CHANGELOG headings and size, docs/gates.md."""

from __future__ import annotations

import pathlib
import re

from .common import ROOT, WORKFLOWS, _die
from .ledger import _split_ledger_row
from .workflows import BUDGET_REQUIRED_JOBS, DOCUMENTED_STUBS, Workflow, parse_budget_toml


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
# S5 doc checks: advisory at the live count until the commit that clears each.
CHANGELOG_HEADINGS_ALLOW = 0
DOCS_SIZE_ALLOW = 0
GATE_DOC_ALLOW = 0
DOCS_SIZE_LIMIT = 60 * 1024
# The CHANGELOG at the S5 close (235,552 bytes) plus 9,000 bytes for S6's bullets: one per PR item
# across S6.1-S6.3, at most 25 at 360 bytes (the median bullet is 341); re-based only by a tool:
# commit at the start of a swath that adds bullets.
CHANGELOG_MAX_BYTES = 244552


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
