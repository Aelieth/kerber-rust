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


# A ### heading outside the set: a group name must be the whole heading (`### Added in W3` is outside),
# a how-to heading starts `How to `.
_CHANGELOG_HEADING = re.compile(
    r"^### (?!(?:Security|Added|Changed|Fixed|Tests and CI|Deprecated|Removed)[ \t]*$|How to )", re.M
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
_DOC_TICK = re.compile(r"`([^`]+)`")
_GATE_HELPER_REF = re.compile(r"scripts/(?:lib|oracle)/[\w.-]+|harness/[\w./-]+\.(?:py|sh|c|conf|env)")
_GATE_PATH_TOKEN = re.compile(r"(?:scripts/)?[\w.-]+-gate\.sh")


def gate_script_text(root: pathlib.Path, rel: str, seen: set[pathlib.Path] | None = None) -> str:
    """A gate script's text followed by every `scripts/lib`, `scripts/oracle` or `harness/` file it names,
    recursively: the files it sources or runs."""
    seen = set() if seen is None else seen
    path = root / rel
    if path in seen or not path.is_file():
        return ""
    seen.add(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return "\n".join([text] + [gate_script_text(root, m, seen) for m in _GATE_HELPER_REF.findall(text)])


def gate_doc_token_misses(root: pathlib.Path | None = None) -> list[str]:
    """Backticked tokens of each docs/gates.md row's asserts cell that appear in neither its gate script nor a
    file that script sources or runs (gate paths and `ci:` / `docs/` / `crates/` tokens are names, not claims)."""
    root = ROOT if root is None else root
    doc = root / "docs" / "gates.md"
    bad: list[str] = []
    for line in doc.read_text(encoding="utf-8").splitlines() if doc.is_file() else []:
        m = _GATE_ROW.match(line)
        if not m:
            continue
        cells = _split_ledger_row(line)
        text = gate_script_text(root, f"scripts/{m.group(1)}")
        for tok in _DOC_TICK.findall(cells[-1]):
            if _GATE_PATH_TOKEN.fullmatch(tok) or tok.startswith(("ci:", "docs/", "crates/")):
                continue
            if tok not in text:
                bad.append(f"{m.group(1)}: `{tok}`")
    return bad


def check_gate_doc_tokens(root: pathlib.Path | None = None, *, allow: int | None = None) -> None:
    """Every backticked token of a docs/gates.md asserts cell is in its gate or a helper it sources or runs
    (pinned at GATE_DOC_TOKEN_ALLOW)."""
    allow = GATE_DOC_TOKEN_ALLOW if allow is None else allow
    bad = gate_doc_token_misses(root)
    if len(bad) != allow:
        _die(f"docs/gates.md: {len(bad)} asserts token(s) in no script, allow {allow}: " + "; ".join(bad[:8]))


# Docs cite a gate's cell by its section tag, not by a script line number: line numbers move whenever a script
# does. A script cite is `scripts/<path>.(sh|py|c):N[-M][,N-M…]`, the same with a bare name that is a file under
# scripts/ (lib/, oracle/, ci_policy/ included), a bare `:N[-M]` after such a line cite in the same table cell
# or prose line, or a bare range `:N-M` / `:N,M` after any script path there (a single `:N` after a bare path is
# a port or a time, not a cite). A `file.c:N` MIT source cite and its `:N` continuations are the anchor checks' class and are not counted,
# nor is `t_vfy_increds.c:N` without its scripts/ prefix (the oracle shares an MIT test's name). The unit is
# cites. A section cite is a backticked `==== <text> ====` after a script path in the same cell or line; it must
# occur in that script. A function cite is a backticked `name()` right after a script path; that script must
# define `name()`.
SCRIPT_LINE_CITE_ALLOW = 0
_CITE_FILE = re.compile(
    r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.(?:sh|py|c|h|rs|md|toml|yml|yaml|conf|env))"
    r"(:[0-9]+(?:-[0-9]+)?(?:,\s?[0-9]+(?:-[0-9]+)?)*)?"
)
_CITE_CONT = re.compile(r"(?<![\w.)\]])(:[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*)(?![\w:])")
_CITE_SECTION = re.compile(r"`(==== .+? ====)`")
_CITE_FUNCTION = re.compile(r"`([A-Za-z_][\w]*)\(\)`")
_BARE_MIT_NAMES = frozenset({"t_vfy_increds.c"})


def _cite_scan_files(root: pathlib.Path) -> list[pathlib.Path]:
    names = [root / "README.md", root / "CONTRIBUTING.md", root / "scripts" / "README.md"]
    docs_dir = root / "docs"
    return [p for p in names if p.is_file()] + (sorted(docs_dir.rglob("*.md")) if docs_dir.is_dir() else [])


def scripts_by_name(root: pathlib.Path) -> dict[str, pathlib.Path]:
    """Every scripts/**/*.(sh|py|c) by its file name (the first in sorted order when two share one)."""
    scripts = root / "scripts"
    by_name: dict[str, pathlib.Path] = {}
    for p in sorted(scripts.rglob("*")) if scripts.is_dir() else []:
        if p.suffix in (".sh", ".py", ".c") and p.is_file() and "__pycache__" not in p.parts:
            by_name.setdefault(p.name, p)
    return by_name


def line_script_cites(
    root: pathlib.Path, line: str, by_name: dict[str, pathlib.Path]
) -> tuple[list[str], list[tuple[str, pathlib.Path, bool]]]:
    """One doc line's script line cites, and its section and function cites as (text, script, resolved in that
    script)."""
    cites: list[str] = []
    sections: list[tuple[str, pathlib.Path, bool]] = []
    # a table row's cells split at an unescaped `|` (the ledger's rule): `\|` inside a cell is text
    for cell in re.split(r"(?<!\\)\|", line) if line.lstrip().startswith("|") else [line]:
        events = [(m.start(), "file", m) for m in _CITE_FILE.finditer(cell)]
        events += [(m.start(), "cont", m) for m in _CITE_CONT.finditer(cell)]
        events += [(m.start(), "section", m) for m in _CITE_SECTION.finditer(cell)]
        events += [(m.start(), "function", m) for m in _CITE_FUNCTION.finditer(cell)]
        current: pathlib.Path | None = None
        last_end = -1  # where the last script path ended: a function cite must follow it directly
        in_script = False  # after a script cite with a line number: a bare `:N` continues it
        for _pos, kind, m in sorted(events, key=lambda e: e[0]):
            if kind == "file":
                name = m.group(1)
                if name.startswith("scripts/"):
                    current = root / name
                elif "/" not in name and name in by_name and name not in _BARE_MIT_NAMES:
                    current = by_name[name]
                else:
                    current = None
                in_script = current is not None and bool(m.group(2))
                last_end = m.end() + 1 if current is not None else -1  # past the closing backtick
                if in_script:
                    cites.append(m.group(0))
            elif kind == "cont":
                ranged = "-" in m.group(1) or "," in m.group(1)
                if (in_script or (current is not None and ranged)) and not cell[: m.start()].endswith(
                    tuple("0123456789")
                ):
                    cites.append(m.group(1))
            elif kind == "function":
                if current is not None and cell[last_end:m.start()].strip() == "":
                    text = current.read_text(encoding="utf-8", errors="replace") if current.is_file() else ""
                    name = m.group(1)
                    ok = re.search(rf"^\s*(?:function\s+)?{re.escape(name)}\s*\(\)", text, re.M) is not None
                    sections.append((f"{name}()", current, ok))
            elif current is not None:
                text = current.read_text(encoding="utf-8", errors="replace") if current.is_file() else ""
                sections.append((m.group(1), current, m.group(1) in text))
    return cites, sections


def script_cite_findings(root: pathlib.Path | None = None) -> tuple[list[str], list[str]]:
    """(script line cites, unresolved section cites), each as `doc:line: text`."""
    root = ROOT if root is None else root
    by_name = scripts_by_name(root)
    cites: list[str] = []
    unresolved: list[str] = []
    for doc in _cite_scan_files(root):
        rel = doc.relative_to(root)
        fence: str | None = None
        for i, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            m = _MD_FENCE.match(line)
            if m:
                fence = m.group(2) if fence is None else (None if m.group(2) == fence else fence)
                continue
            if fence is not None:
                continue
            line_cites, sections = line_script_cites(root, line, by_name)
            cites += [f"{rel}:{i}: {c}" for c in line_cites]
            unresolved += [f"{rel}:{i}: {t} not in {sc.relative_to(root)}" for t, sc, ok in sections if not ok]
    return cites, unresolved


def check_no_script_line_cites(root: pathlib.Path | None = None, *, allow: int | None = None) -> None:
    """No script line cites in the docs (pinned at SCRIPT_LINE_CITE_ALLOW cites), and every section cite resolves
    in the script it names (hard at 0)."""
    allow = SCRIPT_LINE_CITE_ALLOW if allow is None else allow
    cites, unresolved = script_cite_findings(root)
    if unresolved:
        _die(f"{len(unresolved)} section cite(s) that do not resolve: " + "; ".join(unresolved[:8]))
    if len(cites) != allow:
        _die(f"{len(cites)} script line cite(s) in the docs, allow {allow}: " + "; ".join(cites[:8]))


# S5 doc checks: advisory at the live count until the commit that clears each.
CHANGELOG_HEADINGS_ALLOW = 0
DOCS_SIZE_ALLOW = 0
GATE_DOC_ALLOW = 0
GATE_DOC_TOKEN_ALLOW = 0
DOCS_SIZE_LIMIT = 60 * 1024
# The CHANGELOG's size (235,552 bytes when it was set) plus 9,000 bytes for the next 25 bullets at 360
# bytes (the median bullet is 341); re-based only by a tool: commit ahead of the bullets it allows.
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
    for where, name, value in tier_budget_pairs(testing_text):
        want = budget["run_wall"] if name == "[push].run_wall" else budget["jobs"].get(name)
        if want is None or int(value) != int(want):
            _die(f"docs/testing.md {where} says `{name}` {value}, ci-budget.toml says {want}")


_TIER_BULLET = re.compile(r"^- \*\*(Tier [12])\*\*(.*?)(?=^- \*\*Tier |^\s*$)", re.M | re.S)
_TIER_PAIR = re.compile(r"`([\w.\[\]-]+)`\s+\(?([0-9]+)")


def tier_budget_pairs(testing_text: str) -> list[tuple[str, str, str]]:
    """(tier, name, number) for every `` `name` N `` in docs/testing.md's Tier 1 and Tier 2 bullets
    (`[push].run_wall` (N s) included)."""
    return [(m.group(1), n, v) for m in _TIER_BULLET.finditer(testing_text) for n, v in _TIER_PAIR.findall(m.group(2))]


# A working-plan section named in a tracked doc: `§ Deferred`, or any `§ "…"`. RFC section
# citations (`RFC 4120 §5.4.1`) are not plan sections.
_PLAN_SECTION = re.compile(r"§\s*Deferred|§\s*[\"\u201c][^\"\u201d]+[\"\u201d]")


def check_no_plan_section_names(root: pathlib.Path | None = None) -> None:
    """No public doc (doc_files) names a section of the working plan."""
    root = ROOT if root is None else root
    hits = []
    for path in doc_files(root):
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if _PLAN_SECTION.search(line):
                hits.append(f"{path.relative_to(root)}:{i}")
    if hits:
        _die(f"{len(hits)} working-plan section name(s) in the public docs: " + ", ".join(hits[:8]))
