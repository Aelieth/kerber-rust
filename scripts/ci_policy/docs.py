"""Checks on the public docs: file cites, links, CHANGELOG headings and size."""

from __future__ import annotations

import pathlib
import re

from .common import ROOT, _die


CHANGELOG_HEADINGS_ALLOW = 0
DOCS_SIZE_ALLOW = 0
DOCS_SIZE_LIMIT = 100 * 1024
CHANGELOG_UNRELEASED_MAX_BYTES = 25000

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
        # docs/parity is history (option A): a retired path there is not a live cite.
        if doc.startswith("docs/parity/"):
            continue
        for m in _DOC_FILE_CITE_RE.finditer(text):
            rel = m.group(1)
            if any(ch in rel for ch in "*?{}<>"):
                continue
            if not (root / rel).exists():
                missing.append(f"{doc}: `{rel}`")
    if missing:
        _die("doc file cite(s) do not exist: " + "; ".join(missing[:8]))


_SCRIPT_CITE_RE = re.compile(r"scripts/(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\.[A-Za-z0-9]+")


def check_cited_scripts(
    texts: dict[str, str] | None = None,
    root: pathlib.Path | None = None,
) -> None:
    """Every scripts/ file named under docs/ exists. Parity is included."""
    root = pathlib.Path(root) if root is not None else ROOT
    if texts is None:
        texts = {
            str(path.relative_to(root)): path.read_text(encoding="utf-8")
            for path in doc_files(root)
            if str(path.relative_to(root)).startswith("docs/")
        }
    missing: list[str] = []
    for doc, text in sorted(texts.items()):
        if not doc.startswith("docs/"):
            continue
        for match in _SCRIPT_CITE_RE.finditer(text):
            rel = match.group(0)
            if not (root / rel).is_file():
                missing.append(f"{doc}: `{rel}`")
    if missing:
        _die("cited script(s) do not exist: " + "; ".join(missing[:8]))


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


def _unreleased_section_len(text: str) -> int | None:
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.rstrip("\r\n") == "## [Unreleased]"), None)
    if start is None:
        return None
    end = next((j for j in range(start + 1, len(lines)) if lines[j].startswith("## [")), len(lines))
    return len("".join(lines[start:end]).encode())


def check_docs_size(
    root: pathlib.Path | None = None, *, allow: int | None = None, changelog_max: int | None = None
) -> None:
    """No docs/**/*.md is over DOCS_SIZE_LIMIT (advisory while `allow` is the live count), and the
    ## [Unreleased] section of CHANGELOG.md is not over its ceiling."""
    root = ROOT if root is None else root
    allow = DOCS_SIZE_ALLOW if allow is None else allow
    changelog_max = CHANGELOG_UNRELEASED_MAX_BYTES if changelog_max is None else changelog_max
    over = [
        f"{p.relative_to(root)} {p.stat().st_size}"
        for p in sorted((root / "docs").rglob("*.md"))
        if p.stat().st_size > DOCS_SIZE_LIMIT
    ] if (root / "docs").is_dir() else []
    if len(over) != allow:
        _die(f"{len(over)} docs file(s) over {DOCS_SIZE_LIMIT} bytes, allow {allow}: " + "; ".join(over))
    log = root / "CHANGELOG.md"
    if not log.is_file():
        return
    n = _unreleased_section_len(log.read_text(encoding="utf-8"))
    if n is None:
        _die("CHANGELOG.md has no ## [Unreleased] section")
    if n > changelog_max:
        _die(f"CHANGELOG.md [Unreleased] is {n} bytes, over its ceiling {changelog_max}")
