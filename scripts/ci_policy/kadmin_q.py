"""The direct-kadmin-query judge: every kadmin query a gate or a scripts/lib file runs goes through
lib/kadmin-q.sh, bar the keyed container-script sites."""

from __future__ import annotations

import re

from .common import SCRIPTS, _die
from .shell import _join_shell_continuations


# Direct `kadmin` / `kadmin.local` / `krb5-kadmin(-local)` queries (`-q`) in the gates; they belong
# behind the scripts/lib helpers. The rule counts one logical line (continuations
# joined, comments dropped), heredoc bodies included, the query's own `-q`. Pinned at the live count.
KADMIN_Q_DIRECT_ALLOW = 0
# The same count over scripts/lib/*.sh but lib/kadmin-q.sh itself (the runners' home); pinned exactly.
KADMIN_Q_DIRECT_LIB_ALLOW = 0
# The queries that cannot come from scripts/lib: each runs inside a container script (a `docker exec … sh -c`
# body or a heredoc fed to one) between in-container steps, where no host function exists. Keyed by
# (gate, the section's `==== title ====`, the number of sites, the reason); an exception matches only a query
# inside a container script of that section, exactly that many, and one whose sites are gone is an error.
KADMIN_Q_EXCEPTIONS: tuple[tuple[str, str, int, str], ...] = (
    ("capaths-transit-gate.sh", "MIT kdb5_util A/B/C", 1,
     "the heredoc's `kad` runs kadmin.local -r per realm with that realm's KRB5_KDC_PROFILE in one container shell"),
    ("kadmin-local-gate.sh", "local setstr does not clobber concurrent kadmind create", 1,
     "the kadmind addprinc must land while the fifo-fed krb5-kadmin-local session holds the store"),
    ("kadmin-local-gate.sh", "setstr does not clobber concurrent kadmind create", 1,
     "the kadmind addprinc must land while the fifo-fed krb5-kadmin-local session holds the store"),
)
_KADMIN_CMD = re.compile(r"(?:^|[^\w.-])(?:[\w./$-]*/)?(?:krb5-)?kadmin(?:\.local|-local)?(?=\s)")
_GATE_SECTION = re.compile(r"""^\s*echo\s+(["'])====\s*(.*?)\s*====\1\s*$""")
_CONTAINER_SH = re.compile(r"""\bdocker\s+exec\b.*?\b(?:ba)?sh\s+-c\s+(['"])""")


def _strip_word_comment(line: str) -> str:
    """Drop a `#` comment that starts a word outside quotes (so `${#a[@]}` and `$#` stay)."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote and line[i - 1] != "\\":
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t;"):
            return line[:i]
    return line


def _segment_end(code: str, start: int) -> int:
    """The first `|`, `;`, `&&` or unmatched `)` after `start` at its nesting level."""
    quote, depth, i = None, 0, start
    while i < len(code):
        ch = code[i]
        if quote:
            if ch == quote and code[i - 1] != "\\":
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and (ch in "|;" or code.startswith("&&", i)):
            return i
        i += 1
    return len(code)


def _quote_close(text: str, quote: str, start: int = 0) -> int:
    """The index of the quote that ends a `quote`-quoted string running from `start`, or -1 past the line."""
    if quote == "'":
        return text.find("'", start)
    i = start
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i
        i += 1
    return -1


def kadmin_direct_queries(text: str) -> list[tuple[int, str | None, bool]]:
    """(line, the section title it sits under or None, inside a container script) of every direct kadmin query
    in a script. A container script is a heredoc opened on a `docker exec` line, or the quoted body of a
    `docker exec … sh -c` that runs past its line."""
    out: list[tuple[int, str | None, bool]] = []
    section: str | None = None
    heredoc: str | None = None
    heredoc_in = False
    body_quote: str | None = None
    for ln, raw in enumerate(_join_shell_continuations(text).split("\n"), 1):
        if heredoc is not None:
            if re.match(rf"^\s*{re.escape(heredoc)}\s*['\")\s;]*$", raw):
                heredoc = None
                continue
            body = (0, len(raw)) if heredoc_in else None
            code = raw
        elif body_quote is not None:
            end = _quote_close(raw, body_quote)
            body = (0, len(raw) if end < 0 else end)
            code = raw
        else:
            m = _GATE_SECTION.match(raw)
            if m:
                section = m.group(2)
            code = _strip_word_comment(raw)
            m = _CONTAINER_SH.search(code)
            body = (m.end(), len(code)) if m and _quote_close(code, m.group(1), m.end()) < 0 else None
        if code.strip():
            for m in _KADMIN_CMD.finditer(code):
                seg = code[m.end():_segment_end(code, m.end())]
                if re.search(r"(?:^|\s)-q(?:\s|$|\")", seg):
                    out.append((ln, section, body is not None and body[0] <= m.start() < body[1]))
        if heredoc is not None:
            continue
        if body_quote is not None:
            if _quote_close(raw, body_quote) >= 0:
                body_quote = None
            continue
        if body is not None:
            body_quote = _CONTAINER_SH.search(code).group(1)
            continue
        h = re.search(r"<<(-?)\s*['\"]?([A-Za-z_]\w*)['\"]?", code)
        if h and code[h.start():h.start() + 3] != "<<<":
            heredoc = h.group(2)
            heredoc_in = re.search(r"\bdocker\s+exec\b", code[:h.start()]) is not None
    return out


def check_kadmin_q_via_lib(files: dict[str, str] | None = None, allow: int | None = None,
                           exceptions: tuple[tuple[str, str, int, str], ...] | None = None,
                           lib_files: dict[str, str] | None = None, lib_allow: int | None = None) -> None:
    """No gate runs a kadmin query itself: every `kadmin -q` / `kadmin.local -q` goes through a scripts/lib
    helper (pinned at KADMIN_Q_DIRECT_ALLOW), bar the container-script sites KADMIN_Q_EXCEPTIONS keys. The
    other scripts/lib files run theirs through lib/kadmin-q.sh too (pinned at KADMIN_Q_DIRECT_LIB_ALLOW)."""
    if files is None:
        files = {p.name: p.read_text(encoding="utf-8") for p in sorted(SCRIPTS.glob("*-gate.sh"))}
    allow = KADMIN_Q_DIRECT_ALLOW if allow is None else allow
    exceptions = KADMIN_Q_EXCEPTIONS if exceptions is None else exceptions
    keyed = {(gate, title): n for gate, title, n, _ in exceptions}
    matched: dict[tuple[str, str], int] = dict.fromkeys(keyed, 0)
    hits = []
    for name, body in files.items():
        if not name.endswith("-gate.sh"):
            continue
        for ln, section, inside in kadmin_direct_queries(body):
            key = (name, section or "")
            if inside and key in keyed:
                matched[key] += 1
            else:
                hits.append(f"{name}:{ln}")
    wrong = [f"{g} '{t}' matched {matched[(g, t)]} site(s), keyed {n}" for (g, t), n in keyed.items()
             if matched[(g, t)] != n]
    if wrong:
        _die("kadmin query exception(s) out of step with their sites: " + "; ".join(wrong))
    if len(hits) != allow:
        _die(f"{len(hits)} direct kadmin queries in the gates, allow {allow}: " + ", ".join(hits[:8]))
    if lib_files is None:
        lib_files = {p.name: p.read_text(encoding="utf-8") for p in sorted((SCRIPTS / "lib").glob("*.sh"))}
    lib_allow = KADMIN_Q_DIRECT_LIB_ALLOW if lib_allow is None else lib_allow
    lib_hits = [f"lib/{name}:{ln}" for name, body in lib_files.items() if name != "kadmin-q.sh"
                for ln, _section, _inside in kadmin_direct_queries(body)]
    if len(lib_hits) != lib_allow:
        _die(f"{len(lib_hits)} direct kadmin queries in scripts/lib, allow {lib_allow}: " + ", ".join(lib_hits[:8]))
