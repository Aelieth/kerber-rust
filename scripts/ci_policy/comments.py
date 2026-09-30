"""Checks on `crates/` comments: MIT anchor form and truth, process-history tags."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import sys

from .common import ROOT, SCRIPTS, _die
# S4. A commit that changes a live hit count updates the matching
# constant in that commit. Hard means 0.
MIT_ANCHOR_ALLOW = 0
MIT_TRUTH_ALLOW = 0
PROCESS_TAG_ALLOW = 0


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


# The resolution below is a port of the audit's reference resolver (v3.2,
# kept outside the repository): a definition,
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
    r"|\bfails at [0-9a-f]{7,8}\b"
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


# Process-history tags in docs/**/*.md prose and table cells: the W1 and review-round names, the Z
# close-out steps, "item N", the A′ list, the swath names (`W3-S1`), the W0 passes (`W0d`), the tracks
# (`Track A`), the parenthesised phase labels (`(A5)`, `(D2)`), a pass name `C<n>`, a bare workstream
# name (`W3`; a hyphenated one is the W1-/W-S arms'), a phase pair (`A2/A5`), a bare phase or audit label
# (`D2`, `E3`, `J4`; not after a `/`, not a review-round's `R2-D1`, not the whole `(D2)`), and a batch name
# (`Batch D`). The arms are disjoint, so each has its own fixture line. Not process history, and not
# counted: the roadmap's stage names G1–G9 and eras ("Era II", "Era III"), which docs/stages.md defines,
# and the ledger's section keys A1–A5 / B1 (the check_ledger_* keys). A bare `A<n>` phase label is
# indistinguishable from a section key by shape and is not judged. The count is lines with a tag, pinned
# exactly.
DOCS_PROCESS_TAG_ALLOW = 0
_DOCS_PROCESS_TAG = re.compile(
    r"\bW1-[A-Z]|\bR[0-9]-[A-Z][0-9]+|\bZ[0-9]+(?:\.[0-9]+)?b?\b|\bitem [0-9]+\b|A\u2032-[0-9]"
    r"|\bW[0-3]-S[0-9]+|\bW0[a-f]\b|\bTrack [A-C]\b|\((?:A|D)[0-9]\)|\bC[1-9]\b|\bW[0-3]\b(?!-)"
    r"|\bA[0-9]/A[0-9]\b|(?<!/)(?<![A-Z][0-9]-)\b[DEJ][0-9]\b(?![./0-9])(?!(?<=\(D[0-9])\))|\bBatch [A-Z]\b"
)


def docs_process_tag_lines(root: pathlib.Path | None = None) -> list[str]:
    """`path:line` of every docs/**/*.md line outside a code fence that carries a process tag.

    A backticked `==== … ====` section cite that resolves verbatim in the script named before it (the cites
    judge's rule) is the script's text, quoted faithfully, and is not counted; unresolved, it counts. This arm is
    temporary: 31 gate sections carry a tag in their own echo text, and the commit that renames them deletes it.
    """
    from .docs import line_script_cites, scripts_by_name

    root = ROOT if root is None else root
    by_name = scripts_by_name(root)
    out = []
    for path in sorted((root / "docs").rglob("*.md")) if (root / "docs").is_dir() else []:
        fence = False
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if line.startswith("```"):
                fence = not fence
            elif not fence and _DOCS_PROCESS_TAG.search(line):
                for text, _script, ok in line_script_cites(root, line, by_name)[1]:
                    if ok:
                        line = line.replace(f"`{text}`", "``")
                if _DOCS_PROCESS_TAG.search(line):
                    out.append(f"{path.relative_to(root)}:{i}")
    return out


def check_no_docs_process_tags(root: pathlib.Path | None = None, *, allow: int | None = None) -> None:
    """The docs arm of check_no_process_history: no process tag in docs/** prose or table cells
    (pinned at DOCS_PROCESS_TAG_ALLOW)."""
    allow = DOCS_PROCESS_TAG_ALLOW if allow is None else allow
    hits = docs_process_tag_lines(root)
    if len(hits) != allow:
        _die(f"{len(hits)} docs line(s) with a process tag, allow {allow}: " + ", ".join(hits[:8]))
