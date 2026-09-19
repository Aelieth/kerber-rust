#!/usr/bin/env python3
"""Compare product fn bodies between two trees (SHA or directory).

Product-code sibling of hygiene-body-diff.py. Extracts every non-test
`fn` (free, impl and trait methods; keyed
`crate<TAB>module::path::[impl-header::]name`), links old → new by the key and
a keyed `--moves` map (`old_key = new_key`, RHS-as-LHS rejected,
many-to-one needs `merged:`), compares bodies after
a comparison normaliser that keeps string, byte-string, raw-string
and char literal contents (whitespace and comments are still
normalised outside literals), and classifies each pair
`identical` / `vis-only` (private → `pub(crate)` / `pub(super)`, or
those two restricted forms, with a byte-identical rest)
/ `doc-only` / `changed`. The compared blob includes the attribute
block above the fn. Reports `added` and `removed`. A key collision
never drops a body.

Fails on any `changed`, `added` or `removed` not in `--accept` (keyed,
blob-pinned, unused entry red). `--split old_key = new_a + new_b + …`
checks that the concatenated new bodies equal the old body modulo
per-split `--glue` lines (whole lines present in the new bodies and
absent from the old; unused glue is red).

Usage:
  python3 scripts/hygiene-fn-diff.py --old SHA --new SHA \\
      [--moves map.txt] [--accept map.txt] [--split map.txt] \\
      [--glue LINE] [--roots DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _hygiene_diff():
    import importlib.util

    path = ROOT / "scripts" / "hygiene-diff.py"
    spec = importlib.util.spec_from_file_location("hygiene_diff", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load scripts/hygiene-diff.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _inventory():
    import importlib.util

    path = ROOT / "scripts" / "lib" / "hygiene_inventory.py"
    spec = importlib.util.spec_from_file_location("hygiene_inventory", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load scripts/lib/hygiene_inventory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_HD = _hygiene_diff()
_INV = _inventory()
load_map = _HD.load_map
strip_merged = _HD.strip_merged
strip_noncode = _INV.strip_noncode
scan_items = _INV.scan_items
cfg_test_files_in_pkg = _INV.cfg_test_files_in_pkg
FN_RE = _INV.FN_RE

NON_FN_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:(?P<kind>const|static)\s+(?:mut\s+)?(?!fn\b)(?P<csname>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<kind2>enum|struct|trait|type)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"|macro_rules!\s+(?P<macro>[A-Za-z_][A-Za-z0-9_]*))"
)
TEST_ATTR_RE = re.compile(r"#\[\s*(?:tokio::test|test)\b")
ACCEPT_LINE_RE = re.compile(
    r"^(?P<old>.+?)\s*=\s*(?P<new>.+?)\s*\|\s*"
    r"sha256:(?P<oldh>[0-9a-f]{64})\s*\|\s*"
    r"sha256:(?P<newh>[0-9a-f]{64})\s*\|\s*"
    r"(?P<reason>.+)$"
)
SPLIT_LINE_RE = re.compile(r"^(?P<old>.+?)\s*=\s*(?P<rhs>.+)$")
VIS_RE = re.compile(r"\bpub(?:\([^)]*\))?\s+")
RESTRICTED_VIS_RE = re.compile(r"\bpub\([^)]*\)\s+")


class FnDiffError(Exception):
    """A product fn changed, appeared, or vanished without an accept pin."""


def materialize(spec: str, dest: pathlib.Path, git_cwd: pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(spec)
    if p.is_dir():
        return p.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "archive", spec],
        cwd=git_cwd,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"git archive {spec} failed: {proc.stderr[-400:]}")
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
        tar.extractall(dest, filter="data")
    return dest


def load_keyed_id_map(path: pathlib.Path | None, kind: str) -> dict[str, str]:
    """`old_key = [merged:]new_key`; keys are crate<TAB>path."""
    if path is not None and path.is_file():
        seen_lhs: set[str] = set()
        in_stamp = True
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if in_stamp and _HD._STAMP_LINE_RE.match(line):
                continue
            in_stamp = False
            if "=" not in line:
                continue
            left = line.split("=", 1)[0].strip()
            if left in seen_lhs:
                raise SystemExit(f"{kind} duplicate LHS: {left}")
            seen_lhs.add(left)
    raw = load_map(path, "=")
    mapping: dict[str, str] = {}
    for left, right in raw.items():
        if "\t" not in left:
            raise SystemExit(f"{kind} LHS must be crate<TAB>path: {left!r}")
        rhs = strip_merged(right)
        if "\t" not in rhs:
            raise SystemExit(f"{kind} RHS must be crate<TAB>path: {right!r}")
        mapping[left] = right
    lhs = set(mapping)
    for left, right in mapping.items():
        rhs = strip_merged(right)
        if rhs in lhs:
            raise SystemExit(f"{kind} RHS is also a LHS: {rhs}")
    targets: dict[str, list[tuple[str, str]]] = {}
    for left, right in mapping.items():
        targets.setdefault(strip_merged(right), []).append((left, right))
    for rhs, ents in targets.items():
        if len(ents) > 1:
            for left, right in ents:
                if not right.startswith("merged:"):
                    raise SystemExit(f"many-to-one {rhs} needs merged: (from {left})")
    return {left: strip_merged(right) for left, right in mapping.items()}


def load_accept(path: pathlib.Path | None) -> dict[str, dict[str, str]]:
    """Keyed `old = new | sha256:old | sha256:new | reason`."""
    if path is None or not path.is_file():
        return {}
    out: dict[str, dict[str, str]] = {}
    in_stamp = True
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if in_stamp and _HD._STAMP_LINE_RE.match(line):
            continue
        in_stamp = False
        m = ACCEPT_LINE_RE.match(line)
        if not m:
            raise SystemExit(f"bad --accept line: {line!r}")
        old, new = m.group("old").strip(), m.group("new").strip()
        if "\t" not in old or "\t" not in new:
            raise SystemExit(f"--accept keys must be crate<TAB>path: {line!r}")
        if old in out:
            raise SystemExit(f"--accept duplicate LHS: {old}")
        out[old] = {
            "new": new,
            "old_hash": m.group("oldh"),
            "new_hash": m.group("newh"),
            "reason": m.group("reason").strip(),
        }
    return out


def load_splits(
    path: pathlib.Path | None, extra: list[str]
) -> dict[str, list[str]]:
    """`old_key = new_a + new_b + …`."""
    rows: list[str] = []
    if path is not None and path.is_file():
        in_stamp = True
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if in_stamp and _HD._STAMP_LINE_RE.match(line):
                continue
            in_stamp = False
            rows.append(line)
    rows.extend(extra)
    out: dict[str, list[str]] = {}
    for line in rows:
        m = SPLIT_LINE_RE.match(line)
        if not m:
            raise SystemExit(f"bad --split line: {line!r}")
        old = m.group("old").strip()
        parts = [p.strip() for p in m.group("rhs").split("+") if p.strip()]
        if "\t" not in old or not parts or any("\t" not in p for p in parts):
            raise SystemExit(f"--split keys must be crate<TAB>path: {line!r}")
        if old in out:
            raise SystemExit(f"--split duplicate LHS: {old}")
        if len(parts) < 2:
            raise SystemExit(f"--split rejects a single-element RHS: {line!r}")
        if len(parts) != len(set(parts)):
            raise SystemExit(f"--split duplicate part: {line!r}")
        out[old] = parts
    lhs = set(out)
    for old, parts in out.items():
        for p in parts:
            if p in lhs:
                raise SystemExit(f"--split RHS is also a LHS: {p}")
    return out


def module_path(rel: str) -> tuple[str, str]:
    parts = rel.split("/")
    if parts[0] == "crates" and len(parts) >= 2:
        crate = parts[1]
        rest = parts[3:] if len(parts) > 3 else []
    else:
        crate = parts[0]
        rest = parts[1:]
    if not rest or rest in (["lib.rs"], ["main.rs"]):
        return crate, ""
    if rest[-1] == "mod.rs":
        rest = rest[:-1]
    elif rest[-1].endswith(".rs"):
        rest = rest[:-1] + [rest[-1][:-3]]
    return crate, "::".join(rest)


def fn_key(crate: str, module: str, ty: str | None, name: str) -> str:
    bits = [p for p in (module, ty, name) if p]
    return f"{crate}\t{'::'.join(bits)}"


def inner_body(src: str) -> str:
    i = src.find("{")
    if i < 0:
        return src
    return src[i + 1 : src.rfind("}")]


def signature_of(src: str) -> str:
    i = src.find("{")
    return src if i < 0 else src[:i]


def _ident_prev(src: str, i: int) -> bool:
    if i <= 0:
        return False
    return src[i - 1].isalnum() or src[i - 1] == "_"


def _scan_quoted(src: str, i: int) -> int:
    """Index past a `"…"` / `b"…"` starting at the opening quote."""
    n = len(src)
    j = i + 1
    while j < n:
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == '"':
            return j + 1
        j += 1
    return n


def _scan_raw(src: str, i: int) -> int | None:
    """Index past `r"…"`, `r#"…"#`, `br"…"` starting at `r` (or `b` of `br`)."""
    n = len(src)
    j = i
    if src[j] == "b":
        j += 1
        if j >= n or src[j] != "r":
            return None
    if j >= n or src[j] != "r":
        return None
    if _ident_prev(src, i):
        return None
    j += 1
    hashes = 0
    while j < n and src[j] == "#":
        hashes += 1
        j += 1
    if j >= n or src[j] != '"':
        return None
    close = '"' + "#" * hashes
    k = src.find(close, j + 1)
    return n if k < 0 else k + len(close)


def _scan_char(src: str, i: int) -> int | None:
    """Index past `'x'` / `b'x'` / `'\\n'`; None for a lifetime `'a`."""
    n = len(src)
    j = i
    if src[j] == "b":
        j += 1
        if j >= n or src[j] != "'":
            return None
        if _ident_prev(src, i):
            return None
    elif src[j] != "'":
        return None
    nxt = src[j + 1] if j + 1 < n else ""
    if nxt == "\\":
        k = src.find("'", j + 2)
        if 0 < k <= j + 12:
            return k + 1
        return None
    if j + 2 < n and src[j + 2] == "'":
        return j + 3
    return None


def compare_norm(src: str) -> str:
    """Collapse whitespace and comments; keep literal contents.

    Separate from the brace scanner's `strip_noncode`, which blanks
    string and char bodies so an e_text edit would compare equal.
    """
    out: list[str] = []
    pending_space = False
    i, n = 0, len(src)

    def emit_space() -> None:
        nonlocal pending_space
        pending_space = True

    def emit(text: str) -> None:
        nonlocal pending_space
        if pending_space and out:
            out.append(" ")
        pending_space = False
        out.append(text)

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            third = src[i + 2] if i + 2 < n else ""
            j = src.find("\n", i)
            j = n if j < 0 else j
            if third in "/!":
                emit(src[i:j])
            else:
                emit_space()
            i = j
            continue
        if c == "/" and nxt == "*":
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
            i = j
            emit_space()
            continue
        raw_at = i if c == "r" else (i if c == "b" and nxt == "r" else None)
        if raw_at is not None:
            end = _scan_raw(src, raw_at)
            if end is not None:
                emit(src[raw_at:end])
                i = end
                continue
        if c == "b" and nxt == '"':
            end = _scan_quoted(src, i + 1)
            emit(src[i:end])
            i = end
            continue
        if c == '"':
            end = _scan_quoted(src, i)
            emit(src[i:end])
            i = end
            continue
        if c in "'b":
            end = _scan_char(src, i)
            if end is not None:
                emit(src[i:end])
                i = end
                continue
        if c.isspace():
            emit_space()
            i += 1
            continue
        emit(c)
        i += 1
    return "".join(out).strip()


def blob_hash(src: str) -> str:
    return hashlib.sha256(compare_norm(src).encode("utf-8")).hexdigest()


def vis_kind_and_rest(sig: str) -> tuple[str, str]:
    """Split a signature into vis kind and the rest (byte-identical check)."""
    m = VIS_RE.search(sig)
    if not m:
        return "private", sig
    token = m.group(0)
    kind = "pub" if token.startswith("pub ") or token == "pub" else "restricted"
    if token.startswith("pub("):
        kind = "restricted"
    return kind, sig[: m.start()] + sig[m.end() :]


def strip_restricted_vis(src: str) -> str:
    """Drop `pub(crate)` / `pub(super)` / `pub(in …)` tokens. Bare `pub` stays."""
    return RESTRICTED_VIS_RE.sub("", src)


def _strip_doc_lines(src: str) -> str:
    kept: list[str] = []
    for ln in src.splitlines():
        s = ln.strip()
        if s.startswith("///") or s.startswith("//!"):
            continue
        kept.append(ln)
    return "\n".join(kept)


def classify(old_src: str, new_src: str) -> str:
    if compare_norm(old_src) == compare_norm(new_src):
        return "identical"
    if compare_norm(_strip_doc_lines(old_src)) == compare_norm(_strip_doc_lines(new_src)):
        return "doc-only"
    if compare_norm(strip_restricted_vis(old_src)) == compare_norm(strip_restricted_vis(new_src)):
        return "vis-only"
    return "changed"


IMPL_START_RE = re.compile(r"^\s*(?:unsafe\s+)?impl\b")
MOD_NEST_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)


def _norm_header(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _impl_header_at(lines: list[str], line_1: int) -> str | None:
    """Innermost `impl …` header covering 1-based line (full header, not just Type)."""
    stack: list[tuple[int, str]] = []
    depth = 0
    pending: list[str] | None = None
    pending_depth = 0
    for i, raw in enumerate(lines, 1):
        if pending is not None:
            pending.append(raw)
            if "{" in raw:
                head = " ".join(pending)
                stack.append((pending_depth, _norm_header(head[: head.find("{")])))
                pending = None
        elif IMPL_START_RE.match(raw):
            if "{" in raw:
                stack.append((depth, _norm_header(raw[: raw.find("{")])))
            else:
                pending = [raw]
                pending_depth = depth
        if i == line_1:
            return stack[-1][1] if stack else None
        depth += raw.count("{") - raw.count("}")
        while stack and stack[-1][0] >= depth:
            stack.pop()
    return None


def _inline_mod_at(lines: list[str], line_1: int) -> str:
    """`mod name { … }` nesting covering 1-based line."""
    stack: list[tuple[int, str]] = []
    depth = 0
    for i, raw in enumerate(lines, 1):
        m = MOD_NEST_RE.match(raw)
        if m:
            stack.append((depth, m.group(1)))
        if i == line_1:
            return "::".join(name for _d, name in stack)
        depth += raw.count("{") - raw.count("}")
        while stack and stack[-1][0] >= depth:
            stack.pop()
    return ""


def _attr_doc_start(raw_lines: list[str], decl_line: int) -> int:
    """0-based index of the attribute / doc block above a 1-based fn line."""
    idx = decl_line - 2
    start = decl_line - 1
    while idx >= 0:
        s = raw_lines[idx].strip()
        if not s:
            idx -= 1
            continue
        if s.startswith("///") or s.startswith("//!") or s.startswith("#["):
            start = idx
            idx -= 1
            continue
        if s.startswith("#") or s.endswith(",") or s == "]" or s.endswith(")]"):
            start = idx
            idx -= 1
            continue
        break
    return start


def _has_test_attr(raw_lines: list[str], decl_line: int) -> bool:
    idx = decl_line - 2
    while idx >= 0:
        s = raw_lines[idx].strip()
        if not s:
            idx -= 1
            continue
        if s.startswith("#["):
            if TEST_ATTR_RE.search(s):
                return True
            idx -= 1
            continue
        break
    return False


def scan_non_fn(code: str) -> list[tuple[int, int, str, str]]:
    """(start, end, kind, name) for const/static/enum/struct/trait/type/macro_rules; 1-based."""
    lines = code.split("\n")

    def find_term(li: int, ci: int) -> tuple[int, bool]:
        depth_paren = depth_brack = 0
        while li < len(lines):
            s = lines[li]
            while ci < len(s):
                ch = s[ci]
                if ch == "(":
                    depth_paren += 1
                elif ch == ")":
                    depth_paren -= 1
                elif ch == "[":
                    depth_brack += 1
                elif ch == "]":
                    depth_brack -= 1
                elif ch == "{" and depth_paren <= 0 and depth_brack <= 0:
                    return li, True
                elif ch == ";" and depth_paren <= 0 and depth_brack <= 0:
                    return li, False
                ci += 1
            li += 1
            ci = 0
        return len(lines) - 1, False

    def find_close(li: int, ci: int) -> int:
        depth = 0
        while li < len(lines):
            s = lines[li]
            while ci < len(s):
                if s[ci] == "{":
                    depth += 1
                elif s[ci] == "}":
                    depth -= 1
                    if depth == 0:
                        return li
                ci += 1
            li += 1
            ci = 0
        return len(lines) - 1

    items: list[tuple[int, int, str, str]] = []
    for li, s in enumerate(lines):
        m = NON_FN_RE.match(s)
        if not m:
            continue
        kind = m.group("kind") or m.group("kind2") or "macro_rules"
        name = m.group("csname") or m.group("name") or m.group("macro")
        end_li, braced = find_term(li, m.end())
        if braced:
            end_li = find_close(end_li, lines[end_li].find("{"))
        items.append((li + 1, end_li + 1, kind, name))
    return items


def extract(
    root: pathlib.Path, roots: list[str] | None = None
) -> dict[str, dict[str, str]]:
    """key → {src, file, name, kind}."""
    found: dict[str, dict[str, str]] = {}
    roots = roots or ["crates"]
    src_test: set[str] = set()
    crates = root / "crates"
    if crates.is_dir():
        for pdir in sorted(p for p in crates.iterdir() if p.is_dir()):
            prefix = pdir.relative_to(root).as_posix()
            for rel in cfg_test_files_in_pkg(pdir):
                src_test.add(f"{prefix}/{rel}")
    files: list[pathlib.Path] = []
    for top in roots:
        base = root / top
        if base.is_dir():
            files.extend(base.rglob("*.rs"))
        elif base.is_file() and base.suffix == ".rs":
            files.append(base)
    for path in sorted(files):
        rel = path.relative_to(root).as_posix()
        if "/target/" in f"/{rel}/" or "/tests/" in f"/{rel}/" or "/benches/" in f"/{rel}/":
            continue
        if "/krb5-testkit/" in f"/{rel}/":
            continue
        if rel.startswith("crates/") and "/src/" not in f"/{rel}/":
            continue
        if rel in src_test:
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw_lines = raw.splitlines()
        code = strip_noncode(raw)
        code_lines = code.split("\n")
        fns, test_ranges = scan_items(code)
        crate, module = module_path(rel)
        for start, end, name, _vis in fns:
            if any(a <= start <= b for a, b in test_ranges):
                continue
            if _has_test_attr(raw_lines, start):
                continue
            inline = _inline_mod_at(code_lines, start)
            full_mod = "::".join(p for p in (module, inline) if p)
            ty = _impl_header_at(code_lines, start)
            key = fn_key(crate, full_mod, ty, name)
            prelude = _attr_doc_start(raw_lines, start)
            src = "\n".join(raw_lines[prelude:end])
            if key in found:
                # Never drop a colliding body. Disambiguate with file:line
                # when two items still share a key.
                key = f"{key}#{rel}:{start}"
            found[key] = {"src": src, "file": rel, "name": name, "kind": "fn"}
        fn_spans = [(a, b) for a, b, _, _ in fns]
        for start, end, kind, name in scan_non_fn(code):
            if any(a <= start <= b for a, b in test_ranges):
                continue
            if any(a < start < b for a, b in fn_spans):
                continue
            inline = _inline_mod_at(code_lines, start)
            full_mod = "::".join(p for p in (module, inline) if p)
            ty = _impl_header_at(code_lines, start)
            prefix = f"{ty}::{kind}" if ty else kind
            key = fn_key(crate, full_mod, prefix, name)
            prelude = _attr_doc_start(raw_lines, start)
            src = "\n".join(raw_lines[prelude:end])
            if key in found:
                key = f"{key}#{rel}:{start}"
            found[key] = {"src": src, "file": rel, "name": name, "kind": kind}
    return found


def _line_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        counts[s] = counts.get(s, 0) + 1
    return counts


def strip_glue_lines(text: str, glue: list[str]) -> str:
    """Drop one matching line per listed glue occurrence."""
    remain: dict[str, int] = {}
    for g in glue:
        gs = g.strip()
        if gs:
            remain[gs] = remain.get(gs, 0) + 1
    out: list[str] = []
    for ln in text.splitlines():
        s = ln.strip()
        if remain.get(s, 0) > 0:
            remain[s] -= 1
            continue
        out.append(ln)
    return "\n".join(out)


def glue_problems(old_body: str, new_body: str, glue: list[str]) -> tuple[list[str], list[str]]:
    """Each glue line excuses one new-only occurrence; extras are unused."""
    old_c, new_c = _line_counts(old_body), _line_counts(new_body)
    listed: dict[str, int] = {}
    unused: list[str] = []
    illegal: list[str] = []
    for g in glue:
        gs = g.strip()
        if not gs:
            continue
        listed[gs] = listed.get(gs, 0) + 1
    for gs, n in listed.items():
        if old_c.get(gs, 0):
            illegal.append(gs)
        if new_c.get(gs, 0) < n:
            unused.append(gs)
    return unused, illegal


def _glue_for_split(
    glue: dict[str, list[str]] | list[str], old_key: str
) -> list[str]:
    if isinstance(glue, list):
        return glue
    return glue.get(old_key, [])


def compare_trees(
    old_root: pathlib.Path,
    new_root: pathlib.Path,
    moves: dict[str, str],
    accept: dict[str, dict[str, str]],
    splits: dict[str, list[str]],
    glue: dict[str, list[str]] | list[str],
    roots: list[str] | None = None,
) -> dict[str, object]:
    old = extract(old_root, roots)
    new = extract(new_root, roots)
    used_old: set[str] = set()
    used_new: set[str] = set()
    used_moves: set[str] = set()
    move_hits: dict[str, int] = {}
    for v in moves.values():
        move_hits[v] = move_hits.get(v, 0) + 1
    merged_targets = {v for v, n in move_hits.items() if n > 1}
    pairs: list[tuple[str, str, str]] = []
    split_ok: list[str] = []
    split_fail: list[str] = []
    missing_split: list[str] = []
    unused_glue: list[str] = []
    illegal_glue: list[str] = []

    for old_key, new_keys in splits.items():
        if old_key not in old:
            missing_split.append(old_key)
            continue
        missing = [k for k in new_keys if k not in new]
        if missing:
            missing_split.extend(f"{old_key} -> {k}" for k in missing)
            continue
        g_lines = _glue_for_split(glue, old_key)
        old_body = inner_body(old[old_key]["src"])
        concat = "\n".join(inner_body(new[k]["src"]) for k in new_keys)
        unused, illegal = glue_problems(old_body, concat, g_lines)
        unused_glue.extend(f"{old_key}: {g}" for g in unused)
        illegal_glue.extend(f"{old_key}: {g}" for g in illegal)
        stripped = strip_glue_lines(concat, g_lines)
        if (
            compare_norm(old_body) == compare_norm(stripped)
            and not unused
            and not illegal
        ):
            split_ok.append(old_key)
            used_old.add(old_key)
            used_new.update(new_keys)
        else:
            split_fail.append(old_key)

    for okey, ofn in old.items():
        if okey in used_old:
            continue
        nkey = moves.get(okey, okey)
        if okey in moves:
            used_moves.add(okey)
        if nkey not in new or (nkey in used_new and nkey not in merged_targets):
            continue
        kind = classify(ofn["src"], new[nkey]["src"])
        pairs.append((okey, nkey, kind))
        used_old.add(okey)
        used_new.add(nkey)

    removed = sorted(k for k in old if k not in used_old)
    added = sorted(k for k in new if k not in used_new)
    accepted: list[tuple[str, str, str]] = []
    used_accept: set[str] = set()
    empty_h = blob_hash("")
    still_removed: list[str] = []
    still_added: list[str] = []
    for k in removed:
        entry = accept.get(k)
        if entry is None:
            still_removed.append(k)
            continue
        used_accept.add(k)
        if entry["old_hash"] == blob_hash(old[k]["src"]) and (
            entry["new"] in {k, "-"} or entry["new_hash"] == empty_h
        ):
            accepted.append((k, entry["new"], entry["reason"]))
        else:
            still_removed.append(k)
    for k in added:
        entry = accept.get(k)
        if entry is None:
            still_added.append(k)
            continue
        used_accept.add(k)
        if entry["new"] == k and entry["new_hash"] == blob_hash(new[k]["src"]):
            accepted.append((k, k, entry["reason"]))
        else:
            still_added.append(k)
    removed = still_removed
    added = still_added
    unused_moves = sorted(k for k in moves if k not in used_moves)
    identical = sum(1 for _o, _n, k in pairs if k == "identical")
    vis_only = [(o, n) for o, n, k in pairs if k == "vis-only"]
    doc_only = [(o, n) for o, n, k in pairs if k == "doc-only"]
    changed = [(o, n) for o, n, k in pairs if k == "changed"]

    unaccepted: list[tuple[str, str]] = []
    missing_rhs: list[str] = []
    for okey, nkey in changed:
        entry = accept.get(okey)
        if entry is None:
            unaccepted.append((okey, nkey))
            continue
        used_accept.add(okey)
        if entry["new"] not in new:
            missing_rhs.append(entry["new"])
            unaccepted.append((okey, nkey))
            continue
        if entry["new"] != nkey:
            unaccepted.append((okey, nkey))
            continue
        oh, nh = blob_hash(old[okey]["src"]), blob_hash(new[nkey]["src"])
        if entry["old_hash"] == oh and entry["new_hash"] == nh:
            accepted.append((okey, nkey, entry["reason"]))
        else:
            unaccepted.append((okey, nkey))

    unused_accept = sorted(k for k in accept if k not in used_accept)

    def kind_counts(items: dict[str, dict[str, str]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rec in items.values():
            k = rec.get("kind", "fn")
            counts[k] = counts.get(k, 0) + 1
        return counts

    return {
        "pairs": len(pairs),
        "identical": identical,
        "vis_only": len(vis_only),
        "vis_only_items": vis_only,
        "doc_only": len(doc_only),
        "doc_only_items": doc_only,
        "changed": len(changed),
        "accepted": accepted,
        "unaccepted": unaccepted,
        "removed": removed,
        "added": added,
        "split_ok": split_ok,
        "split_fail": split_fail,
        "missing_split": missing_split,
        "unused_accept": unused_accept,
        "unused_moves": unused_moves,
        "unused_glue": unused_glue,
        "illegal_glue": illegal_glue,
        "missing_rhs": missing_rhs,
        "old": len(old),
        "new": len(new),
        "old_kinds": kind_counts(old),
        "new_kinds": kind_counts(new),
    }


def render(report: dict[str, object]) -> str:
    lines = [
        f"pairs {report['pairs']}",
        f"identical {report['identical']}",
        f"vis-only {report['vis_only']}",
        f"doc-only {report['doc_only']}",
        f"changed {report['changed']}",
        f"accepted {len(report['accepted'])}",  # type: ignore[arg-type]
        f"removed {len(report['removed'])}",  # type: ignore[arg-type]
        f"added {len(report['added'])}",  # type: ignore[arg-type]
        f"split-ok {len(report['split_ok'])}",  # type: ignore[arg-type]
        f"old {report['old']}",
        f"new {report['new']}",
        "old-kinds "
        + " ".join(f"{k}={v}" for k, v in sorted(report["old_kinds"].items())),  # type: ignore[union-attr]
        "new-kinds "
        + " ".join(f"{k}={v}" for k, v in sorted(report["new_kinds"].items())),  # type: ignore[union-attr]
    ]
    for o, n in report["vis_only_items"]:  # type: ignore[misc]
        lines.append(f"vis-only {o} -> {n}")
    for o, n in report["doc_only_items"]:  # type: ignore[misc]
        lines.append(f"doc-only {o} -> {n}")
    for o, n, reason in report["accepted"]:  # type: ignore[misc]
        lines.append(f"accepted {o} -> {n}: {reason}")
    return "\n".join(lines) + "\n"


def evaluate(report: dict[str, object]) -> None:
    errs: list[str] = []
    for o, n in report["unaccepted"]:  # type: ignore[misc]
        errs.append(f"changed not in --accept: {o} -> {n}")
    for k in report["removed"]:  # type: ignore[misc]
        errs.append(f"removed item: {k}")
    for k in report["added"]:  # type: ignore[misc]
        errs.append(f"added item: {k}")
    for k in report["split_fail"]:  # type: ignore[misc]
        errs.append(f"--split body mismatch: {k}")
    for k in report["missing_split"]:  # type: ignore[misc]
        errs.append(f"--split key missing: {k}")
    for k in report["unused_accept"]:  # type: ignore[misc]
        errs.append(f"--accept entry unused: {k}")
    for k in report.get("unused_moves", []):  # type: ignore[misc]
        errs.append(f"--moves entry unused: {k}")
    for k in report.get("unused_glue", []):  # type: ignore[misc]
        errs.append(f"--glue unused: {k}")
    for k in report.get("illegal_glue", []):  # type: ignore[misc]
        errs.append(f"--glue present in old body: {k}")
    for k in report["missing_rhs"]:  # type: ignore[misc]
        errs.append(f"--accept RHS missing in new tree: {k}")
    if errs:
        raise FnDiffError("; ".join(errs[:8]))


def _must_red(report: dict[str, object], label: str) -> None:
    try:
        evaluate(report)
    except FnDiffError:
        return
    raise SystemExit(f"hygiene-fn-diff --self-test: {label} must fail")


def _write_crate(root: pathlib.Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _self_test() -> int:
    n = 0
    with tempfile.TemporaryDirectory() as tmp:
        old, new = pathlib.Path(tmp) / "old", pathlib.Path(tmp) / "new"
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "pub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub fn ready(x: i32) -> i32 { x + 2 }\n",
        )
        red = compare_trees(old, new, {}, {}, {}, [])
        if red["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: body edit must be changed")
        _must_red(red, "body edit")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            'fn say() { err("KDC_ERR_NONE"); }\n',
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            'fn say() { err("KDC_ERR_GENERIC"); }\n',
        )
        etext = compare_trees(old, new, {}, {}, {}, [])
        if etext["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: e_text literal must be changed")
        _must_red(etext, "e_text literal")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "fn ch() { let _ = 'a'; }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "fn ch() { let _ = 'b'; }\n")
        ch = compare_trees(old, new, {}, {}, {}, [])
        if ch["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: char literal must be changed")
        _must_red(ch, "char literal")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", 'fn whole() { a("x"); b(); }\n')
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            'fn phase_a() { a("y"); }\nfn phase_b() { b(); }\n',
        )
        lit_split = compare_trees(
            old, new, {}, {}, {"demo\twhole": ["demo\tphase_a", "demo\tphase_b"]}, []
        )
        if not lit_split["split_fail"]:
            raise SystemExit("hygiene-fn-diff --self-test: literal change in --split must fail")
        _must_red(lit_split, "literal change inside --split")
        n += 1

        same = "pub fn ready(x: i32) -> i32 { x + 1 }\n"
        _write_crate(old, "crates/demo/src/lib.rs", same)
        _write_crate(new, "crates/demo/src/lib.rs", same)
        unused = {
            "demo\tother": {
                "new": "demo\tother",
                "old_hash": "a" * 64,
                "new_hash": "b" * 64,
                "reason": "unused",
            },
        }
        unused_rep = compare_trees(old, new, {}, unused, {}, [])
        if unused_rep["changed"] != 0 or unused_rep["removed"] or unused_rep["added"]:
            raise SystemExit(
                "hygiene-fn-diff --self-test: unused-accept fixture must be otherwise green"
            )
        if unused_rep["unused_accept"] != ["demo\tother"]:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: unused --accept: {unused_rep['unused_accept']}"
            )
        try:
            evaluate(unused_rep)
        except FnDiffError as exc:
            if "--accept entry unused" not in str(exc):
                raise SystemExit(
                    f"hygiene-fn-diff --self-test: unused-accept must be the red reason: {exc}"
                )
        else:
            raise SystemExit("hygiene-fn-diff --self-test: unused accept must fail")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "pub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(new, "crates/demo/src/lib.rs", "")
        dropped = compare_trees(old, new, {}, {}, {}, [])
        if dropped["removed"] != ["demo\tready"]:
            raise SystemExit(f"hygiene-fn-diff --self-test: dropped fn: {dropped['removed']}")
        _must_red(dropped, "dropped fn")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    b();\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn phase_a() {\n    a();\n    phase_b();\n}\nfn phase_b() {\n    b();\n}\n",
        )
        split_map = {"demo\twhole": ["demo\tphase_a", "demo\tphase_b"]}
        glue = ["phase_b();"]
        split_ok = compare_trees(old, new, {}, {}, split_map, glue)
        evaluate(split_ok)
        if split_ok["split_ok"] != ["demo\twhole"]:
            raise SystemExit("hygiene-fn-diff --self-test: --split of a pure move-apart must pass")
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn phase_a() {\n    b();\n    phase_b();\n}\nfn phase_b() {\n    a();\n}\n",
        )
        reordered = compare_trees(old, new, {}, {}, split_map, glue)
        if not reordered["split_fail"]:
            raise SystemExit("hygiene-fn-diff --self-test: reordered --split must fail")
        _must_red(reordered, "reordered statement inside --split")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "pub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/moved.rs",
            "pub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(new, "crates/demo/src/lib.rs", "")
        moved = compare_trees(old, new, {"demo\tready": "demo\tmoved::ready"}, {}, {}, [])
        evaluate(moved)
        if moved["identical"] != 1 or moved["changed"] != 0:
            raise SystemExit("hygiene-fn-diff --self-test: pure move must be identical")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(crate) fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        (new / "crates" / "demo" / "src" / "moved.rs").unlink(missing_ok=True)
        vis = compare_trees(old, new, {}, {}, {}, [])
        evaluate(vis)
        if vis["vis_only"] != 1 or vis["changed"] != 0:
            raise SystemExit("hygiene-fn-diff --self-test: private → pub(crate) must be vis-only")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "pub fn ready(x: i32) -> i32 { x + 1 }\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(crate) fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        pub_to_crate = compare_trees(old, new, {}, {}, {}, [])
        if pub_to_crate["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: pub → pub(crate) must be changed")
        _must_red(pub_to_crate, "pub → pub(crate)")
        n += 1

        names = ["codes", "xdr", "rpc", "auth", "iprop", "dispatch"]
        old_kadm = "\n".join(f"fn {n}() {{}}\n" for n in names)
        new_kadm = "\n".join(f"pub(super) fn {n}() {{}}\n" for n in names)
        _write_crate(old, "crates/demo/src/lib.rs", old_kadm)
        _write_crate(new, "crates/demo/src/lib.rs", new_kadm)
        kadm = compare_trees(old, new, {}, {}, {}, [])
        evaluate(kadm)
        if kadm["vis_only"] != 6 or kadm["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: 6-fn pub(super) split must be vis-only: {kadm}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "const A: i32 = 1;\nconst B: i32 = 2;\nstruct S { a: i32 }\n"
            + "\n".join(f"fn {n}() {{}}\n" for n in names),
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(super) const A: i32 = 1;\npub(super) const B: i32 = 2;\n"
            "struct S { pub(super) a: i32 }\n"
            + "\n".join(f"pub(super) fn {n}() {{}}\n" for n in names),
        )
        kadm_full = compare_trees(old, new, {}, {}, {}, [])
        evaluate(kadm_full)
        if kadm_full["vis_only"] != 9 or kadm_full["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: kadm5 consts+field must be vis-only: {kadm_full}"
            )
        named = render(kadm_full)
        if named.count("vis-only ") < 10:
            raise SystemExit("hygiene-fn-diff --self-test: render must name each vis-only item")
        if "vis-only demo\tconst::A -> demo\tconst::A" not in named:
            raise SystemExit("hygiene-fn-diff --self-test: render must name the widened const")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "const A: i32 = 1;\n")
        _write_crate(new, "crates/demo/src/lib.rs", "pub(crate) const A: i32 = 1;\n")
        cst = compare_trees(old, new, {}, {}, {}, [])
        evaluate(cst)
        if cst["vis_only"] != 1 or cst["changed"] != 0:
            raise SystemExit("hygiene-fn-diff --self-test: const vis widening must be vis-only")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "struct S { a: i32 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "struct S { pub a: i32 }\n")
        fld_pub = compare_trees(old, new, {}, {}, {}, [])
        if fld_pub["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: field → pub must be changed")
        _must_red(fld_pub, "struct field → pub")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    b();\n    c();\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn phase_a() {\n    a();\n}\nfn phase_b() {\n    b();\n}\n",
        )
        dropped_glue = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\twhole": ["demo\tphase_a", "demo\tphase_b"]},
            ["c();"],
        )
        if not dropped_glue["split_fail"] and not dropped_glue["unused_glue"]:
            raise SystemExit(
                "hygiene-fn-diff --self-test: dropped statement named in glue must fail"
            )
        _must_red(dropped_glue, "dropped statement named in glue")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    b();\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn phase_a() {\n    a();\n    phase_b();\n    phase_b();\n}\n"
            "fn phase_b() {\n    b();\n}\n",
        )
        dup_glue = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\twhole": ["demo\tphase_a", "demo\tphase_b"]},
            ["phase_b();"],
        )
        if not dup_glue["split_fail"]:
            raise SystemExit(
                "hygiene-fn-diff --self-test: duplicated glue call must fail"
            )
        _must_red(dup_glue, "duplicated tail-phase call")
        n += 1

        try:
            load_splits(None, ["demo\twhole = demo\tphase_a"])
        except SystemExit:
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: single-element --split must fail")

        try:
            load_splits(None, ["demo\twhole = demo\tphase_a + demo\tphase_a"])
        except SystemExit:
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: duplicate --split part must fail")

        try:
            load_splits(
                None,
                [
                    "demo\twhole = demo\tmid + demo\tphase_b",
                    "demo\tmid = demo\ta + demo\tb",
                ],
            )
        except SystemExit:
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: --split RHS-as-LHS must fail")

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "pub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            '#[cfg(feature = "extra")]\npub fn ready(x: i32) -> i32 { x + 1 }\n',
        )
        cfg = compare_trees(old, new, {}, {}, {}, [])
        if cfg["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: added #[cfg] must be changed")
        _must_red(cfg, "added #[cfg(feature)]")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "/// old docs\npub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "/// new docs\npub fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        docs = compare_trees(old, new, {}, {}, {}, [])
        evaluate(docs)
        if docs["doc_only"] != 1 or docs["changed"] != 0:
            raise SystemExit("hygiene-fn-diff --self-test: /// change must be doc-only")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "const MAX: i32 = 1;\n")
        _write_crate(new, "crates/demo/src/lib.rs", "const MAX: i32 = 2;\n")
        cst = compare_trees(old, new, {}, {}, {}, [])
        if cst["changed"] != 1 or cst["old_kinds"].get("const") != 1:
            raise SystemExit("hygiene-fn-diff --self-test: const value must be changed")
        _must_red(cst, "changed const value")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "enum E { A = 1, B = 2 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "enum E { A = 2, B = 1 }\n")
        disc = compare_trees(old, new, {}, {}, {}, [])
        if disc["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: swapped discriminants must be changed")
        _must_red(disc, "swapped discriminants")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "struct S { a: i32, b: u8 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "struct S { b: u8, a: i32 }\n")
        fields = compare_trees(old, new, {}, {}, {}, [])
        if fields["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: reordered struct fields must be changed")
        _must_red(fields, "reordered struct fields")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "macro_rules! m { ($x:tt) => { $x } }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "macro_rules! m { ($x:tt) => { ($x) } }\n",
        )
        mac = compare_trees(old, new, {}, {}, {}, [])
        if mac["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: changed macro body must be changed")
        _must_red(mac, "changed macro body")
        n += 1

        gone_src = "pub fn gone() { 1 }\n"
        _write_crate(old, "crates/demo/src/lib.rs", gone_src)
        _write_crate(new, "crates/demo/src/lib.rs", "")
        gone_acc = {
            "demo\tgone": {
                "new": "-",
                "old_hash": blob_hash(gone_src),
                "new_hash": blob_hash(""),
                "reason": "removed helper",
            }
        }
        gone = compare_trees(old, new, {}, gone_acc, {}, [])
        evaluate(gone)
        if gone["removed"]:
            raise SystemExit("hygiene-fn-diff --self-test: accepted removed item must be green")
        n += 1

        extra_src = "pub fn extra() { 1 }\n"
        _write_crate(old, "crates/demo/src/lib.rs", "")
        _write_crate(new, "crates/demo/src/lib.rs", extra_src)
        extra_acc = {
            "demo\textra": {
                "new": "demo\textra",
                "old_hash": blob_hash(""),
                "new_hash": blob_hash(extra_src),
                "reason": "added helper",
            }
        }
        extra = compare_trees(old, new, {}, extra_acc, {}, [])
        evaluate(extra)
        if extra["added"]:
            raise SystemExit("hygiene-fn-diff --self-test: accepted added item must be green")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "pub fn ready(x: i32) -> i32 { x + 1 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "pub fn ready(x: i32) -> i32 { x + 1 }\n")
        unused_mv = compare_trees(
            old, new, {"demo\tother": "demo\tready"}, {}, {}, []
        )
        _must_red(unused_mv, "unused --moves entry")
        n += 1

        mvpath = pathlib.Path(tmp) / "dup-moves.txt"
        mvpath.write_text("demo\ta = demo\tb\ndemo\ta = demo\tc\n", encoding="utf-8")
        try:
            load_keyed_id_map(mvpath, "moves")
        except SystemExit:
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: duplicate --moves LHS must fail")

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn a() { x(); }\nfn b() { x(); }\n",
        )
        _write_crate(new, "crates/demo/src/lib.rs", "fn c() { x(); }\n")
        merged = compare_trees(
            old,
            new,
            {"demo\ta": "demo\tc", "demo\tb": "demo\tc"},
            {},
            {},
            [],
        )
        if merged["pairs"] != 2 or merged["removed"] or merged["added"]:
            raise SystemExit("hygiene-fn-diff --self-test: merged: compare must keep both olds")
        merpath = pathlib.Path(tmp) / "merged-moves.txt"
        merpath.write_text(
            "demo\ta = merged:demo\tc\ndemo\tb = merged:demo\tc\n",
            encoding="utf-8",
        )
        loaded = load_keyed_id_map(merpath, "moves")
        if loaded != {"demo\ta": "demo\tc", "demo\tb": "demo\tc"}:
            raise SystemExit("hygiene-fn-diff --self-test: merged: parser must keep both LHS")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "impl From<Foo> for Bar {\n"
            "    fn from(x: Foo) -> Bar { Bar }\n"
            "}\n"
            "impl From<Baz> for Bar {\n"
            "    fn from(x: Baz) -> Bar { Bar }\n"
            "}\n"
            "impl Trait for &T {\n"
            "    fn refer() {}\n"
            "}\n"
            "impl Trait for [u8; 16] {\n"
            "    fn arr() {}\n"
            "}\n"
            "impl Trait for (A, B) {\n"
            "    fn tup() {}\n"
            "}\n"
            "impl Trait for Box<T> {\n"
            "    fn boxed() {}\n"
            "}\n"
            "impl foo::Bar for baz::Qux {\n"
            "    fn path_m() {}\n"
            "}\n"
            "impl<T> Wrap<T>\n"
            "where\n"
            "    T: Clone,\n"
            "{\n"
            "    fn bound() {}\n"
            "}\n"
            "mod inner {\n"
            "    fn nest() {}\n"
            "}\n",
        )
        keyed = extract(old)
        from_keys = [k for k in keyed if k.endswith("::from")]
        if len(from_keys) != 2 or any("#" in k for k in from_keys):
            raise SystemExit(f"hygiene-fn-diff --self-test: From::from keys: {from_keys}")
        if not any("From<Foo>" in k for k in from_keys) or not any(
            "From<Baz>" in k for k in from_keys
        ):
            raise SystemExit(f"hygiene-fn-diff --self-test: From headers: {from_keys}")
        for needle, suffix in (
            ("impl Trait for &T", "::refer"),
            ("impl Trait for [u8; 16]", "::arr"),
            ("impl Trait for (A, B)", "::tup"),
            ("impl Trait for Box<T>", "::boxed"),
            ("impl foo::Bar for baz::Qux", "::path_m"),
        ):
            if not any(needle in k and k.endswith(suffix) for k in keyed):
                raise SystemExit(
                    f"hygiene-fn-diff --self-test: header {needle}: {sorted(keyed)}"
                )
        if not any("where" in k and k.endswith("::bound") for k in keyed):
            raise SystemExit(f"hygiene-fn-diff --self-test: where-clause header: {sorted(keyed)}")
        if "demo\tinner::nest" not in keyed:
            raise SystemExit(f"hygiene-fn-diff --self-test: inline mod key missing: {sorted(keyed)}")
        if any("#" in k for k in keyed):
            raise SystemExit(f"hygiene-fn-diff --self-test: fixture collision: {sorted(keyed)}")
        n += 1

        _write_crate(old, "examples/diffsend.rs", "fn main() {}\n")
        ex = extract(old, ["examples"])
        if "examples\tdiffsend::main" not in ex:
            raise SystemExit(f"hygiene-fn-diff --self-test: --roots examples: {sorted(ex)}")
        n += 1
    live = extract(ROOT)
    suffixed = [k for k in live if "#" in k]
    if suffixed:
        raise SystemExit(
            "hygiene-fn-diff --self-test: live tree has line-suffixed keys: "
            + ", ".join(suffixed[:8])
        )
    n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--self-test"]:
        n = _self_test()
        print(f"hygiene-fn-diff: self-test ok ({n} cases)")
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--old", required=True, help="SHA or directory")
    ap.add_argument("--new", required=True, help="SHA or directory")
    ap.add_argument("--moves", type=pathlib.Path)
    ap.add_argument("--accept", type=pathlib.Path)
    ap.add_argument("--split", type=pathlib.Path)
    ap.add_argument(
        "--split-line",
        action="append",
        default=[],
        metavar="OLD=A+B",
        help="one --split entry (repeatable)",
    )
    ap.add_argument(
        "--glue",
        action="append",
        default=[],
        help="per-split new-only line excused from --split concat (repeatable)",
    )
    ap.add_argument("--git-dir", type=pathlib.Path, default=ROOT)
    ap.add_argument(
        "--roots",
        action="append",
        default=[],
        help="tree roots to scan (default: crates; add examples/ fuzz/ for S3.6)",
    )
    ns = ap.parse_args(argv)
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        _self_test()
    moves = load_keyed_id_map(ns.moves, "moves")
    accept = load_accept(ns.accept)
    splits = load_splits(ns.split, ns.split_line)
    if ns.roots:
        roots: list[str] | None = []
        for r in ["crates", *ns.roots]:
            if r not in roots:
                roots.append(r)
    else:
        roots = None
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = pathlib.Path(tmp)
        old_root = materialize(ns.old, tmp_p / "old", ns.git_dir)
        new_root = materialize(ns.new, tmp_p / "new", ns.git_dir)
        report = compare_trees(
            old_root,
            new_root,
            moves,
            accept,
            splits,
            ns.glue,
            roots=roots,
        )
    sys.stdout.write(render(report))
    try:
        evaluate(report)
    except FnDiffError as e:
        print(f"hygiene-fn-diff: {e}", file=sys.stderr)
        return 1
    print("hygiene-fn-diff: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
