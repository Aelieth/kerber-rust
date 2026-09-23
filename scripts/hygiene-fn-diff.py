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
those two restricted forms, or bare `pub` narrowed to a restricted
form, with a rest equal modulo a rustfmt signature rewrap) /
`vis-widen` (`pub(crate)` / `pub(super)` → `pub`, or private → any
`pub`; listed and red unless `--accept`) / `fmt-only` (that rewrap
alone) / `doc-only` / `changed`. A `pub` token inside a comment is
not visibility. The compared blob includes the attribute block above the
fn; a file's `#![…]` inner attributes are the `inner-attrs` item of
its module. Reports `added` and `removed`. A key collision never
drops a body.

Fails on any `changed`, `added` or `removed` not in `--accept` (keyed,
blob-pinned, unused entry red). `--split old_key = new_a + new_b + …`
checks that the concatenated new bodies equal the old body modulo
per-split `--glue` lines (whole lines present in the new bodies and
absent from the old; unused glue is red), optional per-phase `head:` /
`tail:` blocks (start / end only, after whitespace + rewrap
normalisation), and occurrence-counted `edit: OLD => NEW` rows that
drop the single `mut` token after `let`. Under `--split` the old fn's
attribute block must equal the dispatcher's (doc edits are
`doc-only`); a phase attribute block is empty or a blob-pinned
`--accept`. Phase signatures are named in the report.

Usage:
  python3 scripts/hygiene-fn-diff.py --old SHA --new SHA \\
      [--moves map.txt] [--accept map.txt] [--params map.txt] [--split map.txt] \\
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


def _require_map_file(path: pathlib.Path | None, flag: str) -> None:
    if path is None:
        return
    if not path.is_file():
        raise SystemExit(f"{flag} file not found: {path}")


def load_keyed_id_map(path: pathlib.Path | None, kind: str) -> dict[str, str]:
    """`old_key = [merged:]new_key`; keys are crate<TAB>path."""
    _require_map_file(path, f"--{kind}")
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


def load_params(path: pathlib.Path | None) -> dict[str, tuple[str, list[str]]]:
    """`crate<TAB>path = Struct: f1, f2, …`. Field order is the old parameter order."""
    if path is None:
        return {}
    _require_map_file(path, "--params")
    raw = load_map(path, "=")
    out: dict[str, tuple[str, list[str]]] = {}
    for left, right in raw.items():
        if "\t" not in left:
            raise SystemExit(f"--params LHS must be crate<TAB>path: {left!r}")
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$", right.strip())
        if not m:
            raise SystemExit(f"--params RHS must be Struct: f1, f2: {right!r}")
        fields = [part.strip() for part in m.group(2).split(",") if part.strip()]
        if not fields:
            raise SystemExit(f"--params needs at least one field: {left}")
        out[left] = (m.group(1), fields)
    return out


def load_accept(path: pathlib.Path | None) -> dict[str, dict[str, str]]:
    """Keyed `old = new | sha256:old | sha256:new | reason`."""
    _require_map_file(path, "--accept")
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


def _empty_split_extra() -> dict[str, object]:
    return {"heads": {}, "tails": {}, "edits": []}


def _is_let_mut_to_let(old: str, new: str) -> bool:
    """True when NEW is OLD with the single token `mut` removed after `let`."""
    o = " ".join(old.split())
    n = " ".join(new.split())
    if not o.startswith("let mut ") or not n.startswith("let "):
        return False
    if n.startswith("let mut "):
        return False
    return o[len("let mut ") :] == n[len("let ") :]


def _parse_edit_line(payload: str) -> tuple[str, str]:
    if " => " not in payload:
        raise SystemExit(f"bad edit: {payload!r} (want OLD => NEW)")
    old, new = payload.split(" => ", 1)
    old, new = old.strip(), new.strip()
    if not _is_let_mut_to_let(old, new):
        raise SystemExit(
            f"edit: only let mut → let (got {old!r} => {new!r})"
        )
    return old, new


def _block_indent_body(line: str) -> str:
    """Strip one map-file indent from a `head:` / `tail:` continuation."""
    if line.startswith("|"):
        raw = line[1:]
        return raw[1:] if raw.startswith(" ") else raw
    if line.startswith("\t"):
        return line[1:]
    if line.startswith("    "):
        return line[4:]
    return line.lstrip()


def load_splits(
    path: pathlib.Path | None, extra: list[str]
) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, dict[str, object]]]:
    """`old_key = new_a + new_b + …` plus `glue:` / `head:` / `tail:` / `edit:`."""
    _require_map_file(path, "--split")
    out: dict[str, list[str]] = {}
    file_glue: dict[str, list[str]] = {}
    extras: dict[str, dict[str, object]] = {}
    last_old = ""
    block_kind = ""
    block_key = ""
    block_lines: list[str] = []

    def extra_of(old: str) -> dict[str, object]:
        return extras.setdefault(old, _empty_split_extra())

    def flush_block() -> None:
        nonlocal block_kind, block_key, block_lines
        if not block_kind:
            return
        if not last_old:
            raise SystemExit(f"{block_kind}: with no preceding --split line")
        text = "\n".join(block_lines).rstrip("\n")
        if not text.strip():
            raise SystemExit(f"empty {block_kind}: {block_key}")
        if "\t" not in block_key:
            raise SystemExit(
                f"{block_kind}: keys must be crate<TAB>path: {block_key!r}"
            )
        bucket = extra_of(last_old)[f"{block_kind}s"]
        assert isinstance(bucket, dict)
        if block_key in bucket:
            raise SystemExit(f"duplicate {block_kind}: {block_key}")
        bucket[block_key] = text
        block_kind = ""
        block_key = ""
        block_lines = []

    def handle_stripped(line: str) -> None:
        nonlocal last_old, block_kind, block_key, block_lines
        if line.startswith("glue:"):
            flush_block()
            if not last_old:
                raise SystemExit("glue: with no preceding --split line")
            file_glue.setdefault(last_old, []).append(line[5:].strip())
            return
        if line.startswith("head:") or line.startswith("tail:"):
            flush_block()
            kind, _, rest = line.partition(":")
            block_kind = kind
            block_key = rest.strip()
            block_lines = []
            return
        if line.startswith("edit:"):
            flush_block()
            if not last_old:
                raise SystemExit("edit: with no preceding --split line")
            old_e, new_e = _parse_edit_line(line[5:].strip())
            edits = extra_of(last_old)["edits"]
            assert isinstance(edits, list)
            edits.append((old_e, new_e))
            return
        flush_block()
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
        last_old = old

    if path is not None and path.is_file():
        in_stamp = True
        for raw in path.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if in_stamp and stripped and _HD._STAMP_LINE_RE.match(stripped):
                continue
            if in_stamp and not stripped:
                continue
            in_stamp = False
            if block_kind and (
                raw.startswith((" ", "\t")) or raw.startswith("|")
            ):
                block_lines.append(_block_indent_body(raw))
                continue
            if not stripped or stripped.startswith("#"):
                flush_block()
                continue
            handle_stripped(stripped)
        flush_block()
    for line in extra:
        handle_stripped(line.strip())
    lhs = set(out)
    for old, parts in out.items():
        for p in parts:
            if p in lhs and p != old:
                raise SystemExit(f"--split RHS is also a LHS: {p}")
    return out, file_glue, extras


def parse_glue_args(items: list[str]) -> dict[str, list[str]] | list[str]:
    """`--glue KEY=LINE` is per-split; unkeyed `--glue LINE` stays global."""
    keyed: dict[str, list[str]] = {}
    plain: list[str] = []
    for g in items:
        if "\t" in g and "=" in g:
            left, right = g.split("=", 1)
            if "\t" in left.strip():
                keyed.setdefault(left.strip(), []).append(right)
                continue
        plain.append(g)
    if keyed and plain:
        raise SystemExit("unkeyed --glue cannot mix with --glue KEY=LINE")
    return keyed if keyed else plain


def merge_glue(
    file_glue: dict[str, list[str]],
    cli_glue: dict[str, list[str]] | list[str],
) -> dict[str, list[str]] | list[str]:
    if not file_glue:
        return cli_glue
    if isinstance(cli_glue, list) and cli_glue:
        raise SystemExit("unkeyed --glue cannot mix with glue: in --split")
    out = {k: list(v) for k, v in file_glue.items()}
    if isinstance(cli_glue, dict):
        for k, lines in cli_glue.items():
            out.setdefault(k, []).extend(lines)
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


def _rewrite_skipping_comments(text: str, fn) -> str:
    """Apply `fn` to code; copy `//` and `/* */` through unchanged.

    The caller has already split string and char literals out, so a
    `//` here is a comment. `///` and `//!` start with `//`.
    """
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(text)

    def flush() -> None:
        if buf:
            out.append(fn("".join(buf)))
            buf.clear()

    while i < n:
        if text.startswith("/*", i):
            flush()
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(text[i:j])
            i = j
            continue
        if text.startswith("//", i):
            flush()
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(text[i:j])
            i = j
            continue
        buf.append(text[i])
        i += 1
    flush()
    return "".join(out)


def _sub_vis_outside_comments(src: str, pattern: re.Pattern[str]) -> str:
    """Drop visibility tokens in code. Comments and string literals stay."""

    def sub_span(text: str) -> str:
        return _rewrite_skipping_comments(text, lambda code: pattern.sub("", code))

    return _map_code(src, sub_span)


def strip_restricted_vis(src: str) -> str:
    """Drop `pub(crate)` / `pub(super)` / `pub(in …)` tokens. Bare `pub` stays."""
    return _sub_vis_outside_comments(src, RESTRICTED_VIS_RE)


def _strip_doc_lines(src: str) -> str:
    kept: list[str] = []
    for ln in src.splitlines():
        s = ln.strip()
        if s.startswith("///") or s.startswith("//!"):
            continue
        kept.append(ln)
    return "\n".join(kept)


# A word that can precede `(` / `<` without opening a parameter, generic or
# call-like list: the comma after `&mut (T,)` or `*const (T,)` is a type.
_NOT_LIST_OPENER = frozenset(
    "mut const dyn impl in as for where ref move unsafe extern return".split()
)


def _literal_spans(src: str) -> list[tuple[bool, str]]:
    """Split into (is_code, text) runs; literal runs are whole string / char tokens."""
    out: list[tuple[bool, str]] = []
    code: list[str] = []

    def flush() -> None:
        if code:
            out.append((True, "".join(code)))
            code.clear()

    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        end: int | None = None
        if c == "r" or (c == "b" and nxt == "r"):
            end = _scan_raw(src, i)
        if end is None and c == "b" and nxt == '"':
            end = _scan_quoted(src, i + 1)
        if end is None and c == '"':
            end = _scan_quoted(src, i)
        if end is None and c in "'b":
            end = _scan_char(src, i)
        if end is not None:
            flush()
            out.append((False, src[i:end]))
            i = end
            continue
        code.append(c)
        i += 1
    flush()
    return out


def _sig_rewrap_norm(src: str) -> str:
    """Undo a rustfmt rewrap of the signature (the text before the body).

    rustfmt breaks a long parameter or generic list one entry per line and
    adds a trailing comma. Whitespace around punctuation goes; the comma is
    dropped only when the matching `(` / `<` follows an identifier that is
    not a keyword and not a lifetime (the fn name, a type, `Fn`), so
    `(T,)`, `&mut (T,)`, `*const (T,)` and `&'a (T,)` keep theirs. String
    and char literals pass through whole.
    """
    head, brace, body = src.partition("{")
    if not brace or not re.search(r"\bfn\s", head):
        return src
    out: list[str] = []
    stack: list[bool] = []
    for is_code, text in _literal_spans(head):
        if not is_code:
            out.append(text)
            continue
        text = re.sub(r"\s*([^\w\s])\s*", r"\1", text)
        for i, c in enumerate(text):
            if c in "(<":
                j = i
                while j and (text[j - 1].isalnum() or text[j - 1] == "_"):
                    j -= 1
                word = text[j:i]
                lifetime = j > 0 and text[j - 1] == "'"
                stack.append(
                    bool(word) and not lifetime and word not in _NOT_LIST_OPENER
                )
            elif c in ")>":
                if c == ">" and out and out[-1] == "-":
                    out.append(c)
                    continue
                drop = stack.pop() if stack else False
                if drop and out and out[-1] == ",":
                    out.pop()
            out.append(c)
    return "".join(out) + brace + body


def _restricted_vis_tokens(src: str) -> list[str]:
    return [tok for tok in _code_vis_tokens(src) if tok.startswith("pub(")]


# `(?!\w)` so `pubkey` is not a visibility token. `\b` alone matches the
# `pub` prefix of an identifier.
_ALL_VIS_RE = re.compile(r"\bpub(?:\([^)]*\))?(?!\w)\s*")
_VIS_TOKEN_RE = re.compile(r"\bpub(?:\([^)]*\))?(?!\w)")


def _map_code(src: str, fn) -> str:
    return "".join(fn(text) if is_code else text for is_code, text in _literal_spans(src))


def _vis_rank(token: str) -> int:
    """Bare `pub` outranks `pub(crate)` / `pub(super)` / `pub(in …)`."""
    compact = re.sub(r"\s+", "", token)
    if compact == "pub":
        return 2
    if compact.startswith("pub("):
        return 1
    return 0


def _code_vis_tokens(src: str) -> list[str]:
    """Visibility tokens in code. A `pub(crate)` inside `///` is not one."""
    tokens: list[str] = []

    def take(piece: str) -> str:
        tokens.extend(_VIS_TOKEN_RE.findall(piece))
        return piece

    for is_code, text in _literal_spans(src):
        if is_code:
            _rewrite_skipping_comments(text, take)
    return [re.sub(r"\s+", "", tok) for tok in tokens]


def _token_step_ok(old: str, new: str) -> bool:
    """One token may stay, narrow `pub` → restricted, widen restricted → `pub`, or swap restricted forms."""
    if old == new:
        return True
    ro, rn = _vis_rank(old), _vis_rank(new)
    if ro == 1 and rn == 1:
        return True
    if ro == 2 and rn == 1:
        return True
    return ro == 1 and rn == 2


def _vis_delta_class(old_src: str, new_src: str) -> str | None:
    """`vis-only` for a narrowing or a restricted edit; `vis-widen` when any token becomes or is added as bare `pub`.

    Comment text is not a token. `None` means the tokens are not a pure visibility edit.
    """
    old_toks = _code_vis_tokens(old_src)
    new_toks = _code_vis_tokens(new_src)
    if old_toks == new_toks:
        return None
    if len(old_toks) == len(new_toks):
        widened = narrowed = swapped = False
        for old, new in zip(old_toks, new_toks):
            if not _token_step_ok(old, new):
                return None
            ro, rn = _vis_rank(old), _vis_rank(new)
            if rn > ro:
                widened = True
            elif rn < ro:
                narrowed = True
            elif old != new:
                swapped = True
        if widened:
            return "vis-widen"
        if narrowed or swapped:
            return "vis-only"
        return None
    if len(new_toks) < len(old_toks):
        return None
    oi = 0
    widened = False
    inserted_bare = False
    inserted_restricted = False
    for nt in new_toks:
        if oi < len(old_toks) and _token_step_ok(old_toks[oi], nt):
            if _vis_rank(nt) > _vis_rank(old_toks[oi]):
                widened = True
            oi += 1
            continue
        rank = _vis_rank(nt)
        if rank == 2:
            inserted_bare = True
        elif rank == 1:
            inserted_restricted = True
        else:
            return None
    if oi != len(old_toks):
        return None
    if widened or inserted_bare:
        return "vis-widen"
    if inserted_restricted:
        return "vis-only"
    return None


def classify(old_src: str, new_src: str, params_ctx: dict | None = None) -> str:
    if compare_norm(old_src) == compare_norm(new_src):
        return "identical"
    # allow → expect on too_many_arguments, and a sibling lint moved onto
    # its own allow, is not a body edit.
    if compare_norm(_strip_tma_attr(old_src)) == compare_norm(_strip_tma_attr(new_src)):
        return "identical"
    if compare_norm(_strip_doc_lines(old_src)) == compare_norm(_strip_doc_lines(new_src)):
        return "doc-only"
    old_vis = _sig_rewrap_norm(strip_restricted_vis(old_src))
    new_vis = _sig_rewrap_norm(strip_restricted_vis(new_src))
    if compare_norm(old_vis) == compare_norm(new_vis):
        if _restricted_vis_tokens(old_src) != _restricted_vis_tokens(new_src):
            return "vis-only"
        return "fmt-only"
    old_stripped = _sub_vis_outside_comments(old_src, _ALL_VIS_RE)
    new_stripped = _sub_vis_outside_comments(new_src, _ALL_VIS_RE)
    old_all = _sig_rewrap_norm(old_stripped)
    new_all = _sig_rewrap_norm(new_stripped)
    kind = _vis_delta_class(old_src, new_src)
    if kind is not None and compare_norm(old_all) == compare_norm(new_all):
        return kind
    # Doc lines beside a real visibility edit. Skip signature rewrap
    # here: a `(` inside a `///` comment is not a parameter list.
    # The class comes from comment-free tokens, so a `pub(crate)` that
    # appears only in the doc is not enough.
    if kind is not None and compare_norm(_strip_doc_lines(old_stripped)) == compare_norm(
        _strip_doc_lines(new_stripped)
    ):
        return kind
    if params_ctx is not None and _params_only(old_src, new_src, params_ctx):
        return "params-only"
    return "changed"


def _skip_code_ws(src: str, i: int) -> int:
    n = len(src)
    while i < n:
        if src[i].isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        break
    return i


def _scan_balanced(src: str, i: int, open_c: str, close_c: str) -> int:
    """`i` points at `open_c`. Return the index past the matching close."""
    depth = 0
    n = len(src)
    while i < n:
        lit = _INV._copy_literal(src, i)
        if lit is not None:
            i = lit
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        c = src[i]
        if open_c == "<" and c == ">" and i > 0 and src[i - 1] == "-":
            i += 1
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _split_top_commas(src: str) -> list[str]:
    parts: list[str] = []
    start = 0
    i, n = 0, len(src)
    paren = brack = brace = angle = 0
    while i < n:
        lit = _INV._copy_literal(src, i)
        if lit is not None:
            i = lit
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        c = src[i]
        if c == "(":
            paren += 1
        elif c == ")":
            paren = max(0, paren - 1)
        elif c == "[":
            brack += 1
        elif c == "]":
            brack = max(0, brack - 1)
        elif c == "{":
            brace += 1
        elif c == "}":
            brace = max(0, brace - 1)
        elif c == "<" and paren == brack == brace == 0:
            angle += 1
        elif c == ">" and angle and not (i > 0 and src[i - 1] == "-"):
            angle -= 1
        elif c == "," and paren == brack == brace == angle == 0:
            parts.append(src[start:i])
            start = i + 1
        i += 1
    tail = src[start:]
    if tail.strip():
        parts.append(tail)
    return parts


def _param_chunks(src: str) -> list[str] | None:
    sig = signature_of(src)
    m = re.search(r"\bfn\s+", sig)
    if not m:
        return None
    i = m.end()
    while i < len(sig) and (sig[i].isalnum() or sig[i] == "_"):
        i += 1
    i = _skip_code_ws(sig, i)
    if i < len(sig) and sig[i] == "<":
        i = _scan_balanced(sig, i, "<", ">")
        i = _skip_code_ws(sig, i)
    if i >= len(sig) or sig[i] != "(":
        return None
    j = _scan_balanced(sig, i, "(", ")")
    return _split_top_commas(sig[i + 1 : j - 1])


def _param_name(chunk: str) -> str | None:
    s = " ".join(chunk.split())
    if s in {"self", "&self", "&mut self", "mut self"}:
        return "self"
    s = re.sub(r"^mut\s+", "", s)
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:", s)
    return m.group(1) if m else None


def _param_names_of(src: str) -> list[str] | None:
    chunks = _param_chunks(src)
    if chunks is None:
        return None
    names: list[str] = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        name = _param_name(chunk)
        if name is None:
            return None
        names.append(name)
    return names


def _bare_param(name: str) -> str:
    """`_store` is the unused spelling of `store`."""
    if name.startswith("_") and len(name) > 1 and not name.startswith("__"):
        return name[1:]
    return name


def _bare_names(names: list[str]) -> list[str]:
    return [_bare_param(n) for n in names]


def _find_slice(names: list[str], fields: list[str]) -> tuple[int, int] | None:
    if not fields or len(fields) > len(names):
        return None
    width = len(fields)
    for i in range(len(names) - width + 1):
        if names[i : i + width] == fields:
            return i, i + width
    return None


_TMA_RE = re.compile(
    r"^#\[(?:allow|expect)\([^]]*clippy::too_many_arguments\b[^]]*\)\]\s*$"
)
# Sibling lints that share an attribute with too_many_arguments today and
# stay on their own allow after the expect split.
_SIBLING_ALLOW_RE = re.compile(
    r"^#\[allow\(\s*clippy::(?:needless_pass_by_value|unnecessary_wraps)\s*\)\]\s*$"
)


def _strip_tma_attr(src: str) -> str:
    """Drop too_many_arguments suppressions and the two sibling allows.

    The sibling allows are stripped even on a function that no longer has
    too_many_arguments, so splitting one combined attribute stays identical
    after the positional rewrite of a converted call.
    """
    return "\n".join(
        ln
        for ln in src.splitlines()
        if not _TMA_RE.match(ln.strip()) and not _SIBLING_ALLOW_RE.match(ln.strip())
    )


def _blank_fn_params(src: str) -> str:
    """Replace the fn parameter list with `()` so two signatures can share a skeleton."""
    sig = signature_of(src)
    m = re.search(r"\bfn\s+", sig)
    if not m:
        return src
    i = m.end()
    while i < len(sig) and (sig[i].isalnum() or sig[i] == "_"):
        i += 1
    i = _skip_code_ws(sig, i)
    if i < len(sig) and sig[i] == "<":
        i = _scan_balanced(sig, i, "<", ">")
        i = _skip_code_ws(sig, i)
    if i >= len(sig) or sig[i] != "(":
        return src
    j = _scan_balanced(sig, i, "(", ")")
    return src[:i] + "()" + src[j:]


def _type_is_struct(chunk: str, struct: str) -> bool:
    text = " ".join(chunk.split())
    text = re.sub(r"^(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:\s*", "", text)
    text = text.replace(" ", "")
    return bool(
        re.fullmatch(
            rf"(?:&(?:mut)?)?{re.escape(struct)}(?:<'(?:[A-Za-z_][A-Za-z0-9_]*|_)>)?",
            text,
        )
    )


def _skip_stmt_attrs(src: str, i: int) -> int:
    """Skip `#[...]` attributes that decorate the destructure `let`."""
    n = len(src)
    while True:
        i = _skip_code_ws(src, i)
        if not src.startswith("#[", i):
            return i
        depth = 0
        j = i + 1
        while j < n:
            if src[j] == "[":
                depth += 1
            elif src[j] == "]":
                depth -= 1
                if depth == 0:
                    i = j + 1
                    break
            j += 1
        else:
            return i


def _is_semi_fn(src: str) -> bool:
    return "{" not in src and src.rstrip().endswith(";")


def _strip_leading_rest(inner: str) -> str | None:
    """Drop a trailing `..` from the first `let` destructure, if it has one."""
    i = _skip_code_ws(inner, 0)
    if not inner.startswith("let", i):
        return None
    brace = inner.find("{", i)
    if brace < 0:
        return None
    depth = 0
    dot_at = None
    j = brace
    while j < len(inner):
        if inner[j] == "{":
            depth += 1
        elif inner[j] == "}":
            depth -= 1
            if depth == 0:
                break
        elif inner.startswith("..", j) and depth == 1:
            dot_at = j
            break
        j += 1
    if dot_at is None:
        return None
    pre = inner[:dot_at].rstrip()
    if pre.endswith(","):
        pre = pre[:-1].rstrip()
    return pre + inner[dot_at + 2 :]


def _match_destructure_exact(
    inner: str, struct: str, fields: list[str]
) -> tuple[str, str] | None:
    """`let Struct { f1, f2, … } = binder;` or `= *binder`. Shorthand only."""
    i = _skip_stmt_attrs(inner, _skip_code_ws(inner, 0))
    if not inner.startswith("let", i):
        return None
    if i + 3 < len(inner) and (inner[i + 3].isalnum() or inner[i + 3] == "_"):
        return None
    i = _skip_code_ws(inner, i + 3)
    if inner.startswith("mut", i) and not (
        i + 3 < len(inner) and (inner[i + 3].isalnum() or inner[i + 3] == "_")
    ):
        i = _skip_code_ws(inner, i + 3)
    m = re.match(r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Za-z_][A-Za-z0-9_]*)\s*\{", inner[i:])
    if not m or m.group(1) != struct:
        return None
    brace = i + m.end() - 1
    end, _exprs = _INV._parse_exact_literal(inner, brace, fields)
    if _exprs is None:
        return None
    # shorthand expressions must be the field names themselves
    if [e.strip() for e in _exprs] != list(fields):
        return None
    j = _skip_code_ws(inner, end)
    if j >= len(inner) or inner[j] != "=":
        return None
    j = _skip_code_ws(inner, j + 1)
    if j < len(inner) and inner[j] == "*":
        j = _skip_code_ws(inner, j + 1)
    mname = re.match(r"[A-Za-z_][A-Za-z0-9_]*", inner[j:])
    if not mname:
        return None
    j += len(mname.group(0))
    j = _skip_code_ws(inner, j)
    if j >= len(inner) or inner[j] != ";":
        return None
    return mname.group(0), inner[j + 1 :]


def _match_destructure(
    inner: str, struct: str, fields: list[str], allow_rest: bool = False
) -> tuple[str, str] | None:
    """Exact shorthand destructure. `..` only when `allow_rest` is set."""
    matched = _match_destructure_exact(inner, struct, fields)
    if matched is not None or not allow_rest:
        return matched
    stripped = _strip_leading_rest(inner)
    if stripped is None:
        return None
    return _match_destructure_exact(stripped, struct, fields)


def _code_has_semi(src: str) -> bool:
    i, n = 0, len(src)
    while i < n:
        lit = _INV._copy_literal(src, i)
        if lit is not None:
            i = lit
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if src[i] == ";":
            return True
        i += 1
    return False


def _pure_forward(src: str) -> tuple[str, list[str]] | None:
    inner = inner_body(src).strip()
    if not inner or _code_has_semi(inner):
        return None
    m = re.match(
        r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        inner,
    )
    if not m:
        return None
    paren = inner.rfind("(", 0, m.end())
    end = _scan_balanced(inner, paren, "(", ")")
    if inner[end:].strip():
        return None
    args = [a.strip() for a in _split_top_commas(inner[paren + 1 : end - 1])]
    return m.group(1), args


def _fns_by_name(fns: dict[str, dict[str, str]]) -> dict[str, str]:
    buckets: dict[str, list[str]] = {}
    for rec in fns.values():
        buckets.setdefault(rec["name"], []).append(rec["src"])
    return {name: srcs[0] for name, srcs in buckets.items() if len(srcs) == 1}


def _walk_forward(
    by_name: dict[str, str], name: str, src: str, steps: dict[str, tuple]
) -> tuple[str, str]:
    seen: set[str] = set()
    while name not in seen:
        parsed = _pure_forward(src)
        if parsed is None:
            return name, src
        callee, args = parsed
        params = _param_names_of(src) or []
        if len(args) < len(params) or any(
            compare_norm(a) != compare_norm(p) for a, p in zip(args, params)
        ):
            return name, src
        steps[name] = (params, callee, [a.strip() for a in args[len(params) :]])
        seen.add(name)
        nxt = by_name.get(callee)
        if nxt is None:
            return callee, src
        name, src = callee, nxt
    return name, src


def prepare_params(
    old: dict[str, dict[str, str]],
    new: dict[str, dict[str, str]],
    params: dict[str, tuple[str, list[str]]],
    moves: dict[str, str],
) -> tuple[
    dict[str, list[str]],
    dict[str, tuple],
    dict[str, str],
    dict[str, tuple[str, list[str]]],
]:
    """Order-check the map. Return structs, steps, survivors, callee fields.

    Every entry for one struct names that struct's full field list or a
    consecutive slice of it (a function that never took the other fields).
    The longest list is the one call-site literals must name.
    """
    by_name = _fns_by_name(old)
    steps: dict[str, tuple] = {}
    survivor: dict[str, str] = {}
    grouped: dict[str, list[tuple[str, list[str]]]] = {}
    for key, (struct, fields) in params.items():
        grouped.setdefault(struct, []).append((key, list(fields)))
    structs: dict[str, list[str]] = {}
    for struct, entries in grouped.items():
        longest = max((fields for _key, fields in entries), key=len)
        for key, fields in entries:
            if _find_slice(longest, fields) is None:
                raise SystemExit(
                    f"hygiene-fn-diff: --params struct {struct} fields disagree: {key}"
                )
        structs[struct] = list(longest)
    by_callee: dict[str, tuple[str, list[str]]] = {}
    for key, (struct, fields) in params.items():
        if key not in old:
            raise SystemExit(f"hygiene-fn-diff: --params key missing in old tree: {key}")
        names = _param_names_of(old[key]["src"])
        if names is None:
            raise SystemExit(
                f"hygiene-fn-diff: --params field order disagrees with signature: {key}"
            )
        if _find_slice(_bare_names(names), fields) is not None:
            by_callee[old[key]["name"]] = (struct, list(fields))
            continue
        ult_name, ult_src = _walk_forward(by_name, old[key]["name"], old[key]["src"], steps)
        ult_names = _param_names_of(ult_src)
        if ult_names != list(fields) or _bare_names(names) != list(fields)[: len(names)]:
            raise SystemExit(
                f"hygiene-fn-diff: --params field order disagrees with signature: {key}"
            )
        survivor[ult_name] = old[key]["name"]
        by_callee[old[key]["name"]] = (struct, list(fields))
    for key, rec in old.items():
        if key in new or key in moves or rec["name"] in steps:
            continue
        _walk_forward(by_name, rec["name"], rec["src"], steps)
    return structs, steps, survivor, by_callee


def _definition_params(
    old_src: str,
    new_src: str,
    struct: str,
    fields: list[str],
    by_name: dict[str, str],
    self_name: str,
    structs: dict[str, list[str]] | None = None,
    steps: dict[str, tuple] | None = None,
    survivor: dict[str, str] | None = None,
    by_callee: dict[str, tuple[str, list[str]]] | None = None,
) -> bool:
    old_s = _strip_doc_lines(_strip_tma_attr(old_src))
    new_s = _strip_doc_lines(_strip_tma_attr(new_src))
    old_sk = signature_of(_blank_fn_params(old_s))
    new_sk = signature_of(_blank_fn_params(new_s))
    if compare_norm(old_sk) != compare_norm(new_sk):
        return False
    old_names = _param_names_of(old_s)
    new_names = _param_names_of(new_s)
    new_chunks = _param_chunks(new_s)
    if old_names is None or new_names is None or new_chunks is None:
        return False
    sl = _find_slice(_bare_names(old_names), fields)
    expected_fields = list(fields)
    body_old = inner_body(old_s)
    if sl is None:
        steps: dict[str, tuple] = {}
        ult_name, ult_src = _walk_forward(by_name, self_name, old_s, steps)
        if _param_names_of(ult_src) != list(fields) or _bare_names(old_names) != list(fields)[: len(old_names)]:
            return False
        if any(name != "self" and _bare_param(name) not in fields for name in old_names):
            return False
        # The whole parameter list is the field prefix.
        if _bare_names(old_names) != list(fields)[: len(old_names)] or len(new_names) != 1:
            return False
        if not _type_is_struct(new_chunks[0], struct):
            return False
        binder = new_names[0]
        body_old = inner_body(ult_src)
        sl_index = 0
    else:
        a, b = sl
        if new_names[:a] != old_names[:a] or new_names[a + 1 :] != old_names[b:]:
            return False
        if not _type_is_struct(new_chunks[a], struct):
            return False
        binder = new_names[a]
        sl_index = a
    if _is_semi_fn(old_s) and _is_semi_fn(new_s):
        return True
    canon = list((structs or {}).get(struct) or fields)
    allow_rest = list(fields) != canon
    matched = _match_destructure(
        inner_body(new_s), struct, expected_fields, allow_rest=allow_rest
    )
    if matched is None:
        return False
    got_binder, rest = matched
    if got_binder != binder or sl_index < 0:
        return False
    # The rest may call another converted function. Rewrite those literals
    # back to positional arguments before comparing with the old body.
    rest_rw = _params_rewrite(rest, structs or {}, by_callee, got_binder)
    old_ex = expand_forwards(body_old, steps or {}, survivor or {})
    return _params_norm(rest_rw) == _params_norm(old_ex)


def _expand_call_args(
    name: str, args: list[str], steps: dict[str, tuple], survivor: dict[str, str]
) -> tuple[str, list[str]]:
    seen: set[str] = set()
    while name in steps and name not in seen:
        seen.add(name)
        params, callee, tail = steps[name]
        if len(args) != len(params):
            break
        args = [*args, *tail]
        name = callee
    if name in survivor:
        name = survivor[name]
    return name, args


def expand_forwards(src: str, steps: dict[str, tuple], survivor: dict[str, str]) -> str:
    """Inline pure forwards and rename a removed ultimate to the survivor."""
    if not steps and not survivor:
        return src
    out: list[str] = []
    i, n = 0, len(src)

    def expand_from(pos: int) -> tuple[str, int] | None:
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", src[pos:])
        if not m:
            return None
        name = m.group(1)
        k = pos + len(name)
        j = _skip_code_ws(src, k)
        if j >= n or src[j] != "(" or (name not in steps and name not in survivor):
            return None
        end = _scan_balanced(src, j, "(", ")")
        raw_args = _split_top_commas(src[j + 1 : end - 1])
        args = [expand_forwards(a.strip(), steps, survivor) for a in raw_args if a.strip() or len(raw_args) > 1]
        if len(raw_args) == 1 and not raw_args[0].strip():
            args = []
        new_name, new_args = _expand_call_args(name, [a.strip() for a in raw_args], steps, survivor)
        # Expand tails and nested calls in the rewritten argument text.
        rendered = ", ".join(expand_forwards(a, steps, survivor) for a in new_args)
        return f"{new_name}({rendered})", end

    while i < n:
        lit = _INV._copy_literal(src, i)
        if lit is not None:
            out.append(src[i:lit])
            i = lit
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(src[i:j])
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j])
            i = j
            continue
        if src[i].isalpha() or src[i] == "_":
            hit = expand_from(i)
            if hit is not None:
                out.append(hit[0])
                i = hit[1]
                continue
        out.append(src[i])
        i += 1
    return "".join(out)


def _pure_field(expr: str, name: str, binder: str | None) -> bool:
    """The field binding, or `binder.name` / `(*binder).name`."""
    e = expr.strip()
    if e == name:
        return True
    if not binder:
        return False
    return e in {f"{binder}.{name}", f"(*{binder}).{name}"}


def _shrink_struct_arg(
    arg: str,
    struct: str,
    canon: list[str],
    fields: list[str],
    binder: str | None,
) -> str | None:
    """A full struct literal, or the struct binding, as this callee's fields."""
    raw = arg.strip()
    if binder and (raw == binder or (raw.startswith("&") and raw[1:].strip() == binder)):
        return ", ".join(fields)
    body = raw[1:].strip() if raw.startswith("&") else raw
    m = re.match(
        r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Za-z_][A-Za-z0-9_]*)\s*\{",
        body,
    )
    if not m or m.group(1) != struct:
        return None
    brace = m.end() - 1
    end, exprs = _INV._parse_exact_literal(body, brace, canon)
    if exprs is None or body[end:].strip():
        return None
    # Fields this callee never took must be the binding itself, or a
    # field read of the struct value. Anything else is a new call.
    for name, expr in zip(canon, exprs):
        if name not in fields and not _pure_field(expr, name, binder):
            return None
    chosen = [exprs[canon.index(name)].strip() for name in fields]
    return ", ".join(chosen)


def _subset_calls(
    src: str,
    structs: dict[str, list[str]],
    by_callee: dict[str, tuple[str, list[str]]],
    binder: str | None,
) -> str:
    """Rewrite a call that takes only some of the struct's fields."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        lit = _INV._copy_literal(src, i)
        if lit is not None:
            out.append(src[i:lit])
            i = lit
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(src[i:j])
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j])
            i = j
            continue
        if src[i].isalpha() or src[i] == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", src[i:])
            assert m is not None
            name = m.group(0)
            k = i + len(name)
            spec = by_callee.get(name)
            j = _skip_code_ws(src, k)
            preceded_fn = False
            p = i
            while p > 0 and src[p - 1].isspace():
                p -= 1
            if p >= 2 and src[p - 2 : p] == "fn" and (
                p == 2 or not (src[p - 3].isalnum() or src[p - 3] == "_")
            ):
                preceded_fn = True
            if (
                spec is not None
                and not preceded_fn
                and j < n
                and src[j] == "("
            ):
                struct, fields = spec
                canon = structs.get(struct) or fields
                if list(fields) != list(canon):
                    end = _scan_balanced(src, j, "(", ")")
                    args = _split_top_commas(src[j + 1 : end - 1])
                    if args and not (len(args) == 1 and not args[0].strip()):
                        shrunk = _shrink_struct_arg(args[0], struct, list(canon), list(fields), binder)
                        if shrunk is not None:
                            rest = ", ".join(a.strip() for a in args[1:] if a.strip())
                            rendered = shrunk if not rest else f"{shrunk}, {rest}"
                            out.append(f"{name}({rendered})")
                            i = end
                            continue
            out.append(name)
            i = k
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def _params_rewrite(
    src: str,
    structs: dict[str, list[str]],
    by_callee: dict[str, tuple[str, list[str]]] | None = None,
    binder: str | None = None,
) -> str:
    """Thread a let, shrink subset calls, then rewrite remaining literals."""
    src = _INV.expand_threaded_structs(src, structs)
    if by_callee:
        src = _subset_calls(src, structs, by_callee, binder)
    return _INV.params_literal_to_args(src, structs)


def _params_only(old_src: str, new_src: str, ctx: dict) -> bool:
    spec = ctx.get("spec")
    structs: dict[str, list[str]] = ctx.get("structs") or {}
    steps: dict[str, tuple] = ctx.get("steps") or {}
    survivor: dict[str, str] = ctx.get("survivor") or {}
    by_callee: dict[str, tuple[str, list[str]]] = ctx.get("by_callee") or {}
    if spec is not None:
        struct, fields = spec
        if _definition_params(
            old_src,
            new_src,
            struct,
            fields,
            ctx.get("by_name") or {},
            ctx.get("self_name") or "",
            structs,
            steps,
            survivor,
            by_callee,
        ):
            return True
    if not structs:
        return False
    new_rw = _strip_tma_attr(_params_rewrite(new_src, structs, by_callee, None))
    old_ex = _strip_tma_attr(expand_forwards(old_src, steps, survivor))
    if new_rw == _strip_tma_attr(new_src) and old_ex == _strip_tma_attr(old_src):
        return False
    return _params_norm(new_rw) == _params_norm(old_ex)


def _params_norm(src: str) -> str:
    """Whitespace-insensitive compare for a rewritten call.

    rustfmt may wrap a copied argument and insert a trailing comma.
    String and char literals stay whole. A comma that is not before a
    closer still counts, so a real argument edit does not match.
    """
    parts: list[str] = []
    for is_code, text in _literal_spans(src):
        if not is_code:
            parts.append(text)
            continue
        # Drop `//` comments. Keep `///` text so a doc edit is visible.
        kept: list[str] = []
        i, n = 0, len(text)
        while i < n:
            if text.startswith("//", i) and not text.startswith(("///", "//!"), i):
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            if text.startswith("/*", i):
                j = text.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            kept.append(text[i])
            i += 1
        code = re.sub(r"\s+", "", "".join(kept))
        code = re.sub(r",(?=[)\]}])", "", code)
        parts.append(code)
    return "".join(parts)


IMPL_START_RE = re.compile(r"^\s*(?:unsafe\s+)?impl\b")
MOD_NEST_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)
MOD_SEMI_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
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
    """0-based index of the attribute / doc block above a 1-based fn line.

    Inner docs and attributes (`//!`, `#![…]`) belong to the enclosing module,
    not to the first item under them (the `#![…]` lines are its
    `inner-attrs` item, see `scan_inner_attrs`).
    """
    idx = decl_line - 2
    start = decl_line - 1
    while idx >= 0:
        s = raw_lines[idx].strip()
        if not s:
            idx -= 1
            continue
        if s.startswith("//!") or s.startswith("#!["):
            break
        if s.startswith("///") or s.startswith("#["):
            start = idx
            idx -= 1
            continue
        if s.startswith("#") or s.endswith(",") or s == "]" or s.endswith(")]"):
            start = idx
            idx -= 1
            continue
        break
    return start


def _header_end(lines: list[str], start_1: int) -> int:
    """1-based last line of a `mod` / `impl` header."""
    raw = lines[start_1 - 1]
    if raw.rstrip().endswith(";") or "{" in raw:
        return start_1
    for j in range(start_1, len(lines) + 1):
        if "{" in lines[j - 1] or lines[j - 1].rstrip().endswith(";"):
            return j
    return start_1


_IMPL_FN_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)


def _first_fn_in_impl(lines: list[str], start_1: int) -> str | None:
    depth = 0
    seen_open = False
    for i in range(start_1 - 1, len(lines)):
        raw = lines[i]
        if seen_open:
            m = _IMPL_FN_RE.match(raw)
            if m and depth == 1:
                return m.group(1)
        depth += raw.count("{") - raw.count("}")
        if "{" in raw:
            seen_open = True
        if seen_open and depth <= 0:
            break
    return None


def scan_mod_impl_headers(code: str) -> list[tuple[int, int, str, str]]:
    """(start, end, kind, name) for `mod x;` / inline `mod` / `impl` headers."""
    lines = code.split("\n")
    out: list[tuple[int, int, str, str]] = []
    for i, line in enumerate(lines, 1):
        m = MOD_SEMI_RE.match(line)
        if m:
            out.append((i, i, "mod", m.group(1)))
            continue
        m = MOD_NEST_RE.match(line)
        if m:
            end = _header_end(lines, i)
            out.append((i, end, "mod", m.group(1)))
            continue
        if IMPL_START_RE.match(line):
            end = _header_end(lines, i)
            header = _impl_header_at(lines, end) or _norm_header(line.split("{", 1)[0])
            out.append((i, end, "impl-header", header))
    return out


_INNER_ATTR_RE = re.compile(r"^\s*#!\[")
INNER_ATTRS = "inner-attrs"


def scan_inner_attrs(code: str) -> list[tuple[int, int]]:
    """1-based (start, end) of each `#![…]` inner attribute; `//!` docs are not items."""
    lines = code.split("\n")
    out: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if not _INNER_ATTR_RE.match(line):
            continue
        depth = 0
        li, ci = i, line.find("#![") + 2
        while li < len(lines):
            s = lines[li]
            while ci < len(s):
                if s[ci] == "[":
                    depth += 1
                elif s[ci] == "]":
                    depth -= 1
                    if depth == 0:
                        out.append((i + 1, li + 1))
                        li = len(lines)
                        break
                ci += 1
            li += 1
            ci = 0
    return out


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
        if braced and kind == "trait":
            # Header through `{` only. A semicolon method is its own item
            # (`scan_trait_semi_fns`); a default method with a body is an
            # `fn` item. Removing one method must not mark the trait changed.
            items.append((li + 1, end_li + 1, kind, name))
            continue
        if braced:
            end_li = find_close(end_li, lines[end_li].find("{"))
        items.append((li + 1, end_li + 1, kind, name))
    return items


def scan_trait_semi_fns(code: str) -> list[tuple[int, int, str, str]]:
    """`(start, end, name, trait_name)` for `fn …;` inside a trait. 1-based.

    A default method with a body stays an `fn` item from `scan_items`.
    """
    lines = code.split("\n")
    out: list[tuple[int, int, str, str]] = []
    depth = 0
    paren = 0
    stack: list[tuple[str, int]] = []
    pending: str | None = None
    trait_re = re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )

    def sig_semi_end(li: int, ci: int) -> int | None:
        """Line index of the terminating `;`, or None when the sig opens a body."""
        p = br = 0
        while li < len(lines):
            s = lines[li]
            while ci < len(s):
                ch = s[ci]
                if ch == "(":
                    p += 1
                elif ch == ")":
                    p -= 1
                elif ch == "[":
                    br += 1
                elif ch == "]":
                    br -= 1
                elif ch == "{" and p <= 0 and br <= 0:
                    return None
                elif ch == ";" and p <= 0 and br <= 0:
                    return li
                ci += 1
            li += 1
            ci = 0
        return None

    for i, line in enumerate(lines):
        at_item = depth == (stack[-1][1] if stack else 0)
        if pending is None and at_item:
            m = trait_re.match(line)
            if m:
                pending = m.group(1)
        if stack and depth == stack[-1][1] and pending is None:
            fm = FN_RE.match(line)
            if fm:
                end = sig_semi_end(i, fm.end())
                if end is not None:
                    out.append((i + 1, end + 1, fm.group("name"), stack[-1][0]))
        for ch in line:
            if ch == "(":
                paren += 1
            elif ch == ")":
                paren = max(0, paren - 1)
            elif ch == "{" and paren == 0:
                depth += 1
                if pending is not None:
                    stack.append((pending, depth))
                    pending = None
            elif ch == "}" and paren == 0:
                depth -= 1
                while stack and depth < stack[-1][1]:
                    stack.pop()
    return out


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
        # Crate examples are harness tools (S3.6 moves them into src/bin).
        # build.rs and other non-source files under the crate stay out.
        if (
            rel.startswith("crates/")
            and "/src/" not in f"/{rel}/"
            and "/examples/" not in f"/{rel}/"
        ):
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
        for start, end, name, trait_name in scan_trait_semi_fns(code):
            if any(a <= start <= b for a, b in test_ranges):
                continue
            if _has_test_attr(raw_lines, start):
                continue
            inline = _inline_mod_at(code_lines, start)
            full_mod = "::".join(p for p in (module, inline) if p)
            key = fn_key(crate, full_mod, f"trait {trait_name}", name)
            prelude = _attr_doc_start(raw_lines, start)
            src = "\n".join(raw_lines[prelude:end])
            if key in found:
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
        for start, end, kind, name in scan_mod_impl_headers(code):
            if any(a <= start <= b for a, b in test_ranges):
                continue
            if _has_test_attr(raw_lines, start):
                continue
            inline = _inline_mod_at(code_lines, start)
            if kind == "mod" and (inline == name or inline.endswith(f"::{name}")):
                parent = inline[: -len(name)].rstrip(":")
                full_mod = "::".join(p for p in (module, parent) if p)
            else:
                full_mod = "::".join(p for p in (module, inline) if p)
            item_name = name
            if kind == "impl-header":
                first = _first_fn_in_impl(code_lines, start)
                if first:
                    item_name = f"{name}::{first}"
            key = fn_key(crate, full_mod, kind, item_name)
            prelude = _attr_doc_start(raw_lines, start)
            src = "\n".join(raw_lines[prelude:end])
            if key in found:
                key = f"{key}#{rel}:{start}"
            found[key] = {"src": src, "file": rel, "name": name, "kind": kind}
        # The file's (or an inline mod's) `#![…]` lines are one item, so a
        # lint or `forbid` that is added, dropped or edited is a compared blob.
        attrs_by_mod: dict[str, tuple[int, list[str]]] = {}
        for start, end in scan_inner_attrs(code):
            if any(a <= start <= b for a, b in test_ranges):
                continue
            inline = _inline_mod_at(code_lines, start)
            full_mod = "::".join(p for p in (module, inline) if p)
            attrs_by_mod.setdefault(full_mod, (start, []))[1].append(
                "\n".join(raw_lines[start - 1 : end])
            )
        for full_mod, (start, attrs) in attrs_by_mod.items():
            key = fn_key(crate, full_mod, None, INNER_ATTRS)
            if key in found:
                key = f"{key}#{rel}:{start}"
            found[key] = {
                "src": "\n".join(attrs),
                "file": rel,
                "name": INNER_ATTRS,
                "kind": INNER_ATTRS,
            }
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


def _prelude_attr_doc(src: str) -> tuple[str, str]:
    """Non-doc `#[]` attributes and `///` docs before the item declaration."""
    attrs: list[str] = []
    docs: list[str] = []
    for line in src.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("///"):
            docs.append(s)
            continue
        if s.startswith("#[") or (
            (s.startswith("#") or s.endswith(",") or s == "]" or s.endswith(")]"))
            and not s.startswith("#!")
        ):
            attrs.append(s)
            continue
        break
    return "\n".join(attrs), "\n".join(docs)


def _drop_trailing_commas(src: str) -> str:
    """Drop rustfmt trailing commas before `}` / `)` / `]` outside literals."""
    out: list[str] = []
    for is_code, text in _literal_spans(src):
        if not is_code:
            out.append(text)
            continue
        out.append(re.sub(r",(\s*[}\])])", r"\1", text))
    return "".join(out)


def _block_norm(src: str) -> str:
    return compare_norm(_drop_trailing_commas(src))


def _strip_norm_prefix(body: str, block: str) -> str | None:
    """If `body` starts with `block` under rewrap-norm, return the rest."""
    target = _block_norm(block)
    if not target:
        return body
    lines = body.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    accum: list[str] = []
    while i < len(lines):
        accum.append(lines[i])
        got = _block_norm("\n".join(accum))
        if got == target:
            return "\n".join(lines[i + 1 :])
        if len(got) > len(target):
            return None
        i += 1
    return None


def _strip_norm_suffix(body: str, block: str) -> str | None:
    """If `body` ends with `block` under rewrap-norm, return the prefix."""
    target = _block_norm(block)
    if not target:
        return body
    lines = body.splitlines()
    j = len(lines)
    while j > 0 and not lines[j - 1].strip():
        j -= 1
    accum: list[str] = []
    while j > 0:
        j -= 1
        accum.insert(0, lines[j])
        got = _block_norm("\n".join(accum))
        if got == target:
            return "\n".join(lines[:j])
        if len(got) > len(target):
            return None
    return None


def _apply_edits(
    body: str, edits: list[tuple[str, str]]
) -> tuple[str, list[str]]:
    unused: list[str] = []
    text = body
    for old, new in edits:
        if old not in text:
            unused.append(old)
            continue
        text = text.replace(old, new, 1)
    return text, unused


def _sig_one_line(src: str) -> str:
    return " ".join(signature_of(src).split())


def compare_trees(
    old_root: pathlib.Path,
    new_root: pathlib.Path,
    moves: dict[str, str],
    accept: dict[str, dict[str, str]],
    splits: dict[str, list[str]],
    glue: dict[str, list[str]] | list[str],
    roots: list[str] | None = None,
    split_extra: dict[str, dict[str, object]] | None = None,
    params: dict[str, tuple[str, list[str]]] | None = None,
) -> dict[str, object]:
    old = extract(old_root, roots)
    new = extract(new_root, roots)
    params = params or {}
    structs: dict[str, list[str]] = {}
    steps: dict[str, tuple] = {}
    survivor: dict[str, str] = {}
    by_callee: dict[str, tuple[str, list[str]]] = {}
    by_name: dict[str, str] = {}
    if params:
        structs, steps, survivor, by_callee = prepare_params(old, new, params, moves)
        by_name = _fns_by_name(old)
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
    unused_edit: list[str] = []
    unused_head: list[str] = []
    unused_tail: list[str] = []
    split_problems: list[str] = []
    split_sigs: list[tuple[str, str]] = []
    accepted: list[tuple[str, str, str]] = []
    used_accept: set[str] = set()
    extras = split_extra or {}

    for old_key, new_keys in splits.items():
        if old_key not in old:
            missing_split.append(old_key)
            continue
        missing = [k for k in new_keys if k not in new]
        if missing:
            missing_split.extend(f"{old_key} -> {k}" for k in missing)
            continue
        ex = extras.get(old_key, _empty_split_extra())
        heads = ex.get("heads") or {}
        tails = ex.get("tails") or {}
        edits = list(ex.get("edits") or [])
        assert isinstance(heads, dict) and isinstance(tails, dict)
        for hk in heads:
            if hk not in new_keys:
                unused_head.append(f"{old_key}: {hk}")
        for tk in tails:
            if tk not in new_keys:
                unused_tail.append(f"{old_key}: {tk}")
        dispatcher = old_key if old_key in new_keys else new_keys[0]
        old_attrs, old_docs = _prelude_attr_doc(old[old_key]["src"])
        disp_attrs, disp_docs = _prelude_attr_doc(new[dispatcher]["src"])
        attr_ok = compare_norm(old_attrs) == compare_norm(disp_attrs)
        doc_only_disp = compare_norm(old_docs) != compare_norm(disp_docs)
        if not attr_ok:
            split_problems.append(f"--split attribute mismatch: {old_key}")
        phase_attr_ok = True
        for k in new_keys:
            if k == dispatcher:
                continue
            phase_attrs, _docs = _prelude_attr_doc(new[k]["src"])
            if not phase_attrs.strip():
                continue
            entry = accept.get(k)
            if (
                entry is not None
                and entry["new"] == k
                and entry["new_hash"] == blob_hash(new[k]["src"])
            ):
                used_accept_early = True
            else:
                used_accept_early = False
            if not used_accept_early:
                phase_attr_ok = False
                split_problems.append(f"--split phase attributes: {k}")
            else:
                used_accept.add(k)
                accepted.append((k, k, entry["reason"]))
        cores: list[str] = []
        placed = True
        for k in new_keys:
            body = inner_body(new[k]["src"])
            head = heads.get(k)
            tail = tails.get(k)
            if head:
                rest = _strip_norm_prefix(body, str(head))
                if rest is None:
                    placed = False
                    split_problems.append(f"--split head not at start: {k}")
                    break
                if _block_norm(str(head)) in _block_norm(rest):
                    placed = False
                    split_problems.append(f"--split head found elsewhere: {k}")
                    break
                body = rest
            if tail:
                rest = _strip_norm_suffix(body, str(tail))
                if rest is None:
                    placed = False
                    split_problems.append(f"--split tail not at end: {k}")
                    break
                if _block_norm(str(tail)) in _block_norm(rest):
                    placed = False
                    split_problems.append(f"--split tail found elsewhere: {k}")
                    break
                body = rest
            cores.append(body)
        g_lines = _glue_for_split(glue, old_key)
        old_body = inner_body(old[old_key]["src"])
        old_edited, edit_unused = _apply_edits(old_body, edits)
        unused_edit.extend(f"{old_key}: {e}" for e in edit_unused)
        concat = "\n".join(cores) if placed else ""
        unused, illegal = glue_problems(old_edited, concat, g_lines)
        unused_glue.extend(f"{old_key}: {g}" for g in unused)
        illegal_glue.extend(f"{old_key}: {g}" for g in illegal)
        stripped = strip_glue_lines(concat, g_lines)
        affix_unused = any(
            x.startswith(f"{old_key}:") for x in unused_head + unused_tail
        )
        body_ok = (
            placed
            and compare_norm(old_edited) == compare_norm(stripped)
            and not unused
            and not illegal
            and not edit_unused
            and not affix_unused
        )
        if body_ok and attr_ok and phase_attr_ok:
            split_ok.append(old_key)
            used_old.add(old_key)
            used_new.update(new_keys)
            if doc_only_disp:
                pairs.append((old_key, dispatcher, "doc-only"))
            for k in new_keys:
                split_sigs.append((k, _sig_one_line(new[k]["src"])))
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
        ctx = None
        if params:
            ctx = {
                "spec": params.get(okey),
                "structs": structs,
                "steps": steps,
                "survivor": survivor,
                "by_callee": by_callee,
                "by_name": by_name,
                "self_name": ofn["name"],
            }
        kind = classify(ofn["src"], new[nkey]["src"], ctx)
        pairs.append((okey, nkey, kind))
        used_old.add(okey)
        used_new.add(nkey)

    if params:
        unused_params = sorted(k for k in params if k not in used_old)
        if unused_params:
            raise SystemExit(
                f"hygiene-fn-diff: --params entry unused: {unused_params[0]}"
            )
    removed = sorted(k for k in old if k not in used_old)
    added = sorted(k for k in new if k not in used_new)
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
    vis_widen = [(o, n) for o, n, k in pairs if k == "vis-widen"]
    fmt_only = [(o, n) for o, n, k in pairs if k == "fmt-only"]
    doc_only = [(o, n) for o, n, k in pairs if k == "doc-only"]
    changed = [(o, n) for o, n, k in pairs if k == "changed"]
    params_only = [(o, n) for o, n, k in pairs if k == "params-only"]

    unaccepted: list[tuple[str, str]] = []
    missing_rhs: list[str] = []
    for okey, nkey in [*changed, *vis_widen]:
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
        "vis_widen": len(vis_widen),
        "vis_widen_items": vis_widen,
        "fmt_only": len(fmt_only),
        "fmt_only_items": fmt_only,
        "doc_only": len(doc_only),
        "doc_only_items": doc_only,
        "changed": len(changed),
        "params_only": len(params_only),
        "params_only_items": params_only,
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
        "unused_edit": unused_edit,
        "unused_head": unused_head,
        "unused_tail": unused_tail,
        "split_problems": split_problems,
        "split_sigs": split_sigs,
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
        f"vis-widen {report['vis_widen']}",
        f"fmt-only {report['fmt_only']}",
        f"doc-only {report['doc_only']}",
        f"changed {report['changed']}",
        f"params-only {report.get('params_only', 0)}",
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
    for o, n in report["vis_widen_items"]:  # type: ignore[misc]
        lines.append(f"vis-widen {o} -> {n}")
    for o, n in report["fmt_only_items"]:  # type: ignore[misc]
        lines.append(f"fmt-only {o} -> {n}")
    for o, n in report["doc_only_items"]:  # type: ignore[misc]
        lines.append(f"doc-only {o} -> {n}")
    for o, n in report.get("params_only_items") or []:  # type: ignore[misc]
        lines.append(f"params-only {o} -> {n}")
    for o, n, reason in report["accepted"]:  # type: ignore[misc]
        lines.append(f"accepted {o} -> {n}: {reason}")
    for k, sig in report.get("split_sigs", []):  # type: ignore[misc]
        lines.append(f"split-sig {k}: {sig}")
    return "\n".join(lines) + "\n"


def evaluate(report: dict[str, object]) -> None:
    errs: list[str] = []
    widen = {(o, n) for o, n in report.get("vis_widen_items", [])}  # type: ignore[union-attr]
    for o, n in report["unaccepted"]:  # type: ignore[misc]
        if (o, n) in widen:
            errs.append(f"vis-widen not in --accept: {o} -> {n}")
        else:
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
    for k in report.get("unused_edit", []):  # type: ignore[misc]
        errs.append(f"--split edit unused: {k}")
    for k in report.get("unused_head", []):  # type: ignore[misc]
        errs.append(f"--split head unused: {k}")
    for k in report.get("unused_tail", []):  # type: ignore[misc]
        errs.append(f"--split tail unused: {k}")
    for k in report.get("split_problems", []):  # type: ignore[misc]
        errs.append(str(k))
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
        evaluate(pub_to_crate)
        if pub_to_crate["vis_only"] != 1 or pub_to_crate["changed"] != 0:
            raise SystemExit("hygiene-fn-diff --self-test: pub → pub(crate) must be vis-only")
        n += 1

        # A widening is vis-widen and red. Narrowing the other way stays vis-only.
        _write_crate(old, "crates/demo/src/lib.rs", "struct S { a: i32 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "pub struct S { pub(crate) a: i32 }\n")
        widen_struct = compare_trees(old, new, {}, {}, {}, [])
        if (
            widen_struct["vis_widen"] != 1
            or widen_struct["vis_only"] != 0
            or widen_struct["changed"] != 0
        ):
            raise SystemExit(
                "hygiene-fn-diff --self-test: private struct → pub struct "
                f"with a pub(crate) field must be vis-widen: {widen_struct}"
            )
        _must_red(widen_struct, "private struct → pub struct")
        if "vis-widen demo\tstruct::S -> demo\tstruct::S" not in render(widen_struct):
            raise SystemExit("hygiene-fn-diff --self-test: render must name the vis-widen struct")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "struct S { pub(crate) a: i32, pub(crate) b: i32 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "struct S { pub a: i32, pub(crate) b: i32 }\n",
        )
        widen_mixed = compare_trees(old, new, {}, {}, {}, [])
        if widen_mixed["vis_widen"] != 1 or widen_mixed["vis_only"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: pub(crate) fields → pub and "
                f"pub(crate) mixed must be vis-widen: {widen_mixed}"
            )
        _must_red(widen_mixed, "mixed pub and pub(crate) fields")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "pub(crate) fn f() { 1 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "pub fn f() { 1 }\n")
        widen_fn = compare_trees(old, new, {}, {}, {}, [])
        if widen_fn["vis_widen"] != 1 or widen_fn["changed"] != 0 or widen_fn["vis_only"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: pub(crate) → pub with an identical "
                f"body must be vis-widen: {widen_fn}"
            )
        _must_red(widen_fn, "pub(crate) → pub")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "/// was pub(crate)\npub(crate) fn f() { 1 }\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "/// now public\npub fn f() { 1 }\n",
        )
        widen_doc = compare_trees(old, new, {}, {}, {}, [])
        if widen_doc["vis_widen"] != 1 or widen_doc["vis_only"] != 0 or widen_doc["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: pub(crate) inside /// is not a "
                f"visibility token: {widen_doc}"
            )
        _must_red(widen_doc, "/// text that contains pub(crate)")
        n += 1

        # `pub` is a prefix of `pubkey`, not a visibility token. Narrowing
        # the fn while renaming that call is a body edit.
        _write_crate(old, "crates/demo/src/lib.rs", "pub fn f() {\n    pubkey()\n}\n")
        _write_crate(
            new, "crates/demo/src/lib.rs", "pub(crate) fn f() {\n    key()\n}\n"
        )
        ident = compare_trees(old, new, {}, {}, {}, [])
        if ident["changed"] != 1 or ident["vis_only"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: pub prefix of an identifier "
                f"must be changed: {ident}"
            )
        _must_red(ident, "pub prefix of an identifier")
        _write_crate(
            new, "crates/demo/src/lib.rs", "pub(crate) fn f() {\n    pubkey()\n}\n"
        )
        ident_vis = compare_trees(old, new, {}, {}, {}, [])
        if ident_vis["vis_only"] != 1 or ident_vis["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: vis edit beside pubkey() "
                f"must stay vis-only: {ident_vis}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "pub trait T {\n    fn kept(&self) -> i32;\n    fn gone(&self);\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub trait T {\n    fn kept(&self) -> i32;\n}\n",
        )
        semi = compare_trees(old, new, {}, {}, {}, [])
        if semi["changed"] != 0 or semi["removed"] != ["demo\ttrait T::gone"]:
            raise SystemExit(
                "hygiene-fn-diff --self-test: semicolon trait method is a "
                f"removal, trait header stays: {semi}"
            )
        _must_red(semi, "semicolon trait method removal")
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

        # the widening pushes the signature past the width limit: rustfmt
        # breaks the parameter list one per line with a trailing comma
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn wide(store: &Store, acl: &Acl, actor: &str, proc: u32) -> Vec<u8> {\n    v(proc)\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(super) fn wide(\n    store: &Store,\n    acl: &Acl,\n    actor: &str,\n"
            "    proc: u32,\n) -> Vec<u8> {\n    v(proc)\n}\n",
        )
        rewrap = compare_trees(old, new, {}, {}, {}, [])
        evaluate(rewrap)
        if rewrap["vis_only"] != 1 or rewrap["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: rustfmt signature rewrap must be vis-only: {rewrap}"
            )
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(super) fn wide(\n    store: &Store,\n    actor: &str,\n    acl: &Acl,\n"
            "    proc: u32,\n) -> Vec<u8> {\n    v(proc)\n}\n",
        )
        reordered = compare_trees(old, new, {}, {}, {}, [])
        if reordered["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: a reordered parameter under a rewrap is changed")
        _must_red(reordered, "parameter reorder under a rewrap")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "fn one(a: (u32,)) -> u32 {\n    a.0\n}\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(super) fn one(a: (u32)) -> u32 {\n    a.0\n}\n",
        )
        tuple1 = compare_trees(old, new, {}, {}, {}, [])
        if tuple1["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: `(T,)` → `(T)` in a signature is changed")
        _must_red(tuple1, "1-tuple comma")
        n += 1

        # the module header above the first item is the module's, not the item's
        _write_crate(old, "crates/demo/src/lib.rs", "//! Old header.\n\nconst A: i32 = 1;\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "//! New header, two lines\n//! long.\n\npub(super) const A: i32 = 1;\n",
        )
        hdr = compare_trees(old, new, {}, {}, {}, [])
        evaluate(hdr)
        if hdr["vis_only"] != 1 or hdr["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: a `//!` header is not the first item's doc: {hdr}"
            )
        n += 1

        # the file's `#![…]` lines are their own item: kept out of the first
        # item's blob, yet compared
        lints = "#![forbid(unsafe_code)]\n#![deny(clippy::unwrap_used, clippy::panic)]\n"
        _write_crate(old, "crates/demo/src/lib.rs", f"//! Old.\n\n{lints}\nconst A: i32 = 1;\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            f"//! New header.\n\n{lints}\npub(super) const A: i32 = 1;\n",
        )
        inner_same = compare_trees(old, new, {}, {}, {}, [])
        evaluate(inner_same)
        if (
            inner_same["vis_only"] != 1
            or inner_same["identical"] != 1
            or inner_same["new_kinds"].get(INNER_ATTRS) != 1  # type: ignore[union-attr]
        ):
            raise SystemExit(
                f"hygiene-fn-diff --self-test: unchanged `#![…]` must be one identical item: {inner_same}"
            )
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "//! Old.\n\n#![deny(clippy::unwrap_used, clippy::panic)]\n\nconst A: i32 = 1;\n",
        )
        dropped_forbid = compare_trees(old, new, {}, {}, {}, [])
        if dropped_forbid["changed"] != 1 or dropped_forbid["unaccepted"] != [
            ("demo\tinner-attrs", "demo\tinner-attrs")
        ]:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: a dropped `#![forbid]` must be changed: {dropped_forbid}"
            )
        _must_red(dropped_forbid, "dropped #![forbid(unsafe_code)]")
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "//! Old.\n\n#![forbid(unsafe_code)]\n#![warn(clippy::unwrap_used, clippy::panic)]\n\n"
            "const A: i32 = 1;\n",
        )
        deny_to_warn = compare_trees(old, new, {}, {}, {}, [])
        if deny_to_warn["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: `#![deny]` → `#![warn]` must be changed")
        _must_red(deny_to_warn, "#![deny] → #![warn]")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "fn f() {}\n")
        _write_crate(new, "crates/demo/src/lib.rs", "#![allow(dead_code)]\nfn f() {}\n")
        added_allow = compare_trees(old, new, {}, {}, {}, [])
        if added_allow["added"] != ["demo\tinner-attrs"]:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: an added `#![allow]` must be an added item: {added_allow}"
            )
        _must_red(added_allow, "added #![allow(dead_code)]")
        n += 1

        # `mut` / `const` before `(` open a type, not a parameter list: the
        # 1-tuple comma is kept and its loss is a type change
        for prefix in ("&mut ", "*const "):
            _write_crate(
                old, "crates/demo/src/lib.rs", f"fn one(a: {prefix}(u32,)) -> u32 {{\n    a.0\n}}\n"
            )
            _write_crate(
                new,
                "crates/demo/src/lib.rs",
                f"pub(super) fn one(a: {prefix}(u32)) -> u32 {{\n    a.0\n}}\n",
            )
            ptr_tuple = compare_trees(old, new, {}, {}, {}, [])
            if ptr_tuple["changed"] != 1:
                raise SystemExit(
                    f"hygiene-fn-diff --self-test: `{prefix}(T,)` → `{prefix}(T)` must be changed"
                )
            _must_red(ptr_tuple, f"{prefix.strip()} 1-tuple comma")
            n += 1

        # a lifetime before `(` is a type, not a list opener
        _write_crate(
            old, "crates/demo/src/lib.rs", "fn one(a: &'a (u32,)) -> u32 {\n    a.0\n}\n"
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub(super) fn one(a: &'a (u32)) -> u32 {\n    a.0\n}\n",
        )
        life_tuple = compare_trees(old, new, {}, {}, {}, [])
        if life_tuple["changed"] != 1:
            raise SystemExit(
                "hygiene-fn-diff --self-test: `&'a (T,)` → `&'a (T)` must be changed"
            )
        _must_red(life_tuple, "lifetime 1-tuple comma")
        n += 1

        # a `,)` inside a string literal in the head is content, not a rewrap
        _write_crate(
            old, "crates/demo/src/lib.rs", '#[doc = "see foo(a,)"]\nfn d() -> u32 {\n    1\n}\n'
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            '#[doc = "see foo(a)"]\npub(super) fn d() -> u32 {\n    1\n}\n',
        )
        doc_lit = compare_trees(old, new, {}, {}, {}, [])
        if doc_lit["changed"] != 1 or doc_lit["vis_only"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: a `,)` edit inside `#[doc = …]` is never vis-only: {doc_lit}"
            )
        _must_red(doc_lit, "comma edit inside a doc literal")
        n += 1

        # a rewrap with no visibility change is fmt-only, not vis-only
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "pub fn wide(store: &Store, acl: &Acl, actor: &str, proc: u32) -> Vec<u8> {\n    v(proc)\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "pub fn wide(\n    store: &Store,\n    acl: &Acl,\n    actor: &str,\n"
            "    proc: u32,\n) -> Vec<u8> {\n    v(proc)\n}\n",
        )
        fmt_only = compare_trees(old, new, {}, {}, {}, [])
        evaluate(fmt_only)
        if fmt_only["vis_only"] != 0 or fmt_only["fmt_only"] != 1 or fmt_only["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: a comma-only rewrap is fmt-only, not vis-only: {fmt_only}"
            )
        if "fmt-only demo\twide -> demo\twide" not in render(fmt_only):
            raise SystemExit("hygiene-fn-diff --self-test: render must name the fmt-only item")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "struct S { a: i32 }\n")
        _write_crate(new, "crates/demo/src/lib.rs", "struct S { pub a: i32 }\n")
        fld_pub = compare_trees(old, new, {}, {}, {}, [])
        if fld_pub["vis_widen"] != 1 or fld_pub["changed"] != 0 or fld_pub["vis_only"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: field → pub must be vis-widen: "
                f"{fld_pub}"
            )
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

        natural_map, _g, _e = load_splits(None, ["demo\twhole = demo\twhole + demo\ttail"])
        if natural_map != {"demo\twhole": ["demo\twhole", "demo\ttail"]}:
            raise SystemExit("hygiene-fn-diff --self-test: old = old + tail must parse")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    b();\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    tail();\n}\nfn tail() {\n    b();\n}\n",
        )
        natural = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\twhole": ["demo\twhole", "demo\ttail"]},
            ["tail();"],
        )
        evaluate(natural)
        if natural["split_ok"] != ["demo\twhole"]:
            raise SystemExit("hygiene-fn-diff --self-test: old = old + tail must split-ok")
        n += 1

        splitpath = pathlib.Path(tmp) / "splits.txt"
        splitpath.write_text(
            "demo\tone = demo\ta + demo\tb\n"
            "glue: b();\n"
            "demo\ttwo = demo\tc + demo\td\n"
            "glue: d();\n",
            encoding="utf-8",
        )
        smap, sglue, _sex = load_splits(splitpath, [])
        if sglue != {"demo\tone": ["b();"], "demo\ttwo": ["d();"]}:
            raise SystemExit(f"hygiene-fn-diff --self-test: per-split glue map: {sglue}")
        n += 1

        try:
            load_keyed_id_map(pathlib.Path(tmp) / "missing-moves.txt", "moves")
        except SystemExit as exc:
            if "not found" not in str(exc):
                raise SystemExit(f"hygiene-fn-diff --self-test: missing --moves: {exc}")
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: missing --moves must fail")

        try:
            load_accept(pathlib.Path(tmp) / "missing-accept.txt")
        except SystemExit as exc:
            if "not found" not in str(exc):
                raise SystemExit(f"hygiene-fn-diff --self-test: missing --accept: {exc}")
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: missing --accept must fail")

        try:
            load_splits(pathlib.Path(tmp) / "missing-split.txt", [])
        except SystemExit as exc:
            if "not found" not in str(exc):
                raise SystemExit(f"hygiene-fn-diff --self-test: missing --split: {exc}")
            n += 1
        else:
            raise SystemExit("hygiene-fn-diff --self-test: missing --split must fail")

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
        accpath = pathlib.Path(tmp) / "accept-removed.txt"
        accpath.write_text(
            f"demo\tgone = demo\tgone | sha256:{blob_hash(gone_src)} | "
            f"sha256:{blob_hash('')} | removed helper\n",
            encoding="utf-8",
        )
        gone_acc = load_accept(accpath)
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
        from_keys = [k for k in keyed if k.endswith("::from") and "impl-header" not in k]
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

        _write_crate(old, "crates/demo/examples/diffsend.rs", "fn main() {}\nfn helper() {}\n")
        crate_ex = extract(old)
        (old / "crates/demo/examples/diffsend.rs").unlink()
        if "demo\tdiffsend::main" not in crate_ex or "demo\tdiffsend::helper" not in crate_ex:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: crate examples: {sorted(crate_ex)}"
            )
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "mod sub;\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            '#[cfg(feature = "extra")]\nmod sub;\n',
        )
        cfg_mod = compare_trees(old, new, {}, {}, {}, [])
        if cfg_mod["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: #[cfg] on mod sub; must be changed")
        _must_red(cfg_mod, "#[cfg] on mod sub;")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "mod inner {\n    fn m() {}\n}\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            '#[cfg(feature = "extra")]\nmod inner {\n    fn m() {}\n}\n',
        )
        cfg_inline = compare_trees(old, new, {}, {}, {}, [])
        if cfg_inline["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: #[cfg] on inline mod must be changed")
        _must_red(cfg_inline, "#[cfg] on inline mod")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "impl Foo {\n    fn m() {}\n}\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            '#[cfg(feature = "extra")]\nimpl Foo {\n    fn m() {}\n}\n',
        )
        cfg_impl = compare_trees(old, new, {}, {}, {}, [])
        if cfg_impl["changed"] != 1:
            raise SystemExit("hygiene-fn-diff --self-test: #[cfg] on impl must be changed")
        _must_red(cfg_impl, "#[cfg] on impl")
        n += 1

        # R1 (a): attributes under --split. The S3.3a auditor fixture
        # (allow + rustfmt::skip on the dispatcher and the phases) is red.
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn big() {\n    let mut x = a();\n    b(x);\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "#[allow(clippy::all)]\n#[rustfmt::skip]\n"
            "fn big() {\n    let x = p1();\n    p2(x)\n}\n\n"
            "#[allow(unused_mut)]\n#[rustfmt::skip]\n"
            "fn p1() -> u32 {\n    let mut x = a();\n    x\n}\n\n"
            "#[allow(clippy::all, unsafe_code)]\n"
            "fn p2(x: u32) {\n    b(x);\n}\n",
        )
        attr_fix = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\tbig": ["demo\tbig", "demo\tp1", "demo\tp2"]},
            ["let x = p1();", "p2(x)", "x"],
        )
        if not attr_fix["split_fail"]:
            raise SystemExit(
                "hygiene-fn-diff --self-test: split-attr fixture must fail"
            )
        _must_red(attr_fix, "split-attr fixture")
        n += 1

        _write_crate(old, "crates/demo/src/lib.rs", "fn whole() {\n    a();\n    b();\n}\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    tail();\n}\n"
            "#[allow(dead_code)]\nfn tail() {\n    b();\n}\n",
        )
        phase_allow = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\twhole": ["demo\twhole", "demo\ttail"]},
            ["tail();"],
        )
        _must_red(phase_allow, "phase #[allow] without accept")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "#[allow(dead_code)]\nfn whole() {\n    a();\n    b();\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    tail();\n}\nfn tail() {\n    b();\n}\n",
        )
        dropped_attr = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\twhole": ["demo\twhole", "demo\ttail"]},
            ["tail();"],
        )
        _must_red(dropped_attr, "attribute dropped from the old fn")
        n += 1

        # R1 (b): head: / tail: at the boundary after rewrap; elsewhere is red.
        wrap_map = pathlib.Path(tmp) / "split-wrap.txt"
        wrap_map.write_text(
            "demo\twhole = demo\twhole + demo\ttail\n"
            "glue: tail(x);\n"
            "head: demo\ttail\n"
            "    let Packed {\n"
            "        x,\n"
            "    } = Packed { x };\n"
            "tail: demo\ttail\n"
            "    Ok(Out {\n"
            "        x,\n"
            "    })\n"
            "edit: let mut x => let x\n",
            encoding="utf-8",
        )
        _wmap, wglue, wextra = load_splits(wrap_map, [])
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    let mut x = a();\n    b(x);\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    let x = a();\n    tail(x);\n}\n"
            "fn tail(x: i32) {\n    let Packed {\n        x,\n    } = Packed { x };\n"
            "    b(x);\n    Ok(Out {\n        x,\n    })\n}\n",
        )
        wrapped = compare_trees(
            old, new, {}, {}, _wmap, wglue, split_extra=wextra
        )
        if wrapped["split_ok"] != ["demo\twhole"]:
            raise SystemExit(
                "hygiene-fn-diff --self-test: wrapped head: / let-mut edit must split-ok"
            )
        shown = render(wrapped)
        if "split-sig demo\ttail:" not in shown:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: phase signature missing: {shown}"
            )
        evaluate(wrapped)
        n += 1

        mid_map = pathlib.Path(tmp) / "split-mid.txt"
        mid_map.write_text(
            "demo\twhole = demo\twhole + demo\ttail\n"
            "glue: tail();\n"
            "head: demo\ttail\n"
            "    let Packed { x } = g;\n",
            encoding="utf-8",
        )
        _mmap, mglue, mextra = load_splits(mid_map, [])
        _write_crate(old, "crates/demo/src/lib.rs", "fn whole() {\n    a();\n    b();\n}\n")
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    a();\n    tail();\n}\n"
            "fn tail() {\n    b();\n    let Packed { x } = g;\n}\n",
        )
        mid_head = compare_trees(
            old, new, {}, {}, _mmap, mglue, split_extra=mextra
        )
        _must_red(mid_head, "head: block in the middle of a body")
        n += 1

        # R1 (c): only let mut → let.
        try:
            load_splits(None, ["demo\twhole = demo\ta + demo\tb", "edit: foo => bar"])
        except SystemExit:
            n += 1
        else:
            raise SystemExit(
                "hygiene-fn-diff --self-test: edit: that is not let mut → let must fail"
            )

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    let mut x = a();\n    b(x);\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn whole() {\n    let x = a();\n    tail(x);\n}\n"
            "fn tail(x: i32) {\n    b(x);\n}\n",
        )
        no_edit = compare_trees(
            old,
            new,
            {},
            {},
            {"demo\twhole": ["demo\twhole", "demo\ttail"]},
            ["tail(x);"],
        )
        _must_red(no_edit, "let mut without a declared edit")
        n += 1

        pmap = {"demo\tg": ("S", ["a", "b"])}
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(p: S) -> i32 {\n    let S { a, b } = p;\n    a + b\n}\n",
        )
        defined = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        evaluate(defined)
        if defined["params_only"] != 1 or defined["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: params definition must be params-only: {defined}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\nfn caller() {\n    g(x, y)\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\nfn caller() {\n    g(S { a: x, b: y })\n}\n",
        )
        called = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        evaluate(called)
        if called["params_only"] != 1 or called["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: params call site must be params-only: {called}"
            )
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            "fn caller() {\n    g(S { b: y, a: x })\n}\n",
        )
        swapped = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        if swapped["params_only"] != 0 or swapped["changed"] != 1:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: swapped fields must be changed: {swapped}"
            )
        _must_red(swapped, "two fields swapped")
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            "fn caller() {\n    let x = a;\n    g(S { a: x, b: y })\n}\n",
        )
        hoisted = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        if hoisted["params_only"] != 0 or hoisted["changed"] != 1:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: hoisted argument must be changed: {hoisted}"
            )
        _must_red(hoisted, "argument hoisted into a let")
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            "fn caller() {\n    g(S { a: x, ..Default::default() })\n}\n",
        )
        defaulted = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        if defaulted["params_only"] != 0 or defaulted["changed"] != 1:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: ..Default tail must be changed: {defaulted}"
            )
        _must_red(defaulted, "..Default::default() tail")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(p: S) -> i32 {\n    let S { a, b: c } = p;\n    a + b\n}\n",
        )
        renamed = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        if renamed["params_only"] != 0 or renamed["changed"] != 1:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: renamed destructure must be changed: {renamed}"
            )
        _must_red(renamed, "destructure renames a field")
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(p: S) -> i32 {\n    let S { a, b } = p;\n    a + c\n}\n",
        )
        body_tok = compare_trees(old, new, {}, {}, {}, [], params=pmap)
        if body_tok["params_only"] != 0 or body_tok["changed"] != 1:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: body token in a converted fn must be changed: {body_tok}"
            )
        _must_red(body_tok, "body token changed inside a converted fn")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(p: S) -> i32 {\n    let S { b, a } = p;\n    a + b\n}\n",
        )
        try:
            compare_trees(old, new, {}, {}, {}, [], params={"demo\tg": ("S", ["b", "a"])})
        except SystemExit as exc:
            if "disagrees" not in str(exc):
                raise SystemExit(
                    f"hygiene-fn-diff --self-test: map order must name the function: {exc}"
                )
            n += 1
        else:
            raise SystemExit(
                "hygiene-fn-diff --self-test: map order that disagrees with the signature must fail"
            )

        # rustfmt may wrap a copied argument and insert a trailing comma.
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(a: Vec<i32>) {}\nfn caller() {\n    g(vec![x])\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(a: Vec<i32>) {}\nfn caller() {\n    g(S { a: vec![ x, ] })\n}\n",
        )
        wrapped = compare_trees(old, new, {}, {}, {}, [], params={"demo\tg": ("S", ["a"])})
        evaluate(wrapped)
        if wrapped["params_only"] != 1 or wrapped["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: rustfmt trailing comma in a "
                f"copied argument must be params-only: {wrapped}"
            )
        n += 1

        # A callee may take a consecutive slice of the struct. `..` covers
        # the fields that function never had. The extra literal fields must
        # be those bindings, and passing the struct value expands to the slice.
        slice_map = {
            "demo\twide": ("S", ["a", "b", "c"]),
            "demo\tnarrow": ("S", ["a", "b"]),
        }
        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn wide(a: i32, b: i32, c: i32) -> i32 {\n    narrow(a, b)\n}\n"
            "fn narrow(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            "fn caller() {\n    narrow(x, y)\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn wide(p: S) -> i32 {\n    let S { a, b, c } = p;\n    narrow(p)\n}\n"
            "fn narrow(p: S) -> i32 {\n    let S { a, b, .. } = p;\n    a + b\n}\n"
            "fn caller() {\n    narrow(S { a: x, b: y, c })\n}\n",
        )
        sliced = compare_trees(old, new, {}, {}, {}, [], params=slice_map)
        evaluate(sliced)
        if sliced["params_only"] != 3 or sliced["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: struct slice must be params-only: "
                f"{sliced}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn wide(a: i32, b: i32, c: i32) -> i32 {\n    narrow(a, b)\n}\n"
            "fn narrow(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn wide(p: S) -> i32 {\n    let S { a, b, c } = p;\n"
            "    narrow(S { a, b, c: p.c })\n}\n"
            "fn narrow(p: S) -> i32 {\n    let S { a, b, .. } = p;\n    a + b\n}\n",
        )
        read = compare_trees(old, new, {}, {}, {}, [], params=slice_map)
        evaluate(read)
        if read["params_only"] != 2 or read["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: binder.field on an unused struct "
                f"field must be params-only: {read}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn wide(a: i32, b: i32, c: i32) -> i32 {\n    narrow(a, b)\n}\n"
            "fn narrow(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            "fn caller() {\n    narrow(x, y)\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn wide(p: S) -> i32 {\n    let S { a, b, c } = p;\n    narrow(p)\n}\n"
            "fn narrow(p: S) -> i32 {\n    let S { a, .. } = p;\n    a + b\n}\n"
            "fn caller() {\n    narrow(S { a: x, b: y, c })\n}\n",
        )
        dropped = compare_trees(old, new, {}, {}, {}, [], params=slice_map)
        if dropped["params_only"] != 2 or dropped["changed"] != 1:
            raise SystemExit(
                "hygiene-fn-diff --self-test: .. that drops a mapped field must be "
                f"changed: {dropped}"
            )
        _must_red(dropped, ".. drops a mapped field")
        n += 1

        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn wide(p: S) -> i32 {\n    let S { a, b, c } = p;\n    narrow(p)\n}\n"
            "fn narrow(p: S) -> i32 {\n    let S { a, b, .. } = p;\n    a + b\n}\n"
            "fn caller() {\n    narrow(S { a: x, b: y, c: side() })\n}\n",
        )
        side = compare_trees(old, new, {}, {}, {}, [], params=slice_map)
        if side["changed"] != 1:
            raise SystemExit(
                "hygiene-fn-diff --self-test: an extra field expression must stay "
                f"changed: {side}"
            )
        _must_red(side, "extra field is not the binding")
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn wide(a: i32, b: i32, c: i32) {}\nfn narrow(a: i32, c: i32) {}\n",
        )
        try:
            compare_trees(
                old,
                new,
                {},
                {},
                {},
                [],
                params={
                    "demo\twide": ("S", ["a", "b", "c"]),
                    "demo\tnarrow": ("S", ["a", "c"]),
                },
            )
        except SystemExit as exc:
            if "fields disagree" not in str(exc):
                raise SystemExit(
                    f"hygiene-fn-diff --self-test: non-slice fields must disagree: {exc}"
                )
            n += 1
        else:
            raise SystemExit(
                "hygiene-fn-diff --self-test: a non-consecutive field slice must fail"
            )

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) {}\nfn caller() {\n    g(x, y)\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(a: i32, b: i32) {}\nfn caller() {\n    g(&S { a: x, b: y })\n}\n",
        )
        borrowed = compare_trees(
            old, new, {}, {}, {}, [], params={"demo\tg": ("S", ["a", "b"])}
        )
        evaluate(borrowed)
        if borrowed["params_only"] != 1 or borrowed["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: &Struct { } must be params-only: "
                f"{borrowed}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "fn g(_a: i32, b: i32) -> i32 {\n    b\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "fn g(p: S) -> i32 {\n    #[allow(unused_variables)]\n"
            "    let S { a, b } = p;\n    b\n}\n",
        )
        unused = compare_trees(old, new, {}, {}, {}, [], params={"demo\tg": ("S", ["a", "b"])})
        evaluate(unused)
        if unused["params_only"] != 1 or unused["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: a leading underscore and an allow "
                f"on the destructure must be params-only: {unused}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "trait T {\n    fn g(a: i32, b: i32);\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "trait T {\n    fn g(p: S);\n}\n",
        )
        semi = compare_trees(old, new, {}, {}, {}, [], params={"demo\ttrait T::g": ("S", ["a", "b"])})
        evaluate(semi)
        if semi["params_only"] != 1 or semi["changed"] != 0:
            raise SystemExit(
                f"hygiene-fn-diff --self-test: a semicolon trait method must be params-only: {semi}"
            )
        n += 1

        _write_crate(
            old,
            "crates/demo/src/lib.rs",
            "#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]\n"
            "fn g(a: i32) -> i32 {\n    a\n}\n",
        )
        _write_crate(
            new,
            "crates/demo/src/lib.rs",
            "#[expect(clippy::too_many_arguments, reason = \"kept\")]\n"
            "#[allow(clippy::needless_pass_by_value)]\n"
            "fn g(a: i32) -> i32 {\n    a\n}\n",
        )
        split_allow = compare_trees(old, new, {}, {}, {}, [])
        evaluate(split_allow)
        if split_allow["identical"] != 1 or split_allow["changed"] != 0:
            raise SystemExit(
                "hygiene-fn-diff --self-test: splitting a sibling allow off "
                f"too_many_arguments must stay identical: {split_allow}"
            )
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
    ap.add_argument("--params", type=pathlib.Path, help="struct field map (crate<TAB>fn = Struct: f1, f2)")
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
        help="new-only line excused from --split concat; KEY=LINE is per-split",
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
    params = load_params(ns.params)
    splits, file_glue, split_extra = load_splits(ns.split, ns.split_line)
    glue = merge_glue(file_glue, parse_glue_args(ns.glue))
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
            glue,
            roots=roots,
            split_extra=split_extra,
            params=params,
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
