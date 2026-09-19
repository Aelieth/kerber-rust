#!/usr/bin/env python3
"""Compare product fn bodies between two trees (SHA or directory).

Product-code sibling of hygiene-body-diff.py. Extracts every non-test
`fn` (free, impl and trait methods; keyed
`crate<TAB>module::path::[Type::]name`), links old → new by the key and
a keyed `--moves` map (`old_key = new_key`, RHS-as-LHS rejected,
many-to-one needs `merged:`), compares bodies after
a comparison normaliser that keeps string, byte-string, raw-string
and char literal contents (whitespace and comments are still
normalised outside literals), and classifies each pair
`identical` / `vis-only` (only `pub` ↔ `pub(crate)` on the signature)
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
      [--moves map.txt] [--accept map.txt] [--split map.txt]
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

IMPL_RE = re.compile(
    r"^\s*impl(?:<[^;{]*>)?\s+"
    r"(?:(?:!)?[A-Za-z_][A-Za-z0-9_:]*(?:<[^;{]*>)?\s+for\s+)?"
    r"(?P<ty>[A-Za-z_][A-Za-z0-9_]*)"
)
TEST_ATTR_RE = re.compile(r"#\[\s*(?:tokio::test|test)\b")
ACCEPT_LINE_RE = re.compile(
    r"^(?P<old>.+?)\s*=\s*(?P<new>.+?)\s*\|\s*"
    r"sha256:(?P<oldh>[0-9a-f]{64})\s*\|\s*"
    r"sha256:(?P<newh>[0-9a-f]{64})\s*\|\s*"
    r"(?P<reason>.+)$"
)
SPLIT_LINE_RE = re.compile(r"^(?P<old>.+?)\s*=\s*(?P<rhs>.+)$")
VIS_FOLD_RE = re.compile(r"\bpub\(crate\)")


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
    crate = parts[1]
    rest = parts[3:]
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


def vis_fold(sig: str) -> str:
    return VIS_FOLD_RE.sub("pub", sig)


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
    if compare_norm(inner_body(old_src)) == compare_norm(inner_body(new_src)) and vis_fold(
        compare_norm(signature_of(_strip_doc_lines(old_src)))
    ) == vis_fold(compare_norm(signature_of(_strip_doc_lines(new_src)))):
        if compare_norm(signature_of(_strip_doc_lines(old_src))) != compare_norm(
            signature_of(_strip_doc_lines(new_src))
        ):
            return "vis-only"
    return "changed"


def _impl_type_at(lines: list[str], line_1: int) -> str | None:
    """Innermost `impl Type` / `impl Trait for Type` covering 1-based line."""
    stack: list[tuple[int, str]] = []
    depth = 0
    for i, raw in enumerate(lines, 1):
        m = IMPL_RE.match(raw)
        if m and "{" in raw[m.end() :]:
            stack.append((depth, m.group("ty")))
        depth += raw.count("{") - raw.count("}")
        while stack and stack[-1][0] >= depth:
            stack.pop()
        if i == line_1:
            return stack[-1][1] if stack else None
    return None


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


def extract(root: pathlib.Path) -> dict[str, dict[str, str]]:
    """key → {src, file, name}."""
    found: dict[str, dict[str, str]] = {}
    crates = root / "crates"
    if not crates.is_dir():
        return found
    src_test: set[str] = set()
    for pdir in sorted(p for p in crates.iterdir() if p.is_dir()):
        prefix = pdir.relative_to(root).as_posix()
        for rel in cfg_test_files_in_pkg(pdir):
            src_test.add(f"{prefix}/{rel}")
    for path in sorted(crates.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if "/target/" in f"/{rel}/" or "/tests/" in f"/{rel}/" or "/benches/" in f"/{rel}/":
            continue
        if "/krb5-testkit/" in f"/{rel}/" or "/src/" not in f"/{rel}/":
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
            ty = _impl_type_at(code_lines, start)
            key = fn_key(crate, module, ty, name)
            prelude = _attr_doc_start(raw_lines, start)
            src = "\n".join(raw_lines[prelude:end])
            if key in found:
                # Never drop a colliding body. Disambiguate with file:line
                # when two items still share a key.
                key = f"{key}#{rel}:{start}"
            found[key] = {"src": src, "file": rel, "name": name}
    return found


def _line_set(text: str) -> set[str]:
    return {ln.strip() for ln in text.splitlines() if ln.strip()}


def strip_glue_lines(text: str, glue: list[str]) -> str:
    """Drop whole lines whose stripped text is a glue entry."""
    want = {g.strip() for g in glue if g.strip()}
    return "\n".join(ln for ln in text.splitlines() if ln.strip() not in want)


def glue_problems(old_body: str, new_body: str, glue: list[str]) -> tuple[list[str], list[str]]:
    """Glue may only excuse lines present in new and absent from old."""
    old_ls, new_ls = _line_set(old_body), _line_set(new_body)
    unused: list[str] = []
    illegal: list[str] = []
    for g in glue:
        gs = g.strip()
        if not gs:
            continue
        if gs in old_ls:
            illegal.append(g)
        if gs not in new_ls:
            unused.append(g)
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
) -> dict[str, object]:
    old = extract(old_root)
    new = extract(new_root)
    used_old: set[str] = set()
    used_new: set[str] = set()
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
        if nkey not in new or nkey in used_new:
            continue
        kind = classify(ofn["src"], new[nkey]["src"])
        pairs.append((okey, nkey, kind))
        used_old.add(okey)
        used_new.add(nkey)

    removed = sorted(k for k in old if k not in used_old)
    added = sorted(k for k in new if k not in used_new)
    identical = sum(1 for _o, _n, k in pairs if k == "identical")
    vis_only = [(o, n) for o, n, k in pairs if k == "vis-only"]
    doc_only = [(o, n) for o, n, k in pairs if k == "doc-only"]
    changed = [(o, n) for o, n, k in pairs if k == "changed"]

    accepted: list[tuple[str, str, str]] = []
    unaccepted: list[tuple[str, str]] = []
    used_accept: set[str] = set()
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
    return {
        "pairs": len(pairs),
        "identical": identical,
        "vis_only": len(vis_only),
        "doc_only": len(doc_only),
        "changed": len(changed),
        "accepted": accepted,
        "unaccepted": unaccepted,
        "removed": removed,
        "added": added,
        "split_ok": split_ok,
        "split_fail": split_fail,
        "missing_split": missing_split,
        "unused_accept": unused_accept,
        "unused_glue": unused_glue,
        "illegal_glue": illegal_glue,
        "missing_rhs": missing_rhs,
        "old": len(old),
        "new": len(new),
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
    ]
    for o, n, reason in report["accepted"]:  # type: ignore[misc]
        lines.append(f"accepted {o} -> {n}: {reason}")
    return "\n".join(lines) + "\n"


def evaluate(report: dict[str, object]) -> None:
    errs: list[str] = []
    for o, n in report["unaccepted"]:  # type: ignore[misc]
        errs.append(f"changed not in --accept: {o} -> {n}")
    for k in report["removed"]:  # type: ignore[misc]
        errs.append(f"removed fn: {k}")
    for k in report["added"]:  # type: ignore[misc]
        errs.append(f"added fn: {k}")
    for k in report["split_fail"]:  # type: ignore[misc]
        errs.append(f"--split body mismatch: {k}")
    for k in report["missing_split"]:  # type: ignore[misc]
        errs.append(f"--split key missing: {k}")
    for k in report["unused_accept"]:  # type: ignore[misc]
        errs.append(f"--accept entry unused: {k}")
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
            "crates/demo/src/lib.rs",
            "pub fn ready(x: i32) -> i32 { x + 2 }\n",
        )
        unused = {
            "demo\tready": {
                "new": "demo\tready",
                "old_hash": "0" * 64,
                "new_hash": "1" * 64,
                "reason": "wrong",
            },
            "demo\tother": {
                "new": "demo\tother",
                "old_hash": "a" * 64,
                "new_hash": "b" * 64,
                "reason": "unused",
            },
        }
        _must_red(compare_trees(old, new, {}, unused, {}, []), "unused accept")
        n += 1

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
            new,
            "crates/demo/src/lib.rs",
            "pub(crate) fn ready(x: i32) -> i32 { x + 1 }\n",
        )
        (new / "crates" / "demo" / "src" / "moved.rs").unlink(missing_ok=True)
        vis = compare_trees(old, new, {}, {}, {}, [])
        evaluate(vis)
        if vis["vis_only"] != 1 or vis["changed"] != 0:
            raise SystemExit("hygiene-fn-diff --self-test: pub ↔ pub(crate) must be vis-only")
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
    ns = ap.parse_args(argv)
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        _self_test()
    moves = load_keyed_id_map(ns.moves, "moves")
    accept = load_accept(ns.accept)
    splits = load_splits(ns.split, ns.split_line)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = pathlib.Path(tmp)
        old_root = materialize(ns.old, tmp_p / "old", ns.git_dir)
        new_root = materialize(ns.new, tmp_p / "new", ns.git_dir)
        report = compare_trees(old_root, new_root, moves, accept, splits, ns.glue)
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
