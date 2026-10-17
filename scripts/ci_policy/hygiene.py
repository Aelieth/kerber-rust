"""Rust test isolation, registered autotests, and that every scripts Python file compiles."""

from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

from .common import ROOT, SCRIPTS, _die


CFG_TEST_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")
CFG_TEST_MOD_SEMI_RE = re.compile(
    r"^\s*#\[cfg\(test\)\]\s+(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)
MOD_OPEN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{")
MOD_SEMI_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR_RE = re.compile(r'^#\[path\s*=\s*"([^"]+)"\]')


def _blank_keep_newlines(s: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in s)


def strip_noncode(text: str) -> str:
    """Blank comments and string/char literal bodies, keeping line structure.

    The brace scanner below must not see `{` inside `"…"`, `'{'` or `// …`.
    Lifetimes (`'a`) are kept; raw and byte strings are recognised.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(_blank_keep_newlines(text[i:j]))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append('"' + _blank_keep_newlines(text[i + 1 : j - 1]) + '"')
            i = j
            continue
        if c == "r" and nxt in ('"', "#"):
            prev = text[i - 1] if i > 0 else ""
            prev_ok = not (prev.isalnum() or prev == "_") or (
                prev == "b" and (i < 2 or not (text[i - 2].isalnum() or text[i - 2] == "_"))
            )
            j, hashes = i + 1, 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if prev_ok and j < n and text[j] == '"':
                close = '"' + "#" * hashes
                k = text.find(close, j + 1)
                k = n if k < 0 else k + len(close)
                out.append(_blank_keep_newlines(text[i:k]))
                i = k
                continue
        if c == "'":
            if nxt == "\\":
                j = text.find("'", i + 2)
                if 0 < j and j - i <= 12:
                    out.append(" " * (j + 1 - i))
                    i = j + 1
                    continue
            elif i + 2 < n and text[i + 2] == "'":
                out.append("   ")
                i += 3
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _add_cfg_test_child(
    rels: set[str],
    pdir: pathlib.Path,
    path: pathlib.Path,
    name: str,
    path_attr: str | None,
) -> None:
    if path.stem in ("mod", "lib", "main"):
        parent = path.parent
    else:
        parent = path.parent / path.stem
    if path_attr:
        child = path.parent / path_attr
    else:
        as_file = parent / f"{name}.rs"
        as_dir = parent / name
        if as_file.is_file():
            child = as_file
        elif (as_dir / "mod.rs").is_file():
            child = as_dir
        else:
            return
    if child.is_dir():
        for nested in child.rglob("*.rs"):
            try:
                rels.add(nested.relative_to(pdir).as_posix())
            except ValueError:
                pass
    elif child.is_file():
        try:
            rels.add(child.relative_to(pdir).as_posix())
        except ValueError:
            pass


def cfg_test_files_in_pkg(pdir: pathlib.Path) -> set[str]:
    """Package-relative paths of `src/**` files whose parent is `#[cfg(test)] mod`."""
    rels: set[str] = set()
    for path in sorted(pdir.rglob("*.rs")):
        # a build dir inside the package, not a `target` above it (a checkout
        # or fixture under `target/ci-policy/` is still a package)
        if "target" in path.relative_to(pdir).parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        pending = False
        path_attr: str | None = None
        for line in text.splitlines():
            s = line.strip()
            oneline = CFG_TEST_MOD_SEMI_RE.match(line)
            if oneline:
                _add_cfg_test_child(rels, pdir, path, oneline.group(1), None)
                pending = False
                path_attr = None
                continue
            if CFG_TEST_RE.match(line):
                pending = True
                path_attr = None
                continue
            if not pending:
                continue
            pm = PATH_ATTR_RE.match(s)
            if pm:
                path_attr = pm.group(1)
                continue
            if s.startswith("#["):
                continue
            pending = False
            mm = MOD_SEMI_RE.match(line)
            if not mm:
                path_attr = None
                continue
            _add_cfg_test_child(rels, pdir, path, mm.group(1), path_attr)
            path_attr = None
    return rels


def _blank_rust(src: str) -> str:
    """Blank comments and string/char bodies via `strip_noncode`. Same length."""
    try:
        blanked = strip_noncode(src)
    except Exception as exc:
        _die(f"isolate_test_krb5 strip_noncode failed: {exc}")
    if len(blanked) != len(src):
        _die("isolate_test_krb5 strip_noncode length mismatch")
    return blanked


def _attr_end(src: str, start: int) -> int | None:
    """Index after the `]` that closes `#[…]` at `start`, or None if unclosed."""
    if not src.startswith("#[", start):
        return None
    depth = 0
    i = start + 1
    n = len(src)
    while i < n:
        c = src[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _top_level_comma_args(inner: str) -> list[str]:
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    for c in inner:
        if c == "(":
            depth += 1
            buf.append(c)
        elif c == ")":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
    if buf:
        args.append("".join(buf).strip())
    return args


def _cfg_pred_is_test(pred: str) -> bool:
    compact = "".join(pred.split())
    if compact == "test":
        return True
    for head in ("all(", "any("):
        if compact.startswith(head) and compact.endswith(")"):
            inner = compact[len(head) : -1]
            if any(arg == "test" for arg in _top_level_comma_args(inner)):
                return True
    return False


def _cfg_attr_is_test(attr: str) -> bool:
    compact = "".join(attr.split())
    if not (compact.startswith("#[cfg(") and compact.endswith(")]")):
        return False
    return _cfg_pred_is_test(compact[len("#[cfg(") : -2])


def _cfg_test_ranges(src: str) -> list[tuple[int, int]]:
    """Byte ranges of cfg(test) items on blanked source.

    `#[cfg(test)]` matches anywhere on a line; `cfg(all|any(..., test, ...))`
    counts. Brace-match on the blanked text (no quote scanner). An unclosed
    item runs to EOF.
    """
    blanked = _blank_rust(src)
    ranges: list[tuple[int, int]] = []
    n = len(blanked)
    i = 0
    while True:
        j = blanked.find("#[cfg(", i)
        if j < 0:
            break
        end_attr = _attr_end(blanked, j)
        if end_attr is None:
            ranges.append((j, n))
            break
        if not _cfg_attr_is_test(blanked[j:end_attr]):
            i = end_attr
            continue
        k = end_attr
        while True:
            while k < n and blanked[k] in " \t\r\n":
                k += 1
            if k < n and blanked.startswith("#[", k):
                close = _attr_end(blanked, k)
                if close is None:
                    ranges.append((k, n))
                    return ranges
                k = close
                continue
            break
        if k >= n:
            ranges.append((end_attr, n))
            break
        p = k
        depth = 0
        end = n
        while p < n:
            c = blanked[p]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = p + 1
                    break
            elif c == ";" and depth == 0:
                end = p + 1
                break
            p += 1
        ranges.append((k, end))
        i = end
    return ranges


def _cfg_test_has_temp_dir(src: str) -> bool:
    """True if a host-/tmp call sits inside a cfg(test) item, not after one."""
    blanked = _blank_rust(src)
    for a, b in _cfg_test_ranges(src):
        if "temp_dir()" in blanked[a:b] or "/tmp/kerber-test-krb5" in src[a:b]:
            return True
    return False


def check_isolate_test_krb5(
    text: str | None = None,
    tests_text: str | None = "",
    src_files: dict[str, str] | None = None,
    root: pathlib.Path | None = None,
) -> None:
    """Unit-test isolate helper must not write host `/tmp`; live, every crate's tests too
    (check_no_test_temp_dir)."""
    root_dir = pathlib.Path(root) if root is not None else ROOT
    text_was_none = text is None
    if text is None:
        path = root_dir / "crates/krb5-config/src/testenv.rs"
        if not path.is_file():
            _die("missing crates/krb5-config/src/testenv.rs")
        text = path.read_text()
        tests_path = root_dir / "crates/krb5-config/src/tests.rs"
        if not tests_path.is_file():
            _die("missing crates/krb5-config/src/tests.rs")
        tests_text = tests_path.read_text()
        if src_files is None:
            src_dir = root_dir / "crates/krb5-config/src"
            src_files = {
                p.name: p.read_text()
                for p in sorted(src_dir.glob("*.rs"))
                if p.is_file()
            }
    if "fn isolate_test_krb5" not in text:
        _die("isolate_test_krb5 missing")
    blanked = _blank_rust(text)
    if "temp_dir()" in blanked or "/tmp/kerber-test-krb5" in text:
        _die("isolate_test_krb5 writes host /tmp")
    if tests_text:
        tests_blanked = _blank_rust(tests_text)
        if "temp_dir()" in tests_blanked:
            _die("cfg(test) writes host /tmp via temp_dir()")
    if src_files:
        for name, src in src_files.items():
            if name in ("tests.rs", "testenv.rs"):
                continue
            if _cfg_test_has_temp_dir(src):
                _die(f"{name} cfg(test) writes host /tmp via temp_dir()")
    if root is None and text_was_none:
        check_no_test_temp_dir()


# Every crate's tests take a scratch directory from `krb5_testkit::scratch_dir`, never
# `std::env::temp_dir()`, which is host /tmp when TMPDIR is unset. Test scope: files under a crate's
# `tests/`, `src` files that are test modules (a `tests` path segment, `tests.rs`, `testenv.rs`), and the
# cfg(test) items of any other `src` file. Pinned at the live count until the tests are fixed.
TEST_TEMP_DIR_ALLOW = 0


def test_temp_dir_sites(root: pathlib.Path | None = None) -> list[str]:
    """`path:line` of each `temp_dir()` call in test code under crates/ (comments and strings blanked): tests/,
    src/**/tests/ and tests.rs files, the files out-of-line `#[cfg(test)]` modules name, and `#[cfg(test)]` items."""
    root = ROOT if root is None else pathlib.Path(root)
    out = []
    # a file an out-of-line `#[cfg(test)] mod x;` names is test code whole, whatever its name
    test_mods = {f"crates/{pdir.name}/{rel}" for pdir in sorted((root / "crates").glob("*/"))
                 for rel in cfg_test_files_in_pkg(pdir)}
    for path in sorted((root / "crates").rglob("*.rs")):
        rel = path.relative_to(root)
        parts = rel.parts
        if "target" in parts or len(parts) < 3:
            continue
        src = path.read_text(encoding="utf-8")
        blanked = _blank_rust(src)
        whole = (parts[2] == "tests" or "tests" in parts[3:-1] or parts[-1] in ("tests.rs", "testenv.rs")
                 or rel.as_posix() in test_mods)
        ranges = [(0, len(blanked))] if whole else _cfg_test_ranges(src)
        for a, b in ranges:
            start = a
            while True:
                i = blanked.find("temp_dir()", start, b)
                if i < 0:
                    break
                out.append(f"{rel}:{blanked.count(chr(10), 0, i) + 1}")
                start = i + 1
    return sorted(set(out))


def check_no_test_temp_dir(root: pathlib.Path | None = None, *, allow: int | None = None) -> None:
    """The every-crate arm of the test-isolation rule (pinned at TEST_TEMP_DIR_ALLOW)."""
    allow = TEST_TEMP_DIR_ALLOW if allow is None else allow
    sites = test_temp_dir_sites(root)
    if len(sites) != allow:
        _die(f"{len(sites)} temp_dir() call(s) in tests, allow {allow}: " + ", ".join(sites[:8]))

def check_autotests_registered(root: pathlib.Path | None = None) -> None:
    """Every tests/*.rs in an autotests=false crate has a [[test]] entry.

    `tests/common.rs` and `tests/common/**` are shared modules, not harnesses.
    """
    root = pathlib.Path(root) if root is not None else ROOT
    crates = root / "crates"
    if not crates.is_dir():
        _die("missing crates/")
    for toml in sorted(crates.glob("*/Cargo.toml")):
        text = toml.read_text(encoding="utf-8")
        if not re.search(r"(?m)^\s*autotests\s*=\s*false\s*$", text):
            continue
        tests_dir = toml.parent / "tests"
        if not tests_dir.is_dir():
            continue
        listed: set[str] = set()
        for m in re.finditer(r"(?ms)^\[\[test\]\]\s*(.*?)(?=\n\[|\Z)", text):
            block = m.group(1)
            path_m = re.search(r'(?m)^\s*path\s*=\s*"([^"]+)"', block)
            name_m = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
            if path_m:
                p = path_m.group(1)
                listed.add(p.removeprefix("tests/"))
            elif name_m:
                listed.add(f"{name_m.group(1)}.rs")
        orphans = []
        for p in tests_dir.rglob("*.rs"):
            rel = p.relative_to(tests_dir).as_posix()
            if rel == "common.rs" or rel.startswith("common/"):
                continue
            if rel not in listed:
                orphans.append(rel)
        if orphans:
            _die(
                f"{toml.parent.name}: autotests=false tests/*.rs missing [[test]]: "
                + ", ".join(sorted(orphans))
            )


def check_python_compiles(files: dict[str, str] | None = None) -> None:
    """Every scripts/**/*.py compiles (in memory, so no __pycache__ is written). ruff and pyflakes are
    on neither the host nor the runner; this is the floor under them."""
    if files is None:
        files = {
            str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
            for path in sorted(SCRIPTS.rglob("*.py"))
            if "__pycache__" not in path.parts
        }
    bad = []
    for name, src in files.items():
        try:
            compile(src, name, "exec")
        except SyntaxError as e:
            bad.append(f"{name}:{e.lineno}: {e.msg}")
    if bad:
        _die(f"{len(bad)} Python file(s) do not compile: " + "; ".join(bad[:8]))
