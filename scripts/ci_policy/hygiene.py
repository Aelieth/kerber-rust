"""Checks that run the tools' own self-tests (the hygiene judges, py-move-check, claim-remap), the
module attributes other tools read, and the Rust test-isolation rules."""

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

from .common import ROOT, SCRIPTS, _die, _hygiene_inventory
from .ledger import DIFFSEND_CASES


def _blank_rust(src: str) -> str:
    """Blank comments and string/char bodies via `strip_noncode`. Same length."""
    try:
        blanked = _hygiene_inventory().strip_noncode(src)
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
    """Unit-test isolate helper must not write host `/tmp`."""
    root_dir = pathlib.Path(root) if root is not None else ROOT
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


_SELF_TEST_OK_RE = re.compile(r"self-test ok \((\d+) cases\)")
HYGIENE_DIFF_MIN_CASES = 36
HYGIENE_BODY_DIFF_MIN_CASES = 41
HYGIENE_FN_DIFF_MIN_CASES = 142
HYGIENE_INVENTORY_MIN_CASES = 8
PY_MOVE_CHECK_MIN_CASES = 18
CLAIM_REMAP_MIN_CASES = 7


def _self_test_n_from_text(text: str) -> int | None:
    found = [int(x) for x in _SELF_TEST_OK_RE.findall(text)]
    return max(found) if found else None


def _self_test_fn_is_gutted(text: str, name: str = "_self_test") -> bool:
    """True when `name` exists and its body is effectively `return None`."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return bool(
            re.search(
                rf'def {re.escape(name)}\([^)]*\):\s*(?:"""[\s\S]*?"""\s*)?return None\b',
                text,
            )
        )
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != name:
            continue
        body = list(node.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(getattr(body[0], "value", None), ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if not body:
            return True
        if len(body) == 1 and isinstance(body[0], ast.Return):
            val = body[0].value
            return val is None or (isinstance(val, ast.Constant) and val.value is None)
        return False
    return False


def _require_self_test_n(blob: str, label: str, min_n: int) -> None:
    n = _self_test_n_from_text(blob)
    if n is None or n < min_n:
        _die(
            f"{label} --self-test must print self-test ok (N cases) with N>={min_n}, got {n!r}"
        )


def _gut_self_test_source(src: str, name: str = "_self_test") -> str:
    tree = ast.parse(src)
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != name:
            continue
        doc = ast.get_docstring(node)
        new_body: list[ast.stmt] = []
        if doc is not None:
            new_body.append(ast.Expr(value=ast.Constant(value=doc)))
        new_body.append(ast.Return(value=ast.Constant(value=None)))
        node.body = new_body
    return ast.unparse(tree)


def _run_script_self_test(
    path: pathlib.Path, label: str, min_n: int | None = None
) -> None:
    proc = subprocess.run(
        [sys.executable, str(path), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-400:]
        _die(f"{label} --self-test failed (rc={proc.returncode}): {tail}")
    if min_n is not None:
        _require_self_test_n((proc.stdout or "") + "\n" + (proc.stderr or ""), label, min_n)


def _gutted_self_test_must_not_count(
    path: pathlib.Path, src: str, label: str, min_n: int
) -> None:
    """A copy whose `_self_test` body is `return None` must not report N cases."""
    try:
        gutted = _gut_self_test_source(src)
    except SyntaxError:
        return
    with tempfile.TemporaryDirectory() as tmp:
        probe_root = pathlib.Path(tmp)
        dest = probe_root / "scripts" / path.name
        dest.parent.mkdir(parents=True)
        dest.write_text(gutted, encoding="utf-8")
        # Sibling imports resolve ROOT as parents[1] of scripts/*.py.
        # Copy them so a gutted file can start; a missing sibling made
        # the probe vacuous (import crash, no N, treated as green).
        for sib in (
            SCRIPTS / "hygiene-diff.py",
            SCRIPTS / "lib" / "hygiene_inventory.py",
        ):
            if sib.resolve() == path.resolve():
                continue
            target = probe_root / "scripts" / sib.relative_to(SCRIPTS)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sib, target)
        proc = subprocess.run(
            [sys.executable, str(dest), "--self-test"],
            cwd=probe_root,
            capture_output=True,
            text=True,
            check=False,
        )
        n = _self_test_n_from_text((proc.stdout or "") + "\n" + (proc.stderr or ""))
        if n is not None and n >= min_n:
            _die(f"{label} gutted _self_test still reports self-test ok ({n} cases)")


def check_hygiene_diff_self_test(text: str | None = None) -> None:
    """hygiene-diff.py --self-test is executed; a gutted `_self_test` is red."""
    path = SCRIPTS / "hygiene-diff.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/hygiene-diff.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "hygiene-diff.py", HYGIENE_DIFF_MIN_CASES)
        _gutted_self_test_must_not_count(
            path, text, "hygiene-diff.py", HYGIENE_DIFF_MIN_CASES
        )
    elif _self_test_n_from_text(text) is None or (
        _self_test_n_from_text(text) or 0
    ) < HYGIENE_DIFF_MIN_CASES:
        _die(
            "hygiene-diff.py must print self-test ok (N cases) with "
            f"N>={HYGIENE_DIFF_MIN_CASES}"
        )
    if _self_test_fn_is_gutted(text):
        _die("hygiene-diff.py _self_test must not be gutted to return None")
    if "def main" not in text:
        _die("hygiene-diff.py must define main()")
    if "def _self_test" not in text:
        _die("hygiene-diff.py must define _self_test")
    if text.count("_self_test()") < 2:
        _die("hygiene-diff.py must run _self_test on normal compare runs")
    if "redirect_stdout(sys.stderr)" not in text:
        _die("hygiene-diff.py must send compare-run _self_test to stderr")
    if "def load_duplicates_map" not in text or "merged:" not in text:
        _die("hygiene-diff.py must key --duplicates and require merged: for many-to-one")
    if "def load_renames_map" not in text:
        _die("hygiene-diff.py must key --renames")
    if "def _self_test_duplicates" not in text:
        _die("hygiene-diff.py must self-test keyed duplicates maps")


def check_hygiene_body_diff_self_test(text: str | None = None) -> None:
    """hygiene-body-diff.py --self-test is executed; a gutted `_self_test` is red."""
    path = SCRIPTS / "hygiene-body-diff.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/hygiene-body-diff.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "hygiene-body-diff.py", HYGIENE_BODY_DIFF_MIN_CASES)
        _gutted_self_test_must_not_count(
            path, text, "hygiene-body-diff.py", HYGIENE_BODY_DIFF_MIN_CASES
        )
        testing = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
        body_at = testing.find("hygiene-body-diff.py")
        fn_at = testing.find("hygiene-fn-diff.py")
        chunk = testing[body_at:fn_at] if body_at >= 0 and fn_at > body_at else ""
        if "literal" not in chunk:
            _die(
                "docs/testing.md must say hygiene-body-diff keeps string literals whole"
            )
    elif _self_test_n_from_text(text) is None or (
        _self_test_n_from_text(text) or 0
    ) < HYGIENE_BODY_DIFF_MIN_CASES:
        _die(
            "hygiene-body-diff.py must print self-test ok (N cases) with "
            f"N>={HYGIENE_BODY_DIFF_MIN_CASES}"
        )
    if _self_test_fn_is_gutted(text):
        _die("hygiene-body-diff.py _self_test must not be gutted to return None")
    if "def _self_test" not in text:
        _die("hygiene-body-diff.py must define _self_test")
    if text.count("_self_test()") < 2:
        _die("hygiene-body-diff.py must run _self_test on normal compare runs")
    if not re.search(r"assert_eq!\(\s*1,\s*2\s*\)", text):
        _die("hygiene-body-diff.py must self-test an assertion change (assert_eq!(1, 2))")
    if "user_as" not in text:
        _die("hygiene-body-diff.py must self-test a helper rename")
    if '"a  b"' not in text:
        _die("hygiene-body-diff.py must self-test whitespace inside an asserted string")
    if 'r"a\\n\\nb"' not in text:
        _die(
            "hygiene-body-diff.py must self-test a zero-length interior line of an asserted literal"
        )


def check_hygiene_fn_diff_self_test(text: str | None = None) -> None:
    """hygiene-fn-diff.py --self-test is executed; a gutted `_self_test` is red."""
    path = SCRIPTS / "hygiene-fn-diff.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/hygiene-fn-diff.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "hygiene-fn-diff.py", HYGIENE_FN_DIFF_MIN_CASES)
        _gutted_self_test_must_not_count(
            path, text, "hygiene-fn-diff.py", HYGIENE_FN_DIFF_MIN_CASES
        )
        testing = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")
        dead_at = testing.find("`--dead`")
        diff_at = testing.find("hygiene-diff.py")
        fn_at = testing.find("hygiene-fn-diff.py")
        if dead_at < 0 or not (diff_at < dead_at < fn_at):
            _die("docs/testing.md must describe --dead on the hygiene-diff paragraph")
        for needle in (
            "byte-string",
            "line-anchored",
            "impl-header",
            "head:",
            "rustfmt_skip",
            "const-fold",
        ):
            if needle not in testing:
                _die(f"docs/testing.md must describe fn-diff {needle}")
    elif _self_test_n_from_text(text) is None or (
        _self_test_n_from_text(text) or 0
    ) < HYGIENE_FN_DIFF_MIN_CASES:
        _die(
            "hygiene-fn-diff.py must print self-test ok (N cases) with "
            f"N>={HYGIENE_FN_DIFF_MIN_CASES}"
        )
    if _self_test_fn_is_gutted(text):
        _die("hygiene-fn-diff.py _self_test must not be gutted to return None")
    if "def _self_test" not in text:
        _die("hygiene-fn-diff.py must define _self_test")
    if text.count("_self_test()") < 2:
        _die("hygiene-fn-diff.py must run _self_test on normal compare runs")
    if "x + 2" not in text:
        _die("hygiene-fn-diff.py must self-test a body edit")
    if "phase_b" not in text:
        _die("hygiene-fn-diff.py must self-test --split")
    if "pub(crate)" not in text:
        _die("hygiene-fn-diff.py must self-test a vis-only change")
    if "unused-accept fixture must be otherwise green" not in text:
        _die("hygiene-fn-diff.py must isolate unused --accept as its own case")


_PY_MOVE_KINDS = ("missing", "extra", "defined-twice", "changed", "unresolved", "future", "stray", "shim", "cycles")


def _main_self_test_calls(text: str) -> int:
    """Calls of `_self_test()` inside `main`: the --self-test branch plus one before a normal run."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return 0
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return sum(
                1 for x in ast.walk(node)
                if isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id == "_self_test"
            )
    return 0


def check_py_move_self_test(text: str | None = None) -> None:
    """py-move-check.py --self-test is executed; a gutted `_self_test` is red; every finding kind
    has a fixture, and a compare run self-tests first."""
    path = SCRIPTS / "py-move-check.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/py-move-check.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "py-move-check.py", PY_MOVE_CHECK_MIN_CASES)
        _gutted_self_test_must_not_count(path, text, "py-move-check.py", PY_MOVE_CHECK_MIN_CASES)
    elif (_self_test_n_from_text(text) or 0) < PY_MOVE_CHECK_MIN_CASES:
        _die(f"py-move-check.py must print self-test ok (N cases) with N>={PY_MOVE_CHECK_MIN_CASES}")
    if _self_test_fn_is_gutted(text):
        _die("py-move-check.py _self_test must not be gutted to return None")
    if "def _self_test" not in text or "def main" not in text:
        _die("py-move-check.py must define _self_test and main")
    if _main_self_test_calls(text) < 2 or "redirect_stdout(sys.stderr)" not in text:
        _die("py-move-check.py must run _self_test (to stderr) before a compare run")
    for kind in _PY_MOVE_KINDS:
        if f'"{kind}"),' not in text:
            _die(f"py-move-check.py must self-test the {kind} finding")


def check_claim_remap_self_test(text: str | None = None) -> None:
    """claim-remap.py --self-test is executed with its floor; a gutted `_self_test` is red, and a
    remap run self-tests first."""
    path = SCRIPTS / "claim-remap.py"
    if text is None:
        if not path.is_file():
            _die("missing scripts/claim-remap.py")
        text = path.read_text(encoding="utf-8")
        _run_script_self_test(path, "claim-remap.py", CLAIM_REMAP_MIN_CASES)
        _gutted_self_test_must_not_count(path, text, "claim-remap.py", CLAIM_REMAP_MIN_CASES)
    elif (_self_test_n_from_text(text) or 0) < CLAIM_REMAP_MIN_CASES:
        _die(f"claim-remap.py must print self-test ok (N cases) with N>={CLAIM_REMAP_MIN_CASES}")
    if _self_test_fn_is_gutted(text):
        _die("claim-remap.py _self_test must not be gutted to return None")
    if "def _self_test" not in text or _main_self_test_calls(text) < 2:
        _die("claim-remap.py must run _self_test before a remap run")


def check_hygiene_inventory_cfg_test() -> None:
    """Inventory classifies `#[cfg(test)] mod x;` as src-test."""
    path = SCRIPTS / "lib" / "hygiene_inventory.py"
    if not path.is_file():
        _die("missing scripts/lib/hygiene_inventory.py")
    _run_script_self_test(path, "hygiene_inventory.py", HYGIENE_INVENTORY_MIN_CASES)


# The two tools that load scripts/ci-policy.py as a module and read its attributes.
_POLICY_MODULE_CONSUMERS = (
    ("scripts/kdb-dump-gate.sh", ("ROOT", "_dump_key_hexes", "check_golden_dump_unique_keys")),
    (
        "scripts/lib/hygiene_inventory.py",
        ("DIFFSEND_CASES", "ledger_sources", "recount_ledger_verdicts", "_split_ledger_row"),
    ),
)
_POLICY_MODULE_PROBE = """import importlib.util
import json
import sys

spec = importlib.util.spec_from_file_location("ci_policy", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out = {"missing": [n for n in json.loads(sys.argv[2]) if not hasattr(mod, n)]}
if not out["missing"]:
    out["diffsend"] = sorted(mod.DIFFSEND_CASES)
    out["ledger"] = [name for name, _text, _key in mod.ledger_sources(mod.ROOT)]
print(json.dumps(out))
"""


def check_policy_module_attrs(path: pathlib.Path | None = None) -> None:
    """scripts/ci-policy.py, loaded as a module the way kdb-dump-gate.sh:36-40 loads it (`python3 -`
    from cwd=/, spec_from_file_location, no PYTHONPATH), has every name its two consumers read; its
    DIFFSEND_CASES is this policy's list (what hygiene_inventory's diffsend_cases reads) and its
    ledger_sources reads the docs/parity/ split, so a stub with the right names does not pass."""
    path = SCRIPTS / "ci-policy.py" if path is None else path
    names = [n for _consumer, group in _POLICY_MODULE_CONSUMERS for n in group]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    r = subprocess.run(
        [sys.executable, "-", str(path), json.dumps(names)],
        input=_POLICY_MODULE_PROBE,
        cwd="/",
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        tail = (r.stderr or r.stdout).strip().splitlines()[-1:]
        _die(f"{path.name} does not load as a module from cwd=/: {tail}")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    for consumer, group in _POLICY_MODULE_CONSUMERS:
        missing = [n for n in group if n in out["missing"]]
        if missing:
            _die(f"{path.name} loaded as a module lacks {', '.join(missing)}, which {consumer} reads")
    if out["diffsend"] != sorted(DIFFSEND_CASES):
        _die(
            f"{path.name} loaded as a module holds {len(out['diffsend'])} DIFFSEND_CASES, this policy "
            f"{len(DIFFSEND_CASES)}: hygiene_inventory.py's diffsend_cases would read the wrong list"
        )
    if not out["ledger"] or not all(n.startswith("docs/parity/") for n in out["ledger"]):
        _die(
            f"{path.name} loaded as a module: ledger_sources reads {out['ledger'][:2]}, not the "
            "docs/parity/ split that hygiene_inventory.py's ledger_rows needs"
        )
