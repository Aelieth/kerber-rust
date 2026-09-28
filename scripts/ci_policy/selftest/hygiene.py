"""The self-test of the tool self-test runners, the module-attribute check and the isolation rules."""

from __future__ import annotations

import inspect
import pathlib
import subprocess
import tempfile

from ..common import _scratch_root
from ..hygiene import (
    _PY_MOVE_KINDS, _blank_rust, _cfg_test_ranges, check_autotests_registered, check_claim_remap_self_test,
    check_hygiene_body_diff_self_test, check_hygiene_diff_self_test, check_hygiene_fn_diff_self_test,
    check_isolate_test_krb5, check_policy_module_attrs, check_py_move_self_test, check_python_compiles,
)
from ..ledger import DIFFSEND_CASES
from .common import _must_die, _must_die_msg


def _self_test_hygiene() -> None:
    check_hygiene_diff_self_test(
        "def load_duplicates_map():\n    return {'merged:'}\n"
        "def load_renames_map():\n    return {}\n"
        "def _self_test_duplicates():\n    pass\n"
        "def _self_test():\n    pass\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-diff: self-test ok (39 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
        "    return _compare()\n"
    )
    _must_die(
        check_hygiene_diff_self_test,
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n        return 0\n",
    )
    _must_die(
        check_hygiene_diff_self_test,
        "def _self_test():\n    pass\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    _self_test()\n    return _compare()\n",
    )
    _must_die(
        check_hygiene_diff_self_test,
        'def load_duplicates_map():\n    return {"merged:"}\n'
        "def load_renames_map():\n    return {}\n"
        "def _self_test_duplicates():\n    pass\n"
        "def _self_test():\n"
        '    """merged: load_duplicates_map load_renames_map _self_test_duplicates"""\n'
        "    return None\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-diff: self-test ok (39 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
        "    return _compare()\n",
    )
    check_hygiene_body_diff_self_test(
        'def _self_test():\n    assert_eq!(1, 2) vs user_as helper "a  b" r"a\\n\\nb"\n'
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-body-diff: self-test ok (41 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    _must_die(check_hygiene_body_diff_self_test, "def main():\n    return 0\n")
    _must_die(
        check_hygiene_body_diff_self_test,
        "def _self_test():\n    assert_eq! vs user_as helper\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    _must_die(
        check_hygiene_body_diff_self_test,
        "def _self_test():\n"
        '    """assert_eq!(1, 2) vs user_as helper "a  b" r"a\\n\\nb" """\n'
        "    return None\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-body-diff: self-test ok (32 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    check_hygiene_fn_diff_self_test(
        "def _self_test():\n    x + 2 phase_b pub(crate)\n"
        "    # unused-accept fixture must be otherwise green\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-fn-diff: self-test ok (143 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    _must_die(check_hygiene_fn_diff_self_test, "def main():\n    return 0\n")
    _must_die(
        check_hygiene_fn_diff_self_test,
        "def _self_test():\n    x + 2 phase_b pub(crate)\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    _must_die(
        check_hygiene_fn_diff_self_test,
        "def _self_test():\n"
        '    """x + 2 phase_b pub(crate)"""\n'
        "    return None\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-fn-diff: self-test ok (64 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    py_move_ok = (
        "def _self_test():\n    cases = [" + "".join(f'("x", {{}}, s, a, "{k}"),' for k in _PY_MOVE_KINDS) + "]\n"
        "def main(argv):\n    if argv == ['--self-test']:\n        _self_test()\n"
        "        print('py-move-check: self-test ok (18 cases)')\n"
        "        return 0\n    with contextlib.redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    check_py_move_self_test(py_move_ok)
    _must_die_msg("self-test ok (N cases)", check_py_move_self_test, py_move_ok.replace("(18 cases)", "(17 cases)"))
    _must_die_msg(
        "must not be gutted",
        check_py_move_self_test,
        'def _self_test():\n    """' + "".join(f'"{k}"),' for k in _PY_MOVE_KINDS) + '"""\n    return None\n'
        + py_move_ok[py_move_ok.index("def main(argv):"):],
    )
    _must_die_msg("before a compare run", check_py_move_self_test,
                  py_move_ok.replace("with contextlib.redirect_stdout(sys.stderr):\n        _self_test()\n", "pass\n"))
    _must_die_msg("the shim finding", check_py_move_self_test, py_move_ok.replace('"shim"),', '"other"),'))
    remap_ok = (
        "def _self_test():\n    n = 7\n    return n\n"
        "def main(argv):\n    if argv == ['--self-test']:\n"
        "        print(f'claim-remap: self-test ok ({_self_test()} cases)')\n        return 0\n"
        "    _self_test()\n    return main_remap(argv)\n# self-test ok (7 cases)\n"
    )
    check_claim_remap_self_test(remap_ok)
    _must_die_msg("self-test ok (N cases)", check_claim_remap_self_test, remap_ok.replace("(7 cases)", "(6 cases)"))
    _must_die_msg("must not be gutted", check_claim_remap_self_test,
                  remap_ok.replace("    n = 7\n    return n\n", "    return None\n"))
    _must_die_msg("before a remap run", check_claim_remap_self_test,
                  remap_ok.replace("    _self_test()\n    return main_remap", "    return main_remap"))
    with tempfile.TemporaryDirectory() as tmp:
        demo = pathlib.Path(tmp) / "crates" / "demo"
        (demo / "tests" / "common").mkdir(parents=True)
        (demo / "tests" / "listed.rs").write_text("fn main() {}\n", encoding="utf-8")
        (demo / "tests" / "common" / "mod.rs").write_text("", encoding="utf-8")
        (demo / "Cargo.toml").write_text(
            "[package]\nname = \"demo\"\nautotests = false\n\n"
            "[[test]]\nname = \"listed\"\npath = \"tests/listed.rs\"\n",
            encoding="utf-8",
        )
        check_autotests_registered(pathlib.Path(tmp))
        (demo / "tests" / "orphan.rs").write_text("", encoding="utf-8")
        _must_die(check_autotests_registered, pathlib.Path(tmp))
    # S3.4d: tokenise via strip_noncode, scan testenv.rs whole, cfg(test)
    # anywhere on the line including cfg(all|any(..., test, ...)). Missing
    # tests.rs dies on the production is_file() branch (a ROOT-like tree
    # under scratch, text=None).
    _isolate_ok = (
        "fn isolate_scratch_dir() -> PathBuf {\n    PathBuf::from(\"target\").join(\"test-krb5\")\n}\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
    )
    check_isolate_test_krb5(_isolate_ok)
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        "pub fn isolate_test_krb5() {\n"
        "    let path = std::env::temp_dir().join(\"kerber-test-krb5-1.conf\");\n"
        "}\n",
    )
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        "fn isolate_scratch_dir() -> PathBuf { PathBuf::from(\"target/test-krb5\") }\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
        "#[cfg(test)]\nmod tests {\n    fn f() { let _ = std::env::temp_dir(); }\n}\n",
    )
    # C1 / C2: a private helper after isolate_test_krb5 is still testenv.rs
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        _isolate_ok + "fn helper_dir() -> PathBuf {\n    std::env::temp_dir()\n}\n",
    )
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        _isolate_ok
        + "fn helper_dir() -> PathBuf {\n    PathBuf::from(\"/tmp/kerber-test-krb5\")\n}\n",
    )
    # product temp_dir() after a cfg(test) use is not a cfg(test) item
    # (sibling file: testenv.rs is scanned whole)
    check_isolate_test_krb5(
        _isolate_ok,
        src_files={
            "kdcconf.rs": (
                "#[cfg(test)]\nuse foo::bar;\n"
                "fn product() { let _ = std::env::temp_dir(); }\n"
            )
        },
    )
    # temp_dir() inside a string literal in a cfg(test) mod is not a call
    check_isolate_test_krb5(
        _isolate_ok,
        src_files={
            "kdcconf.rs": (
                "#[cfg(test)]\nmod t {\n"
                '    fn f() { let _ = "temp_dir()"; }\n'
                "}\n"
            )
        },
    )

    def _isolate_src_file(name: str, src: str) -> None:
        check_isolate_test_krb5(_isolate_ok, src_files={name: src})

    # U1: lifetime + &'static before the temp_dir() fn (quote scanner ate it)
    _must_die_msg(
        "u1.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u1.rs",
        "#[cfg(test)]\nmod t {\n"
        " fn a<'x>(v: &str) { let r: &'static str = \"k\"; }\n"
        " fn f(){ std::env::temp_dir(); }\n}\n",
    )
    # U3: // comment containing }
    _must_die_msg(
        "u3.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u3.rs",
        "#[cfg(test)]\nmod t {\n // closes } here\n fn f(){ std::env::temp_dir(); }\n}\n",
    )
    # U6: #[cfg(test)] after code on the same line
    _must_die_msg(
        "u6.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u6.rs",
        "fn p(){} #[cfg(test)] mod t { fn f(){ std::env::temp_dir(); } }\n",
    )
    # U4: cfg(all(test, …)) / cfg(any(test, …))
    _must_die_msg(
        "u4.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u4.rs",
        "#[cfg(all(test, unix))]\nmod t {\n fn f(){ std::env::temp_dir(); }\n}\n",
    )
    _must_die_msg(
        "u4any.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u4any.rs",
        "#[cfg(any(test, windows))]\nmod t {\n fn f(){ std::env::temp_dir(); }\n}\n",
    )

    def _isolate_missing_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        src = fake / "crates/krb5-config/src"
        src.mkdir(parents=True)
        (src / "testenv.rs").write_text(_isolate_ok)
        check_isolate_test_krb5(root=fake)

    def _isolate_tree_with_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        src = fake / "crates/krb5-config/src"
        src.mkdir(parents=True)
        (src / "testenv.rs").write_text(_isolate_ok)
        (src / "tests.rs").write_text("// no temp_dir\n")
        check_isolate_test_krb5(root=fake)

    def _isolate_tests_rs_temp_dir() -> None:
        check_isolate_test_krb5(
            _isolate_ok,
            tests_text="fn f() { let _ = std::env::temp_dir(); }\n",
        )

    def _isolate_src_cfg_test_temp_dir() -> None:
        check_isolate_test_krb5(
            _isolate_ok,
            src_files={
                "kdcconf.rs": (
                    "#[cfg(test)]\nmod tests {\n"
                    "    fn f() { let _ = std::env::temp_dir(); }\n"
                    "}\n"
                )
            },
        )

    _iso_src = inspect.getsource(check_isolate_test_krb5)
    _blank_src = inspect.getsource(_blank_rust)
    _range_src = inspect.getsource(_cfg_test_ranges)
    if "if not tests_path.is_file():" not in _iso_src:
        raise AssertionError("missing tests.rs must go through is_file()")
    if "tests_missing" in _iso_src:
        raise AssertionError("tests_missing short-circuit must stay gone")
    if "strip_noncode" not in _blank_src:
        raise AssertionError("must tokenise via strip_noncode")
    if "except" not in _blank_src:
        raise AssertionError("strip_noncode failure must die")
    if "in_str" in _iso_src or "in_str" in _range_src:
        raise AssertionError("hand-rolled string scanner must stay gone")
    if "isolate_scratch_dir" in _iso_src:
        raise AssertionError("testenv.rs must be scanned whole, not as an isolate chunk")
    _must_die_msg(
        "missing crates/krb5-config/src/tests.rs",
        _isolate_missing_tests,
    )
    _isolate_tree_with_tests()
    _must_die(_isolate_tests_rs_temp_dir)
    _must_die(_isolate_src_cfg_test_temp_dir)
    check_isolate_test_krb5()

    # S6-14: the module-attribute consumers, each missing name and each shape red.
    check_policy_module_attrs()
    mod_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        full = {
            "ROOT": "import pathlib\nROOT = pathlib.Path('/nonexistent')\n",
            "_dump_key_hexes": "def _dump_key_hexes(line):\n    return None\n",
            "check_golden_dump_unique_keys": "def check_golden_dump_unique_keys():\n    pass\n",
            "DIFFSEND_CASES": f"DIFFSEND_CASES = frozenset({sorted(DIFFSEND_CASES)!r})\n",
            "ledger_sources": "def ledger_sources(root=None):\n    return [('docs/parity/README.md', '', None)]\n",
            "recount_ledger_verdicts": "def recount_ledger_verdicts(text):\n    return {}\n",
            "_split_ledger_row": "def _split_ledger_row(line):\n    return []\n",
        }
        fake = mod_root / "ci-policy.py"
        fake.write_text("".join(full.values()), encoding="utf-8")
        check_policy_module_attrs(fake)
        for gone, consumer in (("_dump_key_hexes", "kdb-dump-gate.sh"), ("ledger_sources", "hygiene_inventory.py")):
            fake.write_text("".join(v for k, v in full.items() if k != gone), encoding="utf-8")
            _must_die_msg(f"lacks {gone}, which scripts/", check_policy_module_attrs, fake)
            _must_die_msg(consumer, check_policy_module_attrs, fake)
        fake.write_text("".join(full.values()).replace(full["DIFFSEND_CASES"], "DIFFSEND_CASES = frozenset({'x'})\n"),
                        encoding="utf-8")
        _must_die_msg("holds 1 DIFFSEND_CASES", check_policy_module_attrs, fake)
        fake.write_text(
            "".join(full.values()).replace("docs/parity/README.md", "docs/mit-parity-ledger.md"), encoding="utf-8"
        )
        _must_die_msg("not the docs/parity/ split", check_policy_module_attrs, fake)
        fake.write_text("raise SystemExit('no import')\n", encoding="utf-8")
        _must_die_msg("does not load as a module from cwd=/", check_policy_module_attrs, fake)
    finally:
        subprocess.run(["rm", "-rf", str(mod_root)], check=False)
    # S6.1: every scripts/**/*.py compiles.
    check_python_compiles({"a.py": "x = 1\n"})
    _must_die_msg("1 Python file(s) do not compile", check_python_compiles, {"a.py": "x = 1\n", "b.py": "def f(:\n"})
