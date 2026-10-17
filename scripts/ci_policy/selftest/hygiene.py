"""The self-test of the tool self-test runners, the module-attribute check and the isolation rules."""

from __future__ import annotations

import inspect
import pathlib
import subprocess
import tempfile

from ..common import _scratch_root
from ..golden import check_golden_dump_unique_keys
from ..hygiene import (
    _blank_rust, _cfg_test_ranges, check_autotests_registered, check_isolate_test_krb5,
    check_no_test_temp_dir, check_python_compiles,
)
from .common import _must_die, _must_die_msg


def _self_test_hygiene() -> None:
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
        try:
            src = fake / "crates/krb5-config/src"
            src.mkdir(parents=True)
            (src / "testenv.rs").write_text(_isolate_ok)
            check_isolate_test_krb5(root=fake)
        finally:
            subprocess.run(["rm", "-rf", str(fake)], check=False)

    def _isolate_tree_with_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        try:
            src = fake / "crates/krb5-config/src"
            src.mkdir(parents=True)
            (src / "testenv.rs").write_text(_isolate_ok)
            (src / "tests.rs").write_text("// no temp_dir\n")
            check_isolate_test_krb5(root=fake)
        finally:
            subprocess.run(["rm", "-rf", str(fake)], check=False)

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

    # Every crate's tests: temp_dir() in tests/, in test-module files and in cfg(test) items counts; product
    # code, comments and strings do not.
    td_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        demo = td_root / "crates" / "demo"
        (demo / "tests").mkdir(parents=True)
        (demo / "src" / "store" / "tests").mkdir(parents=True)
        (demo / "tests" / "a.rs").write_text("fn t() { let _ = std::env::temp_dir(); }\n", encoding="utf-8")
        (demo / "src" / "store" / "tests" / "b.rs").write_text("fn t() { std::env::temp_dir(); }\n", encoding="utf-8")
        (demo / "src" / "lib.rs").write_text(
            "// temp_dir() in a comment\npub fn p() { let _ = std::env::temp_dir(); }\n"
            "#[cfg(test)]\nmod tests {\n    fn t() { let _ = std::env::temp_dir(); let _s = \"temp_dir()\"; }\n}\n"
            "#[cfg(test)]\nmod helpers;\n",
            encoding="utf-8",
        )
        # an out-of-line cfg(test) module's file is test code, whatever its name
        (demo / "src" / "helpers.rs").write_text("pub fn h() { let _ = std::env::temp_dir(); }\n", encoding="utf-8")
        check_no_test_temp_dir(td_root, allow=4)
        _must_die_msg("4 temp_dir() call(s) in tests, allow 0", check_no_test_temp_dir, td_root, allow=0)
        _must_die_msg("crates/demo/src/helpers.rs:1", check_no_test_temp_dir, td_root, allow=0)
    finally:
        subprocess.run(["rm", "-rf", str(td_root)], check=False)

    def _princ_line(name: str, *keyhexes: str) -> str:
        parts = [
            "princ", "38", str(len(name)), "0", str(len(keyhexes)), "0", name,
            "0", "0", "0", "0", "0", "0", "0", "0",
        ]
        for keyhex in keyhexes:
            parts.extend(["1", "1", "17", str(len(keyhex) // 2), keyhex])
        parts.append("-1")
        return "\t".join(parts) + "\n"

    dump_unique = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "ba", "bb", "bc", "bd")
        + _princ_line("hwuser@KERBER.TEST", "ca", "cb", "cc", "cd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    check_golden_dump_unique_keys(dump_unique)
    dump_clone_user = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("hwuser@KERBER.TEST", "ca", "cb", "cc", "cd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    _must_die(check_golden_dump_unique_keys, dump_clone_user)
    dump_missing = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa")
        + _princ_line("nosvr@KERBER.TEST", "ba")
    )
    _must_die(check_golden_dump_unique_keys, dump_missing)
    # Every scripts/**/*.py compiles.
    check_python_compiles({"a.py": "x = 1\n"})
    _must_die_msg("1 Python file(s) do not compile", check_python_compiles, {"a.py": "x = 1\n", "b.py": "def f(:\n"})
