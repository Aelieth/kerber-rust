"""Helpers and the fixture the self-test files share."""

from __future__ import annotations

import io
import os
import pathlib
import subprocess
import sys
import tempfile

from ..common import GIT_LOCATION_VARS, _die, _scratch_root, reported_git_vars, scrub_git_env, without_git_env


def _must_die(fn, *args) -> None:
    err = sys.stderr
    sys.stderr = open("/dev/null", "w", encoding="utf-8")
    try:
        fn(*args)
        died = False
    except SystemExit:
        died = True
    finally:
        sys.stderr.close()
        sys.stderr = err
    if not died:
        raise AssertionError(f"{fn.__name__} must fail closed")


def _must_die_msg(needle: str, fn, *args, **kwargs) -> None:
    buf = io.StringIO()
    err = sys.stderr
    sys.stderr = buf
    try:
        fn(*args, **kwargs)
        died = False
    except SystemExit:
        died = True
    finally:
        sys.stderr = err
    text = buf.getvalue()
    name = getattr(fn, "__name__", "callable")
    if not died:
        raise AssertionError(f"{name} must fail closed")
    if needle not in text:
        raise AssertionError(f"{name} died without {needle!r}: {text!r}")


# The one fixture two self-test files share (the CI budgets: workflows and docs).
good_toml = (
    "[jobs]\n"
    "test = 300\nharness = 270\nmit-extra = 180\ndoc = 90\n"
    "msrv = 120\naudit = 240\nledger-mit = 60\nmit-image = 90\n"
    "[push]\nrun_wall = 360\n"
)

_SCRATCH_IDENT = {
    "GIT_AUTHOR_NAME": "fx",
    "GIT_AUTHOR_EMAIL": "fx@x",
    "GIT_COMMITTER_NAME": "fx",
    "GIT_COMMITTER_EMAIL": "fx@x",
}


def _self_test_git_env_scrub() -> None:
    """A scratch repository never touches the repository an inherited GIT_* names.

    An exported GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE once made a scratch `git init` write core.worktree into
    the checkout's shared config. Decoy repositories stand in for that checkout: the scratch commands under the
    raw environment change one (so the comparison can see a leak); under the scrub they leave theirs byte for
    byte as they were."""
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    inherited = {k: v for k, v in os.environ.items() if k.startswith("GIT_")}

    def git(cwd: pathlib.Path, env: dict[str, str], *args: str, check: bool = True) -> None:
        subprocess.run(["git", *args], cwd=cwd, env=env, check=check, capture_output=True)

    def repo(name: str) -> pathlib.Path:
        d = root / name
        d.mkdir()
        (d / "f").write_text(f"{name}\n")
        for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", name)):
            git(d, {**without_git_env(), **_SCRATCH_IDENT}, *args)
        return d

    def state(d: pathlib.Path) -> dict[str, bytes]:
        g = d / ".git"
        return {str(p.relative_to(g)): p.read_bytes() for p in sorted(g.rglob("*")) if p.is_file()}

    def naming(d: pathlib.Path) -> dict[str, str]:
        work = root / f"{d.name}-work"
        work.mkdir()
        (work / "w").write_text("work\n")
        g = d / ".git"
        paths = {
            "GIT_DIR": g,
            "GIT_WORK_TREE": work,
            "GIT_INDEX_FILE": g / "index",
            "GIT_COMMON_DIR": g,
            "GIT_OBJECT_DIRECTORY": g / "objects",
        }
        return {name: str(paths[name]) for name in GIT_LOCATION_VARS}

    def scratch(env: dict[str, str], check: bool = True) -> None:
        # The commands the Frozen-at fixture runs in its scratch repository.
        s = pathlib.Path(tempfile.mkdtemp(dir=root))
        (s / "g").write_text("scratch\n")
        for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "scratch")):
            git(s, env, *args, check=check)

    def restore() -> None:
        for name in [k for k in os.environ if k.startswith("GIT_")]:
            del os.environ[name]
        os.environ.update(inherited)

    try:
        raw = repo("raw")
        before = state(raw)
        scratch({**os.environ, **_SCRATCH_IDENT, **naming(raw)}, check=False)
        if state(raw) == before:
            _die("the GIT_* scrub self-test must see a raw scratch repository change the repository GIT_DIR names")
        decoy = repo("decoy")
        before = state(decoy)
        os.environ.update(naming(decoy))
        try:
            scratch({**without_git_env(), **_SCRATCH_IDENT})
        finally:
            restore()
        if state(decoy) != before:
            _die("a scratch repository built under an exported GIT_* changed the repository it names")
        os.environ.update({**naming(repo("scrub")), "GIT_CONFIG_PARAMETERS": "'core.bare'='true'"})
        try:
            dropped = scrub_git_env()
            left = sorted(k for k in os.environ if k.startswith("GIT_"))
        finally:
            restore()
        if left or not {*GIT_LOCATION_VARS, "GIT_CONFIG_PARAMETERS"} <= set(dropped):
            _die(f"scrub_git_env must drop every GIT_* variable: dropped {dropped}, left {left}")
        config = ["GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_KEY_0", "GIT_CONFIG_PARAMETERS",
                  "GIT_CONFIG_VALUE_0"]
        quiet = ["GIT_AUTHOR_NAME", "GIT_EDITOR", "GIT_PAGER"]
        reported = reported_git_vars(sorted([*GIT_LOCATION_VARS, *config, *quiet]))
        if sorted(reported) != sorted([*GIT_LOCATION_VARS, *config]):
            _die(f"ci-policy must report the dropped location and GIT_CONFIG* variables only, got {reported}")
    finally:
        restore()
        subprocess.run(["rm", "-rf", str(root)], check=False)
