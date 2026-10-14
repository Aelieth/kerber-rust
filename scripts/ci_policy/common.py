"""Paths and helpers that every ci-policy module shares."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
NEXTEST_TOML = ROOT / ".config" / "nextest.toml"
GITIGNORE = ROOT / ".gitignore"
SCRIPTS = ROOT / "scripts"


def _die(msg: str) -> None:
    print(f"ci-policy: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _hygiene_inventory():
    spec = importlib.util.spec_from_file_location(
        "hygiene_inventory", SCRIPTS / "lib" / "hygiene_inventory.py"
    )
    if spec is None or spec.loader is None:
        _die("cannot load scripts/lib/hygiene_inventory.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scratch_root() -> pathlib.Path:
    base = pathlib.Path(os.environ.get("KERBER_SCRATCH") or ROOT / "target" / "ci-policy")
    base.mkdir(parents=True, exist_ok=True)
    return base


# Git reads GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_COMMON_DIR, GIT_OBJECT_DIRECTORY, the GIT_CONFIG_*
# family and the rest of its GIT_* variables before it looks at its working directory. A scratch repository
# built while one is inherited is the repository it names: `git init` there re-initialises it (an exported
# GIT_WORK_TREE becomes its core.worktree), `git add` fills its index and `git commit` moves its branch.
# These name the repository, index, work tree or object store.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY")


def reported_git_vars(names: list[str]) -> list[str]:
    """The dropped names ci-policy reports: those that name a repository, index, work tree or object store,
    and the GIT_CONFIG* family, whose settings (a safe.directory among them) no longer reach git. Others,
    such as GIT_EDITOR, go quietly."""
    return [k for k in names if k in GIT_LOCATION_VARS or k.startswith("GIT_CONFIG")]


def git_head() -> str:
    """This checkout's HEAD commit. Git that cannot read the checkout (not a repository, or a dubious-ownership
    refusal once an environment safe.directory is dropped) dies here with git's own error, so a probe that
    needs git never passes as a skip."""
    r = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        _die(f"git cannot read this checkout ({ROOT}): {(r.stderr or r.stdout).strip()[-300:]}")
    return r.stdout.strip()


def without_git_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """A copy of `env` (default: this process's environment) without any GIT_* variable."""
    src = os.environ if env is None else env
    return {k: v for k, v in src.items() if not k.startswith("GIT_")}


def scrub_git_env() -> list[str]:
    """Drop every GIT_* variable from this process's environment, and so from everything it runs;
    return the names dropped."""
    names = sorted(k for k in os.environ if k.startswith("GIT_"))
    for name in names:
        del os.environ[name]
    return names
