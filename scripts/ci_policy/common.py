"""Paths and helpers that every ci-policy module shares."""

from __future__ import annotations

import importlib.util
import os
import pathlib
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
