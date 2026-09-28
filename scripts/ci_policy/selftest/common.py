"""Helpers and the fixture the self-test files share."""

from __future__ import annotations

import io
import sys


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
