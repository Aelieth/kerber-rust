#!/usr/bin/env python3
"""Exit 0 only when every expected test name FAILED in cargo output.

usage: unit-red-check.py <name> [<name> ...] < cargo-output

stdin is `cargo test` output. Exit 1 with "vacuous red" unless every
name has a `test … FAILED` line.
"""
from __future__ import annotations

import re
import sys


def check(out: str, names: list[str]) -> int:
    passed, missing = [], []
    for t in names:
        if re.search(rf"test .*\b{re.escape(t)}\b \.\.\. FAILED$", out, re.M):
            continue
        if re.search(rf"test .*\b{re.escape(t)}\b \.\.\. ok$", out, re.M):
            passed.append(t)
        else:
            missing.append(t)
    if not names:
        print("unit_red_at: vacuous red: empty expected names", file=sys.stderr)
        return 1
    if passed or missing:
        for t in passed:
            print(f"unit_red_at: vacuous red: {t} passed at parent", file=sys.stderr)
        for t in missing:
            print(f"unit_red_at: vacuous red: {t} did not FAIL at parent", file=sys.stderr)
        print(
            f"unit_red_at: require every inject #[test] FAILED "
            f"(passed={len(passed)} missing={len(missing)})",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    names = [n for n in sys.argv[1:] if n]
    out = sys.stdin.read()
    return check(out, names)


if __name__ == "__main__":
    raise SystemExit(main())
