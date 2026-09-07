#!/usr/bin/env python3
"""Every file in an evidence directory must be named by its INDEX.md.

usage: index-check.py <evidence-dir>…   (or --all <root> for every subdirectory that has an INDEX.md)

A name counts when it appears in INDEX.md inside backticks or as the first
cell of a table row; `{a,b}` braces expand; a directory name in the index
covers every file under it. `scratch/` trees (gate `KERBER_SCRATCH` output)
are never evidence and are skipped. Prints `files=N unnamed=M` per
directory and exits 1 when anything is unnamed.
"""
from __future__ import annotations

import pathlib
import re
import sys

BACKTICK = re.compile(r"`([^`\n]+)`")
TABLE_FIRST_CELL = re.compile(r"^\|\s*([^|`\n]+?)\s*\|", re.M)
BRACES = re.compile(r"\{([^{}]*)\}")


def expand(name: str) -> set[str]:
    m = BRACES.search(name)
    if not m:
        return {name}
    out: set[str] = set()
    for alt in m.group(1).split(","):
        out |= expand(name[: m.start()] + alt.strip() + name[m.end() :])
    return out


def named_in(index: pathlib.Path) -> set[str]:
    text = index.read_text(errors="replace")
    names: set[str] = set()
    for n in BACKTICK.findall(text) + TABLE_FIRST_CELL.findall(text):
        names |= expand(n.strip())
    return names


def covered(rel: str, names: set[str]) -> bool:
    if rel in names:
        return True
    parts = rel.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        if prefix in names or prefix + "/" in names:
            return True
    return parts[-1] in names or any(n.endswith("/" + rel) for n in names)


def check(d: pathlib.Path) -> tuple[int, list[str]]:
    index = d / "INDEX.md"
    if not index.is_file():
        return 0, ["INDEX.md missing"]
    names = named_in(index)
    files = 0
    unnamed: list[str] = []
    for p in sorted(d.rglob("*")):
        if not p.is_file() or p == index or "scratch" in p.relative_to(d).parts:
            continue
        files += 1
        rel = str(p.relative_to(d))
        if not covered(rel, names):
            unnamed.append(rel)
    return files, unnamed


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[0] == "--all":
        root = pathlib.Path(argv[1])
        dirs = sorted(p.parent for p in root.rglob("INDEX.md") if "scratch" not in p.parts)
    else:
        dirs = [pathlib.Path(a) for a in argv]
    rc = 0
    for d in dirs:
        files, unnamed = check(d)
        print(f"{d}: files={files} unnamed={len(unnamed)}")
        for u in unnamed:
            print(f"  unnamed: {u}")
        if unnamed:
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
