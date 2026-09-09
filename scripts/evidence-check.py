#!/usr/bin/env python3
"""Flag evidence artefacts that break the W1 evidence contract.

usage: evidence-check.py <dir> --commits SHA [SHA ...]

Every `.log` / `.txt` under <dir> (non-recursive for INDEX.md siblings; recursive
otherwise excluding scratch/) is checked:

- must carry `head_sha=` and `tree_sha=` (unstamped → flag)
- a `.log` whose `head_sha` is not a prefix of one of `--commits` → flag
- `dirty=yes` without a `red-at-parent=` / `override=` label → flag

Exit 0 when nothing is flagged; otherwise print one line per finding and exit 1.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

STAMP_RE = re.compile(r"^head_sha=(\S+)\s*$", re.M)
TREE_RE = re.compile(r"^tree_sha=(\S+)\s*$", re.M)
DIRTY_RE = re.compile(r"^dirty=(\S+)\s*$", re.M)
LABEL_RE = re.compile(r"^(?:red-at-parent=|override=)", re.M)


def iter_artefacts(root: pathlib.Path) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if "scratch" in p.parts:
            continue
        if p.suffix not in {".log", ".txt"}:
            continue
        out.append(p)
    return out


def check_file(path: pathlib.Path, commits: list[str]) -> list[str]:
    text = path.read_bytes().decode("utf-8", "replace")
    rel = str(path)
    findings: list[str] = []
    head_m = STAMP_RE.search(text)
    tree_m = TREE_RE.search(text)
    if not head_m or not tree_m:
        findings.append(f"{rel}: unstamped (need head_sha= and tree_sha=)")
        return findings
    head = head_m.group(1)
    if commits and not any(head.startswith(c) or c.startswith(head) for c in commits):
        findings.append(f"{rel}: head_sha={head[:12]} not in --commits")
    dirty_m = DIRTY_RE.search(text)
    if dirty_m and dirty_m.group(1) == "yes" and not LABEL_RE.search(text):
        findings.append(f"{rel}: dirty=yes without red-at-parent=/override= label")
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dir", type=pathlib.Path)
    ap.add_argument(
        "--commits",
        nargs="+",
        required=True,
        help="landed section SHAs (prefix match against artefact head_sha=)",
    )
    args = ap.parse_args()
    if not args.dir.is_dir():
        print(f"evidence-check: not a directory: {args.dir}", file=sys.stderr)
        return 2
    findings: list[str] = []
    for path in iter_artefacts(args.dir):
        findings.extend(check_file(path, args.commits))
    if not findings:
        print(f"evidence-check: 0 findings under {args.dir}")
        return 0
    for line in findings:
        print(line)
    print(f"evidence-check: {len(findings)} findings under {args.dir}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
