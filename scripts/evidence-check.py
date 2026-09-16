#!/usr/bin/env python3
"""Flag evidence artefacts that break the W1 evidence contract.

usage: evidence-check.py <dir> --commits SHA [SHA ...]
       evidence-check.py --self-test

Every `.log` / `.txt` / `.tsv` under <dir> is checked, except under a scratch
tree (any directory component starting `scratch` — the same rule as
index-check.py, W1-Z Z3.2):

- must carry `head_sha=` and `tree_sha=` (unstamped → flag)
- a `.log` whose `head_sha` is not a prefix of one of `--commits` → flag
- `dirty=yes` without a `red-at-parent=` / `override=` label → flag

A hygiene-snapshot directory (sibling `provenance.txt` + `tests.txt`, the
files `hygiene-snapshot.sh` writes) stamps that directory's inventory
files: they inherit the directory `provenance.txt` instead of each carrying
a copy. A loose log directory without that snapshot marker still fails.

Exit 0 when nothing is flagged; otherwise print one line per finding and exit 1.
`--self-test` runs first from `main()` (red without the snapshot marker).
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

STAMP_RE = re.compile(r"^head_sha=(\S+)\s*$", re.M)
TREE_RE = re.compile(r"^tree_sha=(\S+)\s*$", re.M)
DIRTY_RE = re.compile(r"^dirty=(\S+)\s*$", re.M)
LABEL_RE = re.compile(r"^(?:red-at-parent=|override=)", re.M)
PROV_BANNER = "==== provenance ===="
ARTEFACT_SUFFIXES = {".log", ".txt", ".tsv"}
# Hygiene-snapshot.sh inventory (hygiene_inventory.py). tests.txt is the
# snapshot marker so a stray provenance.txt cannot launder a log directory.
SNAPSHOT_MARKER = "tests.txt"


def iter_artefacts(root: pathlib.Path) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part.startswith("scratch") for part in p.relative_to(root).parts[:-1]):
            continue
        if p.suffix not in ARTEFACT_SUFFIXES:
            continue
        out.append(p)
    return out


def is_snapshot_dir(d: pathlib.Path) -> bool:
    """True when d looks like a hygiene-snapshot.sh output directory."""
    prov = d / "provenance.txt"
    marker = d / SNAPSHOT_MARKER
    if not prov.is_file() or not marker.is_file():
        return False
    text = prov.read_bytes().decode("utf-8", "replace")
    return PROV_BANNER in text and bool(STAMP_RE.search(text) and TREE_RE.search(text))


def dir_stamp(path: pathlib.Path) -> str | None:
    """Return parent provenance.txt text when path is a snapshot inventory file."""
    parent = path.parent
    if not is_snapshot_dir(parent):
        return None
    return (parent / "provenance.txt").read_bytes().decode("utf-8", "replace")


def check_stamp_text(text: str, rel: str, commits: list[str], *, is_log: bool) -> list[str]:
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
    if is_log and "unit-green" in pathlib.Path(rel).name:
        if not re.search(r"Summary .*passed", text):
            findings.append(f"{rel}: unit-green log missing Summary … passed")
    return findings


def check_file(path: pathlib.Path, commits: list[str]) -> list[str]:
    text = path.read_bytes().decode("utf-8", "replace")
    rel = str(path)
    inherited = dir_stamp(path)
    if inherited is not None and path.name != "provenance.txt":
        # Inventory files inherit the directory stamp. dirty=yes is flagged
        # once on provenance.txt, not once per inventory file.
        findings: list[str] = []
        head_m = STAMP_RE.search(inherited)
        tree_m = TREE_RE.search(inherited)
        if not head_m or not tree_m:
            findings.append(f"{rel}: unstamped (need head_sha= and tree_sha=)")
            return findings
        head = head_m.group(1)
        if commits and not any(head.startswith(c) or c.startswith(head) for c in commits):
            findings.append(f"{rel}: head_sha={head[:12]} not in --commits")
        return findings
    return check_stamp_text(text, rel, commits, is_log=path.suffix == ".log")


def _self_test() -> None:
    """Red without the snapshot marker; green with directory provenance.txt."""

    def run_check(d: pathlib.Path, commits: list[str]) -> list[str]:
        findings: list[str] = []
        for path in iter_artefacts(d):
            findings.extend(check_file(path, commits))
        return findings

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        loose = root / "loose"
        loose.mkdir()
        (loose / "gate.log").write_text("no stamp here\n", encoding="utf-8")
        loose_findings = run_check(loose, ["abc"])
        if not any("unstamped" in f for f in loose_findings):
            raise SystemExit("evidence-check --self-test: loose log dir must fail unstamped")

        fake = root / "fake"
        fake.mkdir()
        (fake / "provenance.txt").write_text(
            "==== provenance ====\nhead_sha=abc\ntree_sha=def\ndirty=no\n",
            encoding="utf-8",
        )
        (fake / "gate.log").write_text("still a loose log\n", encoding="utf-8")
        fake_findings = run_check(fake, ["abc"])
        if not any("unstamped" in f for f in fake_findings):
            raise SystemExit(
                "evidence-check --self-test: provenance.txt without tests.txt must not launder logs"
            )

        snap = root / "snap"
        snap.mkdir()
        (snap / "provenance.txt").write_text(
            "==== provenance ====\nhead_sha=abc123\ntree_sha=def456\ndirty=yes\n"
            "override=measured-on-branch-before-squash\n",
            encoding="utf-8",
        )
        (snap / "tests.txt").write_text("# binary\tname\n", encoding="utf-8")
        (snap / "gates.txt").write_text("# gate\tkind\ttag\n", encoding="utf-8")
        (snap / "timings.tsv").write_text("gate\trun\tgate_rc\twall_s\n", encoding="utf-8")
        snap_findings = run_check(snap, ["abc123"])
        if snap_findings:
            raise SystemExit(
                "evidence-check --self-test: snapshot inventory must inherit provenance.txt: "
                + "; ".join(snap_findings)
            )

        dirty = root / "dirty-snap"
        dirty.mkdir()
        (dirty / "provenance.txt").write_text(
            "==== provenance ====\nhead_sha=abc123\ntree_sha=def456\ndirty=yes\n",
            encoding="utf-8",
        )
        (dirty / "tests.txt").write_text("#\n", encoding="utf-8")
        dirty_findings = run_check(dirty, ["abc123"])
        if not any("dirty=yes" in f and "provenance.txt" in f for f in dirty_findings):
            raise SystemExit(
                "evidence-check --self-test: dirty snapshot provenance.txt must be labelled"
            )
        if any("tests.txt" in f and "dirty=yes" in f for f in dirty_findings):
            raise SystemExit(
                "evidence-check --self-test: dirty label must not repeat on inventory files"
            )


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        _self_test()
        print("evidence-check: self-test ok")
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dir", type=pathlib.Path)
    ap.add_argument(
        "--commits",
        nargs="+",
        required=True,
        help="landed section SHAs (prefix match against artefact head_sha=)",
    )
    args = ap.parse_args()
    _self_test()
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
