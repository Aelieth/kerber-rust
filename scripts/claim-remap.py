#!/usr/bin/env python3
"""Re-map the `script:line` cites of a summary's "## Settled live" section from one commit to another.

A cite is claim-audit's form: `path.sh:12`, `path.py:3-9`, or `:34` for the previous path, with
claim-audit's `scripts/` fallback. The cited file at OLD is aligned (difflib, unchanged blocks
only) with its candidates at NEW: the same path, plus, for a path given with `--moved
PATH=DIR`, every `*.py` under DIR at NEW (a module split into a package). A cite maps to the one
candidate whose unchanged block holds the whole cited range; a range that is in no such block,
or in blocks of more than one file with no longer winner, is flagged and left as it was, for a
hand fix. Files that did not change keep their numbers. With `--write` the section is rewritten
in place and its "at Frozen-at `OLD`" becomes NEW; the log goes to stdout either way.

usage: claim-remap.py SUMMARY OLD NEW [--moved PATH=DIR ...] [--write]
       claim-remap.py --self-test
Exit 0 when nothing is flagged, 1 otherwise, 2 on a usage error.
"""

from __future__ import annotations

import difflib
import re
import subprocess
import sys

REF_RE = re.compile(r"`(?P<path>[\w./-]+\.(?:sh|py))?:(?P<a>\d+)(?:-(?P<b>\d+))?`")


def show(rev: str, path: str) -> tuple[str, list[str]] | None:
    for cand in (path, f"scripts/{path}"):
        r = subprocess.run(["git", "show", f"{rev}:{cand}"], capture_output=True, text=True, errors="replace")
        if r.returncode == 0:
            return cand, r.stdout.split("\n")
    return None


def tree_files(rev: str, directory: str) -> list[str]:
    r = subprocess.run(["git", "ls-tree", "-r", "--name-only", rev, "--", directory], capture_output=True,
                       text=True, check=False)
    return sorted(p for p in r.stdout.split() if p.endswith(".py"))


def blocks(old: list[str], new: list[str]) -> list[tuple[int, int, int]]:
    """(old start, new start, length), 1-based, of the unchanged blocks."""
    sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    return [(i1 + 1, j1 + 1, i2 - i1) for tag, i1, i2, j1, _j2 in sm.get_opcodes() if tag == "equal"]


def locate(a: int, b: int, cands: dict[str, list[tuple[int, int, int]]]) -> tuple[str, int, int] | str:
    """(file, new a, new b) for the old range a..b, or the reason it is flagged."""
    hits = []
    for path, bl in cands.items():
        for o, n, length in bl:
            if o <= a and b < o + length:
                hits.append((length, path, n + (a - o), n + (b - o)))
    if not hits:
        return "in no unchanged block"
    hits.sort(reverse=True)
    if len(hits) > 1 and hits[0][0] == hits[1][0]:
        return f"ambiguous: {hits[0][1]} and {hits[1][1]}"
    _length, path, na, nb = hits[0]
    return path, na, nb


def remap_section(section: str, cands_for, same_for) -> tuple[str, list[str], int, int]:
    """(new section, log lines, moved count, flagged count)."""
    log: list[str] = []
    moved = flagged = 0
    last = ""
    last_new = ""

    def repl(m: re.Match[str]) -> str:
        nonlocal last, last_new, moved, flagged
        raw_path = m.group("path")
        path = raw_path or last
        last = path
        a = int(m.group("a"))
        b = int(m.group("b")) if m.group("b") else a
        cite = m.group(0)
        if same_for(path):
            last_new = path
            return cite
        where = locate(a, b, cands_for(path))
        if isinstance(where, str):
            flagged += 1
            log.append(f"flagged {cite} ({path}): {where}")
            last_new = path
            return cite
        new_path, na, nb = where
        rng = f"{na}" if a == b else f"{na}-{nb}"
        # a bare `:N` stays bare only when it lands in the file the previous cite now names
        out = f"`{new_path}:{rng}`" if raw_path or new_path != last_new else f"`:{rng}`"
        last_new = new_path
        if out != cite:
            moved += 1
            log.append(f"moved {cite} ({path}) -> {out}")
        return out

    return REF_RE.sub(repl, section), log, moved, flagged


def main_remap(argv: list[str]) -> int:
    write = "--write" in argv
    args = [a for a in argv if a != "--write"]
    moved_dirs: dict[str, str] = {}
    rest = []
    it = iter(args)
    for a in it:
        if a == "--moved":
            spec = next(it, "")
            if "=" not in spec:
                print("claim-remap: --moved takes PATH=DIR", file=sys.stderr)
                return 2
            k, v = spec.split("=", 1)
            moved_dirs[k] = v
        else:
            rest.append(a)
    if len(rest) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    summary, old_rev, new_rev = rest
    text = open(summary, encoding="utf-8").read()
    start = text.index("\n## Settled live")
    nxt = text.find("\n## ", start + 1)
    end = len(text) if nxt < 0 else nxt
    section = text[start:end]
    cache: dict[str, tuple[bool, dict[str, list[tuple[int, int, int]]]]] = {}

    def prepare(path: str) -> tuple[bool, dict[str, list[tuple[int, int, int]]]]:
        if path in cache:
            return cache[path]
        old = show(old_rev, path)
        if old is None:
            cache[path] = (True, {})
            return cache[path]
        real, old_lines = old
        new = show(new_rev, real)
        cands: dict[str, list[str]] = {}
        if new is not None:
            cands[real] = new[1]
        if real in moved_dirs:
            for f in tree_files(new_rev, moved_dirs[real]):
                got = show(new_rev, f)
                if got is not None:
                    cands[f] = got[1]
        same = new is not None and new[1] == old_lines and real not in moved_dirs
        cache[path] = (same, {f: blocks(old_lines, lines) for f, lines in cands.items()})
        return cache[path]

    new_section, log, moved, flagged = remap_section(section, lambda p: prepare(p)[1], lambda p: prepare(p)[0])
    new_section = new_section.replace(f"at Frozen-at `{old_rev}`", f"at Frozen-at `{new_rev}`")
    print(f"old={old_rev} new={new_rev} moved_dirs={moved_dirs}")
    print(f"cites_moved={moved} flagged={flagged}")
    for line in log:
        print(line)
    if write:
        with open(summary, "w", encoding="utf-8") as fh:
            fh.write(text[:start] + new_section + text[end:])
    return 1 if flagged else 0


def _self_test() -> int:
    """Cites follow unchanged blocks, within a file and across a split; changed, ambiguous and split
    ranges are flagged; a bare `:N` stays bare only inside the previous cite's file."""
    body = [f"line {i}" for i in range(1, 41)]
    old = {"a.py": body}
    n = 0

    def run(section: str, new: dict[str, list[str]], moved: bool) -> tuple[str, list[str], int, int]:
        def cands(path: str):
            files = dict(new) if moved else {path: new.get(path, [])}
            return {f: blocks(old[path], lines) for f, lines in files.items()}

        return remap_section(section, cands, lambda p: False)

    # 1. an insertion above shifts a cite; a range shifts whole
    shifted = ["new top"] * 3 + body
    out, _log, moved, flagged = run("x `a.py:10` y `a.py:20-22`", {"a.py": shifted}, False)
    if out != "x `a.py:13` y `a.py:23-25`" or (moved, flagged) != (2, 0):
        raise SystemExit(f"self-test shift: {out} {moved} {flagged}")
    n += 1
    # 2. a split: lines 1-20 to p/one.py, 21-40 to p/two.py; the bare `:25` changes file, so it is written out
    split = {"a.py": ["shim"], "p/one.py": ["doc"] + body[:20], "p/two.py": ["doc", "doc"] + body[20:]}
    out, _log, moved, flagged = run("`a.py:5` / `:25`", split, True)
    if out != "`p/one.py:6` / `p/two.py:7`" or flagged:
        raise SystemExit(f"self-test split: {out} {flagged}")
    n += 1
    # 3. a bare `:N` in the same new file stays bare
    out, _log, _moved, flagged = run("`a.py:5` / `:7`", split, True)
    if out != "`p/one.py:6` / `:8`" or flagged:
        raise SystemExit(f"self-test bare: {out} {flagged}")
    n += 1
    # 4. a changed cited line is flagged and left as it was
    changed = list(body)
    changed[9] = "line 10 edited"
    out, log, _moved, flagged = run("`a.py:10`", {"a.py": changed}, False)
    if out != "`a.py:10`" or flagged != 1 or "no unchanged block" not in log[0]:
        raise SystemExit(f"self-test changed: {out} {log}")
    n += 1
    # 5. a range split across two files is flagged
    out, log, _moved, flagged = run("`a.py:19-22`", split, True)
    if flagged != 1:
        raise SystemExit(f"self-test range across files: {out} {log}")
    n += 1
    # 6. the same block in two files with no longer winner is ambiguous
    twice = {"p/one.py": body[:20], "p/two.py": body[:20]}
    out, log, _moved, flagged = run("`a.py:5`", twice, True)
    if flagged != 1 or "ambiguous" not in log[0]:
        raise SystemExit(f"self-test ambiguous: {out} {log}")
    n += 1
    # 7. an unchanged file keeps every number
    out, _log, moved, flagged = run("`a.py:10`", {"a.py": body}, False)
    if out != "`a.py:10`" or moved or flagged:
        raise SystemExit(f"self-test unchanged: {out}")
    n += 1
    return n


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        print(f"claim-remap: self-test ok ({_self_test()} cases)")
        return 0
    _self_test()
    return main_remap(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
