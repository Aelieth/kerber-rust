#!/usr/bin/env python3
"""Move a summary's `script:line` citations from the tree they were written at to HEAD.

usage: claim-recite.py [--at SHA …] [--widen N] [--apply] SUMMARY.md…

A summary's "settled live" bullets cite gate cells as `scripts/x-gate.sh:N` or
`:N-M`; when the gate later grows above a cited cell, the numbers point at the
wrong lines and `claim-audit.py` fails the bullet. Of the `--at` candidates the
tool keeps, per file, the one SHA at which the most citations point at an
asserting window (the tree the summary was written against). For every
citation it reads the cited lines from `git show SHA:path`, finds the same text in the working
tree — by exact line content, keeping the citation's ordinal when the text
occurs more than once (the Rust-leg cell before the MIT-leg copy) — and
rewrites the citation. A range must match line for line; otherwise it is
reported as unresolved and left alone. Without `--apply` nothing is written.
Prints one line per citation and a `recite: … resolved … unresolved` total per
file. Exit 1 when anything is unresolved.

`--widen N` runs after the move (or alone): for every citation in a "Settled
live" bullet whose window does not assert one of the bullet's quoted values
under `claim-audit.py`'s rules, the end line is pushed forward, at most N
lines, to the first line that does — a citation of a cell's command becomes
the command through its assertion. A citation that already passes is left
untouched, so the step is idempotent.
"""
from __future__ import annotations

import importlib.util

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REF_RE = re.compile(r"`(?P<path>[\w./-]+\.(?:sh|py))?:(?P<a>\d+)(?:-(?P<b>\d+))?`")


def old_lines(sha: str, path: str) -> list[str] | None:
    r = subprocess.run(["git", "show", f"{sha}:{path}"], capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        return None
    return r.stdout.split("\n")


def occurrences(lines: list[str], text: str) -> list[int]:
    return [i for i, l in enumerate(lines) if l == text]


def resolve(old: list[str], new: list[str], a: int, b: int) -> tuple[int, int] | None:
    """Map old 1-based a..b to new 1-based a'..b' by content and ordinal."""
    if a < 1 or b > len(old) or b < a:
        return None
    first = old[a - 1]
    if not first.strip():
        return None
    olds = occurrences(old, first)
    news = occurrences(new, first)
    if not news:
        return None
    if len(news) == len(olds):
        k = olds.index(a - 1)
        start = news[k]
    elif len(news) == 1:
        start = news[0]
    else:
        # Nearest by relative position in the file.
        rel = (a - 1) / max(len(old), 1)
        start = min(news, key=lambda i: abs(i / max(len(new), 1) - rel))
    for off in range(b - a + 1):
        if start + off >= len(new) or new[start + off] != old[a - 1 + off]:
            return None
    return (start + 1, start + 1 + (b - a))


def pick_sha(text: str, shas: list[str]) -> str | None:
    """The candidate SHA at which the most citations point at an asserting window."""
    ca = load_audit()
    refs = []
    last_path = ""
    for m in REF_RE.finditer(text):
        path = m.group("path") or last_path
        if not path:
            continue
        last_path = path
        refs.append((path, int(m.group("a")), int(m.group("b") or m.group("a"))))
    best, best_n = None, -1
    for sha in shas:
        cache: dict[str, list[str] | None] = {}
        n = 0
        for path, a, b in refs:
            if path not in cache:
                cache[path] = old_lines(sha, path)
            old = cache[path]
            if old is None or a < 1 or b > len(old) or b < a:
                continue
            lo, hi = (max(0, a - 2), min(len(old), b + 1)) if a == b else (max(0, a - 1), min(len(old), b))
            if ca.asserting_text(ROOT, path, "\n".join(old[lo:hi])) is not None:
                n += 1
        if n > best_n:
            best, best_n = sha, n
    if best is not None:
        print(f"  base: {best[:7]} ({best_n}/{len(refs)} citations assert there)")
    return best


def recite(summary: pathlib.Path, shas: list[str], apply: bool) -> tuple[int, int]:
    text = summary.read_text()
    resolved = unresolved = 0
    base = pick_sha(text, shas)
    shas = [base] if base else []
    out = []
    pos = 0
    last_path = ""
    for m in REF_RE.finditer(text):
        path = m.group("path") or last_path
        if not path:
            continue
        last_path = path
        a = int(m.group("a"))
        b = int(m.group("b") or a)
        cur = (ROOT / path)
        if not cur.is_file():
            print(f"  {path}:{a}: not in the working tree")
            unresolved += 1
            continue
        new = cur.read_text().split("\n")
        mapped = None
        used = None
        for sha in shas:
            old = old_lines(sha, path)
            if old is None:
                continue
            mapped = resolve(old, new, a, b)
            if mapped:
                used = sha
                break
        span = f"{a}" if a == b else f"{a}-{b}"
        if not mapped:
            print(f"  {path}:{span}: unresolved")
            unresolved += 1
            continue
        na, nb = mapped
        nspan = f"{na}" if na == nb else f"{na}-{nb}"
        state = "same" if (na, nb) == (a, b) else f"-> {nspan} (at {used[:7]})"
        print(f"  {path}:{span}: {state}")
        resolved += 1
        if (na, nb) != (a, b):
            repl = f"`{m.group('path') or ''}:{nspan}`"
            out.append(text[pos : m.start()])
            out.append(repl)
            pos = m.end()
    out.append(text[pos:])
    if apply and resolved:
        summary.write_text("".join(out))
    return resolved, unresolved


def load_audit():
    spec = importlib.util.spec_from_file_location("claim_audit", ROOT / "scripts" / "claim-audit.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def window_ok(ca, path: str, sl: tuple[str, ...], a: int, b: int, values: list[str]) -> bool:
    """claim-audit's window rule: a single line sees its neighbours, a range is itself."""
    if a == b:
        lo, hi = max(0, a - 2), min(len(sl), b + 1)
    else:
        lo, hi = max(0, a - 1), min(len(sl), b)
    text = ca.asserting_text(ROOT, path, "\n".join(sl[lo:hi]))
    if text is None:
        return False
    return not values or ca.value_in(values, text)


def bullet_regions(lines: list[str]) -> list[tuple[int, int]]:
    """(start, end) line indexes of each bullet of the Settled-live section."""
    start = next((i for i, l in enumerate(lines) if l.startswith("## Settled live")), None)
    if start is None:
        return []
    regions: list[tuple[int, int]] = []
    cur: int | None = None
    i = start + 1
    while i < len(lines) and not lines[i].startswith("## "):
        l = lines[i]
        if l.startswith("- "):
            if cur is not None:
                regions.append((cur, i))
            cur = i
        elif cur is not None and not l.strip():
            regions.append((cur, i))
            cur = None
        i += 1
    if cur is not None:
        regions.append((cur, i))
    return regions


def widen(summary: pathlib.Path, n: int, apply: bool) -> tuple[int, int]:
    ca = load_audit()
    text = summary.read_text()
    lines = text.split("\n")
    widened = unresolved = 0
    for s, e in bullet_regions(lines):
        raw = lines[s:e]
        b = ca.make_bullet([raw[0][2:]] + [l.strip() for l in raw[1:] if l.strip()])
        mapping: dict[tuple[str, int, int], tuple[int, int]] = {}
        last_path = ""
        for m in REF_RE.finditer(b.text):
            path = m.group("path") or last_path
            if not path:
                continue
            last_path = path
            a, z = int(m.group("a")), int(m.group("b") or m.group("a"))
            key = (path, a, z)
            if key in mapping:
                continue
            sl = ca.script_lines(ROOT, path)
            if sl is None or a < 1 or z > len(sl) or z < a:
                continue
            if window_ok(ca, path, sl, a, z, b.values):
                continue
            hit = next((end for end in range(z + 1, min(len(sl), z + n) + 1) if window_ok(ca, path, sl, a, end, b.values)), None)
            span = f"{a}" if a == z else f"{a}-{z}"
            if hit is None:
                print(f"  {path}:{span}: no asserting line within {n} below (bullet: {b.title[:50]})")
                unresolved += 1
                continue
            mapping[key] = (a, hit)
            print(f"  {path}:{span}: widened to {a}-{hit}")
            widened += 1
        if not mapping:
            continue
        last_path = ""

        def sub(m: re.Match) -> str:
            nonlocal last_path
            path = m.group("path") or last_path
            last_path = path or last_path
            key = (path, int(m.group("a")), int(m.group("b") or m.group("a")))
            if key not in mapping:
                return m.group(0)
            na, nb = mapping[key]
            return f"`{m.group('path') or ''}:{na}-{nb}`"

        lines[s:e] = [REF_RE.sub(sub, l) for l in raw]
    if apply and widened:
        summary.write_text("\n".join(lines))
    return widened, unresolved


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--at", action="append", default=[], help="SHA(s) the citations were written at, tried in order")
    ap.add_argument("--widen", type=int, default=0, metavar="N", help="extend citations to their asserting line, at most N lines below")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("summary", nargs="+")
    args = ap.parse_args(argv)
    if not args.at and not args.widen:
        ap.error("nothing to do: pass --at SHA and/or --widen N")
    rc = 0
    for s in args.summary:
        p = pathlib.Path(s)
        print(f"==== {p}")
        if args.at:
            r, u = recite(p, args.at, args.apply)
            print(f"recite: {p.name}: {r} resolved, {u} unresolved{' (applied)' if args.apply else ''}")
            rc |= 1 if u else 0
        if args.widen:
            w, u = widen(p, args.widen, args.apply)
            print(f"widen: {p.name}: {w} widened, {u} without an asserting line{' (applied)' if args.apply else ''}")
            rc |= 1 if u else 0
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
