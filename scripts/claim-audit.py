#!/usr/bin/env python3
"""Check that every "Settled live" bullet of a summary names asserting cells.

Bullet grammar: `- **Title:**` at column 0, continuation lines indented.
Backtick spans are cell references (`scripts/x-gate.sh:12`, `x-gate.sh:12-20`,
`:34` for the script of the previous reference), unit names (snake_case with an
underscore, a `fn` under crates/), MIT cites (`file.c:1-2`), artefacts (`*.log`,
`*.json` in the evidence dir the summary names) or quoted values.

A reference passes when its line sits within one line of an assertion
on one of the quoted values (or the reference is a range that covers
the assertion, or a function of that script which does): `grep -q/-F/-E/-x`,
`diff <(`, `die`, `exit 1`, `[ ]`, `test`, a Python `assert`, or a call
to a function of the same script whose body asserts.  A bullet passes
when every reference passes, it names a cell on each leg (Rust and MIT,
from container variables around the line — `"$NAME"`, `NAME_MIT`,
`MIT_`/`RUST_`, `mit_local`, `kadmin.local`, `kdb5_util`; a `diff <(`
line is both; a cell in a Samba, Heimdal or AD gate carries the oracle
leg) or an oracle settle artefact (its `cmd=` runs a MIT,
Samba or Heimdal tool — a Rust-side gate run is not a leg), a tooling
bullet (references into `scripts/*.py`) names a fixture line or a line
inside a check that runs the tool, and every artefact exists, is stamped (`head_sha=`
and `tree_sha=`) and carries a quoted value.

usage: claim-audit.py [--evidence-dir DIR] [--stamp] SUMMARY...
"""

from __future__ import annotations

import argparse
import functools
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REF_RE = re.compile(r"`(?P<path>[\w./-]+\.(?:sh|py))?:(?P<a>\d+)(?:-(?P<b>\d+))?`")
SPAN_RE = re.compile(r"`([^`]+)`")
ARTEFACT_RE = re.compile(r"^[\w./{},-]+\.(?:log|json)$")
CITE_RE = re.compile(r"^[\w./-]+\.(?:c|h|y|et|x|rs|md|txt)(?::[\d,-]+)?$")
UNIT_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
ASSERT_RE = re.compile(
    r"grep -[a-zA-Z]*[qFEx]\b|diff <\(|\bdie\b|\bexit [1-9]|^\s*\[{1,2} |\bif \[|\belif \[|^\s*test "
    r"|\|\| \{|^\s*assert\b|raise SystemExit|\b_die\(|_must_die\(|must_fail\(|_must_pass\(|raise AssertionError",
    re.M,
)
FUNC_RE = re.compile(r"^(\w+)\(\) \{$", re.M)
MIT_RE = re.compile(
    r'"\$NAME_MIT"|\$NAME_MIT\b|\bMIT_|\bmit_local\b|\bmit_|\bkadmin\.local\b'
    r"|\bkdb5_util\b|(?<!-)kpropd\b|(?<!-)kprop\b"
)
RUST_RE = re.compile(
    r'"\$NAME"|\$NAME\b(?!_MIT)|\bRUST_|\brust_'
)
SOURCE_CMDS = {"grep", "egrep", "fgrep", "rg", "sed", "cat", "head", "tail", "awk"}
ORACLE_TOOLS = {
    "kinit", "kvno", "klist", "kdestroy", "kpasswd", "kadmin", "kadmin.local", "kadmind", "kdb5_util",
    "krb5kdc", "kprop", "kpropd", "kproplog", "ktutil", "gss-mit-client", "gss-mit-server",
    "rd-safe-oracle", "kadm5-changepw-rpc", "kadm5_probe", "samba-tool", "ndrdump", "ldbsearch",
    "smbclient", "net", "kimpersonate",
}
ORACLE_RE = re.compile(r"\b(?:mit|oracle|samba|heimdal)\b", re.I)
ORACLE_GATE_RE = re.compile(r"(?:samba|heimdal|ad-)[\w-]*-gate\.sh$")
DOCKER_OPT_ARG = {"-e", "--env", "-w", "--workdir", "-u", "--user", "--entrypoint", "--name", "--network"}
FIXTURE_RE = re.compile(r"_must_die\(|must_fail\(|_must_pass\(|\bassert\b|raise AssertionError")
PROBE_RE = re.compile(r"subprocess\.(?:run|check_output|Popen)\(|_must_die\(|must_fail\(|\bassert\b")
DEF_RE = re.compile(r"^(?:def |[A-Za-z_])")
HEADER = "asserting cell"


class Bullet:
    def __init__(self, title: str, text: str) -> None:
        self.title = title
        self.text = text
        self.refs: list[tuple[str, int, int]] = []
        self.values: list[str] = []
        self.units: list[str] = []
        self.artefacts: list[str] = []
        self.reasons: list[str] = []
        self.notes: list[str] = []
        self._classify()

    def _classify(self) -> None:
        last_path = ""
        for m in REF_RE.finditer(self.text):
            path = m.group("path") or last_path
            if not path:
                self.reasons.append(f"`:{m.group('a')}` names no script")
                continue
            last_path = path
            a = int(m.group("a"))
            b = int(m.group("b") or a)
            self.refs.append((path, a, b))
        for span in SPAN_RE.findall(self.text):
            if REF_RE.fullmatch(f"`{span}`") or CITE_RE.match(span):
                continue
            if ARTEFACT_RE.match(span):
                self.artefacts.extend(expand_braces(span))
            elif UNIT_RE.match(span) and unit_exists(ROOT, span):
                self.units.append(span)
            elif len(span.strip()) >= 3:
                self.values.append(span)


def expand_braces(name: str) -> list[str]:
    m = re.search(r"\{([^{}]*)\}", name)
    if not m:
        return [name]
    out = []
    for alt in m.group(1).split(","):
        out.extend(expand_braces(name[: m.start()] + alt + name[m.end() :]))
    return out


def parse_section(text: str) -> tuple[str | None, list[Bullet]]:
    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if l.startswith("## Settled live")), None)
    if start is None:
        return None, []
    body: list[str] = []
    for l in lines[start + 1 :]:
        if l.startswith("## "):
            break
        body.append(l)
    bullets: list[Bullet] = []
    cur: list[str] = []
    for l in body:
        if l.startswith("- "):
            if cur:
                bullets.append(make_bullet(cur))
            cur = [l[2:]]
        elif cur and l.strip():
            cur.append(l.strip())
    if cur:
        bullets.append(make_bullet(cur))
    return lines[start], bullets


def make_bullet(lines: list[str]) -> Bullet:
    text = " ".join(lines)
    m = re.match(r"\*\*(.+?)\*\*", text)
    title = (m.group(1) if m else text[:60]).rstrip(":. ")
    return Bullet(title, text)


@functools.lru_cache(maxsize=None)
def script_lines(root: pathlib.Path, path: str) -> tuple[str, ...] | None:
    p = root / path
    if not p.is_file():
        p = root / "scripts" / path
    if not p.is_file():
        return None
    return tuple(p.read_text(errors="replace").split("\n"))


@functools.lru_cache(maxsize=None)
def function_bodies(root: pathlib.Path, path: str) -> dict[str, str]:
    text = "\n".join(script_lines(root, path) or ())
    bodies: dict[str, str] = {}
    for m in FUNC_RE.finditer(text):
        end = text.find("\n}", m.end())
        bodies[m.group(1)] = text[m.end() : end if end >= 0 else None]
    return bodies


@functools.lru_cache(maxsize=None)
def asserting_functions(root: pathlib.Path, path: str) -> frozenset[str]:
    bodies = function_bodies(root, path)
    direct = {n for n, b in bodies.items() if ASSERT_RE.search(b)}
    calls = re.compile(r"^\s*(?:\w+=\"?\$\()?(\w+)\b", re.M)
    return frozenset(
        n for n, b in bodies.items() if n in direct or any(c in direct for c in calls.findall(b))
    )


def asserting_text(root: pathlib.Path, path: str, window: str) -> str | None:
    """The window plus the bodies of asserting functions it calls; None if nothing asserts."""
    funcs = asserting_functions(root, path)
    bodies = function_bodies(root, path)
    called = []
    for line in window.split("\n"):
        m = re.match(r"^\s*(?:\w+=\"?\$\()?(\w+)\b", line)
        if m and m.group(1) in funcs:
            called.append(bodies[m.group(1)])
    if not called and not ASSERT_RE.search(window):
        return None
    return "\n".join([window, *called])


def enclosing_def(lines: tuple[str, ...], lineno: int) -> str:
    """Body of the top-level `def` that contains `lineno` (1-based); empty when none."""
    start = next((i for i in range(lineno - 1, -1, -1) if lines[i].startswith("def ")), None)
    if start is None:
        return ""
    end = next((i for i in range(start + 1, len(lines)) if DEF_RE.match(lines[i])), len(lines))
    return "\n".join(lines[start:end])


def value_in(values: list[str], text: str) -> bool:
    flat = " ".join(text.split())
    for v in values:
        for cand in (v, v.replace("\\", ""), " ".join(v.split())):
            if cand in text or cand in flat:
                return True
    return False


@functools.lru_cache(maxsize=None)
def unit_exists(root: pathlib.Path, name: str) -> bool:
    pat = re.compile(rf"\bfn {re.escape(name)}\b")
    for p in (root / "crates").rglob("*.rs"):
        if pat.search(p.read_text(errors="replace")):
            return True
    return False


def read_text(p: pathlib.Path) -> str:
    return p.read_bytes().decode("utf-8", "replace")


def settle_tool(cmd: str) -> str:
    """The program a settle really ran: through `docker exec … NAME tool` and `sh -c '…'`."""
    words = cmd.split()
    if words and pathlib.Path(words[0]).name == "docker":
        rest = words[1:]
        if rest and rest[0] in {"exec", "run"}:
            rest = rest[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in DOCKER_OPT_ARG else rest[1:]
        words = rest[1:]
    if len(words) >= 3 and words[0] in {"sh", "bash", "dash"} and words[1] == "-c":
        words = words[2].strip("'\"").split()
    return pathlib.Path(words[0]).name if words else ""


def settle_kind(text: str) -> str | None:
    """`oracle`, `run` or `reader` for a settle's `cmd=` line; None without one.

    A `sh -c` whose script continues on the following lines is an oracle
    when that script runs an oracle tool.
    """
    m = re.search(r"^cmd=(.*)$", text, re.M)
    if not m:
        return None
    tool = settle_tool(m.group(1))
    if tool in {"sh", "bash", "dash"} and m.group(1).rstrip().endswith("-c"):
        body = text[m.end():].split("\n====", 1)[0].split("\n\n", 1)[0]
        words = set(re.findall(r"[\w.-]+", body))
        if words & ORACLE_TOOLS or any(ORACLE_RE.search(w) for w in words):
            return "oracle"
        return "run"
    if not tool or tool in SOURCE_CMDS:
        return "reader"
    if tool in ORACLE_TOOLS or ORACLE_RE.search(tool):
        return "oracle"
    return "run"


def resolve_artefact(root: pathlib.Path, evidence: pathlib.Path | None, name: str) -> pathlib.Path | None:
    cands = [root / name]
    if evidence is not None:
        cands += [evidence / name, evidence.parent / name]
    return next((c for c in cands if c.is_file()), None)


def check_bullet(b: Bullet, root: pathlib.Path, evidence: pathlib.Path | None) -> None:
    legs: set[str] = set()
    gate_refs = 0
    tool_refs = 0
    fixture_ref = False
    passing = 0
    for path, a, z in b.refs:
        lines = script_lines(root, path)
        if lines is None:
            b.reasons.append(f"{path} not found")
            continue
        if a < 1 or z > len(lines) or z < a:
            b.reasons.append(f"{path}:{a}-{z} out of range")
            continue
        if a == z:
            lo, hi = max(0, a - 2), min(len(lines), z + 1)
        else:
            lo, hi = max(0, a - 1), min(len(lines), z)
        window = "\n".join(lines[lo:hi])
        text = asserting_text(root, path, window)
        if text is None:
            b.reasons.append(f"{path}:{a} asserts nothing")
            continue
        if b.values and not value_in(b.values, text):
            b.reasons.append(f"{path}:{a} asserts none of the quoted values")
            continue
        passing += 1
        if path.endswith(".py"):
            tool_refs += 1
            fixture_ref = fixture_ref or bool(
                FIXTURE_RE.search(window) or PROBE_RE.search(enclosing_def(lines, a))
            )
        if path.endswith("-gate.sh"):
            gate_refs += 1
            here = {n for n, rx in (("mit", MIT_RE), ("rust", RUST_RE)) if rx.search(window)}
            if "diff <(" in window:
                here |= {"mit", "rust"}
            if ORACLE_GATE_RE.search(path):
                here.add("mit")
            legs |= here
            b.notes.append(f"{path}:{a}-{z} legs={','.join(sorted(here)) or '-'}")
    for u in b.units:
        if not unit_exists(root, u):
            b.reasons.append(f"unit {u} not found under crates/")
    live_settle = False
    for name in b.artefacts:
        p = resolve_artefact(root, evidence, name)
        if p is None:
            b.reasons.append(f"artefact {name} missing")
            continue
        text = read_text(p)
        if name.endswith(".log") and not ("head_sha=" in text and "tree_sha=" in text):
            b.reasons.append(f"artefact {name} is not stamped")
        if b.values and not value_in(b.values, text):
            b.reasons.append(f"artefact {name} carries none of the quoted values")
        if p.name.startswith("settle-"):
            if not re.search(r"^==== settle .* ====$", text, re.M):
                b.reasons.append(f"settle {name} lacks the settle.sh banner")
            kind = settle_kind(text)
            if kind is None:
                b.reasons.append(f"settle {name} has no cmd= line")
            elif kind == "reader":
                b.reasons.append(f"settle {name} is a source excerpt, not a live settle")
            elif kind == "oracle":
                live_settle = True
            else:
                b.notes.append(f"settle {name} is a gate run, not an oracle leg")
    if passing == 0:
        b.reasons.append("names no asserting cell")
    elif gate_refs and not ({"rust", "mit"} <= legs or ("rust" in legs and live_settle)):
        missing = ", ".join(sorted({"rust", "mit"} - legs))
        b.reasons.append(f"no cell on the {missing} leg and no oracle settle")
    elif not gate_refs and tool_refs and not fixture_ref:
        b.reasons.append("tooling claim names no fixture line")


def audit_text(
    text: str, root: pathlib.Path, evidence: pathlib.Path | None
) -> list[tuple[str, str, list[str], list[str]]]:
    header, bullets = parse_section(text)
    if header is None:
        return [("Settled live", "fail", ["no '## Settled live' section"], [])]
    rows = []
    if HEADER not in header:
        rows.append(("Settled live", "fail", [f"header must say '{HEADER}'"], []))
    if not bullets:
        rows.append(("Settled live", "fail", ["no bullets"], []))
    for b in bullets:
        check_bullet(b, root, evidence)
        rows.append((b.title, "fail" if b.reasons else "ok", b.reasons, b.notes))
    return rows


def evidence_dir_of(text: str, root: pathlib.Path) -> pathlib.Path | None:
    m = re.search(r"working/logs/(?:[\w.-]+/)+", text)
    return root / m.group(0).rstrip("/") if m else None


def provenance() -> str:
    r = subprocess.run(
        ["bash", "-c", '. "$ROOT/scripts/lib/provenance.sh"'],
        cwd=ROOT,
        env={**__import__("os").environ, "ROOT": str(ROOT)},
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("summaries", nargs="+", type=pathlib.Path)
    ap.add_argument("--evidence-dir", type=pathlib.Path)
    ap.add_argument("--stamp", action="store_true", help="print the provenance header first")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the legs each cell supplied")
    args = ap.parse_args()
    if args.stamp:
        sys.stdout.write(provenance())
    failed = 0
    total = 0
    for summary in args.summaries:
        text = summary.read_text()
        evidence = args.evidence_dir or evidence_dir_of(text, ROOT)
        print(f"==== claim-audit {summary} ====")
        for title, status, reasons, notes in audit_text(text, ROOT, evidence):
            total += 1
            if status == "ok":
                print(f"ok    {title}")
            else:
                failed += 1
                print(f"fail  {title}: {'; '.join(reasons)}")
            if args.verbose:
                for n in notes:
                    print(f"      {n}")
    print(f"claim-audit: {total - failed} ok, {failed} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
