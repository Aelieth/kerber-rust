#!/usr/bin/env python3
"""Write a W2/W3 hygiene snapshot into an output directory.

Invoked by scripts/hygiene-snapshot.sh. Inventories are line-oriented so
hygiene-diff.py can set-compare them.

W2 recorded time: tests, gate cells, oracles, sleeps, boots. W3 adds shape:
LOC/comment lines per package and file, function and file size maxima,
`pub` surface, `#[allow]` sites, process-history comments, gate assert
counts, binaries and dependencies (always), and under `--quality` the
compiler-backed counts (fmt, clippy, rustdoc `-D warnings`, doctests,
`missing_docs`, shellcheck). Every count is a grep or a compiler run over
the tree — nothing here changes behaviour, so a swath that changes a
number changed the shape.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

SECTION_RE = re.compile(r"""echo\s+["']====\s*(.+?)\s*====""")
IDENT_RE = re.compile(r"\b((?:MIT|RUST)_[A-Z0-9_]+)\b")
SLEEP_RE = re.compile(r"\bsleep\s+([0-9]+(?:\.[0-9]+)?)")
CARGO_BUILD_RE = re.compile(r"\bcargo\s+build\b")
DOCKER_RUN_RE = re.compile(r"\bdocker\s+run\b")
ENTRYPOINT_SLEEP = re.compile(r"--entrypoint\s+sleep")
FLOW_SECTION_RE = re.compile(r"""echo\s+["']====\s*flow:(\S+)\s*====""")
SCRIPT_RE = re.compile(r"scripts/([A-Za-z0-9._-]+\.sh)")
JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.M)
PROTO_HINT = re.compile(
    r"proto:|lockout|postdate|starttime|ticket age|renew|soak|failurecount|nyv",
    re.I,
)


def _run(cmd: list[str], cwd: pathlib.Path, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def write_lines(path: pathlib.Path, header: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = header.rstrip() + "\n" + "".join(f"{ln}\n" for ln in lines)
    path.write_text(body, encoding="utf-8")


def list_tests(root: pathlib.Path) -> list[str]:
    env = os.environ.copy()
    conf = root / "harness" / "nextest-krb5.conf"
    if conf.is_file():
        env["KRB5_CONFIG"] = str(conf)
    proc = _run(
        ["cargo", "nextest", "list", "--workspace", "--message-format", "json"],
        root,
        timeout=600,
    )
    if proc.returncode != 0:
        raise SystemExit(f"nextest list failed: {proc.stderr[-2000:]}")
    obj = json.loads(proc.stdout)
    rows: list[str] = []
    for binary, suite in (obj.get("rust-suites") or {}).items():
        for name in suite.get("testcases") or {}:
            rows.append(f"{binary}\t{name}")
    rows.sort()
    count = obj.get("test-count")
    if count is not None and count != len(rows):
        raise SystemExit(f"nextest test-count {count} != named {len(rows)}")
    return rows


def workflow_membership(root: pathlib.Path) -> dict[str, list[str]]:
    """gate-file-name -> ['ci.yml:harness', ...]"""
    found: dict[str, list[str]] = {}
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return found
    for path in sorted(wf_dir.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        jobs_m = re.search(r"(?m)^jobs:\s*$", text)
        if not jobs_m:
            continue
        rest = text[jobs_m.end() :]
        headers = list(JOB_HEADER_RE.finditer(rest))
        for i, m in enumerate(headers):
            start = m.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(rest)
            body = rest[start:end]
            job = m.group(1)
            for script in SCRIPT_RE.findall(body):
                found.setdefault(script, []).append(f"{path.name}:{job}")
    return found


def gate_tags(text: str) -> list[tuple[str, str]]:
    tags: list[tuple[str, str]] = []
    seen_echo: set[str] = set()
    for line in text.splitlines():
        sm = SECTION_RE.search(line)
        if sm:
            tags.append(("section", sm.group(1).strip()))
        fm = FLOW_SECTION_RE.search(line)
        if fm:
            tags.append(("flow", fm.group(1).strip()))
        for ident in IDENT_RE.findall(line):
            if ident not in seen_echo:
                seen_echo.add(ident)
                tags.append(("echo", ident))
    return tags


def _in_poll_loop(lines: list[str], idx: int) -> bool:
    for j in range(idx, max(-1, idx - 30), -1):
        if re.search(r"for\s+\S+\s+in\s+\$\(seq", lines[j]):
            return True
        if re.search(r"^\s*while\b", lines[j]):
            return True
        if re.match(r"^\s*done\b", lines[j]):
            return False
    return False


def sleep_sites(text: str, rel: str) -> list[str]:
    rows: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        code = line.split("#", 1)[0]
        if ENTRYPOINT_SLEEP.search(line) or re.search(r"docker\s+run.*sleep\s+3600", line):
            continue
        m = SLEEP_RE.search(code)
        if not m:
            continue
        sec = m.group(1)
        kind = "poll" if _in_poll_loop(lines, i) else "padding"
        comment = line[line.index("#") :] if "#" in line else ""
        if kind != "poll" and (comment.strip().startswith("# proto:") or PROTO_HINT.search(line)):
            kind = "proto"
        rows.append(f"{rel}\t{i + 1}\t{sec}\t{kind}")
    return rows


def inventory_gates(root: pathlib.Path) -> tuple[list[str], list[str], list[str], list[str]]:
    """cells, sleeps, cargo-builds, boots."""
    membership = workflow_membership(root)
    cells: list[str] = []
    sleeps: list[str] = []
    builds: list[str] = []
    boots: list[str] = []
    scripts = root / "scripts"
    for path in sorted(scripts.glob("*-gate.sh")):
        rel = f"scripts/{path.name}"
        text = path.read_text(encoding="utf-8", errors="replace")
        for kind, tag in gate_tags(text):
            cells.append(f"{path.name}\t{kind}\t{tag}")
        for loc in membership.get(path.name, []):
            cells.append(f"{path.name}\tworkflow\t{loc}")
        sleeps.extend(sleep_sites(text, rel))
        if CARGO_BUILD_RE.search(text):
            builds.append(path.name)
        mit_boots = len(re.findall(r"docker\s+run\b(?![^\n]*--entrypoint\s+sleep)", text))
        rust_boots = len(re.findall(r"--test-realm|/tmp/krb5-kdc", text))
        boots.append(f"{path.name}\tmit_run_sites={mit_boots}\trust_kdc_sites={rust_boots}")
    cells.sort()
    return cells, sleeps, builds, boots


def diffsend_cases(root: pathlib.Path) -> list[str]:
    sys.path.insert(0, str(root / "scripts"))
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_policy", root / "scripts" / "ci-policy.py")
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load ci-policy.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return sorted(mod.DIFFSEND_CASES)


def ledger_rows(root: pathlib.Path) -> tuple[list[str], dict[str, int]]:
    sys.path.insert(0, str(root / "scripts"))
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_policy_led", root / "scripts" / "ci-policy.py")
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load ci-policy.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    text = (root / "docs" / "mit-parity-ledger.md").read_text(encoding="utf-8")
    recount = mod.recount_ledger_verdicts(text)
    rows: list[str] = []
    for line in text.splitlines():
        if not line.startswith("|") or "MIT file:line" in line or line.startswith("| ---"):
            continue
        cols = mod._split_ledger_row(line)
        if len(cols) < 7 or cols[5] == "verdict":
            continue
        rows.append(f"{cols[0]}\t{cols[5]}")
    return rows, recount


def client_diff_flows(root: pathlib.Path) -> list[str]:
    flows: set[str] = set()
    for path in sorted((root / "scripts").glob("*-gate.sh")):
        text = path.read_text(encoding="utf-8")
        flows.update(m.group(1) for m in FLOW_SECTION_RE.finditer(text))
    return sorted(flows)


def rust_sleeps(root: pathlib.Path) -> list[str]:
    rows: list[str] = []
    for path in sorted((root / "crates").glob("*/tests/**/*.rs")):
        rel = str(path.relative_to(root))
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if "thread::sleep" in line or "std::thread::sleep" in line:
                rows.append(f"{rel}:{i}")
    return rows


def quality_grep(root: pathlib.Path) -> list[str]:
    rows: list[str] = []
    allow_n = 0
    unwrap_n = 0
    src_loc = 0
    test_files = 0
    for path in (root / "crates").rglob("*.rs"):
        rel = str(path.relative_to(root))
        text = path.read_text(encoding="utf-8", errors="replace")
        src_loc += text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        if "/tests/" in rel.replace("\\", "/"):
            test_files += 1
        allow_n += len(re.findall(r"#\[allow\(", text))
        if "/src/" in rel.replace("\\", "/") and "/tests/" not in rel.replace("\\", "/"):
            unwrap_n += len(re.findall(r"\bunwrap\(|\bexpect\(|\bpanic!\(", text))
    rows.append(f"allow={allow_n}")
    rows.append(f"unwrap_expect_panic_src={unwrap_n}")
    rows.append(f"rs_loc={src_loc}")
    rows.append(f"test_rs_files={test_files}")
    rows.append(f"gate_scripts={sum(1 for _ in (root / 'scripts').glob('*-gate.sh'))}")
    traces = root / "tests" / "traces"
    if traces.is_dir():
        tracked = _run(["git", "ls-files", "tests/traces"], root)
        n_tracked = len([ln for ln in tracked.stdout.splitlines() if ln.strip()])
        n_files = sum(1 for p in traces.rglob("*") if p.is_file())
        rows.append(f"traces_tracked={n_tracked}")
        rows.append(f"traces_files={n_files}")
        rows.append(f"traces_untracked={max(0, n_files - n_tracked)}")
    return rows


# ---- W3 shape inventory -----------------------------------------------------

FN_RE = re.compile(
    r"^\s*(?P<vis>pub(?:\([^)]*\))?\s+)?"
    r"(?:(?:const|async|unsafe|extern\s+\"[^\"]*\")\s+)*fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
CFG_TEST_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")
MOD_OPEN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{")
PUB_ITEM_RE = re.compile(
    r"^\s*pub(?P<restrict>\s*\([^)]*\))?\s+(?:(?:const|async|unsafe|extern\s+\"[^\"]*\")\s+)*"
    r"(?:fn|struct|enum|trait|type|const|static|mod|use|union|macro_rules!)\b"
)
ALLOW_SITE_RE = re.compile(r"#!?\[allow\(([^)]*)\)\]")
# The S4 acceptance grep: process tags that do not belong in source comments.
PROCESS_HISTORY_RE = re.compile(r"\bR[0-9]+\b|A′-[0-9]|W0[a-f]|W1-[A-Z]|Round [0-9]|parent [0-9a-f]{7}")
DIE_RE = re.compile(r"\bdie\b")
EXIT_1_RE = re.compile(r"\bexit\s+1\b")
GREP_Q_RE = re.compile(r"\bgrep\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*q[A-Za-z]*\b")
DIFF_SUB_RE = re.compile(r"\bdiff\s+<\(")
# The version the ci.yml shellcheck job installs and make shellcheck falls back to.
SHELLCHECK_IMAGE = "koalaman/shellcheck:v0.11.0"
SHELL_GLOBS = ("scripts/*.sh", "scripts/lib/*.sh", "harness/*.sh")
WARN_LINE_RE = re.compile(r"^(?:warning|error)(?:\[[^\]]+\])?: ")
WARN_SUMMARY_RE = re.compile(
    r"^(?:warning|error): (?:aborting|could not|build failed|\d+ warnings? emitted|`[^`]+` \([^)]*\) generated)"
)


def _blank_keep_newlines(s: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in s)


def strip_noncode(text: str) -> str:
    """Blank comments and string/char literal bodies, keeping line structure.

    The brace scanner below must not see `{` inside `"…"`, `'{'` or `// …`.
    Lifetimes (`'a`) are kept; raw and byte strings are recognised.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(_blank_keep_newlines(text[i:j]))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append('"' + _blank_keep_newlines(text[i + 1 : j - 1]) + '"')
            i = j
            continue
        if c == "r" and nxt in ('"', "#"):
            prev = text[i - 1] if i > 0 else ""
            prev_ok = not (prev.isalnum() or prev == "_") or (
                prev == "b" and (i < 2 or not (text[i - 2].isalnum() or text[i - 2] == "_"))
            )
            j, hashes = i + 1, 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if prev_ok and j < n and text[j] == '"':
                close = '"' + "#" * hashes
                k = text.find(close, j + 1)
                k = n if k < 0 else k + len(close)
                out.append(_blank_keep_newlines(text[i:k]))
                i = k
                continue
        if c == "'":
            if nxt == "\\":
                j = text.find("'", i + 2)
                if 0 < j and j - i <= 12:
                    out.append(" " * (j + 1 - i))
                    i = j + 1
                    continue
            elif i + 2 < n and text[i + 2] == "'":
                out.append("   ")
                i += 3
                continue
        out.append(c)
        i += 1
    return "".join(out)


def scan_items(code: str) -> tuple[list[tuple[int, int, str, str]], list[tuple[int, int]]]:
    """(start, end, name, vis) per fn body and (start, end) per `#[cfg(test)] mod`; 1-based."""
    lines = code.split("\n")

    def find_body(li: int, ci: int) -> tuple[int, int] | None:
        depth = 0
        while li < len(lines):
            s = lines[li]
            while ci < len(s):
                ch = s[ci]
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
                elif ch == "{" and depth <= 0:
                    return li, ci
                elif ch == ";" and depth <= 0:
                    return None
                ci += 1
            li += 1
            ci = 0
        return None

    def find_close(li: int, ci: int) -> int:
        depth = 0
        while li < len(lines):
            s = lines[li]
            while ci < len(s):
                ch = s[ci]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return li
                ci += 1
            li += 1
            ci = 0
        return len(lines) - 1

    fns: list[tuple[int, int, str, str]] = []
    tests: list[tuple[int, int]] = []
    pending_cfg_test = False
    for li, s in enumerate(lines):
        if CFG_TEST_RE.match(s):
            pending_cfg_test = True
            continue
        if pending_cfg_test:
            if s.strip().startswith("#["):
                continue
            pending_cfg_test = False
            if MOD_OPEN_RE.match(s):
                body = find_body(li, s.index("mod"))
                if body is not None:
                    tests.append((li + 1, find_close(*body) + 1))
                continue
        m = FN_RE.match(s)
        if not m:
            continue
        body = find_body(li, m.end())
        if body is None:
            continue
        fns.append((li + 1, find_close(*body) + 1, m.group("name"), "pub" if m.group("vis") else "priv"))
    return fns, tests


def has_doc_header(raw_lines: list[str], decl_line: int) -> bool:
    """A `///` (or block doc) line sits directly above the fn, skipping attributes."""
    idx = decl_line - 2
    while idx >= 0:
        s = raw_lines[idx].strip()
        if s.startswith("#["):
            idx -= 1
            continue
        if s.endswith(")]") and not s.startswith("//"):
            # tail of a multi-line attribute: walk to its `#[`
            k = idx
            while k >= 0 and k > idx - 6 and not raw_lines[k].strip().startswith("#["):
                k -= 1
            if k >= 0 and raw_lines[k].strip().startswith("#["):
                idx = k - 1
                continue
        return s.startswith("///") or s.endswith("*/")
    return False


def classify_lines(raw_lines: list[str]) -> tuple[int, int, int, int]:
    """(sloc, comment, doc, blank) — doc is `///` / `//!`; comment is other `//` or `/* */` lines."""
    sloc = comment = doc = blank = 0
    in_block = False
    for line in raw_lines:
        s = line.strip()
        if in_block:
            comment += 1
            if "*/" in s:
                in_block = False
            continue
        if not s:
            blank += 1
        elif s.startswith("///") or s.startswith("//!"):
            doc += 1
        elif s.startswith("//"):
            comment += 1
        elif s.startswith("/*"):
            comment += 1
            if "*/" not in s[2:]:
                in_block = True
        else:
            sloc += 1
    return sloc, comment, doc, blank


def workspace_members(root: pathlib.Path) -> list[dict]:
    proc = _run(["cargo", "metadata", "--no-deps", "--format-version", "1"], root, timeout=120)
    if proc.returncode != 0:
        raise SystemExit(f"cargo metadata failed: {proc.stderr[-2000:]}")
    meta = json.loads(proc.stdout)
    members: list[dict] = []
    for pkg in meta["packages"]:
        manifest = pathlib.Path(pkg["manifest_path"])
        try:
            rel_dir = manifest.parent.relative_to(root)
        except ValueError:
            continue
        members.append(
            {
                "name": pkg["name"],
                "dir": rel_dir.as_posix(),
                "lib": any("lib" in t["kind"] or "rlib" in t["kind"] for t in pkg["targets"]),
                "bins": sorted(t["name"] for t in pkg["targets"] if "bin" in t["kind"]),
                "deps": sorted((d["name"], d.get("kind") or "normal") for d in pkg["dependencies"]),
            }
        )
    members.sort(key=lambda m: m["dir"])
    return members


def _scope(rel_in_pkg: str, line: int, test_ranges: list[tuple[int, int]]) -> str:
    """Path is relative to the package dir (a package under `examples/` is not an example)."""
    parts = rel_in_pkg.split("/")
    if "tests" in parts:
        return "tests"
    if "examples" in parts:
        return "examples"
    if "benches" in parts:
        return "benches"
    if "bin" in parts or parts[-1] == "main.rs":
        return "bin"
    if any(a <= line <= b for a, b in test_ranges):
        return "src-test"
    return "src"


def shape_inventory(root: pathlib.Path, members: list[dict]) -> dict[str, object]:
    """LOC, fn sizes, pub surface, allow sites, tests, process-history comments per package."""
    loc_files: list[str] = []
    fn_rows: list[str] = []
    allow_sites: list[str] = []
    history: list[str] = []
    pkg_rows: list[str] = []
    pub_rows: list[str] = []
    tot = collections.Counter()
    max_file = ("", 0)
    max_fn = ("", 0)
    fns_over_120_src = 0
    undoc_over_40_src = 0
    files_over_1500_src = 0
    for m in members:
        pdir = root / m["dir"]
        p = collections.Counter()
        for path in sorted(pdir.rglob("*.rs")):
            rel = path.relative_to(root).as_posix()
            in_pkg = path.relative_to(pdir).as_posix()
            if "/target/" in f"/{rel}/":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = text.split("\n")
            if raw_lines and raw_lines[-1] == "":
                raw_lines.pop()
            loc = len(raw_lines)
            sloc, comment, doc, blank = classify_lines(raw_lines)
            loc_files.append(f"{rel}\t{loc}\t{sloc}\t{comment}\t{doc}\t{blank}")
            fns, test_ranges = scan_items(strip_noncode(text))
            file_scope = _scope(in_pkg, 0, [])
            is_product = file_scope in ("src", "bin")
            p["files"] += 1
            p["loc"] += loc
            p["sloc"] += sloc
            p["comment"] += comment
            p["doc"] += doc
            p["blank"] += blank
            if is_product:
                p["src_loc"] += loc
                p["src_test_loc"] += sum(b - a + 1 for a, b in test_ranges)
                if file_scope == "src":
                    if loc > 1500:
                        files_over_1500_src += 1
                    if loc > max_file[1]:
                        max_file = (rel, loc)
            elif file_scope == "tests":
                p["tests_loc"] += loc
            for i, line in enumerate(raw_lines, 1):
                s = line.strip()
                if s.startswith("#[test]"):
                    if is_product:
                        p["tests_in_src"] += 1
                    else:
                        p["tests_in_tests"] += 1
                for am in ALLOW_SITE_RE.finditer(line):
                    allow_sites.append(f"{rel}:{i}\t{am.group(1).strip()}")
                if s.startswith("//") and PROCESS_HISTORY_RE.search(s):
                    history.append(f"{rel}:{i}\t{s}")
                if file_scope == "src" and not any(a <= i <= b for a, b in test_ranges):
                    pm = PUB_ITEM_RE.match(line)
                    if pm:
                        p["pub_restricted" if pm.group("restrict") else "pub_items"] += 1
            for start, end, name, vis in fns:
                n_lines = end - start + 1
                scope = _scope(in_pkg, start, test_ranges)
                documented = "y" if has_doc_header(raw_lines, start) else "n"
                if scope == "src":
                    if n_lines > 120:
                        fns_over_120_src += 1
                    if n_lines > 40 and documented == "n":
                        undoc_over_40_src += 1
                    if n_lines > max_fn[1]:
                        max_fn = (f"{rel}:{start} {name}", n_lines)
                if n_lines > 40:
                    fn_rows.append(f"{rel}\t{start}\t{name}\t{n_lines}\t{scope}\t{vis}\t{documented}")
        pkg_rows.append(
            "\t".join(
                str(x)
                for x in (
                    m["name"],
                    p["files"],
                    p["loc"],
                    p["sloc"],
                    p["comment"],
                    p["doc"],
                    p["blank"],
                    p["src_loc"],
                    p["src_test_loc"],
                    p["tests_loc"],
                    p["tests_in_src"],
                    p["tests_in_tests"],
                )
            )
        )
        pub_rows.append(f"{m['name']}\t{p['pub_items']}\t{p['pub_restricted']}")
        tot.update(p)
    fn_rows.sort(key=lambda r: (-int(r.split("\t")[3]), r))
    return {
        "loc_files": loc_files,
        "loc_pkgs": pkg_rows,
        "pub_pkgs": pub_rows,
        "fn_rows": fn_rows,
        "allow_sites": allow_sites,
        "history": history,
        "keys": [
            f"loc={tot['loc']}",
            f"sloc={tot['sloc']}",
            f"comment_lines={tot['comment']}",
            f"doc_lines={tot['doc']}",
            f"src_test_loc={tot['src_test_loc']}",
            f"tests_in_src={tot['tests_in_src']}",
            f"tests_in_tests={tot['tests_in_tests']}",
            f"pub_items={tot['pub_items']}",
            f"pub_restricted={tot['pub_restricted']}",
            f"allow_sites={len(allow_sites)}",
            f"process_history_comments={len(history)}",
            f"max_file_lines_src={max_file[1]}",
            f"max_file_src={max_file[0]}",
            f"files_over_1500_src={files_over_1500_src}",
            f"max_fn_lines_src={max_fn[1]}",
            f"max_fn_src={max_fn[0]}",
            f"fns_over_120_src={fns_over_120_src}",
            f"undoc_fns_over_40_src={undoc_over_40_src}",
        ],
    }


def gate_asserts(root: pathlib.Path) -> list[str]:
    rows: list[str] = []
    for path in sorted((root / "scripts").glob("*-gate.sh")):
        code = "\n".join(ln.split("#", 1)[0] for ln in path.read_text(encoding="utf-8", errors="replace").splitlines())
        rows.append(
            f"{path.name}\t{len(DIE_RE.findall(code))}\t{len(EXIT_1_RE.findall(code))}"
            f"\t{len(GREP_Q_RE.findall(code))}\t{len(DIFF_SUB_RE.findall(code))}"
        )
    return rows


def dependency_tree(root: pathlib.Path) -> tuple[int, list[str]]:
    """`cargo tree --offline -e normal --prefix none | sort -u`, path suffixes and `(*)` stripped."""
    proc = _run(["cargo", "tree", "--offline", "-e", "normal", "--prefix", "none"], root, timeout=120)
    if proc.returncode != 0:
        return proc.returncode, [f"# cargo tree failed: {proc.stderr.strip()[-500:]}"]
    rows: set[str] = set()
    for line in proc.stdout.splitlines():
        line = re.sub(r"\s+\(\*\)$", "", line.strip())
        line = re.sub(r"\s+\((?:/|proc-macro)[^)]*\)$", "", line)
        if line:
            rows.add(line)
    return 0, sorted(rows)


def shell_files(root: pathlib.Path) -> list[str]:
    files: list[str] = []
    for pattern in SHELL_GLOBS:
        files.extend(p.relative_to(root).as_posix() for p in sorted(root.glob(pattern)))
    return files


def shellcheck_disables(root: pathlib.Path) -> int:
    n = 0
    for rel in shell_files(root):
        n += len(re.findall(r"#\s*shellcheck\s+disable=", (root / rel).read_text(encoding="utf-8", errors="replace")))
    return n


def run_shellcheck(root: pathlib.Path, files: list[str]) -> tuple[str, int | None, list[str]]:
    """(runner, rc, gcc-format lines). Binary on PATH, else the local shellcheck image, else na."""
    args = ["-S", "style", "-f", "gcc", *files]
    if shutil.which("shellcheck"):
        proc = _run(["shellcheck", *args], root, timeout=300)
        return "shellcheck", proc.returncode, proc.stdout.splitlines()
    if shutil.which("docker"):
        have = _run(["docker", "image", "inspect", SHELLCHECK_IMAGE], root, timeout=60)
        if have.returncode == 0:
            proc = _run(
                ["docker", "run", "--rm", "-v", f"{root}:/mnt:ro", SHELLCHECK_IMAGE, *args],
                root,
                timeout=600,
            )
            return f"docker {SHELLCHECK_IMAGE}", proc.returncode, proc.stdout.splitlines()
    return "na", None, []


def count_diagnostics(stderr: str) -> int:
    return sum(1 for ln in stderr.splitlines() if WARN_LINE_RE.match(ln) and not WARN_SUMMARY_RE.match(ln))


def _package_of(package_id: str) -> str:
    if " " in package_id:
        return package_id.split(" ", 1)[0]
    frag = package_id.rsplit("#", 1)[-1] if "#" in package_id else ""
    if "@" in frag:
        return frag.split("@", 1)[0]
    return package_id.split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]


def missing_docs(root: pathlib.Path, members: list[dict]) -> tuple[int, dict[str, int], list[str]]:
    """`missing_docs` warnings per package over the library targets (the public API)."""
    proc = _run(
        [
            "cargo",
            "clippy",
            "--workspace",
            "--lib",
            "--message-format=json",
            "--",
            "--force-warn",
            "missing_docs",
        ],
        root,
        timeout=900,
    )
    per_pkg: dict[str, int] = {m["name"]: 0 for m in members if m["lib"]}
    items: set[str] = set()
    for line in proc.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("reason") != "compiler-message":
            continue
        msg = obj.get("message") or {}
        if ((msg.get("code") or {}).get("code")) != "missing_docs":
            continue
        pkg = _package_of(obj.get("package_id", ""))
        per_pkg[pkg] = per_pkg.get(pkg, 0) + 1
        where = ""
        for span in msg.get("spans") or []:
            if span.get("is_primary"):
                where = f"{span.get('file_name')}:{span.get('line_start')}"
                break
        items.add(f"{where}\t{msg.get('message', '')}")
    return proc.returncode, per_pkg, sorted(items)


def quality_compiler(root: pathlib.Path, out: pathlib.Path, members: list[dict]) -> list[str]:
    """fmt, clippy, rustdoc -D warnings, doctests, missing_docs, shellcheck: rc + counts."""
    q: list[str] = []
    env = os.environ.copy()
    conf = root / "harness" / "nextest-krb5.conf"
    if conf.is_file():
        env["KRB5_CONFIG"] = str(conf)

    fmt = _run(["cargo", "fmt", "--all", "--", "--check"], root, timeout=120)
    q.append(f"fmt_rc={fmt.returncode}")
    q.append(f"fmt_files={sum(1 for ln in fmt.stdout.splitlines() if ln.startswith('Diff in '))}")

    clippy = _run(
        ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
        root,
        timeout=900,
    )
    q.append(f"clippy_rc={clippy.returncode}")
    q.append(f"clippy_warnings={count_diagnostics(clippy.stderr)}")
    (out / "clippy.log").write_text(clippy.stderr[-20000:], encoding="utf-8")

    # Two rustdoc runs: the plain one counts every warning in every crate (under
    # `-D warnings` the first failing crate hides its dependents); the strict one
    # is the rc CI will enforce.
    doc = subprocess.run(
        ["cargo", "doc", "--workspace", "--no-deps"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    q.append(f"doc_warnings={count_diagnostics(doc.stderr)}")
    (out / "doc.log").write_text(doc.stderr[-40000:], encoding="utf-8")
    doc_strict = subprocess.run(
        ["cargo", "doc", "--workspace", "--no-deps"],
        cwd=root,
        env=dict(env, RUSTDOCFLAGS="-D warnings"),
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    q.append(f"doc_rc={doc_strict.returncode}")
    (out / "doc-strict.log").write_text(doc_strict.stderr[-20000:], encoding="utf-8")

    doctest = subprocess.run(
        ["cargo", "test", "--workspace", "--doc"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    ran = sum(int(m.group(1)) for m in re.finditer(r"^running (\d+) tests?", doctest.stdout, re.M))
    q.append(f"doctest_rc={doctest.returncode}")
    q.append(f"doctests={ran}")
    (out / "doctest.log").write_text((doctest.stdout + doctest.stderr)[-20000:], encoding="utf-8")

    md_rc, per_pkg, items = missing_docs(root, members)
    q.append(f"missing_docs_rc={md_rc}")
    q.append(f"undocumented_pub={sum(per_pkg.values())}")
    write_lines(out / "undocumented-pub.txt", "# package<TAB>missing_docs", [f"{k}\t{v}" for k, v in sorted(per_pkg.items())])
    write_lines(out / "undocumented-pub-items.txt", "# file:line<TAB>message", items)

    files = shell_files(root)
    runner, rc, lines = run_shellcheck(root, files)
    q.append(f"shellcheck_runner={runner}")
    q.append(f"shellcheck_rc={'na' if rc is None else rc}")
    q.append(f"shellcheck_findings={'na' if rc is None else len(lines)}")
    write_lines(
        out / "shellcheck.txt",
        f"# {runner}: shellcheck -S style -f gcc {' '.join(SHELL_GLOBS)} ({len(files)} files)",
        lines,
    )
    return q


def claim_audits(root: pathlib.Path) -> list[str]:
    """claim-audit.py rc per open/frozen top-level working summary (absent on a bare tree)."""
    tool = root / "scripts" / "claim-audit.py"
    rows: list[str] = []
    if not tool.is_file():
        return rows
    for path in sorted((root / "working").glob("summary-*.md")):
        proc = _run([sys.executable, str(tool), str(path)], root, timeout=300)
        rows.append(f"{path.relative_to(root).as_posix()}\t{proc.returncode}")
    return rows


# The two `checkpoint*` shapes a later `scripts/checkpoint.sh --out <snapshot>/checkpoint`
# run leaves beside the snapshot: the directory (it writes its own INDEX.md) and
# a runner's captured stdout/stderr. Named here so index-check needs no hand rows.
def checkpoint_rows(out: pathlib.Path) -> list[str]:
    rows = []
    for entry in sorted(out.glob("checkpoint*")):
        if entry.is_dir():
            rows.append(
                f"| `{entry.name}/` | `scripts/checkpoint.sh --out` taken into this directory "
                "after the snapshot; own `INDEX.md` written by checkpoint.sh |"
            )
        else:
            rows.append(f"| `{entry.name}` | stdout/stderr of the checkpoint run beside the snapshot |")
    return rows


def write_index(out: pathlib.Path, quality: bool, counts: dict[str, object], q: list[str]) -> None:
    """INDEX.md: one row per file (index-check.py names files, it does not expand globs)."""
    index = [
        "# hygiene snapshot",
        "",
        "| File | What |",
        "|---|---|",
        "| `tests.txt` | nextest binary + test name |",
        "| `tests.count` | number of tests |",
        "| `gates.txt` | cell tags (section/echo/flow/workflow) |",
        "| `gate-asserts.txt` | `die` / `grep -q` / `diff <(` counts per gate |",
        "| `sleeps.txt` | gate sleep sites |",
        "| `cargo-build-gates.txt` | gates that run cargo build |",
        "| `boots.txt` | static docker-run / rust-kdc sites |",
        "| `diffsend.txt` | diffsend case names |",
        "| `client-differential-flows.txt` | client-differential flow names |",
        "| `ledger-rows.txt` | MIT cite + verdict |",
        "| `ledger-recount.txt` | ci-policy recount |",
        "| `ci-policy.txt` | `ci-policy.py` rc + tail |",
        "| `claim-audit.txt` | `claim-audit.py` rc per `working/summary-*.md` |",
        "| `unit-sleeps.txt` | thread::sleep in crates/*/tests |",
        "| `crates.txt` / `binaries.txt` | workspace packages and their bin targets |",
        "| `deps-declared.txt` / `deps.txt` | per-package declarations / resolved `cargo tree` |",
        "| `loc-crates.txt` / `loc-files.txt` | LOC, SLOC, comment, doc, blank per package / file |",
        "| `pub-items.txt` | `pub` vs restricted items per package |",
        "| `fn-sizes.txt` | functions > 40 lines with scope, visibility, doc header |",
        "| `allow-sites.txt` / `process-history.txt` | `#[allow]` sites / process-tag comments |",
        "| `quality.txt` | grep counts; with `--quality` fmt/clippy/doc/doctest/missing_docs/shellcheck |",
    ]
    if quality:
        index += [
            "| `clippy.log` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |",
            "| `doc.log` / `doc-strict.log` | `cargo doc --workspace --no-deps` plain (the warning count) / under `RUSTDOCFLAGS=-D warnings` (the rc) |",
            "| `doctest.log` | `cargo test --workspace --doc` |",
            "| `undocumented-pub.txt` / `undocumented-pub-items.txt` | `missing_docs` per package / per site |",
            "| `shellcheck.txt` | `shellcheck -S style -f gcc` findings |",
        ]
    index += [
        "| `provenance.txt` | stamp from snapshot.sh (+ host realm and lab_realm_override) |",
        "| `scratch/` | `KERBER_SCRATCH` of the snapshot run (skipped by index-check) |",
    ]
    index += checkpoint_rows(out)
    index += [""] + [f"{k}={v}" for k, v in counts.items()]
    index.extend(q)
    (out / "INDEX.md").write_text("\n".join(index) + "\n", encoding="utf-8")


def data_lines(path: pathlib.Path) -> int:
    """Rows in a write_lines() file: every line after the `#` header."""
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith("#"))


def reindex(out: pathlib.Path) -> None:
    """Rewrite INDEX.md from what is on disk (same rows as the snapshot wrote, plus
    any `checkpoint*` entry taken into the directory since). Counts come from the
    inventory files themselves, so nothing is recomputed from the tree."""
    q = [ln for ln in (out / "quality.txt").read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    quality = "quality=1" in q
    counts = {
        "tests": (out / "tests.count").read_text(encoding="utf-8").strip(),
        "gate_tags": data_lines(out / "gates.txt"),
        "diffsend": data_lines(out / "diffsend.txt"),
        "flows": data_lines(out / "client-differential-flows.txt"),
        "ledger_rows": data_lines(out / "ledger-rows.txt"),
        "cargo_build_gates": data_lines(out / "cargo-build-gates.txt"),
    }
    write_index(out, quality, counts, q)


def snapshot(root: pathlib.Path, out: pathlib.Path, skip_nextest: bool, quality: bool) -> None:
    out.mkdir(parents=True, exist_ok=True)
    if skip_nextest:
        write_lines(out / "tests.txt", "# skipped", [])
        (out / "tests.count").write_text("skipped\n", encoding="utf-8")
    else:
        tests = list_tests(root)
        write_lines(out / "tests.txt", "# binary<TAB>name", tests)
        (out / "tests.count").write_text(f"{len(tests)}\n", encoding="utf-8")

    cells, sleeps, builds, boots = inventory_gates(root)
    write_lines(out / "gates.txt", "# gate<TAB>kind<TAB>tag", cells)
    write_lines(out / "sleeps.txt", "# file<TAB>line<TAB>seconds<TAB>kind", sleeps)
    write_lines(out / "cargo-build-gates.txt", "# gate", builds)
    write_lines(out / "boots.txt", "# gate<TAB>mit<TAB>rust", boots)

    cases = diffsend_cases(root)
    write_lines(out / "diffsend.txt", "# case", cases)
    flows = client_diff_flows(root)
    write_lines(out / "client-differential-flows.txt", "# flow", flows)
    rows, recount = ledger_rows(root)
    write_lines(out / "ledger-rows.txt", "# mit_cite<TAB>verdict", rows)
    write_lines(
        out / "ledger-recount.txt",
        "# key=value",
        [f"{k}={v}" for k, v in sorted(recount.items())] + [f"rows={len(rows)}"],
    )

    policy = _run([sys.executable, str(root / "scripts" / "ci-policy.py")], root, timeout=180)
    (out / "ci-policy.txt").write_text(
        f"rc={policy.returncode}\n{(policy.stdout + policy.stderr)[-4000:]}\n",
        encoding="utf-8",
    )

    write_lines(out / "unit-sleeps.txt", "# file:line", rust_sleeps(root))
    write_lines(out / "gate-asserts.txt", "# gate<TAB>die<TAB>exit_1<TAB>grep_q<TAB>diff_sub", gate_asserts(root))
    write_lines(out / "claim-audit.txt", "# summary<TAB>rc", claim_audits(root))

    members = workspace_members(root)
    write_lines(
        out / "crates.txt",
        "# package<TAB>dir<TAB>lib",
        [f"{m['name']}\t{m['dir']}\t{'y' if m['lib'] else 'n'}" for m in members],
    )
    write_lines(
        out / "binaries.txt",
        "# package<TAB>bin",
        [f"{m['name']}\t{b}" for m in members for b in m["bins"]],
    )
    write_lines(
        out / "deps-declared.txt",
        "# package<TAB>dependency<TAB>kind",
        [f"{m['name']}\t{d}\t{k}" for m in members for d, k in m["deps"]],
    )
    tree_rc, tree_rows = dependency_tree(root)
    write_lines(out / "deps.txt", "# cargo tree --offline -e normal --prefix none | sort -u", tree_rows)

    shape = shape_inventory(root, members)
    write_lines(
        out / "loc-crates.txt",
        "# package<TAB>files<TAB>loc<TAB>sloc<TAB>comment<TAB>doc<TAB>blank<TAB>src_loc<TAB>src_test_loc<TAB>tests_loc<TAB>tests_in_src<TAB>tests_in_tests",
        shape["loc_pkgs"],
    )
    write_lines(out / "loc-files.txt", "# file<TAB>loc<TAB>sloc<TAB>comment<TAB>doc<TAB>blank", shape["loc_files"])
    write_lines(out / "pub-items.txt", "# package<TAB>pub<TAB>pub_restricted (src/, outside cfg(test))", shape["pub_pkgs"])
    write_lines(
        out / "fn-sizes.txt",
        "# file<TAB>line<TAB>fn<TAB>lines<TAB>scope<TAB>vis<TAB>doc (fns > 40 lines; scope src|src-test|bin|tests|examples)",
        shape["fn_rows"],
    )
    write_lines(out / "allow-sites.txt", "# file:line<TAB>lints", shape["allow_sites"])
    write_lines(out / "process-history.txt", "# file:line<TAB>comment (S4 acceptance grep)", shape["history"])

    q = quality_grep(root)
    q.extend(shape["keys"])
    q.append(f"binaries={sum(len(m['bins']) for m in members)}")
    q.append(f"deps_declared={sum(len(m['deps']) for m in members)}")
    q.append(f"deps_tree={len(tree_rows) if tree_rc == 0 else 'na'}")
    q.append(f"shellcheck_disables={shellcheck_disables(root)}")
    q.append(f"quality={1 if quality else 0}")
    if quality:
        q.extend(quality_compiler(root, out, members))
    write_lines(out / "quality.txt", "# key=value", q)

    write_index(
        out,
        quality,
        {
            "tests": (out / "tests.count").read_text(encoding="utf-8").strip(),
            "gate_tags": len(cells),
            "diffsend": len(cases),
            "flows": len(flows),
            "ledger_rows": len(rows),
            "cargo_build_gates": len(builds),
        },
        q,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path)
    ap.add_argument("--skip-nextest", action="store_true")
    ap.add_argument("--quality", action="store_true")
    ap.add_argument(
        "--reindex",
        type=pathlib.Path,
        metavar="SNAPSHOT",
        help="rewrite SNAPSHOT/INDEX.md from the files on disk (names a checkpoint taken since)",
    )
    args = ap.parse_args()
    if args.reindex is not None:
        if args.root or args.out or args.skip_nextest or args.quality:
            ap.error("--reindex takes no other option")
        reindex(args.reindex.resolve())
        return 0
    if args.root is None or args.out is None:
        ap.error("--root and --out are required")
    snapshot(args.root.resolve(), args.out.resolve(), args.skip_nextest, args.quality)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
