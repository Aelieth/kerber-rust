#!/usr/bin/env python3
"""Write a W2/W3 hygiene snapshot into an output directory.

Invoked by scripts/hygiene-snapshot.sh. Inventories are line-oriented so
hygiene-diff.py can set-compare them.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
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
    text = (root / "scripts" / "client-differential-gate.sh").read_text(encoding="utf-8")
    return sorted({m.group(1) for m in FLOW_SECTION_RE.finditer(text)})


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
    q = quality_grep(root)
    if quality:
        fmt = _run(["cargo", "fmt", "--all", "--", "--check"], root, timeout=120)
        q.append(f"fmt_rc={fmt.returncode}")
        clippy = _run(
            [
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            root,
            timeout=600,
        )
        q.append(f"clippy_rc={clippy.returncode}")
    write_lines(out / "quality.txt", "# key=value", q)

    index = [
        "# hygiene snapshot",
        "",
        "| File | What |",
        "|---|---|",
        "| `tests.txt` | nextest binary + test name |",
        "| `tests.count` | number of tests |",
        "| `gates.txt` | cell tags (section/echo/flow/workflow) |",
        "| `sleeps.txt` | gate sleep sites |",
        "| `cargo-build-gates.txt` | gates that run cargo build |",
        "| `boots.txt` | static docker-run / rust-kdc sites |",
        "| `diffsend.txt` | diffsend case names |",
        "| `client-differential-flows.txt` | client-differential flow names |",
        "| `ledger-rows.txt` | MIT cite + verdict |",
        "| `ledger-recount.txt` | ci-policy recount |",
        "| `ci-policy.txt` | `ci-policy.py` rc + tail |",
        "| `unit-sleeps.txt` | thread::sleep in crates/*/tests |",
        "| `quality.txt` | grep (and optional compiler) counts |",
        "| `provenance.txt` | stamp from snapshot.sh |",
        "",
        f"tests={(out / 'tests.count').read_text(encoding='utf-8').strip()}",
        f"gate_tags={len(cells)}",
        f"diffsend={len(cases)}",
        f"flows={len(flows)}",
        f"ledger_rows={len(rows)}",
        f"cargo_build_gates={len(builds)}",
    ]
    (out / "INDEX.md").write_text("\n".join(index) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--skip-nextest", action="store_true")
    ap.add_argument("--quality", action="store_true")
    args = ap.parse_args()
    snapshot(args.root.resolve(), args.out.resolve(), args.skip_nextest, args.quality)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
