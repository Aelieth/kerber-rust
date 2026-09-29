"""Checks on the record tooling: evidence and settle helpers, ci-status, claim-audit, red-at-sha."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import tempfile

from .common import ROOT, SCRIPTS, _die, _scratch_root


def check_red_at_sha_target_trap(text: str | None = None) -> None:
    """W1-Z Z3.4: the cargo tree goes in the EXIT trap (kept only by
    KERBER_KEEP_RED_TARGET=1) and every run stamps `red-at-parent=1`."""
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text()
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    m = re.search(r"cleanup\(\)\s*\{(.*?)\n\}", code, re.S)
    if not m:
        _die("red-at-sha.sh has no cleanup() trap body")
    body = m.group(1)
    if 'rm -rf "$TARGET"' not in body:
        _die("red-at-sha.sh cleanup() must remove the red-target cargo tree (Z3.4)")
    if "KERBER_KEEP_RED_TARGET" not in body:
        _die("red-at-sha.sh cleanup() must keep the tree only under KERBER_KEEP_RED_TARGET=1")
    if "trap cleanup EXIT" not in code:
        _die("red-at-sha.sh must arm cleanup on EXIT")
    if 'echo "red-at-parent=1"' not in code:
        _die("red-at-sha.sh must stamp red-at-parent=1 in its provenance block")


_RED_TARGET_DIR = re.compile(r"^red-target-[0-9a-f]{6,}$")


def find_red_target_trees(root: pathlib.Path) -> list[pathlib.Path]:
    """`red-target-*` dirs and any cargo build tree (CACHEDIR.TAG + debug/) under root."""
    found: list[pathlib.Path] = []
    if not root.is_dir():
        return found
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        names = {e.name for e in entries}
        if _RED_TARGET_DIR.match(d.name) or ("CACHEDIR.TAG" in names and "debug" in names):
            found.append(d)
            continue  # do not descend into a build tree
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                stack.append(pathlib.Path(e.path))
    return sorted(found)


def check_no_red_target_trees(root: pathlib.Path | None = None) -> None:
    """W1-Z Z3.4 (checkpoint runner only — `working/` is gitignored, so CI never
    sees it): no rebuildable cargo tree may sit inside the evidence dirs."""
    root = ROOT / "working" / "logs" if root is None else root
    trees = find_red_target_trees(root)
    if trees:
        listing = "\n  ".join(str(t.relative_to(ROOT)) if t.is_relative_to(ROOT) else str(t) for t in trees)
        total = subprocess.run(
            ["du", "-sch", *map(str, trees)], capture_output=True, text=True, check=False
        ).stdout.strip().splitlines()
        size = total[-1].split("\t")[0] if total else "?"
        _die(
            f"{len(trees)} cargo build tree(s) under {root} ({size}); they are rebuildable "
            "scratch, the stamped unit-red-*.log keeps the rc and FAILED list — "
            "working/w1-sweep/plan-w1z-0913-1915.md Z5: find working/logs/w1-sweep -type d -name 'red-target-*' "
            f"-prune -exec rm -rf {{}} +\n  {listing}"
        )


def check_red_at_sha_overlay_order(text: str | None = None) -> None:
    """`scripts/*.sh` must be copied before `write-tree` so tree_sha includes the gate."""
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text()
    write = -1
    cp = -1
    offset = 0
    for line in text.splitlines(True):
        code = line.split("#", 1)[0]
        if write < 0 and "write-tree" in code:
            write = offset
        if cp < 0 and re.search(r'cp\s+"\$ROOT/scripts/"\*\.sh', code):
            cp = offset
        offset += len(line)
    if write < 0:
        _die("red-at-sha.sh has no write-tree")
    if cp < 0 or cp > write:
        _die("red-at-sha.sh must overlay scripts/*.sh before write-tree")


def check_unit_evidence_helper() -> None:
    """R8: unit_green / unit_red_at exist; red refuses missing files; green refuses dirty."""
    path = SCRIPTS / "lib" / "unit-evidence.sh"
    if not path.is_file():
        _die("missing scripts/lib/unit-evidence.sh")
    text = path.read_text()
    if "unit_green" not in text or "unit_red_at" not in text:
        _die("unit-evidence.sh missing unit_green/unit_red_at")
    if "inject files required" not in text:
        _die("unit_red_at must refuse a command without inject files")
    if "--inject" not in text:
        _die("unit_red_at must pass --inject to red-at-sha.sh")
    if "KERBER_UNIT_ALLOW_DIRTY" not in text:
        _die("unit_green must honour KERBER_UNIT_ALLOW_DIRTY")
    if "red-at-parent=1" not in text:
        _die("unit_red_at must stamp red-at-parent=1")
    if "_unit_test_names" not in text:
        _die("unit_red_at must derive #[test] names from inject files")
    if '--test "$stem"' not in text and "--test \"$stem\"" not in text:
        # Accept either quoting style from the shell helper.
        if "--test" not in text or "stem=" not in text:
            _die("unit_red_at --all must run cargo test --test <stem> per inject file")
    if "IFS='|'" in text or 'IFS="|"' in text:
        _die("unit_red_at must not join test names with | for cargo test")
    if "refusing dirty tree" not in text:
        _die("unit_green must refuse a dirty tree without KERBER_UNIT_ALLOW_DIRTY")
    if "unit_green: missing Summary" not in text:
        _die("unit_green must fail unless a Summary … passed line is present")
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    env["ROOT"] = str(ROOT)
    r = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; unit_red_at',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("unit_red_at accepted missing args")
    r = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; unit_red_at HEAD k12 --all',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("unit_red_at accepted missing inject files")
    err = (r.stderr or b"") + (r.stdout or b"")
    if b"inject files required" not in err:
        _die("unit_red_at missing-files refusal did not mention inject files")
    r = subprocess.run(
        [
            "bash",
            str(SCRIPTS / "red-at-sha.sh"),
            "--inject",
            "--",
            "HEAD",
            "true",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("red-at-sha.sh --inject with no files was accepted")


def check_settle_helper() -> None:
    """K12/U7/R8: settle.sh tees, refuses readers, stamps override= when dirty bypassed."""
    path = SCRIPTS / "lib" / "settle.sh"
    if not path.is_file():
        _die("missing scripts/lib/settle.sh")
    text = path.read_text()
    if "tee" not in text:
        _die("settle.sh must tee command output")
    if "pipefail" not in text:
        _die("settle.sh must set pipefail around tee")
    if "of a file is not a live settle" not in text:
        _die("settle.sh must refuse readers of a file")
    if "override=KERBER_SETTLE_ALLOW_DIRTY" not in text:
        _die("settle.sh must stamp override=KERBER_SETTLE_ALLOW_DIRTY when dirty is bypassed")
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    # The dev tree is dirty while iterating; the self-test exercises settle.sh's
    # tee/refusal logic, not the R2-T8 dirty guard (checked before it in CI).
    env["KERBER_SETTLE_ALLOW_DIRTY"] = "1"
    # settle.sh tees each run into $KERBER_SCRATCH/settle-<name>.log: give the probes a scratch of their own.
    probe = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    env["KERBER_SCRATCH"] = str(probe)
    try:
        _settle_probes(path, env)
    finally:
        subprocess.run(["rm", "-rf", str(probe)], check=False)


def _settle_probes(path: pathlib.Path, env: dict[str, str]) -> None:
    """The refusals and the one live run check_settle_helper drives through settle.sh."""
    existing = ROOT / "scripts" / "ci-policy.py"
    r = subprocess.run(
        [
            "bash",
            str(path),
            "k12-grep",
            "--",
            "grep",
            "-F",
            "ci-policy: ok",
            str(existing),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        _die("settle.sh accepted grep of an existing file")
    err = (r.stderr or b"").decode("utf-8", "replace")
    if "grep of a file is not a live settle" not in err:
        _die("settle.sh grep refusal text missing")
    refusals = [
        (["bash", "-c", f"grep -F ok {existing}"], "bash -c grep"),
        (["rg", "ok", str(existing)], "rg of a file"),
        (["sed", "-n", "1p", str(existing)], "sed -n of a file"),
        (["grep", "-F", "ok", "/tmp/kerber-vanished-settle/gate.log"], "grep of a vanished path"),
    ]
    for cmd, what in refusals:
        r = subprocess.run(
            ["bash", str(path), "k12-reader", "--", *cmd],
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=False,
        )
        if r.returncode == 0:
            _die(f"settle.sh accepted {what}")
        if b"not a live settle" not in (r.stderr or b""):
            _die(f"settle.sh refusal text missing for {what}")
    r = subprocess.run(
        ["bash", str(path), "k12-live", "--", "bash", "-c", "printf live"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0 or b"live" not in (r.stdout or b""):
        _die("settle.sh refused a live bash -c command")
    out = (r.stdout or b"").decode("utf-8", "replace")
    if "dirty=yes" in out and "override=KERBER_SETTLE_ALLOW_DIRTY" not in out:
        _die("settle.sh dirty bypass must stamp override=KERBER_SETTLE_ALLOW_DIRTY")


def check_evidence_check_tool() -> None:
    """R8: evidence-check.py flags unstamped, wrong-SHA, and unlabeled dirty logs."""
    path = SCRIPTS / "evidence-check.py"
    if not path.is_file():
        _die("missing scripts/evidence-check.py")
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (root / "ok.log").write_text(
            "==== provenance ====\nhead_sha=abc1234deadbeef\ntree_sha=t1\ndirty=no\nok\n"
        )
        (root / "unstamped.log").write_text("no stamp\n")
        (root / "wrongsha.log").write_text(
            "head_sha=ffffffffffff\ntree_sha=t2\ndirty=no\n"
        )
        (root / "dirty.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t3\ndirty=yes\n"
        )
        (root / "dirty-red.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t4\ndirty=yes\nred-at-parent=1\n"
        )
        (root / "r13-unit-green.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t5\ndirty=no\n==== unit_green r13 ====\n"
        )
        (root / "r12-unit-green.log").write_text(
            "head_sha=abc1234deadbeef\ntree_sha=t6\ndirty=no\n"
            "     Summary [   0.100s] 11 tests run: 11 passed, 0 skipped\n"
        )
        (root / "ci-bad.txt").write_text("ci-status: HTTP Error 403: rate limit exceeded\n")
        # Z3.2/Z3.6: any scratch* directory is outside the contract (dev runs,
        # KERBER_SCRATCH output); a file merely named scratch* is not.
        for scratch in ("scratch", "scratch-dev", "scratch-pre2"):
            (root / scratch).mkdir()
            (root / scratch / "dirty-dev-run.log").write_text("head_sha=abc1234\ntree_sha=t\ndirty=yes\n")
        (root / "scratch-notes.log").write_text("no stamp\n")
        r = subprocess.run(
            [
                sys.executable,
                str(path),
                str(root),
                "--commits",
                "abc1234",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode == 0:
            _die("evidence-check.py passed a fixture tree with known bad artefacts")
        out = (r.stdout or "") + (r.stderr or "")
        for name in (
            "unstamped.log",
            "wrongsha.log",
            "dirty.log",
            "ci-bad.txt",
            "r13-unit-green.log",
        ):
            if name not in out:
                _die(f"evidence-check.py missed {name}: {out}")
        if "dirty.log: dirty=yes without" not in out:
            _die(f"evidence-check.py must name the dirty label rule: {out}")
        if "unit-green log missing Summary" not in out:
            _die(f"evidence-check.py must flag a header-only unit-green log: {out}")
        if any(ln.startswith("dirty-red.log:") for ln in out.splitlines()):
            _die("evidence-check.py flagged a dirty log that carries red-at-parent=")
        if any(ln.startswith("ok.log:") for ln in out.splitlines()):
            _die(f"evidence-check.py flagged a good log: {out}")
        if "dirty-dev-run.log" in out:
            _die(f"evidence-check.py must skip every scratch* directory: {out}")
        if "scratch-notes.log" not in out:
            _die("evidence-check.py must still check a file merely named scratch*")
        if any(ln.startswith("r12-unit-green.log:") for ln in out.splitlines()):
            _die(f"evidence-check.py flagged a unit-green log that has Summary: {out}")
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=False)


def check_ci_status_save() -> None:
    """R8: ci-status.py --save exists and filters fixture annotations.

    W2-S0: also durations, workflow-file fetch (not branch=main), budget-report.
    """
    path = SCRIPTS / "ci-status.py"
    if not path.is_file():
        _die("missing scripts/ci-status.py")
    text = path.read_text()
    if "--save" not in text:
        _die("ci-status.py must support --save")
    if "is_fixture_annotation" not in text:
        _die("ci-status.py must filter title=fixture annotations")
    if "probe-gate.sh" not in text:
        _die("ci-status.py must filter probe-gate.sh fixture annotations")
    if "403" not in text:
        _die("ci-status.py --save must handle HTTP 403 rate limits")
    if "--durations" not in text:
        _die("ci-status.py must support --durations")
    if "duration_s=" not in text:
        _die("ci-status.py must emit duration_s= records")
    if "run_wall_s=" not in text:
        _die("ci-status.py must emit run_wall_s=")
    if "--budget-report" not in text:
        _die("ci-status.py must support --budget-report")
    if "--check-budget" not in text:
        _die("ci-status.py must support --check-budget")
    if "budget_overruns" not in text:
        _die("ci-status.py must implement budget_overruns")
    if "budget_median_verdict" not in text:
        _die("ci-status.py must implement budget_median_verdict")
    if "over_runs_fail_at" not in text:
        _die("ci-status.py median verdict must take over_runs_fail_at")
    if ">= 3 of 5" not in text and ">=3-of-5" not in text:
        _die("ci-status.py --check-budget must document median / >=3-of-5")
    if "actions/workflows/" not in text:
        _die("ci-status.py must fetch /actions/workflows/<file>/runs")
    if "branch=main" in text:
        _die("ci-status.py must not pin fetch_runs to branch=main")
    if "keep_listing_run" not in text:
        _die("ci-status.py must filter listings to main pushes and the PR under test")
    if "dependabot[bot]" not in text:
        _die("ci-status.py must drop dependabot runs from listings and --check-budget")
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_status_r8", path)
    if spec is None or spec.loader is None:
        _die("ci-status.py load failed")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not mod.is_fixture_annotation({"title": "fixture", "path": "x.sh"}):
        _die("is_fixture_annotation must accept title=fixture")
    if not mod.is_fixture_annotation({"title": "", "path": "scripts/probe-gate.sh"}):
        _die("is_fixture_annotation must accept probe-gate.sh path")
    if not mod.is_fixture_annotation({"title": "", "path": "scripts/die-probe.sh"}):
        _die("is_fixture_annotation must accept *-probe.sh path")
    if mod.is_fixture_annotation({"title": "", "path": "scripts/kadmin-gate.sh"}):
        _die("is_fixture_annotation must not filter product gates")
    if mod.workflow_file("peers") != "peers.yml":
        _die("workflow_file must map peers -> peers.yml")
    if mod.job_duration_s(
        {"started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:01:05Z"}
    ) != 65:
        _die("job_duration_s must use started_at/completed_at")
    over = mod.budget_overruns(
        {"harness": 600, "test": 100},
        700,
        {"jobs": {"harness": 500, "test": 300}, "run_wall": 540},
    )
    if not any("harness" in ln for ln in over) or not any("run_wall" in ln for ln in over):
        _die(f"budget_overruns must flag harness and run_wall: {over}")
    if mod.budget_overruns(
        {"harness": 400, "test": 100},
        500,
        {"jobs": {"harness": 500, "test": 300}, "run_wall": 540},
    ):
        _die("budget_overruns must accept durations under budget")
    _y4_budget = {"jobs": {"mit-extra": 180, "test": 300}, "run_wall": 360}
    # 2 of 5 over, median under — info, not fail.
    _y4_green = [
        (625, {"mit-extra": 183, "test": 136}, 388),
        (624, {"mit-extra": 181, "test": 127}, 272),
        (623, {"mit-extra": 155, "test": 103}, 374),
        (622, {"mit-extra": 174, "test": 108}, 277),
        (613, {"mit-extra": 168, "test": 123}, 288),
    ]
    _fail, _info = mod.budget_median_verdict(_y4_green, _y4_budget)
    if _fail:
        _die(f"budget_median_verdict must pass 2-of-5 with median under cap: {_fail}")
    if not any("mit-extra" in ln for ln in _info):
        _die("budget_median_verdict must info single-run mit-extra breaches")
    # 3 of 5 over / median over — fail.
    _y4_red = [
        (621, {"mit-extra": 198, "test": 128}, 316),
        (619, {"mit-extra": 192, "test": 124}, 314),
        (616, {"mit-extra": 185, "test": 134}, 284),
        (615, {"mit-extra": 164, "test": 131}, 321),
        (613, {"mit-extra": 168, "test": 123}, 288),
    ]
    _fail, _info = mod.budget_median_verdict(_y4_red, _y4_budget)
    if not _fail:
        _die("budget_median_verdict must fail 3-of-5 / median over cap")
    if not any("mit-extra" in ln for ln in _fail):
        _die(f"budget_median_verdict 3-of-5 must name mit-extra: {_fail}")
    dep = {
        "event": "pull_request",
        "head_branch": "dependabot/cargo/foo",
        "actor": {"login": "dependabot[bot]"},
        "pull_requests": [{"number": 46}],
    }
    main_push = {
        "event": "push",
        "head_branch": "main",
        "actor": {"login": "Aelieth"},
        "pull_requests": [],
    }
    pr_run = {
        "event": "pull_request",
        "head_branch": "w3-hygiene-s3-0",
        "actor": {"login": "Aelieth"},
        "pull_requests": [{"number": 60}],
    }
    if mod.keep_listing_run(dep, pr=60):
        _die("keep_listing_run must drop a dependabot run")
    if not mod.keep_listing_run(main_push, pr=None):
        _die("keep_listing_run must keep a main push")
    if not mod.keep_listing_run(pr_run, pr=60):
        _die("keep_listing_run must keep the PR under test")
    if mod.keep_listing_run(pr_run, pr=54):
        _die("keep_listing_run must drop another PR")
    pr_empty = {
        "event": "pull_request",
        "head_branch": "w3-hygiene-s3-0",
        "actor": {"login": "Aelieth"},
        "pull_requests": [],
    }
    if not mod.keep_listing_run(pr_empty, pr=60, pr_head="w3-hygiene-s3-0"):
        _die("keep_listing_run must match head_branch when pull_requests is empty")
    if mod.keep_listing_run(pr_empty, pr=60, pr_head="other-branch"):
        _die("keep_listing_run must not match a different head_branch")
    if mod.keep_listing_run(pr_empty, pr=60):
        _die("keep_listing_run must not keep empty pull_requests without pr_head")
    pr_info = {"head": {"repo": {"full_name": "Aelieth/kerber-rust"}}, "created_at": "2026-09-28T10:00:00Z"}
    own = {**pr_empty, "head_repository": {"full_name": "Aelieth/kerber-rust"}, "created_at": "2026-09-28T11:00:00Z"}
    if not mod.keep_listing_run(own, pr=60, pr_head="w3-hygiene-s3-0", pr_info=pr_info):
        _die("keep_listing_run must keep the PR's own run when pull_requests is empty")
    fork = {**own, "head_repository": {"full_name": "someone/kerber-rust"}}
    if mod.keep_listing_run(fork, pr=60, pr_head="w3-hygiene-s3-0", pr_info=pr_info):
        _die("keep_listing_run must drop a fork's branch of the same name")
    stale = {**own, "created_at": "2026-09-01T00:00:00Z"}
    if mod.keep_listing_run(stale, pr=60, pr_head="w3-hygiene-s3-0", pr_info=pr_info):
        _die("keep_listing_run must drop a run from before the PR (a branch name reused from a closed PR)")


def check_red_at_sha_build(text: str | None = None) -> None:
    """A gate run builds the base SHA's bins: its own scripts/lib/build-bins.sh when the base has
    one, else the five older gate bins, each from the crate that holds it at the base. The old
    fixed list asked for krb5-forge-tgt under krb5-client and failed at every base."""
    live = text is None
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text(encoding="utf-8")
    if 'git cat-file -e "$BASE:scripts/lib/build-bins.sh"' not in text or "build-bins.at-base.sh" not in text:
        _die("red-at-sha.sh must build through the base's own scripts/lib/build-bins.sh when it has one")
    if "src/bin/$b" not in text:
        _die("red-at-sha.sh must look up each fallback bin's crate at the base")
    if re.search(r"--bin krb5-forge-tgt", text):
        _die("red-at-sha.sh must not name krb5-forge-tgt's crate: it moved (krb5-kdc, then krb5-tools)")
    if not live:
        return
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    old = subprocess.run(["git", "rev-parse", "--verify", "672e8e3b^^{commit}"], cwd=ROOT, capture_output=True,
                         text=True, check=False)
    scratch = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    env["KERBER_SCRATCH"] = str(scratch)
    try:
        def build_line(base: str) -> str:
            r = subprocess.run(["bash", str(SCRIPTS / "red-at-sha.sh"), "--print-build", base, "scripts/kdc-gate.sh"],
                               cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            if r.returncode != 0:
                _die(f"red-at-sha --print-build {base} failed: {(r.stdout + r.stderr)[-400:]}")
            return next((line for line in r.stdout.splitlines() if line.startswith("build=")), "")

        if head.returncode == 0:
            line = build_line(head.stdout.strip())
            if line != f"build=scripts/lib/build-bins.sh at {head.stdout.strip()[:12]}":
                _die(f"red-at-sha at HEAD must build through HEAD's build-bins.sh, got {line!r}")
        if old.returncode != 0:
            print("ci-policy: SKIP red-at-sha five-bin probe: base 672e8e3b^ not fetched (shallow clone?) "
                  "— set fetch-depth: 0", file=sys.stderr)
            return
        line = build_line(old.stdout.strip())
        if "no scripts/lib/build-bins.sh" not in line or "-p krb5-kdc --bin krb5-forge-tgt" not in line:
            _die(f"red-at-sha before build-bins.sh must build the five bins from their crates, got {line!r}")
    finally:
        subprocess.run(["rm", "-rf", str(scratch)], check=False)


def check_red_at_sha_inject(text: str | None = None) -> None:
    """K12: --inject copies named HEAD files before write-tree."""
    if text is None:
        path = SCRIPTS / "red-at-sha.sh"
        if not path.is_file():
            _die("missing scripts/red-at-sha.sh")
        text = path.read_text()
    if "--inject" not in text:
        _die("red-at-sha.sh must support --inject")
    if 'cp "$ROOT/$rel" "$WT/$rel"' not in text:
        _die("red-at-sha.sh --inject must copy HEAD files into the worktree")
    write = -1
    cp = -1
    offset = 0
    for line in text.splitlines(True):
        code = line.split("#", 1)[0]
        if write < 0 and "write-tree" in code:
            write = offset
        if cp < 0 and 'cp "$ROOT/$rel" "$WT/$rel"' in code:
            cp = offset
        offset += len(line)
    if write < 0 or cp < 0 or cp > write:
        _die("red-at-sha.sh must copy --inject files before write-tree")
    env = os.environ.copy()
    env["KERBER_NO_IMAGE"] = "1"
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "0d58023^{commit}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    inj = "crates/krb5-types/tests/parse_name_deltat.rs"
    if probe.returncode != 0 or not (ROOT / inj).is_file():
        # R2-T3: a shallow CI checkout (fetch-depth 1) cannot see the historical
        # base, so the probe cannot run. Say so loudly rather than pass silently.
        print(
            "ci-policy: SKIP red-at-sha overlay-probe: base 0d58023 not fetched "
            "(shallow clone?) or fixture missing — set fetch-depth: 0",
            file=sys.stderr,
        )
        return
    scratch = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    env["KERBER_SCRATCH"] = str(scratch)
    try:
        r = subprocess.run(
            [
                "bash",
                str(SCRIPTS / "red-at-sha.sh"),
                "--overlay-probe",
                "--inject",
                inj,
                "--",
                "0d58023",
                inj,
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=False,
            text=True,
        )
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0:
            _die(f"red-at-sha --inject overlay-probe failed: {out[-500:]}")
        if "--inject" not in out:
            _die("red-at-sha --inject overlay-probe log missing --inject")
        if "overlay_match=yes" not in out:
            _die("red-at-sha --inject did not land HEAD file in write-tree")
        if "tree_sha=" not in out:
            _die("red-at-sha --inject overlay-probe missing tree_sha=")
    finally:
        subprocess.run(["rm", "-rf", str(scratch)], check=False)


def _claim_audit_module():
    spec = importlib.util.spec_from_file_location("claim_audit", SCRIPTS / "claim-audit.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/claim-audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_index_check_scratch() -> None:
    """W1-Z Z3.2: index-check.py skips any `scratch*` component (`scratch/`,
    `scratch-pre/`, `scratch-diffsend2/`), flags an unnamed real file, and
    accepts a directory name as cover for the files under it."""
    spec = importlib.util.spec_from_file_location("index_check", SCRIPTS / "index-check.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/index-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (root / "INDEX.md").write_text("| `a.log` | named |\n| `sub/` | covered |\n")
        (root / "a.log").write_text("x")
        (root / "b.log").write_text("x")
        (root / "sub").mkdir()
        (root / "sub" / "c.log").write_text("x")
        for scratch in ("scratch", "scratch-pre", "scratch-diffsend2", "sub/scratch-red"):
            (root / scratch).mkdir()
            (root / scratch / "dump.jsonl").write_text("x")
        files, unnamed = mod.check(root)
        if files != 3 or unnamed != ["b.log"]:
            _die(f"index-check must count 3 files and flag only b.log: files={files} unnamed={unnamed}")
        if not mod.is_scratch(("z1", "scratch-pre", "cdiff", "x.jsonl")):
            _die("index-check is_scratch must match a scratch-* component")
        if mod.is_scratch(("z1", "logs", "settle-kdc-1.log")):
            _die("index-check is_scratch must not match an ordinary path")
        (root / "scratch-notes.log").write_text("x")
        files, unnamed = mod.check(root)
        if files != 4 or unnamed != ["b.log", "scratch-notes.log"]:
            _die(f"index-check must judge directories, not file names, as scratch: {unnamed}")
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=False)


def check_claim_audit() -> None:
    """Round 3: claim-audit.py fails a non-asserting line, a log-only bullet and a grep settle."""
    mod = _claim_audit_module()
    root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (root / "scripts").mkdir()
        pad = 'echo "---- pad ----"\n' * 4
        (root / "scripts" / "fx-gate.sh").write_text(
            'NAME="rust"\nNAME_MIT="mit"\n'
            + pad
            + 'echo "==== value ===="  # MIT omits NULL\nOUT="$(docker exec "$NAME" true)"\n'
            + "echo \"$OUT\" | grep -F 'value=1'\n"
            + pad
            + 'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            + "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
            + pad
            + 'echo "value=1 printed only"\n'
        )
        ev = root / "logs"
        ev.mkdir()
        stamp = "head_sha=0\ntree_sha=0\n"
        (ev / "good.log").write_text(stamp + "value=1\n")
        (ev / "settle-live.log").write_text(stamp + "dirty=no\n==== settle live ====\ncmd=docker exec x kinit user\nvalue=1\n")
        (ev / "settle-grep.log").write_text(stamp + "dirty=no\n==== settle grep ====\ncmd=grep -F value=1 /tmp/x.log\nvalue=1\n")
        (ev / "settle-run.log").write_text(stamp + "dirty=no\n==== settle run ====\ncmd=scripts/fx-gate.sh\nvalue=1\n")
        (ev / "settle-nobanner.log").write_text(stamp + "dirty=no\ncmd=docker exec x kinit user\nvalue=1\n")
        (ev / "settle-commit.log").write_text(stamp + "dirty=no\n==== settle commit ====\ncmd=docker exec c sh -c\ncommit value=1\n")
        (ev / "settle-dirty.log").write_text(
            stamp + "dirty=yes\n==== settle dirty ====\ncmd=docker exec x kinit user\nvalue=1\n"
        )
        (ev / "settle-override.log").write_text(
            stamp
            + "dirty=yes\noverride=KERBER_SETTLE_ALLOW_DIRTY\n==== settle ov ====\n"
            + "cmd=docker exec x kinit user\nvalue=1\n"
        )
        (ev / "unit-red.log").write_text(
            stamp + "dirty=yes\nred-at-parent=1\n==== unit_red_at ====\nvalue=1\n"
        )
        (root / "scripts" / "fx-policy.py").write_text(
            "def check():\n    if bad:\n        _die('value=1 wrong')\n\n\ndef _self_test():\n    _must_die(check, 'value=1')\n"
        )
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"

        def rows(bullet: str):
            return mod.audit_text(head + bullet, root, ev)

        def must_fail(bullet: str, why: str) -> None:
            bad = [r for r in rows(bullet) if r[1] != "ok"]
            if not bad:
                _die(f"claim-audit passed a bullet that {why}")

        good = "- **Both legs:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; live `good.log`.\n"
        if any(r[1] != "ok" for r in rows(good)):
            _die(f"claim-audit failed a valid bullet: {rows(good)}")
        must_fail(
            "- **Echo only:** `value=1` at `scripts/fx-gate.sh:20` / `:15`.\n",
            "names a non-asserting line",
        )
        must_fail("- **Log only:** `value=1` in `good.log`.\n", "names only a log")
        must_fail(
            "- **Grep settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-grep.log`.\n",
            "names a grep settle",
        )
        must_fail(
            "- **One leg:** `value=1` at `scripts/fx-gate.sh:9`.\n",
            "names a cell on one leg only",
        )
        must_fail(
            "- **Far window:** `value=1` at `scripts/fx-gate.sh:12` / `:15`.\n",
            "a reference three lines from an assertion",
        )
        live = "- **Live settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-live.log`.\n"
        if any(r[1] != "ok" for r in rows(live)):
            _die(f"claim-audit refused an oracle settle as the MIT leg: {rows(live)}")
        must_fail(
            "- **Dirty settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-dirty.log`.\n",
            "takes a dirty=yes oracle without a parent-red label",
        )
        must_fail(
            "- **Override settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-override.log`.\n",
            "takes an override= oracle without a parent-red label",
        )
        parent_red = (
            "- **Red at parent:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; Red at parent `unit-red.log`.\n"
        )
        if any(r[1] != "ok" for r in rows(parent_red)):
            _die(f"claim-audit refused a labelled parent-red dirty artefact: {rows(parent_red)}")
        must_fail(
            "- **Red at parent + dirty settle:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; "
            "Red at parent; `settle-dirty.log`.\n",
            "lets a parent-red label excuse a dirty settle",
        )
        must_fail(
            "- **Gate-run settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-run.log`.\n",
            "takes a Rust-side gate run as the MIT leg",
        )
        must_fail(
            "- **No-banner settle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-nobanner.log`.\n",
            "takes a settle without the settle.sh banner",
        )
        must_fail(
            "- **Commit-not-oracle:** `value=1` at `scripts/fx-gate.sh:9`; `settle-commit.log`.\n",
            "matches 'commit' as an oracle word",
        )
        must_fail(
            "- **Tooling without fixture:** `value=1` at `scripts/fx-policy.py:3`.\n",
            "names a tooling die site without its fixture",
        )
        tooling = "- **Tooling with fixture:** `value=1` at `scripts/fx-policy.py:3` / `:7`.\n"
        if any(r[1] != "ok" for r in rows(tooling)):
            _die(f"claim-audit refused a tooling claim with its fixture: {rows(tooling)}")
        # A fixture that asserts the die message counts, by that exact name.
        (root / "scripts" / "fx-msg-policy.py").write_text(
            "def check():\n    if bad:\n        _die('value=1 wrong')\n\n\n"
            "def _self_test():\n    _must_die_msg('value=1 wrong', check)\n"
        )
        msg_tooling = "- **Message fixture:** `value=1` at `scripts/fx-msg-policy.py:3` / `:7`.\n"
        if any(r[1] != "ok" for r in rows(msg_tooling)):
            _die(f"claim-audit refused a tooling claim with its _must_die_msg fixture: {rows(msg_tooling)}")
        no_fixture = "- **Message tooling alone:** `value=1` at `scripts/fx-msg-policy.py:3`.\n"
        if not any("tooling claim names no fixture line" in r[2] for r in rows(no_fixture)):
            _die(f"claim-audit must fail a tooling claim with no fixture call in its window: {rows(no_fixture)}")
        # S6.1: the enclosing def comes from the AST, so a column-0 YAML key inside a fixture string
        # does not end it (the line scan stopped at `on:` and missed the _must_die below).
        yaml_policy = (
            "def check(text):\n    if 'value=1' not in text:\n        _die('value=1 missing')\n\n\n"
            "def _self_test():\n"
            '    snippet = """name: ci\non:\n  push:\n"""\n'
            "    if snippet.count('on:') != 1:\n"
            "        raise SystemExit('value=1 fixture lost its on: key')\n"
            "    pad_a = 1\n    pad_b = 2\n    pad_c = 3\n"
            "    _must_die(check, snippet)\n"
        )
        (root / "scripts" / "fx-yaml-policy.py").write_text(yaml_policy)
        yaml_bullet = "- **YAML fixture:** `value=1` at `scripts/fx-yaml-policy.py:12`.\n"
        if any(r[1] != "ok" for r in rows(yaml_bullet)):
            _die(f"claim-audit must read the enclosing def whole past a column-0 YAML key: {rows(yaml_bullet)}")
        (root / "scripts" / "fx-yaml-policy.py").write_text(
            yaml_policy.replace("    _must_die(check, snippet)\n", "    pad_d = 4\n")
        )
        mod.script_lines.cache_clear()
        mod.def_spans.cache_clear()
        if not any("tooling claim names no fixture line" in r[2] for r in rows(yaml_bullet)):
            _die(f"claim-audit must fail the YAML-fixture claim once its def has no fixture: {rows(yaml_bullet)}")
        # A module of a package under scripts/ is a tooling reference like any scripts/*.py.
        (root / "scripts" / "fx_pkg" / "sub").mkdir(parents=True)
        (root / "scripts" / "fx_pkg" / "sub" / "mod.py").write_text(
            "def check():\n    if bad:\n        _die('value=1 wrong')\n\n\ndef _self_test():\n    _must_die(check, 'value=1')\n"
        )
        pkg_bullet = "- **Package module:** `value=1` at `scripts/fx_pkg/sub/mod.py:3` / `:7`.\n"
        if any(r[1] != "ok" for r in rows(pkg_bullet)):
            _die(f"claim-audit refused a tooling claim in a package module: {rows(pkg_bullet)}")
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=False)
