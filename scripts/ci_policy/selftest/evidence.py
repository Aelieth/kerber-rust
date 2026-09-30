"""The self-test of the record-tooling checks."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile

from ..common import SCRIPTS, _die, _scratch_root
from ..evidence import (
    _claim_audit_module, check_ci_status_save, check_evidence_check_tool, check_index_check_scratch,
    check_no_red_target_trees, check_red_at_sha_build, check_red_at_sha_inject, check_red_at_sha_overlay_order,
    check_red_at_sha_target_trap, check_settle_helper, check_unit_evidence_helper,
)
from .common import _must_die, _must_die_msg


def _self_test_evidence() -> None:
    check_unit_evidence_helper()
    check_settle_helper()
    check_evidence_check_tool()
    check_ci_status_save()
    check_red_at_sha_inject()
    _overlay_dirs = ('    for d in lib oracle ci_policy; do\n        rm -rf "$WT/scripts/$d"\n'
                     '        cp -a "$ROOT/scripts/$d" "$WT/scripts/$d"\n    done\n')
    check_red_at_sha_overlay_order(
        'cp "$ROOT/scripts/"*.sh "$WT/scripts/"\n' + _overlay_dirs + 'TREE="$(git write-tree)"\n', allow=0
    )
    _must_die(
        check_red_at_sha_overlay_order,
        'TREE="$(git write-tree)"\ncp "$ROOT/scripts/"*.sh "$WT/scripts/"\n' + _overlay_dirs, 0,
    )
    # Each script directory HEAD's gates read is overlaid whole before write-tree; one fixture per directory.
    for _d in ("lib", "oracle", "ci_policy"):
        _must_die_msg(
            f"must overlay scripts/{_d}/ whole",
            check_red_at_sha_overlay_order,
            'cp "$ROOT/scripts/"*.sh "$WT/scripts/"\n' + _overlay_dirs.replace(f" {_d}", "", 1)
            + 'TREE="$(git write-tree)"\n',
        )
    _must_die_msg(
        "must overlay scripts/lib/ whole",
        check_red_at_sha_overlay_order,
        'cp "$ROOT/scripts/"*.sh "$WT/scripts/"\nTREE="$(git write-tree)"\n' + _overlay_dirs, 0,
    )
    check_red_at_sha_overlay_order('cp "$ROOT/scripts/"*.sh "$WT/scripts/"\nTREE="$(git write-tree)"\n', allow=3)
    _must_die(
        check_red_at_sha_inject,
        '--inject\nTREE="$(git write-tree)"\ncp "$ROOT/$rel" "$WT/$rel"\n',
    )
    check_red_at_sha_target_trap()
    _trap_ok = (
        'cleanup() {\n    rm -rf "$WT"\n    if [ "${KERBER_KEEP_RED_TARGET:-}" != "1" ]; then\n'
        '        rm -rf "$TARGET"\n    fi\n}\ntrap cleanup EXIT\necho "red-at-parent=1"\n'
    )
    check_red_at_sha_target_trap(_trap_ok)
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace('rm -rf "$TARGET"', "true"))
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace("KERBER_KEEP_RED_TARGET", "X"))
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace('echo "red-at-parent=1"', ""))
    check_red_at_sha_build()
    _build_ok = (SCRIPTS / "red-at-sha.sh").read_text(encoding="utf-8")
    check_red_at_sha_build(_build_ok)
    _must_die_msg("must not name krb5-forge-tgt's crate", check_red_at_sha_build,
                  _build_ok + "\ncargo build -p krb5-client --bin krb5-kinit --bin krb5-forge-tgt\n")
    _must_die_msg("base's own scripts/lib/build-bins.sh", check_red_at_sha_build,
                  _build_ok.replace("build-bins.at-base.sh", "build-bins.sh"))
    _must_die_msg("each fallback bin's crate", check_red_at_sha_build, _build_ok.replace("src/bin/$b", "src/bin/x"))
    _rt = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        check_no_red_target_trees(_rt)
        (_rt / "z9" / "scratch" / "red-target-0123456789ab" / "debug").mkdir(parents=True)
        _must_die(check_no_red_target_trees, _rt)
        subprocess.run(["rm", "-rf", str(_rt / "z9")], check=True)
        (_rt / "z9" / "scratch" / "tgt" / "debug").mkdir(parents=True)
        (_rt / "z9" / "scratch" / "tgt" / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55")
        _must_die(check_no_red_target_trees, _rt)
    finally:
        subprocess.run(["rm", "-rf", str(_rt)], check=False)
    check_index_check_scratch()

    spec = importlib.util.spec_from_file_location("ci_status_r14", SCRIPTS / "ci-status.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/ci-status.py")
    cistat = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cistat)
    cistat.time.sleep = lambda _s: None
    out_dir = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:

        def _inprog(*_a, **_k):
            return [
                {
                    "id": 1,
                    "run_number": 1,
                    "status": "in_progress",
                    "conclusion": None,
                    "head_sha": "abc1234deadbeef",
                }
            ]

        import io
        import urllib.error as _ue
        from email.message import Message

        def _quiet_save(*args, **kwargs):
            sink = io.StringIO()
            oldout, olderr = sys.stdout, sys.stderr
            try:
                sys.stdout = sink
                sys.stderr = sink
                return cistat.save_run(*args, **kwargs)
            finally:
                sys.stdout = oldout
                sys.stderr = olderr

        cistat.fetch_runs = _inprog
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=2)
        if rc != 2 or (out_dir / "ci-abc1234.txt").exists():
            _die("ci-status --save must exit 2 and write no file for in_progress")

        def _403(*_a, **_k):
            raise _ue.HTTPError(
                "https://api.github.com",
                403,
                "rate limit",
                Message(),
                io.BytesIO(b""),
            )

        cistat.fetch_runs = _403
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=3)
        if rc != 2 or (out_dir / "ci-abc1234.txt").exists():
            _die("ci-status --save must exit 2 and write no file after 403 ×N")

        def _done(*_a, **_k):
            return [
                {
                    "id": 9,
                    "run_number": 2,
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "abc1234deadbeef",
                }
            ]

        cistat.fetch_runs = _done
        cistat.format_run = lambda *_a, **_k: ["run ok"]
        _stamped = {"started_at": "2026-09-30T13:00:00Z", "completed_at": "2026-09-30T13:00:05Z"}
        cistat.fetch_jobs = lambda *_a, **_k: [{"name": "j", "steps": [dict(_stamped), dict(_stamped)]}]
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=1)
        saved = out_dir / "ci-abc1234.txt"
        if rc != 0 or not saved.is_file() or "head_sha=" not in saved.read_text():
            _die("ci-status --save must exit 0 with head_sha= for a completed run")
        # A completed run with a step GitHub has not stamped yet is not complete: retry, never a partial file.
        saved.unlink()
        cistat.fetch_jobs = lambda *_a, **_k: [
            {"name": "j", "steps": [dict(_stamped), {"started_at": _stamped["started_at"], "completed_at": None}]}
        ]
        _sleeps: list[float] = []
        cistat.time.sleep = _sleeps.append
        sink = io.StringIO()
        oldout, olderr = sys.stdout, sys.stderr
        try:
            sys.stdout = sink
            sys.stderr = sink
            rc = cistat.save_run("o/r", "ci", "abc1234", str(out_dir))
        finally:
            sys.stdout = oldout
            sys.stderr = olderr
            cistat.time.sleep = lambda _s: None
        if rc != 2 or saved.exists():
            _die("ci-status --save must exit 2 and write no file while a step is unstamped")
        if "run 2: 1 steps unstamped; retrying" not in sink.getvalue():
            _die("ci-status --save must say 'run N: K steps unstamped; retrying'")
        if sum(_sleeps) < 900 or max(_sleeps) > 60:
            _die(f"ci-status --save must retry unstamped steps for >= 15 min at a 60 s cap: {sum(_sleeps)} s")
        # The file is named by workflow: --workflow fuzz writes fuzz-<sha>.txt and leaves ci-<sha>.txt alone.
        cistat.fetch_jobs = lambda *_a, **_k: [{"name": "j", "steps": [dict(_stamped)]}]
        rc = _quiet_save("o/r", "fuzz", "abc1234", str(out_dir), retries=1)
        if rc != 0 or not (out_dir / "fuzz-abc1234.txt").is_file() or saved.exists():
            _die("ci-status --save --workflow fuzz must write fuzz-<sha>.txt, not ci-<sha>.txt")
        if cistat.save_name("fuzz.yml", "abc1234def") != "fuzz-abc1234.txt":
            _die("ci-status save_name must name the file by the workflow's stem")
    finally:
        subprocess.run(["rm", "-rf", str(out_dir)], check=False)

    camod = _claim_audit_module()
    croot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (croot / "scripts").mkdir()
        pad = 'echo "---- pad ----"\n' * 4
        (croot / "scripts" / "fx-gate.sh").write_text(
            'NAME="rust"\nNAME_MIT="mit"\n'
            + pad
            + 'echo "==== value ===="  # MIT omits NULL\nOUT="$(docker exec "$NAME" true)"\n'
            + "echo \"$OUT\" | grep -F 'value=1'\n"
            + pad
            + 'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            + "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
        )
        ev = croot / "logs"
        ev.mkdir()
        stamp = "head_sha=0\ntree_sha=0\n"
        (ev / "x-unit-red.log").write_text(stamp + "dirty=yes\nvalue=1\n")
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"
        bullet = (
            "- **Text excuse only:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; "
            "Red at parent `x-unit-red.log`.\n"
        )
        rows = camod.audit_text(head + bullet, croot, ev)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must not take a parent-red text excuse without red-at-parent=")
        (ev / "x-unit-red.log").write_text(
            stamp + "dirty=yes\nred-at-parent=1\nvalue=1\n"
        )
        rows = camod.audit_text(head + bullet, croot, ev)
        if any(r[1] != "ok" for r in rows):
            _die(f"claim-audit refused a dirty unit-red with red-at-parent=: {rows}")
    finally:
        subprocess.run(["rm", "-rf", str(croot)], check=False)

    # W1-Z Z3.1 freeze rule: a `Frozen-at: <sha>` summary resolves its cites at
    # that commit, so a later gate edit that drops the assertion does not
    # re-open the closed summary; the same bullet without the header is red.
    froot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (froot / "scripts").mkdir()
        gate = froot / "scripts" / "fx-gate.sh"
        asserting = (
            'NAME="rust"\nNAME_MIT="mit"\n'
            'OUT="$(docker exec "$NAME" true)"\n'
            "echo \"$OUT\" | grep -F 'value=1'\n"
            'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
        )
        gate.write_text(asserting)
        genv = {
            **os.environ,
            "GIT_AUTHOR_NAME": "fx",
            "GIT_AUTHOR_EMAIL": "fx@x",
            "GIT_COMMITTER_NAME": "fx",
            "GIT_COMMITTER_EMAIL": "fx@x",
        }
        for cmd in (
            ["git", "init", "-q"],
            ["git", "add", "-A"],
            ["git", "commit", "-q", "-m", "fx"],
        ):
            subprocess.run(cmd, cwd=froot, check=True, env=genv, capture_output=True)
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=froot, check=True, capture_output=True, text=True
        ).stdout.strip()
        gate.write_text(asserting.replace("grep -F 'value=1'", "cat"))
        fev = froot / "logs"
        fev.mkdir()
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"
        bullet = "- **Frozen cite:** `value=1` at `scripts/fx-gate.sh:4` / `:6`.\n"
        if camod.frozen_at(f"# T\n\nFrozen-at: `{sha[:12]}`\n\n" + head + bullet) != sha[:12]:
            _die("claim-audit frozen_at must read the `Frozen-at:` header")
        rows = camod.audit_text(head + bullet, froot, fev)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must read the working tree when no Frozen-at is given")
        rows = camod.audit_text(head + bullet, froot, fev, sha)
        if any(r[1] != "ok" for r in rows):
            _die(f"claim-audit must resolve a frozen cite at its sha: {rows}")
        rows = camod.audit_text(head + bullet, froot, fev, "0" * 40)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must fail a cite frozen at an unknown sha")
    finally:
        subprocess.run(["rm", "-rf", str(froot)], check=False)
