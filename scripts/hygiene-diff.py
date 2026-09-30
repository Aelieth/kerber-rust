#!/usr/bin/env python3
"""Compare two hygiene snapshots. Exit 1 on a forbidden removal or regression.

Fails on:
  - a test `(binary, name)` removed that is not in --renames / --duplicates
    (`--duplicates` and `--renames` are keyed `old_binary<TAB>old_name`
    to `new_binary<TAB>new_name`; a RHS that is also a LHS is rejected;
    many-to-one needs `merged:` on the RHS)
  - a gate cell tag removed (an `echo` tag listed in --dead with a reason is
    information: the MIT_/RUST_ identifier scan also catches path and port
    constants that were never a cell; `section`/`flow` tags cannot be waived)
  - a (file,kind,tag) multiplicity drop (a (kind,tag) count that fell)
  A gate's cells are counted by reachability (hygiene_inventory.gate_cell_reach): its top level and the
  functions reachable from it, its own and those of the scripts/lib files it sources. A cell lost from
  a gate is information only when the tool proves, from the old tree (the old snapshot's stamped
  head_sha, or --old-rev) by that rule, that it sat only in an unreachable function; an old tree it
  cannot read fails closed. A cell gained through a lib is information.
  - a diffsend case, client-differential flow, or ledger row removed or regraded
  - a gate_rc that went from 0 to non-zero
  - quality counts that went up (allow=, allow_sites=, rustfmt_skip=, unwrap_expect_panic_src=, traces_untracked=,
    clippy_warnings=, doc_warnings=, fmt_files=, shellcheck_findings=, undocumented_pub=)
    unless `--accept-rise key=N:reason` names that exact rise
  - a quality rc that went from 0 to non-zero (fmt_rc, clippy_rc, doc_rc, doctest_rc,
    shellcheck_rc)

A key present on only one side is skipped (a W2 snapshot has no W3 keys;
`na`/`skipped` values are not numbers).

gate_rc comes from `<snapshot>/timings.tsv` or `<snapshot>/checkpoint/timings.tsv`;
prints `gate_rc: N gates compared, K non-zero in new (…)` when both sides have one,
`gate_rc: not compared` when neither does.

Reports as information: sleep/boot/cargo-build deltas; LOC, comment and doc
lines per package; file and fn maxima; `pub` surface; binaries and
dependencies added or removed; gate assert-count drops; new shellcheck
findings and new undocumented items when their count rose.
"""
from __future__ import annotations

import argparse
import collections
import os
import pathlib
import re
import subprocess
import sys
import tempfile


def load_data_lines(path: pathlib.Path) -> list[str]:
    if not path.is_file():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def load_set(path: pathlib.Path) -> set[str]:
    return set(load_data_lines(path))


# A provenance.sh stamp line: `==== provenance ====` or `key=value`, where the
# key may carry digits (`acl_sha256_tree`) and the value spaces (`image=sha256:… <date>`).
_STAMP_LINE_RE = re.compile(r"^(?:====.*====|[a-z_][a-z0-9_]*=.*)$")


def load_map(path: pathlib.Path | None, sep: str) -> dict[str, str]:
    """`left <sep> right` per line; `#` comments; a leading provenance stamp
    (`==== provenance ====`, `key=value` lines) is skipped so a map kept as
    evidence can carry the stamp evidence-check.py wants."""
    if path is None or not path.is_file():
        return {}
    mapping: dict[str, str] = {}
    in_stamp = True
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if in_stamp and _STAMP_LINE_RE.match(line):
            continue
        in_stamp = False
        if sep not in line:
            raise SystemExit(f"bad map line in {path}: {line!r}")
        left, right = line.split(sep, 1)
        mapping[left.strip()] = right.strip()
    return mapping


def kv(path: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in load_data_lines(path):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k] = v
    return out


def load_gate_rc(path: pathlib.Path) -> dict[str, int]:
    """timings.tsv: gate run gate_rc wall_s → last rc per gate."""
    rc: dict[str, int] = {}
    if not path.is_file():
        return rc
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if i == 0 and line.startswith("gate"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            rc[parts[0]] = int(parts[2])
        except ValueError:
            continue
    return rc


def strip_merged(s: str) -> str:
    return s[7:] if s.startswith("merged:") else s


def _load_keyed_id_map(path: pathlib.Path | None, sep: str, kind: str) -> dict[str, str]:
    """Keyed `old_binary<TAB>old_name <sep> [merged:]new_binary<TAB>new_name`."""
    raw = load_map(path, sep)
    mapping: dict[str, str] = {}
    for left, right in raw.items():
        if "\t" not in left:
            raise SystemExit(f"{kind} LHS must be binary<TAB>name: {left!r}")
        rhs = strip_merged(right)
        if "\t" not in rhs:
            raise SystemExit(f"{kind} RHS must be binary<TAB>name: {right!r}")
        mapping[left] = right
    lhs = set(mapping)
    for left, right in mapping.items():
        rhs = strip_merged(right)
        if rhs in lhs:
            raise SystemExit(f"{kind} RHS is also a LHS: {rhs}")
    targets: dict[str, list[tuple[str, str]]] = {}
    for left, right in mapping.items():
        targets.setdefault(strip_merged(right), []).append((left, right))
    for rhs, ents in targets.items():
        if len(ents) > 1:
            for left, right in ents:
                if not right.startswith("merged:"):
                    raise SystemExit(f"many-to-one {rhs} needs merged: (from {left})")
    return {left: strip_merged(right) for left, right in mapping.items()}


def load_duplicates_map(path: pathlib.Path | None) -> dict[str, str]:
    """Keyed `old_binary<TAB>old_name = [merged:]new_binary<TAB>new_name`."""
    return _load_keyed_id_map(path, "=", "duplicates")


def load_renames_map(path: pathlib.Path | None) -> dict[str, str]:
    """Keyed `old_binary<TAB>old_name -> [merged:]new_binary<TAB>new_name`."""
    return _load_keyed_id_map(path, "->", "renames")


def apply_rename(t: str, renames: dict[str, str]) -> str:
    """Keyed `old_binary<TAB>old_name -> new_binary<TAB>new_name` only."""
    return renames.get(t, t)


def _write_snap(
    d: pathlib.Path,
    gates: list[str],
    timings: str | None = None,
    quality: dict[str, str] | None = None,
    binaries: list[str] | None = None,
    tests: list[str] | None = None,
) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "gates.txt").write_text("# gate\tkind\ttag\n" + "".join(g + "\n" for g in gates), encoding="utf-8")
    rows = tests if tests is not None else ["bin\tt1"]
    (d / "tests.txt").write_text("# binary\tname\n" + "".join(r + "\n" for r in rows), encoding="utf-8")
    (d / "tests.count").write_text(f"{len(rows)}\n", encoding="utf-8")
    for name in (
        "diffsend.txt",
        "client-differential-flows.txt",
        "ledger-rows.txt",
        "sleeps.txt",
        "cargo-build-gates.txt",
        "unit-sleeps.txt",
    ):
        (d / name).write_text("#\n", encoding="utf-8")
    (d / "quality.txt").write_text(
        "#\n" + "".join(f"{k}={v}\n" for k, v in (quality or {}).items()), encoding="utf-8"
    )
    if binaries is not None:
        (d / "binaries.txt").write_text("#\n" + "".join(b + "\n" for b in binaries), encoding="utf-8")
    if timings is not None:
        (d / "timings.tsv").write_text(timings, encoding="utf-8")


def parse_accept_rise(items: list[str] | None) -> dict[str, tuple[int, str]]:
    """`--accept-rise key=N:reason` → {key: (N, reason)}."""
    out: dict[str, tuple[int, str]] = {}
    for raw in items or []:
        if "=" not in raw:
            raise SystemExit(f"bad --accept-rise {raw!r} (want key=N:reason)")
        key, rest = raw.split("=", 1)
        if ":" not in rest:
            raise SystemExit(f"bad --accept-rise {raw!r} (want key=N:reason)")
        n_s, reason = rest.split(":", 1)
        try:
            n = int(n_s)
        except ValueError as e:
            raise SystemExit(f"bad --accept-rise {raw!r} (N must be int)") from e
        if n < 1 or not key.strip() or not reason.strip():
            raise SystemExit(f"bad --accept-rise {raw!r}")
        out[key.strip()] = (n, reason.strip())
    return out


def _quiet_compare(
    old: pathlib.Path,
    new: pathlib.Path,
    dead_path: pathlib.Path | None = None,
    accept_rise: list[str] | None = None,
    duplicates_path: pathlib.Path | None = None,
    renames_path: pathlib.Path | None = None,
) -> int:
    import io
    from contextlib import redirect_stdout

    with redirect_stdout(io.StringIO()):
        return main_compare(
            old,
            new,
            dead_path=dead_path,
            accept_rise=accept_rise,
            duplicates_path=duplicates_path,
            renames_path=renames_path,
        )


def _must_fail(
    old: pathlib.Path,
    new: pathlib.Path,
    label: str,
    needle: str,
    dead_path: pathlib.Path | None = None,
    accept_rise: list[str] | None = None,
    duplicates_path: pathlib.Path | None = None,
    renames_path: pathlib.Path | None = None,
) -> None:
    """The compare must fail, and its output must carry `needle`: the failure this case is about,
    not some other one."""
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = main_compare(
                old,
                new,
                dead_path=dead_path,
                accept_rise=accept_rise,
                duplicates_path=duplicates_path,
                renames_path=renames_path,
            )
    except SystemExit as e:
        rc = 1
        buf.write(f"\n{e}\n")
    if rc == 0:
        raise SystemExit(f"hygiene-diff --self-test: {label} must fail")
    if needle not in buf.getvalue():
        raise SystemExit(f"hygiene-diff --self-test: {label} failed without {needle!r}: {buf.getvalue()[-300:]!r}")


def _must_pass(
    old: pathlib.Path,
    new: pathlib.Path,
    label: str,
    dead_path: pathlib.Path | None = None,
    accept_rise: list[str] | None = None,
    duplicates_path: pathlib.Path | None = None,
    renames_path: pathlib.Path | None = None,
) -> None:
    if (
        _quiet_compare(
            old,
            new,
            dead_path,
            accept_rise=accept_rise,
            duplicates_path=duplicates_path,
            renames_path=renames_path,
        )
        != 0
    ):
        raise SystemExit(f"hygiene-diff --self-test: {label} must pass")


def _self_test_duplicates(root: pathlib.Path) -> int:
    """Keyed maps; RHS-as-LHS red; many-to-one needs merged:."""
    n = 0
    old, new = root / "dup-old", root / "dup-new"
    _write_snap(old, ["a.sh\techo\tkeep"], tests=["oldbin\tfoo", "oldbin\tkeep"])
    _write_snap(new, ["a.sh\techo\tkeep"], tests=["newbin\tbar", "oldbin\tkeep"])
    _must_fail(old, new, "removed test without keyed map", needle="FAIL test removed: oldbin\tfoo")
    n += 1
    good = root / "dup-good.txt"
    good.write_text("oldbin\tfoo = newbin\tbar\n", encoding="utf-8")
    _must_pass(old, new, "keyed duplicate", duplicates_path=good)
    n += 1
    name_only = root / "dup-name.txt"
    name_only.write_text("foo = bar\n", encoding="utf-8")
    _must_fail(
        old, new, "name-only duplicates", needle="FAIL duplicates LHS must be binary<TAB>name",
        duplicates_path=name_only,
    )
    n += 1
    chained = root / "dup-chain.txt"
    chained.write_text("oldbin\tfoo = midbin\tmid\nmidbin\tmid = newbin\tbar\n", encoding="utf-8")
    _must_fail(old, new, "RHS-as-LHS", needle="FAIL duplicates RHS is also a LHS", duplicates_path=chained)
    n += 1
    many_old, many_new = root / "many-old", root / "many-new"
    _write_snap(many_old, ["a.sh\techo\tkeep"], tests=["a\tx", "b\ty"])
    _write_snap(many_new, ["a.sh\techo\tkeep"], tests=["c\tz"])
    no_merged = root / "dup-nomerge.txt"
    no_merged.write_text("a\tx = c\tz\nb\ty = c\tz\n", encoding="utf-8")
    _must_fail(many_old, many_new, "many-to-one without merged:", needle="needs merged:", duplicates_path=no_merged)
    n += 1
    merged = root / "dup-merged.txt"
    merged.write_text("a\tx = merged:c\tz\nb\ty = merged:c\tz\n", encoding="utf-8")
    _must_pass(many_old, many_new, "many-to-one merged", duplicates_path=merged)
    n += 1
    return n


def _self_test_renames(root: pathlib.Path) -> int:
    """Keyed --renames; two olds → one new needs merged:."""
    n = 0
    old, new = root / "ren-old", root / "ren-new"
    _write_snap(old, ["a.sh\techo\tkeep"], tests=["oldbin\tfoo"])
    _write_snap(new, ["a.sh\techo\tkeep"], tests=["newbin\tbar"])
    _must_fail(old, new, "removed test without keyed rename", needle="FAIL test removed: oldbin\tfoo")
    n += 1
    good = root / "ren-good.txt"
    good.write_text("oldbin\tfoo -> newbin\tbar\n", encoding="utf-8")
    _must_pass(old, new, "keyed rename", renames_path=good)
    n += 1
    name_only = root / "ren-name.txt"
    name_only.write_text("foo -> bar\n", encoding="utf-8")
    _must_fail(old, new, "name-only renames", needle="FAIL renames LHS must be binary<TAB>name", renames_path=name_only)
    n += 1
    many_old, many_new = root / "ren-many-old", root / "ren-many-new"
    _write_snap(many_old, ["a.sh\techo\tkeep"], tests=["a\tx", "b\ty"])
    _write_snap(many_new, ["a.sh\techo\tkeep"], tests=["c\tz"])
    no_merged = root / "ren-nomerge.txt"
    no_merged.write_text("a\tx -> c\tz\nb\ty -> c\tz\n", encoding="utf-8")
    _must_fail(many_old, many_new, "rename many-to-one without merged:", needle="needs merged:", renames_path=no_merged)
    n += 1
    merged = root / "ren-merged.txt"
    merged.write_text("a\tx -> merged:c\tz\nb\ty -> merged:c\tz\n", encoding="utf-8")
    _must_pass(many_old, many_new, "rename many-to-one merged", renames_path=merged)
    n += 1
    return n


def _self_test_quality(root: pathlib.Path) -> int:
    """W3 keys: a rise or a 0 -> non-zero rc is red; a one-sided key or a moved binary is not."""
    n = 0
    red = [
        ("undocumented_pub rose", {"undocumented_pub": "5"}, {"undocumented_pub": "7"}),
        ("rustfmt_skip rose", {"rustfmt_skip": "0"}, {"rustfmt_skip": "1"}),
        ("shellcheck_findings rose", {"shellcheck_findings": "90"}, {"shellcheck_findings": "91"}),
        ("doc_warnings rose", {"doc_warnings": "0"}, {"doc_warnings": "1"}),
        ("doc_rc went red", {"doc_rc": "0"}, {"doc_rc": "1"}),
    ]
    green = [
        ("doc_rc stayed red", {"doc_rc": "1", "doc_warnings": "3"}, {"doc_rc": "1", "doc_warnings": "3"}),
        ("one-sided key", {}, {"doc_warnings": "3", "undocumented_pub": "117"}),
        ("na", {"shellcheck_findings": "na"}, {"shellcheck_findings": "90"}),
        ("counts fell", {"undocumented_pub": "117", "allow": "75"}, {"undocumented_pub": "0", "allow": "70"}),
    ]
    waiver_old, waiver_new = root / "waiver-old", root / "waiver-new"
    _write_snap(waiver_old, ["a.sh\techo\tkeep"], quality={"allow_sites": "77"})
    _write_snap(waiver_new, ["a.sh\techo\tkeep"], quality={"allow_sites": "81"})
    _must_fail(waiver_old, waiver_new, "quality allow_sites rose", needle="FAIL quality allow_sites rose 77 -> 81")
    n += 1
    _must_pass(
        waiver_old,
        waiver_new,
        "quality allow_sites waived",
        accept_rise=["allow_sites=4:+4 tests/common dead_code, -1 status.rs, -1 c2_kpropd_acl.rs"],
    )
    n += 1
    _must_fail(
        waiver_old,
        waiver_new,
        "accept-rise mismatched N",
        needle="FAIL accept-rise allow_sites=2:wrong n unused",
        accept_rise=["allow_sites=2: wrong n"],
    )
    n += 1
    same_old, same_new = root / "rise-same-old", root / "rise-same-new"
    _write_snap(same_old, ["a.sh\techo\tkeep"], quality={"allow_sites": "80"})
    _write_snap(same_new, ["a.sh\techo\tkeep"], quality={"allow_sites": "80"})
    _must_fail(
        same_old,
        same_new,
        "accept-rise unused",
        needle="FAIL accept-rise allow_sites=1:unused unused",
        accept_rise=["allow_sites=1: unused"],
    )
    n += 1
    for i, (label, old_q, new_q) in enumerate(red):
        old, new = root / f"red{i}-old", root / f"red{i}-new"
        _write_snap(old, ["a.sh\techo\tkeep"], quality=old_q)
        _write_snap(new, ["a.sh\techo\tkeep"], quality=new_q)
        _must_fail(old, new, f"quality {label}", needle=f"FAIL quality {label.split()[0]}")
        n += 1
    for i, (label, old_q, new_q) in enumerate(green):
        old, new = root / f"green{i}-old", root / f"green{i}-new"
        _write_snap(old, ["a.sh\techo\tkeep"], quality=old_q)
        _write_snap(new, ["a.sh\techo\tkeep"], quality=new_q)
        _must_pass(old, new, f"quality {label}")
        n += 1
    # comment_lines is reported split: the lines that carry a MIT anchor and the prose.
    import io
    from contextlib import redirect_stdout

    csplit_old, csplit_new = root / "csplit-old", root / "csplit-new"
    _write_snap(csplit_old, ["a.sh\techo\tkeep"], quality={"comment_anchor_lines": "10", "comment_prose_lines": "5"})
    _write_snap(csplit_new, ["a.sh\techo\tkeep"], quality={"comment_anchor_lines": "12", "comment_prose_lines": "5"})
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main_compare(csplit_old, csplit_new)
    if rc != 0 or "info comment_anchor_lines 10 -> 12" not in buf.getvalue():
        raise SystemExit("hygiene-diff --self-test: the comment_lines split must be reported")
    n += 1
    old, new = root / "bin-old", root / "bin-new"
    _write_snap(old, ["a.sh\techo\tkeep"], binaries=["krb5-kdc\tkrb5-forge-tgt"])
    _write_snap(new, ["a.sh\techo\tkeep"], binaries=["krb5-tools\tkrb5-forge-tgt"])
    _must_pass(old, new, "a binary moving packages")
    n += 1
    return n


def _self_test_cell_reach(root: pathlib.Path) -> int:
    """A lost gate cell is information only when the old tree proves it unreachable there."""
    import io
    from contextlib import redirect_stdout

    repo = root / "cells-repo"
    (repo / "scripts" / "lib").mkdir(parents=True)
    (repo / "scripts" / "x-gate.sh").write_text(
        '. "$ROOT/scripts/lib/l.sh"\nf() {\n    echo "==== F called ===="\n}\n'
        'g() {\n    echo "==== G dead ===="\n}\nf\nlf\n',
        encoding="utf-8",
    )
    (repo / "scripts" / "lib" / "l.sh").write_text('lf() {\n    echo "==== LF via lib ===="\n}\n', encoding="utf-8")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@x")
    for cmd in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-q", "-m", "old"]):
        subprocess.run(cmd, cwd=repo, env=env, check=True, capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()

    def snap(d: pathlib.Path, cells: list[str], head: str | None, reach_format: bool = False) -> pathlib.Path:
        _write_snap(d, [f"x-gate.sh\tsection\t{c}" for c in cells])
        if head is not None:
            (d / "provenance.txt").write_text(f"==== provenance ====\nhead_sha={head}\n", encoding="utf-8")
        if reach_format:
            (d / "dead-cells.txt").write_text("#\n", encoding="utf-8")
        return d

    def run(old: pathlib.Path, new: pathlib.Path) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main_compare(old, new, old_git=str(repo))
        return rc, buf.getvalue()

    n = 0
    # A dead cell (G, in an uncalled function at the old tree) removed: information naming the function.
    rc, out = run(snap(root / "cr-old1", ["F called", "G dead"], sha), snap(root / "cr-new1", ["F called"], None))
    if rc != 0 or "gate cell removed as dead at the old tree: x-gate.sh\tg\tsection\tG dead" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a cell dead at the old tree must be information: {out[-300:]}")
    n += 1
    # A cell of a called function removed: the old tree shows it reachable, so the "dead" claim fails.
    rc, out = run(snap(root / "cr-old2", ["F called", "G dead"], sha), snap(root / "cr-new2", ["G dead"], None))
    if rc == 0 or "FAIL gate cell tag removed: section\tF called" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a reachable cell removed must fail: {out[-300:]}")
    n += 1
    # An old tree the tool cannot read fails closed, even for a cell that was dead.
    rc, out = run(snap(root / "cr-old3", ["F called", "G dead"], "0" * 40), snap(root / "cr-new3", ["F called"], None))
    if rc == 0 or "FAIL gate cell tag removed: section\tG dead" not in out:
        raise SystemExit(f"hygiene-diff --self-test: an unreadable old tree must fail closed: {out[-300:]}")
    n += 1
    # A snapshot in the reachability format counts no dead cell: a removal there is red without the tree.
    rc, out = run(snap(root / "cr-old4", ["F called"], sha, reach_format=True), snap(root / "cr-new4", [], None))
    if rc == 0 or "FAIL gate cell tag removed: section\tF called" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a reachable cell of a reach-format snapshot must fail: {out[-300:]}")
    n += 1
    # A cell gained through a lib is information naming the gate and the function.
    new5 = snap(root / "cr-new5", ["F called", "LF via lib"], None, reach_format=True)
    (new5 / "lib-cells.txt").write_text("#\nx-gate.sh\tlib/l.sh\tlf\tsection\tLF via lib\n", encoding="utf-8")
    rc, out = run(snap(root / "cr-old5", ["F called"], sha), new5)
    if rc != 0 or "cells attributed through lib: x-gate.sh, lf, 1" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a cell gained through a lib must be information: {out[-300:]}")
    n += 1
    return n

def _self_test_ledger_rekey(root: pathlib.Path) -> int:
    """A listed check-cell reword (--ledger-rekey) is information; without its entry, with an unused entry, or with
    a changed verdict or proof it is red."""
    import io
    from contextlib import redirect_stdout

    repo = root / "rekey-repo"
    (repo / "docs" / "parity").mkdir(parents=True)
    doc = repo / "docs" / "parity" / "a1-tgs.md"
    head = "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n| --- | --- | --- | --- | --- | --- | --- |\n"
    row_b = "| b.c:2 | check b | m | r | e | exact | pb |\n"
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@x")

    def commit(text: str) -> str:
        doc.write_text(head + text + row_b, encoding="utf-8")
        for cmd in (["git", "add", "-A"], ["git", "commit", "-q", "-m", "x"]):
            subprocess.run(cmd, cwd=repo, env=env, check=True, capture_output=True)
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True,
                              check=True).stdout.strip()

    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True, capture_output=True)
    base = commit("| a.c:1 | the W1 sweep aligned | m | r | e | exact | pa |\n")
    blob = subprocess.run(["git", "rev-parse", f"{base}:docs/parity/a1-tgs.md"], cwd=repo, capture_output=True,
                          text=True, check=True).stdout.strip()
    reworded = commit("| a.c:1 | Rust follows MIT | m | r | e | exact | pa |\n")
    regraded = commit("| a.c:1 | Rust follows MIT | m | r | e | deviation | pa |\n")
    reproved = commit("| a.c:1 | Rust follows MIT | m | r | e | exact | pz |\n")

    def snap(d: pathlib.Path, check: str, verdict: str, sha: str) -> pathlib.Path:
        _write_snap(d, ["a.sh\techo\tkeep"])
        (d / "ledger-rows.txt").write_text(
            f"#\na.c:1\t{check}\t{verdict}\tdocs/parity/a1-tgs.md\nb.c:2\tcheck b\texact\tdocs/parity/a1-tgs.md\n",
            encoding="utf-8")
        (d / "provenance.txt").write_text(f"==== provenance ====\nhead_sha={sha}\n", encoding="utf-8")
        return d

    def entries(name: str, *rows: str) -> pathlib.Path:
        f = root / name
        f.write_text("# rekey\n" + "".join(r + "\n" for r in rows), encoding="utf-8")
        return f

    def run(new: pathlib.Path, rk: pathlib.Path | None) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main_compare(old, new, old_git=str(repo), ledger_rekey=rk)
        return rc, buf.getvalue()

    old = snap(root / "rk-old", "the W1 sweep aligned", "exact", base)
    good = entries("rk-good.txt", f"docs/parity/a1-tgs.md\ta.c:1\tthe W1 sweep aligned = Rust follows MIT\tblob={blob}")
    n = 0
    rc, out = run(snap(root / "rk-new1", "Rust follows MIT", "exact", reworded), good)
    if rc != 0 or "info ledger row reworded (check cell): docs/parity/a1-tgs.md a.c:1" not in out \
            or "ledger row removed" in out:
        raise SystemExit(f"hygiene-diff --self-test: a listed check-cell reword must be information: {out[-300:]}")
    n += 1
    rc, out = run(snap(root / "rk-new2", "Rust follows MIT", "exact", reworded), None)
    if rc == 0 or "FAIL ledger row removed: a.c:1\tthe W1 sweep aligned" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a check-cell reword without an entry must fail: {out[-300:]}")
    n += 1
    unused = entries("rk-unused.txt", f"docs/parity/a1-tgs.md\tb.c:2\tcheck b = check b2\tblob={blob}")
    rc, out = run(snap(root / "rk-new3", "the W1 sweep aligned", "exact", base), unused)
    if rc == 0 or "FAIL ledger rekey entry unused: docs/parity/a1-tgs.md b.c:2" not in out:
        raise SystemExit(f"hygiene-diff --self-test: an unused rekey entry must fail: {out[-300:]}")
    n += 1
    rc, out = run(snap(root / "rk-new4", "Rust follows MIT", "deviation", regraded), good)
    if rc == 0 or "with a changed verdict or proof: docs/parity/a1-tgs.md a.c:1" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a reword that also regrades must fail: {out[-300:]}")
    n += 1
    rc, out = run(snap(root / "rk-new5", "Rust follows MIT", "exact", reproved), good)
    if rc == 0 or "with a changed verdict or proof: docs/parity/a1-tgs.md a.c:1" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a reword that also re-proves must fail: {out[-300:]}")
    n += 1
    # A listed proof span excuses exactly that substitution in the proof cell, nothing more.
    respan = commit("| a.c:1 | Rust follows MIT | m | r | e | exact | pa x |\n".replace("pa x", "pq"))
    spanned = entries("rk-span.txt", f"docs/parity/a1-tgs.md\ta.c:1\tthe W1 sweep aligned = Rust follows MIT\t"
                                     f"blob={blob}\tproof: pa = pq")
    rc, out = run(snap(root / "rk-new7", "Rust follows MIT", "exact", respan), spanned)
    if rc != 0 or "info ledger row reworded (check cell): docs/parity/a1-tgs.md a.c:1" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a reword with its listed proof span must be information: {out[-300:]}")
    n += 1
    beyond = commit("| a.c:1 | Rust follows MIT | m | r | e | exact | pq extra |\n")
    rc, out = run(snap(root / "rk-new8", "Rust follows MIT", "exact", beyond), spanned)
    if rc == 0 or "with a changed verdict or proof: docs/parity/a1-tgs.md a.c:1" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a proof change beyond the listed span must fail: {out[-300:]}")
    n += 1
    nospan = entries("rk-nospan.txt", f"docs/parity/a1-tgs.md\ta.c:1\tthe W1 sweep aligned = Rust follows MIT\t"
                                      f"blob={blob}\tproof: zz = pq")
    rc, out = run(snap(root / "rk-new9", "Rust follows MIT", "exact", respan), nospan)
    if rc == 0 or "proof span not once in the old proof cell: docs/parity/a1-tgs.md a.c:1" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a proof span that does not occur must fail: {out[-300:]}")
    n += 1
    # A check cell may hold " = " itself: the entry is split where the keys match.
    eq_base = commit("| a.c:1 | `e = f` in W1 | m | r | e | exact | pa |\n")
    eq_new = commit("| a.c:1 | `e = f` here | m | r | e | exact | pa |\n")
    eq_blob = subprocess.run(["git", "rev-parse", f"{eq_base}:docs/parity/a1-tgs.md"], cwd=repo, capture_output=True,
                             text=True, check=True).stdout.strip()
    eq_old = snap(root / "rk-old10", "`e = f` in W1", "exact", eq_base)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main_compare(eq_old, snap(root / "rk-new10", "`e = f` here", "exact", eq_new), old_git=str(repo),
                          ledger_rekey=entries("rk-eq.txt", f"docs/parity/a1-tgs.md\ta.c:1\t`e = f` in W1 = `e = f` here"
                                                            f"\tblob={eq_blob}"))
    if rc != 0 or "info ledger row reworded (check cell): docs/parity/a1-tgs.md a.c:1" not in buf.getvalue():
        raise SystemExit(f"hygiene-diff --self-test: a check cell holding ' = ' must re-key: {buf.getvalue()[-300:]}")
    n += 1
    # The cite field may re-key the cite as well: with its entry the row is reworded; without it, removed.
    ct_base = commit("| a.c:1 (step E3) | same check | m | r | e | exact | pa |\n")
    ct_new = commit("| a.c:1 | same check | m | r | e | exact | pa |\n")
    ct_blob = subprocess.run(["git", "rev-parse", f"{ct_base}:docs/parity/a1-tgs.md"], cwd=repo, capture_output=True,
                             text=True, check=True).stdout.strip()

    def ct_snap(d: pathlib.Path, cite: str, sha: str) -> pathlib.Path:
        _write_snap(d, ["a.sh\techo\tkeep"])
        (d / "ledger-rows.txt").write_text(
            f"#\n{cite}\tsame check\texact\tdocs/parity/a1-tgs.md\nb.c:2\tcheck b\texact\tdocs/parity/a1-tgs.md\n",
            encoding="utf-8")
        (d / "provenance.txt").write_text(f"==== provenance ====\nhead_sha={sha}\n", encoding="utf-8")
        return d

    ct_old = ct_snap(root / "rk-old11", "a.c:1 (step E3)", ct_base)
    for label, rk, want_rc, needle in (
        ("with its entry", entries("rk-ct.txt", f"docs/parity/a1-tgs.md\ta.c:1 (step E3) = a.c:1\t"
                                                f"same check = same check\tblob={ct_blob}"),
         0, "info ledger row reworded (check cell): docs/parity/a1-tgs.md a.c:1"),
        ("without an entry", None, 1, "FAIL ledger row removed: a.c:1 (step E3)\tsame check"),
    ):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main_compare(ct_old, ct_snap(root / f"rk-new11-{want_rc}", "a.c:1", ct_new), old_git=str(repo),
                              ledger_rekey=rk)
        if (rc == 0) != (want_rc == 0) or needle not in buf.getvalue():
            raise SystemExit(f"hygiene-diff --self-test: a cite re-key {label}: {buf.getvalue()[-300:]}")
        n += 1
    stale = entries("rk-stale.txt", f"docs/parity/a1-tgs.md\ta.c:1\tthe W1 sweep aligned = Rust follows MIT\tblob={'0' * 40}")
    rc, out = run(snap(root / "rk-new6", "Rust follows MIT", "exact", reworded), stale)
    if rc == 0 or "FAIL ledger rekey entry not pinned to docs/parity/a1-tgs.md at the old tree" not in out:
        raise SystemExit(f"hygiene-diff --self-test: a rekey entry pinned to another blob must fail: {out[-300:]}")
    n += 1
    return n


def _self_test() -> int:
    """Red on (file,kind,tag) multiplicity drop; gate_rc: not compared when no timings."""
    n = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        n += _self_test_quality(root)
        n += _self_test_duplicates(root)
        n += _self_test_renames(root)
        n += _self_test_cell_reach(root)
        n += _self_test_ledger_rekey(root)
        old, new = root / "old", root / "new"
        _write_snap(
            old,
            [
                "a.sh\techo\tcell-x",
                "b.sh\techo\tcell-x",
                "a.sh\techo\tkeep",
            ],
        )
        _write_snap(
            new,
            [
                "a.sh\techo\tcell-x",
                "a.sh\techo\tkeep",
            ],
        )
        rc = main_compare(old, new)
        if rc == 0:
            raise SystemExit("hygiene-diff --self-test: multiplicity drop must fail")
        n += 1

        # --dead waives an `echo` tag with a reason; never a section, never unlisted.
        dead_map = root / "dead.txt"
        dead_map.write_text(
            "==== provenance ====\nhead_sha=abc\ntree_sha=def\ndirty=no\n"
            "image=sha256:0123 2026-09-12T16:52:22-05:00\nacl_sha256_tree=5668\n"
            "# a provenance.sh-stamped map still parses\nMIT_DEAD_PORT: unused constant, S1 commit 4\n",
            encoding="utf-8",
        )
        dead_old, dead_new = root / "dead-old", root / "dead-new"
        _write_snap(dead_old, ["a.sh\techo\tMIT_DEAD_PORT", "b.sh\techo\tMIT_DEAD_PORT", "a.sh\techo\tkeep"])
        _write_snap(dead_new, ["a.sh\techo\tkeep"])
        _must_fail(
            dead_old, dead_new, "unlisted echo tag removal", needle="FAIL gate cell tag removed: echo\tMIT_DEAD_PORT"
        )
        n += 1
        _must_pass(dead_old, dead_new, "--dead echo tag removal", dead_path=dead_map)
        n += 1
        sect_old, sect_new = root / "sect-old", root / "sect-new"
        _write_snap(sect_old, ["a.sh\tsection\tMIT_DEAD_PORT", "a.sh\techo\tkeep"])
        _write_snap(sect_new, ["a.sh\techo\tkeep"])
        _must_fail(
            sect_old, sect_new, "--dead listed section tag removal",
            needle="FAIL gate cell tag removed: section\tMIT_DEAD_PORT", dead_path=dead_map,
        )
        n += 1

        moved_old, moved_new = root / "moved-old", root / "moved-new"
        _write_snap(moved_old, ["a.sh\techo\tcell-y"])
        _write_snap(moved_new, ["b.sh\techo\tcell-y"])
        if main_compare(moved_old, moved_new) != 0:
            raise SystemExit("hygiene-diff --self-test: file move must not fail")
        n += 1

        # Ledger rows keyed by MIT cite + check: a row that changes file is moved (green,
        # counted), a row that disappears is removed (red), and an old two-column snapshot is
        # compared by cite alone.
        led_old, led_new = root / "led-old", root / "led-new"
        _write_snap(led_old, ["a.sh\techo\tkeep"])
        _write_snap(led_new, ["a.sh\techo\tkeep"])
        rows_old = "a.c:1\tcheck a\texact\tdocs/mit-parity-ledger.md\nb.c:2\tcheck b\tdeviation\tdocs/mit-parity-ledger.md\n"
        (led_old / "ledger-rows.txt").write_text("#\n" + rows_old, encoding="utf-8")
        (led_new / "ledger-rows.txt").write_text(
            "#\n" + rows_old.replace("docs/mit-parity-ledger.md", "docs/parity/a1-tgs.md"), encoding="utf-8"
        )
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main_compare(led_old, led_new)
        if rc != 0 or "ledger rows moved: 2" not in buf.getvalue():
            raise SystemExit("hygiene-diff --self-test: a ledger row that changes file must read moved")
        n += 1
        (led_new / "ledger-rows.txt").write_text(
            "#\na.c:1\tcheck a\texact\tdocs/parity/a1-tgs.md\n", encoding="utf-8"
        )
        _must_fail(led_old, led_new, "a ledger row that disappears", needle="FAIL ledger row removed: b.c:2\tcheck b")
        n += 1
        (led_old / "ledger-rows.txt").write_text("#\na.c:1\texact\nb.c:2\tdeviation\n", encoding="utf-8")
        (led_new / "ledger-rows.txt").write_text(
            "#\n" + rows_old.replace("docs/mit-parity-ledger.md", "docs/parity/a1-tgs.md"), encoding="utf-8"
        )
        _must_pass(led_old, led_new, "an old two-column ledger snapshot compared by cite")
        n += 1
        # A cite the ledger holds twice stays two rows under the cite-only compare: dropping one fails.
        (led_old / "ledger-rows.txt").write_text("#\nk.c:1\texact\nk.c:1\tdeviation\n", encoding="utf-8")
        (led_new / "ledger-rows.txt").write_text(
            "#\nk.c:1\tcheck x\texact\tdocs/parity/a1-tgs.md\nk.c:1\tcheck y\tdeviation\tdocs/parity/a1-tgs.md\n",
            encoding="utf-8",
        )
        _must_pass(led_old, led_new, "a cite held twice, compared by cite")
        n += 1
        (led_new / "ledger-rows.txt").write_text("#\nk.c:1\tcheck x\texact\tdocs/parity/a1-tgs.md\n", encoding="utf-8")
        _must_fail(led_old, led_new, "one of a cite's two rows dropped", needle="FAIL ledger row removed: k.c:1 (2 row(s) -> 1)")
        n += 1
        # The regrade check compares the grade (the first verdict word): a reworded qualifier is
        # listed, even one that names another grade inside the parenthetical; a new grade fails.
        (led_old / "ledger-rows.txt").write_text(
            "#\na.c:1\tcheck a\tdeviation (R2-D1: cache first)\tdocs/parity/a1-tgs.md\n", encoding="utf-8"
        )
        (led_new / "ledger-rows.txt").write_text(
            "#\na.c:1\tcheck a\tdeviation (the cache answers first; not exact)\tdocs/parity/a1-tgs.md\n",
            encoding="utf-8",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main_compare(led_old, led_new)
        if (
            rc != 0
            or "ledger verdict qualifiers reworded: 1" not in buf.getvalue()
            or "qualifier reworded: a.c:1\tcheck a" not in buf.getvalue()
        ):
            raise SystemExit("hygiene-diff --self-test: a reworded verdict qualifier must pass and be listed")
        n += 1
        (led_new / "ledger-rows.txt").write_text(
            "#\na.c:1\tcheck a\texact (the cache answers first)\tdocs/parity/a1-tgs.md\n", encoding="utf-8"
        )
        _must_fail(
            led_old, led_new, "a ledger row whose grade changes", needle="FAIL ledger row regraded: a.c:1\tcheck a"
        )
        n += 1

        none_old, none_new = root / "none-old", root / "none-new"
        _write_snap(none_old, ["a.sh\techo\tkeep"])
        _write_snap(none_new, ["a.sh\techo\tkeep"])
        # Capture stdout for the not-compared line.
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main_compare(none_old, none_new)
        if rc != 0:
            raise SystemExit("hygiene-diff --self-test: identical snaps must be ok")
        if "gate_rc: not compared" not in buf.getvalue():
            raise SystemExit("hygiene-diff --self-test: missing gate_rc: not compared")
        n += 1
    return n


_LEDGER_GRADES = ("exact", "stricter-documented", "deviation", "absent", "deferred")


def ledger_grade(verdict: str) -> str:
    """A verdict cell's grade: its first verdict word, the ledger tally's counting rule
    (`exact (unit)` is `exact`); the parenthetical is a qualifier. A cell with no known grade
    word is its own grade."""
    v = verdict.strip()
    for grade in _LEDGER_GRADES:
        if v == grade or v.startswith(grade + " ") or v.startswith(grade + "("):
            return grade
    return v


def load_ledger_rows(path: pathlib.Path) -> list[tuple[str, str | None, str, str | None]]:
    """`ledger-rows.txt` as (MIT cite, check, verdict, file) rows, duplicates kept.

    A snapshot from before the cite + check key has two columns (cite, verdict): no check, no file.
    """
    rows: list[tuple[str, str | None, str, str | None]] = []
    for ln in load_data_lines(path):
        parts = ln.split("\t")
        if len(parts) >= 4:
            rows.append((parts[0], parts[1], parts[2], parts[3]))
        elif len(parts) >= 2:
            rows.append((parts[0], None, parts[1], None))
    return rows


def load_ledger_rekey(
    path: pathlib.Path | None,
) -> list[tuple[str, str, str, str, tuple[str, str] | None]]:
    """`--ledger-rekey`: `path<TAB>cite<TAB>old check = new check<TAB>blob=<git blob of path at the base>`, with an
    optional fifth column `proof: <old span> = <new span>` naming the one substitution the row's proof cell may
    carry, as (path, cite, the `old check = new check` text, blob, (old span, new span) or None). The cite field may
    be `old cite = new cite` to re-key the cite too. A cell can itself hold " = ", so both texts are split where
    the keys match, at compare time (`_rekey_splits`)."""
    out: list[tuple[str, str, str, str, tuple[str, str] | None]] = []
    if path is None:
        return out
    for n, ln in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not ln.strip() or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        proof = None
        if len(parts) == 5 and parts[4].startswith("proof: ") and " = " in parts[4]:
            old_span, new_span = parts[4][len("proof: "):].split(" = ", 1)
            proof = (old_span, new_span)
            parts = parts[:4]
        if len(parts) != 4 or " = " not in parts[2] or not re.fullmatch(r"blob=[0-9a-f]{40}", parts[3]):
            raise SystemExit(
                f"{path}:{n}: want path<TAB>cite<TAB>old check = new check<TAB>blob=<40 hex>[<TAB>proof: old = new]"
            )
        out.append((parts[0], parts[1], parts[2], parts[3][5:], proof))
    return out


def _rekey_splits(text: str) -> list[tuple[str, str]]:
    """Every (old check, new check) that `old check = new check` can mean: one per " = " in the text."""
    return [(text[:m.start()], text[m.end():]) for m in re.finditer(" = ", text)]


def _ledger_cells(line: str) -> list[str]:
    """A ledger table row's cells (ci-policy's `_split_ledger_row` rule: `|` not after a backslash)."""
    inner = line.strip()
    inner = inner[1:] if inner.startswith("|") else inner
    inner = inner[:-1] if inner.endswith("|") else inner
    return [c.strip() for c in re.split(r"(?<!\\)\|", inner)]


def _ledger_row_cells(text: str, cite: str, check: str) -> list[str] | None:
    for line in text.splitlines():
        if line.startswith("|"):
            cells = _ledger_cells(line)
            if len(cells) >= 7 and cells[0] == cite and cells[1] == check:
                return cells
    return None


def _git_out(git_dir: str, *args: str) -> str | None:
    r = subprocess.run(["git", "-C", git_dir, *args], capture_output=True, text=True, check=False)
    return r.stdout if r.returncode == 0 else None


def _snapshot_head(snap: pathlib.Path) -> str | None:
    """The head_sha a snapshot is stamped with (its provenance.txt), or None."""
    prov = snap / "provenance.txt"
    if not prov.is_file():
        return None
    m = re.search(r"^head_sha=([0-9a-f]{7,40})$", prov.read_text(encoding="utf-8", errors="replace"), re.M)
    return m.group(1) if m else None


def _tree_shell_texts(rev: str, git_dir: str | None = None) -> dict[str, str] | None:
    """scripts/*.sh and scripts/lib/*.sh at rev (keyed by repo path), or None when git cannot read it."""
    repo = git_dir or str(pathlib.Path(__file__).resolve().parent.parent)
    ls = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--name-only", rev, "scripts"],
                        capture_output=True, text=True, check=False)
    if ls.returncode != 0:
        return None
    out: dict[str, str] = {}
    for name in ls.stdout.split():
        if re.fullmatch(r"scripts/[^/]+\.sh|scripts/lib/[^/]+\.sh", name):
            r = subprocess.run(["git", "-C", repo, "show", f"{rev}:{name}"], capture_output=True, text=True,
                               errors="replace", check=False)
            if r.returncode != 0:
                return None
            out[name] = r.stdout
    return out


_INVENTORY = None


def _inventory():
    """scripts/lib/hygiene_inventory.py as a module (its gate_cell_reach is the one reachability rule)."""
    global _INVENTORY
    if _INVENTORY is None:
        import importlib.util
        import sys as _sys

        path = pathlib.Path(__file__).resolve().parent / "lib" / "hygiene_inventory.py"
        spec = importlib.util.spec_from_file_location("hygiene_inventory_for_diff", path)
        mod = importlib.util.module_from_spec(spec)
        _sys.modules["hygiene_inventory_for_diff"] = mod
        spec.loader.exec_module(mod)
        _INVENTORY = mod
    return _INVENTORY


def main_compare(
    old: pathlib.Path,
    new: pathlib.Path,
    renames_path=None,
    duplicates_path=None,
    dead_path=None,
    accept_rise=None,
    old_rev=None,
    old_git=None,
    ledger_rekey=None,
) -> int:
    class NS:
        pass

    args = NS()
    args.old = old
    args.new = new
    args.renames = renames_path
    args.duplicates = duplicates_path
    args.dead = dead_path
    args.accept_rise = accept_rise
    args.old_rev = old_rev
    args.old_git = old_git
    args.ledger_rekey = ledger_rekey
    return _compare(args)


def _compare(args) -> int:
    old, new = args.old, args.new
    if not old.is_dir() or not new.is_dir():
        print(f"hygiene-diff: need directories, got {old} {new}", file=sys.stderr)
        return 2

    failed = 0
    try:
        renames = load_renames_map(args.renames)
        duplicates = load_duplicates_map(args.duplicates)
        rekey = load_ledger_rekey(getattr(args, "ledger_rekey", None))
    except SystemExit as e:
        print(f"FAIL {e}")
        return 1
    dead = load_map(getattr(args, "dead", None), ":")

    def fail(msg: str) -> None:
        nonlocal failed
        failed += 1
        print(f"FAIL {msg}")

    def info(msg: str) -> None:
        print(f"info {msg}")

    old_tests = load_set(old / "tests.txt")
    new_tests = load_set(new / "tests.txt")
    mapped_old: set[str] = set()
    for t in old_tests:
        if t in duplicates:
            kept = duplicates[t]
            if kept in new_tests:
                info(f"test removed as duplicate {t} = {kept}")
                continue
            fail(f"test removed: {t} (duplicate target missing: {kept})")
            continue
        mapped_old.add(apply_rename(t, renames))
    removed_tests = mapped_old - new_tests
    for t in sorted(removed_tests):
        fail(f"test removed: {t}")
    added_tests = new_tests - mapped_old
    if added_tests:
        info(f"tests added: {len(added_tests)}")

    old_cells = load_set(old / "gates.txt")
    new_cells = load_set(new / "gates.txt")
    # workflow tags may move with a job rename; still fail on section/echo/flow loss.
    # A cell may move files (W2: the tag survives). Identity is (kind, tag).
    def cell_key(line: str) -> tuple[str, str, str]:
        parts = line.split("\t")
        if len(parts) < 3:
            return ("", "", line)
        return parts[0], parts[1], parts[2]

    def cell_tag(line: str) -> tuple[str, str]:
        _fn, kind, tag = cell_key(line)
        return kind, tag

    # A cell lost from a gate is red unless the tool proves, from the old tree by the inventory's own
    # reachability rule, that the old gate never ran it (it sat only in an unreachable function). A
    # snapshot in the reachability format (dead-cells.txt present) already left dead cells out.
    old_by: dict[tuple[str, str], set[str]] = {}
    new_by: dict[tuple[str, str], set[str]] = {}
    for c in old_cells:
        fn, kind, tag = cell_key(c)
        if kind != "workflow":
            old_by.setdefault((kind, tag), set()).add(fn)
    for c in new_cells:
        fn, kind, tag = cell_key(c)
        if kind != "workflow":
            new_by.setdefault((kind, tag), set()).add(fn)
    old_reach: dict[str, object] = {}

    def proven_dead(gate: str, kind: str, tag: str) -> tuple[bool, str]:
        if (old / "dead-cells.txt").is_file():
            return False, "the old snapshot counts reachable cells only"
        if "err" not in old_reach and "files" not in old_reach:
            rev = getattr(args, "old_rev", None) or _snapshot_head(old)
            files = _tree_shell_texts(rev, getattr(args, "old_git", None)) if rev else None
            if files is None:
                old_reach["err"] = "cannot read the old tree" + (f" at {rev}" if rev else " (no head_sha, no --old-rev)")
            else:
                old_reach["files"] = files
        if "err" in old_reach:
            return False, str(old_reach["err"])
        files = old_reach["files"]
        if f"scripts/{gate}" not in files:
            return False, f"{gate} is not in the old tree"
        cells, _lib, dead = _inventory().gate_cell_reach(gate, files)
        if (kind, tag) in cells:
            return False, f"{gate} reaches it at the old tree"
        fns = sorted({fn for fn, _line, k, tg in dead if (k, tg) == (kind, tag)})
        if not fns:
            return False, f"not a cell of {gate} at the old tree"
        return True, ",".join(fns)

    for (kind, tag), files_old in sorted(old_by.items()):
        files_new = new_by.get((kind, tag), set())
        drop = len(files_old) - len(files_new)
        if drop <= 0:
            continue
        proven = []
        for gate in sorted(files_old - files_new):
            ok, why = proven_dead(gate, kind, tag)
            if ok:
                proven.append((gate, why))
        if len(proven) >= drop:
            for gate, why in proven:
                info(f"gate cell removed as dead at the old tree: {gate}\t{why}\t{kind}\t{tag}")
            continue
        if kind == "echo" and dead.get(tag):
            info(f"gate cell tag removed as dead: {kind}\t{tag} ({dead[tag]})")
            continue
        if not files_new:
            fail(f"gate cell tag removed: {kind}\t{tag}")
        else:
            fail(f"gate cell multiplicity drop: {kind}\t{tag} {len(files_old)} -> {len(files_new)}")
    added = set(new_by) - set(old_by)
    if added:
        info(f"gate cell tags added: {len(added)}")
    old_keys = {cell_key(c) for c in old_cells}
    via_lib: collections.Counter[tuple[str, str]] = collections.Counter()
    for line in load_data_lines(new / "lib-cells.txt") if (new / "lib-cells.txt").is_file() else []:
        parts = line.split("\t")
        if len(parts) == 5 and (parts[0], parts[3], parts[4]) not in old_keys:
            via_lib[(parts[0], parts[2])] += 1
    for (gate, fn), n in sorted(via_lib.items()):
        info(f"cells attributed through lib: {gate}, {fn}, {n}")
    old_files: dict[tuple[str, str], set[str]] = {}
    new_files: dict[tuple[str, str], set[str]] = {}
    for c in old_cells:
        fn, kind, tag = cell_key(c)
        if kind == "workflow":
            continue
        old_files.setdefault((kind, tag), set()).add(fn)
    for c in new_cells:
        fn, kind, tag = cell_key(c)
        if kind == "workflow":
            continue
        new_files.setdefault((kind, tag), set()).add(fn)
    for key in sorted(set(old_files) & set(new_files)):
        if old_files[key] != new_files[key]:
            info(
                f"gate cell moved {key[0]}\t{key[1]}: "
                f"{sorted(old_files[key])} -> {sorted(new_files[key])}"
            )

    for fname, label in (
        ("diffsend.txt", "diffsend case"),
        ("client-differential-flows.txt", "client-differential flow"),
    ):
        old_s, new_s = load_set(old / fname), load_set(new / fname)
        for item in sorted(old_s - new_s):
            fail(f"{label} removed: {item}")
        extra = new_s - old_s
        if extra:
            info(f"{label}s added: {len(extra)}")

    old_rows = load_ledger_rows(old / "ledger-rows.txt")
    new_rows = load_ledger_rows(new / "ledger-rows.txt")
    if any(r[1] is None for r in old_rows) or any(r[1] is None for r in new_rows):
        # A snapshot from before the cite + check key: compare the verdicts under each cite as a
        # multiset, so a cite the ledger holds twice is not merged into one row.
        if any(r[1] is None for r in old_rows) != any(r[1] is None for r in new_rows):
            info("ledger rows compared by MIT cite alone (one snapshot predates the cite + check key)")
        old_by: dict[str, list[str]] = collections.defaultdict(list)
        new_by: dict[str, list[str]] = collections.defaultdict(list)
        for cite, _check, verdict, _where in old_rows:
            old_by[cite].append(verdict)
        for cite, _check, verdict, _where in new_rows:
            new_by[cite].append(verdict)
        for cite, verdicts in old_by.items():
            got = new_by.get(cite, [])
            if len(got) < len(verdicts):
                fail(f"ledger row removed: {cite} ({len(verdicts)} row(s) -> {len(got)})")
                continue
            lost = collections.Counter(map(ledger_grade, verdicts)) - collections.Counter(map(ledger_grade, got))
            if lost:
                fail(f"ledger row regraded: {cite} lost {sorted(lost.elements())}")
        old_led: dict[tuple[str, str | None], tuple[str, str | None]] = {}
        new_led: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    else:
        old_led = {(r[0], r[1]): (r[2], r[3]) for r in old_rows}
        new_led = {(r[0], r[1]): (r[2], r[3]) for r in new_rows}
    # A listed check-cell reword (--ledger-rekey): the old key gone, the new key present, the verdict cell unchanged
    # and the proof cell unchanged but for the entry's one listed span. It counts in neither removed nor added; an entry that matches no such pair is red.
    git_dir = getattr(args, "old_git", None) or str(pathlib.Path(__file__).resolve().parent.parent)
    old_head = getattr(args, "old_rev", None) or _snapshot_head(old)
    new_head = _snapshot_head(new)
    for path, cite_field, pair, blob, proof_span in rekey:
        what = f"{path} {cite_field}"
        cites = _rekey_splits(cite_field) + [(cite_field, cite_field)]
        splits = [
            (oc, o, nc, n) for oc, nc in cites for o, n in _rekey_splits(pair)
            if (oc, o) in old_led and (oc, o) not in new_led and (nc, n) in new_led and (nc, n) not in old_led
        ]
        if len(splits) > 1:
            fail(f"ledger rekey entry ambiguous (" + str(len(splits)) + f" ways to split it): {what}")
            continue
        if not splits:
            fail(f"ledger rekey entry unused: {what}")
            continue
        old_cite, old_check, new_cite, new_check = splits[0]
        what = f"{path} {new_cite}"
        k_old, k_new = (old_cite, old_check), (new_cite, new_check)
        pinned = _git_out(git_dir, "rev-parse", f"{old_head}:{path}") if old_head else None
        if pinned is None or pinned.strip() != blob:
            fail(f"ledger rekey entry not pinned to {path} at the old tree: {what}")
            continue
        old_doc = _git_out(git_dir, "cat-file", "blob", blob)
        new_doc = _git_out(git_dir, "show", f"{new_head}:{path}") if new_head else None
        old_cells = _ledger_row_cells(old_doc or "", old_cite, old_check)
        new_cells = _ledger_row_cells(new_doc or "", new_cite, new_check)
        if old_cells is None or new_cells is None:
            fail(f"ledger rekey row not found in {path} at the old or new tree: {what}")
            continue
        old_proof = old_cells[6]
        if proof_span is not None:
            if old_proof.count(proof_span[0]) != 1:
                fail(f"ledger rekey proof span not once in the old proof cell: {what}")
                continue
            old_proof = old_proof.replace(proof_span[0], proof_span[1])
        if old_led[k_old][0] != new_led[k_new][0] or old_proof != new_cells[6]:
            fail(f"ledger row reworded (check cell) with a changed verdict or proof: {what}")
            continue
        info(f"ledger row reworded (check cell): {what}")
        del old_led[k_old]
        del new_led[k_new]
    moved = 0
    requalified: list[str] = []
    for key, (verdict, where) in old_led.items():
        label = key[0] if key[1] is None else f"{key[0]}\t{key[1]}"
        if key not in new_led:
            fail(f"ledger row removed: {label}\t{verdict}")
            continue
        new_verdict, new_where = new_led[key]
        if ledger_grade(new_verdict) != ledger_grade(verdict):
            fail(f"ledger row regraded: {label} {verdict} -> {new_verdict}")
        elif new_verdict != verdict:
            requalified.append(label)
        if where and new_where and where != new_where:
            moved += 1
    if moved:
        info(f"ledger rows moved: {moved}")
    if requalified:
        info(f"ledger verdict qualifiers reworded: {len(requalified)}")
        for label in requalified:
            info(f"  qualifier reworded: {label}")
    if len(new_rows) > len(old_rows):
        info(f"ledger rows added: {len(new_rows) - len(old_rows)}")

    old_rc = load_gate_rc(old / "timings.tsv") or load_gate_rc(old / "checkpoint" / "timings.tsv")
    new_rc = load_gate_rc(new / "timings.tsv") or load_gate_rc(new / "checkpoint" / "timings.tsv")
    if old_rc and new_rc:
        for gate, rc in old_rc.items():
            if rc == 0 and new_rc.get(gate, 0) not in (0, None) and new_rc.get(gate, 0) != 0:
                # unavailable (2) is not a product failure if it was 0 before — that is a regression.
                fail(f"gate_rc 0 -> {new_rc[gate]}: {gate}")
        both = sorted(set(old_rc) & set(new_rc))
        nonzero = [f"{g}={new_rc[g]}" for g in both if new_rc[g] != 0]
        info(
            f"gate_rc: {len(both)} gates compared, {len(nonzero)} non-zero in new"
            + (f" ({', '.join(nonzero)})" if nonzero else "")
        )
    elif old_rc or new_rc:
        info("gate_rc: only one side has timings.tsv (informational)")
    else:
        info("gate_rc: not compared")

    def int_or_none(d: dict[str, str], k: str) -> int | None:
        v = d.get(k)
        if v is None or v == "skipped" or v == "na":
            return None
        try:
            return int(v)
        except ValueError:
            return None

    old_q, new_q = kv(old / "quality.txt"), kv(new / "quality.txt")
    waivers = parse_accept_rise(getattr(args, "accept_rise", None))
    waived_used: set[str] = set()
    for key in (
        "allow",
        "allow_sites",
        "rustfmt_skip",
        "unwrap_expect_panic_src",
        "traces_untracked",
        "clippy_warnings",
        "doc_warnings",
        "fmt_files",
        "shellcheck_findings",
        "undocumented_pub",
    ):
        a, b = int_or_none(old_q, key), int_or_none(new_q, key)
        if a is not None and b is not None and b > a:
            delta = b - a
            if key in waivers and waivers[key][0] == delta:
                waived_used.add(key)
                info(f"quality {key} rose {a} -> {b} accepted ({waivers[key][1]})")
            else:
                fail(f"quality {key} rose {a} -> {b}")
        elif a is not None and b is not None and b != a:
            info(f"quality {key} {a} -> {b}")
    for key, (n, reason) in waivers.items():
        if key not in waived_used:
            fail(f"accept-rise {key}={n}:{reason} unused")
    for key in ("fmt_rc", "clippy_rc", "doc_rc", "doctest_rc", "shellcheck_rc"):
        a, b = int_or_none(old_q, key), int_or_none(new_q, key)
        if a == 0 and b not in (None, 0):
            fail(f"quality {key} 0 -> {b}")

    def _norm_finding(line: str) -> str:
        # shellcheck `file:line:col: level: message [SCnnnn]` -> `file: level: message [SCnnnn]`;
        # undocumented `file:line<TAB>message` -> `file<TAB>message` (line numbers shift).
        if "\t" in line:
            where, msg = line.split("\t", 1)
            return f"{where.rsplit(':', 1)[0]}\t{msg}"
        parts = line.split(":", 3)
        return f"{parts[0]}:{parts[3].strip()}" if len(parts) == 4 else line

    for fname, key, label in (
        ("shellcheck.txt", "shellcheck_findings", "shellcheck finding"),
        ("undocumented-pub-items.txt", "undocumented_pub", "undocumented item"),
    ):
        a, b = int_or_none(old_q, key), int_or_none(new_q, key)
        if a is None or b is None or b <= a:
            continue
        old_s = {_norm_finding(ln) for ln in load_data_lines(old / fname)}
        new_l = [ln for ln in load_data_lines(new / fname) if _norm_finding(ln) not in old_s]
        for ln in new_l[:20]:
            info(f"new {label}: {ln}")

    for fname, label in (
        ("crates.txt", "package"),
        ("binaries.txt", "binary"),
        ("deps-declared.txt", "declared dependency"),
        ("deps.txt", "resolved dependency"),
    ):
        old_s, new_s = load_set(old / fname), load_set(new / fname)
        if not old_s and not new_s:
            continue
        for item in sorted(old_s - new_s):
            info(f"{label} removed: {item}")
        for item in sorted(new_s - old_s):
            info(f"{label} added: {item}")

    def table(path: pathlib.Path) -> dict[str, list[str]]:
        rows: dict[str, list[str]] = {}
        for ln in load_data_lines(path):
            parts = ln.split("\t")
            rows[parts[0]] = parts[1:]
        return rows

    old_loc, new_loc = table(old / "loc-crates.txt"), table(new / "loc-crates.txt")
    for pkg in sorted(set(old_loc) | set(new_loc)):
        a, b = old_loc.get(pkg), new_loc.get(pkg)
        if a is None or b is None or a == b:
            continue
        # columns: files loc sloc comment doc blank src_loc src_test_loc tests_loc tests_in_src tests_in_tests
        names = ("files", "loc", "sloc", "comment", "doc", "blank", "src_loc", "src_test_loc", "tests_loc", "tests_in_src", "tests_in_tests")
        deltas = [f"{n} {x}->{y}" for n, x, y in zip(names, a, b) if x != y]
        info(f"loc {pkg}: " + ", ".join(deltas))
    old_pub, new_pub = table(old / "pub-items.txt"), table(new / "pub-items.txt")
    for pkg in sorted(set(old_pub) | set(new_pub)):
        a, b = old_pub.get(pkg), new_pub.get(pkg)
        if a is None or b is None or a == b:
            continue
        info(f"pub {pkg}: pub {a[0]}->{b[0]}, restricted {a[1]}->{b[1]}")
    old_as, new_as = table(old / "gate-asserts.txt"), table(new / "gate-asserts.txt")
    for gate in sorted(set(old_as) & set(new_as)):
        a, b = old_as[gate], new_as[gate]
        if a == b:
            continue
        names = ("die", "exit_1", "grep_q", "diff_sub")
        dropped = [f"{n} {x}->{y}" for n, x, y in zip(names, a, b) if int(y) < int(x)]
        if dropped:
            info(f"gate asserts dropped {gate}: " + ", ".join(dropped))
    for key in (
        "loc",
        "sloc",
        "comment_lines",
        "comment_anchor_lines",
        "comment_prose_lines",
        "doc_lines",
        "src_test_loc",
        "tests_in_src",
        "tests_in_tests",
        "doctests",
        "pub_items",
        "pub_restricted",
        "allow_sites",
        "process_history_comments",
        "max_file_lines_src",
        "files_over_1500_src",
        "max_fn_lines_src",
        "fns_over_120_src",
        "undoc_fns_over_40_src",
        "binaries",
        "deps_declared",
        "deps_tree",
        "shellcheck_disables",
    ):
        a, b = old_q.get(key), new_q.get(key)
        if (a or b) and a != b:
            info(f"{key} {a} -> {b}")

    old_sleeps = load_data_lines(old / "sleeps.txt")
    new_sleeps = load_data_lines(new / "sleeps.txt")
    def sleep_sum(rows: list[str], kind: str) -> float:
        total = 0.0
        for row in rows:
            parts = row.split("\t")
            if len(parts) < 4:
                continue
            if kind != "all" and parts[3] != kind:
                continue
            try:
                total += float(parts[2])
            except ValueError:
                continue
        return total

    info(
        f"sleeps padding {sleep_sum(old_sleeps, 'padding'):.2f} -> "
        f"{sleep_sum(new_sleeps, 'padding'):.2f}s; proto "
        f"{sleep_sum(old_sleeps, 'proto'):.2f} -> {sleep_sum(new_sleeps, 'proto'):.2f}s"
    )
    info(
        f"cargo-build gates {len(load_data_lines(old / 'cargo-build-gates.txt'))} -> "
        f"{len(load_data_lines(new / 'cargo-build-gates.txt'))}"
    )
    info(
        f"unit sleeps {len(load_data_lines(old / 'unit-sleeps.txt'))} -> "
        f"{len(load_data_lines(new / 'unit-sleeps.txt'))}"
    )
    for key in ("rs_loc", "test_rs_files", "traces_files"):
        a, b = old_q.get(key), new_q.get(key)
        if a or b:
            info(f"{key} {a} -> {b}")

    old_n = (old / "tests.count").read_text(encoding="utf-8").strip() if (old / "tests.count").is_file() else "?"
    new_n = (new / "tests.count").read_text(encoding="utf-8").strip() if (new / "tests.count").is_file() else "?"
    info(f"tests {old_n} -> {new_n}")
    info(f"gate tags {len(old_by)} -> {len(new_by)}")
    info(f"diffsend {len(load_set(old / 'diffsend.txt'))} -> {len(load_set(new / 'diffsend.txt'))}")

    if failed:
        print(f"hygiene-diff: {failed} failure(s)")
        return 1
    print("hygiene-diff: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        n = _self_test()
        print(f"hygiene-diff: self-test ok ({n} cases)")
        return 0
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        _self_test()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("old", type=pathlib.Path)
    ap.add_argument("new", type=pathlib.Path)
    ap.add_argument(
        "--renames",
        type=pathlib.Path,
        help="old_binary<TAB>old_name -> [merged:]new_binary<TAB>new_name",
    )
    ap.add_argument(
        "--duplicates",
        type=pathlib.Path,
        help="old_binary<TAB>old_name = [merged:]new_binary<TAB>new_name",
    )
    ap.add_argument("--dead", type=pathlib.Path, help="echo tag: reason (a MIT_/RUST_ name that was never a cell)")
    ap.add_argument("--old-rev", help="the old tree's commit (default: the old snapshot's stamped head_sha), read to "
                    "prove a lost gate cell was unreachable there")
    ap.add_argument(
        "--accept-rise",
        action="append",
        default=[],
        metavar="KEY=N:REASON",
        help="allow quality KEY to rise by exactly N (recorded reason)",
    )
    ap.add_argument(
        "--ledger-rekey",
        type=pathlib.Path,
        help="path<TAB>cite<TAB>old check = new check<TAB>blob=<git blob of path at the old tree>[<TAB>proof: old = new]: "
        "a listed check-cell reword",
    )
    args = ap.parse_args()
    if args.old.is_dir() and args.new.is_dir():
        for line in provenance_header(args.old, args.new):
            print(line)
    return _compare(args)


def provenance_header(old: pathlib.Path, new: pathlib.Path) -> list[str]:
    """Stamp the compare output like any other artefact (evidence-check.py wants
    `head_sha=` and `tree_sha=`): the tree the compare ran on, from
    `scripts/lib/provenance.sh`, then the two snapshots' own stamps."""
    root = pathlib.Path(__file__).resolve().parent.parent
    env = dict(os.environ, KERBER_NO_IMAGE="1")
    scratch = pathlib.Path(env.get("KERBER_SCRATCH") or new / "scratch")
    scratch.mkdir(parents=True, exist_ok=True)
    env["KERBER_SCRATCH"] = str(scratch)
    try:
        stamp = subprocess.run(
            ["bash", "-c", ". scripts/lib/provenance.sh"],
            cwd=root, env=env, capture_output=True, text=True, check=False,
        ).stdout
    except OSError:
        stamp = ""
    keep = ("==== provenance ====", "head_sha=", "tree_sha=", "dirty=", "captured_at=")
    lines = [ln for ln in stamp.splitlines() if ln.startswith(keep)]
    if len(lines) < 3:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
        tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=root, capture_output=True, text=True).stdout.strip()
        lines = ["==== provenance ====", f"head_sha={head}", f"tree_sha={tree}", "dirty=unknown"]
    for label, d in (("old", old), ("new", new)):
        side = kv(d / "provenance.txt")
        lines.append(
            f"{label}={d} {label}_head={side.get('head_sha', '?')[:12]} {label}_dirty={side.get('dirty', '?')}"
        )
    lines.append("==== compare ====")
    return lines


if __name__ == "__main__":
    raise SystemExit(main())
