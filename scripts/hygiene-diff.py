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
  - a diffsend case, client-differential flow, or ledger row removed or regraded
  - a gate_rc that went from 0 to non-zero
  - quality counts that went up (allow=, allow_sites=, unwrap_expect_panic_src=, traces_untracked=,
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
    dead_path: pathlib.Path | None = None,
    accept_rise: list[str] | None = None,
    duplicates_path: pathlib.Path | None = None,
    renames_path: pathlib.Path | None = None,
) -> None:
    try:
        rc = _quiet_compare(
            old,
            new,
            dead_path,
            accept_rise=accept_rise,
            duplicates_path=duplicates_path,
            renames_path=renames_path,
        )
    except SystemExit:
        return
    if rc == 0:
        raise SystemExit(f"hygiene-diff --self-test: {label} must fail")


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
    _must_fail(old, new, "removed test without keyed map")
    n += 1
    good = root / "dup-good.txt"
    good.write_text("oldbin\tfoo = newbin\tbar\n", encoding="utf-8")
    _must_pass(old, new, "keyed duplicate", duplicates_path=good)
    n += 1
    name_only = root / "dup-name.txt"
    name_only.write_text("foo = bar\n", encoding="utf-8")
    _must_fail(old, new, "name-only duplicates", duplicates_path=name_only)
    n += 1
    chained = root / "dup-chain.txt"
    chained.write_text("oldbin\tfoo = midbin\tmid\nmidbin\tmid = newbin\tbar\n", encoding="utf-8")
    _must_fail(old, new, "RHS-as-LHS", duplicates_path=chained)
    n += 1
    many_old, many_new = root / "many-old", root / "many-new"
    _write_snap(many_old, ["a.sh\techo\tkeep"], tests=["a\tx", "b\ty"])
    _write_snap(many_new, ["a.sh\techo\tkeep"], tests=["c\tz"])
    no_merged = root / "dup-nomerge.txt"
    no_merged.write_text("a\tx = c\tz\nb\ty = c\tz\n", encoding="utf-8")
    _must_fail(many_old, many_new, "many-to-one without merged:", duplicates_path=no_merged)
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
    _must_fail(old, new, "removed test without keyed rename")
    n += 1
    good = root / "ren-good.txt"
    good.write_text("oldbin\tfoo -> newbin\tbar\n", encoding="utf-8")
    _must_pass(old, new, "keyed rename", renames_path=good)
    n += 1
    name_only = root / "ren-name.txt"
    name_only.write_text("foo -> bar\n", encoding="utf-8")
    _must_fail(old, new, "name-only renames", renames_path=name_only)
    n += 1
    many_old, many_new = root / "ren-many-old", root / "ren-many-new"
    _write_snap(many_old, ["a.sh\techo\tkeep"], tests=["a\tx", "b\ty"])
    _write_snap(many_new, ["a.sh\techo\tkeep"], tests=["c\tz"])
    no_merged = root / "ren-nomerge.txt"
    no_merged.write_text("a\tx -> c\tz\nb\ty -> c\tz\n", encoding="utf-8")
    _must_fail(many_old, many_new, "rename many-to-one without merged:", renames_path=no_merged)
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
    _must_fail(waiver_old, waiver_new, "quality allow_sites rose")
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
        accept_rise=["allow_sites=1: unused"],
    )
    n += 1
    for i, (label, old_q, new_q) in enumerate(red):
        old, new = root / f"red{i}-old", root / f"red{i}-new"
        _write_snap(old, ["a.sh\techo\tkeep"], quality=old_q)
        _write_snap(new, ["a.sh\techo\tkeep"], quality=new_q)
        _must_fail(old, new, f"quality {label}")
        n += 1
    for i, (label, old_q, new_q) in enumerate(green):
        old, new = root / f"green{i}-old", root / f"green{i}-new"
        _write_snap(old, ["a.sh\techo\tkeep"], quality=old_q)
        _write_snap(new, ["a.sh\techo\tkeep"], quality=new_q)
        _must_pass(old, new, f"quality {label}")
        n += 1
    old, new = root / "bin-old", root / "bin-new"
    _write_snap(old, ["a.sh\techo\tkeep"], binaries=["krb5-kdc\tkrb5-forge-tgt"])
    _write_snap(new, ["a.sh\techo\tkeep"], binaries=["krb5-tools\tkrb5-forge-tgt"])
    _must_pass(old, new, "a binary moving packages")
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
        _must_fail(dead_old, dead_new, "unlisted echo tag removal")
        n += 1
        _must_pass(dead_old, dead_new, "--dead echo tag removal", dead_path=dead_map)
        n += 1
        sect_old, sect_new = root / "sect-old", root / "sect-new"
        _write_snap(sect_old, ["a.sh\tsection\tMIT_DEAD_PORT", "a.sh\techo\tkeep"])
        _write_snap(sect_new, ["a.sh\techo\tkeep"])
        _must_fail(sect_old, sect_new, "--dead listed section tag removal", dead_path=dead_map)
        n += 1

        moved_old, moved_new = root / "moved-old", root / "moved-new"
        _write_snap(moved_old, ["a.sh\techo\tcell-y"])
        _write_snap(moved_new, ["b.sh\techo\tcell-y"])
        if main_compare(moved_old, moved_new) != 0:
            raise SystemExit("hygiene-diff --self-test: file move must not fail")
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


def main_compare(
    old: pathlib.Path,
    new: pathlib.Path,
    renames_path=None,
    duplicates_path=None,
    dead_path=None,
    accept_rise=None,
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

    old_stable = {cell_tag(c) for c in old_cells if cell_tag(c)[0] != "workflow"}
    new_stable = {cell_tag(c) for c in new_cells if cell_tag(c)[0] != "workflow"}
    for kind, tag in sorted(old_stable - new_stable):
        if kind == "echo" and dead.get(tag):
            info(f"gate cell tag removed as dead: {kind}\t{tag} ({dead[tag]})")
            continue
        fail(f"gate cell tag removed: {kind}\t{tag}")
    added = new_stable - old_stable
    if added:
        info(f"gate cell tags added: {len(added)}")
    # (file,kind,tag) multiplicity: a tag that exists in two files and then
    # only one is a lost cell even though the (kind,tag) set is unchanged.
    # File moves (same (kind,tag) count, different files) stay informational.
    old_ft = collections.Counter(
        cell_key(c) for c in old_cells if cell_tag(c)[0] != "workflow"
    )
    new_ft = collections.Counter(
        cell_key(c) for c in new_cells if cell_tag(c)[0] != "workflow"
    )
    old_tag_n = collections.Counter((k, t) for _, k, t in old_ft.elements())
    new_tag_n = collections.Counter((k, t) for _, k, t in new_ft.elements())
    for (kind, tag), n in sorted(old_tag_n.items()):
        mapped = duplicates.get(tag) or renames.get(tag)
        new_n = new_tag_n.get((kind, tag), 0)
        if mapped:
            new_n = max(new_n, new_tag_n.get((kind, mapped), 0))
        if new_n < n:
            if kind == "echo" and dead.get(tag):
                info(f"gate cell multiplicity drop as dead: {kind}\t{tag} {n} -> {new_n} ({dead[tag]})")
                continue
            fail(f"gate cell multiplicity drop: {kind}\t{tag} {n} -> {new_n}")
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

    old_led = {ln.split("\t", 1)[0]: ln.split("\t", 1)[1] for ln in load_data_lines(old / "ledger-rows.txt") if "\t" in ln}
    new_led = {ln.split("\t", 1)[0]: ln.split("\t", 1)[1] for ln in load_data_lines(new / "ledger-rows.txt") if "\t" in ln}
    for cite, verdict in old_led.items():
        if cite not in new_led:
            fail(f"ledger row removed: {cite}\t{verdict}")
        elif new_led[cite] != verdict:
            fail(f"ledger row regraded: {cite} {verdict} -> {new_led[cite]}")
    if len(new_led) > len(old_led):
        info(f"ledger rows added: {len(new_led) - len(old_led)}")

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
    info(f"gate tags {len(old_stable)} -> {len(new_stable)}")
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
    ap.add_argument(
        "--accept-rise",
        action="append",
        default=[],
        metavar="KEY=N:REASON",
        help="allow quality KEY to rise by exactly N (recorded reason)",
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
