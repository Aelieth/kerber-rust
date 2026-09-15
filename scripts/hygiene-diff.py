#!/usr/bin/env python3
"""Compare two hygiene snapshots. Exit 1 on a forbidden removal or regression.

Fails on:
  - a test name removed that is not in --renames / --duplicates
  - a gate cell tag removed
  - a diffsend case, client-differential flow, or ledger row removed or regraded
  - a gate_rc that went from 0 to non-zero
  - quality counts that went up (allow=, unwrap_expect_panic_src=, traces_untracked=)

Reports as information: sleep/boot/cargo-build/LOC deltas.
"""
from __future__ import annotations

import argparse
import pathlib
import sys


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


def load_map(path: pathlib.Path | None, sep: str) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    mapping: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("old", type=pathlib.Path)
    ap.add_argument("new", type=pathlib.Path)
    ap.add_argument("--renames", type=pathlib.Path, help="old_name -> new_name")
    ap.add_argument("--duplicates", type=pathlib.Path, help="removed_name = kept_name")
    args = ap.parse_args()
    old, new = args.old, args.new
    if not old.is_dir() or not new.is_dir():
        print(f"hygiene-diff: need directories, got {old} {new}", file=sys.stderr)
        return 2

    failed = 0
    renames = load_map(args.renames, "->")
    duplicates = load_map(args.duplicates, "=")

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
        binary, _, name = t.partition("\t")
        new_name = renames.get(name, name)
        mapped_old.add(f"{binary}\t{new_name}" if "\t" in t else new_name)
    removed_tests = mapped_old - new_tests
    kept_names = {t.split("\t", 1)[-1] for t in new_tests}
    for t in sorted(removed_tests):
        name = t.split("\t", 1)[-1]
        kept = duplicates.get(name)
        if kept and kept in kept_names:
            info(f"test removed as duplicate {name} = {kept}")
            continue
        fail(f"test removed: {t}")
    added_tests = new_tests - mapped_old
    if added_tests:
        info(f"tests added: {len(added_tests)}")

    old_cells = load_set(old / "gates.txt")
    new_cells = load_set(new / "gates.txt")
    # workflow tags may move with a job rename; still fail on section/echo/flow loss.
    def cell_key(line: str) -> tuple[str, str, str]:
        parts = line.split("\t")
        if len(parts) < 3:
            return ("", "", line)
        return parts[0], parts[1], parts[2]

    old_stable = {c for c in old_cells if cell_key(c)[1] != "workflow"}
    new_stable = {c for c in new_cells if cell_key(c)[1] != "workflow"}
    for c in sorted(old_stable - new_stable):
        fail(f"gate cell tag removed: {c}")
    moved = len(new_stable - old_stable)
    if moved:
        info(f"gate cell tags added: {moved}")

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
    elif old_rc or new_rc:
        info("gate_rc: only one side has timings.tsv (informational)")

    def int_or_none(d: dict[str, str], k: str) -> int | None:
        v = d.get(k)
        if v is None or v == "skipped" or v == "na":
            return None
        try:
            return int(v)
        except ValueError:
            return None

    old_q, new_q = kv(old / "quality.txt"), kv(new / "quality.txt")
    for key in ("allow", "unwrap_expect_panic_src", "traces_untracked"):
        a, b = int_or_none(old_q, key), int_or_none(new_q, key)
        if a is not None and b is not None and b > a:
            fail(f"quality {key} rose {a} -> {b}")

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


if __name__ == "__main__":
    raise SystemExit(main())
