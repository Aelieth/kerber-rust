#!/usr/bin/env bash
# Stamped unit green / parent-red helpers. Source after cd "$ROOT".
# shellcheck shell=bash
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

# Every #[test] / #[tokio::test] fn name in the named files, one per line.
_unit_test_names() {
    python3 - "$@" <<'PY'
import re, sys
attr = re.compile(r"#\[(?:\w+::)*test\]")
fn = re.compile(r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)")
for path in sys.argv[1:]:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    i = 0
    while i < len(lines):
        head = lines[i].split("//", 1)[0].strip()
        if attr.search(head):
            j = i + 1
            while j < len(lines):
                s = lines[j].split("//", 1)[0].strip()
                if s.startswith("#["):
                    j += 1
                    continue
                m = fn.match(s)
                if m:
                    print(m.group(1))
                break
            i = j
        i += 1
PY
}

unit_guard_dirty() {
    local who=${1:-unit_green}
    if [ "${dirty:-yes}" != no ]; then
        if [ "${KERBER_UNIT_ALLOW_DIRTY:-}" != 1 ]; then
            echo "$who: refusing dirty tree (dirty=${dirty:-yes}); set KERBER_UNIT_ALLOW_DIRTY=1 to override" >&2
            return 1
        fi
        echo "override=KERBER_UNIT_ALLOW_DIRTY"
    fi
    return 0
}

unit_green() {
    local name=$1
    local filter=$2
    if [ -z "$name" ] || [ -z "$filter" ]; then
        echo "unit_green <name> <nextest filter>" >&2
        return 2
    fi
    unit_guard_dirty unit_green || return 1
    echo "==== unit_green $name filter=$filter ===="
    local out rc
    set +e
    out="$(cargo nextest run --workspace --profile ci -E "test($filter)" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    if [ "$rc" -ne 0 ]; then
        echo "unit_green: nextest failed (rc=$rc)" >&2
        return 1
    fi
    if ! printf '%s\n' "$out" | grep -qE 'Summary .* passed'; then
        echo "unit_green: missing Summary … passed line" >&2
        return 1
    fi
}

# unit_red_at <parent> <name> [--all|<filter>] <files…>
# --all (default): derive the cargo filter from every #[test] in the inject
# files and require each of those names FAILED at the parent (a green or
# filtered-out unit is a vacuous red → exit 1). An explicit <filter> still
# requires every #[test] in the inject files to appear in the cargo output as
# FAILED — use a focused inject file.
unit_red_at() {
    local parent=$1
    local name=$2
    shift 2 || true
    local filter=""
    local mode=all
    if [ "${1:-}" = "--all" ]; then
        shift
    elif [ -n "${1:-}" ] && [[ "$1" != */* && "$1" != *.rs && "$1" != *.toml ]]; then
        # Positional filter (legacy); still verify every inject-file test failed.
        filter=$1
        mode=filter
        shift
    fi
    if [ -z "$parent" ] || [ -z "$name" ]; then
        echo "unit_red_at: usage: unit_red_at <parent> <name> [--all|<filter>] <files…>" >&2
        return 2
    fi
    if [ "$#" -eq 0 ]; then
        echo "unit_red_at: inject files required: unit_red_at <parent> <name> [--all|<filter>] <files…>" >&2
        return 2
    fi
    unit_guard_dirty unit_red_at || return 1
    local f
    for f in "$@"; do
        if [ ! -f "$ROOT/$f" ] && [ ! -f "$f" ]; then
            echo "unit_red_at: inject path is not a file: $f" >&2
            return 2
        fi
    done
    local -a abs=()
    for f in "$@"; do
        if [ -f "$ROOT/$f" ]; then
            abs+=("$ROOT/$f")
        else
            abs+=("$f")
        fi
    done
    local names
    names="$(_unit_test_names "${abs[@]}")"
    if [ -z "$names" ]; then
        echo "unit_red_at: no #[test] fns in inject files: $*" >&2
        return 2
    fi
    local -a name_list=()
    while IFS= read -r t; do
        [ -n "$t" ] && name_list+=("$t")
    done <<<"$names"
    if [ "$mode" = all ] || [ -z "$filter" ]; then
        # cargo test treats FILTER as a single substring — do not join with `|`.
        # Run every inject integration binary (tests/<stem>.rs → --test <stem>).
        # Non-.rs injects (Cargo.toml, lib sources) are overlay-only.
        filter=""
    fi
    echo "==== unit_red_at parent=$parent name=$name filter=${filter:---test stems} inject=$* ===="
    echo "red-at-parent=1"
    echo "expected_fail=${name_list[*]}"
    # Workspace default is fail-fast: the second inject crate never runs.
    local -a cargo_args=(cargo test --workspace --no-fail-fast)
    if [ -n "$filter" ]; then
        cargo_args+=("$filter")
    else
        local f stem
        for f in "$@"; do
            case "$f" in
                *.rs) ;;
                *) continue ;;
            esac
            case "$f" in
                */tests/*|tests/*) ;;
                *) continue ;;
            esac
            stem=$(basename -- "$f")
            stem=${stem%.rs}
            cargo_args+=(--test "$stem")
        done
        if [ "${#cargo_args[@]}" -eq 3 ]; then
            echo "unit_red_at: --all needs at least one tests/*.rs inject" >&2
            return 2
        fi
    fi
    local out rc
    set +e
    out="$(scripts/red-at-sha.sh --inject "$@" -- "$parent" "${cargo_args[@]}" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    if ! printf '%s\n' "$out" | python3 "$ROOT/scripts/lib/unit-red-check.py" "${name_list[@]}"; then
        echo "unit_red_at: vacuous red (cargo_rc=$rc)" >&2
        return 1
    fi
    echo "unit_red_at: all ${#name_list[@]} inject tests FAILED at parent (cargo_rc=$rc)"
    return 0
}
