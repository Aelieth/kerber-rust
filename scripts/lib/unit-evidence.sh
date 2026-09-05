#!/usr/bin/env bash
# Stamped unit green / parent-red helpers. Source after cd "$ROOT".
# shellcheck shell=bash
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

unit_green() {
    local name=$1
    local filter=$2
    if [ -z "$name" ] || [ -z "$filter" ]; then
        echo "unit_green <name> <nextest filter>" >&2
        return 2
    fi
    echo "==== unit_green $name filter=$filter ===="
    cargo nextest run --workspace --profile ci -E "test($filter)"
}

unit_red_at() {
    local parent=$1
    local name=$2
    local filter=$3
    shift 3 || true
    if [ -z "$parent" ] || [ -z "$name" ] || [ -z "$filter" ]; then
        echo "unit_red_at: test filter required: unit_red_at <parent> <name> <filter> [files…]" >&2
        return 2
    fi
    echo "==== unit_red_at parent=$parent name=$name filter=$filter ===="
    scripts/red-at-sha.sh "$parent" cargo test --workspace "$filter"
}
