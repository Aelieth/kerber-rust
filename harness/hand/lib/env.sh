#!/bin/bash
# Sourced by the hand drivers: field.env (mode 0600 only), require_env, and the input guards.
LAB_HOME=${KERBER_LAB_HOME:-$HOME/kerber-lab}
if [ -f "$LAB_HOME/field.env" ]; then
    if [ "$(stat -c %a "$LAB_HOME/field.env")" != 600 ]; then
        echo "$LAB_HOME/field.env must be mode 0600" >&2
        exit 2
    fi
    set -a
    # shellcheck source=../../field/field.env.example
    . "$LAB_HOME/field.env"
    set +a
fi

# require_env NAME...: stop when a name is unset or empty.
require_env() {
    local n
    for n in "$@"; do
        if [ -z "${!n-}" ]; then
            echo "$n is not set in field.env" >&2
            exit 2
        fi
    done
}

# require_bins PATH...: stop before the lab unless each is an executable file.
require_bins() {
    local f
    for f in "$@"; do
        [ -f "$f" ] && [ -x "$f" ] && continue
        echo "HAND_STOP missing program $f" >&2
        exit 2
    done
}

# require_files PATH...: stop unless each is a non-empty file.
require_files() {
    local f
    for f in "$@"; do
        [ -f "$f" ] && [ -s "$f" ] && continue
        echo "HAND_STOP missing file $f" >&2
        exit 2
    done
}

# require_dirs PATH...: stop unless each is a directory.
require_dirs() {
    local d
    for d in "$@"; do
        [ -d "$d" ] && continue
        echo "HAND_STOP missing directory $d" >&2
        exit 2
    done
}
