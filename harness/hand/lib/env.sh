#!/bin/bash
# Sourced by the hand drivers: field.env (mode 0600 only) and require_env.
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
