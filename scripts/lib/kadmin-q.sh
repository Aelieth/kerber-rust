#!/usr/bin/env bash
# The gates' one kadmin query path: MIT kadmin through the gate's client config inside $NAME. Sourced after
# gate-common.sh. A gate sets KADMIN_Q_CONF (and GATE_CLIENT_CONF for kinit_try) to its config's path in
# the container.
# shellcheck shell=bash

# kadmin_q QUERY: MIT kadmin as admin@KERBER.TEST; output and errors on stdout, never a failing rc.
kadmin_q() {
    docker exec -e KRB5_CONFIG="${KADMIN_Q_CONF:?kadmin_q: set KADMIN_Q_CONF}" \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

# kadmin_q_as PRINCIPAL PASSWORD QUERY: the same as another principal.
kadmin_q_as() {
    docker exec -e KRB5_CONFIG="${KADMIN_Q_CONF:?kadmin_q_as: set KADMIN_Q_CONF}" \
        "$NAME" kadmin -p "$1" -w "$2" -q "$3" 2>&1 || true
}

# kinit_try SCRIPT: a client shell command in $NAME through the gate's client config; never a failing rc.
kinit_try() {
    docker exec -e KRB5_CONFIG="${GATE_CLIENT_CONF:?kinit_try: set GATE_CLIENT_CONF}" \
        "$NAME" sh -c "$1" 2>&1 || true
}
