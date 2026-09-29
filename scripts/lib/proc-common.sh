#!/usr/bin/env bash
# /proc helpers for the gates that stop a daemon inside $NAME by its comm name. Sourced after
# gate-common.sh.
# shellcheck shell=bash

# kill_comm COMM: SIGKILL every process in $NAME whose comm is COMM.
kill_comm() {
    local comm="$1"
    docker exec "$NAME" sh -c '
comm="'"$comm"'"
for f in /proc/[0-9]*/comm; do
    [ -f "$f" ] || continue
    read -r name < "$f" || continue
    if [ "$name" = "$comm" ]; then
        pid=${f#/proc/}
        pid=${pid%/comm}
        kill -9 "$pid" 2>/dev/null || true
    fi
done
'
}

# term_comm COMM: SIGTERM every process in $NAME whose comm is COMM (rc4-session-gate's restarts).
term_comm() {
    local comm_name=$1
    docker exec "$NAME" sh -c '
name="$1"
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r n < "$comm" || continue
    if [ "$n" = "$name" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
' sh "$comm_name"
}
