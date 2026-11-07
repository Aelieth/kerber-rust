#!/usr/bin/env bash
# peers.yml wrapper: runs one peer gate, prints peer_rc= for the step log and
# appends ok|unavailable|failed to $KERBER_SCRATCH/peer-tally.txt for the job
# tally. A gate that did not run (exit 2) fails its step, as a failure does.
set +e
"$@"
rc=$?
set -e
echo "peer_rc=$rc"
tally="${KERBER_SCRATCH:-.}/peer-tally.txt"
mkdir -p "$(dirname "$tally")"
if [ "$rc" -eq 2 ]; then
    echo unavailable >>"$tally"
    echo "::error::peer gate unavailable (exit 2): $*"
    exit 1
fi
if [ "$rc" -ne 0 ]; then
    echo failed >>"$tally"
    exit "$rc"
fi
echo ok >>"$tally"
exit 0
