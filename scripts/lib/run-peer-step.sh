#!/usr/bin/env bash
# peers.yml wrapper: exit 2 (oracle unavailable) is not a job failure.
# exit 1 / other non-zero stays red. Prints peer_rc= for the step log.
# Appends unavailable|failed|ok to $KERBER_SCRATCH/peer-tally.txt for the
# job tally (red only when failed > 0).
set +e
"$@"
rc=$?
set -e
echo "peer_rc=$rc"
tally="${KERBER_SCRATCH:-.}/peer-tally.txt"
mkdir -p "$(dirname "$tally")"
if [ "$rc" -eq 2 ]; then
    echo unavailable >>"$tally"
    echo "peer-step unavailable (exit 2); not failing the job"
    exit 0
fi
if [ "$rc" -ne 0 ]; then
    echo failed >>"$tally"
    exit "$rc"
fi
echo ok >>"$tally"
exit 0
