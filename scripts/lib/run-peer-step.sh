#!/usr/bin/env bash
# peers.yml wrapper: exit 2 (oracle unavailable) is not a job failure.
# exit 1 / other non-zero stays red. Prints peer_rc= for the step log.
set +e
"$@"
rc=$?
set -e
echo "peer_rc=$rc"
if [ "$rc" -eq 2 ]; then
    echo "peer-step unavailable (exit 2); not failing the job"
    exit 0
fi
exit "$rc"
