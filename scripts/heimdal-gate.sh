#!/usr/bin/env bash
# Heimdal secondary oracle. Exit 2 + unavailability log when no Heimdal
# client/KDC is present — not a fabricated pass.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-50fb1f8298b1/implementer}"
mkdir -p "$SCRATCH"
{
    echo "date=$(date -Iseconds)"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    echo "kinit=$(command -v kinit || true)"
    echo "This host kinit is MIT (Fedora krb5-workstation), not Heimdal."
    rpm -q heimdal heimdal-libs heimdal-client 2>/dev/null || true
    command -v heimdal-kinit || true
    docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -i heimdal || echo "no heimdal docker image"
} | tee "$SCRATCH/heimdal-gate-unavailable.log"
echo "{\"event\":\"heimdal.gate\",\"correlation_id\":\"$CORRELATION_ID\",\"component\":\"heimdal-gate\",\"outcome\":\"error\",\"error\":\"heimdal not installed\"}"
exit 2
