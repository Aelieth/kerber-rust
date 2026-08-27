#!/usr/bin/env bash
# Windows SSPI peer for GSS wrap. Exit 2 + unavailability log when no
# SSPI acceptor can be driven — not a fabricated pass. Isolation: ~/adlab
# only; never host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-gss-sspi-gate}"
mkdir -p "$SCRATCH"
{
    echo "date=$(date -Iseconds)"
    echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
    grep default_realm /etc/krb5.conf | head -1 || true
    echo "DC ping:"
    ping -c 1 -W 2 10.10.38.38 || true
    echo "No SSPI acceptor binary or Windows GSS server is in this tree."
    echo "Shipped bar remains krb5-gss wrap RRC=16 + scripts/gss-gate.sh (MIT libgssapi)."
} | tee "$SCRATCH/gss-sspi-gate-unavailable.log"
echo "{\"event\":\"gss.sspi.gate\",\"correlation_id\":\"$CORRELATION_ID\",\"component\":\"gss-sspi-gate\",\"outcome\":\"error\",\"error\":\"no SSPI peer\"}"
exit 2
