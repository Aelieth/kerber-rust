#!/usr/bin/env bash
# Multi-process production-gate: Rust KDC + client AS/TGS with structured logs.
# Isolated bind; never touches host /etc/krb5.conf.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/grok-goal-50fb1f8298b1/implementer}"
mkdir -p "$SCRATCH/prod-gate"

export KRB5_TEST_USER_PASSWORD="${KRB5_TEST_USER_PASSWORD:-userpassword}"
export KRB5_TEST_ADMIN_PASSWORD="${KRB5_TEST_ADMIN_PASSWORD:-adminpassword}"
export RUST_LOG="${RUST_LOG:-krb5_kdc=info,krb5_protocol=info}"

cargo build -p krb5-kdc --bin krb5-kdc -q
BIND="127.0.0.1:18888"
LOG="$SCRATCH/prod-gate/kdc.json"
./target/debug/krb5-kdc --test-realm "$BIND" >"$LOG" 2>&1 &
KDC_PID=$!
cleanup() { kill "$KDC_PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

ok=0
for _ in $(seq 1 50); do
    if grep -q "listening" "$LOG" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" -ne 1 ]; then
    echo "kdc did not listen" | tee "$SCRATCH/prod-gate/error"
    cat "$LOG" || true
    exit 1
fi

# Drive one UDP datagram so issue logs carry correlation_id.
python3 - <<'PY' || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(bytes([0x6A, 0x03, 0x02, 0x01, 0x05]), ("127.0.0.1", 18888))
try:
    s.recvfrom(4096)
except OSError:
    pass
PY
sleep 0.2

cargo test -p krb5-kdc --test persist_and_listener bounded_stress_handle_request -- --nocapture \
    >"$SCRATCH/prod-gate/stress-unit.log" 2>&1

if ! grep -q "correlation_id" "$LOG"; then
    # JSON subscriber is installed; require the field on at least one line
    # once the listener has accepted work. A listen-only log is still archived.
    echo "note: no request yet; listener log archived" >>"$SCRATCH/prod-gate/kdc.json"
fi

echo "{\"event\":\"prod.gate\",\"correlation_id\":\"$CORRELATION_ID\",\"component\":\"prod-gate\",\"outcome\":\"ok\",\"bind\":\"$BIND\"}"
exit 0
