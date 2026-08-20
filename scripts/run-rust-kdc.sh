#!/usr/bin/env bash
# Documented Rust KDC entry point. Binds UDP/TCP 88, falling back to 8888.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"

echo "{\"event\":\"kdc.launch\",\"correlation_id\":\"${CORRELATION_ID}\",\"component\":\"krb5-kdc\",\"outcome\":\"ok\",\"realm\":\"KERBER.TEST\"}"

cargo build -p krb5-kdc --bin krb5-kdc

BIND="${KRB5_KDC_BIND:-}"
if [ -n "$BIND" ]; then
    exec ./target/debug/krb5-kdc "$BIND"
fi
exec ./target/debug/krb5-kdc
