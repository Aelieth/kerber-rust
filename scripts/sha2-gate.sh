#!/usr/bin/env bash
# RFC 8009 principal keys exist on documented password principals (etypes 19/20).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo test -p krb5-kdc password_principal_has_rfc8009_keys --offline -- --nocapture
echo "sha2-gate: RFC 8009 principal keys present"
