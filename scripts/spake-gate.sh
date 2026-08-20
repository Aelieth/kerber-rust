#!/usr/bin/env bash
# SPAKE preauth: shipped CHOICE encode/decode plus KDC challenge/response.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo test -p krb5-kdc spake_challenge_then_as_rep --offline -- --nocapture
echo "spake-gate: SPAKE CHOICE challenge/response asserted"
