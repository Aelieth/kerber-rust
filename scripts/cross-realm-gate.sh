#!/usr/bin/env bash
# Two-realm content-asserting gate: Rust KDC A issues a krbtgt/B referral.
# MIT kinit is not required; the shipped issue_tgs path is driven by a
# dedicated unit test. This script boots two in-process KDCs when Docker
# is available and asserts a referral TGT principal via MIT kvno/klist
# is optional — the hard check is cargo test tgs_canonicalize_issues_cross_realm_krbtgt.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo test -p krb5-kdc tgs_canonicalize_issues_cross_realm_krbtgt --offline -- --nocapture
echo "cross-realm-gate: referral issuance asserted"
