#!/usr/bin/env bash
# One cargo build of the bins and examples the gates and prod jobs need.
# Gates (S2) call need_bins and must not invoke cargo themselves.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
cargo build -p krb5-kdc -p krb5-admin -p krb5-client -p krb5-gss -p krb5-tools --bins
cargo build -p krb5-client --example loadgen
cargo build -p krb5-protocol --example diffsend --features diff
cargo build -p krb5-protocol --example ccache-probe
