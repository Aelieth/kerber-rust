#!/usr/bin/env bash
# One cargo build of the bins the gates and prod jobs need, with the
# test-hooks feature the gates drive (a release build leaves it off).
# Harness bins: kprop-expired-apreq ccache-probe loadgen krb5-vfy-increds
# krb5-forge-tgt krb5-pac-extract diffsend.
# Gates (S2) call need_bins and must not invoke cargo themselves.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
cargo build -p krb5-kdc -p krb5-admin -p krb5-client -p krb5-gss -p krb5-tools --bins --features krb5-kdc/test-hooks,krb5-admin/test-hooks
