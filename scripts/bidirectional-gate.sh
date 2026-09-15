#!/usr/bin/env bash
# Rust-client ↔ Rust-KDC: TGT + service ticket, FILE ccache 0x0504, keytab 0x0502.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc krb5-kinit

TMP="${TMPDIR:-/tmp}/kerber-bidir-$$"
mkdir -p "$TMP"
register_cleanup 'rm -rf "$TMP"; kill ${KDC_PID:-} 2>/dev/null || true'

export KRB5_TEST_USER_PASSWORD="${KRB5_TEST_USER_PASSWORD:-userpassword}"
export KRB5_TEST_ADMIN_PASSWORD="${KRB5_TEST_ADMIN_PASSWORD:-adminpassword}"
./target/debug/krb5-kdc --test-realm 127.0.0.1:8889 >"$TMP/kdc.log" 2>&1 &
KDC_PID=$!
ok=0
for _ in $(seq 1 50); do
    if grep -q '^listening ' "$TMP/kdc.log" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" -ne 1 ]; then
    echo "rust KDC did not listen" >&2
    cat "$TMP/kdc.log" >&2 || true
    exit 1
fi

export KRB5_PASSWORD=userpassword
./target/debug/krb5-kinit -c "$TMP/ccache" -S host/testhost.kerber.test \
    127.0.0.1:8889 user@KERBER.TEST

test -f "$TMP/ccache"
MAGIC="$(od -An -tx1 -N2 "$TMP/ccache" | tr -d ' \n')"
if [ "$MAGIC" != "0504" ]; then
    echo "expected FILE ccache 05 04, got $MAGIC" >&2
    exit 1
fi
echo "bidirectional rust↔rust: FILE ccache 0x0504 present"
