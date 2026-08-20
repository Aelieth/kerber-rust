#!/usr/bin/env bash
# Production-gate: pure-Rust kinit + TGS against the MIT 1.22.2 harness,
# then MIT klist of the FILE ccache. Requires the KDC container to be running.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
NAME="kerber-rust-mit-kdc"
if ! docker ps -q --filter "name=^${NAME}$" | grep -q .; then
    echo "start the harness first: ./scripts/run-harness.sh" >&2
    exit 1
fi
cargo build -p krb5-client --bin krb5-kinit
docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit
docker exec -e KRB5_PASSWORD=userpassword "$NAME" /tmp/krb5-kinit \
    127.0.0.1 user@KERBER.TEST /tmp/krb5cc_rust \
    host/testhost.kerber.test
echo "==== MIT klist of Rust FILE ccache ===="
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_rust)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
echo "$KLIST" | grep -q 'host/testhost.kerber.test'
