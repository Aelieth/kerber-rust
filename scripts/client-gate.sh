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
cargo build -p krb5-client --bin krb5-kinit --bin krb5-klist --bin krb5-kdestroy --bin krb5-kvno
docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker cp target/debug/krb5-klist "$NAME":/tmp/krb5-klist
docker cp target/debug/krb5-kdestroy "$NAME":/tmp/krb5-kdestroy
docker cp target/debug/krb5-kvno "$NAME":/tmp/krb5-kvno
docker exec "$NAME" chmod +x /tmp/krb5-kinit /tmp/krb5-klist /tmp/krb5-kdestroy /tmp/krb5-kvno
docker exec "$NAME" mkdir -p /tmp/client-traces
docker exec -e KRB5_PASSWORD=userpassword -e KERBER_CAPTURE_DIR=/tmp/client-traces \
    "$NAME" /tmp/krb5-kinit \
    127.0.0.1 user@KERBER.TEST /tmp/krb5cc_rust \
    host/testhost.kerber.test
TRACE_DST="${KERBER_TRACE_DST:-$ROOT/tests/traces}"
mkdir -p "$TRACE_DST"
docker cp "$NAME":/tmp/client-traces/. "$TRACE_DST/" 2>/dev/null || true
echo "==== MIT klist of Rust FILE ccache ===="
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_rust)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
echo "$KLIST" | grep -q 'host/testhost.kerber.test'

echo "==== MIT kinit FILE ccache for Rust klist ===="
docker exec "$NAME" sh -c 'echo userpassword | kinit -c /tmp/krb5cc_mit user@KERBER.TEST'
echo "==== Rust klist -c -f -e of MIT FILE ccache ===="
RKLIST="$(docker exec "$NAME" /tmp/krb5-klist -c /tmp/krb5cc_mit -f -e)"
echo "$RKLIST"
echo "$RKLIST" | grep -q 'Default principal: user@KERBER.TEST'
echo "$RKLIST" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'
echo "$RKLIST" | grep -q 'Flags:'
echo "$RKLIST" | grep -q 'Etype (skey, tkt):'

echo "==== MIT klist -f -e of Rust FILE ccache ===="
MKLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_rust -f -e)"
echo "$MKLIST"
echo "$MKLIST" | grep -q 'user@KERBER.TEST'
echo "$MKLIST" | grep -q 'host/testhost.kerber.test'
echo "$MKLIST" | grep -q 'Flags:'
echo "$MKLIST" | grep -q 'Etype (skey, tkt):'
echo "==== Rust klist -f -e of Rust FILE ccache ===="
RK2="$(docker exec "$NAME" /tmp/krb5-klist -c /tmp/krb5cc_rust -f -e)"
echo "$RK2"
echo "$RK2" | grep -q 'Default principal: user@KERBER.TEST'
echo "$RK2" | grep -q 'host/testhost.kerber.test'
echo "$RK2" | grep -q 'Flags:'
echo "$RK2" | grep -q 'Etype (skey, tkt):'
MIT_FLAGS="$(echo "$MKLIST" | grep -oE 'Flags: [A-Za-z]+')"
RUST_FLAGS="$(echo "$RK2" | grep -oE 'Flags: [A-Za-z]+')"
echo "mit_flags=$MIT_FLAGS"
echo "rust_flags=$RUST_FLAGS"
test "$MIT_FLAGS" = "$RUST_FLAGS"
MIT_ET="$(echo "$MKLIST" | grep -oE 'Etype \(skey, tkt\): [^[:space:]]+, [^[:space:]]+' | sed 's/[[:space:]]*$//')"
RUST_ET="$(echo "$RK2" | grep -oE 'Etype \(skey, tkt\): [^[:space:]]+, [^[:space:]]+' | sed 's/[[:space:]]*$//')"
echo "mit_etype=$MIT_ET"
echo "rust_etype=$RUST_ET"
test "$MIT_ET" = "$RUST_ET"

echo "==== Rust kvno obtains a service ticket ===="
docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit 127.0.0.1 user@KERBER.TEST /tmp/krb5cc_kvno
KVNO="$(docker exec "$NAME" /tmp/krb5-kvno -c /tmp/krb5cc_kvno 127.0.0.1 host/testhost.kerber.test)"
echo "$KVNO"
echo "$KVNO" | grep -q 'host/testhost.kerber.test'
echo "$KVNO" | grep -q 'kvno ='
MKVNO="$(docker exec "$NAME" klist -c /tmp/krb5cc_kvno)"
echo "$MKVNO"
echo "$MKVNO" | grep -q 'host/testhost.kerber.test'

echo "==== MIT kvno then Rust klist ===="
docker exec "$NAME" sh -c 'echo userpassword | kinit -c /tmp/krb5cc_mitkvno user@KERBER.TEST'
docker exec "$NAME" kvno -c /tmp/krb5cc_mitkvno host/testhost.kerber.test
RKVNO="$(docker exec "$NAME" /tmp/krb5-klist -c /tmp/krb5cc_mitkvno)"
echo "$RKVNO"
echo "$RKVNO" | grep -q 'host/testhost.kerber.test'

echo "==== Rust kdestroy then MIT klist ===="
docker exec "$NAME" /tmp/krb5-kdestroy -c /tmp/krb5cc_rust
set +e
GONE="$(docker exec "$NAME" klist -c /tmp/krb5cc_rust 2>&1)"
grc=$?
set -e
echo "$GONE"
echo "$GONE" | grep -qi 'No credentials cache'
test "$grc" -ne 0
