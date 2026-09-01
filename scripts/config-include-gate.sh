#!/usr/bin/env bash
# MIT 1.22.2 include/includedir + colon-split KRB5_CONFIG vs Rust loader.
# Isolation: container /tmp only. Host /etc/krb5.conf is not touched.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"config-include-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}
NAME="kerber-rust-mit-kdc"
if ! docker ps -q --filter "name=^${NAME}$" | grep -q .; then
    echo "start the harness first: ./scripts/run-harness.sh" >&2
    exit 1
fi

cargo build -p krb5-client --bin krb5-kinit --bin krb5-kvno --bin krb5-klist -q
docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker cp target/debug/krb5-kvno "$NAME":/tmp/krb5-kvno
docker cp target/debug/krb5-klist "$NAME":/tmp/krb5-klist
docker exec "$NAME" chmod +x /tmp/krb5-kinit /tmp/krb5-kvno /tmp/krb5-klist

docker exec -i "$NAME" bash -s <<'EOS'
set -euo pipefail
BASE=/tmp/g9a-include
rm -rf "$BASE"
mkdir -p "$BASE/d.d" "$BASE/merge" "$BASE/miss"

echo "==== (a) includedir dotted 10.conf is read ===="
cat >"$BASE/d-main.conf" <<EOF
includedir $BASE/d.d
[libdefaults]
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 10h
EOF
cat >"$BASE/d.d/10.conf" <<EOF
[libdefaults]
    default_realm = KERBER.TEST
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF
echo userpassword | env KRB5_CONFIG="$BASE/d-main.conf" kinit -c /tmp/g9a_inc_mit user
MIT_A="$(env KRB5_CONFIG="$BASE/d-main.conf" klist -c /tmp/g9a_inc_mit)"
echo "$MIT_A"
echo "$MIT_A" | grep -q 'user@KERBER.TEST'
env KRB5_CONFIG="$BASE/d-main.conf" KRB5_PASSWORD=userpassword \
    /tmp/krb5-kinit -c /tmp/g9a_inc_rust user
RUST_A="$(env KRB5_CONFIG="$BASE/d-main.conf" /tmp/krb5-klist -c /tmp/g9a_inc_rust)"
echo "$RUST_A"
echo "$RUST_A" | grep -q 'user@KERBER.TEST'
env KRB5_CONFIG="$BASE/d-main.conf" /tmp/krb5-kvno -c /tmp/g9a_inc_rust host/testhost.kerber.test \
    | grep -q 'host/testhost.kerber.test'
env KRB5_CONFIG="$BASE/d-main.conf" kvno -c /tmp/g9a_inc_mit host/testhost.kerber.test \
    | grep -q 'host/testhost.kerber.test'

echo "==== (b) two-file scalar first-wins (A:B vs B:A) ===="
cat >"$BASE/merge/a.conf" <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 10h
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF
cat >"$BASE/merge/b.conf" <<EOF
[libdefaults]
    default_realm = FAKE.TEST
    dns_lookup_kdc = false
    rdns = false
[realms]
    FAKE.TEST = {
        kdc = 127.0.0.1
    }
EOF
echo userpassword | env KRB5_CONFIG="$BASE/merge/a.conf:$BASE/merge/b.conf" \
    kinit -c /tmp/g9a_ab_mit user
env KRB5_CONFIG="$BASE/merge/a.conf:$BASE/merge/b.conf" klist -c /tmp/g9a_ab_mit \
    | grep -q 'user@KERBER.TEST'
env KRB5_CONFIG="$BASE/merge/a.conf:$BASE/merge/b.conf" KRB5_PASSWORD=userpassword \
    /tmp/krb5-kinit -c /tmp/g9a_ab_rust user
env KRB5_CONFIG="$BASE/merge/a.conf:$BASE/merge/b.conf" /tmp/krb5-klist -c /tmp/g9a_ab_rust \
    | grep -q 'user@KERBER.TEST'

set +e
echo userpassword | timeout 5 env KRB5_CONFIG="$BASE/merge/b.conf:$BASE/merge/a.conf" \
    kinit -c /tmp/g9a_ba_mit user
MIT_BA=$?
timeout 5 env KRB5_CONFIG="$BASE/merge/b.conf:$BASE/merge/a.conf" KRB5_PASSWORD=userpassword \
    /tmp/krb5-kinit -c /tmp/g9a_ba_rust user
RUST_BA=$?
set -e
echo "B:A mit_rc=$MIT_BA rust_rc=$RUST_BA"
test "$MIT_BA" -ne 0
test "$RUST_BA" -ne 0

echo "==== (c) missing include does not hang ===="
cat >"$BASE/miss/main.conf" <<EOF
include $BASE/miss/does-not-exist.conf
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF
set +e
echo userpassword | timeout 5 env KRB5_CONFIG="$BASE/miss/main.conf" \
    kinit -c /tmp/g9a_miss_mit user
MIT_M=$?
timeout 5 env KRB5_CONFIG="$BASE/miss/main.conf" KRB5_PASSWORD=userpassword \
    /tmp/krb5-kinit -c /tmp/g9a_miss_rust user
RUST_M=$?
set -e
echo "missing include mit_rc=$MIT_M rust_rc=$RUST_M"
test "$MIT_M" -ne 0
test "$RUST_M" -ne 0
test "$MIT_M" -ne 124
test "$RUST_M" -ne 124

echo "==== (d) nested missing include is an error even with another KRB5_CONFIG path ===="
# other.conf is a complete KERBER.TEST profile. A skippable-include bug would
# swallow the missing nested include and kinit as KERBER.TEST.
set +e
MIT_D_OUT=$(echo userpassword | timeout 5 env \
    KRB5_CONFIG="$BASE/miss/main.conf:$BASE/merge/a.conf" \
    kinit -c /tmp/g9a_mp_mit user 2>&1)
MIT_D=$?
RUST_D_OUT=$(timeout 5 env KRB5_CONFIG="$BASE/miss/main.conf:$BASE/merge/a.conf" \
    KRB5_PASSWORD=userpassword /tmp/krb5-kinit -c /tmp/g9a_mp_rust user 2>&1)
RUST_D=$?
set -e
echo "$MIT_D_OUT"
echo "$RUST_D_OUT"
echo "multi-path missing include mit_rc=$MIT_D rust_rc=$RUST_D"
test "$MIT_D" -ne 0
test "$RUST_D" -ne 0
test "$MIT_D" -ne 124
test "$RUST_D" -ne 124
echo "$MIT_D_OUT" | grep -q 'Included profile file could not be read'
echo "$RUST_D_OUT" | grep -q 'include target not found'

echo "==== (e) missing top-level KRB5_CONFIG path is still skipped ===="
echo userpassword | env KRB5_CONFIG="$BASE/miss/does-not-exist.conf:$BASE/merge/a.conf" \
    kinit -c /tmp/g9a_skip_mit user
env KRB5_CONFIG="$BASE/miss/does-not-exist.conf:$BASE/merge/a.conf" klist -c /tmp/g9a_skip_mit \
    | grep -q 'user@KERBER.TEST'
env KRB5_CONFIG="$BASE/miss/does-not-exist.conf:$BASE/merge/a.conf" KRB5_PASSWORD=userpassword \
    /tmp/krb5-kinit -c /tmp/g9a_skip_rust user
env KRB5_CONFIG="$BASE/miss/does-not-exist.conf:$BASE/merge/a.conf" /tmp/krb5-klist -c /tmp/g9a_skip_rust \
    | grep -q 'user@KERBER.TEST'
EOS

log "config.include.gate" "ok" ',"dotted_conf":true,"first_wins":true,"malformed_no_hang":true'
exit 0
