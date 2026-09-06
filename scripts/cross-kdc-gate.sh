#!/usr/bin/env bash
# One identical dump, MIT krb5kdc on :88 and the Rust KDC on :8888: a TGT
# issued by either KDC must be accepted by the other's TGS. Isolation:
# in-container; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-cross-kdc-gate"
GOLDEN="tests/traces/kdb/mit-dump-v7.txt"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-cross-kdc-gate}"
OUT="$SCRATCH/cross-kdc-gate"
mkdir -p "$OUT"
CC=/tmp/cross-kdc.cc

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"cross-kdc-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "cross.kdc.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

unavailable() {
    log "cross.kdc.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/cross-kdc-unavailable.log"
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
if [ ! -f "$GOLDEN" ]; then
    die "missing golden dump $GOLDEN"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb -q

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT" || true
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    unavailable "MIT image unavailable"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kdb "$NAME":/tmp/krb5-kdb
docker cp "$GOLDEN" "$NAME":/tmp/mit.dump
docker cp harness/client-krb5.conf "$NAME":/tmp/mit-krb5.conf
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb
docker exec "$NAME" sh -c "sed 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:8888/' /tmp/mit-krb5.conf > /tmp/rust-krb5.conf && sed -i 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:88/' /tmp/mit-krb5.conf"

echo "==== load identical dump into Rust KDC on :8888 ===="
LOAD="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/mit.dump)"
echo "$LOAD"
echo "$LOAD" | grep -q 'ok load version=7' || die "rust kdb load failed"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "rust kdc did not listen on 8888"

echo "==== load identical dump into MIT krb5kdc on :88 ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kdb5_util load /tmp/mit.dump
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1 & sleep 0.5; cat /tmp/mit-kdc.log' 2>&1 || true)"
echo "$STARTLOG"
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "MIT krb5kdc did not listen on 88"
echo "$STARTLOG" | grep -q 'setting up network' || die "MIT krb5kdc did not start"

kinit_via() {
    docker exec -e KRB5CCNAME="$CC" "$NAME" kdestroy -A >/dev/null 2>&1 || true
    docker exec -e KRB5_CONFIG="/tmp/$1-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' ||
        die "kinit via $1 KDC failed"
}

tgt_etype_via() {
    local listing
    listing="$(docker exec -e KRB5CCNAME="$CC" "$NAME" klist -e 2>&1 || true)"
    echo "$listing" | grep -A1 'krbtgt/KERBER.TEST' | sed -n 's/.*tkt): *[^,]*, *//p' | tr -d ' '
}

kvno_via() {
    docker exec -e KRB5_CONFIG="/tmp/$1-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" \
        kvno host/testhost.kerber.test 2>&1 || true
}

kdc_logs() {
    echo "---- rust kdc log tail ----"
    docker exec "$NAME" tail -n 6 /tmp/rust-kdc.log 2>&1 | cut -c1-600
    echo "---- mit kdc log tail ----"
    docker exec "$NAME" tail -n 6 /tmp/mit-kdc.log 2>&1 | cut -c1-600
}

cross_case() {
    local issuer=$1 tgs=$2 got
    echo "==== TGT from $issuer KDC, service ticket from $tgs TGS ===="
    kinit_via "$issuer"
    got="$(kvno_via "$tgs")"
    echo "$got"
    if ! echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1'; then
        kdc_logs
        die "$issuer TGT rejected by $tgs TGS: $got"
    fi
}

cross_case mit rust
cross_case rust mit
cross_case mit mit
cross_case rust rust

echo "==== TGT enc-part etype is the first current krbtgt key on both KDCs ===="
kinit_via mit
MIT_TGT_ETYPE="$(tgt_etype_via)"
kinit_via rust
RUST_TGT_ETYPE="$(tgt_etype_via)"
echo "mit_tgt_etype=$MIT_TGT_ETYPE rust_tgt_etype=$RUST_TGT_ETYPE"
[ -n "$MIT_TGT_ETYPE" ] || die "MIT TGT etype not found in klist -e"
[ "$MIT_TGT_ETYPE" = "$RUST_TGT_ETYPE" ] || die "TGT etype differs: mit=$MIT_TGT_ETYPE rust=$RUST_TGT_ETYPE"

docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true
docker cp "$NAME":/tmp/mit-kdc.log "$OUT/mit-kdc.log" 2>/dev/null || true
if grep -q 'HEADER_PAC' "$OUT/rust-kdc.log"; then
    die "Rust KDC logged HEADER_PAC during the cross-KDC exchange"
fi
if grep -q 'PROCESS_TGS' "$OUT/mit-kdc.log"; then
    die "MIT krb5kdc logged PROCESS_TGS during the cross-KDC exchange"
fi

log "cross.kdc.gate" "ok" ",\"tgt_etype\":\"$MIT_TGT_ETYPE\",\"directions\":4"
echo "cross-kdc-gate ok"
