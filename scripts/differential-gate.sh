#!/usr/bin/env bash
# Same AS/TGS bytes to a live Rust KDC and a live MIT 1.22.2 krb5kdc on one
# identical dump. Isolation: in-container; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-differential-gate"
GOLDEN="tests/traces/kdb/mit-dump-v7.txt"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-differential-gate}"
OUT="$SCRATCH/differential-gate"
mkdir -p "$OUT"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"differential-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "differential.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

unavailable() {
    log "differential.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/differential-unavailable.log"
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
if [ ! -f "$GOLDEN" ]; then
    die "missing golden dump $GOLDEN"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb -q
cargo build -p krb5-protocol --example diffsend --features diff -q

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
docker cp target/debug/examples/diffsend "$NAME":/tmp/diffsend
docker cp "$GOLDEN" "$NAME":/tmp/mit.dump
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/diffsend

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
    "$NAME" sh -c '/tmp/krb5-kdc --export-keytab /tmp/host.keytab --export-krbtgt-keytab /tmp/krbtgt.keytab 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    die "rust kdc did not listen on 8888"
}
docker exec "$NAME" test -f /tmp/krbtgt.keytab || die "krbtgt keytab missing"
docker exec "$NAME" test -f /tmp/host.keytab || die "host keytab missing"

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
echo "$STARTLOG" | grep -q 'Address already in use' && die "MIT krb5kdc could not bind :88"
echo "$STARTLOG" | grep -q 'setting up network' || die "MIT krb5kdc did not start"

echo "==== diffsend build-once/send-twice ===="
set +e
DIFF="$(docker exec \
    -e KRB5_PASSWORD=userpassword \
    -e KERBER_PAUSER_PASSWORD=preauthpw \
    -e KERBER_DIFF_REALM=KERBER.TEST \
    -e KERBER_KRBTGT_KEYTAB=/tmp/krbtgt.keytab \
    -e KERBER_HOST_KEYTAB=/tmp/host.keytab \
    "$NAME" /tmp/diffsend 127.0.0.1:8888 127.0.0.1:88 /tmp/diff-corpus 2>&1)"
RC=$?
set -e
echo "$DIFF" | tee "$OUT/diffsend.log"
docker cp "$NAME":/tmp/diff-corpus "$OUT/diff-corpus" 2>/dev/null || true
docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true
docker cp "$NAME":/tmp/mit-kdc.log "$OUT/mit-kdc.log" 2>/dev/null || true
if [ "$RC" != 0 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    die "diffsend failed (rc=$RC)"
fi
echo "$DIFF" | grep -q '"same_request_bytes":true' || die "diffsend did not log same request bytes"
echo "$DIFF" | grep -q '"case":"unknown-cname","outcome":"ok","error_code":6,"e_text":"CLIENT_NOT_FOUND"' || die "unknown-cname was not CLIENT_NOT_FOUND"
echo "$DIFF" | grep -q '"case":"etype-nosupp","outcome":"ok","error_code":14,"e_text":"BAD_ENCRYPTION_TYPE"' || die "missing BAD_ENCRYPTION_TYPE"
echo "$DIFF" | grep -q '"case":"as-session-enctype","outcome":"ok","error_code":14,"e_text":"BAD_ENCRYPTION_TYPE"' || die "missing as-session-enctype"
echo "$DIFF" | grep -q '"case":"wrong-realm","outcome":"ok","error_code":6,"e_text":"CLIENT_NOT_FOUND"' || die "wrong-realm was not CLIENT_NOT_FOUND"
echo "$DIFF" | grep -q '"case":"pauser-no-preauth","outcome":"ok","error_code":25' || die "missing PREAUTH_REQUIRED(25)"
echo "$DIFF" | grep -q '"e_text":"NEEDED_PREAUTH"' || die "missing NEEDED_PREAUTH"
echo "$DIFF" | grep -q '"case":"skewed-timestamp","outcome":"ok","error_code":37,"e_text":"PREAUTH_FAILED"' || die "missing PREAUTH_FAILED"
echo "$DIFF" | grep -q '"case":"unknown-sname","outcome":"ok","error_code":7,"e_text":"SERVER_NOT_FOUND"' || die "missing SERVER_NOT_FOUND"
echo "$DIFF" | grep -q '"case":"garbage-pdu","outcome":"ok","rust_tag":"drop","mit_tag":"drop"' || die "garbage-pdu was not both-drop"
echo "$DIFF" | grep -q '"case":"tgs-not-a-tgt","outcome":"ok","error_code":35,"e_text":"BAD TGS SERVER NAME"' || die "missing BAD TGS SERVER NAME"
echo "$DIFF" | grep -q '"case":"tgt-expired","outcome":"ok","error_code":32' || die "missing TKT_EXPIRED(32)"
echo "$DIFF" | grep -q '"case":"tgt-nyv","outcome":"ok","error_code":33' || die "missing TKT_NYV(33)"
echo "$DIFF" | grep -q '"case":"as-success"' || die "missing as-success"
echo "$DIFF" | grep -q '"case":"tgs-success"' || die "missing tgs-success"
echo "$DIFF" | grep -q '"rust_tag":"0x6b"' || die "as-success missing AS-REP tag"
echo "$DIFF" | grep -q '"rust_tag":"0x6d"' || die "tgs-success missing TGS-REP tag"
echo "$DIFF" | grep -q '"outcome":"ok","cases":13' || die "diffsend did not finish 13 cases"

docker cp "$NAME":/tmp/diff-corpus "$OUT/diff-corpus" 2>/dev/null || true
docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true

log "differential.gate" "ok" ',"same_db":true,"transport":"tcp"'
exit 0
