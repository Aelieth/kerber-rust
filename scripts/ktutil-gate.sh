#!/usr/bin/env bash
# MIT ktadd keytab listed by Rust ktutil; Rust-written keytab kinit -k on MIT.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-ktutil-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ktutil-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "ktutil.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-admin --bin krb5-ktutil

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    log "ktutil.gate" "error" ',"error":"harness did not become ready"'
    exit 1
fi

docker cp target/debug/krb5-ktutil "$NAME":/tmp/krb5-ktutil
docker exec "$NAME" chmod +x /tmp/krb5-ktutil

echo "==== MIT ktadd then Rust ktutil list ===="
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/mit.keytab -norandkey user'
LIST="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/mit.keytab\nlist -t -K\n" | /tmp/krb5-ktutil')"
echo "$LIST"
echo "$LIST" | grep -q 'user@KERBER.TEST'

echo "==== Rust ktutil-written keytab MIT kinit -k ===="
docker exec -e KRB5_PASSWORD=userpassword "$NAME" sh -c \
    'printf "addent -password -p user@KERBER.TEST -k 1 -e aes256-cts-hmac-sha1-96\nwkt /tmp/rust.keytab\n" | /tmp/krb5-ktutil'
docker exec "$NAME" kinit -k -t /tmp/rust.keytab user@KERBER.TEST
KLIST="$(docker exec "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
log "ktutil.gate" "ok" ',"principal":"user@KERBER.TEST"'
exit 0
