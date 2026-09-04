#!/usr/bin/env bash
# MIT ktadd keytab listed by Rust ktutil; Rust-written keytab kinit -k on MIT.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

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
MITK="$(docker exec "$NAME" klist -k -t -e /tmp/mit.keytab)"
echo "$MITK"
LIST="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/mit.keytab\nlist -t -e\n" | /tmp/krb5-ktutil')"
echo "$LIST"
echo "$LIST" | grep -q 'user@KERBER.TEST'
MIT_KVNO="$(echo "$MITK" | awk '/user@KERBER.TEST/{print $1; exit}')"
RUST_KVNO="$(echo "$LIST" | awk '/user@KERBER.TEST/{print $2; exit}')"
MIT_ET="$(echo "$MITK" | awk -F'[()]' '/user@KERBER.TEST/{print $2; exit}')"
RUST_ET="$(echo "$LIST" | awk '/user@KERBER.TEST/{print $NF; exit}')"
RUST_T="$(echo "$LIST" | awk '/user@KERBER.TEST/{for(i=1;i<=NF;i++) if($i ~ /^t=/){print substr($i,3); exit}}')"
echo "mit_kvno=$MIT_KVNO rust_kvno=$RUST_KVNO"
echo "mit_etype=$MIT_ET rust_etype=$RUST_ET"
echo "rust_timestamp=$RUST_T"
test "$MIT_KVNO" = "$RUST_KVNO"
test "$MIT_ET" = "$RUST_ET"
test -n "$RUST_T"
test "$RUST_T" -gt 0

echo "==== MIT unknown-etype keytab listed by Rust ktutil ===="
docker exec -i "$NAME" python3 - <<'PY'
import struct
def put16(b, data):
    return b + struct.pack('>H', len(data)) + data
body = struct.pack('>H', 1)
body = put16(body, b'KERBER.TEST')
body = put16(body, b'user')
body += struct.pack('>i', 1)
body += struct.pack('>I', 1700000000)
body += struct.pack('B', 3)
body += struct.pack('>H', 99)
body = put16(body, b'\x00' * 16)
body += struct.pack('>I', 3)
open('/tmp/unk.keytab', 'wb').write(b'\x05\x02' + struct.pack('>i', len(body)) + body)
PY
MITU="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/unk.keytab\nlist\n" | ktutil')"
echo "$MITU"
echo "$MITU" | grep -q 'user@KERBER.TEST'
echo "$MITU" | grep -Eq ' 3 .*user@KERBER.TEST'
RUSTU="$(docker exec "$NAME" sh -c 'printf "rkt /tmp/unk.keytab\nlist -e\n" | /tmp/krb5-ktutil')"
echo "$RUSTU"
echo "$RUSTU" | grep -q 'user@KERBER.TEST'
echo "$RUSTU" | grep -q 'Unknown (99)'
echo "$RUSTU" | grep -Eq ' 3 .*user@KERBER.TEST Unknown \(99\)'

echo "==== Rust ktutil-written keytab MIT kinit -k ===="
docker exec -e KRB5_PASSWORD=userpassword "$NAME" sh -c \
    'printf "addent -password -p user@KERBER.TEST -k 1 -e aes256-cts-hmac-sha1-96\nwkt /tmp/rust.keytab\n" | /tmp/krb5-ktutil'
docker exec "$NAME" kinit -k -t /tmp/rust.keytab user@KERBER.TEST
KLIST="$(docker exec "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
log "ktutil.gate" "ok" ',"principal":"user@KERBER.TEST"'
exit 0
