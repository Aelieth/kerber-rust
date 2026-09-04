#!/usr/bin/env bash
# MIT kinit SPAKE vs Rust KDC. Fails unless MIT obtains a TGT via PA-SPAKE (151).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-spake-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"spake-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "spake.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker exec "$NAME" chmod +x /tmp/krb5-kdc
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
if [ "$ok" -ne 1 ]; then
    log "spake.gate" "error" ',"error":"rust KDC did not listen"'
    exit 1
fi

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac

PROXY=1888
docker cp "$ROOT/scripts/lib/kdc-error-proxy.py" "$NAME":/tmp/kdc-error-proxy.py
docker exec -d "$NAME" python3 /tmp/kdc-error-proxy.py "$PROXY" 127.0.0.1 "$PORT" /tmp/spake-91.txt
sleep 0.2

docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:${PROXY}/' /etc/krb5.conf"
docker exec "$NAME" sh -c "cat >> /etc/krb5.conf <<EOF

[libdefaults]
    preferred_preauth_types = 151
    spake_preauth_groups = P-256
EOF"

echo "==== MIT kinit SPAKE ===="
set +e
TRACE="$(docker exec -e KRB5_TRACE=/dev/stderr "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' 2>&1)"
rc=$?
set -e
echo "$TRACE"
KLIST="$(docker exec "$NAME" klist 2>/dev/null || true)"
echo "$KLIST"
if [ "$rc" -ne 0 ]; then
    echo "==== rust KDC log after kinit ===="
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    log "spake.gate" "error" ',"error":"mit kinit spake failed","rc":'"$rc"
    exit 1
fi
echo "$KLIST" | grep -q 'user@KERBER.TEST'
if ! echo "$TRACE" | grep -Eq 'pa[_ ]?type[[:space:]]*151|padata type 151|PA-SPAKE[[:space:]]*\(151\)|etype 151'; then
    if ! echo "$TRACE" | grep -q '151'; then
        log "spake.gate" "error" ',"error":"kinit succeeded without pa_type 151"'
        exit 1
    fi
fi
if ! echo "$TRACE" | grep -Eq 'group[[:space:]]*2|group=2|SPAKE challenge with group 2'; then
    log "spake.gate" "error" ',"error":"kinit succeeded without SPAKE group 2"'
    exit 1
fi
SPAKE91="$(docker exec "$NAME" cat /tmp/spake-91.txt 2>/dev/null || true)"
echo "==== SPAKE 91 e_text (MIT kinit vs Rust KDC) ===="
echo "$SPAKE91"
echo "$SPAKE91" | grep -F 'error_code=91'
echo "$SPAKE91" | grep -F 'e_text=PREAUTH_FAILED'
if echo "$SPAKE91" | grep -F 'e_text=SPAKE challenge'; then
    echo "SPAKE 91 e_text was prose SPAKE challenge" >&2
    exit 1
fi
KDCLOG="$(docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true)"
echo "$KDCLOG" | grep -F '"code":91,"e_text":"PREAUTH_FAILED"'
log "spake.gate" "ok" ',"mode":"mit-kinit","pa_type":151,"group":2,"principal":"user@KERBER.TEST","e_text":"PREAUTH_FAILED"'
exit 0
