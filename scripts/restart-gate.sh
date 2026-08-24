#!/usr/bin/env bash
# B1 restart: persist a kadmind mutation, kill krb5-kdc by comm name,
# relaunch the same binary, MIT kinit still works.
# Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-restart-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"restart-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

kill_comm() {
    local comm="$1"
    docker exec "$NAME" sh -c '
comm="'"$comm"'"
for f in /proc/[0-9]*/comm; do
    [ -f "$f" ] || continue
    read -r name < "$f" || continue
    if [ "$name" = "$comm" ]; then
        pid=${f#/proc/}
        pid=${pid%/comm}
        kill -9 "$pid" 2>/dev/null || true
    fi
done
'
}

if ! command -v docker >/dev/null 2>&1; then
    log "restart.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec "$NAME" sh -c 'cat >/tmp/restart-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_restart
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

start_kdc() {
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_KDC_DB=/tmp/principal \
        -e KRB5_KDC_STASH=/tmp/stash \
        "$NAME" sh -c '/tmp/krb5-kdc '"$1"' 127.0.0.1:88 >/tmp/kdc.log 2>&1'
    ok=0
    for _ in $(seq 1 80); do
        if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.25
    done
    if [ "$ok" != 1 ]; then
        docker exec "$NAME" cat /tmp/kdc.log >&2 || true
        log "restart.gate" "error" ',"error":"kdc did not listen"'
        exit 1
    fi
}

echo "==== start KDC --test-realm (persist) ===="
start_kdc --test-realm

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "restart.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

echo "==== MIT kadmin addprinc extra ===="
docker exec -e KRB5_CONFIG=/tmp/restart-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra'
echo "==== MIT kinit extra before restart ===="
docker exec -e KRB5_CONFIG=/tmp/restart-krb5.conf \
    "$NAME" sh -c 'printf "extra-secret\n" | kinit extra@KERBER.TEST'
KLIST1="$(docker exec -e KRB5_CONFIG=/tmp/restart-krb5.conf "$NAME" klist)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'extra@KERBER.TEST'

echo "==== kill krb5-kdc by comm; relaunch without --test-realm ===="
kill_comm krb5-kdc
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
if [ "$free" != 1 ]; then
    log "restart.gate" "error" ',"error":":88 still occupied"'
    exit 1
fi
docker exec "$NAME" sh -c ':> /tmp/kdc.log'
start_kdc ""

echo "==== MIT kinit extra after restart ===="
docker exec -e KRB5_CONFIG=/tmp/restart-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/restart-krb5.conf \
    "$NAME" sh -c 'printf "extra-secret\n" | kinit extra@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "restart.gate" "error" ',"error":"MIT kinit extra after restart failed"'
    exit 1
fi
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/restart-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'extra@KERBER.TEST'

log "restart.gate" "ok" ',"principal":"extra@KERBER.TEST","op":"mutate+kill+relaunch+kinit"'
exit 0
