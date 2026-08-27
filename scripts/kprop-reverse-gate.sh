#!/usr/bin/env bash
# Rust krb5-kprop → MIT kpropd (dump version 7) then MIT kinit.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kprop-reverse-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kprop-reverse-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kprop-reverse-gate","outcome":"%s"%s}\n' \
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
    log "kprop.reverse.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/kprop-reverse-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kprop

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "kprop.reverse.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/kprop-reverse-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname testhost.kerber.test --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! docker exec "$NAME" sh -c 'command -v kpropd >/dev/null && command -v kdb5_util >/dev/null'; then
    log "kprop.reverse.gate" "error" ',"error":"kpropd/kdb5_util missing"'
    echo "kpropd or kdb5_util missing in $IMAGE" >"$SCRATCH/kprop-reverse-unavailable.log"
    exit 2
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kprop "$NAME":/tmp/krb5-kprop
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kprop

docker exec "$NAME" sh -c 'cat >/tmp/kprop-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kprop_rev
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== MIT replica realm (empty, matching master password) ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" sh -c 'printf "host/testhost.kerber.test@KERBER.TEST\n" >/tmp/kpropd.acl'

echo "==== Rust primary KDC + persist ===="
kill_comm krb5kdc
kill_comm krb5-kdc
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'
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
    log "kprop.reverse.gate" "error" ',"error":"rust kdc did not listen"'
    exit 1
fi
if ! docker exec "$NAME" test -f /tmp/host.keytab; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kprop.reverse.gate" "error" ',"error":"host keytab not exported"'
    exit 1
fi
LIVE_HEAD="$(docker exec "$NAME" head -1 /tmp/principal)"
echo "$LIVE_HEAD"
echo "$LIVE_HEAD" | grep -q 'kdb5_util load_dump version 7'

echo "==== MIT kpropd on 754 ===="
kill_comm kpropd
docker exec -d \
    -e KRB5_CONFIG=/tmp/kprop-krb5.conf \
    -e KRB5_KTNAME=/tmp/host.keytab \
    "$NAME" sh -c 'kpropd -S -d -a /tmp/kpropd.acl -P 754 -f /tmp/from_kprop.dump -p "$(command -v kdb5_util)" >/tmp/kpropd.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -Eq 'ready|waiting for a kprop' /tmp/kpropd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "kprop.reverse.gate" "error" ',"error":"MIT kpropd did not listen"'
    exit 1
fi

echo "==== Rust krb5-kprop ===="
KPROP="$(docker exec \
    -e KRB5_CONFIG=/tmp/kprop-krb5.conf \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    "$NAME" /tmp/krb5-kprop -P 754 -s /tmp/host.keytab -n testhost.kerber.test 127.0.0.1 2>&1 || true)"
echo "$KPROP"
echo "==== kpropd.log ===="
docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true
echo "$KPROP" | grep -q 'kprop ok'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" test -s /tmp/from_kprop.dump 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kprop.reverse.gate" "error" ',"error":"MIT kpropd did not write dump"'
    exit 1
fi
DUMP_HEAD="$(docker exec "$NAME" head -1 /tmp/from_kprop.dump)"
echo "$DUMP_HEAD"
echo "$DUMP_HEAD" | grep -q 'kdb5_util load_dump version 7'

echo "==== stop Rust KDC; MIT krb5kdc on replica ===="
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
    log "kprop.reverse.gate" "error" ',"error":":88 still occupied"'
    exit 1
fi

# kpropd -p kdb5_util should have loaded; load again if the replica is empty.
docker exec "$NAME" sh -c 'kdb5_util load /tmp/from_kprop.dump >/tmp/kdb-load.log 2>&1 || true'
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc; sleep 0.4' 2>&1 || true)"
echo "$STARTLOG"
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdb-load.log >&2 || true
    log "kprop.reverse.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

echo "==== MIT kinit user against MIT replica ===="
docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    docker exec "$NAME" cat /tmp/kdb-load.log >&2 || true
    log "kprop.reverse.gate" "error" ',"error":"MIT kinit after reverse kprop failed"'
    exit 1
fi
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

log "kprop.reverse.gate" "ok" ',"dump_version":7,"direction":"rust-kprop-to-mit-kpropd"'
exit 0
