#!/usr/bin/env bash
# MIT iprop both ways vs Rust kadmind (program 100423) + full-resync kprop.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-iprop-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-iprop-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"iprop-gate","outcome":"%s"%s}\n' \
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
    log "iprop.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/iprop-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind --bin krb5-kprop --bin krb5-kpropd

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "iprop.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/iprop-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname testhost.kerber.test --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! docker exec "$NAME" sh -c 'command -v kpropd >/dev/null && command -v kprop >/dev/null'; then
    log "iprop.gate" "error" ',"error":"kprop/kpropd missing"'
    echo "kprop/kpropd missing" >"$SCRATCH/iprop-unavailable.log"
    exit 2
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker cp target/debug/krb5-kprop "$NAME":/tmp/krb5-kprop
docker cp target/debug/krb5-kpropd "$NAME":/tmp/krb5-kpropd
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind /tmp/krb5-kprop /tmp/krb5-kpropd

docker exec "$NAME" sh -c 'cat >/tmp/iprop-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_iprop
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== Rust KDC + kadmind (iprop program 100423) ===="
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
    log "iprop.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kadmind --test-realm 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
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
    log "iprop.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

echo "==== MIT kpropd -A probes IPROP_PROG ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" sh -c 'printf "host/testhost.kerber.test@KERBER.TEST\n" >/tmp/kpropd.acl'
kill_comm kpropd
docker exec -d \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_KTNAME=/tmp/host.keytab \
    "$NAME" sh -c 'kpropd -S -d -A 127.0.0.1 -a /tmp/kpropd.acl -P 754 -f /tmp/from_kprop.dump -p "$(command -v kdb5_util)" >/tmp/kpropd-iprop.log 2>&1'
sleep 2
IPROP_LOG="$(docker exec "$NAME" cat /tmp/kpropd-iprop.log 2>/dev/null || true)"
echo "$IPROP_LOG"
if echo "$IPROP_LOG" | grep -qiE 'Program not registered|PROG_UNAVAIL|rpc program'; then
    log "iprop.gate" "error" ',"error":"MIT kpropd -A: IPROP program not served"'
    exit 1
fi

echo "==== full-resync: Rust kprop → MIT kpropd, MIT kinit ===="
kill_comm kpropd
docker exec -d \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
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
    log "iprop.gate" "error" ',"error":"MIT kpropd did not listen"'
    exit 1
fi
KPROP="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    "$NAME" /tmp/krb5-kprop -P 754 -s /tmp/host.keytab -n testhost.kerber.test 127.0.0.1 2>&1 || true)"
echo "$KPROP"
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
    log "iprop.gate" "error" ',"error":"MIT kpropd did not write dump"'
    exit 1
fi
kill_comm krb5-kdc
kill_comm krb5-kadmind
kill_comm kpropd
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
docker exec "$NAME" sh -c 'kdb5_util load /tmp/from_kprop.dump >/tmp/kdb-load.log 2>&1 || true'
docker exec "$NAME" sh -c 'krb5kdc; sleep 0.4' >/dev/null 2>&1 || true
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
    log "iprop.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
kill_comm krb5kdc

echo "==== MIT kprop → Rust kpropd (other direction), MIT kinit vs Rust replica ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kadmin.local -q 'addprinc -pw userpassword user'
HN="$(docker exec "$NAME" hostname)"
docker exec "$NAME" kadmin.local -q "addprinc -randkey host/localhost"
docker exec "$NAME" kadmin.local -q "addprinc -randkey host/${HN}"
docker exec "$NAME" kadmin.local -q "ktadd -k /tmp/mit.host.keytab host/localhost host/${HN}"
docker exec "$NAME" kdb5_util dump /tmp/mit.dump
kill_comm krb5kdc
docker exec "$NAME" sh -c 'krb5kdc; sleep 0.3' >/dev/null 2>&1 || true
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/mit.host.keytab \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd 127.0.0.1:754 >/tmp/rust-kpropd.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kpropd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-kpropd.log >&2 || true
    log "iprop.gate" "error" ',"error":"rust kpropd did not listen"'
    exit 1
fi
KPROP2="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" kprop -f /tmp/mit.dump -s /tmp/mit.host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$KPROP2"
echo "$KPROP2" | grep -q 'SUCCEEDED'
kill_comm krb5kdc
kill_comm krb5-kpropd
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
docker exec -d \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:88 >/tmp/rust-replica.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-replica.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-replica.log >&2 || true
    echo "MIT kprop to rust replica did not yield a listening KDC" >"$SCRATCH/phase4-mit.err"
    log "iprop.gate" "error" ',"error":"rust replica did not listen after MIT kprop"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'user@KERBER.TEST'

log "iprop.gate" "ok" ',"op":"iprop-probe+kprop-both-ways+kinit"'
exit 0
