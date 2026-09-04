#!/usr/bin/env bash
# MIT kprop as an unauthorized GSS peer is refused by Rust kpropd; host
# sender still loads. Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-prop-acl-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-prop-acl-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"prop-acl-gate","outcome":"%s"%s}\n' \
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
    log "propacl.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/prop-acl-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kpropd --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "propacl.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/prop-acl-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! docker exec "$NAME" sh -c 'command -v kprop >/dev/null'; then
    log "propacl.gate" "error" ',"error":"kprop binary missing"'
    exit 2
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kpropd "$NAME":/tmp/krb5-kpropd
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kpropd /tmp/krb5-kadmind

docker exec "$NAME" sh -c 'cat >/tmp/prop-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_propacl
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== MIT realm + dump ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kadmin.local -q 'addprinc -pw userpassword user'
HN="$(docker exec "$NAME" hostname)"
docker exec "$NAME" kadmin.local -q "addprinc -randkey host/localhost"
docker exec "$NAME" kadmin.local -q "addprinc -randkey host/${HN}"
docker exec "$NAME" kadmin.local -q "ktadd -k /tmp/host.keytab host/localhost host/${HN}"
docker exec "$NAME" kdb5_util dump /tmp/dump
docker exec "$NAME" sh -c 'printf "" >/tmp/kpropd.acl.empty'
docker exec "$NAME" sh -c "printf 'host/localhost@KERBER.TEST\\nhost/${HN}@KERBER.TEST\\n' >/tmp/kpropd.acl"

echo "==== MIT krb5kdc ===="
kill_comm krb5kdc
kill_comm krb5-kdc
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
    log "propacl.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

echo "==== Rust kpropd unset ACL (deny even host/ peers) ===="
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd 127.0.0.1:754 >/tmp/kpropd.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kpropd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "propacl.gate" "error" ',"error":"kpropd (unset ACL) did not listen"'
    exit 1
fi

echo "==== unauthorized MIT kprop (ACL unset) ===="
UNSET="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$UNSET"
UNSET_LOG="$(docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true)"
echo "$UNSET_LOG"
if echo "$UNSET" | grep -q 'SUCCEEDED'; then
    echo "unset-ACL kprop succeeded" >&2
    exit 1
fi
echo "$UNSET_LOG" | grep -qiE 'acl denied|ACL'
if docker exec "$NAME" test -f /tmp/replica; then
    echo "unset-ACL kprop wrote a replica dump" >&2
    exit 1
fi

echo "==== Rust kpropd empty ACL (deny all MIT GSS peers) ===="
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    -e KRB5_KPROP_ACL=/tmp/kpropd.acl.empty \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd 127.0.0.1:754 >/tmp/kpropd.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kpropd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "propacl.gate" "error" ',"error":"kpropd did not listen"'
    exit 1
fi

echo "==== unauthorized MIT kprop (empty allowlist) ===="
BAD="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$BAD"
KPD="$(docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true)"
echo "$KPD"
if echo "$BAD" | grep -q 'SUCCEEDED'; then
    echo "empty-ACL kprop succeeded" >&2
    exit 1
fi
echo "$KPD" | grep -qiE 'acl denied|ACL'
if docker exec "$NAME" test -f /tmp/replica; then
    echo "unauthorized kprop wrote a replica dump" >&2
    exit 1
fi

echo "==== Rust kpropd with host allowlist ===="
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    -e KRB5_KPROP_ACL=/tmp/kpropd.acl \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd 127.0.0.1:754 >/tmp/kpropd.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kpropd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "propacl.gate" "error" ',"error":"kpropd (allowlist) did not listen"'
    exit 1
fi

echo "==== authorized MIT kprop as host ===="
GOOD="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$GOOD"
echo "$GOOD" | grep -q 'SUCCEEDED'
docker exec "$NAME" test -f /tmp/replica

echo "==== MIT kinit user against replica ===="
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
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:88 >/tmp/kdc.log 2>&1'
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
    log "propacl.gate" "error" ',"error":"replica kdc did not listen"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

log "propacl.gate" "ok" ',"unauthorized_refused":true,"unset_acl_refused":true,"authorized_kprop":true'
exit 0
