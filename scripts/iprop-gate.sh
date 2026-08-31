#!/usr/bin/env bash
# MIT iprop serial-delta both ways, then MIT kinit of the *new* principal.
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

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract -p krb5-admin --bin krb5-kadmind --bin krb5-kprop --bin krb5-kpropd --bin krb5-iprop-pull

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
docker exec "$NAME" sh -c 'grep -v testhost.kerber.test /etc/hosts >/tmp/hosts.new; echo "127.0.0.1 testhost.kerber.test testhost" >>/tmp/hosts.new; cat /tmp/hosts.new >/etc/hosts'

if ! docker exec "$NAME" sh -c 'command -v kpropd >/dev/null && command -v kadmind >/dev/null'; then
    log "iprop.gate" "error" ',"error":"kpropd/kadmind missing"'
    echo "kpropd/kadmind missing" >"$SCRATCH/iprop-unavailable.log"
    exit 2
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker cp target/debug/krb5-kprop "$NAME":/tmp/krb5-kprop
docker cp target/debug/krb5-kpropd "$NAME":/tmp/krb5-kpropd
docker cp target/debug/krb5-iprop-pull "$NAME":/tmp/krb5-iprop-pull
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract /tmp/krb5-kadmind /tmp/krb5-kprop /tmp/krb5-kpropd /tmp/krb5-iprop-pull

docker exec "$NAME" sh -c 'cat >/tmp/iprop-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_iprop
[realms]
    KERBER.TEST = {
        kdc = testhost.kerber.test
        admin_server = testhost.kerber.test
        iprop_enable = true
        iprop_port = 749
        iprop_slave_poll = 10
    }
EOF'

echo "==== A: Rust master → MIT kpropd -A serial-delta ===="
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 0.0.0.0:88 >/tmp/kdc.log 2>&1'
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
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kadmind 0.0.0.0:749 >/tmp/kadmind.log 2>&1'
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

docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q \
    'addprinc -randkey kiprop/testhost.kerber.test' || true
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q \
    'ktadd -k /tmp/iprop.keytab kiprop/testhost.kerber.test host/testhost.kerber.test'

docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" sh -c 'printf "host/testhost.kerber.test@KERBER.TEST\nkiprop/testhost.kerber.test@KERBER.TEST\n" >/tmp/kpropd.acl'
kill_comm kpropd
docker exec -d \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_KTNAME=/tmp/iprop.keytab \
    "$NAME" sh -c 'kpropd -S -d -A testhost.kerber.test -a /tmp/kpropd.acl -P 754 -s /tmp/iprop.keytab -f /tmp/from_kprop.dump -p "$(command -v kdb5_util)" >/tmp/kpropd-iprop.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -Eq 'ready|waiting for a kprop|iprop' /tmp/kpropd-iprop.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
sleep 1
IPROP_LOG="$(docker exec "$NAME" cat /tmp/kpropd-iprop.log 2>/dev/null || true)"
echo "$IPROP_LOG"
if echo "$IPROP_LOG" | grep -qiE 'Program not registered|PROG_UNAVAIL'; then
    log "iprop.gate" "error" ',"error":"MIT kpropd -A: IPROP program not served"'
    exit 1
fi

echo "==== hosts / listeners ===="
docker exec "$NAME" cat /etc/hosts || true
docker exec "$NAME" sh -c 'ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null || true'

echo "==== wait kpropd FULL_RESYNC request ===="
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -Eq 'Full resync needed|Calling iprop_get_updates' /tmp/kpropd-iprop.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.5
done
echo "kpropd FULL_RESYNC wait ok=$ok"
echo "==== kpropd-iprop.log (pre-kprop) ===="
docker exec "$NAME" cat /tmp/kpropd-iprop.log 2>/dev/null || true

echo "==== first contact: Rust kprop -i dump (ipropx last_sno) ===="
KPROP="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/iprop.keytab \
    "$NAME" /tmp/krb5-kprop -i -P 754 -s /tmp/iprop.keytab -n testhost.kerber.test testhost.kerber.test 2>&1 || true)"
echo "$KPROP"
echo "$KPROP" | grep -q 'kprop ok'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" kadmin.local -q 'getprinc user' 2>/dev/null | grep -q 'Principal: user@KERBER.TEST'; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" kadmin.local -q 'getprinc user' 2>&1 || true
    docker exec "$NAME" cat /tmp/kpropd-iprop.log >&2 || true
    log "iprop.gate" "error" ',"error":"MIT replica missing user after full-resync kprop"'
    exit 1
fi

echo "==== mutate master: MIT kadmin addprinc extra ===="
ADD="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra' 2>&1 || true)"
echo "$ADD"
echo "$ADD" | grep -qi 'created'

echo "==== restart Rust master; ulog must survive ===="
kill_comm krb5-kadmind
kill_comm krb5-kdc
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null \
        && ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
[ "$free" = 1 ] || {
    log "iprop.gate" "error" ',"error":"master ports still bound"'
    exit 1
}
docker exec "$NAME" sh -c ':> /tmp/kdc.log; :> /tmp/kadmind.log'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 0.0.0.0:88 >/tmp/kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "iprop.gate" "error" ',"error":"kdc did not listen after restart"'
    exit 1
}
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kadmind 0.0.0.0:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "iprop.gate" "error" ',"error":"kadmind did not listen after restart"'
    exit 1
}

echo "==== persisted ulog after restart ===="
ULOG="$(docker exec "$NAME" cat /tmp/principal.ulog 2>/dev/null || true)"
echo "$ULOG"
echo "$ULOG" | grep -q extra

echo "==== wait MIT kpropd -A GET_UPDATES serial-delta ===="
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" kadmin.local -q 'getprinc extra' 2>/dev/null | grep -q 'Principal: extra@KERBER.TEST'; then
        ok=1
        break
    fi
    sleep 1
done
echo "==== kpropd-iprop.log (delta) ===="
DELTA_LOG="$(docker exec "$NAME" cat /tmp/kpropd-iprop.log 2>/dev/null || true)"
echo "$DELTA_LOG"
echo "$DELTA_LOG" | grep -qiE 'Got incremental updates|Incremental updates:'
FR="$(echo "$DELTA_LOG" | grep -ci 'Full resync needed' || true)"
if [ "$FR" -gt 1 ]; then
    log "iprop.gate" "error" ",\"error\":\"spurious FULL_RESYNC after restart, got $FR\""
    exit 1
fi
echo "$DELTA_LOG" | grep -qi 'Got incremental updates'
if [ "$ok" != 1 ]; then
    docker exec "$NAME" kadmin.local -q 'getprinc extra' 2>&1 || true
    docker exec "$NAME" kadmin.local -q 'getprinc user' 2>&1 || true
    docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kdb5_util dump /tmp/after-delta.dump 2>&1 || true
    echo "==== replica dump extra ===="
    docker exec "$NAME" grep extra /tmp/after-delta.dump 2>/dev/null || true
    docker exec "$NAME" head -3 /tmp/after-delta.dump 2>/dev/null || true
    echo "==== kadmind.log ===="
    docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true
    log "iprop.gate" "error" ',"error":"MIT replica missing extra after serial-delta (GET_UPDATES)"'
    exit 1
fi

echo "==== MIT kinit extra on replica after delta ===="
kill_comm krb5-kdc
kill_comm krb5-kadmind
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
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
    log "iprop.gate" "error" ',"error":"MIT krb5kdc did not listen after delta"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'printf "extra-secret\n" | kinit extra@KERBER.TEST'
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'extra@KERBER.TEST'
kill_comm krb5kdc
kill_comm kpropd

echo "==== B: MIT kadmind master → Rust slave GET_UPDATES, MIT kinit extra2 ===="
docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
*/admin@KERBER.TEST *
admin@KERBER.TEST *
kiprop/testhost.kerber.test@KERBER.TEST p
EOF'
docker exec "$NAME" sh -c 'cat >/tmp/kdc.conf <<EOF
[kdcdefaults]
[realms]
    KERBER.TEST = {
        database_name = /var/lib/krb5kdc/principal
        acl_file = /tmp/kadm5.acl
        key_stash_file = /var/lib/krb5kdc/.k5.KERBER.TEST
        kadmind_port = 749
        kdc_ports = 88
        master_key_type = aes256-cts-hmac-sha384-192
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        iprop_enable = true
        iprop_port = 2121
        iprop_listen = 0.0.0.0:2121
        iprop_master_ulogsize = 1000
        iprop_slave_poll = 10
    }
EOF'
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kdb5_util create -s -P masterpassword
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kadmin.local -q 'addprinc -pw userpassword user'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kadmin.local -q 'addprinc -pw adminpassword admin'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kadmin.local -q 'addprinc -randkey kiprop/testhost.kerber.test'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kadmin.local -q 'addprinc -randkey host/testhost.kerber.test'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kadmin.local -q 'ktadd -k /tmp/mit-iprop.keytab kiprop/testhost.kerber.test host/testhost.kerber.test'
kill_comm krb5kdc
kill_comm kadmind
docker exec -d -e KRB5_KDC_PROFILE=/tmp/kdc.conf -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'krb5kdc; kadmind -nofork >/tmp/mit-kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null \
        && docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null \
        && docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',2121),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kadmind.log >&2 || true
    docker exec "$NAME" sh -c 'ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null || true' >&2
    log "iprop.gate" "error" ',"error":"MIT krb5kdc/kadmind did not listen"'
    exit 1
fi
echo "==== MIT iprop dump (first contact) ===="
DUMP_OUT="$(docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" kdb5_util dump -i1 /tmp/mit.dump 2>&1 || true)"
echo "$DUMP_OUT"
HEAD="$(docker exec "$NAME" head -1 /tmp/mit.dump 2>/dev/null || true)"
echo "$HEAD"
echo "$HEAD" | grep -q '^ipropx '
SNO="$(echo "$HEAD" | awk '{print $3}')"
SEC="$(echo "$HEAD" | awk '{print $4}')"
USEC="$(echo "$HEAD" | awk '{print $5}')"
echo "dump last_sno=$SNO last_time=$SEC $USEC"
LOAD="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    "$NAME" /tmp/krb5-iprop-pull --load-dump /tmp/mit.dump 2>&1 || true)"
echo "$LOAD"
echo "$LOAD" | grep -q 'iprop dump'

echo "==== mutate MIT master: extra2 + setstr ===="
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" kadmin.local -q 'addprinc -pw extra2-secret extra2'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" kadmin.local -q 'setstr extra2 note hello-g4a'

echo "==== MIT kinit -k kiprop (keytab probe) ===="
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" kinit -k -t /tmp/mit-iprop.keytab kiprop/testhost.kerber.test 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" klist 2>&1 || true
echo "==== Rust iprop-pull vs MIT kadmind serial-delta ===="
PULL="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    -e KRB5_KPROP_KEYTAB=/tmp/mit-iprop.keytab \
    -e KRB5_KDC=127.0.0.1 \
    -e KRB5_IPROP_HOST=testhost.kerber.test \
    "$NAME" /tmp/krb5-iprop-pull --last-sno "$SNO" --last-time "$SEC" "$USEC" testhost.kerber.test:2121 2>&1 || true)"
echo "$PULL"
echo "==== mit-kadmind.log ===="
docker exec "$NAME" cat /tmp/mit-kadmind.log 2>/dev/null || true
echo "$PULL" | grep -q 'iprop pull ok'
SNO2="$(echo "$PULL" | sed -n 's/.*iprop pull ok last_sno=\([0-9]*\).*/\1/p' | tail -1)"
SEC2="$(echo "$PULL" | sed -n 's/.*last_time=\([0-9]*\) \([0-9]*\).*/\1/p' | tail -1)"
USEC2="$(echo "$PULL" | sed -n 's/.*last_time=\([0-9]*\) \([0-9]*\).*/\2/p' | tail -1)"
: "${SNO2:=$SNO}"
: "${SEC2:=$SEC}"
: "${USEC2:=$USEC}"
echo "replica last_sno=$SNO2 last_time=$SEC2 $USEC2"
REPLICA="$(docker exec "$NAME" cat /tmp/rust-replica 2>/dev/null || true)"
echo "$REPLICA" | grep extra2 || true
echo "$REPLICA" | grep -q '6e6f74650068656c6c6f2d67346100'
kill_comm krb5kdc
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    -e KRB5_EXPORT_KEYTAB=/tmp/replica-host.keytab \
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
    log "iprop.gate" "error" ',"error":"rust replica did not listen after iprop pull"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'printf "extra2-secret\n" | kinit extra2@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'extra2@KERBER.TEST'

echo "==== replica PAC RID for extra2 after incremental ===="
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test@KERBER.TEST
PACRID="$(docker exec "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/replica-host.keytab --ccache /tmp/krb5cc_iprop \
    --out /tmp/extra2.pac --print-rid 2>&1 || true)"
echo "$PACRID"
RID="$(echo "$PACRID" | sed -n 's/^pac_rid=\([0-9][0-9]*\)$/\1/p' | tail -1)"
if [ -z "$RID" ] || [ "$RID" = "1000" ]; then
    log "iprop.gate" "error" ",\"error\":\"replica extra2 PAC RID is ${RID:-missing} (want != 1000)\""
    exit 1
fi
echo "extra2 pac_rid=$RID"

echo "==== MIT delprinc extra2 then Rust pull ===="
kill_comm krb5-kdc
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
docker exec -d -e KRB5_KDC_PROFILE=/tmp/kdc.conf -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'krb5kdc'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "iprop.gate" "error" ',"error":"MIT krb5kdc did not listen for delete pull"'
    exit 1
fi
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" kadmin.local -q 'delprinc -force extra2'
PULL2="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    -e KRB5_KPROP_KEYTAB=/tmp/mit-iprop.keytab \
    -e KRB5_KDC=127.0.0.1 \
    -e KRB5_IPROP_HOST=testhost.kerber.test \
    "$NAME" /tmp/krb5-iprop-pull --last-sno "$SNO2" --last-time "$SEC2" "$USEC2" testhost.kerber.test:2121 2>&1 || true)"
echo "$PULL2"
echo "$PULL2" | grep -q 'iprop pull ok'
kill_comm krb5kdc
kill_comm kadmind
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:88 >/tmp/rust-replica2.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-replica2.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-replica2.log >&2 || true
    log "iprop.gate" "error" ',"error":"rust replica did not listen after delete pull"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
GONE="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" sh -c 'printf "extra2-secret\n" | kinit extra2@KERBER.TEST' 2>&1 || true)"
echo "$GONE"
echo "$GONE" | grep -qiE 'Client not found|not found in Kerberos database|UNKNOWN_PRINC'

log "iprop.gate" "ok" ",\"op\":\"kpropd-A-delta-kinit-extra+mit-kadmind-pull-kinit-extra2+delprinc\",\"extra2_pac_rid\":$RID"
exit 0
