#!/usr/bin/env bash
# krb5-kdb dump, then Rust krb5-kprop -f of that file → MIT kpropd (dump version 7), then MIT
# kinit against the MIT replica. Isolated: docker --entrypoint sleep; never touches host
# /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/proc-common.sh"
need_bins krb5-kdc krb5-kdb krb5-kprop

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kprop-reverse-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"

need_image

shell_container 3600 testhost.kerber.test

if ! docker exec "$NAME" sh -c 'command -v kpropd >/dev/null && command -v kdb5_util >/dev/null'; then
    log "kprop.reverse.gate" "error" ',"error":"kpropd/kdb5_util missing"'
    echo "kpropd or kdb5_util missing in $IMAGE" >"$SCRATCH/kprop-reverse-unavailable.log"
    exit 2
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kprop" "$NAME":/tmp/krb5-kprop
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kprop

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

echo "==== krb5-kdb dump, then Rust krb5-kprop -f, as MIT's kdb5_util dump + kprop ===="
# kprop opens no database: it sends the file krb5-kdb dump wrote (with its .dump_ok), with a
# ticket from the Rust KDC for the replica's host/ name, as host/<this host> from -s.
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kdb dump /tmp/prop.dump
docker exec "$NAME" test -f /tmp/prop.dump.dump_ok
KPROP="$(docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf \
    "$NAME" /tmp/krb5-kprop -f /tmp/prop.dump -P 754 -s /tmp/host.keytab -d testhost.kerber.test 2>&1 || true)"
echo "$KPROP"
echo "==== kpropd.log ===="
docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true
echo "$KPROP" | grep -qx 'Database propagation to testhost.kerber.test: SUCCEEDED'
echo "$KPROP" | grep -qE '^[0-9]+ bytes sent\.$'
docker exec "$NAME" grep -q 'authenticated client: host/testhost.kerber.test@KERBER.TEST' /tmp/kpropd.log
LAST="$(docker exec "$NAME" od -An -tx1 /tmp/prop.dump.testhost.kerber.test.last_prop)"
echo "last_prop:$LAST"
[ "$(echo "$LAST" | tr -d ' ')" = 00 ] || {
    log "kprop.reverse.gate" "error" ',"error":"no one-NUL .last_prop"'
    exit 1
}
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
docker exec "$NAME" cmp /tmp/prop.dump /tmp/from_kprop.dump

echo "==== a dump of several KRB-PRIV blocks: the same dump and 250 principals more, past 64 KiB ===="
# kprop chains one cipher state through a dump's blocks, and only a dump of more than one block
# shows whether this side chains it as MIT's kpropd does.
docker cp "$ROOT/scripts/lib/bulk-dump.py" "$NAME":/tmp/bulk-dump.py
docker exec "$NAME" python3 /tmp/bulk-dump.py /tmp/prop.dump /tmp/bulk.dump 250
BULK="$(docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf \
    "$NAME" /tmp/krb5-kprop -f /tmp/bulk.dump -P 754 -s /tmp/host.keytab -d testhost.kerber.test 2>&1 || true)"
echo "$BULK"
echo "$BULK" | grep -qx 'Database propagation to testhost.kerber.test: SUCCEEDED'
[ "$(echo "$BULK" | grep -cE '^[0-9]+ bytes sent\.$')" -ge 3 ]
docker exec "$NAME" cmp /tmp/bulk.dump /tmp/from_kprop.dump

echo "==== the same dump under each AES enctype as the ticket's session key ===="
# The cipher state each enctype chains is its own code: the sha1 and the sha2 enctypes differ in what
# their MAC covers. The session key is the one kprop asks for, so its trace names the one used.
for pair in aes128-cts-hmac-sha1-96:aes128-cts aes256-cts-hmac-sha1-96:aes256-cts \
    aes128-cts-hmac-sha256-128:aes128-sha2 aes256-cts-hmac-sha384-192:aes256-sha2; do
    et="${pair%%:*}"
    short="${pair##*:}"
    docker exec "$NAME" sh -c "rm -f /tmp/from_kprop.dump /tmp/et.trace
sed 's/^\[libdefaults\]/&\n    default_tkt_enctypes = $et/' /tmp/kprop-krb5.conf >/tmp/kprop-krb5-et.conf"
    BULK="$(docker exec -e KRB5_CONFIG=/tmp/kprop-krb5-et.conf -e KRB5_TRACE=/tmp/et.trace \
        "$NAME" /tmp/krb5-kprop -f /tmp/bulk.dump -P 754 -s /tmp/host.keytab -d testhost.kerber.test 2>&1 || true)"
    echo "$et: $(echo "$BULK" | tail -1)"
    echo "$BULK" | grep -qx 'Database propagation to testhost.kerber.test: SUCCEEDED'
    [ "$(echo "$BULK" | grep -cE '^[0-9]+ bytes sent\.$')" -ge 3 ]
    docker exec "$NAME" grep -q "session key is: $short/" /tmp/et.trace
    docker exec "$NAME" cmp /tmp/bulk.dump /tmp/from_kprop.dump
done

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
[ "$(docker exec "$NAME" sh -c 'kdb5_util dump | grep -c "^princ.*bulk0250@KERBER.TEST"')" = 1 ]
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc' 2>&1 || true)"
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
