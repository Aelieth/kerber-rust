#!/usr/bin/env bash
# MIT iprop serial-delta both ways, then MIT kinit of the *new* principal.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/proc-common.sh"
need_bins krb5-kdc krb5-pac-extract krb5-kadmind krb5-kdb krb5-kprop krb5-kpropd krb5-iprop-pull krb5-kadmin-local

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-iprop-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"

need_image

shell_container 3600 testhost.kerber.test
docker exec "$NAME" sh -c 'grep -v testhost.kerber.test /etc/hosts >/tmp/hosts.new; echo "127.0.0.1 testhost.kerber.test testhost" >>/tmp/hosts.new; cat /tmp/hosts.new >/etc/hosts'

if ! docker exec "$NAME" sh -c 'command -v kpropd >/dev/null && command -v kadmind >/dev/null'; then
    log "iprop.gate" "error" ',"error":"kpropd/kadmind missing"'
    echo "kpropd/kadmind missing" >"$SCRATCH/iprop-unavailable.log"
    exit 2
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-pac-extract" "$NAME":/tmp/krb5-pac-extract
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kprop" "$NAME":/tmp/krb5-kprop
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpropd" "$NAME":/tmp/krb5-kpropd
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-iprop-pull" "$NAME":/tmp/krb5-iprop-pull
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract /tmp/krb5-kadmind /tmp/krb5-kdb /tmp/krb5-kprop /tmp/krb5-kpropd /tmp/krb5-iprop-pull /tmp/krb5-kadmin-local
# The full dump an iprop replica takes, as MIT kadmind's resync child makes and sends it
# (ipropd_svc.c ipropx_resync): `kdb5_util dump -i1` of the Rust master, then `kprop -f`.
iprop_full_dump() {
    docker exec \
        -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf \
        -e KRB5_KDC_DB=/tmp/principal \
        -e KRB5_KDC_STASH=/tmp/stash \
        -e KRB5_MASTER_PASSWORD=masterpassword \
        "$NAME" /tmp/krb5-kdb dump -i1 /tmp/iprop.dump
    docker exec "$NAME" head -1 /tmp/iprop.dump | grep -E '^ipropx 1 [0-9]+ [0-9]+ [0-9]+$'
    docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
        "$NAME" /tmp/krb5-kprop -f /tmp/iprop.dump -P 754 -s /tmp/iprop.keytab testhost.kerber.test 2>&1 || true
}
docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *
kiprop/*@KERBER.TEST p
EOF'

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
# The Rust kadmind serves the iprop program only with iprop_enable, as MIT's registers it only
# then (ovsec_kadmd.c setup_loop): its profile is the container's kdc.conf with iprop on, and
# its update log /tmp/principal.ulog, which MIT's kproplog reads with the same profile.
docker exec "$NAME" sh -c '{ sed -n "1,/^    KERBER.TEST = {/p" /etc/krb5kdc/kdc.conf; printf "        iprop_enable = true\n        iprop_port = 749\n        iprop_logfile = /tmp/principal.ulog\n"; sed "1,/^    KERBER.TEST = {/d" /etc/krb5kdc/kdc.conf; } >/tmp/rust-iprop-kdc.conf'
docker exec "$NAME" cat /tmp/rust-iprop-kdc.conf
docker exec "$NAME" grep -q '^        iprop_enable = true$' /tmp/rust-iprop-kdc.conf

# A full resync as MIT's ipropx_resync makes it (ipropd_svc.c:257-447): a legacy request gets the
# -i0 dump; after an outside write, a replica's gets an -i1 dump from disk with its .dump_ok, then
# kprop with its .last_prop. An outside policy change restarts the log, and the synced replica's next
# resync must carry it. MIT's kadmind first, then ours; -k 754, as this image has no krb5_prop
# service.
outside_mit() { kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/m0/kdc.conf "$NAME" -- -q "$1"; }
outside_rust() {
    kadmin_q_ok rust_kadmin_local -e KRB5_KDC_DB=/tmp/r0/principal -e KRB5_KDC_STASH=/tmp/r0/stash \
        -e KRB5_KDC_PROFILE=/tmp/r0/kdc.conf "$NAME" -- -q "$1"
}
wait_for() {
    local n=$1
    shift
    for _ in $(seq 1 "$n"); do
        "$@" && return 0
        sleep 0.1
    done
    return 1
}
has_head() { docker exec "$NAME" sh -c "head -1 '$1' 2>/dev/null | grep -Eq '$2'"; }
replica_has() {
    docker exec -e KRB5_KDC_PROFILE=/tmp/replica/kdc.conf "$NAME" kadmin.local -q listprincs 2>/dev/null |
        grep -qx "$1@KERBER.TEST"
}
replica_has_policy() {
    docker exec -e KRB5_KDC_PROFILE=/tmp/replica/kdc.conf "$NAME" kadmin.local -q "getpol $1" 2>/dev/null |
        grep -qx "Policy: $1"
}
replica_kpropd() {
    local port=$1 stash=$2 keytab=$3
    docker exec "$NAME" sh -c "rm -rf /tmp/replica && mkdir /tmp/replica &&
printf 'host/testhost.kerber.test@KERBER.TEST\n' >/tmp/replica/kpropd.acl &&
printf '[realms]\n    KERBER.TEST = {\n        database_name = /tmp/replica/principal\n        key_stash_file = $stash\n        iprop_enable = true\n        iprop_port = $port\n        iprop_slave_poll = 2\n    }\n' >/tmp/replica/kdc.conf &&
sed 's/iprop_port = 749/iprop_port = $port/' /tmp/iprop-krb5.conf >/tmp/replica/krb5.conf"
    docker exec -d -e KRB5_KDC_PROFILE=/tmp/replica/kdc.conf -e KRB5_CONFIG=/tmp/replica/krb5.conf "$NAME" \
        sh -c "kpropd -S -d -A testhost.kerber.test -a /tmp/replica/kpropd.acl -P 754 -s $keytab \
-f /tmp/replica/from-kprop.dump -p \"\$(command -v kdb5_util)\" >/tmp/replica/kpropd.log 2>&1"
}
resync_cells() {
    local leg=$1 port=$2 keytab=$3 dump=$4 stash=$5 outside=$6 primary_log=$7 differ='' v0 x1
    docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf -e KRB5_MASTER_PASSWORD=masterpassword \
        -e KRB5_KDC_DB=/tmp/v0-pull -e KRB5_KDC_STASH=/tmp/v0-pull.stash -e KRB5_KPROP_KEYTAB="$keytab" \
        -e KRB5_KDC=127.0.0.1 -e KRB5_IPROP_HOST=testhost.kerber.test \
        "$NAME" /tmp/krb5-iprop-pull --full-resync-v0 "testhost.kerber.test:$port" || true
    wait_for 100 has_head "$dump" '^iprop [0-9]+ [0-9]+ [0-9]+$' || differ="$differ v0-header"
    v0="$(docker exec "$NAME" head -1 "$dump" 2>/dev/null || true)"
    docker exec "$NAME" sh -c "rm -f '$dump' '$dump.dump_ok' '$dump'.*.last_prop"
    "$outside" 'addprinc -randkey outsider'
    replica_kpropd "$port" "$stash" "$keytab"
    wait_for 300 replica_has outsider || differ="$differ replica-outsider"
    replica_has user || differ="$differ replica-user"
    has_head "$dump" '^ipropx 1 [0-9]+ [0-9]+ [0-9]+$' || differ="$differ x1-header"
    x1="$(docker exec "$NAME" head -1 "$dump" 2>/dev/null || true)"
    docker exec "$NAME" test -f "$dump.dump_ok" || differ="$differ dump_ok"
    docker exec "$NAME" test -f "$dump.testhost.kerber.test.last_prop" || differ="$differ last_prop"
    "$outside" 'addpol -history 2 outpol'
    wait_for 300 replica_has_policy outpol || differ="$differ replica-policy"
    docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" \
        /tmp/krb5-kprop -f "$dump" -P 754 -s "$keytab" testhost.kerber.test 2>&1 |
        grep -qx 'Database propagation to testhost.kerber.test: SUCCEEDED' || differ="$differ kprop-f"
    kill_comm kpropd
    echo "$leg full resync: -i0 '$v0', -i1 '$x1', differences:${differ:- none}"
    if [ -n "$differ" ]; then
        docker exec "$NAME" cat /tmp/replica/kpropd.log "$primary_log" >&2 || true
        die "the $leg kadmind's full resync is not MIT's:$differ"
    fi
}

echo "==== 0: MIT kadmind master: full resyncs, dumped from disk and kpropped ===="
# krb5-iprop-pull takes its realm from a store; the legacy probe's is a fresh one.
docker exec -e KRB5_KDC_DB=/tmp/v0-pull -e KRB5_KDC_STASH=/tmp/v0-pull.stash "$NAME" \
    /tmp/krb5-kdb -r KERBER.TEST -P masterpassword create -s >/dev/null
docker exec "$NAME" sh -c 'rm -rf /tmp/m0 && mkdir /tmp/m0 &&
printf "admin@KERBER.TEST *\nkiprop/testhost.kerber.test@KERBER.TEST p\n" >/tmp/m0/kadm5.acl &&
printf "[realms]\n    KERBER.TEST = {\n        database_name = /tmp/m0/principal\n        acl_file = /tmp/m0/kadm5.acl\n        key_stash_file = /tmp/m0/stash\n        kadmind_port = 749\n        kdc_ports = 88\n        iprop_enable = true\n        iprop_port = 2121\n        iprop_listen = 0.0.0.0:2121\n        iprop_master_ulogsize = 1000\n    }\n" >/tmp/m0/kdc.conf'
docker exec -e KRB5_KDC_PROFILE=/tmp/m0/kdc.conf "$NAME" kdb5_util create -s -P masterpassword >/dev/null
for q in 'addprinc -pw userpassword user' 'addprinc -randkey kiprop/testhost.kerber.test' \
    'addprinc -randkey host/testhost.kerber.test' \
    'ktadd -k /tmp/m0/iprop.keytab kiprop/testhost.kerber.test host/testhost.kerber.test'; do
    kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/m0/kdc.conf "$NAME" -- -q "$q"
done
docker exec -d -e KRB5_KDC_PROFILE=/tmp/m0/kdc.conf -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_KTNAME=/tmp/m0/iprop.keytab \
    "$NAME" sh -c 'krb5kdc; kadmind -nofork -F /tmp/m0/resync.dump -k 754 >/tmp/m0/kadmind.log 2>&1'
wait_port_in "$NAME" 88 || die "MIT krb5kdc did not listen"
wait_port_in "$NAME" 749 || die "MIT kadmind did not listen"
wait_port_in "$NAME" 2121 || die "MIT kadmind's iprop did not listen"
resync_cells MIT 2121 /tmp/m0/iprop.keytab /tmp/m0/resync.dump /tmp/m0/stash outside_mit \
    /tmp/m0/kadmind.log
kill_comm kadmind
kill_comm krb5kdc

echo "==== 0R: Rust kadmind master: the same full resyncs ===="
docker exec "$NAME" sh -c 'rm -rf /tmp/r0 && mkdir /tmp/r0 && { sed -n "1,/^    KERBER.TEST = {/p" /etc/krb5kdc/kdc.conf; printf "        iprop_enable = true\n        iprop_port = 749\n        iprop_logfile = /tmp/r0/principal.ulog\n"; sed "1,/^    KERBER.TEST = {/d" /etc/krb5kdc/kdc.conf; } >/tmp/r0/kdc.conf'
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/r0/principal \
    -e KRB5_KDC_STASH=/tmp/r0/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 0.0.0.0:88 >/tmp/r0/kdc.log 2>&1'
require_log "$NAME" /tmp/r0/kdc.log '^listening ' "the Rust KDC for 0R"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/r0/principal \
    -e KRB5_KDC_STASH=/tmp/r0/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    -e KRB5_KDC_PROFILE=/tmp/r0/kdc.conf \
    -e KRB5_KTNAME=/tmp/r0/iprop.keytab \
    "$NAME" sh -c '/tmp/krb5-kadmind -F /tmp/r0/resync.dump -k 754 0.0.0.0:749 >/tmp/r0/kadmind.log 2>&1'
require_log "$NAME" /tmp/r0/kadmind.log '^listening ' "the Rust kadmind for 0R"
kadmin_q_try mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -randkey kiprop/testhost.kerber.test'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q \
    'ktadd -k /tmp/r0/iprop.keytab kiprop/testhost.kerber.test host/testhost.kerber.test'
resync_cells Rust 749 /tmp/r0/iprop.keytab /tmp/r0/resync.dump /tmp/r0/stash outside_rust \
    /tmp/r0/kadmind.log
kill_comm krb5-kadmind
kill_comm krb5-kdc

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
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf \
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
kadmin_q_try mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q \
    'addprinc -randkey kiprop/testhost.kerber.test'
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q \
    'ktadd -k /tmp/iprop.keytab kiprop/testhost.kerber.test host/testhost.kerber.test'

echo "==== full-resync deny is kdb_fullresync_result_t (Rust) ===="
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q \
    'ktadd -k /tmp/user-iprop.keytab user'
DENY="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_KPROP_KEYTAB=/tmp/user-iprop.keytab \
    -e KRB5_KDC=127.0.0.1 \
    -e KRB5_IPROP_HOST=testhost.kerber.test \
    "$NAME" /tmp/krb5-iprop-pull --full-resync testhost.kerber.test:749 2>&1 || true)"
echo "$DENY"
echo "$DENY" | grep -F 'fullresync_status=5'
if echo "$DENY" | grep -q 'fullresync_status=0'; then
    echo "Rust full-resync deny granted: $DENY" >&2
    exit 1
fi
# ipropd_svc.c:311-320: a refused full resync is a LOG_UNAUTH line.
# MIT's, in its cell below, is the oracle.
unauth_line() { sed -n 's/^.*(Notice): \(Unauthorized request: iprop_[a-z_]*_1, client=[^,]*, service=[^,]*\), addr=.*$/\1/p' | head -1; }
RUST_FR_UNAUTH="$(docker exec "$NAME" cat /tmp/kadmind.log | unauth_line)"
echo "rust: $RUST_FR_UNAUTH"
[ "$RUST_FR_UNAUTH" = 'Unauthorized request: iprop_full_resync_1, client=user@KERBER.TEST, service=kiprop/testhost.kerber.test@KERBER.TEST' ] ||
    die "the Rust kadmind's full-resync deny is not MIT's LOG_UNAUTH line"

docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" sh -c 'printf "host/testhost.kerber.test@KERBER.TEST\nkiprop/testhost.kerber.test@KERBER.TEST\n" >/tmp/kpropd.acl'
kill_comm kpropd

echo "==== MIT kpropd is denied by the Rust master when kiprop has no p (get_updates permission denied) ===="
docker exec "$NAME" sh -c 'printf "%s\n" "admin@KERBER.TEST *" > /tmp/kadm5.acl'
kill_comm krb5-kadmind
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kadmind 0.0.0.0:749 >/tmp/kadmind-nop.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind-nop.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind-nop.log >&2 || true
    log "iprop.gate" "error" ',"error":"kadmind did not listen with no-p ACL"'
    exit 1
fi
KPROPD_DENY="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf -e KRB5_KTNAME=/tmp/iprop.keytab \
    "$NAME" sh -c 'timeout 25 kpropd -S -d -A testhost.kerber.test -a /tmp/kpropd.acl -P 754 -s /tmp/iprop.keytab -f /tmp/from_kprop.dump -p "$(command -v kdb5_util)" 2>&1' || true)"
echo "$KPROPD_DENY"
echo "$KPROPD_DENY" | grep -F 'get_updates permission denied'
retry_until --log "$NAME" /tmp/kadmind-nop.log -- 200 'LOG_UNAUTH in /tmp/kadmind-nop.log' \
    docker exec "$NAME" grep -qF '(Notice): Unauthorized request: iprop_get_updates_1, client=kiprop/testhost.kerber.test@KERBER.TEST, service=' /tmp/kadmind-nop.log
docker exec "$NAME" grep -F 'Unauthorized request: iprop_get_updates_1' /tmp/kadmind-nop.log
docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *
kiprop/*@KERBER.TEST p
EOF'
kill_comm krb5-kadmind
# The rpc.flavor event below is debug; a test-hooks build reads RUST_LOG.
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf \
    -e RUST_LOG=krb5_kdc=info,krb5_admin=debug \
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
    log "iprop.gate" "error" ',"error":"kadmind did not listen after restoring p"'
    exit 1
fi
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
IPROP_LOG="$(docker exec "$NAME" cat /tmp/kpropd-iprop.log 2>/dev/null || true)"
echo "$IPROP_LOG"
if echo "$IPROP_LOG" | grep -qiE 'Program not registered|PROG_UNAVAIL'; then
    log "iprop.gate" "error" ',"error":"MIT kpropd -A: IPROP program not served"'
    exit 1
fi
echo "==== Rust kadmind rpc_flavor vs MIT kpropd ===="
_iprop_rpcsec_gss() {
    docker exec "$NAME" grep -F '"prog":100423' /tmp/kadmind.log \
        | grep -qF '"rpc_flavor":"RPCSEC_GSS"'
}
retry_until --log "$NAME" /tmp/kadmind.log -- 200 'RPCSEC_GSS on IPROP_PROG in /tmp/kadmind.log' _iprop_rpcsec_gss
KADMLOG="$(docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true)"
echo "$KADMLOG"
echo "$KADMLOG" | grep -F '"prog":100423' | grep -F '"rpc_flavor":"RPCSEC_GSS"' || {
    echo "MIT kpropd did not negotiate RPCSEC_GSS on IPROP_PROG against Rust kadmind" >&2
    exit 1
}
if echo "$KADMLOG" | grep -F '"prog":100423' | grep -F '"rpc_flavor":"AUTH_GSSAPI"'; then
    echo "MIT kpropd used AUTH_GSSAPI on IPROP_PROG against Rust kadmind" >&2
    exit 1
fi
echo "rpc_flavor=RPCSEC_GSS"

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

# A policy change starts the update log over (kdb5.c ulog_init_header), so the
# history policy is made before the first-contact dump the replica loads.
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addpol -history 3 ihp'
mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'getpol ihp' 2>&1 | grep -F 'Policy: ihp'

echo "==== first contact: krb5-kdb dump -i1 (ipropx last_sno), then Rust kprop -f ===="
KPROP="$(iprop_full_dump)"
echo "$KPROP"
echo "$KPROP" | grep -qE '^ipropx 1 [0-9]+ [0-9]+ [0-9]+$'
echo "$KPROP" | grep -qx 'Database propagation to testhost.kerber.test: SUCCEEDED'
ok=0
for _ in $(seq 1 40); do
    if mit_kadmin_local "$NAME" -- -q 'getprinc user' 2>/dev/null | grep -q 'Principal: user@KERBER.TEST'; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    kadmin_q_try mit_kadmin_local "$NAME" -- -q 'getprinc user' 2>&1
    docker exec "$NAME" cat /tmp/kpropd-iprop.log >&2 || true
    log "iprop.gate" "error" ',"error":"MIT replica missing user after full-resync kprop"'
    exit 1
fi

echo "==== mutate master: MIT kadmin addprinc extra ===="
ADD="$(mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addprinc -pw extra-secret extra' 2>&1 || true)"
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
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf \
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

echo "==== persisted ulog after restart: MIT kproplog reads the Rust master's update log ===="
KPL="$(docker exec -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf "$NAME" kproplog -v 2>&1 || true)"
echo "$KPL"
echo "$KPL" | grep -F 'Kerberos update log (/tmp/principal.ulog)'
echo "$KPL" | grep -F 'Update principal : extra@KERBER.TEST'

echo "==== wait MIT kpropd -A GET_UPDATES serial-delta ===="
ok=0
for _ in $(seq 1 40); do
    if mit_kadmin_local "$NAME" -- -q 'getprinc extra' 2>/dev/null | grep -q 'Principal: extra@KERBER.TEST'; then
        ok=1
        break
    fi
    sleep 1
done
echo "==== kpropd-iprop.log (delta) ===="
require_log "$NAME" /tmp/kpropd-iprop.log 'Got incremental updates|Incremental updates:' "incremental updates in /tmp/kpropd-iprop.log"
DELTA_LOG="$(docker exec "$NAME" cat /tmp/kpropd-iprop.log 2>/dev/null || true)"
echo "$DELTA_LOG"
echo "$DELTA_LOG" | grep -qiE 'Got incremental updates|Incremental updates:'
FR="$(echo "$DELTA_LOG" | grep -ci 'Full resync needed' || true)"
if [ "$FR" -gt 1 ]; then
    log "iprop.gate" "error" ",\"error\":\"spurious FULL_RESYNC after restart, got $FR\""
    exit 1
fi
echo "$DELTA_LOG" | grep -qi 'Got incremental updates'
# ipropd_svc.c:202-230: each GET_UPDATES is a Request line; MIT's kadmind writes the same in leg B.
REQ_RE='\(Notice\): Request: iprop_get_updates_1, UPDATE_OK; Incoming SerialNo=[0-9]+; Outgoing SerialNo=[0-9]+, success, client=kiprop/testhost.kerber.test@KERBER.TEST, service=kiprop/testhost.kerber.test@KERBER.TEST, addr='
docker exec "$NAME" grep -E "$REQ_RE" /tmp/kadmind.log | tail -1
docker exec "$NAME" grep -qE "$REQ_RE" /tmp/kadmind.log ||
    die "the Rust kadmind wrote no MIT Request line for GET_UPDATES"
if [ "$ok" != 1 ]; then
    kadmin_q_try mit_kadmin_local "$NAME" -- -q 'getprinc extra' 2>&1
    kadmin_q_try mit_kadmin_local "$NAME" -- -q 'getprinc user' 2>&1
    docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kdb5_util dump /tmp/after-delta.dump 2>&1 || true
    echo "==== replica dump extra ===="
    docker exec "$NAME" grep extra /tmp/after-delta.dump 2>/dev/null || true
    docker exec "$NAME" head -3 /tmp/after-delta.dump 2>/dev/null || true
    echo "==== kadmind.log ===="
    docker exec "$NAME" cat /tmp/kadmind.log 2>/dev/null || true
    log "iprop.gate" "error" ',"error":"MIT replica missing extra after serial-delta (GET_UPDATES)"'
    exit 1
fi

echo "==== a kadm5 tl_data 1024 on the Rust master reaches MIT kpropd in AT_TL_DATA ===="
# kdb_convert.c ulog_conv_2logentry sends every tl_data; here the delegation ACL is one of them.
docker cp "$ROOT/scripts/oracle/kadm5-changepw-rpc.c" "$NAME":/tmp/kadm5-changepw-rpc.c
mit_oracle_cc "$NAME" /tmp/kadm5-changepw-rpc /tmp/kadm5-changepw-rpc.c kadm-client
DELEG="$(docker exec -e KRB5_CONFIG=/tmp/iprop-krb5.conf "$NAME" /tmp/kadm5-changepw-rpc \
    --service kadmin/admin admin@KERBER.TEST adminpassword KERBER.TEST \
    tl-deleg extra host/target.kerber.test@KERBER.TEST 2>&1 || true)"
echo "$DELEG"
echo "$DELEG" | grep -Fx 'tl=1024:host/target.kerber.test@KERBER.TEST'
DELEG_HEX="$(printf 'host/target.kerber.test@KERBER.TEST\0' | od -An -tx1 | tr -d ' \n')"
ok=0
for _ in $(seq 1 40); do
    docker exec "$NAME" kdb5_util dump /tmp/deleg.dump >/dev/null 2>&1 || true
    if docker exec "$NAME" grep -F $'\textra@KERBER.TEST\t' /tmp/deleg.dump 2>/dev/null |
        grep -qF $'\t1024\t36\t'"$DELEG_HEX"; then
        ok=1
        break
    fi
    sleep 1
done
[ "$ok" = 1 ] || die "the MIT replica has no tl_data 1024 for extra after the Rust master's update"

echo "==== a policy change restarts the log: MIT kpropd asks for a full resync, and the dump carries the policy ===="
# kdb5.c krb5_db_create_policy: a logging primary reinitializes its update log
# after a policy change (one dummy entry at serial 1), so the replica, past it,
# needs the full dump. Here it is pushed with krb5-kdb dump -i1 and krb5-kprop -f, as an operator
# would; legs 0 and 0R prove kadmind's own resync.
FR_BEFORE="$(docker exec "$NAME" grep -c 'Full resync needed' /tmp/kpropd-iprop.log || true)"
kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q 'addpol -history 2 ihp2'
KPL_RESET="$(docker exec -e KRB5_KDC_PROFILE=/tmp/rust-iprop-kdc.conf "$NAME" kproplog -h 2>&1 || true)"
echo "$KPL_RESET"
echo "$KPL_RESET" | grep -F 'Number of entries : 1'
echo "$KPL_RESET" | grep -F 'Last serial # : 1'
_full_resync_again() {
    [ "$(docker exec "$NAME" grep -c 'Full resync needed' /tmp/kpropd-iprop.log || true)" -gt "$FR_BEFORE" ]
}
retry_until --log "$NAME" /tmp/kpropd-iprop.log -- 400 'a second Full resync needed in /tmp/kpropd-iprop.log' _full_resync_again
echo "MIT kpropd Full resync needed: $FR_BEFORE before the policy, $(docker exec "$NAME" grep -c 'Full resync needed' /tmp/kpropd-iprop.log || true) after"
KPROP2="$(iprop_full_dump)"
echo "$KPROP2"
echo "$KPROP2" | grep -qE '^ipropx 1 [0-9]+ [0-9]+ [0-9]+$'
echo "$KPROP2" | grep -qx 'Database propagation to testhost.kerber.test: SUCCEEDED'
ok=0
for _ in $(seq 1 40); do
    if mit_kadmin_local "$NAME" -- -q 'getpol ihp2' 2>/dev/null | grep -q 'Policy: ihp2'; then
        ok=1
        break
    fi
    sleep 0.5
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd-iprop.log >&2 || true
    log "iprop.gate" "error" ',"error":"MIT replica missing ihp2 after the full resync"'
    exit 1
fi
mit_kadmin_local "$NAME" -- -q 'getpol ihp2' 2>&1 | grep -F 'Number of old keys kept: 2'

echo "==== password history propagates: MIT kpropd applies the KADM_DATA record under kadmin/history ===="
# kdb_convert.c: the admin record, with the policy and the history, travels
# inside AT_TL_DATA, and the replica refuses the remembered password itself.
for q in 'addprinc -pw i3cret1 -policy ihp ihist' 'cpw -pw i3cret2 ihist'; do
    kadmin_q_ok mit_kadmin -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
        "$NAME" -- -p admin@KERBER.TEST -w adminpassword -q "$q"
done
ok=0
for _ in $(seq 1 40); do
    if mit_kadmin_local "$NAME" -- -q 'getprinc ihist' 2>/dev/null | grep -q 'Policy: ihp'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    kadmin_q_try mit_kadmin_local "$NAME" -- -q 'getprinc ihist' 2>&1
    docker exec "$NAME" cat /tmp/kpropd-iprop.log >&2 || true
    log "iprop.gate" "error" ',"error":"MIT replica missing ihist with its policy after the history chpass"'
    exit 1
fi
REPL_HIST="$(mit_kadmin_local "$NAME" -- -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$REPL_HIST"
echo "$REPL_HIST" | grep -F 'Principal: kadmin/history@KERBER.TEST'
REPL_REUSE="$(mit_kadmin_local "$NAME" -- -q 'cpw -pw i3cret1 ihist' 2>&1 || true)"
echo "$REPL_REUSE"
echo "$REPL_REUSE" | grep -F 'Cannot reuse password while changing password for "ihist@KERBER.TEST".'
mit_kadmin_local "$NAME" -- -q 'cpw -pw i3cret3 ihist' 2>&1 | grep -F 'Password for "ihist@KERBER.TEST" changed.'

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
docker exec "$NAME" sh -c 'krb5kdc' >/dev/null 2>&1 || true
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
[logging]
    admin_server = FILE:/tmp/mit-admin.log
EOF'
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" kdb5_util create -s -P masterpassword
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" -- -q 'addprinc -pw userpassword user'
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" -- -q 'addprinc -pw adminpassword admin'
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" -- -q 'addprinc -randkey kiprop/testhost.kerber.test'
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" -- -q 'addprinc -randkey host/testhost.kerber.test'
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf "$NAME" -- -q 'ktadd -k /tmp/mit-iprop.keytab kiprop/testhost.kerber.test host/testhost.kerber.test'
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
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    "$NAME" /tmp/krb5-iprop-pull --load-dump /tmp/mit.dump 2>&1 || true)"
echo "$LOAD"
echo "$LOAD" | grep -q 'iprop dump'

echo "==== full-resync deny is kdb_fullresync_result_t (MIT) ===="
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" -- -q 'ktadd -k /tmp/user-iprop.keytab user'
MIT_DENY="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    -e KRB5_KPROP_KEYTAB=/tmp/user-iprop.keytab \
    -e KRB5_KDC=127.0.0.1 \
    -e KRB5_IPROP_HOST=testhost.kerber.test \
    "$NAME" /tmp/krb5-iprop-pull --full-resync testhost.kerber.test:2121 2>&1 || true)"
echo "$MIT_DENY"
echo "$MIT_DENY" | grep -F 'fullresync_status=5'
if echo "$MIT_DENY" | grep -q 'fullresync_status=0'; then
    echo "MIT full-resync deny granted: $MIT_DENY" >&2
    exit 1
fi
MIT_FR_UNAUTH="$(docker exec "$NAME" cat /tmp/mit-admin.log | unauth_line)"
echo "mit:  $MIT_FR_UNAUTH"
echo "rust: $RUST_FR_UNAUTH"
[ -n "$MIT_FR_UNAUTH" ] && [ "$MIT_FR_UNAUTH" = "$RUST_FR_UNAUTH" ] ||
    die "MIT's full-resync LOG_UNAUTH line is not the Rust kadmind's"

echo "==== mutate MIT master: extra2 + setstr ===="
# extra2's flags, lifetimes and expirations are set before the setstr, whose MIT update
# carries none of them (kdb_convert.c find_changed_attrs).
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" -- -q 'addprinc -pw extra2-secret +requires_preauth -allow_postdated -maxlife "5 hours" -maxrenewlife "3 days" -expire "2031-01-01 00:00:00 UTC" -pwexpire "2030-06-01 00:00:00 UTC" extra2'
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" -- -q 'setstr extra2 note hello-g4a'

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
docker exec "$NAME" grep -E "$REQ_RE" /tmp/mit-admin.log | tail -1
docker exec "$NAME" grep -qE "$REQ_RE" /tmp/mit-admin.log ||
    die "MIT's kadmind wrote no Request line for GET_UPDATES"
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
# kdb_convert.c ulog_conv_2dbentry: the replica applies only what an update carries.
kadmin_q_ok \
    --then 'getprinc extra2' '^Attributes: DISALLOW_POSTDATED REQUIRES_PRE_AUTH$' \
    --then 'getprinc extra2' '^Maximum ticket life: 0 days 05:00:00$' \
    --then 'getprinc extra2' '^Maximum renewable life: 3 days 00:00:00$' \
    --then 'getprinc extra2' '^Expiration date: Wed Jan 01 00:00:00 UTC 2031$' \
    --then 'getprinc extra2' '^Password expiration date: Sat Jun 01 00:00:00 UTC 2030$' \
    rust_kadmin_local -e KRB5_CONFIG=/tmp/iprop-krb5.conf -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash "$NAME" -- -q 'getprinc extra2'
echo "==== Rust iprop-pull vs MIT kadmind: a MIC lost between two calls ===="
# client_init.c:662 asks MUTUAL|REPLAY, so the primary takes a call after a gap with no refresh.
GAP="$(docker exec \
    -e KRB5_CONFIG=/tmp/iprop-krb5.conf \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    -e KRB5_KPROP_KEYTAB=/tmp/mit-iprop.keytab \
    -e KRB5_KDC=127.0.0.1 \
    -e KRB5_IPROP_HOST=testhost.kerber.test \
    "$NAME" /tmp/krb5-iprop-pull --skip-mic --last-sno "$SNO2" --last-time "$SEC2" "$USEC2" testhost.kerber.test:2121 2>&1 || true)"
echo "$GAP"
echo "$GAP" | grep -q 'iprop pull ok'
echo "$GAP" | grep -q '^iprop refreshes=0$'
kill_comm krb5kdc
# A PAC carries the RID only as AD data: the replica's kdc.conf gives the realm an AD identity.
docker exec "$NAME" sh -c "sed 's/^\( *\)KERBER.TEST = {\$/&\n\1    domain_sid = S-1-5-21-4242424242-4242424242-4242424245/' \
    /etc/krb5kdc/kdc.conf > /tmp/rust-replica-kdc.conf"
docker exec "$NAME" grep -q 'domain_sid = S-1-5-21-' /tmp/rust-replica-kdc.conf
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust-replica \
    -e KRB5_KDC_STASH=/tmp/rust-replica.stash \
    -e KRB5_EXPORT_KEYTAB=/tmp/replica-host.keytab \
    -e KRB5_KDC_PROFILE=/tmp/rust-replica-kdc.conf \
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
kadmin_q_ok mit_kadmin_local -e KRB5_KDC_PROFILE=/tmp/kdc.conf \
    "$NAME" -- -q 'delprinc -force extra2'
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

log "iprop.gate" "ok" ",\"op\":\"full-resync-mit+rust+kpropd-A-delta-kinit-extra+mit-kadmind-pull-kinit-extra2+delprinc\",\"extra2_pac_rid\":$RID"
exit 0
