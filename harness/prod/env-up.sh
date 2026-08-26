#!/usr/bin/env bash
# Bring up the C1 multi-host prod realm: a real docker network with three
# resource-capped containers — a Rust KDC primary, a Rust KDC replica (staged),
# and an MIT client — then prove cross-container AS+TGS with the real MIT client
# and (best-effort) a real NIC packet capture.
#
# This is the *substrate* `scripts/prod-realm-gate.sh` formalizes. It brings up
# a named realm (`KERBER_PROD_REALM`, default PROD.KERBER.TEST) via
# `krb5-kdb create` (not `--test-realm`).
#
# Isolation: fully in-container on a dedicated docker network; never touches the
# host /etc/krb5.conf (stays TESTLABBY.LOCAL) or host SSSD.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$HERE/limits.env"

REALM="$KERBER_PROD_REALM"
DNS_DOMAIN="$(printf '%s' "$REALM" | tr '[:upper:]' '[:lower:]')"
NET="$KERBER_PROD_NET"
PRIMARY="kerber-rust-prod-kdc1"
REPLICA="kerber-rust-prod-kdc2"
CLIENT="kerber-rust-prod-client"
PRIMARY_FQDN="kdc1.${DNS_DOMAIN}"
REPLICA_FQDN="kdc2.${DNS_DOMAIN}"

say()  { printf '\033[1;36m[env-up]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[env-up] WARN:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[env-up] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"

# Pick the capture-tooling image; fall back to the lean base if it is not built.
IMAGE="$KERBER_PROD_IMAGE"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    warn "$IMAGE absent; falling back to $KERBER_PROD_IMAGE_FALLBACK (no in-container tcpdump/tshark)"
    IMAGE="$KERBER_PROD_IMAGE_FALLBACK"
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "neither prod-node nor base MIT image is built"
fi

for b in krb5-kdc krb5-kadmind krb5-kpropd krb5-kprop krb5-kdb; do
    [ -x "target/debug/$b" ] || die "missing target/debug/$b — run: cargo build -p krb5-kdc -p krb5-admin"
done

# Safety ceiling: never launch past KERBER_PROD_MAX_NODES capped containers.
existing="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -c '^kerber-rust-' || true)"
if [ "$existing" -gt "$KERBER_PROD_MAX_NODES" ]; then
    die "$existing kerber-rust-* containers already exist (ceiling $KERBER_PROD_MAX_NODES); run env-down.sh first"
fi

say "realm=$REALM  net=$NET  image=$IMAGE  caps=${KERBER_KDC_MEM}/${KERBER_KDC_CPUS}cpu per node"

# --- clean any prior instance, create the network -------------------------------
docker rm -f "$PRIMARY" "$REPLICA" "$CLIENT" >/dev/null 2>&1 || true
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
say "network $NET ready"

run_node() { # name hostname
    docker run -d --name "$1" --hostname "$2" --network "$NET" \
        --memory="$KERBER_KDC_MEM" --cpus="$KERBER_KDC_CPUS" \
        --cap-add=NET_RAW \
        --entrypoint sleep "$IMAGE" 86400 >/dev/null \
        || die "failed to launch $1"
}
run_node "$PRIMARY" "$PRIMARY_FQDN"
run_node "$REPLICA" "$REPLICA_FQDN"
run_node "$CLIENT"  "client.${DNS_DOMAIN}"
say "launched 3 capped nodes (primary/replica/client)"

# --- stage the Rust binaries on the KDC nodes -----------------------------------
for n in "$PRIMARY" "$REPLICA"; do
    docker cp target/debug/krb5-kdc     "$n":/usr/local/bin/krb5-kdc
    docker cp target/debug/krb5-kadmind "$n":/usr/local/bin/krb5-kadmind
    docker cp target/debug/krb5-kpropd  "$n":/usr/local/bin/krb5-kpropd
    docker cp target/debug/krb5-kprop   "$n":/usr/local/bin/krb5-kprop
    docker cp target/debug/krb5-kdb     "$n":/usr/local/bin/krb5-kdb
    docker exec "$n" chmod +x /usr/local/bin/krb5-kdc /usr/local/bin/krb5-kadmind \
        /usr/local/bin/krb5-kpropd /usr/local/bin/krb5-kprop /usr/local/bin/krb5-kdb
done
say "staged Rust binaries on kdc1 + kdc2"

# --- discover IPs, inject cross-container /etc/hosts (the samba-realtrust idiom) --
ip_of() { docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" "$1"; }
PIP="$(ip_of "$PRIMARY")"; RIP="$(ip_of "$REPLICA")"; CIP="$(ip_of "$CLIENT")"
[ -n "$PIP" ] && [ -n "$RIP" ] && [ -n "$CIP" ] || die "IP discovery failed"
for n in "$PRIMARY" "$REPLICA" "$CLIENT"; do
    docker exec "$n" sh -c "printf '%s %s\n%s %s\n%s client.%s\n' \
        '$PIP' '$PRIMARY_FQDN' '$RIP' '$REPLICA_FQDN' '$CIP' '$DNS_DOMAIN' >> /etc/hosts"
done
say "primary=$PIP  replica=$RIP  client=$CIP  (/etc/hosts cross-wired)"

# --- provision + start the PRIMARY Rust KDC (0.0.0.0:88) + kadmind ---------------
docker exec "$PRIMARY" sh -c "printf '%s *\n' 'admin@$REALM' >/tmp/kadm5.acl"
CREATE="$(docker exec \
    -e KRB5_KDC_DB=/tmp/prod.db -e KRB5_KDC_STASH=/tmp/prod.stash \
    -e KRB5_MASTER_PASSWORD="$KERBER_PROD_MASTER_PW" \
    -e KRB5_TEST_USER_PASSWORD="$KERBER_PROD_USER_PW" \
    -e KRB5_TEST_ADMIN_PASSWORD="$KERBER_PROD_ADMIN_PW" \
    "$PRIMARY" /usr/local/bin/krb5-kdb create "$REALM" 2>&1)" || {
    echo "$CREATE" >&2
    die "krb5-kdb create $REALM failed"
}
echo "$CREATE" | grep -q "ok create version=7" || die "create did not report dump v7: $CREATE"
echo "$CREATE" | grep -q "realm=$REALM" || die "create did not report realm: $CREATE"
docker exec "$PRIMARY" head -1 /tmp/prod.db | grep -q 'kdb5_util load_dump version 7' \
    || die "created db is not dump version 7"
docker exec "$PRIMARY" grep -q "krbtgt/${REALM}@${REALM}" /tmp/prod.db \
    || die "created db missing krbtgt/${REALM}"
say "created dump-v7 realm $REALM"

docker exec "$PRIMARY" mkdir -p /tmp/pdus
docker exec -d \
    -e KRB5_KDC_DB=/tmp/prod.db -e KRB5_KDC_STASH=/tmp/prod.stash \
    -e KRB5_MASTER_PASSWORD="$KERBER_PROD_MASTER_PW" \
    -e KERBER_CAPTURE_DIR=/tmp/pdus \
    -e RUST_LOG=info \
    -e CORRELATION_ID="${CORRELATION_ID:-}" \
    "$PRIMARY" sh -c '/usr/local/bin/krb5-kdc 0.0.0.0:88 >/tmp/kdc.log 2>&1'

ok=0
for _ in $(seq 1 60); do
    docker exec "$PRIMARY" grep -q '^listening' /tmp/kdc.log 2>/dev/null && { ok=1; break; }
    sleep 0.25
done
[ "$ok" = 1 ] || { docker exec "$PRIMARY" cat /tmp/kdc.log 2>&1 | tail -20 >&2; die "primary KDC did not listen"; }
say "primary KDC listening on ${PIP}:88 (realm $REALM)"

docker exec -d \
    -e KRB5_KDC_DB=/tmp/prod.db -e KRB5_KDC_STASH=/tmp/prod.stash \
    -e KRB5_MASTER_PASSWORD="$KERBER_PROD_MASTER_PW" \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    -e RUST_LOG=info \
    "$PRIMARY" sh -c '/usr/local/bin/krb5-kadmind 0.0.0.0:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    docker exec "$PRIMARY" grep -q '^listening' /tmp/kadmind.log 2>/dev/null && { ok=1; break; }
    sleep 0.25
done
[ "$ok" = 1 ] || { docker exec "$PRIMARY" cat /tmp/kadmind.log 2>&1 | tail -20 >&2; die "primary kadmind did not listen"; }
say "primary kadmind listening on ${PIP}:749"

# --- write the MIT client's KRB5_CONFIG (primary + replica by IP) ----------------
docker exec "$CLIENT" sh -c "cat >/tmp/prod-krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_prod
[realms]
    $REALM = {
        kdc = $PIP
        kdc = $RIP
        admin_server = $PIP
    }
EOF"

# --- SMOKE: real MIT client, cross-container AS+TGS (+ real pcap if tooling) ------
say "smoke: MIT kinit/kvno from client -> primary (cross-container)"
CAP=0
if docker exec "$PRIMARY" sh -c 'command -v tcpdump >/dev/null'; then
    # -U unbuffered. `port 88` alone drops IP fragments after the first (no UDP
    # header); PAC-sized AS-REP needs the fragment match or tshark never sees 11.
    docker exec -d "$PRIMARY" sh -c \
        'tcpdump -i eth0 -n -U -s 0 -w /tmp/prod.pcap "port 88 or port 754 or (ip[6:2] & 0x1fff != 0)" >/tmp/tcpdump.log 2>&1 & echo $! >/tmp/tcpdump.pid'
    sleep 0.8; CAP=1
fi

docker exec -e KRB5_CONFIG=/tmp/prod-krb5.conf "$CLIENT" kdestroy -A >/dev/null 2>&1 || true
smoke_rc=0
docker exec -e KRB5_CONFIG=/tmp/prod-krb5.conf "$CLIENT" \
    sh -c "printf '%s\n' '$KERBER_PROD_USER_PW' | kinit user@$REALM" >/tmp/prod-smoke.log 2>&1 || smoke_rc=1
docker exec -e KRB5_CONFIG=/tmp/prod-krb5.conf "$CLIENT" \
    kvno "host/testhost.${DNS_DOMAIN}@$REALM" >>/tmp/prod-smoke.log 2>&1 || smoke_rc=1
KL="$(docker exec -e KRB5_CONFIG=/tmp/prod-krb5.conf "$CLIENT" klist 2>&1)"
echo "$KL" | sed 's/^/    /'
echo "$KL" | grep -q "krbtgt/$REALM" || smoke_rc=1
echo "$KL" | grep -q "host/testhost.${DNS_DOMAIN}" || smoke_rc=1

if [ "$CAP" = 1 ]; then
    sleep 1.0
    docker exec "$PRIMARY" sh -c 'kill -INT "$(cat /tmp/tcpdump.pid 2>/dev/null)" 2>/dev/null; sleep 0.4' || true
    MSG="$(docker exec "$PRIMARY" sh -c 'tshark -r /tmp/prod.pcap -Y kerberos -T fields -e kerberos.msg_type 2>/dev/null | tr "," "\n" | sort -un | tr "\n" " "' 2>/dev/null)"
    PSZ="$(docker exec "$PRIMARY" sh -c 'wc -c </tmp/prod.pcap 2>/dev/null' 2>/dev/null | tr -d ' ')"
    say "real pcap on primary eth0: ${PSZ:-0} bytes, kerberos msg_types seen: ${MSG:-none}"
fi

if [ "$smoke_rc" != 0 ]; then
    docker exec "$CLIENT" cat /tmp/prod-smoke.log 2>&1 | tail -40 | sed 's/^/    /'
    die "smoke failed (MIT kinit/kvno against $REALM)"
fi
say "SMOKE OK — cross-container AS+TGS proven (MIT client -> Rust KDC over $NET)"

echo
say "realm is UP. Nodes (capped ${KERBER_KDC_MEM}/${KERBER_KDC_CPUS}cpu):"
printf '    %-28s %s\n' "$PRIMARY ($PRIMARY_FQDN)" "$PIP  [krb5-kdc :88, kadmind :749]"
printf '    %-28s %s\n' "$REPLICA ($REPLICA_FQDN)" "$RIP  [staged: krb5-kpropd/krb5-kdc ready]"
printf '    %-28s %s\n' "$CLIENT" "$CIP  [MIT kinit/kvno/kadmin; KRB5_CONFIG=/tmp/prod-krb5.conf]"
echo
say "next: exercise kprop primary->replica + failover (plan S1d), or ./harness/prod/env-status.sh"
say "tear down with: ./harness/prod/env-down.sh"
