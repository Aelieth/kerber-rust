#!/usr/bin/env bash
# MIT parse-site knobs vs ignored Heimdal spellings. Needs the MIT harness.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"knobs-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}
NAME="kerber-rust-mit-kdc"
if ! docker ps -q --filter "name=^${NAME}$" | grep -q .; then
    echo "start the harness first: ./scripts/run-harness.sh" >&2
    exit 1
fi

cargo build -p krb5-client --bin krb5-kinit --bin krb5-klist -q
docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker cp target/debug/krb5-klist "$NAME":/tmp/krb5-klist
docker exec "$NAME" chmod +x /tmp/krb5-kinit /tmp/krb5-klist

echo "==== MIT kinit pacing is unchanged by kdc_timeout/max_retries ===="
docker exec "$NAME" sh -c 'cat >/tmp/heimdal-knobs.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    kdc_timeout = 1
    max_retries = 1
    ticket_lifetime = 10h
    forwardable = true
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF'
# MIT has no parse site for those keys; kinit must still succeed (not a 1s/1-retry fail).
MIT_RC=0
docker exec -e KRB5_CONFIG=/tmp/heimdal-knobs.conf "$NAME" \
    sh -c 'echo userpassword | kinit -c /tmp/krb5cc_knob_mit user@KERBER.TEST' || MIT_RC=$?
echo "mit_kinit_with_heimdal_knobs_rc=$MIT_RC"
test "$MIT_RC" -eq 0
docker exec -e KRB5_CONFIG=/tmp/heimdal-knobs.conf "$NAME" klist -c /tmp/krb5cc_knob_mit | grep -q 'user@KERBER.TEST'

RUST_RC=0
docker exec -e KRB5_CONFIG=/tmp/heimdal-knobs.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/krb5cc_knob_rust user@KERBER.TEST || RUST_RC=$?
echo "rust_kinit_with_heimdal_knobs_rc=$RUST_RC"
test "$RUST_RC" -eq 0

echo "==== honored forwardable + default_tkt_enctypes ===="
docker exec "$NAME" sh -c 'cat >/tmp/honored-knobs.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    ticket_lifetime = 10h
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF'
docker exec -e KRB5_CONFIG=/tmp/honored-knobs.conf "$NAME" \
    sh -c 'echo userpassword | kinit -c /tmp/krb5cc_etype_mit user@KERBER.TEST'
MIT_FE="$(docker exec -e KRB5_CONFIG=/tmp/honored-knobs.conf "$NAME" klist -f -e -c /tmp/krb5cc_etype_mit)"
echo "$MIT_FE"
echo "$MIT_FE" | grep -q 'Flags:'
echo "$MIT_FE" | awk -F'Flags: ' '/Flags:/{print $2}' | grep -q F
echo "$MIT_FE" | grep -q 'aes256-cts-hmac-sha1-96'

docker exec -e KRB5_CONFIG=/tmp/honored-knobs.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/krb5cc_etype_rust user@KERBER.TEST
RUST_FE="$(docker exec "$NAME" /tmp/krb5-klist -f -e -c /tmp/krb5cc_etype_rust)"
echo "$RUST_FE"
echo "$RUST_FE" | grep -q 'Flags:'
echo "$RUST_FE" | awk -F'Flags: ' '/Flags:/{print $2}' | grep -q F
echo "$RUST_FE" | grep -q 'aes256-cts-hmac-sha1-96'

echo "==== default_ccache_name env > conf > builtin ===="
UIDN="$(docker exec "$NAME" id -u)"
docker exec "$NAME" sh -c "cat >/tmp/ccache-conf.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    ticket_lifetime = 10h
    default_ccache_name = FILE:/tmp/g9b_conf_%{uid}
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF"
docker exec "$NAME" sh -c "cat >/tmp/ccache-none.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    ticket_lifetime = 10h
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF"

cache_line() {
    echo "$1" | sed -n 's/^Ticket cache: //p' | head -1
}

echo userpassword | docker exec -i -e KRB5_CONFIG=/tmp/ccache-conf.conf -e KRB5CCNAME=FILE:/tmp/g9b_env "$NAME" \
    kinit user@KERBER.TEST
MIT_ENV="$(docker exec -e KRB5_CONFIG=/tmp/ccache-conf.conf -e KRB5CCNAME=FILE:/tmp/g9b_env "$NAME" klist)"
echo "$MIT_ENV"
test "$(cache_line "$MIT_ENV")" = "FILE:/tmp/g9b_env"
docker exec -e KRB5_CONFIG=/tmp/ccache-conf.conf -e KRB5CCNAME=FILE:/tmp/g9b_env -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit user@KERBER.TEST
RUST_ENV="$(docker exec -e KRB5_CONFIG=/tmp/ccache-conf.conf -e KRB5CCNAME=FILE:/tmp/g9b_env "$NAME" /tmp/krb5-klist)"
echo "$RUST_ENV"
test "$(cache_line "$RUST_ENV")" = "FILE:/tmp/g9b_env"

docker exec "$NAME" rm -f "/tmp/g9b_conf_${UIDN}"
echo userpassword | docker exec -i -e KRB5_CONFIG=/tmp/ccache-conf.conf "$NAME" \
    env -u KRB5CCNAME kinit user@KERBER.TEST
MIT_CONF="$(docker exec -e KRB5_CONFIG=/tmp/ccache-conf.conf "$NAME" env -u KRB5CCNAME klist)"
echo "$MIT_CONF"
test "$(cache_line "$MIT_CONF")" = "FILE:/tmp/g9b_conf_${UIDN}"
docker exec -e KRB5_CONFIG=/tmp/ccache-conf.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    env -u KRB5CCNAME /tmp/krb5-kinit user@KERBER.TEST
RUST_CONF="$(docker exec -e KRB5_CONFIG=/tmp/ccache-conf.conf "$NAME" env -u KRB5CCNAME /tmp/krb5-klist)"
echo "$RUST_CONF"
test "$(cache_line "$RUST_CONF")" = "FILE:/tmp/g9b_conf_${UIDN}"

docker exec "$NAME" rm -f "/tmp/krb5cc_${UIDN}"
echo userpassword | docker exec -i -e KRB5_CONFIG=/tmp/ccache-none.conf "$NAME" \
    env -u KRB5CCNAME kinit user@KERBER.TEST
MIT_DEF="$(docker exec -e KRB5_CONFIG=/tmp/ccache-none.conf "$NAME" env -u KRB5CCNAME klist)"
echo "$MIT_DEF"
test "$(cache_line "$MIT_DEF")" = "FILE:/tmp/krb5cc_${UIDN}"
docker exec -e KRB5_CONFIG=/tmp/ccache-none.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    env -u KRB5CCNAME /tmp/krb5-kinit user@KERBER.TEST
RUST_DEF="$(docker exec -e KRB5_CONFIG=/tmp/ccache-none.conf "$NAME" env -u KRB5CCNAME /tmp/krb5-klist)"
echo "$RUST_DEF"
test "$(cache_line "$RUST_DEF")" = "FILE:/tmp/krb5cc_${UIDN}"

log "knobs.gate" "ok" ',"kdc_timeout":"ignored","forwardable":true,"default_tkt_enctypes":"aes256-cts-hmac-sha1-96","default_ccache_name":"env>conf>builtin"'
exit 0
