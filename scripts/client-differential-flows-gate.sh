#!/usr/bin/env bash
# 11 FLOW_* sections (plain…anon): both clients vs the MIT 1.22.2 KDC
# through kdc-req-proxy.py. KEEP-attach for the CLI/gss/Z half.
# Isolation: in-container; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/client-diff-common.sh"
need_bins krb5-kinit krb5-klist krb5-kvno krb5-kdestroy krb5-vfy-increds krb5-kdc krb5-forge-tgt krb5-pac-extract krb5-gss-accept krb5-gss-init krb5-kpasswd

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-client-diff-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-client-diff-gate}"
mkdir -p "$SCRATCH"
PROXY_PORT=1891
EXPECTED_FLOWS=11

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi

need_image
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    unavailable "MIT image unavailable"
fi

python3 "$ROOT/scripts/lib/kdc-req-proxy.py" --self-test || die "kdc-req-proxy self-test failed"

if [ "${KERBER_CLIENT_DIFF_KEEP:-}" = 1 ]; then
    export KERBER_STOCK_KEEP=1
fi
stock_mit_kdc
if [ "${KERBER_LIVE:-}" = 1 ]; then
    mit_conf_snapshot "$NAME"
    if [ "${KERBER_CLIENT_DIFF_KEEP:-}" != 1 ]; then
        register_cleanup "mit_conf_restore '$NAME'"
    fi
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-klist" "$NAME":/tmp/krb5-klist
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kvno" "$NAME":/tmp/krb5-kvno
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdestroy" "$NAME":/tmp/krb5-kdestroy
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc-export
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-gss-accept" "$NAME":/tmp/krb5-gss-accept
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-gss-init" "$NAME":/tmp/krb5-gss-init
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-forge-tgt" "$NAME":/tmp/krb5-forge-tgt
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-pac-extract" "$NAME":/tmp/krb5-pac-extract
docker cp "$ROOT/scripts/lib/kdc-req-proxy.py" "$NAME":/tmp/kdc-req-proxy.py
docker cp "$ROOT/scripts/lib/skew-preload.c" "$NAME":/tmp/skew-preload.c
docker cp "$ROOT/scripts/gss-mit-client.c" "$NAME":/tmp/gss-mit-client.c
docker cp "$ROOT/scripts/gss-mit-server.c" "$NAME":/tmp/gss-mit-server.c
docker exec "$NAME" chmod +x /tmp/krb5-kinit /tmp/krb5-klist /tmp/krb5-kvno /tmp/krb5-kdestroy \
    /tmp/krb5-kdc-export /tmp/krb5-gss-accept /tmp/krb5-gss-init /tmp/krb5-forge-tgt \
    /tmp/krb5-pac-extract /tmp/kdc-req-proxy.py

docker exec "$NAME" mkdir -p /tmp/pkinit /tmp/cdiff
docker exec \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    "$NAME" sh -c '
        /tmp/krb5-kdc-export --test-realm --export-pkinit /tmp/pkinit 127.0.0.1:18888 >/tmp/pkinit-export.log 2>&1 &
        ep=$!
        okpem=0
        for _ in $(seq 1 200); do
            if [ -s /tmp/pkinit/kdc.pem ]; then
                okpem=1
                break
            fi
            sleep 0.1
        done
        kill "$ep" 2>/dev/null || true
        wait "$ep" 2>/dev/null || true
        test "$okpem" = 1
    ' || {
    docker exec "$NAME" cat /tmp/pkinit-export.log >&2 || true
    die "pkinit export timed out"
}
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/ca.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/user.pem
docker exec "$NAME" grep -q 'BEGIN CERTIFICATE' /tmp/pkinit/kdc.pem

docker exec "$NAME" sh -c 'grep -q spake_preauth_groups /etc/krb5kdc/kdc.conf || sed -i "/\[kdcdefaults\]/a\\    spake_preauth_groups = P-256" /etc/krb5kdc/kdc.conf'
docker exec "$NAME" sh -c 'grep -q pkinit_identity /etc/krb5kdc/kdc.conf || sed -i "/\[kdcdefaults\]/a\\    pkinit_identity = FILE:/tmp/pkinit/kdc.pem\\n    pkinit_anchors = FILE:/tmp/pkinit/ca.pem\\n    pkinit_dh_min_bits = P-256" /etc/krb5kdc/kdc.conf'

docker exec "$NAME" python3 -c '
from pathlib import Path
direct = """[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 10h
    forwardable = true
    spake_preauth_groups = P-256
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1
    }
[domain_realm]
    .kerber.test = KERBER.TEST
    kerber.test = KERBER.TEST
"""
pk = """
    pkinit_eku_checking = none
    pkinit_kdc_hostname = kerber.test
    pkinit_dh_min_bits = 3072
"""
pk_realm = """
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
        pkinit_eku_checking = none
        pkinit_kdc_hostname = kerber.test
"""
proxy = direct.replace("kdc = 127.0.0.1:88", "kdc = 127.0.0.1:1891")
spake = proxy.replace("[libdefaults]", "[libdefaults]\n    preferred_preauth_types = 151")
pkinit = proxy.replace("[libdefaults]", "[libdefaults]" + pk).replace(
    "admin_server = 127.0.0.1", "admin_server = 127.0.0.1" + pk_realm
)
Path("/tmp/direct-krb5.conf").write_text(direct)
Path("/tmp/proxy-krb5.conf").write_text(proxy)
Path("/tmp/spake-krb5.conf").write_text(spake)
Path("/tmp/pkinit-krb5.conf").write_text(pkinit)
'

docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5kdc || true
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1'
if ! wait_port_in "$NAME" 88 200; then
    docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
    die "MIT krb5kdc listening on :88 never appeared"
fi

wait_bound_free_in "$NAME" "$PROXY_PORT" udp || die "proxy :$PROXY_PORT already bound"
docker exec -d "$NAME" python3 /tmp/kdc-req-proxy.py "$PROXY_PORT" 127.0.0.1 88 /tmp/cdiff/live.jsonl
wait_udp_in "$NAME" "$PROXY_PORT" || die "kdc-req-proxy did not listen"

docker exec "$NAME" kadmin.local -q 'addprinc -randkey WELLKNOWN/ANONYMOUS@KERBER.TEST' >/dev/null || true
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/user.keytab -norandkey user' >/dev/null
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/host.keytab -norandkey host/testhost.kerber.test' >/dev/null || \
    docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/host.keytab host/testhost.kerber.test' >/dev/null

FLOW_N=0

compare_flow() {
    local flow=$1 rc
    echo "==== compare $flow ===="
    set +e
    CMP="$(docker exec "$NAME" python3 /tmp/kdc-req-proxy.py --compare \
        "/tmp/cdiff/mit-${flow}.jsonl" "/tmp/cdiff/rust-${flow}.jsonl" "$flow" 2>&1)"
    rc=$?
    set -e
    echo "$CMP"
    if [ "$rc" -ne 0 ]; then
        docker exec "$NAME" sh -c "echo '---- mit-${flow}.jsonl ----'; cat /tmp/cdiff/mit-${flow}.jsonl; echo '---- rust-${flow}.jsonl ----'; cat /tmp/cdiff/rust-${flow}.jsonl"
        die "compare $flow failed (rc=$rc)"
    fi
    echo "$CMP" | grep -q "FLOW_${flow} mit_reqs="
    echo "$CMP" | grep -q "CORE_MATCH"
    echo "$CMP" | grep -q "SHAPE_MATCH kdc_options="
    FLOW_N=$((FLOW_N + 1))
}

echo "==== flow:plain ===="
reset_cap
mit_kinit /tmp/cc_mit_plain || die "MIT kinit plain failed"
save_cap mit-plain
reset_cap
rust_kinit /tmp/cc_rust_plain || die "Rust kinit plain failed"
save_cap rust-plain
compare_flow plain

echo "==== flow:keytab ===="
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    kinit -k -t /tmp/user.keytab -c /tmp/cc_mit_kt user@KERBER.TEST || die "MIT kinit -k failed"
save_cap mit-keytab
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    /tmp/krb5-kinit -k -t /tmp/user.keytab -c /tmp/cc_rust_kt \
    user@KERBER.TEST || die "Rust kinit -k failed"
save_cap rust-keytab
compare_flow keytab

echo "==== flow:renew ===="
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -r 1d -c /tmp/cc_mit_renew user@KERBER.TEST"
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -r 1d -c /tmp/cc_rust_renew user@KERBER.TEST
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    kinit -R -c /tmp/cc_mit_renew || die "MIT kinit -R failed"
save_cap mit-renew
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    /tmp/krb5-kinit -R -c /tmp/cc_rust_renew user@KERBER.TEST \
    || die "Rust kinit -R failed"
save_cap rust-renew
compare_flow renew

echo "==== flow:fast ===="
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/cc_armor_mit user@KERBER.TEST"
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/cc_armor_rust user@KERBER.TEST
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -T /tmp/cc_armor_mit -c /tmp/cc_mit_fast user@KERBER.TEST" \
    || die "MIT kinit -T failed"
save_cap mit-fast
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --armor-ccache /tmp/cc_armor_rust -c /tmp/cc_rust_fast \
    user@KERBER.TEST || die "Rust kinit --armor-ccache failed"
save_cap rust-fast
compare_flow fast

echo "==== flow:kvno_plain ===="
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/cc_mit_kvno user@KERBER.TEST"
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/cc_rust_kvno user@KERBER.TEST
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5CCNAME=FILE:/tmp/cc_mit_kvno "$NAME" \
    kvno host/testhost.kerber.test || die "MIT kvno failed"
save_cap mit-kvno_plain
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    /tmp/krb5-kvno -c /tmp/cc_rust_kvno host/testhost.kerber.test \
    || die "Rust kvno failed"
save_cap rust-kvno_plain
compare_flow kvno_plain

echo "==== flow:kvno_s4u ===="
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    kinit -f -k -t /tmp/host.keytab -c /tmp/cc_mit_s4u host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    /tmp/krb5-kinit -k -t /tmp/host.keytab -c /tmp/cc_rust_s4u \
    host/testhost.kerber.test@KERBER.TEST
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5CCNAME=FILE:/tmp/cc_mit_s4u "$NAME" \
    kvno -U user host/testhost.kerber.test || die "MIT kvno -U failed"
echo "MIT_kvno_U"
save_cap mit-kvno_s4u
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    /tmp/krb5-kvno -c /tmp/cc_rust_s4u -U user host/testhost.kerber.test \
    || die "Rust kvno -U failed"
save_cap rust-kvno_s4u
compare_flow kvno_s4u

echo "==== flow:kvno_u2u ===="
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/cc_mit_u2u_user user@KERBER.TEST"
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    kinit -k -t /tmp/host.keytab -c /tmp/cc_mit_u2u_host host/testhost.kerber.test@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/cc_rust_u2u_user user@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    /tmp/krb5-kinit -k -t /tmp/host.keytab -c /tmp/cc_rust_u2u_host \
    host/testhost.kerber.test@KERBER.TEST
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5CCNAME=FILE:/tmp/cc_mit_u2u_user "$NAME" \
    kvno --u2u FILE:/tmp/cc_mit_u2u_host host/testhost.kerber.test || die "MIT kvno --u2u failed"
save_cap mit-kvno_u2u
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf "$NAME" \
    /tmp/krb5-kvno -c /tmp/cc_rust_u2u_user --u2u FILE:/tmp/cc_rust_u2u_host \
    --body-realm KERBER.TEST host/testhost.kerber.test \
    || die "Rust kvno --u2u failed"
save_cap rust-kvno_u2u
compare_flow kvno_u2u

echo "==== flow:preauth ===="
docker exec "$NAME" kadmin.local -q 'modprinc +requires_preauth user'
reset_cap
mit_kinit /tmp/cc_mit_pa || die "MIT kinit preauth failed"
save_cap mit-preauth
reset_cap
rust_kinit /tmp/cc_rust_pa || die "Rust kinit preauth failed"
save_cap rust-preauth
compare_flow preauth

echo "==== flow:spake ===="
reset_cap
docker exec -e KRB5_CONFIG=/tmp/spake-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/cc_mit_spake user@KERBER.TEST" \
    || die "MIT kinit SPAKE failed"
save_cap mit-spake
reset_cap
docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --spake -c /tmp/cc_rust_spake user@KERBER.TEST \
    || die "Rust kinit --spake failed"
save_cap rust-spake
compare_flow spake

echo "==== flow:pkinit ===="
reset_cap
docker exec -e KRB5_CONFIG=/tmp/pkinit-krb5.conf "$NAME" \
    kinit -c /tmp/cc_mit_pkinit -X X509_user_identity=FILE:/tmp/pkinit/user.pem \
    user@KERBER.TEST || die "MIT kinit PKINIT failed"
save_cap mit-pkinit
reset_cap
docker exec -e KRB5_CONFIG=/tmp/pkinit-krb5.conf "$NAME" \
    /tmp/krb5-kinit --pkinit FILE:/tmp/pkinit/user.pem --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/cc_rust_pkinit user@KERBER.TEST \
    || die "Rust kinit --pkinit failed"
save_cap rust-pkinit
compare_flow pkinit

echo "==== flow:anon ===="
reset_cap
docker exec -e KRB5_CONFIG=/tmp/pkinit-krb5.conf "$NAME" \
    kinit -n -c /tmp/cc_mit_anon || die "MIT kinit -n failed"
save_cap mit-anon
reset_cap
docker exec -e KRB5_CONFIG=/tmp/pkinit-krb5.conf "$NAME" \
    /tmp/krb5-kinit -n --pkinit-anchors FILE:/tmp/pkinit/ca.pem \
    -c /tmp/cc_rust_anon || die "Rust kinit -n failed"
save_cap rust-anon
compare_flow anon

if [ "$FLOW_N" -ne "$EXPECTED_FLOWS" ]; then
    die "flows:$FLOW_N != $EXPECTED_FLOWS"
fi
echo "flows:$EXPECTED_FLOWS"
log "client.diff.shapes" "ok" ",\"flows\":$EXPECTED_FLOWS"

echo "client-differential-flows-gate ok flows:$EXPECTED_FLOWS"
