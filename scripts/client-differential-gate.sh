#!/usr/bin/env bash
# Both clients against the MIT 1.22.2 KDC through kdc-req-proxy.py.
# Seed + CI vehicle for W1-B: request-shape compare, MIT klist over both
# artefacts, CLI error texts/exit codes, gss-mit-client → Rust acceptor majors.
# Isolation: in-container; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-client-diff-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-client-diff-gate}"
mkdir -p "$SCRATCH"
PROXY_PORT=1891
EXPECTED_FLOWS=11

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"client-differential-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "client.diff.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

unavailable() {
    log "client.diff.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/client-differential-unavailable.log"
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi

cargo build -p krb5-client --bin krb5-kinit --bin krb5-klist --bin krb5-kvno --bin krb5-kdestroy --bin krb5-vfy-increds -q
cargo build -p krb5-kdc --bin krb5-kdc -q
cargo build -p krb5-gss --bin krb5-gss-accept -q

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT" || true
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    unavailable "MIT image unavailable"
fi

python3 "$ROOT/scripts/lib/kdc-req-proxy.py" --self-test || die "kdc-req-proxy self-test failed"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        die "harness kinit failed"
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    docker logs "$NAME" >&2 || true
    die "harness did not become ready"
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-klist" "$NAME":/tmp/krb5-klist
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kvno" "$NAME":/tmp/krb5-kvno
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdestroy" "$NAME":/tmp/krb5-kdestroy
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc-export
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-gss-accept" "$NAME":/tmp/krb5-gss-accept
docker cp "$ROOT/scripts/lib/kdc-req-proxy.py" "$NAME":/tmp/kdc-req-proxy.py
docker cp "$ROOT/scripts/lib/skew-preload.c" "$NAME":/tmp/skew-preload.c
docker cp "$ROOT/scripts/gss-mit-client.c" "$NAME":/tmp/gss-mit-client.c
docker exec "$NAME" chmod +x /tmp/krb5-kinit /tmp/krb5-klist /tmp/krb5-kvno /tmp/krb5-kdestroy \
    /tmp/krb5-kdc-export /tmp/krb5-gss-accept /tmp/kdc-req-proxy.py

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
sleep 0.3
docker exec -d \
    -e KRB5_TRACE=/tmp/mit-kdc.trace \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
    die "MIT krb5kdc did not listen after SPAKE/PKINIT config"
fi

docker exec -d "$NAME" python3 /tmp/kdc-req-proxy.py "$PROXY_PORT" 127.0.0.1 88 /tmp/cdiff/live.jsonl
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.sendto(b'x',('127.0.0.1',$PROXY_PORT))" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" != 1 ]; then
    die "kdc-req-proxy did not listen"
fi

docker exec "$NAME" kadmin.local -q 'addprinc -randkey WELLKNOWN/ANONYMOUS@KERBER.TEST' >/dev/null || true
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/user.keytab -norandkey user' >/dev/null
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/host.keytab -norandkey host/testhost.kerber.test' >/dev/null || \
    docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/host.keytab host/testhost.kerber.test' >/dev/null

FLOW_N=0

reset_cap() {
    docker exec "$NAME" sh -c 'cat /dev/null > /tmp/cdiff/live.jsonl'
}

save_cap() {
    docker exec "$NAME" cp /tmp/cdiff/live.jsonl "/tmp/cdiff/$1.jsonl"
    docker exec "$NAME" test -s "/tmp/cdiff/$1.jsonl" || die "empty capture $1"
}

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

mit_kinit() {
    local cc=$1
    shift
    docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_TRACE=/tmp/mit-client.trace \
        "$NAME" sh -c "printf 'userpassword\n' | kinit -c '$cc' $* user@KERBER.TEST"
}

rust_kinit() {
    local cc=$1
    shift
    docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_PASSWORD=userpassword \
        "$NAME" /tmp/krb5-kinit -c "$cc" "$@" user@KERBER.TEST
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

echo "==== MIT klist -C -f -e -a over both FILE ccaches ===="
for pair in "mit-plain:/tmp/cc_mit_plain" "rust-plain:/tmp/cc_rust_plain" \
    "mit-fast:/tmp/cc_mit_fast" "rust-fast:/tmp/cc_rust_fast"; do
    label="${pair%%:*}"
    cc="${pair#*:}"
    echo "---- klist $label $cc ----"
    KL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -C -f -e -a -c "$cc")"
    echo "$KL"
    echo "$KL" | grep -q 'KERBER.TEST'
    echo "$KL" | grep -q 'Flags:'
    echo "$KL" | grep -q 'Etype (skey, tkt):'
done
echo "MIT_klist_Cfea_both_caches"
KLKT="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -k -e /tmp/user.keytab)"
echo "$KLKT"
echo "$KLKT" | grep -q 'user@KERBER.TEST'
echo "MIT_klist_ke_rust_keytab"

echo "==== CLI error paths (MIT vs Rust, MIT KDC) ===="
cli_pair() {
    local name=$1
    local mit_rc rust_rc
    local mit_out rust_out
    shift
    echo "---- cli $name ----"
    set +e
    mit_out="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" sh -c "$1" 2>&1)"
    mit_rc=$?
    rust_out="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" sh -c "$2" 2>&1)"
    rust_rc=$?
    set -e
    echo "MIT_${name}_rc=$mit_rc"
    echo "$mit_out"
    echo "RUST_${name}_rc=$rust_rc"
    echo "$rust_out"
    if [ "$mit_rc" -eq 0 ]; then
        die "MIT $name unexpectedly succeeded"
    fi
    if [ "$rust_rc" -eq 0 ]; then
        die "Rust $name unexpectedly succeeded"
    fi
}

cli_pair wrong_password \
    "printf 'badpassword\n' | kinit -c /tmp/cc_badpw user@KERBER.TEST" \
    "KRB5_PASSWORD=badpassword /tmp/krb5-kinit -c /tmp/cc_badpw_r user@KERBER.TEST"
cli_pair unknown_principal \
    "printf 'userpassword\n' | kinit -c /tmp/cc_unk nosuch@KERBER.TEST" \
    "KRB5_PASSWORD=userpassword /tmp/krb5-kinit -c /tmp/cc_unk_r nosuch@KERBER.TEST"
docker exec "$NAME" kadmin.local -q 'addprinc -pw userpassword expireduser' >/dev/null
docker exec "$NAME" kadmin.local -q 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" expireduser'
cli_pair expired \
    "printf 'userpassword\n' | kinit -c /tmp/cc_exp expireduser@KERBER.TEST" \
    "KRB5_PASSWORD=userpassword /tmp/krb5-kinit -c /tmp/cc_exp_r expireduser@KERBER.TEST"
docker exec "$NAME" kadmin.local -q 'addprinc -pw userpassword revokeduser' >/dev/null
docker exec "$NAME" kadmin.local -q 'modprinc +disallow_all_tix revokeduser'
cli_pair revoked \
    "printf 'userpassword\n' | kinit -c /tmp/cc_rev revokeduser@KERBER.TEST" \
    "KRB5_PASSWORD=userpassword /tmp/krb5-kinit -c /tmp/cc_rev_r revokeduser@KERBER.TEST"
echo "---- cli skew ----"
docker exec "$NAME" cc -shared -fPIC -o /tmp/skew.so /tmp/skew-preload.c -ldl
REAL_EPOCH="$(docker exec "$NAME" date -u +%s)"
SKEW_EPOCH="$(docker exec "$NAME" sh -c 'LD_PRELOAD=/tmp/skew.so date -u +%s')"
echo "SKEW_preload_real=$REAL_EPOCH preload=$SKEW_EPOCH"
DELTA=$((SKEW_EPOCH - REAL_EPOCH))
if [ "$DELTA" -lt 250000 ] || [ "$DELTA" -gt 270000 ]; then
    die "skew.so did not advance clock by ~3d (delta=$DELTA)"
fi
echo "SKEW_preload_ok delta=$DELTA"
docker exec "$NAME" python3 -c '
from pathlib import Path
t = Path("/tmp/direct-krb5.conf").read_text()
if "kdc_timesync" not in t:
    t = t.replace("[libdefaults]\n", "[libdefaults]\n    kdc_timesync = 0\n")
Path("/tmp/notimesync-krb5.conf").write_text(t)
'
set +e
MIT_SKEW0="$(docker exec -e KRB5_CONFIG=/tmp/notimesync-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | LD_PRELOAD=/tmp/skew.so kinit -c /tmp/cc_skew0 user@KERBER.TEST" 2>&1)"
MIT_SKEW0_RC=$?
set -e
echo "MIT_skew_notimesync_rc=$MIT_SKEW0_RC"
echo "$MIT_SKEW0"
if [ "$MIT_SKEW0_RC" -eq 0 ]; then
    die "MIT kinit +3d with kdc_timesync=0 unexpectedly succeeded"
fi
echo "$MIT_SKEW0" | grep -qiE 'Clock skew|skew too great'
echo "MIT_skew_notimesync"
reset_cap
set +e
MIT_SKEW="$(docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_TRACE=/tmp/mit-skew.trace "$NAME" \
    sh -c "printf 'userpassword\n' | LD_PRELOAD=/tmp/skew.so kinit -c /tmp/cc_skew user@KERBER.TEST" 2>&1)"
MIT_SKEW_RC=$?
set -e
save_cap mit-skew
echo "MIT_skew_rc=$MIT_SKEW_RC"
echo "$MIT_SKEW"
if [ "$MIT_SKEW_RC" -ne 0 ]; then
    die "MIT kinit +3d with default kdc_timesync failed"
fi
MIT_SKEW_KL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -c /tmp/cc_skew)"
echo "$MIT_SKEW_KL"
echo "$MIT_SKEW_KL" | grep -q 'user@KERBER.TEST'
echo "MIT_skew_timesync_recovered"
reset_cap
set +e
RUST_SKEW="$(docker exec -e KRB5_CONFIG=/tmp/proxy-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    sh -c "LD_PRELOAD=/tmp/skew.so /tmp/krb5-kinit -c /tmp/cc_skew_r user@KERBER.TEST" 2>&1)"
RUST_SKEW_RC=$?
set -e
save_cap rust-skew
echo "RUST_skew_rc=$RUST_SKEW_RC"
echo "$RUST_SKEW"
if [ "$RUST_SKEW_RC" -ne 0 ]; then
    die "Rust kinit +3d with default kdc_timesync failed"
fi
RUST_SKEW_KL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -c /tmp/cc_skew_r)"
echo "$RUST_SKEW_KL"
echo "$RUST_SKEW_KL" | grep -q 'user@KERBER.TEST'
echo "RUST_skew_timesync_recovered"
reset_cap
set +e
RUST_SKEW0="$(docker exec -e KRB5_CONFIG=/tmp/notimesync-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    sh -c "LD_PRELOAD=/tmp/skew.so /tmp/krb5-kinit -c /tmp/cc_skew0_r user@KERBER.TEST" 2>&1)"
RUST_SKEW0_RC=$?
set -e
echo "RUST_skew_notimesync_rc=$RUST_SKEW0_RC"
echo "$RUST_SKEW0"
if [ "$RUST_SKEW0_RC" -eq 0 ]; then
    die "Rust kinit +3d with kdc_timesync=0 unexpectedly succeeded"
fi
echo "$RUST_SKEW0" | grep -qiE 'Clock skew|skew too great'
echo "RUST_skew_notimesync"
docker exec "$NAME" python3 -c '
from pathlib import Path
t = Path("/tmp/direct-krb5.conf").read_text().replace("kdc = 127.0.0.1:88", "kdc = 127.0.0.1:1")
Path("/tmp/dead-krb5.conf").write_text(t)
'
set +e
MIT_NOKDC="$(docker exec -e KRB5_CONFIG=/tmp/dead-krb5.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/cc_nokdc user@KERBER.TEST" 2>&1)"
MIT_NOKDC_RC=$?
RUST_NOKDC="$(docker exec -e KRB5_CONFIG=/tmp/dead-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/cc_nokdc_r user@KERBER.TEST 2>&1)"
RUST_NOKDC_RC=$?
set -e
echo "MIT_no_kdc_rc=$MIT_NOKDC_RC"
echo "$MIT_NOKDC"
echo "RUST_no_kdc_rc=$RUST_NOKDC_RC"
echo "$RUST_NOKDC"
if [ "$MIT_NOKDC_RC" -eq 0 ]; then
    die "MIT kinit to :1 succeeded"
fi
if [ "$RUST_NOKDC_RC" -eq 0 ]; then
    die "Rust kinit to :1 succeeded"
fi
echo "MIT_no_kdc"
echo "RUST_no_kdc"

cli_pair bad_keytab \
    "kinit -k -t /tmp/no-such.keytab -c /tmp/cc_badkt user@KERBER.TEST" \
    "/tmp/krb5-kinit -k -t /tmp/no-such.keytab -c /tmp/cc_badkt_r user@KERBER.TEST"
cli_pair bad_ccache \
    "printf 'userpassword\n' | kinit -c /no/such/dir/cc user@KERBER.TEST" \
    "KRB5_PASSWORD=userpassword /tmp/krb5-kinit -c /no/such/dir/cc user@KERBER.TEST"
echo "CLI_error_paths=8"

echo "==== Rust kvno -P is not implemented ===="
set +e
RUST_P="$(docker exec "$NAME" /tmp/krb5-kvno -P host/testhost.kerber.test 2>&1)"
RUST_P_RC=$?
set -e
echo "$RUST_P"
echo "RUST_kvno_P_rc=$RUST_P_RC"
if [ "$RUST_P_RC" -eq 0 ]; then
    die "Rust kvno -P unexpectedly succeeded"
fi
echo "$RUST_P" | grep -q 'not implemented'

echo "==== gss-mit-client → Rust acceptor majors ===="
if ! docker exec "$NAME" cc -o /tmp/gss-mit-client /tmp/gss-mit-client.c -lgssapi_krb5 -lkrb5; then
    die "cc gss-mit-client failed"
fi
docker exec -d "$NAME" sh -c '/tmp/krb5-gss-accept --keytab /tmp/host.keytab --listen 127.0.0.1:4444 >/tmp/gss-accept.log 2>&1'
ok=0
for _ in $(seq 1 20); do
    if docker exec "$NAME" grep -q listening /tmp/gss-accept.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/gss-accept.log >&2 || true
    die "gss-accept did not listen"
fi
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    "$NAME" /tmp/gss-mit-client testhost.kerber.test host hello-from-mit-gss 127.0.0.1 4444
ACCEPT="$(docker exec "$NAME" cat /tmp/gss-accept.log)"
echo "$ACCEPT"
echo "$ACCEPT" | grep -q 'gss-accept unwrap ok'
echo "MIT_gss_happy"
echo "GSS_happy_maj=0"

set +e
GSS_BAD="$(docker exec -e KRB5CCNAME=/tmp/krb5cc_harness -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    "$NAME" /tmp/gss-mit-client nosuch.kerber.test host hello 127.0.0.1 4444 2>&1)"
GSS_BAD_RC=$?
set -e
echo "$GSS_BAD"
echo "GSS_wrong_service_rc=$GSS_BAD_RC"
if [ "$GSS_BAD_RC" -eq 0 ]; then
    die "gss-mit-client wrong service succeeded"
fi
echo "$GSS_BAD" | grep -q 'maj='
echo "MIT_gss_wrong_service"
echo "GSS_wrong_service_major"

echo "==== replayed AP-REQ vs Rust acceptor ===="
docker exec -e KRB5CCNAME=/tmp/krb5cc_harness -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    -e GSS_DUMP_TOKEN=/tmp/gss-apreq "$NAME" \
    /tmp/gss-mit-client testhost.kerber.test host hello-replay 127.0.0.1 4444
docker exec "$NAME" python3 -c 'import socket,struct; tok=open("/tmp/gss-apreq","rb").read(); s=socket.create_connection(("127.0.0.1",4444),5); s.sendall(struct.pack(">I", len(tok))+tok); s.close()'
ok=0
REPLAY_LOG=""
for _ in $(seq 1 20); do
    REPLAY_LOG="$(docker exec "$NAME" cat /tmp/gss-accept.log 2>/dev/null || true)"
    if echo "$REPLAY_LOG" | grep -qiE '34|replay'; then
        ok=1
        break
    fi
    sleep 0.15
done
echo "$REPLAY_LOG"
if [ "$ok" != 1 ]; then
    die "replayed AP-REQ did not log 34/replay"
fi
echo "$REPLAY_LOG" | grep -q '34'
echo "MIT_gss_replay_token"
echo "GSS_replay_major_34"

echo "==== kinit -k highest keytab kvno (gic_keytab.c) ===="
docker exec "$NAME" kadmin.local -q 'addprinc -randkey ktuser' >/dev/null
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/ktuser-v1.keytab -norandkey ktuser' >/dev/null
docker exec "$NAME" kadmin.local -q 'cpw -randkey ktuser' >/dev/null
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/ktuser-v2.keytab -norandkey ktuser' >/dev/null
docker exec "$NAME" sh -c 'printf "rkt /tmp/ktuser-v1.keytab\nrkt /tmp/ktuser-v2.keytab\nwkt /tmp/ktuser-both.keytab\n" | ktutil'
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    kinit -k -t /tmp/ktuser-both.keytab -c /tmp/cc_mit_kt_kvno ktuser@KERBER.TEST \
    || die "MIT kinit -k two-kvno failed"
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    /tmp/krb5-kinit -k -t /tmp/ktuser-both.keytab -c /tmp/cc_rust_kt_kvno \
    ktuser@KERBER.TEST || die "Rust kinit -k two-kvno failed"
MIT_KT_KVNO="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -c /tmp/cc_mit_kt_kvno)"
RUST_KT_KVNO="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -c /tmp/cc_rust_kt_kvno)"
echo "$MIT_KT_KVNO"
echo "$RUST_KT_KVNO"
echo "$MIT_KT_KVNO" | grep -q 'ktuser@KERBER.TEST'
echo "$RUST_KT_KVNO" | grep -q 'ktuser@KERBER.TEST'
echo "MIT_kinit_kt_highest_kvno"
echo "RUST_kinit_kt_highest_kvno"

echo "==== KEY_EXP changepw (gic_pwd.c) ===="
docker exec "$NAME" sh -c 'python3 -c "import socket;s=socket.create_connection((\"127.0.0.1\",464),0.3)" 2>/dev/null || kadmind'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',464),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    die "MIT kadmind 464 did not listen"
fi
docker exec "$NAME" kadmin.local -q 'modprinc +password_changing_service kadmin/changepw' >/dev/null
docker exec "$NAME" kadmin.local -q 'addprinc -pw exp-old mitexpuser' >/dev/null
docker exec "$NAME" kadmin.local -q 'modprinc +needchange mitexpuser' >/dev/null
docker exec "$NAME" kadmin.local -q 'addprinc -pw exp-old rustexpuser' >/dev/null
docker exec "$NAME" kadmin.local -q 'modprinc +needchange rustexpuser' >/dev/null
MIT_CHPW="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c 'printf "exp-old\nexp-new\nexp-new\n" | kinit -c /tmp/cc_mit_chpw mitexpuser@KERBER.TEST' 2>&1)" \
    || die "MIT kinit KEY_EXP changepw failed"
echo "$MIT_CHPW"
echo "$MIT_CHPW" | grep -q 'Password expired'
RUST_CHPW="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    -e KRB5_PASSWORD=exp-old -e KRB5_NEW_PASSWORD=exp-new "$NAME" \
    /tmp/krb5-kinit -c /tmp/cc_rust_chpw rustexpuser@KERBER.TEST 2>&1)" \
    || die "Rust kinit KEY_EXP changepw failed"
echo "$RUST_CHPW"
echo "$RUST_CHPW" | grep -q 'Password expired'
MIT_CHPW_KL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -c /tmp/cc_mit_chpw)"
RUST_CHPW_KL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" klist -c /tmp/cc_rust_chpw)"
echo "$MIT_CHPW_KL"
echo "$RUST_CHPW_KL"
echo "$MIT_CHPW_KL" | grep -q 'mitexpuser@KERBER.TEST'
echo "$RUST_CHPW_KL" | grep -q 'rustexpuser@KERBER.TEST'
echo "MIT_kinit_keyexp_changepw"
echo "RUST_kinit_keyexp_changepw"

echo "==== vfy_increds (vfy_increds.c) ===="
docker cp "$ROOT/scripts/t_vfy_increds.c" "$NAME":/tmp/t_vfy_increds.c
if ! docker exec "$NAME" cc -o /tmp/t_vfy_increds /tmp/t_vfy_increds.c -lkrb5 -lcom_err; then
    die "MIT t_vfy_increds compile failed"
fi
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-vfy-increds" "$NAME":/tmp/krb5-vfy-increds
docker exec "$NAME" chmod +x /tmp/krb5-vfy-increds
docker exec "$NAME" kadmin.local -q 'addprinc -randkey host/vfy.kerber.test' >/dev/null
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/vfy.kt host/vfy.kerber.test' >/dev/null
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -c /tmp/cc_vfy user@KERBER.TEST' \
    || die "kinit for vfy_increds failed"
VFY_ENV="-e KRB5_CONFIG=/tmp/direct-krb5.conf -e KRB5CCNAME=/tmp/cc_vfy -e KRB5_KTNAME=/tmp/vfy.kt"
docker exec $VFY_ENV "$NAME" /tmp/t_vfy_increds || die "MIT t_vfy_increds host failed"
docker exec $VFY_ENV "$NAME" /tmp/krb5-vfy-increds || die "Rust t_vfy_increds host failed"
echo "MIT_vfy_increds_host"
echo "RUST_vfy_increds_host"
docker exec "$NAME" kadmin.local -q 'cpw -randkey host/vfy.kerber.test' >/dev/null
set +e
docker exec $VFY_ENV "$NAME" /tmp/t_vfy_increds
mit_vfy_old=$?
docker exec $VFY_ENV "$NAME" /tmp/krb5-vfy-increds
rust_vfy_old=$?
set -e
[ "$mit_vfy_old" != 0 ] || die "MIT t_vfy_increds outdated unexpectedly succeeded"
[ "$rust_vfy_old" != 0 ] || die "Rust t_vfy_increds outdated unexpectedly succeeded"
echo "MIT_vfy_increds_outdated"
echo "RUST_vfy_increds_outdated"
docker exec "$NAME" rm -f /tmp/vfy.kt
docker exec $VFY_ENV "$NAME" /tmp/t_vfy_increds || die "MIT t_vfy_increds no keytab failed"
docker exec $VFY_ENV "$NAME" /tmp/krb5-vfy-increds || die "Rust t_vfy_increds no keytab failed"
set +e
docker exec $VFY_ENV "$NAME" /tmp/t_vfy_increds -n
mit_vfy_n=$?
docker exec $VFY_ENV "$NAME" /tmp/krb5-vfy-increds -n
rust_vfy_n=$?
set -e
[ "$mit_vfy_n" != 0 ] || die "MIT t_vfy_increds -n no keytab unexpectedly succeeded"
[ "$rust_vfy_n" != 0 ] || die "Rust t_vfy_increds -n no keytab unexpectedly succeeded"
echo "MIT_vfy_increds_nokeytab"
echo "RUST_vfy_increds_nokeytab"
docker exec "$NAME" kadmin.local -q 'addprinc -randkey nfs/vfy.kerber.test' >/dev/null
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/vfy.kt nfs/vfy.kerber.test' >/dev/null
docker exec $VFY_ENV "$NAME" /tmp/t_vfy_increds || die "MIT t_vfy_increds nfs-default failed"
docker exec $VFY_ENV "$NAME" /tmp/krb5-vfy-increds || die "Rust t_vfy_increds nfs-default failed"
docker exec $VFY_ENV "$NAME" /tmp/t_vfy_increds nfs/vfy.kerber.test@KERBER.TEST \
    || die "MIT t_vfy_increds nfs-explicit failed"
docker exec $VFY_ENV "$NAME" /tmp/krb5-vfy-increds nfs/vfy.kerber.test@KERBER.TEST \
    || die "Rust t_vfy_increds nfs-explicit failed"
echo "MIT_vfy_increds_nfs"
echo "RUST_vfy_increds_nfs"
docker exec "$NAME" rm -f /tmp/vfy.kt
docker exec "$NAME" python3 -c '
from pathlib import Path
t = Path("/tmp/direct-krb5.conf").read_text()
Path("/tmp/vfy-nofail.conf").write_text(t.replace("[libdefaults]", "[libdefaults]\n    verify_ap_req_nofail = true"))
'
set +e
docker exec -e KRB5_CONFIG=/tmp/vfy-nofail.conf -e KRB5CCNAME=/tmp/cc_vfy -e KRB5_KTNAME=/tmp/vfy.kt \
    "$NAME" /tmp/t_vfy_increds
mit_vfy_nf=$?
docker exec -e KRB5_CONFIG=/tmp/vfy-nofail.conf -e KRB5CCNAME=/tmp/cc_vfy -e KRB5_KTNAME=/tmp/vfy.kt \
    "$NAME" /tmp/krb5-vfy-increds
rust_vfy_nf=$?
set -e
[ "$mit_vfy_nf" != 0 ] || die "MIT t_vfy_increds verify_ap_req_nofail unexpectedly succeeded"
[ "$rust_vfy_nf" != 0 ] || die "Rust t_vfy_increds verify_ap_req_nofail unexpectedly succeeded"
echo "MIT_vfy_increds_nofail"
echo "RUST_vfy_increds_nofail"

echo "==== chpw texts + setpw (chpw.c) ===="
cargo build -p krb5-admin --bin krb5-kpasswd -q
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpasswd" "$NAME":/tmp/krb5-kpasswd
docker cp "$ROOT/scripts/kpasswd-tgs-client.c" "$NAME":/tmp/kpasswd-tgs-client.c
if ! docker exec "$NAME" cc -o /tmp/kpasswd-tgs-client /tmp/kpasswd-tgs-client.c -lkrb5; then
    die "MIT kpasswd-tgs-client compile failed"
fi
docker exec "$NAME" chmod +x /tmp/krb5-kpasswd
docker exec "$NAME" kadmin.local -q 'addpol -minlength 8 chpwmin' >/dev/null
docker exec "$NAME" kadmin.local -q 'addprinc -policy chpwmin -pw LongPass1 chpwpol' >/dev/null
docker exec "$NAME" kadmin.local -q 'addprinc -pw setold chpwset' >/dev/null
docker exec "$NAME" kadmin.local -q 'addprinc -pw otherpw chpwother' >/dev/null
MIT_CHPW_POL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c 'printf "LongPass1\nshort\nshort\n" | kpasswd chpwpol@KERBER.TEST' 2>&1)" || true
echo "$MIT_CHPW_POL"
echo "$MIT_CHPW_POL" | grep -q 'Password change rejected'
RUST_CHPW_POL="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    -e KRB5_PASSWORD=LongPass1 -e KRB5_NEW_PASSWORD=short "$NAME" \
    /tmp/krb5-kpasswd 127.0.0.1 chpwpol@KERBER.TEST 2>&1)" || true
echo "$RUST_CHPW_POL"
echo "$RUST_CHPW_POL" | grep -q 'Password change rejected'
echo "MIT_kpasswd_soft_rejected"
echo "RUST_kpasswd_soft_rejected"
docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf "$NAME" \
    sh -c 'printf "setold\n" | kinit -c /tmp/cc_chpw_set chpwset@KERBER.TEST' \
    || die "kinit chpwset for setpw failed"
MIT_SETPW="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    -e KRB5CCNAME=/tmp/cc_chpw_set -e KPASSWD_AS_PASSWORD=setold \
    -e KPASSWD_TARGET=chpwother@KERBER.TEST "$NAME" \
    /tmp/kpasswd-tgs-client FILE:/tmp/cc_chpw_set KERBER.TEST shouldfail)"
echo "$MIT_SETPW"
echo "$MIT_SETPW" | grep -q 'result_code=5'
echo "$MIT_SETPW" | grep -q 'Access denied'
RUST_SETPW="$(docker exec -e KRB5_CONFIG=/tmp/direct-krb5.conf \
    -e KRB5_PASSWORD=setold -e KRB5_NEW_PASSWORD=shouldfail \
    -e KRB5_KPASSWD_TARGET=chpwother@KERBER.TEST "$NAME" \
    /tmp/krb5-kpasswd 127.0.0.1 chpwset@KERBER.TEST 2>&1)" || true
echo "$RUST_SETPW"
echo "$RUST_SETPW" | grep -q 'Access denied'
echo "MIT_kpasswd_setpw_denied"
echo "RUST_kpasswd_setpw_denied"

mkdir -p "$SCRATCH/cdiff"
docker cp "$NAME:/tmp/cdiff/." "$SCRATCH/cdiff/"
log "client.diff.gate" "ok" ",\"flows\":$EXPECTED_FLOWS,\"cli_errors\":8"
echo "client-differential-gate ok flows:$EXPECTED_FLOWS"
