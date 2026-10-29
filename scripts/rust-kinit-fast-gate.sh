#!/usr/bin/env bash
# Rust kinit --fast vs MIT 1.22.2 KDC. Armor TGT from a prior enc-ts kinit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
need_bins krb5-kinit krb5-kvno krb5-kpasswd krb5-kdc krb5-kdb

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-fast-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "fast.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

stock_mit_kdc
mit_live_guard

docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5kdc || true
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
    log "fast.client.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kinit

echo "==== armor TGT (enc-ts) ===="
set +e
ARMOR="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/krb5cc_armor user@KERBER.TEST 2>&1)"
arc=$?
set -e
echo "$ARMOR"
if [ "$arc" -ne 0 ]; then
    log "fast.client.gate" "error" ',"error":"rust kinit armor failed","rc":'"$arc"
    exit 1
fi
assert_no_error_log "$ARMOR" fast.client.gate
echo "==== Rust kinit --fast --armor-ccache ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast user@KERBER.TEST 2>&1)"
rc=$?
set -e
echo "$OUT"
if [ "$rc" -ne 0 ]; then
    echo "==== MIT kdc TRACE ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast failed","rc":'"$rc"
    exit 1
fi
assert_no_error_log "$OUT" fast.client.gate
KLIST="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
# write_out_ccache: fast_avail is recorded because the KDC echoed PA-FX-FAST
# inside the FAST reply; user needs no preauth here, so like MIT no pa_type
# entry is written (save_selected_preauth_type returns on KRB5_PADATA_NONE).
echo "==== Rust kinit --fast recorded fast_avail (and no pa_type without preauth) like write_out_ccache ===="
KLISTC="$(docker exec "$NAME" klist -C -c /tmp/krb5cc_fast 2>/dev/null || true)"
echo "$KLISTC"
echo "$KLISTC" | grep -F 'config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes'
if echo "$KLISTC" | grep -q 'config: pa_type('; then
    echo "pa_type recorded without a selected preauth type" >&2
    exit 1
fi
require_log "$NAME" /tmp/mit-kdc.trace 'Decrypted AP-REQ' "Decrypted AP-REQ in /tmp/mit-kdc.trace"
TRACE="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE" >&2
    log "fast.client.gate" "error" ',"error":"kinit succeeded without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE" | grep -F 'Decrypted AP-REQ'

echo "==== FAST immediate AS-REP (no +requires_preauth) ===="
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'addprinc -pw userpassword nopreauth'
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'modprinc -requires_preauth nopreauth'
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT2="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast_np nopreauth@KERBER.TEST 2>&1)"
rc2=$?
set -e
echo "$OUT2"
if [ "$rc2" -ne 0 ]; then
    echo "==== MIT kdc TRACE (nopreauth) ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast nopreauth failed","rc":'"$rc2"
    exit 1
fi
assert_no_error_log "$OUT2" fast.client.gate
KLIST2="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast_np 2>/dev/null || true)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'nopreauth@KERBER.TEST'
require_log "$NAME" /tmp/mit-kdc.trace 'Decrypted AP-REQ' "Decrypted AP-REQ in /tmp/mit-kdc.trace"
TRACE2="$(docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true)"
if ! echo "$TRACE2" | grep -Fq 'Decrypted AP-REQ'; then
    echo "$TRACE2" >&2
    log "fast.client.gate" "error" ',"error":"nopreauth FAST without Decrypted AP-REQ TRACE"'
    exit 1
fi
echo "$TRACE2" | grep -F 'Decrypted AP-REQ'
if ! echo "$TRACE2" | grep -F 'Decrypted AP-REQ' | grep -F 'aes256-sha2'; then
    echo "$TRACE2" >&2
    log "fast.client.gate" "error" ',"error":"nopreauth FAST AP-REQ was not aes256-sha2"'
    exit 1
fi
KLIST2E="$(docker exec "$NAME" klist -e -c /tmp/krb5cc_fast_np 2>/dev/null || true)"
echo "$KLIST2E"
echo "$KLIST2E" | grep -F 'aes256-cts-hmac-sha384-192'

echo "==== Rust kinit --fast -S host (TGS strengthen-key) ===="
docker exec "$NAME" sh -c 'cat /dev/null > /tmp/mit-kdc.trace' || true
set +e
OUT3="$(docker exec -e RUST_LOG=krb5_protocol=debug -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/krb5cc_armor \
    -c /tmp/krb5cc_fast_tgs -S host/testhost.kerber.test user@KERBER.TEST 2>&1)"
rc3=$?
set -e
echo "$OUT3"
if [ "$rc3" -ne 0 ]; then
    echo "==== MIT kdc TRACE (FAST TGS) ===="
    docker exec "$NAME" cat /tmp/mit-kdc.trace 2>/dev/null || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast -S failed","rc":'"$rc3"
    exit 1
fi
assert_no_error_log "$OUT3" fast.client.gate
KLIST3="$(docker exec "$NAME" klist -c /tmp/krb5cc_fast_tgs 2>/dev/null || true)"
echo "$KLIST3"
echo "$KLIST3" | grep -q 'host/testhost.kerber.test'
echo "$OUT3" | grep -q '"fast_strengthen":true' || {
    echo "$OUT3" >&2
    log "fast.client.gate" "error" ',"error":"FAST TGS rust client log missing fast_strengthen"'
    exit 1
}

echo "==== kinit -T: the AS reply's time offset replaces the armor cache's stale one (MIT first) ===="
docker cp "$ROOT/scripts/lib/ccache-offset.py" "$NAME":/tmp/ccache-offset.py
for who in mit rust; do
    docker exec "$NAME" rm -f /tmp/so-armor.cc "/tmp/so-$who.cc"
    docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/so-armor.cc user@KERBER.TEST' >/dev/null
    docker exec "$NAME" python3 /tmp/ccache-offset.py set /tmp/so-armor.cc 120
    if [ "$who" = mit ]; then
        docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit -T /tmp/so-armor.cc -c /tmp/so-mit.cc user@KERBER.TEST' >/dev/null
    else
        docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
            /tmp/krb5-kinit -T /tmp/so-armor.cc -c /tmp/so-rust.cc user@KERBER.TEST >/dev/null
    fi
    off="$(docker exec "$NAME" python3 /tmp/ccache-offset.py show "/tmp/so-$who.cc")"
    echo "$who -T header offset: $off (armor cache said 120)"
    case "$off" in
    0 | 1 | -1) ;;
    *)
        log "fast.client.gate" "error" ",\"error\":\"$who kinit -T kept the armor cache's offset $off\""
        exit 1
        ;;
    esac
done

echo "==== kdc_timesync = 0, kinit -s 1h: no skew check on a postdated reply (MIT first) ===="
docker exec "$NAME" sh -c 'sed "s/^\[libdefaults\]\$/[libdefaults]\n    kdc_timesync = 0/" /etc/krb5.conf > /tmp/ts0-krb5.conf'
docker exec "$NAME" grep -q 'kdc_timesync = 0' /tmp/ts0-krb5.conf
for who in mit rust; do
    docker exec "$NAME" rm -f "/tmp/ps-$who.cc"
    set +e
    if [ "$who" = mit ]; then
        PS="$(docker exec -e KRB5_CONFIG=/tmp/ts0-krb5.conf "$NAME" \
            sh -c "printf 'userpassword\n' | kinit -s 1h -c /tmp/ps-mit.cc user@KERBER.TEST" 2>&1)"
    else
        PS="$(docker exec -e KRB5_CONFIG=/tmp/ts0-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
            /tmp/krb5-kinit -s 1h -c /tmp/ps-rust.cc user@KERBER.TEST 2>&1)"
    fi
    prc=$?
    set -e
    echo "$who kinit -s 1h rc=$prc: $PS"
    if [ "$prc" -ne 0 ]; then
        log "fast.client.gate" "error" ",\"error\":\"$who kinit -s 1h refused under kdc_timesync = 0\",\"rc\":$prc"
        exit 1
    fi
    docker exec "$NAME" klist -c "/tmp/ps-$who.cc" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'
done

echo "==== kvno: a TGS reply outside clockskew of the cache's offset (MIT first) ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kvno" "$NAME":/tmp/krb5-kvno
docker exec "$NAME" chmod +x /tmp/krb5-kvno
docker exec "$NAME" sh -c 'sed "s/^\[libdefaults\]\$/[libdefaults]\n    clockskew = 60/" /etc/krb5.conf > /tmp/cs60-krb5.conf'
for off in 120 -120 0; do
    for who in mit rust; do
        docker exec "$NAME" rm -f /tmp/kv.cc
        docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/kv.cc user@KERBER.TEST' >/dev/null
        docker exec "$NAME" python3 /tmp/ccache-offset.py set /tmp/kv.cc "$off"
        if [ "$who" = mit ]; then bin=kvno; else bin=/tmp/krb5-kvno; fi
        set +e
        KV="$(docker exec -e KRB5_CONFIG=/tmp/cs60-krb5.conf -e KRB5CCNAME=FILE:/tmp/kv.cc "$NAME" \
            "$bin" host/testhost.kerber.test@KERBER.TEST 2>&1)"
        krc=$?
        set -e
        echo "$who kvno offset $off rc=$krc: $KV"
        if [ "$off" = 0 ]; then want=0; else want=1; fi
        if [ "$krc" -ne "$want" ] || { [ "$want" = 1 ] && ! grep -q 'Clock skew too great in KDC reply' <<<"$KV"; }; then
            log "fast.client.gate" "error" ",\"error\":\"$who kvno at offset $off gave rc $krc\""
            exit 1
        fi
    done
done

echo "==== no preauth: the reply's salt (norealm, onlyrealm, special) takes the password key (MIT first) ===="
for salt in norealm onlyrealm special; do
    kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -pw userpassword -e aes256-cts-hmac-sha1-96:$salt -requires_preauth s_$salt"
    for who in mit rust; do
        docker exec "$NAME" rm -f /tmp/sl.cc
        set +e
        if [ "$who" = mit ]; then
            SL="$(docker exec "$NAME" sh -c "printf 'userpassword\n' | kinit -c /tmp/sl.cc s_$salt@KERBER.TEST" 2>&1)"
        else
            SL="$(docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
                /tmp/krb5-kinit -c /tmp/sl.cc "s_$salt@KERBER.TEST" 2>&1)"
        fi
        src=$?
        set -e
        echo "$who kinit $salt key rc=$src: $SL"
        if [ "$src" -ne 0 ]; then
            log "fast.client.gate" "error" ",\"error\":\"$who kinit refused a $salt key without preauth\",\"rc\":$src"
            exit 1
        fi
    done
done

echo "==== kvno: an expired krbtgt/SREALM in the cache is skipped, the walk starts at the local TGT (MIT first) ===="
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'addprinc -randkey krbtgt/OTHER.TEST@KERBER.TEST'
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'modprinc -maxlife "5 seconds" krbtgt/OTHER.TEST@KERBER.TEST'
docker exec "$NAME" sh -c 'sed "s/^\[realms\]\$/[realms]\n    OTHER.TEST = {\n        kdc = 127.0.0.1\n    }/" /etc/krb5.conf > /tmp/other-krb5.conf'
docker exec "$NAME" rm -f /tmp/xt.cc
docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/xt.cc user@KERBER.TEST' >/dev/null
docker exec -e KRB5_CONFIG=/tmp/other-krb5.conf -e KRB5CCNAME=FILE:/tmp/xt.cc "$NAME" kvno krbtgt/OTHER.TEST@KERBER.TEST >/dev/null
sleep 6
for who in mit rust; do
    docker exec "$NAME" cp /tmp/xt.cc "/tmp/xt-$who.cc"
    if [ "$who" = mit ]; then bin=kvno; else bin=/tmp/krb5-kvno; fi
    set +e
    TR="$(docker exec -e KRB5_CONFIG=/tmp/other-krb5.conf -e KRB5_TRACE=/dev/stdout -e "KRB5CCNAME=FILE:/tmp/xt-$who.cc" \
        "$NAME" "$bin" host/h.other.test@OTHER.TEST 2>&1)"
    set -e
    echo "$who: $(grep -c 'Starting with TGT for client realm' <<<"$TR") local-TGT start, $(grep -c 'Found cached TGT for service realm' <<<"$TR") cached-TGT use"
    if ! grep -q 'Starting with TGT for client realm' <<<"$TR" || grep -q 'Found cached TGT for service realm' <<<"$TR"; then
        echo "$TR"
        log "fast.client.gate" "error" ",\"error\":\"$who kvno used an expired krbtgt/OTHER.TEST\""
        exit 1
    fi
done

echo "==== request_timeout = 3: a TCP reply sent one byte a second fails at 3 s (MIT first) ===="
docker cp "$ROOT/scripts/lib/trickle-kdc.py" "$NAME":/tmp/trickle-kdc.py
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpasswd" "$NAME":/tmp/krb5-kpasswd
docker exec "$NAME" chmod +x /tmp/krb5-kpasswd
docker exec -d "$NAME" timeout 120 python3 /tmp/trickle-kdc.py 1899
docker exec "$NAME" sh -c 'sed "s/^\[libdefaults\]\$/[libdefaults]\n    udp_preference_limit = 1\n    request_timeout = 3/" /etc/krb5.conf > /tmp/rt-base.conf
sed "s/kdc = 127.0.0.1\$/kdc = 127.0.0.1:1899/" /tmp/rt-base.conf > /tmp/rt-kdc.conf
sed "s/^\(        admin_server = 127.0.0.1\)\$/\1\n        kpasswd_server = 127.0.0.1:1899/" /tmp/rt-base.conf > /tmp/rt-kpw.conf'
for what in kinit kpasswd; do
    for who in mit rust; do
        conf=/tmp/rt-kdc.conf
        [ "$what" = kpasswd ] && conf=/tmp/rt-kpw.conf
        docker exec "$NAME" rm -f /tmp/rt.cc
        start=$SECONDS
        set +e
        case "$what.$who" in
        kinit.mit) RT="$(docker exec -e KRB5_CONFIG=$conf "$NAME" sh -c 'printf "userpassword\n" | kinit -c /tmp/rt.cc user@KERBER.TEST' 2>&1)" ;;
        kinit.rust) RT="$(docker exec -e KRB5_CONFIG=$conf -e KRB5_PASSWORD=userpassword "$NAME" /tmp/krb5-kinit -c /tmp/rt.cc user@KERBER.TEST 2>&1)" ;;
        kpasswd.mit) RT="$(docker exec -e KRB5_CONFIG=$conf "$NAME" sh -c 'printf "userpassword\ntrickle-pw\ntrickle-pw\n" | kpasswd user@KERBER.TEST' 2>&1)" ;;
        *) RT="$(docker exec -e KRB5_CONFIG=$conf -e KRB5_PASSWORD=userpassword -e KRB5_NEW_PASSWORD=trickle-pw "$NAME" /tmp/krb5-kpasswd user@KERBER.TEST 2>&1)" ;;
        esac
        rtrc=$?
        set -e
        took=$((SECONDS - start))
        echo "$who $what rc=$rtrc after ${took}s: $(tail -n 1 <<<"$RT")"
        if [ "$rtrc" -ne 1 ] || [ "$took" -gt 6 ] || ! grep -q 'Cannot contact any KDC' <<<"$RT"; then
            log "fast.client.gate" "error" ",\"error\":\"$who $what did not stop at request_timeout\",\"rc\":$rtrc,\"secs\":$took"
            exit 1
        fi
    done
done

echo "==== kvno: a TGS reply with a modified ticket fails and retries once; kpasswd bad reply (MIT first) ===="
docker cp "$ROOT/harness/field/lib/kdc-rewrite-proxy.py" "$NAME":/tmp/kdc-rewrite-proxy.py
docker exec -d "$NAME" timeout 120 python3 /tmp/kdc-rewrite-proxy.py 1898 127.0.0.1 88 /tmp/mod-proxy.log tgs-rep-ticket
docker exec -d "$NAME" timeout 120 python3 /tmp/trickle-kdc.py 1897 badlen
docker exec "$NAME" sh -c 'sed "s/kdc = 127.0.0.1\$/kdc = 127.0.0.1:1898/" /etc/krb5.conf > /tmp/mod-kdc.conf
sed "s/^\[libdefaults\]\$/[libdefaults]\n    udp_preference_limit = 1/; s/^\(        admin_server = 127.0.0.1\)\$/\1\n        kpasswd_server = 127.0.0.1:1897/" /etc/krb5.conf > /tmp/mod-kpw.conf'
sleep 1
for who in mit rust; do
    docker exec "$NAME" sh -c 'rm -f /tmp/mod.cc; : > /tmp/mod-proxy.log; printf "userpassword\n" | kinit -c /tmp/mod.cc user@KERBER.TEST'
    if [ "$who" = mit ]; then bin=kvno; else bin=/tmp/krb5-kvno; fi
    set +e
    KV="$(docker exec -e KRB5_CONFIG=/tmp/mod-kdc.conf -e KRB5CCNAME=FILE:/tmp/mod.cc "$NAME" $bin host/testhost.kerber.test@KERBER.TEST 2>&1)"
    reqs="$(docker exec "$NAME" grep -c msg_type=12 /tmp/mod-proxy.log)"
    case "$who" in
    mit) PW="$(docker exec -e KRB5_CONFIG=/tmp/mod-kpw.conf "$NAME" sh -c 'printf "userpassword\nmod-pw\nmod-pw\n" | kpasswd user@KERBER.TEST' 2>&1)" ;;
    *) PW="$(docker exec -e KRB5_CONFIG=/tmp/mod-kpw.conf -e KRB5_PASSWORD=userpassword -e KRB5_NEW_PASSWORD=mod-pw "$NAME" /tmp/krb5-kpasswd user@KERBER.TEST 2>&1)" ;;
    esac
    set -e
    KV="${KV#*: }"
    PW="$(tr -d '\r' <<<"$PW" | grep -v '^$' | tail -n 1)"
    PW="${PW##*: }"
    echo "$who: kvno '$KV' ($reqs TGS requests); kpasswd '$PW'"
    if [ "$who" = mit ]; then want_kv="$KV"; want_reqs="$reqs"; want_pw="$PW"; fi
    if [ "${KV#Ticket modified in KDC reply}" = "$KV" ] || [ "$KV" != "$want_kv" ] || [ "$reqs" != "$want_reqs" ] || [ "$PW" != "$want_pw" ]; then
        log "fast.client.gate" "error" ",\"error\":\"$who modified-reply cell differs from MIT\""
        exit 1
    fi
done

echo "==== require_auth encrypted_challenge: FAST issued, password 12 both legs ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "$ROOT/harness/client-krb5.conf" "$NAME":/tmp/mit-krb5.conf
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb
docker exec "$NAME" sh -c "sed 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:8888/' /tmp/mit-krb5.conf > /tmp/rust-krb5.conf && sed -i 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:88/' /tmp/mit-krb5.conf"
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
t = p.read_text()
if "encrypted_challenge_indicator" not in t:
    t = t.replace("supported_enctypes", "        encrypted_challenge_indicator = encrypted_challenge\n        supported_enctypes", 1)
    p.write_text(t)
Path("/tmp/rust-kdc.conf").write_text("""[libdefaults]
    spake_preauth_groups = P-256
[realms]
    KERBER.TEST = {
        encrypted_challenge_indicator = encrypted_challenge
    }
[logging]
    json = STDOUT
""")
'
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'modprinc +requires_preauth user'
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'setstr host/testhost.kerber.test require_auth encrypted_challenge'
docker exec "$NAME" kdb5_util dump /tmp/ec-ind.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5kdc || true
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
    log "fast.client.gate" "error" ',"error":"MIT krb5kdc did not listen after EC indicator"'
    exit 1
fi
docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/ec-ind.dump || {
    log "fast.client.gate" "error" ',"error":"rust kdb load after EC indicator failed"'
    exit 1
}
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_PROFILE=/tmp/rust-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"rust kdc did not listen after EC indicator"'
    exit 1
fi
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/mit-krb5.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit -c /tmp/ec-armor.cc user@KERBER.TEST'; then
    log "fast.client.gate" "error" ',"error":"MIT armor kinit for EC cell failed"'
    exit 1
fi
ec_fast_kvno() {
    local side=$1
    local conf="/tmp/${side}-krb5.conf"
    docker exec "$NAME" rm -f /tmp/ec-fast.cc
    if ! docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit -T /tmp/ec-armor.cc -c /tmp/ec-fast.cc user@KERBER.TEST'; then
        echo "==== $side FAST kinit failed ===="
        docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
        docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"MIT kinit -T via $side KDC failed\""
        exit 1
    fi
    KLISTC="$(docker exec "$NAME" klist -C -c /tmp/ec-fast.cc 2>/dev/null || true)"
    echo "$KLISTC"
    echo "$KLISTC" | grep -q 'pa_type.*= 138' || {
        log "fast.client.gate" "error" ",\"error\":\"$side FAST kinit missing pa_type 138\""
        exit 1
    }
    set +e
    got="$(docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/ec-fast.cc "$NAME" \
        kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$side ec_kvno=$got"
    echo "$got" | grep -q 'host/testhost.kerber.test@KERBER.TEST: kvno =' || {
        docker exec "$NAME" cat /tmp/mit-kdc.log >&2 || true
        docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"$side kvno after EC TGT + require_auth failed\""
        exit 1
    }
}
ec_fast_kvno mit
ec_fast_kvno rust
echo "==== Rust kinit -T answers with encrypted challenge: pa_type 138, the indicator require_auth needs ===="
rust_ec_kvno() {
    local side=$1
    local conf="/tmp/${side}-krb5.conf"
    docker exec "$NAME" rm -f /tmp/rust-ec.cc /tmp/rust-ec.trace
    if ! docker exec -e KRB5_CONFIG="$conf" -e KRB5_PASSWORD=userpassword \
        -e KRB5_TRACE=/tmp/rust-ec.trace "$NAME" \
        /tmp/krb5-kinit -T /tmp/ec-armor.cc -c /tmp/rust-ec.cc user@KERBER.TEST; then
        docker exec "$NAME" cat /tmp/rust-ec.trace >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"Rust kinit -T via $side KDC failed\""
        exit 1
    fi
    RTRACE="$(docker exec "$NAME" cat /tmp/rust-ec.trace)"
    echo "$RTRACE"
    ecn="$(echo "$RTRACE" | grep -cF 'Preauth module encrypted_challenge (138) (real) returned: 0/Success' || true)"
    if [ "$ecn" != 2 ]; then
        log "fast.client.gate" "error" ",\"error\":\"Rust kinit -T via $side KDC: encrypted challenge traced $ecn times, not request and reply\""
        exit 1
    fi
    if echo "$RTRACE" | grep -F 'Produced preauth for next request:' | grep -qF 'PA-ENC-TIMESTAMP'; then
        log "fast.client.gate" "error" ",\"error\":\"Rust kinit -T via $side KDC sent an encrypted timestamp the KDC withheld\""
        exit 1
    fi
    RKLISTC="$(docker exec "$NAME" klist -C -c /tmp/rust-ec.cc 2>/dev/null || true)"
    echo "$RKLISTC"
    echo "$RKLISTC" | grep -q 'pa_type.*= 138' || {
        log "fast.client.gate" "error" ",\"error\":\"Rust kinit -T via $side KDC missing pa_type 138\""
        exit 1
    }
    set +e
    got="$(docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/rust-ec.cc "$NAME" \
        kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$side rust_ec_kvno=$got"
    echo "$got" | grep -q 'host/testhost.kerber.test@KERBER.TEST: kvno =' || {
        log "fast.client.gate" "error" ",\"error\":\"$side kvno after the Rust EC TGT + require_auth failed\""
        exit 1
    }
}
rust_ec_kvno mit
rust_ec_kvno rust
docker exec "$NAME" sh -c ': >/tmp/mit-kdc.log; : >/tmp/rust-kdc.log'
ec_pw_kvno() {
    local side=$1
    local conf="/tmp/${side}-krb5.conf"
    local logf
    if [ "$side" = mit ]; then
        logf=/tmp/mit-kdc.log
    else
        logf=/tmp/rust-kdc.log
    fi
    docker exec -e KRB5_CONFIG="$conf" "$NAME" kdestroy -A >/dev/null 2>&1 || true
    if ! docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit -c /tmp/ec-pw.cc user@KERBER.TEST'; then
        log "fast.client.gate" "error" ",\"error\":\"$side password kinit for EC negative failed\""
        exit 1
    fi
    set +e
    got="$(docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=/tmp/ec-pw.cc "$NAME" \
        kvno host/testhost.kerber.test 2>&1)"
    set -e
    echo "$side pw_kvno=$got"
    echo "$got" | grep -q 'KDC policy rejects request' || {
        log "fast.client.gate" "error" ",\"error\":\"$side password kvno missing KDC policy rejects request\""
        exit 1
    }
    docker exec "$NAME" grep -q 'HIGHER_AUTHENTICATION_REQUIRED' "$logf" || {
        docker exec "$NAME" cat "$logf" >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"$side KDC log missing HIGHER_AUTHENTICATION_REQUIRED\""
        exit 1
    }
}
ec_pw_kvno mit
ec_pw_kvno rust

echo "==== MIT kinit -T TRACE: FAST-inner METHOD-DATA and TGS strengthen ===="
fast_inner_trace() {
    local side=$1
    local conf="/tmp/${side}-krb5.conf"
    docker exec "$NAME" rm -f /tmp/fast-inner.trace /tmp/fast-inner.cc
    if ! docker exec -e KRB5_CONFIG="$conf" -e KRB5_TRACE=/tmp/fast-inner.trace "$NAME" \
        sh -c 'printf "userpassword\n" | kinit -T /tmp/ec-armor.cc -c /tmp/fast-inner.cc user@KERBER.TEST'; then
        docker exec "$NAME" cat /tmp/fast-inner.trace >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"MIT kinit -T TRACE via $side KDC failed\""
        exit 1
    fi
    TRACE="$(docker exec "$NAME" cat /tmp/fast-inner.trace)"
    echo "$TRACE"
    echo "$TRACE" | grep -F 'Processing preauth types:' | grep -F 'PA-FX-FAST (136)' || {
        log "fast.client.gate" "error" ",\"error\":\"$side FAST-inner TRACE missing PA-FX-FAST (136)\""
        exit 1
    }
    echo "$TRACE" | grep -F 'Processing preauth types:' | grep -F 'PA-ENCRYPTED-CHALLENGE (138)' || {
        log "fast.client.gate" "error" ",\"error\":\"$side FAST-inner TRACE missing PA-ENCRYPTED-CHALLENGE (138)\""
        exit 1
    }
    docker exec "$NAME" rm -f /tmp/fast-tgs.trace
    if ! docker exec -e KRB5_CONFIG="$conf" -e KRB5_TRACE=/tmp/fast-tgs.trace -e KRB5CCNAME=/tmp/fast-inner.cc "$NAME" \
        kvno host/testhost.kerber.test; then
        docker exec "$NAME" cat /tmp/fast-tgs.trace >&2 || true
        log "fast.client.gate" "error" ",\"error\":\"$side FAST kvno TRACE failed\""
        exit 1
    fi
    TGST="$(docker exec "$NAME" cat /tmp/fast-tgs.trace)"
    echo "$TGST"
    echo "$TGST" | grep -F 'Encoding request body and padata into FAST request' || {
        log "fast.client.gate" "error" ",\"error\":\"$side FAST TGS TRACE missing FAST request encode\""
        exit 1
    }
    echo "$TGST" | grep -F 'FAST reply key:' || {
        log "fast.client.gate" "error" ",\"error\":\"$side FAST TGS TRACE missing FAST reply key\""
        exit 1
    }
}
fast_inner_trace mit
fast_inner_trace rust

echo "==== Rust kinit --fast -S against rust KDC ===="
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'delstr host/testhost.kerber.test require_auth'
docker exec "$NAME" kdb5_util dump /tmp/plain-host.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5-kdc || true
docker exec "$NAME" sh -c ': >/tmp/rust-kdc.log'
LOAD_PLAIN="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/plain-host.dump)"
echo "$LOAD_PLAIN"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_PROFILE=/tmp/rust-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"rust kdc did not listen for FAST TGS"'
    exit 1
fi
docker exec "$NAME" rm -f /tmp/rust-armor.cc /tmp/rust-fast-tgs.cc
if ! docker exec -e KRB5_CONFIG=/tmp/rust-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit -c /tmp/rust-armor.cc user@KERBER.TEST; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"rust kinit armor against rust KDC failed"'
    exit 1
fi
set +e
RUST_TGS="$(docker exec -e RUST_LOG=krb5_protocol=debug \
    -e KRB5_CONFIG=/tmp/rust-krb5.conf -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit --fast --armor-ccache /tmp/rust-armor.cc \
    -c /tmp/rust-fast-tgs.cc -S host/testhost.kerber.test user@KERBER.TEST 2>&1)"
rtrc=$?
set -e
echo "$RUST_TGS"
if [ "$rtrc" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    log "fast.client.gate" "error" ',"error":"rust kinit --fast -S against rust KDC failed","rc":'"$rtrc"
    exit 1
fi
assert_no_error_log "$RUST_TGS" fast.client.gate
echo "$RUST_TGS" | grep -q '"fast_strengthen":true' || {
    log "fast.client.gate" "error" ',"error":"rust KDC FAST TGS missing fast_strengthen"'
    exit 1
}
KLISTR="$(docker exec "$NAME" klist -c /tmp/rust-fast-tgs.cc 2>/dev/null || true)"
echo "$KLISTR"
echo "$KLISTR" | grep -q 'host/testhost.kerber.test'

log "fast.client.gate" "ok" ',"mode":"rust-kinit","pa_type":136,"principal":"user@KERBER.TEST","nopreauth":true,"etype":20,"tgs_strengthen":true,"mit_tgs_strengthen":true,"ec_require_auth":"issued+12","rust_kdc_fast_tgs":true,"fast_inner_method":true'
exit 0
