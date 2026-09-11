#!/usr/bin/env bash
# Same AS/TGS bytes to a live Rust KDC and a live MIT 1.22.2 krb5kdc on one
# identical dump. Isolation: in-container; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-differential-gate"
GOLDEN="tests/traces/kdb/mit-dump-v7.txt"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-differential-gate}"
OUT="$SCRATCH/differential-gate"
mkdir -p "$OUT"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"differential-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "differential.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

unavailable() {
    log "differential.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/differential-unavailable.log"
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
if [ ! -f "$GOLDEN" ]; then
    die "missing golden dump $GOLDEN"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb -q
cargo build -p krb5-admin --bin krb5-kadmin-local -p krb5-client --bin krb5-kvno -q
cargo build -p krb5-protocol --example diffsend --features diff -q

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT" || true
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    unavailable "MIT image unavailable"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local && docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kvno" "$NAME":/tmp/krb5-kvno
docker cp "${CARGO_TARGET_DIR:-target}/debug/examples/diffsend" "$NAME":/tmp/diffsend
docker cp "$GOLDEN" "$NAME":/tmp/mit.dump
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kadmin-local /tmp/krb5-kvno /tmp/diffsend

echo "==== load identical dump into Rust KDC on :8888 ===="
LOAD="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/mit.dump)"
echo "$LOAD"
echo "$LOAD" | grep -q 'ok load version=7' || die "rust kdb load failed"
ADD="$(docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey krbtgt/OTHER.TEST')"
echo "$ADD"
echo "$ADD" | grep -q 'created' || die "rust addprinc krbtgt/OTHER.TEST failed"
ADDLOCK="$(docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey +0x40 host/locked.kerber.test')"
echo "$ADDLOCK"
echo "$ADDLOCK" | grep -q 'created' || die "rust addprinc host/locked.kerber.test failed"
ADDDUP="$(docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey +0x24 host/dupskey.kerber.test')"
echo "$ADDDUP"
echo "$ADDDUP" | grep -q 'created' || die "rust addprinc host/dupskey.kerber.test failed"
ADDNOSVR="$(docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey +0x1000 host/nosvr.kerber.test')"
echo "$ADDNOSVR"
echo "$ADDNOSVR" | grep -q 'created' || die "rust addprinc host/nosvr.kerber.test failed"
ADDEXP="$(docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey expiredsvc')"
echo "$ADDEXP"
echo "$ADDEXP" | grep -q 'created' || die "rust addprinc expiredsvc failed"
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc -expire 1 expiredsvc'
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'setstr expiredsvc require_auth pkinit'

docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc --export-keytab /tmp/host.keytab --export-krbtgt-keytab /tmp/krbtgt.keytab 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'

ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    die "rust kdc did not listen on 8888"
}
docker exec "$NAME" test -f /tmp/krbtgt.keytab || die "krbtgt keytab missing"
docker exec "$NAME" test -f /tmp/host.keytab || die "host keytab missing"

echo "==== load identical dump into MIT krb5kdc on :88 ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kdb5_util load /tmp/mit.dump
MITADD="$(docker exec "$NAME" kadmin.local -q 'addprinc -randkey krbtgt/OTHER.TEST@KERBER.TEST')"
echo "$MITADD"
echo "$MITADD" | grep -qi 'created' || die "MIT addprinc krbtgt/OTHER.TEST failed"
docker exec "$NAME" kadmin.local -q 'addprinc -randkey host/locked.kerber.test'
docker exec "$NAME" kadmin.local -q 'modprinc -allow_tix host/locked.kerber.test'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey host/dupskey.kerber.test'
docker exec "$NAME" kadmin.local -q 'modprinc +disallow_dup_skey +disallow_tgt_based host/dupskey.kerber.test'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey host/nosvr.kerber.test'
docker exec "$NAME" kadmin.local -q 'modprinc +disallow_svr host/nosvr.kerber.test'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey expiredsvc'
docker exec "$NAME" kadmin.local -q 'modprinc -expire 1/1/1990 expiredsvc'
docker exec "$NAME" kadmin.local -q 'setstr expiredsvc require_auth pkinit'
# Advertise SPAKE like the Rust KDC (always-on SpakeMod) so PREAUTH hint
# multisets match. MIT krb5kdc reads spake_preauth_groups from [libdefaults].
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5.conf")
t = p.read_text()
if "spake_preauth_groups" not in t:
    t = t.replace("[libdefaults]", "[libdefaults]\n    spake_preauth_groups = P-256", 1)
p.write_text(t)
'
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc -n >/tmp/mit-kdc.log 2>&1 & sleep 0.5; cat /tmp/mit-kdc.log' 2>&1 || true)"
echo "$STARTLOG"
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "MIT krb5kdc did not listen on 88"
echo "$STARTLOG" | grep -q 'Address already in use' && die "MIT krb5kdc could not bind :88"
echo "$STARTLOG" | grep -q 'setting up network' || die "MIT krb5kdc did not start"
echo "$STARTLOG" | grep -qi 'spake failed to initialize' && die "MIT SPAKE preauth did not initialize"


echo "==== diffsend build-once/send-twice ===="
set +e
DIFF="$(docker exec \
    -e KRB5_PASSWORD=userpassword \
    -e KERBER_PAUSER_PASSWORD=preauthpw \
    -e KERBER_DIFF_REALM=KERBER.TEST \
    -e KERBER_KRBTGT_KEYTAB=/tmp/krbtgt.keytab \
    -e KERBER_HOST_KEYTAB=/tmp/host.keytab \
    "$NAME" /tmp/diffsend 127.0.0.1:8888 127.0.0.1:88 /tmp/diff-corpus 2>&1)"
RC=$?
set -e
echo "$DIFF" | tee "$OUT/diffsend.log"
docker cp "$NAME":/tmp/diff-corpus "$OUT/diff-corpus" 2>/dev/null || true
docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true
docker cp "$NAME":/tmp/mit-kdc.log "$OUT/mit-kdc.log" 2>/dev/null || true
if [ "$RC" != 0 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log >&2 || true
    die "diffsend failed (rc=$RC)"
fi
echo "$DIFF" | grep -q '"same_request_bytes":true' || die "diffsend did not log same request bytes"
echo "$DIFF" | grep -q '"case":"unknown-cname","outcome":"ok","error_code":6,"e_text":"CLIENT_NOT_FOUND","rust_tag":"0x7e","mit_tag":"0x7e"' || die "unknown-cname was not CLIENT_NOT_FOUND"
echo "$DIFF" | grep -q '"case":"etype-nosupp","outcome":"ok","error_code":14,"e_text":"BAD_ENCRYPTION_TYPE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "missing BAD_ENCRYPTION_TYPE"
echo "$DIFF" | grep -q '"case":"as-session-enctype","outcome":"ok","error_code":14,"e_text":"BAD_ENCRYPTION_TYPE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "missing as-session-enctype"
echo "$DIFF" | grep -q '"case":"wrong-realm","outcome":"ok","error_code":6,"e_text":"CLIENT_NOT_FOUND","rust_tag":"0x7e","mit_tag":"0x7e"' || die "wrong-realm was not CLIENT_NOT_FOUND"
echo "$DIFF" | grep -q '"case":"pauser-no-preauth","outcome":"ok","error_code":25' || die "missing PREAUTH_REQUIRED(25)"
echo "$DIFF" | grep -q '"e_text":"NEEDED_PREAUTH"' || die "missing NEEDED_PREAUTH"
echo "$DIFF" | grep -q '"case":"skewed-timestamp","outcome":"ok","error_code":37,"e_text":"PREAUTH_FAILED","rust_tag":"0x7e","mit_tag":"0x7e"' || die "missing PREAUTH_FAILED"
echo "$DIFF" | grep -q '"case":"unknown-sname","outcome":"ok","error_code":7,"e_text":"SERVER_NOT_FOUND","rust_tag":"0x7e","mit_tag":"0x7e"' || die "missing SERVER_NOT_FOUND"
echo "$DIFF" | grep -q '"case":"garbage-pdu","outcome":"ok","rust_tag":"drop","mit_tag":"drop"' || die "garbage-pdu was not both-drop"
echo "$DIFF" | grep -q '"case":"tgs-not-a-tgt","outcome":"ok","error_code":35,"e_text":"BAD TGS SERVER NAME","rust_tag":"0x7e","mit_tag":"0x7e"' || die "missing BAD TGS SERVER NAME"
echo "$DIFF" | grep -q '"case":"tgt-expired","outcome":"ok","error_code":32,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgt-expired not code 32 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"tgt-nyv","outcome":"ok","error_code":33,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgt-nyv not code 33 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"as-success"' || die "missing as-success"
echo "$DIFF" | grep -q '"case":"tgs-success"' || die "missing tgs-success"
echo "$DIFF" | grep -q '"rust_tag":"0x6b"' || die "as-success missing AS-REP tag"
echo "$DIFF" | grep -q '"rust_tag":"0x6d"' || die "tgs-success missing TGS-REP tag"
echo "$DIFF" | grep -q '"case":"as-success".*"rust_enc_tag":"0x7a".*"mit_enc_tag":"0x7a"' || die "as-success enc-part not APPLICATION 26 both legs"
echo "$DIFF" | grep -q '"case":"tgs-success".*"rust_enc_tag":"0x7a".*"mit_enc_tag":"0x7a"' || die "tgs-success enc-part not APPLICATION 26 both legs"
echo "$DIFF" | grep -q '"case":"as-optimistic-encts-wrong-etype","outcome":"ok","error_code":24' || die "as-optimistic-encts-wrong-etype not code 24 on both legs"
echo "$DIFF" | grep -q '"case":"as-invalid-opts","outcome":"ok","error_code":13' || die "as-invalid-opts (RENEW) not code 13 on both legs"
echo "$DIFF" | grep -q '"case":"as-request-anonymous","outcome":"ok","error_code":13,"e_text":"VALIDATE_ANONYMOUS_PRINCIPAL","rust_tag":"0x7e","mit_tag":"0x7e"' || die "as-request-anonymous not code 13 e_text VALIDATE_ANONYMOUS_PRINCIPAL on both legs"
echo "$DIFF" | grep -q '"case":"as-validate-before-preauth","outcome":"ok","error_code":23' || die "as-validate-before-preauth (preauth+needchange) not code 23 on both legs"
echo "$DIFF" | grep -q '"case":"as-retransmit","outcome":"ok","rust_retransmit_identical":true,"mit_retransmit_identical":true' || die "as-retransmit reply not identical from the lookaside on both legs"
echo "$DIFF" | grep -q '"outcome":"ok","cases":98' || die "diffsend did not finish 98 cases"
echo "$DIFF" | grep -q '"case":"fast-armor-no-subkey","outcome":"ok","error_code":12,"e_text":"FIND_FAST","rust_tag":"0x7e","mit_tag":"0x7e"' || die "fast-armor-no-subkey not code 12 e_text FIND_FAST on both legs"
echo "$DIFF" | grep -q '"case":"armor-ap-req-as-pa-tgs-req","outcome":"ok","error_code":12,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "armor-ap-req-as-pa-tgs-req not code 12 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"tgs-ad-fx-armor-authenticator","outcome":"ok","error_code":12,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-ad-fx-armor-authenticator not code 12 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"as-bad-msg-type","outcome":"ok","error_code":60,"e_text":"VALIDATE_MESSAGE_TYPE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "as-bad-msg-type not code 60 e_text VALIDATE_MESSAGE_TYPE on both legs"
echo "$DIFF" | grep -q '"case":"as-bad-pvno","outcome":"ok","rust_tag":"drop","mit_tag":"drop"' || die "as-bad-pvno was not both-drop"
echo "$DIFF" | grep -q '"case":"tgs-bad-msg-type","outcome":"ok","error_code":60,"e_text":"UNKNOWN_REASON","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-bad-msg-type not code 60 e_text UNKNOWN_REASON on both legs"
echo "$DIFF" | grep -q '"case":"as-service-not-allowed","outcome":"ok","error_code":27,"e_text":"SERVICE NOT ALLOWED","rust_tag":"0x7e","mit_tag":"0x7e"' || die "as-service-not-allowed not code 27 e_text SERVICE NOT ALLOWED on both legs"
echo "$DIFF" | grep -q '"case":"tgs-ap-options","outcome":"ok","error_code":12,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-ap-options not code 12 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"tgs-header-kvno-zero","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-header-kvno-zero not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"as-hw-preauth","outcome":"ok","error_code":25,"e_text":"NEEDED_HW_PREAUTH","e_data_types":\[19,133,136\],"rust_tag":"0x7e","mit_tag":"0x7e"' || die "as-hw-preauth not code 25 with e_data_types [19,133,136] on both legs"
echo "$DIFF" | grep -q '"case":"as-spake-round1","outcome":"ok","error_code":91,"e_text":"PREAUTH_FAILED"' || die "as-spake-round1 not code 91 e_text PREAUTH_FAILED on both legs"
echo "$DIFF" | grep -E '"case":"as-spake-round1".*"e_data_types":\[.*19.*133.*151.*\]' || die "as-spake-round1 e_data_types missing 19/133/151"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-unknown-server","outcome":"ok","error_code":7,"e_text":"2ND_TKT_SERVER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-unknown-server not code 7 e_text 2ND_TKT_SERVER on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-bad-etype","outcome":"ok","error_code":60,"e_text":"2ND_TKT_SERVER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-bad-etype not code 60 e_text 2ND_TKT_SERVER on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-corrupt","outcome":"ok","error_code":31,"e_text":"2ND_TKT_DECRYPT","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-corrupt not code 31 e_text 2ND_TKT_DECRYPT on both legs"
echo "$DIFF" | grep -q '"case":"tgs-pac-client-mismatch","outcome":"ok","error_code":13,"e_text":"HEADER_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-pac-client-mismatch not code 13 e_text HEADER_PAC on both legs"
echo "$DIFF" | grep -q '"case":"tgs-pac-corrupt-before-sname","outcome":"ok","error_code":41,"e_text":"HEADER_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-pac-corrupt-before-sname not code 41 e_text HEADER_PAC on both legs"
echo "$DIFF" | grep -q '"case":"tgs-pac-request-false","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d".*"issued_pac":true' || die "tgs-pac-request-false not issued_pac true on both legs"
echo "$DIFF" | grep -q '"case":"tgs-from-pacless-tgt","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d".*"issued_pac":false' || die "tgs-from-pacless-tgt not issued_pac false on both legs"
echo "$DIFF" | grep -q '"case":"tgs-renew-service-ticket","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-renew-service-ticket not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"tgs-proxy-krbtgt","outcome":"ok","error_code":13,"e_text":"CAN'\''T PROXY TGT","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-proxy-krbtgt not code 13 e_text CAN'T PROXY TGT on both legs"
echo "$DIFF" | grep -q '"case":"tgs-canonicalize-renew","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-canonicalize-renew not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"tgs-expired-vs-unknown-sname","outcome":"ok","error_code":32,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-expired-vs-unknown-sname not code 32 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"s4u2self-no-pac","outcome":"ok","error_code":20,"e_text":"S4U2SELF_NO_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2self-no-pac not code 20 e_text S4U2SELF_NO_PAC on both legs"
echo "$DIFF" | grep -q '"case":"s4u2self-pac-client-mismatch","outcome":"ok","error_code":13,"e_text":"S4U2SELF_LOCAL_PAC_CLIENT","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2self-pac-client-mismatch not code 13 e_text S4U2SELF_LOCAL_PAC_CLIENT on both legs"
echo "$DIFF" | grep -q '"case":"pa-s4u-x509-user-bad-checksum","outcome":"ok","error_code":41,"e_text":"INVALID_S4U2SELF_CHECKSUM","rust_tag":"0x7e","mit_tag":"0x7e"' || die "pa-s4u-x509-user-bad-checksum not code 41 e_text INVALID_S4U2SELF_CHECKSUM on both legs"
echo "$DIFF" | grep -q '"case":"pa-s4u-x509-user-nonce","outcome":"ok","error_code":41,"e_text":"INVALID_S4U2SELF_CHECKSUM","rust_tag":"0x7e","mit_tag":"0x7e"' || die "pa-s4u-x509-user-nonce not code 41 e_text INVALID_S4U2SELF_CHECKSUM on both legs"
echo "$DIFF" | grep -q '"case":"pa-for-user-only","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "pa-for-user-only not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"pa-s4u-x509-user-empty","outcome":"ok","error_code":6,"e_text":"INVALID_S4U2SELF_REQUEST","rust_tag":"0x7e","mit_tag":"0x7e"' || die "pa-s4u-x509-user-empty not code 6 e_text INVALID_S4U2SELF_REQUEST on both legs"
echo "$DIFF" | grep -q '"case":"pa-for-user-undecodable","outcome":"ok","error_code":60,"e_text":"DECODE_PA_FOR_USER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "pa-for-user-undecodable not code 60 e_text DECODE_PA_FOR_USER on both legs"
echo "$DIFF" | grep -q '"case":"pa-s4u-x509-user","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d".*"reply_padata":130' || die "pa-s4u-x509-user not reply_padata 130 on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-no-2nd-tkt","outcome":"ok","error_code":60,"e_text":"UNKNOWN_REASON","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-no-2nd-tkt not code 60 e_text UNKNOWN_REASON on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-not-forwardable","outcome":"ok","error_code":13,"e_text":"EVIDENCE_TKT_NOT_FORWARDABLE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-not-forwardable not code 13 e_text EVIDENCE_TKT_NOT_FORWARDABLE on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-u2u-combo","outcome":"ok","error_code":13,"e_text":"INVALID_S4U2PROXY_OPTIONS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-u2u-combo not code 13 e_text INVALID_S4U2PROXY_OPTIONS on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-tgs-target","outcome":"ok","error_code":12,"e_text":"NOT_ALLOWED_TO_DELEGATE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-tgs-target not code 12 e_text NOT_ALLOWED_TO_DELEGATE on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-no-header-pac","outcome":"ok","error_code":20,"e_text":"S4U2PROXY_NO_HEADER_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-no-header-pac not code 20 e_text S4U2PROXY_NO_HEADER_PAC on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-header-pac","outcome":"ok","error_code":13,"e_text":"S4U2PROXY_HEADER_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-header-pac not code 13 e_text S4U2PROXY_HEADER_PAC on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-no-stkt-pac","outcome":"ok","error_code":41,"e_text":"S4U2PROXY_NO_STKT_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-no-stkt-pac not code 41 e_text S4U2PROXY_NO_STKT_PAC on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-evidence-mismatch","outcome":"ok","error_code":26,"e_text":"EVIDENCE_TICKET_MISMATCH","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-evidence-mismatch not code 26 e_text EVIDENCE_TICKET_MISMATCH on both legs"
echo "$DIFF" | grep -q '"case":"s4u2proxy-local-stkt-pac","outcome":"ok","error_code":13,"e_text":"S4U2PROXY_LOCAL_STKT_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2proxy-local-stkt-pac not code 13 e_text S4U2PROXY_LOCAL_STKT_PAC on both legs"
echo "$DIFF" | grep -q '"case":"u2u-no-2nd-tkt","outcome":"ok","error_code":13,"e_text":"NO_2ND_TKT","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-no-2nd-tkt not code 13 e_text NO_2ND_TKT on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-not-tgs","outcome":"ok","error_code":12,"e_text":"2ND_TKT_NOT_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-not-tgs not code 12 e_text 2ND_TKT_NOT_TGS on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-mismatch","outcome":"ok","error_code":26,"e_text":"2ND_TKT_MISMATCH","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-mismatch not code 26 e_text 2ND_TKT_MISMATCH on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-bad-pac","outcome":"ok","error_code":41,"e_text":"2ND_TKT_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-bad-pac not code 41 e_text 2ND_TKT_PAC on both legs"
echo "$DIFF" | grep -q '"case":"u2u-bad-etype","outcome":"ok","error_code":14,"e_text":"BAD_ETYPE_IN_2ND_TKT","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-bad-etype not code 14 e_text BAD_ETYPE_IN_2ND_TKT on both legs"
echo "$DIFF" | grep -q '"case":"u2u-success","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "u2u-success not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"tgs-addr-mismatch","outcome":"ok","error_code":38,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-addr-mismatch not code 38 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"tgs-forwarded-addresses","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-forwarded-addresses not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-foreign-realm","outcome":"ok","error_code":7,"e_text":"2ND_TKT_SERVER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-foreign-realm not code 7 e_text 2ND_TKT_SERVER on both legs"
echo "$DIFF" | grep -q '"case":"s4u2self-renew-options","outcome":"ok","error_code":13,"e_text":"INVALID S4U2SELF OPTIONS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2self-renew-options not code 13 e_text INVALID S4U2SELF OPTIONS on both legs"
echo "$DIFF" | grep -q '"case":"pa-s4u-x509-user-truncated","outcome":"ok","error_code":60,"e_text":"DECODE_PA_S4U_X509_USER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "pa-s4u-x509-user-truncated not code 60 e_text DECODE_PA_S4U_X509_USER on both legs"
echo "$DIFF" | grep -q '"case":"s4u2self-krbtgt-other","outcome":"ok","error_code":36,"e_text":"INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2self-krbtgt-other not code 36 e_text INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH on both legs"
echo "$DIFF" | grep -q '"case":"tgs-locked-pac-mismatch","outcome":"ok","error_code":13,"e_text":"HEADER_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-locked-pac-mismatch not code 13 e_text HEADER_PAC on both legs"
echo "$DIFF" | grep -q '"case":"u2u-dup-skey-tgt-based","outcome":"ok","error_code":12,"e_text":"DUP_SKEY DISALLOWED","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-dup-skey-tgt-based not code 12 e_text DUP_SKEY DISALLOWED on both legs"
echo "$DIFF" | grep -q '"case":"tgs-expired-addr-mismatch","outcome":"ok","error_code":38,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-expired-addr-mismatch not code 38 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"tgs-expired-badmatch","outcome":"ok","error_code":36,"e_text":"PROCESS_TGS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-expired-badmatch not code 36 e_text PROCESS_TGS on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-kvno-miss","outcome":"ok","error_code":60,"e_text":"2ND_TKT_SERVER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-kvno-miss not code 60 e_text 2ND_TKT_SERVER on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-disallow-svr","outcome":"ok","error_code":7,"e_text":"2ND_TKT_SERVER","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-disallow-svr not code 7 e_text 2ND_TKT_SERVER on both legs"
echo "$DIFF" | grep -q '"case":"s4u2self-cert-only","outcome":"ok","error_code":60,"e_text":"LOOKING_UP_S4U2SELF_PRINCIPAL","rust_tag":"0x7e","mit_tag":"0x7e"' || die "s4u2self-cert-only not code 60 e_text LOOKING_UP_S4U2SELF_PRINCIPAL on both legs"
echo "$DIFF" | grep -q '"case":"tgs-forwarded-tgt-addresses","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-forwarded-tgt-addresses not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"tgs-forwarded-addresses".*"forwarded":true' || die "tgs-forwarded-addresses missing forwarded true on both legs"
echo "$DIFF" | grep -q '"case":"tgs-forwarded-tgt-addresses".*"forwarded":true' || die "tgs-forwarded-tgt-addresses missing forwarded true on both legs"
echo "$DIFF" | grep -q '"case":"tgs-forwarded-on-non-f-tgt","outcome":"ok","error_code":13,"e_text":"TGT NOT FORWARDABLE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-forwarded-on-non-f-tgt not code 13 e_text TGT NOT FORWARDABLE on both legs"
echo "$DIFF" | grep -q '"case":"tgs-proxy-on-non-p-tgt","outcome":"ok","error_code":13,"e_text":"TGT NOT PROXIABLE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-proxy-on-non-p-tgt not code 13 e_text TGT NOT PROXIABLE on both legs"
echo "$DIFF" | grep -q '"case":"tgs-postdate-on-non-postdatable","outcome":"ok","error_code":13,"e_text":"TGT NOT POSTDATABLE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-postdate-on-non-postdatable not code 13 e_text TGT NOT POSTDATABLE on both legs"
echo "$DIFF" | grep -q '"case":"tgs-validate-invalid-non-renewable","outcome":"ok","error_code":13,"e_text":"TICKET NOT RENEWABLE","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-validate-invalid-non-renewable not code 13 e_text TICKET NOT RENEWABLE on both legs"
echo "$DIFF" | grep -q '"case":"tgs-postdated-is-invalid","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d".*"invalid":true' || die "tgs-postdated-is-invalid not invalid true on both legs"
echo "$DIFF" | grep -q '"case":"tgs-no-preauth-flag","outcome":"ok","error_code":60,"e_text":"NO PREAUTH","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-no-preauth-flag not code 60 e_text NO PREAUTH on both legs"
echo "$DIFF" | grep -q '"case":"tgs-hw-preauth-flag","outcome":"ok","error_code":60,"e_text":"NO HW PREAUTH","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-hw-preauth-flag not code 60 e_text NO HW PREAUTH on both legs"
echo "$DIFF" | grep -q '"case":"tgs-nyv-inside-skew","outcome":"ok","error_code":33,"e_text":"NOT_YET_VALID","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-nyv-inside-skew not code 33 e_text NOT_YET_VALID on both legs"
echo "$DIFF" | grep -q '"case":"tgs-body-authdata","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","copied":true' || die "tgs-body-authdata not copied on both legs"
echo "$DIFF" | grep -q '"case":"tgs-ad-mandatory-for-kdc","outcome":"ok","error_code":12,"e_text":"HANDLE_AUTHDATA","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-ad-mandatory-for-kdc not code 12 e_text HANDLE_AUTHDATA on both legs"
echo "$DIFF" | grep -q '"case":"tgs-body-authdata-kdc-issued-stripped","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","kept":true,"dummy_stripped":true' || die "tgs-body-authdata-kdc-issued-stripped not keep/strip on both legs"
echo "$DIFF" | grep -q '"case":"tgs-truncated-cammac","outcome":"ok","error_code":60,"e_text":"GET_AUTH_INDICATORS","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-truncated-cammac not code 60 e_text GET_AUTH_INDICATORS on both legs"
echo "$DIFF" | grep -qF '"case":"ec-outside-fast","outcome":"ok","error_code":24,"e_text":"PREAUTH_FAILED","e_data_types":[2,19,133,136,151],"rust_tag":"0x7e","mit_tag":"0x7e"' || die "ec-outside-fast not code 24 e_text PREAUTH_FAILED on both legs"
echo "$DIFF" | grep -q '"case":"tgs-rbcd-pac-options","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","pac_options":true' || die "tgs-rbcd-pac-options not PAC-OPTIONS enc_padata on both legs"
echo "$DIFF" | grep -q '"case":"tgs-till-in-past","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-till-in-past not TGS-REP on both legs"
echo "$DIFF" | grep -q '"case":"tgs-service-expired-require-auth","outcome":"ok","error_code":2,"e_text":"SERVICE EXPIRED","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-service-expired-require-auth not code 2 e_text SERVICE EXPIRED on both legs"
echo "$DIFF" | grep -q '"case":"tgs-postdated-from","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"' || die "tgs-postdated-from not TGS-REP on both legs"
echo "==== MIT_HINT kdc-padata-proxy 25/91 e_data wire order ===="
docker cp "$ROOT/scripts/lib/kdc-padata-proxy.py" "$NAME":/tmp/kdc-padata-proxy.py
HINT_ORDER="$(docker exec "$NAME" python3 -c '
import importlib.machinery
p = importlib.machinery.SourceFileLoader("proxy", "/tmp/kdc-padata-proxy.py").load_module()
want = {
    "pauser-no-preauth": (25, [136, 19, 151, 2, 133]),
    "as-hw-preauth": (25, [136, 19, 133]),
    "as-spake-round1": (91, [151, 19, 133]),
    "ec-outside-fast": (24, [136, 19, 151, 2, 133]),
}
for case, (wcode, wtypes) in want.items():
    for leg in ("rust", "mit"):
        data = open(f"/tmp/diff-corpus/{case}.{leg}.der", "rb").read()
        code, enc, types = p.parse_error_edata(data)
        print(f"{case}.{leg} code={code} enc={enc} types={types}")
        if code != wcode or types != wtypes:
            raise SystemExit(f"{case}.{leg} want {wcode} {wtypes} got {code} {types}")
print("hint-order-ok")
')"
echo "$HINT_ORDER"
echo "$HINT_ORDER" | grep -qF 'hint-order-ok' || die "25/91 hint e_data wire order mismatch"
echo "$HINT_ORDER" | grep -qF 'pauser-no-preauth.mit code=25 enc=method types=[136, 19, 151, 2, 133]' || die "MIT_HINT 25 hint list not [136, 19, 151, 2, 133]"
echo "$HINT_ORDER" | grep -qF 'as-spake-round1.mit code=91 enc=method types=[151, 19, 133]' || die "MIT_HINT 91 e_data not [151, 19, 133]"
echo "$HINT_ORDER" | grep -qF 'as-spake-round1.rust code=91 enc=method types=[151, 19, 133]' || die "rust_hint 91 e_data not [151, 19, 133]"
# W1-K M2b: the differential oracle has no case-name whitelist; no diffsend line
# may carry a "whitelist" key.
if echo "$DIFF" | grep -q '"whitelist"'; then
    die "diffsend emitted a whitelist key; M2b bans case-name whitelists"
fi

echo "==== 128 KiB padded AS-REQ and 1 MiB+1 TCP cap both legs ===="
TCP_CAP="$(docker exec "$NAME" python3 -c '
import socket, struct, time, sys

def der_len(n):
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    if n < 65536:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

def tlv(tag, val):
    return bytes([tag]) + der_len(len(val)) + val

def parse_tlv(data, i=0):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + l], i + l

def ctx(n, val):
    return tlv(0xA0 | n, val)

def integer(n):
    if n == 0:
        return tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return tlv(0x02, b)

def gstr(s):
    return tlv(0x1B, s.encode("ascii"))

def seq(*parts):
    return tlv(0x30, b"".join(parts))

def pname(nt, *comps):
    return seq(ctx(0, integer(nt)), ctx(1, seq(*[gstr(c) for c in comps])))

def gtime(ts):
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(ts)).encode())

def krb_error(der):
    _, inner, _ = parse_tlv(der)
    _, seqb, _ = parse_tlv(inner)
    i = 0
    fields = {}
    while i < len(seqb):
        t, v, i = parse_tlv(seqb, i)
        n = t & 0x1F
        if t & 0x20 and v:
            _, inner2, _ = parse_tlv(v)
            fields[n] = inner2
        else:
            fields[n] = v
    code = int.from_bytes(fields.get(6, b"\x00"), "big")
    return code, fields.get(11, b"")

body = seq(
    ctx(0, tlv(0x03, b"\x00\x00\x00\x00\x00")),
    ctx(1, pname(1, "nosuch")),
    ctx(2, gstr("KERBER.TEST")),
    ctx(3, pname(2, "krbtgt", "KERBER.TEST")),
    ctx(5, gtime(time.time() + 3600)),
    ctx(7, integer(12345)),
    ctx(8, seq(integer(18))),
)

def asreq_with_pad(pad):
    padata = seq(seq(ctx(1, integer(9999)), ctx(2, tlv(0x04, b"\x00" * pad))))
    inner = seq(ctx(1, integer(5)), ctx(2, integer(10)), ctx(3, padata), ctx(4, body))
    return tlv(0x6A, inner)

want = 128 * 1024
pad = 1
asreq = asreq_with_pad(pad)
pad = max(1, want - len(asreq))
asreq = asreq_with_pad(pad)
while len(asreq) != want:
    if len(asreq) > want:
        pad -= len(asreq) - want
    else:
        pad += want - len(asreq)
    if pad < 1:
        raise SystemExit("pad")
    asreq = asreq_with_pad(pad)

def exchange(port, payload, timeout=8):
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(timeout)
    s.sendall(struct.pack(">I", len(payload)) + payload)
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c:
            raise SystemExit("eof hdr port %d" % port)
        hdr += c
    n = struct.unpack(">I", hdr)[0]
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            break
        body += c
    return body

def exchange_len(port, n, timeout=8):
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(timeout)
    s.sendall(struct.pack(">I", n))
    hdr = b""
    while len(hdr) < 4:
        c = s.recv(4 - len(hdr))
        if not c:
            raise SystemExit("eof hdr port %d" % port)
        hdr += c
    ln = struct.unpack(">I", hdr)[0]
    body = b""
    while len(body) < ln:
        c = s.recv(ln - len(body))
        if not c:
            break
        body += c
    return body

for port, label in ((8888, "rust"), (88, "mit")):
    der = exchange(port, asreq)
    code, etext = krb_error(der)
    print("%s_128k error_code=%d e_text=%r n=%d" % (label, code, etext, len(asreq)))
    if code != 6 or etext != b"CLIENT_NOT_FOUND":
        raise SystemExit("%s 128k want 6 CLIENT_NOT_FOUND" % label)
    der = exchange_len(port, 1024 * 1024 + 1)
    code, etext = krb_error(der)
    print("%s_1mib error_code=%d e_text=%r" % (label, code, etext))
    if code != 61:
        raise SystemExit("%s 1MiB+1 want 61" % label)
print("tcp_cap=ok")
')"
echo "$TCP_CAP"
echo "$TCP_CAP" | grep -F 'rust_128k error_code=6' || die "rust 128KiB was not CLIENT_NOT_FOUND"
echo "$TCP_CAP" | grep -F 'mit_128k error_code=6' || die "MIT 128KiB was not CLIENT_NOT_FOUND"
echo "$TCP_CAP" | grep -F 'rust_1mib error_code=61' || die "rust 1MiB+1 was not FIELD_TOOLONG"
echo "$TCP_CAP" | grep -F 'mit_1mib error_code=61' || die "MIT 1MiB+1 was not FIELD_TOOLONG"
echo "$TCP_CAP" | grep -F 'tcp_cap=ok' || die "tcp cap cell did not finish"

docker cp "$NAME":/tmp/diff-corpus "$OUT/diff-corpus" 2>/dev/null || true
docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true

echo "$DIFF" | grep -q '"case":"tgs-pac-server-cksum-wrong-enctype","outcome":"ok","error_code":60,"e_text":"HEADER_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "tgs-pac-server-cksum-wrong-enctype not code 60 e_text HEADER_PAC on both legs"
echo "$DIFF" | grep -q '"case":"u2u-2nd-ticket-pac-wrong-enctype","outcome":"ok","error_code":60,"e_text":"2ND_TKT_PAC","rust_tag":"0x7e","mit_tag":"0x7e"' || die "u2u-2nd-ticket-pac-wrong-enctype not code 60 e_text 2ND_TKT_PAC on both legs"
echo "$DIFF" | grep -q '"case":"u2u-success","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","ticket_etype":18,"reply_session_etype":17' || die "u2u-success not distinct-stkt decrypt + reply 17 (both sessions etype 18)"
echo "$DIFF" | grep -q '"case":"u2u-success-offered","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","ticket_etype":18,"reply_session_etype":18' || die "u2u-success-offered not ticket 18 / reply 18"

echo "==== krbtgt rekey keepold then RENEW service ticket both legs ===="
docker exec "$NAME" sh -c 'cat >/tmp/rust-client.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    rdns = false
    forwardable = true
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
EOF'
docker exec "$NAME" sh -c "printf 'userpassword\n' | kinit -r 1d -S host/testhost.kerber.test@KERBER.TEST -c /tmp/krb5cc_mit_rekey user"
MITCPW="$(docker exec "$NAME" kadmin.local -q 'cpw -randkey -keepold -e aes128-cts-hmac-sha1-96 krbtgt/KERBER.TEST')"
echo "$MITCPW"
echo "$MITCPW" | grep -qi 'randomized' || die "MIT cpw -keepold krbtgt failed"
set +e
MITREN="$(docker exec "$NAME" /tmp/krb5-kvno --renew-ticket --body-realm KERBER.TEST \
    -c /tmp/krb5cc_mit_rekey 127.0.0.1:88 host/testhost.kerber.test@KERBER.TEST 2>&1)"
mitren_rc=$?
set -e
echo "$MITREN"
echo "MIT_krbtgt_rekey_renew rc=${mitren_rc}"
[ "$mitren_rc" = 0 ] || die "MIT RENEW after krbtgt rekey failed"
echo "$MITREN" | grep -q 'kvno =' || die "MIT RENEW after rekey missing kvno"
docker exec -e KRB5_CONFIG=/tmp/rust-client.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -r 1d -S host/testhost.kerber.test@KERBER.TEST -c /tmp/krb5cc_rust_rekey user"
RUSTCPW="$(docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" /tmp/krb5-kadmin-local -q 'cpw -randkey -keepold -e aes128-cts-hmac-sha1-96:normal krbtgt/KERBER.TEST')"
echo "$RUSTCPW"
echo "$RUSTCPW" | grep -qi 'randomized' || die "rust cpw -keepold krbtgt failed"
docker exec "$NAME" sh -c 'for p in /proc/[0-9]*; do comm=$(cat "$p/comm" 2>/dev/null) || continue; [ "$comm" = krb5-kdc ] || continue; cmd=$(tr "\0" " " < "$p/cmdline" 2>/dev/null) || continue; echo "$cmd" | grep -q "/tmp/krb5-kdc" || continue; kill -9 "${p#/proc/}" 2>/dev/null || true; done'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',8888),0.15)" 2>/dev/null; then
        sleep 0.2
        continue
    fi
    ok=1
    break
done
[ "$ok" = 1 ] || die "rust kdc still listening after rekey kill"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc-rekey.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc-rekey.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/rust-kdc-rekey.log >&2 || true
    die "rust kdc did not listen after rekey"
}
set +e
RUSTREN="$(docker exec -e KRB5_CONFIG=/tmp/rust-client.conf "$NAME" /tmp/krb5-kvno --renew-ticket --body-realm KERBER.TEST \
    -c /tmp/krb5cc_rust_rekey 127.0.0.1:8888 host/testhost.kerber.test@KERBER.TEST 2>&1)"
rustren_rc=$?
set -e
echo "$RUSTREN"
echo "RUST_krbtgt_rekey_renew rc=${rustren_rc}"
[ "$rustren_rc" = 0 ] || {
    docker exec "$NAME" cat /tmp/rust-kdc-rekey.log >&2 || true
    die "rust RENEW after krbtgt rekey failed"
}
echo "$RUSTREN" | grep -q 'kvno =' || die "rust RENEW after rekey missing kvno"

log "differential.gate" "ok" ',"same_db":true,"transport":"tcp"'
exit 0
