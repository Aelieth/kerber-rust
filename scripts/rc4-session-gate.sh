#!/usr/bin/env bash
# MIT kinit+kvno against Rust KDC and Rust krb5-kinit+krb5-kvno against MIT,
# with session_enctypes=rc4-hmac on krbtgt and host/testhost.kerber.test.
# Isolation: in-container; never touches host /etc/krb5.conf.
# tkt etype is recorded here; scripts/cross-kdc-gate.sh asserts it on one dump
# (this Rust store is minted with the default key order, supported_enctypes unread).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-rc4-session-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-rc4-session-gate}"
OUT="$SCRATCH/rc4-session-gate"
mkdir -p "$OUT"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"rc4-session-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "rc4.session" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    docker exec "$NAME" cat /tmp/rust-kdc.log 2>/dev/null | tail -80 >&2 || true
    docker exec "$NAME" cat /tmp/mit-kinit-rustkdc.trace 2>/dev/null | tail -80 >&2 || true
    exit 1
}

kill_comm() {
    local comm_name=$1
    docker exec "$NAME" sh -c '
name="$1"
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r n < "$comm" || continue
    if [ "$n" = "$name" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
' sh "$comm_name"
}

wait_port() {
    local port=$1 n=${2:-40}
    local i
    for i in $(seq 1 "$n"); do
        if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$port),0.3)" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

wait_port_free() {
    local port=$1 n=${2:-40}
    local i
    for i in $(seq 1 "$n"); do
        if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$port),0.2)" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

tkt_etype_of() {
    printf '%s\n' "$1" | awk '/krbtgt\//{getline; sub(/.*tkt\):[ \t]*/, ""); print; exit}'
}

skey_of_host() {
    printf '%s\n' "$1" | awk '/host\/testhost/{getline; print; exit}'
}

if ! command -v docker >/dev/null 2>&1; then
    log "rc4.session" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb --bin krb5-forge-tgt --bin krb5-pac-extract \
    -p krb5-admin --bin krb5-kadmin-local \
    -p krb5-client --bin krb5-kinit --bin krb5-kvno --bin krb5-klist -q

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

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
    sleep 1
done
[ "$ok" = 1 ] || die "harness did not become ready"

echo "==== patch kdc.conf + krb5.conf (allow_rc4, arcfour permitted, rc4 keysalt) ===="
docker exec -i "$NAME" python3 - <<'PY'
from pathlib import Path

kdc = Path("/etc/krb5kdc/kdc.conf")
t = kdc.read_text()
if "allow_rc4" not in t:
    t = t.replace("[kdcdefaults]", "[kdcdefaults]\n    allow_weak_crypto = true\n    allow_rc4 = true")
if "rc4-hmac:normal" not in t:
    t = t.replace(
        "aes128-cts-hmac-sha1-96:normal",
        "aes128-cts-hmac-sha1-96:normal rc4-hmac:normal",
    )
kdc.write_text(t)

conf = Path("/etc/krb5.conf")
c = conf.read_text()
if "allow_rc4" not in c:
    c = c.replace(
        "[libdefaults]",
        "[libdefaults]\n    allow_rc4 = true\n    allow_weak_crypto = true",
    )
for key in ("permitted_enctypes", "default_tgs_enctypes", "default_tkt_enctypes"):
    if key in c and "arcfour-hmac" not in c.split(key, 1)[1].split("\n", 1)[0]:
        c = c.replace(
            f"{key} = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96",
            f"{key} = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 arcfour-hmac",
            1,
        )
conf.write_text(c)
Path("/tmp/krb5-8888.conf").write_text(
    c.replace("kdc = 127.0.0.1\n", "kdc = 127.0.0.1:8888\n")
)
print("kdc.conf allow_rc4", "allow_rc4" in kdc.read_text())
print("krb5.conf allow_rc4", "allow_rc4" in conf.read_text())
PY
docker exec "$NAME" grep -q allow_rc4 /etc/krb5.conf || die "krb5.conf missing allow_rc4"
docker exec "$NAME" grep -q allow_rc4 /etc/krb5kdc/kdc.conf || die "kdc.conf missing allow_rc4"
docker exec "$NAME" grep -q arcfour-hmac /etc/krb5.conf || die "krb5.conf missing arcfour-hmac"

echo "==== MIT kadmin.local rc4user + session_enctypes ===="
docker exec "$NAME" kadmin.local -q 'addprinc -e rc4-hmac:normal -pw rc4-secret rc4user'
docker exec "$NAME" kadmin.local -q 'setstr krbtgt/KERBER.TEST session_enctypes rc4-hmac'
docker exec "$NAME" kadmin.local -q 'setstr host/testhost.kerber.test session_enctypes rc4-hmac'
docker exec "$NAME" kadmin.local -q 'getprinc rc4user' | tee "$OUT/mit-getprinc-rc4user.txt"

echo "==== restart MIT krb5kdc via /proc/*/comm ===="
kill_comm krb5kdc
wait_port_free 88 || die "MIT krb5kdc still bound :88 after kill"
docker exec -d \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc >/tmp/mit-kdc.log 2>&1'
wait_port 88 || die "MIT krb5kdc did not listen after restart"

echo "==== control: MIT kinit against MIT KDC ===="
set +e
MIT_SELF="$(docker exec \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'printf "%s\n" rc4-secret | kinit -c /tmp/mit-self.cc rc4user@KERBER.TEST' 2>&1)"
MIT_SELF_RC=$?
set -e
echo "mit-kinit-vs-mit rc=$MIT_SELF_RC"
echo "$MIT_SELF"
[ "$MIT_SELF_RC" = 0 ] || die "MIT kinit against MIT KDC failed (control)"
MIT_SELF_KLIST="$(docker exec -e KRB5_CONFIG=/etc/krb5.conf "$NAME" klist -e -c /tmp/mit-self.cc 2>&1)"
echo "$MIT_SELF_KLIST"
echo "tkt_etype_mit_vs_mit=$(tkt_etype_of "$MIT_SELF_KLIST")"

echo "==== start Rust KDC :8888 ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kvno" "$NAME":/tmp/krb5-kvno
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-klist" "$NAME":/tmp/krb5-klist
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-forge-tgt" "$NAME":/tmp/krb5-forge-tgt
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-pac-extract" "$NAME":/tmp/krb5-pac-extract
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmin-local /tmp/krb5-kinit /tmp/krb5-kvno /tmp/krb5-klist /tmp/krb5-forge-tgt /tmp/krb5-pac-extract

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
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

echo "==== Rust kadmin.local rc4user + session_enctypes ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    -e KRB5_PASSWORD=rc4-secret \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -e rc4-hmac:normal -pw rc4-secret rc4user'
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'setstr krbtgt/KERBER.TEST session_enctypes rc4-hmac'
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'setstr host/testhost.kerber.test session_enctypes rc4-hmac'

echo "==== A) MIT kinit+kvno against Rust KDC :8888 ===="
set +e
MIT_KINIT="$(docker exec \
    -e KRB5_CONFIG=/tmp/krb5-8888.conf \
    -e KRB5_TRACE=/tmp/mit-kinit-rustkdc.trace \
    "$NAME" sh -c 'printf "%s\n" rc4-secret | kinit -c /tmp/mit-vs-rust.cc rc4user@KERBER.TEST' 2>&1)"
MIT_KINIT_RC=$?
set -e
echo "$MIT_KINIT"
[ "$MIT_KINIT_RC" = 0 ] || die "MIT kinit against rust KDC failed rc=$MIT_KINIT_RC"
MIT_KLIST="$(docker exec -e KRB5_CONFIG=/tmp/krb5-8888.conf "$NAME" klist -e -c /tmp/mit-vs-rust.cc 2>&1)"
echo "$MIT_KLIST"
echo "$MIT_KLIST" | grep -q 'arcfour-hmac' || die "MIT klist against rust: no arcfour skey"
echo "tkt_etype_mit_vs_rust=$(tkt_etype_of "$MIT_KLIST")"
set +e
MIT_KVNO="$(docker exec \
    -e KRB5_CONFIG=/tmp/krb5-8888.conf \
    -e KRB5_TRACE=/tmp/mit-kvno-rustkdc.trace \
    "$NAME" kvno -c /tmp/mit-vs-rust.cc host/testhost.kerber.test 2>&1)"
MIT_KVNO_RC=$?
set -e
echo "$MIT_KVNO"
[ "$MIT_KVNO_RC" = 0 ] || die "MIT kvno against rust KDC failed rc=$MIT_KVNO_RC"
MIT_KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/krb5-8888.conf "$NAME" klist -e -c /tmp/mit-vs-rust.cc 2>&1)"
echo "$MIT_KLIST2"
echo "$MIT_KLIST2" | grep -q 'host/testhost.kerber.test' || die "MIT kvno did not store host ticket"
echo "$MIT_KLIST2" | grep -A1 'host/testhost' | grep -q 'arcfour-hmac' || die "MIT host skey is not arcfour"
echo "host_skey_mit_vs_rust=$(skey_of_host "$MIT_KLIST2")"

docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true
KU9="$(grep '"key_usage":9' "$OUT/rust-kdc.log" || true)"
echo "$KU9"
echo "$KU9" | grep -q '"key_usage":9' || die "rust TGS-REP log missing key_usage 9"

echo "==== B) Rust krb5-kinit+krb5-kvno against MIT KDC :88 ===="
set +e
RUST_KINIT="$(docker exec \
    -e KRB5_CONFIG=/etc/krb5.conf \
    -e KRB5_PASSWORD=rc4-secret \
    "$NAME" /tmp/krb5-kinit -c /tmp/rust-vs-mit.cc 127.0.0.1:88 rc4user@KERBER.TEST 2>&1)"
RUST_KINIT_RC=$?
set -e
echo "$RUST_KINIT"
[ "$RUST_KINIT_RC" = 0 ] || die "Rust kinit against MIT KDC failed rc=$RUST_KINIT_RC"
RUST_KLIST="$(docker exec -e KRB5_CONFIG=/etc/krb5.conf "$NAME" /tmp/krb5-klist -e -c /tmp/rust-vs-mit.cc 2>&1)"
echo "$RUST_KLIST"
echo "$RUST_KLIST" | grep -q 'arcfour-hmac' || die "Rust klist against MIT: no arcfour skey"
echo "tkt_etype_rust_vs_mit=$(tkt_etype_of "$RUST_KLIST")"
set +e
RUST_KVNO="$(docker exec \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kvno -c /tmp/rust-vs-mit.cc 127.0.0.1:88 host/testhost.kerber.test 2>&1)"
RUST_KVNO_RC=$?
set -e
echo "$RUST_KVNO"
[ "$RUST_KVNO_RC" = 0 ] || die "Rust kvno against MIT KDC failed rc=$RUST_KVNO_RC"
RUST_KLIST2="$(docker exec -e KRB5_CONFIG=/etc/krb5.conf "$NAME" /tmp/krb5-klist -e -c /tmp/rust-vs-mit.cc 2>&1)"
echo "$RUST_KLIST2"
echo "$RUST_KLIST2" | grep -q 'host/testhost.kerber.test' || die "Rust kvno did not store host ticket"
echo "$RUST_KLIST2" | grep -A1 'host/testhost' | grep -q 'arcfour-hmac' || die "Rust host skey is not arcfour"
echo "host_skey_rust_vs_mit=$(skey_of_host "$RUST_KLIST2")"

echo "==== C) DEPRECATED: display parity on the klist -e session etype line ===="
# MIT klist.c etype_string prepends DEPRECATED: for arcfour-hmac; the Rust
# krb5-klist must do the same, so both legs print the identical skey token.
et_line() { printf '%s\n' "$1" | grep -F 'Etype (skey, tkt):' | head -1 | sed 's/^[[:space:]]*//'; }
MIT_ETLINE="$(et_line "$MIT_KLIST")"
RUST_ETLINE="$(et_line "$RUST_KLIST")"
echo "mit_vs_rust:  $MIT_ETLINE"
echo "rust_vs_mit:  $RUST_ETLINE"
echo "$MIT_ETLINE" | grep -q 'Etype (skey, tkt): DEPRECATED:arcfour-hmac,' ||
    die "MIT klist session etype is not DEPRECATED:arcfour-hmac"
echo "$RUST_ETLINE" | grep -q 'Etype (skey, tkt): DEPRECATED:arcfour-hmac,' ||
    die "Rust klist session etype is not DEPRECATED:arcfour-hmac"

docker exec "$NAME" cat /tmp/mit-kinit-rustkdc.trace 2>/dev/null | tee "$OUT/mit-kinit-rustkdc.trace" | grep -E 'usage|arcfour|enctype' | head -40 || true
docker cp "$NAME":/tmp/mit-kdc.log "$OUT/mit-kdc.log" 2>/dev/null || true

echo "==== D) allow_rc4 under [kdcdefaults] alone is ignored: both KDCs refuse the rc4-only client ===="
# MIT reads allow_rc4 / allow_weak_crypto from [libdefaults] only (init_ctx.c
# get_boolean); the copy this gate put under kdc.conf [kdcdefaults] must not
# enable rc4 on its own. The clients keep offering rc4 through their own
# config so the refusal is the KDC's decision.
docker exec -i "$NAME" python3 - <<'PY'
from pathlib import Path
c = Path("/etc/krb5.conf").read_text()
c = c.replace("    allow_rc4 = true\n", "").replace("    allow_weak_crypto = true\n", "")
Path("/etc/krb5.conf").write_text(c)
rc = c.replace("[libdefaults]", "[libdefaults]\n    allow_rc4 = true\n    allow_weak_crypto = true", 1)
Path("/tmp/krb5-88-rc4.conf").write_text(rc)
Path("/tmp/krb5-8888-rc4.conf").write_text(rc.replace("kdc = 127.0.0.1\n", "kdc = 127.0.0.1:8888\n"))
PY
docker exec "$NAME" grep -q allow_rc4 /etc/krb5kdc/kdc.conf || die "kdc.conf lost allow_rc4"
if docker exec "$NAME" grep -q allow_rc4 /etc/krb5.conf; then
    die "krb5.conf still carries allow_rc4"
fi
kill_comm krb5kdc
wait_port_free 88 || die "MIT krb5kdc still bound :88 after kill (D)"
docker exec -d \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c 'krb5kdc >/tmp/mit-kdc-d.log 2>&1'
wait_port 88 || die "MIT krb5kdc did not listen (D)"
# The Rust KDC's UDP loop leaves the shutdown flag unread until its read
# timeout, so a plain kill can keep :8888 bound; kill -9 like policy-gate, and
# relaunch on the persisted DB without --test-realm like restart-gate.
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r n < "$comm" || continue
    if [ "$n" = krb5-kdc ]; then
        pid=${comm#/proc/}
        kill -9 "${pid%/comm}" 2>/dev/null || true
    fi
done
'
sleep 0.5
wait_port_free 8888 || die "rust kdc still bound :8888 after kill (D)"
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc-d.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc-d.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/rust-kdc-d.log >&2 || true
    die "rust kdc did not listen on 8888 (D)"
}
MIT_D="$(docker exec -e KRB5_CONFIG=/tmp/krb5-88-rc4.conf \
    "$NAME" sh -c 'printf "%s\n" rc4-secret | kinit -c /tmp/d-mit.cc rc4user@KERBER.TEST' 2>&1 || true)"
RUST_D="$(docker exec -e KRB5_CONFIG=/tmp/krb5-8888-rc4.conf \
    "$NAME" sh -c 'printf "%s\n" rc4-secret | kinit -c /tmp/d-rust.cc rc4user@KERBER.TEST' 2>&1 || true)"
echo "mit:  $MIT_D"
echo "rust: $RUST_D"
echo "$MIT_D" | grep -F 'kinit: KDC has no support for encryption type while getting initial credentials' ||
    die "MIT KDC honoured [kdcdefaults] allow_rc4 (the premise is wrong): $MIT_D"
[ "$MIT_D" = "$RUST_D" ] || die "rc4-only client with allow_rc4 only under [kdcdefaults]: MIT and Rust replies differ"

echo "==== E) permitted_enctypes on the KDC steers the service key (krb5_dbe_find_enctype) ===="
# Z1.4. MIT seals a service ticket with `get_first_current_key(server)` =
# `krb5_dbe_find_enctype(server, -1, -1, 0)` (kdb_default.c:47-94): the first
# key of the top kvno *whose enctype is permitted*, and NO_PERMITTED_KEY → 60
# FINDING_SERVER_KEY when none is. Two service principals keyed by kadmin.local
# on each leg, in the same keysalt order: z14mixed = [aes128, aes256] (aes128
# stored first), z14only = [aes128]. Control under the D config (aes128
# permitted): both KDCs seal z14mixed with the first-stored aes128. Then both
# KDCs restart with `[libdefaults] permitted_enctypes = aes256-cts-hmac-sha1-96`
# (the KDC's own krb5.conf; the clients keep theirs) and both seal z14mixed with
# aes256 and refuse z14only with the same kvno error line.
# A) left krbtgt with `session_enctypes rc4-hmac` and D) took rc4 away from
# both KDCs, so a plain `kinit user` would be 14 on both legs for a reason
# unrelated to this cell; point the TGT session etype at aes256 on both.
docker exec "$NAME" kadmin.local -q 'setstr krbtgt/KERBER.TEST session_enctypes aes256-cts-hmac-sha1-96'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey -e aes128-cts-hmac-sha1-96:normal,aes256-cts-hmac-sha1-96:normal z14mixed'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey -e aes128-cts-hmac-sha1-96:normal z14only'
docker exec "$NAME" kadmin.local -q 'getprinc z14mixed' | tee "$OUT/mit-getprinc-z14mixed.txt" | grep -E '^Key: vno'
for p in 'setstr krbtgt/KERBER.TEST session_enctypes aes256-cts-hmac-sha1-96' \
         'addprinc -randkey -e aes128-cts-hmac-sha1-96:normal,aes256-cts-hmac-sha1-96:normal z14mixed' \
         'addprinc -randkey -e aes128-cts-hmac-sha1-96:normal z14only'; do
    docker exec \
        -e KRB5_KDC_DB=/tmp/rust.db \
        -e KRB5_KDC_STASH=/tmp/rust.stash \
        -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
        -e KRB5_CONFIG=/etc/krb5.conf \
        "$NAME" /tmp/krb5-kadmin-local -q "$p"
done
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc z14mixed' | tee "$OUT/rust-getprinc-z14mixed.txt" | grep -E '^Key: vno'

# tkt etype of one service in `klist -e` output: the line after the service's
# entry is "Etype (skey, tkt): <skey>, <tkt>".
tkt_etype_for() {
    printf '%s\n' "$2" | awk -v svc="$1" 'index($0, svc){getline; sub(/.*tkt\):[ \t]*/, ""); sub(/^[^,]*,[ \t]*/, ""); sub(/[ \t]+$/, ""); print; exit}'
}
# kvno <svc> with a fresh user TGT against the KDC of <conf>; prints the klist
# -e tkt etype for <svc> on success, else the kvno error line.
e_kvno() {
    local conf=$1 svc=$2 cc=$3 out ki
    if ! ki="$(docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c "printf '%s\n' userpassword | kinit -c $cc user@KERBER.TEST" 2>&1)"; then
        die "E) kinit user against $conf failed: $ki"
    fi
    set +e
    out="$(docker exec -e KRB5_CONFIG="$conf" "$NAME" kvno -c "$cc" "$svc" 2>&1)"
    local rc=$?
    set -e
    if [ "$rc" = 0 ]; then
        tkt_etype_for "$svc" "$(docker exec -e KRB5_CONFIG="$conf" "$NAME" klist -e -c "$cc" 2>&1)"
    else
        printf '%s\n' "$out" | grep -F 'kvno:' | head -1
    fi
}

E_CTL_MIT="$(e_kvno /etc/krb5.conf z14mixed /tmp/e-ctl-mit.cc)"
E_CTL_RUST="$(e_kvno /tmp/krb5-8888.conf z14mixed /tmp/e-ctl-rust.cc)"
echo "control (aes128 permitted) z14mixed tkt: mit=$E_CTL_MIT rust=$E_CTL_RUST"
[ "$E_CTL_MIT" = "aes128-cts-hmac-sha1-96" ] || die "E control: MIT did not seal z14mixed with the first-stored aes128 key: $E_CTL_MIT"
[ "$E_CTL_RUST" = "aes128-cts-hmac-sha1-96" ] || die "E control: Rust did not seal z14mixed with the first-stored aes128 key: $E_CTL_RUST"

docker exec -i "$NAME" python3 - <<'PY'
from pathlib import Path
import re
c = Path("/etc/krb5.conf").read_text()
c2, n = re.subn(r"(?m)^(\s*)permitted_enctypes\s*=.*$", r"\1permitted_enctypes = aes256-cts-hmac-sha1-96", c)
if n == 0:
    c2 = c.replace("[libdefaults]", "[libdefaults]\n    permitted_enctypes = aes256-cts-hmac-sha1-96", 1)
Path("/tmp/krb5-e-kdc.conf").write_text(c2)
print("kdc krb5.conf permitted_enctypes lines:", n or 1)
PY
docker exec "$NAME" grep -E '^\s*permitted_enctypes = aes256-cts-hmac-sha1-96$' /tmp/krb5-e-kdc.conf >/dev/null ||
    die "E) /tmp/krb5-e-kdc.conf lacks the aes256-only permitted_enctypes"
kill_comm krb5kdc
wait_port_free 88 || die "MIT krb5kdc still bound :88 after kill (E)"
docker exec -d \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/tmp/krb5-e-kdc.conf \
    "$NAME" sh -c 'krb5kdc >/tmp/mit-kdc-e.log 2>&1'
wait_port 88 || die "MIT krb5kdc did not listen (E)"
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r n < "$comm" || continue
    if [ "$n" = krb5-kdc ]; then
        pid=${comm#/proc/}
        kill -9 "${pid%/comm}" 2>/dev/null || true
    fi
done
'
sleep 0.5
wait_port_free 8888 || die "rust kdc still bound :8888 after kill (E)"
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/tmp/krb5-e-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc-e.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc-e.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || {
    docker exec "$NAME" cat /tmp/rust-kdc-e.log >&2 || true
    die "rust kdc did not listen on 8888 (E)"
}

E_MIX_MIT="$(e_kvno /etc/krb5.conf z14mixed /tmp/e-mix-mit.cc)"
E_MIX_RUST="$(e_kvno /tmp/krb5-8888.conf z14mixed /tmp/e-mix-rust.cc)"
echo "permitted=aes256 z14mixed tkt: mit=$E_MIX_MIT rust=$E_MIX_RUST"
[ "$E_MIX_MIT" = "aes256-cts-hmac-sha1-96" ] || die "E) MIT did not skip the non-permitted first key: $E_MIX_MIT"
[ "$E_MIX_RUST" = "$E_MIX_MIT" ] || die "E) Rust z14mixed tkt etype differs from MIT: rust=$E_MIX_RUST mit=$E_MIX_MIT"

E_ONLY_MIT="$(e_kvno /etc/krb5.conf z14only /tmp/e-only-mit.cc)"
E_ONLY_RUST="$(e_kvno /tmp/krb5-8888.conf z14only /tmp/e-only-rust.cc)"
echo "permitted=aes256 z14only: mit=$E_ONLY_MIT"
echo "permitted=aes256 z14only: rust=$E_ONLY_RUST"
echo "$E_ONLY_MIT" | grep -F 'kvno: KDC returned error string: FINDING_SERVER_KEY while getting credentials for z14only@KERBER.TEST' >/dev/null ||
    die "E) MIT did not refuse z14only with FINDING_SERVER_KEY: $E_ONLY_MIT"
[ "$E_ONLY_RUST" = "$E_ONLY_MIT" ] || die "E) Rust z14only refusal differs from MIT"
echo "==== F) a stale keytab is Password incorrect (24): enc-ts keys are searched at the top kvno only ===="
# Z1.4, the other `krb5_dbe_*search_enctype` caller: enc_ts_verify
# (kdc_preauth_encts.c:74-92) walks the client's keys of the timestamp's etype
# at the highest kvno only (kvno 0 in kdb_default.c:65-67). `ktadd` writes the
# kvno-2 keys, `cpw -randkey -keepold` moves the entry to kvno 3 while keeping
# kvno 2 in the DB; MIT still refuses the kvno-2 timestamp with 24, which
# `kinit -kt` reports as "Password incorrect" (the wrong-password text).
# Control first: the fresh keytab kinits on both legs.
docker exec "$NAME" kadmin.local -q 'addprinc -randkey z14kt'
docker exec "$NAME" kadmin.local -q 'ktadd -k /tmp/z14kt-mit.kt z14kt'
for p in 'addprinc -randkey z14kt' 'ktadd -k /tmp/z14kt-rust.kt z14kt'; do
    docker exec \
        -e KRB5_KDC_DB=/tmp/rust.db \
        -e KRB5_KDC_STASH=/tmp/rust.stash \
        -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
        -e KRB5_CONFIG=/etc/krb5.conf \
        "$NAME" /tmp/krb5-kadmin-local -q "$p"
done
f_kinit() {
    local conf=$1 kt=$2 cc=$3
    docker exec -e KRB5_CONFIG="$conf" "$NAME" kinit -k -t "$kt" -c "$cc" z14kt@KERBER.TEST 2>&1 && echo "kinit ok"
}
F_CTL_MIT="$(f_kinit /etc/krb5.conf /tmp/z14kt-mit.kt /tmp/f-ctl-mit.cc || true)"
F_CTL_RUST="$(f_kinit /tmp/krb5-8888.conf /tmp/z14kt-rust.kt /tmp/f-ctl-rust.cc || true)"
echo "control fresh keytab: mit=$F_CTL_MIT rust=$F_CTL_RUST"
[ "$F_CTL_MIT" = "kinit ok" ] || die "F control: MIT kinit -kt with the fresh keytab failed: $F_CTL_MIT"
[ "$F_CTL_RUST" = "kinit ok" ] || die "F control: Rust kinit -kt with the fresh keytab failed: $F_CTL_RUST"
docker exec "$NAME" kadmin.local -q 'cpw -randkey -keepold z14kt'
docker exec "$NAME" kadmin.local -q 'getprinc z14kt' | grep -E '^Key: vno' | tee "$OUT/mit-getprinc-z14kt.txt"
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'cpw -randkey -keepold z14kt'
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc z14kt' | grep -E '^Key: vno' | tee "$OUT/rust-getprinc-z14kt.txt"
grep -q 'Key: vno 2,' "$OUT/mit-getprinc-z14kt.txt" || die "F) MIT did not keep the kvno-2 keys"
grep -q 'Key: vno 2,' "$OUT/rust-getprinc-z14kt.txt" || die "F) Rust did not keep the kvno-2 keys"
F_MIT="$(f_kinit /etc/krb5.conf /tmp/z14kt-mit.kt /tmp/f-mit.cc || true)"
F_RUST="$(f_kinit /tmp/krb5-8888.conf /tmp/z14kt-rust.kt /tmp/f-rust.cc || true)"
echo "stale keytab (kvno 2 kept, kvno 3 current): mit=$F_MIT"
echo "stale keytab (kvno 2 kept, kvno 3 current): rust=$F_RUST"
[ "$F_MIT" = "kinit: Password incorrect while getting initial credentials" ] ||
    die "F) MIT did not refuse the stale keytab with Password incorrect (24): $F_MIT"
[ "$F_RUST" = "$F_MIT" ] || die "F) Rust stale-keytab kinit differs from MIT"
docker cp "$NAME":/tmp/mit-kdc-e.log "$OUT/mit-kdc-e.log" 2>/dev/null || true
docker cp "$NAME":/tmp/rust-kdc-e.log "$OUT/rust-kdc-e.log" 2>/dev/null || true

echo "==== G) FAST armor TGT under a non-permitted etype (krb5_dbe_find_enctype) ===="
# Z6.1. MIT `armor_ap_request` (`fast_util.c:52-54`) calls `krb5_rd_req` with
# the KDB keytab; `krb5_ktkdb_get_entry` (`keytab.c:157`) is
# `krb5_dbe_find_enctype(entry, xrealm ? etype : -1, -1, kvno)` and then a
# similar-enctype check (`:171-178`). Both KDCs still have
# `permitted_enctypes = aes256-cts-hmac-sha1-96` from cell E. Give krbtgt a
# current kvno that also holds aes128, mint a real TGT (aes256), reseal it
# under the leftover aes128 key with `krb5-forge-tgt`, and drive MIT
# `kinit -T` against both KDCs. The walk that accepted any key would issue;
# MIT's pick is `KRB5_KDB_NO_PERMITTED_KEY` → wire 60 `FIND_FAST`.
docker exec "$NAME" kadmin.local -q \
    'cpw -randkey -keepold -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal krbtgt/KERBER.TEST'
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kadmin-local -q \
    'cpw -randkey -keepold -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal krbtgt/KERBER.TEST'
docker exec "$NAME" kadmin.local -q 'getprinc krbtgt/KERBER.TEST' \
    | grep -E '^Key: vno' | tee "$OUT/mit-getprinc-z61-krbtgt.txt"
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc krbtgt/KERBER.TEST' \
    | grep -E '^Key: vno' | tee "$OUT/rust-getprinc-z61-krbtgt.txt"
grep -q 'aes128-cts-hmac-sha1-96' "$OUT/mit-getprinc-z61-krbtgt.txt" \
    || die "G) MIT krbtgt has no aes128 key after cpw"
grep -q 'aes128-cts-hmac-sha1-96' "$OUT/rust-getprinc-z61-krbtgt.txt" \
    || die "G) Rust krbtgt has no aes128 key after cpw"
docker exec "$NAME" kadmin.local -q 'ktadd -norandkey -k /tmp/g-mit-krbtgt.kt krbtgt/KERBER.TEST' \
    || die "G) MIT ktadd -norandkey krbtgt failed"
docker exec \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    -e KRB5_CONFIG=/etc/krb5.conf \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -norandkey -k /tmp/g-rust-krbtgt.kt krbtgt/KERBER.TEST' \
    || die "G) Rust ktadd -norandkey krbtgt failed"
G_MIT_AES128="$(docker exec "$NAME" /tmp/krb5-pac-extract --dump-keytab /tmp/g-mit-krbtgt.kt \
    | awk '$1=="KEY" && $2=="17" {hex=$3; kv=$NF} END {print hex}')"
G_RUST_AES128="$(docker exec "$NAME" /tmp/krb5-pac-extract --dump-keytab /tmp/g-rust-krbtgt.kt \
    | awk '$1=="KEY" && $2=="17" {hex=$3; kv=$NF} END {print hex}')"
[ "${#G_MIT_AES128}" -eq 32 ] || die "G) MIT krbtgt has no 16-byte aes128 key: '$G_MIT_AES128'"
[ "${#G_RUST_AES128}" -eq 32 ] || die "G) Rust krbtgt has no 16-byte aes128 key: '$G_RUST_AES128'"
g_kinit_src() {
    local conf=$1 cc=$2
    docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c "printf '%s\n' userpassword | kinit -c $cc user@KERBER.TEST" 2>&1
}
g_kinit_src /etc/krb5.conf /tmp/g-mit-src.cc >/dev/null \
    || die "G) MIT kinit source TGT failed"
g_kinit_src /tmp/krb5-8888.conf /tmp/g-rust-src.cc >/dev/null \
    || die "G) Rust kinit source TGT failed"
docker exec "$NAME" /tmp/krb5-forge-tgt \
    --ccache /tmp/g-mit-src.cc --out /tmp/g-mit-armor.cc \
    --tgt krbtgt/KERBER.TEST --claim-realm KERBER.TEST \
    --decrypt-keytab /tmp/g-mit-krbtgt.kt --reseal-key-hex "$G_MIT_AES128" \
    || die "G) forge MIT aes128 armor TGT failed"
docker exec "$NAME" /tmp/krb5-forge-tgt \
    --ccache /tmp/g-rust-src.cc --out /tmp/g-rust-armor.cc \
    --tgt krbtgt/KERBER.TEST --claim-realm KERBER.TEST \
    --decrypt-keytab /tmp/g-rust-krbtgt.kt --reseal-key-hex "$G_RUST_AES128" \
    || die "G) forge Rust aes128 armor TGT failed"
g_kinit_t() {
    local conf=$1 armor=$2 cc=$3 out rc
    set +e
    out="$(docker exec -e KRB5_CONFIG="$conf" "$NAME" \
        sh -c "printf '%s\n' userpassword | kinit -T $armor -c $cc user@KERBER.TEST" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    return "$rc"
}
G_MIT="$(g_kinit_t /etc/krb5.conf /tmp/g-mit-armor.cc /tmp/g-mit-out.cc)" && die "G) MIT kinit -T accepted the aes128 armor TGT"
G_RUST="$(g_kinit_t /tmp/krb5-8888.conf /tmp/g-rust-armor.cc /tmp/g-rust-out.cc)" && die "G) Rust kinit -T accepted the aes128 armor TGT"
echo "G MIT kinit -T aes128-armor: $G_MIT"
echo "G Rust kinit -T aes128-armor: $G_RUST"
[ "$G_MIT" = "kinit: Generic error (see e-text) while getting initial credentials" ] \
    || die "G) MIT kinit -T is not Generic error (60): $G_MIT"
[ "$G_RUST" = "$G_MIT" ] || die "G) Rust FAST-armor refusal differs from MIT: rust=$G_RUST mit=$G_MIT"
printf '%s\n' "$G_MIT" | tee "$OUT/g-mit-kinit-t.txt" >/dev/null
printf '%s\n' "$G_RUST" | tee "$OUT/g-rust-kinit-t.txt" >/dev/null
# MIT kinit prints Generic error (60) and does not echo e_text. Units pin
# FIND_FAST; the live bar is the identical client string on both legs.
# Control: the unforged aes256 TGT still armors.
G_CTL_MIT="$(g_kinit_t /etc/krb5.conf /tmp/g-mit-src.cc /tmp/g-mit-ctl.cc)" \
    || die "G control: MIT kinit -T with the genuine TGT failed: $G_CTL_MIT"
G_CTL_RUST="$(g_kinit_t /tmp/krb5-8888.conf /tmp/g-rust-src.cc /tmp/g-rust-ctl.cc)" \
    || die "G control: Rust kinit -T with the genuine TGT failed: $G_CTL_RUST"
echo "G control MIT kinit -T aes256-armor: $G_CTL_MIT"
echo "G control Rust kinit -T aes256-armor: $G_CTL_RUST"

log "rc4.session" "ok" ',"mit_vs_rust":"kinit+kvno","rust_vs_mit":"kinit+kvno","skey":"arcfour-hmac","kvno_rc":0,"kdcdefaults_allow_rc4":"ignored","permitted_enctypes_key_lookup":"aes256 both, FINDING_SERVER_KEY both","stale_keytab":"Password incorrect (24) both","fast_armor_nonpermitted_etype":"FIND_FAST both"'
echo "rc4-session-gate both directions ok"
