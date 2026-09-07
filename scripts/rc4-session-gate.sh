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

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb \
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
docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmin-local "$NAME":/tmp/krb5-kadmin-local
docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker cp target/debug/krb5-kvno "$NAME":/tmp/krb5-kvno
docker cp target/debug/krb5-klist "$NAME":/tmp/krb5-klist
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmin-local /tmp/krb5-kinit /tmp/krb5-kvno /tmp/krb5-klist

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

log "rc4.session" "ok" ',"mit_vs_rust":"kinit+kvno","rust_vs_mit":"kinit+kvno","skey":"arcfour-hmac","kvno_rc":0,"kdcdefaults_allow_rc4":"ignored"'
echo "rc4-session-gate both directions ok"
