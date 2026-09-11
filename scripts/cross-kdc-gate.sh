#!/usr/bin/env bash
# One identical dump, MIT krb5kdc on :88 and the Rust KDC on :8888: a TGT
# issued by either KDC must be accepted by the other's TGS. Isolation:
# in-container; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-cross-kdc-gate"
GOLDEN="tests/traces/kdb/mit-dump-v7.txt"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-cross-kdc-gate}"
OUT="$SCRATCH/cross-kdc-gate"
mkdir -p "$OUT"
CC=/tmp/cross-kdc.cc

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"cross-kdc-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

die() {
    log "cross.kdc.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

unavailable() {
    log "cross.kdc.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/cross-kdc-unavailable.log"
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
if [ ! -f "$GOLDEN" ]; then
    die "missing golden dump $GOLDEN"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb --bin krb5-pac-extract -q

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
docker cp "$GOLDEN" "$NAME":/tmp/mit.dump
docker cp harness/client-krb5.conf "$NAME":/tmp/mit-krb5.conf
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb
docker exec "$NAME" sh -c "sed 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:8888/' /tmp/mit-krb5.conf > /tmp/rust-krb5.conf && sed -i 's/kdc = 127.0.0.1\$/kdc = 127.0.0.1:88/' /tmp/mit-krb5.conf"

echo "==== load identical dump into Rust KDC on :8888 ===="
LOAD="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/mit.dump)"
echo "$LOAD"
echo "$LOAD" | grep -q 'ok load version=7' || die "rust kdb load failed"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "rust kdc did not listen on 8888"

echo "==== load identical dump into MIT krb5kdc on :88 ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kdb5_util load /tmp/mit.dump
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
echo "$STARTLOG" | grep -q 'setting up network' || die "MIT krb5kdc did not start"

kinit_via() {
    docker exec -e KRB5CCNAME="$CC" "$NAME" kdestroy -A >/dev/null 2>&1 || true
    docker exec -e KRB5_CONFIG="/tmp/$1-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' ||
        die "kinit via $1 KDC failed"
}

tgt_etype_via() {
    local listing
    listing="$(docker exec -e KRB5CCNAME="$CC" "$NAME" klist -e 2>&1 || true)"
    echo "$listing" | grep -A1 'krbtgt/KERBER.TEST' | sed -n 's/.*tkt): *[^,]*, *//p' | tr -d ' '
}

kvno_via() {
    docker exec -e KRB5_CONFIG="/tmp/$1-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" \
        kvno host/testhost.kerber.test 2>&1 || true
}

kdc_logs() {
    echo "---- rust kdc log tail ----"
    docker exec "$NAME" tail -n 6 /tmp/rust-kdc.log 2>&1 | cut -c1-600
    echo "---- mit kdc log tail ----"
    docker exec "$NAME" tail -n 6 /tmp/mit-kdc.log 2>&1 | cut -c1-600
}

cross_case() {
    local issuer=$1 tgs=$2 got
    echo "==== TGT from $issuer KDC, service ticket from $tgs TGS ===="
    kinit_via "$issuer"
    got="$(kvno_via "$tgs")"
    echo "$got"
    if ! echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1'; then
        kdc_logs
        die "$issuer TGT rejected by $tgs TGS: $got"
    fi
}

cross_case mit rust
cross_case rust mit
cross_case mit mit
cross_case rust rust

echo "==== TGT enc-part etype is the first current krbtgt key on both KDCs ===="
kinit_via mit
MIT_TGT_ETYPE="$(tgt_etype_via)"
kinit_via rust
RUST_TGT_ETYPE="$(tgt_etype_via)"
echo "mit_tgt_etype=$MIT_TGT_ETYPE rust_tgt_etype=$RUST_TGT_ETYPE"
[ -n "$MIT_TGT_ETYPE" ] || die "MIT TGT etype not found in klist -e"
[ "$MIT_TGT_ETYPE" = "$RUST_TGT_ETYPE" ] || die "TGT etype differs: mit=$MIT_TGT_ETYPE rust=$RUST_TGT_ETYPE"

docker cp "$NAME":/tmp/rust-kdc.log "$OUT/rust-kdc.log" 2>/dev/null || true
docker cp "$NAME":/tmp/mit-kdc.log "$OUT/mit-kdc.log" 2>/dev/null || true
if grep -q 'HEADER_PAC' "$OUT/rust-kdc.log"; then
    die "Rust KDC logged HEADER_PAC during the cross-KDC exchange"
fi
if grep -q 'PROCESS_TGS' "$OUT/mit-kdc.log"; then
    die "MIT krb5kdc logged PROCESS_TGS during the cross-KDC exchange"
fi

echo "==== MIT kinit SPAKE P-256 on the golden dump both KDCs ===="
docker exec "$NAME" python3 -c '
from pathlib import Path
for src, dst in (("/tmp/rust-krb5.conf", "/tmp/spake-rust-krb5.conf"), ("/tmp/mit-krb5.conf", "/tmp/spake-mit-krb5.conf")):
    t = Path(src).read_text()
    if "spake_preauth_groups" not in t:
        t = t.replace("[libdefaults]", "[libdefaults]\n    spake_preauth_groups = P-256\n    preferred_preauth_types = 151", 1)
    Path(dst).write_text(t)
'
# MIT krb5kdc reads spake_preauth_groups from [libdefaults] (krb5.conf).
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5.conf")
t = p.read_text()
if "spake_preauth_groups" not in t:
    t = t.replace("[libdefaults]", "[libdefaults]\n    spake_preauth_groups = P-256", 1)
Path("/tmp/spake-kdc-krb5.conf").write_text(t)
'
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
STARTLOG="$(docker exec "$NAME" sh -c 'KRB5_CONFIG=/tmp/spake-kdc-krb5.conf krb5kdc -n >/tmp/mit-kdc.log 2>&1 & sleep 0.5; cat /tmp/mit-kdc.log' 2>&1 || true)"
echo "$STARTLOG"
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "MIT krb5kdc did not listen on 88 after SPAKE groups"
spake_kinit_via() {
    local side=$1 listing
    docker exec -e KRB5CCNAME="$CC" "$NAME" kdestroy -A >/dev/null 2>&1 || true
    if ! docker exec -e KRB5_CONFIG="/tmp/spake-${side}-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" \
        sh -c 'printf "preauthpw\n" | kinit pauser@KERBER.TEST'; then
        kdc_logs
        die "SPAKE kinit via $side KDC failed"
    fi
    listing="$(docker exec -e KRB5_CONFIG="/tmp/spake-${side}-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" klist -C 2>&1 || true)"
    echo "$listing"
    echo "$listing" | grep -q 'pa_type.*= 151' || die "SPAKE kinit via $side (rust_kdc or mit_kdc) missing pa_type 151"
}
spake_kinit_via rust
spake_kinit_via mit

echo "==== MIT-TGT → Rust-TGS PAC buffer types match MIT-TGT → MIT-TGS ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-pac-extract" "$NAME":/tmp/krb5-pac-extract
docker exec "$NAME" chmod +x /tmp/krb5-pac-extract
docker exec "$NAME" kadmin.local -q 'ktadd -norandkey -k /tmp/host.kt host/testhost.kerber.test' \
    >/dev/null 2>&1 || die "ktadd -norandkey host failed"
docker exec "$NAME" kadmin.local -q 'ktadd -norandkey -k /tmp/krbtgt.kt krbtgt/KERBER.TEST' \
    >/dev/null 2>&1 || die "ktadd -norandkey krbtgt failed"
pac_types_via() {
    local tgs=$1
    kinit_via mit
    got="$(kvno_via "$tgs")"
    echo "$got"
    echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1' \
        || die "PAC-types $tgs kvno failed: $got"
    docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
        --keytab /tmp/host.kt --ccache "$CC" --print-types
}
MIT_PAC_TYPES="$(pac_types_via mit | sed -n 's/^pac_types=//p')"
RUST_PAC_TYPES="$(pac_types_via rust | sed -n 's/^pac_types=//p')"
echo "mit_pac_types=$MIT_PAC_TYPES rust_pac_types=$RUST_PAC_TYPES"
[ -n "$MIT_PAC_TYPES" ] || die "MIT TGS PAC types empty"
[ "$MIT_PAC_TYPES" = "$RUST_PAC_TYPES" ] || die "PAC types differ: mit=$MIT_PAC_TYPES rust=$RUST_PAC_TYPES"

echo "==== setstr pac_privsvr_enctype + MIT kvno both legs ===="
docker exec "$NAME" kadmin.local -q \
    'setstr host/testhost.kerber.test pac_privsvr_enctype aes128-cts-hmac-sha1-96'
docker exec "$NAME" kdb5_util dump /tmp/privsvr.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true; : >/tmp/rust-kdc.log'
sleep 0.3
LOAD_PRIV="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/privsvr.dump)"
echo "$LOAD_PRIV"
echo "$LOAD_PRIV" | grep -q 'ok load version=7' || die "rust kdb reload after setstr failed"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "rust kdc did not listen after privsvr reload"
privsvr_kvno() {
    local tgs=$1
    kinit_via mit
    got="$(kvno_via "$tgs")"
    echo "$got"
    echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1' \
        || die "privsvr $tgs kvno failed: $got"
    docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
        --keytab /tmp/host.kt --krbtgt-keytab /tmp/krbtgt.kt --ccache "$CC" \
        --verify-privsvr aes128-cts-hmac-sha1-96
}
MIT_PRIVSVR="$(privsvr_kvno mit | sed -n 's/^privsvr_ok=//p')"
RUST_PRIVSVR="$(privsvr_kvno rust | sed -n 's/^privsvr_ok=//p')"
echo "mit_privsvr=$MIT_PRIVSVR rust_privsvr=$RUST_PRIVSVR"
[ "$MIT_PRIVSVR" = "aes128-cts-hmac-sha1-96" ] || die "MIT privsvr verify failed"
[ "$RUST_PRIVSVR" = "aes128-cts-hmac-sha1-96" ] || die "Rust privsvr verify failed"

echo "==== MIT TGT AD shape through Rust TGS (copy_tgt strips KDC-issued) ===="
kinit_via mit
TGT_AD="$(docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/krbtgt.kt --ccache "$CC" --tgt --print-ad-types | sed -n 's/^ad_types=//p')"
echo "mit_tgt_ad_types=$TGT_AD"
[ "$TGT_AD" = "1/128" ] || die "MIT TGT AD shape want 1/128 got $TGT_AD"
got="$(kvno_via rust)"
echo "$got"
echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1' \
    || die "AD-shape rust TGS kvno failed: $got"
SVC_AD="$(docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/host.kt --ccache "$CC" --print-ad-types | sed -n 's/^ad_types=//p')"
echo "rust_svc_ad_types=$SVC_AD"
[ "$SVC_AD" = "1/128" ] || die "Rust TGS AD shape want 1/128 (no copied TGT PAC) got $SVC_AD"

echo "==== require_auth password kvno is 12 both legs ===="
docker exec "$NAME" kadmin.local -q 'setstr host/testhost.kerber.test require_auth pkinit'
docker exec "$NAME" kdb5_util dump /tmp/reqauth.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true; : >/tmp/rust-kdc.log'
sleep 0.3
LOAD_REQ="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/reqauth.dump)"
echo "$LOAD_REQ"
echo "$LOAD_REQ" | grep -q 'ok load version=7' || die "rust kdb reload after require_auth failed"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "rust kdc did not listen after require_auth reload"
kinit_via mit
MIT_REQ="$(kvno_via mit)"
RUST_REQ="$(kvno_via rust)"
echo "mit_require_auth=$MIT_REQ"
echo "rust_require_auth=$RUST_REQ"
echo "$MIT_REQ" | grep -qi 'KDC policy' || echo "$MIT_REQ" | grep -q 'while getting credentials' \
    || die "MIT kvno after require_auth did not fail: $MIT_REQ"
echo "$RUST_REQ" | grep -qi 'KDC policy' || echo "$RUST_REQ" | grep -q 'while getting credentials' \
    || die "Rust kvno after require_auth did not fail: $RUST_REQ"
docker exec "$NAME" kadmin.local -q 'delstr host/testhost.kerber.test require_auth'
docker exec "$NAME" kdb5_util dump /tmp/reqauth-clear.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true; : >/tmp/rust-kdc.log'
sleep 0.3
LOAD_CLR="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/reqauth-clear.dump)"
echo "$LOAD_CLR"
echo "$LOAD_CLR" | grep -q 'ok load version=7' || die "rust kdb reload after delstr failed"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "rust kdc did not listen after require_auth clear"

echo "==== require_auth on krbtgt password kinit is 12 both legs ===="
docker exec "$NAME" kadmin.local -q 'setstr krbtgt/KERBER.TEST require_auth pkinit'
docker exec "$NAME" kdb5_util dump /tmp/reqauth-as.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true; : >/tmp/rust-kdc.log'
sleep 0.3
LOAD_AS="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/reqauth-as.dump)"
echo "$LOAD_AS"
echo "$LOAD_AS" | grep -q 'ok load version=7' || die "rust kdb reload after krbtgt require_auth failed"
docker exec -d \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "rust kdc did not listen after krbtgt require_auth"
try_kinit() {
    docker exec -e KRB5CCNAME="$CC" "$NAME" kdestroy -A >/dev/null 2>&1 || true
    docker exec -e KRB5_CONFIG="/tmp/$1-krb5.conf" -e KRB5CCNAME="$CC" "$NAME" \
        sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST' 2>&1 || true
}
MIT_AS="$(try_kinit mit)"
RUST_AS="$(try_kinit rust)"
echo "mit_as_require_auth=$MIT_AS"
echo "rust_as_require_auth=$RUST_AS"
echo "$MIT_AS" | grep -qi 'KDC policy' || echo "$MIT_AS" | grep -q 'while getting initial credentials' \
    || die "MIT password kinit after krbtgt require_auth did not fail: $MIT_AS"
echo "$RUST_AS" | grep -qi 'KDC policy' || echo "$RUST_AS" | grep -q 'while getting initial credentials' \
    || die "Rust password kinit after krbtgt require_auth did not fail: $RUST_AS"
docker exec "$NAME" kadmin.local -q 'delstr krbtgt/KERBER.TEST require_auth'
docker exec "$NAME" kdb5_util dump /tmp/reqauth-as-clear.dump
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true; : >/tmp/rust-kdc.log'
sleep 0.3
LOAD_ASC="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/rust.db \
    -e KRB5_KDC_STASH=/tmp/rust.stash \
    "$NAME" /tmp/krb5-kdb load /tmp/reqauth-as-clear.dump)"
echo "$LOAD_ASC"
echo "$LOAD_ASC" | grep -q 'ok load version=7' || die "rust kdb reload after krbtgt delstr failed"

echo "==== SPAKE CAMMAC honor MIT TGT through Rust TGS ===="
docker exec "$NAME" python3 -c '
from pathlib import Path
p = Path("/etc/krb5kdc/kdc.conf")
t = p.read_text()
if "spake_preauth_indicator" not in t:
    t = t.replace("supported_enctypes", "        spake_preauth_indicator = spake\n        supported_enctypes", 1)
    p.write_text(t)
Path("/tmp/rust-kdc.conf").write_text("""[realms]
    KERBER.TEST = {
        spake_preauth_indicator = spake
    }
""")
'
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) 2>/dev/null || true'
sleep 0.3
STARTLOG="$(docker exec "$NAME" sh -c 'KRB5_CONFIG=/tmp/spake-kdc-krb5.conf krb5kdc -n >/tmp/mit-kdc.log 2>&1 & sleep 0.5; cat /tmp/mit-kdc.log' 2>&1 || true)"
echo "$STARTLOG"
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
[ "$ok" = 1 ] || die "MIT krb5kdc did not listen after indicator knob"
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true; : >/tmp/rust-kdc.log'
sleep 0.3
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
[ "$ok" = 1 ] || die "rust kdc did not listen after indicator knob"
spake_kinit_via mit
CAMMAC_TGT="$(docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/krbtgt.kt --ccache "$CC" --tgt --print-ad-types | sed -n 's/^ad_types=//p')"
echo "mit_spake_tgt_ad=$CAMMAC_TGT"
echo "$CAMMAC_TGT" | grep -q '96' || die "MIT SPAKE TGT missing CAMMAC 96: $CAMMAC_TGT"
got="$(kvno_via rust)"
echo "$got"
echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1' \
    || die "Rust TGS rejected MIT SPAKE TGT CAMMAC: $got"
CAMMAC_SVC="$(docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/host.kt --ccache "$CC" --print-ad-types | sed -n 's/^ad_types=//p')"
echo "rust_spake_svc_ad=$CAMMAC_SVC"
echo "$CAMMAC_SVC" | grep -q '96' || die "Rust TGS service ticket missing CAMMAC 96: $CAMMAC_SVC"

echo "==== SPAKE CAMMAC honor Rust TGT through MIT TGS ===="
spake_kinit_via rust
RUST_CAMMAC_TGT="$(docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/krbtgt.kt --ccache "$CC" --tgt --print-ad-types | sed -n 's/^ad_types=//p')"
echo "rust_spake_tgt_ad=$RUST_CAMMAC_TGT"
echo "$RUST_CAMMAC_TGT" | grep -q '96' || die "Rust SPAKE TGT missing CAMMAC 96: $RUST_CAMMAC_TGT"
got="$(kvno_via mit)"
echo "$got"
echo "$got" | grep -Fx 'host/testhost.kerber.test@KERBER.TEST: kvno = 1' \
    || die "MIT TGS rejected Rust SPAKE TGT CAMMAC: $got"
MIT_CAMMAC_SVC="$(docker exec -e KRB5CCNAME="$CC" "$NAME" /tmp/krb5-pac-extract \
    --keytab /tmp/host.kt --ccache "$CC" --print-ad-types | sed -n 's/^ad_types=//p')"
echo "mit_spake_svc_ad=$MIT_CAMMAC_SVC"
echo "$MIT_CAMMAC_SVC" | grep -q '96' || die "MIT TGS service ticket missing CAMMAC 96: $MIT_CAMMAC_SVC"

log "cross.kdc.gate" "ok" ",\"tgt_etype\":\"$MIT_TGT_ETYPE\",\"directions\":4,\"spake_pa_type\":151,\"pac_types\":\"$MIT_PAC_TYPES\",\"tgt_ad\":\"$TGT_AD\",\"svc_ad\":\"$SVC_AD\",\"require_auth\":\"12\",\"cammac_tgt\":\"$CAMMAC_TGT\",\"cammac_svc\":\"$CAMMAC_SVC\",\"rust_cammac_tgt\":\"$RUST_CAMMAC_TGT\",\"mit_cammac_svc\":\"$MIT_CAMMAC_SVC\""
echo "cross-kdc-gate ok"
