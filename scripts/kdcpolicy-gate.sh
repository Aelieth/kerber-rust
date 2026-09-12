#!/usr/bin/env bash
# MIT 1.22.2 kdcpolicy test module vs Rust TestPolicy (KRB5_KDCPOLICY=test).
# Isolated: never touches host /etc/krb5.conf.
#
# Both legs: AS/TGS deny when the first component is `fail`; SPAKE
# `spake_preauth_indicator = ONE_HOUR` rewrites AS/TGS life; a foreign
# indicator is 12 LOCAL_POLICY.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kdcpolicy-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kdcpolicy-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kdcpolicy-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kdcpolicy.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/kdcpolicy-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "kdcpolicy.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/kdcpolicy-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! docker exec "$NAME" test -f /usr/lib/krb5/plugins/kdcpolicy/kdcpolicy_test.so; then
    echo "MIT image lacks kdcpolicy_test.so; rebuilding" >&2
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
    docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
    if ! docker exec "$NAME" test -f /usr/lib/krb5/plugins/kdcpolicy/kdcpolicy_test.so; then
        log "kdcpolicy.gate" "error" ',"error":"kdcpolicy_test.so missing after rebuild"'
        exit 1
    fi
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec "$NAME" sh -c '
grep -q "spake_preauth_indicator" /etc/krb5kdc/kdc.conf || \
    sed -i "/supported_enctypes/a\\        spake_preauth_indicator = ONE_HOUR" /etc/krb5kdc/kdc.conf
grep -q "spake_preauth_groups" /etc/krb5kdc/kdc.conf || \
    sed -i "/\\[kdcdefaults\\]/a\\    spake_preauth_groups = P-256" /etc/krb5kdc/kdc.conf
cat >> /etc/krb5.conf <<EOF

[plugins]
    kdcpolicy = {
        module = test:/usr/lib/krb5/plugins/kdcpolicy/kdcpolicy_test.so
    }
EOF
'

docker exec "$NAME" sh -c 'cat >/tmp/policy-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    preferred_preauth_types = 151
    spake_preauth_groups = P-256
    default_ccache_name = FILE:/tmp/krb5cc_policy
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
[plugins]
    kdcpolicy = {
        module = test:/usr/lib/krb5/plugins/kdcpolicy/kdcpolicy_test.so
    }
EOF'

life_delta() {
    docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" klist | python3 -c '
import re, sys
from datetime import datetime
want = int(sys.argv[1])
needle = sys.argv[2]
out = sys.stdin.read()
pat = re.compile(
    r"^(\d\d/\d\d/\d\d \d\d:\d\d:\d\d) +(\d\d/\d\d/\d\d \d\d:\d\d:\d\d) +(\S+)",
    re.M,
)
rows = pat.findall(out)
print(f"klist_rows={rows}", file=sys.stderr)
hit = None
for start_s, end_s, svc in rows:
    if needle in svc:
        hit = (start_s, end_s, svc)
if hit is None:
    sys.stderr.write(out + f"\nno klist row for {needle}\n")
    sys.exit(1)
start = datetime.strptime(hit[0], "%m/%d/%y %H:%M:%S")
end = datetime.strptime(hit[1], "%m/%d/%y %H:%M:%S")
delta = (end - start).total_seconds()
print(f"delta={int(delta)} svc={hit[2]}")
if abs(delta - want) > 90:
    sys.stderr.write(f"lifetime {delta} want {want}\n")
    sys.exit(1)
' "$1" "$2"
}

kill_named() {
    docker exec "$NAME" sh -c '
for want in '"$*"'; do
    for comm in /proc/[0-9]*/comm; do
        [ -f "$comm" ] || continue
        read -r name < "$comm" || continue
        if [ "$name" = "$want" ]; then
            pid=${comm#/proc/}
            pid=${pid%/comm}
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
done
'
}

wait_listen() {
    ok=0
    for _ in $(seq 1 80); do
        if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.25
    done
    [ "$ok" = 1 ]
}

wait_free() {
    free=0
    for _ in $(seq 1 40); do
        if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
            free=1
            break
        fi
        sleep 0.25
    done
    [ "$free" = 1 ]
}

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

kinit_try() {
    docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
        "$NAME" sh -c "$1" 2>&1 || true
}

echo "==== rust KDC TestPolicy ===="
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_KDCPOLICY=test \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'

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
    log "kdcpolicy.gate" "error" ',"error":"rust kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
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
    log "kdcpolicy.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

kadmin_q 'addprinc -pw fail-secret fail' | grep -F 'Principal "fail@KERBER.TEST" created.'

echo "==== rust AS fail is LOCAL_POLICY ===="
FAIL_AS="$(kinit_try 'printf "fail-secret\n" | kinit fail@KERBER.TEST')"
echo "$FAIL_AS"
echo "$FAIL_AS" | grep -q 'KDC policy rejects request'
docker exec "$NAME" grep -q 'LOCAL_POLICY' /tmp/kdc.log
echo "RUST_as_fail" # RUST_as_fail

echo "==== rust SPAKE ONE_HOUR rewrites AS/TGS life ===="
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit -l 12h -r 1d user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kdcpolicy.gate" "error" ',"error":"rust SPAKE kinit failed"'
    exit 1
fi
life_delta 3600 'krbtgt/' || exit 1 # RUST_one_hour_as
echo "RUST_one_hour_as"
if ! docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kdcpolicy.gate" "error" ',"error":"rust kvno host failed"'
    exit 1
fi
life_delta 1800 'host/' || exit 1 # RUST_one_hour_tgs
echo "RUST_one_hour_tgs"

echo "==== rust TGS fail is LOCAL_POLICY ===="
FAIL_TGS="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" kvno fail@KERBER.TEST 2>&1 || true)"
echo "$FAIL_TGS"
echo "$FAIL_TGS" | grep -q 'KDC policy rejects request'
echo "RUST_tgs_fail" # RUST_tgs_fail

echo "==== rust foreign indicator is LOCAL_POLICY ===="
kill_named krb5-kdc krb5-kadmind
if ! wait_free; then
    log "kdcpolicy.gate" "error" ',"error":"rust kdc still bound :88"'
    exit 1
fi
docker exec "$NAME" sed -i 's/spake_preauth_indicator = ONE_HOUR/spake_preauth_indicator = OTHER/' /etc/krb5kdc/kdc.conf
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDCPOLICY=test \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:88 >/tmp/kdc-other.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc-other.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc-other.log >&2 || true
    log "kdcpolicy.gate" "error" ',"error":"rust kdc OTHER did not listen"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
OTHER="$(kinit_try 'printf "userpassword\n" | kinit user@KERBER.TEST')"
echo "$OTHER"
echo "$OTHER" | grep -q 'KDC policy rejects request'
echo "RUST_foreign_indicator" # RUST_foreign_indicator

echo "==== MIT kdcpolicy_test.so ===="
kill_named krb5-kdc
if ! wait_free; then
    log "kdcpolicy.gate" "error" ',"error":"rust kdc still bound :88 before MIT"'
    exit 1
fi
docker exec "$NAME" sed -i 's/spake_preauth_indicator = OTHER/spake_preauth_indicator = ONE_HOUR/' /etc/krb5kdc/kdc.conf
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kadmin.local -q 'addprinc -pw userpassword user'
docker exec "$NAME" kadmin.local -q 'modprinc +requires_preauth user'
docker exec "$NAME" kadmin.local -q 'addprinc -randkey host/testhost.kerber.test'
docker exec "$NAME" kadmin.local -q 'addprinc -pw fail-secret fail'
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc; sleep 0.4' 2>&1 || true)"
echo "$STARTLOG"
if ! wait_listen; then
    docker exec "$NAME" cat /tmp/mit-kdc.log 2>/dev/null >&2 || true
    log "kdcpolicy.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

echo "==== MIT AS fail is LOCAL_POLICY ===="
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
FAIL_AS_MIT="$(kinit_try 'printf "fail-secret\n" | kinit fail@KERBER.TEST')"
echo "$FAIL_AS_MIT"
echo "$FAIL_AS_MIT" | grep -q 'KDC policy rejects request'
echo "MIT_as_fail" # MIT_as_fail

echo "==== MIT SPAKE ONE_HOUR rewrites AS/TGS life ===="
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit -l 12h -r 1d user@KERBER.TEST'; then
    log "kdcpolicy.gate" "error" ',"error":"MIT SPAKE kinit failed"'
    exit 1
fi
life_delta 3600 'krbtgt/' || exit 1 # MIT_one_hour_as
echo "MIT_one_hour_as"
if ! docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test; then
    log "kdcpolicy.gate" "error" ',"error":"MIT kvno host failed"'
    exit 1
fi
life_delta 1800 'host/' || exit 1 # MIT_one_hour_tgs
echo "MIT_one_hour_tgs"

echo "==== MIT TGS fail is LOCAL_POLICY ===="
FAIL_TGS_MIT="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" kvno fail@KERBER.TEST 2>&1 || true)"
echo "$FAIL_TGS_MIT"
echo "$FAIL_TGS_MIT" | grep -q 'KDC policy rejects request'
echo "MIT_tgs_fail" # MIT_tgs_fail

echo "==== MIT foreign indicator is LOCAL_POLICY ===="
kill_named krb5kdc
if ! wait_free; then
    log "kdcpolicy.gate" "error" ',"error":"MIT krb5kdc still bound :88"'
    exit 1
fi
docker exec "$NAME" sed -i 's/spake_preauth_indicator = ONE_HOUR/spake_preauth_indicator = OTHER/' /etc/krb5kdc/kdc.conf
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc; sleep 0.4' 2>&1 || true)"
echo "$STARTLOG"
if ! wait_listen; then
    log "kdcpolicy.gate" "error" ',"error":"MIT krb5kdc OTHER did not listen"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
OTHER_MIT="$(kinit_try 'printf "userpassword\n" | kinit user@KERBER.TEST')"
echo "$OTHER_MIT"
echo "$OTHER_MIT" | grep -q 'KDC policy rejects request'
echo "MIT_foreign_indicator" # MIT_foreign_indicator

log "kdcpolicy.gate" "ok" ',"as_fail":true,"tgs_fail":true,"one_hour":true,"foreign_indicator":true'
exit 0
