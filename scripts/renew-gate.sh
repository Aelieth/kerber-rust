#!/usr/bin/env bash
# MIT 1.22.2 kinit -R / kinit -p vs Rust KDC. Isolated: never touches
# host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-renew-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-renew-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"renew-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "renew.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/renew-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "renew.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/renew-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
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
    log "renew.gate" "error" ',"error":"kdc did not listen"'
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
    log "renew.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/renew-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_renew
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== addprinc renewuser; four-term defaults ===="
kadmin_q 'addprinc -pw renew-secret renewuser'
KRBTGT_P="$(kadmin_q 'getprinc krbtgt/KERBER.TEST')"
USER_P="$(kadmin_q 'getprinc renewuser')"
echo "$KRBTGT_P"
echo "$USER_P"
# New-principal default copies realm policy (7d), so maxrenewlife is not 0.
echo "$KRBTGT_P" | grep -E 'Maximum renewable life:' | grep -qvE '0 days 00:00:00'
echo "$USER_P" | grep -E 'Maximum renewable life:' | grep -qvE '0 days 00:00:00'
kadmin_q 'modprinc -maxrenewlife "7 days" renewuser'
kadmin_q 'modprinc -maxrenewlife "7 days" krbtgt/KERBER.TEST'

echo "==== MIT kinit -r 7d -l 10h (renew until ≈ start + 7d) ===="
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -r 7d -l 10h renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -r failed"'
    exit 1
fi
BEFORE="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$BEFORE"
echo "$BEFORE" | grep -q 'renewuser@KERBER.TEST'
FLAGBITS="$(echo "$BEFORE" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "flagbits=$FLAGBITS"
echo "$FLAGBITS" | grep -q R
EXP1="$(echo "$BEFORE" | awk '/krbtgt\//{print $3, $4; exit}')"
REN1="$(echo "$BEFORE" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "exp1=$EXP1 renew1=$REN1"
[ -n "$EXP1" ] && [ -n "$REN1" ]
START1="$(echo "$BEFORE" | awk '/krbtgt\//{print $1, $2; exit}')"
echo "start1=$START1"
if date -d "$START1" +%s >/dev/null 2>&1 && date -d "$REN1" +%s >/dev/null 2>&1; then
    S_UNIX="$(date -d "$START1" +%s)"
    R_UNIX="$(date -d "$REN1" +%s)"
    DELTA=$((R_UNIX - S_UNIX))
    echo "renew_delta_secs=$DELTA"
    # 7d ± 2h
    test "$DELTA" -ge 590400
    test "$DELTA" -le 619200
fi

sleep 2
echo "==== MIT kinit -R ===="
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -R failed"'
    exit 1
fi
AFTER="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$AFTER"
EXP2="$(echo "$AFTER" | awk '/krbtgt\//{print $3, $4; exit}')"
REN2="$(echo "$AFTER" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "exp2=$EXP2 renew2=$REN2"
[ "$REN1" = "$REN2" ]
[ "$EXP1" != "$EXP2" ]
FLAG2="$(echo "$AFTER" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "flagbits2=$FLAG2"
echo "$FLAG2" | grep -q R

echo "==== DISALLOW_RENEWABLE: kinit -R strips R ===="
kadmin_q 'modprinc -allow_renewable renewuser'
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -R after DISALLOW_RENEWABLE failed"'
    exit 1
fi
STRIP="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$STRIP"
STRIPBITS="$(echo "$STRIP" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "stripbits=$STRIPBITS"
echo "$STRIPBITS" | grep -qv R
if echo "$STRIP" | grep -q 'renew until'; then
    echo "DISALLOW_RENEWABLE renew kept renew until" >&2
    exit 1
fi

echo "==== second kinit -R after strip must fail ===="
AGAIN="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R 2>&1 || true)"
echo "$AGAIN"
echo "$AGAIN" | grep -qiE "can't fulfill requested option|BADOPTION"
if echo "$AGAIN" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "second kinit -R after strip succeeded" >&2
    exit 1
fi

echo "==== MIT kinit -p shows P ===="
kadmin_q 'modprinc +allow_renewable renewuser'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -p renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -p failed"'
    exit 1
fi
PFLAGS="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$PFLAGS"
PBITS="$(echo "$PFLAGS" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "pbits=$PBITS"
echo "$PBITS" | grep -q P

echo "==== NON-RENEWABLE TICKET: kvno after kinit -r vs -allow_renewable (rust) ===="
kadmin_q 'addprinc -randkey host/norenew.kerber.test'
kadmin_q 'modprinc -allow_renewable host/norenew.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -r 7d renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -r before NON-RENEWABLE rust failed"'
    exit 1
fi
set +e
NORENEW_RUST="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" kvno host/norenew.kerber.test 2>&1)"
set -e
echo "$NORENEW_RUST"
echo "$NORENEW_RUST" | grep -qF "KDC policy rejects request" || {
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"rust kvno against -allow_renewable did not POLICY"'
    exit 1
}

echo "==== NON-RENEWABLE TICKET: kvno after kinit -r vs -allow_renewable (mit) ===="
MITNAME="kerber-rust-renew-mit-oracle"
docker rm -f "$MITNAME" >/dev/null 2>&1 || true
docker run -d --name "$MITNAME" "$IMAGE" >/dev/null
cleanup_mit() { docker rm -f "$MITNAME" >/dev/null 2>&1 || true; }
trap 'cleanup; cleanup_mit' EXIT
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$MITNAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        log "renew.gate" "error" ',"error":"MIT oracle harness kinit failed"'
        exit 1
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT oracle harness did not become ready"'
    exit 1
fi
docker exec "$MITNAME" kadmin.local -q "addprinc -randkey host/norenew.kerber.test"
docker exec "$MITNAME" kadmin.local -q "modprinc -allow_renewable host/norenew.kerber.test"
docker exec "$MITNAME" sh -c 'cat >/tmp/renew-mit-oracle.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_renew_mit
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF'
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -r 7d user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT kinit -r before NON-RENEWABLE failed"'
    exit 1
fi
set +e
NORENEW_MIT="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" kvno host/norenew.kerber.test 2>&1)"
set -e
echo "$NORENEW_MIT"
echo "$NORENEW_MIT" | grep -qF "KDC policy rejects request" || {
    log "renew.gate" "error" ',"error":"MIT kvno against -allow_renewable did not POLICY"'
    exit 1
}

echo "==== MIT kinit -p shows P (mit oracle) ===="
docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -p user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT oracle kinit -p failed"'
    exit 1
fi
MIT_PFLAGS="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" klist -f)"
echo "$MIT_PFLAGS"
MIT_PBITS="$(echo "$MIT_PFLAGS" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "mit_pbits=$MIT_PBITS"
echo "$MIT_PBITS" | grep -q P || {
    log "renew.gate" "error" ',"error":"MIT oracle kinit -p missing P"'
    exit 1
}

log "renew.gate" "ok" ',"kinit_r":true,"renew_till_preserved":true,"disallow_strips":true,"proxiable":true,"non_renewable":true'
exit 0
