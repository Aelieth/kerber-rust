#!/usr/bin/env bash
# MIT 1.22.2 kinit -s / kinit -v vs Rust KDC. Isolated: never touches
# host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-postdate-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-postdate-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"postdate-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "postdate.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/postdate-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "postdate.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/postdate-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
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
    log "postdate.gate" "error" ',"error":"kdc did not listen"'
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
    log "postdate.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/postdate-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_postdate
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== addprinc pduser ===="
kadmin_q 'addprinc -pw pd-secret pduser'

echo "==== MIT kinit -s +20s ===="
START="$(docker exec "$NAME" date -u -d '+20 seconds' '+%Y%m%d%H%M%S')"
echo "start=$START"
docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
    "$NAME" sh -c "printf 'pd-secret\n' | kinit -s '$START' pduser@KERBER.TEST"; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "postdate.gate" "error" ',"error":"kinit -s failed"'
    exit 1
fi
KL="$(docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" klist -f)"
echo "$KL"
echo "$KL" | grep -q 'pduser@KERBER.TEST'
PBITS="$(echo "$KL" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "pbits=$PBITS"
echo "$PBITS" | grep -q i

echo "==== kvno before validate is TKT_NYV ===="
NYV="$(docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test 2>&1 || true)"
echo "$NYV"
echo "$NYV" | grep -qiE "not yet valid|TKT_NYV|NYV"
if echo "$NYV" | grep -q 'kvno ='; then
    echo "invalid ticket issued a service ticket" >&2
    exit 1
fi

echo "==== wait for starttime then kinit -v ===="
sleep 21
if ! docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" kinit -v; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "postdate.gate" "error" ',"error":"kinit -v failed"'
    exit 1
fi
AFTER="$(docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" klist -f)"
echo "$AFTER"
ABITS="$(echo "$AFTER" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "abits=$ABITS"
echo "$ABITS" | grep -qv i
if ! docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "postdate.gate" "error" ',"error":"kvno after validate failed"'
    exit 1
fi

echo "==== kinit -s +20s -l 5m endtime is absolute till ===="
docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
STARTL="$(docker exec "$NAME" date -u -d '+20 seconds' '+%Y%m%d%H%M%S')"
echo "startl=$STARTL"
if ! docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
    "$NAME" sh -c "printf 'pd-secret\n' | kinit -s '$STARTL' -l 5m pduser@KERBER.TEST"; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "postdate.gate" "error" ',"error":"kinit -s -l 5m failed"'
    exit 1
fi
KL5="$(docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" klist -f)"
echo "$KL5"
LIFE="$(python3 -c '
import datetime, sys
out = sys.argv[1]
line = [l for l in out.splitlines() if "krbtgt/" in l][0]
parts = line.split()
start = datetime.datetime.strptime(parts[0] + " " + parts[1], "%m/%d/%y %H:%M:%S")
end = datetime.datetime.strptime(parts[2] + " " + parts[3], "%m/%d/%y %H:%M:%S")
delta = int((end - start).total_seconds())
print(delta)
if delta != 300:
    raise SystemExit("end-start=%s want 300" % delta)
' "$KL5")"
echo "life_secs=$LIFE"

echo "==== DISALLOW_POSTDATED: kinit -s CANNOT_POSTDATE ===="
kadmin_q 'addprinc -pw nd-secret nduser'
kadmin_q 'modprinc -allow_postdated nduser'
docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
START2="$(docker exec "$NAME" date -u -d '+1 minute' '+%Y%m%d%H%M%S')"
ND="$(docker exec -e KRB5_CONFIG=/tmp/postdate-krb5.conf \
    "$NAME" sh -c "printf 'nd-secret\n' | kinit -s '$START2' nduser@KERBER.TEST" 2>&1 || true)"
echo "$ND"
echo "$ND" | grep -qiE "cannot postdate|CANNOT_POSTDATE|ineligible for postdat"
if echo "$ND" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "DISALLOW_POSTDATED principal obtained a postdated ticket" >&2
    exit 1
fi

log "postdate.gate" "ok" ',"invalid":true,"tkt_nyv":true,"validate":true,"cannot_postdate":true,"till_absolute":true'
exit 0
