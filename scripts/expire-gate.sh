#!/usr/bin/env bash
# MIT 1.22.2 kinit vs Rust KDC: principal expiry (NAME_EXP) and password
# expiry (KEY_EXPIRED), plus PWCHANGE_SERVICE exception.
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-expire-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-expire-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"expire-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "expire.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/expire-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "expire.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/expire-unavailable.log"
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
    log "expire.gate" "error" ',"error":"kdc did not listen"'
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
    log "expire.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/expire-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_expire
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

kinit_try() {
    docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
        "$NAME" sh -c "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== MIT kadmin addprinc expuser + modprinc -expire past ===="
ADD="$(kadmin_q 'addprinc -pw exp-secret expuser')"
echo "$ADD"
MOD="$(kadmin_q 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" expuser')"
echo "$MOD"
GET="$(kadmin_q 'getprinc expuser')"
echo "$GET"
echo "$GET" | grep '^Expiration date:' | grep -v '\[never\]'

echo "==== MIT kinit expuser (must NAME_EXP, not a ticket) ===="
EXP="$(kinit_try 'printf "exp-secret\n" | kinit expuser@KERBER.TEST')"
echo "$EXP"
echo "$EXP" | grep -qiE "entry in database has expired|name.exp"
if echo "$EXP" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "expired principal obtained a ticket" >&2
    exit 1
fi

echo "==== MIT kadmin addprinc pwexpuser + modprinc -pwexpire past ===="
ADD2="$(kadmin_q 'addprinc -pw pw-secret pwexpuser')"
echo "$ADD2"
MOD2="$(kadmin_q 'modprinc -pwexpire "Jan 1, 2020 00:00:00 UTC" pwexpuser')"
echo "$MOD2"
GET2="$(kadmin_q 'getprinc pwexpuser')"
echo "$GET2"
echo "$GET2" | grep 'Password expiration date:' | grep -v '\[never\]'

echo "==== MIT kinit pwexpuser (must KEY_EXPIRED, not a ticket) ===="
# MIT kinit auto-tries kadmin/changepw when KEY_EXPIRED; strip the flag so
# the protocol code is visible instead of an interactive cpw prompt.
kadmin_q 'modprinc -password_changing_service kadmin/changepw'
PW="$(kinit_try 'printf "pw-secret\n" | kinit pwexpuser@KERBER.TEST')"
echo "$PW"
echo "$PW" | grep -qiE "Password has expired|key has expired|KEY_EXP"
if echo "$PW" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "password-expired principal obtained a TGT" >&2
    exit 1
fi
kadmin_q 'modprinc +password_changing_service kadmin/changepw'

echo "==== kadmin/changepw carries PWCHANGE_SERVICE ===="
CPWGET="$(kadmin_q 'getprinc kadmin/changepw')"
echo "$CPWGET"
echo "$CPWGET" | grep -q 'PWCHANGE_SERVICE'

echo "==== MIT kinit -S kadmin/changepw pwexpuser (PWCHANGE_SERVICE) ===="
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "pw-secret\n" | kinit -S kadmin/changepw@KERBER.TEST pwexpuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "expire.gate" "error" ',"error":"PWCHANGE_SERVICE kinit failed"'
    exit 1
fi
CPW="$(docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" klist)"
echo "$CPW"
echo "$CPW" | grep -q 'kadmin/changepw'

echo "==== both -expire and -pwexpire: NAME_EXP wins ===="
ADD3="$(kadmin_q 'addprinc -pw both-secret bothexp')"
echo "$ADD3"
kadmin_q 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" -pwexpire "Jan 1, 2020 00:00:00 UTC" bothexp'
BOTH="$(kinit_try 'printf "both-secret\n" | kinit bothexp@KERBER.TEST')"
echo "$BOTH"
echo "$BOTH" | grep -qiE "entry in database has expired|name.exp"
if echo "$BOTH" | grep -qiE 'Password has expired'; then
    echo "principal expiry must win over password expiry" >&2
    exit 1
fi

echo "==== unexpired user still kinit ===="
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

echo "==== TGS after pwexpire: kvno still succeeds ===="
kadmin_q 'addprinc -pw tgs-secret tgsuser'
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "tgs-secret\n" | kinit tgsuser@KERBER.TEST'
kadmin_q 'modprinc -pwexpire "Jan 1, 2020 00:00:00 UTC" tgsuser'
if ! docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "expire.gate" "error" ',"error":"TGS after pwexpire failed"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
kadmin_q 'modprinc -password_changing_service kadmin/changepw'
PW_AS="$(kinit_try 'printf "tgs-secret\n" | kinit tgsuser@KERBER.TEST')"
echo "$PW_AS"
echo "$PW_AS" | grep -qiE "Password has expired|key has expired|KEY_EXP"
if echo "$PW_AS" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "password-expired tgsuser obtained a TGT after TGS" >&2
    exit 1
fi
kadmin_q 'modprinc +password_changing_service kadmin/changepw'

echo "==== TGS after account expire: kvno still succeeds ===="
kadmin_q 'addprinc -pw acct-secret tgsacct'
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "acct-secret\n" | kinit tgsacct@KERBER.TEST'
kadmin_q 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" tgsacct'
if ! docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "expire.gate" "error" ',"error":"TGS after account expire failed"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
ACCT_AS="$(kinit_try 'printf "acct-secret\n" | kinit tgsacct@KERBER.TEST')"
echo "$ACCT_AS"
echo "$ACCT_AS" | grep -qiE "entry in database has expired|name.exp"
if echo "$ACCT_AS" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "account-expired tgsacct obtained a TGT after TGS" >&2
    exit 1
fi

echo "==== TGS expired server is SERVICE_EXP ===="
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
kadmin_q 'modprinc -expire "Jan 1, 2020 00:00:00 UTC" host/testhost.kerber.test'
SVC="$(docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test 2>&1 || true)"
echo "$SVC"
echo "$SVC" | grep -qiE "entry in database has expired|SERVICE_EXP"
if echo "$SVC" | grep -q 'kvno ='; then
    echo "expired server issued a service ticket" >&2
    exit 1
fi
kadmin_q 'modprinc -expire never host/testhost.kerber.test'

echo "==== MIT kadmin +needchange → KEY_EXPIRED; changepw still issues ===="
kadmin_q 'addprinc -pw need-secret needuser'
NEEDGET="$(kadmin_q 'modprinc +needchange needuser'; kadmin_q 'getprinc needuser')"
echo "$NEEDGET"
echo "$NEEDGET" | grep -q 'REQUIRES_PWCHANGE'
kadmin_q 'modprinc -password_changing_service kadmin/changepw'
NEED="$(kinit_try 'printf "need-secret\n" | kinit needuser@KERBER.TEST')"
echo "$NEED"
echo "$NEED" | grep -qiE "Password has expired|key has expired|KEY_EXP"
if echo "$NEED" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "+needchange principal obtained a TGT" >&2
    exit 1
fi
kadmin_q 'modprinc +password_changing_service kadmin/changepw'
docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf \
    "$NAME" sh -c 'printf "need-secret\n" | kinit -S kadmin/changepw@KERBER.TEST needuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "expire.gate" "error" ',"error":"+needchange changepw kinit failed"'
    exit 1
fi
NEEDCPW="$(docker exec -e KRB5_CONFIG=/tmp/expire-krb5.conf "$NAME" klist)"
echo "$NEEDCPW"
echo "$NEEDCPW" | grep -q 'kadmin/changepw'

log "expire.gate" "ok" ',"name_exp":true,"key_expired":true,"pwchange_service":true,"tgs_after_client_expire":true,"service_exp":true,"needchange":true'
exit 0
