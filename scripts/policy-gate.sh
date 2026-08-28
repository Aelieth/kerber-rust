#!/usr/bin/env bash
# MIT 1.22.2 kadmin policy verbs against Rust kadmind, then MIT kinit lockout.
# Isolated: runs inside the MIT image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-policy-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-policy-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"policy-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "policy.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/policy-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "policy.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/policy-unavailable.log"
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
    log "policy.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
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
    log "policy.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/policy-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_policy
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== MIT kadmin addpol lockme ===="
ADD="$(kadmin_q 'addpol -minlength 8 -minclasses 2 -history 1 -maxfailure 2 lockme')"
echo "$ADD"

echo "==== MIT kadmin getpol lockme ===="
GET="$(kadmin_q 'getpol lockme')"
echo "$GET"
echo "$GET" | grep -q 'Policy: lockme'
echo "$GET" | grep -q 'Minimum password length: 8'
echo "$GET" | grep -qiE 'Maximum password failures.*2|failures before lockout: 2'

echo "==== MIT kadmin listpols ===="
LIST="$(kadmin_q 'listpols')"
echo "$LIST"
echo "$LIST" | grep -q 'lockme'

echo "==== MIT kadmin modpol -minlength 10 lockme ===="
kadmin_q 'modpol -minlength 10 lockme' >/dev/null
GET2="$(kadmin_q 'getpol lockme')"
echo "$GET2"
echo "$GET2" | grep -q 'Minimum password length: 10'
echo "$GET2" | grep -qiE 'Maximum password failures.*2|failures before lockout: 2'

echo "==== MIT kadmin addprinc -policy lockme lockuser ===="
ADDPR="$(kadmin_q 'addprinc -policy lockme -pw lock-secret lockuser')"
echo "$ADDPR"
GETPR="$(kadmin_q 'getprinc lockuser')"
echo "$GETPR"
echo "$GETPR" | grep -q 'Principal: lockuser@KERBER.TEST'
echo "$GETPR" | grep -q 'Policy: lockme'

echo "==== MIT kadmin cpw too-short and reuse ===="
SHORT="$(kadmin_q 'cpw -pw ab lockuser')"
echo "$SHORT"
if ! echo "$SHORT" | grep -qiE 'too short|TOOSHORT'; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "policy.gate" "error" ',"error":"cpw too-short did not assert KADM5_PASS_Q_TOOSHORT"'
    exit 1
fi
REUSE="$(kadmin_q 'cpw -pw lock-secret lockuser')"
echo "$REUSE"
if ! echo "$REUSE" | grep -qiE 'reuse|REUSE|history'; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "policy.gate" "error" ',"error":"cpw reuse did not assert KADM5_PASS_REUSE"'
    exit 1
fi

echo "==== MIT kinit lockuser maxfailure 2 reset then lock ===="
WRONG1="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit lockuser@KERBER.TEST' 2>&1 || true)"
echo "$WRONG1"
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "lock-secret\n" | kinit lockuser@KERBER.TEST'; then
    log "policy.gate" "error" ',"error":"correct kinit after one fail must reset lockout"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
WRONG2="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit lockuser@KERBER.TEST' 2>&1 || true)"
echo "$WRONG2"
echo "$WRONG2" | grep -qiE 'revoked|CLIENT_REVOKED' && {
    log "policy.gate" "error" ',"error":"first fail after reset must not lock"'
    exit 1
}
WRONG3="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit lockuser@KERBER.TEST' 2>&1 || true)"
echo "$WRONG3"
LOCKED="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit lockuser@KERBER.TEST' 2>&1 || true)"
echo "$LOCKED"
echo "$LOCKED" | grep -qiE 'revoked|CLIENT_REVOKED'

echo "==== MIT kadmin cpw minclasses 5 ===="
kadmin_q 'addpol -minlength 8 -minclasses 5 class5' >/dev/null
ADD5="$(kadmin_q 'addprinc -policy class5 -pw "Aa1!aaa " classuser')"
echo "$ADD5"
FOUR="$(kadmin_q 'cpw -pw Aa1!aaaa classuser')"
echo "$FOUR"
if ! echo "$FOUR" | grep -qi 'enough character classes'; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "policy.gate" "error" ',"error":"cpw 4-class did not assert KADM5_PASS_Q_CLASS"'
    exit 1
fi
FIVE="$(kadmin_q 'cpw -pw "Aa1!aaB " classuser')"
echo "$FIVE"
if ! echo "$FIVE" | grep -qi 'password .* changed'; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "policy.gate" "error" ',"error":"cpw 5-class must succeed"'
    exit 1
fi
kadmin_q 'delprinc -force classuser' >/dev/null
kadmin_q 'delpol -force class5' >/dev/null

echo "==== MIT kadmin lockout duration and failcnt interval ===="
kadmin_q 'addpol -minlength 8 -minclasses 1 -history 0 -maxfailure 1 -lockoutduration 2s -failurecountinterval 2s timed' >/dev/null
TGET="$(kadmin_q 'getpol timed')"
echo "$TGET"
echo "$TGET" | grep -q 'Policy: timed'
echo "$TGET" | grep -qiE 'lockout duration: 0 days 00:00:02'
echo "$TGET" | grep -qiE 'failure count reset interval: 0 days 00:00:02'
kadmin_q 'addprinc -policy timed -pw Time-sec1 timeduser' >/dev/null
T1="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit timeduser@KERBER.TEST' 2>&1 || true)"
echo "$T1"
T2="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit timeduser@KERBER.TEST' 2>&1 || true)"
echo "$T2"
echo "$T2" | grep -qiE 'revoked|CLIENT_REVOKED'
sleep 3
if ! docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "Time-sec1\n" | kinit timeduser@KERBER.TEST'; then
    log "policy.gate" "error" ',"error":"elapsed lockout duration must allow kinit"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
I1="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit timeduser@KERBER.TEST' 2>&1 || true)"
echo "$I1"
sleep 3
I2="$(docker exec -e KRB5_CONFIG=/tmp/policy-krb5.conf \
    "$NAME" sh -c 'printf "wrong-password\n" | kinit timeduser@KERBER.TEST' 2>&1 || true)"
echo "$I2"
echo "$I2" | grep -qiE 'revoked|CLIENT_REVOKED' && {
    log "policy.gate" "error" ',"error":"elapsed failcnt interval must not lock on next wrong"'
    exit 1
}
kadmin_q 'delprinc -force timeduser' >/dev/null
kadmin_q 'delpol -force timed' >/dev/null

echo "==== MIT kadmin history depth 2 ===="
kadmin_q 'addpol -minlength 8 -minclasses 2 -history 2 histn' >/dev/null
kadmin_q 'addprinc -policy histn -pw Hist-pw0 histuser' >/dev/null
kadmin_q 'cpw -pw Hist-pw1 histuser' >/dev/null
kadmin_q 'cpw -pw Hist-pw2 histuser' >/dev/null
H0="$(kadmin_q 'cpw -pw Hist-pw0 histuser')"
echo "$H0"
if ! echo "$H0" | grep -qiE 'reuse|REUSE|history'; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "policy.gate" "error" ',"error":"history-2 must reject password 2 changes ago"'
    exit 1
fi
H1="$(kadmin_q 'cpw -pw Hist-pw1 histuser')"
echo "$H1"
if ! echo "$H1" | grep -qiE 'reuse|REUSE|history'; then
    log "policy.gate" "error" ',"error":"history-2 must reject password 1 change ago"'
    exit 1
fi
kadmin_q 'cpw -pw Hist-pw3 histuser' >/dev/null
HOK="$(kadmin_q 'cpw -pw Hist-pw0 histuser')"
echo "$HOK"
if ! echo "$HOK" | grep -qi 'password .* changed'; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "policy.gate" "error" ',"error":"N+1-th password must be reusable"'
    exit 1
fi
kadmin_q 'delprinc -force histuser' >/dev/null
kadmin_q 'delpol -force histn' >/dev/null

echo "==== MIT kadmin delpol lockme ===="
kadmin_q 'delpol -force lockme' >/dev/null
DELGET="$(kadmin_q 'getpol lockme')"
echo "$DELGET"
echo "$DELGET" | grep -qiE 'does not exist|not found|UNK|unknown policy'

log "policy.gate" "ok" ',"policy":"lockme","op":"addpol+getpol+listpols+modpol+cpw-pwqual+lockout-reset+delpol"'
exit 0
