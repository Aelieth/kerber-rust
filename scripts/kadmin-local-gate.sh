#!/usr/bin/env bash
# Rust kadmin.local mutates the dump; MIT kadmin getprinc/listprincs is the oracle.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-local-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kadmin-local-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.local.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb -p krb5-admin --bin krb5-kadmind --bin krb5-kadmin-local

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kdb "$NAME":/tmp/krb5-kdb
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker cp target/debug/krb5-kadmin-local "$NAME":/tmp/krb5-kadmin-local
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kadmind /tmp/krb5-kadmin-local

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
    log "kadmin.local.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

echo "==== Rust kadmin.local addprinc/listprincs/getprinc ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=extra-local \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc extra2'
LIST="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'listprincs')"
echo "$LIST"
echo "$LIST" | grep -q 'extra2@KERBER.TEST'
GET="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc extra2')"
echo "$GET"
echo "$GET" | grep -q 'Principal: extra2@KERBER.TEST'

echo "==== Rust kadmin.local addprinc host/slashhost ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=slash-local \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc host/slashhost'
SLASH="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc host/slashhost')"
echo "$SLASH"
echo "$SLASH" | grep -q 'Principal: host/slashhost@KERBER.TEST'

echo "==== addprinc -randkey / ktadd principals before kadmind ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey randsvc'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey ktone'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey kttwo'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc -requires_preauth extra2'
set +e
UNK="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -bogus nosuch' 2>&1)"
unkrc=$?
set -e
echo "$UNK"
test "$unkrc" -ne 0
echo "$UNK" | grep -qi 'unknown flag'

echo "==== KRB5_ACL_FILE unreadable is a hard error ===="
set +e
ACLERR="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/no-such-acl \
    "$NAME" /tmp/krb5-kadmin-local -q 'listprincs' 2>&1)"
aclrc=$?
set -e
echo "$ACLERR"
test "$aclrc" -ne 0
echo "$ACLERR" | grep -qi 'ACL'

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *e
EOF'

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadmin-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kadmin
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== MIT kadmin getprinc/listprincs extra2 ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'
MITGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra2')"
echo "$MITGET"
echo "$MITGET" | grep -q 'extra2@KERBER.TEST'
MITLIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs extra2*')"
echo "$MITLIST"
echo "$MITLIST" | grep -q 'extra2@KERBER.TEST'

echo "==== MIT kadmin getprinc host/slashhost ===="
MITSLASH="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc host/slashhost')"
echo "$MITSLASH"
echo "$MITSLASH" | grep -q 'Principal: host/slashhost@KERBER.TEST'
echo "$MITSLASH" | grep -qi 'does not exist' && {
    log "kadmin.local.gate" "error" ',"error":"MIT did not find host/slashhost as two components"'
    exit 1
}

echo "==== MIT getprinc randsvc (vno 1) + kinit -k ===="
MITRAND="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc randsvc')"
echo "$MITRAND"
echo "$MITRAND" | grep -q 'randsvc@KERBER.TEST'
echo "$MITRAND" | grep -Eqi 'vno[[:space:]]*1'
echo "$MITGET" | grep -q 'REQUIRES_PRE_AUTH' && {
    echo "extra2 should have been cleared of REQUIRES_PRE_AUTH before kadmind" >&2
    exit 1
}
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -norandkey -k /tmp/rand.keytab randsvc'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kinit -k -t /tmp/rand.keytab randsvc@KERBER.TEST
echo "kinit -k randsvc ok"

echo "==== modprinc +requires_preauth and ktadd merge ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +requires_preauth extra2'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/both.keytab ktone'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/both.keytab kttwo'
KLISTK="$(docker exec "$NAME" klist -k /tmp/both.keytab)"
echo "$KLISTK"
echo "$KLISTK" | grep -q 'ktone@KERBER.TEST'
echo "$KLISTK" | grep -q 'kttwo@KERBER.TEST'

docker exec "$NAME" sh -c 'kill $(pidof krb5-kadmind) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen after restart"'
    exit 1
fi
MITPRE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra2')"
echo "$MITPRE"
echo "$MITPRE" | grep -q 'REQUIRES_PRE_AUTH'
MITKV="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc ktone')"
echo "$MITKV"
echo "$MITKV" | grep -Eqi 'vno[[:space:]]*2'

echo "==== listprincs does not clobber concurrent kadmind create ===="
docker exec "$NAME" sh -c '
  rm -f /tmp/klfifo
  mkfifo /tmp/klfifo
  env KRB5_KDC_DB=/tmp/principal KRB5_KDC_STASH=/tmp/stash \
    /tmp/krb5-kadmin-local </tmp/klfifo >/tmp/kl.out 2>/tmp/kl.err &
  echo $! >/tmp/kl.pid
  exec 3>/tmp/klfifo
  sleep 0.3
  env KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    kadmin -p admin@KERBER.TEST -w adminpassword -q "addprinc -pw race-pw raceprinc"
  echo listprincs >&3
  echo q >&3
  exec 3>&-
  wait "$(cat /tmp/kl.pid)" || true
'
RACE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc raceprinc')"
echo "$RACE"
echo "$RACE" | grep -q 'raceprinc@KERBER.TEST'
echo "$RACE" | grep -qi 'does not exist' && {
    log "kadmin.local.gate" "error" ',"error":"listprincs clobbered concurrent kadmind principal"'
    exit 1
}

echo "==== MIT kadmin.local lockdown oracle ===="
docker exec "$NAME" sh -c '
set -e
kdb5_util create -s -P masterpassword -r KERBER.TEST
kadmin.local -r KERBER.TEST -q "addprinc -randkey lockee@KERBER.TEST"
kadmin.local -r KERBER.TEST -q "modprinc +lockdown_keys lockee@KERBER.TEST"
echo "---- getprinc lockee before ktadd ----"
kadmin.local -r KERBER.TEST -q "getprinc lockee@KERBER.TEST"
kadmin.local -r KERBER.TEST -q "ktadd -k /tmp/mit-lockee.keytab lockee@KERBER.TEST"
echo mit_lockee_ktadd_rc=$?
echo "---- getprinc lockee after ktadd ----"
kadmin.local -r KERBER.TEST -q "getprinc lockee@KERBER.TEST"
kadmin.local -r KERBER.TEST -q "ktadd -k /tmp/mit-krbtgt.keytab krbtgt/KERBER.TEST"
echo mit_krbtgt_ktadd_rc=$?
echo "---- getprinc krbtgt after ktadd ----"
kadmin.local -r KERBER.TEST -q "getprinc krbtgt/KERBER.TEST"
echo "---- klist -k ----"
klist -k /tmp/mit-lockee.keytab
klist -k /tmp/mit-krbtgt.keytab
'
MITL="$(docker exec "$NAME" kadmin.local -r KERBER.TEST -q 'getprinc lockee@KERBER.TEST')"
echo "$MITL"
echo "$MITL" | grep -qi LOCKDOWN
echo "$MITL" | grep -Eqi 'Key: vno[[:space:]]*2'
docker exec "$NAME" test -s /tmp/mit-lockee.keytab
docker exec "$NAME" test -s /tmp/mit-krbtgt.keytab

echo "==== Rust ktadd on +lockdown_keys (test-realm) ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey lockee'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +lockdown_keys lockee'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/lockee.keytab lockee'
LK="$(docker exec "$NAME" klist -k /tmp/lockee.keytab)"
echo "$LK"
echo "$LK" | grep -q 'lockee@KERBER.TEST'
docker exec "$NAME" sh -c 'kill $(pidof krb5-kadmind) 2>/dev/null || true'
sleep 0.3
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen after lockdown ktadd"'
    exit 1
fi
MITLOCK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc lockee')"
echo "$MITLOCK"
echo "$MITLOCK" | grep -qi LOCKDOWN
echo "$MITLOCK" | grep -Eqi 'Key: vno[[:space:]]*2'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kinit -k -t /tmp/lockee.keytab lockee@KERBER.TEST
echo "kinit -k lockee ok"

echo "==== golden dump ktadd lockdown + krbtgt footgun ===="
docker cp tests/traces/kdb/mit-dump-v7.txt "$NAME":/tmp/mit.dump
docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kdb load /tmp/mit.dump
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey gldlock'
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +lockdown_keys gldlock'
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/gld.locktab gldlock'
GLD="$(docker exec "$NAME" klist -k /tmp/gld.locktab)"
echo "$GLD"
echo "$GLD" | grep -q 'gldlock@KERBER.TEST'
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/gld-krbtgt.keytab krbtgt/KERBER.TEST'
GTGT="$(docker exec "$NAME" klist -k /tmp/gld-krbtgt.keytab)"
echo "$GTGT"
echo "$GTGT" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'

log "kadmin.local.gate" "ok" ',"principal":"extra2@KERBER.TEST,host/slashhost@KERBER.TEST,randsvc,ktone,kttwo,raceprinc,lockee,gldlock,krbtgt"'
exit 0
