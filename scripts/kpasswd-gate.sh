#!/usr/bin/env bash
# MIT kpasswd (RFC 3244) against Rust kadmind UDP 464 + kadmin/changepw.
# Isolated inside the MIT 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kpasswd-gate"
NAME_MIT="kerber-rust-kpasswd-mit-pol"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kpasswd-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kpasswd-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kpasswd.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kadmind --bin krb5-kpasswd

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kadmind "$NAME":/tmp/krb5-kadmind
docker cp target/debug/krb5-kpasswd "$NAME":/tmp/krb5-kpasswd
docker cp "$ROOT/scripts/kpasswd-tgs-client.c" "$NAME":/tmp/kpasswd-tgs-client.c
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind /tmp/krb5-kpasswd
if ! docker exec "$NAME" cc -o /tmp/kpasswd-tgs-client /tmp/kpasswd-tgs-client.c -lkrb5; then
    log "kpasswd.gate" "error" ',"error":"cc kpasswd-tgs-client failed"'
    exit 1
fi

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
    log "kpasswd.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^kpasswd ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "kpasswd.gate" "error" ',"error":"kpasswd 464 did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kpasswd-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kpasswd
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
        kpasswd_server = 127.0.0.1
    }
EOF'

echo "==== MIT kvno kadmin/changepw with TGT against Rust KDC (must refuse) ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
for run in 1 2; do
    echo "---- changepw run $run ----"
    set +e
    KVNO="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
        "$NAME" kvno kadmin/changepw@KERBER.TEST 2>&1)"
    kv_rc=$?
    set -e
    echo "$KVNO"
    if [ "$kv_rc" -eq 0 ]; then
        echo "kvno changepw rc=0 (want refuse)" >&2
        docker exec "$NAME" cat /tmp/kdc.log >&2 || true
        log "kpasswd.gate" "error" ',"error":"kvno kadmin/changepw issued from TGT"'
        exit 1
    fi
    echo "$KVNO" | grep -F 'KDC policy rejects request while getting credentials for kadmin/changepw@KERBER.TEST'
done
for run in 1 2; do
    echo "---- admin run $run ----"
    set +e
    KVNO="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
        "$NAME" kvno kadmin/admin@KERBER.TEST 2>&1)"
    kv_rc=$?
    set -e
    echo "$KVNO"
    if [ "$kv_rc" -eq 0 ]; then
        echo "kvno admin rc=0 (want refuse)" >&2
        docker exec "$NAME" cat /tmp/kdc.log >&2 || true
        log "kpasswd.gate" "error" ',"error":"kvno kadmin/admin issued from TGT"'
        exit 1
    fi
    echo "$KVNO" | grep -F 'KDC policy rejects request while getting credentials for kadmin/admin@KERBER.TEST'
done
docker exec "$NAME" grep -F '"code":12,"e_text":"TGT BASED NOT ALLOWED"' /tmp/kdc.log

echo "==== MIT kpasswd once ===="
set +e
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\nkpasswd-one\nkpasswd-one\n" | kpasswd user@KERBER.TEST'
kp1=$?
set -e
if [ "$kp1" -ne 0 ]; then
    echo "==== kadmind.log ===="
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    echo "==== kdc.log ===="
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kpasswd.gate" "error" ',"error":"kpasswd once failed"'
    exit 1
fi
echo "==== kinit kpasswd-one ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-one\n" | kinit user@KERBER.TEST'
KLIST1="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" klist)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'user@KERBER.TEST'

echo "==== old password must fail ===="
set +e
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
old_rc=$?
set -e
if [ "$old_rc" -eq 0 ]; then
    log "kpasswd.gate" "error" ',"error":"old password still kinit-able"'
    exit 1
fi

echo "==== MIT kpasswd twice ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-one\nkpasswd-two\nkpasswd-two\n" | kpasswd user@KERBER.TEST'
echo "==== kinit kpasswd-two ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-two\n" | kinit user@KERBER.TEST'
KLIST2="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'user@KERBER.TEST'

echo "==== Rust kpasswd vs Rust kadmind ===="
docker exec -e KRB5_PASSWORD=kpasswd-two -e KRB5_NEW_PASSWORD=rust-kpw \
    "$NAME" /tmp/krb5-kpasswd 127.0.0.1 user@KERBER.TEST
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
KLIST3="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" klist)"
echo "$KLIST3"
echo "$KLIST3" | grep -q 'user@KERBER.TEST'
set +e
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "kpasswd-two\n" | kinit user@KERBER.TEST'
old2=$?
set -e
if [ "$old2" -eq 0 ]; then
    log "kpasswd.gate" "error" ',"error":"rust kpasswd old password still works"'
    exit 1
fi

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== getprinc kadmin/changepw and kadmin/admin ===="
CPWGET="$(kadmin_q 'getprinc kadmin/changepw')"
echo "$CPWGET"
echo "$CPWGET" | grep -F 'DISALLOW_TGT_BASED'
echo "$CPWGET" | grep -F 'PWCHANGE_SERVICE'
echo "$CPWGET" | grep -F 'LOCKDOWN_KEYS'
ADMGET="$(kadmin_q 'getprinc kadmin/admin')"
echo "$ADMGET"
echo "$ADMGET" | grep -F 'DISALLOW_TGT_BASED'
echo "$ADMGET" | grep -F 'LOCKDOWN_KEYS'
if echo "$ADMGET" | grep -F 'PWCHANGE_SERVICE'; then
    echo "kadmin/admin must not carry PWCHANGE_SERVICE" >&2
    exit 1
fi

echo "==== ktadd -norandkey kadmin/changepw is extract-keys ===="
KTN="$(kadmin_q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw')"
echo "$KTN"
echo "$KTN" | grep -F 'extract-keys'

echo "==== TGS kpasswd self-change is INITIAL_FLAG_NEEDED (Rust) ===="
kadmin_q 'modprinc +allow_tgs_req kadmin/changepw'
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
set +e
D2R="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpasswd KERBER.TEST d2-should-fail)"
d2r_rc=$?
set -e
echo "$D2R"
echo "$D2R" | grep -F 'result_code=7'
echo "$D2R" | grep -F 'Ticket must be derived from a password'
docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" | grep -F 'Ticket must be derived from a password'
if docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "d2-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "TGS kpasswd changed the password" >&2
    exit 1
fi
echo "==== TGS kpasswd NT-UNKNOWN targname still INITIAL (Rust) ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
set +e
D2NT="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KPASSWD_TARGNAME_TYPE=0 \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpasswd KERBER.TEST e1-should-fail)"
d2nt_rc=$?
set -e
echo "$D2NT"
echo "$D2NT" | grep -F 'result_code=7'
echo "$D2NT" | grep -F 'Ticket must be derived from a password'
if docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "e1-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "NT-UNKNOWN targname kpasswd changed the password" >&2
    kadmin_q 'cpw -pw rust-kpw user'
    exit 1
fi
kadmin_q 'modprinc -allow_tgs_req kadmin/changepw'

echo "==== Rust kadmind policy rejection is SOFTERROR ===="
kadmin_q 'addpol -minlength 8 short8'
kadmin_q 'modprinc -policy short8 user'
nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
set +e
POL="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" \
    sh -c 'printf "rust-kpw\nabc\nabc\n" | kpasswd user@KERBER.TEST' 2>&1)"
pol_rc=$?
set -e
echo "$POL"
if [ "$pol_rc" -ne 2 ]; then
    echo "Rust policy kpasswd rc=$pol_rc want 2" >&2
    docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" >&2 || true
    log "kpasswd.gate" "error" ',"error":"policy rejection did not return rc 2"'
    exit 1
fi
echo "$POL" | grep -qi 'Password change rejected'
echo "$POL" | grep -F 'min_length 8'
docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" | grep -q 'chpw request'

echo "==== MIT kadmind policy rejection is SOFTERROR ===="
docker run -d --name "$NAME_MIT" "$IMAGE" >/dev/null
ok=0
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME_MIT" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    docker logs "$NAME_MIT" >&2 || true
    log "kpasswd.gate" "error" ',"error":"MIT harness did not become ready"'
    exit 1
fi
echo "==== MIT krb5kdc FILE log ===="
docker exec "$NAME_MIT" sh -c 'sed -i "s|kdc = STDERR|kdc = FILE:/tmp/krb5kdc.log|" /etc/krb5.conf'
docker exec "$NAME_MIT" sh -c 'sed -i "s|admin_server = STDERR|admin_server = FILE:/tmp/kadmind.log|" /etc/krb5.conf'
docker exec "$NAME_MIT" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5kdc" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
sleep 0.4
docker exec "$NAME_MIT" krb5kdc
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kpasswd.gate" "error" ',"error":"MIT krb5kdc did not listen after log restart"'
    exit 1
fi
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME_MIT" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',464),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kpasswd.gate" "error" ',"error":"MIT kadmind 464 did not listen"'
    exit 1
fi
echo "==== MIT kvno kadmin/changepw with TGT against MIT KDC (must refuse) ===="
docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d1; printf "userpassword\n" | kinit user@KERBER.TEST'
for run in 1 2; do
    echo "---- MIT changepw run $run ----"
    set +e
    KVNO="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d1; kvno kadmin/changepw@KERBER.TEST' 2>&1)"
    kv_rc=$?
    set -e
    echo "$KVNO"
    if [ "$kv_rc" -eq 0 ]; then
        echo "MIT kvno changepw rc=0 (want refuse)" >&2
        log "kpasswd.gate" "error" ',"error":"MIT kvno kadmin/changepw issued from TGT"'
        exit 1
    fi
    echo "$KVNO" | grep -F 'KDC policy rejects request while getting credentials for kadmin/changepw@KERBER.TEST'
done
for run in 1 2; do
    echo "---- MIT admin run $run ----"
    set +e
    KVNO="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d1; kvno kadmin/admin@KERBER.TEST' 2>&1)"
    kv_rc=$?
    set -e
    echo "$KVNO"
    if [ "$kv_rc" -eq 0 ]; then
        echo "MIT kvno admin rc=0 (want refuse)" >&2
        log "kpasswd.gate" "error" ',"error":"MIT kvno kadmin/admin issued from TGT"'
        exit 1
    fi
    echo "$KVNO" | grep -F 'KDC policy rejects request while getting credentials for kadmin/admin@KERBER.TEST'
done
docker exec "$NAME_MIT" grep -F 'TGT BASED NOT ALLOWED' /tmp/krb5kdc.log

echo "==== MIT getprinc kadmin/changepw and kadmin/admin ===="
MITCPW="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc kadmin/changepw')"
echo "$MITCPW"
echo "$MITCPW" | grep -F 'DISALLOW_TGT_BASED'
echo "$MITCPW" | grep -F 'PWCHANGE_SERVICE'
echo "$MITCPW" | grep -F 'LOCKDOWN_KEYS'
MITADM="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc kadmin/admin')"
echo "$MITADM"
echo "$MITADM" | grep -F 'DISALLOW_TGT_BASED'
echo "$MITADM" | grep -F 'LOCKDOWN_KEYS'

echo "==== MIT ktadd -norandkey kadmin/changepw is extract-keys ===="
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw adminpassword admin/admin' >/dev/null
MITKT="$(docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword -q 'ktadd -norandkey -k /tmp/changepw.keytab kadmin/changepw' 2>&1 || true)"
echo "$MITKT"
echo "$MITKT" | grep -F 'extract-keys'

echo "==== TGS kpasswd self-change is INITIAL_FLAG_NEEDED (MIT) ===="
docker exec "$NAME_MIT" kadmin.local -q 'modprinc +allow_tgs_req kadmin/changepw'
docker cp "$ROOT/scripts/kpasswd-tgs-client.c" "$NAME_MIT":/tmp/kpasswd-tgs-client.c
if ! docker exec "$NAME_MIT" cc -o /tmp/kpasswd-tgs-client /tmp/kpasswd-tgs-client.c -lkrb5; then
    log "kpasswd.gate" "error" ',"error":"cc MIT kpasswd-tgs-client failed"'
    exit 1
fi
docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; printf "userpassword\n" | kinit user@KERBER.TEST'
set +e
D2M="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_d2 KERBER.TEST d2-should-fail')"
d2m_rc=$?
set -e
echo "$D2M"
echo "$D2M" | grep -F 'result_code=7'
echo "$D2M" | grep -F 'Ticket must be derived from a password'
echo "==== MIT kadmind.log ===="
docker exec "$NAME_MIT" sh -c 'cat /tmp/kadmind.log 2>/dev/null || true'
docker logs "$NAME_MIT" 2>&1 | grep -F 'chpw request from 127.0.0.1 for user@KERBER.TEST: Operation requires initial ticket' \
    || docker exec "$NAME_MIT" grep -F 'chpw request from 127.0.0.1 for user@KERBER.TEST: Operation requires initial ticket' /tmp/kadmind.log
if docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; printf "d2-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "MIT TGS kpasswd changed the password" >&2
    exit 1
fi
echo "==== TGS kpasswd NT-UNKNOWN targname still INITIAL (MIT) ===="
docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; printf "userpassword\n" | kinit user@KERBER.TEST'
set +e
D2MNT="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2 KPASSWD_TARGNAME_TYPE=0; /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_d2 KERBER.TEST e1-should-fail')"
d2mnt_rc=$?
set -e
echo "$D2MNT"
echo "$D2MNT" | grep -F 'result_code=7'
echo "$D2MNT" | grep -F 'Ticket must be derived from a password'
if docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; printf "e1-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "MIT NT-UNKNOWN targname kpasswd changed the password" >&2
    docker exec "$NAME_MIT" kadmin.local -q 'cpw -pw userpassword user'
    exit 1
fi
docker exec "$NAME_MIT" kadmin.local -q 'modprinc -allow_tgs_req kadmin/changepw'

docker exec "$NAME_MIT" kadmin.local -q 'addpol -minlength 8 short8'
docker exec "$NAME_MIT" kadmin.local -q 'modprinc -policy short8 user'
set +e
MITPOL="$(docker exec "$NAME_MIT" sh -c 'printf "userpassword\nabc\nabc\n" | kpasswd user@KERBER.TEST' 2>&1)"
mit_rc=$?
set -e
echo "$MITPOL"
if [ "$mit_rc" -ne 2 ]; then
    echo "MIT policy kpasswd rc=$mit_rc want 2" >&2
    log "kpasswd.gate" "error" ',"error":"MIT policy rejection did not return rc 2"'
    exit 1
fi
echo "$MITPOL" | grep -qi 'Password change rejected'
echo "$MITPOL" | grep -F 'New password is too short'

log "kpasswd.gate" "ok" ',"principal":"user@KERBER.TEST","op":"kpasswd+kinit","softerror":true'
exit 0
