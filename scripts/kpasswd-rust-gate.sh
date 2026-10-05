#!/usr/bin/env bash
# Rust kadmind kpasswd cells (RFC 3244). KEEP-attach for the MIT half.
# Isolated inside the MIT 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/kpasswd-common.sh"
need_bins krb5-kdc krb5-kadmind krb5-kpasswd krb5-kadmin-local krb5-kinit

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kpasswd-gate"
NAME_MIT="kerber-rust-kpasswd-mit-pol"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"

if ! command -v docker >/dev/null 2>&1; then
    log "kpasswd.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

if [ -z "${KERBER_SHELL:-}" ] && [ "${KERBER_KPASSWD_KEEP:-}" = 1 ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --hostname testhost.kerber.test --entrypoint sleep "$IMAGE" 3600 >/dev/null
    json_log_on "$NAME"
    KERBER_SHELL="$NAME"
    export KERBER_SHELL
fi
if [ -z "${KERBER_SHELL:-}" ]; then
    docker rm -f "$NAME" "$NAME_MIT" >/dev/null 2>&1 || true
fi
if [ "${KERBER_KPASSWD_KEEP:-}" != 1 ]; then
    register_cleanup "docker rm -f '$NAME' '$NAME_MIT' >/dev/null 2>&1 || true"
fi
shell_container

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpasswd" "$NAME":/tmp/krb5-kpasswd
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker cp "$ROOT/scripts/oracle/kpasswd-tgs-client.c" "$NAME":/tmp/kpasswd-tgs-client.c
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind /tmp/krb5-kpasswd /tmp/krb5-kadmin-local
mit_oracle_cc "$NAME" /tmp/kpasswd-tgs-client /tmp/kpasswd-tgs-client.c krb5

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'

if ! wait_log "$NAME" /tmp/kdc.log '^listening '; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kpasswd.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *
*/admin@KERBER.TEST *
EOF'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
if ! wait_log "$NAME" /tmp/kadmind.log '^kpasswd '; then
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
    "$NAME" /tmp/krb5-kpasswd user@KERBER.TEST
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

KADMIN_Q_CONF=/tmp/kpasswd-krb5.conf

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
kadmin_q_ok kadmin_q 'modprinc +allow_tgs_req kadmin/changepw'
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
set +e
D2R="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpasswd KERBER.TEST d2-should-fail)"
d2r_rc=$?
set -e
echo "$D2R"
echo "helper_rc=$d2r_rc"
[ "$d2r_rc" -eq 0 ]
echo "$D2R" | grep -F 'result_code=7'
echo "$D2R" | grep -F 'Ticket must be derived from a password'
docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" | grep -F 'chpw request from 127.0.0.1 for user@KERBER.TEST: Operation requires initial ticket'
if docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "d2-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "TGS kpasswd changed the password" >&2
    exit 1
fi
echo "==== TGS kpasswd NT-UNKNOWN targname still INITIAL (Rust) ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
set +e
D2NT="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KPASSWD_TARGNAME_TYPE=0 \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpasswd KERBER.TEST e1-should-fail)"
d2nt_rc=$?
set -e
echo "$D2NT"
echo "helper_rc=$d2nt_rc"
[ "$d2nt_rc" -eq 0 ]
echo "$D2NT" | grep -F 'result_code=7'
echo "$D2NT" | grep -F 'Ticket must be derived from a password'
docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" | grep -F 'setpw request from 127.0.0.1 by user@KERBER.TEST for user@KERBER.TEST: Operation requires initial ticket'
if docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "e1-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "NT-UNKNOWN targname kpasswd changed the password" >&2
    kadmin_q_ok kadmin_q 'cpw -pw rust-kpw user'
    exit 1
fi
echo "==== TGS kpasswd other principal is ACCESSDENIED (Rust) ===="
EXTRA_ADD="$(kadmin_q 'addprinc -pw extra-secret extra')"
echo "$EXTRA_ADD"
echo "$EXTRA_ADD" | grep -F 'Principal "extra@KERBER.TEST" created'
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
set +e
D2O="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KPASSWD_TARGET=extra@KERBER.TEST \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpasswd KERBER.TEST other-should-fail)"
d2o_rc=$?
set -e
echo "$D2O"
echo "helper_rc=$d2o_rc"
[ "$d2o_rc" -eq 0 ]
echo "$D2O" | grep -F 'result_code=5'
echo "$D2O" | grep -F 'Unauthorized request'
kadmin_q_ok kadmin_q 'modprinc -allow_tgs_req kadmin/changepw'

echo "==== kpasswd min_life is SOFTERROR ===="
kadmin_q_ok kadmin_q 'addpol -minlife 1h minlife'
kadmin_q_ok kadmin_q 'modprinc -policy minlife user'
set +e
KPMIN="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf "$NAME" \
    sh -c 'printf "rust-kpw\nrust-kpw2\nrust-kpw2\n" | kpasswd user@KERBER.TEST' 2>&1)"
kpmin_rc=$?
set -e
echo "$KPMIN"
echo "kpasswd_minlife_rc=$kpmin_rc"
echo "$KPMIN" | grep -F 'Password cannot be changed because it was changed too recently'
if [ "$kpmin_rc" -eq 0 ]; then
    echo "kpasswd min_life succeeded" >&2
    exit 1
fi
echo "==== kpasswd min_life is result_code=4 (Rust) ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_kpw4 \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
set +e
KPMIN4="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_kpw4 -e KPASSWD_AS_PASSWORD=rust-kpw \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpw4 KERBER.TEST rust-kpw2)"
kpmin4_rc=$?
set -e
echo "$KPMIN4"
echo "helper_rc=$kpmin4_rc"
[ "$kpmin4_rc" -eq 0 ]
echo "$KPMIN4" | grep -F 'result_code=4'

echo "==== Rust kadmind policy rejection is SOFTERROR ===="
kadmin_q_ok kadmin_q 'addpol -minlength 8 short8'
kadmin_q_ok kadmin_q 'modprinc -policy short8 user'
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
echo "==== kpasswd policy is result_code=4 (Rust) ===="
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_kpw4 \
    "$NAME" sh -c 'printf "rust-kpw\n" | kinit user@KERBER.TEST'
set +e
POL4="$(docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    -e KRB5CCNAME=FILE:/tmp/krb5cc_kpw4 -e KPASSWD_AS_PASSWORD=rust-kpw \
    "$NAME" /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpw4 KERBER.TEST abc)"
pol4_rc=$?
set -e
echo "$POL4"
echo "helper_rc=$pol4_rc"
[ "$pol4_rc" -eq 0 ]
echo "$POL4" | grep -F 'result_code=4'
docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" | grep -q 'chpw request'

echo "==== Rust kpasswd raw vno/length (schpw.c:60-82) ===="
pin_kpasswd_raw_rust
echo "==== Rust kpasswd bad AP-REQ retransmit (schpw.c:126-136,110-111) ===="
pin_kpasswd_apreq_retransmit "$NAME" "Rust"
echo "==== Rust kpasswd fill-datagram AP-REQ (schpw.c:89-95) ===="
pin_kpasswd_fill_datagram "$NAME" "Rust"

log "kpasswd.gate" "ok" ',"principal":"user@KERBER.TEST","op":"kpasswd-rust"'
exit 0
