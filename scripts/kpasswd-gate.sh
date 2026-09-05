#!/usr/bin/env bash
# MIT kpasswd (RFC 3244) against Rust kadmind UDP 464 + kadmin/changepw.
# Isolated inside the MIT 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

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

# Raw UDP kpasswd: vno 0x0002 / plen != len. MIT schpw.c:60-82 sets
# numresult then goto bailout; dispatch logs com_err and sends no datagram.
kpasswd_raw() {
    local ctn=$1 kind=$2
    docker exec "$ctn" python3 -c '
import socket, struct, sys

def tlv(data, i=0):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + l], i + l

def krb_error(der):
    _, inner, _ = tlv(der)
    _, seqb, _ = tlv(inner)
    i = 0
    fields = {}
    while i < len(seqb):
        t, v, i = tlv(seqb, i)
        n = t & 0x1F
        if t & 0x20 and v:
            _, inner2, _ = tlv(v)
            fields[n] = inner2
        else:
            fields[n] = v
    code = int.from_bytes(fields.get(6, b"\x00"), "big")
    return code, fields.get(11, b""), fields.get(12, b"")

kind = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
if kind == "vno":
    pkt = struct.pack(">HHH", 6, 2, 0)
elif kind == "len":
    pkt = struct.pack(">HHH", 99, 1, 0)
elif kind == "apreq":
    # schpw.c:89 uses `>=` so AP-REQ must leave at least one PRIV byte
    # or MIT goto bailout (no datagram). Junk AP-REQ then chpwfail.
    pkt = struct.pack(">HHH", 11, 1, 4) + b"junk" + b"x"
elif kind == "fill":
    pkt = struct.pack(">HHH", 10, 1, 4) + b"junk"
else:
    raise SystemExit("kind")
s.sendto(pkt, ("127.0.0.1", 464))
try:
    data, _ = s.recvfrom(4096)
except socket.timeout:
    print("timeout")
    raise SystemExit(2)
print("hex=" + data.hex())
print("ap_len=" + str(struct.unpack(">H", data[4:6])[0] if len(data) >= 6 else -1))
if len(data) >= 6 and struct.unpack(">H", data[4:6])[0] == 0:
    code, etext, edata = krb_error(data[6:])
    print("error_code=%d" % code)
    print("e_data_hex=" + edata.hex())
if b"\x00\x06Request contained unknown protocol version number 2" in data:
    print("result=6")
if b"\x00\x01Request length was inconsistent" in data:
    print("result=1")
if b"Failed reading application request" in data:
    print("result=3")
    print("text=autherror")
if b"Request contained unknown protocol version number 2" in data:
    print("text=unknown_version")
if b"Request length was inconsistent" in data:
    print("text=inconsistent_length")
' "$kind"
}

pin_kpasswd_apreq_retransmit() {
    local ctn=$1 label=$2 run OUT rc
    for run in 1 2; do
        echo "---- $label bad AP-REQ $run ----"
        set +e
        OUT="$(kpasswd_raw "$ctn" apreq)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 0 ]
        echo "$OUT" | grep -F 'ap_len=0'
        echo "$OUT" | grep -F 'result=3'
        echo "$OUT" | grep -F 'text=autherror'
        echo "$OUT" | grep -F 'error_code=60'
        echo "$OUT" | grep -F 'e_data_hex=00034661696c65642072656164696e67206170706c69636174696f6e2072657175657374'
    done
}

pin_kpasswd_fill_datagram() {
    local ctn=$1 label=$2 run OUT rc
    for run in 1 2; do
        echo "---- $label fill-datagram AP-REQ $run ----"
        set +e
        OUT="$(kpasswd_raw "$ctn" fill)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        if echo "$OUT" | grep -F 'hex='; then
            echo "$label framed a fill-the-datagram kpasswd AP-REQ" >&2
            exit 1
        fi
    done
}

# MIT schpw.c goto bailout; dispatch logs com_err and sends no framed reply.
pin_kpasswd_raw_rust() {
    local run nlog OUT rc
    for run in 1 2; do
        nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- Rust raw vno $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME" vno)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        if echo "$OUT" | grep -F 'hex='; then
            echo "Rust framed a malformed kpasswd datagram" >&2
            exit 1
        fi
        docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Requested protocol version not supported - while dispatching (udp)'
        nlog="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- Rust raw len $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME" len)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        if echo "$OUT" | grep -F 'hex='; then
            echo "Rust framed a malformed kpasswd datagram" >&2
            exit 1
        fi
        docker exec "$NAME" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Message stream modified - while dispatching (udp)'
    done
}

# MIT schpw.c goto bailout; dispatch logs com_err and sends no framed reply.
pin_kpasswd_raw_mit() {
    local run nlog OUT rc
    for run in 1 2; do
        nlog="$(docker exec "$NAME_MIT" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- MIT raw vno $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME_MIT" vno)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        docker exec "$NAME_MIT" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Requested protocol version not supported - while dispatching (udp)'
        nlog="$(docker exec "$NAME_MIT" sh -c 'wc -l < /tmp/kadmind.log' | tr -d '[:space:]')"
        echo "---- MIT raw len $run ----"
        set +e
        OUT="$(kpasswd_raw "$NAME_MIT" len)"
        rc=$?
        set -e
        echo "$OUT"
        [ "$rc" -eq 2 ]
        echo "$OUT" | grep -F timeout
        docker exec "$NAME_MIT" sh -c "tail -n +$((nlog + 1)) /tmp/kadmind.log" \
            | grep -F 'Message stream modified - while dispatching (udp)'
    done
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

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *
*/admin@KERBER.TEST *
EOF'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    kadmin_q 'cpw -pw rust-kpw user'
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
kadmin_q 'modprinc -allow_tgs_req kadmin/changepw'

echo "==== kpasswd min_life is SOFTERROR ===="
kadmin_q 'addpol -minlife 1h minlife'
kadmin_q 'modprinc -policy minlife user'
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

echo "==== Rust kpasswd raw vno/length (schpw.c:60-82) ===="
pin_kpasswd_raw_rust
echo "==== Rust kpasswd bad AP-REQ retransmit (schpw.c:126-136,110-111) ===="
pin_kpasswd_apreq_retransmit "$NAME" "Rust"
echo "==== Rust kpasswd fill-datagram AP-REQ (schpw.c:89-95) ===="
pin_kpasswd_fill_datagram "$NAME" "Rust"

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
echo "helper_rc=$d2m_rc"
[ "$d2m_rc" -eq 0 ]
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
echo "helper_rc=$d2mnt_rc"
[ "$d2mnt_rc" -eq 0 ]
echo "$D2MNT" | grep -F 'result_code=7'
echo "$D2MNT" | grep -F 'Ticket must be derived from a password'
docker logs "$NAME_MIT" 2>&1 | grep -F 'setpw request from 127.0.0.1 by user@KERBER.TEST for user@KERBER.TEST: Operation requires initial ticket' \
    || docker exec "$NAME_MIT" grep -F 'setpw request from 127.0.0.1 by user@KERBER.TEST for user@KERBER.TEST: Operation requires initial ticket' /tmp/kadmind.log
if docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; printf "e1-should-fail\n" | kinit user@KERBER.TEST'; then
    echo "MIT NT-UNKNOWN targname kpasswd changed the password" >&2
    docker exec "$NAME_MIT" kadmin.local -q 'cpw -pw userpassword user'
    exit 1
fi
echo "==== TGS kpasswd other principal is ACCESSDENIED (MIT) ===="
MIT_EXTRA="$(docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw extra-secret extra' 2>&1)"
echo "$MIT_EXTRA"
echo "$MIT_EXTRA" | grep -F 'Principal "extra@KERBER.TEST" created'
docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2; printf "userpassword\n" | kinit user@KERBER.TEST'
set +e
D2MO="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_d2 KPASSWD_TARGET=extra@KERBER.TEST; /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_d2 KERBER.TEST other-should-fail')"
d2mo_rc=$?
set -e
echo "$D2MO"
echo "helper_rc=$d2mo_rc"
[ "$d2mo_rc" -eq 0 ]
echo "$D2MO" | grep -F 'result_code=5'
echo "$D2MO" | grep -F 'Unauthorized request'
docker exec "$NAME_MIT" kadmin.local -q 'modprinc -allow_tgs_req kadmin/changepw'

echo "==== MIT kpasswd min_life is SOFTERROR ===="
docker exec "$NAME_MIT" kadmin.local -q 'addpol -minlife 1h minlife'
docker exec "$NAME_MIT" kadmin.local -q 'modprinc -policy minlife user'
set +e
MIT_KPMIN="$(docker exec "$NAME_MIT" sh -c 'printf "userpassword\nuser-new\nuser-new\n" | kpasswd user@KERBER.TEST' 2>&1)"
mit_kpmin_rc=$?
set -e
echo "$MIT_KPMIN"
echo "mit_kpasswd_minlife_rc=$mit_kpmin_rc"
echo "$MIT_KPMIN" | grep -F 'Password cannot be changed because it was changed too recently'
if [ "$mit_kpmin_rc" -eq 0 ]; then
    echo "MIT kpasswd min_life succeeded" >&2
    exit 1
fi

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

echo "==== MIT kpasswd raw vno/length (schpw.c:60-82; bailout, no framed reply) ===="
pin_kpasswd_raw_mit
echo "==== MIT kpasswd bad AP-REQ retransmit (schpw.c:126-136,110-111) ===="
pin_kpasswd_apreq_retransmit "$NAME_MIT" "MIT"
echo "==== MIT kpasswd fill-datagram AP-REQ (schpw.c:89-95) ===="
pin_kpasswd_fill_datagram "$NAME_MIT" "MIT"

log "kpasswd.gate" "ok" ',"principal":"user@KERBER.TEST","op":"kpasswd+kinit","softerror":true'
exit 0
