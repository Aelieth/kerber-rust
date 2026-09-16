#!/usr/bin/env bash
# MIT kadmind kpasswd cells (RFC 3244). Attaches to the rust KEEP container.
# Isolated inside the MIT 1.22.2 image; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc krb5-kadmind krb5-kpasswd krb5-kadmin-local krb5-kinit

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kpasswd-gate"
NAME_MIT="kerber-rust-kpasswd-mit-pol"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kpasswd-gate}"
mkdir -p "$SCRATCH"

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

need_image

NAME="${KERBER_SHELL:-$NAME}"
if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]; then
    die "kpasswd-mit-gate needs rust container (run kpasswd-rust-gate.sh with KERBER_KPASSWD_KEEP=1 first)"
fi
kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== MIT kadmind policy rejection is SOFTERROR ===="
_saved=$NAME
stock_mit_kdc
NAME_MIT=$NAME
NAME=$_saved
if [ "${KERBER_LIVE:-}" = 1 ]; then
    mit_conf_snapshot "$NAME_MIT"
    register_cleanup "mit_conf_restore '$NAME_MIT'"
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
wait_gone_in "$NAME_MIT" 88 || die "MIT krb5kdc still bound :88 after kill"
docker exec "$NAME_MIT" krb5kdc
if ! wait_port_in "$NAME_MIT" 88; then
    log "kpasswd.gate" "error" ',"error":"MIT krb5kdc did not listen after log restart"'
    exit 1
fi
docker exec -d "$NAME_MIT" sh -c 'kadmind -nofork >/tmp/kadmind.log 2>&1'
if ! wait_port_in "$NAME_MIT" 464; then
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
echo "==== MIT kpasswd min_life is result_code=4 ===="
docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_kpw4; printf "userpassword\n" | kinit user@KERBER.TEST'
set +e
MIT_KPMIN4="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_kpw4 KPASSWD_AS_PASSWORD=userpassword; /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpw4 KERBER.TEST user-new')"
mit_kpmin4_rc=$?
set -e
echo "$MIT_KPMIN4"
echo "helper_rc=$mit_kpmin4_rc"
[ "$mit_kpmin4_rc" -eq 0 ]
echo "$MIT_KPMIN4" | grep -F 'result_code=4'

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
echo "==== MIT kpasswd policy is result_code=4 ===="
docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_kpw4; printf "userpassword\n" | kinit user@KERBER.TEST'
set +e
MITPOL4="$(docker exec "$NAME_MIT" sh -c 'export KRB5CCNAME=FILE:/tmp/krb5cc_kpw4 KPASSWD_AS_PASSWORD=userpassword; /tmp/kpasswd-tgs-client FILE:/tmp/krb5cc_kpw4 KERBER.TEST abc')"
mitpol4_rc=$?
set -e
echo "$MITPOL4"
echo "helper_rc=$mitpol4_rc"
[ "$mitpol4_rc" -eq 0 ]
echo "$MITPOL4" | grep -F 'result_code=4'

echo "==== MIT kpasswd raw vno/length (schpw.c:60-82; bailout, no framed reply) ===="
pin_kpasswd_raw_mit
echo "==== MIT kpasswd bad AP-REQ retransmit (schpw.c:126-136,110-111) ===="
pin_kpasswd_apreq_retransmit "$NAME_MIT" "MIT"
echo "==== MIT kpasswd fill-datagram AP-REQ (schpw.c:89-95) ===="
pin_kpasswd_fill_datagram "$NAME_MIT" "MIT"

# W1-Z Z1b.2: kinit's expired-password flow order (gic_pwd.c:205-240) against
# the MIT KDC + MIT kadmind 464: the kadmin/changepw AS runs *first* with the
# typed password, so a wrong password is "Password incorrect" and never
# prompts; the right password changes it and gets a TGT. MIT kinit is the
# oracle, Rust krb5-kinit the subject, same stdin script for both.
echo "==== Z1b.2 kinit KEY_EXP flow order (gic_pwd.c:205-240): MIT kinit vs Rust krb5-kinit against the MIT KDC ===="
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME_MIT":/tmp/krb5-kinit
docker exec "$NAME_MIT" chmod +x /tmp/krb5-kinit
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw exp-old -pwexpire 2020-01-01 z1bmit' >/dev/null
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw exp-old -pwexpire 2020-01-01 z1brust' >/dev/null
docker exec "$NAME_MIT" kadmin.local -q 'getprinc z1brust' | grep -E '^Password expiration date: ' | grep -qv never
z1b2_check() {
    local leg=$1 out=$2 rc=$3 want_rc=$4
    echo "$leg (rc=$rc):"
    echo "$out" | sed "s/^/  $leg| /"
    if [ "$rc" -ne "$want_rc" ]; then
        echo "$leg: rc $rc want $want_rc" >&2
        exit 1
    fi
}
echo "---- wrong password on an expired principal: the password failure, no new-password prompt ----"
set +e
MIT_Z1B_WRONG="$(docker exec "$NAME_MIT" sh -c 'printf "not-it\nexp-new\nexp-new\n" | kinit -c /tmp/cc_z1b_mit_wrong z1bmit@KERBER.TEST' 2>&1)"
mit_rc=$?
RUST_Z1B_WRONG="$(docker exec -e KRB5_PASSWORD=not-it "$NAME_MIT" sh -c 'printf "exp-new\nexp-new\n" | /tmp/krb5-kinit -c /tmp/cc_z1b_rust_wrong z1brust@KERBER.TEST' 2>&1)"
rust_rc=$?
set -e
z1b2_check mit "$MIT_Z1B_WRONG" "$mit_rc" 1
z1b2_check rust "$RUST_Z1B_WRONG" "$rust_rc" 1
echo "$MIT_Z1B_WRONG" | grep -qF 'kinit: Password incorrect while getting initial credentials' || { echo "MIT kinit did not report the password failure" >&2; exit 1; }
echo "$RUST_Z1B_WRONG" | grep -qF 'kinit: Password incorrect while getting initial credentials' || { echo "Rust krb5-kinit did not report the password failure" >&2; exit 1; }
if echo "$MIT_Z1B_WRONG$RUST_Z1B_WRONG" | grep -q 'Enter new password'; then
    echo "a kinit prompted for a new password before the changepw AS" >&2
    exit 1
fi
docker exec "$NAME_MIT" kadmin.local -q 'getprinc z1brust' | grep -qE '^Key: vno 1, ' || { echo "Rust wrong-password run changed the key" >&2; exit 1; }
echo "---- right password: changepw AS, then the prompts, the change and a TGT ----"
MIT_Z1B_OK="$(docker exec "$NAME_MIT" sh -c 'printf "exp-old\nexp-new\nexp-new\n" | kinit -c /tmp/cc_z1b_mit_ok z1bmit@KERBER.TEST' 2>&1)" \
    || { echo "$MIT_Z1B_OK"; echo "MIT kinit KEY_EXP change failed" >&2; exit 1; }
RUST_Z1B_OK="$(docker exec -e KRB5_PASSWORD=exp-old "$NAME_MIT" sh -c 'printf "exp-new\nexp-new\n" | /tmp/krb5-kinit -c /tmp/cc_z1b_rust_ok z1brust@KERBER.TEST' 2>&1)" \
    || { echo "$RUST_Z1B_OK"; echo "Rust krb5-kinit KEY_EXP change failed" >&2; exit 1; }
z1b2_check mit "$MIT_Z1B_OK" 0 0
z1b2_check rust "$RUST_Z1B_OK" 0 0
echo "$MIT_Z1B_OK" | grep -qF 'Password expired.  You must change it now.'
echo "$RUST_Z1B_OK" | grep -qF 'Password expired.  You must change it now.'
echo "$RUST_Z1B_OK" | grep -qF 'Enter new password'
docker exec "$NAME_MIT" klist -c /tmp/cc_z1b_mit_ok | grep -qF 'krbtgt/KERBER.TEST@KERBER.TEST'
docker exec "$NAME_MIT" klist -c /tmp/cc_z1b_rust_ok | grep -qF 'krbtgt/KERBER.TEST@KERBER.TEST'
docker exec "$NAME_MIT" kadmin.local -q 'getprinc z1brust' | grep -qE '^Key: vno 2, ' || { echo "Rust change did not bump the kvno" >&2; exit 1; }
docker exec "$NAME_MIT" kadmin.local -q 'getprinc z1bmit' | grep -qE '^Key: vno 2, ' || { echo "MIT change did not bump the kvno" >&2; exit 1; }
echo "MIT_z1b2_keyexp_order"
echo "RUST_z1b2_keyexp_order"

echo "==== Z7.2 kpasswd stamps kadmind@REALM (ovsec_kadmd.c:446) ===="
# Fresh principals: user@ already has min_life leftover from earlier cells.
z72_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
kadmin_q 'addprinc -pw z72old z72kpw' | grep -F 'Principal "z72kpw@KERBER.TEST" created.'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw z72old z72kpw' >/dev/null
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "z72old\nz72new\nz72new\n" | kpasswd z72kpw@KERBER.TEST'
docker exec "$NAME_MIT" sh -c 'printf "z72old\nz72new\nz72new\n" | kpasswd z72kpw@KERBER.TEST'
R72="$(kadmin_q 'getprinc z72kpw')"
M72="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc z72kpw')"
echo "$R72"
echo "$M72"
R72MOD="$(echo "$R72" | z72_mod)"
M72MOD="$(echo "$M72" | z72_mod)"
echo "rust modifier=$R72MOD"
echo "mit modifier=$M72MOD"
[ "$R72MOD" = "kadmind@KERBER.TEST" ] || {
    echo "Rust kpasswd modifier is not kadmind@KERBER.TEST: $R72" >&2
    exit 1
}
[ "$M72MOD" = "kadmind@KERBER.TEST" ] || {
    echo "MIT kpasswd modifier is not kadmind@KERBER.TEST: $M72" >&2
    exit 1
}
[ "$R72MOD" = "$M72MOD" ] || {
    echo "Z7.2 kpasswd modifier differs: rust=$R72MOD mit=$M72MOD" >&2
    exit 1
}

echo "==== Z8.1 kpasswd reloads after kadmin.local (write_store house rule) ===="
# kadmind is already up. A local addprinc must survive the next kpasswd save.
kadmin_q 'addprinc -pw z8old z8kpw' | grep -F 'Principal "z8kpw@KERBER.TEST" created.'
docker exec "$NAME_MIT" kadmin -p admin/admin -w adminpassword \
    -q 'addprinc -pw z8old z8kpw' | grep -F 'Principal "z8kpw@KERBER.TEST" created.'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=z8x-secret \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc z8x' \
    | grep -F 'Principal "z8x@KERBER.TEST" created.'
docker exec "$NAME_MIT" kadmin.local -q 'addprinc -pw z8x-secret z8x' \
    | grep -F 'Principal "z8x@KERBER.TEST" created.'
docker exec -e KRB5_CONFIG=/tmp/kpasswd-krb5.conf \
    "$NAME" sh -c 'printf "z8old\nz8new\nz8new\n" | kpasswd z8kpw@KERBER.TEST'
docker exec "$NAME_MIT" sh -c 'printf "z8old\nz8new\nz8new\n" | kpasswd z8kpw@KERBER.TEST'
R8X="$(kadmin_q 'getprinc z8x')"
M8X="$(docker exec "$NAME_MIT" kadmin.local -q 'getprinc z8x')"
echo "$R8X"
echo "$M8X"
echo "$R8X" | grep -F 'Principal: z8x@KERBER.TEST'
echo "$M8X" | grep -F 'Principal: z8x@KERBER.TEST'
echo "MIT_z81_local_princ_survives_kpasswd"
echo "RUST_z81_local_princ_survives_kpasswd"

log "kpasswd.gate" "ok" ',"principal":"user@KERBER.TEST","op":"kpasswd+kinit","softerror":true'
exit 0
