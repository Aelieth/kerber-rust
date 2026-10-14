#!/usr/bin/env bash
# MIT 1.22.2 krb5kdc with its otp module and a stdlib RADIUS stub (Access-Accept for one code), then MIT kinit -T and the
# Rust kinit against it, cell for cell: the right code, a wrong code (no password fallback), end of file at the prompt with
# SPAKE and encrypted challenge offered, the password path with require_auth, a bad [otp]. An LD_PRELOAD shim in krb5kdc
# reads the clients' FAST requests (key usage 51) and the nonce each sends back (usage 45).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/proc-common.sh"
. "$ROOT/scripts/lib/otp-common.sh"
need_bins krb5-kinit

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-otp-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "otp.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

register_cleanup otp_stop
shell_container
otp_stage otp-radius-stub.py
mit_oracle_brand "$NAME" /usr/sbin/krb5kdc
mit_oracle_brand "$NAME" /usr/bin/kinit

PROMPT='Enter OTP Token Value: \n'
ARMOR=(-T "$OTP_DIR/armor.cc")
KQ=(mit_kadmin_local -e KRB5_CONFIG="$OTP_DIR/krb5.conf" -e KRB5_KDC_PROFILE="$OTP_DIR/kdc.conf" "$NAME" --)
HINT='fastresp types=136,19,141,151,138,133,137 pa141=30318024{nonce:36}a209300780050000000000'
PA142='fastreq inner=133,142,150,149 pa142=306180050000000000a24da003020112a2460444{cipher:68}8401008506313233343536'

# start_kdc PRELOAD: MIT's krb5kdc in the foreground on the realm's profile, PRELOAD (or nothing) in LD_PRELOAD.
start_kdc() {
    docker exec "$NAME" sh -c ': >"$1/kdc.log"' sh "$OTP_DIR"
    docker exec -d -e KRB5_CONFIG="$OTP_DIR/krb5.conf" -e KRB5_KDC_PROFILE="$OTP_DIR/kdc.conf" \
        -e KR_SHIM_OUT="$OTP_DIR/shim.out" \
        "$NAME" sh -c 'export LD_PRELOAD=$2; exec krb5kdc -n >"$1/kdc.out" 2>&1' sh "$OTP_DIR" "$1"
    require_log "$NAME" "$OTP_DIR/kdc.log" 'commencing operation' "MIT krb5kdc"
}

# stub_count TEXT: how many lines of the stub's log hold TEXT.
stub_count() {
    docker exec "$NAME" sh -c 'grep -c -F -- "$2" "$1/stub.log" || true' sh "$OTP_DIR" "$1"
}

echo "==== MIT realm OTP.TEST: [otp] DEFAULT on the RADIUS stub with indicator otpind, otpuser with an otp attribute, a require_auth service ===="
otp_write_confs "[otp]
    DEFAULT = {
        server = $OTP_DIR/otp.sock
        indicator = otpind
    }"
otp_x kdb5_util -P otpmaster create -s >/dev/null || die "kdb5_util create failed"
kadmin_q_ok "${KQ[@]}" -q 'addprinc -randkey host/armor.otp.test'
kadmin_q_ok "${KQ[@]}" -q "ktadd -k $OTP_DIR/host.keytab host/armor.otp.test"
kadmin_q_ok "${KQ[@]}" -q 'addprinc -pw otpuserpw +requires_preauth otpuser'
kadmin_q_ok --then 'getstrs otpuser' '^otp: \[\]$' "${KQ[@]}" -q 'setstr otpuser otp "[]"'
kadmin_q_ok "${KQ[@]}" -q 'addprinc -randkey host/svc.otp.test'
kadmin_q_ok --then 'getstrs host/svc.otp.test' '^require_auth: otpind$' "${KQ[@]}" \
    -q 'setstr host/svc.otp.test require_auth otpind'
docker exec -d "$NAME" sh -c 'echo $$ >"$1/stub.pid"; exec python3 -I "$1/otp-radius-stub.py" --unix "$1/otp.sock" --accept 123456 --log "$1/stub.log" --idle 300 >"$1/stub.out" 2>&1' sh "$OTP_DIR"
retry_until --log "$NAME" "$OTP_DIR/stub.out" -- 100 "the RADIUS stub's socket" docker exec "$NAME" test -S "$OTP_DIR/otp.sock"
start_kdc "$OTP_DIR/otp-fast-shim.so"
docker exec "$NAME" grep -qF '(info): Loaded' "$OTP_DIR/kdc.log" || die "MIT's otp module did not load"
otp_x kinit -k -t "$OTP_DIR/host.keytab" -c "$OTP_DIR/armor.cc" "host/armor.otp.test@$OTP_REALM"

echo "==== right code 123456: MIT kinit -T and the Rust kinit get a TGT with pa_type 141, the same prompt bytes and the same FAST requests ===="
for kind in mit rust; do
    tag="c1${kind:0:1}"
    accepts="$(stub_count 'verdict: accept')"
    otp_dump_reset
    mark="$(otp_log_lines)"
    otp_kinit "$kind" "$tag" '123456\n' "${ARMOR[@]}" otpuser
    otp_dump "$tag"
    otp_rc "$tag" 0
    otp_expect "$tag" out "$PROMPT"
    otp_expect "$tag" err ''
    otp_cc "$tag" pa_type 141
    otp_cc "$tag" fast_avail yes
    [ "$(otp_flags "$tag")" = IA ] || die "$tag: the ticket flags are not IA"
    otp_has "$tag" trace 'Preauth module otp (141) (real) returned: 0/Success'
    otp_has "$tag" trace 'Produced preauth for next request: PA-FX-COOKIE (133), PA-OTP-REQUEST (142)'
    [ "$(stub_count 'verdict: accept')" = "$((accepts + 1))" ] || die "$tag: the stub did not accept exactly once"
    KDCLOG="$(otp_log_since "$mark")"
    grep -q 'ISSUE: .*otpuser@OTP.TEST for krbtgt/OTP.TEST@OTP.TEST' <<<"$KDCLOG" || die "$tag: no ISSUE line"
    KV="$(otp_kvno "$tag")"
    echo "$KV"
    grep -qF 'kvno = ' <<<"$KV" || die "$tag: the require_auth service is not reachable with the OTP TGT"
    otp_has "$tag" sum "$HINT"
    otp_has "$tag" sum 'fastreq inner=150,149'
    otp_has "$tag" sum "$PA142"
    nonce_back "$tag"
done
docker exec "$NAME" grep -qF "User-Name: b'otpuser'" "$OTP_DIR/stub.log" || die "the stub saw no User-Name otpuser"
otp_same c1m c1r out
otp_same c1m c1r err
[ "$(masked_sum c1m)" = "$(masked_sum c1r)" ] || die "the Rust kinit's FAST requests differ from MIT kinit's"

echo "==== wrong code 000000: Preauthentication failed, no password read, two AS_REQs, one stub Reject ===="
for kind in mit rust; do
    tag="c2${kind:0:1}"
    rejects="$(stub_count 'verdict: reject')"
    mark="$(otp_log_lines)"
    otp_kinit "$kind" "$tag" '000000\notpuserpw\n' "${ARMOR[@]}" otpuser
    otp_rc "$tag" 1
    otp_expect "$tag" out "$PROMPT"
    otp_expect "$tag" err 'kinit: Preauthentication failed while getting initial credentials\n'
    docker exec "$NAME" test ! -e "$OTP_DIR/$tag.cc" || die "$tag: a ccache was written"
    [ "$(stub_count 'verdict: reject')" = "$((rejects + 1))" ] || die "$tag: the stub did not reject exactly once"
    KDCLOG="$(otp_log_since "$mark")"
    [ "$(grep -c 'NEEDED_PREAUTH: otpuser@OTP.TEST' <<<"$KDCLOG")" = 1 ] || die "$tag: not one NEEDED_PREAUTH"
    [ "$(grep -c 'PREAUTH_FAILED: otpuser@OTP.TEST' <<<"$KDCLOG")" = 1 ] || die "$tag: not one PREAUTH_FAILED"
    grep -qF 'preauth (otp) verify failure: Generic preauthentication failure' <<<"$KDCLOG" || die "$tag: no verify failure line"
done
otp_same c2m c2r out
otp_same c2m c2r err

echo "==== end of file at the OTP prompt with SPAKE and encrypted challenge offered: one prompt per mechanism ===="
for kind in mit rust; do
    tag="c3${kind:0:1}"
    asks="$(stub_count 'request:')"
    mark="$(otp_log_lines)"
    otp_kinit "$kind" "$tag" '' "${ARMOR[@]}" otpuser
    otp_rc "$tag" 1
    otp_expect "$tag" out 'Enter OTP Token Value: \nPassword for otpuser@OTP.TEST: \nPassword for otpuser@OTP.TEST: \n'
    otp_expect "$tag" err 'kinit: Pre-authentication failed: Cannot read password while getting initial credentials\n'
    otp_has "$tag" trace 'Preauth module otp (141) (real) returned: -1765328254/Cannot read password'
    otp_has "$tag" trace 'Preauth module spake (151) (real) returned: -1765328254/Cannot read password'
    otp_has "$tag" trace 'Preauth module encrypted_challenge (138) (real) returned: -1765328254/Cannot read password'
    [ "$(stub_count 'request:')" = "$asks" ] || die "$tag: the stub was asked"
    KDCLOG="$(otp_log_since "$mark")"
    [ "$(grep -c 'otpuser@OTP.TEST' <<<"$KDCLOG")" = 1 ] || die "$tag: not one AS_REQ"
done
otp_same c3m c3r out
otp_same c3m c3r err

echo "==== no armor, the password: no PA-OTP-CHALLENGE offered, and the require_auth service refuses the password TGT ===="
for kind in mit rust; do
    tag="c4${kind:0:1}"
    mark="$(otp_log_lines)"
    otp_kinit "$kind" "$tag" 'otpuserpw\n' otpuser
    otp_rc "$tag" 0
    otp_expect "$tag" out 'Password for otpuser@OTP.TEST: \n'
    otp_lacks "$tag" trace 'PA-OTP-CHALLENGE'
    KV="$(otp_kvno "$tag")"
    echo "$KV"
    grep -qF "KDC policy rejects request while getting credentials for $OTP_SVC" <<<"$KV" || die "$tag: kvno was not refused"
    KDCLOG="$(otp_log_since "$mark")"
    grep -qF 'Required auth indicators not present in ticket: otpind' <<<"$KDCLOG" || die "$tag: no indicator refusal in the KDC log"
done
otp_same c4m c4r out

echo "==== [otp] DEFAULT = { timeout = 5s }: the module is left out of MIT's KDC, the hint has no PA-OTP-CHALLENGE, the password path ===="
term_comm krb5kdc
wait_pid_gone "$NAME" krb5kdc || die "krb5kdc did not stop"
otp_write_confs "[otp]
    DEFAULT = {
        timeout = 5s
    }"
start_kdc ''
docker exec "$NAME" grep -qF 'preauth otp failed to initialize: Invalid integer value' "$OTP_DIR/kdc.log" \
    || die "no otp initialization failure in the KDC log"
for kind in mit rust; do
    tag="b${kind:0:1}"
    otp_kinit "$kind" "$tag" 'otpuserpw\n' "${ARMOR[@]}" otpuser
    otp_rc "$tag" 0
    otp_expect "$tag" out 'Password for otpuser@OTP.TEST: \n'
    otp_has "$tag" trace 'Processing preauth types: PA-FX-FAST (136), PA-ETYPE-INFO2 (19), PA-SPAKE (151), PA-ENCRYPTED-CHALLENGE (138), PA-FX-COOKIE (133), PA-FX-ERROR (137)'
done
otp_same bm br out

log "otp.gate" "ok" ',"mode":"mit-kdc","pa_type":141,"cells":["right","wrong","eof","password","bad-otp"]'
exit 0
