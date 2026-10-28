#!/usr/bin/env bash
# The Rust KDC's OTP module through the example embedder krb5-otp-kdc (examples/embed-realm: the KLLDAP seam in miniature, a
# TOTP OtpVerifier), then MIT kinit -T and the Rust kinit against it, cell for cell as otp-gate.sh runs them against
# MIT's KDC: the right code, a wrong code, end of file at the prompt with SPAKE and encrypted challenge offered, the
# password path with [otp] indicator and require_auth, a bad [otp], MIT's server relation refused. The TOTP codes come from
# the standard library (scripts/lib/otp-totp.py), not from the verifier under test.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/proc-common.sh"
. "$ROOT/scripts/lib/otp-common.sh"
need_bins krb5-kinit krb5-otp-kdc krb5-kdb krb5-kadmin-local

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kinit-otp-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "otp.client.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

register_cleanup otp_stop
shell_container
otp_stage otp-totp.py
mit_oracle_brand "$NAME" /usr/bin/kinit
for bin in krb5-otp-kdc krb5-kdb krb5-kadmin-local; do
    docker cp "${CARGO_TARGET_DIR:-target}/debug/$bin" "$NAME":/tmp/"$bin"
    docker exec "$NAME" chmod +x /tmp/"$bin"
done

# The RFC 6238 appendix B secret, a public test vector; one user per successful login, so no code is replayed.
SEED=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
PROMPT='Enter OTP Token Value: \n'
ARMOR=(-T "$OTP_DIR/armor.cc")
KQ=(rust_kadmin_local -e KRB5_CONFIG="$OTP_DIR/krb5.conf" -e KRB5_KDC_PROFILE="$OTP_DIR/kdc.conf" "$NAME" --)
HINT='fastresp types=136,19,141,151,138,133,137 pa141=30318024{nonce:36}a209300780050000000000'

# start_kdc: the example embedder in the foreground on the realm's profile, with the seeds file.
start_kdc() {
    docker exec "$NAME" sh -c ': >"$1/kdc.log"' sh "$OTP_DIR"
    docker exec -d -e KRB5_CONFIG="$OTP_DIR/krb5.conf" -e KRB5_KDC_PROFILE="$OTP_DIR/kdc.conf" \
        -e KERBER_EXAMPLE_TOTP_SEEDS="$OTP_DIR/seeds" -e KERBER_EXAMPLE_TOTP_ONLY=1 \
        "$NAME" sh -c 'exec /tmp/krb5-otp-kdc -n >"$1/kdc.out" 2>&1' sh "$OTP_DIR"
    require_log "$NAME" "$OTP_DIR/kdc.log" 'commencing operation' "krb5-otp-kdc"
}

# totp OFFSET: the code of the current step plus OFFSET.
totp() {
    docker exec "$NAME" python3 -I "$OTP_DIR/otp-totp.py" code "$SEED" "$1"
}

echo "==== Rust realm OTP.TEST: [otp] totp with indicator otpind, users with the totp verifier, a require_auth service ===="
printf 'otpmit@OTP.TEST %s\notprust@OTP.TEST %s\n' "$SEED" "$SEED" | docker exec -i "$NAME" sh -c 'cat >"$1/seeds"' sh "$OTP_DIR"
otp_write_confs "[otp]
    totp = {
        indicator = otpind
    }"
otp_x /tmp/krb5-kdb -r "$OTP_REALM" -P otpmaster create -s >/dev/null || die "krb5-kdb create failed"
kadmin_q_ok "${KQ[@]}" -q 'addprinc -randkey host/armor.otp.test'
kadmin_q_ok "${KQ[@]}" -q "ktadd -k $OTP_DIR/host.keytab host/armor.otp.test"
for user in otpmit otprust; do
    kadmin_q_ok "${KQ[@]}" -q "addprinc -pw otpuserpw +requires_preauth $user"
    kadmin_q_ok --then "getstrs $user" '^otp: \[\{"type":"totp"\}\]$' "${KQ[@]}" \
        -q "setstr $user otp \"[{\"\"type\"\":\"\"totp\"\"}]\""
done
kadmin_q_ok "${KQ[@]}" -q 'addprinc -randkey host/svc.otp.test'
kadmin_q_ok --then 'getstrs host/svc.otp.test' '^require_auth: otpind$' "${KQ[@]}" \
    -q 'setstr host/svc.otp.test require_auth otpind'
start_kdc
docker exec "$NAME" grep -qF '(info): Loaded' "$OTP_DIR/kdc.log" || die "the Rust KDC's otp module did not load"
otp_x kinit -k -t "$OTP_DIR/host.keytab" -c "$OTP_DIR/armor.cc" "host/armor.otp.test@$OTP_REALM"

echo "==== right code: MIT kinit -T and the Rust kinit get a TGT with pa_type 141, the same prompt bytes, and require_auth opens ===="
for kind in mit rust; do
    tag="c1${kind:0:1}"
    user="otp${kind}"
    mark="$(otp_log_lines)"
    otp_kinit "$kind" "$tag" "$(totp 0)\\n" "${ARMOR[@]}" "$user"
    otp_rc "$tag" 0
    otp_expect "$tag" out "$PROMPT"
    otp_expect "$tag" err ''
    otp_cc "$tag" pa_type 141
    otp_cc "$tag" fast_avail yes
    [ "$(otp_flags "$tag")" = IA ] || die "$tag: the ticket flags are not IA"
    otp_has "$tag" trace 'Preauth module otp (141) (real) returned: 0/Success'
    KDCLOG="$(otp_log_since "$mark")"
    grep -q "ISSUE: .*$user@OTP.TEST for krbtgt/OTP.TEST@OTP.TEST" <<<"$KDCLOG" || die "$tag: no ISSUE line"
    KV="$(otp_kvno "$tag")"
    echo "$KV"
    grep -qF 'kvno = ' <<<"$KV" || die "$tag: the require_auth service is not reachable with the OTP TGT"
done
otp_same c1m c1r out
otp_same c1m c1r err

echo "==== wrong code: Preauthentication failed, no password read, MIT kinit reads the Rust KDC's PA-OTP-CHALLENGE bytes ===="
WRONG="$(docker exec "$NAME" python3 -I "$OTP_DIR/otp-totp.py" wrong "$SEED")"
for kind in mit rust; do
    tag="c2${kind:0:1}"
    mark="$(otp_log_lines)"
    if [ "$kind" = mit ]; then
        OTP_PRELOAD="$OTP_DIR/otp-fast-shim.so"
        otp_dump_reset
    fi
    otp_kinit "$kind" "$tag" "$WRONG\\notpuserpw\\n" "${ARMOR[@]}" otpmit
    OTP_PRELOAD=''
    otp_rc "$tag" 1
    otp_expect "$tag" out "$PROMPT"
    otp_expect "$tag" err 'kinit: Preauthentication failed while getting initial credentials\n'
    docker exec "$NAME" test ! -e "$OTP_DIR/$tag.cc" || die "$tag: a ccache was written"
    KDCLOG="$(otp_log_since "$mark")"
    [ "$(grep -c 'NEEDED_PREAUTH: otpmit@OTP.TEST' <<<"$KDCLOG")" = 1 ] || die "$tag: not one NEEDED_PREAUTH"
    [ "$(grep -c 'PREAUTH_FAILED: otpmit@OTP.TEST' <<<"$KDCLOG")" = 1 ] || die "$tag: not one PREAUTH_FAILED"
    grep -qF 'preauth (otp) verify failure: Generic preauthentication failure' <<<"$KDCLOG" || die "$tag: no verify failure line"
    if [ "$kind" = mit ]; then
        otp_dump "$tag"
        otp_has "$tag" sum "$HINT"
        otp_has "$tag" sum 'fastreq inner=150,149'
        otp_has "$tag" sum 'fastreq inner=133,142,150,149'
        nonce_back "$tag"
    fi
done
otp_same c2m c2r out
otp_same c2m c2r err

echo "==== end of file at the OTP prompt with SPAKE and encrypted challenge offered: one prompt per mechanism ===="
for kind in mit rust; do
    tag="c3${kind:0:1}"
    otp_kinit "$kind" "$tag" '' "${ARMOR[@]}" otpmit
    otp_rc "$tag" 1
    otp_expect "$tag" out 'Enter OTP Token Value: \nPassword for otpmit@OTP.TEST: \nPassword for otpmit@OTP.TEST: \n'
    otp_expect "$tag" err 'kinit: Pre-authentication failed: Cannot read password while getting initial credentials\n'
    otp_has "$tag" trace 'Preauth module otp (141) (real) returned: -1765328254/Cannot read password'
    otp_has "$tag" trace 'Preauth module spake (151) (real) returned: -1765328254/Cannot read password'
    otp_has "$tag" trace 'Preauth module encrypted_challenge (138) (real) returned: -1765328254/Cannot read password'
done
otp_same c3m c3r out
otp_same c3m c3r err

echo "==== no armor, the password: no PA-OTP-CHALLENGE offered, and the require_auth service refuses the password TGT ===="
for kind in mit rust; do
    tag="c4${kind:0:1}"
    mark="$(otp_log_lines)"
    otp_kinit "$kind" "$tag" 'otpuserpw\n' otpmit
    otp_rc "$tag" 0
    otp_expect "$tag" out 'Password for otpmit@OTP.TEST: \n'
    otp_lacks "$tag" trace 'PA-OTP-CHALLENGE'
    KV="$(otp_kvno "$tag")"
    echo "$KV"
    grep -qF "KDC policy rejects request while getting credentials for $OTP_SVC" <<<"$KV" || die "$tag: kvno was not refused"
    KDCLOG="$(otp_log_since "$mark")"
    grep -qF 'Required auth indicators not present in ticket: otpind' <<<"$KDCLOG" || die "$tag: no indicator refusal in the KDC log"
done
otp_same c4m c4r out

echo "==== [otp] totp = { timeout = 5s }: the module is left out of the Rust KDC, the hint has no PA-OTP-CHALLENGE, the password path ===="
term_comm krb5-otp-kdc
wait_pid_gone "$NAME" krb5-otp-kdc || die "krb5-otp-kdc did not stop"
otp_write_confs "[otp]
    totp = {
        timeout = 5s
    }"
start_kdc
docker exec "$NAME" grep -qF 'preauth otp failed to initialize: Invalid integer value' "$OTP_DIR/kdc.log" \
    || die "no otp initialization failure in the KDC log"
for kind in mit rust; do
    tag="b${kind:0:1}"
    otp_kinit "$kind" "$tag" 'otpuserpw\n' "${ARMOR[@]}" otpmit
    otp_rc "$tag" 0
    otp_expect "$tag" out 'Password for otpmit@OTP.TEST: \n'
    otp_has "$tag" trace 'Processing preauth types: PA-FX-FAST (136), PA-ETYPE-INFO2 (19), PA-SPAKE (151), PA-ENCRYPTED-CHALLENGE (138), PA-FX-COOKIE (133), PA-FX-ERROR (137)'
done
otp_same bm br out

echo "==== MIT's [otp] server relation is refused (RADIUS is not implemented): the module is left out, the password path ===="
term_comm krb5-otp-kdc
wait_pid_gone "$NAME" krb5-otp-kdc || die "krb5-otp-kdc did not stop"
otp_write_confs "[otp]
    DEFAULT = {
        server = $OTP_DIR/x.sock
    }"
start_kdc
KDCLOG="$(docker exec "$NAME" cat "$OTP_DIR/kdc.log")"
grep -qF "Unsupported relation 'server' (token type 'DEFAULT'): RADIUS is not implemented; an embedder's OtpVerifier decides" <<<"$KDCLOG" \
    || die "no server refusal line in the KDC log"
grep -qF 'preauth otp failed to initialize: Invalid argument' <<<"$KDCLOG" || die "no otp initialization failure in the KDC log"
otp_kinit mit sm 'otpuserpw\n' "${ARMOR[@]}" otpmit
otp_rc sm 0
otp_lacks sm trace 'PA-OTP-CHALLENGE'

log "otp.client.gate" "ok" ',"mode":"rust-kdc","pa_type":141,"cells":["right","wrong","eof","password","bad-otp","server"]'
exit 0
