#!/usr/bin/env bash
# harness/field/scenarios/embed-otp.sh --leg rust: OTP preauth (RFC 6560) for examples/embed-realm's
# krb5-otp-kdc, MIT krb5 1.22.2 first as the oracle. ONE guest run on the kdc VM, formalizing the earlier
# ad-hoc OTP lab run: it reverts kdc to the MIT snapshot ($MIT_SNAPSHOT_KDC), stages the example
# binaries and the driver, and runs lib/embed-otp-guest.py there. That driver builds a scratch realm
# EMBED.KERBER.TEST under /var/tmp/ov3, serves it with MIT krb5 + otp.so against a TOTP RADIUS stub
# (lib/embed-otp-stub.py) for the MIT cells, then DUMP/LOADs it into our krb5-otp-kdc (krb5-kdb load) for the
# ours cells; the chaos build serves V9/V10. It prints one `CELL <name> rc <n>` line per cell, graded here.
# The driver generates and redacts its own seed, passwords and master key, so no secret reaches the record.
#
# Cells (`CELL` lines from the driver; both legs unless noted). V5-V13 are the cells the first lab run
# validated; V1-V4 and V12 are inferred from the OTP cell list, to be checked in the lab (MIT first):
#   V1  a right code logs in and the require_auth=mfa service issues (the mfa indicator reached the ticket)
#   V2  a wrong code is refused (24); the password key is not read as a fallback
#   V3  EOF at the OTP prompt: kinit reads no value and fails
#   V4  a password login with no FAST armor gets a TGT without the mfa indicator; the service refuses it
#   V5  a TGT issued before require_mfa (MIT); ours refuses the password AS and the pre-mfa TGT at TGS
#   V6  password||code, right / wrong code / wrong password / replay, and a fresh code after (mit-v6-next)
#   V6 -keepold  an old -keepold password does not pass the password half (keep-old refused, keep-new passes)
#   V7  replay in-window refused, and again after a KDC restart
#   V8  lockout, max_fail=3: three wrong, then the 4th with a right code is CLIENT_REVOKED
#   V9  (ours, chaos) a slow verifier blocks only its own request; a second user is unaffected
#   V10 (ours, chaos) a panicking / erroring verifier is refused and the KDC stays up
#   V11 (ours) an unknown token type is refused; a plain principal still logs in
#   V12 a renewed ticket keeps the mfa indicator; the require_auth service still issues
#   V13 no seed, password or code leaks into any log or the ours replay-state file
#
# The example binaries are built release from FIELD_SHA (krb5-otp-kdc and krb5-otp-kdc-chaos from
# krb5-embed-realm-example, the latter --features chaos; krb5-kdb from krb5-kdc) and left under
# $EMBED_OTP_BINS on the host; `bins.present` grades their presence. TODO(field build-integration): the
# field preflight should build them from FIELD_SHA, so a profile can select this scenario; until then it is
# run only when an operator has placed the binaries there.
#
# vms: kdc
# legs: rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg rust") LEG=$2 ;;
    *) echo "usage: embed-otp.sh --leg rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"

BINS_SRC=${EMBED_OTP_BINS:-$LAB_HOME/ov3-bins}
GBINS=/var/tmp/ov3-bins
OTP_TOTP=$HERE/../../../scripts/lib/otp-totp.py

# The driver tears down its own MIT, ours, chaos and stub processes; this removes the scratch tree and any
# straggler of our own binaries (never the system krb5kdc) when the scenario exits.
cleanup() {
    timeout -k 5 120 "$LAB" ssh kdc -- \
        "sudo pkill -f embed-otp-guest.py; sudo pkill -x krb5-otp-kdc; sudo pkill -x krb5-otp-kdc-chaos; sudo pkill -f embed-otp-stub.py; sudo rm -rf /var/tmp/ov3 $GBINS; true" \
        < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# g/o: grade or observe a cell against the driver's saved output, read back on the runner.
g() { check "$1" "$2" host "cat $STATE/guest.out"; }
o() { observe "$1" "$2" host "cat $STATE/guest.out"; }
# par <name> <mit-cell> <ours-cell>: PASS when the two cells' summary text (after "rc <n> ") is non-empty
# and equal -- the "equal to MIT" parity assertion. The client is MIT's kinit/kvno on both legs, so an equal
# line means the two KDCs answered the same, with no guessed string.
par() {
    check "$1" '^equal: ' host \
        "a=\$(sed -n 's/^CELL $2 rc [0-9]* //p' $STATE/guest.out | head -1); b=\$(sed -n 's/^CELL $3 rc [0-9]* //p' $STATE/guest.out | head -1); if [ -n \"\$a\" ] && [ \"\$a\" = \"\$b\" ]; then echo \"equal: \$a\"; else echo \"differ: mit[\$a] ours[\$b]\"; fi"
}

section "embed-otp --leg rust: OTP preauth for krb5-otp-kdc, MIT first (one guest run on kdc)"
check reset.kdc rc host "$LABQ reset kdc $MIT_SNAPSHOT_KDC"
waitsync kdc
check bins.present '^present: 3 example binaries$' host \
    "n=0; for f in krb5-otp-kdc krb5-otp-kdc-chaos krb5-kdb; do [ -x $(printf '%q' "$BINS_SRC")/\$f ] && n=\$((n+1)); done; echo \"present: \$n example binaries\""
if [ -x "$BINS_SRC/krb5-otp-kdc" ] && [ -x "$BINS_SRC/krb5-otp-kdc-chaos" ] && [ -x "$BINS_SRC/krb5-kdb" ]; then
    run kdc "rm -rf $GBINS && mkdir -p $GBINS"
    for b in krb5-otp-kdc krb5-otp-kdc-chaos krb5-kdb; do
        runin kdc "$b" "cat > $GBINS/$b" < "$BINS_SRC/$b"
    done
    runin kdc "embed-otp-guest.py" "cat > $GBINS/embed-otp-guest.py" < "$FIELD_LIB/embed-otp-guest.py"
    runin kdc "embed-otp-stub.py" "cat > $GBINS/embed-otp-stub.py" < "$FIELD_LIB/embed-otp-stub.py"
    runin kdc "otp-totp.py" "cat > $GBINS/otp-totp.py" < "$OTP_TOTP"
    check stage.ok '^staged: 3 binaries, 3 scripts$' run kdc \
        "chmod 755 $GBINS/krb5-otp-kdc $GBINS/krb5-otp-kdc-chaos $GBINS/krb5-kdb; b=0; s=0; for f in krb5-otp-kdc krb5-otp-kdc-chaos krb5-kdb; do [ -s $GBINS/\$f ] && [ -x $GBINS/\$f ] && b=\$((b+1)); done; for f in embed-otp-guest.py embed-otp-stub.py otp-totp.py; do [ -s $GBINS/\$f ] && s=\$((s+1)); done; echo \"staged: \$b binaries, \$s scripts\""
fi
if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then
    note "a setup check failed (lab, the example binaries, or staging); the scenario stops before the guest runs"
    finish
    exit 1
fi

section "run the driver: MIT then ours on the scratch realm EMBED.KERBER.TEST"
run kdc "sudo python3 $GBINS/embed-otp-guest.py"
cp "$LAST_OUT" "$STATE/guest.out"
g guest.create   'CREATE rc 0'
g guest.armor    'ARMOR rc 0'
g guest.mit-kdc  'MIT_KDC .* up True'
g guest.dump     'DUMP rc 0'
g guest.load     'LOAD rc 0'
g guest.ours-kdc 'OURS .* up True'

section "V6: password||code, right / wrong code / wrong password / replay"
for leg in mit ours; do
    g "$leg-v6-right"      "CELL $leg-v6-right rc 0"
    g "$leg-v6-wrong-code" "CELL $leg-v6-wrong-code rc 1"
    g "$leg-v6-wrong-pw"   "CELL $leg-v6-wrong-pw rc 1"
    g "$leg-v6-replay"     "CELL $leg-v6-replay rc 1"
done
g mit-v6-next "CELL mit-v6-next rc 0"

section "V6 -keepold: an old -keepold password does not pass the password half"
for leg in mit ours; do
    g "$leg-keep-old" "CELL $leg-keep-old rc 1"
    g "$leg-keep-new" "CELL $leg-keep-new rc 0"
done

section "V7: replay in-window refused, then again after a KDC restart"
g mit-v7-replay "CELL mit-v7-replay rc 1"
for leg in mit ours; do
    g "$leg-v7-first"         "CELL $leg-v7-first rc 0"
    g "$leg-v7-after-restart" "CELL $leg-v7-after-restart rc 1"
done

section "V8: lockout, max_fail=3; three wrong then a right code is CLIENT_REVOKED"
for leg in mit ours; do
    for n in 0 1 2; do
        g "$leg-v8-wrong-$n" "CELL $leg-v8-wrong-$n rc 1"
    done
    g "$leg-v8-fourth" "CELL $leg-v8-fourth rc 1"
done
o mit-v8.getprinc 'Failed password attempts: [0-9]+'

section "V5: the password AS and the pre-mfa TGT are refused (ours)"
g mit-v5-tgt-before 'CELL v5-tgt-before rc 0'
g ours-v5-password  'CELL ours-v5-password rc 1'
# host/svc carries `require_auth mfa`, so the pre-mfa TGT is refused by check_indicators with KDC_ERR_POLICY
# (12, "KDC policy rejects request") -- MIT's server auth-indicator path, not require_mfa, and it refuses
# first (MIT do_tgs_req.c:898, before the kdcpolicy check). require_mfa (the example KdcPolicy) denies with
# PREAUTH_FAILED (24), which reaches the wire unchanged at AS and TGS alike; no code is remapped.
g ours-v5-tgs      'CELL ours-v5-tgs rc 1 kvno: KDC policy rejects request'
o ours-v5-tgs.line 'TGS_REQ.*'

section "V11 (ours): an unknown token type is refused; a plain principal still logs in"
g ours-v11-otp   'CELL ours-v11-otp rc 1'
g ours-v11-plain 'CELL ours-v11-plain rc 0'

section "V9/V10 (ours, chaos build): a slow verifier blocks only itself; panic/error stay up"
g ours-v9-slow       'CELL ours-v9-slow rc 1'
o ours-v9-slow.s     'ours-v9-slow seconds [0-9.]+'
g ours-v9-other      'CELL ours-v9-other rc 0'
g ours-v10-panic     'CELL ours-v10-panic rc 1'
g ours-v10-error     'CELL ours-v10-error rc 1'
g ours-v10-alive     'CELL ours-v10-alive rc 0'
g ours-v10-kdc-alive 'CELL ours-v10-kdc-alive rc 0'

section "V1-V4, V12 (inferred from the OTP cell list, to be checked in the lab): right code, service issue, wrong code, EOF, no-armor, renewal"
for leg in mit ours; do
    g "$leg-v1-code"    "CELL $leg-v1-code rc 0"
    g "$leg-v1-flags"   "V1 $leg flags.*Flags:.*I.*A"
    g "$leg-v1-patype"  "V1 $leg patype.*141"
    g "$leg-v1-svc"     "CELL $leg-v1-svc rc 0"
    g "$leg-v2-wrong"   "CELL $leg-v2-wrong rc 1"
    g "$leg-v3-eof"     "CELL $leg-v3-eof rc 1"
    g "$leg-v4-noarmor" "CELL $leg-v4-noarmor rc 0"
    g "$leg-v4-svc"     "CELL $leg-v4-svc rc 1"
    check "$leg-v4-notpatype" "^$leg v4 pa_type not 141\$" host \
        "sed -n 's/^V4 $leg patype //p' $STATE/guest.out | grep -q 141 && echo '$leg v4 pa_type is 141' || echo '$leg v4 pa_type not 141'"
    g "$leg-v12-init"   "CELL $leg-v12-init rc 0"
    g "$leg-v12-renew"  "CELL $leg-v12-renew rc 0"
    g "$leg-v12-svc"    "CELL $leg-v12-svc rc 0"
done
# V2/V3/V4 "equal to MIT": the MIT kinit:/kvno: summary equals ours. The client is MIT's kinit/kvno on both
# legs, so an equal line means the two KDCs answered the same -- 24 for a wrong code, the read failure for EOF,
# and "KDC policy rejects request" for the service -- with no guessed string.
par v2-parity mit-v2-wrong ours-v2-wrong
par v3-parity mit-v3-eof   ours-v3-eof
par v4-parity mit-v4-svc   ours-v4-svc

section "V13: no seed, password or code in any log or the ours replay-state file"
for f in mit-kdc.log ours-kdc.log stub.log ours-state; do
    g "hygiene.$f" "HYGIENE $f leaked none"
done
g guest.final 'FINAL_GUEST'
finish
