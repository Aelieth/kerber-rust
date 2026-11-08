#!/usr/bin/env bash
# harness/field/scenarios/otp-default.sh --leg mit|rust: the OTP default token type with nothing behind it, on the
# leg's KDC. otpdef is +requires_preauth with string attribute otp = "[]", one token of the DEFAULT type
# (otp_state.c:473-503); there is no [otp] stanza, so that type is KDC_RUN_DIR/DEFAULT.socket, 5 s, 3 tries
# (:42-45, :144-166), where nothing listens. From client2, MIT kinit -T (armor: a keytab kinit of otparm, the same on
# both legs; the client pinned to the otp module) sends a code on stdin. Checks: no [otp] stanza, no socket, the
# armor, that the KDC offered PA-OTP-CHALLENGE and the client answered it, that kinit was refused (not timed out),
# that the KDC logged none of the otp module's stages before its server, and that the same KDC then serves a plain
# kinit. INFO rows, compared with MIT's leg: the offer, the otp module's result, kinit's error, the time (bucketed),
# the KDC's log lines.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: otp-default.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ADMIN

R=${REALM//./\\.}
OD="\$HOME/od"
STAGES='No armor key found when verifying padata|Unable to decode OTP request|Unable to decrypt nonce'
STAGES+='|Unable to verify nonce or timestamp|decode otp config string'
PIDS="{ systemctl show -p MainPID --value $UNIT_KDC; systemctl show -p NRestarts --value $UNIT_KDC; }"

cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "for p in otpdef otparm; do sudo kadmin.local -q \"delprinc -force \$p\"; done \
        > /dev/null 2>&1; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- "rm -rf $OD; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

section "otp-default --leg $LEG: otpdef's DEFAULT token with no [otp] stanza and no socket, MIT kinit -T from client2"
kdcis
resetvm client2
check od.nostanza '^no \[otp\] stanza in [1-9]' run kdc "f=\$(sudo find $KDCDIR/kdc.conf /etc/krb5.conf \
    /etc/krb5.conf.d -maxdepth 1 -type f 2> /dev/null); sudo grep -qE '^[[:space:]]*\\[otp\\]' \$f; s=\$?; \
    [ \$s = 1 ] && echo \"no [otp] stanza in \$(echo \$f | wc -w) files\" || echo \"grep status \$s\""
# MIT's KDC_RUN_DIR, from the DEFAULT_SOCKET_FMT literal in its otp module; ours has no socket.
check od.nosocket '^no DEFAULT\.socket in /' run kdc "m=\$(ls /usr/lib*/krb5/plugins/preauth/otp.so 2> /dev/null \
    | head -n 1); p=\$([ -n \"\$m\" ] && sudo grep -aoE '/[[:alnum:]/._-]+/%s\\.socket' \$m | head -n 1); \
    d=\${p%/%s.socket}; d=\${d:-/run/krb5kdc}; w=\${p:+from \$m}; w=\${w:-the default}; \
    if [ -e \$d/DEFAULT.socket ]; then echo \"DEFAULT.socket exists in \$d (\$w)\"; else \
    echo \"no DEFAULT.socket in \$d (\$w)\"; fi"
check od.otpdef "^Principal \"otpdef@$R\" created\\.\$" run kdc \
    "sudo kadmin.local -q 'addprinc +requires_preauth -randkey otpdef' 2>&1"
check od.setstr '^otp: \[\]$' run kdc \
    "sudo kadmin.local -q 'setstr otpdef otp []' 2>&1; sudo kadmin.local -q 'getstrs otpdef' 2>&1"
check od.otparm "^Principal \"otparm@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey otparm' 2>&1"
check od.dir rc run client2 "rm -rf $OD; mkdir -m 0700 $OD && printf '[plugins]\\n    clpreauth = {\\n        \
enable_only = otp\\n    }\\n' > $OD/pin.conf"
check od.ktadd '^Entry for principal otparm with kvno [0-9]+, .*added to keytab' runin client2 "admin's password" \
    "kadmin -p admin/admin@$REALM -q \"ktadd -k $OD/arm.kt otparm\" 2>&1" < <(once "$ADMIN")
check od.armor "^Default principal: otparm@$R\$" run client2 \
    "kinit -k -t $OD/arm.kt -c FILE:$OD/arm.cc otparm@$REALM && klist -c FILE:$OD/arm.cc"
check od.before '^[1-9][0-9]*$' run kdc "$PIDS"
read -r PID0 R0 < <(paste -sd' ' "$LAST_OUT")

section "OD: kinit -T FILE:arm.cc otpdef, a code on stdin, the otp module only"
kdcmark od
check OD.refused '^kinit: rc=[0-9]+ ms=[0-9]+ refused$' runin client2 "a six-digit code (not a secret)" \
    "t0=\$(date +%s%N); KRB5_CONFIG=$OD/pin.conf:/etc/krb5.conf KRB5_TRACE=$OD/otp.trace \
    KRB5CCNAME=FILE:$OD/otp.cc timeout 60 kinit -T FILE:$OD/arm.cc otpdef@$REALM > /dev/null 2> $OD/otp.err; \
    rc=\$?; case \$rc in 0) w=accepted ;; 124 | 137) w=hung ;; *) w=refused ;; esac; \
    echo \"kinit: rc=\$rc ms=\$(( (\$(date +%s%N) - t0) / 1000000 )) \$w\"; \
    sed -n 's/^kinit: /error: /p' $OD/otp.err; \
    sed -n 's/^.*Processing preauth types: /offer: /p' $OD/otp.trace; \
    sed -n 's/^.*\\(Preauth module [a-z_]* ([0-9]*) ([a-z]*) returned: \\)/module: \\1/p' $OD/otp.trace; \
    sed -n 's/^.*Received error from KDC: /kdc error: /p' $OD/otp.trace" < <(echo 314159)
cp "$LAST_OUT" "$STATE/od.out"
checklast OD.hung '^kinit: rc=[0-9]+ ms=[0-9]+ (refused|accepted)$'
checklast OD.offer.otp '^offer: .*PA-OTP-CHALLENGE \(141\)'
checklast OD.answered '^module: Preauth module otp \(141\) \(real\) returned: '
observelast OD.offer '^offer: .*'
observelast OD.module '^module: .*'
observelast OD.kdcerror '^kdc error: .*' '$'
observelast OD.error '^error: .*'
observe OD.time '^time: .*' host "ms=\$(sed -n 's/^kinit: rc=[0-9]* ms=\\([0-9]*\\) .*/\\1/p' \
    $(printf '%q' "$STATE/od.out")); if [ \"\${ms:-99999}\" -lt 2000 ]; then echo 'time: under 2 s'; \
    elif [ \"\$ms\" -lt 20000 ]; then echo 'time: 2 to 20 s'; else echo 'time: 20 s or more'; fi"
kdcsince od
cp "$LAST_OUT" "$STATE/od.log"
# The otp module's stages before its server is asked, each logged (MIT main.c:301-326, otp_state.c:722; ours
# preauth/otp.rs:309-354): none in the window means the request reached the DEFAULT server.
check OD.path '^otp stage lines: 0, otpdef lines: [1-9]' host "f=$(printf '%q' "$STATE/od.log"); grep -qx -- \
    '--- kadmind.log' \$f || { echo 'no KDC log read'; exit 1; }; grep -E '$STAGES' \$f; \
    n=\$(grep -cE '$STAGES' \$f); o=\$(grep -c 'otpdef@' \$f); echo \"otp stage lines: \$n, otpdef lines: \$o\""
observe OD.log '.*' host "grep -v '^--- kadmind.log$' $(printf '%q' "$STATE/od.log") | sed -E \
    's/^.*\\]\\(([A-Za-z]+)\\): /(\\1): /; s/authtime [0-9]+/authtime T/' | sort -u | paste -sd'|' - | grep . \
    || echo '(no log line)'"

section "OD.after: the same KDC process serves a plain kinit"
check OD.state "^$PID0 $R0\$" run kdc "$PIDS | paste -sd' ' -"
check OD.kinit '^kinit: rc=0$' runin client2 "admin/admin's password ($ADMIN)" \
    "KRB5CCNAME=FILE:$OD/after.cc kinit admin/admin@$REALM > /dev/null; echo \"kinit: rc=\$?\"" < <(once "$ADMIN")

finish
