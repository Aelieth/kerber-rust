#!/usr/bin/env bash
# harness/field/scenarios/kdc-profile.sh --leg mit|rust: what the leg's KDC (as upgrade.sh left it on kdc) takes from
# kdc.conf, seen from client2's MIT kinit, kdc.conf restored after each cell:
#   CF.a: [libdefaults] clockskew = 60, client2's clock +120 s: the AS-REQ's timestamp is refused (Clock skew too
#         great); clockskew = 600 and +400 s: it is accepted. client2's copy of krb5.conf sets kdc_timesync = 0 (the
#         timestamp is client2's clock, not the KDC's), its own clockskew = 900, and enables only the encrypted_timestamp
#         preauth module (the lab's krb5.conf enables SPAKE, which carries no timestamp), so only the KDC's skew decides.
#         The principal is cfskew, made +requires_preauth for these cells: the lab's principals do not require preauth,
#         so their AS-REQ carries no timestamp to judge. The kinit trace's preauth module line is recorded;
#   CF.d: a second realm stanza (DUMMY.TEST, max_life = 1h) after KERBER.TEST's: alice's TGT life is what it was
#         without it.
# Graded on both legs, MIT's first.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kdc-profile.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE
R=${REALM//./\\.}
KC=/var/kerberos/krb5kdc/kdc.conf
CF="export KRB5_CONFIG=\$HOME/cf/krb5.conf"
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "[ -e $KC.cf ] && sudo mv $KC.cf $KC && sudo systemctl restart krb5kdc; sudo kadmin.local -q 'delprinc -force cfskew'; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'sudo systemctl start chronyd; rm -rf ~/cf; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kdcwith <check> <text appended to kdc.conf>: the original kdc.conf plus that text, then the KDC restarted.
kdcwith() {
    check "$1" '^krb5kdc: active, 88 listening$' run kdc "sudo cp -p $KC.cf $KC && printf '%b' '$2' | sudo tee -a $KC > /dev/null && sudo systemctl restart krb5kdc && for i in \$(seq 1 40); do ss -Hlun 'sport = :88' | grep -q . && break; sleep 0.25; done; sudo tail -n 6 $KC; echo \"krb5kdc: \$(systemctl is-active krb5kdc), 88 \$(ss -Hlun 'sport = :88' | grep -q . && echo listening)\""
}
# skewed <check> <seconds> <ERE>: client2's clock moved ahead by that much (chronyd stopped), cfskew's kinit through
# the copy of krb5.conf with its trace's preauth and KDC error lines after it, then chronyd started again to step it
# back.
skewed() {
    run client2 "sudo systemctl stop chronyd && sudo date -s @\$(( \$(date +%s) + $2 )) > /dev/null && date -u +%T"
    check "$1" "$3" runin client2 "cfskew's password, alice's ($ALICE)" "$CF; rm -f \$HOME/cf/a.trace; KRB5_TRACE=\$HOME/cf/a.trace kinit -c FILE:\$HOME/cf/a.cc cfskew 2>&1; echo \"kinit rc=\$?\"; grep -hE 'Preauth module|Received error from KDC' \$HOME/cf/a.trace"
    observelast "obs.$1.preauth" 'Preauth module [a-z_0-9]+ \([0-9]+\) \(real\) returned: .*'
    run client2 "sudo systemctl start chronyd"
    waitsync client2
}
# life <name>: alice's TGT life in seconds from a fresh kinit, in LIFE.
life() {
    runin client2 "alice's password ($ALICE)" "kdestroy -c FILE:\$HOME/cf/l.cc 2> /dev/null; kinit -c FILE:\$HOME/cf/l.cc alice > /dev/null && klist -f -c FILE:\$HOME/cf/l.cc" < <(once "$ALICE")
    local line
    line=$(tgtline "^krbtgt/$R@$R\$")
    LIFE=$(printf '%s\n' "$line" | sed -n 's/^.*: \([0-9][0-9]*\) s life,.*$/\1/p')
    _checkrow "obs.$1" INFO "alice's TGT" "$LAST_RC" "$line"
}

section "kdc-profile --leg $LEG: kdc.conf as the $LEG KDC reads it, MIT kinit from client2"
kdcis
resetvm client2
check kdc.conf.saved '^no clockskew, no DUMMY\.TEST$' run kdc "sudo cp -p $KC $KC.cf && ! sudo grep -qE '^[[:space:]]*clockskew|DUMMY\\.TEST' $KC && echo 'no clockskew, no DUMMY.TEST'"
run kdc "sudo kadmin.local -q 'delprinc -force cfskew' 2>&1 | grep -v '^Authenticating'; true"
check setup.cfskew "^Principal \"cfskew@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc +requires_preauth cfskew' 2>&1" < <(twice "$ALICE")
check client2.cfconf '^> +kdc_timesync = 0$' run client2 "mkdir -p ~/cf && awk '/^\\[libdefaults\\]/ && !d { print; print \"    kdc_timesync = 0\"; print \"    clockskew = 900\"; d = 1; next } { print }' /etc/krb5.conf > ~/cf/krb5.conf; printf '\\n[plugins]\\n    clpreauth = {\\n        enable_only = encrypted_timestamp\\n    }\\n' >> ~/cf/krb5.conf; diff /etc/krb5.conf ~/cf/krb5.conf; true"

section "CF.a clockskew = 60, client2 +120 s: refused (MIT and ours)"
kdcwith CF.a.60.kdc '\n[libdefaults]\n    clockskew = 60\n'
skewed CF.a.60.kinit 120 'Clock skew too great while getting initial credentials$' < <(once "$ALICE")

section "CF.a clockskew = 600, client2 +400 s: accepted (MIT and ours)"
kdcwith CF.a.600.kdc '\n[libdefaults]\n    clockskew = 600\n'
skewed CF.a.600.kinit 400 '^kinit rc=0$' < <(once "$ALICE")

section "CF.d a DUMMY.TEST stanza with max_life = 1h after KERBER.TEST's: alice's TGT life unchanged (MIT and ours)"
kdcwith CF.d.one-stanza ''
life CF.d.life-before
L0=${LIFE:-}
check CF.d.longer-than-1h '^life before: [0-9]+ s, over 3600$' host "[ \"${L0:-0}\" -gt 3600 ] && echo 'life before: $L0 s, over 3600'"
kdcwith CF.d.two-stanzas '\n[realms]\n    DUMMY.TEST = {\n        max_life = 1h\n    }\n'
life CF.d.life-after
check CF.d.life "^same TGT life: ${L0:-none} s\$" host "echo 'same TGT life: ${LIFE:-none} s'"

section "kdc.conf restored"
check kdc.conf.restored '^restored, krb5kdc active$' run kdc "sudo mv $KC.cf $KC && sudo systemctl restart krb5kdc && systemctl is-active krb5kdc > /dev/null && ! sudo grep -qE '^[[:space:]]*clockskew|DUMMY\\.TEST' $KC && echo 'restored, krb5kdc active'"
finish
