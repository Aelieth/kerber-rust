#!/usr/bin/env bash
# harness/field/scenarios/kdb-writes.sh --leg mit|rust: kadmind's writes to the database against the KDC's lockout writes, on
# the leg's KDC as upgrade.sh left it on kdc, MIT kinit and kadmin from client2:
#   SW.lockout: swlock (policy swpol, maxfailure 10) fails kinit 3 times, kadmind changes swother twice, swlock fails
#               twice more, kadmind changes swother again: getprinc shows 5 failed attempts;
#   SW.undo: a cpw of swpw that its policy (swpol2, minlength 20) refuses leaves its keys; the next cpw -randkey
#            changes them.
#   KD: kdb5_util dump's name filter is POSIX ERE, matched against the whole name: with principals kd1 kdd kd kddd
#       kdax kd]x kda]x, 'kd\d@.*' dumps kdd ("\d" is "d"), 'kd{,2}@.*' dumps kd and kdd ("{,2}" is {0,2}),
#       'kd[a\]]x@.*' dumps kda]x (the bracket is "a" or a backslash, then "]"), and 'kd(' is glibc's "Unmatched ( or
#       \(" for each principal.
#   KA: kadmin as MIT has it: kadm5_get_privs answers all ones whoever asks (getprivs as admin/admin and as ctself, who
#       has no kadm5.acl line); ctself refused in MIT's words (add, delete, list, modify's get, a policy's add, list
#       and delete); cpw -keepold keeps every key version for admin/admin and 5 when ctself changes its own; and
#       kadmin.local's dates and intervals as MIT's getdate parses and refuses them.
# Graded on both legs, MIT's first.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kdb-writes.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE ADMIN
R=${REALM//./\\.}
KA="kadmin -p admin/admin@$REALM -q"
KD="kd1 kdd kd kddd kdax 'kd]x' 'kda]x'"
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo rm -f /var/tmp/kd.dump /var/tmp/kd.dump.dump_ok; for p in swlock swother swpw ctself ctdate ctkeep ctdeny $KD; do sudo kadmin.local -q \"delprinc -force \$p\"; done; for p in swpol swpol2 ctdenypol; do sudo kadmin.local -q \"delpol -force \$p\"; done; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kadm <check> <ERE> <query>: remote MIT kadmin as admin/admin from client2 (a refused query may exit non-zero; its
# text is what is graded).
kadm() { check "$1" "$2" runin client2 "admin/admin's password ($ADMIN)" "$KA '$3' 2>&1; true" < <(once "$ADMIN"); }
# kself <check> <ERE> <password> <query>: remote MIT kadmin as ctself (no kadm5.acl line) from client2, its own password
# (a scratch value) on stdin.
kself() { check "$1" "$2" runin client2 "ctself's password ($3)" "kadmin -p ctself@$REALM -q '$4' 2>&1; true" < <(printf '%s\n' "$3"); }
# fails <check> <n>: n kinits of swlock from client2 with a wrong password, each refused.
fails() {
    check "$1" "^refused: $2\$" run client2 "n=0; for i in \$(seq 1 $2); do echo 'not-the-password' | kinit -c MEMORY:sw swlock@$REALM > /dev/null 2>&1 || n=\$((n + 1)); done; echo \"refused: \$n\""
}

section "kdb-writes --leg $LEG: kadmind's writes beside the KDC's lockout writes on the $LEG KDC"
kdcis
resetvm client2
run kdc "for p in swlock swother swpw ctself ctdate ctkeep ctdeny; do sudo kadmin.local -q \"delprinc -force \$p\" 2>&1 | grep -v '^Authenticating'; done; for p in swpol swpol2 ctdenypol; do sudo kadmin.local -q \"delpol -force \$p\" 2>&1 | grep -v '^Authenticating'; done; true"
check setup.policies 'policy swpol2' run kdc "sudo kadmin.local -q 'addpol -maxfailure 10 swpol' 2>&1; sudo kadmin.local -q 'addpol -minlength 20 swpol2' 2>&1; sudo kadmin.local -q listpols | grep -E '^swpol2?\$' | sed 's/^/policy /'"
check setup.swlock "^Principal \"swlock@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc -policy swpol swlock' 2>&1" < <(twice "$ALICE")
check setup.swother "^Principal \"swother@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey swother' 2>&1"
check setup.swpw "^Principal \"swpw@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey -policy swpol2 swpw' 2>&1"
check setup.ctself "^Principal \"ctself@$R\" created\\.\$" runin kdc "Ct-self-0, twice" "sudo kadmin.local -q 'addprinc ctself' 2>&1" < <(printf '%s\n%s\n' Ct-self-0 Ct-self-0)
check setup.ctdate "^Principal \"ctdate@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey ctdate' 2>&1"
check setup.ctkeep "^Principal \"ctkeep@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey ctkeep' 2>&1"

section "SW.lockout: swlock's failed attempts kept across kadmind's writes to swother (MIT and ours: 5)"
fails SW.lockout.fail-3 3
kadm SW.lockout.write-1 "^Key for \"swother@$R\" randomized\\.\$" "cpw -randkey swother"
kadm SW.lockout.write-2 "^Principal \"swother@$R\" modified\\.\$" "modprinc -maxlife 1h swother"
fails SW.lockout.fail-2 2
kadm SW.lockout.write-3 "^Principal \"swother@$R\" modified\\.\$" "modprinc -maxlife 2h swother"
check SW.lockout.count '^Failed password attempts: 5$' run kdc "sudo kadmin.local -q 'getprinc swlock' 2>&1 | grep -E '^(Failed password attempts|Policy)'"

section "SW.undo: a cpw swpol2 refuses leaves swpw's keys; the next cpw -randkey changes them (MIT and ours)"
run kdc "sudo kadmin.local -q 'getprinc swpw' 2>&1 | grep -m1 -E '^Key: vno '"
K0=$(sed -n 's/^Key: vno \([0-9][0-9]*\),.*/\1/p' "$LAST_OUT")
kadm SW.undo.refused 'Password is too short' "cpw -pw short-pw-1 swpw"
check SW.undo.kept "^Key: vno ${K0:-none}, " run kdc "sudo kadmin.local -q 'getprinc swpw' 2>&1 | grep -m1 -E '^Key: vno '"
kadm SW.undo.next "^Key for \"swpw@$R\" randomized\\.\$" "cpw -randkey swpw"
check SW.undo.changed "^Key: vno $(( ${K0:-0} + 1 )), " run kdc "sudo kadmin.local -q 'getprinc swpw' 2>&1 | grep -m1 -E '^Key: vno '"

section "KD: kdb5_util dump's name filter is POSIX ERE, matched against the whole name (MIT and ours)"
check KD.setup '^kd principals: 7$' run kdc "for p in $KD; do sudo kadmin.local -q \"delprinc -force \$p\" > /dev/null 2>&1; sudo kadmin.local -q \"addprinc -randkey \$p\" > /dev/null 2>&1; done; sudo kadmin.local -q listprincs 2>&1 | grep -cE '^kd(1|d{0,2}|ax|a?[]]x)@$R\$' | sed 's/^/kd principals: /'"
# kddump <check> <ERE> <pattern>: what kdb5_util dump -verbose writes to stderr for the pattern, sorted and unique, on one line
kddump() {
    check "$1" "$2" run kdc "sudo kdb5_util dump -verbose /var/tmp/kd.dump '$3' 2>&1 > /dev/null | LC_ALL=C sort -u | paste -sd' ' -; sudo rm -f /var/tmp/kd.dump /var/tmp/kd.dump.dump_ok"
}
kddump KD.d "^kdd@$R\$" 'kd\d@.*'
kddump KD.brace "^kd@$R kdd@$R\$" 'kd{,2}@.*'
kddump KD.bracket "^kda[]]x@$R\$" 'kd[a\]]x@.*'
kddump KD.bad '^kdb5_util: regular expression error: Unmatched \( or \\\($' 'kd('
section "KA.privs: kadm5_get_privs answers all ones whoever asks (server_misc.c:146-158), so MIT's kadmin names all four for admin/admin and for ctself"
kadm KA.privs.admin '^current privileges: INQUIRE ADD MODIFY DELETE$' 'getprivs'
kself KA.privs.self '^current privileges: INQUIRE ADD MODIFY DELETE$' Ct-self-0 'getprivs'

section "KA.deny: ctself, with no kadm5.acl line, refused in MIT's words (server_stubs.c; kadmin.c's com_err lines; modprinc reads first)"
kself KA.deny.add "^add_principal: Operation requires \`\`add'' privilege while creating \"ctdeny@$R\"\\.\$" Ct-self-0 'addprinc -randkey ctdeny'
kself KA.deny.delete "^(Password for [^:]*: )?delete_principal: Operation requires \`\`delete'' privilege while deleting principal \"ctdate@$R\"\$" Ct-self-0 'delprinc -force ctdate'
kself KA.deny.list "^(Password for [^:]*: )?get_principals: Operation requires \`\`list'' privilege while retrieving list\\.\$" Ct-self-0 'listprincs'
kself KA.deny.modify "^(Password for [^:]*: )?modify_principal: Operation requires \`\`get'' privilege while getting \"ctdate@$R\"\\.\$" Ct-self-0 'modprinc -maxlife 1h ctdate'
kself KA.deny.addpol "^(Password for [^:]*: )?add_policy: Operation requires \`\`add'' privilege while creating policy \"ctdenypol\"\\.\$" Ct-self-0 'addpol ctdenypol'
kself KA.deny.listpols "^(Password for [^:]*: )?get_policies: Operation requires \`\`list'' privilege while retrieving list\\.\$" Ct-self-0 'listpols'
kself KA.deny.delpol "^(Password for [^:]*: )?delete_policy:: Operation requires \`\`delete'' privilege while deleting policy \"swpol\"\$" Ct-self-0 'delpol -force swpol'

section "KA.keep: cpw -keepold keeps every key version for admin/admin, and MAX_SELF_KEEPOLD (5, the new one included) when ctself changes its own (server_stubs.c:383-399, kdb_cpw.c:116-137)"
for i in 1 2 3 4 5 6; do
    kadm "KA.keep.admin.$i" "^Key for \"ctkeep@$R\" randomized\\.\$" 'cpw -randkey -keepold ctkeep'
done
check KA.keep.admin '^kvnos: 7 \(1 to 7\)$' run kdc "v=\$(sudo kadmin.local -q 'getprinc ctkeep' | sed -n 's/^Key: vno \\([0-9]*\\),.*/\\1/p' | sort -un); echo \"kvnos: \$(printf '%s\\n' \"\$v\" | grep -c .) (\$(printf '%s\\n' \"\$v\" | head -n 1) to \$(printf '%s\\n' \"\$v\" | tail -n 1))\""
for i in 1 2 3 4 5 6; do
    kself "KA.keep.self.$i" "^Password for \"ctself@$R\" changed\\.\$" "Ct-self-$((i - 1))" "cpw -keepold -pw Ct-self-$i ctself"
done
check KA.keep.self '^kvnos: 5 \(3 to 7\)$' run kdc "v=\$(sudo kadmin.local -q 'getprinc ctself' | sed -n 's/^Key: vno \\([0-9]*\\),.*/\\1/p' | sort -un); echo \"kvnos: \$(printf '%s\\n' \"\$v\" | grep -c .) (\$(printf '%s\\n' \"\$v\" | head -n 1) to \$(printf '%s\\n' \"\$v\" | tail -n 1))\""

section "KA.date: kadmin.local's dates and intervals (kadmin.c parse_date and parse_interval :157-195, getdate.y), on ctdate, as getprinc reads them back"
# dates <check> <option> <getprinc field> <form>...: on kdc, kadmin.local (the leg's own parser) sets <option> on ctdate to
# each form; one line per form: "<form> => " and what getprinc then reads, or kadmin's first error line.
dates() {
    local name=$1 opt=$2 field=$3 f
    shift 3
    for f in "$@"; do
        printf 'f=%q\n' "$f"
        printf '%s\n' "e=\$(sudo kadmin.local -q \"modprinc $opt \\\"\$f\\\" ctdate\" 2>&1 > /dev/null | grep -v '^Authenticating' | head -n 1); printf '%s => %s\\n' \"\$f\" \"\${e:-\$(sudo kadmin.local -q 'getprinc ctdate' | sed -n 's/^$field: //p')}\""
    done > "$STATE/$name.sh"
    check "$name" rc runin kdc "the forms ($name.sh)" "bash -s" < "$STATE/$name.sh"
}
dates KA.date.abs -expire 'Expiration date' '2030-01-01 00:00:00 UTC' 'Jan 1, 2020 00:00:00 UTC' '2031-06-01 12:00:00 UTC' \
    '1970-01-01 00:00:01 UTC' never 1/1/90 17-JUN-1992 bogus-date 'Feb 30, 2021' 13/1/2020 2030-01 1/1/1960 '10:00 11:00'
checklast KA.date.abs.iso 'line:2030-01-01 00:00:00 UTC => Tue Jan 01 00:00:00 UTC 2030'
checklast KA.date.abs.comma 'line:Jan 1, 2020 00:00:00 UTC => Wed Jan 01 00:00:00 UTC 2020'
checklast KA.date.abs.noon 'line:2031-06-01 12:00:00 UTC => Sun Jun 01 12:00:00 UTC 2031'
checklast KA.date.abs.epoch 'line:1970-01-01 00:00:01 UTC => Thu Jan 01 00:00:01 UTC 1970'
checklast KA.date.abs.never 'line:never => [never]'
checklast KA.date.abs.slash 'line:1/1/90 => Mon Jan 01 00:00:00 UTC 1990'
checklast KA.date.abs.dmy 'line:17-JUN-1992 => Wed Jun 17 00:00:00 UTC 1992'
for f in bogus-date 'Feb 30, 2021' 13/1/2020 2030-01 1/1/1960 '10:00 11:00'; do
    checklast "KA.date.abs.refused.${f//[^0-9A-Za-z]/_}" "line:$f => Invalid date specification \"$f\"."
done
dates KA.date.int -maxlife 'Maximum ticket life' 7days 7d 10h '2 hours' '1 week' '30 days' never 1/1/1990 '42 ' 'Jan 1, 1990' '2 days ago'
checklast KA.date.int.days 'line:7days => 7 days 00:00:00'
checklast KA.date.int.d 'line:7d => 7 days 00:00:00'
checklast KA.date.int.h 'line:10h => 0 days 10:00:00'
checklast KA.date.int.hours 'line:2 hours => 0 days 02:00:00'
checklast KA.date.int.week 'line:1 week => 7 days 00:00:00'
checklast KA.date.int.thirty 'line:30 days => 30 days 00:00:00'
checklast KA.date.int.never 'line:never => 0 days 00:00:00'
checklast KA.date.int.slash 'line:1/1/1990 => 0 days 00:00:01'
checklast KA.date.int.bad 'line:42  => Invalid date specification "42 ".'
checklast KA.date.int.past 'line:Jan 1, 1990 => Interval specification "Jan 1, 1990" is in the past.'
checklast KA.date.int.ago 'line:2 days ago => Interval specification "2 days ago" is in the past.'
check KA.date.rel '^tomorrow: 1440 min ahead; \+90 days: 129600 min ahead$' run kdc "for f in tomorrow '+90 days'; do sudo kadmin.local -q \"modprinc -expire \\\"\$f\\\" ctdate\" > /dev/null 2>&1; e=\$(sudo kadmin.local -q 'getprinc ctdate' | sed -n 's/^Expiration date: //p'); printf '%s: %s min ahead\\n' \"\$f\" \$(( (\$(date -u -d \"\$e\" +%s) - \$(date -u +%s) + 30) / 60 )); done | paste -sd';' - | sed 's/;/; /'"
finish
