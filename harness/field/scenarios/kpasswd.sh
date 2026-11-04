#!/usr/bin/env bash
# harness/field/scenarios/kpasswd.sh --leg mit|rust: kpasswd (464) on the leg's KDC as upgrade.sh left it on kdc,
# driven from client2 by MIT's libkrb5 (lib/setpw.py) and by raw datagrams (lib/udp-send.py):
#   KH.2: admin/admin (kadm5.acl '*') sets khtarget's password: 0, kvno + 1 (the control);
#   KH.other-unprivileged: khuser sets khtarget's: 5, kvno kept;
#   KH.no-initial: khuser sets its own with a changepw ticket from the TGS (+allow_tgs_req for the cell): 7;
#   KH.5: khuser sets its own to alice-changed's password, a NUL and 'suffix' (setpw.py --frame); kinit with the
#         part before the NUL;
#   KH.6: the database cannot be written (bound read-only), then is gone (moved aside): MIT's answers, no path;
#   KH.4: kpasswd's answer to its own error frame (CVE-2002-2443's loop);
#   KH.3: kadmin/changepw (LOCKDOWN_KEYS) sets its own password with an INITIAL ticket;
#   KH.1: admin/admin sets krbtgt/KERBER.TEST's password.
# MIT answers KH.4's echo and allows KH.3 and KH.1 (INFO rows on its leg); ours refuses them (graded). Every other
# row is graded on both legs, MIT's first. KH.3 and KH.1 change keys on a leg that allows it, so this scenario is
# the last of its profiles.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kpasswd.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE ALICE_TEMP ADMIN
R=${REALM//./\\.}
DB=/var/kerberos/krb5kdc
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "findmnt -n $DB > /dev/null && sudo umount $DB; [ -e $DB/principal.kh ] && sudo mv $DB/principal.kh $DB/principal; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'rm -rf ~/kh; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kc <ccache> <principal> <what stdin carries> [kinit options]: kinit on client2 into ~/kh/<ccache>.cc.
kc() { local cc=$1 p=$2 what=$3; shift 3; runin client2 "$what" "kinit $* -c FILE:\$HOME/kh/$cc.cc $p && klist -c FILE:\$HOME/kh/$cc.cc"; }
# sp <ccache> <target> <what stdin carries> [--frame]: setpw.py from client2, the new password on stdin.
sp() { local cc=$1 t=$2 what=$3; shift 3; runin client2 "$what" "python3 \$HOME/kh/setpw.py -c FILE:\$HOME/kh/$cc.cc -t $t@$REALM $* kdc.kerber.test"; }
# kv <principal>: its newest key's version from kadmin.local on kdc, in KV (-1 when none is read).
kv() {
    run kdc "sudo kadmin.local -q 'getprinc $1' 2>&1 | grep -m1 -E '^Key: vno '"
    KV=$(sed -n 's/^Key: vno \([0-9][0-9]*\),.*/\1/p' "$LAST_OUT")
    KV=${KV:--1}
}
# ours <name> <ERE> <MIT's ERE>: graded on our leg; on MIT's an INFO row of what MIT answered.
ours() { if [ "$LEG" = mit ]; then observelast "obs.$1" "$3"; else checklast "$1" "$2"; fi; }

section "kpasswd --leg $LEG: 464 on the $LEG KDC, MIT's libkrb5 from client2"
kdcis
resetvm client2
run client2 "rm -rf ~/kh; mkdir -m 0700 ~/kh"
check client2.setpw rc runin client2 "lib/setpw.py" "cat > ~/kh/setpw.py" < "$FIELD_LIB/setpw.py"
check client2.udp-send rc runin client2 "lib/udp-send.py" "cat > ~/kh/udp-send.py" < "$FIELD_LIB/udp-send.py"
run kdc "for p in khuser khtarget; do sudo kadmin.local -q \"delprinc -force \$p\" 2>&1 | grep -v '^Authenticating'; done; sudo kadmin.local -q 'getprinc kadmin/changepw' | grep -E '^(Attributes|Key)'"
check setup.khuser "^Principal \"khuser@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc khuser' 2>&1" < <(twice "$ALICE")
check setup.khtarget "^Principal \"khtarget@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey khtarget' 2>&1"

section "KH.2 the control: admin/admin sets khtarget's password (MIT and ours: 0, kvno + 1)"
check kinit.admin "^Default principal: admin/admin@$R\$" kc admin admin/admin "admin/admin's password ($ADMIN)" -S kadmin/changepw < <(once "$ADMIN")
kv khtarget; K0=$KV
check KH.2.result '^result: 0 \(Success\)$' sp admin khtarget "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
checklast KH.2.ticket "^ticket: kadmin/changepw@$R, initial\$"
check KH.2.kvno "^Key: vno $((K0 + 1)), " kv khtarget

section "KH.other-unprivileged: khuser (no kadm5.acl line) sets khtarget's password (MIT and ours: 5, kvno kept)"
check kinit.khuser "^Default principal: khuser@$R\$" kc khuser khuser "alice's password ($ALICE)" -S kadmin/changepw < <(once "$ALICE")
kv khtarget; K0=$KV
check KH.other-unprivileged.result '^result: 5 \(Access denied\)$' sp khuser khtarget "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
checklast KH.other-unprivileged.text '^text: Unauthorized request$'
check KH.other-unprivileged.kvno "^Key: vno $K0, " kv khtarget

section "KH.no-initial: khuser sets its own password with a changepw ticket from the TGS (MIT and ours: 7)"
check no-initial.allow '^Attributes: ' run kdc "sudo kadmin.local -q 'modprinc +allow_tgs_req kadmin/changepw' 2>&1; sudo kadmin.local -q 'getprinc kadmin/changepw' | grep -E '^Attributes' | grep -v DISALLOW_TGT_BASED"
check kinit.khuser-tgt "^Default principal: khuser@$R\$" kc khtgt khuser "alice's password ($ALICE)" < <(once "$ALICE")
check KH.no-initial.result '^result: 7 \(Initial password required\)$' sp khtgt khuser "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
checklast KH.no-initial.ticket "^ticket: kadmin/changepw@$R, not initial\$"
checklast KH.no-initial.text '^text: Ticket must be derived from a password$'
check no-initial.disallow '^Attributes: .*DISALLOW_TGT_BASED' run kdc "sudo kadmin.local -q 'modprinc -allow_tgs_req kadmin/changepw' 2>&1; sudo kadmin.local -q 'getprinc kadmin/changepw' | grep -E '^Attributes'"

section "KH.5 an embedded NUL: khuser sets its own password to alice-changed's, a NUL, then 'suffix' (setpw.py --frame); kinit with the part before the NUL (MIT and ours)"
check kinit.khuser5 "^Default principal: khuser@$R\$" kc kh5 khuser "alice's password ($ALICE)" -S kadmin/changepw < <(once "$ALICE")
check KH.5.result '^result: 0 \(Success\)$' sp kh5 khuser "alice-changed's password ($ALICE_TEMP), a NUL, 'suffix'" --frame < <(printf '%s\0suffix\n' "$(< "$SECRETS/$ALICE_TEMP")")
checklast KH.5.ticket "^ticket: kadmin/changepw@$R, initial\$"
check KH.5.kinit "^Default principal: khuser@$R\$" kc khnul khuser "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")

section "KH.6 the database cannot be written: $DB bound read-only on kdc; khuser sets its own password (MIT's text; ours the same, no path)"
check KH.6.setup "^Password for \"khuser@$R\" changed\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'cpw khuser' 2>&1" < <(twice "$ALICE")
check kinit.khuser6 "^Default principal: khuser@$R\$" kc kh6 khuser "alice's password ($ALICE)" -S kadmin/changepw < <(once "$ALICE")
check KH.6.ro '^ro,' run kdc "findmnt -n $DB && exit 1; sudo mount --bind $DB $DB && sudo mount -o remount,ro,bind $DB && findmnt -no OPTIONS $DB"
check KH.6.result '^result: 2 \(Server error\)$' sp kh6 khuser "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
checklast KH.6.text '^text: Password not changed\.\\nRead-only file system while trying to change password\.\\n$'
checklast KH.6.no-path '^text: [^/]*$'
check KH.6.rw '^not a mount$' run kdc "sudo umount $DB; findmnt -n $DB || echo 'not a mount'"

section "KH.6 the database is gone: $DB/principal moved aside; khuser sets its own password (MIT's answer: the AP-REQ is not read; ours the same)"
check kinit.khuser6b "^Default principal: khuser@$R\$" kc kh6b khuser "alice's password ($ALICE)" -S kadmin/changepw < <(once "$ALICE")
check KH.6-gone.moved rc run kdc "sudo mv $DB/principal $DB/principal.kh && sudo ls $DB"
check KH.6-gone.result '^result: 3 \(Authentication error\)$' sp kh6b khuser "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
checklast KH.6-gone.text '^text: Failed reading application request$'
check KH.6-gone.back rc run kdc "sudo mv $DB/principal.kh $DB/principal && sudo ls $DB"

section "KH.4 kpasswd's answer to its own error frame, sent back from client2 (CVE-2002-2443): MIT answers it (INFO), ours does not"
kdcmark echo
check KH.4.probe "^probe: sent 8 bytes, reply [0-9]+ bytes, version 1, AP-REP length 0, KRB-ERROR 60, result 3 'Failed reading application request'\$" run client2 "python3 \$HOME/kh/udp-send.py kdc.kerber.test"
ours KH.4.echo '^echo: sent the reply back \([0-9]+ bytes\), no reply in 3 s$' '^echo: .*'
kdcsince echo 'dispatching'
ours KH.4.log 'Invalid message type - while dispatching \(udp\)$' '.*dispatching.*'

section "KH.3 kadmin/changepw (LOCKDOWN_KEYS) sets its own password with an INITIAL ticket: MIT allows it (INFO); ours 5, kvno kept"
check KH.3.setup "^Password for \"kadmin/changepw@$R\" changed\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'cpw kadmin/changepw' 2>&1" < <(twice "$ALICE")
check kinit.changepw "^Default principal: kadmin/changepw@$R\$" kc cpw kadmin/changepw "alice's password ($ALICE)" -S kadmin/changepw < <(once "$ALICE")
kv kadmin/changepw; K0=$KV
sp cpw kadmin/changepw "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
ours KH.3.result '^result: 5 \(Access denied\)$' '^result: .*'
ours KH.3.text '^text: Unauthorized request$' '^text: .*'
kv kadmin/changepw
ours KH.3.kvno "^Key: vno $K0, " '^Key: vno [0-9]+'

section "KH.1 admin/admin sets krbtgt/$REALM's password: MIT allows it (INFO); ours 5, kvno kept, the change-password line logged"
check kinit.admin1 "^Default principal: admin/admin@$R\$" kc admin1 admin/admin "admin/admin's password ($ADMIN)" -S kadmin/changepw < <(once "$ADMIN")
kv "krbtgt/$REALM"; K0=$KV
kdcmark lockdown
sp admin1 "krbtgt/$REALM" "alice-changed's password ($ALICE_TEMP)" < <(once "$ALICE_TEMP")
ours KH.1.result '^result: 5 \(Access denied\)$' '^result: .*'
ours KH.1.text '^text: Unauthorized request$' '^text: .*'
kv "krbtgt/$REALM"
ours KH.1.kvno "^Key: vno $K0, " '^Key: vno [0-9]+'
kdcsince lockdown 'setpw request'
ours KH.1.log "setpw request from 192\\.168\\.177\\.22 by admin/admin@$R for admin/admin@$R: Operation requires \`\`change-password'' privilege\$" 'setpw request .*'

finish
