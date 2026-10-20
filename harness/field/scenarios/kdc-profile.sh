#!/usr/bin/env bash
# harness/field/scenarios/kdc-profile.sh --leg mit|rust: what the leg's KDC (as upgrade.sh left it on kdc) takes from
# kdc.conf, seen from client2's MIT kinit, kdc.conf restored after each cell:
#   CF.a: [libdefaults] clockskew = 60, client2's clock +120 s: the AS-REQ's timestamp is refused (Clock skew too
#         great); clockskew = 600 and +400 s: it is accepted. client2's copy of krb5.conf sets kdc_timesync = 0 (the
#         timestamp is client2's clock, not the KDC's), its own clockskew = 900, and enables only the encrypted_timestamp
#         preauth module (the lab's krb5.conf enables SPAKE, which carries no timestamp), so only the KDC's skew decides.
#         The principal is cfskew, made +requires_preauth for these cells: the lab's principals do not require preauth,
#         so their AS-REQ carries no timestamp to judge. The kinit trace's preauth module line is recorded;
#   CF.c: [libdefaults] clockskew = 60 with kadmin restarted on it, client2's clock +120 s: kpasswd of cfpw (made
#         -requires_preauth, so its changepw AS carries no timestamp) is refused for its authenticator's time;
#   CF.d: a second realm stanza (DUMMY.TEST, max_life = 1h) after KERBER.TEST's: alice's TGT life is what it was
#         without it;
#   CF.f: an include line naming a file whose KERBER.TEST stanza sets max_life = 2h: alice's TGT life is 7200 s;
#   CF.g: a KERBER.TEST stanza with Max_Life = 1h, a name MIT matches only as written: alice's TGT life is what it
#         was;
#   CF.h: two [libdefaults] permitted_enctypes lines, aes256-cts-hmac-sha1-96 then aes128-cts-hmac-sha1-96: the KDC
#         takes the first, as MIT's context reads it, so alice's kinit asking for aes256 alone is issued and one
#         asking for aes128 alone is refused (client2's copies of krb5.conf ask for one enctype each). Then an empty
#         first permitted_enctypes line: MIT's KDC permits no enctype, so the aes256 kinit is refused. Each
#         refusal's kinit line is recorded;
#   REP2a: kadmind's listeners, kadmin restarted with iprop on (and [logging] debug, for MIT's debug line), each probed
#         from kdc with an RPC call of procedure 0 under AUTH_NONE (lib/rpc-probe.py): with iprop_port = 749,
#         kadmind's own port, the iprop listener is not added ("Address already added to server") and the iprop
#         program is PROG_UNAVAIL on 749, kadm5 still served (AUTH_TOOWEAK); with iprop_port = 754 kadmind listens
#         on 464, 749 and 754, and each program is served on both RPC ports; with -proponly (KADMIND_ARGS) it listens
#         on 754 alone and kadm5 is PROG_UNAVAIL there. Then, with no iprop, kadmind -port 749 and a krb5.conf (by
#         KRB5_CONFIG in /etc/sysconfig/kadmin) whose admin_server is kdc.kerber.test:754: the MIT leg records the TCP
#         ports kadmind listens on and kadm5's answer on 749 and on 754, and the rust leg must give the same (this run's
#         MIT leg, else runs/mit-latest; with neither, a FAIL);
#   CF.e0: strace on kadmind while client2 changes cfpw's password and runs a kadmin session, and on a second kpropd
#         (port 7754, its own kdc.conf, database, keytab and ACL) while kdc's kprop sends it the realm: neither opens
#         krb5.conf or kdc.conf for a request (lib/profile-opens.sh). strace is installed when kdc lacks it.
# Graded on both legs, MIT's first.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kdc-profile.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}" "${FIELD_RUN:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE ALICE_TEMP ADMIN
R=${REALM//./\\.}
KC=/var/kerberos/krb5kdc/kdc.conf
SC=/etc/sysconfig/kadmin
CF="export KRB5_CONFIG=\$HOME/cf/krb5.conf"
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo rm -f /etc/krb5-rep2a.conf; [ -e $SC.cf ] && sudo mv $SC.cf $SC; [ -e $KC.cf ] && sudo mv $KC.cf $KC && sudo systemctl reset-failed krb5kdc kadmin && sudo systemctl restart krb5kdc kadmin; for p in cfskew cfpw; do sudo kadmin.local -q \"delprinc -force \$p\"; done; sudo rm -f $KC.inc; sudo pkill -x strace; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo sh -s -- kpropd-stop $REALM" < "$FIELD_LIB/profile-opens.sh" > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'sudo systemctl start chronyd; rm -rf ~/cf; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kdcwith <check> <text appended to kdc.conf>: the original kdc.conf plus that text, then the KDC restarted.
kdcwith() {
    local expect='^krb5kdc: active, 88 listening$'
    [ -n "${3:-}" ] && expect=$3
    check "$1" "$expect" run kdc "sudo cp -p $KC.cf $KC && printf '%b' '$2' | sudo tee -a $KC > /dev/null && sudo systemctl reset-failed krb5kdc kadmin && sudo systemctl restart krb5kdc && for i in \$(seq 1 40); do ss -Hlun 'sport = :88' | grep -q . && break; sleep 0.25; done; sudo tail -n 6 $KC; echo \"krb5kdc: \$(systemctl is-active krb5kdc), 88 \$(ss -Hlun 'sport = :88' | grep -q . && echo listening)\"; if [ \"\$(systemctl is-active krb5kdc)\" != active ]; then sudo systemctl status krb5kdc --no-pager -n 12 || true; fi"
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
# admrestart <check>: kadmin restarted on kdc.conf as it now is.
admrestart() {
    check "$1" '^kadmin: active, 464 listening$' run kdc "sudo systemctl reset-failed krb5kdc kadmin && sudo systemctl restart kadmin && for i in \$(seq 1 40); do ss -Hlun 'sport = :464' | grep -q . && break; sleep 0.25; done; echo \"kadmin: \$(systemctl is-active kadmin), 464 \$(ss -Hlun 'sport = :464' | grep -q . && echo listening)\"; if [ \"\$(systemctl is-active kadmin)\" != active ]; then sudo systemctl status kadmin --no-pager -n 12; fi"
}
# kpwskewed <check> <seconds> <ERE>: client2's clock moved ahead by that much, cfpw's kpasswd through the copy of
# krb5.conf (the old password, then the new one twice), then chronyd started again to step the clock back.
kpwskewed() {
    run client2 "sudo systemctl stop chronyd && sudo date -s @\$(( \$(date +%s) + $2 )) > /dev/null && date -u +%T"
    check "$1" "$3" runin client2 "cfpw's password, then the new one twice (all alice's, $ALICE)" "$CF; kpasswd cfpw 2>&1; echo \"kpasswd rc=\$?\""
    run client2 "sudo systemctl start chronyd"
    waitsync client2
}
# etkinit <check> <enctype> <ERE>: alice's kinit from client2 through the copy of krb5.conf that asks for that enctype
# alone.
etkinit() {
    check "$1" "$3" runin client2 "alice's password ($ALICE)" "KRB5_CONFIG=\$HOME/cf/$2.conf kinit -c FILE:\$HOME/cf/e.cc alice 2>&1; echo \"kinit rc=\$?\"" < <(once "$ALICE")
}
# admwith <check> <text appended to kdc.conf> [kadmind options] [another sysconfig line]: the original kdc.conf plus
# that text, KADMIND_ARGS set to the options, kadmin restarted; then the TCP ports kadmind listens on.
admwith() {
    check "$1" '^kadmin: active$' run kdc "sudo cp -p $KC.cf $KC && printf '%b' '$2' | sudo tee -a $KC > /dev/null && { echo 'KADMIND_ARGS=${3:-}'; [ -z '${4:-}' ] || echo '${4:-}'; } | sudo tee $SC > /dev/null && sudo systemctl reset-failed krb5kdc kadmin && sudo systemctl restart kadmin; for i in \$(seq 1 40); do sudo ss -Hltnp | grep -q '\"kadmind\"' && break; sleep 0.25; done; sleep 1; echo \"kadmin: \$(systemctl is-active kadmin)\"; echo \"tcp ports: \$(sudo ss -Hltnp | grep '\"kadmind\"' | awk '{print \$4}' | sed 's/.*://' | sort -un | paste -sd' ')\""
}
# ipropconf <port>: kdc.conf text turning iprop on at that port, with [logging] debug for MIT's debug lines.
ipropconf() {
    printf '%s' "\n[realms]\n    $REALM = {\n        iprop_enable = true\n        iprop_port = $1\n    }\n\n[logging]\n    debug = true\n"
}
# added <check> <mark> <ERE>: the "Address already added to server" lines kadmind.log gained since kdcmark <mark>.
added() {
    local k='' a=''
    read -r k a 2> /dev/null < "$STATE/mark.$2" || true
    check "$1" "$3" run kdc "printf 'already added: %s\n' \"\$(sudo tail -n +$(( ${a:-0} + 1 )) /var/log/kadmind.log | grep -c 'Address already added to server')\""
}
# probe <check> <port> <program> <version> <ERE>: kdc's RPC call of procedure 0 under AUTH_NONE to kadmind there.
probe() {
    check "$1" "$5" runin kdc "lib/rpc-probe.py" "python3 - 127.0.0.1 $2 $3 $4" < "$FIELD_LIB/rpc-probe.py"
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
run kdc "for p in cfskew cfpw; do sudo kadmin.local -q \"delprinc -force \$p\" 2>&1 | grep -v '^Authenticating'; done; true"
check setup.cfskew "^Principal \"cfskew@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc +requires_preauth cfskew' 2>&1" < <(twice "$ALICE")
check setup.cfpw "^Principal \"cfpw@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc -requires_preauth cfpw' 2>&1" < <(twice "$ALICE")
check client2.cfconf '^> +kdc_timesync = 0$' run client2 "mkdir -p ~/cf && awk '/^\\[libdefaults\\]/ && !d { print; print \"    kdc_timesync = 0\"; print \"    clockskew = 900\"; d = 1; next } { print }' /etc/krb5.conf > ~/cf/krb5.conf; printf '\\n[plugins]\\n    clpreauth = {\\n        enable_only = encrypted_timestamp\\n    }\\n' >> ~/cf/krb5.conf; diff /etc/krb5.conf ~/cf/krb5.conf; true"

section "CF.a clockskew = 60, client2 +120 s: refused (MIT and ours)"
kdcwith CF.a.60.kdc '\n[libdefaults]\n    clockskew = 60\n'
skewed CF.a.60.kinit 120 'Clock skew too great while getting initial credentials$' < <(once "$ALICE")

section "CF.a clockskew = 600, client2 +400 s: accepted (MIT and ours)"
kdcwith CF.a.600.kdc '\n[libdefaults]\n    clockskew = 600\n'
skewed CF.a.600.kinit 400 '^kinit rc=0$' < <(once "$ALICE")

section "CF.c clockskew = 60, kadmin restarted, client2 +120 s: kpasswd refused for the AP-REQ's time (MIT and ours)"
kdcwith CF.c.kdc '\n[libdefaults]\n    clockskew = 60\n'
admrestart CF.c.kadmin
kpwskewed CF.c.kpasswd 120 'Failed reading application request$' < <(chpw "$ALICE" "$ALICE")

section "CF.d a DUMMY.TEST stanza with max_life = 1h after KERBER.TEST's: alice's TGT life unchanged (MIT and ours)"
kdcwith CF.d.one-stanza ''
life CF.d.life-before
L0=${LIFE:-}
check CF.d.longer-than-1h '^life before: [0-9]+ s, over 3600$' host "[ \"${L0:-0}\" -gt 3600 ] && echo 'life before: $L0 s, over 3600'"
kdcwith CF.d.two-stanzas '\n[realms]\n    DUMMY.TEST = {\n        max_life = 1h\n    }\n'
life CF.d.life-after
check CF.d.life "^same TGT life: ${L0:-none} s\$" host "echo 'same TGT life: ${LIFE:-none} s'"

section "CF.f an include line naming a file with KERBER.TEST's max_life = 2h: alice's TGT life 7200 s (MIT and ours)"
check CF.f.inc "^        max_life = 2h\$" run kdc "printf '[realms]\\n    $REALM = {\\n        max_life = 2h\\n    }\\n' | sudo tee $KC.inc > /dev/null && sudo cat $KC.inc"
kdcwith CF.f.kdc "\ninclude $KC.inc\n"
life CF.f.life
check CF.f.life-2h '^TGT life: 7200 s$' host "echo 'TGT life: ${LIFE:-none} s'"

section "CF.g a KERBER.TEST stanza with Max_Life = 1h: a name MIT does not know, so alice's TGT life unchanged (MIT and ours)"
kdcwith CF.g.kdc "\n[realms]\n    $REALM = {\n        Max_Life = 1h\n    }\n"
life CF.g.life-after
check CF.g.life "^same TGT life: ${L0:-none} s\$" host "echo 'same TGT life: ${LIFE:-none} s'"

section "CF.h two [libdefaults] permitted_enctypes lines: the KDC takes the first (MIT and ours)"
kdcwith CF.h.kdc '\n[libdefaults]\n    permitted_enctypes = aes256-cts-hmac-sha1-96\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n'
check CF.h.client '^two copies$' run client2 "for e in aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96; do awk -v e=\$e '/^\\[libdefaults\\]/ && !d { print; print \"    default_tkt_enctypes = \" e; print \"    permitted_enctypes = \" e; d = 1; next } { print }' /etc/krb5.conf > ~/cf/\$e.conf; done; grep -h 'default_tkt_enctypes' ~/cf/aes*.conf; echo 'two copies'"
etkinit CF.h.first aes256-cts-hmac-sha1-96 '^kinit rc=0$'
etkinit CF.h.second aes128-cts-hmac-sha1-96 '^kinit rc=1$'
observelast obs.CF.h.second 'kinit: .*'
kdcwith CF.h.empty.kdc '\n[libdefaults]\n    permitted_enctypes =\n    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n' 'krb5kdc: failed'
checklast CF.h.empty.kdc.status 'Improper format of Kerberos configuration file'
etkinit CF.h.empty aes256-cts-hmac-sha1-96 '^kinit rc=1$'
observelast obs.CF.h.empty 'kinit: .*'

section "REP2a iprop_port = kadmind's 749: the iprop listener is not added, so iprop is not served there (MIT and ours)"
check REP2a.sysconfig '^KADMIND_ARGS=' run kdc "sudo cp -p $SC $SC.cf && cat $SC"
kdcmark rep2a749
admwith REP2a.749.kadmin "$(ipropconf 749)"
checklast REP2a.749.ports '^tcp ports: 464 749$'
added REP2a.749.log rep2a749 '^already added: [1-9][0-9]*$'
probe REP2a.749.iprop 749 100423 1 'PROG_UNAVAIL$'
probe REP2a.749.kadm5 749 2112 2 'AUTH_TOOWEAK$'

section "REP2a iprop_port = 754: kadmind listens on 464, 749 and 754, and each RPC port serves both programs (MIT and ours)"
kdcmark rep2a754
admwith REP2a.754.kadmin "$(ipropconf 754)"
checklast REP2a.754.ports '^tcp ports: 464 749 754$'
added REP2a.754.log rep2a754 '^already added: 0$'
probe REP2a.754.iprop 754 100423 1 'AUTH_TOOWEAK$'
probe REP2a.754.iprop-on-749 749 100423 1 'AUTH_TOOWEAK$'
probe REP2a.754.kadm5-on-754 754 2112 2 'AUTH_TOOWEAK$'

section "REP2a -proponly with iprop_port = 754: kadmind listens on 754 alone and serves iprop only (MIT and ours)"
admwith REP2a.proponly.kadmin "$(ipropconf 754)" -proponly
checklast REP2a.proponly.ports '^tcp ports: 754$'
probe REP2a.proponly.iprop 754 100423 1 'AUTH_TOOWEAK$'
probe REP2a.proponly.kadm5 754 2112 2 'PROG_UNAVAIL$'

section "REP2a krb5.conf plus a $REALM stanza with admin_server = kdc.kerber.test:754, the realm's last, and kadmind -port 749: the ports MIT's kadmind takes, and ours must take the same"
check REP2a.port.krb5conf 'admin_server = kdc\.kerber\.test:754$' run kdc "{ cat /etc/krb5.conf; printf '\\n[realms]\\n    $REALM = {\\n        admin_server = kdc.kerber.test:754\\n    }\\n'; } | sudo tee /etc/krb5-rep2a.conf > /dev/null && grep -n 'admin_server' /etc/krb5-rep2a.conf"
admwith REP2a.port.kadmin '' '-port 749' 'KRB5_CONFIG=/etc/krb5-rep2a.conf'
REF=''
if [ "$LEG" = rust ]; then
    if [ -f "$FIELD_RUN/kdc-profile/mit/result" ]; then REF=$FIELD_RUN/kdc-profile/mit/checks.tsv
    elif [ -f "$LAB_HOME/runs/mit-latest/kdc-profile/mit/checks.tsv" ]; then REF=$LAB_HOME/runs/mit-latest/kdc-profile/mit/checks.tsv; fi
    note "REP2a.port is compared with ${REF:-no MIT leg: neither this run nor runs/mit-latest has one}"
fi
# portfact <fact>: the last command's line, recorded; on the rust leg it must be the MIT leg's.
portfact() {
    local mit=''
    observelast "obs.REP2a.port.$1" '.+'
    [ "$LEG" = rust ] || return 0
    [ -n "$REF" ] && mit=$(awk -F'\t' -v n="obs.REP2a.port.$1" '$1 == n { print $5; exit }' "$REF")
    if [ -n "$mit" ]; then
        checklast "REP2a.port.$1" "line:$mit"
    else
        _checkrow "REP2a.port.$1" FAIL "as the MIT leg's obs.REP2a.port.$1" - "NOT-RUN: no MIT leg's obs.REP2a.port.$1 to compare with"
    fi
}
run kdc "echo \"tcp ports: \$(sudo ss -Hltnp | grep '\"kadmind\"' | awk '{print \$4}' | sed 's/.*://' | sort -un | paste -sd' ')\""
portfact ports
runin kdc "lib/rpc-probe.py" "python3 - 127.0.0.1 749 2112 2" < "$FIELD_LIB/rpc-probe.py"
portfact kadm5-749
runin kdc "lib/rpc-probe.py" "python3 - 127.0.0.1 754 2112 2" < "$FIELD_LIB/rpc-probe.py"
portfact kadm5-754

section "kdc.conf restored"
check kdc.conf.restored '^restored, krb5kdc and kadmin active$' run kdc "sudo rm -f /etc/krb5-rep2a.conf && sudo mv $KC.cf $KC && sudo mv $SC.cf $SC && sudo systemctl reset-failed krb5kdc kadmin && sudo systemctl restart krb5kdc kadmin && systemctl is-active krb5kdc kadmin > /dev/null && ! sudo grep -qE '^[[:space:]]*clockskew|DUMMY\\.TEST' $KC && echo 'restored, krb5kdc and kadmin active' || sudo systemctl status krb5kdc kadmin --no-pager -n 12"

# opens <name> <pid expression>: strace attached to the daemon that pid names.
opens() {
    check "CF.e0.$1.attach" "^$1 [0-9]+ traced by [1-9][0-9]*\$" runin kdc "lib/profile-opens.sh" "sudo sh -s -- attach $1 $2" < "$FIELD_LIB/profile-opens.sh"
}
# opened <name>: strace detached; the daemon took requests, and opened neither krb5.conf nor kdc.conf for them.
opened() {
    check "CF.e0.$1.live" "^$1 live: [1-9][0-9]* accept/recv lines\$" runin kdc "lib/profile-opens.sh" "sudo sh -s -- detach $1" < "$FIELD_LIB/profile-opens.sh"
    checklast "CF.e0.$1.opens" "^$1 profile opens: 0\$"
}

section "CF.e0 kadmind takes a kpasswd change and a kadmin session without opening krb5.conf or kdc.conf (MIT and ours)"
check CF.e0.strace '^strace-[0-9]' run kdc "rpm -q strace > /dev/null 2>&1 || sudo dnf -y -q install strace > /dev/null 2>&1; rpm -q strace"
opens kadmind "\$(systemctl show -p MainPID --value kadmin)"
check CF.e0.kpasswd '^Password changed\.$' runin client2 "cfpw's password ($ALICE), then alice-changed's twice ($ALICE_TEMP)" "kpasswd cfpw 2>&1" < <(chpw "$ALICE" "$ALICE_TEMP")
check CF.e0.kadmin "^Principal: cfpw@$R\$" runin client2 "admin/admin's password ($ADMIN)" "kadmin -p admin/admin -q 'getprinc cfpw' 2>&1" < <(once "$ADMIN")
opened kadmind

section "CF.e0 a second kpropd takes one kprop without opening krb5.conf or kdc.conf (MIT and ours)"
check CF.e0.kpropd.start '^kpropd [0-9]+ listening on 7754$' runin kdc "lib/profile-opens.sh" "sudo sh -s -- kpropd-start $LEG $REALM" < "$FIELD_LIB/profile-opens.sh"
opens kpropd "\$(cat /var/tmp/cf-e0/kpropd.pid)"
check CF.e0.kprop 'SUCCEEDED$' run kdc "sudo kprop -r $REALM -f /var/tmp/cf-e0/dump -P 7754 -s /var/tmp/cf-e0/kt \$(hostname -f) 2>&1"
check CF.e0.kpropd.loaded '^loaded$' run kdc "for i in \$(seq 1 40); do sudo test -e /var/tmp/cf-e0/replica/principal && break; sleep 0.25; done; sleep 1; sudo test -e /var/tmp/cf-e0/replica/principal && echo loaded"
opened kpropd
check CF.e0.kpropd.stop '^kpropd stopped' runin kdc "lib/profile-opens.sh" "sudo sh -s -- kpropd-stop $REALM" < "$FIELD_LIB/profile-opens.sh"
finish
