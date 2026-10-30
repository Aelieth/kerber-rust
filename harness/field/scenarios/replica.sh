#!/usr/bin/env bash
# harness/field/scenarios/replica.sh --leg mit|rust: incremental propagation from an MIT primary to a replica (REP-4b
# legs 1 and 2, REP-1's proof). kdc is reset to the MIT baseline in both legs and serves as the primary, with iprop on
# port 754 for the run (on 749, MIT's net-server keeps kadmind's own program and drops iprop's, and Fedora's
# kadmind_t may bind kprop_port_t but no unreserved port); kdc2 is the replica: MIT's kpropd and krb5kdc on f4-mit-f44
# (leg mit), this port's on rust-replica-f44 with the ref's build streamed from kdc, where upgrade left it (leg rust:
# upgrade runs first, and this scenario last, as it leaves kdc on the MIT baseline; without that build on kdc the leg
# stops before kdc is reset, so a lone --only replica has nothing to stream). FIELD_REPLICA_BAKED=1 keeps
# rust-replica-f44's own programs instead (the parent leg, without upgrade). Each kpropd is started from the ssh session
# with -d in a session of its own (setsid -f), so the ssh command returns; its lines go to /var/tmp/rep/kpropd.log on
# kdc2. The stash and the keytabs go from kdc to kdc2 through an ssh pipe, which the host relays without a copy, never
# into a file on the host or the record. Cells, graded on both legs unless noted:
#   REP.1: kdc2's kpropd asks for a full resync and kdc's kadmind sends the dump; kprop -f of a plain kdb5_util dump is
#          refused, as MIT's iprop replica loads only an iprop dump (load -i); kdc2's krb5kdc then issues alice's TGT
#          to client2, whose krb5.conf names kdc2 alone;
#   REP.4: kpropd.acl without the primary: MIT's kprop line "Broken pipe while sending database", and kpropd's
#          "Rejected connection from unauthorized principal";
#   REP.2: addprinc, cpw, modprinc -maxlife, a second addprinc, delprinc and renprinc on kdc reach kdc2 within two
#          polls (10 s each): the renamed principal's getprinc lines equal kdc's, the deleted one is gone, and MIT's
#          kproplog -h gives one last serial on both;
#   REP.3: addpol and a principal put under it. The MIT leg records whether kdc2's kpropd then asked for a full
#          resync, whether the policy is on kdc2 and whether the principal is under it there; the rust leg must say
#          the same three (this run's MIT leg, else runs/mit-latest; with neither, a FAIL);
#   REP.6: a +requires_preauth principal fails twice on kdc2 and once on kdc, then a modprinc on kdc arrives: each KDC
#          keeps its own count (MIT's replica ignores AT_FAIL_AUTH_COUNT);
#   REP.7: setstr on kdc arrives, and kdc2 keeps its count;
#   REP.5: kiprop/kdc2 without p: kpropd logs MIT's "get_updates permission denied", bails and exits;
#   REP.8: kpropd started again asks from its last serial, takes one addprinc and asks for no full resync.
# kdc2 must be up for the run's preflight (lab.sh up kdc2); this scenario resets it to its leg's snapshot at the start
# and at the end, and parks it.
# vms: kdc kdc2 client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: replica.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}" "${FIELD_RUN:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
# The primary is MIT's in both legs, so its realm's passwords are.
REALM=$MIT_REALM ALICE=$MIT_SECRET_ALICE
R=${REALM//./\\.}
KC=/var/kerberos/krb5kdc/kdc.conf
ACL=/var/kerberos/krb5kdc/kadm5.acl
W=/var/tmp/rep
IPORT=754
CO=kerber-rust-${FIELD_SHA:0:12}
# The replica's programs: each cargo binary and the MIT name it is installed under.
PROGS='krb5-kdc:krb5kdc krb5-kpropd:kpropd krb5-kdb:kdb5_util krb5-kadmin-local:kadmin.local'
BINS='krb5-kdc krb5-kpropd krb5-kdb krb5-kadmin-local'
INSTALLED='/usr/sbin/krb5kdc /usr/sbin/kpropd /usr/sbin/kdb5_util /usr/sbin/kadmin.local'
KPROPD="cd / && sudo setsid -f /usr/sbin/kpropd -d -D -A kdc.kerber.test -s /etc/krb5.keytab >> $W/kpropd.log 2>&1 < /dev/null;"
# A line kdc2 prints itself, not its login shell (rust-replica-f44's ~/.bashrc reports a missing ~/.cargo/env first).
OWN='^([^/]|/usr/).*'
# The getprinc lines both KDCs must agree on.
FIELDS='^(Principal|Maximum ticket life|Maximum renewable life|Attributes|Policy|Key: vno)'
# kdc's kadmind restarted, and up once its iprop program listens.
KADMIND="sudo systemctl restart kadmin; for i in \$(seq 1 40); do sudo ss -Hltnp 'sport = :$IPORT' | grep -q kadmind && break; sleep 0.25; done; echo \"kadmind: \$(systemctl is-active kadmin)\$(sudo ss -Hltnp 'sport = :$IPORT' | grep -q kadmind && echo ', iprop on $IPORT')\""
if [ "$LEG" = mit ]; then KDC2_SNAP=$MIT_SNAPSHOT_KDC2; else KDC2_SNAP=$RUST_SNAPSHOT_KDC2; fi
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc2 -- "sudo pkill -x kpropd; sudo pkill -x krb5kdc; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo rm -rf $W" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- "rm -rf ~/rep" < /dev/null > /dev/null 2>&1
    timeout -k 5 300 "$LAB" reset kdc2 "$KDC2_SNAP" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" down kdc2 < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# kadm <query>: kadmin.local on kdc, recorded.
kadm() { run kdc "sudo kadmin.local -q '$1' 2>&1 | grep -v '^Authenticating'"; }
# replicated <check> <principal> <ERE>: kdc2's getprinc of it, waited for up to two polls and a margin (30 s).
replicated() {
    check "$1" "$3" run kdc2 "for i in \$(seq 1 30); do sudo kadmin.local -q 'getprinc $2' 2>&1 | grep -qE '$3' && break; sleep 1; done; sudo kadmin.local -q 'getprinc $2' 2>&1 | grep -v '^Authenticating'"
}
# kpropdlog <check> <ERE> [seconds]: kdc2's kpropd lines, waited for (30 s unless given).
kpropdlog() {
    check "$1" "$2" run kdc2 "for i in \$(seq 1 ${3:-30}); do grep -qE '$2' $W/kpropd.log && break; sleep 1; done; grep -nE '$2' $W/kpropd.log | tail -n 3"
}
# serial <vm> <kproplog>: the last serial of the vm's update log, as MIT's kproplog -h gives it, into the run's state.
serial() {
    run "$1" "$2 -h | grep -E 'Last serial # :' | sed -E 's/^[[:space:]]+//'"
    grep -E '^Last serial # :' "$LAST_OUT" > "$STATE/serial.$1"
}
# fields <vm> <principal> <file>: the getprinc lines both KDCs must agree on, into the run's state.
fields() {
    run "$1" "sudo kadmin.local -q 'getprinc $2' 2>&1 | grep -E '$FIELDS'"
    grep -E "$FIELDS" "$LAST_OUT" > "$STATE/$3"
}

section "replica --leg $LEG: MIT primary on kdc ($MIT_SNAPSHOT_KDC), replica on kdc2 ($KDC2_SNAP)"
BAKED=${FIELD_REPLICA_BAKED:-0}
if [ "$LEG" = rust ] && [ "$BAKED" = 0 ]; then
    note "the ref's build is on kdc as upgrade left it; it is streamed to kdc2 before kdc is reset"
    kdcis
    check build.kdc '^4 programs built$' run kdc "cd ~/$CO/target/release && ls $BINS | wc -l | sed 's/\$/ programs built/'"
    check build.sums '^[0-9a-f]{64}  krb5-' run kdc "cd ~/$CO/target/release && sha256sum $BINS"
    cp "$LAST_OUT" "$STATE/build.sums"
    check build.tar rc host "$LABQ ssh kdc -- 'tar -C ~/$CO/target/release -c $BINS' > $(printf '%q' "$STATE/build.tar")"
    if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then
        note "the ref's build is not on kdc as upgrade --leg rust leaves it: the leg stops here, before kdc is reset"
        finish
        exit 1
    fi
fi
check reset.kdc rc host "$LABQ reset kdc $MIT_SNAPSHOT_KDC"
check reset.client2 rc host "$LABQ reset client2 $MIT_SNAPSHOT_CLIENT2"
check reset.kdc2 rc host "$LABQ reset kdc2 $KDC2_SNAP"
waitsync kdc
waitsync client2
waitsync kdc2
if [ "$LEG" = rust ] && [ "$BAKED" = 1 ]; then
    note "FIELD_REPLICA_BAKED=1: kdc2 keeps $RUST_SNAPSHOT_KDC2's own programs"
    observe obs.build.baked '[0-9a-f]{64} .*' run kdc2 "sha256sum $INSTALLED"
elif [ "$LEG" = rust ]; then
    check build.kdc2 '^installed 4$' hostin "the ref's programs (tar)" "$LABQ ssh kdc2 -- 'rm -rf ~/rep-bin && mkdir ~/rep-bin && tar -x -C ~/rep-bin && n=0; for p in $PROGS; do sudo install -m 0755 ~/rep-bin/\${p%%:*} /usr/sbin/\${p#*:} && n=\$((n + 1)); done; sudo restorecon $INSTALLED; echo installed \$n'" < "$STATE/build.tar"
    rm -f "$STATE/build.tar"
    run kdc2 "sha256sum $INSTALLED"
    check build.same '^same: 4 programs$' host "diff <(grep -oE '^[0-9a-f]{64}' $(printf '%q' "$STATE/build.sums")) <(grep -oE '^[0-9a-f]{64}' $(printf '%q' "$LAST_OUT")) > /dev/null && echo \"same: \$(grep -cE '^[0-9a-f]{64}' $(printf '%q' "$LAST_OUT")) programs\""
fi
# rust-replica-f44 has no krb5-server, so MIT's kproplog comes from kdc (Fedora 43's krb5-server 1.22.2-4) when ldd
# finds each library it needs on kdc2, else from Fedora 44's krb5-server rpm, unpacked and not installed. It reads the
# replica's update log, which this port keeps in MIT's format.
if [ "$LEG" = rust ]; then
    check kproplog.copied '^kproplog copied$' host "$LABQ ssh kdc -- 'cat /usr/sbin/kproplog' | $LABQ ssh kdc2 -- 'mkdir -p ~/rep-bin && install -m 0755 /dev/stdin ~/rep-bin/kproplog && echo kproplog copied'"
    check kproplog.ldd '^kproplog: each library found$' run kdc2 "cd ~/rep-bin && if ldd kproplog | grep -q 'not found'; then { rpm -q cpio > /dev/null || sudo dnf -y -q install cpio > /dev/null 2>&1; }; rm -rf krb5-server-*.rpm usr && dnf download -q krb5-server > /dev/null 2>&1 && rpm2cpio krb5-server-*.rpm | cpio -id --quiet '*/kproplog' && install -m 0755 usr/*/kproplog kproplog && echo 'kproplog: unpacked from the fc44 rpm'; fi; ldd kproplog | grep -E 'libkadm5|libkdb5|not found'; ldd kproplog | grep -q 'not found' || echo 'kproplog: each library found'"
    KPL="sudo ~/rep-bin/kproplog"
else
    KPL="sudo kproplog"
fi

section "the primary: iprop on kdc's realm (port $IPORT), kiprop/kdc2 with p, kdc2's keys, kdc's own key for kprop"
# A second stanza for the realm: MIT's profile reads a realm's relations from every stanza of that name.
check primary.conf "^        iprop_port = $IPORT\$" run kdc "sudo mkdir -p $W && printf '\\n[realms]\\n    %s = {\\n        iprop_enable = true\\n        iprop_port = $IPORT\\n    }\\n' $REALM | sudo tee -a $KC > /dev/null && sudo tail -n 5 $KC"
check primary.acl '^kiprop/kdc2\.kerber\.test@' run kdc "echo 'kiprop/kdc2.kerber.test@$REALM p' | sudo tee -a $ACL"
check primary.kadmind "^kadmind: active, iprop on $IPORT\$" run kdc "$KADMIND"
for p in host/kdc2.kerber.test kiprop/kdc2.kerber.test; do
    check "primary.addprinc.${p%%/*}" "^Principal \"$p@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey $p' 2>&1"
done
# MIT kpropd authenticates as kiprop/kdc2 to kiprop/<admin_server>, which kadmind accepts from the database (KDB:).
check primary.kiprop "^Principal: kiprop/kdc\\.kerber\\.test@$R\$" run kdc "sudo kadmin.local -q 'getprinc kiprop/kdc.kerber.test' 2>&1 | grep -q '^Principal:' || sudo kadmin.local -q 'addprinc -randkey kiprop/kdc.kerber.test' > /dev/null 2>&1; sudo kadmin.local -q 'getprinc kiprop/kdc.kerber.test' 2>&1 | grep '^Principal:'"
check primary.kt.kdc2 'added to keytab' run kdc "sudo kadmin.local -q 'ktadd -k $W/kdc2.keytab host/kdc2.kerber.test kiprop/kdc2.kerber.test' 2>&1"
# kdc's own key, unchanged when the database has it: kprop's here, and the one MIT kadmind's own kprop takes from
# /etc/krb5.keytab for a full resync.
check primary.kt.kprop 'added to keytab' run kdc "sudo kadmin.local -q 'getprinc host/kdc.kerber.test' 2>&1 | grep -q '^Principal:' || sudo kadmin.local -q 'addprinc -randkey host/kdc.kerber.test'; sudo kadmin.local -q 'ktadd -k $W/kprop.keytab -norandkey host/kdc.kerber.test' 2>&1 && sudo kadmin.local -q 'ktadd -k /etc/krb5.keytab -norandkey host/kdc.kerber.test' 2>&1 && sudo restorecon /etc/krb5.keytab"

section "the replica: kdc2's keytab, the primary's stash, kdc.conf, krb5.conf, kpropd.acl, then kpropd"
check replica.keytab '^keytab copied$' host "$LABQ ssh kdc -- 'sudo cat $W/kdc2.keytab' | $LABQ ssh kdc2 -- 'sudo install -m 0600 /dev/stdin /etc/krb5.keytab && sudo restorecon /etc/krb5.keytab && echo keytab copied'"
check replica.stash '^stash copied$' host "$LABQ ssh kdc -- 'sudo cat /var/kerberos/krb5kdc/.k5.$REALM' | $LABQ ssh kdc2 -- 'sudo install -m 0600 /dev/stdin /var/kerberos/krb5kdc/.k5.$REALM && sudo restorecon /var/kerberos/krb5kdc/.k5.$REALM && echo stash copied'"
check replica.conf "^        iprop_port = $IPORT\$" run kdc2 "printf '[kdcdefaults]\\n    kdc_ports = 88\\n    kdc_tcp_ports = 88\\n\\n[realms]\\n    %s = {\\n        iprop_enable = true\\n        iprop_port = $IPORT\\n        iprop_replica_poll = 10s\\n    }\\n' $REALM | sudo tee $KC > /dev/null && printf '[libdefaults]\\n    default_realm = %s\\n    dns_lookup_kdc = false\\n\\n[realms]\\n    %s = {\\n        kdc = kdc.kerber.test\\n        admin_server = kdc.kerber.test\\n    }\\n' $REALM $REALM | sudo tee /etc/krb5.conf > /dev/null && echo 'host/kdc.kerber.test@$REALM' | sudo tee /var/kerberos/krb5kdc/kpropd.acl > /dev/null && sudo cat $KC"
# The log belongs to the ssh user, whose shell opens it for kpropd's output.
check replica.kpropd '^kpropd listening on 754$' run kdc2 "sudo mkdir -p $W && sudo install -m 0644 -o \$(id -un) /dev/null $W/kpropd.log && $KPROPD for i in \$(seq 1 40); do ss -Hltn 'sport = :754' | grep -q . && break; sleep 0.25; done; ss -Hltn 'sport = :754' | grep -q . && echo 'kpropd listening on 754'"
if [ "$LEG" = rust ] && [ "$BAKED" = 0 ]; then
    KH=$(awk '$2 == "krb5-kpropd" { print $1 }' "$STATE/build.sums")
    check build.running "^running kpropd: ${KH:-none}\$" run kdc2 "echo \"running kpropd: \$(sudo sha256sum /proc/\$(pgrep -xo kpropd)/exe | cut -d' ' -f1)\""
fi

section "REP.1 the first sync: a full resync at kpropd's start, a plain dump refused, kdc2's KDC serving the realm alone"
kpropdlog REP.1.resync 'Full resync request granted'
replicated REP.1.loaded alice "^Principal: alice@$R\$"
check REP.1.dump rc run kdc "sudo kdb5_util dump $W/dump"
run kdc2 "echo '==== plain dump' >> $W/kpropd.log"
run kdc "sudo kprop -r $REALM -f $W/dump -s $W/kprop.keytab kdc2.kerber.test 2>&1; echo \"kprop rc=\$?\""
checklast REP.1.plain '^kprop: .* while reading response from server$'
checklast REP.1.plain.rc '^kprop rc=1$'
observe obs.REP.1.plain.kpropd "$OWN" run kdc2 "sleep 2; sed -n '/^==== plain dump\$/,\$p' $W/kpropd.log | grep -v '^====' | tail -n 6"
# kpropd runs unconfined from the ssh session, so the database its kdb5_util loads gets kdc.conf's directory label.
check REP.1.krb5kdc '^krb5kdc: active, 88 listening$' run kdc2 "sudo restorecon -R /var/kerberos/krb5kdc; sudo systemctl start krb5kdc; for i in \$(seq 1 40); do ss -Hlun 'sport = :88' | grep -q . && break; sleep 0.25; done; echo \"krb5kdc: \$(systemctl is-active krb5kdc), 88 \$(ss -Hlun 'sport = :88' | grep -q . && echo listening)\""
observe obs.REP.1.krb5kdc "$OWN" run kdc2 "systemctl is-active -q krb5kdc && echo 'krb5kdc: active' || { sudo journalctl -u krb5kdc -n 8 --no-pager -o cat; echo \"\$(sudo ausearch -m avc -ts boot 2>/dev/null | grep -c denied) AVC denials since boot\"; }"
check REP.1.client.conf '^        kdc = kdc2\.kerber\.test$' run client2 "mkdir -p ~/rep && printf '[libdefaults]\\n    default_realm = %s\\n    dns_lookup_kdc = false\\n\\n[realms]\\n    %s = {\\n        kdc = kdc2.kerber.test\\n    }\\n' $REALM $REALM > ~/rep/krb5.conf && cat ~/rep/krb5.conf"
check REP.1.kinit "^Default principal: alice@$R\$" runin client2 "alice's password ($ALICE)" "KRB5_CONFIG=\$HOME/rep/krb5.conf kinit -c FILE:\$HOME/rep/a.cc alice > /dev/null && klist -c FILE:\$HOME/rep/a.cc" < <(once "$ALICE")

section "REP.4 kpropd.acl without the primary: the kprop is refused, as MIT's"
run kdc2 "sudo cp -p /var/kerberos/krb5kdc/kpropd.acl $W/kpropd.acl.good && echo 'host/nobody.kerber.test@$REALM' | sudo tee /var/kerberos/krb5kdc/kpropd.acl"
run kdc "sudo kprop -r $REALM -f $W/dump -s $W/kprop.keytab kdc2.kerber.test 2>&1; echo \"kprop rc=\$?\""
checklast REP.4.kprop '^kprop: Broken pipe while sending database'
checklast REP.4.kprop.rc '^kprop rc=1$'
kpropdlog REP.4.rejected "Rejected connection from unauthorized principal host/kdc\\.kerber\\.test@$R"
run kdc2 "sudo cp -p $W/kpropd.acl.good /var/kerberos/krb5kdc/kpropd.acl && sudo cat /var/kerberos/krb5kdc/kpropd.acl"

section "REP.2 incremental: six changes on kdc reach kdc2 within two polls"
for q in 'addprinc -randkey repa' 'cpw -randkey repa' 'modprinc -maxlife "2 hours" repa' 'addprinc -randkey repb' 'delprinc -force repb' 'renprinc -force repa repc'; do
    kadm "$q"
done
replicated REP.2.renamed repc "^Principal: repc@$R\$"
replicated REP.2.deleted repb 'Principal does not exist'
fields kdc repc repc.kdc
fields kdc2 repc repc.kdc2
sides REP.2.equal kdc "$STATE/repc.kdc" kdc2 "$STATE/repc.kdc2" \
    && check REP.2.equal '^repc: [1-9][0-9]* lines, equal$' host "diff $(printf '%q' "$STATE/repc.kdc") $(printf '%q' "$STATE/repc.kdc2") && echo \"repc: \$(wc -l < $(printf '%q' "$STATE/repc.kdc")) lines, equal\""
serial kdc "sudo kproplog"
serial kdc2 "$KPL"
check REP.2.serial '^serials equal: Last serial # : [1-9][0-9]*$' host "diff $(printf '%q' "$STATE/serial.kdc") $(printf '%q' "$STATE/serial.kdc2") > /dev/null && echo \"serials equal: \$(cat $(printf '%q' "$STATE/serial.kdc2"))\""

section "REP.3 a policy on kdc: the MIT leg records what its replica does, and the rust leg must do the same"
run kdc2 "echo '==== REP.3' >> $W/kpropd.log"
kadm 'addpol -maxlife "3 hours" reppol'
kadm 'modprinc -policy reppol repc'
run kdc2 "for i in \$(seq 1 40); do sudo kadmin.local -q 'getprinc repc' 2>&1 | grep -qx 'Policy: reppol' && break; sleep 1; done; sed -n '/^==== REP.3\$/,\$p' $W/kpropd.log | tail -n 12"
REF=''
if [ "$LEG" = rust ]; then
    if [ -f "$FIELD_RUN/replica/mit/result" ]; then REF=$FIELD_RUN/replica/mit/checks.tsv
    elif [ -f "$LAB_HOME/runs/mit-latest/replica/mit/checks.tsv" ]; then REF=$LAB_HOME/runs/mit-latest/replica/mit/checks.tsv; fi
    note "REP.3 is compared with ${REF:-no MIT leg: neither this run nor runs/mit-latest has one}"
fi
# rep3 <fact> <command>: one line, in the same words on both legs; on the rust leg it must be the MIT leg's.
rep3() {
    local mit=''
    observe "obs.REP.3.$1" "$OWN" run kdc2 "$2"
    [ "$LEG" = rust ] || return 0
    [ -n "$REF" ] && mit=$(awk -F'\t' -v n="obs.REP.3.$1" '$1 == n { print $5; exit }' "$REF")
    if [ -n "$mit" ]; then
        checklast "REP.3.$1" "line:$mit"
    else
        _checkrow "REP.3.$1" FAIL "as the MIT leg's obs.REP.3.$1" - "NOT-RUN: no MIT leg's obs.REP.3.$1 to compare with"
    fi
}
rep3 resync "sed -n '/^==== REP.3\$/,\$p' $W/kpropd.log | grep -q 'Full resync needed' && echo 'kpropd asked for a full resync' || echo 'kpropd asked for no full resync'"
rep3 policy "sudo kadmin.local -q 'getpol reppol' 2>&1 | grep -qx 'Policy: reppol' && echo 'reppol is on kdc2' || echo 'reppol is not on kdc2'"
rep3 principal "sudo kadmin.local -q 'getprinc repc' 2>&1 | grep -qx 'Policy: reppol' && echo 'repc is under reppol' || echo 'repc is not under reppol'"

section "REP.6 lockout counts stay on each KDC: kdc2's failures are kept, and kdc's are not sent"
check REP.6.addprinc "^Principal \"replk@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc +requires_preauth replk' 2>&1" < <(twice "$ALICE")
replicated REP.6.replicated replk "^Principal: replk@$R\$"
for n in 1 2; do
    check "REP.6.kdc2.fail$n" '^kinit rc=1$' run client2 "echo not-the-password | KRB5_CONFIG=\$HOME/rep/krb5.conf kinit -c FILE:\$HOME/rep/l.cc replk > /dev/null 2>&1; echo \"kinit rc=\$?\""
done
check REP.6.kdc.fail '^kinit rc=1$' run client2 "echo not-the-password | kinit -c FILE:\$HOME/rep/l.cc replk > /dev/null 2>&1; echo \"kinit rc=\$?\""
kadm 'modprinc -maxlife "5 hours" replk'
replicated REP.6.maxlife replk '^Maximum ticket life: 0 days 05:00:00$'
check REP.6.kdc2.count '^Failed password attempts: 2$' run kdc2 "sudo kadmin.local -q 'getprinc replk' 2>&1 | grep '^Failed password attempts'"
check REP.6.kdc.count '^Failed password attempts: 1$' run kdc "sudo kadmin.local -q 'getprinc replk' 2>&1 | grep '^Failed password attempts'"

section "REP.7 setstr on the MIT primary arrives and kdc2 keeps the attributes the update does not carry"
kadm 'setstr replk repkey repval'
check REP.7.string '^repkey: repval$' run kdc2 "for i in \$(seq 1 30); do sudo kadmin.local -q 'getstrs replk' 2>&1 | grep -q '^repkey: repval' && break; sleep 1; done; sudo kadmin.local -q 'getstrs replk' 2>&1 | grep -v '^Authenticating'"
check REP.7.count '^Failed password attempts: 2$' run kdc2 "sudo kadmin.local -q 'getprinc replk' 2>&1 | grep '^Failed password attempts'"

section "REP.5 kiprop/kdc2 without p: kdc2's kpropd is refused, bails and exits, as MIT's"
check REP.5.acl '^no kiprop line$' run kdc "sudo sed -i '/^kiprop\\/kdc2/d' $ACL && ! sudo grep -q '^kiprop' $ACL && echo 'no kiprop line'"
check REP.5.kadmind "^kadmind: active, iprop on $IPORT\$" run kdc "$KADMIND"
kpropdlog REP.5.denied 'get_updates permission denied' 60
kpropdlog REP.5.bailed 'ERROR returned by primary, bailing'
check REP.5.exited '^kpropd: exited$' run kdc2 "for i in \$(seq 1 40); do pgrep -x kpropd > /dev/null || break; sleep 0.5; done; pgrep -x kpropd > /dev/null && echo 'kpropd: running' || echo 'kpropd: exited'"
check REP.5.acl.back '^kiprop/kdc2\.kerber\.test@' run kdc "echo 'kiprop/kdc2.kerber.test@$REALM p' | sudo tee -a $ACL"
check REP.5.restored "^kadmind: active, iprop on $IPORT\$" run kdc "$KADMIND"

section "REP.8 kpropd started again asks from its last serial"
serial kdc2 "$KPL"
SNO=$(grep -oE '[0-9]+' "$STATE/serial.kdc2" | tail -n 1)
check REP.8.restart '^kpropd listening on 754$' run kdc2 "sudo pkill -x kpropd; for i in \$(seq 1 20); do pgrep -x kpropd > /dev/null || break; sleep 0.25; done; echo '==== restarted' >> $W/kpropd.log; $KPROPD for i in \$(seq 1 40); do ss -Hltn 'sport = :754' | grep -q . && break; sleep 0.25; done; ss -Hltn 'sport = :754' | grep -q . && echo 'kpropd listening on 754'"
check REP.8.resumed "^first poll after the restart: sno=${SNO:-none}\$" run kdc2 "for i in \$(seq 1 30); do sed -n '/^==== restarted\$/,\$p' $W/kpropd.log | grep -q 'Calling iprop_get_updates_1' && break; sleep 1; done; echo \"first poll after the restart: \$(sed -n '/^==== restarted\$/,\$p' $W/kpropd.log | grep -m 1 -oE 'sno=[0-9]+')\""
kadm 'addprinc -randkey repd'
replicated REP.8.added repd "^Principal: repd@$R\$"
check REP.8.no-resync '^no full resync after the restart$' run kdc2 "sed -n '/^==== restarted\$/,\$p' $W/kpropd.log | grep -q 'Full resync' || echo 'no full resync after the restart'"
run kdc2 "tail -n 80 $W/kpropd.log"
# SELinux on kdc, where kadmind runs confined and forks kdb5_util and kprop for a full resync.
observe obs.avc.kdc '[0-9]+ AVC denials since boot|no ausearch' run kdc "if command -v ausearch > /dev/null; then echo \"\$(sudo ausearch -m avc -ts boot 2>/dev/null | grep -c denied) AVC denials since boot\"; sudo ausearch -m avc -ts boot 2>/dev/null | grep denied | grep -oE 'comm=\"[^\"]+\"|tcontext=[^ ]+|tclass=[^ ]+' | sort | uniq -c | head -n 12; else echo 'no ausearch'; fi"
finish
