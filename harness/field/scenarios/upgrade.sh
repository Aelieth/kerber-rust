#!/usr/bin/env bash
# harness/field/scenarios/upgrade.sh --leg rust: kdc upgraded in place to the ref under test by the ref's own
# docs/install.md, "Upgrading kerber-rust" (its two blocks as written, taken from the archive by heading, so a
# doc change is what runs), then the deterministic checks of the hand record f-UP1. First in every run: it
# leaves kdc on the ref's install. Run by run.sh (REC_DIR, TMPDIR, FIELD_TREE_TAR, FIELD_SHA, FIELD_REF,
# FIELD_DEADLINE).
# --leg mit (minimal; the fuller MIT comparison is F4d's): kdc reset to the MIT baseline, the stock Fedora
# krb5-server realm the other scenarios' MIT legs run against: its binaries as packaged, krb5kdc and kadmin active
# and listening, the package versions recorded.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: upgrade.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_TREE_TAR:?run by run.sh}" "${FIELD_SHA:?run by run.sh}" "${FIELD_REF:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
T0=$(date +%s)
SS="'( sport = :88 or sport = :464 or sport = :749 )'"
# listencheck: kdc's listeners, the set MIT's own daemons open (its leg grades the same two checks): exactly the
# wildcard 0.0.0.0 and [::] sockets on 88 udp/tcp, 464 udp/tcp and 749 tcp, with listen queues 5 / 5 / 2.
listencheck() {
    check listen.sockets 'line:sockets: tcp 0.0.0.0:464 tcp 0.0.0.0:749 tcp 0.0.0.0:88 tcp [::]:464 tcp [::]:749 tcp [::]:88 udp 0.0.0.0:464 udp 0.0.0.0:88 udp [::]:464 udp [::]:88' \
        run kdc "sudo ss -H -lntup $SS; printf 'sockets: %s\n' \"\$(sudo ss -H -lntu $SS | awk '{ print \$1, \$5 }' | LC_ALL=C sort | paste -sd' ' -)\"; printf 'backlog: %s\n' \"\$(sudo ss -H -lntu $SS | awk '\$1 == \"tcp\" { n = split(\$5, a, \":\"); print a[n] \"=\" \$4 }' | LC_ALL=C sort -u | paste -sd' ' -)\""
    checklast listen.backlog 'line:backlog: 464=5 749=2 88=5'
}
if [ "$LEG" = mit ]; then
    section "upgrade --leg mit: kdc reset to $MIT_SNAPSHOT_KDC, the stock MIT realm $REALM (the oracle); the ref under test is not installed"
    resetvm kdc
    kdcis
    check mit.active '^active active$' run kdc "systemctl is-active krb5kdc kadmin | paste -sd' ' -"
    listencheck
    observe obs.mit.packages 'krb5-server-[^ ]+' run kdc "rpm -q krb5-server krb5-libs krb5-workstation | paste -sd' ' -; uname -r"
    MIN=$(( ($(date +%s) - T0) / 60 + 2 ))
    host "COLLECT_MINUTES=$MIN $LABQ collect kdc $(printf '%q' "$REC_DIR/collect") /etc/krb5.conf /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl"
    if [ -f "$REC_DIR/collect/kdc/journal.txt" ]; then _redact < "$REC_DIR/collect/kdc/journal.txt" > "$STATE/j" && mv "$STATE/j" "$REC_DIR/collect/kdc/journal.txt"; fi
    finish
    exit
fi
DOCB=$FIELD_LIB/docblocks.py
CO=kerber-rust-${FIELD_SHA:0:12}
R=$RUST_REALM
ALICE=$RUST_SECRET_ALICE BOB=$RUST_SECRET_BOB BOBT=$RUST_SECRET_BOB_TEMP ADMIN=$RUST_SECRET_ADMIN
U="export KRB5_CONFIG=\$HOME/field/udp.conf:/etc/krb5.conf KRB5CCNAME=FILE:\$HOME/field/u.cc;"
T="export KRB5_CONFIG=\$HOME/field/tcp.conf:/etc/krb5.conf KRB5CCNAME=FILE:\$HOME/field/t.cc;"
CARGO_ENV=". \"\$HOME/.cargo/env\""
ET='aes256-cts-hmac-sha1-96\(18\), aes128-cts-hmac-sha1-96\(17\)'
E3='rep=aes256-cts-hmac-sha1-96\(18\), tkt=aes256-cts-hmac-sha1-96\(18\), ses=aes256-cts-hmac-sha1-96\(18\)'
LISTEN="'^[[:space:]]*(kdc_listen|kdc_tcp_listen|kadmind_listen|kpasswd_listen)[[:space:]]*='"
# all6 [file]: the line numbers of the listing's entries (`N:<entry>`) whose addresses are all IPv6: the doc
# says to edit those before the daemons start.
all6() {
    awk -F: '/^[0-9]+:/ { v = $0; sub(/^[^=]*=/, "", v); n = split(v, a, /[ ,\t]+/); six = 0; four = 0
        for (i = 1; i <= n; i++) if (a[i] != "") { if (a[i] ~ /^\[/) six++; else four++ }
        if (six > 0 && four == 0) print $1 }' "$@"
}
# On any exit: no refused TCP 464, no capture left running, no raw capture left on kdc, no scratch on client2.
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- 'sudo nft delete table inet field_tmp 2>/dev/null; sudo systemctl stop "field-pcap-*" 2>/dev/null; sudo rm -f /var/tmp/field-*.pcap; true' < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- "for c in ~/field/*.cc; do [ -e \"\$c\" ] && KRB5CCNAME=FILE:\$c kdestroy; done; rm -rf ~/field; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# docscript <name> <docblocks.py script args...>: the doc block as a session script, $STATE/<name>.sh.
docscript() {
    local name=$1
    shift
    check "doc.$name.script" rc host "python3 -B $(printf '%q' "$DOCB") script $(printf '%q ' "$@") > $(printf '%q' "$STATE/$name.sh")"
}
# docrun <name> [listing ERE]: run $STATE/<name>.sh on kdc in one session, as a reader pastes the block, then one
# check per command: doc.<name>.<i> rc 0; a command the ERE matches is a listing that may find nothing (rc 0 or 1).
docrun() {
    local name=$1 listing=${2:-} i rc nout first res exp
    hostin "$name.sh" "$LABQ ssh kdc -- 'install -d -m 0700 ~/field && cat > ~/field/$name.sh'" < "$STATE/$name.sh"
    run kdc "bash ~/field/$name.sh"
    cp "$LAST_OUT" "$STATE/$name.out"
    if ! python3 -B "$DOCB" results "$STATE/$name.out" > "$STATE/$name.results"; then
        _checkrow "doc.$name" FAIL units "$LAST_RC" "no command of the block ran"
        return
    fi
    while IFS=$'\t' read -r i rc nout first; do
        res=FAIL exp=rc
        if [ -n "$listing" ] && [[ $first =~ $listing ]]; then
            exp='rc=0|1'
            case $rc in 0 | 1) res=PASS ;; esac
        elif [ "$rc" = 0 ]; then
            res=PASS
        fi
        _checkrow "doc.$name.$i" "$res" "$exp" "$rc" "rc=$rc, $nout output lines: $first"
    done < "$STATE/$name.results"
}

section "upgrade --leg rust: kdc from $RUST_SNAPSHOT_KDC to ref $FIELD_REF = $FIELD_SHA by docs/install.md; MIT clients on client2 ($RUST_SNAPSHOT_CLIENT2)"
section "1. the baselines, and the realm before"
check reset.kdc rc host "$LABQ reset kdc $RUST_SNAPSHOT_KDC"
check reset.client2 rc host "$LABQ reset client2 $RUST_SNAPSHOT_CLIENT2"
waitsync kdc
waitsync client2
run kdc "getenforce; systemctl is-active krb5kdc kadmin | paste -sd' ' -; sudo sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind; sudo grep -c _listen /var/kerberos/krb5kdc/kdc.conf; ls ~"
check realm.before.listprincs "^alice@$R\$" run kdc "sudo kadmin.local -q listprincs"
cp "$LAST_OUT" "$STATE/listprincs.before"
check realm.before.alice "^Principal: alice@$R\$" run kdc "sudo kadmin.local -q 'getprinc alice'"
cp "$LAST_OUT" "$STATE/alice.before"

section "2. the ref's archive on kdc, in place of the doc's git pull (kdc has no clone)"
check tree.kdc rc hostin "the ref's archive (tar)" "$LABQ ssh kdc -- 'rm -rf ~/$CO && tar -x -C ~ && find ~/$CO -type f | wc -l'" < "$FIELD_TREE_TAR"
tar -xOf "$FIELD_TREE_TAR" "$CO/docs/install.md" > "$STATE/install.md"

section "3. Build: 'run make build as in Build', its block without git clone and cd kerber-rust (the archive is the checkout)"
docscript build "$STATE/install.md" '## Build' 1 --drop '^git clone ' --drop '^cd kerber-rust$' \
    --session "$CARGO_ENV" --session "cd ~/$CO"
docrun build

section "4. Upgrading kerber-rust: block 1, the listen-entry edit the doc asks for, block 2"
check doc.upgrade.blocks 'line:2' host "python3 -B $(printf '%q' "$DOCB") count $(printf '%q' "$STATE/install.md") '## Upgrading kerber-rust'"
docscript upgrade-1 "$STATE/install.md" '## Upgrading kerber-rust' 1 --set "REALM=$R" --set PREFIX=/usr --set OLD= \
    --session "$CARGO_ENV" --session "cd ~/$CO"
docscript upgrade-2 "$STATE/install.md" '## Upgrading kerber-rust' 2 \
    --session "$CARGO_ENV" --session "cd ~/$CO" --session "REALM=$R PREFIX=/usr OLD="
# ausearch -ts reads local time: the window start is kdc's own clock in its local time (kdc runs UTC).
WSTART=$(limited "$LAB" ssh kdc -- 'date "+%m/%d/%Y %H:%M:%S"' < /dev/null)
note "window start on kdc's clock, local time (ausearch -ts): ${WSTART:-<none: the SELinux checks fail>}"
kdcmark up
docrun upgrade-1 '^sudo grep .*_listen'
li=$(awk -F'\t' '$4 ~ /^sudo grep .*_listen/ { print $1; exit }' "$STATE/upgrade-1.results")
mapfile -t EDIT < <(python3 -B "$DOCB" output "$STATE/upgrade-1.out" "${li:-0}" | all6 | sort -rn)
if [ "${#EDIT[@]}" -gt 0 ]; then
    run kdc "sudo sed -i $(printf -- '-e %sd ' "${EDIT[@]}")/var/kerberos/krb5kdc/kdc.conf; echo \"sed: rc=\$?\"; sudo grep -nE $LISTEN /var/kerberos/krb5kdc/kdc.conf; true"
    left=$(all6 "$LAST_OUT" | wc -l)
    res=FAIL
    if grep -qx 'sed: rc=0' "$LAST_OUT" && [ "$left" = 0 ]; then res=PASS; fi
    _checkrow doc.upgrade.edit "$res" "sed rc 0, no all-IPv6 entry left" "$LAST_RC" "$(grep -x 'sed: rc=[0-9]*' "$LAST_OUT"); all-IPv6 entries left: $left"
else
    note "the listing printed no all-IPv6 listen entry: nothing to edit (kdc.conf keeps MIT's wildcards)"
fi
capstart kdc upgrade '(port 88 or port 464 or port 749) or (ip[6:2] & 0x1fff != 0)'
docrun upgrade-2

section "5. kdc runs the ref's build; listeners, the daemons' log lines, SELinux, the realm after, the strings check"
check install.programs '^programs: [1-9][0-9]* in the manifest, each identical to the build$' \
    runin kdc "lib/install-check.sh" "sh -s -- ~/$CO" < "$FIELD_LIB/install-check.sh"
check install.manifest '^manifest: [1-9][0-9]* files as installed$' \
    run kdc "sudo sha256sum -c /usr/share/kerber-rust/install-manifest && echo \"manifest: \$(wc -l < /usr/share/kerber-rust/install-manifest) files as installed\""
listencheck
kdcsince up 'setting up network|V6ONLY|set up [0-9]+ sockets|commencing operation|starting|Loaded|\((Error|error|err|warning)\)'
checklast log.kdc.sockets 'krb5kdc\[[0-9]+\]\(info\): set up 4 sockets$'
checklast log.kdc.commencing 'krb5kdc\[[0-9]+\]\(info\): commencing operation$'
checklast log.kadmind.sockets 'kadmind\[[0-9]+\]\(info\): set up 6 sockets$'
checklast log.kadmind.starting 'kadmind\[[0-9]+\]\(info\): starting$'
observelast obs.log.loaded '\(info\): Loaded.*'
AVC="getenforce; d=\$(sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $WSTART 2>&1); r=\$?; [ \"\$r\" = 1 ] || printf '%s\n' \"\$d\"; c=\$(sudo ausearch --input-logs -m USER_CMD -ts $WSTART 2>/dev/null | grep -c '^type=USER_CMD'); printf 'denials: %s (ausearch rc=%s); USER_CMD control: %s records\n' \"\$(printf '%s\n' \"\$d\" | tail -n 1)\" \"\$r\" \"\$c\""
AVC_OK='^denials: <no matches> \(ausearch rc=1\); USER_CMD control: [1-9][0-9]* records$'
check selinux.avc "$AVC_OK" run kdc "$AVC; ps -eZ | grep -E 'krb5kdc|kadmind'"
checklast selinux.enforcing '^Enforcing$'
checklast selinux.krb5kdc_t ':krb5kdc_t:s0 +[0-9]+ .* krb5kdc$'
checklast selinux.kadmind_t ':kadmind_t:s0 +[0-9]+ .* kadmind$'
check realm.after.listprincs "^alice@$R\$" run kdc "sudo kadmin.local -q listprincs"
cp "$LAST_OUT" "$STATE/listprincs.after"
check realm.after.alice "^Principal: alice@$R\$" run kdc "sudo kadmin.local -q 'getprinc alice'"
cp "$LAST_OUT" "$STATE/alice.after"
check realm.listprincs.same rc host "cd $(printf '%q' "$STATE") && diff listprincs.before listprincs.after && echo identical"
check realm.alice.same rc host "cd $(printf '%q' "$STATE") && diff alice.before alice.after && echo identical"
check strings.control rc runin kdc "lib/strings-check.sh" "sh -s -- --control" < "$FIELD_LIB/strings-check.sh"
check strings.manifest '^programs in /usr/share/kerber-rust/install-manifest: [1-9][0-9]*, all [1-9][0-9]* checked$' \
    runin kdc "lib/strings-check.sh" "sh -s -- --manifest /usr/share/kerber-rust/install-manifest" < "$FIELD_LIB/strings-check.sh"
RSS="printf 'krb5kdc %s KiB, kadmind %s KiB\n' \"\$(ps -o rss= -C krb5kdc | head -n 1 | tr -d ' ')\" \"\$(ps -o rss= -C kadmind | head -n 1 | tr -d ' ')\"; systemctl show -p MemoryCurrent krb5kdc kadmin"
observe obs.rss.start 'krb5kdc [0-9]+ KiB, kadmind [0-9]+ KiB' run kdc "$RSS"

section "6. MIT clients on client2 (IPv4): kinit, kvno and remote kadmin over UDP, then over TCP"
for vm in client2 kdc; do
    hostin "lib/ktrace.sh" "$LABQ ssh $vm -- 'rm -rf ~/field/ktrace.sh && install -d -m 0700 ~/field && cat > ~/field/ktrace.sh && chmod 0755 ~/field/ktrace.sh'" < "$FIELD_LIB/ktrace.sh"
done
run client2 "printf '[libdefaults]\n    udp_preference_limit = 4096\n' > ~/field/udp.conf; printf '[libdefaults]\n    udp_preference_limit = 1\n' > ~/field/tcp.conf; head ~/field/*.conf; rpm -q krb5-workstation; grep -rhE 'udp_preference_limit|_enctypes' /etc/krb5.conf /etc/krb5.conf.d/; true"
kdcmark clients
for p in udp:dgram tcp:stream; do
    pass=${p%%:*} tr=${p#*:} cfg=$U
    if [ "$pass" = tcp ]; then cfg=$T; fi
    check "client2.$pass.kinit" "^answers: $tr 192\.168\.177\.10:88\$" runin client2 "alice's password ($ALICE)" "$cfg ~/field/ktrace.sh $pass-kinit kinit alice && klist -f" < <(once "$ALICE")
    if [ "$pass" = udp ]; then
        observelast obs.as.preauth 'Processing preauth types: .*'
        observelast obs.as.rep.bytes 'Received answer \([0-9]+ bytes\)' 2
    fi
    check "client2.$pass.kvno" "^answers: $tr 192\.168\.177\.10:88\$" run client2 "$cfg ~/field/ktrace.sh $pass-kvno kvno host/client2.kerber.test"
    if [ "$pass" = udp ]; then
        observelast obs.tgs.req.bytes 'Sending request \([0-9]+ bytes\)'
        observelast obs.tgs.rep.bytes 'Received answer \([0-9]+ bytes\)'
    fi
    check "client2.$pass.kadmin" "^answers: $tr 192\.168\.177\.10:88\$" runin client2 "admin/admin's password ($ADMIN)" "$cfg ~/field/ktrace.sh $pass-kadmin kadmin -p admin/admin -q listprincs" < <(once "$ADMIN")
    checklast "client2.$pass.kadmin.list" "^alice@$R\$"
    if [ "$pass" = udp ]; then
        observelast obs.kadmin.aprep 'Read AP-REP, time [0-9.]+, subkey [^,]+, seqnum [0-9]+'
    fi
done

section "7. bob's kpasswd there over UDP 464 (kdc refuses client2's TCP 464 for that exchange) and back over TCP"
check kpasswd.refuse.tcp rc run kdc "sudo nft add table inet field_tmp && sudo nft add chain inet field_tmp input '{ type filter hook input priority filter - 1; policy accept; }' && sudo nft add rule inet field_tmp input ip saddr 192.168.177.22 tcp dport 464 counter reject with tcp reset && sudo nft list table inet field_tmp"
check client2.kpasswd.udp '^answers: dgram 192\.168\.177\.10:464 dgram 192\.168\.177\.10:88$' runin client2 "bob's password, then $BOBT twice" "$U ~/field/ktrace.sh udp-kpasswd kpasswd bob" < <(chpw "$BOB" "$BOBT")
checklast client2.kpasswd.udp.changed '^Password changed\.$'
observelast obs.kpasswd.aprep 'Read AP-REP, time [0-9.]+, subkey [^,]+, seqnum [0-9]+'
check kpasswd.refuse.removed rc run kdc "sudo nft list table inet field_tmp; sudo nft delete table inet field_tmp && sudo nft list tables"
check client2.kpasswd.tcp '^answers: stream 192\.168\.177\.10:464 stream 192\.168\.177\.10:88$' runin client2 "$BOBT, then bob's password twice" "$T ~/field/ktrace.sh tcp-kpasswd kpasswd bob" < <(chpw "$BOBT" "$BOB")
checklast client2.kpasswd.tcp.changed '^Password changed\.$'
check client2.kinit.bob rc runin client2 "bob's password ($BOB)" "export KRB5CCNAME=FILE:\$HOME/field/bob.cc; kinit bob && klist && kdestroy" < <(once "$BOB")
kdcsince clients '192\.168\.177\.22|chpw'
n=$(grep -c "chpw request from 192\.168\.177\.22 for bob@$R: success\$" "$LAST_OUT" || true)
res=FAIL
if [ "$LAST_RC" = 0 ] && [ "$n" = 2 ]; then res=PASS; fi
_checkrow log.kadmind.chpw "$res" "2 chpw success lines" "$LAST_RC" "chpw request from 192.168.177.22 for bob@$R: success, $n lines"
checklast log.kdc.as.preauth "AS_REQ \\(2 etypes \\{$ET\\}\\) 192\\.168\\.177\\.22: NEEDED_PREAUTH: alice@$R for krbtgt/$R@$R, Additional pre-authentication required\$"
checklast log.kdc.as.issue "AS_REQ \\(2 etypes \\{$ET\\}\\) 192\\.168\\.177\\.22: ISSUE: authtime [0-9]+, etypes \\{$E3\\}, alice@$R for krbtgt/$R@$R\$"
checklast log.kdc.tgs.issue "TGS_REQ \\(2 etypes \\{$ET\\}\\) 192\\.168\\.177\\.22: ISSUE: authtime [0-9]+, etypes \\{$E3\\}, alice@$R for host/client2\\.kerber\\.test@$R\$"
checklast log.kadmind.kadm5_init "Request: kadm5_init, admin/admin@$R, success, client=admin/admin@$R, service=kadmin/admin@$R, addr=192\\.168\\.177\\.22, vers=4, flavor=6\$"

section "8. kdc itself: MIT kinit on ::1 over UDP and TCP, and on 127.0.0.2 (a UDP reply leaves from the request's address)"
KC="[libdefaults]\n default_realm = $R\n"
run kdc "printf '${KC}[realms]\n $R = {\n  kdc = [::1]\n }\n' > ~/field/v6-udp.conf; printf '$KC udp_preference_limit = 1\n[realms]\n $R = {\n  kdc = [::1]\n }\n' > ~/field/v6-tcp.conf; printf '${KC}[realms]\n $R = {\n  kdc = 127.0.0.2\n }\n' > ~/field/lo2.conf; head -n 20 ~/field/v6-udp.conf ~/field/v6-tcp.conf ~/field/lo2.conf"
for k in 'v6-udp:dgram \[::1\]' 'v6-tcp:stream \[::1\]' 'lo2:dgram 127\.0\.0\.2'; do
    check "kdc.${k%%:*}.kinit" "^answers: ${k#*:}:88\$" runin kdc "alice's password ($ALICE)" "KRB5_CONFIG=\$HOME/field/${k%%:*}.conf ~/field/ktrace.sh ${k%%:*} kinit -c MEMORY:field alice" < <(once "$ALICE")
done
observe obs.rss.end 'krb5kdc [0-9]+ KiB, kadmind [0-9]+ KiB' run kdc "$RSS"
capstop kdc upgrade

section "9. leaving the VMs: client2's caches and scratch removed; kdc keeps the ref's install and ~/$CO; AVC over the whole window"
run client2 "for c in ~/field/*.cc; do [ -e \"\$c\" ] && KRB5CCNAME=FILE:\$c kdestroy; done; rm -rf ~/field; ls -a ~"
run kdc "rm -rf ~/field; ls ~; sudo nft list tables; systemctl list-units --all 'field-*' --no-legend | wc -l"
check selinux.avc.end "$AVC_OK" run kdc "$AVC"
MIN=$(( ($(date +%s) - T0) / 60 + 2 ))
host "COLLECT_MINUTES=$MIN $LABQ collect kdc $(printf '%q' "$REC_DIR/collect") /var/log/krb5kdc.log /var/log/kadmind.log /etc/krb5.conf /etc/krb5.conf.d /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl /usr/share/kerber-rust/install-manifest /usr/lib/systemd/system/krb5kdc.service /usr/lib/systemd/system/kadmin.service /etc/sysconfig/krb5kdc /etc/sysconfig/kadmin && COLLECT_MINUTES=$MIN $LABQ collect client2 $(printf '%q' "$REC_DIR/collect") /etc/krb5.conf /etc/krb5.conf.d"
for j in "$REC_DIR"/collect/*/journal.txt; do
    [ -f "$j" ] && _redact < "$j" > "$j.r" && mv "$j.r" "$j"
done
finish
