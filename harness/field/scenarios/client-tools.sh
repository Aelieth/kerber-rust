#!/usr/bin/env bash
# harness/field/scenarios/client-tools.sh --leg mit|rust: the client programs on client2 against the leg's KDC as
# upgrade.sh left it, called as the satomlin kit's clients call them: kinit with the password on stdin and
# kinit -k -t into FILE: caches (the default FILE:/tmp/krb5cc_%{uid} too), klist and klist -s, kvno, kdestroy,
# klist -k as the kit parses it; then DIR: collections with kswitch, ktutil, and the refusals. The mit leg runs
# MIT's (krb5-workstation), the oracle: each row grades MIT 1.22.2's own text and exit code. In the rust leg
# every row runs twice, MIT's programs and then ours (kdc's build of krb5-<name>, piped to client2's
# ~/ct/bin/<name> and run by path, so MIT's stay the ones on PATH); ours are graded on the same text, and
# <row>.same diffs the two outputs. Each request kinit and kvno send also goes through
# lib/kdc-req-proxy.py on client2 (shapes only: options, padata types, etypes, time classes), and the rust leg
# compares ours with MIT's request by request; CR sends kinit to made-up realms whose KDC, lib/kdc-rewrite-proxy.py,
# answers with a client referral to $REALM. Then the caches and keytabs cross: MIT's klist and kvno on ours,
# ours on MIT's, MIT's cache entries kept through our rewrite. Then the request shapes of FAST under -T (armored at
# once, and after an upgrade from an armor cache without fast_avail), SPAKE, the preauth cascade, the enctypes
# nothing configures, kvno -U -P, no ticket_lifetime and canonicalize = true; each flow's exit status; kpasswd
# refused by a policy; MIT's krb5_cc_remove_cred on a cache ours wrote. Scratch principals and the scratch policy
# only, removed at the end.
# MIT 1.22.2: clients/kinit/kinit.c (k5_kinit :747-793), clients/klist/klist.c (show_credential, list_ccaches
# :376-410, the keytab listing :300-345), clients/kvno/kvno.c (:165, :376-381), clients/kdestroy/kdestroy.c
# (:207-219), kadmin/ktutil/ktutil.c (:217-269); lib/krb5/os/prompter.c (the prompt on stdout, the reply from
# stdin with no tty); lib/krb5/krb/gic_pwd.c (:240-253, the expired-password change); lib/krb5/ccache/cc_file.c
# (:117-123, the "(filename: ...)" messages); lib/krb5/krb/str_conv.c (:224-245: klist's dates follow the
# locale, so the rows run with LC_ALL=C; ours print the C locale's); lib/krb5/krb/get_in_tkt.c (:718-722,
# :936-947, restart_init_creds_loop :780-848); lib/krb5/krb/fast.c (:172-224); clients/kpasswd/kpasswd.c;
# lib/krb5/ccache/cc_file.c (fcc_remove_cred).
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: client-tools.sh --leg mit|rust" >&2; exit 1 ;;
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
D=client2.${REALM,,}
SVC=ctsvc/$D WEB=ctweb/$D S=ctsvc/${D//./\\.} W=ctweb/${D//./\\.}
PRINCS="ctuser ctpre ctbad ctchg ctpw ctkv $SVC $WEB"
TOOLS="kinit klist kvno kdestroy ktutil kswitch kpasswd"
T='[0-9]{2}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "for p in $PRINCS; do sudo kadmin.local -q \"delprinc -force \$p\" > /dev/null 2>&1; done; sudo kadmin.local -q 'delpol -force ctpol' > /dev/null 2>&1; true" < /dev/null > /dev/null 2>&1
    # shellcheck disable=SC2016 # the pid file is client2's
    timeout -k 5 60 "$LAB" ssh client2 -- 'for f in ~/ct/px/pid ~/ct/px/cr.pid; do [ -f "$f" ] && kill "$(cat "$f")"; done; kdestroy -q 2> /dev/null; rm -rf ~/ct; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# E <k>: the start of a client2 command line for <k>'s programs in $B (mit: /usr/bin, ours: ~/ct/bin), with no
# KRB5CCNAME and LC_ALL=C. P <k>: the same through the shape proxy (~/ct/px.conf names it as the KDC). C <k>: with
# ~/ct/cr.conf, whose made-up realms' KDC is the referral proxy, its log and the shape capture emptied first.
# shellcheck disable=SC2016 # $HOME is client2's
E() { printf 'unset KRB5CCNAME KRB5_CONFIG; export LC_ALL=C B=%s;' "$([ "$1" = ours ] && echo '$HOME/ct/bin' || echo /usr/bin)"; }
# shellcheck disable=SC2016 # $HOME is client2's
P() { printf '%s export KRB5_CONFIG=$HOME/ct/px.conf;' "$(E "$1")"; }
# shellcheck disable=SC2016 # $HOME is client2's
C() { printf '%s export KRB5_CONFIG=$HOME/ct/cr.conf; : > $HOME/ct/px/cr.log; : > $HOME/ct/px/live.jsonl;' "$(E "$1")"; }
# keep <step> <k>: the last output, kept for <step>.same.
keep() { cp "$LAST_OUT" "$STATE/$1.$2"; }
# M: what a .same diff masks: the dates, which program set's file it is (mit / ours), the uid, DIR: cache names.
M='s#[0-9]{2}/[0-9]{2}/[0-9]{2,4} [0-9]{2}:[0-9]{2}(:[0-9]{2})?#<time>#g; s#/ct/(mit|ours)([.-])#/ct/<k>\2#g; s#krb5cc_[0-9]+#krb5cc_<uid>#g; s#tkt[A-Za-z0-9]+#tkt<id>#g'
MX='s#/ct/(mit|ours)([.-])#/ct/<k>\2#g'
# same <step> [mask]: ours printed what MIT's printed (masked by M, or the mask given); graded <step>.same.
same() {
    local m=${2:-$M}
    sides "$1.same" "MIT $1" "$STATE/$1.mit" "ours $1" "$STATE/$1.ours" || return
    check "$1.same" '^same: ' host "diff <(sed -E $(printf '%q' "$m") $(printf '%q' "$STATE/$1.mit")) <(sed -E $(printf '%q' "$m") $(printf '%q' "$STATE/$1.ours")) && echo 'same: ours printed what MIT'\\''s printed'"
}
# rcof <step> <rc>: each program set's kept <step> output ends in rc=<rc>, graded <step>.rc.<k>.
rcof() {
    local k res
    for k in mit $OURS; do
        res=FAIL
        grep -qx "rc=$2" "$STATE/$1.$k" && res=PASS
        _checkrow "$1.rc.$k" "$res" "rc=$2" 0 "$(grep -m1 '^rc=' "$STATE/$1.$k")"
    done
}
# both <step> <ERE> <secret|-> <cmd>: <cmd> (its programs as \$B/<name>, <k> as _K_) for each program set, graded
# <step>.<k> on <ERE> (_K_ there too); the password from <secret> on stdin, or none.
both() {
    local step=$1 ere=$2 sec=$3 cmd=$4 k
    for k in mit $OURS; do
        if [ "$sec" = - ]; then
            check "$step.$k" "${ere//_K_/$k}" run client2 "$(E "$k") ${cmd//_K_/$k}"
        else
            check "$step.$k" "${ere//_K_/$k}" runin client2 "the password ($sec)" "$(E "$k") ${cmd//_K_/$k}" < <(once "$sec")
        fi
        keep "$step" "$k"
    done
}
# shape <flow> <secret|-> <cmd> [rc0]: <cmd> through the proxy for each program set; its requests kept in
# ~/ct/px/<flow>.<k>.jsonl. MIT's request shapes are an observation (compared across the legs); ours = MIT's.
# With rc0 each set's command must exit 0; without it ours must exit as MIT's did.
shape() {
    local f=$1 sec=$2 cmd=$3 want=${4:-} k mrc=
    for k in mit $OURS; do
        run client2 ": > \$HOME/ct/px/live.jsonl"
        if [ "$sec" = - ]; then
            run client2 "$(P "$k") ${cmd//_K_/$k}"
        else
            runin client2 "the password ($sec)" "$(P "$k") ${cmd//_K_/$k}" < <(once "$sec")
        fi
        [ "$k" = mit ] && mrc=$LAST_RC
        if [ "$want" = rc0 ]; then checklast "CT.px.$f.rc.$k" rc; else checklast "CT.px.$f.rc.$k" "rc=$mrc"; fi
        check "CT.px.$f.$k" '^requests: [1-9][0-9]*$' run client2 "cp \$HOME/ct/px/live.jsonl \$HOME/ct/px/$f.$k.jsonl && echo \"requests: \$(grep -c '\"kind\": \"req\"' \$HOME/ct/px/$f.$k.jsonl)\""
    done
    observe "obs.CT.px.$f" 'shape: .*' run client2 "printf 'shape: %s\\n' \"\$(jq -c 'select(.kind == \"req\") | [.msg_type, .kdc_options, .padata, .etypes, .from, .till, .rtime, .addl_tickets]' \$HOME/ct/px/$f.mit.jsonl | paste -sd' ' -)\""
    [ -n "$OURS" ] && check "CT.px.$f.same" "^FLOW_${f}_equal\$" run client2 "python3 \$HOME/ct/kdc-req-proxy.py --compare \$HOME/ct/px/$f.mit.jsonl \$HOME/ct/px/$f.ours.jsonl $f"
}

section "client-tools --leg $LEG: MIT's client programs on client2$([ "$LEG" = rust ] && echo ', then ours,') against the $LEG KDC"
kdcis
resetvm client2
check client2.ccache '^default_ccache_name = FILE:/tmp/krb5cc_%\{uid\}, no includedir$' run client2 "awk '/^[[:space:]]*default_ccache_name[[:space:]]*=/ { c = \$3 } /^[[:space:]]*include(dir)?[[:space:]]/ { i = 1 } END { printf \"default_ccache_name = %s, %s\\n\", c, i ? \"an include\" : \"no includedir\" }' /etc/krb5.conf"
# MIT's package, the session's locale and KRB5CCNAME, for the record (not a row: the two snapshots' builds may differ)
run client2 "rpm -q krb5-workstation krb5-libs | paste -sd' ' -; locale | grep -E '^(LANG|LC_TIME)='; echo \"KRB5CCNAME=\${KRB5CCNAME-unset}\""
run client2 "kdestroy -q 2> /dev/null; rm -rf ~/ct; mkdir -m 0700 ~/ct ~/ct/bin ~/ct/px && echo 'client2: ~/ct made'"
run kdc "for p in $PRINCS; do sudo kadmin.local -q \"delprinc -force \$p\" 2>&1 | grep -v '^Authenticating'; done; sudo kadmin.local -q 'delpol -force ctpol' 2>&1 | grep -v '^Authenticating'; true"
check setup.ctpol '^Minimum password length: 8$' run kdc "sudo kadmin.local -q 'addpol -minlength 8 ctpol' > /dev/null 2>&1; sudo kadmin.local -q 'getpol ctpol' | grep -E '^Minimum password length:'"
# Both legs' kdc.conf set default_principal_flags = +preauth, so these principals require preauth like the services
# (a TGT without it is refused a preauth service, NO PREAUTH); ctuser's TGT is renewed below, so it gets a renewable
# life (a new principal's default is 0).
for p in ctuser ctpre ctbad ctchg ctpw; do
    case $p in
        ctuser) o='-maxrenewlife 7d' ;;
        ctpre) o='+requires_preauth' ;;
        ctpw) o='-policy ctpol' ;;
        *) o='' ;;
    esac
    check "setup.$p" "^Principal \"$p@$R\" created\\.\$" runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'addprinc $o $p' 2>&1" < <(twice "$ALICE")
done
for p in ctkv $SVC $WEB; do
    check "setup.${p%%/*}" "^Principal \"${p//./\\.}@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey $p' 2>&1"
done
check setup.flags '^preauth: ctpre yes, ctuser yes; ctuser renewable 7 days 00:00:00$' run kdc "a=\$(sudo kadmin.local -q 'getprinc ctpre' | grep -c REQUIRES_PRE_AUTH); b=\$(sudo kadmin.local -q 'getprinc ctuser' | grep -c REQUIRES_PRE_AUTH); r=\$(sudo kadmin.local -q 'getprinc ctuser' | sed -n 's/^Maximum renewable life: //p'); echo \"preauth: ctpre \$([ \"\$a\" -ge 1 ] && echo yes || echo no), ctuser \$([ \"\$b\" = 0 ] && echo no || echo yes); ctuser renewable \$r\""
check setup.krbtgt '^krbtgt: Maximum renewable life: ' run kdc "l=\$(sudo kadmin.local -q 'getprinc krbtgt/$REALM' 2>&1 | grep -F 'Maximum renewable life:'); echo \"krbtgt: \$l\"; case \"\$l\" in '' | *': 0 days 00:00:00') exit 1 ;; esac"
check setup.keytab "^Entry for principal $S with kvno 2, encryption type aes256-cts-hmac-sha1-96 added to keytab WRFILE:/home/[^/]+/ct/svc\\.keytab\\.\$" \
    runin client2 "admin/admin's password ($ADMIN)" "kadmin -p admin/admin@$REALM -q \"ktadd -k \$HOME/ct/svc.keytab $SVC\" 2>&1" < <(once "$ADMIN")
OURS=
if [ "$LEG" = rust ]; then
    n=0
    for t in $TOOLS; do
        b=kerber-rust-${FIELD_SHA:0:12}/target/release/krb5-$t
        check "ours.$t.build" '^[0-9a-f]{64}$' run kdc "sha256sum < ~/$b | cut -c1-64"
        h=$(grep -m1 -oE '^[0-9a-f]{64}$' "$LAST_OUT")
        check "ours.$t.copy" "^client2: ~/ct/bin/$t ${h:-none}\$" host "$LABQ ssh kdc -- 'cat ~/$b' | $LABQ ssh client2 -- 'cat > ~/ct/bin/$t && chmod 0755 ~/ct/bin/$t && echo \"client2: ~/ct/bin/$t \$(sha256sum < ~/ct/bin/$t | cut -c1-64)\"'"
        [ -n "$h" ] && grep -q "^client2: ~/ct/bin/$t $h\$" "$LAST_OUT" && n=$((n + 1))
    done
    [ "$n" = "$(wc -w <<< "$TOOLS")" ] && OURS=ours
fi
check client2.kt-records rc runin client2 "lib/kt-records.py" "cat > ~/ct/kt-records.py" < "$FIELD_LIB/kt-records.py"
check client2.ptydrive rc runin client2 "lib/ptydrive.py" "cat > ~/ct/ptydrive.py" < "$FIELD_LIB/ptydrive.py"
check px.copy '^self-test ok$' hostin "lib/kdc-req-proxy.py" "$LABQ ssh client2 -- 'cat > ~/ct/kdc-req-proxy.py && python3 ~/ct/kdc-req-proxy.py --self-test | tail -n 1'" < "$FIELD_LIB/kdc-req-proxy.py"
check px.conf '^ +kdc = 127\.0\.0\.1:1891$' run client2 "sed -E 's/^([[:space:]]*kdc[[:space:]]*=[[:space:]]*).*/\\1127.0.0.1:1891/' /etc/krb5.conf > ~/ct/px.conf && grep -E '^[[:space:]]*kdc[[:space:]]*=' ~/ct/px.conf"
check px.up '^proxy: listening on 127\.0\.0\.1:1891$' run client2 "setsid python3 -u ~/ct/kdc-req-proxy.py 1891 kdc.${REALM,,} 88 ~/ct/px/live.jsonl > /dev/null 2> ~/ct/px/proxy.err < /dev/null & echo \$! > ~/ct/px/pid; sleep 1; ss -Hltn 'sport = :1891' | grep -q . && echo 'proxy: listening on 127.0.0.1:1891'"

section "CT.flow: each program set on its own FILE: cache: the password on stdin, klist, klist -s, kvno, klist -f -e, kinit -R, kdestroy, then the cache is gone"
for k in mit $OURS; do
    C="FILE:\$HOME/ct/$k.cc"
    check "CT.kinit.$k" "^Password for ctuser@$R: \$" runin client2 "ctuser's password ($ALICE)" "$(E "$k") \$B/kinit -c $C ctuser@$REALM" < <(once "$ALICE")
    keep CT.kinit "$k"
    check "CT.klist.$k" "^Default principal: ctuser@$R\$" run client2 "$(E "$k") \$B/klist -c $C"
    checklast "CT.klist.cache.$k" "^Ticket cache: FILE:/home/[^/]+/ct/$k\\.cc\$"
    checklast "CT.klist.head.$k" '^Valid starting     Expires            Service principal$'
    checklast "CT.klist.tgt.$k" "^$T  $T  krbtgt/$R@$R\$"
    keep CT.klist "$k"
    check "CT.klist-s.$k" rc run client2 "$(E "$k") \$B/klist -s -c $C"
    keep CT.klist-s "$k"
    check "CT.kvno.$k" "^$S@$R: kvno = 2\$" run client2 "$(E "$k") \$B/kvno -c $C $SVC@$REALM"
    keep CT.kvno "$k"
    check "CT.klist-fe.$k" "^$T  $T  $S@$R\$" run client2 "$(E "$k") \$B/klist -f -e -c $C"
    checklast "CT.klist-fe.etype.$k" '^	Etype \(skey, tkt\): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 $'
    keep CT.klist-fe "$k"
    check "CT.renew.$k" "^$T  $T  krbtgt/$R@$R\$" run client2 "$(E "$k") \$B/kinit -R -c $C && \$B/klist -c $C"
    keep CT.renew "$k"
    check "CT.kdestroy.$k" '^gone: the cache file$' run client2 "$(E "$k") \$B/kdestroy -c $C && ! test -e \$HOME/ct/$k.cc && echo 'gone: the cache file'"
    keep CT.kdestroy "$k"
    check "CT.klist-s.gone.$k" rc=1 run client2 "$(E "$k") \$B/klist -s -c $C"
    check "CT.klist.gone.$k" "^klist: No credentials cache found \\(filename: /home/[^/]+/ct/$k\\.cc\\)\$" run client2 "$(E "$k") \$B/klist -c $C 2>&1; echo \"rc=\$?\""
    checklast "CT.klist.gone.rc.$k" 'line:rc=1'
    keep CT.klist.gone "$k"
done

section "CT.default: the kit's default cache FILE:/tmp/krb5cc_%{uid}: kinit with no -c, klist -s, kvno, klist, kdestroy, klist -s"
for k in mit $OURS; do
    check "CT.d.kinit.$k" "^Password for ctuser@$R: \$" runin client2 "ctuser's password ($ALICE)" "$(E "$k") \$B/kinit ctuser@$REALM" < <(once "$ALICE")
    check "CT.d.klist-s.$k" rc run client2 "$(E "$k") \$B/klist -s"
    check "CT.d.kvno.$k" "^$S@$R: kvno = 2\$" run client2 "$(E "$k") \$B/kvno $SVC@$REALM"
    check "CT.d.klist.$k" '^Ticket cache: FILE:/tmp/krb5cc_[0-9]+$' run client2 "$(E "$k") \$B/klist"
    checklast "CT.d.klist.svc.$k" "^$T  $T  $S@$R\$"
    keep CT.d.klist "$k"
    check "CT.d.kdestroy.$k" '^gone: /tmp/krb5cc_[0-9]+$' run client2 "$(E "$k") \$B/kdestroy && ! test -e /tmp/krb5cc_\$(id -u) && echo \"gone: /tmp/krb5cc_\$(id -u)\""
    check "CT.d.klist-s.gone.$k" rc=1 run client2 "$(E "$k") \$B/klist -s"
done

section "CT.keytab: kinit -k -t with -c and with KRB5CCNAME (the kit's two forms), klist -k as the kit parses it (NR > 3, column 2), klist -k -e -t"
both CT.kt.c "^Default principal: $S@$R\$" - "\$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/_K_-kt.cc $SVC@$REALM && \$B/klist -c FILE:\$HOME/ct/_K_-kt.cc"
both CT.kt.env "^Default principal: $S@$R\$" - "env KRB5CCNAME=FILE:\$HOME/ct/_K_-env.cc \$B/kinit -k -t \$HOME/ct/svc.keytab $SVC@$REALM && \$B/klist -c FILE:\$HOME/ct/_K_-env.cc"
for k in mit $OURS; do
    check "CT.klist-k.$k" '^Keytab name: FILE:/home/[^/]+/ct/svc\.keytab$' run client2 "$(E "$k") \$B/klist -k \$HOME/ct/svc.keytab"
    checklast "CT.klist-k.head.$k" 'line:KVNO Principal'
    checklast "CT.klist-k.rule.$k" '^---- -{74}$'
    checklast "CT.klist-k.entry.$k" "^   2 $S@$R\$"
    keep CT.klist-k "$k"
    check "CT.klist-k.kit.$k" "^$S@$R\$" run client2 "$(E "$k") \$B/klist -k \$HOME/ct/svc.keytab | awk 'NR > 3 { print \$2 }' | sort -u"
    countlast "CT.klist-k.kit.one.$k" '.' 1
done
both CT.klist-ket 'line:KVNO Timestamp         Principal' - "\$B/klist -k -e -t \$HOME/ct/svc.keytab"

section "CT.shape: the requests themselves, through the proxy: AS plain, preauth, keytab, -C, -s; TGS kvno, kvno -U, renew, validate, --u2u; the lifetimes asked for"
shape plain "$ALICE" "\$B/kinit -c FILE:\$HOME/ct/_K_.px.cc ctuser@$REALM"
shape preauth "$ALICE" "\$B/kinit -c FILE:\$HOME/ct/_K_.pre.cc ctpre@$REALM"
shape keytab - "\$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/_K_.svc.cc $SVC@$REALM"
shape kvno_s4u - "\$B/kvno -c FILE:\$HOME/ct/_K_.svc.cc -U ctuser $SVC@$REALM" rc0
shape kvno_plain - "\$B/kvno -c FILE:\$HOME/ct/_K_.px.cc $WEB@$REALM"
shape renew - "\$B/kinit -R -c FILE:\$HOME/ct/_K_.px.cc"
shape kvno_u2u - "\$B/kvno -c FILE:\$HOME/ct/_K_.px.cc --u2u FILE:\$HOME/ct/_K_.svc.cc $SVC@$REALM" rc0
shape canonicalize "$ALICE" "\$B/kinit -C -c FILE:\$HOME/ct/_K_.c.cc ctuser@$REALM" rc0
shape postdate "$ALICE" "\$B/kinit -s 1h -c FILE:\$HOME/ct/_K_.v.cc ctuser@$REALM" rc0
shape validate - "\$B/kinit -v -c FILE:\$HOME/ct/_K_.v.cc"
check CT.px.renew.opt '^renew: set$' run client2 "jq -r 'select(.kind == \"req\" and .msg_type == 12) | .kdc_options | if any(.[]; . == \"renew\") then \"renew: set\" else \"renew: not set\" end' \$HOME/ct/px/renew.mit.jsonl"
check CT.px.validate.opt '^validate: set$' run client2 "jq -r 'select(.kind == \"req\" and .msg_type == 12) | .kdc_options | if any(.[]; . == \"validate\") then \"validate: set\" else \"validate: not set\" end' \$HOME/ct/px/validate.mit.jsonl"
check CT.px.plain.life '^asked: rtime - till = 518400 s$' run client2 "jq -r 'select(.kind == \"req\") | \"asked: rtime - till = \\(.rtime_unix - .till_unix) s\"' \$HOME/ct/px/plain.mit.jsonl | head -n 1"
if [ -n "$OURS" ]; then
    check CT.px.plain.life.ours '^asked: rtime - till = 518400 s$' run client2 "jq -r 'select(.kind == \"req\") | \"asked: rtime - till = \\(.rtime_unix - .till_unix) s\"' \$HOME/ct/px/plain.ours.jsonl | head -n 1"
    check CT.px.plain.life.same '^till: within [0-9]+ s of MIT.s$' run client2 "a=\$(jq -s '[.[] | select(.kind == \"req\")][0].till_unix' \$HOME/ct/px/plain.mit.jsonl); b=\$(jq -s '[.[] | select(.kind == \"req\")][0].till_unix' \$HOME/ct/px/plain.ours.jsonl); d=\$((b - a)); [ \"\$d\" -ge 0 ] && [ \"\$d\" -le 300 ] && echo \"till: within \$d s of MIT's\""
fi

section "CT.shape2: FAST under -T and its upgrade, SPAKE preferred, the preauth cascade, the enctypes nothing configures, kvno -U -P, no ticket_lifetime with and without -r 12h (get_in_tkt.c, fast.c, s4u_creds.c, init_ctx.c)"
# Each conf is px.conf with one change, and a row shows the change took.
check CT.conf.spake '^preferred_preauth_types = 151$' run client2 "sed '0,/^\\[libdefaults\\]/s//[libdefaults]\\n    preferred_preauth_types = 151/' ~/ct/px.conf > ~/ct/spake.conf && grep -E '^[[:space:]]*preferred_preauth_types' ~/ct/spake.conf | sed 's/^[[:space:]]*//'"
check CT.conf.etypes '^enctype lines left: 0$' run client2 "grep -v -E '^[[:space:]]*(permitted_enctypes|default_tkt_enctypes|default_tgs_enctypes)[[:space:]]*=' ~/ct/px.conf > ~/ct/noetype.conf && [ -s ~/ct/noetype.conf ] && echo \"enctype lines left: \$(grep -c -E 'enctypes[[:space:]]*=' ~/ct/noetype.conf)\""
check CT.conf.canon '^canonicalize = true$' run client2 "sed '0,/^\\[libdefaults\\]/s//[libdefaults]\\n    canonicalize = true/' ~/ct/px.conf > ~/ct/canon.conf && grep -E '^[[:space:]]*canonicalize' ~/ct/canon.conf | sed 's/^[[:space:]]*//'"
check CT.conf.z71 '^ticket_lifetime lines left: 0$' run client2 "grep -v -E '^[[:space:]]*ticket_lifetime[[:space:]]*=' ~/ct/px.conf > ~/ct/z71.conf && [ -s ~/ct/z71.conf ] && echo \"ticket_lifetime lines left: \$(grep -c -E 'ticket_lifetime' ~/ct/z71.conf)\""
for k in mit $OURS; do
    check "CT.armor.$k" "^Default principal: $S@$R\$" run client2 "$(E "$k") \$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/$k.armor.cc $SVC@$REALM && \$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/$k.s4up.cc $SVC@$REALM && \$B/klist -c FILE:\$HOME/ct/$k.armor.cc"
done
shape fast "$ALICE" "\$B/kinit -T FILE:\$HOME/ct/_K_.armor.cc -c FILE:\$HOME/ct/_K_.fast.cc ctuser@$REALM"
check client2.cc-remove '^cc-remove self-test ok$' hostin "lib/cc-remove.py" "$LABQ ssh client2 -- 'cat > ~/ct/cc-remove.py && python3 ~/ct/cc-remove.py --self-test \$HOME/ct/ccrm-self.cc | tail -n 1'" < "$FIELD_LIB/cc-remove.py"
# Without fast_avail the first request goes bare, and the KDC's PA-FX-FAST restarts it armored.
for k in mit $OURS; do
    check "CT.armorx.$k" '^fast_avail: 1 then 0$' run client2 "cp \$HOME/ct/$k.armor.cc \$HOME/ct/$k.armorx.cc && b=\$(LC_ALL=C /usr/bin/klist -C -c FILE:\$HOME/ct/$k.armorx.cc | grep -c '^config: fast_avail') && python3 \$HOME/ct/cc-remove.py FILE:\$HOME/ct/$k.armorx.cc 'krb5_ccache_conf_data/fast_avail/krbtgt\\/$REALM\\@$REALM@X-CACHECONF:' > /dev/null && echo \"fast_avail: \$b then \$(LC_ALL=C /usr/bin/klist -C -c FILE:\$HOME/ct/$k.armorx.cc | grep -c '^config: fast_avail')\""
done
shape fast_upgrade "$ALICE" "\$B/kinit -T FILE:\$HOME/ct/_K_.armorx.cc -c FILE:\$HOME/ct/_K_.fu.cc ctuser@$REALM"
shape spake "$ALICE" "KRB5_CONFIG=\$HOME/ct/spake.conf \$B/kinit -c FILE:\$HOME/ct/_K_.spake.cc ctpre@$REALM" rc0
# Neither KDC holds a delegation target, so the proxy step is refused: ours must fail as MIT's kvno does.
shape kvno_s4u_proxy - "\$B/kvno -c FILE:\$HOME/ct/_K_.s4up.cc -U ctuser -P $SVC@$REALM"
shape z71 "$ALICE" "KRB5_CONFIG=\$HOME/ct/z71.conf \$B/kinit -c FILE:\$HOME/ct/_K_.z71.cc ctuser@$REALM" rc0
shape z82 "$ALICE" "KRB5_CONFIG=\$HOME/ct/z71.conf \$B/kinit -r 12h -c FILE:\$HOME/ct/_K_.z82.cc ctuser@$REALM" rc0
shape canonconf "$ALICE" "KRB5_CONFIG=\$HOME/ct/canon.conf \$B/kinit -c FILE:\$HOME/ct/_K_.canon.cc ctuser@$REALM" rc0
for k in mit $OURS; do
    run client2 ": > \$HOME/ct/px/live.jsonl"
    runin client2 "ctuser's password ($ALICE)" "$(P "$k") KRB5_CONFIG=\$HOME/ct/noetype.conf \$B/kinit -c FILE:\$HOME/ct/$k.et.cc ctuser@$REALM" < <(once "$ALICE")
    run client2 "cp \$HOME/ct/px/live.jsonl \$HOME/ct/px/etypes.$k.jsonl"
done
# J <flow> <k> <jq on the AS-REQs (10) or TGS-REQs (12), as one array>: one line from that capture.
J() { run client2 "jq -rs '[.[] | select(.kind == \"req\" and .msg_type == $3)] | $4' \$HOME/ct/px/$1.$2.jsonl"; }
OUTER='"outer: \(map(select(.padata == [136]) | "till \(.till), rtime \(.rtime), renewable_ok \(any(.kdc_options[]; . == "renewable_ok"))") | unique | join("; "))"'
for k in mit $OURS; do
    J fast "$k" 10 '"till: \(.[0].till // "none")"'
    checklast "CT.px.fast.till.$k" '^till: zero$'
    J fast "$k" 10 "$OUTER"
    checklast "CT.px.fast.outer.$k" '^outer: till zero, rtime absent, renewable_ok true$'
    J fast_upgrade "$k" 10 '"padata: \(map(.padata) | tojson)"'
    checklast "CT.px.fast_upgrade.padata.$k" '^padata: \[\[150,149\],\[136\],\[136\]\]$'
    J fast_upgrade "$k" 10 "$OUTER"
    checklast "CT.px.fast_upgrade.outer.$k" '^outer: till present, rtime present, renewable_ok false$'
    J spake "$k" 10 '"first: \(.[0].padata | tojson)"'
    checklast "CT.px.spake.first.$k" '^first: \[150,149\]$'
    J preauth "$k" 10 '"cascade: \(map(.padata) | tojson)"'
    checklast "CT.px.preauth.cascade.$k" '^cascade: \[\[150,149\],\[133,151,150,149\]\]$'
    J kvno_s4u_proxy "$k" 12 '"tgs: \(map(.padata | tojson) | join(" "))"'
    checklast "CT.px.kvno_s4u_proxy.tgs.$k" '^tgs: \[1,136,130,129\] \[1,136,167\]$'
    J z82 "$k" 10 'if .[0].rtime_unix != null and .[0].rtime_unix == .[0].till_unix then "rtime: till" else "rtime: \(.[0].rtime_unix) till \(.[0].till_unix)" end'
    checklast "CT.px.z82.rtime.$k" '^rtime: till$'
    J canonconf "$k" 10 '"canonicalize: \(.[0].kdc_options | any(. == "canonicalize"))"'
    checklast "CT.px.canonconf.opt.$k" '^canonicalize: true$'
    check "CT.px.z71.till.$k" '^till: now \+ 24 h$' run client2 "n=\$(date +%s); t=\$(jq -s '[.[] | select(.kind == \"req\" and .msg_type == 10)][0].till_unix // empty' \$HOME/ct/px/z71.$k.jsonl); d=\$((\${t:-0} - n - 86400)); if [ -n \"\$t\" ] && [ \"\${d#-}\" -le 300 ]; then echo 'till: now + 24 h'; else echo \"till: \${t:-none}, now \$n\"; fi"
done
# Nothing configured: MIT's list is Fedora's build's (no DES3); ours is its documented default (docs/mit-deviations.md).
J etypes mit 10 '"etypes: \(.[0].etypes | tojson)"'
checklast CT.px.etypes.mit '^etypes: \[18,17,20,19,23,25,26\]$'
if [ -n "$OURS" ]; then
    J etypes ours 10 '"etypes: \(.[0].etypes | tojson)"'
    checklast CT.px.etypes.ours '^etypes: \[18,17,20,19\]$'
fi

section "CT.chpw: kpasswd on ctpw, whose policy wants 8 characters, to 'short': each program set's refusal (chpw.c)"
for k in mit $OURS; do
    check "CT.chpw.$k" '^((Password for [^:]*|Enter new password|Enter it again): )*Password change rejected' runin client2 "ctpw's password ($ALICE), then 'short' twice" "$(E "$k") \$B/kpasswd ctpw@$REALM 2>&1; echo \"rc=\$?\"" < <(once "$ALICE"; printf 'short\nshort\n')
    keep CT.chpw "$k"
done
[ -n "$OURS" ] && same CT.chpw

if [ -n "$OURS" ]; then
    section "CT.ccrm: MIT's krb5_cc_remove_cred (lib/cc-remove.py, client2's libkrb5) on a cache ours wrote: the service ticket goes, the default principal, the TGT and the config entries stay, in both klists (cc_file.c fcc_remove_cred)"
    check CT.ccrm.make "^$W@$R: kvno = [0-9]+\$" runin client2 "ctuser's password ($ALICE)" "$(E ours) \$B/kinit -c FILE:\$HOME/ct/rm.cc ctuser@$REALM > /dev/null && \$B/kvno -c FILE:\$HOME/ct/rm.cc $WEB@$REALM && LC_ALL=C /usr/bin/klist -C -c FILE:\$HOME/ct/rm.cc | grep -E '^config: ' > \$HOME/ct/rm.config.before" < <(once "$ALICE")
    check CT.ccrm.remove "^removed: $W@$R\$" run client2 "python3 \$HOME/ct/cc-remove.py FILE:\$HOME/ct/rm.cc $WEB@$REALM"
    for k in mit ours; do
        check "CT.ccrm.$k" "^principal ctuser@$R; tickets: krbtgt/$R@$R, no $W@$R\$" run client2 "$(E "$k") l=\$(\$B/klist -c FILE:\$HOME/ct/rm.cc) && echo \"principal \$(echo \"\$l\" | sed -n 's/^Default principal: //p'); tickets: \$(echo \"\$l\" | grep -o 'krbtgt/$REALM@$REALM' | head -n 1), \$(echo \"\$l\" | grep -q '$WEB@$REALM' && echo has || echo no) $WEB@$REALM\""
    done
    check CT.ccrm.config '^config entries kept: [1-9][0-9]*$' run client2 "f=\$HOME/ct/rm.config.before; if [ ! -s \"\$f\" ]; then echo 'empty: config before'; exit 1; fi; LC_ALL=C /usr/bin/klist -C -c FILE:\$HOME/ct/rm.cc | grep -E '^config: ' | diff -q - \"\$f\" > /dev/null && echo \"config entries kept: \$(wc -l < \"\$f\")\""
fi

section "CR: client referrals (get_in_tkt.c:1450-1458, :1745-1758, :1268-1270): lib/kdc-rewrite-proxy.py answers an AS-REQ for a made-up realm with WRONG_REALM (68) or C_PRINCIPAL_UNKNOWN (6) naming $REALM; kinit -C restarts there and asks for the password of the rewritten client, without -C the error stands, and LOOPA <-> LOOPB stops after 16 requests"
check cr.copy '^kdc-rewrite-proxy self-test ok$' hostin "lib/kdc-rewrite-proxy.py" "$LABQ ssh client2 -- 'cat > ~/ct/kdc-rewrite-proxy.py && python3 ~/ct/kdc-rewrite-proxy.py --self-test | tail -n 1'" < "$FIELD_LIB/kdc-rewrite-proxy.py"
check cr.conf '^referred realms: 4 in \[realms\]$' run client2 "{ sed -n '1,/^\\[realms\\]/p' ~/ct/px.conf; for r in REFER CPU LOOPA LOOPB; do printf '    %s.TEST = {\\n        kdc = 127.0.0.1:1893\\n    }\\n' \$r; done; sed '1,/^\\[realms\\]/d' ~/ct/px.conf; } | sed '/^[[:space:]]*canonicalize[[:space:]]*=/d' > ~/ct/cr.conf && awk '/^\\[/ { s = \$1 } /= 127\\.0\\.0\\.1:1893\$/ { n++; if (s != \"[realms]\") bad = 1 } END { print \"referred realms: \" n (bad ? \" outside [realms]\" : \" in [realms]\") }' ~/ct/cr.conf"
check cr.up '^refer: listening on 127\.0\.0\.1:1893$' run client2 "setsid python3 -u ~/ct/kdc-rewrite-proxy.py 1893 127.0.0.1 1891 ~/ct/px/cr.log refer 'REFER.TEST=$REALM,CPU.TEST=$REALM/6,LOOPA.TEST=LOOPB.TEST,LOOPB.TEST=LOOPA.TEST' > /dev/null 2> ~/ct/px/cr.err < /dev/null & echo \$! > ~/ct/px/cr.pid; sleep 1; ss -Hlun 'sport = :1893' | grep -q . && echo 'refer: listening on 127.0.0.1:1893'"
for k in mit $OURS; do
    for c in 68 6; do
        cr=REFER.TEST
        [ "$c" = 6 ] && cr=CPU.TEST
        check "CR.$c.$k" "^Default principal: ctuser@$R\$" runin client2 "ctuser's password ($ALICE)" "$(C "$k") \$B/kinit -C -c FILE:\$HOME/ct/$k-cr$c.cc ctuser@$cr && \$B/klist -c FILE:\$HOME/ct/$k-cr$c.cc" < <(once "$ALICE")
        checklast "CR.$c.prompt.$k" "^Password for ctuser@$R: "
        keep "CR.$c" "$k"
        check "CR.$c.asked.$k" "^$cr asked once: rep kind=error error_code=$c rewritten=answered\$" run client2 "echo \"$cr asked \$([ \"\$(grep -c '^req#' \$HOME/ct/px/cr.log)\" = 1 ] && echo once || echo more): \$(grep '^rep#' \$HOME/ct/px/cr.log | sed 's/^rep#[0-9]* /rep /')\"; cp \$HOME/ct/px/live.jsonl \$HOME/ct/px/cr$c.$k.jsonl"
        check "CR.$c.restart.$k" "^restarted: realm $R, sname krbtgt/$R, cname ctuser, canonicalize\$" run client2 "jq -rs '[.[] | select(.kind == \"req\")][0] // empty | \"restarted: realm \\(.realm), sname \\(.sname), cname \\(.cname), \\(if any(.kdc_options[]; . == \"canonicalize\") then \"canonicalize\" else \"no canonicalize\" end)\"' \$HOME/ct/px/cr$c.$k.jsonl"
    done
    check "CR.nocanon.$k" '^kinit: Realm not local to KDC while getting initial credentials$' run client2 "$(C "$k") \$B/kinit -c FILE:\$HOME/ct/$k-crn.cc ctuser@REFER.TEST < /dev/null 2>&1; echo \"rc=\$?, requests \$(grep -c '^req#' \$HOME/ct/px/cr.log)\""
    checklast "CR.nocanon.once.$k" 'line:rc=1, requests 1'
    keep CR.nocanon "$k"
    check "CR.loop.$k" '^kinit: Looping detected inside krb5_get_in_tkt while getting initial credentials$' run client2 "$(C "$k") \$B/kinit -C -c FILE:\$HOME/ct/$k-crl.cc ctuser@LOOPA.TEST < /dev/null 2>&1; echo \"rc=\$?, requests \$(grep -c '^req#' \$HOME/ct/px/cr.log)\""
    checklast "CR.loop.16.$k" 'line:rc=1, requests 16'
    keep CR.loop "$k"
done
if [ -n "$OURS" ]; then
    for c in 68 6; do
        check "CR.$c.px.same" "^FLOW_cr${c}_equal\$" run client2 "python3 \$HOME/ct/kdc-req-proxy.py --compare \$HOME/ct/px/cr$c.mit.jsonl \$HOME/ct/px/cr$c.ours.jsonl cr$c"
    done
fi
run client2 "kill \$(cat ~/ct/px/cr.pid) && rm -f ~/ct/px/cr.pid; cat ~/ct/px/cr.err; kill \$(cat ~/ct/px/pid) && rm -f ~/ct/px/pid; cat ~/ct/px/proxy.err"

if [ -n "$OURS" ]; then
    section "CT.cross: MIT's klist and kvno on our cache, ours on MIT's; our kvno adds a second service ticket to MIT's preauth cache, MIT's klist reads all three back with its config entries kept; each kdestroy on the other's cache"
    for k in mit ours; do
        check "CT.x.cc.$k" "^Default principal: ctuser@$R\$" runin client2 "ctuser's password ($ALICE)" "$(E "$k") \$B/kinit -c FILE:\$HOME/ct/$k.cc ctuser@$REALM > /dev/null && /usr/bin/klist -f -e -c FILE:\$HOME/ct/$k.cc" < <(once "$ALICE")
        keep CT.x.cc "$k"
    done
    check CT.x.mitkvno "^$S@$R: kvno = 2\$" run client2 "LC_ALL=C /usr/bin/kvno -c FILE:\$HOME/ct/ours.cc $SVC@$REALM"
    check CT.x.ourslist "^$T  $T  $S@$R\$" run client2 "$(E ours) \$B/klist -c FILE:\$HOME/ct/ours.cc"
    checklast CT.x.ourslist.tgt "^$T  $T  krbtgt/$R@$R\$"
    check CT.x.conf.before '^config: ' runin client2 "ctpre's password ($ALICE)" "LC_ALL=C /usr/bin/kinit -c FILE:\$HOME/ct/mit-conf.cc ctpre@$REALM > /dev/null && LC_ALL=C /usr/bin/kvno -c FILE:\$HOME/ct/mit-conf.cc $SVC@$REALM > /dev/null && LC_ALL=C /usr/bin/klist -C -c FILE:\$HOME/ct/mit-conf.cc" < <(once "$ALICE")
    cp "$LAST_OUT" "$STATE/conf.before"
    check CT.x.ourskvno "^$W@$R: kvno = 1\$" run client2 "$(E ours) \$B/kvno -c FILE:\$HOME/ct/mit-conf.cc $WEB@$REALM"
    check CT.x.kept.web "^$T  $T  $W@$R\$" run client2 "LC_ALL=C /usr/bin/klist -C -c FILE:\$HOME/ct/mit-conf.cc"
    checklast CT.x.kept.svc "^$T  $T  $S@$R\$"
    checklast CT.x.kept.tgt "^$T  $T  krbtgt/$R@$R\$"
    cp "$LAST_OUT" "$STATE/conf.after"
    check CT.x.kept.conf '^config entries kept: [1-9][0-9]*$' host "diff <(grep '^config: ' $(printf '%q' "$STATE/conf.before")) <(grep '^config: ' $(printf '%q' "$STATE/conf.after")) && echo \"config entries kept: \$(grep -c '^config: ' $(printf '%q' "$STATE/conf.after"))\""
    check CT.x.ourskdestroy rc run client2 "$(E ours) \$B/kdestroy -c FILE:\$HOME/ct/mit.cc"
    check CT.x.ourskdestroy.mit rc=1 run client2 "/usr/bin/klist -s -c FILE:\$HOME/ct/mit.cc"
    check CT.x.mitkdestroy rc run client2 "/usr/bin/kdestroy -c FILE:\$HOME/ct/ours.cc"
    check CT.x.mitkdestroy.ours rc=1 run client2 "$(E ours) \$B/klist -s -c FILE:\$HOME/ct/ours.cc"
fi

section "CT.dir: a DIR: collection: two principals, klist -l, kswitch -p and -c, kdestroy -A; in the rust leg one collection crossed between the program sets; a missing DIR: is made on resolve, 0700, primary tkt (MIT's verify_dir)"
both CT.dir.two '^Principal name                 Cache name$' "$ALICE" "export KRB5CCNAME=DIR:\$HOME/ct/_K_.dir && mkdir -m 0700 \$HOME/ct/_K_.dir && \$B/kinit ctuser@$REALM > /dev/null && \$B/kinit -k -t \$HOME/ct/svc.keytab $SVC@$REALM && \$B/klist -l"
both CT.dir.primary "^Default principal: $S@$R\$" - "export KRB5CCNAME=DIR:\$HOME/ct/_K_.dir && \$B/klist"
both CT.dir.switch-p "^Default principal: ctuser@$R\$" - "export KRB5CCNAME=DIR:\$HOME/ct/_K_.dir && \$B/kswitch -p ctuser@$REALM && \$B/klist"
both CT.dir.switch-c "^Default principal: $S@$R\$" - "export KRB5CCNAME=DIR:\$HOME/ct/_K_.dir && f=\$(grep -l -a ctsvc \$HOME/ct/_K_.dir/tkt*) && \$B/kswitch -c DIR::\$f && \$B/klist"
both CT.dir.destroy-a '^left: 0$' - "export KRB5CCNAME=DIR:\$HOME/ct/_K_.dir && \$B/kdestroy -A && echo \"left: \$(ls \$HOME/ct/_K_.dir | grep -c '^tkt')\""
if [ -n "$OURS" ]; then
    # One collection both program sets use: MIT's kinit and kswitch -p read by our klist, our kswitch -c read by MIT's.
    check CT.dir.x.mitkinit.mit "^Default principal: $S@$R\$" runin client2 "ctuser's password ($ALICE)" "$(E mit) export KRB5CCNAME=DIR:\$HOME/ct/x.dir && mkdir -m 0700 \$HOME/ct/x.dir && \$B/kinit ctuser@$REALM > /dev/null && \$B/kinit -k -t \$HOME/ct/svc.keytab $SVC@$REALM && \$B/klist" < <(once "$ALICE")
    check CT.dir.x.mitkinit.ours "^Default principal: $S@$R\$" run client2 "$(E ours) \$B/klist -c DIR:\$HOME/ct/x.dir"
    check CT.dir.x.mitswitch.mit "^Default principal: ctuser@$R\$" run client2 "$(E mit) export KRB5CCNAME=DIR:\$HOME/ct/x.dir && \$B/kswitch -p ctuser@$REALM && \$B/klist"
    check CT.dir.x.mitswitch.ours "^Default principal: ctuser@$R\$" run client2 "$(E ours) \$B/klist -c DIR:\$HOME/ct/x.dir"
    check CT.dir.x.ourswitch.ours "^Default principal: $S@$R\$" run client2 "$(E ours) export KRB5CCNAME=DIR:\$HOME/ct/x.dir && f=\$(grep -l -a ctsvc \$HOME/ct/x.dir/tkt*) && \$B/kswitch -c DIR::\$f && \$B/klist"
    check CT.dir.x.ourswitch.mit "^Default principal: $S@$R\$" run client2 "$(E mit) \$B/klist -c DIR:\$HOME/ct/x.dir"
fi
both CT.dir.missing '^rc=1, made 700, primary tkt$' - "\$B/klist -c DIR:\$HOME/ct/_K_.nodir > /dev/null 2>&1; echo \"rc=\$?, \$(test -e \$HOME/ct/_K_.nodir && echo made \$(stat -c %a \$HOME/ct/_K_.nodir), primary \$(cat \$HOME/ct/_K_.nodir/primary 2> /dev/null) || echo absent)\""

section "CT.ktutil: rkt and list -e; an unknown enctype; a v1 keytab (kvno past 255) read; wkt keeps a v1 file v1 and makes a new one v2, the records MIT's; addent -password on a tty (lib/ptydrive.py), the keytab MIT's kinit -k uses; a keytab with kvnos 2 and 3"
both CT.kt.list "^   1    2 +$S@$R \\(aes256-cts-hmac-sha1-96\\) *\$" - "printf 'rkt %s\\nlist -e\\nquit\\n' \$HOME/ct/svc.keytab | \$B/ktutil 2>&1"
check CT.kt.unknown.make '^/home/[^/]+/ct/unk\.keytab: one entry, ctuser@[^,]+, kvno 3, enctype 99$' run client2 "python3 \$HOME/ct/kt-records.py unknown \$HOME/ct/unk.keytab $REALM ctuser"
for k in mit $OURS; do
    check "CT.kt.unknown.$k" "^ +1 +3 +ctuser@$R\$" run client2 "$(E "$k") printf 'rkt %s\\nlist\\nlist -e\\nquit\\n' \$HOME/ct/unk.keytab | \$B/ktutil 2>&1"
    checklast "CT.kt.unknown.etype.$k" 'While converting enctype to string$'
done
check CT.kt.v1.kvno '^Key: vno 300, ' run kdc "sudo kadmin.local -q 'modprinc -kvno 300 ctkv' 2>&1 > /dev/null; sudo kadmin.local -q 'getprinc ctkv' | grep -m1 '^Key: vno '"
check CT.kt.v1.make "^Entry for principal ctkv with kvno 301, encryption type aes256-cts-hmac-sha1-96 added to keytab WRFILE:/home/[^/]+/ct/v1\\.keytab\\.\$" \
    runin client2 "admin/admin's password ($ADMIN)" "printf '\\005\\001' > \$HOME/ct/v1.keytab && kadmin -p admin/admin@$REALM -q \"ktadd -k \$HOME/ct/v1.keytab ctkv\" 2>&1" < <(once "$ADMIN")
check CT.kt.v1.header '^v1: 0501$' run client2 "echo \"v1: \$(od -An -tx1 -N2 \$HOME/ct/v1.keytab | tr -d ' ')\""
both CT.kt.v1 "^ 301 ctkv@$R \\(aes256-cts-hmac-sha1-96\\) \$" - "\$B/klist -k -e \$HOME/ct/v1.keytab"
both CT.kt.wkt '^headers: 0501 0502$' - "cp \$HOME/ct/v1.keytab \$HOME/ct/_K_-v1w.keytab && printf 'rkt %s\\nrkt %s\\nwkt %s\\nwkt %s\\nquit\\n' \$HOME/ct/svc.keytab \$HOME/ct/v1.keytab \$HOME/ct/_K_-v1w.keytab \$HOME/ct/_K_-new.keytab | \$B/ktutil > /dev/null 2>&1; echo \"headers: \$(od -An -tx1 -N2 \$HOME/ct/_K_-v1w.keytab | tr -d ' ') \$(od -An -tx1 -N2 \$HOME/ct/_K_-new.keytab | tr -d ' ')\""
if [ -n "$OURS" ]; then
    for f in v1w new; do
        check "CT.kt.wkt.$f.records" '^records: [1-9][0-9]*, the same but for the timestamps$' run client2 "python3 \$HOME/ct/kt-records.py compare \$HOME/ct/mit-$f.keytab \$HOME/ct/ours-$f.keytab"
    done
fi
both CT.kt.addent "^Default principal: ctuser@$R\$" "$ALICE" "python3 \$HOME/ct/ptydrive.py --timeout 60 --secrets 1 --max 1 --rule 'Password for [^:]+:=0' --send-after 'ktutil:=addent -password -p ctuser@$REALM -k 1 -e aes256-cts-hmac-sha1-96' --send-after \"ktutil:=wkt \$HOME/ct/_K_-pw.keytab\" --send-after 'ktutil:=quit' -- \$B/ktutil > /dev/null 2>&1; /usr/bin/kinit -k -t \$HOME/ct/_K_-pw.keytab -c FILE:\$HOME/ct/_K_-pw.cc ctuser@$REALM && /usr/bin/klist -c FILE:\$HOME/ct/_K_-pw.cc"
check CT.kt.multi.add "^Entry for principal $S with kvno 3, encryption type aes256-cts-hmac-sha1-96 added to keytab WRFILE:/home/[^/]+/ct/svc\\.keytab\\.\$" \
    runin client2 "admin/admin's password ($ADMIN)" "kadmin -p admin/admin@$REALM -q \"ktadd -k \$HOME/ct/svc.keytab $SVC\" 2>&1" < <(once "$ADMIN")
both CT.kt.multi "^Default principal: $S@$R\$" - "\$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/_K_-multi.cc $SVC@$REALM && \$B/klist -c FILE:\$HOME/ct/_K_-multi.cc"

section "CT.pwexpired: kinit for a principal that must change its password (+needchange): MIT's banner and prompts, the change through kpasswd, then the ticket"
for k in mit $OURS; do
    check "CT.pwexp.set.$k" '^Attributes: .*REQUIRES_PWCHANGE' runin kdc "alice's password ($ALICE), twice" "sudo kadmin.local -q 'cpw ctchg' > /dev/null 2>&1; sudo kadmin.local -q 'modprinc +needchange ctchg' > /dev/null 2>&1; sudo kadmin.local -q 'getprinc ctchg' | grep '^Attributes:'" < <(twice "$ALICE")
    check "CT.pwexp.$k" 'Password expired\.  You must change it now\.$' runin client2 "ctchg's password ($ALICE), then a new one twice" "$(E "$k") \$B/kinit -c FILE:\$HOME/ct/$k-chg.cc ctchg@$REALM && \$B/klist -c FILE:\$HOME/ct/$k-chg.cc" < <(once "$ALICE"; printf '%s\n%s\n' 'Ct-new-pw-1' 'Ct-new-pw-1')
    checklast "CT.pwexp.ticket.$k" "^Default principal: ctchg@$R\$"
    keep CT.pwexp "$k"
done

section "CT.refusals: MIT's text and exit code: an unknown client, an unknown service, a missing keytab (kinit -k, klist -k), kdestroy of no cache, an unknown cache type (and KEYRING: for ours, which have none), a missing cache directory, no KDC, an expired client, a revoked one, kvno -P alone; a wrong password last"
both CT.err.client "kinit: Client 'nosuch@$R' not found in Kerberos database while getting initial credentials\$" "$ALICE" "\$B/kinit -c FILE:\$HOME/ct/_K_-e.cc nosuch@$REALM 2>&1; echo \"rc=\$?\""
both CT.err.svc "^kvno: Server nosuch/x@$R not found in Kerberos database while getting credentials for nosuch/x@$R\$" - "\$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/_K_-e.cc $SVC@$REALM && \$B/kvno -c FILE:\$HOME/ct/_K_-e.cc nosuch/x@$REALM 2>&1; echo \"rc=\$?\""
both CT.err.kt "^kinit: Pre-authentication failed: Key table file '/home/[^/]+/ct/none\\.keytab' not found while getting initial credentials\$" - "\$B/kinit -k -t \$HOME/ct/none.keytab -c FILE:\$HOME/ct/_K_-e.cc $SVC@$REALM 2>&1; echo \"rc=\$?\""
both CT.err.klist-k "^klist: Key table file '/home/[^/]+/ct/none\\.keytab' not found while starting keytab scan\$" - "o=\$(\$B/klist -k \$HOME/ct/none.keytab 2> \$HOME/ct/_K_-kerr); r=\$?; cat \$HOME/ct/_K_-kerr; printf '%s\\n' \"\$o\"; echo \"rc=\$r\""
both CT.err.kdestroy '^kdestroy: No credentials cache found while destroying cache$' - "\$B/kdestroy -c FILE:\$HOME/ct/none.cc 2>&1; echo \"rc=\$?\""
both CT.err.cctype '^klist: Unknown credential cache type while resolving ccache$' - "\$B/klist -c XYZ:nosuch 2>&1; echo \"rc=\$?\""
if [ -n "$OURS" ]; then
    check CT.keyring.ours '^klist: Unknown credential cache type while resolving ccache$' run client2 "$(E ours) \$B/klist -c KEYRING:persistent:\$(id -u) 2>&1; echo \"rc=\$?\""
    checklast CT.keyring.ours.rc 'line:rc=1'
fi
both CT.err.ccdir 'kinit: Failed to store credentials: No credentials cache found while getting initial credentials$' "$ALICE" "\$B/kinit -c FILE:\$HOME/ct/nodir/cc ctuser@$REALM 2>&1; echo \"rc=\$?\""
both CT.err.nokdc "kinit: Cannot contact any KDC for realm '$R' while getting initial credentials\$" "$ALICE" "sed -E 's/^([[:space:]]*kdc[[:space:]]*=[[:space:]]*).*/\\1127.0.0.1:1/' /etc/krb5.conf > \$HOME/ct/_K_-nokdc.conf && KRB5_CONFIG=\$HOME/ct/_K_-nokdc.conf \$B/kinit -c FILE:\$HOME/ct/_K_-e.cc ctuser@$REALM 2>&1; echo \"rc=\$?\""
check CT.err.expired.set "^Principal \"ctbad@$R\" modified\\.\$" run kdc "sudo kadmin.local -q 'modprinc -expire \"Jan 1, 2020 00:00:00 UTC\" ctbad' 2>&1"
both CT.err.expired "kinit: Client's entry in database has expired while getting initial credentials\$" "$ALICE" "\$B/kinit -c FILE:\$HOME/ct/_K_-e.cc ctbad@$REALM 2>&1; echo \"rc=\$?\""
check CT.err.revoked.set "^Principal \"ctbad@$R\" modified\\.\$" run kdc "sudo kadmin.local -q 'modprinc -expire never +disallow_all_tix ctbad' 2>&1"
both CT.err.revoked "kinit: Client's credentials have been revoked while getting initial credentials\$" "$ALICE" "\$B/kinit -c FILE:\$HOME/ct/_K_-e.cc ctbad@$REALM 2>&1; echo \"rc=\$?\""
for k in mit $OURS; do
    check "CT.err.kvno-P.$k" '^Option -P \(constrained delegation\) requires option -I\|-U\|-F \(protocol transition\)$' run client2 "$(E "$k") \$B/kvno -P $SVC@$REALM 2>&1; echo \"rc=\$?\""
    checklast "CT.err.kvno-P.rc.$k" 'line:rc=1'
done
both CT.err.pw "kinit: Password incorrect while getting initial credentials\$" - "printf 'not-the-password\\n' | \$B/kinit -c FILE:\$HOME/ct/_K_-e.cc ctuser@$REALM 2>&1; echo \"rc=\$?\""
for s in CT.err.client CT.err.svc CT.err.kt CT.err.klist-k CT.err.cctype CT.err.ccdir CT.err.nokdc CT.err.expired CT.err.revoked CT.err.pw; do
    rcof "$s" 1
done
rcof CT.err.kdestroy 0

section "CT.locale: klist in the session's own locale (INFO): MIT's dates follow it, ours print the C locale's (docs/install.md lists it)"
for k in mit $OURS; do
    observe "obs.CT.locale.$k" 'Valid starting +Expires +Service principal' run client2 "$(E "$k") unset LC_ALL; \$B/kinit -k -t \$HOME/ct/svc.keytab -c FILE:\$HOME/ct/$k-loc.cc $SVC@$REALM && \$B/klist -c FILE:\$HOME/ct/$k-loc.cc"
done

if [ -n "$OURS" ]; then
    section "CT.same: ours printed what MIT's printed, step by step (the dates, the program set's file names, the uid and DIR: cache names masked)"
    for s in CT.kinit CT.klist CT.klist-s CT.kvno CT.klist-fe CT.renew CT.kdestroy CT.klist.gone CT.d.klist CT.kt.c CT.kt.env CT.klist-k \
        CT.x.cc CT.dir.two CT.dir.primary CT.dir.switch-p CT.dir.switch-c CT.dir.destroy-a CT.dir.missing CT.kt.v1 CT.kt.wkt CT.kt.addent CT.kt.multi CT.pwexp \
        CT.err.client CT.err.svc CT.err.kt CT.err.klist-k CT.err.kdestroy CT.err.cctype CT.err.ccdir CT.err.nokdc CT.err.expired CT.err.revoked CT.err.pw \
        CR.68 CR.6 CR.nocanon CR.loop; do
        same "$s"
    done
    same CT.klist-ket "$MX"
fi
finish
