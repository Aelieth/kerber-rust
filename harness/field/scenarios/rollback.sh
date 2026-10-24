#!/usr/bin/env bash
# harness/field/scenarios/rollback.sh --leg mit|rust: the leg's realm back on MIT's KDC, its principals as the leg's KDC
# kept them (SW-2's export bar; docs/install.md "Going back to MIT"):
#   RB.ops: on kdc, addprinc of rbadd, cpw -randkey of rbcpw and delprinc of rbdel (each made first), then the getprinc
#           lines of rbadd, rbcpw, rbdel and alice that both KDCs must agree on;
#   RB.back: rust leg, "Going back to MIT" run as written, its block by heading in the ref's checkout: kerber-rust's
#           kdb5_util dump, make uninstall, dnf install krb5-server, MIT's kdb5_util load and daemons. A dnf that does
#           not reach the mirrors is a mirror failure (RB.mirror), never a pass. Mit leg, the oracle's own round trip:
#           MIT's kdb5_util dump and load of the same realm;
#   RB.mit: MIT's KDC serves the realm, its getprinc lines equal those before, and MIT's kinit from client2 gets alice
#           a TGT.
# Graded on both legs, MIT's first. Each leg leaves kdc on MIT; replica, next in weekly, resets it.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: rollback.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}" "${FIELD_TREE_TAR:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE
R=${REALM//./\\.}
W=/var/tmp/rb
CO=kerber-rust-${FIELD_SHA:0:12}
DOCB=$FIELD_LIB/docblocks.py
FIELDS='^(Principal|Maximum ticket life|Maximum renewable life|Attributes|Policy|Key: vno)|does not exist'
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "for p in rbadd rbcpw rbdel; do sudo kadmin.local -q \"delprinc -force \$p\" > /dev/null 2>&1; done; sudo rm -rf $W; rm -f ~/field/back.sh; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh client2 -- 'rm -rf ~/rb; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# fields <file>: the getprinc lines both KDCs must agree on, for rbadd, rbcpw, rbdel and alice, into $STATE/<file>.
fields() {
    run kdc "for p in rbadd rbcpw rbdel alice; do sudo kadmin.local -q \"getprinc \$p\" 2>&1 | grep -E '$FIELDS'; done"
    grep -E "$FIELDS" "$LAST_OUT" > "$STATE/$1"
}

section "rollback --leg $LEG: the $LEG KDC's realm back on MIT's KDC, its principals as they were"
kdcis

section "RB.ops: three writes on the $LEG KDC, then the getprinc lines both KDCs must agree on"
check RB.ops.setup "^Principal \"rbdel@$R\" created\\.\$" run kdc "for p in rbadd rbcpw rbdel; do sudo kadmin.local -q \"delprinc -force \$p\" > /dev/null 2>&1; done; sudo kadmin.local -q 'addprinc -randkey rbcpw' 2>&1; sudo kadmin.local -q 'addprinc -randkey rbdel' 2>&1"
check RB.ops.add "^Principal \"rbadd@$R\" created\\.\$" run kdc "sudo kadmin.local -q 'addprinc -randkey rbadd' 2>&1"
check RB.ops.cpw "^Key for \"rbcpw@$R\" randomized\\.\$" run kdc "sudo kadmin.local -q 'cpw -randkey rbcpw' 2>&1"
check RB.ops.del "^Principal \"rbdel@$R\" deleted\\.\$" run kdc "sudo kadmin.local -q 'delprinc -force rbdel' 2>&1"
fields before
check RB.ops.before '^rbcpw: Key: vno 2, ' host "awk '/^Principal:/ { p = \$2; sub(/@.*/, \"\", p) } /^Key: vno/ { print p \": \" \$0 }' $(printf '%q' "$STATE/before")"
check RB.ops.deleted '"rbdel@' host "grep -E 'does not exist' $(printf '%q' "$STATE/before")"

if [ "$LEG" = rust ]; then
    section "RB.back: docs/install.md \"Going back to MIT\", its block as written, in the ref's checkout"
    observe RB.back.dir 'principal[.a-z]*' run kdc "sudo ls -la /var/kerberos/krb5kdc"
    tar -xOf "$FIELD_TREE_TAR" "$CO/docs/install.md" > "$STATE/install.md"
    check doc.back.blocks 'line:1' host "python3 -B $(printf '%q' "$DOCB") count $(printf '%q' "$STATE/install.md") '### Going back to MIT'"
    check doc.back.script rc host "python3 -B $(printf '%q' "$DOCB") script $(printf '%q' "$STATE/install.md") '### Going back to MIT' 1 --session '. \"\$HOME/.cargo/env\"' --session 'cd ~/$CO' > $(printf '%q' "$STATE/back.sh")"
    hostin "back.sh" "$LABQ ssh kdc -- 'install -d -m 0700 ~/field && cat > ~/field/back.sh'" < "$STATE/back.sh"
    run kdc "bash ~/field/back.sh"
    cp "$LAST_OUT" "$STATE/back.out"
    if python3 -B "$DOCB" results "$STATE/back.out" > "$STATE/back.results"; then
        while IFS=$'\t' read -r i rc nout first; do
            res=FAIL
            [ "$rc" = 0 ] && res=PASS
            _checkrow "doc.back.$i" "$res" rc "$rc" "rc=$rc, $nout output lines: $first"
            if [[ $first =~ ^sudo\ dnf\ install ]] && [ "$rc" != 0 ]; then
                python3 -B "$DOCB" output "$STATE/back.out" "$i" > "$STATE/dnf.out"
                _checkrow RB.mirror FAIL 'dnf reaches the mirrors' "$rc" "mirror failure: $(grep -m1 -iE 'curl|download|mirror|repo|resolve' "$STATE/dnf.out" || echo "dnf exited $rc")"
            fi
        done < "$STATE/back.results"
    else
        _checkrow doc.back FAIL units "$LAST_RC" "no command of the block ran"
    fi
else
    section "RB.back: the oracle's own round trip, MIT's kdb5_util dump and load of the realm"
    check RB.back.dump rc run kdc "sudo install -d -m 0700 $W && sudo kdb5_util dump $W/mit.dump"
    check RB.back.load rc run kdc "sudo systemctl stop krb5kdc kadmin && sudo kdb5_util load $W/mit.dump && sudo systemctl start krb5kdc kadmin"
fi

section "RB.mit: MIT's KDC serves the realm, its getprinc lines as before, and MIT's kinit gets alice a TGT"
check RB.mit.kdc '^kdc: MIT krb5-server-[0-9].*, binaries as packaged, active active$' run kdc "sudo rpm -V krb5-server | grep -E ' /usr/sbin/'; ! sudo rpm -V krb5-server | grep -qE '^..5.* /usr/sbin/(krb5kdc|kadmind|kdb5_util|kadmin\\.local)\$' && echo \"kdc: MIT \$(rpm -q krb5-server), binaries as packaged, \$(systemctl is-active krb5kdc kadmin | paste -sd' ' -)\""
fields after
check RB.mit.fields '^fields equal$' host "diff $(printf '%q' "$STATE/before") $(printf '%q' "$STATE/after") && echo 'fields equal'"
check RB.mit.kinit "^Default principal: alice@$R\$" runin client2 "alice's password ($ALICE)" "mkdir -p ~/rb && kinit -c FILE:\$HOME/rb/a.cc alice > /dev/null 2>&1; echo \"kinit rc=\$?\"; klist -c FILE:\$HOME/rb/a.cc 2>&1 | grep -E '^Default principal'" < <(once "$ALICE")
finish
