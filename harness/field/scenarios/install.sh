#!/usr/bin/env bash
# harness/field/scenarios/install.sh --leg rust: kdc reset to its pristine 'base' snapshot, then a fresh
# kerber-rust install from docs/install.md's program-install blocks (Prerequisites, Build, Replacing
# krb5-server, taken from the archive by heading through lib/docblocks.py, so a doc change is what runs), and
# the KERBER.TEST realm and population ported from the hand record f-L2-rust: kdb5_util create, the bootstrap
# and populated principals' getprinc (F4d's compare.py grades the two legs by check), the five svc/setup ACL
# variants (lib/acl-variant.sh) and the refusal texts, the kadm5 calls from client2, strings-check.sh on the
# installed binaries, and no SELinux AVC. It resets kdc, so it runs last in the weekly profile. --leg mit: the
# same realm and population on a stock Fedora krb5-server (the oracle), minus the services principals and the
# install-only gates. INSTALL_DOC (a scratch doc) overrides the doc read from the archive -- the negative
# control. Run by run.sh (REC_DIR, TMPDIR, FIELD_TREE_TAR, FIELD_SHA, FIELD_REF, FIELD_DEADLINE).
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: install.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_TREE_TAR:?run by run.sh}" "${FIELD_SHA:?run by run.sh}" "${FIELD_REF:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
R=$REALM DOMAIN=kerber.test KDC_HOST=kdc.kerber.test
# shellcheck source=../lib/acl-variant.sh
. "$FIELD_LIB/acl-variant.sh"
T0=$(date +%s)
legset ADMIN ALICE BOB MASTER
DOCB=$FIELD_LIB/docblocks.py
CO=kerber-rust-${FIELD_SHA:0:12}
CARGO_ENV=". \"\$HOME/.cargo/env\""
KD=/var/kerberos/krb5kdc
cleanup() {
    timeout -k 5 60 "$LAB" ssh client2 -- "for c in ~/field/*.cc; do [ -e \"\$c\" ] && KRB5CCNAME=FILE:\$c kdestroy; done; rm -rf ~/field; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh kdc -- 'rm -rf ~/field; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

# docscript/docrun: a doc block as a session script, then one check per command (from upgrade.sh).
docscript() { local n=$1; shift; check "doc.$n.script" rc host "python3 -B $(printf '%q' "$DOCB") script $(printf '%q ' "$@") > $(printf '%q' "$STATE/$n.sh")"; }
docrun() {
    local n=$1 lst=${2:-} i rc nout first res exp
    hostin "$n.sh" "$LABQ ssh kdc -- 'install -d -m 0700 ~/field && cat > ~/field/$n.sh'" < "$STATE/$n.sh"
    run kdc "bash ~/field/$n.sh"; cp "$LAST_OUT" "$STATE/$n.out"
    if ! python3 -B "$DOCB" results "$STATE/$n.out" > "$STATE/$n.results"; then
        _checkrow "doc.$n" FAIL units "$LAST_RC" "no command of the block ran"; return; fi
    while IFS=$'\t' read -r i rc nout first; do
        res=FAIL exp=rc
        if [ -n "$lst" ] && [[ $first =~ $lst ]]; then exp='rc=0|1'; case $rc in 0 | 1) res=PASS ;; esac
        elif [ "$rc" = 0 ]; then res=PASS; fi
        _checkrow "doc.$n.$i" "$res" "$exp" "$rc" "rc=$rc, $nout lines: $first"
    done < "$STATE/$n.results"
}
# The realm's config files on $STATE, tee'd to kdc (realm is always KERBER.TEST; rust adds the 4 listen lines).
kdcconf() {
    cat > "$STATE/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
    spake_preauth_kdc_challenge = edwards25519

[realms]
$R = {
     master_key_type = aes256-cts-hmac-sha1-96
     acl_file = $KD/kadm5.acl
     dict_file = /usr/share/dict/words
     default_principal_flags = +preauth
     admin_keytab = $KD/kadm5.keytab
     max_life = 24h
     max_renewable_life = 7d
EOF
    [ "$1" = rust ] && printf '     kdc_listen = [::]:88\n     kdc_tcp_listen = [::]:88\n     kadmind_listen = [::]:749\n     kpasswd_listen = [::]:464\n' >> "$STATE/kdc.conf"
    printf '     supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n}\n' >> "$STATE/kdc.conf"
    check conf.kdc rc hostin kdc.conf "$LABQ ssh kdc -- 'sudo install -d -m 0755 $KD && sudo tee $KD/kdc.conf >/dev/null && sudo restorecon $KD/kdc.conf'" < "$STATE/kdc.conf"
    printf '[libdefaults]\n    default_realm = %s\n    dns_lookup_kdc = false\n\n[realms]\n    %s = {\n        kdc = %s\n        admin_server = %s\n        kpasswd_server = %s\n    }\n\n[domain_realm]\n    .%s = %s\n    %s = %s\n' "$R" "$R" "$KDC_HOST" "$KDC_HOST" "$KDC_HOST" "$DOMAIN" "$R" "$DOMAIN" "$R" > "$STATE/krb5.conf"
    check conf.krb5 rc hostin krb5.conf "$LABQ ssh kdc -- 'sudo tee /etc/krb5.conf >/dev/null && sudo restorecon /etc/krb5.conf'" < "$STATE/krb5.conf"
    # The settled aci ACL, written before kadmind starts (admin/admin has all; svc/setup has aci on host/* nfs/*).
    check conf.acl rc hostin kadm5.acl "$LABQ ssh kdc -- 'sudo tee $KD/kadm5.acl >/dev/null && sudo restorecon $KD/kadm5.acl'" \
        <<< "$(printf 'admin/admin@%s\t*\nsvc/setup@%s\taci\thost/*@%s\nsvc/setup@%s\taci\tnfs/*@%s\n' "$R" "$R" "$R" "$R" "$R")"
}
# gp_capture <tag> <principal>...: each principal's getprinc block, graded by name and cp'd for the record.
gp_capture() {
    local tag=$1 p n; shift
    for p in "$@"; do
        n=${p//[\/]/_}
        check "getprinc.$tag.$n" '^Principal: ' run kdc "sudo kadmin.local -q 'getprinc $p'"
        cp "$LAST_OUT" "$STATE/getprinc.$tag.$n"
    done
}
# make_principals: the L2 realm's users (kadmin.local on kdc; passwords on ssh stdin). Services: rust only.
make_principals() {
    local p pe
    check princ.admin 'Principal "admin/admin@'"$R"'" created\.' runin kdc "admin pw" "sudo kadmin.local -q 'addprinc admin/admin'" < <(twice "$ADMIN")
    check princ.svcsetup 'Principal "svc/setup@'"$R"'" created\.' run kdc "sudo kadmin.local -q 'addprinc -randkey svc/setup'"
    check princ.alice 'Principal "alice@'"$R"'" created\.' runin kdc "alice pw" "sudo kadmin.local -q 'addprinc -maxrenewlife 7d alice'" < <(twice "$ALICE")
    check princ.bob 'Principal "bob@'"$R"'" created\.' runin kdc "bob pw" "sudo kadmin.local -q 'addprinc -maxrenewlife 7d bob'" < <(twice "$BOB")
    check princ.krbtgt 'Principal "krbtgt/'"$R"'@'"$R"'" modified\.' run kdc "sudo kadmin.local -q 'modprinc -maxrenewlife 7d krbtgt/$R'"
    [ "$LEG" = rust ] || return 0
    for p in nfs/services.$DOMAIN nfs/services HTTP/services.$DOMAIN host/services.$DOMAIN; do
        pe=${p//./\\.}
        check "princ.svc.${p//[\/.]/_}" "Principal \"$pe@$R\" created\\." run kdc "sudo kadmin.local -q 'addprinc -randkey $p@$R'"
    done
}
# stage_svc_keytab: svc/setup's keytab on client2 via admin/admin's ktadd (rotates it to kvno 2; the keytab is
# made locally on client2, so no key bytes cross the host or land in the record).
stage_svc_keytab() {
    check svc.keytab 'Entry for principal svc/setup@'"$R"' with kvno 2, .*added to keytab' runin client2 "admin pw" \
        "install -d -m 0700 ~/field && kadmin -p admin/admin@$R -q \"ktadd -k \$HOME/field/svc-setup.keytab svc/setup\" 2>&1" < <(once "$ADMIN")
}
# refusals: the eight svc/setup refusals under the settled aci ACL, from client2 (host/aci exists: the aci
# variant made it, and the variant loop ends on aci, so the ACL is aci). Each prints its exit; MIT's exact texts.
refusals() {
    local K="kadmin -p svc/setup@$R -k -t \$HOME/field/svc-setup.keytab -s $KDC_HOST" H="host/aci.$DOMAIN@$R"
    check refuse.add "add_principal: Operation requires .add. privilege while creating \"HTTP/negative\\.$DOMAIN@$R\"\\." run client2 "$K -q 'addprinc -randkey HTTP/negative.$DOMAIN@$R' 2>&1; echo exit=\$?"
    check refuse.ktadd "Operation requires .change-password. privilege while changing alice@$R's key" run client2 "$K -q \"ktadd -k \$HOME/field/x.keytab alice@$R\" 2>&1; echo exit=\$?"
    check refuse.getprinc "get_principal: Operation requires .get. privilege while retrieving \"alice@$R\"\\." run client2 "$K -q 'getprinc alice@$R' 2>&1; echo exit=\$?"
    check refuse.modget "modify_principal: Operation requires .get. privilege while getting \"alice@$R\"\\." run client2 "$K -q 'modprinc -allow_tix alice@$R' 2>&1; echo exit=\$?"
    check refuse.modify "modify_principal: Operation requires .modify. privilege while modifying \"$H\"\\." run client2 "$K -q 'modprinc -maxrenewlife 1d $H' 2>&1; echo exit=\$?"
    check refuse.delete "delete_principal: Operation requires .delete. privilege while deleting principal \"$H\"" run client2 "$K -q 'delprinc -force $H' 2>&1; echo exit=\$?"
    check refuse.list "get_principals: Operation requires .list. privilege while retrieving list\\." run client2 "$K -q 'listprincs' 2>&1; echo exit=\$?"
    check refuse.extract "Operation requires .extract-keys. privilege while changing host/aci\\.$DOMAIN@$R's key" run client2 "$K -q \"ktadd -norandkey -k \$HOME/field/n.keytab $H\" 2>&1; echo exit=\$?"
    check refuse.allowed '^Principal: host/aci\.'"$DOMAIN"'@'"$R"'$' run client2 "$K -q 'getprinc $H' 2>&1"
}
# realm_and_population <leg>: the shared build, from a KDC program already present on kdc, through the population.
realm_and_population() {
    kdcconf "$1"
    check db.create "master key name 'K/M@$R" runin kdc "master pw" "sudo kdb5_util create -s -r $R 2>&1" < <(twice "$MASTER")
    gp_capture boot K/M "krbtgt/$R" kadmin/admin kadmin/changepw
    check kdc.start '^active active$' run kdc "sudo restorecon -Rv $KD >/dev/null 2>&1; sudo systemctl enable --now krb5kdc kadmin && systemctl is-active krb5kdc kadmin | paste -sd' ' -"
    make_principals
    stage_svc_keytab
    gp_capture pop admin/admin svc/setup alice bob "krbtgt/$R"
    local v
    for v in acim acm aim cim aci; do acl_variant "$v" "$v"; done
    refusals
    check client2.listprincs "^svc/setup@$R\$" runin client2 "admin pw" "kadmin -p admin/admin@$R -q listprincs 2>&1" < <(once "$ADMIN")
    check client2.getprinc.alice "^Principal: alice@$R\$" runin client2 "admin pw" "kadmin -p admin/admin@$R -q 'getprinc alice' 2>&1" < <(once "$ADMIN")
}

if [ "$LEG" = mit ]; then
    section "install --leg mit: a fresh Fedora krb5-server realm $R on kdc's base snapshot (the oracle), with L2's population"
    check reset.kdc rc host "$LABQ reset kdc base"
    check reset.client2 rc host "$LABQ reset client2 $MIT_SNAPSHOT_CLIENT2"
    waitsync kdc; waitsync client2
    check mit.install '^krb5-server-' run kdc "sudo dnf install -y krb5-server krb5-workstation > /dev/null 2>&1; rpm -q krb5-server"
    realm_and_population mit
else
    section "install --leg rust: a fresh kerber-rust install from docs/install.md on kdc's base snapshot, with L2's population"
    check reset.kdc rc host "$LABQ reset kdc base"
    check reset.client2 rc host "$LABQ reset client2 $RUST_SNAPSHOT_CLIENT2"
    waitsync kdc; waitsync client2
    WSTART=$(limited "$LAB" ssh kdc -- 'date "+%m/%d/%Y %H:%M:%S"' < /dev/null)
    note "SELinux window start on kdc's clock, local time (ausearch -ts): ${WSTART:-<none: the AVC check fails>}"
    check tree.kdc rc hostin "the ref's archive (tar)" "$LABQ ssh kdc -- 'rm -rf ~/$CO && tar -x -C ~ && find ~/$CO -type f | wc -l'" < "$FIELD_TREE_TAR"
    if [ -n "${INSTALL_DOC:-}" ]; then cp "$INSTALL_DOC" "$STATE/install.md"; note "INSTALL_DOC override (negative control): $INSTALL_DOC"; else tar -xOf "$FIELD_TREE_TAR" "$CO/docs/install.md" > "$STATE/install.md"; fi
    docscript prereq "$STATE/install.md" '## Prerequisites' 1
    docrun prereq
    docscript build "$STATE/install.md" '## Build' 1 --drop '^git clone ' --drop '^cd kerber-rust$' --session "$CARGO_ENV" --session "cd ~/$CO"
    docrun build
    docscript replace "$STATE/install.md" '### Replacing krb5-server' 1 --session "$CARGO_ENV" --session "cd ~/$CO"
    docrun replace
    check install.programs '^programs: [1-9][0-9]* in the manifest, each identical to the build$' runin kdc "lib/install-check.sh" "sh -s -- ~/$CO" < "$FIELD_LIB/install-check.sh"
    realm_and_population rust
    check strings.control rc runin kdc "lib/strings-check.sh" "sh -s -- --control" < "$FIELD_LIB/strings-check.sh"
    check strings.manifest '^programs in /usr/share/kerber-rust/install-manifest: [1-9][0-9]*, all [1-9][0-9]* checked$' runin kdc "lib/strings-check.sh" "sh -s -- --manifest /usr/share/kerber-rust/install-manifest" < "$FIELD_LIB/strings-check.sh"
    AVC="getenforce; d=\$(sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $WSTART 2>&1); r=\$?; [ \"\$r\" = 1 ] || printf '%s\n' \"\$d\"; c=\$(sudo ausearch --input-logs -m USER_CMD -ts $WSTART 2>/dev/null | grep -c '^type=USER_CMD'); printf 'denials: %s (ausearch rc=%s); USER_CMD control: %s records\n' \"\$(printf '%s\n' \"\$d\" | tail -n 1)\" \"\$r\" \"\$c\""
    check selinux.avc '^denials: <no matches> \(ausearch rc=1\); USER_CMD control: [1-9][0-9]* records$' run kdc "$AVC"
    checklast selinux.enforcing '^Enforcing$'
fi
MIN=$(( ($(date +%s) - T0) / 60 + 2 ))
host "COLLECT_MINUTES=$MIN $LABQ collect kdc $(printf '%q' "$REC_DIR/collect") /var/log/krb5kdc.log /var/log/kadmind.log /etc/krb5.conf $KD/kdc.conf $KD/kadm5.acl && COLLECT_MINUTES=$MIN $LABQ collect client2 $(printf '%q' "$REC_DIR/collect") /etc/krb5.conf"
for j in "$REC_DIR"/collect/*/journal.txt; do [ -f "$j" ] && _redact < "$j" > "$j.r" && mv "$j.r" "$j"; done
finish
