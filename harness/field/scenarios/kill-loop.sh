#!/usr/bin/env bash
# harness/field/scenarios/kill-loop.sh --leg rust: SW-3's crash proof (plan-SW) on the database of the KDC upgrade.sh
# left on kdc, judged by MIT's own tools on kdc2 (krb5-server as packaged, $MIT_SNAPSHOT_KDC2):
#   KL.loop: lib/kill-loop.py drive runs kadmin.local -q on kl000..kl099 (addprinc, modprinc -maxlife, cpw -randkey,
#            delprinc), at least 1,000 ops, and kills at least 200 with SIGKILL: at a random time, once the database
#            file changes, at least 50 while a compaction's .principal.tmp-* is there, and once a compaction's rename
#            lands. After each kill an op not acknowledged shows all of its change or none, and kdb5_util dump writes
#            a dump. The first whole write that completes after a kill left a compaction's temp file leaves none
#            (KL.tmp-clean).
#   KL.mit: every dump loads with MIT's kdb5_util load, and MIT's getprinc and listprincs give what the acknowledged
#           ops left, the realm's other principals unchanged.
# The rust leg only: MIT is the judge. kdc2 must be up for the run's preflight (lab.sh up kdc2); this scenario resets
# it at the start and the end, then parks it.
# vms: kdc kdc2
# legs: rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg rust") LEG=$2 ;;
    *) echo "usage: kill-loop.sh --leg rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
W=/var/tmp/kl
cleanup() {
    timeout -k 5 300 "$LAB" ssh kdc -- "for p in \$(sudo kadmin.local -q listprincs 2>/dev/null | grep -E '^kl[0-9]{3}@'); do sudo kadmin.local -q \"delprinc -force \$p\" > /dev/null 2>&1; done; sudo find /var/kerberos/krb5kdc -maxdepth 1 -name '.principal.tmp-*' -delete; sudo rm -rf $W ~/kill-loop.py; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 300 "$LAB" reset kdc2 "$MIT_SNAPSHOT_KDC2" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" down kdc2 < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

section "kill-loop --leg rust: kadmin.local killed on kdc, every kill judged by MIT's tools on kdc2"
kdcis
check reset.kdc2 rc host "$LABQ reset kdc2 $MIT_SNAPSHOT_KDC2"
waitsync kdc2
check kdc2.mit '^kdc2: MIT krb5-server-[0-9].*, binaries as packaged, python 3' run kdc2 \
    "sudo rpm -V krb5-server krb5-libs | grep -E ' /usr/(s?bin|lib64)/'; ! sudo rpm -V krb5-server | grep -qE '^..5.* /usr/sbin/(kdb5_util|kadmin\\.local)\$' && echo \"kdc2: MIT \$(rpm -q krb5-server), binaries as packaged, \$(python3 -V | tr P p)\""
check kdc2.stash '^stash copied$' host "$LABQ ssh kdc -- 'sudo cat /var/kerberos/krb5kdc/.k5.$REALM' | $LABQ ssh kdc2 -- 'sudo install -d -m 0700 $W && sudo install -m 0600 /dev/stdin $W/stash && echo stash copied'"
for vm in kdc kdc2; do
    check "$vm.driver" rc runin "$vm" "lib/kill-loop.py" "cat > ~/kill-loop.py" < "$FIELD_LIB/kill-loop.py"
done
if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then
    note "a setup check failed: the leg stops here, before any write to kdc's database"
    finish
    exit 1
fi

section "KL.loop: the ops and their kills on kdc, kerber-rust's kadmin.local and kdb5_util"
check KL.unexpected '^unexpected: 0$' run kdc "sudo rm -rf $W && sudo install -d -m 0700 $W && sudo python3 -u ~/kill-loop.py drive --realm $REALM --dir $W"
checklast KL.ops '^ops: [1-9][0-9]{3,} attempted'
checklast KL.kills '^kills: ([2-9][0-9]{2}|[1-9][0-9]{3,})$'
checklast KL.compaction '^compaction kills: ([5-9][0-9]|[1-9][0-9]{2,}) '
checklast KL.spread '^kills by mode: time ([4-9][0-9]|[1-9][0-9]{2,}), grow ([4-9][0-9]|[1-9][0-9]{2,}), compaction [1-9][0-9]*, renamed ([3-9]|[1-9][0-9]+)$'
checklast KL.tmp-clean '^stale temps after the next whole write: 0 \(checked [1-9][0-9]* times\)$'
observelast KL.database '^the database after a kill: .*'
observelast KL.doubt '^in doubt: .*'
observelast KL.stale '^stale temp files: .*'
N=$(sed -n 's/^dumps: \([0-9][0-9]*\) .*/\1/p' "$LAST_OUT")
check KL.daemons '^krb5kdc active, kadmin active$' run kdc "printf 'krb5kdc %s, kadmin %s\\n' \$(systemctl is-active krb5kdc kadmin)"

section "KL.mit: each dump through MIT's kdb5_util load, then MIT's listprincs and getprinc, on kdc2"
check KL.copy "^dumps on kdc2: ${N:-none}\$" host "$LABQ ssh kdc -- 'sudo tar -C $W -c dumps expect.jsonl base.txt' | $LABQ ssh kdc2 -- 'sudo tar -C $W -x && echo \"dumps on kdc2: \$(sudo find $W/dumps -name \"*.dump\" | wc -l)\"'"
check KL.mit.match "^matched: ${N:-none} of ${N:-none}\$" run kdc2 "sudo python3 -u ~/kill-loop.py judge --realm $REALM --dir $W"
checklast KL.mit.load "^loaded: ${N:-none} of ${N:-none}\$"
finish
