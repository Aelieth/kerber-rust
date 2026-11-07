#!/usr/bin/env bash
# harness/field/scenarios/rd-safe.sh --leg mit|rust: rd-sweep's AP-REQ, KRB-PRIV and KRB-SAFE cases on client2, MIT
# first: krb5_rd_req, krb5_rd_priv and krb5_rd_safe (scripts/oracle/rd-priv-oracle.c, built here from the ref against
# the host's libkrb5, the VMs' MIT 1.22.2) answer each case, then ours (rd-sweep judge). Among the cases, each counter
# with a needless leading 00 octet, signed or sealed as sent: MIT takes KRB-SAFE-BODY's seq-number so. Checks: MIT
# answers every case, takes the three pristine ones and that seq-number, and ours answers each case as MIT does. No
# KDC is asked, so both legs run the same cases on client2's own MIT.
# vms: client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: rd-safe.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}" "${FIELD_TREE_TAR:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"

RS="\$HOME/rs"
SW=${FIELD_RDSWEEP:-}
OR=$STATE/rd-priv-oracle
LZ=krb-safe/30.3:a3.0:02/leading-zero
PE="aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96"

cleanup() {
    timeout -k 5 60 "$LAB" ssh client2 -- "rm -rf $RS /tmp/rd-sweep.keytab; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

section "rd-safe --leg $LEG: rd-sweep's cases, MIT's acceptor first, then ours, on client2"
resetvm client2

section "1. rd-sweep (FIELD_RDSWEEP) and MIT's oracle, built from the ref, copied to client2"
check rs.sweep '^rd-sweep: [0-9a-f]{64}$' host "f=$(printf '%q' "$SW"); if [ -n \"\$f\" ] && [ -s \"\$f\" ]; then \
    echo \"rd-sweep: \$(sha256sum < \"\$f\" | cut -c1-64)\"; else echo 'set FIELD_RDSWEEP to the ref'\\''s rd-sweep \
    (cargo build --release -p krb5-tools --bin rd-sweep --features krb5-admin/test-hooks)'; exit 1; fi"
check rs.oracle '^oracle: built [0-9a-f]{64}$' host "grep -q 'Fedora release 43' /etc/fedora-release && rpm -q \
    krb5-devel | grep -Eq '^krb5-devel-1\\.22\\.2-[0-9]+\\.fc43' || { echo 'the host needs Fedora 43 and krb5-devel \
    1.22.2, the VMs'\\'' MIT'; exit 1; }; tar -x -O -f $(printf '%q' "$FIELD_TREE_TAR") --wildcards \
    '*/scripts/oracle/rd-priv-oracle.c' > $(printf '%q' "$OR.c") && cc -O1 -o $(printf '%q' "$OR") $(printf '%q' \
    "$OR.c") \$(krb5-config --cflags krb5) \$(krb5-config --libs krb5) && echo \"oracle: built \$(sha256sum < \
    $(printf '%q' "$OR") | cut -c1-64)\""
check client2.dir rc run client2 "rm -rf $RS; mkdir -m 0700 $RS && { echo '[libdefaults]'; printf '    %s\\n' \
    'default_realm = KERBER.TEST' 'dns_lookup_realm = false' 'dns_lookup_kdc = false' 'rdns = false' \
    'dns_canonicalize_hostname = false' 'permitted_enctypes = $PE'; } > $RS/krb5.conf"
for b in "rd-sweep:$SW" "rd-priv-oracle:$OR"; do
    check "client2.${b%%:*}" '^client2: [0-9a-f]{64}$' host "cat $(printf '%q' "${b#*:}") | $LABQ ssh client2 -- \
        'cat > $RS/${b%%:*} && chmod 0755 $RS/${b%%:*} && echo \"client2: \$(sha256sum < $RS/${b%%:*} | cut -c1-64)\"'"
done
check client2.libkrb5 '^ldd: 0 not found, krb5-libs-1\.22\.2-' run client2 "echo \"ldd: \$(ldd $RS/rd-priv-oracle \
    | grep -c 'not found') not found, \$(rpm -q krb5-libs)\""
if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then
    note "a setup check failed: the leg stops here"
    finish
    exit 1
fi

section "2. the cases, MIT's answers (the nightly gate container's libdefaults), ours against them"
check RS.cases '^cases: [1-9][0-9]*$' run client2 "$RS/rd-sweep cases > $RS/cases.tsv && echo \"cases: \$(grep -vc \
    '^#' $RS/cases.tsv)\""
N=$(sed -n 's/^cases: \([0-9]*\)$/\1/p' "$LAST_OUT")
check RS.mit "^mit answered ${N:-none} of ${N:-none}\$" run client2 "KRB5_CONFIG=$RS/krb5.conf KRB5RCACHETYPE=none \
    $RS/rd-priv-oracle < $RS/cases.tsv > $RS/mit.tsv; echo \"mit answered \$(wc -l < $RS/mit.tsv) of ${N:-none}\""
check RS.pristine '^pristine accepted: 3$' run client2 "echo \"pristine accepted: \$(awk -F'\\t' '\$1 ~ \
    /^(ap-req|krb-priv|krb-safe)\\/pristine\$/ && \$2 == \"0\"' $RS/mit.tsv | wc -l)\""
check RS.lz.mit '^mit: 0$' run client2 "awk -F'\\t' '\$1 == \"$LZ\" { print \"mit: \" \$2 }' $RS/mit.tsv"
observe RS.lz.all '^leading-zero: .*' run client2 "echo \"leading-zero: \$(grep leading-zero $RS/mit.tsv | tr '\\t' \
    '=' | paste -sd' ' -)\""
observe RS.accepts '^accepts: [0-9]+' run client2 "echo \"accepts: \$(awk -F'\\t' '\$2 == \"0\"' $RS/mit.tsv | wc \
    -l)\""
check RS.judge "^0 of ${N:-none} cases part from MIT\$" run client2 "KRB5_CONFIG=$RS/krb5.conf $RS/rd-sweep judge \
    $RS/cases.tsv $RS/mit.tsv > $RS/judge.txt; rc=\$?; grep -m 20 '^PART' $RS/judge.txt; tail -n 1 $RS/judge.txt; \
    exit \$rc"
check RS.lz.ours '^ours: SAME$' run client2 "awk -F'\\t' '\$2 == \"$LZ\" { print \"ours: \" \$1 }' $RS/judge.txt"

finish
