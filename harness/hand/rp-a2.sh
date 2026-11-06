#!/bin/bash
# Cell A2, MIT leg only. Passwords stay in the secret file.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/al-a2
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
echo $$ > "$REC/driver.pid"
exec 9>&-
LAB=$WT/harness/field/lab.sh
mkdir -p "$REC"
echo "REC:$REC"
lab() { bash "$LAB" "$@"; }
HERE=$(dirname "$LAB")
if command -v virsh >/dev/null 2>&1; then
    vsh() { virsh -c qemu:///system "$@"; }
else
    vsh() { (cd "$HERE" && distrobox-host-exec virsh -c qemu:///system "$@"); }
fi
echo "KDC_BEFORE:$(vsh snapshot-current kerber-kdc --name 2>/dev/null || echo unknown)"
echo "C2_BEFORE:$(vsh snapshot-current kerber-client2 --name 2>/dev/null || echo unknown)"
SECRET=$LAB_HOME/secrets/mit-realm.bob.password
if [ ! -f "$SECRET" ]; then
    echo "NO_SECRET"
    echo "A2_END"
    exit 1
fi
kdc_now=$(vsh snapshot-current kerber-kdc --name 2>/dev/null || true)
c2_now=$(vsh snapshot-current kerber-client2 --name 2>/dev/null || true)
if [ "$kdc_now" = "f4-mit-f44" ] && [ "$c2_now" = "mit-kit-fc44" ]; then
    echo "RESET_SKIPPED"
else
    echo "==== reset MIT ===="
    lab reset kdc f4-mit-f44
    echo "RESET_KDC:$?"
    lab reset client2 mit-kit-fc44
    echo "RESET_C2:$?"
fi
kadmin_q() {
    lab ssh kdc -- "sudo kadmin.local -q $(printf '%q' "$1")"
}
echo "==== A2 mit ===="
kadmin_q "delpol -force dictpol" >/dev/null || true
kadmin_q "addpol dictpol"
echo "ADDPOL_RC:$?"
kadmin_q "modprinc -policy dictpol bob"
echo "MODPRINC_RC:$?"
kadmin_q "getprinc bob" | grep -E '^(Principal:|Policy:)' || true
dict=$(lab ssh kdc -- "sudo awk -F= '/dict_file/ && \$0 !~ /^[[:space:]]*#/ {gsub(/[[:space:]\"]/,\"\",\$2); print \$2; exit}' /var/kerberos/krb5kdc/kdc.conf" | tr -d '\r' | awk 'NF{p=$0} END{print p}')
echo "DICT:${dict:-missing}"
if [ -z "$dict" ]; then
    echo "NO_DICT"
    echo "A2_END"
    exit 1
fi
word=$(lab ssh kdc -- "sudo awk 'NF && \$1 !~ /^#/ { print; exit }' $(printf '%q' "$dict")" | tr -d '\r\n')
echo "WORD_LEN:${#word}"
if [ -z "$word" ]; then
    echo "NO_WORD"
    echo "A2_END"
    exit 1
fi
old=$(tr -d '\r\n' < "$SECRET")
out=$(timeout 90 bash "$LAB" ssh client2 -- kpasswd bob <<EOF
$old
$word
$word
EOF
)
rc=$?
echo "KPASSWD_RC:$rc"
OLD="$old" WORD="$word" python3 -c '
import os, sys
text = sys.stdin.read()
old = os.environ.get("OLD", "")
word = os.environ.get("WORD", "")
if old:
    text = text.replace(old, "[REDACTED]")
if word:
    text = text.replace(word, "[REDACTED]")
for line in text.splitlines():
    low = line.lower()
    if "key:" in low or "session key" in low:
        continue
    print(line[:200])
' <<<"$out"
if printf '%s\n' "$out" | grep -q 'Password changed'; then
    echo "CHANGED:1"
else
    echo "CHANGED:0"
fi
kadmin_q "modprinc -clearpolicy bob" >/dev/null || true
kadmin_q "delpol -force dictpol" >/dev/null || true
kadmin_q "getprinc bob" | grep -E '^(Principal:|Policy:)' || true
echo "A2_END"
exit 0
