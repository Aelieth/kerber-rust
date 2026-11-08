#!/bin/bash
# Re-hash the 13 ship binaries against this sha's step 1 file.
# Usage: ship-guard.sh SHA REC
# Needs HAND_WT and HAND_REC (HAND_SHIP overrides the build dir).
# Writes REC/ship-guard.sha256 and exits 2 if any name is missing or differs.
# Step 1's file is HAND_REC/SHA/step1/ship.sha256. The 806c20f1 baseline is what
# step 1 compares against; a later sha is expected to differ from that baseline
# and must still match its own step 1 file. This does not start the lab.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
require_env HAND_WT HAND_REC
SHA=${1:?sha}
REC=${2:?record}
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "SHIP_GUARD_STOP sha"; exit 2; }
BASE=$HAND_REC/$SHA/step1/ship.sha256
REL=${HAND_SHIP:-$HAND_WT/target-rp/release}
names='krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd krb5-kinit krb5-klist krb5-kdestroy krb5-kswitch krb5-kvno krb5-kpasswd krb5-ktutil'
[ -f "$BASE" ] || { echo "SHIP_GUARD_STOP no step1 file"; exit 2; }
mkdir -p "$REC"
: > "$REC/ship-guard.sha256"
diff=no
for name in $names; do
    if [ ! -x "$REL/$name" ]; then
        echo "SHIP_GUARD_MISSING $name"
        diff=yes
        continue
    fi
    newhash=$(sha256sum "$REL/$name" | awk 'NR==1 {print $1}')
    printf '%s  %s\n' "$newhash" "$name" >> "$REC/ship-guard.sha256"
    oldhash=$(awk -v n="$name" '$2==n {print $1; exit}' "$BASE")
    if [ -z "$oldhash" ] || [ "$newhash" != "$oldhash" ]; then
        echo "SHIP_GUARD_DIFF $name"
        diff=yes
    fi
done
if [ "$diff" = yes ]; then
    echo "SHIP_GUARD:fail"
    exit 2
fi
echo "SHIP_GUARD:ok"
