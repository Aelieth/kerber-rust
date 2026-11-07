#!/bin/bash
# CM, the client matrix. Arguments: the landed sha, then the suite, cm (the
# default) or hm:
#   cm  stock MIT clients and SSSD on client2 (Fedora 44), rocky10, deb13 and
#       ub26; cells 1-8 under FILE: and KCM:, cell 9 once per client
#   hm  Debian 13's Heimdal client tools on deb13; cells 1-5 under FILE:
# Against the lab KDC: MIT's leg, then ours. Each leg resets kdc to
# MIT_SNAPSHOT_KDC and runs the same setup with MIT's kadmin.local, so both
# KDCs serve the same database; ours' leg then moves the realm by the README
# route. lib/cm-cells.sh runs the cells; lib/cm-grade.py grades ours against MIT.
# Does not fetch, and installs only the clients' stock packages, before the
# first leg.
set -u
set +x
umask 077
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
. "$HDIR/lib/cm-host.sh"
require_env HAND_WT HAND_REC HAND_RELEASE_TAG
P=CM
TAG_RX=${HAND_RELEASE_TAG//./\\.}
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap drop_sec EXIT
TMPDIR=$SEC
export TMPDIR

SHA=${1:?landed sha}
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "CM_STOP sha"; exit 2; }
SUITE=${2:-cm}
case $SUITE in
    cm) TAGS=(f44 rocky deb ub) PREP_MODE=prep RUN_MODE=run ;;
    hm) TAGS=(hm) PREP_MODE=prep-hm RUN_MODE=run-hm ;;
    *) echo "CM_STOP suite"; exit 2 ;;
esac

WT=$HAND_WT
REC=$HAND_REC/$SHA/$SUITE
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
DOC=$WT/harness/field/lib/docblocks.py
SCAN=$WT/harness/field/lib/scan-secrets.py
PTY=$WT/harness/field/lib/ptydrive.py
CELLS=$HDIR/lib/cm-cells.sh
GRADE=$HDIR/lib/cm-grade.py
SECRETS=$LAB_HOME/secrets
TREE_TAR=$TMPDIR/kr-cm-tree.tar
CAP_MIB=$((32 * 1024))
GUEST_TMO=1800
REALM=KERBER.TEST
H_USE='## Download, install and use'
H_MOVE='## Move an MIT realm over'

vm_for() {
    case $1 in
        f44) echo client2 ;;
        rocky) echo rocky10 ;;
        deb | hm) echo deb13 ;;
        ub) echo ub26 ;;
    esac
}
snap_for() {
    case $1 in
        f44) echo f44-base ;;
        rocky) echo client ;;
        deb | hm) echo krb5 ;;
        ub) echo base ;;
    esac
}
VMS=(kdc)
for t in "${TAGS[@]}"; do VMS+=("$(vm_for "$t")"); done

trap 'rm -f "$TREE_TAR"; park; drop_sec' EXIT

push_keytabs() {
    local t
    for t in "${TAGS[@]}"; do
        "$LAB" ssh kdc -- "cat ~/field/cm-kt/$t.keytab" < /dev/null > "$SEC/kt-$t.keytab" 2> /dev/null || return 1
        [ -s "$SEC/kt-$t.keytab" ] || return 1
        "$LAB" ssh "$(vm_for "$t")" -- 'cat > ~/field/cm.keytab && chmod 0600 ~/field/cm.keytab' < "$SEC/kt-$t.keytab" || return 1
        rm -f "$SEC/kt-$t.keytab"
    done
}

prep_client() {
    local tag=$1 vm
    vm=$(vm_for "$tag")
    stage "$vm" || { echo "STAGE_FAIL:$tag" > "$REC/prep-$tag.status"; return; }
    timeout -k 30 "$GUEST_TMO" "$LAB" ssh "$vm" -- "bash ~/field/cm-cells.sh $PREP_MODE $tag" < /dev/null > "$REC/prep-$tag.out" 2>&1
    if grep -qx "PREP_OK:$tag" "$REC/prep-$tag.out"; then
        echo "PREP:$tag:ok" > "$REC/prep-$tag.status"
    else
        echo "PREP:$tag:fail" > "$REC/prep-$tag.status"
    fi
}

run_client() {
    local leg=$1 tag=$2 vm dir rc
    vm=$(vm_for "$tag")
    dir=$REC/$leg/$tag
    mkdir -p "$dir"
    secrets_for "pw-$tag|cmu-$tag|k9-$tag|(chpw|chpw2|exp|pwexp|pwexp2|lock|wrong)-$tag-|admin" |
        timeout -k 30 "$GUEST_TMO" "$LAB" ssh "$vm" -- "bash ~/field/cm-cells.sh $RUN_MODE $leg $tag" > "$dir/run.out" 2>&1
    rc=$?
    timeout -k 30 300 "$LAB" ssh "$vm" -- 'tar -C ~/field/out -cf - .' < /dev/null | tar -x -C "$dir"
    echo "RUN_RC:$leg:$tag:$rc:${PIPESTATUS[0]}:${PIPESTATUS[1]}" > "$dir/host.status"
}

run_leg() {
    local leg=$1 t
    for t in "${TAGS[@]}"; do
        run_client "$leg" "$t" &
    done
    wait
    for t in "${TAGS[@]}"; do
        cat "$REC/$leg/$t/host.status"
        grep -qx "RUN_DONE:$leg:$t" "$REC/$leg/$t/run.out" || return 1
    done
}

# --- gates that do not touch a VM ---
host_gates "$CELLS" "$GRADE" "$PTY" "$HDIR/lib/cm-host.sh"

mkdir -p "$REC/move" "$REC/mit" "$REC/ours"
chmod 700 "$REC"
make_secrets
check_secrets

echo "==== resets ===="
reset_vm kdc "$MIT_SNAPSHOT_KDC" || stop "reset kdc"
for t in "${TAGS[@]}"; do
    reset_vm "$(vm_for "$t")" "$(snap_for "$t")" || stop "reset $t"
done
for vm in "${VMS[@]}"; do
    wait_ntp "$vm" || stop "ntp $vm"
done

echo "==== clients: stock packages, local user, PAM ===="
for t in "${TAGS[@]}"; do
    prep_client "$t" &
done
wait
for t in "${TAGS[@]}"; do
    cat "$REC/prep-$t.status"
    grep -qx "PREP:$t:ok" "$REC/prep-$t.status" || stop "prep $t"
done

for leg in mit ours; do
    echo "==== $leg leg ===="
    if [ "$leg" = ours ]; then
        reset_vm kdc "$MIT_SNAPSHOT_KDC" || stop "reset kdc"
        wait_ntp kdc || stop "ntp kdc"
    fi
    wait_units || fail "ORACLE_FAIL:kdc-units:$leg"
    prove_mit "$leg" || fail "ORACLE_FAIL:kdc-prove:$leg"
    kdc_setup "$leg" || fail "SETUP_FAIL:$leg"
    if [ "$leg" = ours ]; then
        move || fail "MOVE_FAIL"
        prove_ours || fail "OURS_PROVE:no"
    fi
    for vm in "${VMS[@]}"; do
        wait_ntp "$vm" || stop "ntp $vm"
    done
    run_leg "$leg" || fail "RUN_FAIL:$leg"
    if [ "$leg" = mit ]; then
        python3 -B "$GRADE" oracle "$REC" "${TAGS[@]}" || fail "ORACLE_FAIL:cells"
    fi
done

echo "==== grade ===="
python3 -B "$GRADE" grade "$REC" "${TAGS[@]}"
grade_rc=$?
if scans && [ "$grade_rc" = 0 ]; then
    echo "CM_PASS:yes"
else
    echo "CM_PASS:no"
fi
echo "CM_DONE"
exit 0
