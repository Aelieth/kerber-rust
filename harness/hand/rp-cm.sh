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
require_env HAND_WT HAND_REC HAND_RELEASE_TAG
TAG_RX=${HAND_RELEASE_TAG//./\\.}
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
drop_sec() {
    find "$SEC" -type f -exec shred -u {} + 2>/dev/null
    rm -rf "$SEC"
}
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

booted=0
move_pass=no

stop() { echo "CM_STOP $*"; exit 2; }
# Both scans over the record; rc 0 when neither finds a value.
scans() {
    local scan_rc gen_rc
    python3 -B "$SCAN" "$REC"
    scan_rc=$?
    echo "SECRET_SCAN:$scan_rc"
    python3 -B "$GRADE" scan "$REC" "$SEC/all.tsv"
    gen_rc=$?
    echo "CM_SECRET_SCAN:$gen_rc"
    [ "$scan_rc" = 0 ] && [ "$gen_rc" = 0 ]
}
fail() {
    echo "$1"
    scans
    echo "CM_PASS:no"
    echo "CM_DONE"
    exit 0
}

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

vsh() {
    if command -v virsh >/dev/null 2>&1; then
        virsh -q -c qemu:///system "$@"
    else
        (cd "$HERE" && distrobox-host-exec virsh -q -c qemu:///system "$@")
    fi
}
domstate() { vsh domstate "$1" 2>/dev/null || echo missing; }

park() {
    local vm rc
    [ "$booted" = 1 ] || return 0
    booted=0
    for vm in client2 rocky10 deb13 ub26 kdc; do
        [ -f "$REC/booted-$vm" ] || continue
        "$LAB" down "$vm" > "$REC/down-$vm.out" 2>&1
        rc=$?
        echo "DOWN_RC:$vm:$rc"
    done
}
trap 'rm -f "$TREE_TAR"; park; drop_sec' EXIT

extract() {
    local dest=$1 rc
    shift
    python3 -B "$DOC" script "$WT/README.md" "$@" > "$dest"
    rc=$?
    echo "EXTRACT:$(basename "$dest"):$rc"
    return "$rc"
}

grade_block() {
    local tag=$1 line n rc rest
    local out=$REC/move/$tag.out
    local res=$REC/move/$tag.results
    if [ ! -s "$out" ]; then
        echo "UNIT_FAIL:$tag:no-output"
        move_pass=no
        return 0
    fi
    if ! python3 -B "$DOC" results "$out" > "$res"; then
        echo "UNIT_FAIL:$tag:results"
        move_pass=no
        return 0
    fi
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        echo "UNIT_RESULT:$tag:$line"
        n=${line%%$'\t'*}
        rest=${line#*$'\t'}
        rc=${rest%%$'\t'*}
        rest=${rest#*$'\t'}
        rest=${rest#*$'\t'}
        if [ "$rc" != 0 ]; then
            echo "UNIT_FAIL:$tag:$n:$rest"
            move_pass=no
        fi
    done < "$res"
}

unit_rc() {
    awk -v cmd="$2" '
        /^\$ / { c = substr($0, 3); sub(/    # .*/, "", c); on = (c == cmd) }
        /^@@ unit [0-9]+ rc=/ && on { split($0, a, "="); print a[2]; exit }
    ' "$1"
}

run_block() {
    local tag=$1 rc
    "$LAB" ssh kdc -- 'install -d -m 0700 ~/field && cat > ~/field/block.sh' < "$REC/move/$tag.sh" > "$REC/move/$tag.copy" 2>&1 || return 1
    "$LAB" ssh kdc -- 'bash ~/field/block.sh' < /dev/null > "$REC/move/$tag.out" 2>&1
    rc=$?
    echo "BLOCK_RC:$tag:$rc"
    return "$rc"
}

put_tree() {
    local rc
    echo "STANDIN:git-clone"
    echo "STANDIN_SAYS:git clone --branch $HAND_RELEASE_TAG is replaced; the tag is not required"
    echo "STANDIN_ROUTE:git archive --prefix=kerber-rust/ $SHA"
    GIT_OPTIONAL_LOCKS=0 git -C "$WT" archive --format=tar --prefix=kerber-rust/ "$SHA" > "$TREE_TAR" || { rm -f "$TREE_TAR"; return 1; }
    "$LAB" ssh kdc -- 'rm -rf ~/kerber-rust && tar -x -C ~ && find ~/kerber-rust -type f | wc -l' < "$TREE_TAR" > "$REC/move/tree-count.out" 2>&1
    rc=$?
    rm -f "$TREE_TAR"
    echo "TREE_ON_KDC_RC:$rc"
    echo "TREE_ON_KDC:$(tr -d '[:space:]' < "$REC/move/tree-count.out")"
    return "$rc"
}

reset_vm() {
    local vm=$1 snap=$2 rc
    echo "RESET:$vm:$snap"
    touch "$REC/booted-$vm"
    booted=1
    "$LAB" reset "$vm" "$snap" > "$REC/reset-$vm.out" 2>&1
    rc=$?
    echo "RESET_RC:$vm:$rc"
    return "$rc"
}

wait_ntp() {
    local vm=$1 i=0 val
    while [ "$i" -lt 90 ]; do
        "$LAB" ssh "$vm" -- 'timedatectl show -p NTPSynchronized --value' > "$REC/ntp-$vm.out" 2>&1 || true
        val=$(head -n 1 "$REC/ntp-$vm.out" | tr -d '[:space:]')
        if [ "$val" = yes ]; then
            echo "NTP:$vm:yes"
            return 0
        fi
        sleep 2
        i=$((i + 1))
    done
    echo "NTP:$vm:${val:-missing}"
    return 1
}

wait_units() {
    local i=0 n
    while [ "$i" -lt 30 ]; do
        "$LAB" ssh kdc -- 'systemctl is-active krb5kdc; echo ---; systemctl is-active kadmin' > "$REC/kdc-active.out" 2>&1 || true
        n=$(grep -c '^active$' "$REC/kdc-active.out" || true)
        if [ "${n:-0}" = 2 ]; then
            echo "KDC_UNITS:active"
            return 0
        fi
        sleep 2
        i=$((i + 1))
    done
    echo "KDC_UNITS:not-active"
    return 1
}

prove_mit() {
    "$LAB" ssh kdc -- 'rpm -qf /usr/sbin/krb5kdc; rpm -q krb5-server' > "$REC/$1/kdc-prove-mit.out" 2>&1
    local rc=$?
    echo "KDC_PROVE_MIT_RC:$rc"
    echo "KDC_MIT_VERSION:$(grep -m1 '^krb5-server-' "$REC/$1/kdc-prove-mit.out")"
    if [ "$rc" = 0 ] && grep -q '^krb5-server-1\.22\.2-' "$REC/$1/kdc-prove-mit.out"; then
        echo "KDC_PROVE:mit:krb5-server"
        return 0
    fi
    echo "KDC_PROVE:mit:no"
    return 1
}

prove_ours() {
    # Cells 7 and 9 talk to kadmind, so that binary is held
    # to the same rule: no package owns it, and its sha256 is the guest build.
    "$LAB" ssh kdc -- 'rpm -qf /usr/sbin/krb5kdc; echo RC:$?; sha256sum /usr/sbin/krb5kdc ~/kerber-rust/target/release/krb5-kdc; echo ---; rpm -qf /usr/sbin/kadmind; echo KADMIND_RC:$?; sha256sum /usr/sbin/kadmind ~/kerber-rust/target/release/krb5-kadmind' > "$REC/move/kdc-prove-our.out" 2>&1
    local rc=$?
    echo "KDC_PROVE_OUR_SSH:$rc"
    python3 -B - "$REC/move/kdc-prove-our.out" << 'PY'
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace").splitlines()

def hashes(suffixes):
    out = []
    for line in text:
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64 and parts[1].endswith(suffixes):
            out.append(parts[0])
    return out

kdc_lines = hashes(("krb5kdc", "krb5-kdc"))
kad = hashes(("kadmind", "krb5-kadmind"))
owned = any(ln.startswith("RC:0") for ln in text)
kadmin_owned = any(ln.startswith("KADMIND_RC:0") for ln in text)
ok = (
    not owned
    and not kadmin_owned
    and len(kdc_lines) == 2
    and kdc_lines[0] == kdc_lines[1]
    and len(kad) == 2
    and kad[0] == kad[1]
)
print("OURS_KDC_SHA:%s" % (kdc_lines[0] if kdc_lines else "missing"))
print("OURS_KADMIND_SHA:%s" % (kad[0] if kad else "missing"))
print("OURS_PROVE:%s" % ("yes" if ok else "no"))
sys.exit(0 if ok else 1)
PY
}

# One random password per name, in $SEC/all.tsv; admin's from the lab secrets.
make_secrets() {
    python3 -B - "$SEC/all.tsv" "${TAGS[@]}" << 'PY'
import secrets, sys
from pathlib import Path
names = []
for t in sys.argv[2:]:
    names += ["pw-" + t, "kt-" + t, "cmu-" + t, "k9-" + t]
    for c in ("file", "kcm"):
        names += [p + "-" + t + "-" + c for p in ("chpw", "chpw2", "exp", "pwexp", "pwexp2", "lock", "wrong")]
Path(sys.argv[1]).write_text("".join("%s\t%s\n" % (n, secrets.token_urlsafe(18)) for n in names))
PY
    printf 'admin\t%s\n' "$(< "$SECRETS/$MIT_SECRET_ADMIN")" >> "$SEC/all.tsv"
}
secrets_for() { grep -E "^($1)" "$SEC/all.tsv"; }

stage() {
    local vm=$1
    "$LAB" ssh "$vm" -- 'install -d -m 0700 ~/field && cat > ~/field/cm-cells.sh' < "$CELLS" &&
        "$LAB" ssh "$vm" -- 'cat > ~/field/ptydrive.py && chmod 0700 ~/field/ptydrive.py' < "$PTY"
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

kdc_setup() {
    local leg=$1 t n
    stage kdc || return 1
    secrets_for 'pw-|kt-|cmu-|chpw-|exp-|pwexp-|lock-' | timeout -k 30 "$GUEST_TMO" "$LAB" ssh kdc -- "bash ~/field/cm-cells.sh kdc-setup ${TAGS[*]}" > "$REC/$leg/setup.out" 2>&1
    echo "SETUP_RC:$leg:$?"
    n=$(sed -n 's/^SETUP_CREATED://p' "$REC/$leg/setup.out")
    echo "SETUP_CREATED:$leg:${n:-none}"
    [ "${n:-0}" = $((1 + 11 * ${#TAGS[@]})) ] || return 1
    grep -qx "host/cm.kerber.test@$REALM" "$REC/$leg/setup.out" || return 1
    grep -qx "KEYTABS:${#TAGS[@]}" "$REC/$leg/setup.out" || return 1
    for t in "${TAGS[@]}"; do
        "$LAB" ssh kdc -- "cat ~/field/cm-kt/$t.keytab" < /dev/null > "$SEC/kt-$t.keytab" 2> /dev/null || return 1
        [ -s "$SEC/kt-$t.keytab" ] || return 1
        "$LAB" ssh "$(vm_for "$t")" -- 'cat > ~/field/cm.keytab && chmod 0600 ~/field/cm.keytab' < "$SEC/kt-$t.keytab" || return 1
        rm -f "$SEC/kt-$t.keytab"
    done
    "$LAB" ssh kdc -- 'sudo kadmin.local -q listprincs' < /dev/null > "$REC/$leg/listprincs.before" 2>&1
    echo "LISTPRINCS_BEFORE_RC:$leg:$?"
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

move() {
    move_pass=yes
    put_tree || move_pass=no
    if [ "$move_pass" = yes ] && extract "$REC/move/move-build.sh" "$H_USE" 1 --session "cd \"\$HOME\"" --drop "^git clone --branch $TAG_RX "; then
        run_block move-build || move_pass=no
        grade_block move-build
        mrc=$(unit_rc "$REC/move/move-build.out" "make build" || true)
        echo "MOVE_MAKE_BUILD_RC:${mrc:-missing}"
        [ "$mrc" = 0 ] || move_pass=no
    else
        move_pass=no
    fi
    if [ "$move_pass" = yes ] && extract "$REC/move/move.sh" "$H_MOVE" 1 --session "cd \"\$HOME/kerber-rust\""; then
        run_block move || move_pass=no
        grade_block move
    else
        move_pass=no
    fi
    if [ "$move_pass" = yes ]; then
        "$LAB" ssh kdc -- 'sudo kadmin.local -q listprincs' < /dev/null > "$REC/ours/listprincs.after" 2>&1
        echo "LISTPRINCS_AFTER_RC:$?"
        grep -E '^[^[:space:]]+@[^[:space:]]+$' "$REC/ours/listprincs.before" | LC_ALL=C sort > "$REC/ours/listprincs.before.names" || true
        grep -E '^[^[:space:]]+@[^[:space:]]+$' "$REC/ours/listprincs.after" | LC_ALL=C sort > "$REC/ours/listprincs.after.names" || true
        if [ ! -s "$REC/ours/listprincs.before.names" ] || ! diff -q "$REC/ours/listprincs.before.names" "$REC/ours/listprincs.after.names" > /dev/null; then
            echo "LISTPRINCS:differ"
            move_pass=no
        else
            echo "LISTPRINCS:same"
        fi
        wait_units || move_pass=no
    fi
    echo "MOVE_PASS:$move_pass"
    [ "$move_pass" = yes ]
}

# --- gates that do not touch a VM ---
[ -e "$REC" ] && stop "exists $REC"
for f in "$CELLS" "$GRADE" "$PTY" "$DOC" "$SCAN"; do
    [ -f "$f" ] || stop "missing $f"
done
if ! git -C "$WT" diff --quiet --ignore-submodules -- || ! git -C "$WT" diff --cached --quiet --ignore-submodules --; then
    stop dirty
fi
if [ "$(git -C "$WT" rev-parse HEAD)" != "$SHA" ]; then
    git -C "$WT" checkout --detach "$SHA" || stop checkout
fi
got=$(git -C "$WT" rev-parse HEAD)
echo "SUITE:$SUITE"
echo "HEAD:$got"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
[ "$got" = "$SHA" ] || stop head
# shellcheck source=../field/baseline.env
. "$WT/harness/field/baseline.env"
echo "SNAP_KDC:${MIT_SNAPSHOT_KDC:-}"
[ "${MIT_REALM:-}" = "$REALM" ] || stop "MIT_REALM"
[ -n "${MIT_SNAPSHOT_KDC:-}" ] || stop "MIT_SNAPSHOT_KDC"
[ -f "$SECRETS/${MIT_SECRET_ADMIN:-}" ] || stop "secret-file admin"
echo "SECRET_FILE:admin:${MIT_SECRET_ADMIN}"
for f in "$CELLS" "$GRADE" "$PTY"; do
    echo "SCRIPT_SHA:$(basename "$f"):$(sha256sum "$f" | awk '{print $1}')"
done

exec 8>>"$LAB_HOME/state/lab.lock"
if ! flock -n 8; then
    exec 8>&-
    stop lock
fi
flock -u 8
exec 8>&-

sum=0
for name in kdc services client1 client2 klldap mitd3 ub26 deb13 rocky10 kdc2 win; do
    dom=kerber-$name
    st=$(domstate "$dom")
    echo "VM $name $st"
    add=no
    case " ${VMS[*]} " in
        *" $name "*) add=yes ;;
    esac
    [ "$st" = running ] && add=yes
    [ "$add" = yes ] || continue
    [ "$st" = missing ] && stop "missing $name"
    kb=$(vsh dominfo "$dom" | awk '/Max memory:/ { print $3 }')
    case $kb in
        '' | *[!0-9]*) stop "no memory for $name" ;;
    esac
    mib=$((kb / 1024))
    echo "VM_MIB $name $mib"
    sum=$((sum + mib))
done
echo "RAM_SUM_MIB $sum CAP_MIB $CAP_MIB"
[ "$sum" -le "$CAP_MIB" ] || stop "ram $sum"

mkdir -p "$REC/move" "$REC/mit" "$REC/ours"
chmod 700 "$REC"
make_secrets

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
