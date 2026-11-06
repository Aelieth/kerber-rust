#!/bin/bash
# Run only after the weekly is graded. Argument: the landed sha.
# kadmin -q one command at a time; KRB5_CONFIG instead of editing
# krb5.conf; a FILE cache in every cell; klist's two- or four-digit dates.
# The cell and the scratch cleanup merge stderr on the guest.
# The record is clients-r2. CELL4_LINE is printed and is not part of the grade.
#
# One MIT-first client leg on rocky10 and deb13 against the lab KDC.
# The database stays the MIT snapshot's: reset kdc to MIT_SNAPSHOT_KDC, run
# the cells, then (only if that oracle passed) put the sha on that same VM
# by the final driver's route and run the cells again.
#
# Does not move target-rp, does not fetch, and does not update packages.
set -u
set +x
umask 077
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC HAND_RELEASE_TAG
TAG_RX=${HAND_RELEASE_TAG//./\\.}
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap 'rm -rf "$SEC"' EXIT
TMPDIR=$SEC
export TMPDIR

SHA=${1:?landed sha}
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "CLIENTS_STOP sha"; exit 2; }

WT=$HAND_WT
BASE=$HAND_REC/$SHA
REC=$BASE/clients-r2
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
DOC=$WT/harness/field/lib/docblocks.py
SCAN=$WT/harness/field/lib/scan-secrets.py
SECRETS=$LAB_HOME/secrets
TREE_TAR=$TMPDIR/kr-clients-tree.tar
CAP_MIB=$((32 * 1024))
REALM=KERBER.TEST
H_USE='## Download, install and use'
H_MOVE='## Move an MIT realm over'

booted=0
move_pass=no
oracle_pass=no
compare_pass=no
KVNO_PRINC=

stop() { echo "CLIENTS_STOP $*"; exit 2; }

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
    for vm in rocky10 deb13 kdc; do
        [ -f "$REC/booted-$vm" ] || continue
        "$LAB" down "$vm" > "$REC/down-$vm.out" 2>&1
        rc=$?
        echo "DOWN_RC:$vm:$rc"
    done
}
cleanup() {
    rm -f "$TREE_TAR"
    rm -f "$TMPDIR"/cell-stdin-*
    park
}
trap 'cleanup; rm -rf "$SEC"' EXIT

pw_line() {
    # Append one secret file as a single stdin line. Never print the value.
    local name=$1 dest=$2 p
    p=$(< "$SECRETS/$name")
    printf '%s\n' "$p" >> "$dest"
}

gen_line() {
    # Write one random password line. The process does not print it.
    python3 -B - "$1" << 'PY'
import secrets, sys
from pathlib import Path
Path(sys.argv[1]).write_text(secrets.token_urlsafe(18) + "\n")
PY
}

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
    : > "$TMPDIR/cell-stdin-move"
    "$LAB" ssh kdc -- 'install -d -m 0700 ~/field && cat > ~/field/block.sh' < "$REC/move/$tag.sh" > "$REC/move/$tag.copy" 2>&1 || return 1
    "$LAB" ssh kdc -- 'bash ~/field/block.sh' < "$TMPDIR/cell-stdin-move" > "$REC/move/$tag.out" 2>&1
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
    "$LAB" ssh kdc -- 'rpm -qf /usr/sbin/krb5kdc' > "$REC/kdc-prove-mit.out" 2>&1
    local rc=$?
    echo "KDC_PROVE_MIT_RC:$rc"
    if [ "$rc" = 0 ] && grep -q 'krb5-server' "$REC/kdc-prove-mit.out"; then
        echo "KDC_PROVE:mit:krb5-server"
        return 0
    fi
    echo "KDC_PROVE:mit:no"
    return 1
}

prove_ours() {
    # Cells 4-6 talk to kadmind, so that binary is held
    # to the same rule: no package owns it, and its sha256 is the guest build.
    "$LAB" ssh kdc -- 'rpm -qf /usr/sbin/krb5kdc; echo RC:$?; sha256sum /usr/sbin/krb5kdc ~/kerber-rust/target/release/krb5-kdc; echo ---; rpm -qf /usr/sbin/kadmind; echo KADMIND_RC:$?; sha256sum /usr/sbin/kadmind ~/kerber-rust/target/release/krb5-kadmind' > "$REC/kdc-prove-our.out" 2>&1
    local rc=$?
    echo "KDC_PROVE_OUR_SSH:$rc"
    python3 -B - "$REC/kdc-prove-our.out" << 'PY'
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

record_client() {
    local vm=$1 tag=$2
    "$LAB" ssh "$vm" -- 'cat /etc/os-release' > "$REC/os-$tag.out" 2>&1 || true
    echo "OS_RC:$tag:$?"
    if [ "$tag" = rocky ]; then
        "$LAB" ssh "$vm" -- 'rpm -q krb5-workstation krb5-libs; echo ---; command -v kinit; command -v klist; command -v kvno; command -v kpasswd; command -v kadmin; command -v kdestroy' > "$REC/pkg-$tag.out" 2>&1 || true
    else
        "$LAB" ssh "$vm" -- "dpkg -l 'krb5*' libkrb5-3; echo ---; command -v kinit; command -v klist; command -v kvno; command -v kpasswd; command -v kadmin; command -v kdestroy" > "$REC/pkg-$tag.out" 2>&1 || true
    fi
    echo "PKG_RC:$tag:$?"
}

write_config() {
    # The distro file stays as the snapshot left it. Cells put this snippet
    # first via KRB5_CONFIG, so default_realm is ours and the distro profile
    # still applies after it. The stock ccache name is printed on the MIT pass.
    local vm=$1 tag=$2 when=$3
    local ccache=""
    if [ "$when" = mit ]; then
        ccache=$(cat << 'EOS'
unset KRB5CCNAME KRB5_CONFIG
klist > "$HOME/field/ccache-default.out" 2>&1 || true
echo "==== ccache default ===="
cat "$HOME/field/ccache-default.out"
EOS
)
    fi
    "$LAB" ssh "$vm" -- 'bash -s' > "$REC/config-$tag-$when.out" 2>&1 << EOF
set -u
set +x
install -d -m 0700 "\$HOME/field"
cat > "\$HOME/field/realm.conf" << 'CFG'
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false

[realms]
    KERBER.TEST = {
        kdc = kdc.kerber.test
        admin_server = kdc.kerber.test
        kpasswd_server = kdc.kerber.test
    }

[domain_realm]
    .kerber.test = KERBER.TEST
    kerber.test = KERBER.TEST
CFG
echo CONFIG_ROUTE:KRB5_CONFIG
${ccache}
echo '==== krb5.conf ===='
sudo cat /etc/krb5.conf
echo '==== conf.d ===='
sudo ls -la /etc/krb5.conf.d 2>/dev/null || true
sudo cat /etc/krb5.conf.d/* 2>/dev/null || true
if grep -q crypto-policies /etc/krb5.conf 2>/dev/null; then
    echo '==== crypto-policies ===='
    sudo cat /etc/crypto-policies/back-ends/krb5.config 2>/dev/null || true
fi
echo '==== realm.conf ===='
cat "\$HOME/field/realm.conf"
EOF
    echo "CONFIG_RC:$tag:$when:$?"
}

tools_missing() {
    local tag=$1
    local n
    n=$(awk '/^---$/{p=1; next} p && /^\//{c++} END{print c+0}' "$REC/pkg-$tag.out")
    [ "$n" -ge 6 ]
}

write_script() {
    local path=$1
    shift
    printf '%s\n' "$@" > "$path"
}

run_cell() {
    local leg=$1 vm=$2 tag=$3 n=$4
    local dir=$REC/$leg/$tag
    mkdir -p "$dir"
    "$LAB" ssh "$vm" -- 'install -d -m 0700 ~/field && cat > ~/field/cell.sh' < "$dir/cell$n.sh" > "$dir/cell$n.copy" 2>&1 || return 1
    "$LAB" ssh "$vm" -- 'bash ~/field/cell.sh 2>&1' < "$TMPDIR/cell-stdin-$leg-$tag-$n" > "$dir/cell$n.out" 2>&1
    local rc=$?
    printf '%s\n' "$rc" > "$dir/cell$n.rc"
    echo "CELL_RC:$leg:$tag:$n:$rc"
    return 0
}

oracle_cell_ok() {
    local tag=$1 n=$2 scratch=$3
    local rc out
    rc=$(tr -d '[:space:]' < "$REC/mit/$tag/cell$n.rc")
    out=$REC/mit/$tag/cell$n.out
    case $n in
        1) [ "$rc" = 0 ] && grep -q 'krbtgt/KERBER.TEST@KERBER.TEST' "$out" ;;
        2) [ "$rc" != 0 ] && grep -qx "KINIT_RC:$rc" "$out" ;;
        3) [ "$rc" = 0 ] && grep -qF "$KVNO_PRINC" "$out" ;;
        4) [ "$rc" = 0 ] && grep -qx "${scratch}@${REALM}" "$out" ;;
        5) [ "$rc" = 0 ] && grep -qx 'KPASSWD_RC:0' "$out" && grep -qx 'KINIT2_RC:0' "$out" ;;
        6) [ "$rc" = 0 ] && grep -qx 'KDESTROY_RC:0' "$out" && ! grep -qx "${scratch}@${REALM}" "$out" ;;
        *) return 1 ;;
    esac
}

cleanup_scratch() {
    local tag=$1 scratch=$2
    local stdin=$TMPDIR/cell-stdin-clean-$tag
    : > "$stdin"
    pw_line "$MIT_SECRET_ADMIN" "$stdin"
    "$LAB" ssh "$(vm_for "$tag")" -- "kadmin -p admin/admin -q 'delprinc -force ${scratch}' 2>&1" < "$stdin" > "$REC/mit/$tag/cleanup.out" 2>&1
    echo "CLEANUP_RC:$tag:$?"
}

vm_for() {
    case $1 in
        rocky) printf '%s\n' rocky10 ;;
        deb) printf '%s\n' deb13 ;;
        *) stop "distro $1" ;;
    esac
}

scratch_for() {
    case $1 in
        rocky) printf '%s\n' clt-rocky ;;
        deb) printf '%s\n' clt-deb ;;
    esac
}

prep_stdins() {
    local leg=$1 tag=$2 scratch=$3
    local dir=$REC/$leg/$tag
    local alice=$MIT_SECRET_ALICE admin=$MIT_SECRET_ADMIN
    mkdir -p "$dir"
    gen_line "$TMPDIR/cell-stdin-wrong-$tag"
    gen_line "$TMPDIR/cell-stdin-new-$tag"
    gen_line "$TMPDIR/cell-stdin-new2-$tag"
    # cell 1: alice's current password
    : > "$TMPDIR/cell-stdin-$leg-$tag-1"
    pw_line "$alice" "$TMPDIR/cell-stdin-$leg-$tag-1"
    # cell 2: one wrong password, not the real one
    cp "$TMPDIR/cell-stdin-wrong-$tag" "$TMPDIR/cell-stdin-$leg-$tag-2"
    : > "$TMPDIR/cell-stdin-$leg-$tag-3"
    # cell 4: one kadmin -q per command. getprinc and listprincs each read
    # the admin password. addprinc reads admin, then the new password twice.
    : > "$TMPDIR/cell-stdin-$leg-$tag-4"
    pw_line "$admin" "$TMPDIR/cell-stdin-$leg-$tag-4"
    pw_line "$admin" "$TMPDIR/cell-stdin-$leg-$tag-4"
    cat "$TMPDIR/cell-stdin-new-$tag" >> "$TMPDIR/cell-stdin-$leg-$tag-4"
    cat "$TMPDIR/cell-stdin-new-$tag" >> "$TMPDIR/cell-stdin-$leg-$tag-4"
    pw_line "$admin" "$TMPDIR/cell-stdin-$leg-$tag-4"
    # cell 5: kinit(first), kpasswd(current, new, new), kinit(new).
    # MIT kpasswd asks for the current password to get a kadmin/changepw
    # ticket, then the new password twice. The first password is the one
    # addprinc just set.
    : > "$TMPDIR/cell-stdin-$leg-$tag-5"
    {
        cat "$TMPDIR/cell-stdin-new-$tag"
        cat "$TMPDIR/cell-stdin-new-$tag"
        cat "$TMPDIR/cell-stdin-new2-$tag"
        cat "$TMPDIR/cell-stdin-new2-$tag"
        cat "$TMPDIR/cell-stdin-new2-$tag"
    } >> "$TMPDIR/cell-stdin-$leg-$tag-5"
    # cell 6: delprinc, then listprincs. Each reads the admin password.
    : > "$TMPDIR/cell-stdin-$leg-$tag-6"
    pw_line "$admin" "$TMPDIR/cell-stdin-$leg-$tag-6"
    pw_line "$admin" "$TMPDIR/cell-stdin-$leg-$tag-6"
}

write_cells() {
    local tag=$1 scratch=$2
    local dir n princ_q env1 env2
    for leg in mit our; do
        dir=$REC/$leg/$tag
        mkdir -p "$dir"
        princ_q=$(printf '%q' "$KVNO_PRINC")
        env1="export KRB5_CONFIG=\$HOME/field/realm.conf:/etc/krb5.conf"
        env2="export KRB5CCNAME=FILE:\$HOME/field/cell.cc"
        write_script "$dir/cell1.sh" \
            'set +x' "$env1" "$env2" \
            'kdestroy >/dev/null 2>&1 || true' \
            'kinit alice' "rc=\$?" "echo \"KINIT_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            'klist' "rc=\$?" "echo \"KLIST_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            'klist -e' "rc=\$?" "echo \"KLIST_E_RC:\$rc\"" \
            "exit \"\$rc\""
        write_script "$dir/cell2.sh" \
            'set +x' "$env1" "$env2" \
            'kinit alice' "rc=\$?" "echo \"KINIT_RC:\$rc\"" \
            'klist' "echo \"KLIST_AFTER_RC:\$?\"" \
            "exit \"\$rc\""
        write_script "$dir/cell3.sh" \
            'set +x' "$env1" "$env2" \
            'klist' "echo \"KLIST_RC:\$?\"" \
            "kvno ${princ_q}" "rc=\$?" "echo \"KVNO_RC:\$rc\"" \
            "exit \"\$rc\""
        write_script "$dir/cell4.sh" \
            'set +x' "$env1" "$env2" \
            'kadmin -p admin/admin -q "getprinc alice"' "rc=\$?" "echo \"GETPRINC_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            "kadmin -p admin/admin -q \"addprinc ${scratch}\"" "rc=\$?" "echo \"ADDPRINC_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            'kadmin -p admin/admin -q "listprincs"' "rc=\$?" "echo \"LISTPRINCS_RC:\$rc\"" \
            "exit \"\$rc\""
        write_script "$dir/cell5.sh" \
            'set +x' "$env1" "$env2" \
            "kinit ${scratch}" "rc=\$?" "echo \"KINIT1_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            "kpasswd ${scratch}" "rc=\$?" "echo \"KPASSWD_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            'kdestroy' \
            "kinit ${scratch}" "rc=\$?" "echo \"KINIT2_RC:\$rc\"" \
            'klist' \
            "exit \"\$rc\""
        write_script "$dir/cell6.sh" \
            'set +x' "$env1" "$env2" \
            "kadmin -p admin/admin -q \"delprinc -force ${scratch}\"" "rc=\$?" "echo \"DELPRINC_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            'kadmin -p admin/admin -q "listprincs"' "rc=\$?" "echo \"LISTPRINCS_RC:\$rc\"" \
            "if [ \"\$rc\" != 0 ]; then exit \"\$rc\"; fi" \
            'kdestroy' "rc=\$?" "echo \"KDESTROY_RC:\$rc\"" \
            "exit \"\$rc\""
    done
}

run_leg() {
    local leg=$1 tag=$2 vm=$3 n
    for n in 1 2 3 4 5 6; do
        run_cell "$leg" "$vm" "$tag" "$n" || return 1
        if [ "$leg" = mit ] && ! oracle_cell_ok "$tag" "$n" "$(scratch_for "$tag")"; then
            echo "ORACLE_FAIL:$tag:cell$n"
            if [ "$n" -ge 4 ]; then
                cleanup_scratch "$tag" "$(scratch_for "$tag")" || true
            fi
            return 1
        fi
    done
    return 0
}

write_mask_rules() {
    cat > "$REC/mask-rules.txt" << 'EOF'
Masked, and only these, before the MIT-vs-ours diff:
- mm/dd/yy hh:mm:ss and mm/dd/yyyy hh:mm:ss
- yyyy-mm-dd hh:mm:ss and yyyy-mm-ddThh:mm:ss
- kadmin ctime: "Dow Mon D hh:mm:ss TZ yyyy" and the same without TZ
Not masked: enctypes, kvno numbers, error text, principal names,
listprincs order, "never", ticket lifetimes, failure counters.
A difference outside the masked timestamps is shown.
EOF
    cat "$REC/mask-rules.txt"
}

compare_legs() {
    write_mask_rules
    python3 -B - "$REC" << 'PY'
import re, sys
from pathlib import Path
rec = Path(sys.argv[1])
pats = [
    re.compile(r"\d{2}/\d{2}/\d{2}(?:\d{2})? \d{2}:\d{2}:\d{2}"),
    re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"),
    re.compile(r"[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?: [A-Z]{2,5})? \d{4}"),
]
def mask(text):
    for p in pats:
        text = p.sub("<TIME>", text)
    return text
ok = True
for tag in ("rocky", "deb"):
    diffs = []
    for n in range(1, 7):
        a = rec / "mit" / tag / f"cell{n}.out"
        b = rec / "our" / tag / f"cell{n}.out"
        ra = (rec / "mit" / tag / f"cell{n}.rc").read_text().strip()
        rb = (rec / "our" / tag / f"cell{n}.rc").read_text().strip()
        ma, mb = mask(a.read_text(errors="replace")), mask(b.read_text(errors="replace"))
        (rec / "mit" / tag / f"cell{n}.masked").write_text(ma)
        (rec / "our" / tag / f"cell{n}.masked").write_text(mb)
        if ra != rb or ma != mb:
            diffs.append(str(n))
            (rec / tag / f"cell{n}.diff").parent.mkdir(parents=True, exist_ok=True)
            import difflib
            lines = difflib.unified_diff(
                ma.splitlines(True), mb.splitlines(True),
                fromfile=f"mit/{tag}/cell{n}", tofile=f"our/{tag}/cell{n}")
            (rec / f"diff-{tag}-cell{n}.txt").write_text("".join(lines))
            print(f"CLIENT_DIFF:{tag}:cell{n}:rc:{ra}:{rb}")
    if diffs:
        ok = False
        print("CLIENT_CELLS:%s:differ:%s" % (tag, ",".join(diffs)))
    else:
        print("CLIENT_CELLS:%s:equal" % tag)
sys.exit(0 if ok else 1)
PY
}

# --- gates that do not touch a VM ---
[ -e "$REC" ] && stop "exists $REC"
[ -d "$BASE/weekly" ] || stop "weekly-record"
if [ -f "$BASE/driver.pid" ]; then
    old=$(tr -cd '0-9' < "$BASE/driver.pid")
    if [ -n "$old" ] && [ -d "/proc/$old" ] && tr '\0' ' ' < "/proc/$old/cmdline" | grep -q 'rp-final.sh'; then
        stop "rp-final running $old"
    fi
fi
if ! git -C "$WT" diff --quiet --ignore-submodules -- || ! git -C "$WT" diff --cached --quiet --ignore-submodules --; then
    stop dirty
fi
if [ "$(git -C "$WT" rev-parse HEAD)" != "$SHA" ]; then
    git -C "$WT" checkout --detach "$SHA" || stop checkout
fi
got=$(git -C "$WT" rev-parse HEAD)
echo "HEAD:$got"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
[ "$got" = "$SHA" ] || stop head
# shellcheck source=/dev/null
. "$WT/harness/field/baseline.env"
echo "SNAP_KDC:${MIT_SNAPSHOT_KDC:-}"
[ "${MIT_REALM:-}" = "$REALM" ] || stop "MIT_REALM"
[ -n "${MIT_SNAPSHOT_KDC:-}" ] || stop "MIT_SNAPSHOT_KDC"
[ -f "$SECRETS/${MIT_SECRET_ALICE:-}" ] || stop "secret-file alice"
[ -f "$SECRETS/${MIT_SECRET_ADMIN:-}" ] || stop "secret-file admin"
echo "SECRET_FILE:alice:${MIT_SECRET_ALICE}"
echo "SECRET_FILE:admin:${MIT_SECRET_ADMIN}"

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
    case $name in
        kdc|deb13|rocky10) add=yes ;;
    esac
    [ "$st" = running ] && add=yes
    [ "$add" = yes ] || continue
    [ "$st" = missing ] && stop "missing $name"
    kb=$(vsh dominfo "$dom" | awk '/Max memory:/ { print $3 }')
    case $kb in
        ''|*[!0-9]*) stop "no memory for $name" ;;
    esac
    mib=$((kb / 1024))
    echo "VM_MIB $name $mib"
    sum=$((sum + mib))
done
echo "RAM_SUM_MIB $sum CAP_MIB $CAP_MIB"
[ "$sum" -le "$CAP_MIB" ] || stop "ram $sum"

mkdir -p "$REC/move"
chmod 700 "$REC"
echo "==== resets ===="
reset_vm kdc "$MIT_SNAPSHOT_KDC" || stop "reset kdc"
reset_vm rocky10 client || stop "reset rocky10"
reset_vm deb13 krb5 || stop "reset deb13"
wait_ntp kdc || stop "ntp kdc"
wait_ntp rocky10 || stop "ntp rocky10"
wait_ntp deb13 || stop "ntp deb13"

echo "==== client facts ===="
record_client rocky10 rocky
record_client deb13 deb
write_config rocky10 rocky mit
write_config deb13 deb mit
grep -q '^CONFIG_ROUTE:' "$REC/config-rocky-mit.out" || stop "config rocky"
grep -q '^CONFIG_ROUTE:' "$REC/config-deb-mit.out" || stop "config deb"
tools_missing rocky || stop "tools rocky"
tools_missing deb || stop "tools deb"

echo "==== MIT oracle ===="
if ! wait_units || ! prove_mit; then
    echo "ORACLE_FAIL:kdc"
    echo "CLIENTS_PASS:no"
    echo "CLIENTS_DONE"
    exit 0
fi
"$LAB" ssh kdc -- 'sudo kadmin.local -q listprincs' > "$REC/listprincs.before" 2>&1
echo "LISTPRINCS_BEFORE_RC:$?"
KVNO_PRINC=$(grep -x 'host/kdc.kerber.test@KERBER.TEST' "$REC/listprincs.before" | head -n 1 || true)
if [ -z "$KVNO_PRINC" ]; then
    KVNO_PRINC=$(grep -E '^host/[^@]+@KERBER\.TEST$' "$REC/listprincs.before" | head -n 1 || true)
fi
printf '%s\n' "$KVNO_PRINC" > "$REC/kvno-princ.txt"
echo "KVNO_PRINC:${KVNO_PRINC:-missing}"
if ! printf '%s\n' "$KVNO_PRINC" | grep -Eq '^[A-Za-z0-9_./@-]+$'; then
    echo "ORACLE_FAIL:kvno-princ"
    echo "CLIENTS_PASS:no"
    echo "CLIENTS_DONE"
    exit 0
fi
for tag in rocky deb; do
    if grep -qx "$(scratch_for "$tag")@${REALM}" "$REC/listprincs.before"; then
        echo "ORACLE_FAIL:$tag:scratch-exists"
        echo "CLIENTS_PASS:no"
        echo "CLIENTS_DONE"
        exit 0
    fi
done

oracle_pass=yes
for tag in rocky deb; do
    vm=$(vm_for "$tag") || stop "distro $tag"
    scratch=$(scratch_for "$tag")
    prep_stdins mit "$tag" "$scratch"
    write_cells "$tag" "$scratch"
    if ! run_leg mit "$tag" "$vm"; then
        oracle_pass=no
        break
    fi
done
if [ "$oracle_pass" != yes ]; then
    echo "CLIENTS_PASS:no"
    echo "CLIENTS_DONE"
    exit 0
fi

echo "==== move, same database ===="
move_pass=yes
mkdir -p "$REC/move"
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
    "$LAB" ssh kdc -- 'sudo kadmin.local -q listprincs' > "$REC/listprincs.after" 2>&1
    echo "LISTPRINCS_AFTER_RC:$?"
    grep -E '^[^[:space:]]+@[^[:space:]]+$' "$REC/listprincs.before" | LC_ALL=C sort > "$REC/listprincs.before.names" || true
    grep -E '^[^[:space:]]+@[^[:space:]]+$' "$REC/listprincs.after" | LC_ALL=C sort > "$REC/listprincs.after.names" || true
    if [ ! -s "$REC/listprincs.before.names" ] || ! diff -q "$REC/listprincs.before.names" "$REC/listprincs.after.names" >/dev/null; then
        echo "LISTPRINCS:differ"
        move_pass=no
    else
        echo "LISTPRINCS:same"
    fi
    "$LAB" ssh kdc -- 'systemctl is-active krb5kdc; echo ---; systemctl is-active kadmin' > "$REC/move-active.out" 2>&1 || true
    act=$(grep -c '^active$' "$REC/move-active.out" || true)
    echo "MOVE_ACTIVE_COUNT:${act:-0}"
    [ "${act:-0}" = 2 ] || move_pass=no
fi
echo "MOVE_PASS:$move_pass"
if [ "$move_pass" != yes ]; then
    echo "MOVE_FAIL"
    echo "CLIENTS_PASS:no"
    echo "CLIENTS_DONE"
    exit 0
fi
if ! prove_ours; then
    echo "OURS_PROVE:no"
    echo "CLIENTS_PASS:no"
    echo "CLIENTS_DONE"
    exit 0
fi
wait_ntp kdc || stop "ntp kdc before ours"
wait_ntp rocky10 || stop "ntp rocky before ours"
wait_ntp deb13 || stop "ntp deb before ours"
write_config rocky10 rocky our
write_config deb13 deb our

echo "==== our KDC, same clients ===="
for tag in rocky deb; do
    vm=$(vm_for "$tag") || stop "distro $tag"
    scratch=$(scratch_for "$tag")
    prep_stdins our "$tag" "$scratch"
    if ! run_leg our "$tag" "$vm"; then
        echo "OUR_CELL_FAIL:$tag"
        echo "CLIENTS_PASS:no"
        echo "CLIENTS_DONE"
        exit 0
    fi
done

echo "==== compare ===="
if compare_legs; then
    compare_pass=yes
else
    compare_pass=no
fi
# Printed for the prediction. Not an input to CLIENTS_PASS.
cell4_line() {
    local leg=$1 tag=$2 line
    local out=$REC/$leg/$tag/cell4.out
    if [ -f "$out" ]; then
        line=$(grep -F 'No policy specified' "$out" | head -n 1 || true)
    fi
    if [ -n "${line:-}" ]; then
        printf 'CELL4_LINE:%s:%s:%s\n' "$leg" "$tag" "$line"
    else
        printf 'CELL4_LINE:%s:%s:missing\n' "$leg" "$tag"
    fi
}
cell4_line mit rocky
cell4_line mit deb
cell4_line our rocky
cell4_line our deb
python3 -B "$SCAN" "$REC"
scan_rc=$?
echo "SECRET_SCAN:$scan_rc"
if [ "$compare_pass" = yes ] && [ "$scan_rc" = 0 ]; then
    echo "CLIENTS_PASS:yes"
else
    echo "CLIENTS_PASS:no"
fi
echo "CLIENTS_DONE"
exit 0
