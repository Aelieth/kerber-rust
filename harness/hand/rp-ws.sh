#!/bin/bash
# WS/WA: Windows 11's own Kerberos client on kerber-win (SSPI, klist, the LSA) against the lab KDC,
# MIT's leg then ours, by CM's route (lib/cm-host.sh): each leg resets kdc and services, runs MIT's
# setup, and ours' leg then moves the realm by the README. kerber-win reverts to win-pre-ksetup per
# leg and joins the realm with ksetup and a power cycle. lib/ws-cells.ps1 runs the cells through the
# guest agent (lib/win-agent.py); lib/ws-grade.py grades ours against MIT. Argument: the landed sha.
set -u
set +x
umask 077
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
. "$HDIR/lib/cm-host.sh"
require_env HAND_WT HAND_REC HAND_RELEASE_TAG
P=WS
TAG_RX=${HAND_RELEASE_TAG//./\\.}
SEC=$(mktemp -d "${TMPDIR:-/var/tmp}/hand-sec.XXXXXX")
trap drop_sec EXIT
TMPDIR=$SEC
export TMPDIR

SHA=${1:?landed sha}
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "WS_STOP sha"; exit 2; }
SUITE=ws
TAGS=(win)
VMS=(kdc services win)

WT=$HAND_WT
REC=$HAND_REC/$SHA/$SUITE
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
DOC=$WT/harness/field/lib/docblocks.py
SCAN=$WT/harness/field/lib/scan-secrets.py
PTY=$WT/harness/field/lib/ptydrive.py
CELLS=$HDIR/lib/cm-cells.sh
GRADE=$HDIR/lib/cm-grade.py
AGENT=$HDIR/lib/win-agent.py
PS1=$HDIR/lib/ws-cells.ps1
WGRADE=$HDIR/lib/ws-grade.py
MITSRV=$WT/scripts/oracle/gss-mit-server.c
PROBE=$WT/harness/field/lib/spnego-probe.sh
ACCEPT=$WT/target/release/krb5-gss-accept
SECRETS=$LAB_HOME/secrets
TREE_TAR=$TMPDIR/kr-ws-tree.tar
CAP_MIB=$((32 * 1024))
GUEST_TMO=1800
REALM=KERBER.TEST
H_USE='## Download, install and use'
H_MOVE='## Move an MIT realm over'
WIN=kerber-win
WIN_SNAP=win-pre-ksetup
WTMP='C:\Windows\Temp'
POWERSHELL='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
SVC=host/cm.kerber.test
PORT=4444
win_up=0

# WIN_END:ok only when kerber-win is back on its snapshot and shut off; a run without it doesn't count.
win_park() {
    local rc st snap
    [ "$win_up" = 1 ] || return 0
    win_up=0
    vsh destroy "$WIN" > "$REC/win-end.out" 2>&1
    vsh snapshot-revert "$WIN" --snapshotname "$WIN_SNAP" >> "$REC/win-end.out" 2>&1
    rc=$?
    [ "$(domstate "$WIN")" = "shut off" ] || vsh destroy "$WIN" >> "$REC/win-end.out" 2>&1
    st=$(domstate "$WIN")
    snap=$(vsh snapshot-current "$WIN" --name 2> /dev/null)
    if [ "$rc" = 0 ] && [ "$st" = "shut off" ] && [ "$snap" = "$WIN_SNAP" ]; then
        echo "WIN_END:ok"
    else
        echo "WIN_END:FAIL:revert=$rc:state=$st:snapshot=${snap:-none}"
    fi
}
trap 'rm -f "$TREE_TAR"; win_park; park; drop_sec' EXIT

value() { awk -F'\t' -v k="$1" '$1 == k { print $2; exit }' "$SEC/all.tsv"; }
wa() { python3 -B "$AGENT" "$WIN" "$SEC/all.tsv" "$@"; }

# wput GUEST_PATH NAME...: the named secrets, one per line, into a guest file the cell deletes on read.
wput() {
    local path=$1 n
    shift
    for n in "$@"; do value "$n"; done | wa write "$path" | grep -qx WROTE
}

# wexec OUT ARGV...: one guest-exec, its output CR-stripped into OUT; rc 0 when the guest's exit code is 0.
wexec() {
    local out=$1
    shift
    timeout -k 30 900 python3 -B "$AGENT" "$WIN" "$SEC/all.tsv" exec "$@" 2>&1 | tr -d '\r' > "$out"
    grep -qx 'exitcode 0' "$out"
}

# wksetup OUT ARG...: ksetup exits 0 even when it fails, so its "Failed" line counts.
wksetup() {
    wexec "$@" && ! grep -q '^Failed ' "$1"
}

# wps OUT MODE ARG...: ws-cells.ps1 in that mode; rc 0 when it reached PS_DONE.
wps() {
    local out=$1
    shift
    wexec "$out" "$POWERSHELL" -NoProfile -ExecutionPolicy Bypass -File "$WTMP\\ws.ps1" "$@"
    grep -qx PS_DONE "$out"
}

win_wait() {
    local i=0
    while [ "$i" -lt "$1" ]; do
        if wa ping 2> /dev/null | grep -qx AGENT_UP; then
            return 0
        fi
        sleep 5
        i=$((i + 1))
    done
    return 1
}

# Revert to the snapshot (gotcha 2: a revert keeps the snapshot's power state), then read the
# guest's name: kdc_setup makes its machine principal.
win_revert() {
    local leg=$1 d=$REC/$1/win
    win_up=1
    vsh destroy "$WIN" > "$d/revert.out" 2>&1
    vsh snapshot-revert "$WIN" --snapshotname "$WIN_SNAP" >> "$d/revert.out" 2>&1 || return 1
    [ "$(domstate "$WIN")" = running ] || vsh start "$WIN" >> "$d/revert.out" 2>&1 || return 1
    win_wait 60 || return 1
    wa write "$WTMP\\ws.ps1" < "$PS1" | grep -qx WROTE || return 1
    wps "$d/info.txt" info || return 1
    WIN_HOST=$(sed -n 's/^WIN_HOST://p' "$d/info.txt" | tr '[:upper:]' '[:lower:]')
    [ -n "$WIN_HOST" ] || return 1
    MACH=host/$WIN_HOST.${REALM,,}
    echo "WIN_HOST:$leg:$WIN_HOST"
    echo "WIN_UTC:$leg:$(sed -n 's/^WIN_UTC://p' "$d/info.txt") HOST_UTC:$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# kdc_setup's hook, on kdc with MIT's kadmin.local before any move: the acceptors' keytab and the
# guest's machine principal (its password on stdin; no PAC, which a workgroup machine can't validate).
push_keytabs() {
    local d=$REC/$1
    "$LAB" ssh kdc -- "install -d -m 0700 /var/tmp/ws && sudo kadmin.local -q 'ktadd -k /var/tmp/ws/svc.keytab -norandkey $SVC' && sudo chown lab:lab /var/tmp/ws/svc.keytab" < /dev/null > "$d/svc-keytab.out" 2>&1 || return 1
    grep -q 'added to keytab' "$d/svc-keytab.out" || return 1
    { value mach-win; value mach-win; } | "$LAB" ssh kdc -- "sudo kadmin.local -q 'addprinc +no_auth_data_required $MACH'" > "$d/machine.out" 2>&1 || return 1
    grep -q "Principal \"$MACH@$REALM\" created" "$d/machine.out"
}

acceptors() {
    local d=$REC/$1
    "$LAB" ssh kdc -- 'cat > /var/tmp/ws/gss-mit-server.c' < "$MITSRV" || return 1
    "$LAB" ssh kdc -- 'cat > /var/tmp/ws/krb5-gss-accept && chmod 0755 /var/tmp/ws/krb5-gss-accept' < "$ACCEPT" || return 1
    "$LAB" ssh kdc -- 'bash -s' > "$d/acceptors.out" 2>&1 << 'EOF'
rpm -q gcc krb5-devel > /dev/null 2>&1 || sudo -n dnf install -y gcc krb5-devel > /var/tmp/ws/dnf.out 2>&1
rpm -q gcc krb5-devel krb5-libs
gcc -O2 -o /var/tmp/ws/gss-mit-server /var/tmp/ws/gss-mit-server.c -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
echo "COMPILE_RC:$?"
sha256sum /var/tmp/ws/krb5-gss-accept
EOF
    grep -qx 'COMPILE_RC:0' "$d/acceptors.out" && grep -q "^$ACCEPT_SHA " "$d/acceptors.out"
}

acc_start() {
    local leg=$1 kind=$2 cmd i
    if [ "$kind" = mit ]; then
        cmd="GSS_VERIFY_MIC=1 GSS_REPLY=1 /var/tmp/ws/gss-mit-server /var/tmp/ws/svc.keytab 0.0.0.0 $PORT $SVC@$REALM"
    else
        cmd="/var/tmp/ws/krb5-gss-accept --keytab /var/tmp/ws/svc.keytab --listen 0.0.0.0:$PORT --verify-mic --reply"
    fi
    "$LAB" ssh kdc -- "($cmd > /var/tmp/ws/acc-$kind.log 2>&1 < /dev/null & echo \$! > /var/tmp/ws/acc-$kind.pid)" < /dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do
        "$LAB" ssh kdc -- "grep -q listening /var/tmp/ws/acc-$kind.log" < /dev/null && return 0
        sleep 1
    done
    echo "ACC_LISTEN:$leg:$kind:no"
    return 1
}

acc_stop() {
    local leg=$1 kind=$2 i
    "$LAB" ssh kdc -- "kill \$(cat /var/tmp/ws/acc-$kind.pid) 2>/dev/null; cat /var/tmp/ws/acc-$kind.log" < /dev/null > "$REC/$leg/win/acc-$kind.log" 2>&1
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [ -z "$("$LAB" ssh kdc -- "ss -ltnH 'sport = :$PORT'" < /dev/null)" ] && return 0
        sleep 1
    done
    echo "ACC_STOPPED:$leg:$kind:no"
    return 1
}

# A clean power cycle (the realm settings need a restart), forced only if shutdown hangs.
win_cycle() {
    local i=0 how=forced
    vsh shutdown "$WIN" > /dev/null 2>&1
    while [ "$i" -lt 36 ]; do
        if [ "$(domstate "$WIN")" = "shut off" ]; then
            how=clean
            break
        fi
        sleep 5
        i=$((i + 1))
    done
    [ "$how" = clean ] || vsh destroy "$WIN" > /dev/null 2>&1
    echo "WIN_SHUTDOWN:$1:$how"
    vsh start "$WIN" > /dev/null 2>&1 || return 1
    win_wait 60
}

win_setup() {
    local leg=$1 d=$REC/$1/win
    wksetup "$d/ksetup-realm.txt" ksetup /setrealm "$REALM" || return 1
    wksetup "$d/ksetup-kdc.txt" ksetup /addkdc "$REALM" kdc.kerber.test || return 1
    wksetup "$d/ksetup-kpasswd.txt" ksetup /addkpasswd "$REALM" kdc.kerber.test || return 1
    wps "$d/localuser.txt" localuser winuser || return 1
    if grep -qx 'LOCALUSER:absent' "$d/localuser.txt"; then
        wput "$WTMP\\ws-1.pw" win-local && wps "$d/mkuser.txt" mkuser winuser "$WTMP\\ws-1.pw" || return 1
        grep -qx 'LOCALUSER_CREATED:True' "$d/mkuser.txt" || return 1
    fi
    wksetup "$d/ksetup-map.txt" ksetup /mapuser "cm-win@$REALM" winuser || return 1
    wps "$d/suffix.txt" suffix "${REALM,,}" || return 1
    wput "$WTMP\\ws-m.pw" mach-win || return 1
    wps "$d/machinepw.txt" machinepw "$WTMP\\ws-m.pw" || return 1
    grep -qx 'LSA_STORE:0x00000000' "$d/machinepw.txt" || return 1
    wa write "$WTMP\\ws-ca.crt" < "$SECRETS/$LAB_CA" | grep -qx WROTE || return 1
    wps "$d/ca.txt" ca "$WTMP\\ws-ca.crt" || return 1
    win_restart "$leg" || return 1
    wexec "$d/w1-ksetup.txt" ksetup
}

# A power cycle, then ws.ps1 again: the cells' copy goes in after the cycle, as R4's did.
win_restart() {
    win_cycle "$1" && wa write "$WTMP\\ws.ps1" < "$PS1" | grep -qx WROTE
}

reset_both() {
    reset_vm kdc "$MIT_SNAPSHOT_KDC" || stop "reset kdc"
    reset_vm services "$MIT_SNAPSHOT_SERVICES" || stop "reset services"
    wait_ntp kdc || stop "ntp kdc"
    wait_ntp services || stop "ntp services"
}

# Both KDCs log to these files on Fedora (as the field harness's marks read them).
kdc_marks() { "$LAB" ssh kdc -- 'sudo wc -l /var/log/krb5kdc.log /var/log/kadmind.log' < /dev/null | awk 'NR <= 2 { printf "%s ", $1 }'; }
kdc_log() {
    "$LAB" ssh kdc -- "sudo tail -n +$(($2 + 1)) /var/log/krb5kdc.log; echo '--- kadmind.log'; sudo tail -n +$(($3 + 1)) /var/log/kadmind.log" < /dev/null 2>&1 | grep -v 'closing down fd' > "$REC/$1/win/kdc.log"
}

# The cells, in the design's order, L1 last; each cell's own principal, so no cached ticket is reused.
# R1c's RC4-only policy is set and removed, each with a restart. L1's events are recorded, not graded.
cells() {
    local leg=$1 d=$REC/$1/win kind marks
    read -r -a marks < <(kdc_marks)
    [ "${#marks[@]}" = 2 ] || return 1
    wps "$d/w1.txt" reach kdc.kerber.test
    wput "$WTMP\\ws-1.pw" pw-win && wps "$d/w2.txt" klist cm-win "$REALM" "$SVC" "$WTMP\\ws-1.pw"
    for kind in mit ours; do
        acc_start "$leg" "$kind" || return 1
        wput "$WTMP\\ws-1.pw" pw-win && wps "$d/s-$kind.txt" sspi kdc.kerber.test "$PORT" "$SVC" cm-win "$REALM" "$WTMP\\ws-1.pw"
        acc_stop "$leg" "$kind" || return 1
    done
    wput "$WTMP\\ws-2.pw" chpw-win-file chpw2-win-file && wps "$d/p1.txt" chpw cm-win-file-chpw "$REALM" "$WTMP\\ws-2.pw"
    wput "$WTMP\\ws-1.pw" chpw2-win-file && wps "$d/p1-new.txt" ticket "$SVC" cm-win-file-chpw "$REALM" "$WTMP\\ws-1.pw"
    wput "$WTMP\\ws-1.pw" chpw-win-file && wps "$d/p1-old.txt" ticket "$SVC" cm-win-file-chpw "$REALM" "$WTMP\\ws-1.pw"
    wput "$WTMP\\ws-1.pw" wrong-win-kcm && wps "$d/p2-wrong.txt" ticket "$SVC" cm-win-kcm-chpw "$REALM" "$WTMP\\ws-1.pw"
    wput "$WTMP\\ws-1.pw" pwexp-win-file && wps "$d/p2-pwexp.txt" ticket "$SVC" cm-win-file-pwexp "$REALM" "$WTMP\\ws-1.pw"
    wput "$WTMP\\ws-1.pw" exp-win-file && wps "$d/p2-exp.txt" ticket "$SVC" cm-win-file-exp "$REALM" "$WTMP\\ws-1.pw"
    wput "$WTMP\\ws-1.pw" alice && wps "$d/k1.txt" k1 "$KC_URL" alice "$REALM" "$WTMP\\ws-1.pw"
    wps "$d/r1c-set.txt" etype 4
    win_restart "$leg:r1c" || return 1
    wput "$WTMP\\ws-1.pw" kt-win && wps "$d/r1c.txt" ticket "$SVC" cm-win-kt "$REALM" "$WTMP\\ws-1.pw"
    wps "$d/r1c-unset.txt" etype none
    wps "$d/l1-diag.txt" diag
    win_restart "$leg:l1" || return 1
    wput "$WTMP\\ws-1.pw" pw-win && wps "$d/l1.txt" logon cm-win "$REALM" "$WTMP\\ws-1.pw"
    grep -q '^LOGON:True' "$d/l1.txt" || wps "$d/l1-events.txt" events 2
    kdc_log "$leg" "${marks[0]}" "${marks[1]}"
    echo "CELLS_DONE:$leg"
}

# --- gates that do not touch a VM ---
host_gates "$CELLS" "$GRADE" "$PTY" "$HDIR/lib/cm-host.sh" "$AGENT" "$PS1" "$WGRADE" "$MITSRV" "$PROBE"
[ -n "${MIT_SNAPSHOT_SERVICES:-}" ] || stop "MIT_SNAPSHOT_SERVICES"
[ -f "$SECRETS/${LAB_CA:-}" ] || stop "lab CA"
[ -f "$SECRETS/${MIT_SECRET_ALICE:-}" ] || stop "secret-file alice"
KC_URL=$(sed -n "s/^URL='\(.*\)'$/\1/p" "$PROBE")
[ -n "$KC_URL" ] || stop "keycloak url"
vsh snapshot-list "$WIN" --name 2> /dev/null | grep -qx "$WIN_SNAP" || stop "no $WIN_SNAP"
echo "==== krb5-gss-accept (test hooks) from the sha ===="
(cd "$WT" && cargo build --release --locked -p krb5-gss --features test-hooks --bin krb5-gss-accept) > "$SEC/build.out" 2>&1 || {
    tail -n 20 "$SEC/build.out"
    stop "build krb5-gss-accept"
}
ACCEPT_SHA=$(sha256sum "$ACCEPT" | awk '{print $1}')
echo "ACCEPT_SHA:$ACCEPT_SHA"

mkdir -p "$REC/move" "$REC/mit/win" "$REC/ours/win"
chmod 700 "$REC"
make_secrets
{
    printf 'mach-win\t%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
    printf 'win-local\t%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(18) + "Zz9-")')"
    printf 'alice\t%s\n' "$(< "$SECRETS/$MIT_SECRET_ALICE")"
} >> "$SEC/all.tsv"

echo "==== resets ===="
reset_both

for leg in mit ours; do
    echo "==== $leg leg ===="
    [ "$leg" = mit ] || reset_both
    win_revert "$leg" || fail "WIN_FAIL:revert:$leg"
    wait_units || fail "ORACLE_FAIL:kdc-units:$leg"
    prove_mit "$leg" || fail "ORACLE_FAIL:kdc-prove:$leg"
    kdc_setup "$leg" || fail "SETUP_FAIL:$leg"
    acceptors "$leg" || fail "ACCEPTORS_FAIL:$leg"
    if [ "$leg" = ours ]; then
        move || fail "MOVE_FAIL"
        prove_ours || fail "OURS_PROVE:no"
    fi
    win_setup "$leg" || fail "WIN_FAIL:setup:$leg"
    cells "$leg" || fail "RUN_FAIL:$leg"
    if [ "$leg" = mit ]; then
        python3 -B "$WGRADE" oracle "$REC" || fail "ORACLE_FAIL:cells"
    fi
done

echo "==== grade ===="
python3 -B "$WGRADE" grade "$REC"
grade_rc=$?
if scans && [ "$grade_rc" = 0 ]; then
    echo "WS_PASS:yes"
else
    echo "WS_PASS:no"
fi
echo "WS_DONE"
exit 0
