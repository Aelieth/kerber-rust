#!/bin/bash
# hc.sh: HOLD C of the 1.1 full pass (tree 242a461f): the hand legs R3 (sshd GSSAPI client1 -> client2) and RA0-RA3 (AD and Windows against
# the KERBER.TEST realm), MIT realm first, then the same cells against the ship build installed by docs/install.md "Upgrading an MIT realm".
# One lab-lock hold. VMs only through harness/field/lab.sh. No AD change, no change to the user's containers, no docker, no host /tmp.
#   L0 lock (/var/tmp/kr-lab.lock, set -C, 60 s re-check) + the hand lock (~/kerber-lab/state/lab.lock), pre-status (all four VMs shut off)
#   L1 reset kdc, services, client2, client1 to f4-mit; check --lab-only; the Fedora identity rule per VM; services' lldap; the AD DC probe
#      (lab.sh check kdc: LAN address, filter, DC :88 - reported, never fatal)
#   L2 pushes: the ship build's server programs and dist/ to the kdc (sha256 both sides), install-ours.sh, vmctl.sh
#   L3 MIT stage: cells/r3.sh --stage mit, cells/ra.sh --stage mit
#   L4 docs/install.md "Upgrading an MIT realm", literally, from the ship build (install-ours.sh); the installed programs equal the ship build
#   L5 ours stage: cells/r3.sh --stage ours, cells/ra.sh --stage ours
#   L6 parity MIT vs ours per cell (parity.py), the summary
#   L7 shred on the VMs, restore (kdc, client1 -> f4-mit; client2 -> rust-ssh; services -> services-rust-f44; all shut off), post-status = pre-status,
#      scan-secrets, the host /tmp check, publish, release the locks (all from the EXIT trap)
# Usage: bash hc.sh        (STOP_AFTER=L1|L2|L3|L4|L5 stops early and still restores; ALLOW_RUNNING_PRE=1 lets VMs be running at the start)
set -u
exec < /dev/null
SESSION=${SESSION:-fullpass-hand-r3rerun}
REPO=${REPO:?REPO is not set}
HCD=${HCD:?HCD is not set}
HC=${HC:-$HCD/rerun-r3/hc}
CELLFNS=${CELLFNS:-$HC/lib/cellfns.sh}; export CELLFNS   # countlast, tktcheck, tgtline for cells/r3.sh
SRC=${SRC:-$HCD/src}                                  # git archive of tree 242a461f (harness libs, dist/, docs/install.md)
IN=${IN:-$HCD/inputs}                                 # the proven inputs copied from the records
SHIP=${SHIP:?SHIP is not set}     # the head's frozen ship build (default features, --release --locked) of the same tree
SHIPSHA=${SHIPSHA:?SHIPSHA is not set}
SHIPSRC=${SHIPSRC:?SHIPSRC is not set}
TREE=${TREE:-242a461f3b4d7bd79487c0c030ff23d362315730}
COMMIT=${COMMIT:-84acde7c3531c8ecc78f41d2dc9f09c67bdc6aa6}
LAB=${LAB:-$REPO/harness/field/lab.sh}
LOCK=${LOCK:-/var/tmp/kr-lab.lock}
HANDLOCK=${HANDLOCK:-$HOME/kerber-lab/state/lab.lock}
VMD=/var/tmp/hand3
OUT=${OUT:-$HCD/out/r3rerun-$(date -u +%Y%m%dT%H%M%SZ)}
REC=${REC:?REC is not set}
MAX_LEG_S=${MAX_LEG_S:-1800}                           # about 30 min of lab, then stop, restore, report
HARD_STOP_EPOCH=${HARD_STOP_EPOCH:-}                   # optional wall-clock stop: past it no stage starts, the hold restores and reports
CELL_S=${CELL_S:-600}                                # one cell script's budget: its commands are cut to what is left (rec.sh FIELD_DEADLINE)
STOP_AFTER=${STOP_AFTER:-}
RESTSNAP_LEG=f4-mit
SERVER_PROGS=(krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd krb5-otp-kdc)
VMS=(kdc services client2 client1)
declare -A REST_SNAP=([kdc]=f4-mit [services]=services-rust-f44 [client2]=rust-ssh [client1]=f4-mit)
PKG_VERSION_RX='1\.22\.2-[0-9]+\.fc43'
KLIST_VERSION=1.22.2
NOTE_FALLBACK_RX='{"type":"rpm","name":"krb5","version":"[^"]*"'
BRAND_ENFORCE=${BRAND_ENFORCE:-1}
TMPDIR=$HCD/tmp/$(basename "$OUT"); export TMPDIR   # one fresh work dir per hold: a staged file of an earlier run (the ship copies are mode 0555) can never be reused
case $(realpath -m "$TMPDIR") in /tmp | /tmp/*) echo "hc.sh: TMPDIR $TMPDIR is under the host's /tmp" >&2; exit 2 ;; esac
mkdir -p "$OUT" "$TMPDIR"
LOG=$OUT/driver.log
: > "$LOG"
cd "$REPO" || exit 2   # lab.sh reaches virsh through distrobox-host-exec, which runs the host command in the caller's directory: it must exist on the host

now() { date -u +%FT%TZ; }
note() { printf '%s %s\n' "$(now)" "$*" | tee -a "$LOG"; }
# fd 9 holds the hand lock (flock): every child closes it (9>&-), so that no process left running can keep the lock after this driver has exited
lab() { note "+ lab.sh $*"; "$LAB" "$@" >> "$LOG" 2>&1; }
vm() { local v=$1; shift; timeout 900 "$LAB" ssh "$v" -- "$@" 9>&-; }
vmlog() { local v=$1; shift; note "+ ssh $v: $*"; timeout 900 "$LAB" ssh "$v" -- "$@" >> "$LOG" 2>&1 9>&-; }
redact() { python3 -B "$SRC/harness/field/lib/redact.py"; }

HAVE_LOCK=0; TOUCHED=0; RESTORED=0; LEG_RC=0; REASON=""; NFAIL=0; LOCK_T0=""; BRAND_BAD=0; PUBLISHED=0
declare -A PRE_STATE
declare -A TOUCHED_VM

take_lock() {
    until ( set -C; echo "$SESSION $$ $(now)" > "$LOCK" ) 2>/dev/null; do
        if [ -n "$HARD_STOP_EPOCH" ] && [ "$(date +%s)" -ge $(( HARD_STOP_EPOCH - 1800 )) ]; then
            note "LAB_WAIT_GIVE_UP the lab lock is still held by [$(cat "$LOCK" 2>/dev/null)] 30 min before the hard stop: no hold is started"
            REASON="the lab lock was not free before the hard stop"; exit 2
        fi
        note "LAB_WAIT held by [$(cat "$LOCK" 2>/dev/null)]; re-check in 60 s"
        sleep 60
    done
    HAVE_LOCK=1; LOCK_T0=$(now); SECONDS=0
    note "LOCK_ACQUIRED $(cat "$LOCK")"
    mkdir -p "$(dirname "$HANDLOCK")"
    exec 9> "$HANDLOCK"
    until flock -n 9; do note "HANDLOCK_WAIT $HANDLOCK is held (a hand runner or a field run); re-check in 60 s"; sleep 60; done
    note "HANDLOCK_ACQUIRED $HANDLOCK"
}
release_lock() {
    if [ "$HAVE_LOCK" = 1 ] && grep -q " $$ " "$LOCK" 2>/dev/null; then
        rm -f "$LOCK"; HAVE_LOCK=0
        exec 9>&-
        note "LOCK_RELEASED (held $LOCK_T0 to $(now))"
        echo "lab lock $SESSION: taken $LOCK_T0, released $(now)" >> "$OUT/lock-holds.txt"
    fi
}

fail() { REASON="$*"; LEG_RC=1; note "LEG_FAIL: $*"; exit 1; }
deadline() {
    [ "$SECONDS" -le "$MAX_LEG_S" ] || fail "the hold ran past its $MAX_LEG_S s deadline"
    [ -z "$HARD_STOP_EPOCH" ] || [ "$(date +%s)" -lt "$HARD_STOP_EPOCH" ] || fail "the hold ran past the hard stop ($(date -u -d "@$HARD_STOP_EPOCH" +%FT%TZ))"
}

host_tmp_snapshot() { find /tmp -maxdepth 1 -user "$(id -u)" 2>/dev/null | grep -v -e '^/tmp/claude-' -e '^/tmp/\.org\.chromium\.Chromium\.' | sort; }
host_tmp_check() {
    host_tmp_snapshot > "$OUT/host-tmp-after.txt"
    if diff -u "$OUT/host-tmp-before.txt" "$OUT/host-tmp-after.txt" > "$OUT/host-tmp.diff"; then
        note "HOST_TMP nothing new in the host's /tmp (own entries; the session's /tmp/claude-* and the browser's singleton file left out)"
    else
        note "HOST_TMP DIFFERENT (see host-tmp.diff)"; LEG_RC=1; REASON="$REASON; host /tmp changed"
    fi
}
krb5_sums() { local f; for f in /etc/krb5.conf /run/host/etc/krb5.conf; do if [ -e "$f" ]; then sha256sum "$f"; fi; done; }

# ---------------------------------------------------------------- the driver-level checks (one row per check in results.tsv)
result() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "${6:-}" | tr -d '\r' >> "$OUT/results.tsv"; }
expect() {    # expect LABEL FILE EXTENDED-REGEX [COUNT]
    local label=$1 file=$2 rx=$3 want=${4:-} n res
    n=$(grep -cE -- "$rx" "$file" 2>/dev/null || true)
    if [ -n "$want" ]; then [ "$n" = "$want" ] && res=PASS || res=FAIL
    else [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL; fi
    result "$label" "$res" "$rx" "${want:-1+}" "${n:-0}"
    note "CHECK $res $label (want ${want:-1+} of /$rx/ in $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}
expect_under() {   # expect_under LABEL FILE HEADER-RX LINE-RX [COUNT]
    local label=$1 file=$2 hdr=$3 rx=$4 want=${5:-} n res
    n=$(RX="$hdr" awk 'f && /^(==|# )/ { exit } f { print } $0 ~ ENVIRON["RX"] { f = 1 }' "$file" 2>/dev/null | grep -cE -- "$rx" || true)
    if [ -n "$want" ]; then [ "$n" = "$want" ] && res=PASS || res=FAIL
    else [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL; fi
    result "$label" "$res" "under /$hdr/: $rx" "${want:-1+}" "${n:-0}"
    note "CHECK $res $label (want ${want:-1+} of /$rx/ under /$hdr/ in $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}
expect_rpmv_config_only() {   # expect_rpmv_config_only LABEL FILE [yes|no]: every line rpm -V printed is a config file (flag c)
    local label=$1 file=$2 ost=${3:-no} lines n m=0 res
    lines=$(RX='^== sudo rpm -V ' awk 'f && /^(==|# )/ { exit } f { print } $0 ~ ENVIRON["RX"] { f = 1 }' "$file" 2>/dev/null | grep -v -E '^rpm -V rc=' | grep -v -E '^[.SM5DLUGTP?]{9} +c ' || true)
    if [ "$ost" = yes ]; then
        m=$(printf '%s\n' "$lines" | grep -c -E '^\.{7}T\. ' || true)
        lines=$(printf '%s\n' "$lines" | grep -v -E '^\.{7}T\. ' || true)
    fi
    n=$(printf '%s' "$lines" | grep -c . || true)
    [ "${n:-0}" = 0 ] && res=PASS || res=FAIL
    result "$label" "$res" "every line rpm -V printed is a config file (c)$([ "$ost" = yes ] && echo '; ostree: a lone T (mtime) is not a difference')" 0 "${n:-0}" "$([ "$ost" = yes ] && echo "$m lines with only the mtime flag, not counted")"
    note "CHECK $res $label (lines of rpm -V that are not config files: ${n:-0}$([ "$ost" = yes ] && echo "; ostree: $m mtime-only lines not counted"))"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}
info() {      # info LABEL FILE RX [NOTE]
    local label=$1 file=$2 rx=$3 n first
    n=$(grep -cE -- "$rx" "$file" 2>/dev/null || true)
    first=$(grep -m1 -E -- "$rx" "$file" 2>/dev/null | cut -c1-400 | tr '\t' ' ')
    result "$label" INFO "$rx" - "${n:-0}" "${first:-${4:-}}"
    note "INFO $label (${n:-0} of /$rx/ in $(basename "$file")): $first"
}
push() {      # push VM LOCAL REMOTE MODE: stdin to a file on the VM, sha256 checked on both sides
    local v=$1 src=$2 dst=$3 mode=$4 want got
    vm "$v" "install -d -m 0700 $VMD $(dirname "$dst") && cat > $dst && chmod $mode $dst" < "$src" >> "$LOG" 2>&1 || return 1
    want=$(sha256sum "$src" | cut -d' ' -f1)
    got=$(vm "$v" "sha256sum $dst" 2>> "$LOG" | cut -d' ' -f1)
    if [ "$want" != "$got" ]; then note "PUSH_SHA_MISMATCH $v:$dst want=$want got=$got"; return 1; fi
    note "pushed $v:$dst sha256=${want:0:16}"
}

# ---------------------------------------------------------------- restore, publish, scan
restore() {   # every VM this hold started back to its rest snapshot, shut off, post-status identical to the pre-status
    [ "$RESTORED" = 1 ] && return 0
    note "RESTORE_START"
    local v
    for v in "${VMS[@]}"; do   # best-effort shred of what the hold left (the snapshot reverts below remove it anyway)
        [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
        timeout 60 "$LAB" ssh "$v" -- "sudo shred -u $VMD/*.dump $VMD/r3-save/* 2>/dev/null; sudo shred -u /var/kerberos/krb5kdc/mit-realm.dump 2>/dev/null; true" >> "$LOG" 2>&1 9>&- || note "RESTORE: best-effort clean of $v did not run (rc=$?)"
    done
    for v in "${VMS[@]}"; do
        if [ "${TOUCHED_VM[$v]:-0}" != 1 ]; then note "RESTORE: $v was never started by this hold: left as it was"; continue; fi
        lab reset "$v" "${REST_SNAP[$v]}" || { note "RESTORE: reset $v ${REST_SNAP[$v]} rc=$?"; LEG_RC=1; REASON="$REASON; reset $v ${REST_SNAP[$v]} failed"; }
    done
    for v in "${VMS[@]}"; do   # while they are up on their rest snapshots: nothing of the hold is left on them
        [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
        { echo "# $(now) $v after the reset to ${REST_SNAP[$v]}"
          "$LAB" ssh "$v" -- "if [ -e $VMD ] || [ -e /var/tmp/hand3-ra-dropin-made ]; then echo RESIDUE_PRESENT $VMD; else echo RESIDUE_NONE $VMD; fi; \
              for f in /var/kerberos/krb5kdc/mit-realm.dump /var/tmp/r3-sshd-krb5.trace; do if sudo test -e \$f; then echo RESIDUE_PRESENT \$f; fi; done; \
              echo \"snapshot-state: \$(rpm -q krb5-libs krb5-workstation krb5-server 2>&1 | paste -sd' ' -)\"" 2>&1 < /dev/null 9>&-
        } > "$OUT/L7-residue-$v.txt"
        cat "$OUT/L7-residue-$v.txt" >> "$LOG"
        expect "L7.$v.no-residue" "$OUT/L7-residue-$v.txt" '^RESIDUE_NONE ' 1
        expect "L7.$v.no-residue-file" "$OUT/L7-residue-$v.txt" '^RESIDUE_PRESENT ' 0
    done
    for v in "${VMS[@]}"; do
        [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
        if [ "${PRE_STATE[$v]:-}" = "shut off" ]; then lab down "$v" || { note "RESTORE: down $v rc=$?"; LEG_RC=1; REASON="$REASON; down $v failed"; }; fi
    done
    "$LAB" status > "$OUT/post-status.txt" 2>> "$LOG" 9>&-
    if diff -u "$OUT/pre-status.txt" "$OUT/post-status.txt" > "$OUT/status.diff"; then
        note "RESTORE_CHECK post-status identical to pre-status"
    else
        note "RESTORE_CHECK DIFFERENT (see status.diff)"; LEG_RC=1; REASON="$REASON; post-status differs"
    fi
    RESTORED=1
    note "RESTORE_DONE"
}

make_index() {   # INDEX.txt: the first file of the record directory
    local d=$1
    {
        echo "HOLD C R3-ONLY RE-RUN of the 1.1 full pass: R3 (sshd GSSAPI client1 -> client2), MIT first, then the installed ship build; the helpers hold C's cell called undefined are defined, so its five never-run rows run (EXPECT-CHANGES.txt). Hold C's own record (the parent directory) stands as filed."
        echo "tree $TREE (commit $COMMIT, origin/f-functional; CI run 821 14/14). Every record in this directory is headed by that tree."
        echo "ship build: $(head -1 "$SHIPSRC" 2>/dev/null | cut -c1-400)"
        echo "ship programs (sha256, frozen copy): $(awk '{ printf "%s:%s ", $2, substr($1, 1, 12) }' "$SHIPSHA" 2>/dev/null)"
        echo "lab lock: $( [ -e "$OUT/lock-holds.txt" ] && tr '\n' ' ' < "$OUT/lock-holds.txt" || echo '(held; the release line is added at the end)')"
        echo "driver exit: rc=${FINAL_RC:-?} checks_failed=$NFAIL reason=[$REASON]"
        echo
        echo "cells (rc = the cell script's exit status; counts from its checks.tsv):"
        cat "$OUT/SUMMARY.tsv" 2>/dev/null | column -t -s "$(printf '\t')"
        echo
        [ -e "$OUT/NOT-RUN.txt" ] && { cat "$OUT/NOT-RUN.txt"; echo; }
        echo "files:"
        echo "  INDEX.txt SUMMARY.tsv NOT-RUN.txt PARITY.txt driver.log results.tsv pre-status.txt post-status.txt status.diff lock-holds.txt host-tmp*.txt"
        echo "  r3-mit/ r3-ours/   record.txt checks.tsv result stdout.txt (+ pcap/ logs/)"
        echo "  EXPECT-CHANGES.txt   the cell changes with the MIT record line of every expectation concerned; source-check.txt   the helper check run before the lab lock"
        echo "  L1-*.txt vm-facts-*.txt l1-check-*.txt   per VM: reset, check --lab-only, the identity rows"
        echo "  install.txt ship-on-vm.sha256 inputs-sha256.txt   the upgrade and its programs"
        echo "  scripts/   the driver and the cell scripts as run (hc.sh cells/ vmctl.sh install-ours.sh parity.py), inputs.sha256"
        echo "  scan-secrets.txt"
    } > "$d/INDEX.txt"
}

publish() {   # the records: transcripts, scripts, statuses, sha lists. No password, seed, keytab or dump.
    [ "$PUBLISHED" = 1 ] && return 0
    mkdir -p "$REC"
    if [ -n "$(find "$REC" -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then
        local old_dir
        old_dir="$REC/earlier-$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$old_dir" && find "$REC" -maxdepth 1 -type f -exec mv -t "$old_dir" {} + 2>/dev/null
    fi
    cp -rp "$OUT"/* "$REC/" 2>/dev/null
    cp -p "$HCD/rerun-r3/EXPECT-CHANGES.txt" "$REC/" 2>/dev/null
    mkdir -p "$REC/scripts" && cp -rp "$HC"/. "$REC/scripts/" 2>/dev/null
    cp -p "$HCD/inputs.sha256" "$HCD/rerun-r3/hc.sha256" "$REC/scripts/" 2>/dev/null
    make_index "$REC"
    chmod -R go-w "$REC" 2>/dev/null
    PUBLISHED=1
}
scan() {
    local rc
    cp -p "$LOG" "$REC/driver.log" 2>/dev/null
    note "SCAN_SECRETS (every lab secret, ~/adlab/env value and keytab key; the planted control first) over $REC"
    python3 -B "$SRC/harness/field/lib/scan-secrets.py" "$REC" > "$OUT/scan-secrets.txt" 2>&1; rc=$?
    cat "$OUT/scan-secrets.txt" >> "$LOG"
    cp -p "$OUT/scan-secrets.txt" "$REC/" 2>/dev/null
    note "SCAN_SECRETS rc=$rc"
    [ "$rc" = 0 ] || { LEG_RC=1; REASON="$REASON; scan-secrets failed"; }
}

finish() {    # on every exit
    local rc=$?
    [ "$LEG_RC" != 0 ] && rc=$LEG_RC
    trap - EXIT
    if [ "$HAVE_LOCK" = 1 ]; then
        [ "$TOUCHED" = 1 ] && restore
        host_tmp_check
        krb5_sums > "$OUT/krb5.conf.end" 2>/dev/null
        if diff -u "$OUT/krb5.conf.start" "$OUT/krb5.conf.end" > "$OUT/krb5.conf.diff" 2>&1; then note "GUARD /etc/krb5.conf (container and host) unchanged"; else note "GUARD /etc/krb5.conf DIFFERENT"; LEG_RC=1; REASON="$REASON; /etc/krb5.conf changed"; fi
        [ "$LEG_RC" != 0 ] && rc=$LEG_RC
        [ "$NFAIL" != 0 ] && [ "$rc" = 0 ] && rc=4
        FINAL_RC=$rc
        note "RESULT $(awk -F'\t' '{ n[$2]++ } END { printf "%d driver checks: %d PASS, %d FAIL, %d INFO", n["PASS"] + n["FAIL"], n["PASS"], n["FAIL"], n["INFO"] }' "$OUT/results.tsv" 2>/dev/null)"
        note "DRIVER_EXIT rc=$rc checks_failed=$NFAIL reason=[$REASON]"
        publish
        scan
        [ "$LEG_RC" != 0 ] && rc=$LEG_RC
        release_lock
        cp -p "$LOG" "$REC/driver.log" 2>/dev/null
        cp -p "$OUT/lock-holds.txt" "$REC/" 2>/dev/null
        make_index "$REC"
    fi
    exit "$rc"
}

# ---------------------------------------------------------------- the identity and the per-VM start
note_cmd() {   # note_cmd FILE: the command a VM runs to print FILE's ELF package note: readelf -n, else grep -a (and it says which)
    local f=$1
    cat <<EOF
if readelf -n $f > /dev/null 2>&1; then echo "(read with readelf -n)"; readelf -n $f | sed -n '/Displaying notes found in: .note.package/,/Packaging Metadata:/p'; else echo "(readelf is not usable on this VM: the same note read with grep -a)"; grep -a -o '$NOTE_FALLBACK_RX' $f | head -1 | sed 's/^/    Packaging Metadata: /'; fi
EOF
}
l1_vm() {   # l1_vm VM: reset to f4-mit, check --lab-only, the helper pushed, the facts and (kdc, clients) the MIT identity
    local v=$1 crc pk="krb5-libs krb5-workstation" nrx daemon="/usr/bin/kinit" ost
    [ "$v" = kdc ] && { pk="$pk krb5-server"; daemon=/usr/sbin/krb5kdc; }
    TOUCHED=1; TOUCHED_VM[$v]=1
    lab reset "$v" "$RESTSNAP_LEG" || fail "reset $v $RESTSNAP_LEG"
    "$LAB" check --lab-only "$v" > "$OUT/l1-check-$v.txt" 2>&1 9>&-; crc=$?
    cat "$OUT/l1-check-$v.txt" >> "$LOG"
    note "L1 check --lab-only $v rc=$crc"
    [ "$crc" = 0 ] || fail "lab.sh check --lab-only $v rc=$crc"
    vmlog "$v" "install -d -m 0700 $VMD" || fail "no ssh to $v"
    push "$v" "$HC/vmctl.sh" "$VMD/vmctl.sh" 755 || fail "push vmctl.sh to $v"
    [ "$v" = services ] && return 0   # services runs no Kerberos server or client of the leg: no identity rows
    ost=$(vm "$v" "if [ -e /run/ostree-booted ]; then echo yes; else echo no; fi" 2>> "$LOG" | tr -d '[:space:]')
    [ "$ost" = yes ] || ost=no
    {
        echo "# identity rule applied on $v: the Fedora identity rule. Fedora's build of MIT 1.22.2 carries no KRB5_BRAND string, so the release is established by"
        echo "#   (1) the ELF package note of /usr/lib64/libkrb5.so.3.3 and of $daemon: name krb5, version 1.22.2-<rel>.fc43 (readelf -n, else grep -a: the line under each header says which),"
        echo "#   (2) rpm -V $pk: only config files differ (each is listed below), (3) klist -V = Kerberos 5 version $KLIST_VERSION."
        echo "#   ostree system: $ost$([ "$ost" = yes ] && echo '. ostree gives every file one normalized mtime, so rpm -V flags each package file with T alone; a non-config file whose only flag is T is not counted as different')"
        echo "#   Each is a row that stops the hold before the MIT stage. The KRB5_BRAND grep (expected absent) and the rpm signature are recorded as INFO rows."
        vm "$v" "sudo bash $VMD/vmctl.sh facts" 2>&1
        echo "== rpm -q $pk"
        vm "$v" "rpm -q $pk" 2>&1
        echo "== test -e /run/ostree-booted"
        echo "ostree: $ost"
        echo "== readelf -n /usr/lib64/libkrb5.so.3.3 (.note.package)"
        vm "$v" "$(note_cmd /usr/lib64/libkrb5.so.3.3)" 2>&1
        echo "== readelf -n $daemon (.note.package)"
        vm "$v" "$(note_cmd $daemon)" 2>&1
        echo "== sudo rpm -V $pk"
        vm "$v" "sudo rpm -V $pk; echo \"rpm -V rc=\$?\"" 2>&1
        echo "== klist -V"
        vm "$v" "klist -V" 2>&1
        echo "== grep -a -o 'KRB5_BRAND: [^ ]*' /usr/lib64/libkrb5.so.3 | head -1"
        vm "$v" "grep -a -o 'KRB5_BRAND: [^ ]*' /usr/lib64/libkrb5.so.3 | head -1" 2>&1
        if [ "$v" = kdc ]; then
            echo "== grep -a -o 'KRB5_BRAND: [^ ]*' /usr/sbin/krb5kdc | head -1"
            vm "$v" "grep -a -o 'KRB5_BRAND: [^ ]*' /usr/sbin/krb5kdc | head -1" 2>&1
        fi
        echo "== rpm signature of krb5-libs"
        vm "$v" "rpm -q --qf 'SIGPGP: %{SIGPGP:pgpsig}\nRSAHEADER: %{RSAHEADER:pgpsig}\n' krb5-libs" 2>&1
        echo "== evidence: the library, its package, its digest and its build"
        vm "$v" "readlink -f /usr/lib64/libkrb5.so.3; rpm -qf /usr/lib64/libkrb5.so.3; sha256sum /usr/lib64/libkrb5.so.3; echo \"KRB5_BRAND strings in libkrb5.so.3: \$(grep -a -c 'KRB5_BRAND' /usr/lib64/libkrb5.so.3)\"; rpm -qi krb5-libs | grep -E '^(Version|Release|Build Date|Build Host|Signature)'" 2>&1
        if [ "$v" = kdc ]; then
            vm "$v" "rpm -qf /usr/sbin/krb5kdc; sha256sum /usr/sbin/krb5kdc; echo \"KRB5_BRAND strings in krb5kdc: \$(grep -a -c 'KRB5_BRAND' /usr/sbin/krb5kdc)\"" 2>&1
        fi
    } 2>&1 | redact > "$OUT/vm-facts-$v.txt"
    cat "$OUT/vm-facts-$v.txt" >> "$LOG"
    result "L1.$v.identity-rule" INFO "the Fedora identity rule" - 1 "package note of libkrb5 and $daemon, rpm -V config files only, klist -V; KRB5_BRAND and the rpm signature as INFO"
    info "L1.$v.brand-libkrb5" "$OUT/vm-facts-$v.txt" '^KRB5_BRAND: ' "absent in Fedora's build (expected; recorded, not judged)"
    if [ "$v" = kdc ]; then info "L1.kdc.brand-krb5kdc" "$OUT/vm-facts-kdc.txt" '^KRB5_BRAND: ' "absent in Fedora's build (expected; recorded, not judged)"; fi
    info "L1.$v.rpm-signature" "$OUT/vm-facts-$v.txt" '^(SIGPGP|RSAHEADER): ' "(no signature line)"
    info "L1.$v.package-note-tool" "$OUT/vm-facts-$v.txt" '^\((read with readelf -n|readelf is not usable)'
    nrx='Packaging Metadata: \{"type":"rpm","name":"krb5","version":"'"$PKG_VERSION_RX"'"'
    expect_under "L1.$v.package-note-libkrb5" "$OUT/vm-facts-$v.txt" '^== readelf -n /usr/lib64/libkrb5\.so\.3\.3 ' "$nrx" || BRAND_BAD=1
    if [ "$v" = kdc ]; then
        expect_under "L1.kdc.package-note-krb5kdc" "$OUT/vm-facts-kdc.txt" '^== readelf -n /usr/sbin/krb5kdc ' "$nrx" || BRAND_BAD=1
    else
        expect_under "L1.$v.package-note-kinit" "$OUT/vm-facts-$v.txt" '^== readelf -n /usr/bin/kinit ' "$nrx" || BRAND_BAD=1
    fi
    expect "L1.$v.rpm-V-ran" "$OUT/vm-facts-$v.txt" '^rpm -V rc=[0-3]$' || BRAND_BAD=1
    expect_rpmv_config_only "L1.$v.rpmV-config-only" "$OUT/vm-facts-$v.txt" "$ost" || BRAND_BAD=1
    info "L1.$v.rpmV-config-files" "$OUT/vm-facts-$v.txt" '^[.SM5DLUGTP?]{9} +c ' "(no file differs)"
    expect "L1.$v.klist-version" "$OUT/vm-facts-$v.txt" "^Kerberos 5 version ${KLIST_VERSION//./\\.}\$" || BRAND_BAD=1
    if [ "$BRAND_BAD" != 0 ]; then
        if [ "$BRAND_ENFORCE" = 1 ]; then fail "the MIT on $v is not the 1.22.2 release the hold needs (package note krb5 1.22.2-<rel>.fc43, rpm -V config files only, klist -V $KLIST_VERSION): stopping before the MIT stage (vm-facts-$v.txt)"; fi
        note "BRAND_ENFORCE=0: the identity rows stay as measured and the hold goes on"
    fi
}

# ---------------------------------------------------------------- cells
SUMMARY=$OUT/SUMMARY.tsv
printf 'cell\trc\tpass\tfail\tinfo\twall_s\tstarted\n' > "$SUMMARY"
run_cell() {   # run_cell DIRNAME SCRIPT STAGE: one cell script as a child process with its own record directory and TMPDIR
    local name=$1 script=$2 stage=$3 d=$OUT/$1 t0 rc p f i
    mkdir -p "$d" "$TMPDIR/$name"
    t0=$(date +%s)
    note "CELL $name: $script --stage $stage (budget ${CELL_S} s)"
    ( cd "$REPO" && env STAGE="$stage" REC_DIR="$d" TMPDIR="$TMPDIR/$name" HCIN="$IN" HCSRC="$SRC" LAB="$LAB" TREE="$TREE" SHIPNOTE="$SHIPNOTE" RA_PRIOR_REFUSAL="${RA_PRIOR:-}" \
        FIELD_CMD_TIMEOUT=600 FIELD_DEADLINE=$(( t0 + CELL_S )) bash "$HC/cells/$script" --stage "$stage" ) 9>&- > "$d/stdout.txt" 2>&1
    rc=$?
    p=$(awk -F'\t' '$2 == "PASS"' "$d/checks.tsv" 2>/dev/null | wc -l); f=$(awk -F'\t' '$2 == "FAIL"' "$d/checks.tsv" 2>/dev/null | wc -l); i=$(awk -F'\t' '$2 == "INFO"' "$d/checks.tsv" 2>/dev/null | wc -l)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$rc" "$p" "$f" "$i" "$(( $(date +%s) - t0 ))" "$(date -u -d "@$t0" +%FT%TZ)" >> "$SUMMARY"
    # Guards: an undefined helper or a missing row may never pass silently
    expect "cell.$name.no-undefined-commands" "$d/stdout.txt" 'command not found' 0 || true
    if [ "$script" = r3.sh ]; then
        for row in r3.3.tgt r3.4b.kdc-one-tgs r3.4d.three-logins r3.4d.acceptor-decrypts r3.6.no-kdc-line; do
            expect "cell.$name.row.$row" "$d/checks.tsv" "^${row//./\\.}[[:space:]](PASS|FAIL)[[:space:]]" 1 || true
        done
    fi
    note "CELL_DONE $name rc=$rc pass=$p fail=$f info=$i wall=$(( $(date +%s) - t0 )) s"
    if [ "$rc" = 3 ]; then   # the Windows side was unusable and the cell said so (dc-down): not run, which is not a failure of the product
        result "cell.$name" INFO "the cell script exits 0 (all its checks pass)" 0 "NOT RUN (exit 3: $(cat "$d/dc-down" 2>/dev/null))" "pass=$p fail=$f info=$i"
    else
        result "cell.$name" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" "the cell script exits 0 (all its checks pass)" 0 "$rc" "pass=$p fail=$f info=$i"
        [ "$rc" = 0 ] || NFAIL=$((NFAIL + 1))
    fi
    return 0
}

# source_check: The cell's helpers must exist before the cell can start; hold C's cell called countlast and tktcheck undefined, bash printed 'command not found', and five rows
# were never written. This runs before the lab lock and before any lab step (lib/undef-check.sh; SKIP_SOURCE_CHECK=1 exists for the rehearsal that proves the guards after the cells).
source_check() {
    local out rc=0
    if [ "${SKIP_SOURCE_CHECK:-0}" = 1 ]; then echo "hc.sh: SOURCE CHECK SKIPPED (rehearsal only)" >&2; return 0; fi
    out=$(HCSRC="$SRC" TMPDIR="$TMPDIR" bash "$HC/lib/undef-check.sh" "$HC/cells/r3.sh" "$CELLFNS" 2>&1) || rc=$?
    if [ "$rc" != 0 ]; then
        echo "hc.sh: SOURCE CHECK FAILED before any lock or lab step: $out" >&2
        { echo "SOURCE CHECK FAILED: $out"; } > "$OUT/source-check.txt"
        return 1
    fi
    echo "$out" > "$OUT/source-check.txt"
    return 0
}

# ================================================================ main
[ "${SOURCE_ONLY:-}" = 1 ] && return 0 2> /dev/null
trap finish EXIT
trap 'REASON="interrupted (SIGTERM)"; exit 143' TERM
trap 'REASON="interrupted (SIGINT)"; exit 130' INT
trap 'REASON="interrupted (SIGHUP)"; exit 129' HUP
: > "$OUT/results.tsv"
host_tmp_snapshot > "$OUT/host-tmp-before.txt"
krb5_sums > "$OUT/krb5.conf.start" 2>/dev/null

# ---- before any lock or VM: the inputs
note "RERUN_START (R3 only) tree $TREE (commit $COMMIT); driver sha256 $(sha256sum "$0" | cut -c1-16); lab.sh sha256 $(sha256sum "$LAB" | cut -c1-16)"
[ -x "$LAB" ] || { echo "hc.sh: $LAB is not executable" >&2; exit 2; }
source_check || exit 2   # before the lab lock: a missing helper stops the hold with no lab step taken
for f in hc.sh vmctl.sh install-ours.sh parity.py cells/r3.sh lib/cellfns.sh lib/undef-check.sh; do [ -e "$HC/$f" ] || { echo "hc.sh: $HC/$f is missing" >&2; exit 2; }; done
[ -d "$SRC/harness/field/lib" ] && [ -d "$SRC/dist" ] && [ -f "$SRC/docs/install.md" ] || { echo "hc.sh: $SRC is not an extraction of the tree" >&2; exit 2; }
for p in "${SERVER_PROGS[@]}"; do [ -x "$SHIP/$p" ] || { echo "hc.sh: $SHIP/$p is missing or not executable" >&2; exit 2; }; done
( cd "$SHIP" && sha256sum -c --quiet "$SHIPSHA" ) > "$OUT/ship-verify.txt" 2>&1 || { echo "hc.sh: the ship copy does not match $SHIPSHA (ship-verify.txt)" >&2; cat "$OUT/ship-verify.txt" >&2; exit 2; }
grep -q "tree $TREE" "$SHIPSRC" || { echo "hc.sh: $SHIPSRC does not say tree $TREE" >&2; exit 2; }
SHIPNOTE="ship build $(sed -n 's/.*built \([0-9TZ:-]*\);.*/\1/p' "$SHIPSRC"), default features, --release --locked, frozen copy $SHIP (sha256 list verified), dist/ and docs/install.md from the tree"
note "inputs: $SHIPNOTE"
{ echo "# sha256 of the ship programs the hold installs (SHIP=$SHIP)"; cat "$SHIPSHA"; echo "# sha256 of dist/ (tree $TREE)"; ( cd "$SRC/dist" && find . -type f | LC_ALL=C sort | xargs sha256sum ); } > "$OUT/inputs-sha256.txt"
# the secrets the hold uses must exist (names only are checked; values are never printed)
for s in mit-realm.alice.password mit-realm.bob.password mit-realm.user.password; do [ -s "$HOME/kerber-lab/secrets/$s" ] || { echo "hc.sh: ~/kerber-lab/secrets/$s is missing" >&2; exit 2; }; done
for k in AD_KBRUSER_PASSWORD AD_KRBADMIN_PASSWORD AD_KRBADMIN_USER AD_TRUST_PASSWORD; do grep -q "^$k=" "$HOME/adlab/env" || { echo "hc.sh: ~/adlab/env has no $k" >&2; exit 2; }; done
python3 -B -c 'import winrm' 2> /dev/null || { echo "hc.sh: python3 has no winrm module (pywinrm)" >&2; exit 2; }

# ================================================================ L0 lock, pre-status
take_lock
"$LAB" status > "$OUT/pre-status.txt" 2>> "$LOG" 9>&- || fail "lab.sh status"
cat "$OUT/pre-status.txt" >> "$LOG"
for v in "${VMS[@]}"; do
    if awk -v v="$v" '$1 == v' "$OUT/pre-status.txt" | grep -q 'shut off'; then PRE_STATE[$v]="shut off"
    elif awk -v v="$v" '$1 == v' "$OUT/pre-status.txt" | grep -q ' running '; then PRE_STATE[$v]=running; fi
    note "pre-state $v: [${PRE_STATE[$v]:-}]"
    [ -n "${PRE_STATE[$v]:-}" ] || fail "cannot read the state of $v from the pre-status"
    if [ "${PRE_STATE[$v]}" != "shut off" ] && [ "${ALLOW_RUNNING_PRE:-0}" != 1 ]; then fail "$v is running before the hold (ALLOW_RUNNING_PRE=1 to go on)"; fi
    snaps=$(awk -v v="$v" '$1 == v { print $NF }' "$OUT/pre-status.txt")
    for s in "$RESTSNAP_LEG" "${REST_SNAP[$v]}"; do
        case ",$snaps," in *",$s,"*) ;; *) fail "$v has no snapshot '$s' (it has: $snaps)" ;; esac
    done
done
note "snapshots: the hold runs on $RESTSNAP_LEG; rest: kdc ${REST_SNAP[kdc]}, client1 ${REST_SNAP[client1]}, client2 ${REST_SNAP[client2]}, services ${REST_SNAP[services]}; all shut off afterwards"

# ================================================================ L1 resets, checks, the identity per VM
note "L1 per VM, the kdc first: reset to $RESTSNAP_LEG, check --lab-only, the helper, the facts and the MIT identity (a failing row stops the hold)"
l1_vm kdc
l1_vm services
l1_vm client2
l1_vm client1
expect L1.kdc.mit-version "$OUT/vm-facts-kdc.txt" '^krb5-server-1\.22\.2-4\.fc43'
expect L1.kdc.services-active "$OUT/vm-facts-kdc.txt" '^active$' 2
for c in client1 client2; do
    expect "L1.$c.kinit" "$OUT/vm-facts-$c.txt" '^/usr/s?bin/kinit$'
    expect "L1.$c.host-keytab" "$OUT/vm-facts-$c.txt" "host/$c\\.kerber\\.test@KERBER\\.TEST"
    expect "L1.$c.mit-libs" "$OUT/vm-facts-$c.txt" '^krb5-libs-1\.22'
done
# the services VM: lldap answers (client1's SSSD takes alice and bob from it); up to 5 min after the reset
vm services "for i in \$(seq 1 60); do a=\$(systemctl is-active lldap | grep -c '^active\$'); [ \"\$a\" = 1 ] && break; sleep 5; done; echo \"try \$i: lldap \$(systemctl is-active lldap)\"; systemctl is-active lldap nfs-klldap-host keycloak keycloak-proxy | paste -sd' ' -" > "$OUT/L1-services-ready.txt" 2>&1
cat "$OUT/L1-services-ready.txt" >> "$LOG"
expect L1.services.lldap "$OUT/L1-services-ready.txt" '^try [0-9]+: lldap active$'
info L1.services.units "$OUT/L1-services-ready.txt" '^(in)?active( |$)' "(units)"
# the AD DC probe from the lab: kdc's LAN NIC, its filter, the DC's :88 (lab.sh check kdc, the full check; reported, never fatal)
note "L1 the full lab.sh check kdc (internet, LAN address, filter, the AD DC's :88) is not run: R3 does not need the AD DC, and this hold makes no contact with it"
# clock skew, host -> VM
{ for v in "${VMS[@]}"; do t0=$(date +%s.%N); vt=$(vm "$v" "date +%s.%N" 2>> "$LOG"); t1=$(date +%s.%N); python3 -B -I -c "import sys; t0,vt,t1=map(float,sys.argv[1:]); print('$v: VM clock minus host clock = %+.3f s (ssh round trip %.3f s)' % (vt-(t0+t1)/2, t1-t0))" "$t0" "$vt" "$t1"; done; } > "$OUT/clock-skew.txt"
cat "$OUT/clock-skew.txt" >> "$LOG"
[ "$STOP_AFTER" = L1 ] && { note "STOP_AFTER L1"; exit 0; }

# ================================================================ L2 pushes
note "L2 pushes: the ship build's server programs and dist/ (sha256 both sides), install-ours.sh"
push kdc "$HC/install-ours.sh" "$VMD/install-ours.sh" 755 || fail "push install-ours.sh"
chmod -R u+w "$TMPDIR/shiptar" 2> /dev/null; rm -rf "$TMPDIR/shiptar"   # never a leftover of an earlier run
mkdir -p "$TMPDIR/shiptar/release" || fail "mkdir the ship staging dir"
for p in "${SERVER_PROGS[@]}"; do cp -p "$SHIP/$p" "$TMPDIR/shiptar/release/$p" || fail "stage $p from the frozen ship copy"; done
cp -rp "$SRC/dist" "$TMPDIR/shiptar/dist" || fail "stage dist/"
tar -C "$TMPDIR/shiptar" -cf - release dist | vm kdc "install -d -m 0700 $VMD/ship && tar -C $VMD/ship -xf -" >> "$LOG" 2>&1 || fail "push the ship tar"
vm kdc "cd $VMD/ship/release && sha256sum ${SERVER_PROGS[*]}" > "$OUT/ship-on-vm.sha256" 2>> "$LOG"
( cd "$SHIP" && sha256sum "${SERVER_PROGS[@]}" ) > "$OUT/ship-server.sha256"
cmp -s "$OUT/ship-on-vm.sha256" "$OUT/ship-server.sha256" || fail "ship programs on the VM differ from the ship build"
note "the ship build's server programs on the VM equal the host's frozen copy (sha256, ${#SERVER_PROGS[@]} programs)"
[ "$STOP_AFTER" = L2 ] && { note "STOP_AFTER L2"; exit 0; }
deadline

# ================================================================ L3 the MIT stage on the stock f4-mit realm
note "L3 MIT stage (the stock Fedora krb5-server 1.22.2 realm): R3"
AVC_MARK=$(vm kdc "sudo bash $VMD/vmctl.sh avc-mark" 2>> "$LOG" | tr -d '[:space:]')
run_cell r3-mit r3.sh mit
deadline
[ "$STOP_AFTER" = L3 ] && { note "STOP_AFTER L3"; exit 0; }
deadline

# ================================================================ L4 install ours (docs/install.md, Upgrading an MIT realm)
note "L4 install ours (docs/install.md, Upgrading an MIT realm, from the ship build)"
AVC_MARK3=$(vm kdc "sudo bash $VMD/vmctl.sh avc-mark" 2>> "$LOG" | tr -d '[:space:]')
timeout 900 "$LAB" ssh kdc -- "sudo bash $VMD/install-ours.sh" > "$OUT/install.txt" 2>&1 9>&-; irc=$?
cat "$OUT/install.txt" >> "$LOG"
note "INSTALL rc=$irc"
[ "$irc" = 0 ] || fail "install rc=$irc"
want=$(awk '{ n = $2; sub(/^krb5-kdc$/, "krb5kdc", n); sub(/^krb5-kadmind$/, "kadmind", n); sub(/^krb5-kadmin-local$/, "kadmin.local", n); sub(/^krb5-kdb$/, "kdb5_util", n); sub(/^krb5-kprop$/, "kprop", n); sub(/^krb5-kpropd$/, "kpropd", n); if ($2 != "krb5-otp-kdc") print $1, n }' "$OUT/ship-server.sha256" | sort)
got=$(awk 'length($1) == 64 && $2 ~ /^\/usr\/sbin\// { n = $2; sub(/^\/usr\/sbin\//, "", n); print $1, n }' "$OUT/install.txt" | sort)
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "$want" > "$OUT/want-sha.txt"; echo "$got" > "$OUT/got-sha.txt"; fail "installed daemons differ from the ship build (want-sha.txt got-sha.txt)"; }
note "installed /usr/sbin programs equal the ship build sha256"
grep -q 'active: active active' "$OUT/install.txt" || fail "krb5kdc/kadmin not active after the install"
expect L4.install.restored-kdc-conf "$OUT/install.txt" '^RESTORED:/var/kerberos/krb5kdc/kdc\.conf$'
expect L4.install.requires-preauth-step "$OUT/install.txt" '^Principal ".*" modified\.$'
expect L4.install.trust-listed "$OUT/install.txt" '^krbtgt/AD\.KERBER\.TEST@KERBER\.TEST$'
expect L4.install.user-listed "$OUT/install.txt" '^user@KERBER\.TEST$'
[ "$STOP_AFTER" = L4 ] && { note "STOP_AFTER L4"; exit 0; }
deadline

# ================================================================ L5 ours stage
note "L5 ours stage (the ship build as the realm's KDC): R3"
run_cell r3-ours r3.sh ours
{ echo "== $(now) after the ours stage"; vm kdc "rpm -qf /usr/sbin/kadmind; systemctl is-active krb5kdc kadmin httpd; rpm -q krb5-libs; sudo ss -H -lnt 'sport = :749'; sudo ss -H -lntu 'sport = :464'; sudo bash $VMD/vmctl.sh avc $AVC_MARK3" 2>&1; } | redact > "$OUT/vm-facts-ours.txt"
cat "$OUT/vm-facts-ours.txt" >> "$LOG"
expect L5.kdc.active "$OUT/vm-facts-ours.txt" '^active$' 3
info L5.kdc.avc "$OUT/vm-facts-ours.txt" 'AVC|no AVC' "(none)"
{ echo "== AVC records on kdc since the MIT stage began"; vm kdc "sudo bash $VMD/vmctl.sh avc $AVC_MARK; getenforce" 2>&1; } | redact > "$OUT/L5-kdc-avc-whole-hold.txt"
cat "$OUT/L5-kdc-avc-whole-hold.txt" >> "$LOG"
expect L5.kdc.no-avc-whole-hold "$OUT/L5-kdc-avc-whole-hold.txt" 'no AVC'
[ "$STOP_AFTER" = L5 ] && { note "STOP_AFTER L5"; exit 0; }

# ================================================================ L6 parity
{
    echo "What did not run, and why (every line is a note the cell scripts wrote into their records):"
    grep -h -i -E 'NOT RUN|is not run|not run:' "$OUT"/r3-*/record.txt "$OUT"/ra-*/record.txt 2> /dev/null | sed -e 's/^# //' | sort -u
    for d in "$OUT"/ra-mit "$OUT"/ra-ours; do [ -s "$d/dc-down" ] && echo "$(basename "$d"): Windows side unusable: $(cat "$d/dc-down")"; done
} > "$OUT/NOT-RUN.txt"
cat "$OUT/NOT-RUN.txt" >> "$LOG"
note "L6 parity per cell, MIT vs ours"
python3 -B "$HC/parity.py" "$OUT" r3 > "$OUT/PARITY.txt" 2>> "$LOG"; note "PARITY rc=$?"
head -n 60 "$OUT/PARITY.txt" >> "$LOG"

# ================================================================ L7 (the EXIT trap restores, publishes and scans)
note "L7 shred on the VMs, restore, publish, scan, release (from the EXIT trap)"
exit 0
