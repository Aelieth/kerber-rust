#!/bin/bash
# driver-b2.sh: B2, the extra lab hold of the 1.1 full pass: the section-F packages whose VM legs were transcript-only and do not carry to tree 242a461f (commit 84acde7c),
# re-run on the final tree in ONE hold, MIT realm first. The shell below is hold B's combined driver (sha256 d05fcc8af9de9584, 1512 lines) with the RA r4 / KA / OTP / P16a / P8 stages and their
# inputs taken out and the module hooks put in; the modules (mod/<pkg>.sh) hold the packages' cells.
#   TREE=<tree id> SHIP=<dir with the built programs> DIST=<checkout with dist/, docs/install.md and harness/field/baseline.env> [B2_MODULES=bl,pg7 B2_SKIP=p6l] bash driver-b2.sh
#   L0 lock + pre-status | L1 reset kdc, client2, client1 to f4-mit, check --lab-only each, the Fedora identity rule per VM (a failing row stops the leg here), our kinit, klist, kvno, kpasswd and
#      kdestroy on the clients (sha256 both sides), the VMs' pristine config recorded | L2 pushes (the ship build's server programs and dist/, then every module's <pkg>_push), facts
#   L3 the MIT stage on the stock f4-mit realm: every module's <pkg>_mit, in the module order | L4 docs/install.md "Upgrading an MIT realm", literally, from the ship build (dump, dnf remove, install.sh,
#      load, the requires_preauth step), the installed programs equal the ship build | L5 every module's <pkg>_ours | L6 every module's <pkg>_parity (MIT against ours per cell, with controls)
#   L7 every module's <pkg>_clean, shred on the VMs, restore (kdc and client1 to f4-mit, client2 to rust-ssh, all shut off; services is not used and not started: services-rust), post-status = pre-status,
#      scan-secrets twice, the host /tmp check, release the locks
# Start it with setsid (its own process group) and abort it with `kill -TERM -- -<PGID>`: the TERM trap kills every process of the run (found by a token in its environment: a `timeout` command runs in a group of its own), then runs the restore (the modules' clean, shred on the VMs, reset to the rest snapshots, the scans);
# a bare `kill <pid>` reaches only the shell. `bash driver-b2.sh --check-modules` runs the module hygiene checks alone (no lab, no lock) and exits 4 when a module fails; the same checks run before the
# lock in every hold, and a module that fails them is NOT-RUN (a <PKG>.check.* row says which rule). Rehearse the whole set on the fake lab first (rehearse-b2/b2-admin/flowtest-b2.sh all).
# Module order (survey section 6, and INTERFACE-CHANGES.md): bl pg1 pg2 pg3 pl p6g pg6 pg7 p8e p16ae p15b p6b ki kp p6l dn kl ks d3. ORDER fix: ks and d3 appended, matching ORDER-CHANGE.txt; the working copy's line was still the short list. B2_MODULES (comma or space separated; default: every module file present) selects, B2_SKIP drops (a NOT-RUN row each);
# a module in the order without a file is a NOT-RUN row too. B2_EXTRA names modules beyond the order (the template is `tpl`: mod/TEMPLATE.sh). After every <pkg>_mit and <pkg>_ours the shell records
# the VMs' state (daemons active, SELinux enforcing, the config files as L1 found them): a module hands the VMs back as it found them, or its rows go red.
# VMs only through harness/field/lab.sh. The lab lock /var/tmp/kr-lab.lock (set -C) is held for the whole VM hold. The lab passwords, the leg's throwaway passwords and the keytabs never enter a record: they
# live under $SECD on the host or on a VM, and travel on ssh stdin only (alice_pw prints the MIT realm's alice password for a pipe; ADMIN_SECRET is the admin/admin password's file).
# Environment (the rehearsals use the rest): LAB W OUT REC LOCK HANDLOCK VMD SECD REALM KT SVC HOSTPRINC1 HOSTPRINC2 STOP_AFTER (L1 L2 L3 L4 L5 L6) REST_SNAP_KDC REST_SNAP_CLIENT1 REST_SNAP_CLIENT2
# ALLOW_RUNNING_PRE MAX_LEG_S ADMIN_SECRET ALICE_SECRET ALICE_TEMP_SECRET B2_MODULES B2_SKIP B2_EXTRA STAND_IN (1: the MIT stage runs against our programs because the host has no MIT krb5-server: rehearsals only).
set -u
exec < /dev/null
SESSION=full-lab-B2
REPO=${REPO:?REPO is not set}
SCRIPTS=${SCRIPTS:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}   # scripts-b2: mod/ helpers/ otp/ beside this file
TREE=${TREE:-}                                      # the tree id the checkout DIST must be (a prefix is enough)
SHIP=${SHIP:-}                                      # the built programs: a cargo release directory or a frozen copy of the programs
DIST=${DIST:-}                                      # the checkout whose dist/, docs/install.md and harness/field/baseline.env the hold uses
ADMIN_SECRET=${ADMIN_SECRET:-$HOME/kerber-lab/secrets/mit-realm.admin-admin.password}   # the lab realm's admin/admin password (stdin only)
ALICE_SECRET=${ALICE_SECRET:-}                      # the MIT realm's alice password file; empty: the name baseline.env gives it (MIT_SECRET_ALICE) under ~/kerber-lab/secrets
ALICE_TEMP_SECRET=${ALICE_TEMP_SECRET:-}            # MIT_SECRET_ALICE_TEMP: the password alice is changed to
LAB=${LAB:-$REPO/harness/field/lab.sh}
W=${W:?W is not set}
OUT=${OUT:-$W/out-$(date -u +%Y%m%dT%H%M%SZ)}
REC=${REC:?REC is not set}
LOCK=${LOCK:-/var/tmp/kr-lab.lock}
HANDLOCK=${HANDLOCK:-$HOME/kerber-lab/state/lab.lock}
VMD=${VMD:-/var/tmp/otp3}                           # the leg's directory on every VM (install-ours.sh reads the ship build from here)
SECD=${SECD:?SECD is not set}
SCANHOME=$SECD/scanhome
REALM=${REALM:-KERBER.TEST}
RRX=${REALM//./\\.}                                # the realm as a regular expression
KT=${KT:-/etc/krb5.keytab}                         # the clients' host keytab
SVC=${SVC:-host/client2.kerber.test@$REALM}        # a service of the realm, for kvno
# The MIT identity of a lab VM (the git authority asked for the brand; Fedora's build of MIT carries no KRB5_BRAND string, so the Director settled
# the Fedora identity rule): the ELF package note of libkrb5 and of the daemon (krb5kdc on the kdc, kinit on a client) names krb5 1.22.2-<rel>.fc43,
# rpm -V lists config files only, klist -V says Kerberos 5 version 1.22.2. A row that fails stops the leg before the MIT stage.
PKG_VERSION_RX='1\.22\.2-[0-9]+\.fc43'
KLIST_VERSION=${KLIST_VERSION:-1.22.2}
NOTE_FALLBACK_RX='{"type":"rpm","name":"krb5","version":"[^"]*"'   # grep -a form of the note, for a VM whose readelf does not run
BRAND_ENFORCE=${BRAND_ENFORCE:-1}              # 1: a row that fails stops the leg before the MIT stage; 0 (only when the Director says so): the rows stay as measured and the leg goes on
RESTSNAP_LEG=f4-mit                                # what L1 resets the three VMs to
MAX_LEG_S=${MAX_LEG_S:-7200}
STAND_IN=${STAND_IN:-0}
SERVER_PROGS=(krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd krb5-otp-kdc)   # the server seven: copied to the kdc (install.sh needs six; the embedder rides along as in hold B)
CLIENT_PROGS=(krb5-kinit krb5-klist krb5-kvno krb5-kdestroy krb5-kpasswd)                              # the client five: all five go to the clients ($VMD/ours/kinit, klist, kvno, kdestroy, kpasswd)
export TMPDIR=${DRIVER_TMPDIR:?DRIVER_TMPDIR is not set}
case $(realpath -m "$TMPDIR") in /tmp|/tmp/*) echo "driver-b2.sh: TMPDIR $TMPDIR is under the host's /tmp" >&2; exit 2 ;; esac
LOG=${LOG:-$OUT/driver.log}
mkdir -p "$OUT" "$TMPDIR"
: > "$LOG"
# lab.sh reaches virsh through distrobox-host-exec, which runs the host command in the caller's directory: it must exist on the host.
cd "$REPO" || exit 2

now() { date -u +%FT%TZ; }
note() { printf '%s %s\n' "$(now)" "$*" | tee -a "$LOG"; }
lab() { note "+ lab.sh $*"; timeout "${LAB_TMO:-900}" "$LAB" "$@" >> "$LOG" 2>&1; }   # reset and down included: a wedged lab call must not hold the lock for ever
vm() { local v=$1; shift; timeout "${VM_TMO:-900}" "$LAB" ssh "$v" -- "$@"; }
vmlog() { local v=$1; shift; note "+ ssh $v: $*"; timeout "${VM_TMO:-900}" "$LAB" ssh "$v" -- "$@" >> "$LOG" 2>&1; }
redact() {   # the lab filter, then the same filter over this leg's own secrets (the throwaway passwords)
    python3 -B "$REPO/harness/field/lib/redact.py" | KERBER_LAB_HOME="$SCANHOME" FIELD_ADLAB_ENV=/dev/null python3 -B "$REPO/harness/field/lib/redact.py"
}

SECRETS_MADE=0; HAVE_LOCK=0; TOUCHED=0; RESTORED=0; CLEANED=0; LEG_RC=0; REASON=""; STOP_AFTER=${STOP_AFTER:-}; NFAIL=0; LOCK_T0=""; BRAND_BAD=0
declare -A PRE_STATE
declare -A TOUCHED_VM          # VMs this leg has reset: only those are reverted again (a VM the leg never started is left as it was)
VMS=(kdc client2 client1)          # the reset order
CLIENTS=(client1 client2)          # the cell order
declare -A HOSTPRINC=([client1]="${HOSTPRINC1:-host/client1.kerber.test@$REALM}" [client2]="${HOSTPRINC2:-host/client2.kerber.test@$REALM}")
# where each VM rests when the leg is over (the Director: client2 is on rust-ssh, not f4-mit); every VM is shut off then
declare -A REST_SNAP=([kdc]="${REST_SNAP_KDC:-f4-mit}" [client1]="${REST_SNAP_CLIENT1:-f4-mit}" [client2]="${REST_SNAP_CLIENT2:-rust-ssh}")

# ---- the B2 machinery's state (the functions are further down)
B2_ORDER=(bl pg1 pg2 pg3 pl p6g pg6 pg7 p8e p16ae p15b p6b ki kp p6l dn kl ks d3)   # the module order (survey section 6): PG7 crashes MIT's kadmind and restores it; P8E (ours stage only) follows the other kdc modules; P16a-edges' FIFO cell is last on the kdc; P15b and P6b follow every kadmind restart; P6l's glibc step is last on client2; DN and KL (private resolver, DNS stub) run last
B2_MODS=()                                           # the modules that run, in order
B2_NOTRUN=()                                         # "pkg:reason" for each module of the order that does not run
B2_RESIDUE_PATHS=()                                  # paths a module may leave on a VM (outside $VMD): checked gone after the reset to the rest snapshot (a module appends in its file or its _prep)

take_lock() {
    until ( set -C; echo "$SESSION $$ $(now)" > "$LOCK" ) 2>/dev/null; do
        note "LAB_WAIT held by [$(cat "$LOCK" 2>/dev/null)]; re-check in 60 s"
        sleep 60
    done
    HAVE_LOCK=1; LOCK_T0=$(now); SECONDS=0   # the deadline counts the hold, not the wait
    note "LOCK_ACQUIRED $(cat "$LOCK")"
    # the README's hand-runner lock, so that no field run starts under this leg
    mkdir -p "$(dirname "$HANDLOCK")"
    exec 9> "$HANDLOCK"
    until flock -n 9; do note "HANDLOCK_WAIT $HANDLOCK is held (a hand runner or a field run); re-check in 60 s"; sleep 60; done
    note "HANDLOCK_ACQUIRED $HANDLOCK"
}
release_lock() {
    if [ "$HAVE_LOCK" = 1 ] && grep -q " $$ " "$LOCK" 2>/dev/null; then
        rm -f "$LOCK"; HAVE_LOCK=0
        flock -u 9 2> /dev/null; exec 9>&-      # unlock first: a child that inherited fd 9 shares the lock's open file description, so closing the shell's copy alone would leave the flock held
        note "LOCK_RELEASED (held $LOCK_T0 to $(now))"
        echo "lab lock $SESSION: taken $LOCK_T0, released $(now)" >> "$OUT/lock-holds.txt"
    fi
}

restore() {   # reset the VMs this leg started to their rest snapshots, shut them off, post-status identical to the pre-status
    [ "$RESTORED" = 1 ] && return 0
    note "RESTORE_START"
    local v rp="${B2_RESIDUE_PATHS[*]:-}"
    if [ "$CLEANED" = 0 ]; then   # the leg stopped early: shred what it left on the VMs before the snapshots are reverted (60 s a call: a wedged VM must not hold the restore)
        local VM_TMO=60 CELL_TMO=60
        for v in "${VMS[@]}"; do
            [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
            timeout 60 "$LAB" ssh "$v" -- "sudo bash $VMD/vmctl.sh clean" >> "$LOG" 2>&1 || note "RESTORE: best-effort clean on $v did not run (rc=$?)"
        done
        b2_clean_hooks best-effort
        if [ "${TOUCHED_VM[kdc]:-0}" = 1 ]; then
            timeout 60 "$LAB" ssh kdc -- "sudo shred -u /var/kerberos/krb5kdc/mit-realm.dump 2>/dev/null; true" >> "$LOG" 2>&1 || note "RESTORE: best-effort shred of the dump did not run (rc=$?)"
        fi
    fi
    for v in "${VMS[@]}"; do
        if [ "${TOUCHED_VM[$v]:-0}" != 1 ]; then note "RESTORE: $v was never started by this leg: left as it was"; continue; fi
        lab reset "$v" "${REST_SNAP[$v]}" || { note "RESTORE: reset $v ${REST_SNAP[$v]} rc=$?"; LEG_RC=1; REASON="$REASON; reset $v ${REST_SNAP[$v]} failed"; }
    done
    # while they are up on their rest snapshots: nothing of the leg is left on them
    for v in "${VMS[@]}"; do
        [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
        { echo "# $(now) $v after the reset to ${REST_SNAP[$v]}"
          timeout 120 "$LAB" ssh "$v" -- "n=0; for f in $VMD /var/kerberos/krb5kdc/kdc.conf.otp3-orig /var/kerberos/krb5kdc/mit-realm.dump $rp; do if sudo test -e \$f; then echo RESIDUE_PRESENT \$f; n=1; fi; done; \
              [ \$n = 0 ] && echo \"RESIDUE_NONE $VMD $rp\"; \
              echo \"snapshot-state: \$(rpm -q krb5-libs krb5-workstation krb5-server 2>&1 | paste -sd' ' -)\"" 2>&1 < /dev/null
        } > "$OUT/L4-residue-$v.txt"
        cat "$OUT/L4-residue-$v.txt" >> "$LOG"
        expect "L4.$v.no-residue" "$OUT/L4-residue-$v.txt" '^RESIDUE_NONE ' 1
        expect "L4.$v.no-residue-file" "$OUT/L4-residue-$v.txt" '^RESIDUE_PRESENT ' 0
    done
    for v in "${VMS[@]}"; do
        [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
        if [ "${PRE_STATE[$v]:-}" = "shut off" ]; then lab down "$v" || { note "RESTORE: down $v rc=$?"; LEG_RC=1; REASON="$REASON; down $v failed"; }; fi
    done
    timeout 120 "$LAB" status > "$OUT/post-status.txt" 2>> "$LOG"
    if diff -u "$OUT/pre-status.txt" "$OUT/post-status.txt" > "$OUT/status.diff"; then
        note "RESTORE_CHECK post-status identical to pre-status"
    else
        note "RESTORE_CHECK DIFFERENT (see status.diff)"; LEG_RC=1; REASON="$REASON; post-status differs"
    fi
    RESTORED=1
    note "RESTORE_DONE"
}

finish() {    # on every exit
    local rc=$?
    [ "$LEG_RC" != 0 ] && rc=$LEG_RC
    trap - EXIT
    if [ "$HAVE_LOCK" = 1 ]; then
        [ "$TOUCHED" = 1 ] && restore
        host_tmp_check
        publish
        scan
        host_secrets_shred
        [ "$LEG_RC" != 0 ] && rc=$LEG_RC
        release_lock
    elif [ "$SECRETS_MADE" = 1 ]; then
        host_secrets_shred
    fi
    [ "$NFAIL" != 0 ] && [ "$rc" = 0 ] && rc=4
    note "RESULT $(awk -F'\t' '{ n[$2]++ } END { printf "%d checks: %d PASS, %d FAIL, %d INFO", n["PASS"] + n["FAIL"], n["PASS"], n["FAIL"], n["INFO"] }' "$OUT/results.tsv" 2>/dev/null) (results.tsv)"
    note "DRIVER_EXIT rc=$rc checks_failed=$NFAIL reason=[$REASON]"
    cp -p "$LOG" "$REC/driver.log" 2>/dev/null
    [ -e "$OUT/lock-holds.txt" ] && cp -p "$OUT/lock-holds.txt" "$REC/" 2>/dev/null
    exit "$rc"
}

fail() { REASON="$*"; LEG_RC=1; note "LEG_FAIL: $*"; exit 1; }
deadline() { [ "$SECONDS" -le "$MAX_LEG_S" ] || fail "the leg ran past its $MAX_LEG_S s deadline"; }

# The session's own /tmp/claude-* and /tmp/grok-file-lock-*, and Chromium's rotating files, are not this leg's.
# D12: also skip the undotted Chromium dirs, and count only additions. A removal is INFO.
host_tmp_snapshot() { find /tmp -maxdepth 1 -user "$(id -u)" 2>/dev/null | grep -v -e '^/tmp/claude-' -e '^/tmp/grok-file-lock-' -e '^/tmp/\.org\.chromium\.Chromium\.' -e '^/tmp/org\.chromium\.Chromium\.' | sort; }
host_tmp_check() {
    host_tmp_snapshot > "$OUT/host-tmp-after.txt"
    comm -13 "$OUT/host-tmp-before.txt" "$OUT/host-tmp-after.txt" > "$OUT/host-tmp-added.txt"
    comm -23 "$OUT/host-tmp-before.txt" "$OUT/host-tmp-after.txt" > "$OUT/host-tmp-removed.txt"
    {
        if [ -s "$OUT/host-tmp-removed.txt" ]; then
            echo "HOST_TMP removed:"
            sed 's/^/-/' "$OUT/host-tmp-removed.txt"
        fi
        if [ -s "$OUT/host-tmp-added.txt" ]; then
            echo "HOST_TMP added:"
            sed 's/^/+/' "$OUT/host-tmp-added.txt"
        fi
    } > "$OUT/host-tmp.diff"
    if [ -s "$OUT/host-tmp-added.txt" ]; then
        note "HOST_TMP DIFFERENT (see host-tmp.diff)"; LEG_RC=1; REASON="$REASON; host /tmp changed"
    else
        note "HOST_TMP nothing new in the host's /tmp (own entries, /tmp/claude-* and /tmp/grok-file-lock-* left out)"
        [ -s "$OUT/host-tmp-removed.txt" ] && note "HOST_TMP removed: $(wc -l < "$OUT/host-tmp-removed.txt") entries (INFO, not a fail)"
    fi
}

host_secrets_shred() {   # the leg's throwaway passwords on the host and their copies for the scan: shredded once the scan has used them
    local f
    for f in "$SECD"/b2-*.pw "$SCANHOME"/secrets/*; do
        [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }
    done
    note "HOST_SECRETS shredded under $SECD ($(find "$SECD" -type f 2>/dev/null | wc -l) files left)"
}

publish() {   # the records: transcripts, scripts (modules and helpers with them), statuses, sha lists. No password, keytab or dump.
    mkdir -p "$REC"
    cp -rp "$OUT"/* "$REC/" 2>/dev/null
    local f
    mkdir -p "$REC/scripts" && cp -rp "$SCRIPTS"/* "$REC/scripts/" 2>/dev/null
    for f in ship-sha256.txt dist-sha256.txt ship-source.txt; do [ -e "$W/$f" ] && cp -p "$W/$f" "$REC/"; done
    chmod -R go-w "$REC" 2>/dev/null
}

scan() {
    local rc
    cp -p "$LOG" "$REC/driver.log" 2>/dev/null
    note "SCAN_SECRETS (the lab secrets) $REC"
    python3 -B "$REPO/harness/field/lib/scan-secrets.py" "$REC" >> "$LOG" 2>&1; rc=$?
    note "SCAN_SECRETS lab rc=$rc"
    [ "$rc" = 0 ] || { LEG_RC=1; REASON="$REASON; scan-secrets (lab secrets) failed"; }
    note "SCAN_SECRETS (this leg's throwaway passwords) $REC"
    KERBER_LAB_HOME="$SCANHOME" FIELD_ADLAB_ENV=/dev/null python3 -B "$REPO/harness/field/lib/scan-secrets.py" "$REC" >> "$LOG" 2>&1; rc=$?
    note "SCAN_SECRETS leg rc=$rc"
    [ "$rc" = 0 ] || { LEG_RC=1; REASON="$REASON; scan-secrets (leg secrets) failed"; }
    cp -p "$LOG" "$REC/driver.log"
}

# ---------------------------------------------------------------- helpers
push() {      # push VM LOCAL REMOTE MODE: stdin to a file on the VM, sha256 checked on both sides
    local v=$1 src=$2 dst=$3 mode=$4 want got
    vm "$v" "install -d -m 0700 $VMD $(dirname "$dst") && cat > $dst && chmod $mode $dst" < "$src" >> "$LOG" 2>&1 || return 1
    want=$(sha256sum "$src" | cut -d' ' -f1)
    got=$(vm "$v" "sha256sum $dst" 2>> "$LOG" | cut -d' ' -f1)
    if [ "$want" != "$got" ]; then note "PUSH_SHA_MISMATCH $v:$dst want=$want got=$got"; return 1; fi
    note "pushed $v:$dst sha256=${want:0:16}"
}

result() {    # result LABEL PASS|FAIL|INFO RX WANT GOT [TEXT]: one row of results.tsv
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "${6:-}" | tr -d '\r' >> "$OUT/results.tsv"
}

expect() {    # expect LABEL FILE EXTENDED-REGEX [COUNT]: PASS when the file has a matching line (or exactly COUNT of them); status 0 on PASS
    local label=$1 file=$2 rx=$3 want=${4:-} n res
    n=$(grep -cE -- "$rx" "$file" 2>/dev/null || true)
    if [ -n "$want" ]; then [ "$n" = "$want" ] && res=PASS || res=FAIL
    else [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL; fi
    result "$label" "$res" "$rx" "${want:-1+}" "${n:-0}"
    note "CHECK $res $label (want ${want:-1+} of /$rx/ in $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

expect_order() {   # expect_order LABEL FILE RX1 RX2 ...: a line for RX1, a LATER line for RX2, a still later one for RX3 ...
    local label=$1 file=$2 rx ln last=0 res=PASS got="" all=""
    shift 2
    for rx in "$@"; do
        all="$all${all:+ < }$rx"
        ln=$(RX="$rx" awk -v start="$last" '(NR > start) && ($0 ~ ENVIRON["RX"]) { print NR; exit }' "$file" 2>/dev/null)
        if [ -z "$ln" ]; then res=FAIL; got="$got none-for[$rx]"; break; fi
        got="$got $ln"; last=$ln
    done
    result "$label" "$res" "$all" "in order" "${got# }"
    note "CHECK $res $label (in order: $all; lines ${got# } of $(basename "$file"))"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

expect_adjacent() {   # expect_adjacent LABEL FILE RX1 RX2: a line for RX1 immediately followed by a line for RX2
    local label=$1 file=$2 rx1=$3 rx2=$4 n res
    n=$(RX1="$rx1" RX2="$rx2" awk 'prev && ($0 ~ ENVIRON["RX2"]) { c++ } { prev = ($0 ~ ENVIRON["RX1"]) } END { print c + 0 }' "$file" 2>/dev/null)
    [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL
    result "$label" "$res" "$rx1 / next line: $rx2" "1+" "${n:-0}"
    note "CHECK $res $label (adjacent lines /$rx1/ then /$rx2/ in $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

expect_under() {   # expect_under LABEL FILE HEADER-RX LINE-RX [COUNT]: LINE-RX matches in the lines under the first line that matches HEADER-RX (up to the next "==" or "# " line)
    local label=$1 file=$2 hdr=$3 rx=$4 want=${5:-} n res
    n=$(RX="$hdr" awk 'f && /^(==|# )/ { exit } f { print } $0 ~ ENVIRON["RX"] { f = 1 }' "$file" 2>/dev/null | grep -cE -- "$rx" || true)
    if [ -n "$want" ]; then [ "$n" = "$want" ] && res=PASS || res=FAIL
    else [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL; fi
    result "$label" "$res" "under /$hdr/: $rx" "${want:-1+}" "${n:-0}"
    note "CHECK $res $label (want ${want:-1+} of /$rx/ under /$hdr/ in $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

expect_rpmv_config_only() {   # expect_rpmv_config_only LABEL FILE [yes|no]: every line rpm -V printed is a config file (flag c): no binary or library differs.
    # On an ostree system (3rd argument yes) every file has the same normalized mtime, so rpm -V flags each package file with T alone (".......T."): such a line says only
    # that the mtime is not the package's, with size, digest, mode, owner and link equal, and is not counted. Any other flag on a non-config file is.
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

info() {      # info LABEL FILE RX [NOTE]: not a judgement: the number of matching lines and the first of them (NOTE when there is none)
    local label=$1 file=$2 rx=$3 n first
    n=$(grep -cE -- "$rx" "$file" 2>/dev/null || true)
    first=$(grep -m1 -E -- "$rx" "$file" 2>/dev/null | cut -c1-400 | tr '\t' ' ')
    result "$label" INFO "$rx" - "${n:-0}" "${first:-${4:-}}"
    note "INFO $label (${n:-0} of /$rx/ in $(basename "$file")): $first"
}

klog_size()    { vm kdc "sudo bash $VMD/vmctl.sh klog-size" 2>> "$LOG" < /dev/null | tr -d '[:space:]'; }
klog_since()   { vm kdc "sudo bash $VMD/vmctl.sh klog-since $1" 2>> "$LOG" < /dev/null; }
alog_size()    { vm kdc "sudo bash $VMD/b2ctl.sh alog-size" 2>> "$LOG" < /dev/null | tr -d '[:space:]'; }
alog_since()   { vm kdc "sudo bash $VMD/b2ctl.sh alog-since $1" 2>> "$LOG" < /dev/null; }

cell_rc() { sed -n 's/^\[rc=\([0-9]*\)\]$/\1/p' "$OUT/$1.txt" | head -1; }
cell() {      # cell NAME VM REMOTE-COMMAND [kdc|kdc+kadmin|none]: the command runs with the caller's stdin; transcript -> $OUT/NAME.txt (NAME may be <pkg>/mit-<cell>); the log parts: the KDC log lines the cell added
    # (default), and the kadmind log's too (kdc+kadmin), or none. The command should print "[rc=N]" itself (cell_rc reads it): `cmd; echo "[rc=$?]"`.
    local name=$1 vmn=$2 cmd=$3 logs=${4:-kdc} in f="$OUT/$1.txt" km="" am=""
    in=$(cat)
    [ "$logs" != none ] && km=$(klog_size)
    [ "$logs" = "kdc+kadmin" ] && am=$(alog_size)
    {
        echo "# cell $name on $vmn at $(now)"
        echo "# \$ $cmd"
        echo "# stdin: $( [ -n "$in" ] && echo "$(printf '%s\n' "$in" | wc -l) line(s), not recorded" || echo none )"
        printf '%s\n' "$in" | timeout "${CELL_TMO:-300}" "$LAB" ssh "$vmn" -- "$cmd" 2>&1
        echo "# end of cell output"
    } | redact > "$f"
    if [ "$logs" != none ]; then
        {
            echo
            echo "# KDC log lines added by this cell (/var/log/krb5kdc.log on kdc)"
            klog_since "$km"
            if [ -n "$am" ]; then echo; echo "# kadmind log lines added by this cell (/var/log/kadmind.log on kdc)"; alog_since "$am"; fi
        } | redact >> "$f"
    fi
    note "CELL $name ($vmn) rc=$(cell_rc "$name") -> $(basename "$f")"
}

restart_cell() {   # restart_cell NAME VM-COMMAND: a service or embedder (re)start on the kdc; the command prints its state and "# KDC log lines added by this cell" itself
    local name=$1 cmd=$2 f="$OUT/$1.txt"
    {
        echo "# cell $name on kdc at $(now)"
        echo "# \$ $cmd"
        timeout "${CELL_TMO:-300}" "$LAB" ssh kdc -- "$cmd" 2>&1 < /dev/null
        echo "# end of cell output"
    } | redact > "$f"
    cat "$f" >> "$LOG"
    note "RESTART_CELL $name -> $(basename "$f")"
}

kadm() {      # kadm NAME 'kadmin.local command' : on the kdc, output to $OUT/NAME.txt
    local name=$1 line=$2
    { echo "# $name at $(now)"; echo "# kadmin.local -q '$line'"; printf '%s\n' "$line" | vm kdc "sudo bash $VMD/vmctl.sh kadm" 2>&1; } | redact > "$OUT/$name.txt"
    note "KADM $name: $(tail -1 "$OUT/$name.txt")"
}

set_conf() {  # set_conf NAME STANZA-FUNCTION: kdc.conf := the original + the stanza (none for "true" or an empty function); the diff is the record
    local name=$1 fn=$2
    { echo "# $name at $(now)"; "$fn" | vm kdc "sudo bash $VMD/vmctl.sh conf-otp-set" 2>&1; } | redact > "$OUT/$name.txt"
    cat "$OUT/$name.txt" >> "$LOG"
}

# ---------------------------------------------------------------- what the kinit prints on stdout, byte for byte (the prompts end in a newline when stdin is not a terminal)
sha_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

expect_part() {   # expect_part LABEL FILE client|kdc|kadmin EXTENDED-REGEX [COUNT]: expect on one part of a cell file: the client's output, the KDC's log lines, the kadmind log's lines
    local label=$1 file=$2 part=$3 rx=$4 want=${5:-} n res
    n=$( { case $part in
               client) sed -n '1,/^# end of cell output/p' "$file" ;;
               kdc) sed -n '/^# KDC log lines added/,/^# kadmind log lines/p' "$file" ;;
               kadmin) sed -n '/^# kadmind log lines added/,$p' "$file" ;;
           esac; } 2>/dev/null | grep -cE -- "$rx" || true)
    if [ -n "$want" ]; then [ "$n" = "$want" ] && res=PASS || res=FAIL
    else [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL; fi
    result "$label" "$res" "[$part] $rx" "${want:-1+}" "${n:-0}"
    note "CHECK $res $label (want ${want:-1+} of /$rx/ in the $part part of $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

note_cmd() {   # note_cmd FILE: the command a VM runs to print FILE's ELF package note: readelf -n, else grep -a (and it says which)
    local f=$1
    cat <<EOF
if readelf -n $f > /dev/null 2>&1; then echo "(read with readelf -n)"; readelf -n $f | sed -n '/Displaying notes found in: .note.package/,/Packaging Metadata:/p'; else echo "(readelf is not usable on this VM: the same note read with grep -a)"; grep -a -o '$NOTE_FALLBACK_RX' $f | head -1 | sed 's/^/    Packaging Metadata: /'; fi
EOF
}

push_ours() {   # push_ours VM: our client programs on a client, on ssh stdin (sha256 checked on both sides), under the names dist/install.sh install-clients gives them: kinit, klist, kvno, kdestroy, kpasswd;
    # the clients' own libkrb5, /etc/krb5.conf and MIT's tools are untouched. A program's error lines carry its own name, and MIT's say "kinit:".
    local v=$1 p n want
    for p in "${CLIENT_PROGS[@]}"; do
        push "$v" "$W/ship/release/$p" "$VMD/ours/${p#krb5-}" 755 || return 1
    done
    {
        echo "# our client programs on $v: copies of the ship build's ${CLIENT_PROGS[*]}, run from $VMD/ours as kinit, klist, kvno, kdestroy, kpasswd (the names dist/install.sh install-clients gives them;"
        echo "# a program's error lines carry its own name, and MIT's say \"kinit:\"); the clients' own libkrb5, /etc/krb5.conf and MIT's tools are untouched"
        vm "$v" "cd $VMD/ours && ls -l kinit klist kvno kdestroy kpasswd && sha256sum kinit klist kvno kdestroy kpasswd" 2>&1
        echo "== $VMD/ours/klist -V (it runs here: not a noexec /var/tmp)"
        vm "$v" "$VMD/ours/klist -V" 2>&1
        echo "== $VMD/ours/kvno -V (usage line: no network)"
        vm "$v" "$VMD/ours/kvno -V 2>&1 | grep -m1 '^usage:'" 2>&1
        echo "== $VMD/ours/kdestroy -V (usage line: no network)"
        vm "$v" "$VMD/ours/kdestroy -V 2>&1 | grep -m1 '^Usage:'" 2>&1
        echo "== KRB5_CONFIG=/dev/null $VMD/ours/kpasswd (no default realm: no network)"
        vm "$v" "KRB5_CONFIG=/dev/null $VMD/ours/kpasswd 2>&1 < /dev/null | head -n 1" 2>&1
    } | redact > "$OUT/L1-ours-$v.txt"
    cat "$OUT/L1-ours-$v.txt" >> "$LOG"
    for p in "${CLIENT_PROGS[@]}"; do
        n=${p#krb5-}
        want=$(awk -v p="$p" '$2 == p { print $1 }' "$W/ship-local.sha256")
        expect "L1.$v.ours-$n-sha256" "$OUT/L1-ours-$v.txt" "^$want  $n\$"
    done
    expect "L1.$v.ours-klist-runs" "$OUT/L1-ours-$v.txt" '^Kerberos 5 version 1\.22\.2$'
    expect "L1.$v.ours-kvno-runs" "$OUT/L1-ours-$v.txt" '^usage: kvno '
    expect "L1.$v.ours-kdestroy-runs" "$OUT/L1-ours-$v.txt" '^Usage: kdestroy '
    expect "L1.$v.ours-kpasswd-runs" "$OUT/L1-ours-$v.txt" '/kpasswd: Configuration file does not specify default realm'
    return 0   # a row that failed is counted; the leg goes on (the cells show what does not run)
}

# ---------------------------------------------------------------- the first steps per VM
l1_vm() {   # l1_vm VM: reset to f4-mit, check, the helper pushed, the facts and the MIT identity
    local v=$1 crc pk="krb5-libs krb5-workstation" nrx daemon="/usr/bin/kinit" ost
    [ "$v" = kdc ] && { pk="$pk krb5-server"; daemon=/usr/sbin/krb5kdc; }
    TOUCHED=1; TOUCHED_VM[$v]=1
    lab reset "$v" "$RESTSNAP_LEG" || fail "reset $v $RESTSNAP_LEG"
    timeout 300 "$LAB" check --lab-only "$v" > "$OUT/l1-check-$v.txt" 2>&1; crc=$?
    cat "$OUT/l1-check-$v.txt" >> "$LOG"
    note "L1 check --lab-only $v rc=$crc"
    [ "$crc" = 0 ] || fail "lab.sh check --lab-only $v rc=$crc"
    vmlog "$v" "install -d -m 0700 $VMD" || fail "no ssh to $v"
    push "$v" "$SCRIPTS/otp/vmctl.sh" "$VMD/vmctl.sh" 755 || fail "push vmctl.sh to $v"
    push "$v" "$SCRIPTS/otp/log-since.sh" "$VMD/log-since.sh" 755 || fail "push log-since.sh to $v"
    push "$v" "$SCRIPTS/b2ctl.sh" "$VMD/b2ctl.sh" 755 || fail "push b2ctl.sh to $v"
    if [ "$v" != kdc ]; then push_ours "$v" || fail "push our client programs to $v"; fi
    ost=$(vm "$v" "if [ -e /run/ostree-booted ]; then echo yes; else echo no; fi" 2>> "$LOG" | tr -d '[:space:]')
    [ "$ost" = yes ] || ost=no
    {
        echo "# identity rule applied on $v: the Fedora identity rule. Fedora's build of MIT 1.22.2 carries no KRB5_BRAND string, so the release is established by"
        echo "#   (1) the ELF package note of /usr/lib64/libkrb5.so.3.3 and of $daemon: name krb5, version 1.22.2-<rel>.fc43 (readelf -n, else grep -a: the line under each header says which),"
        echo "#   (2) rpm -V $pk: only config files differ (each is listed below), (3) klist -V = Kerberos 5 version $KLIST_VERSION."
        echo "#   ostree system: $ost$([ "$ost" = yes ] && echo '. ostree gives every file one normalized mtime, so rpm -V flags each package file with T alone; a non-config file whose only flag is T is not counted as different')"
        echo "#   Each is a row that stops the leg before the MIT stage. The KRB5_BRAND grep (expected absent) and the rpm signature are recorded as INFO rows."
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
    vm "$v" "sudo bash $VMD/b2ctl.sh snapshot-conf" 2>&1 < /dev/null | redact > "$OUT/L1-conf-snapshot-$v.txt"   # the VM's config as the reset left it: the state rows after each module compare with it
    cat "$OUT/L1-conf-snapshot-$v.txt" >> "$LOG"
    expect "L1.$v.conf-snapshot" "$OUT/L1-conf-snapshot-$v.txt" '^SNAPSHOT_OK '
    # recorded, not judged
    result "L1.$v.identity-rule" INFO "the Fedora identity rule" - 1 "package note of libkrb5 and $daemon, rpm -V config files only, klist -V; KRB5_BRAND and the rpm signature as INFO"
    info "L1.$v.brand-libkrb5" "$OUT/vm-facts-$v.txt" '^KRB5_BRAND: ' "absent in Fedora's build (expected; recorded, not judged)"
    if [ "$v" = kdc ]; then info "L1.kdc.brand-krb5kdc" "$OUT/vm-facts-kdc.txt" '^KRB5_BRAND: ' "absent in Fedora's build (expected; recorded, not judged)"; fi
    info "L1.$v.rpm-signature" "$OUT/vm-facts-$v.txt" '^(SIGPGP|RSAHEADER): ' "(no signature line)"
    info "L1.$v.package-note-tool" "$OUT/vm-facts-$v.txt" '^\((read with readelf -n|readelf is not usable)'
    # the identity: each row stops the leg before the MIT stage
    nrx='Packaging Metadata: \{"type":"rpm","name":"krb5","version":"'"$PKG_VERSION_RX"'"'
    expect_under "L1.$v.package-note-libkrb5" "$OUT/vm-facts-$v.txt" '^== readelf -n /usr/lib64/libkrb5\.so\.3\.3 ' "$nrx" || BRAND_BAD=1
    if [ "$v" = kdc ]; then
        expect_under "L1.kdc.package-note-krb5kdc" "$OUT/vm-facts-kdc.txt" '^== readelf -n /usr/sbin/krb5kdc ' "$nrx" || BRAND_BAD=1
    else
        expect_under "L1.$v.package-note-kinit" "$OUT/vm-facts-$v.txt" '^== readelf -n /usr/bin/kinit ' "$nrx" || BRAND_BAD=1
    fi
    # rpm -V exits with the number of packages that have a difference (2 on the kdc: krb5-libs' /etc/krb5.conf, krb5-server's kdc.conf and kadm5.acl); sudo or rpm failing
    # would print an error line, which the config-only row below refuses
    expect "L1.$v.rpm-V-ran" "$OUT/vm-facts-$v.txt" '^rpm -V rc=[0-3]$' || BRAND_BAD=1
    expect_rpmv_config_only "L1.$v.rpmV-config-only" "$OUT/vm-facts-$v.txt" "$ost" || BRAND_BAD=1
    info "L1.$v.rpmV-config-files" "$OUT/vm-facts-$v.txt" '^[.SM5DLUGTP?]{9} +c ' "(no file differs)"
    expect "L1.$v.klist-version" "$OUT/vm-facts-$v.txt" "^Kerberos 5 version ${KLIST_VERSION//./\\.}\$" || BRAND_BAD=1
    if [ "$BRAND_BAD" != 0 ]; then
        # the git authority's rule as the Director settled it for Fedora's MIT: a MIT that is not the 1.22.2 release holds the push, so the leg
        # stops here, before the MIT stage; the VMs it has not started are not started. BRAND_ENFORCE=0 (only when the Director says so) keeps the rows as measured.
        if [ "$BRAND_ENFORCE" = 1 ]; then fail "the MIT on $v is not the 1.22.2 release the leg needs (package note krb5 1.22.2-<rel>.fc43, rpm -V config files only, klist -V $KLIST_VERSION): the push is held (vm-facts-$v.txt)"; fi
        note "BRAND_ENFORCE=0: the identity rows stay as measured and the leg goes on"
    fi
}


# ---------------------------------------------------------------- rows decided by the caller, scripts on a VM, SELinux
verdict() {   # verdict LABEL PASS|FAIL RX WANT GOT [TEXT]: a row decided by the caller
    local label=$1 res=$2
    shift 2
    result "$label" "$res" "$@"
    note "CHECK $res $label ($*)"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

same() {   # same LABEL WANT GOT [TEXT]: a row decided by a comparison of two values (PASS when equal)
    if [ "$2" = "$3" ]; then verdict "$1" PASS "${4:-equal}" "$2" "$3"; else verdict "$1" FAIL "${4:-equal}" "$2" "$3"; fi
}

kdc_script() {   # kdc_script NAME LOCAL-SCRIPT [TIMEOUT]: the script on the kdc's sh, the admin password its stdin's first line (ADMIN_PW); the output through the record filter into $OUT/NAME.txt; sets KS_RC
    local name=$1 script=$2 t=${3:-600}
    if [ ! -s "$script" ]; then note "kdc_script: $script is missing or empty"; KS_RC=127; : > "$OUT/$name.txt"; return 1; fi
    { cat "$ADMIN_SECRET"; cat "$script"; } | timeout "$t" "$LAB" ssh kdc -- 'IFS= read -r ADMIN_PW; export ADMIN_PW; exec sh -s' 2>&1 | redact > "$OUT/$name.txt"
    KS_RC=${PIPESTATUS[1]}
    cat "$OUT/$name.txt" >> "$LOG"
}
export KS_RC=0

vm_script() {   # vm_script NAME VM LOCAL-SCRIPT [TIMEOUT [VAR=SECRETFILE ...]]: the script on VM's sh (sudo is the script's own business); each SECRETFILE's content is one stdin line, read into the environment
    # variable VAR before the script (never on a command line); the output (stderr too) through the record filter into $OUT/NAME.txt; sets KS_RC. TIMEOUT defaults to 600 s.
    local name=$1 vmn=$2 script=$3 t=${4:-600} a pre=": "
    shift 3; [ $# -gt 0 ] && shift
    if [ ! -s "$script" ]; then note "vm_script: $script is missing or empty"; KS_RC=127; : > "$OUT/$name.txt"; return 1; fi
    for a in "$@"; do pre="${pre}; IFS= read -r ${a%%=*}; export ${a%%=*}"; done
    {
        for a in "$@"; do printf '%s\n' "$(cat "${a#*=}")"; done
        cat "$script"
    } | timeout "$t" "$LAB" ssh "$vmn" -- "$pre; exec sh -s" 2>&1 | redact > "$OUT/$name.txt"
    KS_RC=${PIPESTATUS[1]}
    cat "$OUT/$name.txt" >> "$LOG"
}

alice_pw() { printf '%s\n' "$(cat "$ALICE_SECRET")"; }               # the MIT realm's alice password as ONE line, for a pipe into cell / vm_script (stdin only: never argv, never printed)
alice_temp_pw() { printf '%s\n' "$(cat "$ALICE_TEMP_SECRET")"; }     # the password alice is changed to (MIT_SECRET_ALICE_TEMP), one line
admin_pw() { printf '%s\n' "$(cat "$ADMIN_SECRET")"; }               # the admin/admin password, one line (a file without its final newline cannot glue the next stdin line onto it)

avc_rows() {   # avc_rows LABEL MARK [END]: SELinux is enforcing on the kdc and nothing was denied from MARK to END (the kdc's clock, HH:MM:SS; END default: now): upgrade.sh's selinux.avc form, judged
    local label=$1 mark=$2 end=${3:-} te="" f="$OUT/$1.txt"
    [ -n "$end" ] && te="-te $end"
    vm kdc "getenforce; d=\$(sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $mark $te 2>&1); r=\$?; [ \"\$r\" = 1 ] || printf '%s\n' \"\$d\"; c=\$(sudo ausearch --input-logs -m USER_CMD -ts $mark $te 2>/dev/null | grep -c '^type=USER_CMD'); printf 'denials: %s (ausearch rc=%s); USER_CMD control: %s records\n' \"\$(printf '%s\n' \"\$d\" | tail -n 1)\" \"\$r\" \"\$c\"; ps -eZ | grep -E 'krb5kdc|kadmind|krb5-otp-kdc'" 2>&1 < /dev/null | redact > "$f"
    cat "$f" >> "$LOG"
    expect "$label.enforcing" "$f" '^Enforcing$' 1
    expect "$label.no-denial" "$f" '^denials: <no matches> \(ausearch rc=1\); USER_CMD control: [1-9][0-9]* records$' 1
    info "$label.daemon-domains" "$f" 'krb5kdc|kadmind|krb5-otp-kdc'
}

avc_mark() { vm kdc "sudo bash $VMD/vmctl.sh avc-mark" 2>> "$LOG" < /dev/null | tr -d '[:space:]'; }   # the kdc's clock, HH:MM:SS
B2_AVC_MARK=""
avc_judge() {   # avc_judge LABEL: judge the SELinux denials from the stage's mark to now (a module calls it before a cell that provokes denials ON PURPOSE), then move the mark past that cell with avc_skip
    avc_rows "$1" "$B2_AVC_MARK"
    B2_AVC_MARK=$(avc_mark)
}
avc_skip() {   # avc_skip: the denials up to now are not judged (a module's cell provoked them on purpose and judged them itself): the mark moves two seconds past them (ausearch -ts has a one-second grain)
    sleep 2
    B2_AVC_MARK=$(avc_mark)
    note "AVC_MARK moved to $B2_AVC_MARK (denials before it were provoked on purpose and are judged by their module)"
}

# ================================================================ the B2 machinery: modules, hooks, the state rows, the leg's throwaway passwords, the parity helpers
b2_has() { declare -F "$1" > /dev/null; }
b2_listed() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }   # b2_listed NAME COMMA-LIST
b2_modfile() { if [ "$1" = tpl ]; then echo "$SCRIPTS/mod/TEMPLATE.sh"; else echo "$SCRIPTS/mod/$1.sh"; fi; }

b2_discover() {   # B2_MODS := the modules of the order (and B2_EXTRA) that have a file, are selected by B2_MODULES and are not in B2_SKIP; B2_NOTRUN := the others with a reason. Exit 2 on an unknown name.
    local sel=${B2_MODULES:-} skip=${B2_SKIP:-} m x allcsv
    local -a all=("${B2_ORDER[@]}")
    sel=${sel//[ ]/,}; skip=${skip//[ ]/,}
    for x in ${B2_EXTRA:-}; do all+=("$x"); done
    allcsv=$(IFS=,; echo "${all[*]}")
    for x in ${sel//,/ } ${skip//,/ }; do
        b2_listed "$x" "$allcsv" || { echo "driver-b2.sh: unknown module '$x' (the order: ${B2_ORDER[*]}; B2_EXTRA adds more)" >&2; exit 2; }
    done
    B2_MODS=(); B2_NOTRUN=()
    for m in "${all[@]}"; do
        if [ -n "$sel" ] && ! b2_listed "$m" "$sel"; then B2_NOTRUN+=("$m:not in B2_MODULES"); continue; fi
        if b2_listed "$m" "$skip"; then B2_NOTRUN+=("$m:dropped by B2_SKIP"); continue; fi
        if [ ! -f "$(b2_modfile "$m")" ]; then B2_NOTRUN+=("$m:no module file $(b2_modfile "$m")"); continue; fi
        B2_MODS+=("$m")
    done
}

b2_load() {   # source the modules (their syntax checked first: all before any lock) and require at least one stage hook, <pkg>_mit or <pkg>_ours (a module of one stage only, such as p8e, defines just that one),
    # and <pkg>_parity when it defines both; <pkg>_prep, _push and _clean are optional
    local m f bad=0
    for m in "${B2_MODS[@]}"; do
        f=$(b2_modfile "$m")
        if ! bash -n "$f" 2> "$TMPDIR/b2-syntax-$m.txt"; then echo "driver-b2.sh: $f has a syntax error:" >&2; cat "$TMPDIR/b2-syntax-$m.txt" >&2; bad=1; continue; fi
        # shellcheck source=/dev/null
        . "$f"
        if ! b2_has "${m}_mit" && ! b2_has "${m}_ours"; then echo "driver-b2.sh: module $m ($f) defines neither ${m}_mit nor ${m}_ours" >&2; bad=1; fi
        if b2_has "${m}_mit" && b2_has "${m}_ours" && ! b2_has "${m}_parity"; then echo "driver-b2.sh: module $m ($f) defines ${m}_mit and ${m}_ours but no ${m}_parity" >&2; bad=1; fi
    done
    [ "$bad" = 0 ] || exit 2
}

declare -A B2_DEAD=()      # pkg -> why: a module whose _prep or _push failed (or that failed the module check) runs no cell: no cell runs on missing inputs
declare -A B2_DEAD_AT=()   # pkg -> prep | push

b2_hook() {   # b2_hook HOOK: <pkg>_<HOOK> of every module, in the module order; an absent optional hook is skipped; a return status other than 0 is a FAIL row (<PKG>.hook.<HOOK>) and the next module still runs;
    # a failing _prep or _push makes the module NOT-RUN (a row says why) and none of its later hooks runs (its _clean still runs after a failed _push, which may have pushed part of its inputs)
    local hook=$1 m fn rc
    # dynamic scoping: these are the shell's own names (loop variables of the main flow); a module function that forgets `local` on one of them writes THESE copies, not the shell's
    local v c f s snaps e x t t0 t1 vt want got irc n h p i k l
    for m in "${B2_MODS[@]}"; do
        fn=${m}_$hook
        b2_has "$fn" || continue
        if [ -n "${B2_DEAD[$m]:-}" ] && ! { [ "$hook" = clean ] && [ "${B2_DEAD_AT[$m]}" = push ]; }; then
            note "B2 MODULE $m: $hook skipped (NOT-RUN: ${B2_DEAD[$m]})"; continue
        fi
        [ "$hook" = prep ] || deadline
        mkdir -p "$OUT/$m"
        export B2_PKG=$m
        note "B2 MODULE $m: $hook"
        "$fn"; rc=$?
        verdict "${m^^}.hook.$hook" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" "$fn exit status" 0 "$rc"
        if [ "$rc" != 0 ] && { [ "$hook" = prep ] || [ "$hook" = push ]; }; then
            B2_DEAD[$m]="${m}_$hook failed (rc $rc)"; B2_DEAD_AT[$m]=$hook
            result "${m^^}.not-run" INFO "module not run" - 0 "NOT-RUN: ${B2_DEAD[$m]}; no cell runs on missing inputs"
            note "NOT-RUN module $m: ${B2_DEAD[$m]}; no cell runs on missing inputs"
            continue
        fi
        case $hook in mit|ours) b2_state_rows "$m" "$hook" ;; esac
    done
}

b2_state_rows() {   # b2_state_rows PKG STAGE: the VMs after a module's hook, each against what L1 found: SELinux enforcing and the config files as found on all three; on the kdc both daemons active and the realm
    # database as found (the sorted principals and policies, the key version numbers of alice, bob and admin/admin): a module that leaves a principal, a policy or a password change behind is red at ITS boundary
    local m=$1 st=$2 v f L=${1^^}
    for v in kdc "${CLIENTS[@]}"; do
        f="$OUT/$m/state-$st-$v.txt"
        vm "$v" "sudo bash $VMD/b2ctl.sh state" 2>&1 < /dev/null | redact > "$f"
        expect "$L.$st.after.$v.selinux-enforcing" "$f" '^selinux: Enforcing$' 1
        expect "$L.$st.after.$v.config-as-found" "$f" '^config: same as found$' 1
        if [ "$v" = kdc ]; then
            expect "$L.$st.after.kdc.daemons-active" "$f" '^units: krb5kdc=active kadmin=active$' 1
            expect "$L.$st.after.kdc.realm-as-found" "$f" '^realm: same as found$' 1
        fi
        # a boundary that went red is the module's own: the state it left becomes the baseline, so that the next module's boundary is not red for the same leftover
        if grep -q -E '^(config|realm): DIFFERS' "$f"; then
            vm "$v" "sudo bash $VMD/b2ctl.sh rebaseline" 2>&1 < /dev/null | redact > "$OUT/$m/rebaseline-$st-$v.txt"
            info "$L.$st.after.$v.rebaselined" "$OUT/$m/rebaseline-$st-$v.txt" '^REBASELINED' "(the rebaseline did not run)"
        fi
    done
    return 0
}

b2_clean_hooks() {   # b2_clean_hooks [best-effort]: every module's <pkg>_clean (undo what the reset will not; shred a module's secrets on the VMs); best-effort (a stopped leg): errors are noted, no rows;
    # a module whose _prep failed did nothing on the VMs and is skipped
    local mode=${1:-} m fn rc
    local v c f s snaps e x t t0 t1 vt want got irc n h p i k l
    : "${i-}" "${k-}" "${l-}"
    for m in "${B2_MODS[@]}"; do
        fn=${m}_clean; b2_has "$fn" || continue
        [ "${B2_DEAD_AT[$m]:-}" = prep ] && continue
        mkdir -p "$OUT/$m"
        note "B2 MODULE $m: clean${mode:+ ($mode)}"
        "$fn" >> "$LOG" 2>&1; rc=$?
        if [ -z "$mode" ]; then verdict "${m^^}.hook.clean" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" "$fn exit status" 0 "$rc"
        elif [ "$rc" != 0 ]; then note "RESTORE: $fn rc=$rc"; fi
    done
}

# ---- module hygiene (the head implementer's rule 6), before the lock: bash -n, shellcheck, no variable assigned outside a function, the shell's names `local` inside module functions
B2_LOOPVARS="v c f s snaps rc e m x t t0 t1 vt want got irc n h p i k l SKEW TARLIST SRCINFO"
B2_ASSIGN_OK=" B2_RESIDUE_PATHS "     # the shell variables a module function may assign (the interface says so)

b2_check_inner() {   # b2_check_inner FILE: in a SUBSHELL (the caller's): source the module and say, one finding per line, which variable it assigned outside a function (TOPLEVEL name) and which of the shell's names
    # (every variable that exists before the module is sourced, and the loop variables) a function of it assigns without `local` (LOCAL function name)
    local f=$1 vol pre post prefn postfn protected fn body name cand
    vol='^declare -[-a-zA-Z]+ (_|BASH_ARGC|BASH_ARGV|BASH_COMMAND|BASH_LINENO|BASH_SOURCE|FUNCNAME|LINENO|SECONDS|EPOCHSECONDS|EPOCHREALTIME|RANDOM|SRANDOM|BASHPID|PIPESTATUS|OLDPWD|PWD|SHLVL)='
    set +eu
    pre=$(declare -p 2> /dev/null | grep -v -E "$vol" | LC_ALL=C sort)
    prefn=$(declare -F | awk '{ print $3 }' | LC_ALL=C sort)
    protected=$( { tr ' ' '\n' <<< "$B2_LOOPVARS"; printf '%s\n' "$pre" | sed -n 's/^declare -[-a-zA-Z]* \([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'; } | LC_ALL=C sort -u)
    # shellcheck source=/dev/null
    . "$f" > /dev/null 2>&1
    post=$(declare -p 2> /dev/null | grep -v -E "$vol" | LC_ALL=C sort)
    postfn=$(declare -F | awk '{ print $3 }' | LC_ALL=C sort)
    LC_ALL=C comm -13 <(printf '%s\n' "$pre") <(printf '%s\n' "$post") | sed -n 's/^declare -[-a-zA-Z]* \([A-Za-z_][A-Za-z0-9_]*\)=.*/TOPLEVEL \1/p' \
        | grep -v -x -E 'TOPLEVEL (f|vol|pre|post|prefn|postfn|protected|fn|body|name|cand)'      # this function's own variables
    for fn in $(LC_ALL=C comm -13 <(printf '%s\n' "$prefn") <(printf '%s\n' "$postfn")); do
        body=$(declare -f "$fn" | awk 'BEGIN { st = 0 }   # the function text without its quoted strings (a string is not an assignment)
            { out = ""; n = length($0)
              for (i = 1; i <= n; i++) {
                  c = substr($0, i, 1)
                  if (st == 0) { if (c == "\\") { out = out "Q"; i++ } else if (c == "\047") { st = 1; out = out "Q" } else if (c == "\042") { st = 2; out = out "Q" } else out = out c }
                  else if (st == 1) { if (c == "\047") st = 0 }
                  else { if (c == "\\") i++; else if (c == "\042") st = 0 }
              }
              print out }')
        # the names this function assigns: NAME= / NAME+= at the start of a command, for NAME in, printf -v NAME, read / mapfile ... NAME
        cand=$( { printf '%s\n' "$body" | grep -o -E '(^|[;&|({]|[[:space:]])[A-Za-z_][A-Za-z0-9_]*\+?=' | sed -E 's/^[^A-Za-z_]*//; s/\+?=$//'
                  printf '%s\n' "$body" | grep -o -E 'for [A-Za-z_][A-Za-z0-9_]* in ' | sed -E 's/^for //; s/ in $//'
                  printf '%s\n' "$body" | grep -o -E 'printf -v [A-Za-z_][A-Za-z0-9_]*' | sed -E 's/^printf -v //'
                  printf '%s\n' "$body" | grep -E '^[[:space:]]*(read|mapfile|readarray)[[:space:]]' | sed -E 's/[;|<].*$//' | tr -s ' ' '\n' | grep -E '^[A-Za-z_][A-Za-z0-9_]*$' | grep -v -x -E 'read|mapfile|readarray'
                } | LC_ALL=C sort -u | LC_ALL=C comm -12 - <(printf '%s\n' "$protected"))
        for name in $cand; do
            case "$B2_ASSIGN_OK" in *" $name "*) continue ;; esac
            printf '%s\n' "$body" | grep -q -E "(^|[[:space:];])(local|declare|typeset)([[:space:]]+-[A-Za-z]+)*[^;|&]*[[:space:]]$name([=[:space:];]|$)" || printf 'LOCAL %s %s\n' "$fn" "$name"
        done
    done
}

b2_check_module() {   # b2_check_module PKG: the four rules as rows <PKG>.check.{bash-n,shellcheck,hooks,no-top-level-assignment,locals}; returns 1 when one fails (B2_CHECK_WHY says which)
    local m=$1 L=${1^^} f ok=1 n out
    f=$(b2_modfile "$m"); B2_CHECK_WHY=""
    mkdir -p "$OUT/check"
    if bash -n "$f" 2> "$OUT/check/$m.bash-n.txt"; then verdict "$L.check.bash-n" PASS "bash -n $(basename "$f")" ok ok ""
    else verdict "$L.check.bash-n" FAIL "bash -n $(basename "$f")" ok "$(head -n 1 "$OUT/check/$m.bash-n.txt" | cut -c1-200)"; B2_CHECK_WHY="bash -n"; return 1; fi
    if command -v shellcheck > /dev/null 2>&1; then
        if shellcheck -s bash -S warning -e SC2154,SC2034,SC2155 "$f" > "$OUT/check/$m.shellcheck.txt" 2>&1; then verdict "$L.check.shellcheck" PASS "shellcheck -S warning" ok ok ""
        else n=$(grep -c '^In ' "$OUT/check/$m.shellcheck.txt"); verdict "$L.check.shellcheck" FAIL "shellcheck -S warning" ok "$n finding(s): check/$m.shellcheck.txt"; ok=0; B2_CHECK_WHY="shellcheck"; fi
    else verdict "$L.check.shellcheck" FAIL "shellcheck -S warning" ok "shellcheck is not installed on this host"; ok=0; B2_CHECK_WHY="shellcheck missing"; fi
    out=$( ( b2_check_inner "$f" ) 2>&1 )
    printf '%s\n' "$out" > "$OUT/check/$m.hygiene.txt"
    if printf '%s\n' "$out" | grep -q '^TOPLEVEL '; then
        verdict "$L.check.no-top-level-assignment" FAIL "no variable assigned outside a function" none "$(printf '%s\n' "$out" | sed -n 's/^TOPLEVEL //p' | paste -sd' ' -)"; ok=0; B2_CHECK_WHY="${B2_CHECK_WHY:+$B2_CHECK_WHY, }top-level assignment"
    else verdict "$L.check.no-top-level-assignment" PASS "no variable assigned outside a function" none none ""; fi
    if printf '%s\n' "$out" | grep -q '^LOCAL '; then
        verdict "$L.check.locals" FAIL "the shell's names are local inside module functions" none "$(printf '%s\n' "$out" | sed -n 's/^LOCAL //p' | paste -sd';' -)"; ok=0; B2_CHECK_WHY="${B2_CHECK_WHY:+$B2_CHECK_WHY, }names not local"
    else verdict "$L.check.locals" PASS "the shell's names are local inside module functions" none none ""; fi
    # the hooks: at least one stage hook, and a parity hook when both stage hooks are there (seen from the sourced file in a subshell)
    # shellcheck source=/dev/null
    out=$( ( set +eu; . "$f" > /dev/null 2>&1; for h in prep push mit ours parity clean; do declare -F "${m}_$h" > /dev/null && printf '%s ' "$h"; done ) 2>&1 )
    case " $out " in
        *" mit "*|*" ours "*) case " $out " in *" mit "*" ours "*|*" ours "*" mit "*) case " $out " in *" parity "*) verdict "$L.check.hooks" PASS "hooks: $out" ok ok "" ;; *) verdict "$L.check.hooks" FAIL "mit and ours without parity" ok "hooks: $out"; ok=0; B2_CHECK_WHY="${B2_CHECK_WHY:+$B2_CHECK_WHY, }no parity hook" ;; esac ;; *) verdict "$L.check.hooks" PASS "hooks: $out" ok ok "" ;; esac ;;
        *) verdict "$L.check.hooks" FAIL "no stage hook (${m}_mit or ${m}_ours)" ok "hooks: ${out:-none}"; ok=0; B2_CHECK_WHY="${B2_CHECK_WHY:+$B2_CHECK_WHY, }no stage hook" ;;
    esac
    [ "$ok" = 1 ]
}

b2_check_all() {   # the module check for every selected module; a module that fails any rule is NOT-RUN (its rows say which) and leaves B2_MODS
    local m
    local -a keep=()
    for m in "${B2_MODS[@]}"; do
        if b2_check_module "$m"; then keep+=("$m"); else B2_NOTRUN+=("$m:failed the module check ($B2_CHECK_WHY)"); note "NOT-RUN module $m: failed the module check ($B2_CHECK_WHY)"; fi
    done
    B2_MODS=("${keep[@]}")
}

make_secrets() {   # the leg's throwaway passwords (b2_pw 1..3) under $SECD (0600), and copies under $SCANHOME for the leg's own scan: four character classes, never on a command line
    local f
    mkdir -p "$SCANHOME/secrets"; chmod 700 "$SECD" "$SCANHOME" "$SCANHOME/secrets"
    for f in "$SECD"/b2-*.pw "$SCANHOME"/secrets/*; do [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; done
    python3 -B -I - "$SECD" <<'PY'
import os, secrets, sys
d = sys.argv[1]
def w(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data.encode())
for i in (1, 2, 3):
    pw = "Zq-" + secrets.token_hex(8) + "-%d" % i          # upper, lower, digit and punctuation; far from any dictionary word and any timestamp
    w(os.path.join(d, "b2-pw%d.pw" % i), pw + "\n")
    w(os.path.join(d, "scanhome", "secrets", "b2-pw%d.pw" % i), pw + "\n")
PY
}
b2_pw() { cat "$SECD/b2-pw$1.pw"; }     # b2_pw N: the leg's throwaway password N (1..3), for a pipe

# ---- parity helpers: a module may use them or compare in its own way (every parity hook needs at least one control that can fail)
cell_body() {   # cell_body FILE: the client's part of a cell transcript without its header lines (cell name, command, stdin note) and trailer
    sed -n '1,/^# end of cell output/p' "$1" | grep -v -e '^# cell ' -e '^# \$ ' -e '^# stdin: ' -e '^# end of cell output'
}
b2_norm() {   # b2_norm FILE [SED-EXPR ...]: FILE through the sed -E expressions (the named mask); to stdout
    local f=$1 e; shift
    local -a sa=()
    for e in "$@"; do sa+=(-e "$e"); done
    if [ ${#sa[@]} -gt 0 ]; then sed -E "${sa[@]}" "$f"; else cat "$f"; fi
}
parity_eq() {   # parity_eq LABEL MITFILE OURSFILE [SED-EXPR ...]: the two files equal after the sed -E expressions (the mask is named in the row); PASS/FAIL row; the normalised copies and the diff are kept in $OUT/parity/
    local label=$1 a=$2 b=$3 n m=""
    shift 3
    [ $# -gt 0 ] && m=" after the mask [$*]"
    mkdir -p "$OUT/parity"
    b2_norm "$a" "$@" > "$OUT/parity/$label.mit.txt"; b2_norm "$b" "$@" > "$OUT/parity/$label.ours.txt"
    n=$(wc -l < "$OUT/parity/$label.mit.txt")
    if [ -s "$OUT/parity/$label.mit.txt" ] && diff -u "$OUT/parity/$label.mit.txt" "$OUT/parity/$label.ours.txt" > "$OUT/parity/$label.diff"; then
        verdict "$label" PASS "MIT = ours$m" equal equal "$n lines"
    else
        verdict "$label" FAIL "MIT = ours$m" equal differ "$n lines; parity/$label.diff"
    fi
}
parity_control() {   # parity_control LABEL MITFILE OURSFILE [SED-EXPR ...]: the same comparison on a doctored copy of OURSFILE (a line appended) must DIFFER: it proves the comparison, mask included, can fail
    local label=$1 a=$2 b=$3
    shift 3
    mkdir -p "$OUT/parity"
    { b2_norm "$b" "$@"; echo "a doctored line (control)"; } > "$OUT/parity/$label.doctored.txt"
    b2_norm "$a" "$@" > "$OUT/parity/$label.control-mit.txt"
    if diff -q "$OUT/parity/$label.control-mit.txt" "$OUT/parity/$label.doctored.txt" > /dev/null; then
        verdict "$label.control" FAIL "a doctored copy must differ" differ same ""
    else
        verdict "$label.control" PASS "a doctored copy must differ" differ differ ""
    fi
}

parity_dev() {   # parity_dev LABEL CITE MITFILE MITRX OURSFILE OURSRX: a documented deviation (CITE: docs/mit-deviations*.md file:line at the tip): MIT shows MITRX and ours shows OURSRX; PASS only when both hold
    local label=$1 cite=$2 mf=$3 mrx=$4 of=$5 orx=$6 a b
    a=$(grep -cE -- "$mrx" "$mf" 2>/dev/null || true); b=$(grep -cE -- "$orx" "$of" 2>/dev/null || true)
    if [ "${a:-0}" -ge 1 ] && [ "${b:-0}" -ge 1 ]; then
        verdict "$label" PASS "documented deviation ($cite): MIT /$mrx/, ours /$orx/" both "MIT ${a:-0}, ours ${b:-0}"
    else
        verdict "$label" FAIL "documented deviation ($cite): MIT /$mrx/, ours /$orx/" both "MIT ${a:-0}, ours ${b:-0}"
    fi
}

b2_facts() {   # what the modules rely on: python3 on the kdc, the kadmind log, :464 and :749 listening, MIT's tools on the clients
    local c
    {
        echo "== $(now) the VMs at f4-mit, before the MIT stage"
        echo "== python3 on kdc"; vm kdc "python3 --version" 2>&1
        echo "== /var/log/kadmind.log"; vm kdc "ls -l /var/log/kadmind.log" 2>&1
        echo "== :464 listeners"; vm kdc "sudo ss -H -lntu 'sport = :464' | grep -c ." 2>&1
        echo "== :749 listeners"; vm kdc "sudo ss -H -lnt 'sport = :749' | grep -c ." 2>&1
        for c in "${CLIENTS[@]}"; do echo "== MIT tools on $c"; vm "$c" "command -v kinit klist kvno kdestroy kpasswd kadmin" 2>&1; done
    } 2>&1 | redact > "$OUT/L2-facts.txt"
    cat "$OUT/L2-facts.txt" >> "$LOG"
    expect L2.facts.python3 "$OUT/L2-facts.txt" '^Python 3\.'
    expect L2.facts.kadmind-log "$OUT/L2-facts.txt" 'kadmind\.log$'
    expect_under L2.facts.464-listening "$OUT/L2-facts.txt" '^== :464 listeners' '^[1-9][0-9]*$'
    expect_under L2.facts.749-listening "$OUT/L2-facts.txt" '^== :749 listeners' '^[1-9][0-9]*$'
    for c in "${CLIENTS[@]}"; do
        expect_under "L2.facts.mit-tools-on-$c" "$OUT/L2-facts.txt" "^== MIT tools on $c\$" '/(kinit|klist|kvno|kdestroy|kpasswd|kadmin)$' 6
    done
}

package_summary() {   # SUMMARY.txt: the checks per package and the cells behind them, the modules that did not run
    local m e mc oc
    {
        echo "# $(now) B2: the checks per package (results.tsv) and the cells behind them"
        awk -F'\t' -v pk="$(printf '%s ' "${B2_ORDER[@]}" "${B2_EXTRA:-}" | tr '[:lower:]' '[:upper:]')" '
            BEGIN { n = split(pk, a, " "); for (i = 1; i <= n; i++) if (a[i] != "") mod[a[i]] = 1 }
            function grp(l,   p) { split(l, x, "."); p = x[1]; if (p in mod) return p; return "common (inputs, resets, identity, install, AVC, shred, restore)" }
            { g = grp($1); c[g " " $2]++; seen[g] = 1 }
            END { for (g in seen) printf "%-62s %5d PASS %4d FAIL %5d INFO\n", g, c[g " PASS"], c[g " FAIL"], c[g " INFO"] }' "$OUT/results.tsv" | sort
        echo "# cells per module (transcripts under <pkg>/): MIT stage, ours stage"
        for m in "${B2_MODS[@]}"; do
            mc=$(find "$OUT/$m" -maxdepth 1 -name 'mit-*.txt' 2>/dev/null | wc -l); oc=$(find "$OUT/$m" -maxdepth 1 -name 'ours-*.txt' 2>/dev/null | wc -l)
            printf '%-8s %3d mit cells, %3d ours cells\n' "$m" "$mc" "$oc"
        done
        for e in "${B2_NOTRUN[@]}"; do echo "NOT-RUN ${e%%:*}: ${e#*:}"; done
    } > "$OUT/SUMMARY.txt"
    cat "$OUT/SUMMARY.txt" >> "$LOG"
}

# ================================================================ the inputs (host only, before the lock): the ship build, the checkout, the secrets' names
prep_inputs() {   # SHIP = the built programs, DIST = the checkout whose dist/, docs/install.md and baseline.env the hold uses, TREE = the tree id they must be
    local p tree treeinfo section
    [ -d "$SHIP/release" ] && SHIP=$SHIP/release
    if ! { [ -d "$SHIP" ] && [ -d "$DIST/dist" ] && [ -f "$DIST/docs/install.md" ]; }; then
        echo "driver-b2.sh: SHIP=$SHIP or DIST=$DIST is not what it should be (SHIP: the built programs, a cargo release dir or a frozen copy; DIST: the checkout with dist/ and docs/install.md)" >&2; exit 2
    fi
    for p in "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}"; do
        [ -x "$SHIP/$p" ] || { echo "driver-b2.sh: $SHIP/$p is missing or not executable" >&2; exit 2; }
    done
    tree=$(git -C "$DIST" rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)
    if [ -n "$TREE" ] && [ "$tree" != unknown ]; then
        case $tree in "$TREE"*) ;; *) echo "driver-b2.sh: DIST=$DIST is tree $tree, not TREE=$TREE" >&2; exit 2 ;; esac
    fi
    treeinfo=$tree
    [ "$tree" = unknown ] && [ -n "$TREE" ] && treeinfo="$TREE (as given by TREE=; $DIST is a git archive of that tree, not a git checkout)"
    rm -rf "$W/ship"; mkdir -p "$W/ship/release"
    for p in "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}"; do cp -p "$SHIP/$p" "$W/ship/release/$p"; done
    cp -rp "$DIST/dist" "$W/ship/dist"
    ( cd "$W/ship/release" && sha256sum "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}" ) > "$W/ship-sha256.txt"
    ( cd "$W/ship/dist" && find . -type f | LC_ALL=C sort | xargs sha256sum ) > "$W/dist-sha256.txt"
    section=$(awk '/^## Upgrading an MIT realm/{f=1;print;next} /^## /&&f{exit} f{print}' "$DIST/docs/install.md" | sha256sum | cut -d' ' -f1)
    {
        echo "tree $treeinfo, ship build $SHIP (${SHIP_NOTE:-default features, --release --locked}), dist/ and docs of $DIST"
        echo "docs/install.md 'Upgrading an MIT realm' section sha256 $section"
    } > "$W/ship-source.txt"
    ( cd "$W/ship/release" && sha256sum "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}" ) > "$W/ship-local.sha256"
    ( cd "$W/ship/release" && sha256sum "${SERVER_PROGS[@]}" ) > "$W/ship-server.sha256"
    [ -s "$ADMIN_SECRET" ] || { echo "driver-b2.sh: no admin secret file at $ADMIN_SECRET" >&2; exit 2; }
    # the MIT realm's alice password files: the NAMES come from harness/field/baseline.env (MIT_SECRET_ALICE, MIT_SECRET_ALICE_TEMP); the secrets directory is never listed, the values never read here
    BASELINE_ENV=$DIST/harness/field/baseline.env
    [ -f "$BASELINE_ENV" ] || BASELINE_ENV=$REPO/harness/field/baseline.env
    [ -n "$ALICE_SECRET" ] || ALICE_SECRET=$(b2_secret_file MIT_SECRET_ALICE)
    [ -n "$ALICE_TEMP_SECRET" ] || ALICE_TEMP_SECRET=$(b2_secret_file MIT_SECRET_ALICE_TEMP)
    [ -s "$ALICE_SECRET" ] || { echo "driver-b2.sh: no alice secret file at '$ALICE_SECRET' (MIT_SECRET_ALICE in $BASELINE_ENV, or ALICE_SECRET=)" >&2; exit 2; }
    [ -s "$ALICE_TEMP_SECRET" ] || { note "ALICE_TEMP_SECRET: no file at '$ALICE_TEMP_SECRET' (MIT_SECRET_ALICE_TEMP in $BASELINE_ENV): alice_temp_pw prints nothing; a module that needs it will fail its own row"; ALICE_TEMP_SECRET=/dev/null; }
}
b2_secret_file() {   # b2_secret_file VAR: the path of the secret file whose NAME baseline.env gives to VAR (a name, never a value)
    local n
    n=$(sed -n "s/^$1=//p" "$BASELINE_ENV" | head -n 1)
    [ -n "$n" ] && printf '%s\n' "$HOME/kerber-lab/secrets/$n"
}

b2_after_install() {   # what the dump and the load must have left: the kdc's daemons from the ship build (no package owns kadmind), active, SELinux enforcing
    {
        echo "# $(now) after the install"
        vm kdc "rpm -qf /usr/sbin/kadmind 2>&1; systemctl is-active krb5kdc kadmin; getenforce; ls -lZ /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl; ls -lZ /usr/sbin/krb5kdc /usr/sbin/kadmind" 2>&1
    } | redact > "$OUT/L3-after-install.txt"
    cat "$OUT/L3-after-install.txt" >> "$LOG"
    vm kdc "sudo bash $VMD/b2ctl.sh state" 2>&1 < /dev/null | redact > "$OUT/L3-state-after-install.txt"   # hold B had L3.install.kdc-conf-plain: the config and the realm as the reset found them, the daemons from the ship build
    cat "$OUT/L3-state-after-install.txt" >> "$LOG"
    expect L3.install.config-as-found "$OUT/L3-state-after-install.txt" '^config: same as found$' 1
    expect L3.install.realm-as-found "$OUT/L3-state-after-install.txt" '^realm: same as found$' 1
    expect L3.install.units-active "$OUT/L3-state-after-install.txt" '^units: krb5kdc=active kadmin=active$' 1
    expect L3.install.kadmind-not-owned "$OUT/L3-after-install.txt" 'is not owned by any package'
    expect L3.install.daemons-active "$OUT/L3-after-install.txt" '^active$' 2
    expect L3.install.enforcing "$OUT/L3-after-install.txt" '^Enforcing$' 1
}

# ================================================================ main
[ "${SOURCE_ONLY:-}" = 1 ] && return 0 2>/dev/null
B2_RUN_TOKEN="b2-$$-$(date +%s)"; export B2_RUN_TOKEN     # every process the run starts carries it in its environment
kill_run() {   # kill every process of this run except the shell, by the token in its environment: a `timeout` puts its command in a group of its own and a kill of the shell's group does not reach it, and an
    # orphan (its parent already killed) is no child of the shell any more; this runs in the TERM and INT traps, before the restore starts its own children
    local p
    for p in /proc/[0-9]*; do
        p=${p#/proc/}
        [ "$p" = "$$" ] && continue
        [ -r "/proc/$p/environ" ] || continue
        tr '\0' '\n' < "/proc/$p/environ" 2> /dev/null | grep -qx "B2_RUN_TOKEN=$B2_RUN_TOKEN" && kill -TERM "$p" 2> /dev/null
    done
    return 0
}
trap finish EXIT
trap 'REASON="interrupted (SIGTERM)"; kill_run; exit 143' TERM
trap 'REASON="interrupted (SIGINT)"; kill_run; exit 130' INT
host_tmp_snapshot > "$OUT/host-tmp-before.txt"
: > "$OUT/results.tsv"

# ---- --check-modules: the module hygiene checks alone (no lab, no lock, no ship build)
if [ "${1:-}" = --check-modules ]; then
    REC=$OUT/rec-check; mkdir -p "$REC"      # finish() copies the log to $REC/driver.log: never into an earlier pass's record
    b2_discover
    b2_check_all
    echo "== module check (driver-b2.sh --check-modules): modules checked and kept: ${B2_MODS[*]:-none}"
    for e in "${B2_NOTRUN[@]}"; do echo "   ${e%%:*}: ${e#*:}"; done
    awk -F'\t' '$1 ~ /\.check\./ { printf "   %-4s %s\n", $2, $1 }' "$OUT/results.tsv"
    exit 0      # the EXIT trap turns a FAIL row into exit status 4
fi

# ---- before any lock or VM: the inputs, the scripts, the modules, the record directory
for f in otp/vmctl.sh otp/log-since.sh otp/install-ours.sh otp/install-env.sh b2ctl.sh; do
    [ -e "$SCRIPTS/$f" ] || { echo "driver-b2.sh: $SCRIPTS/$f is missing" >&2; exit 2; }
done
[ -x "$LAB" ] || { echo "driver-b2.sh: $LAB is not executable" >&2; exit 2; }
# every file in helpers/ has its sha256 line in helpers/SHA256SUMS and equals it (the modules push these files; an unlisted or edited helper stops the run before the lock)
if [ -d "$SCRIPTS/helpers" ]; then
    : > "$OUT/helpers-check.txt"
    for f in "$SCRIPTS"/helpers/*; do
        [ -f "$f" ] || continue
        [ "$(basename "$f")" = SHA256SUMS ] && continue
        grep -q -E "^[0-9a-f]{64}  $(basename "$f")\$" "$SCRIPTS/helpers/SHA256SUMS" 2>/dev/null || echo "NOT LISTED: $(basename "$f")" >> "$OUT/helpers-check.txt"
    done
    if [ -s "$SCRIPTS/helpers/SHA256SUMS" ]; then ( cd "$SCRIPTS/helpers" && sha256sum -c --quiet SHA256SUMS ) >> "$OUT/helpers-check.txt" 2>&1 || echo "SUMS DIFFER" >> "$OUT/helpers-check.txt"; fi
    [ -s "$OUT/helpers-check.txt" ] && { echo "driver-b2.sh: helpers/ does not match helpers/SHA256SUMS:" >&2; cat "$OUT/helpers-check.txt" >&2; exit 2; }
fi
b2_discover
b2_check_all
b2_load
prep_inputs
SRCINFO=$(head -1 "$W/ship-source.txt")
note "DRIVER_START $SRCINFO; lab.sh sha256 $(sha256sum "$LAB" | cut -c1-16); driver-b2.sh sha256 $(sha256sum "${BASH_SOURCE[0]}" | cut -c1-16); modules: ${B2_MODS[*]:-none}"
# a record of an earlier pass lives in a subdirectory; loose files at the top are a pass this one would overwrite
if [ -n "$(find "$REC" -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then echo "driver-b2.sh: $REC holds the files of an earlier pass: move them into a subdirectory first" >&2; exit 2; fi
{
    echo "# the sha256 of every program of the ship build (SHIP=$SHIP); the VMs' copies are compared with these"
    cat "$W/ship-sha256.txt"
    echo "# the B2 scripts: this file, the helper scripts, the modules, the helpers"
    ( cd "$SCRIPTS" && mapfile -t hf < <(find helpers -type f 2>/dev/null | LC_ALL=C sort) && sha256sum "$(basename "${BASH_SOURCE[0]}")" otp/vmctl.sh otp/log-since.sh otp/install-ours.sh otp/install-env.sh b2ctl.sh mod/*.sh "${hf[@]}" )
} > "$OUT/inputs-sha256.txt"
result L0.modules INFO "the modules that run, in order" - "${#B2_MODS[@]}" "${B2_MODS[*]:-none}"
for e in "${B2_NOTRUN[@]}"; do m=${e%%:*}; result "${m^^}.not-run" INFO "module not run" - 0 "NOT-RUN: ${e#*:}"; note "NOT-RUN module $m: ${e#*:}"; done

# ---- the leg's throwaway passwords, on the host only
SECRETS_MADE=1
make_secrets || fail "cannot make the leg's throwaway passwords"
note "the leg's throwaway passwords made under $SECD (b2_pw 1..3); none printed"
b2_hook prep

# ================================================================ L0 lock, pre-status
take_lock
timeout 120 "$LAB" status > "$OUT/pre-status.txt" 2>> "$LOG" || fail "lab.sh status"
cat "$OUT/pre-status.txt" >> "$LOG"
for v in "${VMS[@]}"; do
    if awk -v v="$v" '$1 == v' "$OUT/pre-status.txt" | grep -q 'shut off'; then PRE_STATE[$v]="shut off"
    elif awk -v v="$v" '$1 == v' "$OUT/pre-status.txt" | grep -q ' running '; then PRE_STATE[$v]=running; fi
    note "pre-state $v: [${PRE_STATE[$v]:-}]"
    [ -n "${PRE_STATE[$v]:-}" ] || fail "cannot read the state of $v from the pre-status"
    # a running VM would lose its state to the snapshot reverts
    if [ "${PRE_STATE[$v]}" != "shut off" ] && [ "${ALLOW_RUNNING_PRE:-0}" != 1 ]; then fail "$v is running before the leg (ALLOW_RUNNING_PRE=1 to go on)"; fi
    # the snapshots the leg reverts to must exist
    snaps=$(awk -v v="$v" '$1 == v { print $NF }' "$OUT/pre-status.txt")
    for s in "$RESTSNAP_LEG" "${REST_SNAP[$v]}"; do
        case ",$snaps," in *",$s,"*) ;; *) fail "$v has no snapshot '$s' (it has: $snaps)" ;; esac
    done
done
note "snapshots: the leg runs on $RESTSNAP_LEG; rest: kdc ${REST_SNAP[kdc]}, client2 ${REST_SNAP[client2]}, client1 ${REST_SNAP[client1]}, services services-rust (not used: never started, never touched); all shut off afterwards"
note "services in the pre-status (left as it is): $(awk '$1 == "services"' "$OUT/pre-status.txt" | tr -s ' ')"

# ================================================================ L1 resets, checks, the Fedora identity per VM
note "L1 per VM, the kdc first: reset to $RESTSNAP_LEG, check --lab-only, the helpers, our client programs on the clients, the facts and the MIT identity (the Fedora identity rule: package note, rpm -V config only, klist -V $KLIST_VERSION; a row that fails stops the leg)"
l1_vm kdc
for v in client2 client1; do l1_vm "$v"; done
expect L1.kdc.mit-version "$OUT/vm-facts-kdc.txt" '^krb5-server-1\.22\.2-4\.fc43'
expect L1.kdc.services-active "$OUT/vm-facts-kdc.txt" '^active$' 2
for c in "${CLIENTS[@]}"; do
    expect "L1.$c.kinit" "$OUT/vm-facts-$c.txt" '^/usr/s?bin/kinit$'
    expect "L1.$c.host-keytab" "$OUT/vm-facts-$c.txt" "${HOSTPRINC[$c]}"
    expect "L1.$c.mit-libs" "$OUT/vm-facts-$c.txt" '^krb5-libs-1\.22'
done
# clock skew, host -> VM (recorded: the VMs' clocks agree with each other to a second, which the kinit cells need)
{
    for v in "${VMS[@]}"; do
        t0=$(date +%s.%N); vt=$(vm "$v" "date +%s.%N" 2>> "$LOG"); t1=$(date +%s.%N)
        python3 -B -I -c "import sys; t0,vt,t1=map(float,sys.argv[1:]); print('$v: VM clock minus host clock = %+.3f s (ssh round trip %.3f s)' % (vt-(t0+t1)/2, t1-t0))" "$t0" "$vt" "$t1"
    done
} > "$OUT/clock-skew.txt"
cat "$OUT/clock-skew.txt" >> "$LOG"
[ "$STOP_AFTER" = L1 ] && { note "STOP_AFTER L1"; exit 0; }

# ================================================================ L2 pushes and facts
note "L2 pushes: the ship build's server programs and dist/ (sha256 both sides), then every module's <pkg>_push"
push kdc "$SCRIPTS/otp/install-ours.sh" "$VMD/install-ours.sh" 755 || fail "push install-ours.sh"
push kdc "$SCRIPTS/otp/install-env.sh" "$VMD/install-env.sh" 644 || fail "push install-env.sh"
TARLIST=(); for f in "${SERVER_PROGS[@]}"; do TARLIST+=("release/$f"); done
tar -C "$W/ship" -cf - "${TARLIST[@]}" dist | vm kdc "install -d -m 0700 $VMD/ship && tar -C $VMD/ship -xf -" >> "$LOG" 2>&1 || fail "push the ship tar"
vm kdc "cd $VMD/ship/release && sha256sum ${SERVER_PROGS[*]}" > "$OUT/ship-on-vm.sha256" 2>> "$LOG"
cmp -s "$OUT/ship-on-vm.sha256" "$W/ship-server.sha256" || fail "ship programs on the VM differ from the ship build"
note "the ship build's server programs on the VM equal the host's copy (sha256, seven programs); the clients' five programs were checked at their push"
b2_facts
{
    echo "== the MIT daemons the MIT stage runs: their package"
    vm kdc "rpm -qf /usr/sbin/krb5kdc /usr/sbin/kadmind 2>&1" 2>&1
    echo "== readelf -n /usr/sbin/krb5kdc (.note.package)"
    vm kdc "$(note_cmd /usr/sbin/krb5kdc)" 2>&1
    echo "== grep -a -o 'KRB5_BRAND: [^ ]*' /usr/sbin/krb5kdc | head -1"
    vm kdc "grep -a -o 'KRB5_BRAND: [^ ]*' /usr/sbin/krb5kdc | head -1" 2>&1
} | redact > "$OUT/L2-mit-daemon.txt"
cat "$OUT/L2-mit-daemon.txt" >> "$LOG"
info L2.mit.brand-krb5kdc "$OUT/L2-mit-daemon.txt" '^KRB5_BRAND: ' "absent in Fedora's build (expected; recorded, not judged)"
if ! expect_under L2.mit.package-note-krb5kdc "$OUT/L2-mit-daemon.txt" '^== readelf -n /usr/sbin/krb5kdc ' 'Packaging Metadata: \{"type":"rpm","name":"krb5","version":"'"$PKG_VERSION_RX"'"' && [ "$BRAND_ENFORCE" = 1 ]; then
    fail "the MIT krb5kdc is not the 1.22.2 release's (package note): the push is held"
fi
b2_hook push
[ "$STOP_AFTER" = L2 ] && { note "STOP_AFTER L2"; exit 0; }

# ================================================================ L3 the MIT stage on the stock f4-mit realm: every module's <pkg>_mit, in the module order
note "L3 MIT stage: ${B2_MODS[*]:-no modules}"
B2_AVC_MARK=$(avc_mark)
echo "# getenforce on kdc: $(vm kdc getenforce 2>&1)" > "$OUT/L2-getenforce.txt"
cat "$OUT/L2-getenforce.txt" >> "$LOG"
b2_hook mit
avc_rows AVC-mit "$B2_AVC_MARK"
[ "$STOP_AFTER" = L3 ] && { note "STOP_AFTER L3"; exit 0; }

# ================================================================ L4 docs/install.md "Upgrading an MIT realm", literally, from the ship build
note "L4 install ours (docs/install.md, Upgrading an MIT realm)"
B2_AVC_MARK=$(avc_mark)
timeout 900 "$LAB" ssh kdc -- "sudo bash $VMD/install-ours.sh" > "$OUT/install.txt" 2>&1; irc=$?
cat "$OUT/install.txt" >> "$LOG"
note "INSTALL rc=$irc"
[ "$irc" = 0 ] || fail "install rc=$irc"
want=$(awk '{ n = $2; sub(/^krb5-kdc$/, "krb5kdc", n); sub(/^krb5-kadmind$/, "kadmind", n); sub(/^krb5-kadmin-local$/, "kadmin.local", n); sub(/^krb5-kdb$/, "kdb5_util", n); sub(/^krb5-kprop$/, "kprop", n); sub(/^krb5-kpropd$/, "kpropd", n); if ($2 != "krb5-otp-kdc") print $1, n }' "$W/ship-server.sha256" | sort)
got=$(awk 'length($1) == 64 && $2 ~ /^\/usr\/sbin\// { n = $2; sub(/^\/usr\/sbin\//, "", n); print $1, n }' "$OUT/install.txt" | sort)
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "$want" > "$OUT/want-sha.txt"; echo "$got" > "$OUT/got-sha.txt"; fail "installed daemons differ from the ship build (want-sha.txt got-sha.txt)"; }
note "installed /usr/sbin programs equal the ship build sha256"
grep -q 'active: active active' "$OUT/install.txt" || fail "krb5kdc/kadmin not active after the install"
expect L3.install.restored-kdc-conf "$OUT/install.txt" '^RESTORED:/var/kerberos/krb5kdc/kdc\.conf$'
expect L3.install.alice-listed "$OUT/install.txt" "^alice@$RRX\$"
expect L3.install.admin-listed "$OUT/install.txt" "^admin/admin@$RRX\$"
expect L3.install.requires-preauth-step "$OUT/install.txt" '^Principal ".*" modified\.$'
b2_after_install
[ "$STOP_AFTER" = L4 ] && { note "STOP_AFTER L4"; exit 0; }

# ================================================================ L5 the ship build's stage: every module's <pkg>_ours
note "L5 ours stage: ${B2_MODS[*]:-no modules}"
{ echo "== $(now) after the install"; vm kdc "rpm -qf /usr/sbin/kadmind; systemctl is-active krb5kdc kadmin; rpm -q krb5-libs; sudo ss -H -lnt 'sport = :749'; sudo ss -H -lntu 'sport = :464'" 2>&1; } | redact > "$OUT/vm-facts-rust.txt"
cat "$OUT/vm-facts-rust.txt" >> "$LOG"
b2_hook ours
avc_rows AVC-ours "$B2_AVC_MARK"
[ "$STOP_AFTER" = L5 ] && { note "STOP_AFTER L5"; exit 0; }

# ================================================================ L6 parity per module, with controls
note "L6 parity per module: ${B2_MODS[*]:-no modules}"
b2_hook parity
[ "$STOP_AFTER" = L6 ] && { note "STOP_AFTER L6"; exit 0; }

# ================================================================ L7 the modules' clean, shred on the VMs; the restore, the /tmp check, the publish and the scan run from the EXIT trap
note "L7 clean and shred on the VMs"
b2_clean_hooks
for v in "${VMS[@]}"; do
    vm "$v" "sudo bash $VMD/vmctl.sh clean" 2>&1 | redact > "$OUT/L4-clean-$v.txt"
    cat "$OUT/L4-clean-$v.txt" >> "$LOG"
    expect "L4.$v.clean" "$OUT/L4-clean-$v.txt" '^CLEAN_OK secret files left: 0$'
done
CLEANED=1
package_summary
awk -F'\t' 'BEGIN { p = 0; f = 0; i = 0 } $2 == "PASS" { p++ } $2 == "FAIL" { f++ } $2 == "INFO" { i++ } END { printf "checks so far: %d PASS, %d FAIL, %d INFO (the restore adds its own)\n", p, f, i }' "$OUT/results.tsv" | tee -a "$LOG"
exit 0
