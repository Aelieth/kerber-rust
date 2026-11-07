#!/bin/bash
# driver.sh: the full pass, one production leg across the 1.1 packages on the lab VMs (kdc, client1, client2), MIT realm first, under one lab-lock hold.
#   TREE=<tree id> SHIP=<dir with the built programs> DIST=<checkout with dist/ and docs/install.md> bash driver.sh      (optional: ORACLE=<rd-priv-oracle>, ADMIN_SECRET=<file>)
#   L0 lock + pre-status | L1 reset kdc, client2, client1 to f4-mit, check --lab-only each, the Fedora identity rule per VM (package note of libkrb5 and krb5kdc / kinit = krb5
#      1.22.2-<rel>.fc43, rpm -V config files only with the ostree lone-T reading, klist -V = Kerberos 5 version 1.22.2; a failing row stops the leg here), clock skew
#   L2 pushes (the ship build's server programs and dist/, the three packages' inputs; sha256 both sides) and facts
#   L3 the MIT stage on the stock f4-mit realm: RA r4 (the kpasswd acceptor cells: ra/stage.sh), KA (kadmind's refused-key cells: ka/stage.sh, and MIT kadmin sessions from the clients: ka/session.sh),
#      then OTP (MIT's krb5kdc with its otp.so, a RADIUS stub; C1-C4 with MIT's kinit and ours, both clients; then OTP2's M3, a bad [otp]), which changes kdc.conf and restarts MIT's krb5kdc, so it goes last
#   L4 docs/install.md "Upgrading an MIT realm", literally, from the ship build (dump, dnf remove, install.sh, load, the requires_preauth step), the installed programs equal the ship build
#   L5 the ship build's stage: the same RA r4 cells, KA cells and sessions, then OTP (the example embedder as the KDC: C1-C4, OTP1's replay and DEFAULT cells, OTP2's O3, O4 and O5)
#   L6 parity per package with controls: RA (cmp.py per protocol, the acceptor rows, a doctored copy must part), KA (norm.py per client, the cell lines, doctored copies must differ), OTP (parity.sh with 24 controls, parity-m3o3.sh with 4)
#   L7 shred on the VMs, restore (kdc and client1 to f4-mit, client2 to rust-ssh, all shut off), post-status = pre-status, scan-secrets twice, the host /tmp check, release the locks
# The packages' cells are their own proven scripts, unchanged (scripts/ra, scripts/ka, scripts/otp); this file is the OTP3a/OTP3/OTP4 legs' driver with the RA r4 and KA legs' stage and session
# calls added between its steps. VMs only through harness/field/lab.sh. The lab lock /var/tmp/kr-lab.lock (set -C) is held for the whole VM hold. The seed, the lab password, the MIT stub's codes, the
# TOTP codes, the admin password and the keytabs never enter a record: they live under $SECD on the host or on a VM, and travel on ssh stdin only.
# Environment (the rehearsals use the rest): LAB W OUT REC LOCK HANDLOCK VMD SECD REALM KT SVC HOSTPRINC1 HOSTPRINC2 SOCK SEED_USER OTP_ATTR_Q OTP_ATTR_RX STOP_AFTER (L1 L2 L3 L4 L5)
# REST_SNAP_KDC REST_SNAP_CLIENT1 REST_SNAP_CLIENT2 ALLOW_RUNNING_PRE MAX_LEG_S C3_PW_PROMPTS STAND_IN (1: the MIT stage runs against our programs because the host has no MIT krb5-server: rehearsals only).
set -u
exec < /dev/null
SESSION=full-lab
REPO=${REPO:?REPO is not set}
SCRIPTS=${SCRIPTS:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}   # the scripts directory: otp/ ra/ ka/ beside this file
TREE=${TREE:-}                                      # the tree id the checkout DIST must be (a prefix is enough)
SHIP=${SHIP:-}                                      # the built programs: a cargo release directory or a frozen copy of the eleven programs and rd-sweep
DIST=${DIST:-}                                      # the checkout whose dist/ and docs/install.md the upgrade uses
ORACLE=${ORACLE:-}                                  # RA r4's rd-priv-oracle; built from DIST's source with the host's cc when not given
ADMIN_SECRET=${ADMIN_SECRET:-$HOME/kerber-lab/secrets/mit-realm.admin-admin.password}   # the lab realm's admin/admin password (the KA sessions; stdin only)
LAB=${LAB:-$REPO/harness/field/lab.sh}
W=${W:?W is not set}
OUT=${OUT:-$W/out-$(date -u +%Y%m%dT%H%M%SZ)}
REC=${REC:?REC is not set}
LOCK=${LOCK:-/var/tmp/kr-lab.lock}
HANDLOCK=${HANDLOCK:-$HOME/kerber-lab/state/lab.lock}
VMD=${VMD:-/var/tmp/otp3}
SECD=${SECD:?SECD is not set}
SCANHOME=$SECD/scanhome
REALM=${REALM:-KERBER.TEST}
RRX=${REALM//./\\.}                                # the realm as a regular expression
KT=${KT:-/etc/krb5.keytab}                         # the clients' host keytab
SVC=${SVC:-host/client2.kerber.test@$REALM}        # the service with require_auth, for kvno
SVCP=${SVC%@*}                                     # the same without the realm (kadmin's name for it)
SVCX=${SVC//./\\.}                                 # the same as a regular expression
SOCK=${SOCK:-/run/krb5kdc/otp3.sock}               # the RADIUS stub's socket (M1)
SOCKX=${SOCK//./\\.}
INDICATOR=${INDICATOR:-otpind}
SEED_USER=${SEED_USER:-otpuser}                    # the seeds file's name for the user: [otp] totp = {...} strips the realm
OTP_ATTR_Q=${OTP_ATTR_Q:-'[{""type"":""totp""}]'}  # the otp attribute as kadmin's ss_parse takes it (inside a double-quoted word "" is one ")
OTP_ATTR_RX=${OTP_ATTR_RX:-'\[\{"type":"totp"\}\]'}  # and as getstrs prints it
# The MIT identity of a lab VM (the git authority asked for the brand; Fedora's build of MIT carries no KRB5_BRAND string, so the Director settled
# the Fedora identity rule): the ELF package note of libkrb5 and of the daemon (krb5kdc on the kdc, kinit on a client) names krb5 1.22.2-<rel>.fc43,
# rpm -V lists config files only, klist -V says Kerberos 5 version 1.22.2. A row that fails stops the leg before the MIT stage.
PKG_VERSION_RX='1\.22\.2-[0-9]+\.fc43'
KLIST_VERSION=${KLIST_VERSION:-1.22.2}
NOTE_FALLBACK_RX='{"type":"rpm","name":"krb5","version":"[^"]*"'   # grep -a form of the note, for a VM whose readelf does not run
BRAND_ENFORCE=${BRAND_ENFORCE:-1}              # 1: a row that fails stops the leg before the MIT stage; 0 (only when the Director says so): the rows stay as measured and the leg goes on
RESTSNAP_LEG=f4-mit                                # what L1 resets the three VMs to
MAX_LEG_S=${MAX_LEG_S:-5400}
STAND_IN=${STAND_IN:-0}
C3_PW_PROMPTS=${C3_PW_PROMPTS:-2}   # the password prompts C3 shows after the OTP prompt: one per later mechanism that asks; the lab KDC offers SPAKE and encrypted challenge
SERVER_PROGS=(krb5-kdc krb5-kadmind krb5-kadmin-local krb5-kdb krb5-kprop krb5-kpropd krb5-otp-kdc)   # the server seven: copied to the kdc
CLIENT_PROGS=(krb5-kinit krb5-klist krb5-kvno krb5-kdestroy)                                        # the client four: kinit and klist go to the clients
export TMPDIR=${DRIVER_TMPDIR:?DRIVER_TMPDIR is not set}
case $(realpath -m "$TMPDIR") in /tmp|/tmp/*) echo "driver.sh: TMPDIR $TMPDIR is under the host's /tmp" >&2; exit 2 ;; esac
LOG=${LOG:-$OUT/driver.log}
mkdir -p "$OUT" "$TMPDIR"
: > "$LOG"
# lab.sh reaches virsh through distrobox-host-exec, which runs the host command in the caller's directory: it must exist on the host.
cd "$REPO" || exit 2

now() { date -u +%FT%TZ; }
note() { printf '%s %s\n' "$(now)" "$*" | tee -a "$LOG"; }
lab() { note "+ lab.sh $*"; "$LAB" "$@" >> "$LOG" 2>&1; }
vm() { local v=$1; shift; timeout 900 "$LAB" ssh "$v" -- "$@"; }
vmlog() { local v=$1; shift; note "+ ssh $v: $*"; timeout 900 "$LAB" ssh "$v" -- "$@" >> "$LOG" 2>&1; }
redact() {   # the lab filter, then the same filter over this leg's own secrets (seed, password, the stub's code)
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
        exec 9>&-
        note "LOCK_RELEASED (held $LOCK_T0 to $(now))"
        echo "lab lock $SESSION: taken $LOCK_T0, released $(now)" >> "$OUT/lock-holds.txt"
    fi
}

restore() {   # reset the VMs this leg started to their rest snapshots, shut them off, post-status identical to the pre-status
    [ "$RESTORED" = 1 ] && return 0
    note "RESTORE_START"
    local v
    if [ "$CLEANED" = 0 ]; then   # the leg stopped early: shred what it left on the VMs before the snapshots are reverted
        for v in "${VMS[@]}"; do
            [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
            timeout 60 "$LAB" ssh "$v" -- "sudo bash $VMD/vmctl.sh clean" >> "$LOG" 2>&1 || note "RESTORE: best-effort clean on $v did not run (rc=$?)"
            if [ "$v" = kdc ]; then
                timeout 60 "$LAB" ssh kdc -- "sudo env STAGE=clean D=$RAD bash $RAD/stage.sh; sudo env STAGE=clean D=$KAD bash $KAD/stage.sh; sudo shred -u /var/kerberos/krb5kdc/mit-realm.dump 2>/dev/null; true" >> "$LOG" 2>&1 || note "RESTORE: best-effort clean of the RA r4 and KA files did not run (rc=$?)"
            fi
        done
    fi
    for v in "${VMS[@]}"; do
        if [ "${TOUCHED_VM[$v]:-0}" != 1 ]; then note "RESTORE: $v was never started by this leg: left as it was"; continue; fi
        lab reset "$v" "${REST_SNAP[$v]}" || { note "RESTORE: reset $v ${REST_SNAP[$v]} rc=$?"; LEG_RC=1; REASON="$REASON; reset $v ${REST_SNAP[$v]} failed"; }
    done
    # while they are up on their rest snapshots: nothing of the leg is left on them
    for v in "${VMS[@]}"; do
        [ "${TOUCHED_VM[$v]:-0}" = 1 ] || continue
        { echo "# $(now) $v after the reset to ${REST_SNAP[$v]}"
          "$LAB" ssh "$v" -- "if [ -e $VMD ] || [ -e $RAD ] || [ -e $KAD ]; then echo RESIDUE_PRESENT $VMD $RAD $KAD; else echo RESIDUE_NONE $VMD $RAD $KAD; fi; \
              for f in /var/kerberos/krb5kdc/kdc.conf.otp3-orig /var/kerberos/krb5kdc/mit-realm.dump $SOCK; do if sudo test -e \$f; then echo RESIDUE_PRESENT \$f; fi; done; \
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
    "$LAB" status > "$OUT/post-status.txt" 2>> "$LOG"
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

host_secrets_shred() {   # the seed, the lab password, the MIT stub's codes and the TOTP codes on the host: shredded once the scan has used them
    local f
    for f in "$SECD"/otpuser.seed "$SECD"/otpuser.pw "$SECD"/mit.code "$SECD"/mit.wrong "$SECD"/totp.codes "$SCANHOME"/secrets/*; do
        [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }
    done
    note "HOST_SECRETS shredded under $SECD ($(find "$SECD" -type f 2>/dev/null | wc -l) files left)"
}

publish() {   # the records: transcripts, scripts, statuses, sha lists. No seed, password, code, keytab or dump.
    mkdir -p "$REC"
    cp -rp "$OUT"/* "$REC/" 2>/dev/null
    local f
    mkdir -p "$REC/scripts" && cp -rp "$SCRIPTS"/* "$REC/scripts/" 2>/dev/null
    for f in ship-sha256.txt dist-sha256.txt ship-source.txt; do [ -e "$W/$f" ] && cp -p "$W/$f" "$REC/"; done
    [ -e "$W/oracle/build.txt" ] && cp -p "$W/oracle/build.txt" "$W/oracle/oracle-sha256.txt" "$REC/" 2>/dev/null
    chmod -R go-w "$REC" 2>/dev/null
}
scan() {
    local rc
    cp -p "$LOG" "$REC/driver.log" 2>/dev/null
    note "SCAN_SECRETS (the lab secrets) $REC"
    python3 -B "$REPO/harness/field/lib/scan-secrets.py" "$REC" >> "$LOG" 2>&1; rc=$?
    note "SCAN_SECRETS lab rc=$rc"
    [ "$rc" = 0 ] || { LEG_RC=1; REASON="$REASON; scan-secrets (lab secrets) failed"; }
    note "SCAN_SECRETS (this leg's seed, password and stub code) $REC"
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
stublog_size() { vm kdc "sudo bash $VMD/vmctl.sh stublog-size" 2>> "$LOG" < /dev/null | tr -d '[:space:]'; }
stublog_since() { vm kdc "sudo bash $VMD/vmctl.sh stublog-since $1" 2>> "$LOG" < /dev/null; }

cell_rc() { sed -n 's/^\[rc=\([0-9]*\)\]$/\1/p' "$OUT/$1.txt" | head -1; }
cell() {      # cell NAME VM REMOTE-COMMAND [kdc|kdc+stub]: the command runs with the caller's stdin; transcript -> $OUT/NAME.txt
    local name=$1 vmn=$2 cmd=$3 logs=${4:-kdc} in f="$OUT/$1.txt" km="" sm=""
    in=$(cat)
    km=$(klog_size)
    [ "$logs" = "kdc+stub" ] && sm=$(stublog_size)
    {
        echo "# cell $name on $vmn at $(now)"
        echo "# \$ $cmd"
        echo "# stdin: $( [ -n "$in" ] && echo "$(printf '%s\n' "$in" | wc -l) line(s), not recorded" || echo none )"
        printf '%s\n' "$in" | timeout 300 "$LAB" ssh "$vmn" -- "$cmd" 2>&1
        echo "# end of cell output"
    } | redact > "$f"
    {
        echo
        echo "# KDC log lines added by this cell (/var/log/krb5kdc.log on kdc)"
        klog_since "$km"
        if [ -n "$sm" ]; then echo; echo "# RADIUS stub log lines added by this cell (stub.log on kdc)"; stublog_since "$sm"; fi
    } | redact >> "$f"
    note "CELL $name ($vmn) rc=$(cell_rc "$name") -> $(basename "$f")"
}

restart_cell() {   # restart_cell NAME VM-COMMAND: a service or embedder (re)start on the kdc; the command prints its state and "# KDC log lines added by this cell" itself
    local name=$1 cmd=$2 f="$OUT/$1.txt"
    {
        echo "# cell $name on kdc at $(now)"
        echo "# \$ $cmd"
        timeout 300 "$LAB" ssh kdc -- "$cmd" 2>&1 < /dev/null
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

# the [otp] stanzas of the cells
stanza_none() { :; }
stanza_o1() { printf '[otp]\n    totp = {\n        indicator = %s\n    }\n' "$INDICATOR"; }
stanza_m1() {   # MIT's own: a RADIUS server; the rehearsal's stand-in for MIT's KDC is the embedder, which refuses that stanza (the STRICTER deviation OTP2 showed), so it gets the totp one
    if [ "$STAND_IN" = 1 ]; then stanza_o1; else printf '[otp]\n    DEFAULT = {\n        server = %s\n        indicator = %s\n    }\n' "$SOCK" "$INDICATOR"; fi
}

armor_cmd() { printf 'sudo bash -c %q' "kinit -k -t $KT -c $1 $2 2>&1; echo \"[rc=\$?]\"; klist -e -c $1 2>&1"; }

# ---------------------------------------------------------------- what the kinit prints on stdout, byte for byte (the prompts end in a newline when stdin is not a terminal)
sha_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
STD_C1=$'Enter OTP Token Value: \n'                       # C1 and C2: the OTP prompt only
STD_C4="Password for otpuser@$REALM: "$'\n'               # C4: no armor, no OTP: the password prompt only

# ================================================================ what each cell must show, as functions (so that they can be rehearsed)

expect_part() {   # expect_part LABEL FILE client|kdc|stub EXTENDED-REGEX [COUNT]: expect on one part of a cell file: the client's output, the KDC's log lines, the RADIUS stub's lines
    local label=$1 file=$2 part=$3 rx=$4 want=${5:-} n res
    n=$( { case $part in
               client) sed -n '1,/^# end of cell output/p' "$file" ;;
               kdc) sed -n '/^# KDC log lines added/,/^# RADIUS stub log lines/p' "$file" ;;
               stub) sed -n '/^# RADIUS stub log lines/,$p' "$file" ;;
           esac; } 2>/dev/null | grep -cE -- "$rx" || true)
    if [ -n "$want" ]; then [ "$n" = "$want" ] && res=PASS || res=FAIL
    else [ "${n:-0}" -ge 1 ] && res=PASS || res=FAIL; fi
    result "$label" "$res" "[$part] $rx" "${want:-1+}" "${n:-0}"
    note "CHECK $res $label (want ${want:-1+} of /$rx/ in the $part part of $(basename "$file"), saw ${n:-0})"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

chk_armor() {   # chk_armor LABEL FILE
    expect "$1.armor" "$2" '^\[rc=0\]$'
    expect "$1.armor-tgt" "$2" "krbtgt/$RRX@$RRX"
}

chk_clean() {   # chk_clean LABEL FILE KIND: nothing the record filter masks is in the client's part (it would mean the kinit printed the lab password, a code or the seed), no TOTP code of this leg is
    # anywhere in the cell's file, and (ours) no "ok ..." line and no JSON log line: the shipped program prints only what MIT's does
    local l=$1 f=$2 kind=$3 n
    expect_part "$l.no-secret-marker" "$f" client '<REDACTED:' 0
    n=$(grep -c -F -f "$SECD/totp.codes" "$f" 2>/dev/null || true)
    if [ "${n:-0}" = 0 ]; then result "$l.no-totp-code" PASS "no TOTP code of this leg in the cell's file" 0 0; else result "$l.no-totp-code" FAIL "no TOTP code of this leg in the cell's file" 0 "$n"; NFAIL=$((NFAIL + 1)); fi
    note "CHECK $([ "${n:-0}" = 0 ] && echo PASS || echo FAIL) $l.no-totp-code (TOTP codes of this leg in $(basename "$f"): ${n:-0})"
    if [ "$kind" = ours ]; then
        expect_part "$l.no-ok-line" "$f" client '^ok( |$)' 0
        expect_part "$l.no-json-line" "$f" client '^\{"' 0
    fi
}

chk_c1() {   # chk_c1 LABEL FILE: a right code through the otp module, -T armor: a TGT, pa_type 141, the indicator opens the require_auth service
    local l=$1 f=$2
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.stdout-sha256" "$f" "^stdout-sha256 $(sha_of "$STD_C1")\$"
    expect "$l.stdout-bytes" "$f" "^stdout-bytes ${#STD_C1}\$"
    expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
    expect "$l.ccache" "$f" '^ccache written$'
    expect_under "$l.pa_type-141" "$f" '^== klist -C$' "pa_type\\(krbtgt/$RRX@$RRX\\) = 141"
    expect_under "$l.fast_avail" "$f" '^== klist -C$' "fast_avail\\(krbtgt/$RRX@$RRX\\) = yes"
    expect_under "$l.hint-141" "$f" '^== trace$' 'Processing preauth types:.*PA-OTP-CHALLENGE \(141\)'
    expect_under "$l.otp-module" "$f" '^== trace$' 'Preauth module otp \(141\) \(real\) returned: 0/Success'
    expect_under "$l.request-142" "$f" '^== trace$' 'Produced preauth for next request:.*PA-OTP-REQUEST \(142\)'
    expect_under "$l.kvno" "$f" '^== kvno ' "^$SVCX: kvno = [0-9]+"
    expect "$l.kvno-rc" "$f" '^\[kvno rc=0\]$'
    expect_part "$l.kdc-issue" "$f" kdc "\\(info\\): AS_REQ \\(.*ISSUE: authtime .*otpuser@$RRX for krbtgt/$RRX@$RRX"
    expect_part "$l.tgs-issue" "$f" kdc "\\(info\\): TGS_REQ \\(.*ISSUE: .*otpuser@$RRX for $SVCX"
    info "$l.pa_config_data" "$f" 'pa_config_data' "(none: the token carries no vendor, algID or tokenID)"
    info "$l.hint-list" "$f" 'Processing preauth types:'
}

chk_c2() {   # chk_c2 LABEL FILE: a wrong code: the request is refused, no fallback to the next mechanism, the password on the next stdin line is never read
    local l=$1 f=$2
    expect "$l.rc" "$f" '^\[rc=1\]$'
    expect "$l.stdout-sha256" "$f" "^stdout-sha256 $(sha_of "$STD_C1")\$"
    expect "$l.stdout-bytes" "$f" "^stdout-bytes ${#STD_C1}\$"
    expect_under "$l.stderr-line" "$f" '^== stderr$' '^kinit: Preauthentication failed while getting initial credentials$' 1
    expect_under "$l.stderr-only-line" "$f" '^== stderr$' '.' 1
    expect "$l.no-ccache" "$f" '^no ccache was written$'
    expect_under "$l.hint-141" "$f" '^== trace$' 'Processing preauth types:.*PA-OTP-CHALLENGE \(141\)'
    expect_under "$l.request-142" "$f" '^== trace$' 'Produced preauth for next request:.*PA-OTP-REQUEST \(142\)'
    expect_under "$l.kdc-error" "$f" '^== trace$' 'Received error from KDC: -1765328360/Preauthentication failed' 1
    expect_part "$l.kdc-two-as-reqs" "$f" kdc "\\(info\\): AS_REQ .*otpuser@$RRX" 2
    info "$l.kdc-failure-line" "$f" "PREAUTH_FAILED: otpuser@$RRX"
    info "$l.hint-list" "$f" 'Processing preauth types:'
}

chk_c3() {   # chk_c3 LABEL FILE: end of file at the OTP prompt: the otp module fails with "Cannot read password", then SPAKE and encrypted challenge each ask for the password and read end of file again
    local l=$1 f=$2
    local n_all n_pw
    expect "$l.rc" "$f" '^\[rc=1\]$'
    # stdout: the OTP prompt, then one password prompt per later mechanism that asks. The lab KDC offers 141, 151 and 138, so MIT's kinit asks twice (SPAKE, encrypted challenge): C3_PW_PROMPTS = 2,
    # and the build's kinit must print the same
    expect "$l.stdout-first-line" "$f" '^stdout-line: Enter OTP Token Value: $' 1
    expect "$l.stdout-password-prompts" "$f" "^stdout-line: Password for otpuser@$RRX: \$" "$C3_PW_PROMPTS"
    n_all=$(grep -c '^stdout-line: ' "$f" || true); n_pw=$(grep -c "^stdout-line: Password for otpuser@$RRX: \$" "$f" || true)
    if [ "${n_all:-0}" = "$(( ${n_pw:-0} + 1 ))" ]; then result "$l.stdout-only-prompts" PASS "stdout is the OTP prompt and then password prompts, nothing else" "$(( ${n_pw:-0} + 1 )) lines" "$n_all"
    else result "$l.stdout-only-prompts" FAIL "stdout is the OTP prompt and then password prompts, nothing else" "$(( ${n_pw:-0} + 1 )) lines" "$n_all"; NFAIL=$((NFAIL + 1)); fi
    note "CHECK $([ "${n_all:-0}" = "$(( ${n_pw:-0} + 1 ))" ] && echo PASS || echo FAIL) $l.stdout-only-prompts (stdout lines ${n_all:-0}, password prompts ${n_pw:-0})"
    expect_under "$l.stderr-line" "$f" '^== stderr$' '^kinit: Pre-authentication failed: Cannot read password while getting initial credentials$' 1
    expect_under "$l.stderr-only-line" "$f" '^== stderr$' '.' 1
    expect "$l.no-ccache" "$f" '^no ccache was written$'
    expect_under "$l.hint-141" "$f" '^== trace$' 'Processing preauth types:.*PA-OTP-CHALLENGE \(141\)'
    expect_under "$l.hint-151-138" "$f" '^== trace$' 'Processing preauth types:.*PA-OTP-CHALLENGE \(141\), PA-SPAKE \(151\), PA-ENCRYPTED-CHALLENGE \(138\)'
    expect_under "$l.otp-module" "$f" '^== trace$' 'Preauth module otp \(141\) \(real\) returned: -1765328254/Cannot read password' 1
    expect_under "$l.spake-challenge" "$f" '^== trace$' 'SPAKE challenge received with group 1, pubkey' 1
    expect_under "$l.spake-module" "$f" '^== trace$' 'Preauth module spake \(151\) \(real\) returned: -1765328254/Cannot read password' 1
    expect_under "$l.encrypted-challenge-module" "$f" '^== trace$' 'Preauth module encrypted_challenge \(138\) \(real\) returned: -1765328254/Cannot read password' 1
    expect_order "$l.mechanism-order" "$f" 'Preauth module otp \(141\) \(real\) returned: -1765328254/Cannot read password' 'SPAKE challenge received with group 1, pubkey' \
        'Preauth module spake \(151\) \(real\) returned: -1765328254/Cannot read password' 'Preauth module encrypted_challenge \(138\) \(real\) returned: -1765328254/Cannot read password'
    info "$l.kdc-as-reqs" "$f" "\\(info\\): AS_REQ .*otpuser@$RRX"
}

chk_c4() {   # chk_c4 LABEL FILE: no armor, so no OTP: the password path; a TGT without the indicator, which the require_auth service refuses
    local l=$1 f=$2
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.stdout-sha256" "$f" "^stdout-sha256 $(sha_of "$STD_C4")\$"
    expect "$l.stdout-bytes" "$f" "^stdout-bytes ${#STD_C4}\$"
    expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
    expect "$l.ccache" "$f" '^ccache written$'
    expect_under "$l.no-141-ticket" "$f" '^== klist -C$' "pa_type\\(krbtgt/$RRX@$RRX\\) = 141" 0
    expect_under "$l.no-141-hint" "$f" '^== trace$' 'Processing preauth types:.*\(141\)' 0
    expect_under "$l.hint-list-present" "$f" '^== trace$' 'Processing preauth types:'
    expect_under "$l.kvno-refused" "$f" '^== kvno ' "^kvno: KDC policy rejects request while getting credentials for $SVCX\$"
    expect "$l.kvno-rc" "$f" '^\[kvno rc=1\]$'
    expect_part "$l.kdc-indicator" "$f" kdc 'Required auth indicators not present'
    info "$l.hint-list" "$f" 'Processing preauth types:'
    info "$l.pa_type" "$f" 'pa_type\(krbtgt/'
}

chk_stub() {   # chk_stub LABEL FILE CELL: what the RADIUS stub of the MIT stage saw (a stand-in KDC has none)
    local l=$1 f=$2
    [ "$STAND_IN" = 1 ] && return 0
    case $3 in
        C1) expect_part "$l.stub-accept" "$f" stub 'verdict: accept'
            expect_part "$l.stub-user" "$f" stub "attr +1 User-Name: b'otpuser'\$" ;;
        C2) expect_part "$l.stub-reject" "$f" stub 'verdict: reject' ;;
        C3|C4) expect_part "$l.stub-not-asked" "$f" stub 'Access-Request' 0 ;;
    esac
}

# ---------------------------------------------------------------- the codes: the MIT stage's stub accepts one lab code; our KDC (and a stand-in for MIT's in the rehearsals) the current TOTP
code_right() {   # code_right STAGE: the code a right login uses; a TOTP is recorded (fixed strings, under SECD) for the leak check
    local c
    if [ "$1" = O ] || [ "$STAND_IN" = 1 ]; then
        c=$(python3 -B -I "$SCRIPTS/otp/totp.py" fresh "$SEED" "$W/used-steps" --offset "$OFFSET" 2>> "$LOG")
        printf '%s\n' "$c" >> "$SECD/totp.codes"
    else
        c=$MITCODE
    fi
    printf '%s' "$c"
}
code_wrong() {   # code_wrong STAGE: a code the verifier refuses
    local c
    if [ "$1" = O ] || [ "$STAND_IN" = 1 ]; then
        c=$(python3 -B -I "$SCRIPTS/otp/totp.py" wrong "$SEED" --offset "$OFFSET" 2>> "$LOG")
        printf '%s\n' "$c" >> "$SECD/totp.codes"
    else
        c=$MITWRONG
    fi
    printf '%s' "$c"
}

# ---------------------------------------------------------------- the cells
kcell() {   # kcell NAME VM mit|ours ARMOR|- CC [kdc|kdc+stub]: one kinit login of otpuser; the stdin of this function is exactly what the kinit gets on its own stdin; transcript -> $OUT/NAME.txt
    local name=$1 vmn=$2 kind=$3 arm=$4 cc=$5 logs=${6:-kdc} in f="$OUT/$1.txt" km="" sm="" kin cmd
    in=$(cat; printf x); in=${in%x}
    case $kind in mit) kin=/usr/bin/kinit ;; ours) kin=$VMD/ours/kinit ;; *) fail "kcell: kind $kind" ;; esac
    cmd="sudo bash $VMD/vmctl.sh kcell $kin $arm $cc $SVC"
    km=$(klog_size)
    [ "$logs" = "kdc+stub" ] && sm=$(stublog_size)
    {
        echo "# cell $name on $vmn at $(now)"
        echo "# \$ $cmd"
        echo "# stdin: ${#in} byte(s) offered, $(printf '%s' "$in" | wc -l) newline(s), not recorded"
        printf '%s' "$in" | timeout 300 "$LAB" ssh "$vmn" -- "$cmd" 2>&1
        echo "# end of cell output"
    } | redact > "$f"
    {
        echo
        echo "# KDC log lines added by this cell (/var/log/krb5kdc.log on kdc)"
        klog_since "$km"
        if [ -n "$sm" ]; then echo; echo "# RADIUS stub log lines added by this cell (stub.log on kdc)"; stublog_since "$sm"; fi
    } | redact >> "$f"
    note "CELL $name ($vmn, $kind kinit) rc=$(cell_rc "$name") -> $(basename "$f")"
}

locator_capture() {   # locator_capture WHEN: client1 sssd pubconf, read-only
    local when=$1
    local f="$OUT/locator-client1-$when.txt"
    note "LOCATOR client1 $when"
    vm client1 "echo WHEN $when; echo ==ls; ls -l --time-style=full-iso /var/lib/sss/pubconf/; echo ==kdcinfo; cat /var/lib/sss/pubconf/kdcinfo.KERBER.TEST 2>&1; echo ==journal; journalctl -u sssd --since '$LEG_START' --no-pager | grep -i -E 'kdcinfo|KERBER.TEST' | tail -20" > "$f" 2>&1 || true
    cat "$f" >> "$LOG"
}

run_cell() {   # run_cell STAGE CELL KIND CLIENT: one of C1..C4 with one of the two kinits, then what it must show
    local s=$1 k=$2 kind=$3 c=$4 code
    local name="$s$k-k$kind-$c" l="$s$k.k$kind.$c" arm="$VMD/armor-$s-k$kind.cc" cc="$VMD/$s$k-k$kind-$c.cc" logs=kdc
    [ "$s" = M ] && [ "$STAND_IN" != 1 ] && logs=kdc+stub
    deadline
    [ "$c" = client1 ] && [ "$k" = C1 ] && locator_capture "before-$name"
    case $k in
        C1) code=$(code_right "$s"); printf '%s\n' "$code" | kcell "$name" "$c" "$kind" "$arm" "$cc" "$logs"; chk_c1 "$l" "$OUT/$name.txt" ;;
        C2) code=$(code_wrong "$s"); printf '%s\n%s\n' "$code" "$PW" | kcell "$name" "$c" "$kind" "$arm" "$cc" "$logs"; chk_c2 "$l" "$OUT/$name.txt" ;;
        C3) kcell "$name" "$c" "$kind" "$arm" "$cc" "$logs" < /dev/null; chk_c3 "$l" "$OUT/$name.txt" ;;
        C4) printf '%s\n' "$PW" | kcell "$name" "$c" "$kind" - "$cc" "$logs"; chk_c4 "$l" "$OUT/$name.txt" ;;
        *) fail "run_cell: cell $k" ;;
    esac
    [ "$c" = client1 ] && [ "$k" = C1 ] && locator_capture "after-$name"
    chk_clean "$l" "$OUT/$name.txt" "$kind"
    [ "$s" = M ] && chk_stub "$l" "$OUT/$name.txt" "$k"
    return 0
}

stage_cells() {   # stage_cells STAGE: per kinit and per client: the armor, then C1 (right code), C2 (wrong code), C3 (end of file), C4 (no armor)
    local s=$1 kind c k
    for kind in mit ours; do
        for c in "${CLIENTS[@]}"; do
            deadline
            cell "$s-armor-k$kind-$c" "$c" "$(armor_cmd "$VMD/armor-$s-k$kind.cc" "${HOSTPRINC[$c]}")" kdc < /dev/null
            chk_armor "$s.armor.k$kind.$c" "$OUT/$s-armor-k$kind-$c.txt"
            for k in C1 C2 C3 C4; do run_cell "$s" "$k" "$kind" "$c"; done
        done
    done
}

summarize_hints() {
    local f
    {
        echo "# the first preauth hint list each login cell saw (KRB5_TRACE 'Processing preauth types') and the pa_type of the TGT it got"
        for f in "$OUT"/MC?-k*-client?.txt "$OUT"/OC?-k*-client?.txt; do
            [ -e "$f" ] || continue
            printf '%s\n  hints:  %s\n  ticket: %s\n' "$(basename "$f" .txt)" \
                "$(grep -m1 'Processing preauth types:' "$f" | sed 's/^.*Processing preauth types: //')" \
                "$( (grep -m1 'pa_type(krbtgt' "$f" || echo "no TGT") | sed 's/^.*config: //')"
        done
    } > "$OUT/hints.txt"
}

make_secrets() {   # the lab-only seed, password and MIT stub code under $SECD (0600), and copies under $SCANHOME for the leg's own scan
    local f
    mkdir -p "$SCANHOME/secrets"; chmod 700 "$SECD" "$SCANHOME" "$SCANHOME/secrets"
    for f in "$SECD"/otpuser.seed "$SECD"/otpuser.pw "$SECD"/mit.code "$SECD"/mit.wrong "$SECD"/totp.codes "$SCANHOME"/secrets/*; do [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; done
    python3 -B -I - "$SECD" <<'PY'
import base64, os, secrets, sys
d = sys.argv[1]
while True:
    raw = os.urandom(20)
    if 0x80 <= raw[0] < 0xC0:          # an invalid UTF-8 start byte: the scanner then treats the raw bytes as a key
        break
def w(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
b32 = base64.b32encode(raw).decode()
w(os.path.join(d, "otpuser.seed"), b32 + "\n")
w(os.path.join(d, "scanhome", "secrets", "otp.seed"), b32 + "\n")
w(os.path.join(d, "scanhome", "secrets", "otp.seed.raw"), raw)
pw = secrets.token_hex(12)
w(os.path.join(d, "otpuser.pw"), pw + "\n")
w(os.path.join(d, "scanhome", "secrets", "otpuser.pw"), pw + "\n")
# the MIT stub's code: any text does. Twelve hex digits are far from any six-digit stamp, so the scan has no false hit on it.
code = secrets.token_hex(6)
w(os.path.join(d, "mit.code"), code + "\n")
w(os.path.join(d, "scanhome", "secrets", "mit.code"), code + "\n")
# and a wrong one, for the cells that must be refused (never the right one)
while True:
    wrong = secrets.token_hex(6)
    if wrong != code:
        break
w(os.path.join(d, "mit.wrong"), wrong + "\n")
w(os.path.join(d, "scanhome", "secrets", "mit.wrong"), wrong + "\n")
PY
}

note_cmd() {   # note_cmd FILE: the command a VM runs to print FILE's ELF package note: readelf -n, else grep -a (and it says which)
    local f=$1
    cat <<EOF
if readelf -n $f > /dev/null 2>&1; then echo "(read with readelf -n)"; readelf -n $f | sed -n '/Displaying notes found in: .note.package/,/Packaging Metadata:/p'; else echo "(readelf is not usable on this VM: the same note read with grep -a)"; grep -a -o '$NOTE_FALLBACK_RX' $f | head -1 | sed 's/^/    Packaging Metadata: /'; fi
EOF
}

push_ours() {   # push_ours VM: our kinit and klist on a client, on ssh stdin (sha256 checked on both sides), under the names dist/install.sh install-clients gives them
    local v=$1 k l
    push "$v" "$W/ship/release/krb5-kinit" "$VMD/ours/kinit" 755 || return 1
    push "$v" "$W/ship/release/krb5-klist" "$VMD/ours/klist" 755 || return 1
    {
        echo "# our client programs on $v: copies of the ship build's krb5-kinit and krb5-klist, run from $VMD/ours as kinit and klist (the names dist/install.sh install-clients gives them;"
        echo "# a program's error lines carry its own name, and MIT's say \"kinit:\"); the clients' own libkrb5, /etc/krb5.conf and MIT's klist and kvno are untouched"
        vm "$v" "cd $VMD/ours && ls -l kinit klist && sha256sum kinit klist" 2>&1
        echo "== $VMD/ours/klist -V (it runs here: not a noexec /var/tmp)"
        vm "$v" "$VMD/ours/klist -V" 2>&1
    } | redact > "$OUT/L1-ours-$v.txt"
    cat "$OUT/L1-ours-$v.txt" >> "$LOG"
    k=$(awk '$2 == "krb5-kinit" { print $1 }' "$W/ship-local.sha256")
    l=$(awk '$2 == "krb5-klist" { print $1 }' "$W/ship-local.sha256")
    expect "L1.$v.ours-kinit-sha256" "$OUT/L1-ours-$v.txt" "^$k  kinit\$"
    expect "L1.$v.ours-klist-sha256" "$OUT/L1-ours-$v.txt" "^$l  klist\$"
    expect "L1.$v.ours-klist-runs" "$OUT/L1-ours-$v.txt" '^Kerberos 5 version 1\.22\.2$'
    return 0   # a row that failed is counted; the leg goes on (the cells show what does not run)
}

l1_vm() {   # l1_vm VM: reset to f4-mit, check, the helper pushed, the facts and the MIT identity
    local v=$1 crc pk="krb5-libs krb5-workstation" nrx daemon="/usr/bin/kinit" ost
    [ "$v" = kdc ] && { pk="$pk krb5-server"; daemon=/usr/sbin/krb5kdc; }
    TOUCHED=1; TOUCHED_VM[$v]=1
    lab reset "$v" "$RESTSNAP_LEG" || fail "reset $v $RESTSNAP_LEG"
    "$LAB" check --lab-only "$v" > "$OUT/l1-check-$v.txt" 2>&1; crc=$?
    cat "$OUT/l1-check-$v.txt" >> "$LOG"
    note "L1 check --lab-only $v rc=$crc"
    [ "$crc" = 0 ] || fail "lab.sh check --lab-only $v rc=$crc"
    vmlog "$v" "install -d -m 0700 $VMD" || fail "no ssh to $v"
    push "$v" "$SCRIPTS/otp/vmctl.sh" "$VMD/vmctl.sh" 755 || fail "push vmctl.sh to $v"
    push "$v" "$SCRIPTS/otp/log-since.sh" "$VMD/log-since.sh" 755 || fail "push log-since.sh to $v"
    if [ "$v" != kdc ]; then push_ours "$v" || fail "push our kinit and klist to $v"; fi
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


# ================================================================ the other packages' cells: RA r4 (the kpasswd acceptor) and KA (kadmind's refused keys, MIT kadmin sessions)
# Their cells are their own proven scripts, unchanged (scripts/ra/stage.sh, scripts/ka/stage.sh, scripts/ka/session.sh) run on the VMs exactly as their drivers ran them;
# what follows is the thin driver side: the pushes, the stage call, the pulls, the compare calls and the rows. The stage functions are the RA r4 driver's stage() and
# the KA driver's stage() and sessions() with their directory variables renamed and the output files kept under $OUT/ra and $OUT/ka.
RAD=${RAD:-/var/tmp/ra4}               # the RA r4 leg's directory on the kdc VM (stage.sh's own default D; the rehearsals set it)
KAD=${KAD:-/var/tmp/ka2}               # the KA leg's directory on the kdc VM (stage.sh's own default D; the rehearsals set it)
KA_CLIENTS=()                          # the clients that have MIT kadmin: the KA sessions run from them

verdict() {   # verdict LABEL PASS|FAIL RX WANT GOT [TEXT]: a row decided by the caller
    local label=$1 res=$2
    shift 2
    result "$label" "$res" "$@"
    note "CHECK $res $label ($*)"
    [ "$res" = PASS ] && return 0
    NFAIL=$((NFAIL + 1)); return 1
}

ra_push() {   # the RA r4 leg's inputs on the kdc, on ssh stdin with sha256 checked on both sides
    push kdc "$ORACLE" "$RAD/rd-priv-oracle" 755 || return 1
    push kdc "$W/ship/release/rd-sweep" "$RAD/rd-sweep" 755 || return 1
    push kdc "$SCRIPTS/ra/kpwsend.py" "$RAD/kpwsend.py" 644 || return 1
    push kdc "$SCRIPTS/ra/frames-nokey.tsv" "$RAD/frames-nokey.tsv" 644 || return 1
    push kdc "$SCRIPTS/ra/stage.sh" "$RAD/stage.sh" 755 || return 1
}
ka_push() {   # the KA leg's inputs on the kdc
    push kdc "$W/ship/release/rd-sweep" "$KAD/rd-sweep" 755 || return 1
    push kdc "$SCRIPTS/ka/stage.sh" "$KAD/stage.sh" 755 || return 1
}

ra_getf() {   # ra_getf NAME-ON-VM LOCAL-NAME: an outcome file off the kdc VM, through the record filter (ids, wire classes and log lines only)
    vm kdc "test -s $RAD/$1 && cat $RAD/$1" 2>> "$LOG" | redact > "$OUT/ra/$2"
    [ "${PIPESTATUS[0]}" = 0 ] && [ -s "$OUT/ra/$2" ] || { note "PULL_FAILED ra $1"; return 1; }
}

ra_stage() {   # ra_stage mit|rust: the RA r4 driver's stage(): stage.sh as root on the kdc, then its outcome files
    local st=$1 rc f2="$OUT/ra/stage-$1.log"
    deadline
    note "RA STAGE $st START"
    timeout 2400 "$LAB" ssh kdc -- "sudo env STAGE=$st D=$RAD SIP=${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}.10 bash $RAD/stage.sh" 2>&1 | redact > "$f2"; rc=${PIPESTATUS[0]}
    cat "$f2" >> "$LOG"
    note "RA STAGE $st rc=$rc"
    verdict "RA.$st.stage-rc" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" "stage.sh exit status" 0 "$rc" || return 1
    expect "RA.$st.no-abort-token" "$f2" 'STAGE_ABORT|ACCEPTOR_ASSERT_FAIL|SANITY_FAIL' 0
    expect "RA.$st.principal-and-key" "$f2" '^Entry for principal kadmin/changepw with kvno [0-9]+, encryption type .* added to keytab'
    expect "RA.$st.acceptor-rows" "$f2" '^acceptor rows=652 accepts=75 pristine_ok=3 \(want 652 75 3\)$'
    expect "RA.$st.sanity" "$f2" '^SANITY_OK$'
    ra_getf_all "$st"
}
ra_getf_all() {   # ra_getf_all mit|rust: the outcome files off the VM
    local st=$1 f
    for f in acc-$st.tsv $st-udp.tsv $st-tcp.tsv $st-udp-setpw.tsv $st-tcp-setpw.tsv; do ra_getf "$f" "$f" || verdict "RA.$st.pull-$f" FAIL "outcome file pulled" 1 0; done
    if [ "$st" = rust ]; then
        ra_getf judge.txt judge.txt || verdict "RA.rust.pull-judge.txt" FAIL "outcome file pulled" 1 0
        expect "RA.rust.judge-rc" "$OUT/ra/stage-rust.log" '^judge_rc=0$'
        expect "RA.rust.judge-0-parts" "$OUT/ra/stage-rust.log" '^0 of 652 cases part from MIT$'
    fi
}

ra_compare() {   # the RA r4 driver's compare(): cmp.py on the four pairs, and the library acceptor's two files; a control proves cmp.py can fail
    local v p line n of rc f ctl
    for v in "" "-setpw"; do
        for p in udp tcp; do
            f="$OUT/ra/cmp-$p$v.txt"
            if [ -s "$OUT/ra/mit-$p$v.tsv" ] && [ -s "$OUT/ra/rust-$p$v.tsv" ]; then
                python3 -B "$SCRIPTS/ra/cmp.py" "$OUT/ra/mit-$p$v.tsv" "$OUT/ra/rust-$p$v.tsv" > "$f"; rc=$?
                line=$(tail -1 "$f"); n=${line%% of *}; of=${line#* of }; of=${of%% *}
                verdict "RA.cmp.$p$v" "$([ "$rc" = 0 ] && [ "$n" = 0 ] && [ "${of:-0}" -gt 0 ] && echo PASS || echo FAIL)" "cmp.py: no cell parts from MIT" "0 of >0" "$line"
                result "RA.cmp.$p$v.cells" INFO "cells compared" - "${of:-0}" "$(grep -c '^SAME' "$f") SAME"
                if grep -q $'^EXPECTED\tframe/aplen-zero\t' "$f"; then
                    result "RA.cmp.$p$v.aplen-zero" INFO "row 50 expected DIFF (368e126f): MIT answers, ours drops" - "EXPECTED" "docs/mit-deviations.md row 50"
                fi
            else
                verdict "RA.cmp.$p$v" FAIL "cmp.py: no cell parts from MIT" "0 of >0" "an outcome file is missing"
            fi
        done
    done
    if cmp -s "$OUT/ra/acc-mit.tsv" "$OUT/ra/acc-rust.tsv" && [ -s "$OUT/ra/acc-mit.tsv" ]; then
        verdict RA.cmp.acceptor-rows PASS "the library acceptor's rows: MIT's and the ship build's equal byte for byte" equal equal "$(wc -l < "$OUT/ra/acc-mit.tsv") rows"
    else
        verdict RA.cmp.acceptor-rows FAIL "the library acceptor's rows: MIT's and the ship build's equal byte for byte" equal differ ""
    fi
    # the control: the ship build's UDP outcomes with one REP cell turned into an error must part from MIT's, or the comparison cannot fail
    ctl="$OUT/ra/control-rust-udp.tsv"
    awk -F'\t' 'BEGIN { OFS = "\t" } !d && $3 ~ /^REP/ { $3 = "ERR:99:99:control"; d = 1 } { print }' "$OUT/ra/rust-udp.tsv" > "$ctl" 2>/dev/null
    python3 -B "$SCRIPTS/ra/cmp.py" "$OUT/ra/mit-udp.tsv" "$ctl" > "$OUT/ra/cmp-control.txt" 2>&1; rc=$?
    verdict RA.control.cmp-can-fail "$([ "$rc" = 1 ] && tail -1 "$OUT/ra/cmp-control.txt" | grep -q '^1 of ' && echo PASS || echo FAIL)" "cmp.py on a doctored copy must part (exit 1, 1 cell)" "1 of N" "$(tail -1 "$OUT/ra/cmp-control.txt")"
    rm -f "$ctl"
}

ka_stage() {   # ka_stage mit|rust: the KA driver's stage(): the refused-key cells on the kdc
    local st=$1 rc f2="$OUT/ka/stage-$1.log"
    deadline
    note "KA STAGE $st START"
    timeout 900 "$LAB" ssh kdc -- "sudo env STAGE=$st D=$KAD bash $KAD/stage.sh" 2>&1 | redact > "$f2"; rc=${PIPESTATUS[0]}
    cat "$f2" >> "$LOG"
    note "KA STAGE $st rc=$rc"
    verdict "KA.$st.stage-rc" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" "stage.sh exit status" 0 "$rc" || return 1
    expect "KA.$st.no-failed-cell" "$f2" 'STAGE_ABORT|CELL_FAIL|CELLS_FAIL' 0
    expect "KA.$st.cells-ok" "$f2" '^CELLS_OK$'
    expect "KA.$st.first-key-rpcsec" "$f2" 'flavor=rpcsec: ACCEPTED gss_major=0 GSS_S_COMPLETE'
    expect "KA.$st.first-key-agss" "$f2" 'flavor=agss: ACCEPTED gss_major=0 GSS_S_COMPLETE'
    expect "KA.$st.later-key-rpcsec-refused" "$f2" 'flavor=rpcsec: DENIED auth_stat=2 AUTH_REJECTEDCRED'
    expect "KA.$st.later-key-agss-refused" "$f2" 'flavor=agss: ACCEPTED gss_major=851968 GSS_S_FAILURE'
}

ka_sessions() {   # ka_sessions mit|rust: the KA driver's sessions(): the same kadmin session from each client that has kadmin (the admin password is the first stdin line)
    local st=$1 c rc f
    for c in "${KA_CLIENTS[@]}"; do
        deadline
        f="$OUT/ka/session-$c-$st.txt"
        note "KA SESSION $st from $c"
        { cat "$ADMIN_SECRET"; cat "$SCRIPTS/ka/session.sh"; } | timeout 300 "$LAB" ssh "$c" -- "IFS= read -r ADMIN_PW; export ADMIN_PW; exec sh -s ka2${c}probe" 2>&1 | redact > "$f"; rc=${PIPESTATUS[1]}
        note "KA SESSION $st $c rc=$rc: $(tail -1 "$f")"
        verdict "KA.$st.session-$c.rc" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" "ssh exit status" 0 "$rc"
        expect "KA.$st.session-$c.done" "$f" '^SESSION_DONE$'
        # a session that did nothing proves nothing: the probe principal was created and deleted
        expect "KA.$st.session-$c.probe-created" "$f" "Principal \"ka2${c}probe@$RRX\" created"
        expect "KA.$st.session-$c.probe-deleted" "$f" "Principal \"ka2${c}probe@$RRX\" deleted"
    done
}

ka_compare() {   # the KA driver's L7: norm.py on each client's two sessions, the cells' lines on both daemons; controls prove both can fail
    local c r st f ctl
    for c in "${KA_CLIENTS[@]}"; do
        python3 -B "$SCRIPTS/ka/norm.py" "$OUT/ka/session-$c-mit.txt" "$OUT/ka/session-$c-rust.txt" > "$OUT/ka/cmp-$c.txt" 2>&1; r=$?
        verdict "KA.cmp.session-$c" "$([ "$r" = 0 ] && echo PASS || echo FAIL)" "norm.py: the two sessions identical" IDENTICAL "$(tail -1 "$OUT/ka/cmp-$c.txt")"
    done
    for st in mit rust; do grep -E '^kadmind-init' "$OUT/ka/stage-$st.log" | sed -E 's/ handle=[0-9]+B//' > "$OUT/ka/cells-$st.txt"; done
    if diff -u "$OUT/ka/cells-mit.txt" "$OUT/ka/cells-rust.txt" > "$OUT/ka/cmp-cells.txt" && [ -s "$OUT/ka/cells-mit.txt" ]; then
        verdict KA.cmp.cells PASS "the refused-key cells: the same lines on both daemons (the handle size masked)" equal equal "$(wc -l < "$OUT/ka/cells-mit.txt") lines"
    else
        verdict KA.cmp.cells FAIL "the refused-key cells: the same lines on both daemons (the handle size masked)" equal differ "$(wc -l < "$OUT/ka/cells-mit.txt") lines"
    fi
    # controls: a doctored session and a doctored cell line must be seen
    c=${KA_CLIENTS[0]:-}
    if [ -n "$c" ] && [ -s "$OUT/ka/session-$c-rust.txt" ]; then
        ctl="$OUT/ka/control-session.txt"
        sed '0,/^==== listprincs/s//==== listprincs (control)/' "$OUT/ka/session-$c-rust.txt" > "$ctl"
        python3 -B "$SCRIPTS/ka/norm.py" "$OUT/ka/session-$c-mit.txt" "$ctl" > "$OUT/ka/cmp-control-session.txt" 2>&1; r=$?
        verdict KA.control.norm-can-fail "$([ "$r" = 1 ] && echo PASS || echo FAIL)" "norm.py on a doctored session must differ (exit 1)" 1 "$r"
        rm -f "$ctl"
    fi
    ctl="$OUT/ka/control-cells.txt"
    sed '0,/ACCEPTED/s//DENIED/' "$OUT/ka/cells-rust.txt" > "$ctl"
    if diff -q "$OUT/ka/cells-mit.txt" "$ctl" > /dev/null; then verdict KA.control.cells-can-fail FAIL "the cell diff on a doctored cell line must differ" differ same ""
    else verdict KA.control.cells-can-fail PASS "the cell diff on a doctored cell line must differ" differ differ ""; fi
    rm -f "$ctl"
}

ra_ka_facts() {   # the facts the RA r4 and KA drivers recorded before their MIT stage, as rows
    local c n
    {
        echo "== $(now) the kdc at f4-mit, before the MIT stage"
        echo "== python3"; vm kdc "python3 --version" 2>&1
        echo "== ldd $RAD/rd-priv-oracle: libraries not found"; vm kdc "ldd $RAD/rd-priv-oracle | grep -c 'not found'" 2>&1
        echo "== /var/log/kadmind.log"; vm kdc "ls -l /var/log/kadmind.log" 2>&1
        echo "== :464 listeners"; vm kdc "sudo ss -H -lntu 'sport = :464' | grep -c ." 2>&1
        echo "== :749 listeners"; vm kdc "sudo ss -H -lnt 'sport = :749' | grep -c ." 2>&1
        for c in "${CLIENTS[@]}"; do echo "== kadmin on $c"; vm "$c" "command -v kadmin" 2>&1; done
    } 2>&1 | redact > "$OUT/RA-KA-facts.txt"
    cat "$OUT/RA-KA-facts.txt" >> "$LOG"
    expect RA.facts.python3 "$OUT/RA-KA-facts.txt" '^Python 3\.'
    expect_under RA.facts.oracle-libraries "$OUT/RA-KA-facts.txt" '^== ldd ' '^0$'
    expect RA.facts.kadmind-log "$OUT/RA-KA-facts.txt" 'kadmind\.log$'
    expect_under RA.facts.464-listening "$OUT/RA-KA-facts.txt" '^== :464 listeners' '^[1-9][0-9]*$'
    expect_under KA.facts.749-listening "$OUT/RA-KA-facts.txt" '^== :749 listeners' '^[1-9][0-9]*$'
    KA_CLIENTS=()
    for c in "${CLIENTS[@]}"; do
        if expect_under "KA.facts.kadmin-on-$c" "$OUT/RA-KA-facts.txt" "^== kadmin on $c\$" '/kadmin$'; then KA_CLIENTS+=("$c"); fi
    done
    note "KA: kadmin clients: ${KA_CLIENTS[*]:-none}"
}

# ================================================================ the OTP package's setup and teardown around its cells (stage_cells: the OTP3a driver's, unchanged)
otp_mit_setup() {   # the stub up, kdc.conf [otp] DEFAULT, MIT's krb5kdc restarted, otpuser keyed, the otp attribute, require_auth on the service
    # the stand-in (rehearsal only) is the embedder as the "MIT" KDC: it reads the seeds file the real leg pushes later
    if [ "$STAND_IN" = 1 ]; then
        printf '%s %s\n' "otpuser@KERBER.TEST" "$(cat "$SEED")" | vm kdc "install -d -m 0700 $VMD && cat > $VMD/totp.seeds && chmod 600 $VMD/totp.seeds" 2>&1 | redact >> "$LOG"
        vm kdc "cp -p $VMD/ship/release/krb5-otp-kdc $VMD/krb5-otp-kdc && chmod 755 $VMD/krb5-otp-kdc" >> "$LOG" 2>&1
    fi
    printf '%s\n' "$MITCODE" | vm kdc "sudo bash $VMD/vmctl.sh stub-start $SOCK" 2>&1 | redact > "$OUT/L2-stub-start.txt"
    cat "$OUT/L2-stub-start.txt" >> "$LOG"
    expect L2.stub.listening "$OUT/L2-stub-start.txt" "listening on $SOCKX"
    set_conf L2-conf-M1 stanza_m1
    if [ "$STAND_IN" = 1 ]; then expect L2.conf-M1.totp "$OUT/L2-conf-M1.txt" '^\+ +totp = \{$'
    else expect L2.conf-M1.server "$OUT/L2-conf-M1.txt" "^\\+ +server = $SOCKX\$"; fi
    expect L2.conf-M1.indicator "$OUT/L2-conf-M1.txt" "^\\+ +indicator = $INDICATOR\$"
    restart_cell L2-mit-restart-M1 "sudo bash $VMD/vmctl.sh mit-restart"
    expect L2.mit.krb5kdc-active "$OUT/L2-mit-restart-M1.txt" '^krb5kdc\.service: active$'
    expect L2.mit.otp-loaded "$OUT/L2-mit-restart-M1.txt" '\(info\): Loaded'
    expect L2.mit.operating "$OUT/L2-mit-restart-M1.txt" 'commencing operation'
    expect L2.mit.otp-initialized "$OUT/L2-mit-restart-M1.txt" 'preauth otp failed to initialize' 0

    printf '%s\n' "$PW" | vm kdc "sudo bash $VMD/vmctl.sh addprinc" 2>&1 | redact > "$OUT/L2-addprinc.txt"
    expect L2.mit.addprinc "$OUT/L2-addprinc.txt" "Principal \"otpuser@$RRX\" created\\."
    if [ "$STAND_IN" = 1 ]; then kadm L2-setstr "setstr otpuser otp \"$OTP_ATTR_Q\""; else kadm L2-setstr 'setstr otpuser otp "[]"'; fi
    kadm L2-setstr-require-auth "setstr $SVCP require_auth $INDICATOR"
    kadm L2-getstrs 'getstrs otpuser'
    kadm L2-getstrs-svc "getstrs $SVCP"
    kadm L2-getprinc 'getprinc otpuser'
    if [ "$STAND_IN" = 1 ]; then expect L2.mit.otp-attribute "$OUT/L2-getstrs.txt" "^otp: $OTP_ATTR_RX\$"
    else expect L2.mit.otp-attribute "$OUT/L2-getstrs.txt" '^otp: \[\]$'; fi
    expect L2.mit.require_auth "$OUT/L2-getstrs-svc.txt" "^require_auth: $INDICATOR\$"
    expect L2.mit.requires-preauth "$OUT/L2-getprinc.txt" 'Attributes:.*REQUIRES_PRE_AUTH'
}

otp_mit_teardown() {   # the SELinux end of the MIT stage, the stub stopped, kdc.conf back to the realm's plain config (the upgrade is done on it)
    { vm kdc "sudo bash $VMD/vmctl.sh avc $AVC_MARK" 2>&1; echo "# getenforce at the end of the OTP MIT stage: $(vm kdc getenforce 2>&1)"
      echo "# NOTE: the line above is OTP4's vmctl.sh avc: ausearch without --input-logs reads its stdin, which is empty here, so \"no AVC\" from it is BLIND. The judged rows are AVC-mit.txt (this stage) and AVC-ours.txt."; } | redact > "$OUT/L2-selinux-end.txt"
    cat "$OUT/L2-selinux-end.txt" >> "$LOG"
    vm kdc "sudo bash $VMD/vmctl.sh stub-stop" 2>&1 | redact > "$OUT/L2-stub-stop.txt"
    set_conf L3-conf-clear stanza_none
}

otp_after_install() {   # what the dump and the load must have carried: the otp attribute, require_auth, the plain kdc.conf
    {
        echo "# $(now) after the install"
        vm kdc "rpm -qf /usr/sbin/kadmind 2>&1; systemctl is-active krb5kdc kadmin; getenforce; ls -lZ /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kdc.conf.otp3-orig; echo '== [otp] lines of the restored kdc.conf (none expected)'; sudo grep -c '^\[otp\]' /var/kerberos/krb5kdc/kdc.conf; ls -lZ /usr/sbin/krb5kdc /usr/sbin/kadmind" 2>&1
    } | redact > "$OUT/L3-after-install.txt"
    cat "$OUT/L3-after-install.txt" >> "$LOG"
    expect L3.install.kdc-conf-plain "$OUT/L3-after-install.txt" '^0$'
    kadm L3-getstrs-after-load 'getstrs otpuser'
    kadm L3-getprinc-after-load 'getprinc otpuser'
    kadm L3-getstrs-svc-after-load "getstrs $SVCP"
    if [ "$STAND_IN" = 1 ]; then expect L3.load.otp-attribute-carried-over "$OUT/L3-getstrs-after-load.txt" "^otp: $OTP_ATTR_RX\$"
    else expect L3.load.otp-attribute-carried-over "$OUT/L3-getstrs-after-load.txt" '^otp: \[\]$'; fi
    if grep -qE "^require_auth: $INDICATOR\$" "$OUT/L3-getstrs-svc-after-load.txt"; then
        expect L3.load.require_auth-carried-over "$OUT/L3-getstrs-svc-after-load.txt" "^require_auth: $INDICATOR\$"
    else
        note "require_auth did not come through the load: set again"
        result L3.load.require_auth-carried-over INFO "require_auth: $INDICATOR on $SVCP" - 0 "not carried over by the load; set again on the next line of the log"
        kadm L3-setstr-require-auth "setstr $SVCP require_auth $INDICATOR"
        kadm L3-getstrs-svc "getstrs $SVCP"
        expect L3.require_auth-set-again "$OUT/L3-getstrs-svc.txt" "^require_auth: $INDICATOR\$"
    fi
}

otp_ours_setup() {   # the lab seed on ssh stdin, the embedder from the ship build as the KDC, [otp] totp = { indicator = otpind }, the otp attribute
    printf '%s %s\n' "otpuser@KERBER.TEST" "$(cat "$SEED")" | vm kdc "install -d -m 0700 $VMD && cat > $VMD/totp.seeds && chmod 600 $VMD/totp.seeds && ls -l $VMD/totp.seeds" 2>&1 | redact > "$OUT/L3-seeds-pushed.txt"
    cat "$OUT/L3-seeds-pushed.txt" >> "$LOG"
    vm kdc "cp -p $VMD/ship/release/krb5-otp-kdc $VMD/krb5-otp-kdc && chmod 755 $VMD/krb5-otp-kdc && sha256sum $VMD/krb5-otp-kdc" > "$OUT/L3-embedder-on-vm.sha256" 2>> "$LOG"
    [ "$(cut -d' ' -f1 "$OUT/L3-embedder-on-vm.sha256")" = "$(awk '$2 == "krb5-otp-kdc" { print $1 }' "$W/ship-server.sha256")" ] || fail "the embedder on the VM differs from the ship build"
    set_conf L3-conf-O1 stanza_o1
    expect L3.conf-O1.totp "$OUT/L3-conf-O1.txt" '^\+ +totp = \{$'
    expect L3.conf-O1.indicator "$OUT/L3-conf-O1.txt" "^\\+ +indicator = $INDICATOR\$"
    restart_cell O1-embed-start "sudo bash $VMD/vmctl.sh embed-start"
    expect O1.embed.service-stopped "$OUT/O1-embed-start.txt" '^krb5kdc\.service: (inactive|failed)$'
    expect O1.embed.running "$OUT/O1-embed-start.txt" '^krb5-otp-kdc: starting\.\.\.$'
    expect O1.embed.operating "$OUT/O1-embed-start.txt" 'commencing operation'
    expect O1.embed.listening "$OUT/O1-embed-start.txt" 'pid=[0-9]+'
    expect O1.embed.otp-initialized "$OUT/O1-embed-start.txt" 'preauth otp failed to initialize' 0
    kadm L3-setstr-totp "setstr otpuser otp \"$OTP_ATTR_Q\""
    kadm L3-getstrs-totp 'getstrs otpuser'
    expect O1.otp-attribute "$OUT/L3-getstrs-totp.txt" "^otp: $OTP_ATTR_RX\$"
}

otp_ours_teardown() {
    vm kdc "sudo bash $VMD/vmctl.sh embed-stop" 2>&1 | redact > "$OUT/L3-embed-stop.txt"
    cat "$OUT/L3-embed-stop.txt" >> "$LOG"
    { vm kdc "sudo bash $VMD/vmctl.sh avc $AVC_MARK3" 2>&1; echo "# getenforce after our KDC's stage: $(vm kdc getenforce 2>&1)"
      echo "# NOTE: the line above is OTP4's vmctl.sh avc: ausearch without --input-logs reads its stdin, which is empty here, so \"no AVC\" from it is BLIND. The judged rows are AVC-mit.txt and AVC-ours.txt (this stage)."; } | redact > "$OUT/L3-selinux-end.txt"
    cat "$OUT/L3-selinux-end.txt" >> "$LOG"
}

otp_parity() {   # the OTP3a driver's parity: parity.sh over the cell files, its rows into results.tsv (controls included)
    bash "$SCRIPTS/otp/parity.sh" "$OUT" > "$OUT/parity-mit-vs-ours.txt" 2>> "$LOG"
    cat "$OUT/parity-mit-vs-ours.txt" >> "$LOG"
    while read -r tag kind cellpair who verdict n _; do
        [ "$tag" = PARITY ] || continue
        case $kind in
            control)
                if [ "$verdict" = DIFFER ]; then
                    result "PARITY.control.$cellpair.$who" PASS "must differ" differ "$verdict"
                else
                    result "PARITY.control.$cellpair.$who" FAIL "must differ" differ "$verdict"; NFAIL=$((NFAIL + 1))
                fi ;;
            xstage-*|info-*) result "PARITY.$kind.$cellpair.$who" INFO "xstage: the same kinit against MIT's KDC and ours; info-etypes: the client's default" "$verdict" "$n lines" ;;
            *)
                if [ "$verdict" = EQ ]; then
                    result "PARITY.$kind.$cellpair.$who" PASS "MIT's kinit = ours" equal "$verdict" "$n lines"
                else
                    result "PARITY.$kind.$cellpair.$who" FAIL "MIT's kinit = ours" equal "$verdict" "$n lines (parity-mit-vs-ours.txt lists the differing lines)"; NFAIL=$((NFAIL + 1))
                fi ;;
        esac
    done < "$OUT/parity-mit-vs-ours.txt"
    summarize_hints
}

# ================================================================ the Director's additions to the combined pass: P16a's cpw -pw leg, P8's field check, the enforcing-AVC rows
# P16a's leg.sh and P8's field-check.sh are those packages' own scripts, piped unchanged into `lab.sh ssh kdc` with the admin/admin password as the first line of stdin (never argv).
# The MIT stage runs P16a once (MIT's kadmin.local and kadmind), the ours stage runs P16a again and then P8 (the KDC is the installed ship build). The AVC rows are the field suite's
# selinux.avc form (harness/field/scenarios/upgrade.sh): ausearch --input-logs and a USER_CMD positive control. OTP4's helper (vmctl.sh avc) ran ausearch without --input-logs on a
# stdin that was not a terminal, so it read an empty stdin: its old "no AVC" lines were blind, and these rows replace them as the judged ones.
P16A_LEG=${P16A_LEG:?P16A_LEG is not set}
P8_CHECK=${P8_CHECK:?P8_CHECK is not set}
KS_RC=0

kdc_script() {   # kdc_script NAME LOCAL-SCRIPT [TIMEOUT]: the script on the kdc's sh, the admin password its stdin's first line; the output through the record filter into $OUT/NAME.txt; sets KS_RC
    local name=$1 script=$2 t=${3:-600}
    if [ ! -s "$script" ]; then note "kdc_script: $script is missing or empty"; KS_RC=127; : > "$OUT/$name.txt"; return 1; fi
    { cat "$ADMIN_SECRET"; cat "$script"; } | timeout "$t" "$LAB" ssh kdc -- 'IFS= read -r ADMIN_PW; export ADMIN_PW; exec sh -s' 2>&1 | redact > "$OUT/$name.txt"
    KS_RC=${PIPESTATUS[1]}
    cat "$OUT/$name.txt" >> "$LOG"
}

p16a_section() {   # p16a_section FILE HEADER-RX: the lines under the first line that matches HEADER-RX, up to the next "==" line (the refusal text of one command)
    RX="$2" awk 'f && /^(==|# )/ { exit } f { print } $0 ~ ENVIRON["RX"] { f = 1 }' "$1" 2>/dev/null
}

p16a_leg() {   # p16a_leg mit|rust: P16a: a dictionary word is refused by kadmin.local and by kadmind (MIT's kadmin client) with the dictionary text, on whichever KDC the kdc VM runs
    local st=$1 f="P16A-$1" want
    deadline
    note "P16A $st: leg.sh on the kdc"
    kdc_script "$f" "$P16A_LEG" 300
    note "P16A $st rc=$KS_RC: $(tail -1 "$OUT/$f.txt")"
    verdict "P16A.$st.rc" "$([ "$KS_RC" = 0 ] && echo PASS || echo FAIL)" "ssh exit status" 0 "$KS_RC"
    # rpm -q prints "package krb5-server is not installed" on stdout when the package is gone, and leg.sh's `|| echo` adds its own words on the next line
    if [ "$st" = mit ]; then want="^== kdc: krb5-server-$PKG_VERSION_RX"; else want='^== kdc: package krb5-server is not installed'; fi
    expect "P16A.$st.kdc-is-$st" "$OUT/$f.txt" "$want"
    if [ "$st" = rust ]; then expect "P16A.$st.leg-says-kerber-rust" "$OUT/$f.txt" '^krb5-server not installed \(kerber-rust\); '; fi
    expect "P16A.$st.dict-line-added" "$OUT/$f.txt" 'dict_file = /var/kerberos/krb5kdc/p16a-field\.dict'
    expect_under "P16A.$st.kadmin-local-refused" "$OUT/$f.txt" '^== kadmin\.local cpw -pw <dictionary word> bob' 'Password is in the password dictionary'
    expect_under "P16A.$st.kadmind-refused" "$OUT/$f.txt" '^== MIT kadmin \(to kadmind\) cpw -pw <dictionary word> bob' 'Password is in the password dictionary'
    expect "P16A.$st.dict-line-removed" "$OUT/$f.txt" '^0$' 1
    expect "P16A.$st.no-fail-line" "$OUT/$f.txt" '^(FAIL|kadmin\.local did not refuse|kadmind did not refuse)' 0
    expect "P16A.$st.pass" "$OUT/$f.txt" '^PASS$' 1
}

p16a_compare() {   # the two refusals side by side: MIT's text against ours, byte for byte (judged); a control proves the comparison can fail
    local pair n h a b doctored
    for pair in 'kadmin-local|^== kadmin\.local cpw -pw <dictionary word> bob' 'kadmind|^== MIT kadmin \(to kadmind\) cpw -pw <dictionary word> bob'; do
        n=${pair%%|*}; h=${pair#*|}
        a=$(p16a_section "$OUT/P16A-mit.txt" "$h"); b=$(p16a_section "$OUT/P16A-rust.txt" "$h")
        printf '%s\n' "$a" > "$OUT/P16A-parity-$n-mit.txt"; printf '%s\n' "$b" > "$OUT/P16A-parity-$n-rust.txt"
        if [ -n "$a" ] && [ "$a" = "$b" ]; then
            verdict "PARITY.p16a.$n" PASS "MIT's refusal text = ours" equal equal "$(printf '%s\n' "$a" | grep -c .) lines"
        else
            verdict "PARITY.p16a.$n" FAIL "MIT's refusal text = ours" equal differ "P16A-parity-$n-mit.txt against P16A-parity-$n-rust.txt"
        fi
        doctored="$a"$'\n'"an extra line"
        if [ "$a" = "$doctored" ]; then
            verdict "PARITY.control.p16a.$n" FAIL "a doctored copy must differ" differ same ""
        else
            verdict "PARITY.control.p16a.$n" PASS "a doctored copy must differ" differ differ ""
        fi
    done
}

p8_check() {   # P8's field check (the lockout attributes as MIT's KDC keeps them, the labels, AVC), field-check.sh unchanged, on the kdc with the ship build installed by install.md's upgrade
    local f="$OUT/P8-ours.txt"
    deadline
    note "P8: field-check.sh on the kdc"
    kdc_script P8-ours "$P8_CHECK" 900
    note "P8 rc=$KS_RC: $(tail -1 "$f")"
    verdict P8.rc "$([ "$KS_RC" = 0 ] && echo PASS || echo FAIL)" "ssh exit status" 0 "$KS_RC"
    expect P8.enforcing "$f" '^Enforcing$' 1
    expect P8.fourth-attempt-refused "$f" 'credentials have been revoked'
    expect P8.db-and-lockout-file-unchanged "$f" '^ok: database [0-9a-f]{64} and its age unchanged, principal\.lockout inode [0-9]+ unchanged$' 1
    expect P8.nothing-to-relabel "$f" '^ok: restorecon -n would relabel nothing$' 1
    expect P8.put-back "$f" '^ok: the principal, the policy and /root/p8-check are gone$' 1
    expect P8.no-avc "$f" '^ok: no AVC since the start$' 1
    expect P8.no-fail-line "$f" '^(FAIL|bad:)' 0
    expect P8.pass "$f" '^PASS$' 1
}

avc_rows() {   # avc_rows LABEL MARK: SELinux is enforcing on the kdc and nothing was denied since MARK (the kdc's clock, HH:MM:SS): upgrade.sh's selinux.avc form, judged
    local label=$1 mark=$2 f="$OUT/$1.txt"
    vm kdc "getenforce; d=\$(sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $mark 2>&1); r=\$?; [ \"\$r\" = 1 ] || printf '%s\n' \"\$d\"; c=\$(sudo ausearch --input-logs -m USER_CMD -ts $mark 2>/dev/null | grep -c '^type=USER_CMD'); printf 'denials: %s (ausearch rc=%s); USER_CMD control: %s records\n' \"\$(printf '%s\n' \"\$d\" | tail -n 1)\" \"\$r\" \"\$c\"; ps -eZ | grep -E 'krb5kdc|kadmind|krb5-otp-kdc'" 2>&1 < /dev/null | redact > "$f"
    cat "$f" >> "$LOG"
    expect "$label.enforcing" "$f" '^Enforcing$' 1
    expect "$label.no-denial" "$f" '^denials: <no matches> \(ausearch rc=1\); USER_CMD control: [1-9][0-9]* records$' 1
    info "$label.daemon-domains" "$f" 'krb5kdc|kadmind|krb5-otp-kdc'
}

package_summary() {   # SUMMARY.txt: the checks per package and the cells behind them
    local ra_cells ra_acc ka_cells ka_sess otp_cells otp_armor
    ra_cells=$(awk -F'\t' '$1 ~ /^RA\.cmp\.[a-z-]+\.cells$/ { s += $5 } END { print s + 0 }' "$OUT/results.tsv")
    ra_acc=$(wc -l < "$OUT/ra/acc-mit.tsv" 2>/dev/null || echo 0)
    ka_cells=$(wc -l < "$OUT/ka/cells-mit.txt" 2>/dev/null || echo 0)
    ka_sess=$(cat "$OUT"/ka/session-*-mit.txt 2>/dev/null | grep -c '^==== ' || true)
    otp_cells=$(find "$OUT" -maxdepth 1 -name '[MO]C[1-4]-k*-client[12].txt' | wc -l)
    otp_armor=$(find "$OUT" -maxdepth 1 -name '[MO]-armor-k*-client[12].txt' | wc -l)
    {
        echo "# $(now) the checks per package (results.tsv) and the cells behind them"
        awk -F'\t' '
            function grp(l) {
                if (l ~ /^RA\./) return "1 RA r4 (kpasswd acceptor)"
                if (l ~ /^KA\./) return "2 KA (refused keys, MIT kadmin sessions)"
                if (l ~ /^(L0|L1|L4)\./) return "0 common (inputs, resets, identity, shred, restore)"
                if (l ~ /^L3\.install\./) return "0 common (inputs, resets, identity, shred, restore)"
                if (l ~ /^(P16A\.|PARITY\.p16a|PARITY\.control\.p16a)/) return "4 P16a (cpw -pw dictionary refusal, MIT then ours)"
                if (l ~ /^P8\./) return "5 P8 (lockout attributes, labels, AVC: field check on our KDC)"
                if (l ~ /^AVC/) return "6 SELinux (enforcing, no denial since the stage mark)"
                return "3 OTP (client, [otp] reader, embedder)"
            }
            { g = grp($1); n[g " " $2]++; seen[g] = 1 }
            END { for (g in seen) printf "%-58s %5d PASS %4d FAIL %5d INFO\n", substr(g, 3), n[g " PASS"], n[g " FAIL"], n[g " INFO"] }' "$OUT/results.tsv" | sort
        echo "# cells compared MIT against ours"
        echo "RA r4: $ra_cells wire cells (449 + 449 + 467 + 467 expected: udp, tcp, udp-setpw, tcp-setpw) and $ra_acc library-acceptor rows (652 expected), in each stage"
        echo "KA:    $ka_cells refused-key cell lines and $ka_sess session steps in the MIT stage's sessions (${#KA_CLIENTS[@]} clients)"
        echo "OTP:   $otp_cells login cells (32 expected: C1-C4 x 2 clients x 2 kinits x 2 stages) and $otp_armor armor cells (8 expected); parity rows: $(grep -c '^PARITY\.' "$OUT/results.tsv" | tr -d '\n') (PASS $(awk -F'\t' '$1 ~ /^PARITY\./ && $2 == "PASS"' "$OUT/results.tsv" | wc -l))"
    } > "$OUT/SUMMARY.txt"
    cat "$OUT/SUMMARY.txt" >> "$LOG"
}

# ================================================================ OTP2's and OTP1's cells that the OTP3/OTP4 client cells do not repeat
# OTP2: the [otp] reader with a bad configuration (M3 on MIT's krb5kdc, O3 and O4 on the embedder, O5 on the installed krb5kdc.service): the startup lines, no 141, the password path; OTP1: the TOTP verifier's
# replay and its DEFAULT type. The functions are the OTP2 and OTP1 drivers' own (docs: driver.sh and OTP1/lab/driver.sh), unchanged but for the script path of totp.py
# and the armor files the cells use, which the cells below make themselves.
XSOCK=${XSOCK:-/run/krb5kdc/x.sock}                # the socket in O4's stanza: never created
stanza_m3() { printf '[otp]\n    DEFAULT = {\n        timeout = 5s\n    }\n'; }
stanza_o3() { printf '[otp]\n    totp = {\n        timeout = 5s\n    }\n'; }
stanza_o4() { printf '[otp]\n    DEFAULT = {\n        server = %s\n    }\n' "$XSOCK"; }
login_cmd() {
    local targ=""
    [ "$1" != - ] && targ="-T $1"
    printf 'sudo env KRB5_TRACE=/dev/stderr kinit %s -c %s otpuser 2>&1; echo "[rc=$?]"; if sudo test -e %s; then sudo klist -C -c %s 2>&1; sudo klist -f -e -c %s 2>&1; echo "--- kvno %s with that ticket"; sudo kvno -c %s %s 2>&1; echo "[kvno rc=$?]"; else echo "no ccache %s was written"; fi' \
        "$targ" "$2" "$2" "$2" "$2" "$SVC" "$2" "$SVC" "$2"
}
chk_module_out() {   # chk_module_out LABEL FILE: the otp module is out: no 141 hint, no OTP prompt, the password asked for and a TGT
    local l=$1 f=$2
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.ccache" "$f" "^Default principal: otpuser@$RRX\$"
    expect "$l.no-141-hint" "$f" 'Processing preauth types:.*\(141\)' 0
    expect "$l.hint-138" "$f" 'Processing preauth types:.*PA-ENCRYPTED-CHALLENGE \(138\)'
    expect "$l.password-prompt" "$f" "Password for otpuser@$RRX:"
    expect "$l.no-otp-prompt" "$f" 'Enter OTP Token Value' 0
    expect "$l.no-141-ticket" "$f" "pa_type\\(krbtgt/$RRX@$RRX\\) = 141" 0
    info "$l.hint-list" "$f" 'Processing preauth types:'
    info "$l.pa_type" "$f" 'pa_type\(krbtgt/'
    info "$l.preauth-module" "$f" 'Preauth module .* returned: 0/Success'
    info "$l.kvno" "$f" '^kvno: |: kvno = '
}
chk_init_failed() {   # chk_init_failed LABEL FILE REASON: REASON is MIT's message (Invalid integer value, Invalid argument)
    local l=$1 f=$2 why=$3
    expect "$l.active" "$f" '^krb5kdc\.service: active$|^embedder pid [0-9]+$'
    expect "$l.loaded" "$f" '\(info\): Loaded$'
    expect "$l.otp-failed" "$f" "preauth otp failed to initialize: $why\$" 1
    expect "$l.operating" "$f" 'commencing operation'
    expect_order "$l.order" "$f" '\(info\): Loaded$' "preauth otp failed to initialize: $why\$" 'commencing operation'
    info "$l.pkinit-line" "$f" 'preauth pkinit failed to initialize'
    info "$l.spake-line" "$f" 'preauth spake failed to initialize'
}
mit_M3() {   # mit_M3 CLIENT: the otp module is out (bad [otp]): -T armor, no 141, the password
    local c=$1
    local ARM=$VMD/armor-mit.cc CC=$VMD/mit-M3.cc RF="M3-$c-login"
    deadline
    printf '%s\n' "$PW" | cell "$RF" "$c" "$(login_cmd "$ARM" "$CC")" kdc+stub
    chk_module_out "M3.$c" "$OUT/$RF.txt"
    expect "M3.$c.stub-not-asked" "$OUT/$RF.txt" 'Access-Request' 0
}
ours_module_out() {   # ours_module_out CELL CLIENT: -T armor, the password: the module is out
    local cellname=$1 c=$2 ARM=$VMD/armor-ours.cc CC=$VMD/ours-$1.cc RF="$1-$2-login"
    deadline
    printf '%s\n' "$PW" | cell "$RF" "$c" "$(login_cmd "$ARM" "$CC")" kdc
    chk_module_out "$cellname.$c" "$OUT/$RF.txt"
}
ours_default() { # ours_default CLIENT: type DEFAULT, for which no verifier is registered (a valid current code is typed)
    local c=$1 ARM=$VMD/armor-ours.cc code
    code=$(python3 -B -I "$SCRIPTS/otp/totp.py" now "$SEED" --offset "$OFFSET" 2>> "$LOG")
    printf '%s\n' "$code" | cell "L3-$c-default" "$c" "$(login_cmd "$ARM" "$VMD/ours-default.cc")" kdc
    expect "L3.$c.default.rc" "$OUT/L3-$c-default.txt" '^\[rc=1\]$'
    expect "L3.$c.default.message" "$OUT/L3-$c-default.txt" '^kinit: Preauthentication failed while getting initial credentials$'
    expect "L3.$c.default.no-ccache" "$OUT/L3-$c-default.txt" '^no ccache .*ours-default\.cc was written$'
    expect "L3.$c.default.kdc-log" "$OUT/L3-$c-default.txt" "preauth \\(otp\\) verify failure: No OTP verifier registered for token type 'DEFAULT'"
    expect "L3.$c.default.kdc-status" "$OUT/L3-$c-default.txt" "PREAUTH_FAILED: otpuser@$RRX"
}

# OTP1's ours_client, its armor, right and replay cells (the wrong-code cell is C2 of the OTP3 cells); the lines are OTP1's, with the labels as they were
otp1_replay() {  # otp1_replay CLIENT: armor, the current TOTP code, the same code again (replay) against krb5-otp-kdc
    local c=$1 ARM=$VMD/armor-ours.cc code
    cell "L3-$c-armor" "$c" "$(armor_cmd "$ARM" "${HOSTPRINC[$c]}")" kdc < /dev/null
    expect "L3.$c.armor" "$OUT/L3-$c-armor.txt" '^\[rc=0\]$'
    code=$(python3 -B -I "$SCRIPTS/otp/totp.py" fresh "$SEED" "$W/used-steps" --offset "$OFFSET" 2>> "$LOG")
    printf '%s\n' "$code" | cell "L3-$c-right" "$c" "$(login_cmd "$ARM" "$VMD/ours-right.cc")" kdc
    expect "L3.$c.right.rc" "$OUT/L3-$c-right.txt" '^\[rc=0\]$'
    expect "L3.$c.right.pa_type" "$OUT/L3-$c-right.txt" "pa_type\\(krbtgt/$RRX@$RRX\\) = 141"
    expect "L3.$c.right.otp-module" "$OUT/L3-$c-right.txt" 'Preauth module otp \(141\) \(real\) returned: 0/Success'
    expect "L3.$c.right.kdc-issue" "$OUT/L3-$c-right.txt" "\\(info\\): AS_REQ \\(.*ISSUE: authtime .*otpuser@$RRX for krbtgt/$RRX@$RRX"
    expect "L3.$c.right.kvno" "$OUT/L3-$c-right.txt" "^${SVC//./\\.}: kvno = [0-9]+"
    printf '%s\n' "$code" | cell "L3-$c-replay" "$c" "$(login_cmd "$ARM" "$VMD/ours-replay.cc")" kdc
    expect "L3.$c.replay.rc" "$OUT/L3-$c-replay.txt" '^\[rc=1\]$'
    expect "L3.$c.replay.message" "$OUT/L3-$c-replay.txt" '^kinit: Preauthentication failed while getting initial credentials$'
    expect "L3.$c.replay.no-ccache" "$OUT/L3-$c-replay.txt" '^no ccache .*ours-replay\.cc was written$'
    expect "L3.$c.replay.kdc-status" "$OUT/L3-$c-replay.txt" "PREAUTH_FAILED: otpuser@$RRX"
}

otp1_ours() {   # OTP1's ours-only cells, in OTP1's order: the replay cells, then type DEFAULT (nothing registered for it), then the TOTP attribute back
    local c
    for c in "${CLIENTS[@]}"; do deadline; otp1_replay "$c"; done
    kadm L3-setstr-default 'setstr otpuser otp "[]"'
    kadm L3-getstrs-default 'getstrs otpuser'
    expect L3.default.otp-attribute "$OUT/L3-getstrs-default.txt" '^otp: \[\]$'
    for c in "${CLIENTS[@]}"; do deadline; ours_default "$c"; done
    kadm L3-setstr-totp-again "setstr otpuser otp \"$OTP_ATTR_Q\""
    kadm L3-getstrs-totp-again 'getstrs otpuser'
    expect L3.default.otp-attribute-restored "$OUT/L3-getstrs-totp-again.txt" "^otp: $OTP_ATTR_RX\$"
}

otp2_mit() {   # OTP2's M3: a bad [otp] (the stub stays up), MIT's krb5kdc restarted, the startup lines in order, no 141
    local c
    for c in "${CLIENTS[@]}"; do
        cell "M3-$c-armor" "$c" "$(armor_cmd "$VMD/armor-mit.cc" "${HOSTPRINC[$c]}")" kdc < /dev/null
        chk_armor "M3.$c" "$OUT/M3-$c-armor.txt"
    done
    set_conf L2-conf-M3 stanza_m3
    expect L2.conf-M3.timeout "$OUT/L2-conf-M3.txt" '^\+ +timeout = 5s$'
    restart_cell M3-restart "sudo bash $VMD/vmctl.sh mit-restart"
    chk_init_failed M3.restart "$OUT/M3-restart.txt" 'Invalid integer value'
    for c in "${CLIENTS[@]}"; do mit_M3 "$c"; done
}

otp2_ours() {   # OTP2's O3, O4 and O5, in OTP2's order
    local c
    for c in "${CLIENTS[@]}"; do
        cell "O3-$c-armor" "$c" "$(armor_cmd "$VMD/armor-ours.cc" "${HOSTPRINC[$c]}")" kdc < /dev/null
        chk_armor "O3.$c" "$OUT/O3-$c-armor.txt"
    done
    # ---- O3: a bad [otp] for the embedder: restart, the startup lines, no 141
    set_conf L3-conf-O3 stanza_o3
    expect L3.conf-O3.timeout "$OUT/L3-conf-O3.txt" '^\+ +timeout = 5s$'
    restart_cell O3-restart "sudo bash $VMD/vmctl.sh embed-restart"
    chk_init_failed O3.restart "$OUT/O3-restart.txt" 'Invalid integer value'
    expect O3.restart.no-relation-line "$OUT/O3-restart.txt" 'Unsupported relation' 0
    for c in "${CLIENTS[@]}"; do ours_module_out O3 "$c"; done
    # ---- O4: MIT's own stanza, a server: ours refuses it (STRICTER than MIT)
    set_conf L3-conf-O4 stanza_o4
    expect L3.conf-O4.server "$OUT/L3-conf-O4.txt" "^\\+ +server = ${XSOCK//./\\.}\$"
    restart_cell O4-restart "sudo bash $VMD/vmctl.sh embed-restart"
    expect O4.restart.refusal-line "$OUT/O4-restart.txt" "Invalid argument - Unsupported relation 'server' \\(token type 'DEFAULT'\\): RADIUS is not implemented; an embedder's OtpVerifier decides\$" 1
    expect O4.restart.otp-failed "$OUT/O4-restart.txt" 'preauth otp failed to initialize: Invalid argument$' 1
    expect_adjacent O4.restart.refusal-then-failed "$OUT/O4-restart.txt" 'Unsupported relation' 'preauth otp failed to initialize: Invalid argument$'
    expect_order O4.restart.order "$OUT/O4-restart.txt" '\(info\): Loaded$' 'Unsupported relation' 'preauth otp failed to initialize: Invalid argument$' 'commencing operation'
    expect O4.restart.operating "$OUT/O4-restart.txt" 'commencing operation'
    info O4.restart.pkinit-line "$OUT/O4-restart.txt" 'preauth pkinit failed to initialize'
    for c in "${CLIENTS[@]}"; do ours_module_out O4 "$c"; done
    # ---- O5: the installed krb5kdc.service (not the embedder) with the O3 config
    vm kdc "sudo bash $VMD/vmctl.sh embed-stop" 2>&1 | redact > "$OUT/L3-embed-stop-O5.txt"
    cat "$OUT/L3-embed-stop-O5.txt" >> "$LOG"
    set_conf L3-conf-O5 stanza_o3
    expect L3.conf-O5.timeout "$OUT/L3-conf-O5.txt" '^\+ +timeout = 5s$'
    restart_cell O5-restart "sudo bash $VMD/vmctl.sh svc-restart"
    chk_init_failed O5.restart "$OUT/O5-restart.txt" 'Invalid integer value'
    expect O5.restart.no-relation-line "$OUT/O5-restart.txt" 'Unsupported relation' 0
    expect O5.restart.program "$OUT/O5-restart.txt" 'krb5kdc\[[0-9]+\]\(info\): commencing operation'
    ours_module_out O5 client1
    restart_cell O5-stop "sudo bash $VMD/vmctl.sh svc-stop"
    expect O5.stop.inactive "$OUT/O5-stop.txt" '^krb5kdc\.service: inactive$'
}

otp2_parity() {   # OTP2's M3-O3 comparison (parity-m3o3.sh), its rows into results.tsv
    bash "$SCRIPTS/otp/parity-m3o3.sh" "$OUT" > "$OUT/parity-otp2-m3-o3.txt" 2>> "$LOG"
    cat "$OUT/parity-otp2-m3-o3.txt" >> "$LOG"
    while read -r tag kind cellpair who verdict n _; do
        [ "$tag" = PARITY ] || continue
        case $kind in
            control)
                if [ "$verdict" = DIFFER ]; then result "PARITY2.control.$cellpair.$who" PASS "must differ" differ "$verdict"
                else result "PARITY2.control.$cellpair.$who" FAIL "must differ" differ "$verdict"; NFAIL=$((NFAIL + 1)); fi ;;
            *)
                if [ "$verdict" = EQ ]; then result "PARITY2.$kind.$cellpair.$who" PASS "MIT stage = ours (bad [otp])" equal "$verdict" "$n lines"
                else result "PARITY2.$kind.$cellpair.$who" FAIL "MIT stage = ours (bad [otp])" equal "$verdict" "$n lines (parity-otp2-m3-o3.txt lists the differing lines)"; NFAIL=$((NFAIL + 1)); fi ;;
        esac
    done < "$OUT/parity-otp2-m3-o3.txt"
}

# ================================================================ the inputs (host only, before the lock): the ship build, the checkout, the oracle, the secrets
prep_inputs() {   # SHIP = the built programs, DIST = the checkout whose dist/ and docs/install.md the upgrade uses, TREE = the tree id they must be
    local p tree treeinfo section
    [ -d "$SHIP/release" ] && SHIP=$SHIP/release
    if ! { [ -d "$SHIP" ] && [ -d "$DIST/dist" ] && [ -f "$DIST/docs/install.md" ]; }; then
        echo "driver.sh: SHIP=$SHIP or DIST=$DIST is not what it should be (SHIP: the built programs, a cargo release dir or a frozen copy; DIST: the checkout with dist/ and docs/install.md)" >&2; exit 2
    fi
    for p in "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}" rd-sweep; do
        [ -x "$SHIP/$p" ] || { echo "driver.sh: $SHIP/$p is missing or not executable" >&2; exit 2; }
    done
    tree=$(git -C "$DIST" rev-parse 'HEAD^{tree}' 2>/dev/null || echo unknown)
    if [ -n "$TREE" ] && [ "$tree" != unknown ]; then
        case $tree in "$TREE"*) ;; *) echo "driver.sh: DIST=$DIST is tree $tree, not TREE=$TREE" >&2; exit 2 ;; esac
    fi
    treeinfo=$tree
    [ "$tree" = unknown ] && [ -n "$TREE" ] && treeinfo="$TREE (as given by TREE=; $DIST is a git archive of that tree, not a git checkout)"
    rm -rf "$W/ship"; mkdir -p "$W/ship/release"
    for p in "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}" rd-sweep; do cp -p "$SHIP/$p" "$W/ship/release/$p"; done
    cp -rp "$DIST/dist" "$W/ship/dist"
    ( cd "$W/ship/release" && sha256sum "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}" rd-sweep ) > "$W/ship-sha256.txt"
    ( cd "$W/ship/dist" && find . -type f | LC_ALL=C sort | xargs sha256sum ) > "$W/dist-sha256.txt"
    section=$(awk '/^## Upgrading an MIT realm/{f=1;print;next} /^## /&&f{exit} f{print}' "$DIST/docs/install.md" | sha256sum | cut -d' ' -f1)
    {
        echo "tree $treeinfo, ship build $SHIP (${SHIP_NOTE:-default features, --release --locked}), dist/ and docs of $DIST"
        echo "docs/install.md 'Upgrading an MIT realm' section sha256 $section"
    } > "$W/ship-source.txt"
    ( cd "$W/ship/release" && sha256sum "${SERVER_PROGS[@]}" "${CLIENT_PROGS[@]}" ) > "$W/ship-local.sha256"
    ( cd "$W/ship/release" && sha256sum "${SERVER_PROGS[@]}" ) > "$W/ship-server.sha256"
    # RA r4's library oracle: MIT's rd_req / rd_priv / rd_safe in a C program, built from the tree's source against the host's libkrb5 (the host is the lab VMs' Fedora 43: no docker)
    if [ ! -x "$ORACLE" ]; then
        ORACLE=$W/oracle/rd-priv-oracle
        bash "$SCRIPTS/build-oracle.sh" "$DIST/scripts/oracle/rd-priv-oracle.c" "$W/oracle" > "$OUT/oracle-build.txt" 2>&1 || { echo "driver.sh: the oracle did not build (see $OUT/oracle-build.txt)" >&2; exit 2; }
    fi
    [ -x "$ORACLE" ] || { echo "driver.sh: no oracle at $ORACLE" >&2; exit 2; }
    [ -s "$ADMIN_SECRET" ] || { echo "driver.sh: no admin secret file at $ADMIN_SECRET (the KA sessions)" >&2; exit 2; }
}

# ================================================================ main
[ "${SOURCE_ONLY:-}" = 1 ] && return 0 2>/dev/null
trap finish EXIT
trap 'REASON="interrupted (SIGTERM)"; exit 143' TERM
trap 'REASON="interrupted (SIGINT)"; exit 130' INT
mkdir -p "$OUT/ra" "$OUT/ka"
host_tmp_snapshot > "$OUT/host-tmp-before.txt"
: > "$OUT/results.tsv"

# ---- before any lock or VM: the inputs, the scripts, the record directory
for f in otp/vmctl.sh otp/log-since.sh otp/install-ours.sh otp/install-env.sh otp/totp.py otp/radius_stub.py otp/norm.py otp/parity.sh ra/stage.sh ra/kpwsend.py ra/frames-nokey.tsv ra/cmp.py ka/stage.sh ka/session.sh ka/norm.py build-oracle.sh; do
    [ -e "$SCRIPTS/$f" ] || { echo "driver.sh: $SCRIPTS/$f is missing" >&2; exit 2; }
done
[ -x "$LAB" ] || { echo "driver.sh: $LAB is not executable" >&2; exit 2; }
prep_inputs
SRCINFO=$(head -1 "$W/ship-source.txt")
note "DRIVER_START $SRCINFO; lab.sh sha256 $(sha256sum "$LAB" | cut -c1-16)"
LEG_START=$(date -u '+%Y-%m-%d %H:%M:%S')
# a record of an earlier pass lives in a subdirectory (first-pass/); loose files at the top are a pass this one would overwrite
if [ -n "$(find "$REC" -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then echo "driver.sh: $REC holds the files of an earlier pass: move them into a subdirectory first" >&2; exit 2; fi
{
    echo "# the sha256 of every program of the ship build (SHIP=$SHIP) and of the oracle ($ORACLE); the VMs' copies are compared with these"
    cat "$W/ship-sha256.txt"; ( cd "$(dirname "$ORACLE")" && sha256sum "$(basename "$ORACLE")" )
} > "$OUT/inputs-sha256.txt"
result L0.oracle INFO "rd-priv-oracle built from the tree's source against the host's libkrb5 (host: $(rpm -q krb5-libs 2>/dev/null | head -1))" - "$(sha256sum "$ORACLE" | cut -c1-16)" "$ORACLE"

# ---- secrets, on the host only
SECRETS_MADE=1
make_secrets || fail "cannot make the lab-only secrets"
python3 -B -I "$SCRIPTS/otp/totp.py" selftest > "$OUT/totp-selftest.txt" 2>&1 || fail "totp.py selftest"
SEED=$SECD/otpuser.seed
PW=$(cat "$SECD/otpuser.pw")
MITCODE=$(cat "$SECD/mit.code")
MITWRONG=$(cat "$SECD/mit.wrong")
: > "$W/used-steps"
( umask 077; : > "$SECD/totp.codes" )
note "lab-only secrets made under $SECD (seed, lab password, the MIT stub's right and wrong codes); none printed"

# ================================================================ L0 lock, pre-status
take_lock
"$LAB" status > "$OUT/pre-status.txt" 2>> "$LOG" || fail "lab.sh status"
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
note "snapshots: the leg runs on $RESTSNAP_LEG; rest: kdc ${REST_SNAP[kdc]}, client2 ${REST_SNAP[client2]}, client1 ${REST_SNAP[client1]}; all shut off afterwards"

# ================================================================ L1 resets, checks, the Fedora identity per VM
note "L1 per VM, the kdc first: reset to $RESTSNAP_LEG, check --lab-only, the helper, our client programs on the clients, the facts and the MIT identity (the Fedora identity rule: package note, rpm -V config only, klist -V $KLIST_VERSION; a row that fails stops the leg)"
l1_vm kdc
for v in client2 client1; do l1_vm "$v"; done
expect L1.kdc.mit-version "$OUT/vm-facts-kdc.txt" '^krb5-server-1\.22\.2-4\.fc43'
expect L1.kdc.services-active "$OUT/vm-facts-kdc.txt" '^active$' 2
for c in "${CLIENTS[@]}"; do
    expect "L1.$c.kinit" "$OUT/vm-facts-$c.txt" '^/usr/s?bin/kinit$'
    expect "L1.$c.host-keytab" "$OUT/vm-facts-$c.txt" "${HOSTPRINC[$c]}"
    expect "L1.$c.mit-libs" "$OUT/vm-facts-$c.txt" '^krb5-libs-1\.22'
done
# clock skew, host -> VM (the TOTP code is computed on the host, against the KDC's clock)
{
    for v in "${VMS[@]}"; do
        t0=$(date +%s.%N); vt=$(vm "$v" "date +%s.%N" 2>> "$LOG"); t1=$(date +%s.%N)
        python3 -B -I -c "import sys; t0,vt,t1=map(float,sys.argv[1:]); print('$v: VM clock minus host clock = %+.3f s (ssh round trip %.3f s)' % (vt-(t0+t1)/2, t1-t0))" "$t0" "$vt" "$t1"
    done
} > "$OUT/clock-skew.txt"
cat "$OUT/clock-skew.txt" >> "$LOG"
SKEW=$(sed -n 's/^kdc: VM clock minus host clock = \([-+0-9.]*\) s.*/\1/p' "$OUT/clock-skew.txt")
OFFSET=$(python3 -B -I -c "s=float('${SKEW:-0}'); print(s if abs(s) > 3 else 0)")
note "TOTP clock offset used (the kdc's clock minus the host's, only when over 3 s): $OFFSET s (measured ${SKEW:-?})"
[ "$STOP_AFTER" = L1 ] && { note "STOP_AFTER L1"; exit 0; }

# ================================================================ L2 pushes and facts
note "L2 pushes: the ship build's server programs and dist/ (sha256 both sides), the OTP helpers, the RA r4 and KA inputs"
push kdc "$SCRIPTS/otp/radius_stub.py" "$VMD/radius_stub.py" 644 || fail "push radius_stub.py"
push kdc "$SCRIPTS/otp/install-ours.sh" "$VMD/install-ours.sh" 755 || fail "push install-ours.sh"
push kdc "$SCRIPTS/otp/install-env.sh" "$VMD/install-env.sh" 644 || fail "push install-env.sh"
TARLIST=(); for f in "${SERVER_PROGS[@]}"; do TARLIST+=("release/$f"); done
tar -C "$W/ship" -cf - "${TARLIST[@]}" dist | vm kdc "install -d -m 0700 $VMD/ship && tar -C $VMD/ship -xf -" >> "$LOG" 2>&1 || fail "push the ship tar"
vm kdc "cd $VMD/ship/release && sha256sum ${SERVER_PROGS[*]}" > "$OUT/ship-on-vm.sha256" 2>> "$LOG"
cmp -s "$OUT/ship-on-vm.sha256" "$W/ship-server.sha256" || fail "ship programs on the VM differ from the ship build"
note "the ship build's server programs on the VM equal the host's copy (sha256, seven programs); the clients' two programs were checked at their push"
ra_push || fail "push the RA r4 inputs"
ka_push || fail "push the KA inputs"
ra_ka_facts
{
    vm kdc "sudo bash $VMD/vmctl.sh otpplugin" 2>&1
    echo "== the MIT daemon the MIT stage runs: its package"
    vm kdc "rpm -qf /usr/sbin/krb5kdc 2>&1" 2>&1
    echo "== readelf -n /usr/sbin/krb5kdc (.note.package)"
    vm kdc "$(note_cmd /usr/sbin/krb5kdc)" 2>&1
    echo "== grep -a -o 'KRB5_BRAND: [^ ]*' /usr/sbin/krb5kdc | head -1"
    vm kdc "grep -a -o 'KRB5_BRAND: [^ ]*' /usr/sbin/krb5kdc | head -1" 2>&1
} | redact > "$OUT/L2-otp-plugin.txt"
cat "$OUT/L2-otp-plugin.txt" >> "$LOG"
expect L2.mit.otp-so "$OUT/L2-otp-plugin.txt" 'otp\.so'
info L2.mit.brand-krb5kdc "$OUT/L2-otp-plugin.txt" '^KRB5_BRAND: ' "absent in Fedora's build (expected; recorded, not judged)"
if ! expect_under L2.mit.package-note-krb5kdc "$OUT/L2-otp-plugin.txt" '^== readelf -n /usr/sbin/krb5kdc ' 'Packaging Metadata: \{"type":"rpm","name":"krb5","version":"'"$PKG_VERSION_RX"'"' && [ "$BRAND_ENFORCE" = 1 ]; then
    fail "the MIT krb5kdc is not the 1.22.2 release's (package note): the push is held"
fi
[ "$STOP_AFTER" = L2 ] && { note "STOP_AFTER L2"; exit 0; }

# ================================================================ L3 the MIT stage on the stock f4-mit realm: RA r4, KA, then OTP (it changes kdc.conf and restarts MIT's krb5kdc)
note "L3 MIT stage: RA r4 (kpasswd acceptor), KA (refused keys, MIT kadmin sessions), OTP (RADIUS stub, MIT's otp.so)"
AVC_MARK=$(vm kdc "sudo bash $VMD/vmctl.sh avc-mark" 2>> "$LOG" | tr -d '[:space:]')
echo "# getenforce on kdc: $(vm kdc getenforce 2>&1)" > "$OUT/L2-getenforce.txt"
cat "$OUT/L2-getenforce.txt" >> "$LOG"
ra_stage mit
ka_stage mit
ka_sessions mit
p16a_leg mit
note "OTP MIT stage"
otp_mit_setup
stage_cells M
otp2_mit
otp_mit_teardown
avc_rows AVC-mit "$AVC_MARK"
[ "$STOP_AFTER" = L3 ] && { note "STOP_AFTER L3"; exit 0; }

# ================================================================ L4 docs/install.md "Upgrading an MIT realm", literally, from the ship build
note "L4 install ours (docs/install.md, Upgrading an MIT realm)"
AVC_MARK3=$(vm kdc "sudo bash $VMD/vmctl.sh avc-mark" 2>> "$LOG" | tr -d '[:space:]')
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
expect L3.install.otpuser-listed "$OUT/install.txt" "^otpuser@$RRX\$"
expect L3.install.ra4user-listed "$OUT/install.txt" "^ra4user@$RRX\$"
expect L3.install.requires-preauth-step "$OUT/install.txt" '^Principal ".*" modified\.$'
otp_after_install
[ "$STOP_AFTER" = L4 ] && { note "STOP_AFTER L4"; exit 0; }

# ================================================================ L5 the ship build's stage: RA r4, KA, then OTP (the embedder replaces the service KDC)
note "L5 ours stage: RA r4, KA, OTP"
ra_stage rust
ka_stage rust
ka_sessions rust
p16a_leg rust
p8_check
{ echo "== $(now) after the install"; vm kdc "rpm -qf /usr/sbin/kadmind; systemctl is-active krb5kdc kadmin; rpm -q krb5-libs; sudo ss -H -lnt 'sport = :749'; sudo ss -H -lntu 'sport = :464'" 2>&1; } | redact > "$OUT/vm-facts-rust.txt"
cat "$OUT/vm-facts-rust.txt" >> "$LOG"
note "OTP ours stage"
otp_ours_setup
stage_cells O
otp1_ours
otp2_ours
otp_ours_teardown
avc_rows AVC-ours "$AVC_MARK3"
[ "$STOP_AFTER" = L5 ] && { note "STOP_AFTER L5"; exit 0; }

# ================================================================ L6 parity per package, with controls
note "L6 parity per package: RA r4 (cmp.py), KA (norm.py), OTP (parity.sh)"
ra_compare
ka_compare
p16a_compare
otp_parity
otp2_parity

# ================================================================ L7 shred on the VMs; the restore, the /tmp check, the publish and the scan run from the EXIT trap
note "L7 shred on the VMs"
for v in "${VMS[@]}"; do
    vm "$v" "sudo bash $VMD/vmctl.sh clean" 2>&1 | redact > "$OUT/L4-clean-$v.txt"
    cat "$OUT/L4-clean-$v.txt" >> "$LOG"
    expect "L4.$v.clean" "$OUT/L4-clean-$v.txt" '^CLEAN_OK secret files left: 0$'
done
{
    vm kdc "sudo env STAGE=clean D=$RAD bash $RAD/stage.sh; sudo env STAGE=clean D=$KAD bash $KAD/stage.sh; sudo shred -u /var/kerberos/krb5kdc/mit-realm.dump /var/kerberos/krb5kdc/mit-realm.dump.dump_ok 2>/dev/null; sudo ls -l $RAD $KAD /var/kerberos/krb5kdc | grep -cE 'keytab|mit-realm.dump|cases|frames-all|frames-setpw|frames.tsv'; true" 2>&1
} | redact > "$OUT/L4-clean-ra-ka.txt"
cat "$OUT/L4-clean-ra-ka.txt" >> "$LOG"
expect L4.kdc.ra-clean "$OUT/L4-clean-ra-ka.txt" '^CLEAN_OK \(no keytab, cases or frames file left\)$'
expect L4.kdc.ka-clean "$OUT/L4-clean-ra-ka.txt" '^CLEAN_OK \(no keytab left\)$'
CLEANED=1
package_summary
awk -F'\t' 'BEGIN { p = 0; f = 0; i = 0 } $2 == "PASS" { p++ } $2 == "FAIL" { f++ } $2 == "INFO" { i++ } END { printf "checks so far: %d PASS, %d FAIL, %d INFO (the restore adds its own)\n", p, f, i }' "$OUT/results.tsv" | tee -a "$LOG"
exit 0
