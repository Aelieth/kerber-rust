# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/pg7.sh: PG7 (kadm5_hook) on the final tree. MIT's kadmind and kadmin.local fault on `[plugins] kadm5_hook = { disable = nosuch }` and `{ enable_only = nosuch }` (the SAFER row,
# docs/mit-deviations.md:43); the ship build stays up and the operations succeed. The base cells (no stanza) are the parity half.
# Source records: judge.txt (the 27 judged rows), mit-cells.txt / rust-cells.txt (the four base cells), mit-conf.txt, mit-stanza-{disable,only,off}.txt and
# mit-stanza-cells.txt / mit-stanza-only-cells.txt (the stanza cells), rust-* twins, ship-bins.sha. The original VM script was not saved; the cells are rewritten from those outputs.
# Differences from the recorded leg (LEG, 2026-10-09 01:32Z, tree 7e1f3a32):
#   - the ours stage is dist/install.sh's upgrade of the final ship build (install-ours.sh), not `make install` after `dnf install make`; kdc, client1 and client2 are reset to f4-mit by the shell;
#   - the stanza is appended to kdc.conf by b2a-kdcconf.py (from the kept pristine file, in place) and taken out again by the same script; the record's begin/end MARKER pair is replaced by the
#     [plugins] line count (CONF_PLUGINS_LINES) and by the shell's config-as-found rows;
#   - passwords are the leg's throwaway ones (stdin); principals are m<cell> (MIT) and r<cell> (ours) as recorded;
#   - added: the journal and coredump evidence is recorded per stanza (the record kept it only for the MIT stage's kadmind), and kdc.conf is proved back as found after the last cell; the stage's principals are
#     deleted at its end (the shell compares the realm database with L1's at every module boundary), so the ours stage starts from the realm the reset made.
#   - the MIT stage's crash window is cut out of the stage's SELinux judgement: avc_judge before the first stanza, the window's denials recorded (PG7.mit.crash-window.avc-denials, not judged), avc_skip after.
# Cells (VM: kdc; MIT's kpasswd and kinit on the kdc in both stages, as recorded): base-create, base-cpw, base-kpasswd, base-kinit; stanza disable=nosuch: dis-create, dis-kpasswd, dis-kinit;
# stanza enable_only=nosuch: only-create, only-kinit; stanza off. The MIT stage crashes kadmind and kadmin.local on purpose (core dumps on the VM, discarded by the reset); the stanza is removed and
# kadmin restarted before pg7_mit returns (the later modules need a live kadmind).
# Cell -> record, file:line: base-create mit-cells.txt:1-4, base-cpw :5-8, base-kpasswd :9-15, base-kinit :16-19 (rust-cells.txt: the same cells); stanza disable=nosuch:
# mit-stanza-disable.txt:1-5 (RESTART_RC:1, KADMIN:failed; the coredump journal from :6, its frames at :54-55) and mit-stanza-cells.txt:1-11 (dis-create :1-3, dis-kpasswd :4-7, dis-kinit :8-11), rust-stanza-disable.txt:1-5
# and rust-stanza-cells.txt:1-15; stanza enable_only=nosuch: mit-stanza-only.txt (RESTART_RC:1), mit-stanza-only-cells.txt:1-7 (only-create :1-3, only-kinit :4-7), rust-stanza-only.txt, rust-stanza-only-cells.txt:1-8;
# stanza off: mit-stanza-off.txt:1-5, rust-stanza-off.txt:1-5; the judge: judge.txt:1-27 (MIT base 1-4, stanza 5-9; RUST 10-18; STANZA, INSTALL, SHA, MARKER 19-27).
. "$SCRIPTS/helpers/b2a-host.sh"

pg7_prep() {
    local f
    for f in pg7-kdc.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "pg7: helpers/$f is missing" >&2; return 1; }; done
}
pg7_push() { b2a_push_script pg7-kdc.sh; }

# pg7_run STAGE SECTION: the section's cells on the kdc (three throwaway passwords on stdin), split per cell
pg7_run() {
    b2a_pw3 | b2a_run_kdc "pg7/$1-run-$2" pg7-kdc.sh "$1" "$2"
    b2a_split "$OUT/pg7/$1-run-$2.txt" "$OUT/pg7" "$1"
}

pg7_avc_window() {   # pg7_avc_window FROM: the SELinux records since FROM (the kdc's clock, HH:MM:SS) up to now: recorded, not judged (MIT's crash is what provoked them, if any)
    local f="$OUT/pg7/mit-avc-crash-window.txt"
    vm kdc "sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $1 2>&1 | grep -E 'denied|no matches' | cut -c1-300" 2>&1 < /dev/null | redact > "$f"
    info PG7.mit.crash-window.avc-denials "$f" 'denied' "(no AVC denial in the crash window)"
}

pg7_stage() {   # pg7_stage mit|ours
    local st=$1 P L=PG7.$1 f run c crash0=""
    if [ "$st" = mit ]; then P=m; else P=r; fi
    # ---- base: no stanza (record: mit-cells.txt / rust-cells.txt; judge.txt MIT base-* / RUST base-*)
    pg7_run "$st" base
    run="$OUT/pg7/$st-run-base.txt"
    expect "$L.base.facts-units" "$run" '^KADMIN:active$' 1
    f="$OUT/pg7/$st-base-create.txt"
    expect "$L.base-create.rc" "$f" '^RC:0$'
    expect "$L.base-create.text" "$f" "^Principal \"${P}base@$RRX\" created\\.\$"
    f="$OUT/pg7/$st-base-cpw.txt"
    expect "$L.base-cpw.rc" "$f" '^RC:0$'
    expect "$L.base-cpw.text" "$f" "^Password for \"${P}base@$RRX\" changed\\.\$"
    f="$OUT/pg7/$st-base-kpasswd.txt"
    expect "$L.base-kpasswd.rc" "$f" '^RC:0$'
    expect "$L.base-kpasswd.text" "$f" '^Password changed\.$'
    f="$OUT/pg7/$st-base-kinit.txt"
    expect "$L.base-kinit.rc" "$f" '^KINIT_RC:0$'
    expect "$L.base-kinit.no-error" "$f" '^ERR:$'
    # ---- MIT's stage crashes kadmind and kadmin.local on purpose: everything before is judged for SELinux denials now (avc_judge), the crash window is recorded and then skipped (avc_skip), so that a denial
    # the crash itself provokes (the core dump handler, a restart) is not read as a fault of a later module
    if [ "$st" = mit ]; then avc_judge "$L.avc-before-crash"; crash0=$(avc_mark); fi
    # ---- stanza disable = nosuch (record: mit-stanza-disable.txt, mit-stanza-cells.txt; rust-stanza-disable.txt, rust-stanza-cells.txt)
    pg7_run "$st" stanza-disable
    run="$OUT/pg7/$st-run-stanza-disable.txt"
    expect "$L.stanza-disable.stanza-written" "$run" '^CONF_PLUGINS_LINES:1$'
    if [ "$st" = mit ]; then   # MIT: kadmind faults in configure_interface (plugin.c:336), kadmin.local exits 139
        expect "$L.stanza-disable.restart-rc" "$run" '^RESTART_RC:1$'
        expect "$L.stanza-disable.kadmin-failed" "$run" '^KADMIN:failed$'
        expect "$L.stanza-disable.kdc-active" "$run" '^KDC:active$'
        expect_under "$L.stanza-disable.journal-core-dump" "$run" '^== journal: kadmin\.service' "Failed with result 'core-dump'"
        expect_under "$L.stanza-disable.core-kadmind" "$run" '^== coredumps since' 'Process [0-9]+ \(kadmind\) of user 0 dumped core'
        expect_under "$L.stanza-disable.frame-configure_interface" "$run" '^== coredumps since' '#0 .*configure_interface'
        expect_under "$L.stanza-disable.frame-plugin-load-all" "$run" '^== coredumps since' '#1 .*k5_plugin_load_all'
        info "$L.stanza-disable.core-kadmin-local" "$run" 'Process [0-9]+ \(kadmin\.local\) of user 0 dumped core' "(kadmin.local's own coredump entry is not required: its rc 139 is the evidence)"
        expect "$L.dis-create.rc" "$OUT/pg7/$st-dis-create.txt" '^RC:139$'
        expect "$L.dis-kpasswd.rc" "$OUT/pg7/$st-dis-kpasswd.txt" '^RC:1$'
        expect "$L.dis-kpasswd.text" "$OUT/pg7/$st-dis-kpasswd.txt" '^kpasswd: Client not found in Kerberos database getting initial ticket$'
        expect "$L.dis-kinit.rc" "$OUT/pg7/$st-dis-kinit.txt" '^KINIT_RC:1$'
        expect "$L.dis-kinit.text" "$OUT/pg7/$st-dis-kinit.txt" "^ERR:kinit: Client '${P}dis@$RRX' not found in Kerberos database while getting initial credentials"
    else                       # ours: up, the operations succeed
        expect "$L.stanza-disable.restart-rc" "$run" '^RESTART_RC:0$'
        expect "$L.stanza-disable.kadmin-active" "$run" '^KADMIN:active$'
        expect "$L.stanza-disable.kdc-active" "$run" '^KDC:active$'
        expect_under "$L.stanza-disable.no-core" "$run" '^== coredumps since' 'dumped core' 0
        expect "$L.dis-create.rc" "$OUT/pg7/$st-dis-create.txt" '^RC:0$'
        expect "$L.dis-create.text" "$OUT/pg7/$st-dis-create.txt" "^Principal \"${P}dis@$RRX\" created\\.\$"
        expect "$L.dis-kpasswd.rc" "$OUT/pg7/$st-dis-kpasswd.txt" '^RC:0$'
        expect "$L.dis-kpasswd.text" "$OUT/pg7/$st-dis-kpasswd.txt" '^Password changed\.$'
        expect "$L.dis-kinit.rc" "$OUT/pg7/$st-dis-kinit.txt" '^KINIT_RC:0$'
    fi
    # ---- stanza enable_only = nosuch (record: mit-stanza-only.txt, mit-stanza-only-cells.txt; rust twins)
    pg7_run "$st" stanza-only
    run="$OUT/pg7/$st-run-stanza-only.txt"
    expect "$L.stanza-only.stanza-written" "$run" '^CONF_PLUGINS_LINES:1$'
    if [ "$st" = mit ]; then
        expect "$L.stanza-only.restart-rc" "$run" '^RESTART_RC:1$'
        expect "$L.stanza-only.kadmin-failed" "$run" '^KADMIN:failed$'
        expect "$L.stanza-only.kdc-active" "$run" '^KDC:active$'
        expect_under "$L.stanza-only.core-kadmind" "$run" '^== coredumps since' 'Process [0-9]+ \(kadmind\) of user 0 dumped core'
        expect_under "$L.stanza-only.frame-configure_interface" "$run" '^== coredumps since' '#0 .*configure_interface'
        expect "$L.only-create.rc" "$OUT/pg7/$st-only-create.txt" '^RC:139$'
        expect "$L.only-kinit.rc" "$OUT/pg7/$st-only-kinit.txt" '^KINIT_RC:1$'
        expect "$L.only-kinit.text" "$OUT/pg7/$st-only-kinit.txt" "^ERR:kinit: Client '${P}only@$RRX' not found in Kerberos database while getting initial credentials"
    else
        expect "$L.stanza-only.restart-rc" "$run" '^RESTART_RC:0$'
        expect "$L.stanza-only.kadmin-active" "$run" '^KADMIN:active$'
        expect "$L.stanza-only.kdc-active" "$run" '^KDC:active$'
        expect_under "$L.stanza-only.no-core" "$run" '^== coredumps since' 'dumped core' 0
        expect "$L.only-create.rc" "$OUT/pg7/$st-only-create.txt" '^RC:0$'
        expect "$L.only-create.text" "$OUT/pg7/$st-only-create.txt" "^Principal \"${P}only@$RRX\" created\\.\$"
        expect "$L.only-kinit.rc" "$OUT/pg7/$st-only-kinit.txt" '^KINIT_RC:0$'
    fi
    # ---- the stanza removed: MIT's kadmind starts again (record: mit-stanza-off.txt, "STANZA off / MARKER 0 / RESTART_RC:0 / KADMIN:active")
    pg7_run "$st" stanza-off
    run="$OUT/pg7/$st-run-stanza-off.txt"
    expect "$L.stanza-off.stanza-gone" "$run" '^CONF_PLUGINS_LINES:0$'
    expect "$L.stanza-off.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.stanza-off.kadmin-active" "$run" '^KADMIN:active$'
    expect "$L.stanza-off.kdc-active" "$run" '^KDC:active$'
    expect "$L.stanza-off.kadmind-listening" "$run" '^KADMIND_LISTENING$'
    if [ "$st" = mit ]; then pg7_avc_window "$crash0"; avc_skip; fi
    # ---- the stage's principals deleted again: the realm database is as L1 found it at this module's boundary (the shell's realm-as-found row)
    pg7_run "$st" cleanup
    expect "$L.cleanup.base-deleted" "$OUT/pg7/$st-del-base.txt" "^Principal \"${P}base@$RRX\" deleted\\.\$"
    if [ "$st" = ours ]; then
        expect "$L.cleanup.dis-deleted" "$OUT/pg7/$st-del-dis.txt" "^Principal \"${P}dis@$RRX\" deleted\\.\$"
        expect "$L.cleanup.only-deleted" "$OUT/pg7/$st-del-only.txt" "^Principal \"${P}only@$RRX\" deleted\\.\$"
    fi
    return 0
}

pg7_mit() { pg7_stage mit; }
pg7_ours() { pg7_stage ours; }

pg7_parity() {
    local c f m o sdoc="docs/mit-deviations.md:43"
    # the principal's m / r prefix is the only mask on the base cells (record: "texts equal after the m/r prefix")
    local -a mask=('s/([^A-Za-z0-9_])[mr](base)@/\1P\2@/g')
    for c in base-create base-cpw base-kpasswd base-kinit; do
        parity_eq "PG7.parity.$c" "$OUT/pg7/mit-$c.txt" "$OUT/pg7/ours-$c.txt" "${mask[@]}"
    done
    parity_control PG7.parity.base-create "$OUT/pg7/mit-base-create.txt" "$OUT/pg7/ours-base-create.txt" "${mask[@]}"
    # the stanza cells differ on purpose: MIT faults, the ship build stays up (SAFER, docs/mit-deviations.md:43; MIT cite plugin.c:257-298, :336, :340): one row per cell holds both facts
    parity_dev PG7.parity.dis-create.safer "$sdoc" "$OUT/pg7/mit-dis-create.txt" '^RC:139$' "$OUT/pg7/ours-dis-create.txt" '^RC:0$'
    parity_dev PG7.parity.dis-kpasswd.safer "$sdoc" "$OUT/pg7/mit-dis-kpasswd.txt" '^RC:1$' "$OUT/pg7/ours-dis-kpasswd.txt" '^RC:0$'
    parity_dev PG7.parity.dis-kinit.safer "$sdoc" "$OUT/pg7/mit-dis-kinit.txt" '^KINIT_RC:1$' "$OUT/pg7/ours-dis-kinit.txt" '^KINIT_RC:0$'
    parity_dev PG7.parity.only-create.safer "$sdoc" "$OUT/pg7/mit-only-create.txt" '^RC:139$' "$OUT/pg7/ours-only-create.txt" '^RC:0$'
    parity_dev PG7.parity.only-kinit.safer "$sdoc" "$OUT/pg7/mit-only-kinit.txt" '^KINIT_RC:1$' "$OUT/pg7/ours-only-kinit.txt" '^KINIT_RC:0$'
    parity_dev PG7.parity.stanza-disable-restart.safer "$sdoc" "$OUT/pg7/mit-run-stanza-disable.txt" '^KADMIN:failed$' "$OUT/pg7/ours-run-stanza-disable.txt" '^KADMIN:active$'
    parity_dev PG7.parity.stanza-only-restart.safer "$sdoc" "$OUT/pg7/mit-run-stanza-only.txt" '^KADMIN:failed$' "$OUT/pg7/ours-run-stanza-only.txt" '^KADMIN:active$'
    # after the stanza is gone the two stages are the same again
    parity_eq PG7.parity.stanza-off.state <(grep -E '^(CONF_PLUGINS_LINES|RESTART_RC|KADMIN|KDC|KADMIND_LISTENING)' "$OUT/pg7/mit-run-stanza-off.txt") <(grep -E '^(CONF_PLUGINS_LINES|RESTART_RC|KADMIN|KDC|KADMIND_LISTENING)' "$OUT/pg7/ours-run-stanza-off.txt")
    # the control of the deviation rows: MIT's cell with its 139 turned into 0 must NOT satisfy the row (the row can fail)
    m="$OUT/pg7/control-mit-dis-create.txt"; sed 's/^RC:139$/RC:0/' "$OUT/pg7/mit-dis-create.txt" > "$m"
    o=$(grep -cE '^RC:139$' "$m" || true)
    if [ "${o:-0}" = 0 ]; then verdict PG7.parity.dis-create.safer.control PASS "a doctored MIT cell (139 turned into 0) must not hold the SAFER row's MIT fact" 0 "$o"
    else verdict PG7.parity.dis-create.safer.control FAIL "a doctored MIT cell (139 turned into 0) must not hold the SAFER row's MIT fact" 0 "$o"; fi
    return 0
}

pg7_clean() {   # the stanza is removed in the stage (stanza-off); this puts kdc.conf back once more and leaves no state a reset would not take
    vm kdc "sudo env VMCTL_D=$VMD python3 -I $VMD/b2a/b2a-kdcconf.py" > /dev/null 2>&1
    return 0
}
