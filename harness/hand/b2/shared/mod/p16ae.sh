# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/p16ae.sh: P16a-edges (the dictionary edges of kadmind's password quality, the passwd_check log line, where kdb5_util create stops, the password octets) on the final tree. The old VM leg's ours
# record lacked the no-policy cell; this one has it. At the tip crates/krb5-admin/src/listen.rs:476 sends MIT's dictionary paragraph, so the kpasswd client text is now expected to EQUAL MIT's.
# Source records: driver.log (section banners), edges-mit.txt, edges-rust.txt (the cpw / kpasswd cells and the kadmind log lines), side-mit.txt, prep.txt,
# discover.txt, kdc-staged.txt, kf-*; and the container settles s1-content-edges.sh, s2-create-failure.sh, s3-passwd-check-log.sh (the dictionary shapes, the create cases). The original VM helpers
# (kdc-dict.sh, kdc-prep.sh, kdc-side.sh, kdc-upgrade.sh) and the host driver were not saved: rewritten from those outputs.
# Differences from the recorded leg (18:06Z 2026-10-08, tree 77158296):
#   - the ours stage is dist/install.sh's upgrade of the final ship build, not `make install` after `dnf install make`; all three VMs are reset to f4-mit by the shell;
#   - cells added: stock-nopol in the ours stage (the record lacked it), octets-kinit (kinit p16auser with the password `caf\311` the latin-fold cell set: the raw bytes reach the key), the AVC records of the FIFO
#     window (the record never ran ausearch); the kpasswd stock-reject text is expected equal on both stages (the record's ours column said "Password change rejected: Password is in the password dictionary");
#   - LC_ALL=en_US.ISO-8859-1 reaches kadmind through a systemd drop-in that is removed again (the record does not say how); the throwaway passwords are stdin lines; p16auser and p16anopol are created in each
#     stage and deleted with the policy at its end (the realm database is compared with L1's at every module boundary), not carried through the dump/load;
#   - the side databases live under $VMD/p16ae/side-<stage>/ (the record: /var/tmp/p16a/side-<impl>/); stdout and stderr of kdb5_util create are kept apart as in the record, the master-key prompts are cut out;
#   - KF (7bcc439e): one cell per stage, OUR kinit ($VMD/ours/kinit) logging alice in against the stage's KDC: rc 0, no `ok` line, no JSON line, nothing on stderr.
# Order on the kdc (survey section 6): prep, the side creates, the stock / NUL / Latin-1 / Latin-1 under LC_ALL cells, the KF cell, the SELinux judgement of everything so far (avc_judge), and LAST the FIFO
# cells (they need setenforce 0 and provoke SELinux denials and a 25 s blocked restart); enforcing is restored, then avc_skip moves the AVC mark past the denials the module provoked on purpose.
# MIT-only tools: kdb5_util create and kadmin.local run in the stage's own tools (MIT's in _mit, ours after the upgrade).
# Cell -> record, file:line: prep driver.log:36-54 (prep.txt:1-14); the side creates side-mit.txt (dir :1-8, missing :9-14; driver.log:55-73) and the ours ones
# driver.log:303-322; the MIT cells edges-mit.txt (driver.log:74-203): stock dict :1-29 (stock-reject :5-10, stock-nopol :11-14, kpasswd stock-reject :15-24, stock-ok :25-29), NUL :30-56 (nul-in :34-39, nul-hidden
# :40-45, nul-keep :46-51, nul-shift :52-56), Latin-1 :57-70 (latin-exact :61-66, latin-fold :67-70), under LC_ALL :71-87 (latin-iso-exact :76-81, latin-iso-fold :82-87), FIFO :92-129 (fifo_restart_failed
# enforce=Enforcing :96, setenforce 0 :117, fifo-word :121-124, fifo-nowriter restart_rc=124 :127, setenforce 1 :128); the ours twins edges-rust.txt (driver.log:323-526; fifo_restart_failed :189, restart_rc=124 :221);
# KF: kf-mit.out, kf-mit-kinit.txt:1-3 (driver.log:204-207) and kf-rust-kinit.txt:1-2; the deviation rows docs/mit-deviations.md:21 (principal.lockout instead of principal.kadm5), :55 (kadmind's dictionary).
. "$SCRIPTS/helpers/b2a-host.sh"

p16ae_prep() {
    local f
    for f in p16ae-kdc.sh p16ae-client.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "p16ae: helpers/$f is missing" >&2; return 1; }; done
    B2_RESIDUE_PATHS+=("/var/kerberos/krb5kdc/p16a")
}
p16ae_push() {
    b2a_push_script p16ae-kdc.sh || return 1
    push client1 "$SCRIPTS/helpers/p16ae-client.sh" "$VMD/b2a/p16ae-client.sh" 755 || return 1
    push client2 "$SCRIPTS/helpers/p16ae-client.sh" "$VMD/b2a/p16ae-client.sh" 755 || return 1
}

p16ae_run_file() { printf '%s/p16ae/%s-run-%s.txt' "$OUT" "$1" "$2${3:+-$3}${4:+-$4}"; }   # p16ae_run_file STAGE SECTION [ARG [ARG2]]
p16ae_kdc() {   # p16ae_kdc STAGE SECTION [ARG [ARG2]]: the section on the kdc (three throwaway passwords on stdin); the transcript and its cells split per cell
    local st=$1 f
    f=$(p16ae_run_file "$@")
    b2a_pw3 | b2a_run_kdc "p16ae/$(basename "$f" .txt)" p16ae-kdc.sh "$@"
    b2a_split "$f" "$OUT/p16ae" "$st"
}
p16ae_cpw() {   # p16ae_cpw STAGE LABEL PRINC PWFMT [N]: MIT kadmin cpw -pw from client1 (stdin: the admin password; line 2: throwaway password N when PWFMT is @STDIN2@)
    local st=$1 label=$2 princ=$3 fmt=$4
    { admin_pw; [ "$fmt" = @STDIN2@ ] && b2_pw "${5:-2}"; } | cell "p16ae/$st-cpw-$label" client1 "bash $VMD/b2a/p16ae-client.sh cpw cpw-$label $princ '$fmt'" kdc+kadmin
}
p16ae_logs() {   # the quality / chpass / chpw lines of a cell's kadmind log part, without the syslog prefix, the pid and the addresses
    sed -n '/^# kadmind log lines added/,$p' "$1" | grep -E 'password quality module|Request: kadm5_chpass_principal|chpw request' \
        | sed -E 's/^[A-Z][a-z]{2} [0-9 ]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/; s/ from [^ ]+ for / from ADDR for /; s/addr=[0-9a-fA-F:.%a-z0-9]+$/addr=ADDR/'
}
p16ae_refused() {   # p16ae_refused LABEL FILE PRINC: the dictionary refusal of a cpw: rc 0, the text, and the two kadmind log lines (record: edges-mit.txt lines 5-9)
    expect "$1.rc" "$2" '^RC:0$'
    expect "$1.text" "$2" "^change_password: Password is in the password dictionary while changing password for \"$3@$RRX\"\\.\$"
    expect_part "$1.log-module" "$2" kadmin "password quality module dict rejected password for $3@$RRX: Password is in the password dictionary"
    expect_part "$1.log-request" "$2" kadmin "Request: kadm5_chpass_principal, $3@$RRX, Password is in the password dictionary, client=admin/admin@$RRX, service=kadmin/admin@$RRX, addr="
}
p16ae_changed() {   # p16ae_changed LABEL FILE PRINC: the password was changed: rc 0, the text, and no quality log line
    expect "$1.rc" "$2" '^RC:0$'
    expect "$1.text" "$2" "^Password for \"$3@$RRX\" changed\\.\$"
    expect_part "$1.no-quality-log" "$2" kadmin 'password quality module' 0
}
p16ae_state() {   # p16ae_state LABEL RUNFILE DICTPATH-RX [iso]: kadmin is active under the dict_file of the cell, with or without LC_ALL=en_US.ISO-8859-1 in its environment
    expect "$1.active" "$2" '^active=active$'
    expect "$1.dict-file" "$2" "^dict_file $3\$"
    if [ "${4:-}" = iso ]; then expect "$1.lc-all" "$2" '^LC_ALL=en_US\.ISO-8859-1$'; else expect "$1.no-lc-all" "$2" '^LC_ALL=' 0; fi
}

p16ae_stage() {   # p16ae_stage mit|ours
    local st=$1 L=P16AE.$1 f run word P=p16auser
    # ---- prep: the dictionaries, the FIFO writer, the policy, the two principals (record: prep.txt; the original ours record lacked the no-policy cell)
    p16ae_kdc "$st" prep
    run=$(p16ae_run_file "$st" prep)
    word=$(sed -n 's/^stock_word //p' "$run" | head -n 1)
    expect "$L.prep.stock-word" "$run" '^stock_word [a-z]+$'
    expect "$L.prep.fifo-writer-alive" "$run" '^fifo_writer_alive$'
    expect "$L.prep.prep-done" "$run" '^PREP_DONE$'
    # the units as this module found them (a unit found down is an earlier module's leftover: started once and said here; the shell's row of that module is the one that blames it)
    expect "$L.prep.history-absent-at-start" "$run" '^HISTORY_AT_START no$'                  # kadmin/history as the stage found it (the cpw cells below make it; cleanup deletes what this stage made)
    info "$L.prep.entry-units" "$run" '^ENTRY_UNITS krb5kdc=' "(no ENTRY_UNITS line)"
    info "$L.prep.entry-started" "$run" '^ENTRY_STARTED ' "(none: krb5kdc and kadmin were active at the entry)"
    expect "$L.prep.entry-units-active" "$run" '^ENTRY_UNITS_NOW krb5kdc=active kadmin=active$' 1
    expect "$L.prep.fifo-label" "$run" 'krb5kdc_conf_t.* fifo\.dict$'                         # the dictionaries carry the KDC directory's type (record: edges-mit.txt, "krb5kdc_conf_t")
    expect "$L.prep.user-created" "$OUT/p16ae/$st-addprinc-user.txt" "^Principal \"p16auser@$RRX\" created\\.\$"
    expect "$L.prep.nopol-created" "$OUT/p16ae/$st-addprinc-nopol.txt" "^Principal \"p16anopol@$RRX\" created\\.\$"
    f="$OUT/p16ae/$st-getprinc-user.txt"
    expect "$L.prep.user-attributes" "$f" '^Attributes: .*REQUIRES_PRE_AUTH'
    expect "$L.prep.user-policy" "$f" '^Policy: p16apol$'
    # ---- the side databases: where kdb5_util create stops when dict_file cannot be read (record: side-mit.txt; s2-create-failure.sh)
    p16ae_kdc "$st" side
    run=$(p16ae_run_file "$st" side)
    f="$OUT/p16ae/$st-create-dir.txt"
    expect "$L.create-dir.rc" "$f" '^rc=1$'
    expect "$L.create-dir.message" "$f" 'kdb5_util: Is a directory while initializing the Kerberos admin interface'
    expect "$L.create-dir.files" "$f" '^  files: admin\.log principal .*principal\.kadm5\.lock .*principal\.ok stash $'
    expect "$L.create-dir.no-principals" "$f" '^  principals: $'                        # kadmin.local stops at the unreadable dictionary: nothing listed (record: "principals: ")
    expect "$L.create-dir.kadmin-local-stops" "$f" '^  listprincs-stderr: .*Is a directory'
    info "$L.create-dir.principals-without-dict" "$f" '^  principals-without-dict: ' "(not listed)"           # what the database holds when create stopped (new; compared MIT against ours in the parity)
    f="$OUT/p16ae/$st-create-missing.txt"
    expect "$L.create-missing.rc" "$f" '^rc=0$'
    expect "$L.create-missing.principals" "$f" "^  principals: K/M@$RRX kadmin/admin@$RRX kadmin/changepw@$RRX krbtgt/$RRX@$RRX \$"
    expect "$L.create-missing.warning-kdb5_util" "$f" 'kdb5_util\[pid\]\(Error\): WARNING!  Cannot find dictionary file .*/no-such-dict, continuing without one\.$'
    expect "$L.create-missing.warning-kadmin.local" "$f" 'kadmin\.local\[pid\]\(Error\): WARNING!  Cannot find dictionary file .*/no-such-dict, continuing without one\.$'
    expect "$L.side.done" "$run" "^SIDE_DONE_$st\$"
    # ---- the stock dictionary (dict_file as the realm has it): a word refused, the same word on the principal without a policy changed, kpasswd refused, an ordinary password changed
    p16ae_kdc "$st" dict stock
    run=$(p16ae_run_file "$st" dict stock)
    p16ae_state "$L.stock" "$run" '.*'
    p16ae_cpw "$st" stock-reject $P "$word"
    p16ae_refused "$L.stock-reject" "$OUT/p16ae/$st-cpw-stock-reject.txt" p16auser
    p16ae_cpw "$st" stock-nopol p16anopol "$word"
    p16ae_changed "$L.stock-nopol" "$OUT/p16ae/$st-cpw-stock-nopol.txt" p16anopol          # a principal without a policy skips the dict module: changed, no log line (the ours record lacked this cell)
    b2_pw 1 | cell "p16ae/$st-kpasswd-stock-reject" client2 "bash $VMD/b2a/p16ae-client.sh kpasswd kpasswd-stock-reject $P '$word'" kdc+kadmin
    f="$OUT/p16ae/$st-kpasswd-stock-reject.txt"
    expect "$L.kpasswd-stock-reject.rc" "$f" '^RC:2$'
    expect "$L.kpasswd-stock-reject.dict-1" "$f" '^Password change rejected: New password was found in a dictionary of possible passwords and$'     # equal to MIT's at the tip (listen.rs:476)
    expect "$L.kpasswd-stock-reject.dict-2" "$f" '^therefore may be easily guessed\. Please choose another password\.$'
    expect "$L.kpasswd-stock-reject.dict-3" "$f" '^See the kpasswd man page for help in choosing a good password\.$'
    expect_part "$L.kpasswd-stock-reject.log-module" "$f" kadmin "password quality module dict rejected password for p16auser@$RRX: Password is in the password dictionary"
    expect_part "$L.kpasswd-stock-reject.log-chpw" "$f" kadmin "chpw request from .* for p16auser@$RRX: Password is in the password dictionary"
    p16ae_cpw "$st" stock-ok $P @STDIN2@ 2
    p16ae_changed "$L.stock-ok" "$OUT/p16ae/$st-cpw-stock-ok.txt" p16auser
    # ---- a NUL inside the first line: abc\0def / xyz / qrs (MIT init_dict: the NUL ends the word and shifts the rest; record: nul-in nul-hidden nul-keep refused, nul-shift changed)
    p16ae_kdc "$st" dict nul
    p16ae_state "$L.nul" "$(p16ae_run_file "$st" dict nul)" '.*/p16a/nul\.dict'
    p16ae_cpw "$st" nul-in $P abc;     p16ae_refused "$L.nul-in" "$OUT/p16ae/$st-cpw-nul-in.txt" p16auser
    p16ae_cpw "$st" nul-hidden $P def; p16ae_refused "$L.nul-hidden" "$OUT/p16ae/$st-cpw-nul-hidden.txt" p16auser
    p16ae_cpw "$st" nul-keep $P xyz;   p16ae_refused "$L.nul-keep" "$OUT/p16ae/$st-cpw-nul-keep.txt" p16auser
    p16ae_cpw "$st" nul-shift $P qrs;  p16ae_changed "$L.nul-shift" "$OUT/p16ae/$st-cpw-nul-shift.txt" p16auser
    # ---- Latin-1: caf\351 / zebra, kadmind in en_US.UTF-8: the exact bytes refused, the upper-case Latin-1 letter (caf\311) not folded; the raw bytes reach the key (octets-kinit)
    p16ae_kdc "$st" dict latin
    p16ae_state "$L.latin" "$(p16ae_run_file "$st" dict latin)" '.*/p16a/latin\.dict'
    p16ae_cpw "$st" latin-exact $P 'caf\351'; p16ae_refused "$L.latin-exact" "$OUT/p16ae/$st-cpw-latin-exact.txt" p16auser
    p16ae_cpw "$st" latin-fold $P 'caf\311';  p16ae_changed "$L.latin-fold" "$OUT/p16ae/$st-cpw-latin-fold.txt" p16auser
    cell "p16ae/$st-kinit-octets" client2 "bash $VMD/b2a/p16ae-client.sh kinit kinit-octets $P 'caf\\311'" kdc < /dev/null
    expect "$L.kinit-octets.rc" "$OUT/p16ae/$st-kinit-octets.txt" '^KINIT_RC:0$'
    expect "$L.kinit-octets.no-error" "$OUT/p16ae/$st-kinit-octets.txt" '^ERR:$'
    # ---- the same dictionary with LC_ALL=en_US.ISO-8859-1 in kadmind's environment: strcasecmp folds the Latin-1 letters (caf\311 now refused)
    p16ae_kdc "$st" dict latin iso
    p16ae_state "$L.latin-iso" "$(p16ae_run_file "$st" dict latin iso)" '.*/p16a/latin\.dict' iso
    p16ae_cpw "$st" latin-iso-exact $P 'caf\351'; p16ae_refused "$L.latin-iso-exact" "$OUT/p16ae/$st-cpw-latin-iso-exact.txt" p16auser
    p16ae_cpw "$st" latin-iso-fold $P 'caf\311';  p16ae_refused "$L.latin-iso-fold" "$OUT/p16ae/$st-cpw-latin-iso-fold.txt" p16auser
    # ---- KF: our kinit as a client of this stage's KDC prints no `ok` line, no JSON line, nothing on stderr (the KDC is MIT's here in the MIT stage)
    alice_pw | cell "p16ae/$st-kf" client1 "bash $VMD/b2a/p16ae-client.sh kf kf alice" kdc
    f="$OUT/p16ae/$st-kf.txt"
    expect "$L.kf.rc" "$f" '^RC:0$'
    expect "$L.kf.no-ok-line" "$f" '^OK_LINES:0$'
    expect "$L.kf.no-json-line" "$f" '^JSON_LINES:0$'
    expect "$L.kf.stderr-empty" "$f" '^STDERR:$'
    expect "$L.kf.stdout-is-the-prompt" "$f" "^STDOUT:Password for alice@$RRX: \\|?\$"
    # ---- everything so far judged for SELinux denials; the FIFO cells come last
    avc_judge "$L.avc-before-fifo"
    p16ae_kdc "$st" fifo-enforcing
    run=$(p16ae_run_file "$st" fifo-enforcing)
    expect "$L.fifo.writer-alive" "$run" '^fifo_writer_alive$'
    expect "$L.fifo.enforcing-before" "$run" '^enforce_before=Enforcing$'
    expect "$L.fifo.restart-fails-enforcing" "$run" '^fifo_restart_failed enforce=Enforcing$'            # record: edges-mit.txt line 142 / edges-rust.txt line 189
    expect_under "$L.fifo.permission-denied" "$run" '^== journal: kadmin\.service' 'kadmind: Permission denied while initializing, aborting'
    info "$L.fifo.avc-denials" "$run" 'denied' "(no AVC denial in the window: the survey's reading of the cause is not confirmed)"
    p16ae_kdc "$st" fifo-permissive
    run=$(p16ae_run_file "$st" fifo-permissive)
    expect "$L.fifo.setenforce-0" "$run" '^enforce_now=Permissive$'
    expect "$L.fifo.restart-works-permissive" "$run" '^active=active$'
    expect "$L.fifo.dict-file" "$run" "^dict_file .*/p16a/fifo\\.dict\$"
    p16ae_cpw "$st" fifo-word $P zebra                                    # a FIFO with a writer has st_size 0: an empty dictionary, so the word is accepted
    p16ae_changed "$L.fifo-word" "$OUT/p16ae/$st-cpw-fifo-word.txt" p16auser
    p16ae_kdc "$st" fifo-nowriter
    run=$(p16ae_run_file "$st" fifo-nowriter)
    expect "$L.fifo-nowriter.restart-blocks" "$run" '^restart_rc=124$'                                    # record: restart_rc=124 on both stages (about 25 s)
    p16ae_kdc "$st" fifo-restore
    run=$(p16ae_run_file "$st" fifo-restore)
    expect "$L.fifo-restore.enforcing" "$run" '^enforce_now=Enforcing$'
    expect "$L.fifo-restore.active" "$run" '^active=active$'
    expect "$L.fifo-restore.dict-file" "$run" '^dict_file (\(none\)|/.*words.*)$'
    expect "$L.fifo-restore.units-active" "$run" '^UNITS krb5kdc=active kadmin=active$' 1                # the stage ends with both units active, as it found them
    expect "$L.fifo-restore.krb5kdc-never-down" "$run" '^KRB5KDC_FOUND_DOWN' 0                           # krb5kdc is not this module's to stop: found down here = the module (or the lab) took it down
    avc_skip                                                              # the denials above were provoked on purpose and judged here; the stage's AVC row starts after them
    # ---- the realm as L1 found it
    p16ae_kdc "$st" cleanup
    expect "$L.cleanup.user-deleted" "$OUT/p16ae/$st-del-user.txt" "^Principal \"p16auser@$RRX\" deleted\\.\$"
    expect "$L.cleanup.nopol-deleted" "$OUT/p16ae/$st-del-nopol.txt" "^Principal \"p16anopol@$RRX\" deleted\\.\$"
    expect "$L.cleanup.rc" "$OUT/p16ae/$st-del-pol.txt" '^RC:0$'
    run=$(p16ae_run_file "$st" cleanup)
    info "$L.cleanup.history-created-by-stage" "$run" '^HISTORY_CREATED_BY_STAGE$' "(kadmin/history was not made by this stage)"
    expect "$L.cleanup.history-gone" "$run" '^HISTORY_AT_END no$'                            # the realm is as found for the next stage and for the install's dump
    return 0
}

p16ae_mit() { p16ae_stage mit; }
p16ae_ours() { p16ae_stage ours; }

p16ae_parity() {
    local c m o cite="docs/mit-deviations.md:21"
    # ---- the client cells: the same words from MIT's kadmind and from ours (no principal prefix here: both stages use p16auser / p16anopol)
    for c in cpw-stock-reject cpw-stock-nopol kpasswd-stock-reject cpw-stock-ok cpw-nul-in cpw-nul-hidden cpw-nul-keep cpw-nul-shift cpw-latin-exact cpw-latin-fold kinit-octets \
             cpw-latin-iso-exact cpw-latin-iso-fold kf cpw-fifo-word; do
        parity_eq "P16AE.parity.$c" <(cell_body "$OUT/p16ae/mit-$c.txt") <(cell_body "$OUT/p16ae/ours-$c.txt")
    done
    # ---- the kadmind log lines of each cell: "password quality module X rejected password for P: text", the Request / chpw lines
    # (a successful cpw logs nothing: for those cells both files are empty and equal, which is the expectation)
    for c in cpw-stock-reject cpw-stock-nopol kpasswd-stock-reject cpw-stock-ok cpw-nul-in cpw-nul-shift cpw-latin-exact cpw-latin-fold cpw-latin-iso-fold cpw-fifo-word; do
        p16ae_logs "$OUT/p16ae/mit-$c.txt" > "$OUT/p16ae/mit-log-$c.txt"; p16ae_logs "$OUT/p16ae/ours-$c.txt" > "$OUT/p16ae/ours-log-$c.txt"
        if cmp -s "$OUT/p16ae/mit-log-$c.txt" "$OUT/p16ae/ours-log-$c.txt"; then verdict "P16AE.parity.$c.log" PASS "MIT's kadmind log lines = ours (prefix, pid and addresses masked)" equal equal "$(grep -c . "$OUT/p16ae/mit-log-$c.txt") lines"
        else verdict "P16AE.parity.$c.log" FAIL "MIT's kadmind log lines = ours (prefix, pid and addresses masked)" equal differ "mit-log-$c.txt against ours-log-$c.txt"; fi
    done
    # ---- the dictionary state lines of each switch (dict_file, the unit, the environment) and the FIFO cells' facts, without the pid
    for c in dict-stock dict-nul dict-latin dict-latin-iso fifo-enforcing fifo-permissive fifo-nowriter fifo-restore; do
        parity_eq "P16AE.parity.state-$c" <(grep -E '^(dict_file|active=|LANG=|LC_ALL=|enforce_before=|enforce_now=|setenforce|fifo_restart|restart_rc|state_after_timeout|fifo_writer_alive)' "$OUT/p16ae/mit-run-$c.txt") \
                                          <(grep -E '^(dict_file|active=|LANG=|LC_ALL=|enforce_before=|enforce_now=|setenforce|fifo_restart|restart_rc|state_after_timeout|fifo_writer_alive)' "$OUT/p16ae/ours-run-$c.txt")
    done
    # ---- the side databases: the same messages (stream-agnostic: the master-key prompts and the stream they sit on differ), the same exit status, the same principals and warnings; the file list differs by
    # the database files each implementation keeps (principal.kadm5 is MIT's, principal.lockout is ours: docs/mit-deviations.md:21)
    local -a smask=('s#/side-(mit|ours)/#/side-X/#g' '/^  (out|err): /{s/^  (out|err): /  msg: /}')
    for c in dir missing; do
        for m in mit ours; do
            grep -v -E '^  files: ' "$OUT/p16ae/$m-create-$c.txt" | b2_norm /dev/stdin "${smask[@]}" | LC_ALL=C sort -u > "$OUT/p16ae/$m-create-$c.norm"
        done
        parity_eq "P16AE.parity.create-$c" "$OUT/p16ae/mit-create-$c.norm" "$OUT/p16ae/ours-create-$c.norm"
        grep -h '^  files: ' "$OUT/p16ae/mit-create-$c.txt" | sed -E 's/ principal\.kadm5 / /' > "$OUT/p16ae/mit-files-$c.txt"
        grep -h '^  files: ' "$OUT/p16ae/ours-create-$c.txt" | sed -E 's/ principal\.lockout / /' > "$OUT/p16ae/ours-files-$c.txt"
        parity_eq "P16AE.parity.create-$c.files" "$OUT/p16ae/mit-files-$c.txt" "$OUT/p16ae/ours-files-$c.txt"
        parity_dev "P16AE.parity.create-$c.lockout-file" "$cite" "$OUT/p16ae/mit-create-$c.txt" '^  files: .*principal\.kadm5 ' "$OUT/p16ae/ours-create-$c.txt" '^  files: .* principal\.lockout '
    done
    info P16AE.parity.create-dir.error-stream "$OUT/p16ae/mit-create-dir.txt" '^  (out|err): kdb5_util: Is a directory' "(MIT's error line is not on either stream)"
    info P16AE.parity.create-dir.error-stream-ours "$OUT/p16ae/ours-create-dir.txt" '^  (out|err): kdb5_util: Is a directory' "(ours: the error line is not on either stream)"
    # ---- the controls: the comparison can fail, and the deviation row fails when MIT's cell is doctored to ours
    parity_control P16AE.parity.cpw-stock-reject <(cell_body "$OUT/p16ae/mit-cpw-stock-reject.txt") <(cell_body "$OUT/p16ae/ours-cpw-stock-reject.txt")
    parity_control P16AE.parity.kpasswd-stock-reject <(cell_body "$OUT/p16ae/mit-kpasswd-stock-reject.txt") <(cell_body "$OUT/p16ae/ours-kpasswd-stock-reject.txt")
    m="$OUT/p16ae/control-mit-create-dir.txt"; sed -E 's/principal\.kadm5 /principal.lockout /' "$OUT/p16ae/mit-create-dir.txt" > "$m"
    o=$(grep -cE '^  files: .*principal\.kadm5 ' "$m" || true)
    if [ "${o:-0}" = 0 ]; then verdict P16AE.parity.create-dir.lockout-file.control PASS "a doctored MIT cell (principal.kadm5 turned into principal.lockout) must not hold the row's MIT fact" 0 "$o"
    else verdict P16AE.parity.create-dir.lockout-file.control FAIL "a doctored MIT cell (principal.kadm5 turned into principal.lockout) must not hold the row's MIT fact" 0 "$o"; fi
    return 0
}

p16ae_clean() {   # the writer, the drop-in, SELinux and kdc.conf as found, the files gone (also what the shell's restore runs when the leg stops early)
    b2a_pw3 | cell "p16ae/clean" kdc "sudo bash $VMD/b2a/p16ae-kdc.sh ours clean" none > /dev/null 2>&1
    return 0
}
