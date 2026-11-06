# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/p6l.sh: B2 module P6l, klist / kvno / kadmin getprinc dates and labels in C, en_US.UTF-8 and de_DE.UTF-8 (b2-client; spec: spec/p6l.md).
# Record of the recorded leg (R). Landed f4d054d1 (tree a5f5f581); proof hold 2026-10-08 16:22:20-16:25:19Z, R/lab-r2/ (wrapper.txt, rcs.txt, langpack-{mit,rust}.txt, locale-a-*.txt,
# {mit,rust}/{C,en_US.UTF-8,de_DE.UTF-8}/ with kinit-mit, klist-{mit,rust}, klist-kt-{mit,rust}, kvno-{mit,rust}, getprinc-{mit,rust}, dates-*, locale, rcs, and .diff for de_DE).
# Gate coverage at the tip: none for dates or locale (`grep -rn 'LC_ALL\|LC_TIME\|de_DE\|setlocale' scripts docs/gates.md` is empty); Rust units only (crates/krb5-types/src/timestamp/{locale,strftime}.rs).
# Documented rows at the tip: docs/mit-deviations.md:76 (klist address numeric; the date column follows the process locale), :77 (translated labels: MIT's klist/kvno print gettext labels under de_DE, ours English; the date
# fields match), :78 (LC_TIME data: pure-rust-locales 0.8.2 against glibc 2.42; only C, en_US.UTF-8 and de_DE.UTF-8 are claimed).
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade) and locale, on client2 (alice's password on stdin for the one kinit; LC_ALL=<locale>, the VM's LANG stays en_US.UTF-8):
#   locale    `locale`                                                          LC_ALL and LC_TIME read the locale (R/lab-r2/mit/*/locale.txt)
#   kinit     MIT's kinit -c FILE:<cache> alice: rc 0 (the prompt is translated under de_DE: not judged)  (R/lab-r2/mit/C/rcs.txt kinit_mit_rc=0)
#   klist     MIT's and ours: klist -c <cache>: rc 0 0; the ticket row and the renew row carry the locale's dates: C `10/08/26 16:23:22`, en_US `10/08/2026 16:23:27`, de_DE `08.10.2026 16:23:30`
#   keytab    klist -k -t -e as the lab user (rc 1 1: not world-readable) and as root (rc 0 0), MIT's and ours: the timestamps in the same shapes   (rcs.txt klist_kt_*; the rows show enctypes, so -e: R/lab-r2/mit/C/klist-kt-mit.txt)
#   kvno      kvno -c <cache> host/client2.kerber.test, MIT's and ours: rc 0 0, `host/client2.kerber.test@REALM: kvno = N` (MIT de_DE: `KVNO = N`)
#   getprinc  on the kdc `kadmin.local -q 'getprinc alice'` (MIT's in the MIT stage, ours in the ours stage): the six date lines stay English UTC in every locale
# Parity rule of the leg: the date fields byte-equal MIT's in all three locales (klist rows, renew row, keytab rows, getprinc dates); the whole-file diff of de_DE differs ONLY in the translated labels
# (MIT `Ticketzwischenspeicher`, `Standard-Principal`, `erneuern bis`, `KVNO` against ours `Ticket cache`, `Default principal`, `renew until`, `kvno`: docs/mit-deviations.md:77).
# Differences from the recorded leg:
#   - ours stage = the installed ship KDC and ship tools ($VMD/ours/{klist,kvno}, /usr/sbin/kadmin.local from dist/install.sh), not rust-field-p12; the upgrade is otp/install-ours.sh;
#   - MIT's kadmin.local is gone after the upgrade (dnf remove krb5-server): MIT's getprinc runs in `p6l_mit` only, ours in `p6l_ours`; the two stages are compared by SHAPE (the six lines match the date form, in every locale)
#     and byte for byte on the fields the upgrade does not touch (Expiration date, Last password change, Password expiration date, Last failed authentication); `Last modified` moves with the upgrade's
#     `modprinc +requires_preauth` and `Last successful authentication` with the logins;
#   - glibc-langpack-de is installed LAST on client2: at the end of `p6l_ours`, the last module of the hold, so that no other module's cell runs on an upgraded glibc (the leg's langpack pulled glibc, glibc-common,
#     glibc-gconv-extra, glibc-langpack-en and glibc-minimal-langpack from 2.42-16 to -17: R/lab-r2/langpack-mit.txt). The de_DE cells therefore run once, in the ours stage, with MIT's and ours' tools side by side on the
#     same cache (the locale formatting is client-side: the KDC does not enter); C and en_US.UTF-8 run in both stages. The package versions before and after are INFO rows. If the Fedora mirror or dnf fails, or
#     `locale -a` has no de_DE afterwards, the de_DE cells are NOT-RUN with the reason, not FAIL;
#   - the date extraction accepts `[./]` separators (the leg's dates-klist-* for de_DE missed the ticket row, R/lab-r2/mit/de_DE.UTF-8/dates-klist-mit.txt:1); the whole klist block is compared, not an extract;
#   - the klist outputs of both programs are of the SAME cache, so the ticket dates are equal by construction and any difference is the program's formatting;
#   - ADDED after the B2 hold of 2026-10-13 (58 getprinc rows red: the kdc's work directory $VMD/b2c was root's, made by an earlier `sudo bash b2c-vm.sh pcap-start`, and the lab user's `b2c-vm.sh run` died in mktemp): a PRE-CELL CHECK
#     per stage on the two VMs the cells run on, `b2c-vm.sh workcheck` as the lab user (rows P6L.<stage>.workdir.client2 and .kdc: WORKDIR_OK, or FAIL with the owner, the mode and mktemp's reason). A VM that fails it
#     costs its cells (NOT-RUN rows with the reason), not a screenful of rc 1 rows; the helper now makes the directory the lab user's whichever call comes first (helpers/b2c-vm.sh mkwork). No expectation of a cell changed.
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

p6l_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${P6L_INIT_DONE:-}" ] && return 0
    P6L_INIT_DONE=1
    b2c_init
    P6L_SVC=host/client2.kerber.test
    P6L_D_C='[0-9]{2}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'
    P6L_D_en='[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}'
    P6L_D_de='[0-9]{2}\.[0-9]{2}\.[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}'
    P6L_GP_DATE='([A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC [0-9]{4}|\[never\])'
    P6L_MASK_DE=('s/^Ticketzwischenspeicher: /Ticket cache: /' 's/^Standard-Principal: /Default principal: /' 's/^([[:space:]]*)erneuern bis /\1renew until /' 's/: KVNO = /: kvno = /')
    P6L_H_KL_MIT='^== then: /usr/bin/klist -c '
    P6L_H_KL_OURS='^== then: .*/ours/klist -c '
    P6L_H_KT_MIT_LAB='^== then: /usr/bin/klist -k -t -e$'
    P6L_H_KT_OURS_LAB='^== then: .*/ours/klist -k -t -e$'
    P6L_H_KT_MIT_ROOT='^== then: sudo env LC_ALL=[^ ]+ /usr/bin/klist -k -t -e$'
    P6L_H_KT_OURS_ROOT='^== then: sudo env LC_ALL=[^ ]+ .*/ours/klist -k -t -e$'
    P6L_H_KV_MIT='^== then: /usr/bin/kvno '
    P6L_H_KV_OURS='^== then: .*/ours/kvno '
}

# the documented label mask (docs/mit-deviations.md:77): MIT's German labels to ours' English ones

p6l_prep() { p6l_init; b2c_prep_check; }
p6l_push() { p6l_init; b2c_push_vm kdc client2; }

p6l_tag() { case $1 in C) echo C ;; en_US.UTF-8) echo en ;; de_DE.UTF-8) echo de ;; esac; }
p6l_blk() { b2c_then "$1" "$2" | grep -v '^\[then-rc='; }                                  # p6l_blk FILE HEADER-RX: a then block without its rc line
p6l_rc() { b2c_then "$1" "$2" | sed -n 's/^\[then-rc=\([0-9]*\)\]$/\1/p' | head -n 1; }  # its exit status

# the headers of the then blocks (the commands are in p6l_cell)

# SOURCE RECORD: wrapper.txt (cells mit C / en_US.UTF-8 / de_DE.UTF-8 at 16:23:22-16:23:34, rust at 16:24:23-16:24:35), lab-r2/{mit,rust}/<locale>/{kinit-mit,klist-mit,klist-rust,klist-kt-mit,klist-kt-rust,kvno-mit,kvno-rust,locale,rcs}.txt, the .diff files of de_DE
p6l_cell() {   # p6l_cell STAGE LOCALE: one login and every tool, under LC_ALL=LOCALE, on client2
    local st=$1 loc=$2 tag cc n f l d dx lx h
    local CELL_TMO=400
    tag=$(p6l_tag "$loc")
    cc="$VMD/b2c/p6l-$st-$tag.cc"; n="p6l/$st-cell-$tag"; f="$OUT/$n.txt"; l="P6L.$st.$tag"
    alice_pw | b2c_login "$n" client2 mit p6l-base --cc "$cc" --env "LC_ALL=$loc" \
        --then "$(b2c_tool mit klist) -c FILE:$cc" \
        --then "$(b2c_tool ours klist) -c FILE:$cc" \
        --then "$(b2c_tool mit klist) -k -t -e" \
        --then "$(b2c_tool ours klist) -k -t -e" \
        --then "sudo env LC_ALL=$loc $(b2c_tool mit klist) -k -t -e" \
        --then "sudo env LC_ALL=$loc $(b2c_tool ours klist) -k -t -e" \
        --then "$(b2c_tool mit kvno) -c FILE:$cc $P6L_SVC" \
        --then "$(b2c_tool ours kvno) -c FILE:$cc $P6L_SVC" \
        --then "locale" \
        -- -c "FILE:$cc" alice
    expect "$l.kinit-rc" "$f" '^\[rc=0\]$'
    expect "$l.kinit-ccache" "$f" '^ccache written$'
    expect_part "$l.no-secret-marker" "$f" client '<REDACTED:' 0
    case $tag in C) lx='LC_ALL=C' ;; *) lx="LC_ALL=${loc//./\\.}" ;; esac
    expect_under "$l.locale-lc_all" "$f" '^== then: locale$' "^$lx\$"
    expect_under "$l.locale-lc_time" "$f" '^== then: locale$' "^LC_TIME=\"${loc//./\\.}\"\$"
    eval "d=\$P6L_D_$tag"
    # klist, MIT's and ours: rc 0, the ticket row and the renew row in the locale's date form
    for dx in KL_MIT KL_OURS; do
        eval "h=\$P6L_H_$dx"
        expect_under "$l.$dx-rc" "$f" "$h" '^\[then-rc=0\]$'
        expect_under "$l.$dx-ticket-row" "$f" "$h" "^$d  $d  krbtgt/$RRX@$RRX\$"
        expect_under "$l.$dx-renew-row" "$f" "$h" "^[[:space:]]+(renew until|erneuern bis) $d\$"
    done
    # keytab: the lab user cannot open it (rc 1), root can (rc 0); the rows carry the locale's date form
    for dx in KT_MIT_LAB KT_OURS_LAB; do eval "h=\$P6L_H_$dx"; expect_under "$l.$dx-rc" "$f" "$h" '^\[then-rc=1\]$'; done
    for dx in KT_MIT_ROOT KT_OURS_ROOT; do
        eval "h=\$P6L_H_$dx"
        expect_under "$l.$dx-rc" "$f" "$h" '^\[then-rc=0\]$'
        expect_under "$l.$dx-rows" "$f" "$h" "^ +[0-9]+ $d host/client2(\\.kerber\\.test)?@$RRX \\("
    done
    # kvno: rc 0, the line (MIT's label is translated under de_DE)
    for dx in KV_MIT KV_OURS; do
        eval "h=\$P6L_H_$dx"
        expect_under "$l.$dx-rc" "$f" "$h" '^\[then-rc=0\]$'
        expect_under "$l.$dx-line" "$f" "$h" "^${P6L_SVC//./\\.}@$RRX: (kvno|KVNO) = [0-9]+\$"
    done
    info "$l.keytab-lab-text-mit" "$f" '^klist: ' "(none)"
    info "$l.stderr-of-kinit" "$f" '^== stderr$'
}

# SOURCE RECORD: {mit,rust}/<locale>/getprinc-{mit,rust}.txt and dates-getprinc-*.txt (the six date lines stay English UTC in every locale; MIT's getprinc only in the MIT stage)
p6l_getprinc() {   # p6l_getprinc STAGE LOCALE: on the kdc, MIT's kadmin.local (MIT stage) or ours (ours stage)
    local st=$1 loc=$2 tag n f l
    tag=$(p6l_tag "$loc")
    n="p6l/$st-getprinc-$tag"; f="$OUT/$n.txt"; l="P6L.$st.getprinc-$tag"
    b2c_run "$n" kdc -- sudo env "LC_ALL=$loc" kadmin.local -q 'getprinc alice'
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.principal" "$f" "^Principal: alice@$RRX\$"
    expect "$l.expiration" "$f" "^Expiration date: $P6L_GP_DATE\$" 1
    expect "$l.password-change" "$f" "^Last password change: $P6L_GP_DATE\$" 1
    expect "$l.password-expiration" "$f" "^Password expiration date: $P6L_GP_DATE\$" 1
    expect "$l.last-modified" "$f" "^Last modified: $P6L_GP_DATE \\(.*\\)\$" 1
    expect "$l.last-success" "$f" "^Last successful authentication: $P6L_GP_DATE\$" 1
    expect "$l.last-failed" "$f" "^Last failed authentication: $P6L_GP_DATE\$" 1
}

p6l_getprinc_tz() {   # p6l_getprinc_tz STAGE: ADDED, observation only (INFO rows): the zone token of getprinc's dates under a non-UTC TZ. The lab VMs run in UTC, so the recorded leg could not see it; on the fake lab
    # ours prints the numeric offset (-05:00) where strftime's %Z gives the abbreviation (CDT), which MIT's kadmin does
    local st=$1 n f
    n="p6l/$st-getprinc-tz"; f="$OUT/$n.txt"
    b2c_run "$n" kdc -- sudo env "TZ=America/Chicago" kadmin.local -q 'getprinc alice'
    info "P6L.$st.getprinc-tz.last-password-change" "$f" '^Last password change: ' "(none)"
}
p6l_zone_token() { sed -n 's/^Last password change: [A-Za-z]* [A-Za-z]* [0-9]* [0-9:]* \([^ ]*\) [0-9]*$/\1/p' "$1" | head -n 1; }

# SOURCE RECORD: langpack-mit.txt and langpack-rust.txt (dnf install glibc-langpack-de pulled glibc 2.42-16 to -17 of five packages), locale-a-{mit,rust}.txt
p6l_langpack() {   # p6l_langpack: glibc-langpack-de on client2; the status is 0 when de_DE is there afterwards, 1 with the reason in B2C-visible rows (the caller records NOT-RUN)
    local f="$OUT/p6l/ours-langpack.txt" rc la
    local CELL_TMO=760
    b2c_run p6l/ours-glibc-before client2 -- rpm -q glibc glibc-common glibc-gconv-extra glibc-langpack-en glibc-minimal-langpack glibc-langpack-de
    b2c_run p6l/ours-langpack client2 --timeout 600 -- sudo dnf install -y glibc-langpack-de
    rc=$(cell_rc p6l/ours-langpack)
    b2c_run p6l/ours-glibc-after client2 -- rpm -q glibc glibc-common glibc-gconv-extra glibc-langpack-en glibc-minimal-langpack glibc-langpack-de
    b2c_run p6l/ours-locale-a client2 -- sh -c 'locale -a | grep -i "^de_DE"'
    la=$(grep -ci '^de_DE' "$OUT/p6l/ours-locale-a.txt")
    result P6L.ours.langpack.dnf-rc INFO "dnf install -y glibc-langpack-de (the mirror; may upgrade glibc)" - "${rc:-?}" "see ours-langpack.txt, ours-glibc-before.txt and ours-glibc-after.txt"
    info P6L.ours.langpack.glibc-before "$OUT/p6l/ours-glibc-before.txt" '^glibc-[0-9]' "(no glibc line)"
    info P6L.ours.langpack.glibc-after "$OUT/p6l/ours-glibc-after.txt" '^glibc-[0-9]' "(no glibc line)"
    info P6L.ours.langpack.output "$f" 'Complete|Nothing to do|Failed|Error|error'
    [ "${rc:-1}" = 0 ] && [ "${la:-0}" -ge 1 ]
}

p6l_dirs() {   # p6l_dirs STAGE: the pre-cell check on the two VMs the cells run on (b2c_work_ok: b2c-vm.sh workcheck as the lab user; rows P6L.STAGE.workdir.client2 and P6L.STAGE.workdir.kdc). The status is a mask of
    # what cannot be used: 1 = client2, 2 = the kdc (0 = both fine)
    local st=$1 m=0
    b2c_work_ok p6l "$st" client2 || m=$((m | 1))
    b2c_work_ok p6l "$st" kdc || m=$((m | 2))
    return "$m"
}

p6l_stage_common() {   # p6l_stage_common STAGE MASK: the C and en_US.UTF-8 cells (client2) and the three getprinc locales (kdc); what a failed pre-cell check left unusable is NOT-RUN, with the reason
    local st=$1 m=$2 loc
    if [ $((m & 1)) = 0 ]; then
        for loc in C en_US.UTF-8; do deadline; p6l_cell "$st" "$loc"; done
    else
        b2c_not_run "P6L.$st.cells" "client2's work directory cannot be used by the lab user (P6L.$st.workdir.client2): no klist / kvno / kinit cell ran"
    fi
    if [ $((m & 2)) = 0 ]; then
        for loc in C en_US.UTF-8 de_DE.UTF-8; do deadline; p6l_getprinc "$st" "$loc"; done
        p6l_getprinc_tz "$st"
    else
        b2c_not_run "P6L.$st.getprinc" "the kdc's work directory cannot be used by the lab user (P6L.$st.workdir.kdc): no getprinc cell ran"
    fi
}

p6l_mit() {
    p6l_init
    local m
    b2c_kdc_ready p6l mit || return 0
    p6l_dirs mit; m=$?
    if [ $((m & 1)) = 0 ]; then
        b2c_conf p6l client2 p6l-base || { b2c_not_run P6L.mit.conf "no conf copy on client2"; return 0; }
    fi
    p6l_stage_common mit "$m"
    return 0
}
p6l_ours() {
    p6l_init
    local m
    b2c_kdc_ready p6l ours || return 0
    p6l_dirs ours; m=$?
    if [ $((m & 1)) = 0 ]; then
        b2c_conf p6l client2 p6l-base || { b2c_not_run P6L.ours.conf "no conf copy on client2"; return 0; }
    fi
    p6l_stage_common ours "$m"
    # LAST on client2: the langpack (it may pull a glibc upgrade); the de_DE cells need it
    if [ $((m & 1)) != 0 ]; then
        b2c_not_run P6L.ours.de-DE.cells "client2's work directory cannot be used by the lab user (P6L.ours.workdir.client2): no langpack, no de_DE cell"
    elif p6l_langpack; then
        p6l_cell ours "de_DE.UTF-8"
    else
        b2c_not_run P6L.ours.de-DE.cells "glibc-langpack-de did not install (dnf rc $(cell_rc p6l/ours-langpack), de_DE locales afterwards: $(grep -ci '^de_DE' "$OUT/p6l/ours-locale-a.txt" 2> /dev/null)): see p6l/ours-langpack.txt"
    fi
    return 0
}

p6l_cmp() {   # p6l_cmp LABEL FILE HEADER-MIT HEADER-OURS [SED-EXPR...]: the two programs' blocks equal (the masks are named in the row)
    local label=$1 f=$2 hm=$3 ho=$4 d="$OUT/p6l/norm"
    shift 4
    mkdir -p "$d"
    p6l_blk "$f" "$hm" > "$d/$label.a.txt"; p6l_blk "$f" "$ho" > "$d/$label.b.txt"
    parity_eq "$label" "$d/$label.a.txt" "$d/$label.b.txt" "$@"
}

p6l_label_row() {   # p6l_label_row STAGE: the documented label deviation of de_DE.UTF-8 (docs/mit-deviations.md:77): MIT's klist and kvno print gettext labels, ours English ones
    local st=$1 f="$OUT/p6l/$1-cell-de.txt" l="P6L.parity.de.labels-$1" mk mv ok ov
    [ -s "$f" ] || return 0
    mk=$(p6l_blk "$f" "$P6L_H_KL_MIT" | grep -c -E '^(Ticketzwischenspeicher|Standard-Principal): ')
    mv=$(p6l_blk "$f" "$P6L_H_KV_MIT" | grep -c ': KVNO = ')
    ok=$(p6l_blk "$f" "$P6L_H_KL_OURS" | grep -c -E '^(Ticket cache|Default principal): ')
    ov=$(p6l_blk "$f" "$P6L_H_KV_OURS" | grep -c ': kvno = ')
    if [ "$mk" -ge 1 ] && [ "$mv" -ge 1 ] && [ "$ok" -ge 1 ] && [ "$ov" -ge 1 ]; then
        verdict "$l" PASS "documented deviation (docs/mit-deviations.md:77): MIT's klist/kvno print German labels, ours English" documented documented "MIT klist $mk, kvno $mv German label lines; ours English: klist $ok, kvno $ov"
    elif [ "$mk" = 0 ] && [ "$mv" = 0 ]; then
        result "$l" INFO "documented deviation (docs/mit-deviations.md:77)" - 1 "MIT printed English labels under de_DE.UTF-8 on this host (no German mit-krb5.mo catalogue here): the deviation cannot be shown; the label mask changes nothing"
    elif [ "$mk" -ge 1 ] && [ "$mv" -ge 1 ] && [ "$ok" = 0 ] && [ "$ov" = 0 ]; then
        result "$l" INFO "documented deviation (docs/mit-deviations.md:77)" - 1 "OBSOLETE: ours now prints German labels like MIT's"
    else
        verdict "$l" FAIL "documented deviation (docs/mit-deviations.md:77): MIT German, ours English" documented other "MIT klist $mk kvno $mv; ours klist $ok kvno $ov"
    fi
}

p6l_gp_fields() {   # p6l_gp_fields FILE: the four getprinc lines the upgrade does not touch
    grep -E '^(Expiration date|Last password change|Password expiration date|Last failed authentication): ' "$1"
}
p6l_gp_shape() {   # p6l_gp_shape FILE: the six date lines with the dates masked
    grep -E '^(Expiration date|Last password change|Password expiration date|Last modified|Last successful authentication|Last failed authentication): ' "$1" \
        | sed -E 's/[A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC [0-9]{4}/<DATE>/; s/ \(.*\)$/ (<who>)/'
}

p6l_parity() {
    p6l_init
    local st tag loc f d="$OUT/p6l/norm" mk ok
    mkdir -p "$d"
    for st in mit ours; do
        for tag in C en de; do
            f="$OUT/p6l/$st-cell-$tag.txt"
            [ "$st" = mit ] && [ "$tag" = de ] && continue   # by design: de_DE runs in the ours stage only (the langpack comes last on client2)
            [ -s "$f" ] || { b2c_not_run "P6L.parity.$tag-$st" "no $st-stage cell for this locale"; continue; }
            if [ "$tag" = de ]; then
                p6l_cmp "P6L.parity.$tag.klist-$st" "$f" "$P6L_H_KL_MIT" "$P6L_H_KL_OURS" "${P6L_MASK_DE[@]}"
                p6l_cmp "P6L.parity.$tag.keytab-$st" "$f" "$P6L_H_KT_MIT_ROOT" "$P6L_H_KT_OURS_ROOT" "${P6L_MASK_DE[@]}"
                p6l_cmp "P6L.parity.$tag.kvno-$st" "$f" "$P6L_H_KV_MIT" "$P6L_H_KV_OURS" "${P6L_MASK_DE[@]}"
                p6l_label_row "$st"
            else
                p6l_cmp "P6L.parity.$tag.klist-$st" "$f" "$P6L_H_KL_MIT" "$P6L_H_KL_OURS"
                p6l_cmp "P6L.parity.$tag.keytab-$st" "$f" "$P6L_H_KT_MIT_ROOT" "$P6L_H_KT_OURS_ROOT"
                p6l_cmp "P6L.parity.$tag.kvno-$st" "$f" "$P6L_H_KV_MIT" "$P6L_H_KV_OURS"
            fi
            # the lab user's refusal: the exit status is the leg's rule; the texts are recorded (the leg did not compare them)
            same "P6L.parity.$tag.keytab-lab-rc-$st" "$(p6l_rc "$f" "$P6L_H_KT_MIT_LAB")" "$(p6l_rc "$f" "$P6L_H_KT_OURS_LAB")" "klist -k -t as the lab user: MIT's exit status = ours (1)"
        done
    done
    # getprinc: the shapes of MIT's (MIT stage) and ours (ours stage) equal in every locale; the untouched fields byte for byte; the same lines in every locale of one stage
    for tag in C en de; do
        if [ -s "$OUT/p6l/mit-getprinc-$tag.txt" ] && [ -s "$OUT/p6l/ours-getprinc-$tag.txt" ]; then
            p6l_gp_shape "$OUT/p6l/mit-getprinc-$tag.txt" > "$d/gp-shape-mit-$tag.txt"; p6l_gp_shape "$OUT/p6l/ours-getprinc-$tag.txt" > "$d/gp-shape-ours-$tag.txt"
            parity_eq "P6L.parity.$tag.getprinc-shape" "$d/gp-shape-mit-$tag.txt" "$d/gp-shape-ours-$tag.txt"
            p6l_gp_fields "$OUT/p6l/mit-getprinc-$tag.txt" > "$d/gp-fields-mit-$tag.txt"; p6l_gp_fields "$OUT/p6l/ours-getprinc-$tag.txt" > "$d/gp-fields-ours-$tag.txt"
            parity_eq "P6L.parity.$tag.getprinc-untouched-fields" "$d/gp-fields-mit-$tag.txt" "$d/gp-fields-ours-$tag.txt"
        fi
    done
    for st in mit ours; do
        for tag in en de; do
            [ -s "$OUT/p6l/$st-getprinc-$tag.txt" ] || continue
            p6l_gp_shape "$OUT/p6l/$st-getprinc-C.txt" > "$d/gp-C-$st.txt"; p6l_gp_shape "$OUT/p6l/$st-getprinc-$tag.txt" > "$d/gp-$tag-$st.txt"
            parity_eq "P6L.parity.getprinc-locale-independent-$tag-$st" "$d/gp-C-$st.txt" "$d/gp-$tag-$st.txt"
        done
    done
    # ADDED, observation only: the zone token of getprinc under TZ=America/Chicago
    if [ -s "$OUT/p6l/mit-getprinc-tz.txt" ] && [ -s "$OUT/p6l/ours-getprinc-tz.txt" ]; then
        mk=$(p6l_zone_token "$OUT/p6l/mit-getprinc-tz.txt"); ok=$(p6l_zone_token "$OUT/p6l/ours-getprinc-tz.txt")
        if [ -n "$mk" ] && [ "$mk" = "$ok" ]; then result P6L.parity.getprinc-tz INFO "zone token of getprinc dates under TZ=America/Chicago, MIT = ours" - 1 "equal: [$mk]"
        else result P6L.parity.getprinc-tz INFO "zone token of getprinc dates under TZ=America/Chicago, MIT = ours" - 1 "DIFFER: MIT [$mk] ours [$ok] (observation, not judged: the lab VMs are UTC)"; fi
    fi
    # controls: a doctored klist copy differs; the de_DE comparison WITHOUT the label mask differs (the mask is needed); the en_US date form does not match the C locale's rows
    if [ -s "$d/P6L.parity.C.klist-ours.a.txt" ]; then
        parity_control "P6L.parity.C.klist-ours" "$d/P6L.parity.C.klist-ours.a.txt" "$d/P6L.parity.C.klist-ours.b.txt"
        if grep -qE "^$P6L_D_en  " "$d/P6L.parity.C.klist-ours.a.txt"; then verdict P6L.parity.control.en-shape-vs-C FAIL "the en_US date form must not match the C locale's ticket row" "no match" match ""
        else verdict P6L.parity.control.en-shape-vs-C PASS "the en_US date form must not match the C locale's ticket row" "no match" "no match" ""; fi
    fi
    if [ -s "$d/P6L.parity.de.klist-ours.a.txt" ]; then
        if grep -q -E '^(Ticketzwischenspeicher|Standard-Principal): ' "$d/P6L.parity.de.klist-ours.a.txt"; then
            if cmp -s "$d/P6L.parity.de.klist-ours.a.txt" "$d/P6L.parity.de.klist-ours.b.txt"; then
                verdict P6L.parity.control.de-without-label-mask FAIL "MIT's German klist and ours before the label mask must differ" differ same ""
            else
                verdict P6L.parity.control.de-without-label-mask PASS "MIT's German klist and ours before the label mask must differ" differ differ ""
            fi
        else
            result P6L.parity.control.de-without-label-mask INFO "MIT's German klist and ours before the label mask must differ" - 1 "MIT printed English labels on this host (no German catalogue): the control needs the lab"
        fi
    fi
    return 0
}

p6l_clean() { p6l_init; b2c_clean_vms; return 0; }
