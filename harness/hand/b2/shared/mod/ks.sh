# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/ks.sh: B2-style module KS, the VM leg of the KS series (the KDC log's `preauth (MODULE) verify failure: TEXT` line, MIT first) (lab-agent; cells: VM-LEG.md S1-S4, T1-T3, E1-E2).
# Not a package of the B2 survey: the head implementer asked for the cells of VM-LEG.md; it runs beside the B2 modules in one hold (B2_EXTRA=ks). Tree under test 7612269f (KS's three commits on KP's 140897fb).
# What the change is (VM-LEG.md): MIT's krb5kdc writes one LOG_INFO line for every preauth module whose verify fails, `preauth (NAME) verify failure: TEXT`, between the request's NEEDED_PREAUTH line and its
# PREAUTH_FAILED line (finish_verify_padata, kdc_preauth.c:1224-1228); TEXT is the module's message for its code (`Preauthentication failed` for a wrong password, `Clock skew too great`, `More preauthentication
# data is required` for SPAKE's first round, `Incorrect password in encrypted challenge`). Our KDC wrote none and put a Rust-made text into the AS_REQ line. Equality expected, cell for cell: the KDC log lines a
# cell adds (AS_REQ lines and verify-failure lines, with the pid, the client address and the authtime masked) are the same on MIT's KDC and on the ship KDC for the same client program, and MIT's kinit and ours say
# the same. A red on ours only is PRODUCT (E1's AS_REQ tail is the listed finding B11: MIT's `..., Incorrect password in encrypted challenge`, ours `..., Preauthentication failed`; the verify line is equal).
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43 and its kinit; ours = after docs/install.md's upgrade of the ship build and our kinit), on client2, as the lab user, a private cache per run, MIT's kinit and
# ours in each; ksuser has +requires_preauth, the right password is the leg's PW1, a wrong one PW3. Client profiles are copies of the VM's own krb5.conf with relations first under [libdefaults] (KRB5_CONFIG):
#   S1 wrong, KDC challenge      default profile                                      NEEDED_PREAUTH; spake verify failure `Preauthentication failed`; PREAUTH_FAILED `..., Preauthentication failed`
#   S2 right, KDC challenge      default profile                                      NEEDED_PREAUTH; ISSUE; no verify line
#   S3 wrong, support message    KDC without spake_preauth_kdc_challenge (below)      NEEDED_PREAUTH; spake `More preauthentication data is required` + PREAUTH_FAILED with it; spake `Preauthentication failed` + PREAUTH_FAILED
#   S4 right, support message    the same KDC                                         NEEDED_PREAUTH; the round-one pair; ISSUE; no second verify line
#   S3p wrong, P-256             spake_preauth_groups = P-256                         the literal recipe of VM-LEG's S3: the KDC's own challenge is edwards25519, which this client does not have; MIT's client sends a support
#                                                                                      message with P-256, the KDC has no common group: spake `Preauthentication failed`, then the client falls back to Enc-TS:
#                                                                                      encrypted_timestamp `Preauthentication failed` (fake-lab oracle 2026-10-13; VM-LEG predicted the round-one pair, which only a KDC without a challenge gives)
#   S4p right, P-256             the same profile                                     spake `Preauthentication failed` + PREAUTH_FAILED, then the Enc-TS fallback logs in: ISSUE
#   T1 Enc-TS wrong              preferred_preauth_types = 2                          NEEDED_PREAUTH; encrypted_timestamp `Preauthentication failed`; PREAUTH_FAILED `..., Preauthentication failed`
#   T2 Enc-TS right              the same                                             NEEDED_PREAUTH; ISSUE
#   T3a skew, timesync           the same, client2's clock ten minutes ahead          NEEDED_PREAUTH; ISSUE: the default `kdc_timesync = 1` takes the KDC's time from the first KRB-ERROR (fake-lab oracle: MIT and ours log in)
#   T3b skew, no timesync        + kdc_timesync = 0, the same clock, right password   NEEDED_PREAUTH; encrypted_timestamp `Clock skew too great`; PREAUTH_FAILED `..., Clock skew too great`; kinit: `Clock skew too great while getting initial credentials`
#   T3c skew, SPAKE (extra)      kdc_timesync = 0, default preauth, the same clock    NEEDED_PREAUTH; ISSUE; the client refuses the reply: MIT `Clock skew too great in KDC reply while getting initial credentials` (ours says `reply validation: ` first: product)
#   E1 EC wrong                  preferred_preauth_types = 138, kinit -T <ksarm ccache>   NEEDED_PREAUTH; encrypted_challenge `Incorrect password in encrypted challenge`; PREAUTH_FAILED `..., Incorrect password in encrypted challenge` (ours: B11)
#   E2 EC right                  the same                                             NEEDED_PREAUTH; ISSUE; no verify line
#   F1 FAST + SPAKE wrong (extra)  default profile, kinit -T <ksarm ccache>           with the default profile the armored flow uses SPAKE: NEEDED_PREAUTH; spake `Preauthentication failed`; PREAUTH_FAILED
#   F2 FAST + SPAKE right (extra)  the same                                           NEEDED_PREAUTH; ISSUE
# Controls that must fire (rows KS.control.*): S1, S3, S3p, T1, T3b, E1 and F1 show their verify line in MIT's stage; S2, S4, T2, T3a, E2, F2 end in ISSUE without `Preauthentication failed` in MIT's stage (S4p ends in ISSUE: its
# spake failure is the first move of the fallback); S1 and S2 slices differ; a doctored copy of a slice differs. S3's slice has the round-one pair once or twice (INFO: the retry, if there is one).
# Differences from VM-LEG.md (the oracle is the fake lab with MIT's own binaries, 2026-10-13; the VMs carry the same krb5 1.22.2-4.fc43):
#   - S3/S4: with the lab's KDC (spake_preauth_kdc_challenge = edwards25519 under [kdcdefaults]) a P-256 client gets no round-one pair; the pair appears when the KDC offers no challenge. The module takes the
#     challenge line out of kdc.conf for these two cells (helpers/ks-kdc.sh nochallenge: b2a-kdcconf.py defaults-del, krb5kdc restarted), puts the pristine file back and restarts again right after (challenge),
#     and keeps VM-LEG's literal P-256 recipe as S3p/S4p;
#   - T3: the clock set ten minutes ahead is not enough: a default client takes the KDC's time from the first reply (kdc_timesync = 1) and logs in (T3a). `Clock skew too great` needs kdc_timesync = 0 (T3b/T3c).
#     The clock is set with `date -s` by helpers/ks-vm.sh skew-on (the time-sync services stopped for the window) and put back by skew-off (true time = kept time + the uptime that passed), once per stage for all
#     of T3a-T3c; rows judge the drift (3 s at most) and the clock against the host's. When the VM refuses the change the T3 cells are NOT-RUN rows;
#   - E1/E2: preferred_preauth_types = 138 is needed to reach Encrypted Challenge (the default profile's armored flow is SPAKE: F1/F2); the armor ticket cache of ksarm is made by MIT's kinit once per stage;
#   - ADDED: T3c, F1, F2 (extras beyond VM-LEG's table); rows for the client's words, the exit status and the number of AS_REQ/verify lines in the slice, so a surprise line is seen;
#   - the module runs inside the B2 shell (L1 resets, the Fedora identity rule, install.md's upgrade by otp/install-ours.sh, the state rows, the restore); ours run as $VMD/ours/kinit.
# shellcheck source=/dev/null
. "$SCRIPTS/helpers/b2a-host.sh"
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

ks_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${KSM_INIT_DONE:-}" ] && return 0
    KSM_INIT_DONE=1
    b2c_init
    KSM_CLIENT=client2
    KSM_PRINCS='ksuser ksarm'
    KSM_CELLS_DEF='S1 S2 S3p S4p T1 T2 E1 E2 F1 F2'
    KSM_CELLS_SKEW='T3a T3b T3c'
    KSM_CELLS_NOCH='S3 S4'
    KSM_CELLS_ALL='S1 S2 S3 S4 S3p S4p T1 T2 T3a T3b T3c E1 E2 F1 F2'
    KSM_WRONG_CELLS='S1 S3 S3p T1 T3b E1 F1'
    KSM_RIGHT_CELLS='S2 S4 T2 T3a E2 F2'
    KSM_SKEW=600
}

ks_prep() {
    local f
    ks_init
    for f in ks-kdc.sh ks-vm.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "ks: helpers/$f is missing" >&2; return 1; }; done
    b2c_prep_check || return 1
    return 0
}

ks_push() {   # the kdc-side script, b2c-vm.sh and the clock helper on client2
    ks_init
    b2a_push_script ks-kdc.sh || return 1
    b2c_push_vm client2 || return 1
    push client2 "$SCRIPTS/helpers/ks-vm.sh" "$VMD/ks-vm.sh" 755 || return 1
    return 0
}

ks_def() {   # ks_def CELL: "CONF|ARMOR|PW|RC|CLIENT-TEXT|VERIFY|FAILED|ISSUE|LINES"
    # CONF: the profile (b2c_conf name); ARMOR 1: kinit -T; PW: 1 right, 3 wrong; RC: kinit's status; CLIENT-TEXT: the stderr line after `kinit: ` ("-": none); VERIFY: the verify-failure lines of the slice, in order, module:text, comma-joined;
    # FAILED: the tails of the PREAUTH_FAILED lines, in order; ISSUE: the number of ISSUE lines; LINES: the number of AS_REQ and verify-failure lines in the slice
    local pf='Password incorrect while getting initial credentials' pa='Preauthentication failed' more='More preauthentication data is required'
    case $1 in
        S1)  echo "ks-base|0|3|1|$pf|spake:$pa|$pa|0|3" ;;
        S2)  echo "ks-base|0|1|0|-|||1|2" ;;
        S3)  echo "ks-base|0|3|1|$pf|spake:$more,spake:$pa|$more,$pa|0|5" ;;
        S4)  echo "ks-base|0|1|0|-|spake:$more|$more|1|4" ;;
        S3p) echo "ks-p256|0|3|1|$pf|spake:$pa,encrypted_timestamp:$pa|$pa,$pa|0|5" ;;
        S4p) echo "ks-p256|0|1|0|-|spake:$pa|$pa|1|4" ;;
        T1)  echo "ks-ts|0|3|1|$pf|encrypted_timestamp:$pa|$pa|0|3" ;;
        T2)  echo "ks-ts|0|1|0|-|||1|2" ;;
        T3a) echo "ks-ts|0|1|0|-|||1|2" ;;
        T3b) echo "ks-ts0|0|1|1|Clock skew too great while getting initial credentials|encrypted_timestamp:Clock skew too great|Clock skew too great|0|3" ;;
        T3c) echo "ks-sp0|0|1|1|Clock skew too great in KDC reply while getting initial credentials|||1|2" ;;
        E1)  echo "ks-ec|1|3|1|$pf|encrypted_challenge:Incorrect password in encrypted challenge|Incorrect password in encrypted challenge|0|3" ;;
        E2)  echo "ks-ec|1|1|0|-|||1|2" ;;
        F1)  echo "ks-base|1|3|1|$pf|spake:$pa|$pa|0|3" ;;
        F2)  echo "ks-base|1|1|0|-|||1|2" ;;
        *)   return 1 ;;
    esac
}

ks_vmx() {   # ks_vmx NAME SUB [ARG]: ks-vm.sh SUB on client2 as root; the transcript is $OUT/ks/NAME.txt
    local name=$1 sub=$2 arg=${3:-}
    cell "ks/$name" "$KSM_CLIENT" "sudo bash $VMD/ks-vm.sh $sub $arg; echo \"[rc=\$?]\"" none < /dev/null
}

ks_slice_file() {   # ks_slice_file STAGE CELL TOOL: from the cell's transcript, $OUT/ks/STAGE-CELL-TOOL.slice := the KDC lines of the cell that are requests or verify failures (AS_REQ, `verify failure`), without the syslog prefix,
    # the pid, the client address and the authtime; .verify := the verify-failure lines as module:text
    local b="$OUT/ks/$1-$2-$3"
    sed -n '/^# KDC log lines added/,/^# kadmind log lines/p' "$b.txt" 2> /dev/null | grep -E 'AS_REQ|verify failure' \
        | sed -E 's/^[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/; s/(\) )[^ ]+(: [A-Z_]+: )/\1ADDR\2/; s/authtime [0-9]+/authtime N/' > "$b.slice"
    { echo "# the verify-failure lines of the cell's KDC slice, module:text (the header keeps the file non-empty for a cell with none)"
      sed -n 's/^krb5kdc\[pid\](info): preauth (\([a-z_0-9]*\)) verify failure: /\1:/p' "$b.slice"; } > "$b.verify"
    return 0
}
ks_verify_of() { grep -v '^#' "$1.verify" 2> /dev/null | paste -sd, -; }   # ks_verify_of STAGE-CELL-TOOL-BASE: the verify lines, comma-joined
ks_failed_of() { sed -n 's/^.*: PREAUTH_FAILED: [^ ]* for [^ ]*, //p' "$1.slice" 2> /dev/null | paste -sd, -; }

ks_rows() {   # ks_rows STAGE CELL TOOL: the rows of one run
    local st=$1 cell=$2 t=$3 conf armor pw rc client verify failed issue lines L f b et ad pr tg
    local -a df
    mapfile -d '|' -t df < <(printf '%s' "$(ks_def "$cell")")
    conf=${df[0]} armor=${df[1]} pw=${df[2]} rc=${df[3]} client=${df[4]} verify=${df[5]} failed=${df[6]} issue=${df[7]} lines=${df[8]}
    L="KS.$st.$cell-$t"; f="$OUT/ks/$st-$cell-$t.txt"; b="$OUT/ks/$st-$cell-$t"
    et='\([0-9]+ etypes \{[^}]*\}\)'; ad=ADDR; pr="ksuser@$RRX"; tg="krbtgt/$RRX@$RRX"
    expect "$L.rc" "$f" "^\\[rc=$rc\\]\$"
    expect "$L.prompt" "$f" '^PROMPT=yes$'
    if [ "$client" = - ]; then
        expect_under "$L.stderr-empty" "$f" '^== stderr$' '.' 0
    else
        expect_under "$L.stderr-line" "$f" '^== stderr$' "^([^ :]*/)?(krb5-)?kinit: ${client}\$" 1
        expect_under "$L.stderr-one-line" "$f" '^== stderr$' '.' 1
    fi
    expect_part "$L.no-secret-marker" "$f" client '<REDACTED:' 0
    expect "$L.log-needed-preauth" "$b.slice" "AS_REQ $et $ad: NEEDED_PREAUTH: $pr for $tg, Additional pre-authentication required\$" 1
    same "$L.log-verify" "$verify" "$(ks_verify_of "$b")" "the verify-failure lines of the cell's KDC slice, in order (module:text)"
    same "$L.log-failed" "$failed" "$(ks_failed_of "$b")" "the tails of the PREAUTH_FAILED lines of the slice, in order"
    expect "$L.log-issue" "$b.slice" "AS_REQ $et $ad: ISSUE: authtime N, etypes \\{rep=[^}]*\\}, $pr for $tg\$" "$issue"
    same "$L.log-lines" "$lines" "$(grep -c . "$b.slice" 2> /dev/null || true)" "AS_REQ and verify-failure lines in the cell's KDC slice"
    return 0
}

ks_run() {   # ks_run STAGE CELL TOOL: one login on client2 under the cell's profile (stdin: the password line), then its rows
    local st=$1 cell=$2 t=$3 conf armor pw rc client verify failed issue lines cc ac
    local -a df
    ks_init
    mapfile -d '|' -t df < <(printf '%s' "$(ks_def "$cell")")
    conf=${df[0]} armor=${df[1]} pw=${df[2]} rc=${df[3]} client=${df[4]} verify=${df[5]} failed=${df[6]} issue=${df[7]} lines=${df[8]}
    cc="$VMD/b2c/ks-$st-$cell-$t.cc"; ac="$VMD/b2c/ks-$st-armor.cc"
    local -a ka=(ksuser)
    [ "$armor" = 1 ] && ka=(-T "FILE:$ac" ksuser)
    deadline
    b2_pw "$pw" | b2c_login "ks/$st-$cell-$t" "$KSM_CLIENT" "$t" "$conf" --cc "$cc" --env "KRB5CCNAME=FILE:$cc" -- "${ka[@]}"
    ks_slice_file "$st" "$cell" "$t"
    ks_rows "$st" "$cell" "$t"
    return 0
}

ks_armor() {   # ks_armor STAGE: the armor ticket cache of ksarm, made by MIT's kinit (the default profile)
    local st=$1 ac="$VMD/b2c/ks-$1-armor.cc" f="$OUT/ks/$1-armor.txt"
    b2_pw 1 | b2c_login "ks/$st-armor" "$KSM_CLIENT" mit ks-base --cc "$ac" --env "KRB5CCNAME=FILE:$ac" -- ksarm
    expect "KS.$st.armor.rc" "$f" '^\[rc=0\]$'
    expect "KS.$st.armor.ccache" "$f" '^ccache written$'
    expect_part "KS.$st.armor.no-secret-marker" "$f" client '<REDACTED:' 0
}

ks_clock_row() {   # ks_clock_row STAGE: client2's clock against the host's, read now (the host's clock is the true one): within 5 s
    local st=$1 h0 c h1 res
    h0=$(date +%s); c=$(vm "$KSM_CLIENT" 'date +%s' 2>> "$LOG" < /dev/null | tr -d '[:space:]'); h1=$(date +%s)
    if [ -n "$c" ] && [ "$c" -ge $((h0 - 5)) ] && [ "$c" -le $((h1 + 5)) ]; then res=PASS; else res=FAIL; fi
    verdict "KS.$st.skew.clock-back" "$res" "client2's clock equals the host's (within 5 s) after the skew window" "$h0..$h1 (+-5 s)" "${c:-none}"
}

ks_skew_group() {   # ks_skew_group STAGE: T3a-T3c inside one skew window (ks-vm.sh skew-on ... skew-off)
    local st=$1 L=KS.$1.skew cell t f="$OUT/ks/$1-skew-on.txt"
    ks_vmx "$st-skew-on" skew-on "$KSM_SKEW"
    if grep -q '^SKEW_ON ' "$f"; then
        expect "$L.on" "$f" "^SKEW_ON offset=$KSM_SKEW now=[0-9]+ ahead=(59[0-9]|60[0-9])\$"
        for cell in $KSM_CELLS_SKEW; do for t in mit ours; do ks_run "$st" "$cell" "$t"; done; done
        ks_vmx "$st-skew-off" skew-off
        expect "$L.off" "$OUT/ks/$st-skew-off.txt" '^SKEW_OFF expected=[0-9]+ now=[0-9]+ drift=-?[0-3] '
        expect "$L.off-rc" "$OUT/ks/$st-skew-off.txt" '^\[rc=0\]$'
        ks_clock_row "$st"
    else
        b2c_not_run "$L" "the clock of client2 could not be set ahead ($(grep -m1 -E '^SKEW_|date|Operation' "$f" 2> /dev/null | cut -c1-120)): the T3 cells did not run"
        ks_vmx "$st-skew-off" skew-off
    fi
}

ks_noch_group() {   # ks_noch_group STAGE: S3 and S4 against a KDC without spake_preauth_kdc_challenge, then the KDC as found
    local st=$1 L=KS.$1.nochallenge cell t f="$OUT/ks/$1-run-nochallenge.txt" g="$OUT/ks/$1-run-challenge.txt"
    b2a_pw3 | b2a_run_kdc "ks/$st-run-nochallenge" ks-kdc.sh "$st" nochallenge
    expect "$L.restart-rc" "$f" '^RESTART_RC:0$'
    expect "$L.kdc-active" "$f" '^KDC:active$'
    expect "$L.kdc-listening" "$f" '^KDC_LISTENING$'
    expect "$L.challenge-absent" "$f" '^CHALLENGE_LINES:0$'
    expect_part "$L.kdc-commencing-operation" "$f" kdc 'krb5kdc\[[0-9]+\]\(info\): commencing operation$' 1
    if grep -q '^KDC_LISTENING$' "$f" 2> /dev/null && grep -q '^CHALLENGE_LINES:0$' "$f" 2> /dev/null; then
        for cell in $KSM_CELLS_NOCH; do for t in mit ours; do ks_run "$st" "$cell" "$t"; done; done
    else
        b2c_not_run "$L.cells" "the KDC did not come back without its SPAKE challenge: S3 and S4 did not run"
    fi
    b2a_pw3 | b2a_run_kdc "ks/$st-run-challenge" ks-kdc.sh "$st" challenge
    expect "$L.back.restart-rc" "$g" '^RESTART_RC:0$'
    expect "$L.back.kdc-active" "$g" '^KDC:active$'
    expect "$L.back.kdc-listening" "$g" '^KDC_LISTENING$'
    expect "$L.back.challenge-present" "$g" '^CHALLENGE_LINES:1$'
}

ks_stage() {   # ks_stage mit|ours
    local st=$1 L=KS.$1 cell t n run
    ks_init
    b2c_kdc_ready ks "$st" || return 0
    b2c_work_ok ks "$st" "$KSM_CLIENT" || { b2c_not_run "$L.cells" "client2's work directory cannot be used by the lab user (see $L.workdir.$KSM_CLIENT): no cell ran"; return 0; }
    b2c_conf ks "$KSM_CLIENT" ks-base || { b2c_not_run "$L.conf" "no conf copy on client2"; return 0; }
    b2c_conf ks "$KSM_CLIENT" ks-p256 --libdefaults-first 'spake_preauth_groups = P-256' || { b2c_not_run "$L.conf" "no P-256 conf on client2"; return 0; }
    b2c_conf ks "$KSM_CLIENT" ks-ts --libdefaults-first 'preferred_preauth_types = 2' || { b2c_not_run "$L.conf" "no Enc-TS conf on client2"; return 0; }
    b2c_conf ks "$KSM_CLIENT" ks-ts0 --libdefaults-first 'kdc_timesync = 0' --libdefaults-first 'preferred_preauth_types = 2' || { b2c_not_run "$L.conf" "no Enc-TS no-timesync conf on client2"; return 0; }
    b2c_conf ks "$KSM_CLIENT" ks-sp0 --libdefaults-first 'kdc_timesync = 0' || { b2c_not_run "$L.conf" "no no-timesync conf on client2"; return 0; }
    b2c_conf ks "$KSM_CLIENT" ks-ec --libdefaults-first 'preferred_preauth_types = 138' || { b2c_not_run "$L.conf" "no Encrypted Challenge conf on client2"; return 0; }
    # setup on the kdc: the two principals
    b2a_pw3 | b2a_run_kdc "ks/$st-run-setup" ks-kdc.sh "$st" setup
    b2a_split "$OUT/ks/$st-run-setup.txt" "$OUT/ks" "$st"
    run="$OUT/ks/$st-run-setup.txt"
    expect "$L.setup.challenge-as-found" "$run" '^CHALLENGE_LINES:1$'
    for n in $KSM_PRINCS; do expect "$L.setup.$n-created" "$OUT/ks/$st-add-$n.txt" "^Principal \"$n@$RRX\" created\\.\$"; done
    expect "$L.setup.ksuser-requires-preauth" "$OUT/ks/$st-getprinc-ksuser.txt" '^Attributes:.*REQUIRES_PRE_AUTH'
    ks_armor "$st"
    # the KDC as found: S1 S2 S3p S4p T1 T2 E1 E2 F1 F2
    for cell in $KSM_CELLS_DEF; do for t in mit ours; do ks_run "$st" "$cell" "$t"; done; done
    # the clock window: T3a T3b T3c
    ks_skew_group "$st"
    # the KDC without its SPAKE challenge: S3 S4
    ks_noch_group "$st"
    # undo
    b2a_pw3 | b2a_run_kdc "ks/$st-run-cleanup" ks-kdc.sh "$st" cleanup
    b2a_split "$OUT/ks/$st-run-cleanup.txt" "$OUT/ks" "$st"
    for n in $KSM_PRINCS; do expect "$L.cleanup.$n-deleted" "$OUT/ks/$st-del-$n.txt" "^Principal \"$n@$RRX\" deleted\\.\$"; done
    expect "$L.cleanup.ksuser-gone" "$OUT/ks/$st-getprinc-gone.txt" '^get_principal: Principal does not exist while retrieving "ksuser@'"$RRX"'"\.$'
    expect "$L.cleanup.conf-pristine" "$OUT/ks/$st-run-cleanup.txt" '^CONF_PRISTINE:yes$'
    return 0
}

ks_mit() { ks_init; ks_stage mit; }
ks_ours() { ks_init; ks_stage ours; }

ks_parity() {
    local cell st t d="$OUT/ks" n
    ks_init
    for cell in $KSM_CELLS_ALL; do
        if [ ! -f "$d/mit-$cell-mit.txt" ] || [ ! -f "$d/ours-$cell-mit.txt" ]; then b2c_not_run "KS.parity.$cell" "cell $cell did not run in both stages"; continue; fi
        for t in mit ours; do   # the KDC changes, the program does not: the cell's KDC log slice, then just its verify-failure lines
            parity_eq "KS.parity.$cell-xkdc-$t.kdc-slice" "$d/mit-$cell-$t.slice" "$d/ours-$cell-$t.slice"
            parity_eq "KS.parity.$cell-xkdc-$t.kdc-verify" "$d/mit-$cell-$t.verify" "$d/ours-$cell-$t.verify"
        done
        for st in mit ours; do   # the programs differ, the KDC does not: MIT's kinit against ours (rc, the words, the protocol events)
            b2c_cmp "KS.parity.$cell-prog-$st" "$d/$st-$cell-mit.txt" "$d/$st-$cell-ours.txt"
        done
    done
    # controls: the cells that must fire
    for cell in $KSM_WRONG_CELLS; do
        [ -f "$d/mit-$cell-mit.txt" ] || { b2c_not_run "KS.control.$cell" "cell $cell did not run in the MIT stage"; continue; }
        n=$(grep -v '^#' "$d/mit-$cell-mit.verify" 2> /dev/null | grep -c . || true)
        verdict "KS.control.$cell-mit-slice-has-verify-line" "$([ "${n:-0}" -ge 1 ] && echo PASS || echo FAIL)" "MIT's own KDC slice of a wrong-password cell has a verify-failure line (a cell whose MIT slice lacks it tests nothing)" ">=1" "${n:-0}"
    done
    for cell in $KSM_RIGHT_CELLS S4p; do
        [ -f "$d/mit-$cell-mit.txt" ] || { b2c_not_run "KS.control.$cell" "cell $cell did not run in the MIT stage"; continue; }
        n=$(grep -c ': ISSUE: ' "$d/mit-$cell-mit.slice" 2> /dev/null || true)
        verdict "KS.control.$cell-mit-slice-ends-in-issue" "$([ "$(tail -n 1 "$d/mit-$cell-mit.slice" 2> /dev/null | grep -c ': ISSUE: ' || true)" = 1 ] && echo PASS || echo FAIL)" "MIT's own KDC slice of a right-password cell ends in ISSUE" "last line ISSUE" "$n ISSUE line(s)"
    done
    for cell in $KSM_RIGHT_CELLS; do
        [ -f "$d/mit-$cell-mit.txt" ] || continue
        n=$(grep -c 'Preauthentication failed' "$d/mit-$cell-mit.slice" 2> /dev/null || true)
        verdict "KS.control.$cell-mit-slice-no-preauth-failed" "$([ "${n:-0}" = 0 ] && echo PASS || echo FAIL)" "MIT's own KDC slice of a right-password cell has no 'Preauthentication failed'" 0 "${n:-0}"
    done
    n=$(grep -c 'verify failure: More preauthentication data is required' "$d/mit-S3-mit.slice" 2> /dev/null || true)
    result KS.control.S3-round-one-pair INFO "round-one verify-failure lines in MIT's S3 slice (1: the client answered the challenge once; more: it retried)" - "${n:-0}" "MIT's kinit; the ship KDC with the same client: $(grep -c 'verify failure: More preauthentication data is required' "$d/ours-S3-mit.slice" 2> /dev/null || true)"
    if [ -s "$d/mit-S1-mit.slice" ] && ! cmp -s "$d/mit-S1-mit.slice" "$d/mit-S2-mit.slice"; then verdict KS.parity.control.S1-vs-S2 PASS "two different cells must differ" differ differ ""
    else verdict KS.parity.control.S1-vs-S2 FAIL "two different cells must differ" differ same ""; fi
    parity_control KS.parity.S1-xkdc-mit.kdc-slice "$d/mit-S1-mit.slice" "$d/ours-S1-mit.slice"
    parity_control KS.parity.T1-xkdc-mit.kdc-verify "$d/mit-T1-mit.verify" "$d/ours-T1-mit.verify"
    b2c_cmp_control "KS.parity.S1-prog-mit"
    return 0
}

ks_clean() {   # the clock, kdc.conf and the caches: once more, quietly (the reset undoes them in any case)
    ks_init
    vm "$KSM_CLIENT" "sudo bash $VMD/ks-vm.sh skew-off" > /dev/null 2>&1 < /dev/null
    vm kdc "sudo env VMCTL_D=$VMD python3 -I $VMD/b2a/b2a-kdcconf.py" > /dev/null 2>&1 < /dev/null
    b2c_clean_vms
    return 0
}
