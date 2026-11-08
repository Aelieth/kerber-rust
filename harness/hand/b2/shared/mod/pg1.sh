# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/pg1.sh: B2 module PG1, the `[plugins] hostrealm` stanza in krb5.conf and kdc.conf (b2-client; spec: spec/pg1.md).
# Record of the recorded leg (R). Landed b8263bc1; hold 2026-10-07 22:39:24-22:41:38Z (R/lab/driver.log). Gate coverage at the tip: none.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade) x client (client1, client2) x program (MIT's kinit/klist/kvno, ours):
#   ok         stanza hostrealm = { disable = dns, enable_only = profile } on the kdc (kdc.conf and /etc/krb5.conf) and on the client: `kinit alice` (unqualified), `klist`, `kvno krbtgt/REALM`: rc 0 0 0
#              (R/lab/driver.log:17-26 and :86-94; R/lab/mit.out; R/lab/rust.out; R/lab/reader-view.txt:1-11)
#   noprofile  client-only observation conf with hostrealm = { disable = profile }: MIT's kinit/klist/kvno exit 1 1 1 ("Configuration file does not specify default realm when parsing name alice"),
#              ours 0 0 0: the LAXER row docs/mit-deviations.md:75 (R/lab/driver.log:27-35; R/lab/mit-noprofile.out:1-3; R/lab/rust-noprofile.out; R/lab/reader-view.txt:13-22)
# Differences from the recorded leg (all deliberate, none changes what a cell shows):
#   - the upgrade is otp/install-ours.sh (docs/install.md "Upgrading an MIT realm" + dist/install.sh) in the shell's L4, not the leg's direct script call; the stanza is cleared before it and put back after
#     (the leg let kdc.conf ride through .rpmsave), so the state rows (config as found) hold after each stage;
#   - the client stanza lives in a per-cell copy of the VM's own /etc/krb5.conf (KRB5_CONFIG=$VMD/b2c/pg1-*.conf); /etc/krb5.conf of a client is never edited. The kdc's /etc/krb5.conf and kdc.conf get the stanza
#     (the leg's "stanza on mit kdc and client2") and are put back byte for byte at the end of each stage;
#   - both client VMs run the cells (the leg ran client2 only); alice's password comes on stdin (alice_pw); ours run as $VMD/ours/{kinit,klist,kvno}, so error lines say "kinit:" for both programs;
#   - parity is by the cores of b2c_core (rc, prompt, stdout shape, stderr, the preauth trace events, the klist and kvno output with dates masked), MIT's against ours within a stage and across the stages.
# Not built: the leg's optional host-side re-run of the 14-case MIT hostrealm oracle (R/oracle/pg1-hostrealm.c); the Rust side of those cases is a unit test, not a binary.
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

pg1_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${PG1_INIT_DONE:-}" ] && return 0
    PG1_INIT_DONE=1
    b2c_init
}

pg1_stanza_ok() { printf '# pg1-hostrealm\n[plugins]\n    hostrealm = {\n        disable = dns\n        enable_only = profile\n    }\n# pg1-hostrealm-end\n'; }
pg1_stanza_np() { printf '# pg1-noprofile\n[plugins]\n    hostrealm = {\n        disable = profile\n    }\n# pg1-noprofile-end\n'; }
pg1_stanza_none() { :; }

pg1_prep() { pg1_init; b2c_prep_check; }
pg1_push() { pg1_init; b2c_push_vm kdc client1 client2; }

# SOURCE RECORD: driver.log:9-14 (the stanza on the kdc, krb5kdc restarted, active) and :84-85 (the stanza after the install)
pg1_kdc() {   # pg1_kdc STAGE on|off: the stanza in kdc.conf (set_conf) and in the kdc's /etc/krb5.conf, krb5kdc restarted, active
    local st=$1 how=$2 fn=pg1_stanza_none
    if [ "$how" = on ]; then
        fn=pg1_stanza_ok
        set_conf "pg1/$st-kdcconf-on" "$fn"
        pg1_stanza_ok | cell "pg1/$st-krb5conf-on" kdc "sudo bash $VMD/b2c-vm.sh krb5conf-set pg1; echo \"[rc=\$?]\"" none
    else
        set_conf "pg1/$st-kdcconf-off" "$fn"
        cell "pg1/$st-krb5conf-off" kdc "sudo bash $VMD/b2c-vm.sh krb5conf-restore pg1; echo \"[rc=\$?]\"" none < /dev/null
    fi
    restart_cell "pg1/$st-kdc-restart-$how" "sudo bash $VMD/vmctl.sh svc-restart"
    expect "PG1.$st.kdc-$how.krb5conf-rc" "$OUT/pg1/$st-krb5conf-$how.txt" '^\[rc=0\]$'
    expect "PG1.$st.kdc-$how.restart-active" "$OUT/pg1/$st-kdc-restart-$how.txt" '^krb5kdc\.service: active$'
    expect "PG1.$st.kdc-$how.operating" "$OUT/pg1/$st-kdc-restart-$how.txt" 'commencing operation'
    if [ "$how" = on ]; then
        expect "PG1.$st.kdc-on.kdcconf-has-stanza" "$OUT/pg1/$st-kdcconf-on.txt" '^\+ +enable_only = profile$'
        expect "PG1.$st.kdc-on.krb5conf-has-stanza" "$OUT/pg1/$st-krb5conf-on.txt" '^\+ +enable_only = profile$'
    else
        expect "PG1.$st.kdc-off.krb5conf-restored" "$OUT/pg1/$st-krb5conf-off.txt" '^krb5\.conf put back from pg1: kept sha256 ([0-9a-f]{64}), file sha256 \1$'
    fi
}

# SOURCE RECORD: driver.log:17-26 and :86-94 (cell ok: kinit, klist, kvno rc 0 0 0), :27-35 (cell noprofile: MIT 1 1 1, ours 0 0 0); lab/mit.out:1-8; lab/rust.out:1-8; lab/mit-noprofile.out:1-3; lab/reader-view.txt:1-22
pg1_cell() {   # pg1_cell CLIENT PROG STAGE ok|np: one login, klist and kvno
    local c=$1 p=$2 st=$3 which=$4 cn cc l f
    case $which in ok) cn=ok ;; np) cn=noprofile ;; esac
    cc="$VMD/b2c/pg1-$st-$cn-$p.cc"
    f="$OUT/pg1/$st-$cn-$p-$c.txt"; l="PG1.$st.$cn-$p-$c"
    alice_pw | b2c_login "pg1/$st-$cn-$p-$c" "$c" "$p" "pg1-$which" --cc "$cc" \
        --then "$(b2c_tool "$p" klist) -c FILE:$cc" \
        --then "$(b2c_tool "$p" kvno) -c FILE:$cc krbtgt/$REALM@$REALM" \
        -- -c "FILE:$cc" alice
    if [ "$which" = ok ]; then
        b2c_chk_login "$l" "$f" "$p"
        expect_under "$l.klist-rc" "$f" '^== then: .*klist' '^\[then-rc=0\]$'
        expect_under "$l.klist-principal" "$f" '^== then: .*klist' "^Default principal: alice@$RRX\$"
        expect_under "$l.klist-ticket" "$f" '^== then: .*klist' "krbtgt/$RRX@$RRX\$"
        expect_under "$l.kvno-rc" "$f" '^== then: .*kvno' '^\[then-rc=0\]$'
        expect_under "$l.kvno-line" "$f" '^== then: .*kvno' "^krbtgt/$RRX@$RRX: kvno = [0-9]+\$"
        info "$l.hint-list" "$f" 'Processing preauth types:'
    else
        # the absolute rows of the observation: MIT's tools refuse, ours go on (the documented LAXER row; the verdict is in pg1_parity)
        if [ "$p" = mit ]; then
            expect "$l.kinit-rc" "$f" '^\[rc=1\]$'
            expect_under "$l.kinit-says" "$f" '^== stderr$' '^kinit: Configuration file does not specify default realm when parsing name alice$' 1
            expect "$l.no-prompt" "$f" '^PROMPT=no$'
            expect "$l.no-ccache" "$f" '^no ccache was written$'
            expect_under "$l.klist-rc" "$f" '^== then: .*klist' '^\[then-rc=1\]$'
            expect_under "$l.klist-says" "$f" '^== then: .*klist' '^klist: No credentials cache found \(filename: .*\)$'
            expect_under "$l.kvno-rc" "$f" '^== then: .*kvno' '^\[then-rc=1\]$'
            expect_under "$l.kvno-says" "$f" '^== then: .*kvno' '^kvno: No credentials cache found \(filename: .*\) while getting client principal name$'
        else
            # ours: what it does is observed here and judged in pg1_parity (documented LAXER row, or obsolete when it refuses like MIT); only the hygiene rows are absolute
            b2c_hyg "$l" "$f" ours
            result "$l.rcs" INFO "kinit/klist/kvno exit status (the documented row is judged in the parity hook)" - 1 "$(pg1_rcs "$f")"
        fi
    fi
}

pg1_stage() {   # pg1_stage mit|ours
    local st=$1 c
    b2c_kdc_ready pg1 "$st" || return 0
    for c in "${CLIENTS[@]}"; do
        b2c_conf pg1 "$c" pg1-ok --append-text "$(pg1_stanza_ok)" || { b2c_not_run "PG1.$st.conf-$c" "no conf variant on $c"; return 0; }
        b2c_conf pg1 "$c" pg1-np --append-text "$(pg1_stanza_np)" || { b2c_not_run "PG1.$st.conf-np-$c" "no conf variant on $c"; return 0; }
    done
    pg1_kdc "$st" on
    b2c_each_cp pg1_cell "$st" ok
    b2c_each_cp pg1_cell "$st" np
    pg1_kdc "$st" off
    return 0
}
pg1_mit() { pg1_init; pg1_stage mit; }
pg1_ours() { pg1_init; pg1_stage ours; }

pg1_rcs() {   # pg1_rcs FILE: kinit rc / klist rc / kvno rc of an observation cell
    local f=$1 k l v
    k=$(sed -n 's/^\[rc=\([0-9]*\)\]$/\1/p' "$f" | head -n 1)
    l=$(b2c_then "$f" '^== then: .*klist' | sed -n 's/^\[then-rc=\([0-9]*\)\]$/\1/p' | head -n 1)
    v=$(b2c_then "$f" '^== then: .*kvno' | sed -n 's/^\[then-rc=\([0-9]*\)\]$/\1/p' | head -n 1)
    echo "${k:-?}/${l:-?}/${v:-?}"
}
pg1_dev_eval() {   # pg1_dev_eval MITFILE OURSFILE: documented (MIT 1/1/1 and the texts, ours 0/0/0), obsolete (ours matches MIT's refusal), other
    local m o
    m=$(pg1_rcs "$1"); o=$(pg1_rcs "$2")
    if [ "$m" = 1/1/1 ] && grep -q '^kinit: Configuration file does not specify default realm when parsing name alice$' "$1"; then
        if [ "$o" = 0/0/0 ]; then echo documented; return; fi
        if [ "$o" = 1/1/1 ] && grep -q '^kinit: Configuration file does not specify default realm when parsing name alice$' "$2"; then echo obsolete; return; fi
    fi
    echo other
}

pg1_parity() {
    pg1_init
    local st c p m o r
    # the ok cells: MIT's tools against ours within a stage (same KDC), and each program across the stages (the KDC changes, the client does not)
    for st in mit ours; do
        for c in "${CLIENTS[@]}"; do
            b2c_cmp "PG1.parity.ok-$st-$c" "$OUT/pg1/$st-ok-mit-$c.txt" "$OUT/pg1/$st-ok-ours-$c.txt"
        done
    done
    b2c_cmp_control "PG1.parity.ok-mit-${CLIENTS[0]}"
    for p in mit ours; do
        for c in "${CLIENTS[@]}"; do
            b2c_cmp "PG1.parity.ok-xstage-$p-$c" "$OUT/pg1/mit-ok-$p-$c.txt" "$OUT/pg1/ours-ok-$p-$c.txt"
        done
    done
    # the observation: the documented LAXER row (docs/mit-deviations.md:75), judged in each stage on each client
    for st in mit ours; do
        for c in "${CLIENTS[@]}"; do
            m="$OUT/pg1/$st-noprofile-mit-$c.txt"; o="$OUT/pg1/$st-noprofile-ours-$c.txt"
            r=$(pg1_dev_eval "$m" "$o")
            case $r in
                documented) verdict "PG1.parity.noprofile-$st-$c" PASS "documented deviation (docs/mit-deviations.md:75, LAXER): MIT kinit/klist/kvno 1/1/1 with MIT's refusal, ours 0/0/0" documented "documented" "MIT $(pg1_rcs "$m"), ours $(pg1_rcs "$o")" ;;
                obsolete) result "PG1.parity.noprofile-$st-$c" INFO "documented deviation (docs/mit-deviations.md:75)" - 1 "OBSOLETE: ours now refuses like MIT (1/1/1); the LAXER row can be dropped" ;;
                *) verdict "PG1.parity.noprofile-$st-$c" FAIL "documented deviation (docs/mit-deviations.md:75, LAXER): MIT kinit/klist/kvno 1/1/1 with MIT's refusal, ours 0/0/0" documented "$r" "MIT $(pg1_rcs "$m"), ours $(pg1_rcs "$o")" ;;
            esac
        done
    done
    # the control: the rule applied to the pair swapped (ours as MIT) must NOT read "documented"
    m="$OUT/pg1/mit-noprofile-mit-${CLIENTS[0]}.txt"; o="$OUT/pg1/mit-noprofile-ours-${CLIENTS[0]}.txt"
    r=$(pg1_dev_eval "$o" "$m")
    if [ "$r" != documented ]; then verdict PG1.parity.noprofile.control PASS "the LAXER rule on the swapped pair must not hold" "not documented" "$r"
    else verdict PG1.parity.noprofile.control FAIL "the LAXER rule on the swapped pair must not hold" "not documented" "$r"; fi
    return 0
}

pg1_clean() {
    pg1_init
    vm kdc "sudo bash $VMD/b2c-vm.sh krb5conf-restore pg1" > /dev/null 2>&1 < /dev/null
    b2c_clean_vms
    return 0
}
