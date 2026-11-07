# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/pg6.sh: PG6 (pwqual by name) on the final tree: the kpasswd-with-policy cells through the rewritten :464 acceptor (RA r4), the 3-to-5-character STRICTER row, and the `[plugins] pwqual`
# stanza cells; the kadmin.local half (scripts/kadmin-local-gate.sh:302-336 drives it against MIT's own kadmin.local in the gate) is included because it costs one ssh call per stage.
# Source records: judge.txt (the 11 KADMIN + 14 KPASSWD + 4 STANZA rows), {mit,rust}-kadmin.txt, {mit,rust}-kpasswd.txt, *-stanza-*.txt, mit-conf.txt, mit-dict.txt,
# and lab/probe-LEG/mit2.txt, mit3.txt (the probes that settled the 3-5 character rule). The VM script was not saved: rewritten from those outputs and from the gate (the kadmin commands).
# Differences from the recorded leg (LEG, 2026-10-09 01:19Z, tree 2a956487):
#   - the ours stage is dist/install.sh's upgrade of the final ship build, not `make install` after `dnf install make`; the VMs are reset to f4-mit by the shell, not by a Rust snapshot's revert;
#   - the stanza and the dict_file line are written by b2a-kdcconf.py from the kept pristine kdc.conf (in place), not by a marker-based writer; the stanza is in kdc.conf for both stages (MIT reads
#     kdc.conf ahead of krb5.conf; the ship build reads both);
#   - the cell names of the stanza half are empty-off (the record's mempty-off), only-empty, only-princ, only-dict; passwords are the leg's throwaway ones (stdin) except the words under test;
#   - the policy pq and the principals are deleted at the end of each stage (not carried through the dump/load);
#   - added: the kadmind log lines of the kpasswd and kadmin.local cells ("password quality module X rejected ..." and "chpw request from ... : text") are compared MIT against ours after a named mask
#     (the RA r4 acceptor rewrote the chpw log texts); the one cell that differs by a documented row (kpol-princ) is compared as that row.
# Cells (VM kdc; MIT's kpasswd and kinit on the kdc in both stages): setup, 13 kadmin.local cells, 3-4 kpasswd cells x 7 principals (kpol-* with policy pq, knp-* without), 4 stanza cells.
# kadmin/history (B2 on the real lab, 2026-10-13): the lab's f4-mit realm lacks it as found, MIT's kadmind creates it lazily when the policy cells set passwords, and the realm row at the module boundary went red.
# Each stage now records whether it existed at the start (absent: the ours stage starts without it because the MIT stage deleted what it made), whether it exists after the cells (created: MIT from the oracle,
# ours must create it too; nothing here creates or re-sets it, so a missing creation is a PRODUCT finding), and deletes what it made in the cleanup, after the principals and the policy.
# MIT-only tools: kadmin.local is MIT's in _mit and the ship build's in _ours (L4's dnf remove takes MIT's away). The stage's principals and the policy pq are deleted at its end (the shell compares the
# realm database with L1's at every module boundary), so the ours stage's addpol creates the policy again; the record's ours-only line "add_policy: ... already exists" (rust-kadmin.txt line 3, the
# policy having survived the dump/load) therefore does not occur and the addpol cell needs no mask.
# Cell -> record, file:line: mit-kadmin.txt (rust-kadmin.txt the same): addpol :1-3, empty-nopolicy :4-7, princ-component :8-11, realm :12-15, nopolicy-name-ok :16-19,
# rejected-not-created :20-23, cpw-empty :24-27, modprinc-policy :28-31, cpw-princ :32-35, dict-word :36-39, dict-nopolicy-ok :40-43, dict-substring-ok :44-47, getprinc-dictsub :48-53; mit-kpasswd.txt
# (rust-kpasswd.txt): ke-create :1-4, kpol-empty :5-12, kpol-empty-still :13-16, kp-create :17-20, kpol-princ :21-27, kpol-princ-still :28-31, kd-create :32-35, kpol-dict :36-44, kpol-dict-still :45-48,
# ko-create :49-52, kpol-ok :53-59, kpol-kinit :60-63, ne-create :64-67, knp-empty :68-76, knp-empty-still :77-80, nd-create :81-84, knp-dict :85-91, knp-kinit :92-95, np-create :96-99, knp-princ :100-106,
# knp-princ-kinit :107-110; the stanza cells mit-stanza-disable.txt:1-3 + mit-stanza-empty.txt:1-4, mit-stanza-only.txt:1-3 + mit-stanza-only-{empty,princ,dict}.txt:1-4 (rust twins); the dictionary
# mit-conf.txt:1 (DICT:14) and mit-dict.txt:1-2; the judge judge.txt:1-29. The 3-5 character rule: lab/probe-LEG/mit2.txt (mkp / aaaa / notawordxyz) and mit3.txt (LEN 3 changed, LEN 6-12 dictsentence).
. "$SCRIPTS/helpers/b2a-host.sh"

pg6_prep() {
    local f
    for f in pg6-kdc.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "pg6: helpers/$f is missing" >&2; return 1; }; done
}
pg6_push() { b2a_push_script pg6-kdc.sh; }

pg6_run() {   # pg6_run STAGE SECTION: the section on the kdc (three throwaway passwords on stdin), split per cell
    b2a_pw3 | b2a_run_kdc "pg6/$1-run-$2" pg6-kdc.sh "$1" "$2"
    b2a_split "$OUT/pg6/$1-run-$2.txt" "$OUT/pg6" "$1"
}

# the quality / chpw lines of a run's kadmind log delta, without the syslog prefix, the pid, the client address and the principal prefix (m MIT / r ours)
pg6_logs() {
    sed -n '/^# kadmind log lines added/,$p' "$1" | grep -E 'password quality module|chpw request' \
        | sed -E 's/^[A-Z][a-z]{2} [0-9 ]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/; s/ from [^ ]+ for / from ADDR for /; s/([^A-Za-z0-9_])[mr]([a-z]+)@/\1P\2@/g'
}

pg6_stage() {   # pg6_stage mit|ours
    local st=$1 P L=PG6.$1 f c run
    if [ "$st" = mit ]; then P=m; else P=r; fi
    local R=$RRX Q="@$RRX"
    # ---- setup: dict_file = /var/kerberos/krb5kdc/dict.txt (3 lines), kadmin restarted, policy pq (record: mit-conf.txt "DICT:14", mit-dict.txt "DICT_FILE:3")
    pg6_run "$st" setup
    run="$OUT/pg6/$st-run-setup.txt"
    expect "$L.setup.dict-file-3-lines" "$run" '^DICT_FILE:3$'
    expect "$L.setup.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.setup.kadmin-active" "$run" '^KADMIN:active$'
    expect "$L.setup.kadmind-listening" "$run" '^KADMIND_LISTENING$'
    expect "$L.addpol.rc" "$OUT/pg6/$st-addpol.txt" '^RC:0$'
    expect "$L.getpol.min-length-1-classes-1" "$OUT/pg6/$st-getpol.txt" '^Minimum password length: 1$'
    expect "$L.getpol.classes" "$OUT/pg6/$st-getpol.txt" '^Minimum number of password character classes: 1$'
    expect "$L.getpol.history-1" "$OUT/pg6/$st-getpol.txt" '^Number of old keys kept: 1$'
    expect "$L.history.absent-at-start" "$run" '^HISTORY_AT_START no$'                   # kadmin/history as the stage found it
    # ---- the kadmin.local half (record: mit-kadmin.txt; judge.txt KADMIN rows; the gate's pwq-* checks)
    pg6_run "$st" kadmin
    pg6_cellrow "$L.empty-nopolicy" "$OUT/pg6/$st-empty-nopolicy.txt" "^add_principal: Empty passwords are not allowed while creating \"${P}empty$Q\"\\.\$"
    pg6_cellrow "$L.princ-component" "$OUT/pg6/$st-princ-component.txt" "^add_principal: Password may not match principal name while creating \"${P}name$Q\"\\.\$"
    pg6_cellrow "$L.realm" "$OUT/pg6/$st-realm.txt" "^add_principal: Password is in the password dictionary while creating \"${P}realm$Q\"\\.\$"
    pg6_cellrow "$L.nopolicy-name-ok" "$OUT/pg6/$st-nopolicy-name-ok.txt" "^Principal \"${P}free$Q\" created\\.\$"
    pg6_cellrow "$L.rejected-not-created" "$OUT/pg6/$st-rejected-not-created.txt" "^get_principal: Principal does not exist while retrieving \"${P}name$Q\"\\.\$"
    pg6_cellrow "$L.cpw-empty" "$OUT/pg6/$st-cpw-empty.txt" "^change_password: Empty passwords are not allowed while changing password for \"${P}free$Q\"\\.\$"
    pg6_cellrow "$L.modprinc-policy" "$OUT/pg6/$st-modprinc-policy.txt" "^Principal \"${P}free$Q\" modified\\.\$"
    pg6_cellrow "$L.cpw-princ" "$OUT/pg6/$st-cpw-princ.txt" "^change_password: Password may not match principal name while changing password for \"${P}free$Q\"\\.\$"
    pg6_cellrow "$L.dict-word" "$OUT/pg6/$st-dict-word.txt" "^add_principal: Password is in the password dictionary while creating \"${P}dict$Q\"\\.\$"
    pg6_cellrow "$L.dict-nopolicy-ok" "$OUT/pg6/$st-dict-nopolicy-ok.txt" "^Principal \"${P}dictnp$Q\" created\\.\$"
    pg6_cellrow "$L.dict-substring-ok" "$OUT/pg6/$st-dict-substring-ok.txt" "^Principal \"${P}dictsub$Q\" created\\.\$"
    f="$OUT/pg6/$st-getprinc-dictsub.txt"
    expect "$L.getprinc-dictsub.principal" "$f" "^Principal: ${P}dictsub$Q\$"
    expect "$L.getprinc-dictsub.policy-pq" "$f" '^Policy: pq$'
    # kadmin/history around the cell that makes it (cpw-princ: a password change under the policy pq; the princ module refuses it, the history key is fetched first), on both stages
    expect "$L.history.before-cpw-princ" "$OUT/pg6/$st-run-kadmin.txt" '^HISTORY_BEFORE_CPW_PRINC no$'
    expect "$L.history.created-by-cpw-princ" "$OUT/pg6/$st-run-kadmin.txt" '^HISTORY_AFTER_CPW_PRINC yes$'
    # ---- the kpasswd half (record: mit-kpasswd.txt / rust-kpasswd.txt; judge.txt KPASSWD rows; the 3-5 character rule: probe-LEG/mit2.txt, mit3.txt)
    pg6_run "$st" kpasswd
    local dictp1='^Password change rejected: New password was found in a dictionary of possible passwords and$'
    local dictp2='^therefore may be easily guessed\. Please choose another password\.$'
    local dictp3='^See the kpasswd man page for help in choosing a good password\.$'
    for c in ke kp kd ko ne nd np; do pg6_cellrow "$L.$c-create" "$OUT/pg6/$st-$c-create.txt" "^Principal \"${P}$c$Q\" created\\.\$"; done
    f="$OUT/pg6/$st-kpol-empty.txt"                       # under policy pq (min length 1): the empty password is too short
    expect "$L.kpol-empty.rc" "$f" '^RC:2$'
    expect "$L.kpol-empty.text" "$f" '^Password change rejected: New password is too short\.$'
    expect "$L.kpol-empty.text2" "$f" '^Please choose a password which is at least 1 characters long\.$'
    expect "$L.kpol-empty-still.rc" "$OUT/pg6/$st-kpol-empty-still.txt" '^KINIT_RC:0$'
    if [ "$st" = mit ]; then   # the component of 3 characters: MIT's kpasswd ACCEPTS it, the new password works (STRICTER row, docs/mit-deviations.md:40)
        f="$OUT/pg6/$st-kpol-princ.txt"
        expect "$L.kpol-princ.rc" "$f" '^RC:0$'
        expect "$L.kpol-princ.text" "$f" '^Password changed\.$'
        f="$OUT/pg6/$st-kpol-princ-still.txt"
        expect "$L.kpol-princ-still.rc" "$f" '^KINIT_RC:1$'
        expect "$L.kpol-princ-still.text" "$f" '^ERR:kinit: Password incorrect while getting initial credentials'
    else                       # ours rejects it with the dictionary paragraph, the old password still logs in
        f="$OUT/pg6/$st-kpol-princ.txt"
        expect "$L.kpol-princ.rc" "$f" '^RC:2$'
        expect "$L.kpol-princ.dict-1" "$f" "$dictp1"
        expect "$L.kpol-princ.dict-2" "$f" "$dictp2"
        expect "$L.kpol-princ.dict-3" "$f" "$dictp3"
        expect "$L.kpol-princ-still.rc" "$OUT/pg6/$st-kpol-princ-still.txt" '^KINIT_RC:0$'
    fi
    f="$OUT/pg6/$st-kpol-dict.txt"
    expect "$L.kpol-dict.rc" "$f" '^RC:2$'
    expect "$L.kpol-dict.dict-1" "$f" "$dictp1"
    expect "$L.kpol-dict.dict-2" "$f" "$dictp2"
    expect "$L.kpol-dict.dict-3" "$f" "$dictp3"
    expect "$L.kpol-dict-still.rc" "$OUT/pg6/$st-kpol-dict-still.txt" '^KINIT_RC:0$'
    f="$OUT/pg6/$st-kpol-ok.txt"
    expect "$L.kpol-ok.rc" "$f" '^RC:0$'
    expect "$L.kpol-ok.text" "$f" '^Password changed\.$'
    expect "$L.kpol-kinit.rc" "$OUT/pg6/$st-kpol-kinit.txt" '^KINIT_RC:0$'
    f="$OUT/pg6/$st-knp-empty.txt"                         # no policy: the empty password is refused by the built-in empty module's floor
    expect "$L.knp-empty.rc" "$f" '^RC:2$'
    expect "$L.knp-empty.text" "$f" '^Password change rejected: Password is too short$'
    expect "$L.knp-empty.text2" "$f" '^Password not changed\.$'
    expect "$L.knp-empty-still.rc" "$OUT/pg6/$st-knp-empty-still.txt" '^KINIT_RC:0$'
    f="$OUT/pg6/$st-knp-dict.txt"                          # no policy: dict and princ do not apply
    expect "$L.knp-dict.rc" "$f" '^RC:0$'
    expect "$L.knp-dict.text" "$f" '^Password changed\.$'
    expect "$L.knp-kinit.rc" "$OUT/pg6/$st-knp-kinit.txt" '^KINIT_RC:0$'
    f="$OUT/pg6/$st-knp-princ.txt"
    expect "$L.knp-princ.rc" "$f" '^RC:0$'
    expect "$L.knp-princ.text" "$f" '^Password changed\.$'
    expect "$L.knp-princ-kinit.rc" "$OUT/pg6/$st-knp-princ-kinit.txt" '^KINIT_RC:0$'
    # the kadmind log of the kpasswd run (RA r4 rewrote the chpw texts): MIT's server logs the quality module and the chpw request
    run="$OUT/pg6/$st-run-kpasswd.txt"
    expect_part "$L.kpol-dict.log-module" "$run" kadmin "password quality module dict rejected password for ${P}kd$Q: Password is in the password dictionary"
    expect_part "$L.kpol-dict.log-chpw" "$run" kadmin "chpw request from .* for ${P}kd$Q: Password is in the password dictionary"
    expect_part "$L.kpol-ok.log-chpw" "$run" kadmin "chpw request from .* for ${P}ko$Q: success"
    # kadmin/history after the kpasswd cells: still there (MIT: the oracle's fact; ours: it must; nothing in this module creates it)
    info "$L.history.after-kpasswd" "$run" '^HISTORY_AFTER_KPASSWD ' "(no HISTORY_AFTER_KPASSWD line)"
    expect "$L.history.created" "$run" '^HISTORY_AFTER_KPASSWD yes$'
    info "$L.history.key-line" "$OUT/pg6/$st-getprinc-history.txt" '^Key: vno ' "(no Key line: kadmin/history does not exist or has no key)"
    # ---- the [plugins] pwqual stanza cells (record: *-stanza-*.txt; judge.txt STANZA rows): disable = empty; enable_only = nosuch (no module runs)
    pg6_run "$st" stanza-disable
    run="$OUT/pg6/$st-run-stanza-disable.txt"
    expect "$L.stanza-disable.stanza-written" "$run" '^CONF_PLUGINS_LINES:1$'
    expect "$L.stanza-disable.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.stanza-disable.kadmin-active" "$run" '^KADMIN:active$'
    pg6_cellrow "$L.empty-off" "$OUT/pg6/$st-empty-off.txt" "^Principal \"${P}emptyoff$Q\" created\\.\$"
    pg6_run "$st" stanza-only
    run="$OUT/pg6/$st-run-stanza-only.txt"
    expect "$L.stanza-only.stanza-written" "$run" '^CONF_PLUGINS_LINES:1$'
    expect "$L.stanza-only.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.stanza-only.kadmin-active" "$run" '^KADMIN:active$'
    pg6_cellrow "$L.only-empty" "$OUT/pg6/$st-only-empty.txt" "^Principal \"${P}onlye$Q\" created\\.\$"
    pg6_cellrow "$L.only-princ" "$OUT/pg6/$st-only-princ.txt" "^Principal \"${P}onlyp$Q\" created\\.\$"
    pg6_cellrow "$L.only-dict" "$OUT/pg6/$st-only-dict.txt" "^Principal \"${P}onlyd$Q\" created\\.\$"
    pg6_run "$st" stanza-off
    run="$OUT/pg6/$st-run-stanza-off.txt"
    expect "$L.stanza-off.stanza-gone" "$run" '^CONF_PLUGINS_LINES:0$'
    expect "$L.stanza-off.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.stanza-off.kadmin-active" "$run" '^KADMIN:active$'
    expect "$L.stanza-off.kadmind-listening" "$run" '^KADMIND_LISTENING$'
    # ---- the stage's principals and the policy pq deleted again: the realm database is as L1 found it at this module's boundary (the shell's realm-as-found row)
    pg6_run "$st" cleanup
    expect "$L.cleanup.free-deleted" "$OUT/pg6/$st-del-free.txt" "^Principal \"${P}free$Q\" deleted\\.\$"
    expect "$L.cleanup.pq-gone" "$OUT/pg6/$st-getpol-gone.txt" '^get_policy: Policy does not exist while retrieving policy "pq"\.$'
    run="$OUT/pg6/$st-run-cleanup.txt"
    expect "$L.cleanup.history-created-by-stage" "$run" '^HISTORY_CREATED_BY_STAGE$'      # absent at the start, present now: this stage made it
    expect "$L.cleanup.history-deleted" "$OUT/pg6/$st-del-history.txt" "^Principal \"kadmin/history$Q\" deleted\\.\$"
    expect "$L.cleanup.history-gone" "$run" '^HISTORY_AT_END no$'                          # the realm is as found for the next stage
    return 0
}
pg6_cellrow() {   # pg6_cellrow LABEL FILE TEXT-RX: the cell's RC 0 (kadmin.local answers 0 whatever the operation said) and its one text line
    expect "$1.rc" "$2" '^RC:0$'
    expect "$1.text" "$2" "$3"
}

pg6_mit() { pg6_stage mit; }
pg6_ours() { pg6_stage ours; }

pg6_parity() {
    local c m o f
    # the named mask: the principal's m (MIT stage) / r (ours) prefix
    local -a pfx=('s/([^A-Za-z0-9_])[mr]([a-z]+)@/\1P\2@/g')
    # ---- the kadmin.local cells and the stanza cells and the create cells: equal after the prefix mask
    parity_eq PG6.parity.addpol "$OUT/pg6/mit-addpol.txt" "$OUT/pg6/ours-addpol.txt" "${pfx[@]}"
    for c in empty-nopolicy princ-component realm nopolicy-name-ok rejected-not-created cpw-empty modprinc-policy cpw-princ dict-word dict-nopolicy-ok dict-substring-ok getprinc-dictsub \
             ke-create kp-create kd-create ko-create ne-create nd-create np-create empty-off only-empty only-princ only-dict; do
        parity_eq "PG6.parity.$c" "$OUT/pg6/mit-$c.txt" "$OUT/pg6/ours-$c.txt" "${pfx[@]}"
    done
    # ---- the kpasswd cells: equal, except kpol-princ and its kinit, which are the documented STRICTER row
    for c in kpol-empty kpol-empty-still kpol-dict kpol-dict-still kpol-ok kpol-kinit knp-empty knp-empty-still knp-dict knp-kinit knp-princ knp-princ-kinit; do
        parity_eq "PG6.parity.$c" "$OUT/pg6/mit-$c.txt" "$OUT/pg6/ours-$c.txt" "${pfx[@]}"
    done
    local cite="docs/mit-deviations.md:40"   # pwqual princ on kpasswd: MIT accepts a component of 3 to 5 characters, kerber-rust rejects it with the dictionary paragraph and the old password still kinits
    parity_dev PG6.parity.kpol-princ.stricter "$cite" "$OUT/pg6/mit-kpol-princ.txt" '^RC:0$' "$OUT/pg6/ours-kpol-princ.txt" '^RC:2$'
    parity_dev PG6.parity.kpol-princ-still.stricter "$cite" "$OUT/pg6/mit-kpol-princ-still.txt" '^KINIT_RC:1$' "$OUT/pg6/ours-kpol-princ-still.txt" '^KINIT_RC:0$'
    parity_dev PG6.parity.kpol-princ-text.stricter "$cite" "$OUT/pg6/mit-kpol-princ.txt" '^Password changed\.$' "$OUT/pg6/ours-kpol-princ.txt" '^See the kpasswd man page for help in choosing a good password\.$'
    # ---- the kadmind log lines of the kpasswd run and of the kadmin.local run, equal after the masks, one row per principal stem so that a difference names its cell; the kp cell's lines are the documented row's
    # (MIT: success; ours: the princ module's sentence)
    for c in ke kd ko ne nd np; do
        pg6_logs "$OUT/pg6/mit-run-kpasswd.txt" | grep -E "P$c@" > "$OUT/pg6/mit-log-kpasswd-$c.txt"; pg6_logs "$OUT/pg6/ours-run-kpasswd.txt" | grep -E "P$c@" > "$OUT/pg6/ours-log-kpasswd-$c.txt"
        parity_eq "PG6.parity.log-kpasswd.$c" "$OUT/pg6/mit-log-kpasswd-$c.txt" "$OUT/pg6/ours-log-kpasswd-$c.txt"
    done
    pg6_logs "$OUT/pg6/mit-run-kadmin.txt" > "$OUT/pg6/mit-log-kadmin.txt"; pg6_logs "$OUT/pg6/ours-run-kadmin.txt" > "$OUT/pg6/ours-log-kadmin.txt"
    parity_eq PG6.parity.log-kadmin "$OUT/pg6/mit-log-kadmin.txt" "$OUT/pg6/ours-log-kadmin.txt"
    parity_dev PG6.parity.kpol-princ-log.stricter "$cite" <(pg6_logs "$OUT/pg6/mit-run-kpasswd.txt" | grep -E 'Pkp@') 'chpw request from ADDR for Pkp@KERBER\.TEST: success' \
        <(pg6_logs "$OUT/pg6/ours-run-kpasswd.txt" | grep -E 'Pkp@') 'password quality module princ rejected password for Pkp@KERBER\.TEST: Password may not match principal name'
    # ---- kadmin/history is created by the policy cells on BOTH stages: MIT's from the oracle, ours must (the ours stage started without it, nothing here re-sets it): a no on ours is a product finding
    local hm ho
    hm=$(sed -n -e 's/^HISTORY_BEFORE_CPW_PRINC /before=/p' -e 's/^HISTORY_AFTER_CPW_PRINC /after=/p' "$OUT/pg6/mit-run-kadmin.txt" 2> /dev/null | tr '\n' ' ' | sed 's/ *$//')
    ho=$(sed -n -e 's/^HISTORY_BEFORE_CPW_PRINC /before=/p' -e 's/^HISTORY_AFTER_CPW_PRINC /after=/p' "$OUT/pg6/ours-run-kadmin.txt" 2> /dev/null | tr '\n' ' ' | sed 's/ *$//')
    same PG6.parity.history.created "mit: before=no after=yes; ours: before=no after=yes" "mit: ${hm:-?}; ours: ${ho:-?}" "kadmin/history is made by the cpw-princ cell on both stages (each started without it)"
    ho=$(printf 'HISTORY_BEFORE_CPW_PRINC no\nHISTORY_AFTER_CPW_PRINC no\n' | sed -n -e 's/^HISTORY_BEFORE_CPW_PRINC /before=/p' -e 's/^HISTORY_AFTER_CPW_PRINC /after=/p' | tr '\n' ' ' | sed 's/ *$//')
    if [ "mit: ${hm:-?}; ours: $ho" != "mit: before=no after=yes; ours: before=no after=yes" ]; then verdict PG6.parity.history.created.control PASS "a doctored ours cell (no creation) must not satisfy the row" differ differ
    else verdict PG6.parity.history.created.control FAIL "a doctored ours cell (no creation) must not satisfy the row" differ same; fi
    # and what was created, from getprinc (no key material in it): the kvno and the key enctypes, then the rest of its shape; MIT = ours (MIT's create_hist: server_kdb.c:141-164, ours store/history.rs:107-117)
    local hk='^(Number of keys:|Key: vno|MKey: vno)'
    parity_eq PG6.parity.history.keys <(grep -E "$hk" "$OUT/pg6/mit-getprinc-history.txt" 2> /dev/null | sort) <(grep -E "$hk" "$OUT/pg6/ours-getprinc-history.txt" 2> /dev/null | sort)
    parity_eq PG6.parity.history.shape <(grep -v -E "$hk" "$OUT/pg6/mit-getprinc-history.txt" 2> /dev/null) <(grep -v -E "$hk" "$OUT/pg6/ours-getprinc-history.txt" 2> /dev/null)
    parity_control PG6.parity.history.keys <(grep -E "$hk" "$OUT/pg6/mit-getprinc-history.txt" 2> /dev/null | sort) <(grep -E "$hk" "$OUT/pg6/ours-getprinc-history.txt" 2> /dev/null | sort)
    # ---- the controls: the comparison can fail (a doctored copy of ours differs), and the STRICTER row fails when MIT's cell is doctored to ours' answer
    parity_control PG6.parity.kpol-dict "$OUT/pg6/mit-kpol-dict.txt" "$OUT/pg6/ours-kpol-dict.txt" "${pfx[@]}"
    parity_control PG6.parity.dict-word "$OUT/pg6/mit-dict-word.txt" "$OUT/pg6/ours-dict-word.txt" "${pfx[@]}"
    m="$OUT/pg6/control-mit-kpol-princ.txt"; sed 's/^RC:0$/RC:2/' "$OUT/pg6/mit-kpol-princ.txt" > "$m"
    o=$(grep -cE '^RC:0$' "$m" || true)
    if [ "${o:-0}" = 0 ]; then verdict PG6.parity.kpol-princ.stricter.control PASS "a doctored MIT cell (RC 0 turned into 2) must not hold the STRICTER row's MIT fact" 0 "$o"
    else verdict PG6.parity.kpol-princ.stricter.control FAIL "a doctored MIT cell (RC 0 turned into 2) must not hold the STRICTER row's MIT fact" 0 "$o"; fi
    return 0
}

pg6_clean() {   # the stage's last section puts kdc.conf and kadmin back; once more, quietly
    vm kdc "sudo env VMCTL_D=$VMD python3 -I $VMD/b2a/b2a-kdcconf.py; sudo rm -f /var/kerberos/krb5kdc/dict.txt" > /dev/null 2>&1
    return 0
}
