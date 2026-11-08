# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/p15b.sh: B2 module P15b, the kpasswd quality replies on the clients (b2-client; spec: spec/p15b.md). Part (B) of the survey's P15b section, then part (A), the KDC log texts of the earlier leg (below).
# Records of the recorded leg: {lab,lab2,lab3,lab4}/ (R): per-cell reply texts R/lab2/mit/c1mit-{short,classes,dict}.txt, R/lab3/mit/c1mit-dict.txt, R/lab4/mit/mit-{soon,h1,h2,reuse}.txt and the kadmind
# log lines beside them (*.log), rc lists R/lab*/mit/rcs.txt, the policies and principals R/lab/mit-setup.txt:1-60 (quallife, qualhist: min length 8, classes 3, 2 old keys; quallife min life 5 minutes).
# Landed 37eeac62 (tree bb422ba8); the proof holds 2026-10-08 17:16-17:44Z. No lab script survives: the cells below are rewritten from those outputs.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade), on client1 and client2, with MIT's /usr/bin/kpasswd and ours ($VMD/ours/kpasswd), one principal per
# (client, tool, case group), the old password on the first stdin line, the new one twice:
#   short     policy p15bq, new password 4 characters      rc 2   `Password change rejected: New password is too short.` / `Please choose a password which is at least 8 characters long.`   kadmind: `Password is too short`
#   classes   same principal, 12 lower-case letters         rc 2   `... does not have enough character classes.`, the five classes, `... at least 3 character classes.`        kadmind: `Password does not contain enough character classes`
#   dict      same principal, a word of the dictionary      rc 2   the 3-line dictionary paragraph                                                                                       kadmind: `Password is in the password dictionary`
#   ok        same principal, a good password               rc 0   `Password changed.`                                                                                                  kadmind: `success`
#   soon      policy p15bl (min life 1 hour), right after the principal was made   rc 2   `Password cannot be changed because it was changed too recently.` + wait paragraph   kadmind: `Current password's minimum life has not expired`
#   h1 h2     policy p15bq, principal p15bh-*: two good changes   rc 0 0     reuse   the first of them again   rc 2   `New password was used previously. Please choose a different password.`   kadmind: `Cannot reuse password`
# Parity rule of the leg: reply bodies byte-equal MIT kpasswd against krb5-kpasswd, and MIT's KDC against the ship KDC, masking only the principal names and the too-soon date; the kadmind line after
# `chpw request from <ip> for <princ>: ` equal.
# Differences from the recorded leg:
#   - the ours stage is dist/install.sh's upgrade of the final ship build (otp/install-ours.sh), not a Rust snapshot with two binaries copied in; both clients run both tools in both stages;
#   - the dictionary: the leg replaced the stock `dict_file = /usr/share/dict/words` by a 3-word p15b.dict (R/lab3/mit-setup.txt "DICT 3 28"); here helpers/p15b-kdc.sh does the same through b2a-kdcconf.py from the kept
#     pristine kdc.conf, in place, kadmin restarted, and puts it back at the end of the stage. The three words satisfy the policy, so only the dictionary can refuse them;
#   - one policy pair instead of the leg's per-lab names: p15bq (length 8, classes 3, 2 old keys; the leg's qualhist) for the quality, ok and history cells, p15bl (the same + min life 1 hour, the leg's quallife had 5 minutes: an hour cannot run out between the setup and the last client's cell)
#     for the too-soon cell; 12 principals p15b{q,h,l}-c{1,2}{m,r}, all made at the start of the stage with the leg's throwaway password PW1 and deleted with the policies at its end (the shell compares the realm
#     database at the module boundary); kadmin/history, which the first password change under a policy makes in the lab's realm, is deleted when the stage made it (as PG6 does);
#   - the rejected cells are compared too: the leg's follow-up that "presents the old password" (R/lab/mit/*-soon.txt, `Preauthentication failed getting initial ticket`) was a script slip of the first grid
#     (it logged in with the wrong password), not a cell, and is not replayed;
#   - the log of the dictionary refusal also carries MIT's `password quality module dict rejected password` line; it is an INFO row (the leg and brief-P15b-11 leave that line to P16a-edges), the `chpw request` notice is judged;
#   - ADDED: ours' kpasswd prints the program path in front of an error line (`<dir>/kpasswd: ...`), MIT's the bare name: the cells here end in the programs' own verdict lines, which carry no program name, so no mask is needed.
# PART (A), the KDC log texts of the earlier leg (R/LEG/lab/{mit,rust}/{startup,as-log,tgs-log,kinit-bad,kvno-bad,kvno-xrealm}.txt), per stage after the kpasswd grid:
#   restart-kdc  krb5kdc restarted on the kdc (RESTART_RC 0, active, :88 answers); its log delta: `shutting down`, `setting up network...`, `set up N sockets`, `commencing operation` (judged), `Loaded` (MIT's otp plugin says it; INFO)
#                and `preauth pkinit failed to initialize: ...` (the lab has no pkinit identity; INFO); kadmind's startup lines come from the setup section's own restart (`setting up network...`, `set up N sockets`, `starting`)
#   on client2, MIT's tools and ours, as the lab user, with the scratch principal p15ba (+requires_preauth) instead of the leg's alice (a wrong-password kinit against alice would move her `Last failed authentication`, which P6L compares
#   across the upgrade):  kinit-bad  `Password incorrect while getting initial credentials`, rc 1; KDC: NEEDED_PREAUTH, `preauth (spake) verify failure: Preauthentication failed`, PREAUTH_FAILED
#                         kinit-ok   rc 0; KDC: NEEDED_PREAUTH, ISSUE           kvno-nosuch  host/nosuch.kerber.test: rc 1 `Server ... not found in Kerberos database while getting credentials for ...`; KDC: LOOKING_UP_SERVER twice
#                         kvno-nope  krbtgt/NOPE.TEST: rc 1, the same sentence; KDC: UNKNOWN_SERVER twice
# Differences from the leg: p15ba instead of alice; both tools in both stages (the leg: MIT's clients on both KDCs); the leg's `pols` and kpasswd-short/princ steps (a script slip: `usage: kpasswd [principal]`) are not replayed (the policies are part (B)).
# FINDING at the tip (the fake lab with MIT's real KDC against the ship KDC, 2026-10-13): the ship KDC logs no `preauth (spake) verify failure: Preauthentication failed` line before PREAUTH_FAILED (MIT's does: R/LEG/lab/mit/as-log.txt:63);
# the rows for that line are judged in both stages and are red in the ours stage for as long as the line is missing.
# kadmin/history (B2 on the real lab, 2026-10-13): the first password change under a policy makes it in the lab's f4-mit realm, on both stages; the stage records whether it existed at the start and deletes it at the end
# when it made it (rows P15B.<stage>.setup.history-absent-at-start, cleanup.history-created-by-stage, ...-deleted, ...-gone).
# shellcheck source=/dev/null
. "$SCRIPTS/helpers/b2a-host.sh"
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

p15b_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${P15B_INIT_DONE:-}" ] && return 0
    P15B_INIT_DONE=1
    b2c_init
    P15B_CASES='short classes dict ok soon h1 h2 reuse'
    P15B_PRINCS='p15bq-c1m p15bq-c1r p15bq-c2m p15bq-c2r p15bh-c1m p15bh-c1r p15bh-c2m p15bh-c2r p15bl-c1m p15bl-c1r p15bl-c2m p15bl-c2r'
    P15B_NEW_SHORT='Ab1!'
    P15B_NEW_CLASSES='abcdefghijkl'
    P15B_NEW_DICT='Correct-Horse-9'
    P15B_MASK_PRINC='s/p15b[qlh]-c[12][mr]/PRINC/g'
    P15B_MASK_DATE='s/(Please wait until )[A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]+ [0-9:]{8} [0-9]{4}/\1<DATE>/'
    P15B_A_CLIENT=client2
    P15B_A_CELLS='kinit-bad kinit-ok kvno-nosuch kvno-nope'
    P15B_A_NOSUCH=host/nosuch.kerber.test
    P15B_A_NOPE=krbtgt/NOPE.TEST
    P15B_MASK_PROG='s#^([^ :]*/)?(krb5-)?(kinit|kvno):#PROG:#'
}

p15b_prep() {
    local f
    p15b_init
    for f in p15b-kdc.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "p15b: helpers/$f is missing" >&2; return 1; }; done
    b2c_prep_check
}
p15b_push() { p15b_init; b2a_push_script p15b-kdc.sh && b2c_push_vm client1 client2; }

p15b_run() {   # p15b_run STAGE SECTION: the kdc-side section (the three throwaway passwords on stdin), split per cell
    b2a_pw3 | b2a_run_kdc "p15b/$1-run-$2" p15b-kdc.sh "$1" "$2"
    b2a_split "$OUT/p15b/$1-run-$2.txt" "$OUT/p15b" "$1"
}

p15b_pw() {   # p15b_pw TOKEN: @1 @2 @3 the leg's throwaway passwords, anything else is a literal (a known, non-secret string); one line on stdout
    case $1 in @1) b2_pw 1 ;; @2) b2_pw 2 ;; @3) b2_pw 3 ;; *) printf '%s\n' "$1" ;; esac
}
p15b_case() {   # p15b_case CASE: "GROUP OLD NEW" of a cell (the group is the policy's principal family: q p15bq, l p15bl, h history)
    case $1 in
        short)   echo "q @1 $P15B_NEW_SHORT" ;;
        classes) echo "q @1 $P15B_NEW_CLASSES" ;;
        dict)    echo "q @1 $P15B_NEW_DICT" ;;
        ok)      echo "q @1 @2" ;;
        soon)    echo "l @1 @2" ;;
        h1)      echo "h @1 @2" ;;
        h2)      echo "h @2 @3" ;;
        reuse)   echo "h @3 @2" ;;
    esac
}

# SOURCE RECORD: R/lab2/mit/c1mit-short.txt (short, classes), R/lab3/mit/c1mit-dict.txt (dict), R/lab4/mit/mit-{soon,h1,h2,reuse}.txt and *.log (the kadmind lines); the stdin of the leg's cells is not recorded: the old password,
# the new one, the new one again (the prompts `Password for`, `Enter new password:`, `Enter it again:` are in every transcript)
p15b_kp() {   # p15b_kp STAGE CLIENT TOOL CASE: one kpasswd, on CLIENT as the lab user, with TOOL (mit|ours); transcript + the KDC and kadmind log lines it added -> $OUT/p15b/STAGE-CASE-TOOL-CLIENT.txt
    local st=$1 c=$2 t=$3 k=$4 g old new tl princ prog n f l
    read -r g old new <<< "$(p15b_case "$k")"
    if [ "$t" = mit ]; then tl=m; else tl=r; fi
    princ="p15b$g-c${c#client}$tl"
    prog=$(b2c_tool "$t" kpasswd)
    n="p15b/$st-$k-$t-$c"; f="$OUT/$n.txt"; l="P15B.$st.$k-$t-$c"
    { p15b_pw "$old"; p15b_pw "$new"; p15b_pw "$new"; } | cell "$n" "$c" "bash $VMD/b2c-vm.sh run --in-stdin -- $prog $princ" kdc+kadmin
    p15b_rows "$l" "$f" "$k" "$princ"
}

p15b_rows() {   # p15b_rows LABEL FILE CASE PRINC: what the cell must show
    local l=$1 f=$2 k=$3 p=$4 rc=2 logtext
    expect "$l.prompt-old" "$f" "^Password for $p@$RRX: ?\$"
    expect "$l.prompt-new" "$f" '^Enter new password: ?$'
    expect "$l.prompt-again" "$f" '^Enter it again: ?$'
    expect_part "$l.no-secret-marker" "$f" client '<REDACTED:' 0
    case $k in
        short)
            expect "$l.text-1" "$f" '^Password change rejected: New password is too short\.$'
            expect "$l.text-2" "$f" '^Please choose a password which is at least 8 characters long\.$'
            logtext='Password is too short' ;;
        classes)
            expect "$l.text-1" "$f" '^Password change rejected: New password does not have enough character classes\.$'
            expect "$l.text-2" "$f" '^The character classes are:$'
            expect "$l.text-3" "$f" '^[[:space:]]+- lower-case letters,$'
            expect "$l.text-4" "$f" '^[[:space:]]+- upper-case letters,$'
            expect "$l.text-5" "$f" '^[[:space:]]+- digits,$'
            expect "$l.text-6" "$f" '^[[:space:]]+- punctuation, and$'
            expect "$l.text-7" "$f" '^[[:space:]]+- all other characters \(e\.g\., control characters\)\.$'
            expect "$l.text-8" "$f" '^Please choose a password with at least 3 character classes\.$'
            logtext='Password does not contain enough character classes' ;;
        dict)
            expect "$l.text-1" "$f" '^Password change rejected: New password was found in a dictionary of possible passwords and$'
            expect "$l.text-2" "$f" '^therefore may be easily guessed\. Please choose another password\.$'
            expect "$l.text-3" "$f" '^See the kpasswd man page for help in choosing a good password\.$'
            logtext='Password is in the password dictionary'
            info "$l.log-module" "$f" "password quality module dict rejected password for $p@$RRX" "(no module line: the notice below is the judged one)" ;;
        ok | h1 | h2)
            rc=0
            expect "$l.text" "$f" '^Password changed\.$'
            logtext='success' ;;
        soon)
            expect "$l.text-1" "$f" '^Password change rejected: Password cannot be changed because it was changed too recently\.$'
            expect "$l.text-2" "$f" '^Please wait until [A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]+ [0-9:]{8} [0-9]{4} before you change it\.$'
            expect "$l.text-3" "$f" '^If you need to change your password before then, contact your system$'
            expect "$l.text-4" "$f" '^security administrator\.$'
            logtext="Current password's minimum life has not expired" ;;
        reuse)
            expect "$l.text" "$f" '^Password change rejected: New password was used previously\. Please choose a different password\.$'
            logtext='Cannot reuse password' ;;
    esac
    expect "$l.rc" "$f" "^\\[rc=$rc\\]\$"
    expect_part "$l.log-chpw" "$f" kadmin "chpw request from [0-9a-f.:]+ for $p@$RRX: $logtext\$" 1
}

# ---------------------------------------------------------------- part (A): the KDC log texts of the earlier leg (R/LEG/lab/{mit,rust}/*.txt)
p15b_acc() { printf '%s/b2c/p15b-a-%s-%s' "$VMD" "$1" "$2"; }              # p15b_acc STAGE TOOL: a cache path on the VM
p15b_af() { printf '%s/p15b/%s-a-%s-%s.txt' "$OUT" "$1" "$2" "$3"; }       # p15b_af STAGE CELL TOOL: a part (A) cell's transcript

p15b_a() {   # p15b_a STAGE: part (A) of one stage: krb5kdc restarted (startup lines), then the four cells with each tool on $P15B_A_CLIENT
    local st=$1 t k
    p15b_a_startup "$st"
    if ! grep -q '^KDC_LISTENING$' "$OUT/p15b/$st-run-restart-kdc.txt" 2> /dev/null; then
        b2c_not_run "P15B.$st.a-cells" "krb5kdc did not come back after the restart (see the P15B.$st.a-startup rows): no part (A) cell ran"
        return 0
    fi
    for t in mit ours; do
        for k in $P15B_A_CELLS; do deadline; p15b_a_cell "$st" "$t" "$k"; done
    done
    return 0
}

p15b_a_startup() {   # p15b_a_startup STAGE: krb5kdc restarted on the kdc; its startup lines in the KDC log delta, kadmind's in the setup section's (R/LEG/lab/{mit,rust}/startup.txt)
    local st=$1 l=P15B.$1.a-startup f ks
    p15b_run "$st" restart-kdc
    f="$OUT/p15b/$st-run-restart-kdc.txt"; ks="$OUT/p15b/$st-run-setup.txt"
    expect "$l.restart-rc" "$f" '^RESTART_RC:0$'
    expect "$l.kdc-active" "$f" '^KDC:active$'
    expect "$l.kdc-listening" "$f" '^KDC_LISTENING$'
    expect_part "$l.kdc-shutting-down" "$f" kdc 'krb5kdc\[[0-9]+\]\(info\): shutting down$' 1
    expect_part "$l.kdc-setting-up-network" "$f" kdc 'krb5kdc\[[0-9]+\]\(info\): setting up network\.\.\.$' 1
    expect_part "$l.kdc-set-up-sockets" "$f" kdc 'krb5kdc\[[0-9]+\]\(info\): set up [0-9]+ sockets$' 1
    expect_part "$l.kdc-commencing-operation" "$f" kdc 'krb5kdc\[[0-9]+\]\(info\): commencing operation$' 1
    info "$l.kdc-loaded" "$f" 'krb5kdc\[[0-9]+\]\(info\): Loaded$' "(no Loaded line: MIT's otp plugin prints it, the lab's krb5-server has the plugin)"
    info "$l.kdc-pkinit" "$f" 'krb5kdc\[[0-9]+\]\(Error\): preauth pkinit failed to initialize: ' "(no pkinit line: the realm has a pkinit identity)"
    expect_part "$l.kadmind-setting-up-network" "$ks" kadmin 'kadmind\[[0-9]+\]\(info\): setting up network\.\.\.$' 1
    expect_part "$l.kadmind-set-up-sockets" "$ks" kadmin 'kadmind\[[0-9]+\]\(info\): set up [0-9]+ sockets$' 1
    expect_part "$l.kadmind-starting" "$ks" kadmin 'kadmind\[[0-9]+\]\(info\): starting$' 1
    info "$l.kadmind-finished" "$ks" 'kadmind\[[0-9]+\]\(info\): finished, exiting$' "(no finished line: kadmind was not running at the restart)"
}

p15b_a_cell() {   # p15b_a_cell STAGE TOOL CELL: one part (A) cell on $P15B_A_CLIENT, as the lab user, with TOOL's kinit or kvno; the transcript carries the KDC log lines the cell added
    local st=$1 t=$2 k=$3 c=$P15B_A_CLIENT cc kin kvn n
    cc=$(p15b_acc "$st" "$t"); kin=$(b2c_tool "$t" kinit); kvn=$(b2c_tool "$t" kvno); n="p15b/$st-a-$k-$t"
    case $k in
        kinit-bad)   b2_pw 3 | cell "$n" "$c" "bash $VMD/b2c-vm.sh run --in-stdin --rm $cc -- $kin -c FILE:$cc p15ba" kdc ;;
        kinit-ok)    b2_pw 1 | cell "$n" "$c" "bash $VMD/b2c-vm.sh run --in-stdin --rm $cc -- $kin -c FILE:$cc p15ba" kdc ;;
        kvno-nosuch) cell "$n" "$c" "bash $VMD/b2c-vm.sh run -- $kvn -c FILE:$cc $P15B_A_NOSUCH" kdc < /dev/null ;;
        kvno-nope)   cell "$n" "$c" "bash $VMD/b2c-vm.sh run -- $kvn -c FILE:$cc $P15B_A_NOPE" kdc < /dev/null ;;
    esac
    p15b_a_rows "P15B.$st.a-$k-$t-$c" "$OUT/$n.txt" "$k"
}

p15b_a_rows() {   # p15b_a_rows LABEL FILE CELL: what a part (A) cell must show; the client's words and the KDC's log lines (R/LEG/lab/mit/{kinit-bad,kvno-bad,kvno-xrealm}.txt, as-log.txt, tgs-log.txt)
    local l=$1 f=$2 k=$3 ad='[0-9a-f.:]+' et='\([0-9]+ etypes \{[^}]*\}\)' pr="p15ba@$RRX" tg="krbtgt/$RRX@$RRX"
    expect_part "$l.no-secret-marker" "$f" client '<REDACTED:' 0
    case $k in
        kinit-bad)
            expect "$l.rc" "$f" '^\[rc=1\]$'
            expect "$l.prompt" "$f" "^Password for $pr: ?\$"
            expect_under "$l.stdout-one-line" "$f" '^== stdout$' '.' 1
            expect_under "$l.stderr-line" "$f" '^== stderr$' '^([^ :]*/)?(krb5-)?kinit: Password incorrect while getting initial credentials$' 1
            expect_under "$l.stderr-one-line" "$f" '^== stderr$' '.' 1
            expect_part "$l.log-needed-preauth" "$f" kdc "AS_REQ $et $ad: NEEDED_PREAUTH: $pr for $tg, Additional pre-authentication required\$" 1
            expect_part "$l.log-spake-verify-failure" "$f" kdc 'krb5kdc\[[0-9]+\]\(info\): preauth \(spake\) verify failure: Preauthentication failed$' 1
            expect_part "$l.log-preauth-failed" "$f" kdc "AS_REQ $et $ad: PREAUTH_FAILED: $pr for $tg, Preauthentication failed\$" 1
            expect_part "$l.log-no-issue" "$f" kdc "AS_REQ .*: ISSUE: .*$pr for " 0 ;;
        kinit-ok)
            expect "$l.rc" "$f" '^\[rc=0\]$'
            expect "$l.prompt" "$f" "^Password for $pr: ?\$"
            expect_under "$l.stdout-one-line" "$f" '^== stdout$' '.' 1
            expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
            expect_part "$l.log-needed-preauth" "$f" kdc "AS_REQ $et $ad: NEEDED_PREAUTH: $pr for $tg, Additional pre-authentication required\$" 1
            expect_part "$l.log-issue" "$f" kdc "AS_REQ $et $ad: ISSUE: authtime [0-9]+, etypes \\{rep=[^}]*\\}, $pr for $tg\$" 1
            expect_part "$l.log-no-failure" "$f" kdc 'PREAUTH_FAILED|verify failure' 0 ;;
        kvno-nosuch)
            expect "$l.rc" "$f" '^\[rc=1\]$'
            expect_under "$l.stdout-empty" "$f" '^== stdout$' '.' 0
            expect_under "$l.stderr-line" "$f" '^== stderr$' "^([^ :]*/)?(krb5-)?kvno: Server host/nosuch\\.kerber\\.test@$RRX not found in Kerberos database while getting credentials for host/nosuch\\.kerber\\.test@$RRX\$" 1
            expect_under "$l.stderr-one-line" "$f" '^== stderr$' '.' 1
            expect_part "$l.log-looking-up-server" "$f" kdc "TGS_REQ $et $ad: LOOKING_UP_SERVER: authtime [0-9]+, +$pr for host/nosuch\\.kerber\\.test@$RRX, Server not found in Kerberos database\$" 2
            expect_part "$l.log-no-unknown-server" "$f" kdc 'UNKNOWN_SERVER' 0 ;;
        kvno-nope)
            expect "$l.rc" "$f" '^\[rc=1\]$'
            expect_under "$l.stdout-empty" "$f" '^== stdout$' '.' 0
            expect_under "$l.stderr-line" "$f" '^== stderr$' "^([^ :]*/)?(krb5-)?kvno: Server krbtgt/NOPE\\.TEST@$RRX not found in Kerberos database while getting credentials for krbtgt/NOPE\\.TEST@$RRX\$" 1
            expect_under "$l.stderr-one-line" "$f" '^== stderr$' '.' 1
            expect_part "$l.log-unknown-server" "$f" kdc "TGS_REQ $et $ad: UNKNOWN_SERVER: authtime [0-9]+, +$pr for krbtgt/NOPE\\.TEST@$RRX, Server not found in Kerberos database\$" 2
            expect_part "$l.log-no-looking-up-server" "$f" kdc 'LOOKING_UP_SERVER' 0 ;;
    esac
}

p15b_stage() {   # p15b_stage mit|ours
    local st=$1 L=P15B.$1 c t k run ok=1
    b2c_kdc_ready p15b "$st" || return 0
    for c in "${CLIENTS[@]}"; do b2c_work_ok p15b "$st" "$c" || ok=0; done
    if [ "$ok" = 0 ]; then b2c_not_run "P15B.$st.cells" "a client's work directory cannot be used by the lab user (see the P15B.$st.workdir rows): no kpasswd cell ran"; return 0; fi
    # ---- setup on the kdc: the 3-word dictionary in kdc.conf, kadmin restarted, the two policies, the 12 principals
    p15b_run "$st" setup
    run="$OUT/p15b/$st-run-setup.txt"
    expect "$L.setup.history-absent-at-start" "$run" '^HISTORY_AT_START no$'
    expect "$L.setup.dict-file-3-words" "$run" '^DICT_FILE:3 '
    expect "$L.setup.dict-conf" "$run" '^DICT:[0-9]+:[[:space:]]*dict_file = .*/p15b\.dict$'
    expect "$L.setup.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.setup.kadmin-active" "$run" '^KADMIN:active$'
    expect "$L.setup.kadmind-listening" "$run" '^KADMIND_LISTENING$'
    expect "$L.setup.addpol-q" "$OUT/p15b/$st-addpol-q.txt" '^RC:0$'
    expect "$L.setup.addpol-l" "$OUT/p15b/$st-addpol-l.txt" '^RC:0$'
    expect "$L.setup.policy-q-length" "$OUT/p15b/$st-getpol-q.txt" '^Minimum password length: 8$'
    expect "$L.setup.policy-q-classes" "$OUT/p15b/$st-getpol-q.txt" '^Minimum number of password character classes: 3$'
    expect "$L.setup.policy-q-history" "$OUT/p15b/$st-getpol-q.txt" '^Number of old keys kept: 2$'
    expect "$L.setup.policy-q-no-minlife" "$OUT/p15b/$st-getpol-q.txt" '^Minimum password life: 0 days 00:00:00$'
    expect "$L.setup.policy-l-minlife-1h" "$OUT/p15b/$st-getpol-l.txt" '^Minimum password life: 0 days 01:00:00$'
    expect "$L.setup.policy-l-length" "$OUT/p15b/$st-getpol-l.txt" '^Minimum password length: 8$'
    for t in $P15B_PRINCS p15ba; do expect "$L.setup.$t-created" "$OUT/p15b/$st-add-$t.txt" "^Principal \"$t@$RRX\" created\\.\$"; done
    if ! grep -q '^KADMIND_LISTENING$' "$run" || ! grep -q '^RESTART_RC:0$' "$run"; then
        b2c_not_run "P15B.$st.cells" "kadmind did not come up with the dictionary: no kpasswd cell ran"
    else
        for c in "${CLIENTS[@]}"; do
            for t in mit ours; do
                for k in $P15B_CASES; do deadline; p15b_kp "$st" "$c" "$t" "$k"; done
            done
        done
    fi
    # ---- part (A): krb5kdc restarted, the four KDC-log cells of the earlier leg with each tool
    p15b_a "$st"
    # ---- what the stage did to kadmin/history, then everything the stage made is deleted again
    p15b_run "$st" history
    info "$L.history.now" "$OUT/p15b/$st-run-history.txt" '^HISTORY_NOW ' "(no HISTORY_NOW line)"
    p15b_run "$st" cleanup
    run="$OUT/p15b/$st-run-cleanup.txt"
    for t in $P15B_PRINCS p15ba; do
        expect "$L.cleanup.$t-deleted" "$OUT/p15b/$st-del-$t.txt" "^Principal \"$t@$RRX\" deleted\\.\$"
    done
    expect "$L.cleanup.p15bq-gone" "$OUT/p15b/$st-getpol-gone-q.txt" '^get_policy: Policy does not exist while retrieving policy "p15bq"\.$'
    expect "$L.cleanup.p15bl-gone" "$OUT/p15b/$st-getpol-gone-l.txt" '^get_policy: Policy does not exist while retrieving policy "p15bl"\.$'
    if grep -q '^HISTORY_CREATED_BY_STAGE$' "$run"; then
        expect "$L.cleanup.history-deleted" "$OUT/p15b/$st-del-history.txt" "^Principal \"kadmin/history@$RRX\" deleted\\.\$"
    else
        info "$L.cleanup.history-created-by-stage" "$run" '^HISTORY_CREATED_BY_STAGE$' "(the stage did not make kadmin/history)"
    fi
    expect "$L.cleanup.history-gone" "$run" '^HISTORY_AT_END no$'
    expect "$L.cleanup.dict-gone" "$run" '^DICT_GONE:yes '
    expect "$L.cleanup.restart-rc" "$run" '^RESTART_RC:0$'
    expect "$L.cleanup.kadmin-active" "$run" '^KADMIN:active$'
    expect "$L.cleanup.kadmind-listening" "$run" '^KADMIND_LISTENING$'
    return 0
}
p15b_mit() { p15b_init; p15b_stage mit; }
p15b_ours() { p15b_init; p15b_stage ours; }

p15b_logline() {   # p15b_logline FILE: the `chpw request` notice of a cell's kadmind log part, without the syslog prefix, the pid, the client address and the principal's tool letter
    sed -n '/^# kadmind log lines added/,$p' "$1" | grep -E 'chpw request from' \
        | sed -E 's/^[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/; s/ from [^ ]+ for / from ADDR for /; '"$P15B_MASK_PRINC"
}

p15b_alog() {   # p15b_alog FILE: the KDC log lines of a part (A) cell that concern its principal (and the preauth module's own failure line), without the syslog prefix, the pid, the client address and the auth time
    sed -n '/^# KDC log lines added/,/^# kadmind log lines/p' "$1" | grep -E 'p15ba@|preauth \(' \
        | sed -E 's/^[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/; s/\) [0-9a-f.:]+: /) ADDR: /; s/authtime [0-9]+/authtime N/'
}
p15b_astart() {   # p15b_astart FILE kdc|kadmin: the startup lines of a restart transcript (the KDC log part, or the kadmind log part), without the syslog prefix and the pid, the socket numbers masked; MIT's `Loaded` is not in it
    local part=$2 rx rng
    if [ "$part" = kdc ]; then
        rx='krb5kdc\[[0-9]+\]\((info|Error)\): (shutting down|setting up network|setsockopt|set up [0-9]+ sockets|commencing operation|preauth pkinit failed)'
        rng='/^# KDC log lines added/,/^# kadmind log lines/p'
    else
        rx='kadmind\[[0-9]+\]\(info\): (finished, exiting|setting up network|setsockopt|set up [0-9]+ sockets|starting)'
        rng="/^# kadmind log lines added/,\$p"
    fi
    sed -n "$rng" "$1" | grep -E "$rx" | sed -E 's/^[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]/[pid]/; s/setsockopt\([0-9]+,/setsockopt(N,/'
}

p15b_parity() {
    p15b_init
    local c k t s d="$OUT/p15b/norm" a b
    mkdir -p "$d"
    local -a mask=("$P15B_MASK_PRINC" "$P15B_MASK_DATE")
    for c in "${CLIENTS[@]}"; do
        for k in $P15B_CASES; do
            # the programs differ, the KDC does not: MIT's kpasswd against ours in each stage
            for s in mit ours; do
                p15b_cmp "P15B.parity.$k-prog-$s-$c" "$OUT/p15b/$s-$k-mit-$c.txt" "$OUT/p15b/$s-$k-ours-$c.txt" "$d" "${mask[@]}"
            done
            # the KDC (kadmind) changes, the program does not: MIT's kadmind against the ship kadmind, for each program
            for t in mit ours; do
                p15b_cmp "P15B.parity.$k-xkdc-$t-$c" "$OUT/p15b/mit-$k-$t-$c.txt" "$OUT/p15b/ours-$k-$t-$c.txt" "$d" "${mask[@]}"
            done
            # the server's own words: the chpw notice of every cell, MIT's kadmind against ours
            for t in mit ours; do
                p15b_logline "$OUT/p15b/mit-$k-$t-$c.txt" > "$d/log-mit-$k-$t-$c.txt"; p15b_logline "$OUT/p15b/ours-$k-$t-$c.txt" > "$d/log-ours-$k-$t-$c.txt"
                parity_eq "P15B.parity.$k-log-$t-$c" "$d/log-mit-$k-$t-$c.txt" "$d/log-ours-$k-$t-$c.txt"
            done
        done
    done
    # controls: a doctored copy differs; two different cases differ; the date mask is needed (the too-soon wait date differs between the two stages' cells)
    a="$d/P15B.parity.short-prog-mit-${CLIENTS[0]}"
    parity_control P15B.parity.short-prog "$a.a.txt" "$a.b.txt" "${mask[@]}"
    p15b_differ P15B.parity.control.short-vs-classes "$OUT/p15b/mit-short-mit-${CLIENTS[0]}.txt" "$OUT/p15b/mit-classes-mit-${CLIENTS[0]}.txt" "$d" "${mask[@]}"
    p15b_differ P15B.parity.control.soon-vs-reuse "$OUT/p15b/mit-soon-mit-${CLIENTS[0]}.txt" "$OUT/p15b/mit-reuse-mit-${CLIENTS[0]}.txt" "$d" "${mask[@]}"
    if [ -s "$OUT/p15b/mit-soon-mit-${CLIENTS[0]}.txt" ] && [ -s "$OUT/p15b/ours-soon-mit-${CLIENTS[0]}.txt" ]; then
        b="$d/date-unmasked"
        cell_body "$OUT/p15b/mit-soon-mit-${CLIENTS[0]}.txt" | sed -E "$P15B_MASK_PRINC" > "$b.a.txt"; cell_body "$OUT/p15b/ours-soon-mit-${CLIENTS[0]}.txt" | sed -E "$P15B_MASK_PRINC" > "$b.b.txt"
        if cmp -s "$b.a.txt" "$b.b.txt"; then
            result P15B.parity.control.soon-date-mask INFO "the too-soon wait date of the two stages differs without the date mask" - same "the two stages' wait dates are equal (same second): the mask is not exercised in this record"
        else
            verdict P15B.parity.control.soon-date-mask PASS "the too-soon wait date of the two stages differs without the date mask" differ differ ""
        fi
    fi
    p15b_parity_a "$d" "${mask[@]}"
    return 0
}
p15b_parity_a() {   # p15b_parity_a DIR MASK...: part (A), the four cells' client words (MIT's tool against ours, MIT's KDC against the ship KDC), their KDC log lines (MIT's KDC against the ship KDC), the startup lines
    local d=$1 k s t a
    shift
    local -a mask=("$@" "$P15B_MASK_PROG")
    for k in $P15B_A_CELLS; do
        for s in mit ours; do
            p15b_cmp "P15B.parity.a-$k-prog-$s" "$(p15b_af "$s" "$k" mit)" "$(p15b_af "$s" "$k" ours)" "$d" "${mask[@]}"
        done
        for t in mit ours; do
            p15b_cmp "P15B.parity.a-$k-xkdc-$t" "$(p15b_af mit "$k" "$t")" "$(p15b_af ours "$k" "$t")" "$d" "${mask[@]}"
            p15b_alog "$(p15b_af mit "$k" "$t")" > "$d/alog-mit-$k-$t.txt"; p15b_alog "$(p15b_af ours "$k" "$t")" > "$d/alog-ours-$k-$t.txt"
            parity_eq "P15B.parity.a-$k-log-$t" "$d/alog-mit-$k-$t.txt" "$d/alog-ours-$k-$t.txt"
        done
    done
    p15b_astart "$OUT/p15b/mit-run-restart-kdc.txt" kdc > "$d/astart-kdc-mit.txt"; p15b_astart "$OUT/p15b/ours-run-restart-kdc.txt" kdc > "$d/astart-kdc-ours.txt"
    parity_eq P15B.parity.a-startup-kdc "$d/astart-kdc-mit.txt" "$d/astart-kdc-ours.txt"
    p15b_astart "$OUT/p15b/mit-run-setup.txt" kadmin > "$d/astart-kadmind-mit.txt"; p15b_astart "$OUT/p15b/ours-run-setup.txt" kadmin > "$d/astart-kadmind-ours.txt"
    parity_eq P15B.parity.a-startup-kadmind "$d/astart-kadmind-mit.txt" "$d/astart-kadmind-ours.txt"
    # controls: a doctored copy differs; the bad-password and the good login differ in their client words and in their KDC lines
    a="$d/P15B.parity.a-kinit-bad-prog-mit"
    parity_control P15B.parity.a-kinit-bad-prog "$a.a.txt" "$a.b.txt" "${mask[@]}"
    p15b_differ P15B.parity.control.a-bad-vs-ok "$(p15b_af mit kinit-bad mit)" "$(p15b_af mit kinit-ok mit)" "$d" "${mask[@]}"
    if [ -s "$d/alog-mit-kinit-bad-mit.txt" ] && ! cmp -s "$d/alog-mit-kinit-bad-mit.txt" "$d/alog-mit-kinit-ok-mit.txt"; then
        verdict P15B.parity.control.a-log-bad-vs-ok PASS "the KDC lines of a bad and a good login must differ" differ differ ""
    else
        verdict P15B.parity.control.a-log-bad-vs-ok FAIL "the KDC lines of a bad and a good login must differ" differ same ""
    fi
    return 0
}
p15b_cmp() {   # p15b_cmp LABEL A B DIR MASK...: the client parts of two cells, equal after the named masks (a parity row; the normalised copies are kept for the control)
    local label=$1 a=$2 b=$3 d=$4
    shift 4
    cell_body "$a" > "$d/$label.a.txt" 2> /dev/null; cell_body "$b" > "$d/$label.b.txt" 2> /dev/null
    parity_eq "$label" "$d/$label.a.txt" "$d/$label.b.txt" "$@"
}
p15b_differ() {   # p15b_differ LABEL A B DIR MASK...: the client parts of two different cells must differ after the masks
    local label=$1 a=$2 b=$3 d=$4 na nb
    shift 4
    na=$(cell_body "$a" 2> /dev/null | b2_norm /dev/stdin "$@"); nb=$(cell_body "$b" 2> /dev/null | b2_norm /dev/stdin "$@")
    if [ -n "$na" ] && [ "$na" != "$nb" ]; then verdict "$label" PASS "two different cells must differ" differ differ ""
    else verdict "$label" FAIL "two different cells must differ" differ same ""; fi
}

p15b_clean() {   # the stage's last section puts kdc.conf and kadmin back; once more, quietly, and the work directories go
    p15b_init
    vm kdc "sudo env VMCTL_D=$VMD python3 -I $VMD/b2a/b2a-kdcconf.py; sudo rm -f /var/kerberos/krb5kdc/p15b.dict" > /dev/null 2>&1
    b2c_clean_vms
    return 0
}
