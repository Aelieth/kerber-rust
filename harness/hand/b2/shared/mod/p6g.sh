# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/p6g.sh: B2 module P6g r2, the cells no gate reaches (b2-client; spec: spec/p6g.md).
# Record of the recorded legs (R): r2 lab2 (R/r2/lab2/run.log), r3 (R/r3/lab/run.log, -T FILE:), r4 (R/r4/lab/run.log, -T DIR:, MEMORY: and missing FILE: observed), r5 (R/r5/lab/run.log and run-5b.log,
# the armor flow and disable_encrypted_timestamp). Landed ae102c8d (tree f687c76a). The lab scripts and delay_kinit.py are lost: rebuilt from the run logs, the per-cell files and the overseer notes.
# Gate coverage at the tip: none for -T ccache names, the unarmored-first/upgrade flow, "Error constructing AP-REQ armor:", fast_avail arming, disable_encrypted_timestamp, must-2 or the delayed prompt.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade) x client x program (MIT's kinit, ours); every cell but the armor makers uses the client conf with
# `spake_preauth_groups = nosuch` first under [libdefaults] (SPAKE unusable: R/r3/lab/run.log:7-8 "encts_conf_ok / 2:"):
#   fast-file    kinit -T FILE:<armor cache> ...: rc 0, PROMPT=yes, ticket pa_type 138 with fast_avail yes, the encrypted challenge succeeds on request and reply (R/r3/lab/run.log:10-34 MIT KDC, :43-68 ours)
#   fast-dir     the same with -T DIR:<armor dir> (R/r4/lab/run.log:13-38, :69-94)
#   fast-arm     in both: `Read config in <armor> ...: fast_avail: yes` < `Using FAST due to armor ccache negotiation result` < the first `Sending request (`; two requests (R/r5/lab/run-5b.log:13-26)
#   armor-mem    -T MEMORY:p6g: rc 1, PROMPT=no, one request, "Error constructing AP-REQ armor: No credentials cache found while getting initial credentials" (R/r5/lab/run.log:48-58, :70-80)
#   armor-miss   -T FILE:<missing>: the same with "(filename: <path>)" (R/r5/lab/run.log:59-69, :81-91)
#   must2        kdc.conf [plugins] kdcpreauth = { disable = encrypted_timestamp } (set_conf), the client cannot use SPAKE: rc 1, PROMPT=no, one request, "Generic preauthentication failure while getting initial
#                credentials" (R/r2/lab2/run.log:54-63, mit-noencts-{mit,rust}.txt). The ship KDC honours the stanza since PG2, so this cell runs on the ours stage for the first time
#   encts-off    [realms] REALM disable_encrypted_timestamp = true (first relation of the realm node) with nosuch: rc 1, PROMPT=no, one request, "Pre-authentication failed: Encrypted timestamp is disabled while
#                getting initial credentials" (R/r5/lab/run.log:116-128, run-5b.log:36-47)
#   delay        ONLY with P6G_DELAY=1 (default off, built last): MIT and ours as a pair on client2, the password arriving P6G_DELAY_S (default 330) seconds after the prompt: rc 0, two requests, the encrypted timestamp
#                is the post-prompt clock and the KDC accepts it (default clockskew 300) (R/r2/lab2/run.log:47-53, mit-delay-mit.trace)
# DROPPED: the +1 h clock cell (gate-covered at +3 d: scripts/client-differential-cli-gate.sh:170-199).
# Parity rule of the legs: rc, PROMPT, the count of `Sending request (` lines, the error text after the program-name prefix, the trace pa-type lines, `klist -C` config lines equal; pcaps are not compared byte for byte.
# Differences from the recorded legs:
#   - ours stage = the installed ship KDC (the legs ran rust-field-p12 snapshots with a copied kinit); the upgrade is otp/install-ours.sh; both clients run every cell (the legs: client2 or client1);
#   - the confs are per-cell copies of the VM's own krb5.conf (KRB5_CONFIG), /etc/krb5.conf is not edited; the armor caches are made by MIT's kinit in both stages (the legs' mit-armor / rust-armor);
#   - PROMPT=yes|no is the password prompt on the program's stdout (the legs' delay_kinit.py printed it); the password arrives on a pipe, no pty; ours run as $VMD/ours/kinit, so error lines say "kinit:" for both;
#   - the sizes of FAST requests are not compared: ours' outer body is 3 bytes longer than MIT's in the legs' captures (R/INDEX.txt "request sizes +3"); the count of requests is;
#   - a capture on the kdc around each group (b2c-vm.sh): the armored logins send FAST in every request, the armor errors send one unarmored request, must2 and encts-off one request and no reply ticket;
#   - two NAMED MASKS in the must2 program parity rows: the text `reply validation: ` in front of "Generic preauthentication failure" (ours text sweep after 1.1; not in
#     docs/mit-deviations*.md at the tip; an INFO row says whether it is still there), and the trace line `Processing preauth types:` (ours' trace stops at `Received error from KDC` when no mechanism is usable:
#     the lines MIT prints after it, `Preauthenticating using KDC method data`, the hint line, `Selected etype info`, `Received cookie`, are absent; an INFO row per login; MIT's hint line is judged);
#   - MIT's trace line `Unrecognized SPAKE group name: nosuch` is not traced by ours (crates/krb5-protocol/src/trace/points.rs:843 spake_unknown_group has no caller): an INFO row per nosuch login, not a parity row.
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

p6g_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${P6G_INIT_DONE:-}" ] && return 0
    P6G_INIT_DONE=1
    b2c_init
    P6G_MASK_RV='s/^PROG: reply validation: /PROG: /'
    P6G_MASK_HINT='/^Processing preauth types: /d'
    P6G_HINT_NOENCTS='PA-FX-FAST \(136\), PA-ETYPE-INFO2 \(19\), PA-SPAKE \(151\), PA-FX-COOKIE \(133\)'
}


p6g_stanza_must2() { printf '# p6g-must2\n[plugins]\n    kdcpreauth = {\n        disable = encrypted_timestamp\n    }\n# p6g-must2-end\n'; }
p6g_stanza_none() { :; }

p6g_prep() { p6g_init; b2c_prep_check; }
p6g_push() { p6g_init; b2c_push_vm kdc client1 client2 && b2c_probe_pcap; }

p6g_confs() {
    local c
    for c in "${CLIENTS[@]}"; do
        b2c_conf p6g "$c" p6g-nosuch --libdefaults-first 'spake_preauth_groups = nosuch' || return 1
        b2c_conf p6g "$c" p6g-encts-off --libdefaults-first 'spake_preauth_groups = nosuch' --realm-first "$REALM" 'disable_encrypted_timestamp = true' || return 1
    done
    return 0
}

# SOURCE RECORD: run.log:10-11 and r4/lab/run.log:14-15 (the armor makers: MIT kinit into FILE: and DIR:, PROMPT=yes, fast_avail yes)
p6g_armor() {   # p6g_armor STAGE CLIENT: the two armor caches (a FILE: one and a DIR: one), MIT's kinit, the nosuch conf (R/r3/lab/run.log:10-11, R/r4/lab/run.log:14-15)
    local st=$1 c=$2 n cc dir
    cc="$VMD/b2c/p6g-armor-$st-$c.cc"; n="p6g/$st-armor-make-file-$c"
    alice_pw | b2c_login "$n" "$c" mit p6g-nosuch --cc "$cc" --then "/usr/bin/klist -C -c FILE:$cc" -- -c "FILE:$cc" "alice@$REALM"
    b2c_chk_login "P6G.$st.armor-make-file-$c" "$OUT/$n.txt" mit
    expect_under "P6G.$st.armor-make-file-$c.fast_avail" "$OUT/$n.txt" '^== then: .*klist -C' "fast_avail\\(krbtgt/$RRX@$RRX\\) = yes\$"
    dir="$VMD/b2c/p6g-armordir-$st-$c"; n="p6g/$st-armor-make-dir-$c"
    alice_pw | b2c_login "$n" "$c" mit p6g-nosuch --cc "$dir" --mkdir "$dir" --then "/usr/bin/klist -C -c DIR:$dir" -- -c "DIR:$dir" "alice@$REALM"
    b2c_chk_login "P6G.$st.armor-make-dir-$c" "$OUT/$n.txt" mit
    expect_under "P6G.$st.armor-make-dir-$c.fast_avail" "$OUT/$n.txt" '^== then: .*klist -C' "fast_avail\\(krbtgt/$RRX@$RRX\\) = yes\$"
}

p6g_fast_arm_ok() {   # p6g_fast_arm_ok FILE: the order of the armed first request (exit status only)
    awk '/Read config in .* fast_avail: yes/ { if (!a) a = NR } /Using FAST due to armor ccache negotiation result/ { if (!b) b = NR } /Sending request \(/ { if (!c) c = NR }
         END { exit !(a && b && c && a < b && b < c) }' "$1"
}

# SOURCE RECORD: run.log:12-34 (-T FILE: MIT KDC), :43-68 (ours KDC); r4/lab/run.log:14-38, :69-94 (-T DIR:); r5/lab/run-5b.log:13-26 (fast_avail arming: lines 4,5,14,29); r3/lab/mit-fast-mit.trace:3-6,24-40
p6g_fast() {   # p6g_fast CLIENT PROG STAGE file|dir
    local c=$1 p=$2 st=$3 kind=$4 spec cc n f l
    case $kind in file) spec="FILE:$VMD/b2c/p6g-armor-$st-$c.cc" ;; dir) spec="DIR:$VMD/b2c/p6g-armordir-$st-$c" ;; esac
    cc="$VMD/b2c/p6g-fast-$kind-$st-$p.cc"; n="p6g/$st-fast-$kind-$p-$c"; f="$OUT/$n.txt"; l="P6G.$st.fast-$kind-$p-$c"
    alice_pw | b2c_login "$n" "$c" "$p" p6g-nosuch --cc "$cc" --then "/usr/bin/klist -C -c FILE:$cc" -- -T "$spec" -c "FILE:$cc" "alice@$REALM"
    b2c_chk_login "$l" "$f" "$p"
    expect "$l.fast-negotiated" "$f" 'Using FAST due to armor ccache negotiation result' 1
    expect "$l.ec-success" "$f" 'Preauth module encrypted_challenge \(138\) \(real\) returned: 0/Success' 2
    expect "$l.two-requests" "$f" 'Sending request \(' 2
    if p6g_fast_arm_ok "$f"; then verdict "$l.fast-arm-order" PASS "fast_avail read < FAST due to armor < the first request" ordered ordered "ordered"
    else verdict "$l.fast-arm-order" FAIL "fast_avail read < FAST due to armor < the first request" ordered "not ordered" ""; fi
    expect_under "$l.fast_avail" "$f" '^== then: .*klist -C' "fast_avail\\(krbtgt/$RRX@$RRX\\) = yes\$"
    expect_under "$l.pa_type-138" "$f" '^== then: .*klist -C' "pa_type\\(krbtgt/$RRX@$RRX\\) = 138\$"
    b2c_chk_unrecognized_spake "$l" "$f" "$p"
}

# SOURCE RECORD: run.log:48-58 and :70-80 (-T MEMORY:p6g), :59-69 and :81-91 (-T FILE:<missing>): rc 1, PROMPT=no, one request, the armor error text; r4/lab/run.log:39-56 is the failing form
p6g_armorerr() {   # p6g_armorerr CLIENT PROG STAGE mem|miss
    local c=$1 p=$2 st=$3 kind=$4 spec txt cc n f l vx=${VMD//./\\.}
    case $kind in
        mem) spec="MEMORY:p6g"; txt='No credentials cache found' ;;
        miss) spec="FILE:$VMD/b2c/no-such-armor.cc"; txt="No credentials cache found \\(filename: $vx/b2c/no-such-armor\\.cc\\)" ;;
    esac
    cc="$VMD/b2c/p6g-armorerr-$kind-$st-$p.cc"; n="p6g/$st-armor-$kind-$p-$c"; f="$OUT/$n.txt"; l="P6G.$st.armor-$kind-$p-$c"
    alice_pw | b2c_login "$n" "$c" "$p" p6g-nosuch --cc "$cc" -- -T "$spec" -c "FILE:$cc" "alice@$REALM"
    b2c_chk_login "$l" "$f" "$p" 1
    expect "$l.no-prompt" "$f" '^PROMPT=no$'
    expect "$l.no-ccache" "$f" '^no ccache was written$'
    expect "$l.one-request" "$f" 'Sending request \(' 1
    expect_under "$l.text" "$f" '^== stderr$' "^kinit: Error constructing AP-REQ armor: $txt while getting initial credentials\$" 1
    expect_under "$l.stderr-one-line" "$f" '^== stderr$' '.' 1
    b2c_chk_unrecognized_spake "$l" "$f" "$p"
}

# SOURCE RECORD: run.log:54-63 (MIT KDC with kdcpreauth disable = encrypted_timestamp: rc 1, PROMPT=no), r2/lab2/mit-noencts-mit.txt:2, mit-noencts-rust.txt:2, mit-noencts-mit.trace:2,12 (the unrecognized-group line and the hint 136,19,151,133); the stanza text: the overseer note (lab-p6g-2.sh:157-162)
p6g_must2() {   # p6g_must2 CLIENT PROG STAGE: the hint has no usable mechanism
    local c=$1 p=$2 st=$3 cc n f l
    cc="$VMD/b2c/p6g-must2-$st-$p.cc"; n="p6g/$st-must2-$p-$c"; f="$OUT/$n.txt"; l="P6G.$st.must2-$p-$c"
    alice_pw | b2c_login "$n" "$c" "$p" p6g-nosuch --cc "$cc" -- -c "FILE:$cc" "alice@$REALM"
    b2c_chk_login "$l" "$f" "$p" 1
    expect "$l.no-prompt" "$f" '^PROMPT=no$'
    expect "$l.no-ccache" "$f" '^no ccache was written$'
    expect "$l.one-request" "$f" 'Sending request \(' 1
    if [ "$p" = mit ]; then expect "$l.hint-line" "$f" "Processing preauth types: $P6G_HINT_NOENCTS\$" 1
    else info "$l.hint-line" "$f" 'Processing preauth types: ' "(none: ours' trace stops at 'Received error from KDC' when no mechanism is usable)"; fi
    expect_under "$l.text" "$f" '^== stderr$' '^kinit: (reply validation: )?Generic preauthentication failure while getting initial credentials$' 1
    info "$l.reply-validation-prefix" "$f" '^kinit: reply validation: ' "(none: no 'reply validation: ' prefix)"
    b2c_chk_unrecognized_spake "$l" "$f" "$p"
}

# SOURCE RECORD: run.log:116-128 and r5/lab/run-5b.log:36-47 (disable_encrypted_timestamp = true as the first value under [realms] REALM, with spake_preauth_groups = nosuch: rc 1, PROMPT=no, one request, the text with MIT's "Pre-authentication failed: " prefix)
p6g_enctsoff() {   # p6g_enctsoff CLIENT PROG STAGE
    local c=$1 p=$2 st=$3 cc n f l
    cc="$VMD/b2c/p6g-enctsoff-$st-$p.cc"; n="p6g/$st-encts-off-$p-$c"; f="$OUT/$n.txt"; l="P6G.$st.encts-off-$p-$c"
    alice_pw | b2c_login "$n" "$c" "$p" p6g-encts-off --cc "$cc" -- -c "FILE:$cc" "alice@$REALM"
    b2c_chk_login "$l" "$f" "$p" 1
    expect "$l.no-prompt" "$f" '^PROMPT=no$'
    expect "$l.no-ccache" "$f" '^no ccache was written$'
    expect "$l.one-request" "$f" 'Sending request \(' 1
    expect_under "$l.text" "$f" '^== stderr$' '^kinit: Pre-authentication failed: Encrypted timestamp is disabled while getting initial credentials$' 1
    info "$l.module-line" "$f" 'Preauth module encrypted_timestamp \(2\) \(real\) returned: '
    b2c_chk_unrecognized_spake "$l" "$f" "$p"
}

p6g_group_rows() {   # p6g_group_rows STAGE GROUP: the capture of a group (n logins)
    local st=$1 g=$2 s l
    [ "$B2C_PCAP" = 1 ] || return 0
    s="$OUT/p6g/pcap-$st-$g.txt"; l="P6G.$st.pcap-$g"
    case $g in
        fast)   # 4 logins x 2 cells, two requests each, FAST in every one
            expect "$l.as-req-count" "$s" '^AS-REQ client=' 16
            expect "$l.krb-error-count" "$s" '^KRB-ERROR client=' 8
            expect "$l.as-rep-count" "$s" '^AS-REP client=' 8
            expect "$l.fast-in-every-request" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 136)\$" 16 ;;
        armorerr)   # 4 logins x 2 cells, one unarmored request each, an error, no reply ticket
            expect "$l.as-req-count" "$s" '^AS-REQ client=' 8
            expect "$l.krb-error-count" "$s" '^KRB-ERROR client=' 8
            expect "$l.as-rep-count" "$s" '^AS-REP client=' 0
            expect "$l.first-request-unarmored" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 136)\$" 0 ;;
        must2)
            expect "$l.as-req-count" "$s" '^AS-REQ client=' 4
            expect "$l.as-rep-count" "$s" '^AS-REP client=' 0
            expect "$l.error-25-hint-without-2" "$s" '^KRB-ERROR client=[^ ]+ code=25 padata=\[136,19,151,133\]$' 4 ;;
        enctsoff)
            expect "$l.as-req-count" "$s" '^AS-REQ client=' 4
            expect "$l.as-rep-count" "$s" '^AS-REP client=' 0
            expect "$l.krb-error-count" "$s" '^KRB-ERROR client=' 4 ;;
    esac
}

# SOURCE RECORD: run.log:47-53 (delay pair start 19:52Z, done 19:58Z; PROMPT=yes) and r2/lab2/mit-delay-mit.trace (Encrypted timestamp (for T) 330 s after the cookie line)
p6g_delay_login() {   # p6g_delay_login STAGE PROG: the delayed password, on client2 (the legs' client)
    local st=$1 p=$2 c=client2 cc n
    cc="$VMD/b2c/p6g-delay-$st-$p.cc"; n="p6g/$st-delay-$p-$c"
    local CELL_TMO=$((${P6G_DELAY_S:-330} + 240))
    alice_pw | b2c_login "$n" "$c" "$p" p6g-nosuch --cc "$cc" --delay "${P6G_DELAY_S:-330}" --then "/usr/bin/klist -C -c FILE:$cc" -- -c "FILE:$cc" "alice@$REALM"
}
p6g_delay_rows() {   # p6g_delay_rows STAGE PROG
    local st=$1 p=$2 f l t0 t1 d ds=${P6G_DELAY_S:-330}
    f="$OUT/p6g/$st-delay-$p-client2.txt"; l="P6G.$st.delay-$p-client2"
    b2c_chk_login "$l" "$f" "$p"
    expect "$l.two-requests" "$f" 'Sending request \(' 2
    expect "$l.no-clock-skew" "$f" 'Clock skew too great' 0
    t0=$(sed -n 's/^\[[0-9]*\] \([0-9.]*\): Received error from KDC.*/\1/p' "$f" | head -n 1)
    t1=$(sed -n 's/.*Encrypted timestamp (for \([0-9.]*\)).*/\1/p' "$f" | head -n 1)
    if [ -n "$t0" ] && [ -n "$t1" ]; then
        d=$(awk -v a="$t1" -v b="$t0" 'BEGIN { printf "%d", a - b }')
        if [ "$d" -ge $((ds - 5)) ] && [ "$d" -le $((ds + 120)) ]; then
            verdict "$l.enc-ts-is-post-prompt" PASS "the encrypted timestamp is $ds s (-5, +120) after the KDC's first answer" in-range "$d s"
        else
            verdict "$l.enc-ts-is-post-prompt" FAIL "the encrypted timestamp is $ds s (-5, +120) after the KDC's first answer" in-range "$d s"
        fi
    else
        verdict "$l.enc-ts-is-post-prompt" FAIL "trace lines 'Received error from KDC' and 'Encrypted timestamp (for T)' exist" present "t0=[$t0] T=[$t1]"
    fi
}

p6g_stage() {   # p6g_stage mit|ours
    local st=$1 c
    b2c_kdc_ready p6g "$st" || return 0
    p6g_confs || { b2c_not_run "P6G.$st.confs" "no conf copies"; return 0; }
    for c in "${CLIENTS[@]}"; do p6g_armor "$st" "$c"; done
    b2c_pcap_start p6g "$st-fast"
    b2c_each_cp p6g_fast "$st" file
    b2c_each_cp p6g_fast "$st" dir
    b2c_pcap_stop p6g "$st-fast"; p6g_group_rows "$st" fast
    b2c_pcap_start p6g "$st-armorerr"
    b2c_each_cp p6g_armorerr "$st" mem
    b2c_each_cp p6g_armorerr "$st" miss
    b2c_pcap_stop p6g "$st-armorerr"; p6g_group_rows "$st" armorerr
    b2c_pcap_start p6g "$st-enctsoff"
    b2c_each_cp p6g_enctsoff "$st"
    b2c_pcap_stop p6g "$st-enctsoff"; p6g_group_rows "$st" enctsoff
    # must-2: the KDC's hint has neither the encrypted timestamp nor a usable SPAKE
    set_conf "p6g/$st-kdcconf-must2" p6g_stanza_must2
    restart_cell "p6g/$st-kdc-restart-must2" "sudo bash $VMD/vmctl.sh svc-restart"
    expect "P6G.$st.must2.kdc-restart-active" "$OUT/p6g/$st-kdc-restart-must2.txt" '^krb5kdc\.service: active$'
    expect "P6G.$st.must2.kdc-conf-has-stanza" "$OUT/p6g/$st-kdcconf-must2.txt" '^\+ +disable = encrypted_timestamp$'
    b2c_pcap_start p6g "$st-must2"
    b2c_each_cp p6g_must2 "$st"
    b2c_pcap_stop p6g "$st-must2"; p6g_group_rows "$st" must2
    set_conf "p6g/$st-kdcconf-clear" p6g_stanza_none
    restart_cell "p6g/$st-kdc-restart-clear" "sudo bash $VMD/vmctl.sh svc-restart"
    expect "P6G.$st.kdc-clear.restart-active" "$OUT/p6g/$st-kdc-restart-clear.txt" '^krb5kdc\.service: active$'
    if [ "${P6G_DELAY:-0}" = 1 ]; then   # last: the pair of delayed logins (MIT and ours at once)
        ( p6g_delay_login "$st" mit ) &
        ( p6g_delay_login "$st" ours ) &
        wait
        p6g_delay_rows "$st" mit; p6g_delay_rows "$st" ours
    else
        b2c_not_run "P6G.$st.delay" "the 330 s delayed-prompt cell is off (P6G_DELAY=1 turns it on)"
    fi
    return 0
}
p6g_mit() { p6g_init; p6g_stage mit; }
p6g_ours() { p6g_init; p6g_stage ours; }

p6g_parity() {
    p6g_init
    local st c p k cells="fast-file fast-dir armor-mem armor-miss must2 encts-off" g
    local -a masks
    [ "${P6G_DELAY:-0}" = 1 ] && cells="$cells delay"
    for k in $cells; do
        masks=(); [ "$k" = must2 ] && masks=("$P6G_MASK_RV" "$P6G_MASK_HINT")
        for c in "${CLIENTS[@]}"; do
            [ "$k" = delay ] && [ "$c" != client2 ] && continue
            # the KDC changes, the program does not
            for p in mit ours; do
                b2c_cmp "P6G.parity.$k-xkdc-$p-$c" "$OUT/p6g/mit-$k-$p-$c.txt" "$OUT/p6g/ours-$k-$p-$c.txt"
            done
            # the program changes, the KDC does not (must2: the named mask for the 'reply validation: ' prefix)
            for st in mit ours; do
                b2c_cmp "P6G.parity.$k-prog-$st-$c" "$OUT/p6g/$st-$k-mit-$c.txt" "$OUT/p6g/$st-$k-ours-$c.txt" "${masks[@]}"
            done
        done
    done
    if [ "$B2C_PCAP" = 1 ]; then
        for g in fast armorerr enctsoff must2; do
            parity_eq "P6G.parity.pcap-$g" "$OUT/p6g/pcap-mit-$g.txt" "$OUT/p6g/pcap-ours-$g.txt" '/^#/d'
        done
    fi
    # controls: different cells differ; a doctored copy differs; the arm-order rule fails on a reversed trace; the captures of two groups differ
    b2c_differ P6G.parity.control.fast-file-vs-armor-miss "$OUT/p6g/mit-fast-file-mit-${CLIENTS[0]}.txt" "$OUT/p6g/mit-armor-miss-mit-${CLIENTS[0]}.txt"
    b2c_differ P6G.parity.control.must2-vs-encts-off "$OUT/p6g/mit-must2-mit-${CLIENTS[0]}.txt" "$OUT/p6g/mit-encts-off-mit-${CLIENTS[0]}.txt"
    b2c_cmp_control "P6G.parity.fast-file-xkdc-mit-${CLIENTS[0]}"
    tac "$OUT/p6g/mit-fast-file-mit-${CLIENTS[0]}.txt" > "$OUT/p6g/norm/fast-file-reversed.txt"
    if p6g_fast_arm_ok "$OUT/p6g/norm/fast-file-reversed.txt"; then verdict P6G.parity.control.fast-arm-rule FAIL "the arm-order rule on a reversed trace must fail" fails passes ""
    else verdict P6G.parity.control.fast-arm-rule PASS "the arm-order rule on a reversed trace must fail" fails fails ""; fi
    if [ "$B2C_PCAP" = 1 ]; then
        if cmp -s <(sed '/^#/d' "$OUT/p6g/pcap-mit-fast.txt") <(sed '/^#/d' "$OUT/p6g/pcap-mit-armorerr.txt"); then
            verdict P6G.parity.control.pcap-fast-vs-armorerr FAIL "the capture summaries of two groups must differ" differ same ""
        else
            verdict P6G.parity.control.pcap-fast-vs-armorerr PASS "the capture summaries of two groups must differ" differ differ ""
        fi
    fi
    return 0
}

p6g_clean() {
    p6g_init
    set_conf p6g/clean-kdcconf p6g_stanza_none > /dev/null 2>&1
    b2c_clean_vms
    return 0
}
