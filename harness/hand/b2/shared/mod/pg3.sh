# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/pg3.sh: B2 module PG3, `[plugins] clpreauth` disable / disable + armor / enable_only encrypted_timestamp in the CLIENT's krb5.conf (b2-client; spec: spec/pg3.md).
# Record of the recorded leg (R). Landed ee9e127d (tree ab1ce1f2, "client: Run the first FAST preauth the hint lists"); proof hold r3 2026-10-08 16:50:12-16:54:28Z, R/lab/driver-r3.log (33 KB);
# r2 (R/lab/driver-r2.log) found the armor cell MIT SPAKE 151 against the then-ours 138, fixed in the code, so r3 is the proof.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade) x cell x client x program (MIT's kinit, ours) = 24 logins and 6 captures on the kdc; the KDC has no stanza:
#   disable        client [plugins] clpreauth = { disable = encrypted_timestamp }      hint 136, 19, 151, 2, 133; the client runs SPAKE, never enc-ts, never 138: produced 133, 151        (R/lab/driver-r3.log:60-127 MIT KDC, :361-444 ours)
#   disable-armor  the same stanza and `-T FILE:<armor ccache>` (a TGT from the same KDC made without a stanza): hint 136, 19, 151, 138, 133, 137; SPAKE first under FAST (ee9e127d): produced 133, 151   (:145-213, :460-529)
#   enable         client [plugins] clpreauth = { enable_only = encrypted_timestamp }   hint 136, 19, 151, 2, 133; the client runs enc-ts: produced 133, 2                                (:229-304, :545-594)
#   per login: rc 0, stdout exactly the 33-byte prompt, stderr empty (R/lab/driver-r3.log "RC:0 OUT_BYTES:33 ERR_BYTES:0")
#   ADDED (the brief's note; not in the recorded leg): disable-armor-ec = the disable stanza plus `spake_preauth_groups = nosuch` (first relation under [libdefaults]) with -T: SPAKE is unusable, so the encrypted
#   challenge (138) runs under FAST in both programs. Without that line the armored cell takes SPAKE first (the recorded disable-armor cell), so type 138 is only seen with it (trace lines as P6g r3 mit-fast-mit.trace:24-40).
# Parity rule of the leg: per cell, client and KDC, MIT's lines == ours on every cell and on both KDCs, stderr empty; the capture is evidence (pa-data types), not compared byte for byte.
# Differences from the recorded leg:
#   - the upgrade is otp/install-ours.sh (no `dnf install make`); the client stanza is a per-cell copy of the VM's own krb5.conf (KRB5_CONFIG=$VMD/b2c/pg3-*.conf); /etc/krb5.conf is not edited and "STANZA clear" is
#     the pg3-base copy (the armor ccache is made with it by MIT's kinit, as the leg's ARMOR_RC:0);
#   - the capture is tcpdump on the kdc started by helpers/b2c-vm.sh (the leg: user tcpdump); the pcap stays on the host, the record keeps message kinds, error codes and padata types; under FAST the outer padata
#     is all a capture shows, so the capture rows of the armored cells are counts and the cross-stage equality, the hint rows are those of the unarmored cells;
#   - ADDED rows: `klist -C` of each cache (pa_type), the KDC log's ISSUE line per login.
# The OTP3 `otp` clpreauth module is now in the registry PG3 filters (148a6dac); no cell disables it. `sam2` is absent (docs/mit-deviations.md:34).
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

pg3_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${PG3_INIT_DONE:-}" ] && return 0
    PG3_INIT_DONE=1
    b2c_init
    PG3_HINT_plain='PA-FX-FAST \(136\), PA-ETYPE-INFO2 \(19\), PA-SPAKE \(151\), PA-ENC-TIMESTAMP \(2\), PA-FX-COOKIE \(133\)'
    PG3_HINT_armor='PA-FX-FAST \(136\), PA-ETYPE-INFO2 \(19\), PA-SPAKE \(151\), PA-ENCRYPTED-CHALLENGE \(138\), PA-FX-COOKIE \(133\), PA-FX-ERROR \(137\)'
    PG3_CELLS="disable disable-armor enable disable-armor-ec"
}

pg3_stanza_disable() { printf '# pg3-clpreauth\n[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n    }\n# pg3-clpreauth-end\n'; }
pg3_stanza_enable() { printf '# pg3-clpreauth\n[plugins]\n    clpreauth = {\n        enable_only = encrypted_timestamp\n    }\n# pg3-clpreauth-end\n'; }


pg3_prep() { pg3_init; b2c_prep_check; }
pg3_push() { pg3_init; b2c_push_vm kdc client1 client2 && b2c_probe_pcap; }

pg3_confs() {   # pg3_confs: the client copies, per client
    local c
    for c in "${CLIENTS[@]}"; do
        b2c_conf pg3 "$c" pg3-base || return 1
        b2c_conf pg3 "$c" pg3-disable --append-text "$(pg3_stanza_disable)" || return 1
        b2c_conf pg3 "$c" pg3-enable --append-text "$(pg3_stanza_enable)" || return 1
        b2c_conf pg3 "$c" pg3-disable-nosuch --libdefaults-first 'spake_preauth_groups = nosuch' --append-text "$(pg3_stanza_disable)" || return 1
    done
    return 0
}

# SOURCE RECORD: driver-r3.log:40-43 (STANZA clear / ARMOR_RC:0: the armor ccache made without a stanza)
pg3_armor() {   # pg3_armor CLIENT STAGE: the armor ccache, MIT's kinit with no stanza (the leg's "STANZA clear / ARMOR_RC:0")
    local c=$1 st=$2 n cc
    n="pg3/$st-armor-make-$c"; cc="$VMD/b2c/pg3-armor-$st-$c.cc"
    alice_pw | b2c_login "$n" "$c" mit pg3-base --cc "$cc" --then "/usr/bin/klist -C -c FILE:$cc" -- -c "FILE:$cc" alice
    b2c_chk_login "PG3.$st.armor-make-$c" "$OUT/$n.txt" mit
    expect_under "PG3.$st.armor-make-$c.fast_avail" "$OUT/$n.txt" '^== then: .*klist -C' "fast_avail\\(krbtgt/$RRX@$RRX\\) = yes\$"
}

# SOURCE RECORD: driver-r3.log:44-128 (mit-disable), :129-213 (mit-disable-armor), :214-304 (mit-enable), :356-444, :445-529, :530-594 (the same on the ours KDC); disable-armor-ec: the brief, with mit-fast-mit.trace:24-40 for the lines
pg3_login() {   # pg3_login CLIENT PROG STAGE CELL
    local c=$1 p=$2 st=$3 cn=$4 cc n f l conf hint prod kind="plain" targs=()
    cc="$VMD/b2c/pg3-$st-$cn-$p.cc"; n="pg3/$st-$cn-$p-$c"; f="$OUT/$n.txt"; l="PG3.$st.$cn-$p-$c"
    case $cn in
        disable) conf=pg3-disable; prod='PA-FX-COOKIE \(133\), PA-SPAKE \(151\)' ;;
        disable-armor) conf=pg3-disable; prod='PA-FX-COOKIE \(133\), PA-SPAKE \(151\)'; kind=armor; targs=(-T "FILE:$VMD/b2c/pg3-armor-$st-$c.cc") ;;
        enable) conf=pg3-enable; prod='PA-FX-COOKIE \(133\), PA-ENC-TIMESTAMP \(2\)' ;;
        disable-armor-ec) conf=pg3-disable-nosuch; prod='PA-FX-COOKIE \(133\), PA-ENCRYPTED-CHALLENGE \(138\)'; kind=armor; targs=(-T "FILE:$VMD/b2c/pg3-armor-$st-$c.cc") ;;
    esac
    eval "hint=\$PG3_HINT_$kind"
    alice_pw | b2c_login "$n" "$c" "$p" "$conf" --cc "$cc" --then "/usr/bin/klist -C -c FILE:$cc" -- "${targs[@]}" -c "FILE:$cc" alice
    b2c_chk_login "$l" "$f" "$p"
    expect "$l.hint-line" "$f" "Processing preauth types: $hint\$" 1
    expect "$l.produced" "$f" "Produced preauth for next request: $prod\$" 1
    case $cn in
        disable|disable-armor)
            expect "$l.never-enc-ts" "$f" 'Produced preauth for next request:.*PA-ENC-TIMESTAMP' 0
            expect "$l.never-138" "$f" 'Produced preauth for next request:.*PA-ENCRYPTED-CHALLENGE' 0 ;;
        enable)
            expect "$l.never-spake" "$f" 'Produced preauth for next request:.*PA-SPAKE' 0
            expect "$l.never-138" "$f" 'Produced preauth for next request:.*PA-ENCRYPTED-CHALLENGE' 0 ;;
        disable-armor-ec)
            expect "$l.ec-module" "$f" 'Preauth module encrypted_challenge \(138\) \(real\) returned: 0/Success' 2
            b2c_chk_unrecognized_spake "$l" "$f" "$p"
            expect_under "$l.pa_type" "$f" '^== then: .*klist -C' "pa_type\\(krbtgt/$RRX@$RRX\\) = 138\$" ;;
    esac
    case $cn in
        disable) expect_under "$l.pa_type" "$f" '^== then: .*klist -C' "pa_type\\(krbtgt/$RRX@$RRX\\) = 151\$" ;;
        enable) expect_under "$l.pa_type" "$f" '^== then: .*klist -C' "pa_type\\(krbtgt/$RRX@$RRX\\) = 2\$" ;;
        disable-armor) info "$l.pa_type" "$f" "pa_type\\(krbtgt/" ;;
    esac
    [ "$kind" = armor ] && expect "$l.fast-armor" "$f" 'Using FAST due to armor ccache negotiation result' 1
    expect_part "$l.kdc-issue" "$f" kdc "AS_REQ .*ISSUE: .*alice@$RRX for krbtgt/$RRX@$RRX" 1
}

pg3_pcap_rows() {   # pg3_pcap_rows STAGE GROUP: GROUP = plain-disable, plain-enable, armor (4 logins each; the armor group holds disable-armor and disable-armor-ec = 8 logins)
    local st=$1 g=$2 s l n reqs
    [ "$B2C_PCAP" = 1 ] || return 0
    s="$OUT/pg3/pcap-$st-$g.txt"; l="PG3.$st.pcap-$g"
    case $g in armor) n=8 ;; *) n=4 ;; esac
    reqs=$((n * 2))
    expect "$l.as-req-count" "$s" '^AS-REQ client=' "$reqs"
    expect "$l.krb-error-count" "$s" '^KRB-ERROR client=' "$n"
    expect "$l.as-rep-count" "$s" '^AS-REP client=' "$n"
    case $g in
        plain-disable)
            expect "$l.error-25-only" "$s" '^KRB-ERROR client=[^ ]+ code=25 ' "$n"
            expect "$l.error-25-hint" "$s" '^KRB-ERROR client=[^ ]+ code=25 padata=\[136,19,151,2,133\]$' "$n"
            expect "$l.preauthed-spake" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 151)\$" "$n"
            expect "$l.never-enc-ts" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 2)\$" 0 ;;
        plain-enable)
            expect "$l.error-25-only" "$s" '^KRB-ERROR client=[^ ]+ code=25 ' "$n"
            expect "$l.error-25-hint" "$s" '^KRB-ERROR client=[^ ]+ code=25 padata=\[136,19,151,2,133\]$' "$n"
            expect "$l.preauthed-enc-ts" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 2)\$" "$n"
            expect "$l.never-spake" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 151)\$" 0 ;;
        armor)
            expect "$l.fast-in-every-request" "$s" "^AS-REQ client=[^ ]+ $(b2c_pa_rx 136)\$" "$reqs"
            info "$l.error-hint" "$s" '^KRB-ERROR ' ;;
    esac
}

pg3_stage() {   # pg3_stage mit|ours
    local st=$1 c
    b2c_kdc_ready pg3 "$st" || return 0
    pg3_confs || { b2c_not_run "PG3.$st.confs" "no conf copies"; return 0; }
    for c in "${CLIENTS[@]}"; do pg3_armor "$c" "$st"; done
    b2c_pcap_start pg3 "$st-plain-disable"; b2c_each_cp pg3_login "$st" disable; b2c_pcap_stop pg3 "$st-plain-disable"; pg3_pcap_rows "$st" plain-disable
    b2c_pcap_start pg3 "$st-armor"; b2c_each_cp pg3_login "$st" disable-armor; b2c_each_cp pg3_login "$st" disable-armor-ec; b2c_pcap_stop pg3 "$st-armor"; pg3_pcap_rows "$st" armor
    b2c_pcap_start pg3 "$st-plain-enable"; b2c_each_cp pg3_login "$st" enable; b2c_pcap_stop pg3 "$st-plain-enable"; pg3_pcap_rows "$st" plain-enable
    return 0
}
pg3_mit() { pg3_init; pg3_stage mit; }
pg3_ours() { pg3_init; pg3_stage ours; }

pg3_parity() {
    pg3_init
    local cn st c p g
    for cn in $PG3_CELLS; do
        # the KDC changes, the client does not: the whole core of a login equal on MIT's KDC and ours
        for p in mit ours; do
            for c in "${CLIENTS[@]}"; do
                b2c_cmp "PG3.parity.$cn-xkdc-$p-$c" "$OUT/pg3/mit-$cn-$p-$c.txt" "$OUT/pg3/ours-$cn-$p-$c.txt"
            done
        done
        # the programs differ, the KDC does not: MIT's kinit and ours equal in each stage (the leg's rule: "MIT's lines == ours on every cell and on both KDCs")
        for st in mit ours; do
            for c in "${CLIENTS[@]}"; do
                b2c_cmp "PG3.parity.$cn-prog-$st-$c" "$OUT/pg3/$st-$cn-mit-$c.txt" "$OUT/pg3/$st-$cn-ours-$c.txt"
            done
        done
    done
    # the wire: the capture summaries of the two stages equal per group (the comment lines carry names and packet counts)
    for g in plain-disable armor plain-enable; do
        [ "$B2C_PCAP" = 1 ] && parity_eq "PG3.parity.pcap-$g" "$OUT/pg3/pcap-mit-$g.txt" "$OUT/pg3/pcap-ours-$g.txt" '/^#/d'
    done
    # controls: different cells must differ, a doctored copy must differ, the two stanzas' captures must differ
    b2c_differ PG3.parity.control.disable-vs-enable "$OUT/pg3/mit-disable-mit-${CLIENTS[0]}.txt" "$OUT/pg3/ours-enable-mit-${CLIENTS[0]}.txt"
    b2c_differ PG3.parity.control.disable-vs-armor "$OUT/pg3/mit-disable-mit-${CLIENTS[0]}.txt" "$OUT/pg3/mit-disable-armor-mit-${CLIENTS[0]}.txt"
    b2c_differ PG3.parity.control.armor-vs-armor-ec "$OUT/pg3/mit-disable-armor-mit-${CLIENTS[0]}.txt" "$OUT/pg3/mit-disable-armor-ec-mit-${CLIENTS[0]}.txt"
    b2c_cmp_control "PG3.parity.disable-xkdc-mit-${CLIENTS[0]}"
    [ "$B2C_PCAP" = 1 ] || return 0
    if cmp -s <(sed '/^#/d' "$OUT/pg3/pcap-mit-plain-disable.txt") <(sed '/^#/d' "$OUT/pg3/pcap-mit-plain-enable.txt"); then
        verdict PG3.parity.control.pcap-disable-vs-enable FAIL "the capture summaries of the two stanzas must differ" differ same ""
    else
        verdict PG3.parity.control.pcap-disable-vs-enable PASS "the capture summaries of the two stanzas must differ" differ differ ""
    fi
    return 0
}

pg3_clean() { pg3_init; b2c_clean_vms; return 0; }
