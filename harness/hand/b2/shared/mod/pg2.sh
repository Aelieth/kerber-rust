# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/pg2.sh: B2 module PG2, `[plugins] kdcpreauth` disable / enable_only encrypted_timestamp on the KDC (b2-client; spec: spec/pg2.md).
# Record of the recorded leg (R). Landed 5679818f (tree a32bc3d9); proof hold 2026-10-08 00:29:16-00:34:12Z, R/lab/driver.log (every cell), R/lab/install.txt, per-cell R/lab/*.{rc,out,err,trace}, pcaps R/lab/*.pcap.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade) x stanza x client x program (MIT's kinit, ours) = 16 logins and 4 captures on the kdc:
#   disable      kdc.conf [plugins] kdcpreauth = { disable = encrypted_timestamp }      the KDC's hint is 136, 19, 151, 133 (no 2); the client takes SPAKE (151)   (R/lab/driver.log:23-65 MIT KDC, :189-231 ours)
#   enable       kdc.conf [plugins] kdcpreauth = { enable_only = encrypted_timestamp }  the hint is 136, 19, 2, 133 (no 151); the client takes the encrypted timestamp (2)  (R/lab/driver.log:69-111, :237-279)
#   per login: rc 0, stdout exactly the 33-byte password prompt, stderr empty, no "ok" or JSON line from ours (R/lab/driver.log "RC:0 OUT_BYTES:33 ERR_BYTES:0 HOOKS:no")
# The leg's parity rule: the KDC's hint (read from the MIT client's trace) equal on MIT's and ours KDC for each stanza; rc 0 and the used mechanism equal for all four client x program combinations.
# Differences from the recorded leg:
#   - the upgrade is otp/install-ours.sh (docs/install.md + dist/install.sh); the leg's `dnf install make` was only for `make install` and is not needed; the stanza is cleared before the upgrade (state rows: config as found);
#   - the client is the VM's own krb5.conf as a per-cell copy (KRB5_CONFIG=$VMD/b2c/pg2-base.conf); /etc/krb5.conf is not edited; both programs run on both clients, as in the leg;
#   - the capture is tcpdump -i any -Z root 'port 88' started by helpers/b2c-vm.sh around each stanza group (the leg: a transient pg2-pcap.service); the pcap stays on the host ($W/b2c-pcap), the record keeps a summary
#     of message kinds, error codes, padata types and the client principal of each exchange (helpers/b2c-pcap.py --names), no cookie or ciphertext; the KDC-side KRB5_TRACE file of the leg is not taken (the ours KDC wrote none either): the cell's KDC log lines are the KDC record;
#   - ADDED rows: `klist -C` of each login's cache (MIT's klist reads both programs' caches): pa_type 151 (disable) / 2 (enable), and the pcap rows (below);
#   - the pcap rows judge the exchanges of the cell's OWN principal only (alice@REALM, the name MIT's KDC log gives every login: the kdc-issue rows), in both stages: the summary carries the client principal of each
#     exchange (b2c-pcap.py --names) and pg2_own keeps the lines of alice. Added after the B2 hold of 2026-10-13, whose MIT-stage `enable` window also held client1's own NFS machinery (AS exchanges for host/client1@ and
#     host/client1.kerber.test@, four TGS-REQ for nfs/zima-nas answered code 7), all from client1's address, which also ran the cell's logins: the address cannot tell them apart, the name does. Per capture the
#     MIT oracle's counts of the own exchanges are exact in the hold (disable and enable alike, 16 messages: 8 AS-REQ, 4 KRB-ERROR 25, 4 AS-REP), and ours' were the same 16, line for line. What the kdc saw besides
#     is kept, not judged: INFO rows with the unfiltered counts per kind and the other client names, in both stages (PG2.<stage>.<cell>.pcap.all-*, .other-names), and PG2.parity.<cell>-pcap-unfiltered.
# The OTP1/OTP2 `otp` kdcpreauth module is now in the ship KDC's registry; no cell disables it (the leg could not have, `disable = otp` matched nothing then).
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

pg2_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${PG2_INIT_DONE:-}" ] && return 0
    PG2_INIT_DONE=1
    b2c_init
    PG2_HINT_disable='PA-FX-FAST \(136\), PA-ETYPE-INFO2 \(19\), PA-SPAKE \(151\), PA-FX-COOKIE \(133\)'
    PG2_HINT_enable='PA-FX-FAST \(136\), PA-ETYPE-INFO2 \(19\), PA-ENC-TIMESTAMP \(2\), PA-FX-COOKIE \(133\)'
    PG2_PROD_disable='PA-FX-COOKIE \(133\), PA-SPAKE \(151\)'
    PG2_PROD_enable='PA-FX-COOKIE \(133\), PA-ENC-TIMESTAMP \(2\)'
    PG2_PATYPE_disable=151
    PG2_PATYPE_enable=2
    PG2_PCAPHINT_disable='136,19,151,133'
    PG2_PCAPHINT_enable='136,19,2,133'
    PG2_OTHER_disable=2
    PG2_OTHER_enable=151
}

pg2_stanza_disable() { printf '# pg2-kdcpreauth\n[plugins]\n    kdcpreauth = {\n        disable = encrypted_timestamp\n    }\n# pg2-kdcpreauth-end\n'; }
pg2_stanza_enable() { printf '# pg2-kdcpreauth\n[plugins]\n    kdcpreauth = {\n        enable_only = encrypted_timestamp\n    }\n# pg2-kdcpreauth-end\n'; }
pg2_stanza_none() { :; }

# what the client sees per stanza: the KDC's hint (first "Processing preauth types:" line), the second request's padata, the mechanism's type

pg2_prep() { pg2_init; b2c_prep_check; }
pg2_push() { pg2_init; b2c_push_vm kdc client1 client2 && b2c_probe_pcap; }

pg2_kdc() {   # pg2_kdc STAGE disable|enable|clear: the stanza in kdc.conf (set_conf), krb5kdc restarted and active
    local st=$1 which=$2 fn=pg2_stanza_none
    [ "$which" = clear ] || fn=pg2_stanza_$which
    set_conf "pg2/$st-kdcconf-$which" "$fn"
    restart_cell "pg2/$st-kdc-restart-$which" "sudo bash $VMD/vmctl.sh svc-restart"
    expect "PG2.$st.kdc-$which.restart-active" "$OUT/pg2/$st-kdc-restart-$which.txt" '^krb5kdc\.service: active$'
    expect "PG2.$st.kdc-$which.operating" "$OUT/pg2/$st-kdc-restart-$which.txt" 'commencing operation'
    case $which in
        disable) expect "PG2.$st.kdc-$which.conf-has-stanza" "$OUT/pg2/$st-kdcconf-$which.txt" '^\+ +disable = encrypted_timestamp$' ;;
        enable) expect "PG2.$st.kdc-$which.conf-has-stanza" "$OUT/pg2/$st-kdcconf-$which.txt" '^\+ +enable_only = encrypted_timestamp$' ;;
    esac
}

# SOURCE RECORD: driver.log:22-111 (MIT KDC: cells disable and enable, 2 clients x 2 programs: RC:0 OUT_BYTES:33 ERR_BYTES:0 and the Processing preauth types lines) and :188-283 (ours KDC); lab/oracle: settle.txt
pg2_login() {   # pg2_login CLIENT PROG STAGE CELL
    local c=$1 p=$2 st=$3 cn=$4 cc n f l hint prod pat
    cc="$VMD/b2c/pg2-$st-$cn-$p.cc"; n="pg2/$st-$cn-$p-$c"; f="$OUT/$n.txt"; l="PG2.$st.$cn-$p-$c"
    eval "hint=\$PG2_HINT_$cn prod=\$PG2_PROD_$cn pat=\$PG2_PATYPE_$cn"
    alice_pw | b2c_login "$n" "$c" "$p" pg2-base --cc "$cc" \
        --then "/usr/bin/klist -C -c FILE:$cc" \
        -- -c "FILE:$cc" alice
    b2c_chk_login "$l" "$f" "$p"
    expect "$l.hint-line" "$f" "Processing preauth types: $hint\$" 1
    expect "$l.produced" "$f" "Produced preauth for next request: $prod\$" 1
    expect "$l.second-round" "$f" 'Processing preauth types: PA-ETYPE-INFO2 \(19\)$' 1
    expect_under "$l.pa_type" "$f" '^== then: .*klist -C' "pa_type\\(krbtgt/$RRX@$RRX\\) = $pat\$"
    expect_part "$l.kdc-issue" "$f" kdc "AS_REQ .*ISSUE: .*alice@$RRX for krbtgt/$RRX@$RRX" 1
    info "$l.kdc-needed-preauth" "$f" 'NEEDED_PREAUTH'
}

pg2_own() {   # pg2_own SUMMARY: the lines of a capture summary (b2c_pcap_stop --names) whose exchange is the cell's own principal's, alice@REALM, with the cname= field taken off (the lines then read as the
    # summaries of every other module do). A TGS-REQ names nobody (the client is inside the ticket), so none is kept; a reply that names another client (a KRB-ERROR for another host's TGS) is not kept either.
    grep -E "^(AS-REQ|AS-REP|KRB-ERROR) client=[^ ]+ cname=alice@$RRX( |\$)" "$1" | sed -E 's/ cname=[^ ]+//'
}

# SOURCE RECORD: {mit,rust}-{disable,enable}.pcap (the leg kept the captures; this module keeps a summary) and oracle/settle.txt:3-5 and :8-9 (error 25 with types 136,19,151,133 / 136,19,2,133)
pg2_pcap_rows() {   # pg2_pcap_rows STAGE CELL: what the kdc saw on the wire for the cell's own principal, from the summary (4 logins = 8 AS-REQ, 4 KRB-ERROR, 4 AS-REP); then, not judged, everything it saw
    local st=$1 cn=$2 s o l hint other other_names
    [ "$B2C_PCAP" = 1 ] || return 0
    s="$OUT/pg2/pcap-$st-$cn.txt"; o="$OUT/pg2/pcap-$st-$cn-own.txt"; l="PG2.$st.$cn.pcap"
    eval "hint=\$PG2_PCAPHINT_$cn other=\$PG2_OTHER_$cn"
    pg2_own "$s" > "$o"
    expect "$l.as-req-count" "$o" '^AS-REQ client=' 8
    expect "$l.krb-error-count" "$o" '^KRB-ERROR client=' 4
    expect "$l.as-rep-count" "$o" '^AS-REP client=' 4
    expect "$l.error-25-hint" "$o" "^KRB-ERROR client=[^ ]+ code=25 padata=\\[$hint\\]\$" 4
    expect "$l.preauthed-request" "$o" "^AS-REQ client=[^ ]+ $(b2c_pa_rx "$(eval echo "\$PG2_PATYPE_$cn")")\$" 4
    expect "$l.never-the-other-mechanism" "$o" "^AS-REQ client=[^ ]+ $(b2c_pa_rx "$other")\$" 0
    # recorded, not judged: every message the kdc saw in the window, whoever sent it (any extra exchange of ours stays visible here), and the client names of the ones that are not alice's
    info "$l.all-as-req" "$s" '^AS-REQ client='
    info "$l.all-krb-error" "$s" '^KRB-ERROR client='
    info "$l.all-as-rep" "$s" '^AS-REP client='
    info "$l.all-tgs-req" "$s" '^TGS-REQ client='
    other_names=$(grep -E '^[A-Z-]+ client=' "$s" | grep -v -E " cname=alice@$RRX( |\$)" | sed -E 's/^([A-Z-]+) client=([^ ]+) cname=([^ ]+).*/\1 \3/' | sort | uniq -c | sed -E 's/^ *([0-9]+) /\1x /' | paste -sd ';' -)
    result "$l.other-names" INFO "messages of the window that are not alice@$REALM's exchanges (not judged)" - "$(grep -E '^[A-Z-]+ client=' "$s" | grep -c -v -E " cname=alice@$RRX( |\$)")" "${other_names:-(none)}"
}

pg2_stage() {   # pg2_stage mit|ours
    local st=$1 cn c
    b2c_kdc_ready pg2 "$st" || return 0
    for c in "${CLIENTS[@]}"; do
        b2c_conf pg2 "$c" pg2-base || { b2c_not_run "PG2.$st.conf-$c" "no conf copy on $c"; return 0; }
    done
    for cn in disable enable; do
        pg2_kdc "$st" "$cn"
        b2c_pcap_start pg2 "$st-$cn"
        b2c_each_cp pg2_login "$st" "$cn"
        b2c_pcap_stop pg2 "$st-$cn" --names
        pg2_pcap_rows "$st" "$cn"
    done
    pg2_kdc "$st" clear
    return 0
}
pg2_mit() { pg2_init; pg2_stage mit; }
pg2_ours() { pg2_init; pg2_stage ours; }

pg2_all_row() {   # pg2_all_row CELL: INFO, not judged: the unfiltered capture summaries of the two stages (every message the kdc saw in the window) side by side
    local cn=$1 a="$OUT/pg2/pcap-mit-$1.txt" b="$OUT/pg2/pcap-ours-$1.txt" na nb eq=equal
    na=$(grep -c -v '^#' "$a" 2> /dev/null); nb=$(grep -c -v '^#' "$b" 2> /dev/null)
    cmp -s <(sed '/^#/d' "$a") <(sed '/^#/d' "$b") || eq=DIFFER
    result "PG2.parity.$cn-pcap-unfiltered" INFO "unfiltered capture summaries, MIT's stage against ours (not judged: other hosts' traffic in the window shows here)" - "$eq" "MIT ${na:-0} messages, ours ${nb:-0} messages"
}

pg2_parity() {
    pg2_init
    local cn st c p
    for cn in disable enable; do
        # the KDC changes, the client does not: the hint, the mechanism and the whole core of a login equal on MIT's KDC and ours (the leg's rule)
        for p in mit ours; do
            for c in "${CLIENTS[@]}"; do
                b2c_cmp "PG2.parity.$cn-xkdc-$p-$c" "$OUT/pg2/mit-$cn-$p-$c.txt" "$OUT/pg2/ours-$cn-$p-$c.txt"
            done
        done
        # the programs differ, the KDC does not: MIT's kinit and ours equal in each stage
        for st in mit ours; do
            for c in "${CLIENTS[@]}"; do
                b2c_cmp "PG2.parity.$cn-prog-$st-$c" "$OUT/pg2/$st-$cn-mit-$c.txt" "$OUT/pg2/$st-$cn-ours-$c.txt"
            done
        done
        # the wire: the exchanges of the cell's own principal equal on the two stages (the same filter on both: pg2_own); the unfiltered summaries are compared in an INFO row, not judged
        if [ "$B2C_PCAP" = 1 ]; then
            parity_eq "PG2.parity.$cn-pcap" "$OUT/pg2/pcap-mit-$cn-own.txt" "$OUT/pg2/pcap-ours-$cn-own.txt"
            pg2_all_row "$cn"
        fi
    done
    # controls: the two stanzas' logins must differ, a doctored copy must differ
    b2c_differ PG2.parity.control.disable-vs-enable "$OUT/pg2/mit-disable-mit-${CLIENTS[0]}.txt" "$OUT/pg2/ours-enable-mit-${CLIENTS[0]}.txt"
    b2c_cmp_control "PG2.parity.disable-xkdc-mit-${CLIENTS[0]}"
    [ "$B2C_PCAP" = 1 ] || return 0
    if cmp -s "$OUT/pg2/pcap-mit-disable-own.txt" "$OUT/pg2/pcap-mit-enable-own.txt"; then
        verdict PG2.parity.control.pcap-disable-vs-enable FAIL "the capture summaries of the two stanzas must differ" differ same ""
    else
        verdict PG2.parity.control.pcap-disable-vs-enable PASS "the capture summaries of the two stanzas must differ" differ differ ""
    fi
    return 0
}

pg2_clean() {
    pg2_init
    set_conf pg2/clean-kdcconf pg2_stanza_none > /dev/null 2>&1
    b2c_clean_vms
    return 0
}
