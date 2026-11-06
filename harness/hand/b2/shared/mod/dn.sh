# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/dn.sh: B2 module DN, the client's KDC lookup through DNS SRV records (b2-client; spec: spec/dn.md). Runs last in the hold (with KL), on client1, with a python3 DNS stub on client2 (helpers/dn-stub.py, no dnsmasq, no mirror).
# Records of the recorded leg: lab.txt:1149-1491 (the production run of 2026-10-07 13:37Z), lab-r1..r3.txt and lab-wrap*.txt (the iterations), the pcaps
# krdn-{mit,rust,tc,on-rust}.pcap, the container settles mit-settle/ and mit-dot/; reports of r1 and r2. Landed 24002588 (tree 216c4d25), "client: Look up KDC SRV records through resolv.conf".
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade), on client1 as the lab user, in a private resolver (nameserver = the DNS host, `options timeout:2 attempts:2`, `hosts: files dns`), a krb5.conf
# with `dns_lookup_kdc = true` and no `kdc =` for the realm, MIT's tools (SSSD_KRB5_LOCATOR_DISABLE=1: the sssd locator plugin would skip DNS) and ours ($VMD/ours/{kinit,klist,kvno}), a tcpdump on client1 around each cell:
#   srv  `kinit alice@KERBER.TEST` (password on stdin), `klist`, `kvno krbtgt/KERBER.TEST`   rc 0 0 0, kvno N (record: 1)   SRV queries only to the resolv.conf nameserver, `_kerberos._udp` before `_kerberos._tcp` in every exchange,
#        random IDs and source ports (no ID is 0x1234, the old fixed one), an A query for the target `kdc.kerber.test.`, then the KDC   (R lab.txt:1214-1292 MIT, :1294-1331 ours, against the MIT KDC; :1377-1486 against the ship KDC)
#   tc   `kinit alice@TC.TEST`   rc 1  `Client 'alice@TC.TEST' not found in Kerberos database while getting initial credentials`: the zone answers `_kerberos._udp.TC.TEST.` with the TC bit and no records over UDP, 40 SRV records over
#        TCP; the client retries over TCP (the 2-byte length prefix may come in a segment of its own), `_kerberos._tcp.TC.TEST.` is REFUSED, then it asks A for a target and the KDC answers "not found"   (R lab.txt:1332-1376, ours only)
# Parity rule of the leg: NOT byte equality. Equal: both clients put the SRV queries only to resolv.conf's nameserver, `_udp` before `_tcp`, kinit and kvno rc 0 with the same kvno against both KDCs, random IDs and varying ports.
# Expected to differ (INFO rows, not judged): the packet counts (record: MIT 24 against ours 16 against the MIT KDC: MIT resolves the target twice per send), MIT's URI query, ours does not query URI, `_kerberos-adm`, `_kpasswd` or
# `_kerberos-master` (docs/parity/b1-client.md:64, "deferred").
# Differences from the recorded leg:
#   - the DNS server is helpers/dn-stub.py on client2 (the leg: dnsmasq from the mirror on the services VM, which B2 does not start); its zone is the recorded one: `_kerberos._udp` and `_kerberos._tcp` KERBER.TEST -> `0 10 88 kdc.kerber.test.`,
#     `_kerberos-adm._tcp` served although no client asks, `_kerberos._udp.TC.TEST.` with 40 targets `very-long-kdc-target-name-for-truncation-NN.tc.kerber.test.` (cut over UDP), A for them all -> the KDC; AAAA and every other name are REFUSED
#     as dnsmasq did (the recorded AAAA answers were `Refused`); the KDC's address is read from the VM's own krb5.conf;
#   - client1's resolver is NOT edited (the leg rewrote resolv.conf, nsswitch.conf and stopped systemd-resolved, and put them back): each command runs in a private mount namespace with two bind-mounted files (helpers/dn-vm.sh nsrun);
#     rows prove the VM's own files are byte for byte what they were;
#   - the ours stage is dist/install.sh's upgrade of the final ship build, not `make install` after a snapshot revert; both programs run in both stages; the leg's `kvno` of ours is the shell's $VMD/ours/kvno;
#   - the pcap summarizer is b2c-pcap.py flow (the leg's own summary printed zeros): one line per DNS query, answer and KDC attempt; the judged properties are computed from those lines (spec/dn.md).
# NOT BUILT (container-only cells of the leg, no VM cell): the root target `..`, resolver timeouts, EDNS (mit-settle/, mit-dot/); the root target is a KL cell.
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"
# shellcheck source=/dev/null
declare -F dnl_init > /dev/null || . "$SCRIPTS/helpers/dn-lib.sh"

dn_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${DN_INIT_DONE:-}" ] && return 0
    DN_INIT_DONE=1
    dnl_init
    DN_TC_TARGETS=40
    DN_MASK=('s#^(/[^ :]*/)?(krb5-)?(kinit|klist|kvno): #PROG: #'
             's#/b2c/dn-(mit|ours)-(mit|ours)-#/b2c/dn-STAGE-TOOL-#g')
}

dn_prep() { dn_init; dnl_prep_check; }
dn_push() { dn_init; dnl_push; }

dn_zone() {   # the zone: R lab.txt:1196-1199 (names and shapes), the answers' priority and weight `0 10` (tcpdump: `SRV kdc.kerber.test.:88 0 10`)
    local i
    printf 'ROTATE\n'
    printf 'SRV _kerberos._udp.%s. 0 10 %s kdc.kerber.test.\n' "$REALM" "$DNL_KDC_PORT"
    printf 'SRV _kerberos._tcp.%s. 0 10 %s kdc.kerber.test.\n' "$REALM" "$DNL_KDC_PORT"
    printf 'SRV _kerberos-adm._tcp.%s. 0 10 749 kdc.kerber.test.\n' "$REALM"
    printf 'A kdc.kerber.test. %s\n' "$DNL_KDC_IP"
    printf 'UDPTC _kerberos._udp.TC.TEST.\n'
    for i in $(seq 1 "$DN_TC_TARGETS"); do
        printf 'SRV _kerberos._udp.TC.TEST. 0 10 %s very-long-kdc-target-name-for-truncation-%02d.tc.kerber.test.\n' "$DNL_KDC_PORT" "$i"
        printf 'A very-long-kdc-target-name-for-truncation-%02d.tc.kerber.test. %s\n' "$i" "$DNL_KDC_IP"
    done
}

dn_conf_text() {   # the client's krb5.conf: DNS only (R lab.txt:1196-1199 "dns_lookup_kdc = true and no [realms] kdc")
    printf '[libdefaults]\n    default_realm = %s\n    dns_lookup_kdc = true\n    dns_lookup_realm = false\n    rdns = false\n' "$REALM"
}

dn_flow_rows() {   # dn_flow_rows LABEL FLOWFILE: what the DNS and KDC side of a successful srv cell must show (the record's "equal" list), then the counts (INFO)
    local l=$1 f=$2 nsx n nq nns ids ports nsrv seqs
    nsx=${DNL_NS_IP//./\\.}
    nq=$(dnl_count "$f" '^T\+[0-9.]+ DNS-Q ')
    nsrv=$(dnl_count "$f" '^T\+[0-9.]+ DNS-Q [a-z]+ to=[0-9.]+ id=[0-9]+ sport=[0-9]+ SRV _kerberos\._(udp|tcp)\.')
    nns=$(dnl_count "$f" "^T\\+[0-9.]+ DNS-Q [a-z]+ to=$nsx id=[0-9]+ sport=[0-9]+ SRV _kerberos\\._(udp|tcp)\\.")
    verdict "$l.srv-queries-only-to-ns" "$([ "${nsrv:-0}" -ge 1 ] && [ "$nsrv" = "$nns" ] && echo PASS || echo FAIL)" "every SRV query goes to resolv.conf's nameserver $DNL_NS_IP (the record: both clients put them only there)" "all $nsrv to the nameserver" "$nns of $nsrv"
    result "$l.dns-to-other-servers" INFO "DNS queries about the Kerberos names that went to another server than the nameserver (the VM's own background, not judged)" - "$((nq - $(dnl_count "$f" "^T\\+[0-9.]+ DNS-Q [a-z]+ to=$nsx ")))" "see the flow file"
    seqs=$(grep -E ' DNS-Q .* SRV _kerberos\._(udp|tcp)\.' "$f" 2> /dev/null | sed -E 's/.* SRV _kerberos\._(udp|tcp)\..*/\1/' | paste -sd' ' -)
    verdict "$l.srv-udp-before-tcp" "$([ "${nsrv:-0}" -ge 2 ] && printf '%s\n' "$seqs" | awk '{ ok = (NF % 2 == 0); for (i = 1; i <= NF; i += 2) if ($i != "udp" || $(i + 1) != "tcp") ok = 0; exit !ok }' && echo PASS || echo FAIL)" \
        "the SRV queries come as _kerberos._udp then _kerberos._tcp, once per exchange" "udp tcp (repeated)" "$seqs"
    ids=$(grep -E ' DNS-Q .* SRV ' "$f" 2> /dev/null | sed -n 's/.* id=\([0-9]*\) .*/\1/p')
    ports=$(grep -E ' DNS-Q .* SRV ' "$f" 2> /dev/null | sed -n 's/.* sport=\([0-9]*\) .*/\1/p')
    verdict "$l.id-not-fixed" "$([ -n "$ids" ] && ! printf '%s\n' "$ids" | grep -qx 4660 && echo PASS || echo FAIL)" "no query ID is 0x1234 (4660), the old fixed ID" "none" "$(printf '%s' "$ids" | tr '\n' ' ')"
    verdict "$l.ids-vary" "$([ "$(printf '%s\n' "$ids" | sort -u | grep -c .)" -ge 2 ] && echo PASS || echo FAIL)" "the SRV queries carry different IDs" "2 or more" "$(printf '%s\n' "$ids" | sort -u | grep -c .) distinct of $nsrv"
    verdict "$l.ports-vary" "$([ "$(printf '%s\n' "$ports" | sort -u | grep -c .)" -ge 2 ] && echo PASS || echo FAIL)" "the SRV queries leave from different source ports" "2 or more" "$(printf '%s\n' "$ports" | sort -u | grep -c .) distinct of $nsrv"
    n=$(dnl_count "$f" '^T\+[0-9.]+ DNS-Q [a-z]+ to=[0-9.]+ id=[0-9]+ sport=[0-9]+ A kdc\.kerber\.test\.$')
    verdict "$l.a-for-the-target" "$([ "${n:-0}" -ge 1 ] && echo PASS || echo FAIL)" "an A query for the SRV target kdc.kerber.test." "1 or more" "${n:-0}"
    n=$(dnl_count "$f" "^T\\+[0-9.]+ KDC (udp|tcp-syn) dst=${DNL_KDC_IP//./\\.}:$DNL_KDC_PORT")
    verdict "$l.kdc-reached" "$([ "${n:-0}" -ge 1 ] && [ "$(dnl_count "$f" '^T\+[0-9.]+ KDC-R ')" -ge 1 ] && echo PASS || echo FAIL)" "the KDC at $DNL_KDC_IP:$DNL_KDC_PORT was contacted and answered" "1 or more" "${n:-0} attempts"
    info "$l.counts" "$f" '^T\+[0-9.]+ DNS-Q ' "(no DNS query)"
    result "$l.counts-by-type" INFO "DNS queries by type (not judged: the record has MIT 24 packets, ours 16)" - "$nq" "SRV $(dnl_count "$f" ' DNS-Q .* SRV '), A $(dnl_count "$f" ' DNS-Q .* A '), AAAA $(dnl_count "$f" ' DNS-Q .* AAAA '), URI $(dnl_count "$f" ' DNS-Q .* URI ')"
}

dn_srv() {   # dn_srv STAGE TOOL: kinit, klist, kvno through the SRV records
    local st=$1 t=$2 n f l cc fl
    cc="$VMD/b2c/dn-$st-$t-srv.cc"; n="dn/$st-srv-$t"; f="$OUT/$n.txt"; l="DN.$st.srv-$t"; fl="$OUT/dn/flow-$st-srv-$t.txt"
    dnl_cap_start dn "$st-srv-$t"
    alice_pw | dnl_login "$n" "$t" dn-srv --cc "$cc" \
        --then "$(b2c_tool "$t" klist) -c FILE:$cc" \
        --then "$(b2c_tool "$t" kvno) -c FILE:$cc krbtgt/$REALM" \
        -- -c "FILE:$cc" alice
    dnl_cap_stop dn "$st-srv-$t"
    b2c_chk_login "$l" "$f" "$t"
    expect_under "$l.klist-rc" "$f" '^== then: .*klist' '^\[then-rc=0\]$'
    expect_under "$l.klist-principal" "$f" '^== then: .*klist' "^Default principal: alice@$RRX\$"
    expect_under "$l.klist-ticket" "$f" '^== then: .*klist' "krbtgt/$RRX@$RRX\$"
    expect_under "$l.kvno-rc" "$f" '^== then: .*kvno' '^\[then-rc=0\]$'
    expect_under "$l.kvno-line" "$f" '^== then: .*kvno' "^krbtgt/$RRX@$RRX: kvno = [0-9]+\$"
    expect_part "$l.kdc-issue" "$f" kdc "AS_REQ .*ISSUE: .*alice@$RRX for krbtgt/$RRX@$RRX" 1
    dn_flow_rows "$l" "$fl"
}

dn_tc() {   # dn_tc STAGE TOOL: the realm TC.TEST whose _udp SRV answer is cut over UDP: the retry over TCP, then the KDC says the client is unknown
    local st=$1 t=$2 n f l cc fl x sl mk
    cc="$VMD/b2c/dn-$st-$t-tc.cc"; n="dn/$st-tc-$t"; f="$OUT/$n.txt"; l="DN.$st.tc-$t"; fl="$OUT/dn/flow-$st-tc-$t.txt"
    mk=$(dnl_log_mark dn)
    dnl_cap_start dn "$st-tc-$t"
    alice_pw | dnl_login "$n" "$t" dn-srv --cc "$cc" -- -c "FILE:$cc" "alice@TC.TEST"
    dnl_cap_stop dn "$st-tc-$t"
    dnl_log_get dn "$st-tc-$t" "$mk"
    expect "$l.rc" "$f" '^\[rc=1\]$'
    expect_under "$l.stderr-client-unknown" "$f" '^== stderr$' "^([^ :]*/)?(krb5-)?kinit: Client 'alice@TC\\.TEST' not found in Kerberos database while getting initial credentials\$" 1
    expect "$l.no-ccache" "$f" '^no ccache was written$'
    expect_part "$l.no-secret-marker" "$f" client '<REDACTED:' 0
    # the server's own log is the judge of what reached it (a capture can lose a packet); the capture's view of the same facts is INFO
    sl="$OUT/dn/stublog-$st-tc-$t.txt"
    x=$(dnl_count "$sl" '^T [0-9.]+ udp [0-9.]+:[0-9]+ id=[0-9]+ SRV _kerberos\._udp\.TC\.TEST -> 0 an=0 tc$')
    verdict "$l.udp-answer-truncated" "$([ "${x:-0}" -ge 1 ] && echo PASS || echo FAIL)" "the UDP answer to _kerberos._udp.TC.TEST. had the TC bit and no records (the stub's log)" "1 or more" "${x:-0}"
    x=$(dnl_count "$sl" "^T [0-9.]+ tcp [0-9.]+:[0-9]+ id=[0-9]+ SRV _kerberos\\._udp\\.TC\\.TEST -> 0 an=$DN_TC_TARGETS\$")
    verdict "$l.retried-over-tcp" "$([ "${x:-0}" -ge 1 ] && echo PASS || echo FAIL)" "the query was repeated over a TCP connection to port 53 and answered with all $DN_TC_TARGETS SRV records (the stub's log)" "1 or more" "${x:-0}"
    result "$l.capture-saw-tcp" INFO "the capture's view of the retry (a lost packet shows here, not in the verdict)" - "$(dnl_count "$fl" '^T\+[0-9.]+ DNS-Q tcp ')" "tcp queries $(dnl_count "$fl" '^T\+[0-9.]+ DNS-Q tcp '), tcp answers $(dnl_count "$fl" '^T\+[0-9.]+ DNS-R tcp '), truncated udp answers $(dnl_count "$fl" ' DNS-R udp .* flags=[a-z,]*tc')"
    info "$l.refused-answers" "$fl" '^T\+[0-9.]+ DNS-R [a-z]+ from=[0-9.]+ id=[0-9]+ rcode=5 ' "(none)"
    x=$(dnl_count "$fl" "^T\\+[0-9.]+ KDC (udp|tcp-syn) dst=${DNL_KDC_IP//./\\.}:$DNL_KDC_PORT")
    verdict "$l.kdc-reached" "$([ "${x:-0}" -ge 1 ] && echo PASS || echo FAIL)" "the KDC was contacted through one of the 40 targets" "1 or more" "${x:-0} attempts"
    result "$l.counts-by-type" INFO "DNS queries by type (not judged: the two clients resolve a different number of the 40 targets before the first send)" - "$(dnl_count "$fl" '^T\+[0-9.]+ DNS-Q ')" "SRV $(dnl_count "$fl" ' DNS-Q .* SRV '), A $(dnl_count "$fl" ' DNS-Q .* A '), AAAA $(dnl_count "$fl" ' DNS-Q .* AAAA '), URI $(dnl_count "$fl" ' DNS-Q .* URI ')"
}

dn_stage() {   # dn_stage mit|ours
    local st=$1 t L=DN.$1
    b2c_kdc_ready dn "$st" || return 0
    if dnl_begin dn "$st" dn_zone; then
        dnl_probe dn "$st" "_kerberos._udp.$REALM" SRV "^_kerberos\\._udp\\.$RRX SRV bytes=[0-9]+ an=1 tc=False rcode=0 id=[0-9]+\$"
        dnl_probe dn "$st" "_kerberos._tcp.$REALM" SRV "^_kerberos\\._tcp\\.$RRX SRV bytes=[0-9]+ an=1 tc=False rcode=0 id=[0-9]+\$"
        dnl_probe dn "$st" "_kerberos._udp.TC.TEST" SRV '^_kerberos\._udp\.TC\.TEST SRV bytes=[0-9]+ an=0 tc=True rcode=0 id=[0-9]+$'
        dnl_probe dn "$st" "_kerberos._udp.TC.TEST" SRV "^_kerberos\\._udp\\.TC\\.TEST SRV bytes=[0-9]+ an=$DN_TC_TARGETS tc=False rcode=0 id=[0-9]+\$" --tcp
        dnl_probe dn "$st" "kdc.kerber.test" AAAA '^kdc\.kerber\.test AAAA bytes=[0-9]+ an=0 tc=False rcode=5 id=[0-9]+$'
        if dnl_conf dn-srv "$(dn_conf_text)"; then
            for t in mit ours; do deadline; dn_srv "$st" "$t"; done
            for t in mit ours; do deadline; dn_tc "$st" "$t"; done
        else
            b2c_not_run "$L.cells" "the client conf could not be pushed to client1"
        fi
    fi
    dnl_end dn "$st"
    return 0
}
dn_mit() { dn_init; dn_stage mit; }
dn_ours() { dn_init; dn_stage ours; }

dn_cmp() {   # dn_cmp LABEL CELL STAGE-A TOOL-A STAGE-B TOOL-B: the client parts of two cells equal after the named masks (rc, prompt, stderr, the events b2c_core keeps, klist and kvno blocks)
    local label=$1 k=$2 sa=$3 ta=$4 sb=$5 tb=$6 d="$OUT/dn/norm"
    mkdir -p "$d"
    b2c_core "$OUT/dn/$sa-$k-$ta.txt" > "$d/$label.a.txt" 2> /dev/null; b2c_core "$OUT/dn/$sb-$k-$tb.txt" > "$d/$label.b.txt" 2> /dev/null
    parity_eq "$label" "$d/$label.a.txt" "$d/$label.b.txt" "${DN_MASK[@]}"
}

dn_parity() {
    dn_init
    local k s t d="$OUT/dn/norm" a b
    mkdir -p "$d"
    for k in srv tc; do
        for s in mit ours; do dn_cmp "DN.parity.$k-prog-$s" "$k" "$s" mit "$s" ours; done          # the programs differ, the KDC does not
        for t in mit ours; do dn_cmp "DN.parity.$k-xkdc-$t" "$k" mit "$t" ours "$t"; done           # the KDC changes, the program does not
    done
    # the counts are not compared (the record: MIT 24 packets, ours 16); the properties of the DNS side are judged cell by cell above. What is recorded here: the per-type counts side by side
    for s in mit ours; do
        a=$(grep -E 'DNS queries by type' "$OUT/results.tsv" 2> /dev/null | grep -E "^DN\\.$s\\.srv-mit\\.counts-by-type" | cut -f6)
        b=$(grep -E 'DNS queries by type' "$OUT/results.tsv" 2> /dev/null | grep -E "^DN\\.$s\\.srv-ours\\.counts-by-type" | cut -f6)
        result "DN.parity.srv-counts-$s" INFO "DNS queries of the srv cell, MIT's kinit against ours (not judged: docs/parity/b1-client.md:64 deferrals, the record has MIT 24 packets against ours 16)" - "$([ "$a" = "$b" ] && echo equal || echo DIFFER)" "MIT [$a]; ours [$b]"
    done
    # controls: a doctored copy differs; the srv cell and the tc cell differ; the property rows can fail (a flow with the SRV order reversed does not satisfy them)
    parity_control DN.parity.srv-prog-mit "$d/DN.parity.srv-prog-mit.a.txt" "$d/DN.parity.srv-prog-mit.b.txt" "${DN_MASK[@]}"
    b2c_differ DN.parity.control.srv-vs-tc "$OUT/dn/mit-srv-mit.txt" "$OUT/dn/mit-tc-mit.txt"
    local seqs
    seqs=$(printf '%s\n' 'tcp udp' | awk '{ ok = (NF % 2 == 0); for (i = 1; i <= NF; i += 2) if ($i != "udp" || $(i + 1) != "tcp") ok = 0; exit !ok }' && echo PASS || echo FAIL)
    verdict DN.parity.control.srv-order "$([ "$seqs" = FAIL ] && echo PASS || echo FAIL)" "the srv-order check refuses a reversed sequence (tcp before udp)" refused "$seqs"
    return 0
}

dn_clean() {
    dn_init
    vm "$(dnl_host)" "sudo bash $VMD/dn-vm.sh dns-stop dn" > /dev/null 2>&1 < /dev/null
    b2c_clean_vms
    return 0
}
