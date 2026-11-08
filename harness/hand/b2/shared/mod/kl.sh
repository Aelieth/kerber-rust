# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/kl.sh: B2 module KL, the client tries each KDC of the profile list or of the SRV answer in order (b2-client; spec: spec/kl.md). Runs last in the hold (after DN), on client1, a dead address in front, the live KDC behind it.
# Records of the recorded leg (R): lab-wrap.txt (Lab A, config A, 2026-10-07 16:03-16:07Z), lab-b-r2.txt (Lab B r2, 16:18-16:21Z: the MIT oracle, all four rc 0), lab-b-ours.txt (the landed tree 656f1a90, 16:47-16:49Z),
# vm/*.pcap and *.trace (a-/b- x mit/ours x MIT KDC/rust KDC), vm-r2/b-ours.pcap, mit-two-dead.txt (container), scripts/lab-kl.sh, lab-kl-b.sh, lab-kl-b-ours.sh (the host side);
# Landed a92ea52c (tree 656f1a90) "client: Try each profile or SRV KDC in order". No final-tree gate asserts any of it against MIT (client-differential-cli-gate.sh:200-221 checks one dead KDC by exit status only).
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade), on client1 as the lab user, MIT's kinit and ours, a tcpdump on client1 around each cell, alice's password on stdin:
#   a  config A, the profile list: `[realms] KERBER.TEST = { kdc = 192.0.2.1 (dead, RFC 5737 TEST-NET-1) / kdc = <the live KDC> }`, no DNS   rc 0 on both KDCs; UDP to the dead address at t0, UDP to the live KDC about 1.0 s later
#        (R lab-wrap.txt:38/40 MIT +1.001 s, :99/:100 ours +1.044 s), the same again for the second exchange
#   b  config B, SRV: no `kdc =`, `dns_lookup_kdc = true`; the zone has `_kerberos._udp` -> the root target `.`, `_kerberos._tcp` -> `0 0 88 192.0.2.1.` (dead, priority 0) and `10 0 88 kdc.kerber.test.` (live), the records rotating in
#        the answers like dnsmasq's   rc 0; no UDP to the KDC port at all; TCP to the dead address at t0, TCP to the live KDC about 1.0 s later (R lab-b-r2.txt:147-148 MIT, lab-b-ours.txt ours); one `_udp` and one `_tcp` SRV query per send
# Parity rule of the leg: rc equal (0), and the ordered (protocol, destination, relative time) sequence of KDC packets equal (here: every attempt at the dead address and the attempt after it): dead first, live about 1 s later, TCP only for `_tcp` entries. Allowed to differ (INFO rows): the packet
# counts (MIT 57 against ours 38), MIT's two URI queries (REFUSED; ours has none, URI is deferred: docs/parity/b1-client.md:64), the A/AAAA pairs for the targets (MIT resolves the dead numeric-looking target through DNS, ours reads it as an address).
# Documented limits (docs/parity/b1-client.md:64): an explicit host other than the first discovered KDC is contacted alone, a single KDC keeps the old waits, HTTPS/KKDCP are not ported.
# Differences from the recorded leg: the DNS server is helpers/dn-stub.py on client2 (the leg: dnsmasq from the mirror on the services VM); client1's resolver is not edited, each command runs in a private mount namespace (helpers/dn-vm.sh nsrun; see mod/dn.sh);
#   the ours stage is dist/install.sh's upgrade of the final ship build; the dead address is 192.0.2.1 as in the leg; the live KDC's address is read from the VM's own krb5.conf; the capture helper waits until tcpdump listens (the leg printed tcpdump_ready=0
#   for several captures that did hold the packets).
# NOT BUILT: the container cell with two blackhole KDCs (R mit-two-dead.txt: MIT UDP 1 s each, TCP 1 s each, retry at +4 s and +8 s, about 22 s, rc 1); ours is only unit-tested for it (every_profile_kdc_dead, 3.58 s).
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"
# shellcheck source=/dev/null
declare -F dnl_init > /dev/null || . "$SCRIPTS/helpers/dn-lib.sh"

kl_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${KL_INIT_DONE:-}" ] && return 0
    KL_INIT_DONE=1
    dnl_init
    KL_DEAD=192.0.2.1
    KL_GAP_LO=0.8; KL_GAP_HI=1.5     # seconds from an attempt at the dead address to the next attempt (the leg: 1.001 and 1.044)
    KL_MASK=('s#^(/[^ :]*/)?(krb5-)?(kinit|klist|kvno): #PROG: #'
             's#/b2c/kl-(mit|ours)-(mit|ours)-#/b2c/kl-STAGE-TOOL-#g')
}

kl_prep() { kl_init; dnl_prep_check; }
kl_push() { kl_init; dnl_push; }

kl_zone() {   # config B's zone (R lab-b-r2.txt:56-120): the dead target in front by priority, the live one behind, the answers rotating
    printf 'ROTATE\n'
    printf 'SRV _kerberos._udp.%s. 0 0 %s .\n' "$REALM" "$DNL_KDC_PORT"
    printf 'SRV _kerberos._tcp.%s. 10 0 %s kdc.kerber.test.\n' "$REALM" "$DNL_KDC_PORT"
    printf 'SRV _kerberos._tcp.%s. 0 0 %s %s.\n' "$REALM" "$DNL_KDC_PORT" "$KL_DEAD"
    printf 'A kdc.kerber.test. %s\n' "$DNL_KDC_IP"
    printf 'A %s. %s\n' "$KL_DEAD" "$KL_DEAD"
}

kl_conf_a() {   # config A: the profile list, dead first (the leg's a.conf was not saved)
    local port=""
    [ "$DNL_KDC_PORT" = 88 ] || port=":$DNL_KDC_PORT"
    printf '[libdefaults]\n    default_realm = %s\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    rdns = false\n\n[realms]\n    %s = {\n        kdc = %s%s\n        kdc = %s%s\n    }\n' \
        "$REALM" "$REALM" "$KL_DEAD" "$port" "$DNL_KDC_IP" "$port"
}
kl_conf_b() {   # config B: SRV only (R)
    printf '[libdefaults]\n    default_realm = %s\n    dns_lookup_kdc = true\n    dns_lookup_realm = false\n    rdns = false\n' "$REALM"
}

kl_walk_rows() {   # kl_walk_rows LABEL FLOW PROTO: every attempt at the dead address is followed by an attempt at the live KDC (PROTO = udp for config A, tcp-syn for B) about a second later, once per send, and only the live KDC answers
    local l=$1 f=$2 proto=$3 dead live wk n pairs gaps bad g
    dead="$KL_DEAD:$DNL_KDC_PORT"; live="$DNL_KDC_IP:$DNL_KDC_PORT"
    wk=$(dnl_walk "$f" "$dead")
    n=$(printf '%s\n' "$wk" | grep -c .)
    pairs=$((n / 2))
    verdict "$l.dead-then-live" "$(printf '%s\n' "$wk" | awk -v dd="$proto $dead" -v ll="$proto $live" 'NF { n++; if (n % 2 == 1 && $0 != dd) bad = 1; if (n % 2 == 0 && $0 != ll) bad = 1 } END { exit !(n >= 4 && n % 2 == 0 && !bad) }' && echo PASS || echo FAIL)" \
        "an attempt at $dead is followed by an attempt at $live ($proto), at least two exchanges" "dead, live, dead, live ..." "$(printf '%s\n' "$wk" | paste -sd'|' -)"
    gaps=$(dnl_gaps "$f" "$dead")
    bad=0; for g in $gaps; do awk -v g="$g" -v lo="$KL_GAP_LO" -v hi="$KL_GAP_HI" 'BEGIN { exit !(g >= lo && g <= hi) }' || bad=1; done
    # shellcheck disable=SC2086  # $gaps splits into one word per gap
    verdict "$l.gap-about-one-second" "$([ -n "$gaps" ] && [ "$bad" = 0 ] && echo PASS || echo FAIL)" "the next attempt follows an attempt at the dead address after $KL_GAP_LO to $KL_GAP_HI seconds (the leg: 1.001 and 1.044)" "each in range" "$(printf '%s ' $gaps)"
    n=$(dnl_count "$f" "^T\\+[0-9.]+ KDC-R [a-z]+ src=${DNL_KDC_IP//./\\.}:$DNL_KDC_PORT")
    verdict "$l.live-answers" "$([ "${n:-0}" -ge 1 ] && [ "$(dnl_count "$f" "^T\\+[0-9.]+ KDC-R [a-z]+ src=${KL_DEAD//./\\.}:")" = 0 ] && echo PASS || echo FAIL)" "the live KDC answered and the dead address never did" "answers from the live KDC only" "${n:-0} from the live KDC"
    result "$l.pairs" INFO "exchanges walked (dead then live)" - "$pairs" "walks: $(printf '%s\n' "$wk" | paste -sd'|' -)"
}

kl_a() {   # kl_a STAGE TOOL: config A
    local st=$1 t=$2 n f l cc fl
    cc="$VMD/b2c/kl-$st-$t-a.cc"; n="kl/$st-a-$t"; f="$OUT/$n.txt"; l="KL.$st.a-$t"; fl="$OUT/kl/flow-$st-a-$t.txt"
    dnl_cap_start kl "$st-a-$t"
    alice_pw | dnl_login "$n" "$t" kl-a --cc "$cc" --then "$(b2c_tool "$t" klist) -c FILE:$cc" -- -c "FILE:$cc" alice
    dnl_cap_stop kl "$st-a-$t"
    b2c_chk_login "$l" "$f" "$t"
    expect_under "$l.klist-ticket" "$f" '^== then: .*klist' "krbtgt/$RRX@$RRX\$"
    expect_part "$l.kdc-issue" "$f" kdc "AS_REQ .*ISSUE: .*alice@$RRX for krbtgt/$RRX@$RRX" 1
    kl_walk_rows "$l" "$fl" udp
    verdict "$l.no-dns" "$([ "$(dnl_count "$fl" "^T\\+[0-9.]+ DNS-Q [a-z]+ to=${DNL_NS_IP//./\\.} ")" = 0 ] && echo PASS || echo FAIL)" "config A asks the nameserver nothing about the KDCs (the profile list is used as it is)" 0 "$(dnl_count "$fl" "^T\\+[0-9.]+ DNS-Q [a-z]+ to=${DNL_NS_IP//./\\.} ")"
}

kl_b() {   # kl_b STAGE TOOL: config B
    local st=$1 t=$2 n f l cc fl nu nt nd nsx nq nns nsrv
    cc="$VMD/b2c/kl-$st-$t-b.cc"; n="kl/$st-b-$t"; f="$OUT/$n.txt"; l="KL.$st.b-$t"; fl="$OUT/kl/flow-$st-b-$t.txt"
    dnl_cap_start kl "$st-b-$t"
    alice_pw | dnl_login "$n" "$t" kl-b --cc "$cc" --then "$(b2c_tool "$t" klist) -c FILE:$cc" -- -c "FILE:$cc" alice
    dnl_cap_stop kl "$st-b-$t"
    b2c_chk_login "$l" "$f" "$t"
    expect_under "$l.klist-ticket" "$f" '^== then: .*klist' "krbtgt/$RRX@$RRX\$"
    expect_part "$l.kdc-issue" "$f" kdc "AS_REQ .*ISSUE: .*alice@$RRX for krbtgt/$RRX@$RRX" 1
    kl_walk_rows "$l" "$fl" tcp-syn
    nu=$(grep -E '^T\+[0-9.]+ KDC udp ' "$fl" 2> /dev/null | grep -cE "(dst=${KL_DEAD//./\\.}:|cname=alice@)" || true)
    verdict "$l.no-udp-to-the-kdc" "$([ "${nu:-0}" = 0 ] && echo PASS || echo FAIL)" "no datagram of this login goes to the KDC port: the _udp record is the root target and is skipped, the _tcp records are used over TCP" 0 "${nu:-0}"
    nsx=${DNL_NS_IP//./\\.}
    nq=$(dnl_count "$fl" '^T\+[0-9.]+ DNS-Q ')
    nsrv=$(dnl_count "$fl" ' DNS-Q .* SRV _kerberos\._(udp|tcp)\.'); nns=$(dnl_count "$fl" "^T\\+[0-9.]+ DNS-Q [a-z]+ to=$nsx id=[0-9]+ sport=[0-9]+ SRV _kerberos\\._(udp|tcp)\\.")
    verdict "$l.srv-queries-only-to-ns" "$([ "${nsrv:-0}" -ge 1 ] && [ "$nsrv" = "$nns" ] && echo PASS || echo FAIL)" "every SRV query goes to resolv.conf's nameserver $DNL_NS_IP" "all $nsrv to the nameserver" "$nns of $nsrv"
    nu=$(dnl_count "$fl" ' DNS-Q .* SRV _kerberos\._udp\.'); nt=$(dnl_count "$fl" ' DNS-Q .* SRV _kerberos\._tcp\.'); nd=$(dnl_count "$fl" "^T\\+[0-9.]+ KDC tcp-syn dst=${KL_DEAD//./\\.}:")
    verdict "$l.one-srv-pair-per-send" "$([ "${nu:-0}" -ge 2 ] && [ "$nu" = "$nt" ] && [ "$nu" = "$nd" ] && echo PASS || echo FAIL)" "one _udp and one _tcp SRV query per send (the r1 tree sent six before the first packet)" "$nd of each (one per send)" "_udp $nu, _tcp $nt, sends (attempts at the dead address) $nd"
    result "$l.counts-by-type" INFO "DNS queries by type (not judged: the leg has MIT 57 packets against ours 38; MIT asks URI twice per send, ours does not: docs/parity/b1-client.md:64)" - "$nq" \
        "SRV $(dnl_count "$fl" ' DNS-Q .* SRV '), A $(dnl_count "$fl" ' DNS-Q .* A '), AAAA $(dnl_count "$fl" ' DNS-Q .* AAAA '), URI $(dnl_count "$fl" ' DNS-Q .* URI ')"
}

kl_stage() {   # kl_stage mit|ours
    local st=$1 t L=KL.$1
    b2c_kdc_ready kl "$st" || return 0
    if dnl_begin kl "$st" kl_zone; then
        dnl_probe kl "$st" "_kerberos._udp.$REALM" SRV "^_kerberos\\._udp\\.$RRX SRV bytes=[0-9]+ an=1 tc=False rcode=0 id=[0-9]+\$"
        dnl_probe kl "$st" "_kerberos._tcp.$REALM" SRV "^_kerberos\\._tcp\\.$RRX SRV bytes=[0-9]+ an=2 tc=False rcode=0 id=[0-9]+\$"
        dnl_probe kl "$st" "kdc.kerber.test" A '^kdc\.kerber\.test A bytes=[0-9]+ an=1 tc=False rcode=0 id=[0-9]+$'
        dnl_probe kl "$st" "$KL_DEAD." A '^192\.0\.2\.1\. A bytes=[0-9]+ an=1 tc=False rcode=0 id=[0-9]+$'
        if dnl_conf kl-a "$(kl_conf_a)" && dnl_conf kl-b "$(kl_conf_b)"; then
            for t in mit ours; do deadline; kl_a "$st" "$t"; done
            for t in mit ours; do deadline; kl_b "$st" "$t"; done
        else
            b2c_not_run "$L.cells" "a client conf could not be pushed to client1"
        fi
    fi
    dnl_end kl "$st"
    return 0
}
kl_mit() { kl_init; kl_stage mit; }
kl_ours() { kl_init; kl_stage ours; }

kl_cmp() {   # kl_cmp LABEL CELL STAGE-A TOOL-A STAGE-B TOOL-B: the client parts of two cells equal after the named masks, and the KDC attempts of their flows equal (protocol and destination, in order)
    local label=$1 k=$2 sa=$3 ta=$4 sb=$5 tb=$6 d="$OUT/kl/norm"
    mkdir -p "$d"
    b2c_core "$OUT/kl/$sa-$k-$ta.txt" > "$d/$label.a.txt" 2> /dev/null; b2c_core "$OUT/kl/$sb-$k-$tb.txt" > "$d/$label.b.txt" 2> /dev/null
    parity_eq "$label" "$d/$label.a.txt" "$d/$label.b.txt" "${KL_MASK[@]}"
    dnl_walk "$OUT/kl/flow-$sa-$k-$ta.txt" "$KL_DEAD:$DNL_KDC_PORT" > "$d/$label.seq.a.txt"; dnl_walk "$OUT/kl/flow-$sb-$k-$tb.txt" "$KL_DEAD:$DNL_KDC_PORT" > "$d/$label.seq.b.txt"
    parity_eq "$label.kdc-attempts" "$d/$label.seq.a.txt" "$d/$label.seq.b.txt"
}

kl_parity() {
    kl_init
    local k s t d="$OUT/kl/norm" a b
    mkdir -p "$d"
    for k in a b; do
        for s in mit ours; do kl_cmp "KL.parity.$k-prog-$s" "$k" "$s" mit "$s" ours; done          # the programs differ, the KDC does not
        for t in mit ours; do kl_cmp "KL.parity.$k-xkdc-$t" "$k" mit "$t" ours "$t"; done           # the KDC changes, the program does not
    done
    # recorded, not judged: the DNS counts side by side (the leg: MIT 57 packets, ours 38; URI)
    for s in mit ours; do
        a=$(grep -E "^KL\\.$s\\.b-mit\\.counts-by-type" "$OUT/results.tsv" 2> /dev/null | cut -f6)
        b=$(grep -E "^KL\\.$s\\.b-ours\\.counts-by-type" "$OUT/results.tsv" 2> /dev/null | cut -f6)
        result "KL.parity.b-counts-$s" INFO "DNS queries of config B, MIT's kinit against ours (not judged: docs/parity/b1-client.md:64 deferrals)" - "$([ "$a" = "$b" ] && echo equal || echo DIFFER)" "MIT [$a]; ours [$b]"
    done
    # controls: a doctored copy differs; config A and B differ; the walk rows can fail (a swapped sequence does not satisfy the alternation)
    parity_control KL.parity.a-prog-mit "$d/KL.parity.a-prog-mit.a.txt" "$d/KL.parity.a-prog-mit.b.txt" "${KL_MASK[@]}"
    parity_control KL.parity.a-prog-mit.kdc-attempts "$d/KL.parity.a-prog-mit.seq.a.txt" "$d/KL.parity.a-prog-mit.seq.b.txt"
    if [ -s "$OUT/kl/flow-mit-a-mit.txt" ] && [ -s "$OUT/kl/flow-mit-b-mit.txt" ] && ! cmp -s <(dnl_walk "$OUT/kl/flow-mit-a-mit.txt" "$KL_DEAD:$DNL_KDC_PORT") <(dnl_walk "$OUT/kl/flow-mit-b-mit.txt" "$KL_DEAD:$DNL_KDC_PORT"); then
        verdict KL.parity.control.a-vs-b PASS "the KDC attempts of config A (UDP, profile list) and of config B (TCP, SRV) must differ" differ differ ""
    else verdict KL.parity.control.a-vs-b FAIL "the KDC attempts of config A (UDP, profile list) and of config B (TCP, SRV) must differ" differ same ""; fi
    local sw
    sw=$(printf 'udp %s:88\nudp %s:88\nudp %s:88\nudp %s:88\n' "$DNL_KDC_IP" "$KL_DEAD" "$DNL_KDC_IP" "$KL_DEAD" | awk -v dd="udp $KL_DEAD:88" -v ll="udp $DNL_KDC_IP:88" 'NF { n++; if (n % 2 == 1 && $0 != dd) bad = 1; if (n % 2 == 0 && $0 != ll) bad = 1 } END { exit !(n >= 4 && n % 2 == 0 && !bad) }' && echo PASS || echo FAIL)
    verdict KL.parity.control.walk-order "$([ "$sw" = FAIL ] && echo PASS || echo FAIL)" "the dead-then-live check refuses a sequence that tries the live KDC first" refused "$sw"
    return 0
}

kl_clean() {
    kl_init
    vm "$(dnl_host)" "sudo bash $VMD/dn-vm.sh dns-stop kl" > /dev/null 2>&1 < /dev/null
    b2c_clean_vms
    return 0
}
