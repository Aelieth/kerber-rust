# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# dn-lib.sh: the shared skeleton of the B2 modules DN and KL (mod/dn.sh, mod/kl.sh; b2-client; specs spec/dn.md, spec/kl.md). Sourced by each of those modules (`declare -F dnl_init > /dev/null || . "$SCRIPTS/helpers/dn-lib.sh"`);
# FUNCTIONS ONLY (dnl_init assigns the variables when a module's hook first calls it). It needs b2c-lib.sh (sourced here when absent). Everything runs in driver-b2.sh's shell and uses its helpers (cell, push, vm, expect*, verdict,
# info, result, parity_eq, parity_control, alice_pw, note, deadline, redact) and its variables (OUT VMD SCRIPTS REALM RRX CLIENTS LOG TMPDIR).
# What the two modules have in common: the clients' DNS. A python3 DNS stub (helpers/dn-stub.py: stdlib, UDP and TCP, a zone file) runs on the DNS host (client2 by default; $DNL_DNS_HOST=kdc moves it; never services, no dnsmasq, no mirror),
# client1 is the client, and its resolver is NOT changed: each client command runs in a private mount namespace whose /etc/resolv.conf and /etc/nsswitch.conf are bind-mounted from two temporary files (helpers/dn-vm.sh nsrun),
# so there is nothing to put back; rows prove that the VM's own two files have the same sha256 before and after, and that nothing listens on port 53 afterwards. A capture on client1 (tcpdump, the existing pcap-* of b2c-vm.sh) is
# summarized on the host by b2c-pcap.py flow into one line per DNS query / answer / KDC attempt, with the seconds since the first.
#   dnl_prep_check                        (module _prep) the helper files are there
#   dnl_push                              (module _push) dn-vm.sh and dn-stub.py on client1 and client2, the b2c helper on both
#   dnl_begin PKG STAGE ZONEFN            (stage hook, after b2c_kdc_ready) work-directory checks, the facts (the KDC's address and port from the VM's own krb5.conf, the DNS host's address), the resolver sums, the zone ZONEFN
#                                         prints pushed to the DNS host, the stub started and probed from client1; status 1 = nothing can run (rows and NOT-RUN rows say why; the stub is stopped)
#   dnl_end PKG STAGE                     the stub stopped, its log kept, nothing on port 53, the resolver files as they were
#   dnl_conf NAME TEXT                    a krb5.conf variant pushed to client1 as $VMD/b2c/NAME.conf
#   dnl_cap_start PKG NAME / dnl_cap_stop PKG NAME   tcpdump on client1 (port 53 or 88) around a cell; $OUT/PKG/flow-NAME.txt is the flow summary
#   dnl_login CELL TOOL CONFNAME [b2c-vm.sh login options] -- KINIT-ARGS...   one login on client1 in the private resolver, as the lab user, as a `cell` ($OUT/CELL.txt, with the KDC's log lines)
#   dnl_log_mark PKG / dnl_log_get PKG CELL FROM   the stub's own query log (what reached the server, whatever the capture caught): the line count before a cell, the lines after it
#   dnl_count FILE RX / dnl_seq FILE / dnl_walk FILE DEAD / dnl_gaps FILE DEAD   views of a flow file: the number of lines matching RX; the KDC attempts in order (proto and destination, repeats collapsed); the walks (each attempt at DEAD
#                                         and the next attempt at another destination); the seconds from an attempt at DEAD to the next attempt at another destination

dnl_init() {   # idempotent; the library's variables are assigned HERE, never at the top level of a sourced file
    [ -n "${DNL_INIT_DONE:-}" ] && return 0
    DNL_INIT_DONE=1
    b2c_init
    DNL_MATCH='_kerberos|kdc\.kerber\.test|^192\.0\.2\.1\.?$|very-long-kdc-target'   # the DNS names a cell is about (the VM's other chatter, fedoraproject.org and the like, is left out of the flow)
    DNL_KDC_IP=""; DNL_KDC_PORT=88; DNL_KDC_HOST=""; DNL_NS_IP=""
}

dnl_prep_check() {
    local f
    for f in dn-stub.py dn-vm.sh dn-lib.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "dn: $SCRIPTS/helpers/$f is missing" >&2; return 1; }; done
    b2c_prep_check
}

dnl_push() {
    local c
    b2c_push_vm client1 client2 || return 1
    for c in client1 client2; do
        push "$c" "$SCRIPTS/helpers/dn-vm.sh" "$VMD/dn-vm.sh" 755 || return 1
        push "$c" "$SCRIPTS/helpers/dn-stub.py" "$VMD/dn/dn-stub.py" 644 || return 1
    done
    return 0
}

dnl_host() { printf '%s' "${DNL_DNS_HOST:-client2}"; }   # the DNS host (a knob: read, never assigned)

dnl_begin() {   # dnl_begin PKG STAGE ZONEFN
    local pkg=$1 st=$2 zonefn=$3 L=${1^^}.$2 h c f zf ok=1
    dnl_init
    h=$(dnl_host)
    for c in client1 "$h"; do
        [ "$c" = kdc ] && continue
        b2c_work_ok "$pkg" "$st" "$c" || ok=0
    done
    if [ "$ok" = 0 ]; then b2c_not_run "$L.cells" "a VM's work directory cannot be used by the lab user (see the $L.workdir rows): no cell ran"; return 1; fi
    # ---- the facts: the tools, the KDC's address and port (the VM's own krb5.conf), the DNS host's address towards the KDC
    cell "$pkg/$st-facts-client1" client1 "bash $VMD/dn-vm.sh facts" none < /dev/null
    f="$OUT/$pkg/$st-facts-client1.txt"
    for c in python3 tcpdump unshare setpriv mount ss ip getent; do expect "$L.facts.client1-$c" "$f" "^$c: /" ; done
    cell "$pkg/$st-kdcaddr" client1 "bash $VMD/dn-vm.sh kdcaddr ${B2C_BASE_CONF:-/etc/krb5.conf} $REALM" none < /dev/null
    f="$OUT/$pkg/$st-kdcaddr.txt"
    DNL_KDC_HOST=$(sed -n 's/^KDC_HOST=//p' "$f" | head -n 1); DNL_KDC_IP=$(sed -n 's/^KDC_IP=//p' "$f" | head -n 1); DNL_KDC_PORT=$(sed -n 's/^KDC_PORT=//p' "$f" | head -n 1)
    expect "$L.facts.kdc-address" "$f" '^KDC_IP=[0-9]+(\.[0-9]+){3}$'
    [ -n "$DNL_KDC_PORT" ] || DNL_KDC_PORT=88
    if ! printf '%s' "$DNL_KDC_IP" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then b2c_not_run "$L.cells" "the KDC's address could not be read from the VM's krb5.conf ($f)"; return 1; fi
    cell "$pkg/$st-nsaddr" "$h" "bash $VMD/dn-vm.sh nsaddr $DNL_KDC_IP" none < /dev/null
    f="$OUT/$pkg/$st-nsaddr.txt"
    DNL_NS_IP=$(sed -n 's/^NS_IP=//p' "$f" | head -n 1)
    expect "$L.facts.dns-host-address" "$f" '^NS_IP=[0-9]+(\.[0-9]+){3}$'
    if ! printf '%s' "$DNL_NS_IP" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then b2c_not_run "$L.cells" "the DNS host's address could not be read ($f)"; return 1; fi
    # ---- the VM's resolver as it is: the proof that it stays so
    cell "$pkg/$st-sums-before" client1 "bash $VMD/dn-vm.sh sums" none < /dev/null
    # ---- the zone, the stub, a probe from client1 (reachability from the client to the DNS host's port 53 and the stub's answers)
    zf="$TMPDIR/dnl-zone-$pkg-$st.txt"
    mkdir -p "$TMPDIR"
    "$zonefn" > "$zf"
    push "$h" "$zf" "$VMD/dn/zone-$pkg.txt" 644 || { b2c_not_run "$L.cells" "the zone file could not be pushed to $h"; rm -f "$zf"; return 1; }
    cp "$zf" "$OUT/$pkg/$st-zone.txt"; rm -f "$zf"
    cell "$pkg/$st-stub-start" "$h" "sudo bash $VMD/dn-vm.sh dns-start $pkg $DNL_NS_IP $VMD/dn/zone-$pkg.txt" none < /dev/null
    expect "$L.stub.started" "$OUT/$pkg/$st-stub-start.txt" "^DNS_STARTED $pkg bind=$DNL_NS_IP pid=[0-9]+\$"
    if ! grep -q '^DNS_STARTED ' "$OUT/$pkg/$st-stub-start.txt"; then b2c_not_run "$L.cells" "the DNS stub did not start on $h"; return 1; fi
    return 0
}

dnl_probe() {   # dnl_probe PKG STAGE NAME TYPE WANT-RX [--tcp]: one query from client1 straight to the stub
    local pkg=$1 st=$2 name=$3 type=$4 rx=$5 n
    shift 5
    n=$(printf '%s' "$name" | tr -c 'A-Za-z0-9\n' '-')
    cell "$pkg/$st-probe-$type-$n$([ "${1:-}" = --tcp ] && echo -tcp)" client1 "bash $VMD/dn-vm.sh probe $DNL_NS_IP $name $type ${1:-}" none < /dev/null
    expect "${pkg^^}.$st.stub.probe-$type-$n$([ "${1:-}" = --tcp ] && echo -tcp)" "$OUT/$pkg/$st-probe-$type-$n$([ "${1:-}" = --tcp ] && echo -tcp).txt" "$rx"
}

dnl_end() {   # dnl_end PKG STAGE
    local pkg=$1 st=$2 L=${1^^}.$2 h f
    h=$(dnl_host)
    cell "$pkg/$st-stub-stop" "$h" "sudo bash $VMD/dn-vm.sh dns-stop $pkg" none < /dev/null
    expect "$L.stub.stopped" "$OUT/$pkg/$st-stub-stop.txt" "^DNS_STOPPED $pkg\$"
    cell "$pkg/$st-stub-log" "$h" "sudo bash $VMD/dn-vm.sh dns-log $pkg" none < /dev/null
    info "$L.stub.queries" "$OUT/$pkg/$st-stub-log.txt" '^T [0-9.]+ (udp|tcp) '
    cell "$pkg/$st-listen53" "$h" "bash $VMD/dn-vm.sh listen53 $DNL_NS_IP" none < /dev/null
    # only the lab address the stub bound counts: Fedora's systemd-resolved keeps its own stub on 127.0.0.53 and 127.0.0.54, port 53, UDP and TCP (the shake-out of 2026-10-13 had four red rows for them)
    expect "$L.stub.nothing-on-port-53" "$OUT/$pkg/$st-listen53.txt" "^LISTEN53_ON ${DNL_NS_IP//./\\.} 0\$"
    info "$L.stub.other-listeners-on-53" "$OUT/$pkg/$st-listen53.txt" '^LISTEN53_LINES ' "(none)"
    cell "$pkg/$st-sums-after" client1 "bash $VMD/dn-vm.sh sums" none < /dev/null
    f="$OUT/$pkg/$st"
    verdict "$L.resolver-untouched" "$([ -s "$f-sums-before.txt" ] && cmp -s <(grep -E '^(resolv|nsswitch)\.conf:' "$f-sums-before.txt") <(grep -E '^(resolv|nsswitch)\.conf:' "$f-sums-after.txt") && echo PASS || echo FAIL)" \
        "client1's /etc/resolv.conf and /etc/nsswitch.conf (sha256 and target) are the same after the stage as before: no system file was edited" same "$(grep -cE '^(resolv|nsswitch)\.conf:' "$f-sums-after.txt" 2> /dev/null) lines compared"
    return 0
}

dnl_conf() {   # dnl_conf NAME TEXT: the krb5.conf variant for client1 ($VMD/b2c/NAME.conf, mode 644)
    local name=$1 text=$2 lf="$TMPDIR/dnl-conf-$1.conf"
    mkdir -p "$TMPDIR"
    printf '%s\n' "$text" > "$lf"
    push client1 "$lf" "$VMD/b2c/$name.conf" 644
    local rc=$?
    rm -f "$lf"
    return $rc
}

dnl_cap_start() {   # dnl_cap_start PKG NAME
    vm client1 "sudo bash $VMD/b2c-vm.sh pcap-start $2 'port 53 or port 88'" 2>&1 < /dev/null | redact > "$OUT/$1/capctl-$2-start.txt"
    expect "${1^^}.cap.$2.started" "$OUT/$1/capctl-$2-start.txt" '^PCAP_STARTED '
}
dnl_cap_stop() {   # dnl_cap_stop PKG NAME: stop, pull the capture to the host (0600, outside the record), summarize into $OUT/PKG/flow-NAME.txt
    local pkg=$1 name=$2 pf s pd
    pd=${B2C_PCAPDIR:-${W:?W is not set}/b2c-pcap}
    pf="$pd/$pkg-$name.pcap"; s="$OUT/$pkg/flow-$name.txt"
    vm client1 "sudo bash $VMD/b2c-vm.sh pcap-stop $name" 2>&1 < /dev/null | redact > "$OUT/$pkg/capctl-$name-stop.txt"
    mkdir -p "$pd"; chmod 700 "$pd"
    ( umask 077; vm client1 "sudo bash $VMD/b2c-vm.sh pcap-get $name" > "$pf" 2>> "$LOG" )
    vm client1 "sudo bash $VMD/b2c-vm.sh pcap-rm $name" > /dev/null 2>&1 < /dev/null
    {
        echo "# flow of $pkg/$name on client1 (port 53 and 88), the DNS names $DNL_MATCH; T+ is the seconds since the first event; the capture is on the host: $(basename "$pf")"
        python3 -B -I "$SCRIPTS/helpers/b2c-pcap.py" flow "$pf" --match "$DNL_MATCH" --kdc-port "$DNL_KDC_PORT" 2>&1
    } > "$s"
    cat "$OUT/$pkg/capctl-$name-stop.txt" >> "$LOG"
    expect "${pkg^^}.cap.$name.stopped" "$OUT/$pkg/capctl-$name-stop.txt" '^PCAP_STOPPED '
    expect "${pkg^^}.cap.$name.has-events" "$s" '^T\+[0-9.]+ (DNS-Q|KDC) '
    b2c_cap_stats "${pkg^^}.cap.$name" "$OUT/$pkg/capctl-$name-stop.txt"
}

dnl_login() {   # dnl_login CELL TOOL CONFNAME [b2c-vm.sh login options] -- KINIT-ARGS...: on client1, in the private resolver (nameserver = the DNS host), as the lab user; stdin = the password line
    local name=$1 prog=$2 conf=$3 cmd
    shift 3
    local -a opts=() kargs=()
    local seen=0 a
    for a in "$@"; do
        if [ "$seen" = 0 ] && [ "$a" = -- ]; then seen=1; continue; fi
        if [ "$seen" = 0 ]; then opts+=("$a"); else kargs+=("$a"); fi
    done
    cmd="sudo bash $VMD/dn-vm.sh nsrun --ns $DNL_NS_IP -- bash $VMD/b2c-vm.sh login --conf $VMD/b2c/$conf.conf $(b2c_q "${opts[@]}") -- $(b2c_tool "$prog" kinit) $(b2c_q "${kargs[@]}")"
    cell "$name" client1 "$cmd" kdc
}

dnl_log_mark() {   # dnl_log_mark PKG: the number of lines of the stub's query log now (the cell's own lines are the ones after it)
    local h n
    h=$(dnl_host)
    n=$(vm "$h" "sudo bash $VMD/dn-vm.sh dns-logsize $1" 2>> "$LOG" < /dev/null | sed -n 's/^DNS_LOG_LINES //p' | head -n 1)
    printf '%s' "${n:-0}"
}
dnl_log_get() {   # dnl_log_get PKG CELL FROM: the stub's log lines after the first FROM, into $OUT/PKG/stublog-CELL.txt (what reached the server, whatever the capture caught)
    cell "$1/stublog-$2" "$(dnl_host)" "sudo bash $VMD/dn-vm.sh dns-log $1 $3" none < /dev/null
}

dnl_count() { grep -cE -- "$2" "$1" 2> /dev/null || true; }   # dnl_count FILE RX: the number of lines of a flow file that match RX

dnl_seq() {   # dnl_seq FILE: the KDC attempts of a flow, in order, `udp 192.0.2.1:88` / `tcp-syn ...`, a repeat of the same line collapsed
    awk '$2 == "KDC" { l = $3 " " $4; sub(/^dst=/, "", $4); l = $3 " " $4; if (l != prev) print l; prev = l }' "$1" 2> /dev/null
}

dnl_walk() {   # dnl_walk FILE DEADADDR: for every attempt at DEADADDR (host:port; the first of a run of them) that attempt and the next attempt at another destination, `proto dst` per line: the walk of a send. The VM's other Kerberos
    # chatter (client1's NFS machinery asks the same KDC now and then) is left out except where it lands right after a dead attempt, and then it is still a live-KDC attempt.
    awk -v dead="$2" '
        $2 == "KDC" {
            d = $4; sub(/^dst=/, "", d); l = $3 " " d
            if (pending && d != dead) { print l; pending = 0 }
            if (d == dead && !pending) { print l; pending = 1 }
        }' "$1" 2> /dev/null
}

dnl_gaps() {   # dnl_gaps FILE DEADADDR: for every attempt at DEADADDR (host:port) the seconds to the next attempt at another destination, one per line
    awk -v dead="$2" '
        $2 == "KDC" {
            t = substr($1, 3) + 0; d = $4; sub(/^dst=/, "", d)
            if (pending && d != dead) { printf "%.3f\n", t - pt; pending = 0 }
            if (d == dead) { if (!pending) { pt = t; pending = 1 } }
        }' "$1" 2> /dev/null
}
