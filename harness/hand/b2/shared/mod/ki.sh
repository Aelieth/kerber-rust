# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/ki.sh: B2-style module KI, the VM leg of the KI series (kinit -a, noaddresses, the changepw request and kpasswd's KRB-PRIV), MIT first (lab-agent; cells: VM-LEG.md K0-K9).
# Not a package of the B2 survey: the head implementer asked for the cells of VM-LEG.md; it runs beside the B2 modules in one hold (B2_EXTRA=ki).
# What the change is (VM-LEG.md): MIT's `kinit -a` sends krb5_os_localaddr's list in the AS-REQ (every UP interface's address, IPv4 then IPv6, less 127.0.0.1, ::1 and fe80::/10, repeats dropped; kinit.c:674-683,
# localaddr.c:415-481), a false `noaddresses` does the same (get_in_tkt.c:998-1005); the expired-password flow's changepw request drops the -a list (gic_pwd.c:163) and follows `noaddresses`; kpasswd's request follows
# `noaddresses`. Ours sent ONE IPv4 address. Equality expected, cell for cell: MIT's client and ours send the same list in the same order, and the ticket carries the same `Addresses:` line. A red on ours only is PRODUCT.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43 and its kinit/kpasswd; ours = after docs/install.md's upgrade of the ship build and our kinit/kpasswd), on client2, as the lab user, with a private cache
# per run and a capture around each run (tcpdump -i any 'port 88 or port 464' on client2, pulled to the host and decoded there: helpers/ki-asreq-addrs.py is KI's decoder, byte for byte, helpers/ki-fmt.py formats it):
#   K0 control   BEFORE the setup: `kinit -a kiuser`, `klist -a -n`                           the NIC's addresses alone (none of 127.0.0.1, ::1, fe80::, the setup's)
#   K1 -a        after the setup: `kinit -a kiuser`, `klist -a -n`, `kvno host/client2`      AS-REQ and Addresses: = the expected list; the kvno works (its source is in the list)
#   K2 default   `kinit kiuser`, `klist -a -n`                                                 no address field; Addresses: absent
#   K3 -A        profile `noaddresses = false`: `kinit -A kiuser`                              none
#   K4 false     the same profile: `kinit kiuser`, `klist -a -n`                               the list again
#   K5 down      kidum0 DOWN: `kinit -a kiuser`; kidum0 UP again                               the list loses 192.0.2.77, 198.51.100.77 and 2001:db8:7::77
#   K6 changepw  REQUIRES_PWCHANGE principal: `kinit -a`, old password, new twice              AS-REQs krbtgt (list), kadmin/changepw (NONE), krbtgt (list)
#   K7 changepw  the same, profile `noaddresses = false`, no -a                                all three carry the list
#   K8 kpasswd   profile false: `kpasswd kinew..` (old, new, new); then `kinit` with the new password   its AS-REQ for kadmin/changepw carries the list; "Password changed."; the new password kinits;
#                with the default profile (K8d): no address field
#   K8b request  four `kpasswd` runs of each tool (kiwbm, kiwbr; the password goes between the leg's PW1 and PW2; the default profile, so no address in the ticket), one capture each; KI's
#                kpasswd-req-lengths.py (helpers/ki-req-lengths.py, byte for byte) reads each request: msg, ap_req, ticket_cipher, auth_cipher, priv, priv_cipher. Equal for MIT's kpasswd and ours (tree
#                bc69af3e: the authenticator carries no sequence number any more; the first leg saw ap_req and auth_cipher 5 longer for ours in all 16 requests). The authenticator's microseconds are an
#                INTEGER of 3, 2 or 1 octets (2 or fewer in 3.3% of the runs): auth_cipher, ap_req and msg can differ by 1 or 2, so the judged row compares the largest value of the four runs of
#                each tool (a run with small microseconds cannot be the largest of four but for one run in a million), and the single runs of K6, K7, K8f and K8d are judged with a tolerance of 2
#                octets, the same in the three. The first leg's defect (5 octets in every run) is seen by both.
#   K9           the IPv6 server path: not built (VM-LEG: only when the kdc has a global IPv6 address; the namespace run ns-priv6 settles the KRB-PRIV sender); an INFO row says so
# The expected list is read from the VM, not assumed: helpers/ki-vm.sh `expect` prints the addresses of the UP interfaces (IPv4 less 127.0.0.1, then IPv6 less ::1 and fe80::/10, each family in interface order),
# once before the setup (K0), once with kidum0 up (K1-K4, K6-K8), once with it down (K5). Rows: the AS-REQ signature of the cell (service=addresses in wire order, repeats collapsed) against the expected one, the ticket's
# Addresses: line, rc, no secret marker; parity rows compare the signature files MIT's tool against ours' tool (same KDC) and MIT's KDC against the ship KDC (same tool); controls fire as VM-LEG.md lists them.
# kpasswd's request on the wire: K8's capture counts the packets to and from port 464 (INFO and a judged row); the KRB-PRIV inside is encrypted (MIT's kadmind does not check its sender), the VMs show that the request
# works against MIT's kadmind and ours.
# Differences from VM-LEG.md:
#   - the module runs inside the B2 shell (L1 resets and the Fedora identity rule, install.md's upgrade by otp/install-ours.sh, the state rows, the restore), not as a separate driver; ours run as $VMD/ours/{kinit,kvno,kpasswd}
#     (the names dist/install.sh install-clients gives them), not as /home/lab/ki/bin/krb5-*; `klist -a -n` is MIT's /usr/bin/klist for both (it reads either cache);
#   - the kvno of K1 asks for host/client2.kerber.test (the client's own host principal): the lab realm has no host/kdc.kerber.test; its source address is the NIC, which is in the list;
#   - the expired-password principals and the kpasswd principals are made per tool (kiexp6m kiexp6r kiexp7m kiexp7r, kinewmf kinewmd kinewrf kinewrd), so no cell needs a password reset between tools; the kdc-side script makes
#     and deletes them (the shell's realm row watches alice); the leg's throwaway passwords stand for the lab user's (the passwords are on ssh stdin only);
#   - the capture is one per run (not one for the leg), so each run's AS-REQs are read alone; the capture is on client2, else on the kdc when client2 has no tcpdump.
# Not built (VM-LEG.md): K9's IPv6 server cell, the TCP AS-REQ that spans segments (counted by KI's decoder, not read).
# shellcheck source=/dev/null
. "$SCRIPTS/helpers/b2a-host.sh"
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

ki_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${KI_INIT_DONE:-}" ] && return 0
    KI_INIT_DONE=1
    b2c_init
    KI_CAPVM=client2
    KI_NIC=${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}.22
    KI_SVC=host/client2.kerber.test
    KI_PRINCS='kiuser kiexp6m kiexp6r kiexp7m kiexp7r kinewmf kinewmd kinewrf kinewrd kiwbm kiwbr'
    KI_KEEP='^ki(user|exp[67][mr]|new[mr][fd]|wb[mr])@'
    KI_SETUP_ADDRS='192.0.2.77 198.51.100.77 2001:db8:7::77'
    KI_E0=""; KI_E1=""; KI_E5=""
}

ki_prep() {
    local f
    ki_init
    for f in ki-kdc.sh ki-vm.sh ki-fmt.py ki-asreq-addrs.py b2a-lib.sh b2a-kdcconf.py b2a-host.sh b2c-pcap.py; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "ki: helpers/$f is missing" >&2; return 1; }; done
    b2c_prep_check || return 1
    return 0
}

ki_push() {   # the kdc-side script, the client helper, b2c-vm.sh on client2 (and the kdc, for the capture fallback); where the capture runs
    local v
    ki_init
    b2a_push_script ki-kdc.sh || return 1
    b2c_push_vm kdc client2 || return 1
    push client2 "$SCRIPTS/helpers/ki-vm.sh" "$VMD/ki-vm.sh" 755 || return 1
    v=$(vm client2 'command -v tcpdump' 2>> "$LOG" < /dev/null)
    if [ -n "$v" ]; then KI_CAPVM=client2; else KI_CAPVM=kdc; fi
    note "ki: captures run on $KI_CAPVM (tcpdump on client2: ${v:-none})"
    return 0
}

ki_vmx() {   # ki_vmx NAME SUB: ki-vm.sh SUB on client2 as root; the transcript is $OUT/ki/NAME.txt
    local name=$1 sub=$2
    cell "ki/$name" client2 "sudo bash $VMD/ki-vm.sh $sub; echo \"[rc=\$?]\"" none < /dev/null
}

ki_exp_of() {   # ki_exp_of NAME: the EXPECT_ADDRS list of a ki_vmx expect transcript ("UNKNOWN" when it printed none)
    local line
    line=$(sed -n 's/^EXPECT_ADDRS //p' "$OUT/ki/$1.txt" 2> /dev/null | head -n 1)
    if grep -q '^EXPECT_ADDRS' "$OUT/ki/$1.txt" 2> /dev/null; then printf '%s' "$line"; else printf 'UNKNOWN'; fi
}

ki_cap_start() {   # ki_cap_start NAME: tcpdump around the next run (client2, else the kdc filtered to client2's lab address)
    local nm=$1 flt='port 88 or port 464'
    [ "$KI_CAPVM" = kdc ] && flt="(port 88 or port 464) and host $KI_NIC"
    vm "$KI_CAPVM" "sudo bash $VMD/b2c-vm.sh pcap-start $nm '$flt'" 2>&1 < /dev/null | redact > "$OUT/ki/pcapctl-$nm-start.txt"
    grep -q '^PCAP_STARTED ' "$OUT/ki/pcapctl-$nm-start.txt"
}

ki_cap_stop() {   # ki_cap_stop NAME: stop, pull the capture to the host (0600, outside the record), decode it into $OUT/ki/NAME-sig.txt, NAME-ports.txt and NAME-lengths.txt
    local nm=$1 pd pf names
    names="$OUT/ki/pcapnames-$nm.txt"
    pd=${W:?W is not set}/ki-pcap; pf="$pd/$nm.pcap"
    mkdir -p "$pd"; chmod 700 "$pd"
    vm "$KI_CAPVM" "sudo bash $VMD/b2c-vm.sh pcap-stop $nm" 2>&1 < /dev/null | redact > "$OUT/ki/pcapctl-$nm-stop.txt"
    ( umask 077; vm "$KI_CAPVM" "sudo bash $VMD/b2c-vm.sh pcap-get $nm" > "$pf" 2>> "$LOG" < /dev/null )
    vm "$KI_CAPVM" "sudo bash $VMD/b2c-vm.sh pcap-rm $nm" > /dev/null 2>&1 < /dev/null
    {
        python3 -B -I "$SCRIPTS/helpers/b2c-pcap.py" summarize "$pf" --names > "$names"
        python3 -B -I "$SCRIPTS/helpers/ki-asreq-addrs.py" "$pf" 88 | python3 -B -I "$SCRIPTS/helpers/ki-fmt.py" sig "$names" "$KI_KEEP" > "$OUT/ki/$nm-sig.txt"
        python3 -B -I "$SCRIPTS/helpers/ki-fmt.py" ports "$pf" 464 88 > "$OUT/ki/$nm-ports.txt"
    } 2>> "$LOG"
    { echo "# the change-password requests (port 464) in this run's capture, read by KI's kpasswd-req-lengths.py (none: a run without one)"; python3 -B -I "$SCRIPTS/helpers/ki-req-lengths.py" "$pf" 464 2>> "$LOG"; } > "$OUT/ki/$nm-lengths.txt"
}

ki_klist_addrs() {   # ki_klist_addrs FILE: the Addresses line of `klist -a -n` in a cell transcript, as a,b,c ("none" when the ticket has none)
    awk '/^== then: .*klist/ { on = 1; next } /^== then:/ { on = 0 } /^\[then-rc=/ { on = 0 }
         on && /^[[:space:]]*Addresses:/ { sub(/^[[:space:]]*Addresses:[[:space:]]*/, ""); gsub(/, */, ","); sub(/[[:space:]]+$/, ""); if ($0 == "(none)") $0 = "none"; print; found = 1; exit }
         END { if (!found) print "none" }' "$1"
}

ki_kin() {   # ki_kin STAGE CELL TOOL CONF [b2c_login options] -- KINIT-ARGS...: one login on client2 under a capture; stdin = the password lines. Writes $OUT/ki/STAGE-CELL-TOOL.txt and -sig.txt
    local st=$1 cell=$2 t=$3 conf=$4 cc nm
    shift 4
    ki_init
    cc="$VMD/b2c/ki-$st-$cell-$t.cc"; nm="$st-$cell-$t"
    ki_cap_start "$nm" || note "ki: the capture of $nm did not start"
    b2c_login "ki/$nm" client2 "$t" "$conf" --cc "$cc" --env "KRB5CCNAME=FILE:$cc" "$@"
    ki_cap_stop "$nm"
    printf 'klist %s\n' "$(ki_klist_addrs "$OUT/ki/$nm.txt")" >> "$OUT/ki/$nm-sig.txt"
}

ki_kpw() {   # ki_kpw STAGE CELL TOOL CONF PRINC: kpasswd PRINC under a capture; stdin = old, new, new
    local st=$1 cell=$2 t=$3 conf=$4 princ=$5 nm
    ki_init
    nm="$st-$cell-$t"
    ki_cap_start "$nm" || note "ki: the capture of $nm did not start"
    b2c_run "ki/$nm" client2 --in-stdin --env "KRB5_CONFIG=$VMD/b2c/$conf.conf" -- "$(b2c_tool "$t" kpasswd)" "$princ"
    ki_cap_stop "$nm"
}

ki_pw1() { b2_pw 1; }
ki_pw3() { b2_pw 1; b2_pw 2; b2_pw 2; }
ki_pwnew() { b2_pw 2; }

ki_rows() {   # ki_rows STAGE CELL TOOL RC WANT-SIG [WANT-KLIST]: the rows of one run
    local st=$1 cell=$2 t=$3 rc=$4 want=$5 wk=${6:-} l f s got
    l="KI.$st.$cell-$t"; f="$OUT/ki/$st-$cell-$t.txt"; s="$OUT/ki/$st-$cell-$t-sig.txt"
    expect "$l.rc" "$f" "^\\[rc=$rc\\]\$"
    got=$(sed -n 's/^SIG //p' "$s" 2> /dev/null | head -n 1)
    same "$l.asreq-signature" "$want" "${got:-no-capture}" "the run's AS-REQs in wire order, service=addresses, repeats collapsed"
    if [ -n "$wk" ]; then
        got=$(sed -n 's/^klist //p' "$s" 2> /dev/null | head -n 1)
        same "$l.klist-addresses" "$wk" "${got:-no-klist}" "the Addresses: line of klist -a -n"
    fi
    expect_part "$l.no-secret" "$f" client '<REDACTED:' 0
}

ki_cell() {   # ki_cell STAGE CELL TOOL: one run of one tool; the expected lists are KI_E0 (before the setup), KI_E1 (kidum0 up), KI_E5 (kidum0 down)
    local st=$1 cell=$2 t=$3 tl=m svc="krbtgt/$REALM" kvn
    local -a thens=(--then '/usr/bin/klist -a -n')
    [ "$t" = ours ] && tl=r
    kvn=$(b2c_tool "$t" kvno)
    case $cell in
        K0) ki_pw1 | ki_kin "$st" K0 "$t" ki-base "${thens[@]}" -- -a kiuser; ki_rows "$st" K0 "$t" 0 "$svc=$KI_E0" "$KI_E0" ;;
        K1) ki_pw1 | ki_kin "$st" K1 "$t" ki-base "${thens[@]}" --then "$kvn $KI_SVC" -- -a kiuser
            ki_rows "$st" K1 "$t" 0 "$svc=$KI_E1" "$KI_E1"
            expect_under "KI.$st.K1-$t.kvno" "$OUT/ki/$st-K1-$t.txt" '^== then: .*kvno' "^$KI_SVC@$RRX: kvno = [0-9]+\$"
            expect_under "KI.$st.K1-$t.kvno-rc" "$OUT/ki/$st-K1-$t.txt" '^== then: .*kvno' '^\[then-rc=0\]$' ;;
        K2) ki_pw1 | ki_kin "$st" K2 "$t" ki-base "${thens[@]}" -- kiuser; ki_rows "$st" K2 "$t" 0 "$svc=none" none ;;
        K3) ki_pw1 | ki_kin "$st" K3 "$t" ki-false "${thens[@]}" -- -A kiuser; ki_rows "$st" K3 "$t" 0 "$svc=none" none ;;
        K4) ki_pw1 | ki_kin "$st" K4 "$t" ki-false "${thens[@]}" -- kiuser; ki_rows "$st" K4 "$t" 0 "$svc=$KI_E1" "$KI_E1" ;;
        K5) ki_pw1 | ki_kin "$st" K5 "$t" ki-base "${thens[@]}" -- -a kiuser; ki_rows "$st" K5 "$t" 0 "$svc=$KI_E5" "$KI_E5" ;;
        K6) ki_pw3 | ki_kin "$st" K6 "$t" ki-base "${thens[@]}" -- -a "kiexp6$tl"
            ki_rows "$st" K6 "$t" 0 "$svc=$KI_E1 > kadmin/changepw=none > $svc=$KI_E1" "$KI_E1" ;;
        K7) ki_pw3 | ki_kin "$st" K7 "$t" ki-false "${thens[@]}" -- "kiexp7$tl"
            ki_rows "$st" K7 "$t" 0 "$svc=$KI_E1 > kadmin/changepw=$KI_E1 > $svc=$KI_E1" "$KI_E1" ;;
        K8f) ki_pw3 | ki_kpw "$st" K8f "$t" ki-false "kinew${tl}f"
            ki_rows "$st" K8f "$t" 0 "kadmin/changepw=$KI_E1"
            expect "KI.$st.K8f-$t.changed" "$OUT/ki/$st-K8f-$t.txt" '^Password changed\.$'
            ki_wire "$st" K8f "$t"
            ki_pwnew | ki_kin "$st" K8fk "$t" ki-base "${thens[@]}" -- "kinew${tl}f"; ki_rows "$st" K8fk "$t" 0 "$svc=none" none ;;
        K8d) ki_pw3 | ki_kpw "$st" K8d "$t" ki-base "kinew${tl}d"
            ki_rows "$st" K8d "$t" 0 "kadmin/changepw=none"
            expect "KI.$st.K8d-$t.changed" "$OUT/ki/$st-K8d-$t.txt" '^Password changed\.$'
            ki_wire "$st" K8d "$t"
            ki_pwnew | ki_kin "$st" K8dk "$t" ki-base "${thens[@]}" -- "kinew${tl}d"; ki_rows "$st" K8dk "$t" 0 "$svc=none" none ;;
        *) return 1 ;;
    esac
    return 0
}

ki_wire() {   # ki_wire STAGE CELL TOOL: kpasswd's request on the wire (port 464): packets with a payload to and from the port, from the run's capture
    local st=$1 cell=$2 t=$3 f line to from
    f="$OUT/ki/$st-$cell-$t-ports.txt"
    line=$(grep '^port 464 ' "$f" 2> /dev/null | head -n 1)
    to=$(printf '%s' "$line" | sed -n 's/.* to=\([0-9]*\) .*/\1/p'); from=$(printf '%s' "$line" | sed -n 's/.* from=\([0-9]*\) .*/\1/p')
    verdict "KI.$st.$cell-$t.wire-464" "$([ "${from:-0}" -ge 1 ] && echo PASS || echo FAIL)" "kpasswd's request on port 464 is answered (packets with a payload from the port: 1 or more; the request's own segment is counted too: to=${to:-0})" "from>=1" "${line:-no-capture}"
}

ki_len_val() {   # ki_len_val FILE FIELD: FIELD (msg ap_req ticket_cipher auth_cipher priv priv_cipher) of the first change-password request in a lengths file (KI's decoder: one line per request)
    sed -nE "s/.* $2=([0-9]+).*/\1/p" "$1" 2> /dev/null | head -n 1
}
ki_len_n() {   # ki_len_n FILE: the number of requests the decoder read
    grep -c ' ap_req=' "$1" 2> /dev/null || true
}
ki_max_of() {   # ki_max_of N...: the largest of the numbers (empty when there is none)
    printf '%s\n' "$@" | grep -E '^[0-9]+$' | sort -n | tail -n 1
}

ki_len_diff() {   # ki_len_diff FILE-MIT FILE-OURS FIELD: ours minus MIT for FIELD ("x" when either side has no request)
    local a b
    a=$(ki_len_val "$1" "$3"); b=$(ki_len_val "$2" "$3")
    if [ -n "$a" ] && [ -n "$b" ]; then echo $(( b - a )); else echo x; fi
}
ki_lenpair() {   # ki_lenpair STAGE CELL: the request of MIT's tool and of ours in one cell (K6 K7 K8f K8d): ticket, priv and priv_cipher equal; auth_cipher, ap_req and msg equal or off by the same 1 or 2 (the microseconds)
    local st=$1 cell=$2 L=KI.$1.$2.request fm="$OUT/ki/$1-$2-mit-lengths.txt" fo="$OUT/ki/$1-$2-ours-lengths.txt" fld a b ok=1 txt="" da db dc
    for fld in ticket_cipher priv priv_cipher; do
        a=$(ki_len_val "$fm" "$fld"); b=$(ki_len_val "$fo" "$fld")
        { [ -n "$a" ] && [ "$a" = "$b" ]; } || ok=0
        txt="$txt $fld $a/$b"
    done
    da=$(ki_len_diff "$fm" "$fo" auth_cipher); db=$(ki_len_diff "$fm" "$fo" ap_req); dc=$(ki_len_diff "$fm" "$fo" msg)
    if [ "$da" = x ] || [ "$db" = x ] || [ "$dc" = x ]; then ok=0
    elif [ "$da" != "$db" ] || [ "$da" != "$dc" ] || [ "$da" -lt -2 ] || [ "$da" -gt 2 ]; then ok=0; fi
    txt="$txt auth_cipher(ours-MIT) $da ap_req $db msg $dc"
    verdict "$L" "$([ "$ok" = 1 ] && echo PASS || echo FAIL)" "the request's parts, MIT's tool = ours (the authenticator may differ by 1 or 2 octets, the same in ap_req and msg)" "equal" "${txt# }"
}

ki_k8b() {   # ki_k8b STAGE: K8b, the request's parts: four kpasswd runs of each tool (kiwbm, kiwbr), the password going between PW1 and PW2, the default profile
    local st=$1 L=KI.$1.K8b t tl i old new fld vm_ vo_ vma voa mm mo fx dm dp am="" ao=""
    for i in 1 2 3 4; do
        for t in mit ours; do
            tl=m; [ "$t" = ours ] && tl=r
            if [ $((i % 2)) = 1 ]; then old=1; new=2; else old=2; new=1; fi
            deadline
            { b2_pw "$old"; b2_pw "$new"; b2_pw "$new"; } | ki_kpw "$st" "K8b$i" "$t" ki-base "kiwb$tl"
            expect "KI.$st.K8b$i-$t.rc" "$OUT/ki/$st-K8b$i-$t.txt" '^\[rc=0\]$'
            expect "KI.$st.K8b$i-$t.changed" "$OUT/ki/$st-K8b$i-$t.txt" '^Password changed\.$'
            same "KI.$st.K8b$i-$t.one-request" 1 "$(ki_len_n "$OUT/ki/$st-K8b$i-$t-lengths.txt")" "change-password requests the decoder read from the run's capture (port 464)"
            expect_part "KI.$st.K8b$i-$t.no-secret" "$OUT/ki/$st-K8b$i-$t.txt" client '<REDACTED:' 0
        done
    done
    for fld in msg ap_req ticket_cipher auth_cipher priv priv_cipher; do
        vm_=""; vo_=""
        for i in 1 2 3 4; do
            vm_="$vm_ $(ki_len_val "$OUT/ki/$st-K8b$i-mit-lengths.txt" "$fld")"
            vo_="$vo_ $(ki_len_val "$OUT/ki/$st-K8b$i-ours-lengths.txt" "$fld")"
        done
        read -ra vma <<< "$vm_"; read -ra voa <<< "$vo_"
        result "$L.$fld.values" INFO "$fld of the four requests: MIT's kpasswd | ours" - 0 "${vm_# } | ${vo_# }"
        case $fld in
            ticket_cipher|priv|priv_cipher)   # the same principal names and realm, the same KDC, the same password length: equal in all eight
                fx=$(printf '%s\n' "${vma[@]}" "${voa[@]}" | sort -u | grep -c . || true)
                verdict "$L.$fld" "$([ "$fx" = 1 ] && [ "$(printf '%s\n' "${vma[@]}" "${voa[@]}" | grep -c -E '^[0-9]+$')" = 8 ] && echo PASS || echo FAIL)" "$fld is one value in all eight requests (four of each tool)" "1 value" "${vm_# } | ${vo_# }" ;;
            *)   # the authenticator's microseconds: the largest of four
                mm=$(ki_max_of "${vma[@]}"); mo=$(ki_max_of "${voa[@]}")
                [ "$fld" = auth_cipher ] && { am=$mm; ao=$mo; }
                same "$L.$fld.max" "$mm" "$mo" "the largest $fld of the four requests of each tool is equal (the first leg: ours was 5 longer in every request)" ;;
        esac
    done
    # the control: the comparison must see the first leg's defect (5 octets in every request of ours)
    dm=${am:-0}; dp=$(( ${ao:-0} + 5 ))
    verdict "$L.control.sees-5" "$([ -n "$am" ] && [ "$dm" != "$dp" ] && echo PASS || echo FAIL)" "ours' authenticator made 5 octets longer (the first leg's defect) is not equal to MIT's" differ "MIT ${am:-?} / ours+5 $dp"
}

ki_stage() {   # ki_stage mit|ours
    local st=$1 L=KI.$1 t cell n a bad
    ki_init
    b2c_kdc_ready ki "$st" || return 0
    b2c_work_ok ki "$st" client2 || { b2c_not_run "$L.cells" "client2's work directory cannot be used by the lab user (see $L.workdir.client2): no cell ran"; return 0; }
    b2c_conf ki client2 ki-base || { b2c_not_run "$L.conf" "no conf copy on client2"; return 0; }
    b2c_conf ki client2 ki-false --libdefaults-first 'noaddresses = false' || { b2c_not_run "$L.conf" "no noaddresses = false conf on client2"; return 0; }
    b2a_pw3 | b2a_run_kdc "ki/$st-run-setup" ki-kdc.sh "$st" setup
    b2a_split "$OUT/ki/$st-run-setup.txt" "$OUT/ki" "$st"
    for n in $KI_PRINCS; do expect "$L.setup.$n-created" "$OUT/ki/$st-add-$n.txt" "^Principal \"$n@$RRX\" created\\.\$"; done
    for n in kiexp6m kiexp6r kiexp7m kiexp7r; do expect "$L.setup.$n-needchange" "$OUT/ki/$st-needchange-$n.txt" "^Principal \"$n@$RRX\" modified\\.\$"; done
    # K0, before the setup
    ki_vmx "$st-teardown0" teardown
    ki_vmx "$st-facts" facts
    ki_vmx "$st-expect-before" expect
    KI_E0=$(ki_exp_of "$st-expect-before")
    for t in mit ours; do deadline; ki_cell "$st" K0 "$t"; done
    # the setup
    ki_vmx "$st-setup" setup
    expect "$L.setup.interfaces" "$OUT/ki/$st-setup.txt" '^SETUP_OK$'
    for n in 192.0.2.77/24 198.51.100.77/24 2001:db8:7::77/64 203.0.113.77/24; do expect "$L.setup.addr-${n%%/*}" "$OUT/ki/$st-setup.txt" "inet6? ${n//./\\.}"; done
    ki_vmx "$st-expect-up" expect
    KI_E1=$(ki_exp_of "$st-expect-up")
    bad=0
    for a in $KI_SETUP_ADDRS; do case ",$KI_E1," in *",$a,"*) ;; *) bad=1 ;; esac; done
    verdict "$L.setup.expected-list-has-the-setup" "$([ "$bad" = 0 ] && echo PASS || echo FAIL)" "the expected list holds the three setup addresses" in "$KI_E1"
    case ",$KI_E1," in *",203.0.113.77,"*|*",127.0.0.1,"*|*",::1,"*) verdict "$L.setup.expected-list-excludes" FAIL "the expected list lacks 203.0.113.77 (kidum1 is down), 127.0.0.1 and ::1" out in "$KI_E1" ;; *) verdict "$L.setup.expected-list-excludes" PASS "the expected list lacks 203.0.113.77 (kidum1 is down), 127.0.0.1 and ::1" out out "" ;; esac
    for cell in K1 K2 K3 K4; do for t in mit ours; do deadline; ki_cell "$st" "$cell" "$t"; done; done
    # K5: kidum0 down, then up again
    ki_vmx "$st-down" down
    expect "$L.K5.down" "$OUT/ki/$st-down.txt" '^DOWN_OK$'
    ki_vmx "$st-expect-down" expect
    KI_E5=$(ki_exp_of "$st-expect-down")
    for t in mit ours; do deadline; ki_cell "$st" K5 "$t"; done
    ki_vmx "$st-up" up
    expect "$L.K5.up" "$OUT/ki/$st-up.txt" '^UP_OK$'
    ki_vmx "$st-expect-up2" expect
    same "$L.K5.list-restored" "$KI_E1" "$(ki_exp_of "$st-expect-up2")" "the list after kidum0 is up again equals the list before"
    for cell in K6 K7 K8f K8d; do for t in mit ours; do deadline; ki_cell "$st" "$cell" "$t"; done; done
    for cell in K6 K7 K8f K8d; do ki_lenpair "$st" "$cell"; done
    ki_k8b "$st"
    ki_controls "$st"
    b2c_not_run "$L.K9" "the IPv6 server path is not built (VM-LEG: only with a global IPv6 address on the kdc: $(grep -m1 '^global_ipv6:' "$OUT/ki/$st-run-setup.txt" 2> /dev/null | cut -c1-120)); ns-priv6 settles the KRB-PRIV sender"
    # undo
    ki_vmx "$st-teardown" teardown
    expect "$L.teardown.left" "$OUT/ki/$st-teardown.txt" '^KIDUM_LEFT 0$'
    b2a_pw3 | b2a_run_kdc "ki/$st-run-cleanup" ki-kdc.sh "$st" cleanup
    b2a_split "$OUT/ki/$st-run-cleanup.txt" "$OUT/ki" "$st"
    for n in $KI_PRINCS; do expect "$L.cleanup.$n-deleted" "$OUT/ki/$st-del-$n.txt" "^Principal \"$n@$RRX\" deleted\\.\$"; done
    expect "$L.cleanup.kiuser-gone" "$OUT/ki/$st-getprinc-gone.txt" '^get_principal: Principal does not exist while retrieving "kiuser@'"$RRX"'"\.$'
    return 0
}

ki_sig_of() { sed -n 's/^SIG //p' "$OUT/ki/$1-sig.txt" 2> /dev/null | head -n 1; }   # ki_sig_of STAGE-CELL-TOOL

ki_controls() {   # ki_controls STAGE: the controls VM-LEG.md says must fire
    local st=$1 L=KI.$1 t a k0 k1 k2 k3 k4 k5 miss
    for t in mit ours; do
        k0=$(ki_sig_of "$st-K0-$t"); k1=$(ki_sig_of "$st-K1-$t"); k2=$(ki_sig_of "$st-K2-$t"); k3=$(ki_sig_of "$st-K3-$t"); k4=$(ki_sig_of "$st-K4-$t"); k5=$(ki_sig_of "$st-K5-$t")
        miss=0; for a in $KI_SETUP_ADDRS; do case "$k0" in *"$a"*) miss=1 ;; esac; done
        verdict "$L.control.K0-lacks-the-setup-$t" "$([ "$miss" = 0 ] && [ -n "$k0" ] && echo PASS || echo FAIL)" "K0's list (before the setup) lacks the setup addresses" lacks "${k0:-no-capture}"
        verdict "$L.control.K5-shrinks-$t" "$([ -n "$k5" ] && [ "$k5" != "$k1" ] && echo PASS || echo FAIL)" "K5 (kidum0 down) sends a shorter list than K1" differ "${k5:-no-capture}"
        verdict "$L.control.K2-K3-empty-$t" "$([ -n "$k2" ] && [ "$k2" = "$k3" ] && [ "$k1" != "$k2" ] && [ "$k4" != "$k3" ] && echo PASS || echo FAIL)" "K2 and K3 send no list where K1 and K4 do" "none vs list" "$k2 | $k3"
        verdict "$L.control.kvno-from-the-nic-$t" "$(sed -n '/^== then: .*kvno/,/^\[then-rc=/p' "$OUT/ki/$st-K1-$t.txt" 2> /dev/null | grep -q '^\[then-rc=0\]$' && echo PASS || echo FAIL)" "the kvno after K1 succeeds from the NIC although the ticket lists every address" "rc 0" "see $st-K1-$t.txt"
    done
}

ki_mit() { ki_init; ki_stage mit; }
ki_ours() { ki_init; ki_stage ours; }

ki_parity() {
    local cell st t d="$OUT/ki"
    ki_init
    for cell in K0 K1 K2 K3 K4 K5 K6 K7 K8f K8fk K8d K8dk; do
        for st in mit ours; do parity_eq "KI.parity.$cell-prog-$st" "$d/$st-$cell-mit-sig.txt" "$d/$st-$cell-ours-sig.txt" '/^# /d'; done     # the programs differ, the KDC does not
        for t in mit ours; do parity_eq "KI.parity.$cell-xkdc-$t" "$d/mit-$cell-$t-sig.txt" "$d/ours-$cell-$t-sig.txt" '/^# /d'; done         # the KDC changes, the program does not
    done
    for cell in K8f K8d; do
        for st in mit ours; do
            cell_body "$d/$st-$cell-mit.txt" 2> /dev/null | b2_norm /dev/stdin 's#^(/[^ :]*/)?(krb5-)?kpasswd: #PROG: #' 's/kinew[mr]([fd])/kinewT\1/g' > "$d/$st-$cell-mit.body"
            cell_body "$d/$st-$cell-ours.txt" 2> /dev/null | b2_norm /dev/stdin 's#^(/[^ :]*/)?(krb5-)?kpasswd: #PROG: #' 's/kinew[mr]([fd])/kinewT\1/g' > "$d/$st-$cell-ours.body"
            parity_eq "KI.parity.$cell-text-$st" "$d/$st-$cell-mit.body" "$d/$st-$cell-ours.body"
        done
    done
    # controls: a doctored copy differs; two different cells differ
    parity_control KI.parity.K1-prog "$d/mit-K1-mit-sig.txt" "$d/mit-K1-ours-sig.txt" '/^# /d'
    if [ -s "$d/mit-K1-mit-sig.txt" ] && ! cmp -s "$d/mit-K1-mit-sig.txt" "$d/mit-K2-mit-sig.txt"; then verdict KI.parity.control.K1-vs-K2 PASS "two different cells must differ" differ differ ""
    else verdict KI.parity.control.K1-vs-K2 FAIL "two different cells must differ" differ same ""; fi
    return 0
}

ki_clean() {   # the interfaces and the caches: once more, quietly (the reset undoes them in any case)
    ki_init
    vm client2 "sudo bash $VMD/ki-vm.sh teardown" > /dev/null 2>&1 < /dev/null
    b2c_clean_vms
    return 0
}
