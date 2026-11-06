# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# b2c-lib.sh: the shared skeleton of the B2 client modules (mod/pg1.sh pg2.sh pg3.sh pl.sh p6g.sh p6l.sh): "stanza x client x program x KDC".
# Sourced by each of those modules (`declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"`); defines FUNCTIONS ONLY (b2c_init assigns the variables when a module's hook first calls it). Everything runs in driver-b2.sh's shell and
# uses its helpers (cell, push, vm, expect*, verdict, info, result, parity_eq, parity_control, parity_dev, alice_pw, set_conf, restart_cell, redact, note, deadline) and its variables (OUT VMD SCRIPTS W REALM RRX
# CLIENTS LOG). Names: b2c_* functions, B2C_* variables; the modules' own are <pkg>_* (all modules share one shell).
# The pieces:
#   b2c_q ARGS...                          the arguments quoted for a remote shell
#   b2c_tool mit|ours TOOL                 the program on a client: /usr/bin/TOOL, or $VMD/ours/TOOL (the names dist/install.sh install-clients gives)
#   b2c_prep_check                         (module _prep) the helper files are there
#   b2c_push_vm VM...                      (module _push) helpers/b2c-vm.sh to $VMD/b2c-vm.sh on each VM, once per VM; b2c_probe_pcap: tcpdump on the kdc? (B2C_PCAP)
#   b2c_kdc_ready PKG STAGE                (stage hooks, first) krb5kdc active? started once if an earlier module left it down; 1 = NOT-RUN
#   b2c_conf PKG VM NAME [b2c-conf.py options]    $VMD/b2c/NAME.conf on VM := the VM's own krb5.conf edited by the options; the diff is the record ($OUT/PKG/conf-NAME-VM.diff)
#   b2c_login CELL VM PROG CONFNAME [--cc PATH] [--env K=V]... [--then 'CMD']... -- KINIT-ARGS...    one login through `b2c-vm.sh login` as a `cell` ($OUT/CELL.txt); stdin = the password line (alice_pw |)
#   b2c_run CELL VM [--env K=V]... [--rm PATH]... -- PROG ARGS...         one command through `b2c-vm.sh run` as a `cell` (no KDC log part)
#   b2c_work_ok PKG STAGE VM               the pre-cell check: the work directory $VMD/b2c on VM is there and the lab user can make a directory in it (b2c-vm.sh workcheck); a row PKG.STAGE.workdir.VM; status 1 = it cannot
#   b2c_each_cp FN ARGS...                 FN CLIENT PROG ARGS... for client1/client2 x mit/ours
#   b2c_chk_login LABEL FILE mit|ours [RC]  the shape every successful kinit shares: rc, the prompt as the whole stdout, empty stderr, for ours no "ok" or JSON line, no redaction marker
#   b2c_trace FILE                         the trace lines of a cell file without the "[pid] time: " prefix
#   b2c_hint FILE [N]                      the Nth (default 1st) "Processing preauth types:" payload
#   b2c_then FILE HEADER-RX                the lines of the "== then:" block whose header matches
#   b2c_core FILE                          the judged core of a login cell (rc, prompt, stdout shape, stderr with the program name masked, the trace events that carry the protocol), one line each
#   b2c_sizes FILE                         the request sizes of a login cell, one per line
#   b2c_sizes_norm FILE                    the same minus the DER length of the encrypted timestamp's microseconds (1, 2 or 3 bytes: a login is 1 byte shorter in 3 runs in 100); what two logins are compared by
#   b2c_cmp LABEL A B                      MIT-side file A against ours-side file B by their cores: a parity row; b2c_cmp_control LABEL A B: the control
#   b2c_pcap_start PKG NAME / b2c_pcap_stop PKG NAME [--names]     tcpdump on the kdc around a group of logins; the pcap is kept on the host, $OUT/PKG/pcap-NAME.txt is its summary (message kinds, error codes, padata types;
#                                          with --names also the client principal of each exchange, for a module that judges only its own principals' exchanges)
#   b2c_pa_rx N                            an ERE for "padata list contains N" in a pcap summary line
#   b2c_differ LABEL A B                   a control: the cores of two different cells must differ
#   b2c_not_run LABEL REASON               an INFO row "NOT-RUN: REASON"
#   b2c_clean_vms                          (module _clean) b2c-vm.sh clean on every VM; best effort

b2c_init() {   # idempotent; every module's <pkg>_init calls it. The library's variables are assigned HERE, never at the top level of a sourced file (the shell's hygiene check refuses top-level assignments).
    [ -n "${B2C_INIT_DONE:-}" ] && return 0
    B2C_INIT_DONE=1
    B2C_PCAP=${B2C_PCAP:-1}   # 1: tcpdump is on the kdc (b2c_probe_pcap), 0: the capture rows are NOT-RUN
    declare -gA B2C_PUSHED=()
}

b2c_q() { [ $# -gt 0 ] && printf '%q ' "$@"; return 0; }
b2c_tool() { if [ "$1" = ours ]; then printf '%s/ours/%s' "$VMD" "$2"; else printf '/usr/bin/%s' "$2"; fi; }
b2c_prompt() { printf 'Password for %s@%s: \n' "${1:-alice}" "$REALM"; }   # what a kinit prints on stdout when stdin is not a terminal

b2c_prep_check() {   # (module _prep) every input the module needs on the host; a non-zero status makes the shell skip the module (NOT-RUN)
    local f
    for f in b2c-vm.sh b2c-conf.py b2c-pcap.py b2c-lib.sh; do
        [ -f "$SCRIPTS/helpers/$f" ] || { echo "b2c: $SCRIPTS/helpers/$f is missing" >&2; return 1; }
    done
    command -v python3 > /dev/null || { echo "b2c: python3 is missing on the host" >&2; return 1; }
    command -v sha256sum > /dev/null || { echo "b2c: sha256sum is missing on the host" >&2; return 1; }
    return 0
}

b2c_push_vm() {
    local v rc=0
    b2c_init
    for v in "$@"; do
        [ "${B2C_PUSHED[$v]:-0}" = 1 ] && continue
        if push "$v" "$SCRIPTS/helpers/b2c-vm.sh" "$VMD/b2c-vm.sh" 755; then B2C_PUSHED[$v]=1; else rc=1; fi
    done
    return $rc
}

b2c_probe_pcap() {   # (module _push, after b2c_push_vm) tcpdump on the kdc? B2C_PCAP=1|0; a missing tcpdump costs the capture rows, not the cells
    local out
    b2c_init
    out=$(vm kdc "sudo bash $VMD/b2c-vm.sh facts" 2>> "$LOG" < /dev/null)
    if printf '%s\n' "$out" | grep -q '^tcpdump: /'; then B2C_PCAP=1
    else B2C_PCAP=0; note "b2c: no tcpdump on the kdc: the capture rows are NOT-RUN"; fi
    return 0
}

b2c_kdc_ready() {   # b2c_kdc_ready PKG STAGE: krb5kdc is active at the entry of a stage hook. A module before this one may have left it down (the shell reports that module's own row); it is started ONCE here and an INFO row
    # says so, so that this module's cells are not a dozen red rows for someone else's leftover. Status 1 (and a NOT-RUN row) when it will not start: the caller returns.
    local pkg=$1 st=$2 a l=${1^^}
    a=$(vm kdc "systemctl is-active krb5kdc" 2>> "$LOG" < /dev/null | tr -d '[:space:]')
    [ "$a" = active ] && return 0
    result "$l.$st.entry.kdc-was-down" INFO "krb5kdc at the entry of the $st hook" - 1 "was [$a], left by an earlier module; started once by this module"
    vm kdc "sudo systemctl start krb5kdc; sleep 2" > /dev/null 2>&1 < /dev/null
    a=$(vm kdc "systemctl is-active krb5kdc" 2>> "$LOG" < /dev/null | tr -d '[:space:]')
    [ "$a" = active ] && return 0
    b2c_not_run "$l.$st.entry" "krb5kdc is [$a] on the kdc and would not start: no cell of this stage can run"
    return 1
}

b2c_conf() {
    local pkg=$1 v=$2 name=$3 base out
    shift 3
    b2c_init
    mkdir -p "$OUT/$pkg" "$TMPDIR"
    base=$TMPDIR/b2c-base-$v.conf; out=$TMPDIR/b2c-$v-$name.conf
    vm "$v" "cat ${B2C_BASE_CONF:-/etc/krb5.conf}" > "$base" 2>> "$LOG" || { note "b2c_conf: cannot read ${B2C_BASE_CONF:-/etc/krb5.conf} on $v"; return 1; }
    python3 -B -I "$SCRIPTS/helpers/b2c-conf.py" "$base" "$out" "$@" > "$OUT/$pkg/conf-$name-$v.diff" 2>> "$LOG" || { note "b2c_conf: b2c-conf.py failed for $name on $v"; return 1; }
    push "$v" "$out" "$VMD/b2c/$name.conf" 644 || return 1
    rm -f "$base" "$out"
    return 0
}

b2c_login() {   # b2c_login CELL VM PROG CONFNAME [options] -- KINIT-ARGS...
    local name=$1 vmn=$2 prog=$3 conf=$4 cmd
    shift 4
    local -a opts=() kargs=()
    local seen=0 a
    for a in "$@"; do
        if [ "$seen" = 0 ] && [ "$a" = -- ]; then seen=1; continue; fi
        if [ "$seen" = 0 ]; then opts+=("$a"); else kargs+=("$a"); fi
    done
    cmd="bash $VMD/b2c-vm.sh login --conf $VMD/b2c/$conf.conf $(b2c_q "${opts[@]}") -- $(b2c_tool "$prog" kinit) $(b2c_q "${kargs[@]}")"
    cell "$name" "$vmn" "$cmd" kdc
}

b2c_run() {   # b2c_run CELL VM [options] -- PROG ARGS...
    local name=$1 vmn=$2 cmd
    shift 2
    local -a opts=() rest=()
    local seen=0 a
    for a in "$@"; do
        if [ "$seen" = 0 ] && [ "$a" = -- ]; then seen=1; continue; fi
        if [ "$seen" = 0 ]; then opts+=("$a"); else rest+=("$a"); fi
    done
    cmd="bash $VMD/b2c-vm.sh run $(b2c_q "${opts[@]}") -- $(b2c_q "${rest[@]}")"
    cell "$name" "$vmn" "$cmd" none
}

b2c_work_ok() {   # b2c_work_ok PKG STAGE VM: the pre-cell check (b2c-vm.sh workcheck, run as the ssh user like every cell): the work directory $VMD/b2c on VM is there and the lab user can make a directory in it. A row
    # PKG.STAGE.workdir.VM: PASS, or FAIL with the owner, the mode and mktemp's reason in $OUT/PKG/STAGE-workdir-VM.txt (the B2 hold of 2026-10-13 had a root-owned directory on the kdc and 58 rows red for it).
    # Status 1 when it failed: the caller leaves out what needs that VM (NOT-RUN rows) instead of running into a screenful of rc 1 rows.
    local pkg=$1 st=$2 v=$3 n
    n="$pkg/$st-workdir-$v"
    mkdir -p "$OUT/$pkg"
    cell "$n" "$v" "bash $VMD/b2c-vm.sh workcheck; echo \"[rc=\$?]\"" none < /dev/null
    expect "${pkg^^}.$st.workdir.$v" "$OUT/$n.txt" '^WORKDIR_OK '
}

b2c_each_cp() {   # b2c_each_cp FN ARGS...: FN CLIENT PROG ARGS... in the order client1 mit, client1 ours, client2 mit, client2 ours
    local fn=$1 c p
    shift
    for c in "${CLIENTS[@]}"; do
        for p in mit ours; do
            deadline
            "$fn" "$c" "$p" "$@"
        done
    done
    return 0
}

b2c_chk_login() {   # b2c_chk_login LABEL FILE mit|ours [RC]: a login that worked, or the rc it must have
    local l=$1 f=$2 kind=$3 rc=${4:-0} p
    p=$(b2c_prompt alice; printf x); p=${p%x}   # the trailing newline survives the substitution
    expect "$l.rc" "$f" "^\\[rc=$rc\\]\$"
    if [ "$rc" = 0 ]; then
        expect "$l.prompt" "$f" '^PROMPT=yes$'
        expect "$l.stdout-bytes" "$f" "^stdout-bytes ${#p}\$"
        expect "$l.stdout-sha256" "$f" "^stdout-sha256 $(sha_of "$p")\$"
        expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
        expect "$l.ccache" "$f" '^ccache written$'
    fi
    b2c_hyg "$l" "$f" "$kind"
}

b2c_hyg() {   # b2c_hyg LABEL FILE mit|ours: no redaction marker in the client part (nothing printed a lab secret); ours: no "ok ..." line and no JSON log line (the ship build prints what MIT's does)
    local l=$1 f=$2 kind=$3
    expect_part "$l.no-secret-marker" "$f" client '<REDACTED:' 0
    if [ "$kind" = ours ]; then
        expect_part "$l.no-ok-line" "$f" client '^(stdout-line: )?ok( |$)' 0
        expect_part "$l.no-json-line" "$f" client '^(stdout-line: )?\{"' 0
    fi
}

b2c_chk_unrecognized_spake() {   # b2c_chk_unrecognized_spake LABEL FILE mit|ours: a conf with spake_preauth_groups = nosuch. MIT's kinit traces "Unrecognized SPAKE group name: nosuch" once (TRACE_SPAKE_UNKNOWN_GROUP);
    # ours does not: spake_unknown_group (crates/krb5-protocol/src/trace/points.rs:843) has no caller, a trace-only gap that every earlier P6g and PG3 record shows (the ours traces have 0 such lines). MIT: judged; ours: recorded.
    local l=$1 f=$2 kind=$3
    if [ "$kind" = mit ]; then expect "$l.trace-unrecognized-spake" "$f" 'Unrecognized SPAKE group name: nosuch$' 1
    else info "$l.trace-unrecognized-spake" "$f" 'Unrecognized SPAKE group name: nosuch$' "(none: ours does not trace it; spake_unknown_group in trace/points.rs has no caller)"; fi
}

b2c_trace() { sed -n '/^== trace$/,/^== ccache$/p' "$1" | sed -e '1d;$d' | sed -E 's/^\[[0-9]+\] [0-9.]+: //'; }
b2c_hint() { b2c_trace "$1" | grep '^Processing preauth types: ' | sed -n "${2:-1}p"; }
b2c_then() { RX="$2" awk '/^# end of cell output/ { exit } f && /^== / { exit } f { print } /^== then: / && $0 ~ ENVIRON["RX"] { f = 1 }' "$1"; }

b2c_core() {   # b2c_core FILE: one line per judged fact of a login cell, in file order. The sizes of requests, the cookie, every random value and the cache names are not in it (b2c_sizes has the sizes).
    local f=$1
    sed -n '1,/^# end of cell output/p' "$f" | awk '
        function mask(s) {
            gsub(/(FILE|DIR|MEMORY):[^ ,)]*/, "<cache>", s)
            gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/, "<addr>", s)
            return s
        }
        BEGIN { sec = "head" }
        /^# / { next }
        /^== stderr$/ { sec = "stderr"; print "== stderr"; next }
        /^== trace$/ { sec = "trace"; print "== trace"; next }
        /^== ccache$/ { sec = "ccache"; print "== ccache"; next }
        /^== then: / { sec = "then"; print "== then"; next }
        /^== stdout$/ { sec = "stdout"; next }
        sec == "head" && /^(\[rc=|PROMPT=)/ { print; next }
        sec == "stdout" && /^stdout-(bytes|sha256) / { print; next }
        sec == "stderr" { sub(/^(krb5-)?(kinit|klist|kvno|kpasswd|kdestroy): /, "PROG: "); print mask($0); next }
        sec == "ccache" { print; next }
        sec == "trace" {
            sub(/^\[[0-9]+\] [0-9.]+: /, "")
            if ($0 ~ /^Processing preauth types: / || $0 ~ /^Produced preauth for next request: / || $0 ~ /^Preauth module .* returned: /) { print; next }
            if ($0 ~ /^(Sending unauthenticated request|Using FAST due to armor ccache negotiation result|Encoding request body and padata into FAST request|Decoding FAST response|FAST negotiation: available)$/) { print; next }
            if ($0 ~ /^Received error from KDC: /) { print; next }
            if ($0 ~ /^Sending request \(/) { print "Sending request"; next }
            if ($0 ~ /^SPAKE challenge received with group/) { sub(/, pubkey.*/, ""); print; next }
            if ($0 ~ /^Encrypted timestamp \(for /) { print "Encrypted timestamp (for <t>)"; next }
            if ($0 ~ /^(FAST armor ccache|Read config in) /) { print mask($0); next }
            next
        }
        sec == "then" { gsub(/[0-9][0-9][.\/][0-9][0-9][.\/]([0-9][0-9][0-9][0-9]|[0-9][0-9]) [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/, "<DATE>"); print mask($0); next }'
}
b2c_sizes() { b2c_trace "$1" | sed -n 's/^Sending request (\([0-9]*\) bytes).*/\1/p'; }
b2c_sizes_norm() {   # b2c_sizes_norm FILE: the request sizes of a login cell, one per line, minus the DER length of the microseconds of the encrypted timestamp the request carries. The pausec INTEGER is 1 byte below 128, 2 below 32768,
    # 3 above: a request is 1 byte shorter in about 3 runs in 100 (the trace line `Encrypted timestamp (for SECONDS.MICROS)` says which); two logins that differ only in that value must not differ in size.
    b2c_trace "$1" | awk '
        /^Encrypted timestamp \(for [0-9]+\.[0-9]+\)/ { u = $0; sub(/^.*\(for [0-9]+\./, "", u); sub(/\).*$/, "", u); u += 0; d = (u < 128) ? 1 : ((u < 32768) ? 2 : 3); next }
        /^Sending request \([0-9]+ bytes\)/ { n = $0; sub(/^Sending request \(/, "", n); sub(/ bytes.*$/, "", n); print n - d; d = 0 }'
}

b2c_cmp() {   # b2c_cmp LABEL A B [SED-EXPR...]: the cores of two login cells equal after the named sed -E masks (A is the MIT side of the comparison, B the ours side: names in the row, not claims about the files)
    local label=$1 a=$2 b=$3 d="$OUT/${B2_PKG:-b2c}/norm"
    shift 3
    mkdir -p "$d"
    b2c_core "$a" > "$d/$label.a.txt"; b2c_core "$b" > "$d/$label.b.txt"
    parity_eq "$label" "$d/$label.a.txt" "$d/$label.b.txt" "$@"
}
b2c_cmp_control() {   # b2c_cmp_control LABEL [SED-EXPR...]: the same comparison (same masks) on a doctored copy must differ
    local label=$1 d="$OUT/${B2_PKG:-b2c}/norm"
    shift
    parity_control "$label" "$d/$label.a.txt" "$d/$label.b.txt" "$@"
}

b2c_differ() {   # b2c_differ LABEL A B: the cores of two login cells must DIFFER (a control: the comparison tells different cells apart)
    local label=$1 d="$OUT/${B2_PKG:-b2c}/norm"
    mkdir -p "$d"
    b2c_core "$2" > "$d/$label.a.txt"; b2c_core "$3" > "$d/$label.b.txt"
    if cmp -s "$d/$label.a.txt" "$d/$label.b.txt"; then verdict "$label" FAIL "two different cells must differ" differ same ""
    else verdict "$label" PASS "two different cells must differ" differ differ ""; fi
}

b2c_not_run() { result "$1" INFO "NOT-RUN" - 0 "NOT-RUN: $2"; note "NOT-RUN $1: $2"; }

b2c_pa_rx() { printf 'padata=\\[([0-9]+,)*%s(,[0-9]+)*\\]' "$1"; }

b2c_pcap_start() {   # b2c_pcap_start PKG NAME
    local pkg=$1 name=$2
    b2c_init
    mkdir -p "$OUT/$pkg"
    if [ "$B2C_PCAP" != 1 ]; then b2c_not_run "${pkg^^}.pcap.$name" "no tcpdump on the kdc"; return 0; fi
    vm kdc "sudo bash $VMD/b2c-vm.sh pcap-start $name" 2>&1 < /dev/null | redact > "$OUT/$pkg/pcapctl-$name-start.txt"
    expect "${pkg^^}.pcap.$name.started" "$OUT/$pkg/pcapctl-$name-start.txt" '^PCAP_STARTED '
}
b2c_pcap_stop() {   # b2c_pcap_stop PKG NAME [--names]: stop, pull the capture to the host (0600, outside the record), summarize into $OUT/PKG/pcap-NAME.txt; --names: every line also names the client principal of its exchange
    local pkg=$1 name=$2 names=${3:-} pf s pd hdr="kinds, error codes, padata type numbers; no cookie, ciphertext, name or time"
    [ "$names" = --names ] && hdr="kinds, error codes, padata type numbers and the client principal of each exchange (the cname field); no cookie, ciphertext or time"
    b2c_init
    [ "$B2C_PCAP" = 1 ] || return 0
    pd=${B2C_PCAPDIR:-${W:?W is not set}/b2c-pcap}   # a knob (read, never assigned: the shell's hygiene check refuses an assignment to an inherited name)
    pf="$pd/$pkg-$name.pcap"; s="$OUT/$pkg/pcap-$name.txt"
    vm kdc "sudo bash $VMD/b2c-vm.sh pcap-stop $name" 2>&1 < /dev/null | redact > "$OUT/$pkg/pcapctl-$name-stop.txt"
    mkdir -p "$pd"; chmod 700 "$pd"
    ( umask 077; vm kdc "sudo bash $VMD/b2c-vm.sh pcap-get $name" > "$pf" 2>> "$LOG" )
    vm kdc "sudo bash $VMD/b2c-vm.sh pcap-rm $name" > /dev/null 2>&1 < /dev/null
    {
        echo "# pcap summary $pkg/$name: Kerberos messages on the kdc in capture order ($hdr); the capture is on the host: $(basename "$pf")"
        python3 -B -I "$SCRIPTS/helpers/b2c-pcap.py" summarize "$pf" ${names:+"$names"} 2>&1
    } > "$s"
    cat "$OUT/$pkg/pcapctl-$name-stop.txt" >> "$LOG"
    expect "${pkg^^}.pcap.$name.stopped" "$OUT/$pkg/pcapctl-$name-stop.txt" '^PCAP_STOPPED '
    expect "${pkg^^}.pcap.$name.has-messages" "$s" '^(AS-REQ|AS-REP|KRB-ERROR) client='
    b2c_cap_stats "${pkg^^}.pcap.$name" "$OUT/$pkg/pcapctl-$name-stop.txt"
}
b2c_cap_stats() {   # b2c_cap_stats LABEL STOPFILE: tcpdump's statistics line as an INFO row; a RED row when the kernel dropped packets (the count rows of that capture are then short, and this row says why)
    local l=$1 f=$2
    info "$l.tcpdump-stats" "$f" '^PCAP_STATS ' "(no statistics line)"
    if grep -qE '^PCAP_STATS .* dropped=[1-9]' "$f" 2> /dev/null; then
        verdict "$l.no-kernel-drops" FAIL "tcpdump dropped no packet (a count of messages in this capture is not to be trusted)" 0 "$(grep -m1 '^PCAP_STATS ' "$f" | cut -c1-120)" ""
    fi
}

b2c_clean_vms() {
    local v
    for v in kdc "${CLIENTS[@]}"; do
        vm "$v" "sudo bash $VMD/b2c-vm.sh clean" > /dev/null 2>&1 < /dev/null
    done
    return 0
}
