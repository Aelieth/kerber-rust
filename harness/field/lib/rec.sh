# harness/field/lib/rec.sh: the field record, sourced by run.sh and every scenario.
# shellcheck shell=bash
# Merged from the hand records' copies (R1, R2, R4, RA, UP1 and the rest).
#
# Each helper appends the command, its output and its exit status to $REC_DIR/record.txt, and prints one line
# per command to the terminal (SHOW=<n> adds up to n lines of output). VM commands run through lab.sh ssh (user
# 'lab', passwordless sudo), one ssh session each. Every line a command prints passes through redact.py before
# it is written. Secrets live in $KERBER_LAB_HOME/secrets and reach a VM only on ssh stdin (once / twice /
# chpw); the record names the file, never the value. Temporary files live under $TMPDIR, which must be the
# run's own directory: rec.sh refuses an unset TMPDIR or one under /tmp.
# Every command runs under a time limit: FIELD_CMD_TIMEOUT seconds (default 900), cut to what is left before
# FIELD_DEADLINE (epoch seconds, set by run.sh for each scenario); past the deadline a command is not run.
# A command stopped by its limit exits 124 (137 when TERM was not enough).
#
# The caller sets REC_DIR (the scenario's record directory) before sourcing. Helpers:
#   section / note                      a heading / a comment line in the record
#   run <vm> <cmd>, runin <vm> <what stdin carries> <cmd>
#   host <cmd>, hostin <what stdin carries> <cmd>
#   limited <command...>                                   any other command, under the same time limit
#   once <secret>... / twice <secret> / chpw <old> <new>   secrets, newline-terminated, for stdin
#   check <name> <expect> <helper> [args...]               run one recorded command and grade it
#   checklast <name> <expect>                              grade the last recorded command again
#   observe <name> <ERE> <helper> [args...] / observelast <name> <ERE> [nth]   an INFO line (recorded, not graded)
#   kdcmark <name> / kdcsince <name> [ERE]                 windows of kdc's two daemon logs (check mark.<name>)
#   capstart <vm> <name> <filter> / capstop <vm> <name>    a capture on a VM, kept without AS exchanges
#   waitsync <vm>                                          chrony synchronised (check sync.<vm>)
#   finish                                                 the result: PASS when no check failed and one passed
# <expect>: `rc` (exit status 0), `rc=N` or `rc=N|M`, `line:<text>` (a whole output line equal to text, and
# status 0), or an ERE that must match an output line (and status 0). checks.tsv gets one line per check:
#   name, PASS / FAIL / INFO, expect, rc, observed (the matching line, or what was seen), record.txt line.

FIELD_LIB=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FIELD_DIR=$(dirname "$FIELD_LIB")
LAB=${LAB:-$FIELD_DIR/lab.sh}
LABQ=$(printf '%q' "$LAB")
export LABQ
LAB_HOME=${KERBER_LAB_HOME:-$HOME/kerber-lab}
SECRETS=$LAB_HOME/secrets
SHOW=${SHOW:-0}
FIELD_CMD_TIMEOUT=${FIELD_CMD_TIMEOUT:-900}

_rec_die() { printf 'rec.sh: %s\n' "$*" >&2; exit 1; }
[ -n "${REC_DIR:-}" ] || _rec_die "REC_DIR must name the record directory"
case "${TMPDIR:-/tmp}/" in
    /tmp/*) _rec_die "TMPDIR must be the run's own directory, never the host's /tmp" ;;
esac
STATE=$TMPDIR/rec
REC=$REC_DIR/record.txt
CHECKS=$REC_DIR/checks.tsv
mkdir -p "$REC_DIR" "$STATE"
: >> "$REC"
[ -f "$CHECKS" ] || printf '# check\tresult\texpect\trc\tobserved\trecord line\n' > "$CHECKS"
LAST_RC=0
LAST_OUT=$STATE/last.out
LAST_LINE=0
: > "$LAST_OUT"

_redact() { python3 -B "$FIELD_LIB/redact.py"; }
section() { printf '\n==== %s  [%s]\n' "$*" "$(date -u +%FT%TZ)" | _redact | tee -a "$REC"; }
note() { printf '# %s\n' "$*" | _redact | tee -a "$REC"; }

# _limit: the seconds the next command may take (0: the scenario's deadline has passed).
_limit() {
    local lim=$FIELD_CMD_TIMEOUT left
    if [ -n "${FIELD_DEADLINE:-}" ]; then
        left=$(( FIELD_DEADLINE - $(date +%s) ))
        if [ "$left" -lt "$lim" ]; then lim=$left; fi
        if [ "$lim" -lt 0 ]; then lim=0; fi
    fi
    printf '%s\n' "$lim"
}
# limited <command...>: the command under that limit, in its own process group (TERM, then KILL 10 s later).
limited() {
    local lim
    lim=$(_limit)
    if [ "$lim" -le 0 ]; then
        printf 'not run: the scenario is past its deadline\n' >&2
        return 124
    fi
    timeout -k 10 "$lim" "$@"
}

# _record <head> <raw output file> <rc>: the block into the record; LAST_* for the checks.
_record() {
    local head=$1 raw=$2 rc=$3 n
    _redact < "$raw" > "$LAST_OUT"
    rm -f "$raw"
    LAST_RC=$rc
    LAST_LINE=$(( $(wc -l < "$REC") + 2 ))
    { printf '\n'; printf '%s\n' "$head" | _redact; cat "$LAST_OUT"; printf '[rc=%s]\n' "$rc"; } >> "$REC"
    printf '%s  [rc=%s]\n' "$(printf '%s' "$head" | head -n 1 | cut -c1-160 | _redact)" "$rc"
    if [ "$SHOW" -gt 0 ]; then
        n=$(wc -l < "$LAST_OUT")
        if [ "$n" -gt "$SHOW" ]; then
            tail -n "$SHOW" "$LAST_OUT"
        else
            cat "$LAST_OUT"
        fi
    fi
}
# _exec <vm|host> <what stdin carries, or empty> <command line>: stdin is the caller's.
_exec() {
    local where=$1 what=$2 cmd=$3 head rc=0
    if [ "$where" = host ]; then
        head="[$(date -u +%T)] host\$ $cmd"
    else
        head="[$(date -u +%T)] lab@$where\$ $cmd"
    fi
    [ -n "$what" ] && head="$head   (stdin: $what)"
    if [ "$where" = host ]; then
        limited bash -c "$cmd" > "$STATE/out.raw" 2>&1 || rc=$?
    else
        limited "$LAB" ssh "$where" -- "$cmd" > "$STATE/out.raw" 2>&1 || rc=$?
    fi
    case $rc in
        124 | 137) printf '(exit %s: stopped by the time limit, or past the deadline)\n' "$rc" >> "$STATE/out.raw" ;;
    esac
    _record "$head" "$STATE/out.raw" "$rc"
    return 0
}
run() { local vm=$1; shift; _exec "$vm" "" "$*" < /dev/null; }
runin() { local vm=$1 what=$2; shift 2; _exec "$vm" "$what" "$*"; }
host() { _exec host "" "$*" < /dev/null; }
hostin() { local what=$1; shift; _exec host "$what" "$*"; }

once() { local f; for f in "$@"; do printf '%s\n' "$(< "$SECRETS/$f")"; done; }
twice() { local p; p=$(< "$SECRETS/$1"); printf '%s\n%s\n' "$p" "$p"; }
chpw() { local o n; o=$(< "$SECRETS/$1"); n=$(< "$SECRETS/$2"); printf '%s\n%s\n%s\n' "$o" "$n" "$n"; }

# _checkrow <name> <PASS|FAIL|INFO> <expect> <rc> <observed>
_checkrow() {
    local observed
    observed=$(printf '%s' "$5" | tr '\t\n' '  ' | cut -c1-200)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$observed" "$LAST_LINE" >> "$CHECKS"
    printf '# CHECK %s: %s (%s) %s\n' "$1" "$2" "$3" "$observed" >> "$REC"
    printf '    %-4s %s: %s\n' "$2" "$1" "$observed"
}
checklast() {
    local name=$1 expect=$2 result=FAIL observed
    case $expect in
        rc)
            observed="rc=$LAST_RC"
            [ "$LAST_RC" = 0 ] && result=PASS ;;
        rc=*)
            observed="rc=$LAST_RC"
            case "|${expect#rc=}|" in *"|$LAST_RC|"*) result=PASS ;; esac ;;
        line:*)
            observed=$(grep -Fx -m1 -- "${expect#line:}" "$LAST_OUT" || true)
            if [ -n "$observed" ] && [ "$LAST_RC" = 0 ]; then result=PASS
            elif [ -n "$observed" ]; then observed="rc=$LAST_RC: $observed"
            else observed="no such line (rc=$LAST_RC)"; fi ;;
        *)
            observed=$(grep -E -m1 -- "$expect" "$LAST_OUT" || true)
            if [ -n "$observed" ] && [ "$LAST_RC" = 0 ]; then result=PASS
            elif [ -n "$observed" ]; then observed="rc=$LAST_RC: $observed"
            else observed="no line matches (rc=$LAST_RC)"; fi ;;
    esac
    _checkrow "$name" "$result" "$expect" "$LAST_RC" "$observed"
}
check() { local name=$1 expect=$2; shift 2; "$@"; checklast "$name" "$expect"; }
observelast() {
    local seen
    seen=$(grep -oE -- "$2" "$LAST_OUT" | sed -n "${3:-1}p")
    _checkrow "$1" INFO "$2" "$LAST_RC" "${seen:-no match}"
}
observe() { local name=$1 ere=$2; shift 2; "$@"; observelast "$name" "$ere"; }

# kdcmark <name>: the current length of kdc's two daemon logs (read-only), graded as check mark.<name>.
kdcmark() {
    check "mark.$1" '^marks: [0-9]+ [0-9]+$' run kdc "printf 'marks: %s %s\n' \"\$(sudo sh -c 'wc -l < /var/log/krb5kdc.log')\" \"\$(sudo sh -c 'wc -l < /var/log/kadmind.log')\""
    sed -n 's/^marks: \([0-9][0-9]*\) \([0-9][0-9]*\)$/\1 \2/p' "$LAST_OUT" > "$STATE/mark.$1"
}
# kdcsince <name> [ERE]: the lines both logs gained since that mark that match ERE, minus "closing down fd".
# Without a valid mark it records a failed command and reads nothing, so no check after it passes on old lines.
kdcsince() {
    local k='' a='' pat=${2:-.}
    read -r k a < "$STATE/mark.$1" 2>/dev/null || true
    case "$k:$a" in
        *[!0-9:]* | :* | *:)
            host "echo 'kdcsince $1: no valid log mark, so no log line is read'; exit 1"
            return 0 ;;
    esac
    run kdc "sudo tail -n +$((k + 1)) /var/log/krb5kdc.log | grep -v 'closing down fd' | grep -E $(printf '%q' "$pat"); echo '--- kadmind.log'; sudo tail -n +$((a + 1)) /var/log/kadmind.log | grep -v 'closing down fd' | grep -E $(printf '%q' "$pat"); true"
}

# capstart <vm> <name> <bpf filter>: tcpdump on every interface of <vm>, as a transient unit writing the VM's
# /var/tmp/field-<name>.pcap (the filter should keep IP fragments: a port filter alone drops them).
capstart() {
    run "$1" "sudo systemd-run --unit=field-pcap-$2 --collect tcpdump -i any -s0 -U -w /var/tmp/field-$2.pcap $(printf '%q' "$3"); sleep 2; systemctl is-active field-pcap-$2"
}
# capstop <vm> <name>: stop it; the raw capture comes to $STATE and is deleted on the VM; the record keeps
# pcap/<name>.pcap without AS exchanges (+ .txt, pcap-keep.sh); the raw copy is deleted (check pcap.<name>).
capstop() {
    local vm=$1 name=$2 raw=$STATE/$2.raw.pcap
    run "$vm" "sudo systemctl stop field-pcap-$name; sleep 1; sudo ls -la /var/tmp/field-$name.pcap"
    limited "$LAB" ssh "$vm" -- "sudo cat /var/tmp/field-$name.pcap" < /dev/null > "$raw" 2>/dev/null
    run "$vm" "sudo rm -f /var/tmp/field-$name.pcap"
    mkdir -p "$REC_DIR/pcap"
    check "pcap.$name" rc host "bash $(printf '%q' "$FIELD_LIB/pcap-keep.sh") $(printf '%q' "$raw") $(printf '%q' "$REC_DIR/pcap/$name.pcap") && head -n 1 $(printf '%q' "$REC_DIR/pcap/$name.pcap.txt")"
    rm -f "$raw"
}

# waitsync <vm>: wait up to 60 s for chrony to synchronise the VM's clock (Kerberos needs it).
waitsync() {
    check "sync.$1" '^synchronized: yes$' run "$1" "chronyc -n waitsync 30 0 0 2 > /dev/null 2>&1; printf 'synchronized: %s\n' \"\$(timedatectl show -p NTPSynchronized --value)\"; chronyc -n tracking | grep -E '^(Leap status|System time)'"
}

# finish: the scenario's result into $REC_DIR/result; status 0 for PASS.
finish() {
    local pass fail info result=FAIL
    pass=$(awk -F'\t' '$2 == "PASS"' "$CHECKS" | wc -l)
    fail=$(awk -F'\t' '$2 == "FAIL"' "$CHECKS" | wc -l)
    info=$(awk -F'\t' '$2 == "INFO"' "$CHECKS" | wc -l)
    [ "$fail" -eq 0 ] && [ "$pass" -gt 0 ] && result=PASS
    printf '%s %s pass %s fail %s info\n' "$result" "$pass" "$fail" "$info" > "$REC_DIR/result"
    section "result: $result ($pass pass, $fail fail, $info info; checks.tsv)"
    [ "$result" = PASS ]
}
