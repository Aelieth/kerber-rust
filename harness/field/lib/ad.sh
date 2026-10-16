# harness/field/lib/ad.sh: the AD DC for ad-trust.sh, sourced after rec.sh (set KDC_LAN first).
# shellcheck shell=bash
# Every DC script is lib/ad/<name>.ps1 with its @@VAR@@ filled in, run through dc-ps.py (WinRM) and shown whole in
# the record. A DC change is logged in $ADLOG before it is made; adundo undoes what is logged (lib/ad/undo.ps1
# touches only the scenario's own changes) and the caller's EXIT trap runs it.
#   adonce NAME / adtwice NAME       an AD secret of $FIELD_ADLAB_ENV for stdin, never printed
#   dc <name> [VAR=value...]         run lib/ad/<name>.ps1 on the DC
#   dcskew                           the DC clock minus this host's, as DCSKEW (check dc.skew: under 240 s)
#   adstate <tag>                    the DC's compared state into $STATE/ad.<tag>
#   adbaseline                       the DC is at lib/ad/baseline.txt, after undoing a killed run's leftovers (check dc.baseline)
#   adapply <what> <name> [VAR=value...]   log <what>, then run lib/ad/<name>.ps1 (check ad.apply.<what>)
#   adundo / adrestored              undo what is logged (check ad.undo) / the state equals the one before (check dc.restored)
#   dcwin <name> <from> <to>         the DC's 4768/4769/4771 events between two host epoch seconds, shifted by DCSKEW

ADENV=${FIELD_ADLAB_ENV:-$HOME/adlab/env}
WINRM_PY=${FIELD_WINRM_PY:-python3}
ADLOG=$STATE/ad.changed
DCSKEW=0
: >> "$ADLOG"
mkdir -p "$REC_DIR/dc"

adval() { sed -n "s/^\(export \)\{0,1\}$1=//p" "$ADENV" | tail -n 1 | sed -E "s/^'(.*)'\$/\\1/; s/^\"(.*)\"\$/\\1/"; }
adonce() { printf '%s\n' "$(adval "$1")"; }
adtwice() { local p; p=$(adval "$1"); printf '%s\n%s\n' "$p" "$p"; }

dc() {
    local name=$1 f=$STATE/$1.ps1 kv rc=0 head
    shift
    cp "$FIELD_LIB/ad/$name.ps1" "$f"
    for kv in "$@"; do sed -i "s|@@${kv%%=*}@@|${kv#*=}|g" "$f"; done
    head="[$(date -u +%T)] DC TEST-SERVER\$ dc-ps.py $name.ps1   # its text:"$'\n'"$(sed 's/^/    | /' "$f")"
    limited "$WINRM_PY" -B "$FIELD_LIB/dc-ps.py" "$f" > "$STATE/out.raw" 2>&1 < /dev/null || rc=$?
    case $rc in 124 | 137) printf '(exit %s: stopped by the time limit, or past the deadline)\n' "$rc" >> "$STATE/out.raw" ;; esac
    _record "$head" "$STATE/out.raw" "$rc"
}

dcskew() {
    local h0 h1 t res=FAIL
    h0=$(date +%s.%N)
    dc clock
    h1=$(date +%s.%N)
    t=$(sed -n 's/^DC time (UTC): //p' "$LAST_OUT" | head -n 1)
    DCSKEW=$(python3 -B -I -c 'import sys, datetime as d
t = d.datetime.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=d.timezone.utc).timestamp()
print(round(t - (float(sys.argv[2]) + float(sys.argv[3])) / 2))' "$t" "$h0" "$h1" 2> /dev/null) || DCSKEW=''
    if [ "$LAST_RC" = 0 ] && [ -n "$DCSKEW" ] && [ "${DCSKEW#-}" -lt 240 ]; then res=PASS; fi
    _checkrow dc.skew "$res" "|DC - lab| < 240 s" "$LAST_RC" "${DCSKEW:-no DC time} s"
    DCSKEW=${DCSKEW:-0}
}

adstate() {
    dc state
    cp "$LAST_OUT" "$REC_DIR/dc/state-$1.txt"
    grep -v '^info ' "$LAST_OUT" | sed 's/[[:space:]]*$//' | sed '/^$/d' > "$STATE/ad.$1"
}

adbaseline() {
    local res=FAIL seen
    adstate before
    if [ "$LAST_RC" = 0 ] && [ -s "$STATE/ad.before" ] && ! diff -q "$FIELD_LIB/ad/baseline.txt" "$STATE/ad.before" > /dev/null; then
        note "the DC is not at lib/ad/baseline.txt; the leftovers of a killed run are undone, nothing else is touched"
        printf 'leftovers\n' >> "$ADLOG"
        adundo
        adstate before
    fi
    seen=$(diff "$FIELD_LIB/ad/baseline.txt" "$STATE/ad.before" | grep '^[<>]' | tr '\n' ' ')
    if [ "$LAST_RC" = 0 ] && [ -z "$seen" ]; then res=PASS; fi
    _checkrow dc.baseline "$res" "= lib/ad/baseline.txt" "$LAST_RC" "${seen:-identical}"
}

adapply() {
    local what=$1
    shift
    printf '%s\n' "$what" >> "$ADLOG"
    check "ad.apply.$what" '^applied$' dc "$@"
}

adundo() {
    [ -s "$ADLOG" ] || return 0
    check ad.undo '^undone$' dc undo KDC_LAN="${KDC_LAN:-none}"
    if [ "$LAST_RC" = 0 ] && grep -qx undone "$LAST_OUT"; then : > "$ADLOG"; fi
}

adrestored() {
    local res=FAIL seen
    adstate after
    seen=$(diff "$STATE/ad.before" "$STATE/ad.after" | grep '^[<>]' | tr '\n' ' ')
    if [ "$LAST_RC" = 0 ] && [ -z "$seen" ] && [ ! -s "$ADLOG" ]; then res=PASS; fi
    _checkrow dc.restored "$res" "= the state before the run, nothing left logged" "$LAST_RC" "${seen:-identical}; logged: $(tr '\n' ' ' < "$ADLOG")"
}

dcwin() {
    dc events FROM="$(date -u -d "@$(($2 + DCSKEW - 20))" +%FT%TZ)" TO="$(date -u -d "@$(($3 + DCSKEW + 20))" +%FT%TZ)"
    cp "$LAST_OUT" "$REC_DIR/dc/events-$1.txt"
}
