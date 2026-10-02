#!/usr/bin/env bash
# harness/field/run.sh: one field run on the lab (harness/field/README.md, "Field runs" and "Scenarios").
#
#   run.sh --profile nightly|weekly [--ref <git ref>] [--only <scenario,...>] [--leg mit|rust|both]
#
# The tree under test is `git archive <ref>` of the repository run.sh lives in (read-only, GIT_OPTIONAL_LOCKS=0;
# FIELD_REPO in field.env names another), never a working tree. Each selected scenario's leg drives the real
# products on the lab and leaves its record in ~/kerber-lab/runs/<UTC>-<sha12>-<profile>/<scenario>/<leg>/.
#
# Preflight: ~/kerber-lab/state/lab.lock taken (when it is held, run.sh exits 1 before it makes a run
# directory); every snapshot baseline.env names exists; `lab.sh check --lab-only` of the VMs the selected
# scenarios use (ssh, DNS, time sync: no internet, LAN or AD DC probe); the sha256 of /etc/krb5.conf, and from
# a distrobox of the host's own. Postflight, also after a stop or an interruption: those sums unchanged, nothing
# new in the host's /tmp owned by the user, the secret scan of the whole run with its planted control first.
# Any failure fails the run. A scenario that did not run is NOT-RUN, never green. Exit 0 only when every
# selected scenario passed and every guard held.
# Limits: a scenario has FIELD_SCENARIO_TIMEOUT seconds (default 1800; its commands are cut to what is left,
# lib/rec.sh), a command FIELD_CMD_TIMEOUT (default 900). SIGINT, SIGTERM or SIGHUP stops the running
# scenario (its cleanup runs) and marks the rest NOT-RUN; the postflight still runs.
# runs/index.tsv has one line per run; the last 30 runs and every failed one are kept. TMPDIR is the run's
# own tmp/, removed when the run ends (also after a stop; not after a SIGKILL).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAB_HOME=${KERBER_LAB_HOME:-$HOME/kerber-lab}
RUNS=$LAB_HOME/runs
LOCK=$LAB_HOME/state/lab.lock
KEEP=30
# The scenarios of each profile, in order (none yet: a run selects nothing and fails).
declare -A PROFILES=([nightly]="" [weekly]="")

die() { printf 'run.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '4p' "${BASH_SOURCE[0]}" | sed 's/^# *//'; }
PROFILE='' REF=f-functional ONLY='' LEG=rust
while [ $# -gt 0 ]; do
    case $1 in
        --profile | --ref | --only | --leg) [ $# -ge 2 ] || die "$1 needs a value" ;;
    esac
    case $1 in
        --profile) PROFILE=$2; shift 2 ;;
        --ref) REF=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;;
        --leg) LEG=$2; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument '$1'" ;;
    esac
done
[ -n "${PROFILES[$PROFILE]+x}" ] || { usage >&2; die "--profile must be one of: ${!PROFILES[*]}"; }
case $LEG in
    mit | rust) LEGS=("$LEG") ;;
    both) LEGS=(mit rust) ;;
    *) die "--leg must be mit, rust or both" ;;
esac
read -r -a SEL <<< "${PROFILES[$PROFILE]}"
if [ -n "$ONLY" ]; then
    IFS=, read -r -a want <<< "$ONLY"
    for w in "${want[@]}"; do
        case " ${SEL[*]} " in *" $w "*) ;; *) die "--only: '$w' is not in profile $PROFILE (${SEL[*]})" ;; esac
    done
    keep=()
    for s in "${SEL[@]}"; do
        case ",$ONLY," in *",$s,"*) keep+=("$s") ;; esac
    done
    SEL=("${keep[@]}")
fi
for s in "${SEL[@]}"; do [ -f "$HERE/scenarios/$s.sh" ] || die "missing scenarios/$s.sh"; done

FIELD_ENV=$LAB_HOME/field.env
if [ -f "$FIELD_ENV" ]; then
    [ "$(stat -c %a "$FIELD_ENV")" = 600 ] || die "$FIELD_ENV must be mode 0600"
    set -a
    # shellcheck source=field.env.example
    . "$FIELD_ENV"
    set +a
fi
SCEN_LIMIT=${FIELD_SCENARIO_TIMEOUT:-1800}
REPO=${FIELD_REPO:-$(cd "$HERE/../.." && pwd)}
SHA=$(GIT_OPTIONAL_LOCKS=0 git -C "$REPO" rev-parse --verify --quiet "$REF^{commit}") \
    || die "ref '$REF' does not resolve in $REPO"
SHA12=${SHA:0:12}

mkdir -p "$LAB_HOME/state" "$RUNS"
chmod 0700 "$RUNS"
exec 9>> "$LOCK"
flock -n 9 || die "the lab is held ($LOCK): a hand runner or another field run is on it"

umask 077
STARTED=$(date -u +%FT%TZ)
T0=$(date +%s)
RUN_ID=$(date -u -d "$STARTED" +%Y%m%dT%H%M%SZ)-$SHA12-$PROFILE
RUN=$RUNS/$RUN_ID
mkdir -p "$RUN/tmp" "$RUN/guards"
touch "$RUN/tmp/.start"
export TMPDIR=$RUN/tmp
export KERBER_LAB_HOME=$LAB_HOME
say() { printf '%s\n' "$*" | tee -a "$RUN/run.log"; }
krb5_sums() {
    local f
    for f in /etc/krb5.conf /run/host/etc/krb5.conf; do
        if [ -e "$f" ]; then sha256sum "$f"; fi
    done
}
REC_DIR=$RUN/guards
# shellcheck source=lib/rec.sh
. "$HERE/lib/rec.sh"

DONE=0 STOP='' SCEN='' RESULT=FAIL ALL_PASS=1 GUARDS_OK=0
declare -a ROWS=()

# postflight: the guards that hold whatever happened before them.
postflight() {
    local mark=$RUN/tmp/.start excl='' left=''
    section "postflight"
    krb5_sums > "$RUN/guards/krb5.conf.end"
    check post.krb5.conf rc host "diff $(printf '%q' "$RUN/guards/krb5.conf.start") $(printf '%q' "$RUN/guards/krb5.conf.end") && echo unchanged: && cat $(printf '%q' "$RUN/guards/krb5.conf.end")"
    if [ "${CLAUDECODE:-}" = 1 ]; then
        excl="/tmp/claude-$(id -u)"
        note "driven from a Claude Code session (CLAUDECODE=1): the session writes its own $excl on every tool call, so that one tree is left out of the /tmp guard (and counted)"
        left="; left out: $(find "$excl" -xdev -newer "$mark" 2>/dev/null | wc -l) entries under $excl"
        find /tmp -xdev -path "$excl" -prune -o -user "$(id -un)" -newer "$mark" -print > "$RUN/guards/host-tmp.txt" 2>/dev/null || true
    else
        find /tmp -xdev -user "$(id -un)" -newer "$mark" -print > "$RUN/guards/host-tmp.txt" 2>/dev/null || true
    fi
    printf 'new in /tmp: %s%s\n' "$(grep -c . "$RUN/guards/host-tmp.txt" || true)" "$left" >> "$RUN/guards/host-tmp.txt"
    check post.host.tmp '^new in /tmp: 0(;|$)' host "cat $(printf '%q' "$RUN/guards/host-tmp.txt")"
    check post.secret.scan rc host "python3 -B $(printf '%q' "$FIELD_LIB/scan-secrets.py") $(printf '%q' "$RUN")"
    GUARDS_OK=1
    if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then GUARDS_OK=0; fi
}

# wrapup: the result, tmp/ removed, summary.txt, the index line, retention.
wrapup() {
    local min ids results drop i id
    RESULT=FAIL
    if [ "$ALL_PASS" = 1 ] && [ "$GUARDS_OK" = 1 ] && [ "${#ROWS[@]}" -gt 0 ]; then RESULT=PASS; fi
    rm -rf "$RUN/tmp"
    min=$(( ($(date +%s) - T0) / 60 ))
    {
        printf 'kerber-rust field run %s\n' "$RUN_ID"
        printf 'ref:       %s = %s\n' "$REF" "$SHA"
        printf 'profile:   %s, legs: %s, scenarios: %s\n' "$PROFILE" "${LEGS[*]}" "${SEL[*]}"
        printf 'started:   %s, %s min\n' "$STARTED" "$min"
        if [ -n "$STOP" ]; then printf 'stopped:   %s\n' "$STOP"; fi
        printf '\n%-12s %-5s %-8s %s\n' scenario leg result detail
        printf '%s\n' "${ROWS[@]}"
        printf '\nguards (guards/checks.tsv, guards/record.txt):\n'
        awk -F'\t' '!/^#/ { printf "  %-4s %s: %s\n", $2, $1, $5 }' "$CHECKS"
        printf '\nRESULT: %s\n' "$RESULT"
    } > "$RUN/summary.txt"
    cat "$RUN/summary.txt" >> "$RUN/run.log"
    cat "$RUN/summary.txt"
    [ -f "$RUNS/index.tsv" ] || printf '# run\tresult\tref\tsha\tprofile\tlegs\tscenarios\tstarted\tminutes\n' > "$RUNS/index.tsv"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$RUN_ID" "$RESULT" "$REF" "$SHA" "$PROFILE" "${LEGS[*]}" "${SEL[*]}" \
        "$STARTED" "$min" >> "$RUNS/index.tsv"
    DONE=1
    mapfile -t ids < <(awk -F'\t' '!/^#/ { print $1 }' "$RUNS/index.tsv")
    mapfile -t results < <(awk -F'\t' '!/^#/ { print $2 }' "$RUNS/index.tsv")
    drop=()
    for i in "${!ids[@]}"; do
        if [ "$i" -lt $(( ${#ids[@]} - KEEP )) ] && [ "${results[$i]}" = PASS ]; then drop+=("${ids[$i]}"); fi
    done
    for id in "${drop[@]}"; do
        [[ $id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}-(nightly|weekly)$ ]] || continue
        rm -rf -- "${RUNS:?}/$id"
        awk -F'\t' -v id="$id" '$1 != id' "$RUNS/index.tsv" > "$RUNS/index.tsv.new" && mv "$RUNS/index.tsv.new" "$RUNS/index.tsv"
    done
    if [ "${#drop[@]}" -gt 0 ]; then say "retention: removed ${#drop[@]} passed run(s) older than the last $KEEP"; fi
}

# stop_scenario: TERM to the running scenario's timeout (it passes it on); wait up to 120 s for its cleanup.
stop_scenario() {
    local i
    [ -n "$SCEN" ] || return 0
    kill -TERM "$SCEN" 2>/dev/null || true
    for i in $(seq 1 120); do
        kill -0 "$SCEN" 2>/dev/null || break
        [ "$i" -lt 120 ] && sleep 1
    done
}
on_signal() {
    STOP="by SIG$1 at $(date -u +%T)"
    if [ -n "$SCEN" ]; then kill -TERM "$SCEN" 2>/dev/null || true; fi
}
# on_exit: an exit before the end (an error under set -e): stop the scenario, then the postflight and wrapup.
on_exit() {
    local rc=$?
    [ "$DONE" = 1 ] && return
    DONE=1
    set +e
    trap '' INT TERM HUP
    STOP=${STOP:-"run.sh stopped early (status $rc)"}
    stop_scenario
    ALL_PASS=0
    ROWS+=("$(printf '%-12s %-5s %-8s %s' - - STOPPED "$STOP")")
    postflight
    wrapup
}
trap on_exit EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP

say "field run $RUN_ID: ref $REF = $SHA, profile $PROFILE, legs ${LEGS[*]}, scenarios ${SEL[*]}"
say "record: $RUN"

# ---------------------------------------------------------------- preflight
section "preflight: ref $REF = $SHA, profile $PROFILE, legs ${LEGS[*]}, scenarios ${SEL[*]}"
note "lock: $LOCK held by this run (flock); TMPDIR $TMPDIR; limits: scenario ${SCEN_LIMIT}s, command ${FIELD_CMD_TIMEOUT}s"
host "cd $(printf '%q' "$HERE") && sha256sum lab.sh run.sh baseline.env lib/* scenarios/*"
RQ=$(printf '%q' "$REPO")
TQ=$(printf '%q' "$TMPDIR/tree.tar")
check pre.tree rc host "GIT_OPTIONAL_LOCKS=0 git -C $RQ archive --format=tar --prefix=kerber-rust-$SHA12/ $SHA > $TQ"
host "GIT_OPTIONAL_LOCKS=0 git -C $RQ rev-parse '$SHA^{tree}'; tar -tf $TQ | grep -vc '/\$'; sha256sum $TQ"
# shellcheck source=baseline.env
. "$HERE/baseline.env"
host "$LABQ status"
cp "$LAST_OUT" "$STATE/status"
mapfile -t SNAPVARS < <(compgen -v | grep -E '^(RUST|MIT)_SNAPSHOT_' || true)
for var in "${SNAPVARS[@]}"; do
    vm=${var#*_SNAPSHOT_}
    vm=${vm,,}
    snap=${!var}
    if awk -v vm="$vm" -v s="$snap" '$1 == vm { n = split($NF, a, ","); for (i = 1; i <= n; i++) if (a[i] == s) f = 1 }
            END { exit !f }' "$STATE/status"; then
        _checkrow "pre.snapshot.$var" PASS present 0 "$vm has snapshot $snap"
    else
        _checkrow "pre.snapshot.$var" FAIL present 1 "$vm has no snapshot $snap"
    fi
done
[ "${#SNAPVARS[@]}" -gt 0 ] || _checkrow pre.snapshot FAIL present 1 "baseline.env names no snapshot"
VMS=()
for s in "${SEL[@]}"; do
    read -r -a vms <<< "$(sed -n 's/^# vms: //p' "$HERE/scenarios/$s.sh")"
    for vm in "${vms[@]}"; do
        case " ${VMS[*]} " in *" $vm "*) ;; *) VMS+=("$vm") ;; esac
    done
done
if [ "${#VMS[@]}" -gt 0 ]; then
    check pre.lab.check rc host "$LABQ check --lab-only ${VMS[*]}"
else
    note "the selected scenarios use no lab VM: no lab.sh check"
fi
krb5_sums > "$RUN/guards/krb5.conf.start"
check pre.krb5.conf rc host "cat $(printf '%q' "$RUN/guards/krb5.conf.start")"
PRE_OK=1
if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then PRE_OK=0; fi
say "preflight: $([ "$PRE_OK" = 1 ] && echo PASS || echo FAIL)"

# ---------------------------------------------------------------- scenarios
UPGRADE_FAILED=0
for sc in "${SEL[@]}"; do
    for leg in "${LEGS[@]}"; do
        dir=$RUN/$sc/$leg
        mkdir -p "$dir" "$RUN/tmp/$sc-$leg"
        reason=''
        if [ -n "$STOP" ]; then
            reason="the run was stopped $STOP"
        elif [ "$PRE_OK" != 1 ]; then
            reason="preflight failed"
        elif ! grep -Eq "^# legs: .*\b$leg\b" "$HERE/scenarios/$sc.sh"; then
            reason="scenarios/$sc.sh has no $leg leg"
        elif [ "$UPGRADE_FAILED" = 1 ]; then
            reason="upgrade failed, so kdc does not run the ref under test"
        fi
        if [ -n "$reason" ]; then
            printf 'NOT-RUN %s\n' "$reason" > "$dir/result"
            ROWS+=("$(printf '%-12s %-5s %-8s %s' "$sc" "$leg" NOT-RUN "$reason")")
            ALL_PASS=0
            say "== $sc --leg $leg: NOT-RUN ($reason)"
            continue
        fi
        say "== $sc --leg $leg"
        t=$(date +%s)
        rc=0
        REC_DIR=$dir TMPDIR=$RUN/tmp/$sc-$leg FIELD_RUN=$RUN FIELD_TREE_TAR=$RUN/tmp/tree.tar FIELD_SHA=$SHA \
            FIELD_REF=$REF FIELD_DEADLINE=$(( t + SCEN_LIMIT )) \
            timeout -k 60 $(( SCEN_LIMIT + 120 )) bash "$HERE/scenarios/$sc.sh" --leg "$leg" 9>&- \
            > >(tee -i -a "$RUN/run.log" 9>&-) 2>&1 &
        SCEN=$!
        while :; do
            rc=0
            wait "$SCEN" || rc=$?
            kill -0 "$SCEN" 2>/dev/null || break
        done
        SCEN=''
        res=$(cut -d' ' -f1 "$dir/result" 2>/dev/null || true)
        npass=$(awk -F'\t' '$2 == "PASS"' "$dir/checks.tsv" 2>/dev/null | wc -l)
        nfail=$(awk -F'\t' '$2 == "FAIL"' "$dir/checks.tsv" 2>/dev/null | wc -l)
        ninfo=$(awk -F'\t' '$2 == "INFO"' "$dir/checks.tsv" 2>/dev/null | wc -l)
        if [ "$rc" = 0 ] && [ "$res" = PASS ] && [ "$nfail" = 0 ] && [ "$npass" -gt 0 ]; then
            res=PASS
        else
            res=FAIL
            ALL_PASS=0
            if [ "$sc" = upgrade ] && [ "$leg" = rust ]; then UPGRADE_FAILED=1; fi
        fi
        ROWS+=("$(printf '%-12s %-5s %-8s %s pass / %s fail / %s info, %s min, exit %s%s: %s/%s/record.txt' \
            "$sc" "$leg" "$res" "$npass" "$nfail" "$ninfo" "$(( ($(date +%s) - t) / 60 ))" "$rc" \
            "$([ "$rc" = 124 ] && echo ' (over its time limit)')" "$sc" "$leg")")
        say "== $sc --leg $leg: $res"
    done
done

# ---------------------------------------------------------------- postflight, summary, index, retention
trap '' INT TERM HUP
postflight
wrapup
[ "$RESULT" = PASS ]
