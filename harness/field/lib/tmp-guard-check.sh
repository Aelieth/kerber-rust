#!/usr/bin/env bash
# harness/field/lib/tmp-guard-check.sh: lib/tmp-guard.sh's regression check, on scratch roots plus one read-only
# pass over /tmp.
# Cases: the CLI trees absent (as after a reboot); trees, desktop names and one stray file; a directory of this
# user's that cannot be read; no mark; the real /tmp, which must give a count, not "unknown" (other users'
# unsearchable directories are pruned); names and directories coming and going while the guard scans. Each guard
# runs in its own `set -euo pipefail` shell, as run.sh's postflight does. Nothing is written under /tmp.
#   usage: tmp-guard-check.sh SCRATCH [SECS]   (SCRATCH must not exist; SECS of churn, default 20)
set -u
S=${1:?usage: tmp-guard-check.sh SCRATCH [SECS]} SECS=${2:-20}
case $(realpath -m "$S") in /tmp | /tmp/*) echo "refused: $S is under /tmp" >&2; exit 2 ;; esac
[ ! -e "$S" ] || { echo "refused: $S exists" >&2; exit 2; }
LIB=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tmp-guard.sh
U=$(id -u) M=$S/mark FAILS=0
mkdir -p "$S"/{reboot,stray,locked,nomark,churn}
touch "$M"
sleep 1
# guard <mark> <root> [out]: rc of tmp_guard in a strict shell; OUT defaults to <root>.out.
guard() { bash -c 'set -euo pipefail; . "$1"; tmp_guard "$2" "$3" "$4" > /dev/null' _ "$LIB" "$1" "${3:-$2.out}" "$2"; }
summary() { grep -F "new in $1: " "${2:-$1.out}"; }
# expect <case> <root> <rc> <summary line, exact or a pattern> [out]
expect() {
    local got
    got=$(summary "$2" "${5:-}")
    # shellcheck disable=SC2053 # $4 is a pattern on purpose
    if [ "$3" = 0 ] && [[ $got == $4 ]]; then
        echo "CASE $1 PASS: $got"
    else
        echo "CASE $1 FAIL: rc=$3 got: ${got:-<no summary>} want: $4"
        FAILS=$((FAILS + 1))
    fi
}

R=$S/reboot
guard "$M" "$R"
expect reboot "$R" $? "new in $R: 0; left out: $R/grok-file-lock-$U absent; left out: $R/claude-$U absent; left out: 0 desktop scratch names"

R=$S/stray
mkdir -p "$R/grok-file-lock-$U" "$R/claude-$U/x" "$R/scoped_dirA"
touch "$R/grok-file-lock-$U/lock" "$R/claude-$U/x/f" "$R/stray"
guard "$M" "$R"
expect stray "$R" $? "new in $R: 1; left out: 2 entries under $R/grok-file-lock-$U; left out: 3 entries under $R/claude-$U; left out: 1 desktop scratch names: scoped_dirA"
grep -qxF "$R/stray" "$R.out" || { echo "CASE stray FAIL: $R/stray not listed"; FAILS=$((FAILS + 1)); }

R=$S/locked
mkdir -m 000 "$R/mine"
guard "$M" "$R"
expect locked "$R" $? "new in $R: unknown, the scan failed:*"
chmod 700 "$R/mine"

R=$S/nomark
guard "$S/no-such-mark" "$R"
expect nomark "$R" $? "new in $R: unknown, the scan failed: no mark $S/no-such-mark;*"

R=/tmp
guard "$M" "$R" "$S/realtmp.out"
expect realtmp "$R" $? "new in $R: [0-9]*" "$S/realtmp.out"

R=$S/churn
mkdir -p "$R/grok-file-lock-$U" "$R/claude-$U"
(end=$((SECONDS + SECS)); while [ "$SECONDS" -lt "$end" ]; do
    for i in $(seq 1 100); do
        mkdir -p "$R/scoped_dir$i" "$R/claude-$U/d$i/sub"
        : > "$R/grok-file-lock-$U/lock$i"
        : > "$R/claude-$U/d$i/sub/f"
    done
    rm -rf "$R"/scoped_dir* "$R/grok-file-lock-$U"/lock* "$R/claude-$U"/d*
done) &
w=$! runs=0 died=0 unknown=0 nonzero=0
while kill -0 "$w" 2> /dev/null; do
    runs=$((runs + 1))
    guard "$M" "$R" || died=$((died + 1))
    case $(summary "$R") in
        "new in $R: 0;"*) ;;
        "new in $R: unknown"*) unknown=$((unknown + 1)); cp "$R.out" "$S/churn-unknown.$runs" ;;
        *) nonzero=$((nonzero + 1)); cp "$R.out" "$S/churn-new.$runs" ;;
    esac
done
if [ "$runs" -ge 10 ] && [ "$died" = 0 ] && [ "$unknown" = 0 ] && [ "$nonzero" = 0 ]; then
    echo "CASE churn PASS: runs=$runs died=0 unknown=0 new=0 (${SECS}s)"
else
    echo "CASE churn FAIL: runs=$runs died=$died unknown=$unknown new=$nonzero (outputs kept in $S)"
    FAILS=$((FAILS + 1))
fi

if [ "$FAILS" = 0 ]; then
    rm -rf "$S"
    echo "TMP_GUARD_CHECK PASS"
    exit 0
fi
echo "TMP_GUARD_CHECK FAIL ($FAILS; scratch kept: $S)"
exit 1
