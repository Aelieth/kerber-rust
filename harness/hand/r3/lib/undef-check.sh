#!/usr/bin/env bash
# undef-check.sh CELL [LIB...]: the source check that hc.sh runs before any lock or lab step. It refuses a cell script that calls a command nobody defines.
#   - rec.sh and each LIB are sourced (as the cell sources them); the functions the cell defines itself are added;
#   - every command word at the start of a line of CELL (the cells keep their calls at column 0), minus shell keywords and assignments, must then resolve (function, builtin or file);
#   - countlast, tktcheck and tgtline (the helpers hold C's cell called without defining) and gawk (tgtline's interpreter) are required by name, whether the cell calls them or not.
# Hold C's r3.sh run through this check lists countlast and tktcheck: it would have stopped hold C before the lab.
# Exit 0: all resolved; 1: something is undefined (named on stdout); 2: the check itself could not run.
set -u
cell=${1:?usage: undef-check.sh CELL [LIB...]}; shift
src=${HCSRC:?HCSRC must name the tree extraction}
scratch=$(mktemp -d "${TMPDIR:?TMPDIR must be set}/undef.XXXXXX") || exit 2
export REC_DIR=$scratch/rec LAB=/bin/true TMPDIR=$scratch
mkdir -p "$REC_DIR"
# shellcheck source=/dev/null
. "$src/harness/field/lib/rec.sh" > /dev/null 2>&1 || { echo "undef-check: cannot source $src/harness/field/lib/rec.sh"; exit 2; }
for l in "$@"; do
    # shellcheck source=/dev/null
    . "$l" > /dev/null 2>&1 || { echo "undef-check: cannot source $l"; exit 1; }
done
own=$(grep -oE '^[a-z_][A-Za-z0-9_]*\(\)' "$cell" | tr -d '()')
bad=''; n=0
while read -r w; do
    case $w in if | then | else | elif | fi | for | while | until | do | done | case | 'esac' | in | select | function | time) continue ;; esac
    n=$((n + 1))
    if grep -qx -- "$w" <<< "$own"; then continue; fi
    type -t -- "$w" > /dev/null 2>&1 || bad="$bad $w"
done < <(grep -vE '^[[:space:]]*(#|$)' "$cell" | grep -oE '^[a-z_][A-Za-z0-9_.-]*([= ]|$)' | grep -vE '=$' | sed -E 's/ $//' | sort -u)
for must in countlast tktcheck tgtline; do
    [ "$(type -t "$must" 2> /dev/null)" = function ] || case " $bad " in *" $must "*) ;; *) bad="$bad $must" ;; esac
done
command -v gawk > /dev/null 2>&1 || bad="$bad gawk"
rm -rf "$scratch"
if [ -n "$bad" ]; then
    echo "undef-check: UNDEFINED in $(basename "$cell"):$bad"
    exit 1
fi
echo "undef-check: OK ($n command words of $(basename "$cell") resolve; countlast, tktcheck, tgtline and gawk present)"
