# harness/field/lib/tmp-guard.sh: run.sh's post.host.tmp guard (sourced by run.sh and lib/tmp-guard-check.sh).
# shellcheck shell=bash
#
# tmp_guard MARK OUT [ROOT]: OUT gets this user's paths under ROOT (default /tmp) newer than MARK, then
# "new in ROOT: <n>; left out: ..."; stdout gets what is left out. Left out and counted: the CLI scratch trees,
# written for this user whether or not that CLI drives the run (either may be absent, as after a reboot), and
# the desktop's top-level Chromium and GIMP names (scoped_dir* is Chromium's ScopedTempDir). Directories of
# other users that this user cannot search are skipped: nothing of the run's can be below them. A name that
# vanishes while find reads it is not an error; any other find diagnostic or status makes <n> "unknown".
tmp_guard() {
    local mark=$1 out=$2 root=${3:-/tmp} err=$2.err me uid bad='' left='' t x
    local -a desktop=('.org.chromium.Chromium.*' 'org.chromium.Chromium.*' 'scoped_dir*' 'gimp-*') prune=() names=()
    me=$(id -un) uid=$(id -u)
    : > "$err"
    [ -f "$mark" ] || bad+=" no mark $mark;"
    for t in "$root/grok-file-lock-$uid" "$root/claude-$uid"; do
        prune+=(-path "$t" -prune -o)
        if [ ! -d "$t" ]; then
            left+="; left out: $t absent"
            continue
        fi
        x=$(find "$t" -ignore_readdir_race -xdev -newer "$mark" -printf . 2>> "$err") || bad+=" find $t rc=$?;"
        left+="; left out: ${#x} entries under $t"
    done
    for t in "${desktop[@]}"; do
        prune+=(-path "$root/$t" -prune -o)
        names+=(-o -name "$t")
    done
    x=$(find "$root" -mindepth 1 -maxdepth 1 -ignore_readdir_race -xdev -user "$me" -newer "$mark" \
        \( "${names[@]:1}" \) -printf '%f\n' 2>> "$err") || bad+=" find $root -maxdepth 1 rc=$?;"
    x=$(printf '%s\n' "$x" | sort | paste -sd' ' -)
    left+="; left out: $(printf '%s' "$x" | wc -w) desktop scratch names${x:+: $x}"
    find "$root" -mindepth 1 -ignore_readdir_race -xdev "${prune[@]}" -type d ! -user "$me" ! -executable -prune \
        -o -user "$me" -newer "$mark" -print > "$out" 2>> "$err" || bad+=" find $root rc=$?;"
    if [ -n "$bad" ] || [ -s "$err" ]; then
        printf 'new in %s: unknown, the scan failed:%s %s diagnostics below%s\n' "$root" "$bad" "$(wc -l < "$err")" "$left" >> "$out"
        cat "$err" >> "$out"
    else
        printf 'new in %s: %s%s\n' "$root" "$(wc -l < "$out")" "$left" >> "$out"
    fi
    rm -f "$err"
    printf 'left out of the %s guard (and counted): %s %s %s/{%s}\n' "$root" "$root/grok-file-lock-$uid" \
        "$root/claude-$uid" "$root" "${desktop[*]}"
}
