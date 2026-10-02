#!/bin/sh
# install-check.sh <checkout> [<install-manifest>]: run on a VM after `make install` (a scenario pipes it to
# `sh -s -- ...`). Every program the kerber-rust install manifest lists (an entry in a bin or sbin directory)
# must be byte-identical to the checkout's own build, <checkout>/target/release/<build name>, the two names
# paired by the checkout's dist/install.sh (KDC_PROGS, CLIENT_PROGS). One line per program, then a summary;
# exits 1 when a program differs or has no build name, or when the manifest lists no program.
co=${1:-}
m=${2:-/usr/share/kerber-rust/install-manifest}
[ -r "$co/dist/install.sh" ] || { echo "install-check.sh: no checkout with dist/install.sh at '$co'"; exit 1; }
[ -r "$m" ] || { echo "install-check.sh: cannot read the manifest '$m'"; exit 1; }
pairs=$(sed -n "s/^\(KDC\|CLIENT\)_PROGS='\(.*\)'$/\2/p" "$co/dist/install.sh" | tr ' ' '\n')
[ -n "$pairs" ] || { echo "install-check.sh: no KDC_PROGS / CLIENT_PROGS in $co/dist/install.sh"; exit 1; }
awk '{ print $2 }' "$m" | {
    n=0 bad=0
    while IFS= read -r p; do
        case $p in */bin/* | */sbin/*) ;; *) continue ;; esac
        n=$((n + 1))
        build=$(printf '%s\n' "$pairs" | awk -F: -v name="${p##*/}" '$2 == name { print $1; exit }')
        if [ -z "$build" ]; then
            echo "$p: dist/install.sh pairs no build program with ${p##*/}"
            bad=1
        elif cmp "$co/target/release/$build" "$p"; then
            echo "same: target/release/$build = $p"
        else
            bad=1
        fi
    done
    if [ "$n" -eq 0 ]; then
        echo "install-check.sh: the manifest lists no program"
        exit 1
    fi
    if [ "$bad" -eq 0 ]; then echo "programs: $n in the manifest, each identical to the build"; fi
    exit "$bad"
}
