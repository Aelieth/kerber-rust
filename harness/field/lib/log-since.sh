#!/bin/sh
# log-since.sh: read a log from a mark, across logrotate's rename (create mode). Runs on the VM, as root.
#   mark FILE                  <lines>:<bytes>:<inode>:<sha256 of the first min(bytes, 4096)>; inode 0 when absent
#   since MARK FILE [n|c] [whole]
#                              FILE's text after MARK, by lines (n) or bytes (c). If FILE no longer holds the mark,
#                              the rotated FILE-* or FILE.* that does is read from it, then all of FILE. If none does
#                              (rotated and removed, or a reset VM), a LOG_SINCE line goes to stderr and, with
#                              "whole", all of FILE is printed; without it, nothing, and the exit status is 3.
set -u
head_hash() { head -c "$2" "$1" | sha256sum | cut -c1-64; }
mark() {
    if [ -f "$1" ]; then
        b=$(wc -c < "$1")
        printf '%s:%s:%s:%s\n' "$(wc -l < "$1")" "$b" "$(stat -c %i "$1")" "$(head_hash "$1" $((b < 4096 ? b : 4096)))"
    else
        printf '0:0:0:%s\n' "$(printf '' | sha256sum | cut -c1-64)"
    fi
}
# holds FILE INODE BYTES HASH: FILE is the marked file, at least as long as the mark.
holds() {
    [ -f "$1" ] && [ "$(stat -c %i "$1")" = "$2" ] && [ "$(wc -c < "$1")" -ge "$3" ] \
        && [ "$(head_hash "$1" $(($3 < 4096 ? $3 : 4096)))" = "$4" ]
}
from() { if [ "$2" = c ]; then tail -c +$(($4 + 1)) "$1"; else tail -n +$(($3 + 1)) "$1"; fi; }
since() {
    m=$1 f=$2 u=${3:-n} w=${4:-}
    IFS=: read -r l b i h << EOF
$m
EOF
    case "$l:$b:$i" in *[!0-9:]* | :* | *::* | *:) echo "LOG_SINCE $f: no valid mark ($m)" >&2; return 1 ;; esac
    if [ "$i" = 0 ]; then
        [ -f "$f" ] && cat "$f"
        return 0
    fi
    if holds "$f" "$i" "$b" "$h"; then
        from "$f" "$u" "$l" "$b"
        return 0
    fi
    for g in "$f"-* "$f".*; do
        if holds "$g" "$i" "$b" "$h"; then
            echo "LOG_SINCE $f: rotated to $g after the mark" >&2
            from "$g" "$u" "$l" "$b"
            [ -f "$f" ] && cat "$f"
            return 0
        fi
    done
    echo "LOG_SINCE $f: no file holds the mark (rotated and removed, or a reset VM)" >&2
    [ "$w" = whole ] || return 3
    [ -f "$f" ] && cat "$f"
    return 0
}
cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
    mark) mark "$@" ;;
    since) since "$@" ;;
    *) echo "usage: log-since.sh mark FILE | since MARK FILE [n|c] [whole]" >&2; exit 2 ;;
esac
