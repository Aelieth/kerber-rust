#!/bin/sh
# ktrace.sh <name> <command> [arg...]: run an MIT client command on a VM with KRB5_TRACE in
# $HOME/field/<name>.trace, print the trace after the command's own output, then one summary line:
#   answers: <every transport and address a reply came from, sorted, unique>   (e.g. dgram 192.168.177.10:88)
# and exit with the command's status. Stdin is the command's (a password on stdin stays there).
# Writing the trace to a file, not /dev/stderr, keeps it whole when stderr is a file.
n=$1
shift
t=$HOME/field/$n.trace
rm -f "$t"
KRB5_TRACE=$t "$@"
rc=$?
[ -f "$t" ] && cat "$t"
printf 'answers: %s\n' "$( { grep -oE 'Received answer \([0-9]+ bytes\) from (dgram|stream) [^ ]+' "$t" 2>/dev/null || true; } \
    | sed -E 's/^Received answer \([0-9]+ bytes\) from //' | LC_ALL=C sort -u | paste -sd' ' -)"
exit "$rc"
