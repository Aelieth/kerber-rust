# harness/field/lib/client-opens.sh: run on kdc as root through `sh -s --` (kdc-profile.sh's cell CF.4). How often a
# program opens each profile file: MIT's library reads each file once, when the program's context is made.
#   setup <realm>                    a principal cf4 and its keytab in $D, and $D/dir for a DIR collection; prints
#                                    "cf4 keytab written"
#   run <name> <program> <args...>   the program under strace -f: prints "<name> rc=N", each program it executed
#                                    ("exec: <pid> <path>"), each profile file it opened ("open: <path> xN"), then
#                                    "<name> most opens of one profile file: N"
#   start <name> <unit> <daemon> <args...>  the unit stopped (- for none), the daemon in the foreground under strace
#                                    for 4 s, then SIGINT, the unit started again: prints "<name> listening: N" (its
#                                    successful listen calls), then its opens as run prints them
#   teardown                         cf4 deleted and $D removed; prints "cf4 removed"
# shellcheck shell=sh
set -u
D=/var/tmp/cf-4
T="clone,clone3,fork,vfork,execve,open,openat,openat2"
opens() {
    awk -v name="$1" '
        /execve\(/ && / = 0$/ { p = $0; sub(/^[^"]*"/, "", p); sub(/".*$/, "", p); print "exec: " $1 " " p }
        $2 ~ /^open(at2?)?\(/ && match($0, /"[^"]*(krb5\.conf|kdc\.conf)[^"]*"/) {
            n[substr($0, RSTART + 1, RLENGTH - 2)]++
        }
        END {
            m = 0
            for (p in n) {
                print "open: " p " x" n[p]
                if (n[p] > m) m = n[p]
            }
            print name " most opens of one profile file: " m
        }
    ' "$D/$1.trace"
}
cmd=$1
shift
case $cmd in
setup)
    realm=$1
    mkdir -p "$D"
    mkdir -m 0700 "$D/dir"
    kadmin.local -q "addprinc -randkey cf4@$realm" > /dev/null 2>&1
    kadmin.local -q "ktadd -k $D/cf4.kt -norandkey cf4@$realm" > /dev/null 2>&1
    [ -s "$D/cf4.kt" ] && echo "cf4 keytab written"
    ;;
run)
    name=$1
    shift
    mkdir -p "$D"
    strace -f -qq -e trace="$T" -o "$D/$name.trace" "$@" > "$D/$name.out" 2>&1
    echo "$name rc=$?"
    opens "$name"
    ;;
start)
    name=$1 unit=$2
    shift 2
    mkdir -p "$D"
    [ "$unit" = - ] || systemctl stop "$unit"
    strace -f -qq -e trace="$T,listen" -o "$D/$name.trace" "$@" > "$D/$name.out" 2>&1 &
    s=$!
    sleep 4
    pkill -INT -P "$s"
    wait "$s"
    [ "$unit" = - ] || { systemctl reset-failed "$unit"; systemctl start "$unit"; }
    echo "$name listening: $(grep -c ' listen(.* = 0$' "$D/$name.trace")"
    opens "$name"
    ;;
teardown)
    kadmin.local -q "delprinc -force cf4" > /dev/null 2>&1
    rm -rf "$D"
    echo "cf4 removed"
    ;;
esac
