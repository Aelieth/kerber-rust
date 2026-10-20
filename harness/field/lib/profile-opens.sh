# harness/field/lib/profile-opens.sh: run on kdc as root through `sh -s --` (kdc-profile.sh's cell CF.e0). Whether
# a daemon serving a request opens krb5.conf or kdc.conf: MIT's profile library reads each file once and only stats
# it after, so a request opens neither.
#   attach <name> <pid>         strace -f on <pid>, its threads and its children: their clones, execs, opens,
#                               accepts and receives in $D/<name>.trace; prints "<name> <pid> traced by <tracer pid>"
#   detach <name>               strace stopped; prints each clone ("clone: <parent> -> <child>"), each pid that
#                               executed a program ("exec: <pid>": MIT kpropd's kdb5_util load, which is not the daemon)
#                               and each krb5.conf or kdc.conf open by the daemon itself, then
#                               "<name> live: N accept/recv lines" and "<name> profile opens: N"
#   kpropd-start <leg> <realm>  a second kpropd on port 7754 with its own kdc.conf, database, keytab and ACL; a dump
#                               of the realm in $D/dump for kprop; prints "kpropd <pid> listening on 7754"
#   kpropd-stop <realm>         that kpropd stopped and $D removed, with host/<this host> if it was made here
# shellcheck shell=sh
set -u
D=/var/tmp/cf-e0
KC=/var/kerberos/krb5kdc/kdc.conf
cmd=$1
shift
case $cmd in
attach)
    name=$1 pid=$2
    mkdir -p "$D"
    nohup strace -f -qq -e trace=clone,clone3,fork,vfork,execve,open,openat,openat2,accept,accept4,recvfrom,recvmsg -o "$D/$name.trace" \
        -p "$pid" > /dev/null 2>&1 < /dev/null &
    echo $! > "$D/$name.strace"
    t=0
    for _ in $(seq 1 40); do
        t=$(awk '/^TracerPid:/ { print $2 }' "/proc/$pid/status")
        [ "${t:-0}" != 0 ] && break
        sleep 0.25
    done
    echo "$name $pid traced by ${t:-0}"
    ;;
detach)
    name=$1
    s=$(cat "$D/$name.strace")
    kill -INT "$s"
    for _ in $(seq 1 40); do
        kill -0 "$s" 2> /dev/null || break
        sleep 0.25
    done
    awk -v name="$name" '
        /(clone3?|v?fork)\(|<\.\.\. (clone3?|v?fork) resumed>/ && $(NF-1) == "=" && $NF ~ /^[0-9]+$/ {
            print "clone: " $1 " -> " $NF
        }
        /execve/ && / = 0$/ { ran[$1] = 1; print "exec: " $1 }
        $2 ~ /^(accept4?|recvfrom|recvmsg)\(/ { live++ }
        $2 ~ /^open(at2?)?\(/ && !($1 in ran) && /krb5\.conf|kdc\.conf/ { opens++; print "open: " $0 }
        END { printf "%s live: %d accept/recv lines\n%s profile opens: %d\n", name, live, name, opens }
    ' "$D/$name.trace"
    ;;
kpropd-start)
    leg=$1 realm=$2
    fqdn=$(hostname -f)
    princ="host/$fqdn@$realm"
    mkdir -p "$D/replica"
    if ! kadmin.local -q "getprinc $princ" 2> /dev/null | grep -q '^Principal:'; then
        kadmin.local -q "addprinc -randkey $princ" > /dev/null && touch "$D/made-host"
    fi
    kadmin.local -q "ktadd -k $D/kt -norandkey $princ" > /dev/null
    echo "$princ" > "$D/kpropd.acl"
    stash=$(awk -F= '/^[[:space:]]*key_stash_file[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$KC")
    printf '[realms]\n    %s = {\n        database_name = %s/replica/principal\n        key_stash_file = %s\n    }\n' \
        "$realm" "$D" "${stash:-/var/kerberos/krb5kdc/.k5.$realm}" > "$D/kdc.conf"
    kdb5_util dump "$D/dump"
    # MIT's kpropd writes what it receives to -f's file (else the KDC directory's) for kdb5_util load;
    # this port's loads it itself.
    set -- -D -P 7754 -r "$realm" -s "$D/kt" -a "$D/kpropd.acl"
    if [ "$leg" = mit ]; then
        set -- "$@" -f "$D/from_primary"
    fi
    KRB5_KDC_PROFILE=$D/kdc.conf nohup /usr/sbin/kpropd "$@" > "$D/kpropd.out" 2>&1 < /dev/null &
    echo $! > "$D/kpropd.pid"
    for _ in $(seq 1 40); do
        ss -Hltn 'sport = :7754' | grep -q . && break
        sleep 0.25
    done
    ss -Hltn 'sport = :7754' | grep -q . && echo "kpropd $(cat "$D/kpropd.pid") listening on 7754"
    ;;
kpropd-stop)
    realm=$1
    [ -e "$D/kpropd.pid" ] && kill "$(cat "$D/kpropd.pid")" 2> /dev/null
    [ -e "$D/made-host" ] && kadmin.local -q "delprinc -force host/$(hostname -f)@$realm" > /dev/null
    rm -rf "$D"
    echo "kpropd stopped, $D removed"
    ;;
esac
