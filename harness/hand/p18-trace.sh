#!/bin/bash
# One iprop-on N=10 kadmind strace, MIT then ours (the build under test).
# strace -f from exec. Run as root on klldap, after lib/p18-stage.sh.
set -u
set -o pipefail
B=/srv/p18
P=${PREFIX_DIR}/sbin
export KRB5_CONFIG=$B/krb5.conf KRB5_KDC_PROFILE=$B/kdc.conf
cp -a "$B/kdc-iprop.conf" "$B/kdc.conf"; cmp -s "$B/kdc.conf" "$B/kdc-iprop.conf" || { echo "KDC_CONF_DIFF on"; exit 3; }

load_and_hash() {
    local name="$1" p="$2" wk="$3" wa="$4"
    local D=$B/run/kdc
    rm -rf "$D"
    mkdir -p "$D"
    cp "$B/kadm5.acl" "$D/kadm5.acl"
    cp "$B/seed/stash" "$D/.k5.P18.TEST"
    chmod 0600 "$D"/*
    if ! "$p/kdb5_util" -r P18.TEST load "$B/seed/N10.dump" >/var/tmp/t872-load.out 2>&1; then
        echo "LOAD_FAIL $name"
        exit 3
    fi
    "$p/krb5kdc" -n -r P18.TEST >/var/tmp/t872-kdc.err 2>&1 &
    local kpid=$!
    "$p/kadmind" -nofork -r P18.TEST >/var/tmp/t872-kadm.err 2>&1 &
    local apid=$!
    local hk="" ha=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [ -r "/proc/$kpid/exe" ] && [ -r "/proc/$apid/exe" ]; then
            hk=$(sha256sum "/proc/$kpid/exe" | awk '{print $1}')
            ha=$(sha256sum "/proc/$apid/exe" | awk '{print $1}')
            break
        fi
        sleep 0.1
    done
    echo "PROC $name kdc $hk"
    echo "PROC $name kadm $ha"
    kill "$kpid" "$apid" 2>/dev/null || true
    wait "$kpid" "$apid" 2>/dev/null || true
    pkill -x krb5kdc 2>/dev/null || true
    pkill -x kadmind 2>/dev/null || true
    sleep 0.2
    if [ "$hk" != "$wk" ] || [ "$ha" != "$wa" ]; then
        echo "PROC_MISMATCH $name"
        exit 3
    fi
    echo "PROC_MATCH $name"
}

OURS_KDC=$(sha256sum "$P/krb5kdc" | awk '{print $1}')
OURS_KADM=$(sha256sum "$P/kadmind" | awk '{print $1}')
echo "DISK ours kdc $OURS_KDC"
echo "DISK ours kadm $OURS_KADM"
load_and_hash mit /usr/sbin \
    03a99df39ef3868f5d5bb38174d2ca117d6ce816e2ed4d96834cf6d37a9e00e8 \
    b869f832e6c21506c7400d0d5342e525a11d08780029adf483f8be0c43e4099b
load_and_hash ours "$P" "$OURS_KDC" "$OURS_KADM"
echo PROC_DONE

make_wrap() {
    local name="$1" real="$2"
    local dir="/var/tmp/p18-872-wrap/$name"
    rm -rf "$dir"
    mkdir -p "$dir" /var/tmp/p18-872-trace
    ln -s "$real/krb5kdc" "$dir/krb5kdc"
    ln -s "$real/kdb5_util" "$dir/kdb5_util"
    cat > "$dir/kadmind" << EOF
#!/bin/bash
out=/var/tmp/p18-872-trace/${name}-kadm.strace
setsid strace -f -tt -T -s 0 -y \\
    -e trace=fsync,fdatasync,msync,pwrite64,write,openat,fcntl,close \\
    -o "\$out" -- ${real}/kadmind "\$@" &
sp=\$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    child=\$(ps -o pid= --ppid "\$sp" | awk 'NR==1{print \$1}')
    if [ -n "\${child:-}" ] && [ -r "/proc/\$child/exe" ]; then
        sha256sum "/proc/\$child/exe" > /var/tmp/p18-872-trace/${name}-proc.txt
        break
    fi
    sleep 0.05
done
trap 'kill -TERM -- -"\$sp" 2>/dev/null || kill -TERM "\$sp" 2>/dev/null; wait "\$sp" 2>/dev/null || true' TERM INT
wait "\$sp"
EOF
    chmod 755 "$dir/kadmind"
}

run() {
    local leg="$1" tag="$2"
    echo "BEGIN $tag"
    cp -a "$B/kdc-iprop.conf" "$B/kdc.conf"; cmp -s "$B/kdc.conf" "$B/kdc-iprop.conf" || { echo "KDC_CONF_DIFF on"; exit 3; }
    if ! bash /var/tmp/p18/session.sh "$leg" 10 "$tag" 30 - none; then
        echo "SESSION_RC:1 $tag"
        exit 2
    fi
    echo "SESSION_RC:0 $tag"
}

make_wrap mit /usr/sbin
make_wrap ours "$P"
run "mit:/var/tmp/p18-872-wrap/mit" p872-iprop-trace-mit
got=$(awk 'NR==1{print $1}' /var/tmp/p18-872-trace/mit-proc.txt)
echo "TRACE_PROC mit $got"
[ "$got" = b869f832e6c21506c7400d0d5342e525a11d08780029adf483f8be0c43e4099b ] || { echo TRACE_PROC_MISMATCH mit; exit 4; }
run "ours:/var/tmp/p18-872-wrap/ours" p872-iprop-trace-ours
got=$(awk 'NR==1{print $1}' /var/tmp/p18-872-trace/ours-proc.txt)
echo "TRACE_PROC ours $got"
[ "$got" = "$OURS_KADM" ] || { echo TRACE_PROC_MISMATCH ours; exit 4; }
cp -a /var/tmp/p18-872-trace/mit-kadm.strace /var/tmp/p18-872-trace/mit-proc.txt "$B/out/p872-iprop-trace-mit/"
cp -a /var/tmp/p18-872-trace/ours-kadm.strace /var/tmp/p18-872-trace/ours-proc.txt "$B/out/p872-iprop-trace-ours/"
echo TRACE_DONE
