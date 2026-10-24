#!/bin/bash
# P18 session.sh (klldap VM, root; `sudo bash -s -- LEG N TAG [M [KENV [TRACE [PERF [WORKLOAD]]]]]`):
# one measured kadmin session against one KDC build.
#   LEG  name:/path/to/sbin -- the leg's label and the directory holding krb5kdc, kadmind and
#        kdb5_util. Name the MIT baseline leg `mit`, so tables.py computes the ratio columns
#        against it. Examples: mit:/usr/bin (Fedora krb5-server 1.22.2); ours:/path/to/release/sbin.
#   N    the seed realm to load ($B/seed/N<N>.dump: 10, 100, 1000, 5000 principals)
#   TAG  the output directory $B/out/<TAG>
#   M    calls per op (default 30)
#   KENV="A=1 B=2"   extra environment for kadmind only (eatmydata's LD_PRELOAD, P18_* switches);
#                    `-` for none
#   TRACE=count      strace -f -c on kadmind for the workload (no wire timing taken from it)
#   TRACE=io         strace -f -tt -T -yy on kadmind: the flushes (fsync, fdatasync, msync,
#                    sync_file_range), writes and sends, reads and receives, rename*, openat,
#                    unlink*, ftruncate, utimensat, fcntl, flock
#   PERF=1           perf record -F 2999 on kadmind (a flat profile: the release build has no frame
#                    pointers, so call stacks are not taken)
#   WORKLOAD=perop   one kadmin process per command (a new connection and INIT per op, as KLLDAP's
#                    svc/setup makes them); default batch = one kadmin session
# $B = /srv/p18 holds kdc.conf, krb5.conf, seed/, kadm5.acl and tmp/, made by vm-setup.sh and seed.sh.
# The same kdc.conf and krb5.conf serve every leg; the workload is the same MIT kadmin client
# (/usr/bin/kadmin, krb5-workstation 1.22.2) with admin/admin's keytab, over loopback.
set -euo pipefail
RAW=${1:?leg (name:/path/to/sbin)} N=${2:?N} TAG=${3:?tag} M=${4:-30} KENV=${5:--} TRACE=${6:-none} PERF=${7:-0} WORKLOAD=${8:-batch}
[ "$KENV" = - ] && KENV=
# The leg is name:/path/to/sbin; the name labels the output, the path supplies the binaries.
LEG=${RAW%%:*}; P=${RAW#*:}
if [ "$LEG" = "$RAW" ] || [ -z "$P" ] || [ "$P" = "$LEG" ]; then
    echo "LEG must be name:/path/to/sbin (e.g. mit:/usr/bin)" >&2; exit 2
fi
for bin in kdb5_util krb5kdc kadmind; do
    [ -x "$P/$bin" ] || { echo "no $bin in $P" >&2; exit 2; }
done
B=/srv/p18
O=$B/out/$TAG
D=$B/run/kdc
export KRB5_CONFIG=$B/krb5.conf KRB5_KDC_PROFILE=$B/kdc.conf
rm -rf "$O"; mkdir -p "$O"
say() { printf '[%s] %s\n' "$(date -u +%T.%3N)" "$*"; }

# No daemon of an earlier session (KLLDAP's container is stopped).
pkill -x krb5kdc 2>/dev/null || true; pkill -x kadmind 2>/dev/null || true
for _ in $(seq 50); do pgrep -x 'krb5kdc|kadmind' >/dev/null || break; sleep 0.1; done
if ss -lnt | grep -qE ':(18749|18888) '; then echo "ports busy" >&2; exit 1; fi

# The KDC directory: the seed realm loaded by the leg's own kdb5_util, the seed's stash.
rm -rf "$D"; mkdir -p "$D"
cp $B/kadm5.acl "$D/kadm5.acl"; cp $B/seed/stash "$D/.k5.P18.TEST"; chmod 0600 "$D"/*
"$P/kdb5_util" -r P18.TEST load "$B/seed/N$N.dump" > "$O/load.out" 2>&1
sync; sleep 2

# The raw cost of the primitives on this volume now (same directory as the database).
probe() {
python3 - "$D" <<'EOF'
import os, statistics, sys, time
d = sys.argv[1]
def q(ts):
    ts = sorted(t * 1000 for t in ts)
    return f"median {statistics.median(ts):.2f} ms p90 {ts[int(0.9 * (len(ts) - 1))]:.2f} ms"
def append_fsync(n=40):
    p = os.path.join(d, ".p18probe"); fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); ts = []
    for _ in range(n):
        os.write(fd, os.urandom(4096)); t = time.perf_counter(); os.fsync(fd); ts.append(time.perf_counter() - t)
    os.close(fd); os.unlink(p); return ts
def replace(size, n=40):
    dfd = os.open(d, os.O_RDONLY); body = os.urandom(size); ts = []; dst = os.path.join(d, ".p18probe.db")
    for _ in range(n):
        t = time.perf_counter(); tmp = os.path.join(d, ".p18probe.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, body); os.fsync(fd); os.close(fd)
        os.rename(tmp, dst); os.fsync(dfd); ts.append(time.perf_counter() - t)
    os.close(dfd); os.unlink(dst); return ts
print("probe append 4 KiB + fsync:", q(append_fsync()))
print("probe replace 4 KiB (O_EXCL temp, write, fsync, rename, dir fsync):", q(replace(4096)))
print("probe replace 1 MiB (same):", q(replace(1 << 20)))
EOF
}
probe > "$O/probe-before.txt"

say "start $LEG daemons (N=$N, KENV='$KENV', TRACE=$TRACE, PERF=$PERF, WORKLOAD=$WORKLOAD)" > "$O/session.log"
"$P/krb5kdc" -n -r P18.TEST > "$O/kdc.stdout" 2>&1 &
KDCPID=$!
# shellcheck disable=SC2086  # KENV is a list of assignments
env $KENV "$P/kadmind" -nofork -r P18.TEST > "$O/kadmind.stdout" 2> "$O/kadmind.stderr" &
KADPID=$!
for _ in $(seq 100); do
    ss -lnt | grep -q ':18749 ' && ss -lnu | grep -q ':18888 ' && break; sleep 0.1
done
ss -lntup | grep -E ':(18749|18888|18464) ' >> "$O/session.log" || { echo "daemons not listening" >&2; cat "$O"/*.std* >&2; exit 1; }
tcpdump -i lo -n -s 0 --immediate-mode -U -w "$O/wire.pcap" 'tcp port 18749 or port 18888' 2> "$O/tcpdump.err" &
TCPD=$!
TRPID=; PFPID=
case $TRACE in
    count) strace -f -c -o "$O/strace-count.txt" -p "$KADPID" 2> "$O/strace.err" & TRPID=$! ;;
    io) strace -f -tt -T -yy -s 0 -e trace=fsync,fdatasync,msync,sync_file_range,write,pwrite64,writev,sendto,sendmsg,read,pread64,recvfrom,recvmsg,rename,renameat,renameat2,openat,unlink,unlinkat,ftruncate,utimensat,fcntl,flock \
            -o "$O/strace-io.txt" -p "$KADPID" 2> "$O/strace.err" & TRPID=$! ;;
esac
if [ "$PERF" = 1 ]; then perf record -F 2999 -o "$O/perf.data" -p "$KADPID" > "$O/perf.out" 2>&1 & PFPID=$!; fi
sleep 1.5
say "workload: M=$M per op" >> "$O/session.log"
rm -f $B/tmp/ktadd.keytab
t0=$(date +%s.%N)
gen() {
python3 - "$M" "$B/tmp/ktadd.keytab" <<'EOF'
# The workload: M calls of each write, then reads, then the deletes. Passwords are drawn here,
# per run, and go only into this pipe.
import secrets, sys
m, kt = int(sys.argv[1]), sys.argv[2]
pw = lambda: secrets.token_urlsafe(18)
lines = []
lines += [f"addprinc -pw {pw()} p18u{i:03d}" for i in range(m)]
lines += [f"addprinc -randkey p18h{i:03d}" for i in range(m)]
lines += [f'modprinc -maxlife "8 hours" p18u{i:03d}' for i in range(m)]
lines += [f"cpw -pw {pw()} p18u{i:03d}" for i in range(m)]
lines += [f"ktadd -k {kt} p18h{i:03d}" for i in range(m)]
lines += [f"getprinc p18u{i:03d}" for i in range(m)]
lines += [f"delprinc -force p18u{i:03d}" for i in range(m)]
lines += [f"delprinc -force p18h{i:03d}" for i in range(m)]
print("\n".join(lines))
EOF
}
KADMIN=(/usr/bin/kadmin -k -t "$B/seed/admin.keytab" -p admin/admin@P18.TEST -r P18.TEST)
if [ "$WORKLOAD" = perop ]; then
    : > "$O/kadmin.out"; : > "$O/kadmin.err"
    gen | while IFS= read -r line; do
        printf '%s\n' "$line" | "${KADMIN[@]}" >> "$O/kadmin.out" 2>> "$O/kadmin.err" || true
    done
else
    gen | "${KADMIN[@]}" > "$O/kadmin.out" 2> "$O/kadmin.err" || true
fi
t1=$(date +%s.%N)
say "workload done in $(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }') s" >> "$O/session.log"
sleep 2
[ -n "$PFPID" ] && kill -INT "$PFPID" 2>/dev/null && wait "$PFPID" 2>/dev/null || true
[ -n "$TRPID" ] && kill -INT "$TRPID" 2>/dev/null && wait "$TRPID" 2>/dev/null || true
kill -INT "$TCPD"; wait "$TCPD" 2>/dev/null || true
ls -la --time-style=+%T "$D" > "$O/kdcdir-after.txt"
stat -c "%n size=%s blocks=%b" "$D/principal.ulog" >> "$O/kdcdir-after.txt" 2>/dev/null || echo "no principal.ulog" >> "$O/kdcdir-after.txt"
kill -TERM "$KADPID" "$KDCPID" 2>/dev/null || true
wait "$KADPID" 2>/dev/null || true; wait "$KDCPID" 2>/dev/null || true
cp "$D/kadmind.log" "$D/krb5kdc.log" "$O/" 2>/dev/null || true
probe > "$O/probe-after.txt"
rm -f $B/tmp/ktadd.keytab
if [ -f "$O/perf.data" ]; then
    perf report -i "$O/perf.data" --sort symbol --stdio 2>/dev/null | grep -v '^$' | head -80 > "$O/perf-flat.txt" || true
    perf report -i "$O/perf.data" --sort dso --stdio 2>/dev/null | grep -v '^$' | head -30 > "$O/perf-dso.txt" || true
    rm -f "$O/perf.data"
fi
{
    echo "leg=$LEG N=$N M=$M KENV='$KENV' TRACE=$TRACE PERF=$PERF WORKLOAD=$WORKLOAD programs=$P"
    echo "kadmin: $(grep -o 'Principal "p18[uh][0-9]*@P18.TEST" created\.' "$O/kadmin.out" | wc -l) created, $(grep -o 'Principal "p18[uh][0-9]*@P18.TEST" deleted\.' "$O/kadmin.out" | wc -l) deleted, $(grep -o 'Password for "p18u[0-9]*@P18.TEST" changed\.' "$O/kadmin.out" | wc -l) cpw, $(grep -o 'Principal "p18u[0-9]*@P18.TEST" modified\.' "$O/kadmin.out" | wc -l) modified, $(grep -o 'added to keytab' "$O/kadmin.out" | wc -l) keytab entries, $(grep -o 'Principal: p18u[0-9]*@P18.TEST' "$O/kadmin.out" | wc -l) getprinc"
    echo "kadmin stderr lines: $(wc -l < "$O/kadmin.err"); distinct: $(sed -E 's/p18[uh][0-9]+/p18X/g' "$O/kadmin.err" | sort | uniq -c | sort -rn | head -5 | paste -sd'|')"
    cat "$O/session.log"
    sed 's/^/before: /' "$O/probe-before.txt"
    sed 's/^/after:  /' "$O/probe-after.txt"
    echo "load: $(tr '\n' ' ' < "$O/load.out")"
    echo "pcap frames: $(tcpdump -r "$O/wire.pcap" 2>/dev/null | wc -l); tcpdump: $(grep -E 'captured|received|dropped' "$O/tcpdump.err" | paste -sd' ')"
} > "$O/summary.txt"
cat "$O/summary.txt"
chmod -R a+rX "$O"
