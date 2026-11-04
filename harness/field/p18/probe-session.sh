#!/bin/bash
# P18 probe-session.sh (klldap VM, root; `sudo bash -s -- LEG N TAG`): the P18 probes of the P16b-2
# design: kinit latency during a `cpw`, and a 50-connect TCP burst, at realm size N, one leg.
#   LEG  name:/path/to/sbin -- the leg's label and the directory holding krb5kdc, kadmind and
#        kdb5_util. Examples: mit:/usr/bin (Fedora krb5-server 1.22.2); ours:/path/to/release/sbin.
#   N    the seed realm ($B/seed/N<N>.dump)
#   TAG  the output directory $B/out/<TAG>
# The KDC and kadmind start as in session.sh. The client is Fedora's MIT kinit for both legs:
# `kinit -k -t admin.keytab admin/admin`, each in its own MEMORY: cache. Phases:
#   idle         kinit back to back for 10 s, no writes;
#   cpw          kinit back to back while one kadmin session runs 60 `cpw -randkey` (30 principals
#                made beforehand, twice over), until it ends;
#   burst-idle   5 bursts of 50 kinit at once over TCP (udp_preference_limit = 1), 2 s apart;
#   burst-write  5 times: one `cpw -randkey` (its own kadmin), then at once a burst of 50 over TCP.
# Each kinit's wall time (ms) and exit status go to kinit.csv; the kadmin sessions' times to
# summary.txt. $B = /srv/p18 is the VM layout (see README.md).
set -euo pipefail
RAW=${1:?leg (name:/path/to/sbin)} N=${2:?N} TAG=${3:?tag}
B=/srv/p18
O=$B/out/$TAG
D=$B/run/kdc
export KRB5_CONFIG=$B/krb5.conf KRB5_KDC_PROFILE=$B/kdc.conf
# The leg is name:/path/to/sbin; the name labels the output, the path supplies the binaries.
LEG=${RAW%%:*}; P=${RAW#*:}
if [ "$LEG" = "$RAW" ] || [ -z "$P" ] || [ "$P" = "$LEG" ]; then
    echo "LEG must be name:/path/to/sbin (e.g. mit:/usr/bin)" >&2; exit 2
fi
for bin in kdb5_util krb5kdc kadmind; do
    [ -x "$P/$bin" ] || { echo "no $bin in $P" >&2; exit 2; }
done
rm -rf "$O"; mkdir -p "$O"
say() { printf '[%s] %s\n' "$(date -u +%T.%3N)" "$*"; }

pkill -x krb5kdc 2>/dev/null || true; pkill -x kadmind 2>/dev/null || true
for _ in $(seq 50); do pgrep -x 'krb5kdc|kadmind' >/dev/null || break; sleep 0.1; done
if ss -lnt | grep -qE ':(18749|18888) '; then echo "ports busy" >&2; exit 1; fi
rm -rf "$D"; mkdir -p "$D"
cp $B/kadm5.acl "$D/kadm5.acl"; cp $B/seed/stash "$D/.k5.P18.TEST"; chmod 0600 "$D"/*
"$P/kdb5_util" -r P18.TEST load "$B/seed/N$N.dump" > "$O/load.out" 2>&1
sync; sleep 2

sed 's/^\[libdefaults\]$/[libdefaults]\n    udp_preference_limit = 1/' $B/krb5.conf > $B/krb5-tcp.conf

say "start $LEG daemons (N=$N)" > "$O/session.log"
"$P/krb5kdc" -n -r P18.TEST > "$O/kdc.stdout" 2>&1 &
KDCPID=$!
"$P/kadmind" -nofork -r P18.TEST > "$O/kadmind.stdout" 2> "$O/kadmind.stderr" &
KADPID=$!
for _ in $(seq 100); do
    ss -lnt | grep -q ':18749 ' && ss -lnu | grep -q ':18888 ' && break; sleep 0.1
done
ss -lntup | grep -E ':(18749|18888|18464) ' >> "$O/session.log" || { echo "daemons not listening" >&2; exit 1; }
KADMIN=(/usr/bin/kadmin -k -t "$B/seed/admin.keytab" -p admin/admin@P18.TEST -r P18.TEST)
python3 -c 'print("\n".join(f"addprinc -randkey pk{i:03d}" for i in range(30)))' \
    | "${KADMIN[@]}" > "$O/setup-kadmin.out" 2>&1 || true
say "made $(grep -c 'created\.$' "$O/setup-kadmin.out" || true) principals pk000..pk029" >> "$O/session.log"
sleep 1

python3 - "$O" "$B" <<'EOF'
import csv, os, statistics, subprocess, sys, threading, time
out, b = sys.argv[1], sys.argv[2]
kadmin = ["/usr/bin/kadmin", "-k", "-t", f"{b}/seed/admin.keytab", "-p", "admin/admin@P18.TEST", "-r", "P18.TEST"]
kinit = ["/usr/bin/kinit", "-k", "-t", f"{b}/seed/admin.keytab", "admin/admin@P18.TEST"]
udp = dict(os.environ, KRB5_CONFIG=f"{b}/krb5.conf")
tcp = dict(os.environ, KRB5_CONFIG=f"{b}/krb5-tcp.conf")
t0 = time.perf_counter()
rows, log = [], []
lock = threading.Lock()

def one(env, phase, burst, n):
    e = dict(env, KRB5CCNAME=f"MEMORY:p18u{n}")
    s = time.perf_counter()
    r = subprocess.run(kinit, env=e, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    f = time.perf_counter()
    err = (r.stderr.strip().splitlines() or [""])[0][:120]
    with lock:
        rows.append((phase, burst, f"{s - t0:.4f}", f"{(f - s) * 1000:.3f}", r.returncode, err))

def loop(phase, until):
    n = 0
    while not until():
        one(udp, phase, 0, n)
        n += 1

def burst(phase, k):
    gate = threading.Barrier(50)
    def go(i):
        gate.wait()
        one(tcp, phase, k, i)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(50)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

def kadmin_run(lines):
    s = time.perf_counter()
    r = subprocess.run(kadmin, input="\n".join(lines) + "\n", capture_output=True, text=True)
    return (time.perf_counter() - s) * 1000, r

end = time.perf_counter() + 10
loop("idle", lambda: time.perf_counter() > end)

cpw = [f"cpw -randkey pk{i % 30:03d}" for i in range(60)]
done = threading.Event()
res = {}
def writer():
    ms, r = kadmin_run(cpw)
    res["ms"], res["ok"] = ms, r.stdout.count("randomized")
    done.set()
w = threading.Thread(target=writer)
w.start()
loop("cpw", done.is_set)
w.join()
log.append(f"cpw phase: kadmin 60 cpw -randkey in {res['ms']:.0f} ms ({res['ok']} randomized)")

for k in range(1, 6):
    burst("burst-idle", k)
    time.sleep(2)
for k in range(1, 6):
    ms, r = kadmin_run([f"cpw -randkey pk{k:03d}"])
    log.append(f"burst-write {k}: the cpw before it took {ms:.0f} ms ({r.stdout.count('randomized')} randomized)")
    burst("burst-write", k)
    time.sleep(2)

with open(os.path.join(out, "kinit.csv"), "w", newline="") as f:
    c = csv.writer(f)
    c.writerow(["phase", "burst", "t_start_s", "ms", "rc", "err"])
    c.writerows(rows)
with open(os.path.join(out, "probe.log"), "w") as f:
    f.write("\n".join(log) + "\n")
EOF
say "probes done" >> "$O/session.log"
kill -TERM "$KADPID" "$KDCPID" 2>/dev/null || true
wait "$KADPID" 2>/dev/null || true; wait "$KDCPID" 2>/dev/null || true
cp "$D/kadmind.log" "$D/krb5kdc.log" "$O/" 2>/dev/null || true
ls -la --time-style=+%T "$D" > "$O/kdcdir-after.txt"
{
    echo "leg=$LEG N=$N programs=$P probes"
    cat "$O/session.log"
    cat "$O/probe.log"
    echo "kinit rows: $(($(wc -l < "$O/kinit.csv") - 1)); failures: $(awk -F, 'NR > 1 && $5 != 0' "$O/kinit.csv" | wc -l)"
    echo "load: $(tr '\n' ' ' < "$O/load.out")"
} > "$O/summary.txt"
cat "$O/summary.txt"
chmod -R a+rX "$O"
