#!/usr/bin/env python3
"""P18 strace-split.py <session-dir>: kadmind's file I/O per kadm5 call, from a TRACE=io session.

strace -f -tt -T -yy runs on kadmind for the whole workload. Each kadm5 reply leaves kadmind in
one send to the client's socket (write / sendto / writev / sendmsg on a TCP fd of port 18749), so
the trace is cut after each such send: everything kadmind did since the previous reply belongs to
this reply's call. The k-th reply in the trace is the k-th kadm5 reply in the session's capture,
which names the procedure (the first M CREATE_PRINCIPAL calls are `addprinc -pw`, the next M
`addprinc -randkey`).

Per call it counts: flushes (fsync, fdatasync, msync, sync_file_range) and their time; directory
flushes (an fsync whose fd is a directory); renames; files opened for writing; bytes written to
files and read from files (not sockets). Prints the per-procedure medians and writes
results/strace/<tag>.csv (one row per call).
"""
import csv
import os
import re
import statistics
import subprocess
import sys

d = sys.argv[1].rstrip("/")
tag = os.path.basename(d)
RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "strace")
os.makedirs(RESULTS, exist_ok=True)
m = 30
for line in open(os.path.join(d, "summary.txt")):
    mm = re.search(r"\bM=(\d+)", line)
    if mm:
        m = int(mm.group(1))
        break

# The procedures in reply order, from the capture.
out = subprocess.run(["tshark", "-r", os.path.join(d, "wire.pcap"), "-d", "tcp.port==18749,rpc", "-Y",
                      "rpc.msgtyp == 1 && rpc.program == 2112", "-T", "fields", "-e", "_ws.col.Info"],
                     capture_output=True, text=True, check=True).stdout
procs, creates = [], 0
for info in out.splitlines():
    p = info.split()[1]
    if p == "CREATE_PRINCIPAL":
        p = "CREATE(pw)" if creates < m else "CREATE(rand)"
        creates += 1
    procs.append(p)

LINE = re.compile(r"^(\d+)\s+(\d\d:\d\d:\d\d\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+\w+.*?)?(?:\s+<([0-9.]+)>)?$")
FD = re.compile(r"^(\d+)<([^>]*)>")
FLUSH = {"fsync", "fdatasync", "msync", "sync_file_range"}
SEND = {"write", "sendto", "writev", "sendmsg"}
calls, cur = [], None


def new():
    return {"flush": 0, "flush_ms": 0.0, "dirflush": 0, "rename": 0, "open_w": 0, "wbytes": 0,
            "rbytes": 0, "unlink": 0, "fcntl": 0, "utimens": 0, "other_w": 0}


UNFIN = re.compile(r"^(\d+)\s+(\S+)\s+(\w+)\((.*?)\s*<unfinished \.\.\.>$")
RESUMED = re.compile(r"^(\d+)\s+(\S+)\s+<\.\.\. (\w+) resumed>(.*)$")
pending = {}


def lines():
    """Complete syscall lines; a call strace split (another thread's call came between its entry
    and its exit) is joined from its `<unfinished ...>` and `<... resumed>` halves."""
    for raw in open(os.path.join(d, "strace-io.txt"), errors="replace"):
        s = raw.strip()
        u = UNFIN.match(s)
        if u:
            pending[u.group(1)] = (u.group(2), u.group(3), u.group(4))
            continue
        r = RESUMED.match(s)
        if r and r.group(1) in pending:
            ts, sc, head = pending.pop(r.group(1))
            yield f"{r.group(1)} {ts} {sc}({head}{r.group(4)}"
            continue
        yield s


cur = new()
for s in lines():
    mm = LINE.match(s)
    if not mm:
        continue
    _pid, _ts, sc, args, ret, dur = mm.groups()
    fdm = FD.match(args)
    target = fdm.group(2) if fdm else ""
    is_sock = target.startswith(("TCP", "UDP", "socket:", "UNIX", "NETLINK"))
    r = int(ret) if ret not in ("?",) else 0
    if sc in FLUSH:
        cur["flush"] += 1
        cur["flush_ms"] += float(dur or 0) * 1000
        if fdm and os.path.basename(target) and not os.path.splitext(target)[1] and target.rstrip("/").endswith(("kdc", "run")):
            cur["dirflush"] += 1
    elif sc.startswith("rename"):
        cur["rename"] += 1
    elif sc.startswith("unlink"):
        cur["unlink"] += 1
    elif sc == "openat":
        if re.search(r"O_WRONLY|O_RDWR", args):
            cur["open_w"] += 1
    elif sc in ("fcntl", "flock"):
        cur["fcntl"] += 1
    elif sc == "utimensat":
        cur["utimens"] += 1
    elif sc in ("write", "pwrite64", "writev") and not is_sock and r > 0:
        if target.startswith("/srv/p18/run/kdc/kadmind.log") or target.startswith("pipe:") or target.startswith("/dev/"):
            cur["other_w"] += r
        else:
            cur["wbytes"] += r
    elif sc in ("read", "pread64") and not is_sock and r > 0:
        if not target.startswith(("pipe:", "/dev/", "/proc/")):
            cur["rbytes"] += r
    if sc in SEND and is_sock and ":18749" in target and r > 0:
        calls.append(cur)
        cur = new()

rows = []
for i, c in enumerate(calls):
    p = procs[i] if i < len(procs) else "?"
    rows.append((i + 1, p, c))
with open(os.path.join(RESULTS, tag + ".csv"), "w", newline="") as f:
    w = csv.writer(f)
    keys = list(new().keys())
    w.writerow(["reply", "op"] + keys)
    for i, p, c in rows:
        w.writerow([i, p] + [f"{c[k]:.3f}" if isinstance(c[k], float) else c[k] for k in keys])
print(f"== strace io {tag}: {len(calls)} replies in the trace, {len(procs)} in the capture")
order = ["INIT", "GET_POLICY", "CREATE(pw)", "CREATE(rand)", "MODIFY_PRINCIPAL", "CHPASS_PRINCIPAL",
         "CHRAND_PRINCIPAL3", "GET_PRINCIPAL", "DELETE_PRINCIPAL"]
print(f"   {'per call, median':<20}{'n':>4}{'flushes':>8}{'(dir)':>6}{'flush ms':>10}{'renames':>8}"
      f"{'opens(w)':>9}{'file B written':>15}{'file B read':>12}{'locks':>6}")
for op in order + sorted({p for _, p, _ in rows} - set(order)):
    cs = [c for _, p, c in rows if p == op]
    if not cs:
        continue
    med = {k: statistics.median([c[k] for c in cs]) for k in new()}
    print(f"   {op:<20}{len(cs):>4}{med['flush']:>8.0f}{med['dirflush']:>6.0f}{med['flush_ms']:>10.2f}"
          f"{med['rename']:>8.0f}{med['open_w']:>9.0f}{med['wbytes']:>15.0f}{med['rbytes']:>12.0f}{med['fcntl']:>6.0f}")
