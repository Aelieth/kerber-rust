#!/usr/bin/env python3
"""kill-loop.py: SW-3's kill loop (plan-SW), for the kill-loop scenario. Run as root.

    kill-loop.py drive --realm R --dir D     kdc: kerber-rust's kadmin.local and kdb5_util on the live database
    kill-loop.py judge --realm R --dir D     kdc2: MIT's kdb5_util and kadmin.local on a scratch database in D

drive: kadmin.local -q ops on kl000..kl099 (addprinc and modprinc, each with a maxlife no other op gives; cpw
-randkey; delprinc), at least 1,000, until at least 200 are killed with SIGKILL: at a random time (time), once the
database file changes (grow), while a compaction's .principal.tmp-* is there (compaction: 20 in a row, until 50
leave that temp file), and once the next compaction's rename lands (renamed).
After a kill, an op not acknowledged shows all of its change or none in kadmin.local's getprinc; then kdb5_util
dump writes D/dumps/NNNN.dump and D/expect.jsonl what the acknowledged ops left. Stops at the first thing
unexpected. Prints a line per kill and the totals; exit 0 when nothing was unexpected.
judge: each dump into D/mit by MIT's kdb5_util load (D/kdc.conf: a first stanza for the realm naming that database
and the stash D/stash, then kdc2's kdc.conf), then MIT's listprincs and getprinc of kl000..kl099 against
expect.jsonl and D/base.txt.
"""
import argparse
import json
import os
import random
import re
import signal
import statistics
import subprocess
import time

NAMES = [f"kl{i:03d}" for i in range(100)]
KL = re.compile(r"kl\d{3}")
PROMPT = re.compile(r"^(kadmin\.local:\s*)+")
ACKS = {"addprinc": 'Principal "{}" created.', "modprinc": 'Principal "{}" modified.',
        "cpw": 'Key for "{}" randomized.', "delprinc": 'Principal "{}" deleted.'}
NEED = {"time": 40, "grow": 40, "renamed": 3}
STORM = 20
ENCTYPES = {16: "des3-cbc-sha1", 17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
            19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192", 23: "arcfour-hmac",
            25: "camellia128-cts-cmac", 26: "camellia256-cts-cmac"}


def run(argv, **kw):
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(argv, capture_output=True, text=True, timeout=300, **kw)


def parse(out, err, realm):
    """getprinc's principals, listprincs' names, and the names getprinc found absent."""
    found, listed, absent, cur = {}, set(), set(), None
    tail = "@" + realm
    for line in (PROMPT.sub("", raw) for raw in out.splitlines()):
        if line.startswith("Principal: ") and line.endswith(tail):
            cur = found.setdefault(line[11:-len(tail)], {"life": None, "vnos": [], "keys": None})
        elif " " not in line and line.endswith(tail):
            listed.add(line[:-len(tail)])
        elif cur is not None:
            m = re.fullmatch(r"Maximum ticket life: (\d+) days? (\d\d):(\d\d):(\d\d)", line)
            k = re.match(r"Key: vno (\d+),", line)
            n = re.fullmatch(r"Number of keys: (\d+)", line)
            if m:
                d, h, mi, s = map(int, m.groups())
                cur["life"] = ((d * 24 + h) * 60 + mi) * 60 + s
            elif k:
                cur["vnos"].append(int(k.group(1)))
            elif n:
                cur["keys"] = int(n.group(1))
    absent = set(re.findall(r'Principal does not exist while retrieving "([^"@]+)@', err))
    return found, listed, absent


def state(found, absent, name):
    """[kvno, maxlife], None when absent, or what was seen instead."""
    p = found.get(name)
    if p is None:
        return None if name in absent else "no answer"
    vnos = set(p["vnos"])
    if name in absent or len(vnos) != 1 or p["keys"] != len(p["vnos"]) or p["life"] is None:
        return f"keys {p['vnos']} of {p['keys']}, maxlife {p['life']}, absent {name in absent}"
    return [vnos.pop(), p["life"]]


def pick(rng, model, i):
    absent = [n for n in NAMES if n not in model]
    if absent and i < 150:
        return "addprinc", absent[0]
    r = rng.random()
    if absent and (r >= 0.9 or not model):
        return "addprinc", rng.choice(absent)
    return ("modprinc" if r < 0.45 else "cpw" if r < 0.8 else "delprinc"), rng.choice(sorted(model))


def drive(a):
    db = os.path.join(a.kdcdir, "principal")
    kadmin, kdb = os.path.join(a.bin, "kadmin.local"), os.path.join(a.bin, "kdb5_util")
    os.makedirs(os.path.join(a.dir, "dumps"), mode=0o700, exist_ok=True)
    rng = random.Random(a.seed)

    def temps():
        return {n for n in os.listdir(a.kdcdir) if n.startswith(".principal.tmp-")}

    def moved(st0):
        st = os.stat(db)
        return (st.st_ino, st.st_size) != (st0.st_ino, st0.st_size)

    def ours(name):
        r = run([kadmin, "-q", f"getprinc {name}"])
        found, _, absent = parse(r.stdout, r.stderr, a.realm)
        return state(found, absent, name)

    r = run([kadmin, "-q", "listprincs"])
    listed = parse(r.stdout, r.stderr, a.realm)[1]
    for n in sorted(n for n in listed if KL.fullmatch(n)):
        run([kadmin, "-q", f"delprinc -force {n}"])
    base = sorted(n for n in listed if not KL.fullmatch(n))
    with open(os.path.join(a.dir, "base.txt"), "w") as f:
        f.write("".join(n + "\n" for n in base))
    stale0 = len(temps())
    print(f"seed: {a.seed}")
    print(f"base: {len(base)} principals besides kl000-kl099; stale temp files before: {stale0}", flush=True)
    expect = open(os.path.join(a.dir, "expect.jsonl"), "w")
    model, dumps = {}, [0]

    def dump(after):
        path = os.path.join(a.dir, "dumps", f"{dumps[0]:04d}.dump")
        r = run([kdb, "dump", path])
        if r.returncode != 0 or not os.path.isfile(path):
            return f"kdb5_util dump after {after}: rc {r.returncode}: {(r.stdout + r.stderr).strip()[:200]}"
        expect.write(json.dumps({"id": f"{dumps[0]:04d}", "after": after, "kl": model}) + "\n")
        expect.flush()
        dumps[0] += 1
        return None

    def settle(name, after):
        if after is None:
            model.pop(name, None)
        else:
            model[name] = after

    c = dict.fromkeys(["ops", "applied", "kills", "left", "compactions", "acked", "doubt", "doubt applied"], 0)
    modes = dict.fromkeys(["time", "grow", "compaction", "renamed"], 0)
    dbs = dict.fromkeys(["unchanged", "grown", "replaced", "cut"], 0)
    storm, lives = 0, []
    problem = dump("before the first op") if base else "listprincs gave no principal"
    while problem is None:
        i = c["ops"]
        done = (i >= a.ops and c["kills"] >= a.kills and c["left"] >= a.compaction
                and all(modes[m] >= n for m, n in NEED.items()))
        if done or i >= a.cap:
            break
        verb, name = pick(rng, model, i)
        life, before = 3600 + 10 * i, model.get(name)
        cmd, after = {"addprinc": (f"addprinc -randkey -maxlife {life}s {name}", [1, life]),
                      "modprinc": (f"modprinc -maxlife {life}s {name}", before and [before[0], life]),
                      "cpw": (f"cpw -randkey {name}", before and [before[0] + 1, before[1]]),
                      "delprinc": (f"delprinc -force {name}", None)}[verb]
        mode = rng.choice(["time", "grow"]) if rng.random() < 0.2 else None
        delay = rng.uniform(0, 1.2 * (statistics.median(lives[-50:]) if lives else 0.05))
        hold = c["left"] < a.compaction and storm < STORM
        ack = ACKS[verb].format(f"{name}@{a.realm}").encode()
        st0, temps0 = os.stat(db), temps()
        p = subprocess.Popen([kadmin, "-q", cmd], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        fd = p.stdout.fileno()
        os.set_blocking(fd, False)
        out, why, seen, t0 = b"", None, None, time.monotonic()
        while p.poll() is None:
            try:
                out += os.read(fd, 65536)
            except BlockingIOError:
                pass
            if seen is None:
                seen = min(temps() - temps0, default=None)
            if seen and hold:
                why = "compaction"
            elif seen and os.stat(db).st_ino != st0.st_ino:
                why = "renamed"
            elif (mode == "time" and time.monotonic() - t0 >= delay) or (mode == "grow" and moved(st0)):
                why = mode
            if why:
                os.kill(p.pid, signal.SIGKILL)
                break
        took = time.monotonic() - t0
        p.wait()
        os.set_blocking(fd, True)
        out += p.stdout.read()
        p.stdout.close()
        st1 = os.stat(db)
        replaced = st1.st_ino != st0.st_ino
        c["ops"] += 1
        if seen and replaced:
            c["compactions"] += 1
            storm = 0
        if p.returncode != -signal.SIGKILL:
            lives.append(took)
            if ack not in out:
                problem = f"op {i:04d} {cmd}: rc {p.returncode}, no acknowledgement: {out.decode(errors='replace')[:200]}"
            else:
                settle(name, after)
                c["applied"] += 1
            continue
        c["kills"] += 1
        modes[why] += 1
        storm += why == "compaction"
        left = bool(seen) and os.path.exists(os.path.join(a.kdcdir, seen))
        c["left"] += left
        where = ("replaced" if replaced else "grown" if st1.st_size > st0.st_size
                 else "cut" if st1.st_size < st0.st_size else "unchanged")
        dbs[where] += 1
        if ack in out:
            outcome = "acknowledged"
            c["acked"] += 1
        else:
            c["doubt"] += 1
            seen_now = ours(name)
            if seen_now == after:
                outcome = "in doubt: applied"
                c["doubt applied"] += 1
            elif seen_now == before:
                outcome = "in doubt: not applied"
            else:
                outcome = f"in doubt: neither before ({before}) nor after ({after}): {seen_now}"
                problem = f"op {i:04d} {cmd}: {outcome}"
        if outcome in ("acknowledged", "in doubt: applied"):
            settle(name, after)
            c["applied"] += 1
        line = (f"kill {c['kills']:04d} op {i:04d}: {verb} {name}, {why} at {took * 1000:.1f} ms, database {where}"
                f"{', temp file left' if left else ''}, {outcome}")
        print(line, flush=True)
        problem = problem or dump(line)
    problem = problem or dump("after the last op")
    stale = len(temps())
    print(f"ops: {c['ops']} attempted, {c['applied']} applied")
    print(f"kills: {c['kills']}")
    print("kills by mode: " + ", ".join(f"{m} {n}" for m, n in modes.items()))
    print(f"compaction kills: {c['left']} (the compaction's .principal.tmp-* still there after the kill)")
    print(f"compactions completed: {c['compactions']}")
    print("the database after a kill: " + ", ".join(f"{w} {n}" for w, n in dbs.items()))
    print(f"in doubt: {c['doubt']} (applied {c['doubt applied']}, not applied {c['doubt'] - c['doubt applied']});"
          f" acknowledged before the kill landed: {c['acked']}")
    print(f"dumps: {dumps[0]} (0000 before the first op, one after each kill, the last after the last op)")
    print(f"stale temp files: {stale - stale0} left by this run ({stale} in all)")
    if problem:
        print(f"UNEXPECTED: {problem}")
    print(f"unexpected: {int(problem is not None)}")
    return int(problem is not None)


def stash_enctype(b):
    """The enctype of the first entry of a keytab-format stash (MIT's is a keytab of K/M), else 0."""
    if b[:2] != b"\x05\x02":
        return 0
    o = 8
    for _ in range(int.from_bytes(b[6:8], "big") + 1):
        o += 2 + int.from_bytes(b[o:o + 2], "big")
    return int.from_bytes(b[o + 9:o + 11], "big")


def judge(a):
    kadmin, kdb = os.path.join(a.bin, "kadmin.local"), os.path.join(a.bin, "kdb5_util")
    stash, conf = os.path.join(a.dir, "stash"), os.path.join(a.dir, "kdc.conf")
    with open(stash, "rb") as f:
        mkt = ENCTYPES.get(stash_enctype(f.read(4096)))
    with open(os.path.join(a.kdcdir, "kdc.conf")) as f:
        theirs = f.read()
    with open(conf, "w") as f:
        f.write(f"[realms]\n    {a.realm} = {{\n        database_name = {a.dir}/mit/principal\n"
                f"        key_stash_file = {stash}\n        iprop_enable = false\n"
                + (f"        master_key_type = {mkt}\n" if mkt else "") + "    }\n\n" + theirs)
    os.makedirs(os.path.join(a.dir, "mit"), mode=0o700, exist_ok=True)
    env = dict(os.environ, KRB5_KDC_PROFILE=conf, SS_READLINE_PATH="none")
    with open(os.path.join(a.dir, "base.txt")) as f:
        base = set(f.read().split())
    script = "listprincs\n" + "".join(f"getprinc {n}\n" for n in NAMES)
    print(f"master key type: {mkt or 'not read from the stash'}")
    loaded = matched = total = 0
    with open(os.path.join(a.dir, "expect.jsonl")) as f:
        for e in map(json.loads, f):
            total += 1
            r = run([kdb, "-r", a.realm, "load", os.path.join(a.dir, "dumps", e["id"] + ".dump")], env=env)
            if r.returncode != 0:
                print(f"{e['id']} ({e['after']}): load rc {r.returncode}: {(r.stdout + r.stderr).strip()[:200]}")
                continue
            loaded += 1
            r = run([kadmin, "-r", a.realm], env=env, input=script, stdin=None)
            found, listed, absent = parse(r.stdout, r.stderr, a.realm)
            others = {n for n in listed if not KL.fullmatch(n)}
            bad = [f"other principals: missing {sorted(base - others)[:3]}, extra {sorted(others - base)[:3]}"] \
                if others != base else []
            if {n for n in listed if KL.fullmatch(n)} != set(e["kl"]):
                bad.append(f"listprincs: {sum(map(bool, map(KL.fullmatch, listed)))} kl, expected {len(e['kl'])}")
            bad += [f"{n} {state(found, absent, n)}, expected {e['kl'].get(n)}" for n in NAMES
                    if state(found, absent, n) != e["kl"].get(n)]
            if bad:
                print(f"{e['id']} ({e['after']}): {'; '.join(bad[:3])}" + (f"; {len(bad) - 3} more" if bad[3:] else ""))
            else:
                matched += 1
                print(f"{e['id']}: ok")
    print(f"loaded: {loaded} of {total}")
    print(f"matched: {matched} of {total}")
    return int(matched != total or total == 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["drive", "judge"])
    ap.add_argument("--realm", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--kdcdir", default="/var/kerberos/krb5kdc")
    ap.add_argument("--bin", default="/usr/sbin")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--ops", type=int, default=1000)
    ap.add_argument("--kills", type=int, default=200)
    ap.add_argument("--compaction", type=int, default=50)
    ap.add_argument("--cap", type=int, default=4000)
    a = ap.parse_args()
    return drive(a) if a.what == "drive" else judge(a)


if __name__ == "__main__":
    raise SystemExit(main())
