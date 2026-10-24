"""OV-3 cells on the KDC guest. Prints CELL lines only. Does not print secrets."""
import os
import secrets
import shutil
import socket
import subprocess
import time

ROOT = "/var/tmp/ov3"
BINS = "/var/tmp/ov3-bins"
REALM = "EMBED.KERBER.TEST"
SEED = secrets.token_bytes(20)
# RFC 4648 base32, no padding.
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def b32(raw):
    acc = bits = 0
    out = []
    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPH[(acc >> bits) & 31])
            acc &= (1 << bits) - 1
    if bits:
        out.append(ALPH[(acc << (5 - bits)) & 31])
    return "".join(out)


SEED_B32 = b32(SEED)
PW = secrets.token_hex(8)
PW2 = secrets.token_hex(8)
MASTER = secrets.token_hex(8)
SECRETS = (SEED_B32, PW, PW2, MASTER)


def redact(text):
    for secret in SECRETS:
        text = text.replace(secret, "[redacted]")
    return text


def say(line):
    print(redact(line), flush=True)


def write(path, text, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def env_for(conf):
    env = os.environ.copy()
    env["KRB5_CONFIG"] = ROOT + "/krb5.conf"
    env["KRB5_KDC_PROFILE"] = conf
    return env


def run(argv, env, data=None):
    proc = subprocess.run(argv, env=env, input=data, text=True, capture_output=True)
    return proc.returncode, redact((proc.stdout or "") + (proc.stderr or ""))


def wait_log(path, needle, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path) and needle in open(path, encoding="utf-8", errors="replace").read():
            return True
        time.sleep(0.2)
    return False


def kadmin(env, query):
    rc, text = run(["kadmin.local", "-q", query], env)
    kept = []
    for line in text.splitlines():
        if line.startswith("Key:") or line.startswith("MKey:"):
            continue
        if any(s in line for s in ("Principal:", "Policy:", "Failed", "Attributes", "Number of keys", "error", "kadmin")):
            kept.append(line)
    return rc, "\n".join(kept)


def totp(offset):
    proc = subprocess.run(
        ["python3", BINS + "/otp-totp.py", "code", SEED_B32, str(offset)],
        text=True, capture_output=True, check=True,
    )
    return proc.stdout.strip()


def kinit(env, tag, principal, token):
    cell_env = dict(env)
    cell_env["KRB5CCNAME"] = "FILE:" + ROOT + "/cc-" + tag
    argv = ["kinit", "-V", "-T", ROOT + "/armor.cc", principal]
    proc = subprocess.run(argv, env=cell_env, input=token + "\n", text=True, capture_output=True)
    err = redact((proc.stdout or "") + (proc.stderr or ""))
    summary = ""
    for line in err.splitlines():
        if line.startswith("kinit:"):
            summary = line
    say(f"CELL {tag} rc {proc.returncode} {summary}")
    return proc.returncode


def first_line(text, prefix):
    return next((ln for ln in text.splitlines() if ln.startswith(prefix)), "")


def extra_cells(env, leg):
    """V1-V4 and V12 from the OTP cell list, inferred and to be checked in the lab (MIT first).
    A dedicated v1user keeps these codes off the other cells' per-user replay state."""
    user = f"v1user@{REALM}"
    svc = f"host/svc.embed.kerber.test@{REALM}"
    armor = ["-T", ROOT + "/armor.cc"]

    def cc(tag):
        e = dict(env)
        e["KRB5CCNAME"] = "FILE:" + ROOT + "/cc-" + tag
        return e

    def kvno(e, tag):
        p = subprocess.run(["kvno", svc], env=e, text=True, capture_output=True)
        out = redact((p.stdout or "") + (p.stderr or ""))
        say(f"CELL {tag} rc {p.returncode} {first_line(out, 'kvno:')}")

    def patype(e):
        pc = subprocess.run(["klist", "-C"], env=e, text=True, capture_output=True)
        return next((ln.strip() for ln in pc.stdout.splitlines() if "pa_type" in ln), "")

    # V1: a right code logs in, and the require_auth=mfa service issues -- the OTP indicator reached the ticket.
    e = cc(f"{leg}-v1")
    rc, _ = run(["kinit", "-V"] + armor + [user], e, PW + totp(0) + "\n")
    say(f"CELL {leg}-v1-code rc {rc}")
    fl = subprocess.run(["klist", "-f"], env=e, text=True, capture_output=True)
    flags = next((ln.strip() for ln in fl.stdout.splitlines() if "Flags:" in ln), "")
    say(f"V1 {leg} flags {flags}")
    say(f"V1 {leg} patype {patype(e)}")
    kvno(e, f"{leg}-v1-svc")
    # V2: a wrong code is refused (24); the password key is not read as a fallback.
    e = cc(f"{leg}-v2")
    rc, text = run(["kinit", "-V"] + armor + [user], e, PW + "000000\n")
    say(f"CELL {leg}-v2-wrong rc {rc} {first_line(text, 'kinit:')}")
    # V3: EOF at the OTP prompt -- kinit reads no value and fails.
    e = cc(f"{leg}-v3")
    rc, text = run(["kinit", "-V"] + armor + [user], e, "")
    say(f"CELL {leg}-v3-eof rc {rc} {first_line(text, 'kinit:')}")
    # V4: a password login with no FAST armor yields a TGT without the mfa indicator; the service refuses it.
    e = cc(f"{leg}-v4")
    rc, _ = run(["kinit", "-V", user], e, PW + "\n")
    say(f"CELL {leg}-v4-noarmor rc {rc}")
    kvno(e, f"{leg}-v4-svc")
    say(f"V4 {leg} patype {patype(e)}")
    # V12: a renewed ticket keeps the indicator; the service still issues. totp(1) differs from V1's totp(0).
    e = cc(f"{leg}-v12")
    rc, _ = run(["kinit", "-V", "-r", "7d"] + armor + [user], e, PW + totp(1) + "\n")
    say(f"CELL {leg}-v12-init rc {rc}")
    rr = subprocess.run(["kinit", "-R"], env=e, text=True, capture_output=True)
    out = redact((rr.stdout or "") + (rr.stderr or ""))
    say(f"CELL {leg}-v12-renew rc {rr.returncode} {first_line(out, 'kinit:')}")
    kvno(e, f"{leg}-v12-svc")


def main():
    if os.path.exists(ROOT):
        shutil.rmtree(ROOT)
    os.makedirs(ROOT, 0o700)
    write(ROOT + "/krb5.conf", f"""[libdefaults]
    default_realm = {REALM}
    dns_lookup_kdc = false
    rdns = false
[realms]
    {REALM} = {{
        kdc = 127.0.0.1
    }}
""")
    kdc_common = f"""[kdcdefaults]
    kdc_listen = 127.0.0.1:88
    kdc_tcp_listen = 127.0.0.1:88
[realms]
    {REALM} = {{
        database_name = {ROOT}/principal
        key_stash_file = {ROOT}/stash
        max_life = 1d
        max_renewable_life = 7d
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }}
[dbmodules]
    {REALM} = {{
        database_name = {ROOT}/principal
    }}
[otp]
    totp = {{
        server = {ROOT}/otp.sock
        indicator = mfa
    }}
"""
    write(ROOT + "/kdc-mit.conf", kdc_common + f"""[logging]
    kdc = FILE:{ROOT}/mit-kdc.log
""")
    ours_common = kdc_common.replace(
        f"        server = {ROOT}/otp.sock\n",
        "",
    )
    say("OURS_CONF_SERVER " + str("server =" in ours_common))
    write(ROOT + "/kdc-ours.conf", ours_common + f"""[logging]
    kdc = FILE:{ROOT}/ours-kdc.log
[plugins]
    kdcpolicy = {{
        enable_only = require_mfa
    }}
""")
    def pw_file(keep=PW):
        lines = []
        for name in names:
            password = keep if name == "keepuser" else PW
            lines.append(f"{name} {password}")
            lines.append(f"{name}@{REALM} {password}")
        write(ROOT + "/current-pw", "\n".join(lines) + "\n")

    write(ROOT + "/seed-raw", SEED_B32 + "\n")
    names = [
        "v6user", "v7user", "v8user", "keepuser", "v5user", "plainuser",
        "chaosslow", "chaospanic", "chaoserr", "v11user", "v1user",
    ]
    pw_file()
    seed_lines = []
    for name in names:
        seed_lines.append(f"{name}@{REALM} {SEED_B32}")
    write(ROOT + "/seeds", "\n".join(seed_lines) + "\n")
    mit = env_for(ROOT + "/kdc-mit.conf")
    rc, text = run(["kdb5_util", "create", "-s", "-P", MASTER], mit)
    say(f"CREATE rc {rc}")
    if rc != 0:
        say("CELL setup create failed")
        say(text.splitlines()[-1] if text.splitlines() else "no create output")
        return 1
    commands = [
        "addprinc -randkey host/armor.embed.kerber.test",
        f"ktadd -k {ROOT}/armor.keytab host/armor.embed.kerber.test",
        "addprinc -randkey host/svc.embed.kerber.test",
        "setstr host/svc.embed.kerber.test require_auth mfa",
        "addpol -maxfailure 3 lock3",
    ]
    for name in ("v6user", "v7user", "keepuser", "v5user", "plainuser", "chaosslow", "chaospanic", "chaoserr", "v11user", "v1user"):
        commands.append(f"addprinc -pw {PW} +requires_preauth {name}")
    commands.append(f"addprinc -pw {PW} +requires_preauth -policy lock3 v8user")
    for name in ("v6user", "v7user", "v8user", "keepuser", "v1user"):
        commands.append(f'setstr {name} otp "[{{""type"":""totp""}}]"')
    commands.append('setstr chaosslow otp "[{""type"":""totp"",""username"":""chaos:slow:2000""}]"')
    commands.append('setstr chaospanic otp "[{""type"":""totp"",""username"":""chaos:panic""}]"')
    commands.append('setstr chaoserr otp "[{""type"":""totp"",""username"":""chaos:error""}]"')
    commands.append('setstr v11user otp "[{""type"":""nosuch""}]"')
    for query in commands:
        rc, text = kadmin(mit, query)
        label = query.split()[0]
        target = query.split()[-1]
        say(f"KADM {label} {target} rc {rc}")
        if rc != 0 and text:
            say(text.splitlines()[-1])
    stub = subprocess.Popen(
        ["python3", BINS + "/embed-otp-stub.py", ROOT + "/otp.sock", ROOT + "/current-pw", ROOT + "/seed-raw", ROOT + "/stub-state"],
        stdout=open(ROOT + "/stub.log", "w"),
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 5
    while time.time() < deadline and not os.path.exists(ROOT + "/otp.sock"):
        time.sleep(0.1)
    say(f"STUB pid {stub.pid} sock {os.path.exists(ROOT + '/otp.sock')} alive {stub.poll() is None}")
    if stub.poll() is not None and os.path.exists(ROOT + "/stub.log"):
        say(redact(open(ROOT + "/stub.log", encoding="utf-8", errors="replace").read()[-400:]))
        return 1
    subprocess.run(["systemctl", "stop", "krb5kdc", "kadmin"], check=False)
    kdc = subprocess.Popen(
        ["krb5kdc", "-n"], env=mit,
        stdout=open(ROOT + "/mit-kdc.out", "w"), stderr=subprocess.STDOUT,
    )
    say(f"MIT_KDC pid {kdc.pid} up {wait_log(ROOT + '/mit-kdc.log', 'commencing operation', 15)}")
    armor_env = dict(mit)
    armor_env["KRB5CCNAME"] = "FILE:" + ROOT + "/armor.cc"
    rc, text = run(
        ["kinit", "-k", "-t", ROOT + "/armor.keytab", f"host/armor.embed.kerber.test@{REALM}"],
        armor_env,
    )
    say(f"ARMOR rc {rc}")
    if rc != 0:
        say(text[-300:])
        return 1
    principal = f"v6user@{REALM}"
    code0 = totp(0)
    kinit(mit, "mit-v6-right", principal, PW + code0)
    kinit(mit, "mit-v6-wrong-code", principal, PW + "000000")
    kinit(mit, "mit-v6-wrong-pw", principal, "not-the-password" + code0)
    kinit(mit, "mit-v6-replay", principal, PW + code0)
    code1 = totp(1)
    kinit(mit, "mit-v6-next", principal, PW + code1)
    kadmin(mit, f"cpw -keepold -pw {PW2} keepuser")
    pw_file(PW2)
    kinit(mit, "mit-keep-old", f"keepuser@{REALM}", PW + totp(0))
    kinit(mit, "mit-keep-new", f"keepuser@{REALM}", PW2 + totp(1))
    kinit(mit, "mit-v7-first", f"v7user@{REALM}", PW + totp(0))
    kinit(mit, "mit-v7-replay", f"v7user@{REALM}", PW + totp(0))
    kdc.terminate()
    kdc.wait(timeout=10)
    kdc = subprocess.Popen(
        ["krb5kdc", "-n"], env=mit,
        stdout=open(ROOT + "/mit-kdc.out", "a"), stderr=subprocess.STDOUT,
    )
    say(f"MIT_KDC_RESTART up {wait_log(ROOT + '/mit-kdc.log', 'commencing operation', 15)}")
    kinit(mit, "mit-v7-after-restart", f"v7user@{REALM}", PW + totp(0))
    for n in range(3):
        kinit(mit, f"mit-v8-wrong-{n}", f"v8user@{REALM}", PW + "000000")
    kinit(mit, "mit-v8-fourth", f"v8user@{REALM}", PW + totp(1))
    rc, text = kadmin(mit, "getprinc v8user")
    say("KADM getprinc v8user")
    say(text)
    saved = dict(mit)
    saved["KRB5CCNAME"] = "FILE:" + ROOT + "/v5.cc"
    proc = subprocess.run(
        ["kinit", "-V", "-T", ROOT + "/armor.cc", f"v5user@{REALM}"],
        env=saved, input=PW + "\n", text=True, capture_output=True,
    )
    say(f"CELL v5-tgt-before rc {proc.returncode}")
    rc, text = kadmin(mit, "setstr v5user require_mfa yes")
    say(f"KADM setstr require_mfa rc {rc}")
    rc, text = kadmin(mit, "modprinc -unlock v8user")
    say(f"KADM unlock v8user rc {rc}")
    extra_cells(mit, "mit")
    kdc.terminate()
    kdc.wait(timeout=10)
    if os.path.exists(ROOT + "/stub.log"):
        for line in open(ROOT + "/stub.log", encoding="utf-8", errors="replace"):
            if line.startswith("verdict ") or line.startswith("stub "):
                say("STUB " + line.rstrip())
    rc, text = run(["kdb5_util", "dump", ROOT + "/dump"], mit)
    say(f"DUMP rc {rc}")
    if rc != 0:
        say(text[-200:])
        return 1
    for suffix in ("", ".ok", ".kadm5", ".dump"):
        path = ROOT + "/principal" + suffix
        if os.path.exists(path):
            os.replace(path, path + ".mit")
    ours_env = env_for(ROOT + "/kdc-ours.conf")
    rc, text = run(
        [BINS + "/krb5-kdb", "-r", REALM, "-d", ROOT + "/principal", "-sf", ROOT + "/stash", "-P", MASTER, "load", ROOT + "/dump"],
        ours_env,
    )
    say(f"LOAD rc {rc}")
    if rc != 0:
        say(text[-300:])
        return 1
    ours_env["KERBER_EXAMPLE_TOTP_SEEDS"] = ROOT + "/seeds"
    ours_env["KERBER_EXAMPLE_TOTP_STATE"] = ROOT + "/ours-state"
    ours_env["KERBER_EXAMPLE_MFA_INDICATOR"] = "mfa"
    ours = subprocess.Popen(
        [BINS + "/krb5-otp-kdc", "-n"], env=ours_env,
        stdout=open(ROOT + "/ours-kdc.out", "w"), stderr=subprocess.STDOUT,
    )
    ours_up = wait_log(ROOT + "/ours-kdc.log", "commencing operation", 15)
    say(f"OURS pid {ours.pid} up {ours_up}")
    if not ours_up:
        for path in (ROOT + "/ours-kdc.out", ROOT + "/ours-kdc.log"):
            if os.path.exists(path):
                say(os.path.basename(path))
                say(redact(open(path, encoding="utf-8", errors="replace").read()[-500:]))
        return 1
    saved = dict(ours_env)
    saved["KRB5CCNAME"] = "FILE:" + ROOT + "/v5.cc"
    kinit(ours_env, "ours-v5-password", f"v5user@{REALM}", PW)
    if proc.returncode == 0:
        kv = subprocess.run(
            ["kvno", f"host/svc.embed.kerber.test@{REALM}"],
            env=saved, text=True, capture_output=True,
        )
        err = redact((kv.stdout or "") + (kv.stderr or ""))
        summary = next((ln for ln in err.splitlines() if ln.startswith("kvno:")), "")
        say(f"CELL ours-v5-tgs rc {kv.returncode} {summary}")
    pw_file()
    kinit(ours_env, "ours-v6-right", principal, PW + totp(0))
    kinit(ours_env, "ours-v6-wrong-code", principal, PW + "000000")
    kinit(ours_env, "ours-v6-wrong-pw", principal, "not-the-password" + totp(0))
    kinit(ours_env, "ours-v6-replay", principal, PW + totp(0))
    kinit(ours_env, "ours-keep-old", f"keepuser@{REALM}", PW + totp(1))
    kinit(ours_env, "ours-keep-new", f"keepuser@{REALM}", PW2 + totp(-1))
    kinit(ours_env, "ours-v7-first", f"v7user@{REALM}", PW + totp(0))
    ours.terminate()
    ours.wait(timeout=10)
    ours = subprocess.Popen(
        [BINS + "/krb5-otp-kdc", "-n"], env=ours_env,
        stdout=open(ROOT + "/ours-kdc.out", "a"), stderr=subprocess.STDOUT,
    )
    say(f"OURS_RESTART up {wait_log(ROOT + '/ours-kdc.log', 'commencing operation', 15)}")
    kinit(ours_env, "ours-v7-after-restart", f"v7user@{REALM}", PW + totp(0))
    for n in range(3):
        kinit(ours_env, f"ours-v8-wrong-{n}", f"v8user@{REALM}", PW + "000000")
    kinit(ours_env, "ours-v8-fourth", f"v8user@{REALM}", PW + totp(1))
    kinit(ours_env, "ours-v11-otp", f"v11user@{REALM}", PW + totp(0))
    kinit(ours_env, "ours-v11-plain", f"plainuser@{REALM}", PW)
    extra_cells(ours_env, "ours")
    ours.terminate()
    ours.wait(timeout=10)
    chaos_env = dict(ours_env)
    chaos_env["KRB5_KDC_PROFILE"] = ROOT + "/kdc-ours.conf"
    chaos = subprocess.Popen(
        [BINS + "/krb5-otp-kdc-chaos", "-n"], env=chaos_env,
        stdout=open(ROOT + "/chaos-kdc.out", "w"), stderr=subprocess.STDOUT,
    )
    say(f"CHAOS pid {chaos.pid} up {wait_log(ROOT + '/ours-kdc.log', 'commencing operation', 15)}")
    t0 = time.time()
    kinit(chaos_env, "ours-v9-slow", f"chaosslow@{REALM}", PW + "000000")
    say(f"CELL ours-v9-slow seconds {time.time() - t0:.2f}")
    t1 = time.time()
    kinit(chaos_env, "ours-v9-other", principal, PW + totp(1))
    say(f"CELL ours-v9-other seconds {time.time() - t1:.2f}")
    kinit(chaos_env, "ours-v10-panic", f"chaospanic@{REALM}", PW + "000000")
    kinit(chaos_env, "ours-v10-error", f"chaoserr@{REALM}", PW + "000000")
    alive = kinit(chaos_env, "ours-v10-alive", f"plainuser@{REALM}", PW)
    say(f"CELL ours-v10-kdc-alive rc {0 if chaos.poll() is None else 1}")
    chaos.terminate()
    stub.terminate()
    write(ROOT + "/mit-kdc.log", open(ROOT + "/mit-kdc.log", encoding="utf-8", errors="replace").read() + "OV3_CONTROL\n", mode=0o600)
    if os.path.exists(ROOT + "/ours-kdc.log"):
        shown = 0
        for line in open(ROOT + "/ours-kdc.log", encoding="utf-8", errors="replace"):
            low = line.lower()
            if "otp" in low or "initialize" in low or "require_mfa" in low:
                say("KDCLOG " + line.rstrip())
                shown += 1
                if shown == 12:
                    break
    for path in (ROOT + "/mit-kdc.log", ROOT + "/ours-kdc.log", ROOT + "/stub.log", ROOT + "/ours-state"):
        if not os.path.exists(path):
            say(f"HYGIENE missing {os.path.basename(path)}")
            continue
        body = open(path, encoding="utf-8", errors="replace").read()
        leaked = [name for name, secret in (("seed", SEED_B32), ("pw", PW), ("pw2", PW2), ("master", MASTER)) if secret in body]
        say(f"HYGIENE {os.path.basename(path)} leaked {' '.join(leaked) if leaked else 'none'} control {'OV3_CONTROL' in body}")
    say("FINAL_GUEST")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
