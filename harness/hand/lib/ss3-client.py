#!/usr/bin/env python3
"""SS-3 cells from client2. Passwords stay in files. Nothing secret is printed."""
import os
import select
import subprocess
import time
from pathlib import Path

REALM = "EMBED.KERBER.TEST"
ROOT = Path("/var/tmp/ss3")
ENV = os.environ.copy()
ENV["KRB5_CONFIG"] = str(ROOT / "embed.conf")
ENV["KRB5CCNAME"] = "FILE:/var/tmp/ss3/cc"


def pw(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8").strip()


def redact(text: str) -> str:
    out = text
    for name in ("pw1", "pw2", "pw3"):
        path = ROOT / name
        if path.exists():
            secret = path.read_text(encoding="utf-8").strip()
            if secret:
                out = out.replace(secret, "[redacted]")
    kept = []
    for line in out.splitlines():
        low = line.lower()
        if line.startswith("Key:") or "session key" in low or len(line) > 200:
            continue
        kept.append(line[:200])
    return "\n".join(kept)


def kadmin(query: str) -> tuple[int, str]:
    try:
        got = subprocess.run(
            [
                "/usr/bin/kadmin",
                "-k",
                "-t",
                str(ROOT / "admin.keytab"),
                "-p",
                f"admin/admin@{REALM}",
                "-r",
                REALM,
                "-q",
                query,
            ],
            env=ENV,
            capture_output=True,
            timeout=40,
        )
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    blob = (got.stdout + got.stderr).decode("utf-8", "replace")
    return got.returncode, blob


def kinit_pw(secret: str, cc: str) -> tuple[int, str]:
    env = ENV.copy()
    env["KRB5CCNAME"] = cc
    try:
        got = subprocess.run(
            ["/usr/bin/kinit", f"u1@{REALM}"],
            input=secret + "\n",
            text=True,
            env=env,
            capture_output=True,
            timeout=25,
        )
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return got.returncode, got.stderr


def kind_of(rc: int, err: str) -> str:
    if rc == 0:
        return "ok"
    if "not found" in err:
        return "notfound"
    if "Password incorrect" in err or "Preauthentication failed" in err:
        return "badpw"
    if "Clock skew" in err:
        return "skew"
    if err == "timeout":
        return "timeout"
    return "other"


def show_kinit(tag: str, rc: int, err: str) -> None:
    kind = kind_of(rc, err)
    print(f"{tag} KINIT_RC:{rc} KIND:{kind}")
    if kind == "other":
        safe = redact(err).splitlines()
        if safe:
            print(f"{tag} KINIT_ERR {safe[0]}")


def kpasswd(old: str, new: str) -> tuple[int, int, bool]:
    import pty

    env = ENV.copy()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("/usr/bin/kpasswd", ["kpasswd", f"u1@{REALM}"], env)
    sent = 0
    buf = b""
    seen = b""
    deadline = time.time() + 30
    status = None
    while time.time() < deadline and status is None:
        ready, _, _ = select.select([fd], [], [], 0.4)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                # EIO on pty close is the same event as an empty read.
                chunk = b""
            if not chunk:
                # The child closed the pty. That is an exit, not the 30s timeout.
                try:
                    done, st = os.waitpid(pid, os.WNOHANG)
                    if not done:
                        done, st = os.waitpid(pid, 0)
                    status = st
                except ChildProcessError:
                    status = 0
                break
            buf += chunk
            seen += chunk
            low = buf.lower()
            if sent == 0 and (b"password for" in low or low.rstrip().endswith(b"password:")):
                os.write(fd, (old + "\n").encode())
                sent = 1
                buf = b""
            elif sent == 1 and b"new password" in low:
                os.write(fd, (new + "\n").encode())
                sent = 2
                buf = b""
            elif sent == 2 and (
                b"again" in low or b"re-enter" in low or b"retype" in low
            ):
                os.write(fd, (new + "\n").encode())
                sent = 3
                buf = b""
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
    if status is None:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        return 124, sent, b"password changed" in seen.lower()
    rc = os.waitstatus_to_exitcode(status)
    return rc, sent, b"password changed" in seen.lower()


def cell1() -> None:
    secret = pw("pw1")
    t0 = time.time()
    rc, blob = kadmin(f"addprinc -pw {secret} u1")
    t1 = time.time()
    print(f"CELL1 ADD_RC:{rc}")
    shown = False
    for line in redact(blob).splitlines():
        if "created" in line.lower() or line.startswith("add_principal"):
            print("CELL1 ADD", line[:180])
            shown = True
    if rc != 0 and not shown:
        safe = redact(blob).splitlines()
        if safe:
            print("CELL1 ADD_ERR", safe[0])
    krc, err = kinit_pw(secret, "FILE:/var/tmp/ss3/cc1")
    t2 = time.time()
    show_kinit("CELL1", krc, err)
    print(f"CELL1 GAP_MS:{int((t2 - t1) * 1000)}")
    print(f"CELL1 ADD_S:{int(t1)} KINIT_S:{int(t2)}")


def cell2() -> None:
    old = pw("pw1")
    new = pw("pw2")
    rc, blob = kadmin(f"cpw -pw {new} u1")
    print(f"CELL2 CPW_RC:{rc}")
    for line in redact(blob).splitlines():
        if "password changed" in line.lower() or "change_password" in line.lower():
            print("CELL2 CPW", line[:180])
    nrc, nerr = kinit_pw(new, "FILE:/var/tmp/ss3/cc2")
    show_kinit("CELL2 NEW", nrc, nerr)
    orc, oerr = kinit_pw(old, "FILE:/var/tmp/ss3/cc2old")
    show_kinit("CELL2 OLD", orc, oerr)


def cell3() -> None:
    rc, sent, changed = kpasswd(pw("pw2"), pw("pw3"))
    print(f"CELL3 KPASSWD_RC:{rc} SENT:{sent} CHANGED:{int(changed)}")
    krc, err = kinit_pw(pw("pw3"), "FILE:/var/tmp/ss3/cc3")
    show_kinit("CELL3", krc, err)


def cell4() -> None:
    rc, blob = kadmin("delprinc -force u1")
    print(f"CELL4 DEL_RC:{rc}")
    for line in redact(blob).splitlines():
        if "deleted" in line.lower():
            print("CELL4 DEL", line[:180])
    krc, err = kinit_pw(pw("pw3"), "FILE:/var/tmp/ss3/cc4")
    show_kinit("CELL4", krc, err)


def cell6() -> None:
    secret = pw("pw3")
    workers = []
    for i in range(8):
        script = (
            "for n in 1 2 3 4 5 6 7 8; do "
            "/usr/bin/kinit u1@EMBED.KERBER.TEST < /var/tmp/ss3/pw3 >/dev/null 2>&1; "
            "/usr/bin/kdestroy >/dev/null 2>&1; "
            "done"
        )
        env = ENV.copy()
        env["KRB5CCNAME"] = f"FILE:/var/tmp/ss3/burst-{i}"
        workers.append(
            subprocess.Popen(
                ["/bin/bash", "-c", script],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
    time.sleep(0.4)
    alive = sum(1 for p in workers if p.poll() is None)
    t0 = time.time()
    try:
        rc, blob = kadmin("getprinc u1")
    except Exception:
        rc, blob = 125, ""
    dt = time.time() - t0
    print(f"CELL6 ALIVE:{alive} GET_RC:{rc} GET_MS:{int(dt * 1000)}")
    for line in redact(blob).splitlines():
        stripped = line.strip()
        if stripped.startswith("Principal:"):
            print("CELL6", stripped[:180])
    for p in workers:
        try:
            p.wait(timeout=40)
        except subprocess.TimeoutExpired:
            p.kill()
    print("CELL6 WORKERS_DONE")


def cell7() -> None:
    rc, blob = kadmin("listprincs")
    print(f"CELL7 LIST_RC:{rc}")
    names = []
    for line in blob.splitlines():
        stripped = line.strip()
        if stripped.endswith(f"@{REALM}") and " " not in stripped and len(stripped) < 120:
            names.append(stripped)
    for name in sorted(names):
        print("CELL7 PRINC", name)


if __name__ == "__main__":
    import sys

    mode = sys.argv[1]
    {"1": cell1, "2": cell2, "3": cell3, "4": cell4, "6": cell6, "7": cell7}[mode]()
