#!/usr/bin/env python3
"""argv: trickle | getprinc | kpasswd. Prints rc and elapsed only. No secrets."""
import os
import pathlib
import select
import subprocess
import sys
import time

mode = sys.argv[1]
limit = 55.0


def run_pty(argv, replies):
    import pty
    t0 = time.monotonic()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    sent = 0
    buf = b""
    rc = None
    while True:
        if time.monotonic() - t0 > limit:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
            rc = 124
            break
        ready, _, _ = select.select([fd], [], [], 0.3)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                chunk = b""
            if not chunk:
                break
            buf += chunk
            low = buf.lower()
            want = False
            if sent == 0 and (b"password for" in low or low.rstrip().endswith(b"password:")):
                want = True
            elif sent == 1 and b"new password" in low:
                want = True
            elif sent >= 2 and (b"again" in low or b"re-enter" in low or b"retype" in low):
                want = True
            if want and sent < len(replies):
                os.write(fd, (replies[sent] + "\n").encode())
                sent += 1
                buf = b""
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            rc = os.waitstatus_to_exitcode(status)
            break
    if rc is None:
        try:
            done, status = os.waitpid(pid, 0)
            rc = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            rc = 124
    return rc, time.monotonic() - t0


if mode == "getprinc":
    pw = pathlib.Path("/var/tmp/al3/admin.pw").read_text().strip()
    rc, elapsed = run_pty(
        ["/usr/bin/kadmin", "-p", "admin/admin@KERBER.TEST", "-q", "getprinc bob"],
        [pw],
    )
    print(f"GETPRINC rc={rc} elapsed={elapsed:.1f}", flush=True)
elif mode == "kpasswd":
    pw = pathlib.Path("/var/tmp/al3/bob.pw").read_text().strip()
    newp = pathlib.Path("/var/tmp/al3/bob-new.pw")
    new = newp.read_text().strip() if newp.exists() else pw
    rc, elapsed = run_pty(["/usr/bin/kpasswd", "bob"], [pw, new, new])
    print(f"KPASSWD rc={rc} elapsed={elapsed:.1f}", flush=True)
elif mode == "restore":
    cur = pathlib.Path("/var/tmp/al3/bob-new.pw").read_text().strip()
    old = pathlib.Path("/var/tmp/al3/bob.pw").read_text().strip()
    rc, elapsed = run_pty(["/usr/bin/kpasswd", "bob"], [cur, old, old])
    print(f"RESTORE rc={rc} elapsed={elapsed:.1f}", flush=True)
elif mode == "trickle":
    subprocess.run(["/usr/bin/python3", "/var/tmp/al3/trickle.py", "749", "60"], check=False)
else:
    sys.exit(2)
