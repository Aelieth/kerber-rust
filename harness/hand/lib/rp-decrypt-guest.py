#!/usr/bin/env python3
"""kinit one principal from a password file. Prints rc and a redacted error line."""
import os
import pathlib
import pty
import select
import sys
import time

principal = sys.argv[1]
pw = pathlib.Path(sys.argv[2]).read_text().strip()
pid, fd = pty.fork()
if pid == 0:
    os.execvp("/usr/bin/kinit", ["kinit", principal])
allb = b""
sent = False
t0 = time.time()
rc = None
while time.time() - t0 < 12 and rc is None:
    ready, _, _ = select.select([fd], [], [], 0.3)
    if ready:
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            chunk = b""
        if not chunk:
            try:
                done, st = os.waitpid(pid, os.WNOHANG)
                if not done:
                    done, st = os.waitpid(pid, 0)
                rc = os.waitstatus_to_exitcode(st)
            except ChildProcessError:
                rc = 0
            break
        allb += chunk
        if (not sent) and b"password" in allb.lower():
            os.write(fd, (pw + "\n").encode())
            sent = True
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        rc = os.waitstatus_to_exitcode(st)
if rc is None:
    try:
        os.kill(pid, 15)
    except OSError:
        pass
    os.waitpid(pid, 0)
    rc = 124
text = allb.decode("utf-8", "replace").replace(pw, "[REDACTED]")
err = ""
for ln in text.splitlines():
    if ln.startswith("kinit:"):
        err = ln[:180]
        break
print(f"KINIT {principal} rc={rc} sent={int(sent)} err={err}")
