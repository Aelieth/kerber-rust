#!/usr/bin/python3
"""ptydrive.py: run a command on a pseudo-terminal and answer its prompts.

Runs on client1 (stock python3 only). A login program (su, passwd, sudo) gets
a real tty, as when a person types, and the passwords never touch argv or
the record:

  * --secrets N   the first N lines of stdin are the secrets (read before the
                  child starts; never written anywhere).
  * --rule RX=I   when the pty output since the last answer matches the regex
                  RX (case-insensitive, searched at the end of that output),
                  send secret I and a newline. Rules are tried in order, so put
                  the specific prompts first. Each rule answers at most --max
                  times (default 2), so a rejected password cannot loop.
  * --send-after RX=TEXT  type plain TEXT (not a secret) when RX shows up,
                  once; for shell commands inside an interactive session.

The child's terminal output (prompts and messages; the passwords are not echoed
by a password prompt) goes to stdout. The exit status is the child's, 124 on
--timeout.
"""
import argparse
import os
import pty
import re
import select
import signal
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--secrets", type=int, default=0)
ap.add_argument("--rule", action="append", default=[])
ap.add_argument("--send-after", action="append", default=[])
ap.add_argument("--max", type=int, default=2)
ap.add_argument("--timeout", type=float, default=180.0)
ap.add_argument("cmd", nargs=argparse.REMAINDER)
a = ap.parse_args()

secrets = [sys.stdin.readline().rstrip("\n") for _ in range(a.secrets)]
rules = []
for r in a.rule:
    rx, idx = r.rsplit("=", 1)
    rules.append([re.compile(rx + r"\s*$", re.I), int(idx), 0])
sends = []
for r in a.send_after:
    rx, text = r.split("=", 1)
    sends.append([re.compile(rx, re.I), text, False])
cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
if not cmd:
    sys.exit("ptydrive: no command")

pid, fd = pty.fork()
if pid == 0:
    os.environ.setdefault("TERM", "xterm")
    os.execvp(cmd[0], cmd)

pending = b""
deadline = time.time() + a.timeout
timed_out = False
while True:
    if time.time() > deadline:
        timed_out = True
        os.kill(pid, signal.SIGTERM)
        break
    r, _, _ = select.select([fd], [], [], 0.3)
    if fd not in r:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
    pending += data
    text = pending.decode("utf-8", "replace")
    answered = False
    for rule in rules:
        if rule[2] < a.max and rule[0].search(text):
            time.sleep(0.3)
            os.write(fd, (secrets[rule[1]] + "\n").encode())
            rule[2] += 1
            pending = b""
            answered = True
            break
    if answered:
        continue
    for s in sends:
        if not s[2] and s[0].search(text):
            time.sleep(0.3)
            os.write(fd, (s[1] + "\n").encode())
            s[2] = True
            pending = b""
            break

try:
    _, status = os.waitpid(pid, 0)
except ChildProcessError:
    status = 0
if timed_out:
    sys.stdout.write("\n[ptydrive: timeout after %ss]\n" % a.timeout)
    sys.exit(124)
if os.WIFEXITED(status):
    sys.exit(os.WEXITSTATUS(status))
sys.exit(128 + os.WTERMSIG(status))
