#!/usr/bin/env python3
"""WR cell helpers. Prints rc and redacted lines. Never prints a password or a key."""
import os
import pathlib
import pty
import select
import sys
import time


def redact(text: str) -> str:
    out = text
    root = pathlib.Path("/var/tmp/wr")
    if root.is_dir():
        for p in root.iterdir():
            if not p.is_file() or p.name.endswith(".cc"):
                continue
            try:
                secret = p.read_text(errors="replace").strip()
            except OSError:
                continue
            if secret and secret in out:
                out = out.replace(secret, "[REDACTED]")
    kept = []
    for line in out.splitlines():
        low = line.lower()
        if low.startswith("key:") or "session key" in low:
            continue
        kept.append(line[:200])
    return "\n".join(kept)


def run_pty(argv, replies, limit=25):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    sent = 0
    buf = b""
    allb = b""
    rc = None
    t0 = time.time()
    while time.time() - t0 < limit and rc is None:
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
            buf += chunk
            low = buf.lower()
            if sent < len(replies) and (b"password" in low or b"enter it" in low or b"again" in low):
                os.write(fd, (replies[sent] + "\n").encode())
                sent += 1
                buf = b""
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            rc = os.waitstatus_to_exitcode(st)
            break
    if rc is None:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        rc = 124
    return rc, allb.decode("utf-8", "replace"), sent


def pw(path):
    return pathlib.Path(path).read_text().strip()


def first_err(text, rc):
    if rc == 0:
        return ""
    for line in redact(text).splitlines():
        s = line.strip()
        if not s or s.endswith(":") or "authenticating as principal" in s.lower():
            continue
        return s
    return ""


def kinit_one(principal, pwfile, cc):
    env_cc = cc
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["KRB5CCNAME"] = env_cc
        os.execvp("/usr/bin/kinit", ["kinit", principal])
    secret = pw(pwfile)
    sent = False
    allb = b""
    rc = None
    t0 = time.time()
    while time.time() - t0 < 15 and rc is None:
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
            if not sent and b"password" in allb.lower():
                os.write(fd, (secret + "\n").encode())
                sent = True
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            rc = os.waitstatus_to_exitcode(st)
            break
    if rc is None:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
        os.waitpid(pid, 0)
        rc = 124
    text = allb.decode("utf-8", "replace")
    print(f"KINIT {principal} rc={rc} err={first_err(text, rc)}")


def main():
    op = sys.argv[1]
    if op == "kinit":
        kinit_one(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    if op == "add":
        name, pwfile = sys.argv[2], sys.argv[3]
        secret = pw(pwfile)
        rc, text, sent = run_pty(
            ["sudo", "-n", "/usr/sbin/kadmin.local", "-q", f"addprinc {name}"],
            [secret, secret],
        )
        print(f"ADD {name} rc={rc} sent={sent} err={first_err(text, rc)}")
        return
    if op == "addrand":
        name = sys.argv[2]
        rc, text, sent = run_pty(
            ["sudo", "-n", "/usr/sbin/kadmin.local", "-q", f"addprinc -randkey {name}"],
            [],
        )
        print(f"ADDRAND {name} rc={rc} err={first_err(text, rc)}")
        return
    if op == "delete":
        name = sys.argv[2]
        rc, text, sent = run_pty(
            ["sudo", "-n", "/usr/sbin/kadmin.local", "-q", f"delprinc -force {name}"],
            [],
        )
        print(f"DEL {name} rc={rc} err={first_err(text, rc)}")
        return
    if op == "cpw":
        name, pwfile = sys.argv[2], sys.argv[3]
        secret = pw(pwfile)
        rc, text, sent = run_pty(
            ["sudo", "-n", "/usr/sbin/kadmin.local", "-q", f"cpw {name}"],
            [secret, secret],
        )
        print(f"CPW {name} rc={rc} sent={sent} err={first_err(text, rc)}")
        return
    if op == "life":
        name, life = sys.argv[2], sys.argv[3]
        rc, text, sent = run_pty(
            ["sudo", "-n", "/usr/sbin/kadmin.local", "-q", f"modprinc -maxlife {life} {name}"],
            [],
        )
        print(f"LIFE {name} rc={rc} err={first_err(text, rc)}")
        return
    if op == "getlife":
        name = sys.argv[2]
        rc, text, sent = run_pty(
            ["sudo", "-n", "/usr/sbin/kadmin.local", "-q", f"getprinc {name}"],
            [],
        )
        shown = ""
        for line in redact(text).splitlines():
            if line.startswith("Maximum ticket life:"):
                shown = line.strip()
        print(f"GETLIFE {name} rc={rc} {shown}")
        return
    if op == "remote":
        # remote cpw|add name pwfile adminpw
        kind, name, pwfile, adminpw = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
        secret = pw(pwfile)
        admin = pw(adminpw)
        query = f"cpw {name}" if kind == "cpw" else f"addprinc {name}"
        replies = [admin, secret, secret]
        rc, text, sent = run_pty(
            ["/usr/bin/kadmin", "-p", "admin/admin", "-q", query],
            replies,
            limit=30,
        )
        print(f"REMOTE {kind} {name} rc={rc} sent={sent} err={first_err(text, rc)}")
        return
    if op == "kpasswd":
        name, oldf, newf = sys.argv[2], sys.argv[3], sys.argv[4]
        old, new = pw(oldf), pw(newf)
        rc, text, sent = run_pty(["/usr/bin/kpasswd", name], [old, new, new], limit=25)
        print(f"KPASSWD {name} rc={rc} sent={sent} err={first_err(text, rc)}")
        return
    sys.exit(f"bad op {op}")


if __name__ == "__main__":
    main()
