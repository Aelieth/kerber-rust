#!/usr/bin/env python3
"""The Windows guest's QEMU agent for the hand drivers.

usage: win-agent.py DOMAIN SECRETS ping | exec PATH ARG... | write GUEST_PATH < data | read GUEST_PATH

SECRETS is a file of values to scrub from every output: a name<TAB>value line, or a whole file's text.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXEC_TRIES = int(os.environ.get("WIN_EXEC_TRIES", "600"))


def agent(dom, payload):
    """One agent command, given to virsh on stdin: a file write's data never reaches an argv."""
    body = json.dumps(payload)
    if "'" in body:
        raise ValueError("a quote in an agent command")
    cmd = ["virsh", "-q", "-c", "qemu:///system"]
    if not shutil.which("virsh"):
        # distrobox-host-exec runs in the caller's cwd, which must exist on the host too.
        cmd = ["distrobox-host-exec", *cmd]
    r = subprocess.run(cmd, input="qemu-agent-command %s '%s'\n" % (dom, body), check=False, text=True,
                       capture_output=True, cwd=HERE)
    # virsh's shell exits 0 whatever happened, echoes "virsh # <command>", and may glue its next prompt
    # to the reply; an error goes to stderr only.
    reply = None
    for ln in r.stdout.splitlines():
        if "qemu-agent-command" in ln or "{" not in ln:
            continue
        try:
            reply = json.JSONDecoder().raw_decode(ln, ln.find("{"))[0]
        except ValueError:
            continue
    if reply is None:
        sys.stderr.write(r.stderr)
    return reply


def load_secrets(path):
    values = []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for line in text.splitlines():
        value = line.split("\t", 1)[1] if "\t" in line else line
        if value.strip():
            values.append(value.strip())
    return sorted(set(values), key=len, reverse=True)


def scrub(text, secrets):
    for s in secrets:
        text = text.replace(s, "***")
    return text


def guest_exec(dom, argv, secrets):
    res = agent(dom, {"execute": "guest-exec", "arguments": {"path": argv[0], "arg": argv[1:], "capture-output": True}})
    if not res:
        sys.stdout.write("EXEC_NO_AGENT\n")
        return 1
    pid = res["return"]["pid"]
    for _ in range(EXEC_TRIES):
        st = agent(dom, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if not st:
            sys.stdout.write("EXEC_NO_AGENT\n")
            return 1
        st = st["return"]
        if st.get("exited"):
            out = base64.b64decode(st.get("out-data") or b"").decode("utf-8", "replace")
            err = base64.b64decode(st.get("err-data") or b"").decode("utf-8", "replace")
            sys.stdout.write(scrub(out, secrets))
            if err.strip():
                sys.stdout.write("---ERR---\n")
                sys.stdout.write(scrub(err, secrets))
            sys.stdout.write("\nexitcode %s\n" % st.get("exitcode"))
            return 0
        time.sleep(1)
    sys.stdout.write("EXEC_TIMEOUT\n")
    return 1


def write_file(dom, path, data):
    opened = agent(dom, {"execute": "guest-file-open", "arguments": {"path": path, "mode": "w"}})
    if not opened:
        return 1
    handle = opened["return"]
    wrote = agent(dom, {"execute": "guest-file-write", "arguments": {"handle": handle, "buf-b64": base64.b64encode(data).decode()}})
    agent(dom, {"execute": "guest-file-close", "arguments": {"handle": handle}})
    return 0 if wrote and wrote["return"].get("count") == len(data) else 1


def read_file(dom, path, secrets):
    opened = agent(dom, {"execute": "guest-file-open", "arguments": {"path": path, "mode": "r"}})
    if not opened:
        return 1
    handle = opened["return"]
    chunks = []
    while True:
        part = agent(dom, {"execute": "guest-file-read", "arguments": {"handle": handle, "count": 65536}})
        if not part:
            return 1
        part = part["return"]
        if part.get("buf-b64"):
            chunks.append(base64.b64decode(part["buf-b64"]))
        if part.get("eof"):
            break
    agent(dom, {"execute": "guest-file-close", "arguments": {"handle": handle}})
    sys.stdout.write(scrub(b"".join(chunks).decode("utf-8", "replace"), secrets))
    return 0


def main():
    if len(sys.argv) < 4:
        sys.stderr.write(__doc__)
        return 2
    dom, secrets, cmd = sys.argv[1], load_secrets(sys.argv[2]), sys.argv[3]
    if cmd == "ping":
        if not agent(dom, {"execute": "guest-ping"}):
            return 1
        sys.stdout.write("AGENT_UP\n")
        return 0
    if cmd == "exec":
        return guest_exec(dom, sys.argv[4:], secrets)
    if cmd == "write":
        rc = write_file(dom, sys.argv[4], sys.stdin.buffer.read())
        if rc == 0:
            sys.stdout.write("WROTE\n")
        return rc
    if cmd == "read":
        return read_file(dom, sys.argv[4], secrets)
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
