#!/usr/bin/env python3
"""AZ-2 kdc setup. No passwords, no Key lines."""
import subprocess
import sys
from pathlib import Path

CONF = Path("/var/kerberos/krb5kdc/kdc.conf")
BAK = Path("/var/kerberos/krb5kdc/kdc.conf.az2-bak")
ACL = Path("/var/kerberos/krb5kdc/kadm5.acl")
ACL_BAK = Path("/var/kerberos/krb5kdc/kadm5.acl.az2-bak")
KADMIN = "/usr/sbin/kadmin.local"


def scrub(text: str, pw: bytes) -> str:
    secret = pw.decode("utf-8", "replace")
    kept = []
    for line in text.splitlines():
        if secret and secret in line:
            continue
        low = line.lower()
        if line.startswith("Key:") or "session key" in low or "authenticator" in low:
            continue
        stripped = line.strip()
        if stripped:
            kept.append(stripped)
    return kept[-1][:200] if kept else "none"


def local(query: str, data: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run([KADMIN, "-q", query], input=data or None, capture_output=True, timeout=40)


def remove_kadm5(text: str) -> str:
    key = "kadm5_auth"
    out = []
    i = 0
    while True:
        j = text.find(key, i)
        if j < 0:
            out.append(text[i:])
            break
        line_start = text.rfind("\n", 0, j) + 1
        if text[line_start:j].strip():
            out.append(text[i : j + len(key)])
            i = j + len(key)
            continue
        brace = text.find("{", j)
        if brace < 0:
            out.append(text[i:])
            break
        depth = 0
        k = brace
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    k += 1
                    break
            k += 1
        out.append(text[i:line_start])
        i = k
    return "".join(out)


def apply_plugins(mode: str) -> None:
    if not BAK.exists():
        BAK.write_text(CONF.read_text())
    original = BAK.read_text()
    if mode == "default":
        CONF.write_text(original)
        print("plugins default")
        return
    blocks = {
        "self": "    kadm5_auth = {\n        enable_only = self\n    }\n",
        "nobounce": "    kadm5_auth = {\n        disable = bouncer\n    }\n",
        "bouncer-self": (
            "    kadm5_auth = {\n        enable_only = bouncer\n        enable_only = self\n    }\n"
        ),
    }
    body = remove_kadm5(original).rstrip() + "\n"
    if "\n[plugins]\n" in body or body.startswith("[plugins]\n"):
        body = body.replace("[plugins]\n", "[plugins]\n" + blocks[mode], 1)
    else:
        body += "\n[plugins]\n" + blocks[mode]
    CONF.write_text(body)
    print("plugins", mode)


def show_plugins() -> None:
    text = CONF.read_text()
    start = text.find("kadm5_auth")
    print("kadm5_block", "absent" if start < 0 else "present")
    if start >= 0:
        print(text[start : start + 180].replace("\n", " | "))


def files() -> None:
    if not ACL_BAK.exists():
        ACL_BAK.write_bytes(ACL.read_bytes() if ACL.exists() else b"")
    ACL.write_text("helper@KERBER.TEST a\nadmin/admin@KERBER.TEST *\n")
    apply_plugins("self")
    show_plugins()


def setup() -> None:
    pw = sys.stdin.buffer.read().strip()
    twice = pw + b"\n" + pw + b"\n"
    for name in ("helper", "nobody", "guest-a", "other", "deny-x", "anyone", "x"):
        local(f"delprinc -force {name}")
    made = local("addprinc helper", twice)
    print("helper", scrub((made.stdout + made.stderr).decode("utf-8", "replace"), pw))
    for name in ("guest-a", "other", "deny-x", "anyone", "x"):
        got = local(f"addprinc -randkey {name}")
        print(name, scrub((got.stdout + got.stderr).decode("utf-8", "replace"), pw))
    admin = local("cpw admin/admin", twice)
    blob = (admin.stdout + admin.stderr).decode("utf-8", "replace")
    if "does not exist" in blob or "Principal does not exist" in blob:
        admin = local("addprinc admin/admin", twice)
        blob = (admin.stdout + admin.stderr).decode("utf-8", "replace")
    print("admin", scrub(blob, pw))
    nobody = local("addprinc nobody", twice)
    print("nobody", scrub((nobody.stdout + nobody.stderr).decode("utf-8", "replace"), pw))
    files()
    restarted = subprocess.run(["systemctl", "restart", "kadmin"], capture_output=True)
    print(f"kadmin_restart_rc {restarted.returncode}")
    show_plugins()


def main() -> None:
    mode = sys.argv[1]
    if mode == "setup":
        setup()
    elif mode == "files":
        files()
    elif mode == "plugins":
        apply_plugins(sys.argv[2])
        if len(sys.argv) > 3 and sys.argv[3] == "restart":
            restarted = subprocess.run(["systemctl", "restart", "kadmin"], capture_output=True)
            print(f"kadmin_restart_rc {restarted.returncode}")
        show_plugins()
    elif mode == "show":
        show_plugins()
    else:
        print("unknown", mode)
        sys.exit(1)


if __name__ == "__main__":
    main()
