#!/usr/bin/env python3
"""AZ-1 cells 5, 6, and acl-restriction. Never print a password or a Key line."""
import subprocess
import sys
from pathlib import Path

ACL = Path("/var/kerberos/krb5kdc/kadm5.acl")
BAK = Path("/var/kerberos/krb5kdc/kadm5.acl.az-bak")


def scrub(text: str, pw: bytes) -> str:
    secret = pw.decode("utf-8", "replace")
    kept = []
    for line in text.splitlines():
        if secret and secret in line:
            continue
        if line.startswith("Key:") or "session key" in line.lower():
            continue
        kept.append(line.strip())
    return kept[-1][:200] if kept else "none"


def run(argv, pw=b"", input_extra=b""):
    data = b""
    if pw:
        data += pw + b"\n"
    data += input_extra
    return subprocess.run(argv, input=data or None, capture_output=True)


def local(*args, pw=b"", extra=b""):
    return run(["kadmin.local", "-q", " ".join(args)], pw, extra)


def setup() -> None:
    pw = sys.stdin.buffer.read().strip()
    for name in ("newp", "ua", "victim", "helper"):
        local("delprinc", "-force", name)
    made = local("addprinc", "helper", pw=pw, extra=pw + b"\n")
    victim = local("addprinc", "-randkey", "victim")
    alias = local("add_alias", "ua", "victim")
    text = (made.stdout + made.stderr + victim.stdout + alias.stdout + alias.stderr).decode(
        "utf-8", "replace"
    )
    print("setup_helper", "created" if "created" in text else "missing")
    print("setup_alias", "aliased" if "aliased" in text else scrub(text, pw))
    if not BAK.exists():
        BAK.write_bytes(ACL.read_bytes())
    extra = (
        "helper c ua\n"
        "helper@KERBER.TEST a * -maxlife 1h +requires_preauth\n"
    )
    ACL.write_bytes(BAK.read_bytes() + extra.encode())
    restarted = subprocess.run(["systemctl", "restart", "kadmin"], capture_output=True)
    print(f"kadmin_restart_rc {restarted.returncode}")


def cell5() -> None:
    pw = sys.stdin.buffer.read().strip()
    new = pw + b"-az"
    ran = run(
        ["/usr/bin/kadmin", "-p", "helper@KERBER.TEST", "-q", "cpw ua"],
        pw,
        new + b"\n" + new + b"\n",
    )
    blob = (ran.stdout + ran.stderr).decode("utf-8", "replace")
    print(f"cpw_rc {ran.returncode}")
    print("cpw_changed", "yes" if "changed" in blob else "no")
    print("cpw_line", scrub(blob, pw))


def cell6() -> None:
    listed = subprocess.run(["kadmin.local", "-q", "listprincs"], capture_output=True)
    names = [
        ln.strip()
        for ln in listed.stdout.decode("utf-8", "replace").splitlines()
        if ln.startswith("krbtgt/")
    ]
    print("krbtgt_count", len(names))
    for name in names:
        print("krbtgt", name)
    others = [n for n in names if n != "krbtgt/KERBER.TEST@KERBER.TEST"]
    if not others:
        print("cell6 skipped: no cross-realm krbtgt on this kdc")
        return
    print("cell6 skipped: a krbtgt is present and the other realm's KDC is not on this VM")


def restrict() -> None:
    pw = sys.stdin.buffer.read().strip()
    ran = run(
        ["/usr/bin/kadmin", "-p", "helper@KERBER.TEST", "-q", "addprinc -maxlife 10h newp"],
        pw,
        pw + b"\n" + pw + b"\n",
    )
    blob = (ran.stdout + ran.stderr).decode("utf-8", "replace")
    print("add_changed", "yes" if "created" in blob else "no")
    print("add_line", scrub(blob, pw))
    # getprinc is cleanup() on the KDC. client2 has no kadmin.local.


def cleanup() -> None:
    got = subprocess.run(["kadmin.local", "-q", "getprinc newp"], capture_output=True)
    for line in got.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith(("Principal:", "Maximum ticket life:", "Attributes:")):
            print("getprinc", line.strip())
    for name in ("newp", "ua", "victim", "helper"):
        local("delprinc", "-force", name)
    if BAK.exists():
        ACL.write_bytes(BAK.read_bytes())
        BAK.unlink()
    subprocess.run(["systemctl", "restart", "kadmin"], capture_output=True)
    print("cleanup done")


def main() -> None:
    mode = sys.argv[1]
    if mode == "setup":
        setup()
    elif mode == "cell5":
        cell5()
    elif mode == "cell6":
        cell6()
    elif mode == "restrict":
        restrict()
    elif mode == "cleanup":
        cleanup()
    else:
        print("bad mode")
        sys.exit(2)


if __name__ == "__main__":
    main()
