#!/usr/bin/env python3
"""AZ-2 client probes. The password stays on stdin and out of the log."""
import subprocess
import sys


def interesting(blob: str, secrets: list[str]) -> str:
    kept = []
    for line in blob.splitlines():
        if any(secret and secret in line for secret in secrets):
            continue
        low = line.lower()
        if line.startswith("Key:") or "session key" in low or "authenticator" in low:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if (
            stripped.startswith("Principal:")
            or "privilege" in stripped
            or "AUTH_" in stripped
            or "changed" in stripped
            or "created" in stripped
            or "modified" in stripped
            or stripped.startswith("kadmin:")
        ):
            kept.append(stripped[:200])
    return " || ".join(kept[-4:]) if kept else "none"


def kadmin(principal: str, query: str, pw: bytes, extra: bytes = b"") -> None:
    try:
        got = subprocess.run(
            ["/usr/bin/kadmin", "-p", principal, "-q", query],
            input=pw + b"\n" + extra,
            capture_output=True,
            timeout=40,
        )
        blob = (got.stdout + got.stderr).decode("utf-8", "replace")
        rc = got.returncode
    except subprocess.TimeoutExpired:
        blob, rc = "timeout", 124
    secrets = [pw.decode("utf-8", "replace")]
    if extra:
        secrets.append(extra.decode("utf-8", "replace").strip())
    label = query.split()[0]
    print(f"{label}_rc {rc}")
    print(f"{label}_line", interesting(blob, secrets))


def main() -> None:
    pw = sys.stdin.buffer.read().strip()
    new = pw + b"Z"
    mode = sys.argv[1]
    if mode == "cell1":
        kadmin("helper@KERBER.TEST", "addprinc x", pw, new + b"\n" + new + b"\n")
        kadmin("helper@KERBER.TEST", "cpw helper", pw, new + b"\n" + new + b"\n")
    elif mode == "cell2":
        kadmin("nobody@KERBER.TEST", "getprinc guest-a", pw)
        kadmin("nobody@KERBER.TEST", "getprinc other", pw)
    elif mode == "cell3":
        kadmin("admin/admin@KERBER.TEST", "modprinc -maxlife 1h deny-x", pw)
    elif mode == "cell4":
        kadmin("admin/admin@KERBER.TEST", "getprinc anyone", pw)
    else:
        print("unknown", mode)
        sys.exit(1)


if __name__ == "__main__":
    main()
