#!/usr/bin/env python3
"""BA cells from client2. No key material."""
import os
import subprocess
import sys
from pathlib import Path

REALM = "EMBED.KERBER.TEST"
PRINCS = (
    "K/M",
    f"krbtgt/{REALM}",
    "kadmin/admin",
    "kadmin/changepw",
    "admin/admin",
)


def keep(line: str) -> bool:
    low = line.lower()
    if line.startswith("Key:") or "session key" in low or "authenticator" in low:
        return False
    return True


def fields(blob: str) -> list[str]:
    out = []
    vnos = []
    for line in blob.splitlines():
        if not keep(line):
            if line.startswith("Key:") and "vno" in line:
                parts = line.split()
                etype = ""
                vno = ""
                if "vno" in parts:
                    i = parts.index("vno")
                    vno = parts[i + 1].rstrip(",")
                if "," in line:
                    etype = line.split(",", 1)[1].strip()
                if vno:
                    vnos.append(f"kvno {vno} {etype}")
            continue
        stripped = line.strip()
        if stripped.startswith(
            (
                "Principal:",
                "Attributes:",
                "Policy:",
                "Maximum ticket life:",
                "Maximum renewable life:",
                "Number of keys:",
                "MKey:",
            )
        ):
            out.append(stripped[:180])
    if vnos:
        out.append("keys " + " | ".join(vnos)[:180])
    return out


def kadmin(kt: str, query: str) -> tuple[int, str]:
    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(Path.home() / "field" / "embed.conf")
    try:
        got = subprocess.run(
            ["kadmin", "-k", "-t", kt, "-p", f"admin/admin@{REALM}", "-r", REALM, "-q", query],
            env=env,
            capture_output=True,
            timeout=40,
        )
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return got.returncode, (got.stdout + got.stderr).decode("utf-8", "replace")


def main() -> None:
    mode = sys.argv[1]
    kt = sys.argv[2]
    if mode == "getprinc":
        for name in PRINCS:
            rc, blob = kadmin(kt, f"getprinc {name}")
            print(f"getprinc_rc {name} {rc}")
            for line in fields(blob):
                print(f"getprinc {name} {line}")
            if not fields(blob):
                print(f"getprinc {name} none")
    elif mode == "addprinc":
        rc, blob = kadmin(kt, "addprinc -randkey host/x")
        print(f"addprinc_rc {rc}")
        for line in blob.splitlines():
            if keep(line) and ("created" in line or line.strip().startswith("kadmin:") or "Principal" in line):
                print("addprinc_line", line.strip()[:200])
    elif mode == "kinit":
        env = os.environ.copy()
        env["KRB5_CONFIG"] = str(Path.home() / "field" / "embed.conf")
        env["KRB5CCNAME"] = str(Path.home() / "field" / "embed.cc")
        trace = Path.home() / "field" / "trace"
        trace.unlink(missing_ok=True)
        env["KRB5_TRACE"] = str(trace)
        try:
            got = subprocess.run(
                ["kinit", "-k", "-t", kt, f"admin/admin@{REALM}"],
                env=env,
                capture_output=True,
                timeout=30,
            )
            rc = got.returncode
        except subprocess.TimeoutExpired:
            rc = 124
        print(f"kinit_rc {rc}")
        hits = []
        if trace.exists():
            for line in trace.read_text(errors="replace").splitlines():
                low = line.lower()
                if "key" in low or "authenticator" in low:
                    continue
                if "PA-ENC-TIMESTAMP" in line or "enc-timestamp" in low or "preauth" in low:
                    hits.append(line.strip()[:160])
            trace.unlink(missing_ok=True)
        print("trace", " || ".join(hits[:4]) if hits else "none")
    else:
        print("unknown", mode)
        sys.exit(1)


if __name__ == "__main__":
    main()
