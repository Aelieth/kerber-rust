#!/usr/bin/env python3
"""dc-ps.py <script.ps1>: run a PowerShell script on the AD DC (TEST-SERVER, 10.10.38.38) over WinRM.

http://10.10.38.38:5985/wsman, NTLM with message encryption, as ADKERBER\\<AD_KRBADMIN_USER>. The account and the
other AD secrets come from $FIELD_ADLAB_ENV (default ~/adlab/env) and are never printed: a script names one as
@@PSQ:NAME@@, filled in at send time as a PowerShell single-quoted string, and every AD_* value is redacted from
the output. A long script goes up in chunks to %TEMP%, runs with -File and is deleted.
"""
import base64
import os
import sys
import uuid

import winrm

DC = "http://10.10.38.38:5985/wsman"
ENV = os.environ.get("FIELD_ADLAB_ENV") or os.path.expanduser("~/adlab/env")


def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            env[k] = v
    return env


def redact(text, env):
    for k, v in env.items():
        if k.startswith("AD_") and k != "AD_KRBADMIN_USER" and v:
            text = text.replace(v, "<redacted:%s>" % k)
    return text


def fill(script, env):
    out = script
    for k, v in env.items():
        out = out.replace("@@PSQ:%s@@" % k, v.replace("'", "''"))
    if "@@PSQ:" in out:
        sys.exit("dc-ps.py: unknown @@PSQ:...@@ placeholder in the script")
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: dc-ps.py <script.ps1>")
    env = load_env(ENV)
    user = env["AD_KRBADMIN_USER"]
    if "\\" not in user and "@" not in user:
        user = "ADKERBER\\" + user
    script = fill(open(sys.argv[1], encoding="utf-8").read(), env)
    sess = winrm.Session(DC, auth=(user, env["AD_KRBADMIN_PASSWORD"]), transport="ntlm",
                         message_encryption="always", read_timeout_sec=600, operation_timeout_sec=590)
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    if len(enc) < 7600:
        r = sess.run_ps(script)
    else:
        name = "kerber-ad-%s.ps1" % uuid.uuid4().hex[:12]
        b64 = base64.b64encode(script.encode("utf-8")).decode()
        first = True
        for i in range(0, len(b64), 2000):
            op = "Set-Content" if first else "Add-Content"
            rr = sess.run_ps("%s -NoNewline -Path (Join-Path $env:TEMP '%s.b64') -Value '%s'" % (op, name, b64[i:i + 2000]))
            if rr.status_code != 0:
                sys.stderr.write(redact(rr.std_err.decode("utf-8", "replace"), env))
                sys.exit("dc-ps.py: upload failed")
            first = False
        r = sess.run_ps(
            "$p = Join-Path $env:TEMP '%s'; $b = Get-Content -Raw ($p + '.b64'); "
            "[IO.File]::WriteAllText($p, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)), "
            "(New-Object Text.UTF8Encoding $true)); Remove-Item ($p + '.b64'); "
            "try { & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $p 2>&1 | Out-String -Width 400 } "
            "finally { Remove-Item $p -ErrorAction SilentlyContinue }" % name)
    out = r.std_out.decode("utf-8", "replace")
    err = r.std_err.decode("utf-8", "replace")
    sys.stdout.write(redact(out, env))
    # pywinrm returns PowerShell's CLIXML stream on stderr; progress records alone are noise.
    if err.strip() and not (err.lstrip().startswith("#< CLIXML") and 'S="Error"' not in err):
        sys.stdout.write("\n[stderr]\n" + redact(err, env) + "\n")
    sys.exit(r.status_code)


if __name__ == "__main__":
    main()
