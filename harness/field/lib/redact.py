#!/usr/bin/env python3
"""redact.py: the field records' filter, stdin -> stdout, line by line.

The secret values (secret_values(), which scan-secrets.py uses too) are read at run time and never printed:
- every file under $KERBER_LAB_HOME/secrets (default ~/kerber-lab/secrets), in every subdirectory:
  - a keytab: each key of 16 bytes or more (replaced here in its hex forms);
  - a PEM private key: each base64 body line of 40 characters or more;
  - a *.env file: each assignment's value;
  - any other file: its content, stripped, and each line of a multi-line one;
  - public material is not a secret and is skipped: PEM certificates, *.crt, *.srl, *.cnf;
- every value of $FIELD_ADLAB_ENV (default ~/adlab/env) but AD_KRBADMIN_USER, an account name the AD records
  name on purpose.
A value shorter than 6 characters is not used.

By pattern, so a value that never touched the host is caught too: KRB5_TRACE key prefixes (enctype/XXXX),
"encrypted <hex>", the PA-ENC-TIMESTAMP and SPAKE trace values, OIDC codes and Keycloak session ids,
SPNEGO and Bearer tokens, JSON token fields, JWTs, LLDAP-style secret assignments, cookies and PEM private-key
blocks. ANSI colour codes and carriage returns are stripped.
"""
import os
import re
import struct
import sys

LAB_HOME = os.environ.get("KERBER_LAB_HOME") or os.path.expanduser("~/kerber-lab")
SECRETS = os.path.join(LAB_HOME, "secrets")
ADLAB_ENV = os.environ.get("FIELD_ADLAB_ENV") or os.path.expanduser("~/adlab/env")
MIN_LEN = 6
PUBLIC_SUFFIXES = (".crt", ".srl", ".cnf")


def keytab_keys(data):
    """(label, key bytes) for each entry of an MIT keytab (format 0x0502)."""
    if data[:2] != b"\x05\x02":
        return
    i, n = 2, 0
    while i + 4 <= len(data):
        (size,) = struct.unpack(">i", data[i:i + 4])
        i += 4
        if size <= 0:
            i += -size
            continue
        ent, i = data[i:i + size], i + size
        j = 0
        (ncomp,) = struct.unpack(">H", ent[j:j + 2])
        j += 2
        (rlen,) = struct.unpack(">H", ent[j:j + 2])
        j += 2 + rlen
        for _ in range(ncomp):
            (clen,) = struct.unpack(">H", ent[j:j + 2])
            j += 2 + clen
        j += 4 + 4 + 1  # name type, timestamp, 8-bit kvno
        (etype,) = struct.unpack(">H", ent[j:j + 2])
        j += 2
        (klen,) = struct.unpack(">H", ent[j:j + 2])
        j += 2
        n += 1
        yield "entry%d/etype%d" % (n, etype), ent[j:j + klen]


def _env_values(text, label):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out.append((key, value, "%s:%s" % (label, key)))
    return out


def secret_values():
    """[(label, value bytes, kind)]: kind "text" (a string value) or "key" (raw key bytes)."""
    out = []
    for root, dirs, files in os.walk(SECRETS):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            label = os.path.relpath(path, SECRETS)
            try:
                data = open(path, "rb").read()
            except OSError:
                continue
            if name.endswith(PUBLIC_SUFFIXES):
                continue
            if data[:2] == b"\x05\x02":
                try:
                    for entry, key in keytab_keys(data):
                        if len(key) >= 16:
                            out.append(("keytab:%s:%s" % (label, entry), key, "key"))
                except (struct.error, IndexError):
                    out.append((label, data, "key"))
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                out.append((label, data, "key"))
                continue
            if "-----BEGIN CERTIFICATE-----" in text and "PRIVATE KEY-----" not in text:
                continue
            if "PRIVATE KEY-----" in text:
                body = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("-----")]
                for n, ln in enumerate(body, 1):
                    if len(ln) >= 40:
                        out.append(("pem:%s:line%d" % (label, n), ln.encode(), "text"))
                continue
            if name.endswith(".env"):
                for _key, value, vlabel in _env_values(text, label):
                    if len(value) >= MIN_LEN:
                        out.append((vlabel, value.encode(), "text"))
                continue
            value = text.strip()
            if len(value) >= MIN_LEN:
                out.append((label, value.encode(), "text"))
            lines = [ln.strip() for ln in value.splitlines()]
            if len(lines) > 1:
                for n, ln in enumerate(lines, 1):
                    if len(ln) >= MIN_LEN:
                        out.append(("%s:line%d" % (label, n), ln.encode(), "text"))
    try:
        text = open(ADLAB_ENV, encoding="utf-8").read()
    except OSError:
        text = ""
    for key, value, _vlabel in _env_values(text, "adlab"):
        if key != "AD_KRBADMIN_USER" and len(value) >= MIN_LEN:
            out.append(("adlab:" + key, value.encode(), "text"))
    return out


def text_forms(value, kind):
    """The strings that stand for a value in a text record."""
    if kind == "key":
        return [value.hex(), value.hex().upper()]
    return [value.decode("utf-8", "replace")]


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
PATTERNS = [
    (re.compile(r"((?:aes(?:128|256)-(?:cts|sha\d+)|rc4-hmac|camellia\d+-cts|des3-cbc-sha1|des-cbc-\w+)/)"
                r"[0-9A-F]{4}\b"), r"\1<redacted>"),
    (re.compile(r"(Encrypted timestamp \(for [0-9.]+\)): .*"), r"\1: <redacted: PA-ENC-TIMESTAMP>"),
    (re.compile(r"(SPAKE (?:algorithm result|result|final)[^:\n]*): .*", re.I), r"\1: <redacted>"),
    (re.compile(r"(encrypted )[0-9A-Fa-f]{16,}"), r"\1<redacted>"),
    (re.compile(r"([?&#]code=)[A-Za-z0-9._-]+"), r"\1<REDACTED:oidc-code>"),
    (re.compile(r"([?&#]session_state=)[A-Za-z0-9._-]+"), r"\1<REDACTED:keycloak-session>"),
    (re.compile(r"((?:Authorization|WWW-Authenticate):\s*(?:Negotiate|Bearer))\s+[A-Za-z0-9+/=._-]{16,}", re.I),
     r"\1 <REDACTED:token>"),
    (re.compile(r"(Negotiate) [A-Za-z0-9+/=]{16,}"), r"\1 <REDACTED:spnego-token>"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "<REDACTED:jwt>"),
    (re.compile(r"(refresh_token=)[^;\s\"]+"), r"\1<REDACTED:refresh-token>"),
    (re.compile(r"(\"(?:token|refreshToken|refresh_token|access_token|id_token)\"\s*:\s*\")[^\"]+"),
     r"\1<REDACTED:token>"),
    (re.compile(r"((?:LLDAP_JWT_SECRET|LLDAP_KEY_SEED|LLDAP_LDAP_USER_PASS|LLDAP_USER_PASSWORD|"
                r"ADMIN_PW|SYNC_PW|DIRSYNC_PW|ALICE_PW|BOB_PW|NEW_PW|OLD_PW|PW)=)[^\s\"',\]]+"),
     r"\1<REDACTED:env>"),
    (re.compile(r"^([<>]? ?(?:Set-)?Cookie: *[^=\n]+=)[^;\s]*", re.I), r"\1<REDACTED:cookie>"),
]


def main():
    pairs = []
    for label, value, kind in secret_values():
        for form in text_forms(value, kind):
            pairs.append((form, "<REDACTED:%s>" % label))
    pairs.sort(key=lambda p: -len(p[0]))
    in_pem = False
    out = sys.stdout
    for raw in sys.stdin.buffer:
        line = raw.decode("utf-8", errors="replace")
        line = ANSI.sub("", line).replace("\r\n", "\n").replace("\r", "")
        for form, tag in pairs:
            if form in line:
                line = line.replace(form, tag)
        if in_pem:
            if PEM_END.search(line):
                in_pem = False
            continue
        if PEM_BEGIN.search(line):
            out.write("<REDACTED:private-key>\n")
            in_pem = not PEM_END.search(line)
            continue
        for rx, repl in PATTERNS:
            line = rx.sub(repl, line)
        out.write(line)
    out.flush()


if __name__ == "__main__":
    main()
