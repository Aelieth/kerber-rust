#!/usr/bin/env python3
"""b2c-conf.py BASE OUT [options]: a krb5.conf variant for one cell of the B2 client modules (host side, stdlib only).

BASE is a krb5.conf (the VM's own /etc/krb5.conf, read over ssh); OUT is written; a unified diff BASE -> OUT goes to stdout (it is the record of the edit).
Options (any number, applied in this order):
  --libdefaults-first LINE        LINE as the first relation under the first [libdefaults] header (MIT: the first value of a relation wins); the section is created at the top when absent
  --libdefaults-realm-node REALM K=V[,K=V...]   a realm node under [libdefaults]: "REALM = {" K = V ... "}" right after the header (the per-realm keys MIT reads before the top level)
  --realm-first REALM LINE        LINE as the first relation inside "REALM = {" under [realms] (exit 3 when there is no such block)
  --append-text TEXT              TEXT (a stanza, "\\n" escapes allowed) after the last line
  --append-file FILE              the file's text after the last line
Nothing here reads or writes a secret.
"""
import difflib
import re
import sys


def die(code, msg):
    sys.stderr.write("b2c-conf.py: %s\n" % msg)
    sys.exit(code)


def main(argv):
    if len(argv) < 3:
        die(2, "usage: b2c-conf.py BASE OUT [options]")
    base, out = argv[1], argv[2]
    with open(base, encoding="utf-8", errors="surrogateescape") as f:
        orig = f.read()
    lines = orig.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    i = 3
    while i < len(argv):
        opt = argv[i]
        if opt == "--libdefaults-first":
            line = argv[i + 1]
            i += 2
            idx = next((n for n, l in enumerate(lines) if l.strip() == "[libdefaults]"), None)
            if idx is None:
                lines[0:0] = ["[libdefaults]", "    " + line, ""]
            else:
                lines.insert(idx + 1, "    " + line)
        elif opt == "--libdefaults-realm-node":
            realm, kvs = argv[i + 1], argv[i + 2]
            i += 3
            node = ["    %s = {" % realm]
            for kv in kvs.split(","):
                k, _, v = kv.partition("=")
                node.append("        %s = %s" % (k.strip(), v.strip()))
            node.append("    }")
            idx = next((n for n, l in enumerate(lines) if l.strip() == "[libdefaults]"), None)
            if idx is None:
                lines[0:0] = ["[libdefaults]"] + node + [""]
            else:
                lines[idx + 1:idx + 1] = node
        elif opt == "--realm-first":
            realm, line = argv[i + 1], argv[i + 2]
            i += 3
            rx = re.compile(r"^\s*" + re.escape(realm) + r"\s*=\s*\{\s*$")
            in_realms = False
            done = False
            for n, l in enumerate(lines):
                s = l.strip()
                if s.startswith("[") and s.endswith("]"):
                    in_realms = s == "[realms]"
                    continue
                if in_realms and rx.match(l):
                    lines.insert(n + 1, "        " + line)
                    done = True
                    break
            if not done:
                die(3, "no '%s = {' block under [realms] in %s" % (realm, base))
        elif opt == "--append-text":
            text = argv[i + 1].replace("\\n", "\n")
            i += 2
            lines.append("")
            lines.extend(text.rstrip("\n").split("\n"))
        elif opt == "--append-file":
            with open(argv[i + 1], encoding="utf-8", errors="surrogateescape") as f:
                text = f.read()
            i += 2
            lines.append("")
            lines.extend(text.rstrip("\n").split("\n"))
        else:
            die(2, "unknown option %s" % opt)
    new = "\n".join(lines) + "\n"
    with open(out, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(new)
    sys.stdout.writelines(difflib.unified_diff(orig.splitlines(True), new.splitlines(True), "krb5.conf (the VM's own)", "variant", n=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
