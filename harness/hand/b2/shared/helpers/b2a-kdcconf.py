#!/usr/bin/python3 -I
"""b2a-kdcconf.py: kdc.conf := the kept pristine kdc.conf (b2ctl.sh snapshot-conf keeps it as $VMCTL_D/kdc.conf.pristine) with the edits given, written IN PLACE (the same inode, so the
SELinux label and the mode stay). With no edit the file is the pristine one, byte for byte.
  b2a-kdcconf.py [EDIT ...]       EDIT: realm KEY VALUE | realm-del KEY | defaults KEY VALUE | defaults-del KEY | append   (append reads the stanza on stdin)
  realm: the KERBER.TEST block of [realms] (B2A_REALM); a KEY line is replaced, else inserted before the block's closing brace. defaults: the [kdcdefaults] section.
"""
import os
import re
import sys

D = os.environ.get("VMCTL_D", "/var/tmp/otp3")
KDCDIR = os.environ.get("VMCTL_KDCDIR", "/var/kerberos/krb5kdc")
REALM = os.environ.get("B2A_REALM", "KERBER.TEST")
PRISTINE = os.path.join(D, "kdc.conf.pristine")
CONF = os.environ.get("VMCTL_KDCCONF", os.path.join(KDCDIR, "kdc.conf"))


def die(msg):
    print("b2a-kdcconf.py: " + msg, file=sys.stderr)
    sys.exit(2)


def find_section(lines, name):
    """(start, end) line indices of the body of [name]: after its header, up to the next header."""
    start = None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*\[" + re.escape(name) + r"\]\s*$", ln):
            start = i + 1
        elif start is not None and re.match(r"^\s*\[", ln):
            return start, i
    if start is None:
        die("no [%s] section in %s" % (name, PRISTINE))
    return start, len(lines)


def find_realm(lines):
    s, e = find_section(lines, "realms")
    for i in range(s, e):
        if re.match(r"^\s*" + re.escape(REALM) + r"\s*=\s*\{\s*$", lines[i]):
            depth = 0
            for j in range(i, e):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth == 0:
                    return i + 1, j
            die("the %s block is not closed" % REALM)
    die("no %s block in [realms]" % REALM)


def relation_indent(lines, s, e):
    for i in range(s, e):
        m = re.match(r"^(\s+)\S+\s*=", lines[i])
        if m:
            return m.group(1)
    return "    "


def set_rel(lines, s, e, key, value):
    """Replace the first KEY line in [s, e), else insert one before e; returns the new end."""
    for i in range(s, e):
        if re.match(r"^\s*" + re.escape(key) + r"\s*=", lines[i]):
            ind = re.match(r"^(\s*)", lines[i]).group(1)
            lines[i] = "%s%s = %s\n" % (ind, key, value)
            return e
    lines.insert(e, "%s%s = %s\n" % (relation_indent(lines, s, e), key, value))
    return e + 1


def del_rel(lines, s, e, key):
    out_e = e
    i = s
    while i < out_e:
        if re.match(r"^\s*" + re.escape(key) + r"\s*=", lines[i]):
            del lines[i]
            out_e -= 1
        else:
            i += 1
    return out_e


def main(argv):
    with open(PRISTINE, "r") as f:
        lines = f.readlines()
    i = 0
    while i < len(argv):
        op = argv[i]
        if op == "realm" and i + 2 < len(argv):
            s, e = find_realm(lines)
            set_rel(lines, s, e, argv[i + 1], argv[i + 2])
            i += 3
        elif op == "realm-del" and i + 1 < len(argv):
            s, e = find_realm(lines)
            del_rel(lines, s, e, argv[i + 1])
            i += 2
        elif op == "defaults" and i + 2 < len(argv):
            s, e = find_section(lines, "kdcdefaults")
            set_rel(lines, s, e, argv[i + 1], argv[i + 2])
            i += 3
        elif op == "defaults-del" and i + 1 < len(argv):
            s, e = find_section(lines, "kdcdefaults")
            del_rel(lines, s, e, argv[i + 1])
            i += 2
        elif op == "append":
            text = sys.stdin.read()
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append("\n" + text if not text.startswith("\n") else text)
            if not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            i += 1
        else:
            die("bad edit near '%s'" % op)
    with open(CONF, "r+") as f:           # in place: the same inode, the label and the mode stay
        f.seek(0)
        f.write("".join(lines))
        f.truncate()
    print("kdc.conf := pristine%s (%d lines)" % (" + " + " ".join(argv) if argv else "", len(lines)))


main(sys.argv[1:])
