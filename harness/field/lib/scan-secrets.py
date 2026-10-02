#!/usr/bin/env python3
"""scan-secrets.py <path>...: look for every secret value in every file under the given paths.

The values are redact.py's secret_values(). A planted control comes first: one value is written to a private
directory under $TMPDIR (never the host's /tmp; the scan refuses to run without such a TMPDIR) and must be
found there, in UTF-8 and in UTF-16-LE, before the paths are scanned; the control is removed at once.
Files are read as bytes (pcaps included): a text value is searched as is and in UTF-16-LE, a key as raw bytes
and in its hex forms. Prints names and counts, never a value.
Exit 0: the control was found and the paths hold no value. Exit 1: anything else.
"""
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True  # no __pycache__ beside the harness
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redact  # noqa: E402


def byte_forms(value, kind):
    if kind == "key":
        return [value, value.hex().encode(), value.hex().upper().encode()]
    return [value, value.decode("utf-8", "replace").encode("utf-16-le")]


def scan(paths, values):
    """(files read, [(path, label, count)])."""
    hits, nfiles = [], 0
    for top in paths:
        walk = [(os.path.dirname(top), [], [os.path.basename(top)])] if os.path.isfile(top) else os.walk(top)
        for root, _dirs, files in walk:
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path):
                    continue
                try:
                    blob = open(path, "rb").read()
                except OSError:
                    continue
                nfiles += 1
                for label, value, kind in values:
                    count = sum(blob.count(form) for form in byte_forms(value, kind))
                    if count:
                        hits.append((path, label, count))
    return nfiles, hits


def main():
    paths = sys.argv[1:]
    if not paths:
        print("usage: scan-secrets.py <path>...", file=sys.stderr)
        return 1
    values = redact.secret_values()
    texts = [v for v in values if v[2] == "text"]
    if not texts:
        print("FAIL: no secret value found under %s: the scan would prove nothing" % redact.SECRETS)
        return 1
    base = os.path.realpath(tempfile.gettempdir())
    if base == "/tmp" or base.startswith("/tmp/"):
        print("FAIL: TMPDIR is %s: set it to the run's own directory (never the host's /tmp)" % base)
        return 1
    control = tempfile.mkdtemp(prefix="scan-control.")
    try:
        label, value, _kind = texts[0]
        with open(os.path.join(control, "planted-utf8"), "wb") as f:
            f.write(b"control:" + value + b"\n")
        with open(os.path.join(control, "planted-utf16"), "wb") as f:
            f.write(("control:%s\n" % value.decode("utf-8", "replace")).encode("utf-16-le"))
        nctl, ctl = scan([control], [texts[0]])
    finally:
        shutil.rmtree(control, ignore_errors=True)
    found = {os.path.basename(p) for p, _l, _c in ctl}
    if found != {"planted-utf8", "planted-utf16"}:
        print("FAIL: the planted control (%s, in %d files) was not found in both encodings: %s"
              % (label, nctl, ", ".join(sorted(found)) or "nothing"))
        return 1
    print("control: %s planted under TMPDIR in UTF-8 and UTF-16-LE: found in both (as it must), removed" % label)
    nfiles, hits = scan(paths, values)
    for path, hlabel, count in hits:
        print("HIT %s: %s (%d)" % (path, hlabel, count))
    print("scanned %d files against %d secret values (%d text, %d keys): %d hits"
          % (nfiles, len(values), len(texts), len(values) - len(texts), sum(c for _p, _l, c in hits)))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
