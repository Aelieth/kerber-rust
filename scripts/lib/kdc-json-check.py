"""kdc-json-check.py KIND:FIELD=VALUE...: a KDC log that carries the JSON stream (json = STDOUT), on stdin.

Each kdc.issue event must carry a correlation_id (docs/logging.md), and for each argument there must be an ISSUE
tuple of that kind (AS_REQ or TGS_REQ) whose field has that value. Fields are read under tracing's "fields" or at
the top. Prints one line per check; exit 1 on a miss, 2 on a usage error.
"""
import json
import sys


def field(ev, key):
    return (ev.get("fields") or {}).get(key, ev.get(key))


def main(argv):
    wants = []
    for a in argv:
        kind, _, kv = a.partition(":")
        key, _, value = kv.partition("=")
        if not (kind and key and value):
            print(f"usage: kdc-json-check.py KIND:FIELD=VALUE... (got {a!r})", file=sys.stderr)
            return 2
        wants.append((kind, key, value))
    issues = []
    for line in sys.stdin:
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict) and field(ev, "event") == "kdc.issue":
            issues.append(ev)
    bare = [e for e in issues if not field(e, "correlation_id") or field(e, "correlation_id") == "none"]
    ok = bool(issues) and not bare
    print(f"kdc.issue: {len(issues)} events, {len(bare)} without a correlation_id")
    for kind, key, value in wants:
        hit = [e for e in issues
               if field(e, "kind") == kind and field(e, "status") == "ISSUE" and field(e, key) == value]
        print(f"{kind} ISSUE {key}={value}: {len(hit)}")
        ok = ok and bool(hit)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
