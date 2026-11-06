#!/usr/bin/env python3
"""journal-lines.py [--utc-offset +HHMM]: `journalctl -o json` records on stdin, each printed as MIT's FILE log line
(lib/kadm5/logger.c:661-672): `Mon DD HH:MM:SS host prog[pid](severity): message`. PRIORITY is named as
severity2string names it (:584-616, the strings at :58-66), the host is _HOSTNAME (MIT logs gethostname(), :506-512).
Debian's units log only to the journal; this gives the field harness the lines it reads from /var/log on Fedora.
A record that does not parse goes to stderr, and the exit status is then 1.
"""
import datetime
import json
import sys

SEVERITY = ["EMERGENCY", "ALERT", "CRITICAL", "Error", "Warning", "Notice", "info", "debug"]


def text(v):
    if isinstance(v, list):
        return bytes(v).decode("utf-8", "replace")
    return "" if v is None else str(v)


def zone(off):
    if len(off) != 5 or off[0] not in "+-" or not off[1:].isdigit():
        raise ValueError(off)
    mins = int(off[1:3]) * 60 + int(off[3:])
    return datetime.timezone(datetime.timedelta(minutes=mins if off[0] == "+" else -mins))


def main():
    args = sys.argv[1:]
    try:
        tz = zone(args[1]) if len(args) == 2 and args[0] == "--utc-offset" else zone("+0000")
        if args and len(args) != 2:
            raise ValueError(args)
    except ValueError:
        print("usage: journal-lines.py [--utc-offset +HHMM]", file=sys.stderr)
        return 2
    rc = 0
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            r = json.loads(raw)
            when = datetime.datetime.fromtimestamp(int(r["__REALTIME_TIMESTAMP"]) / 1e6, tz)
            pri = int(r.get("PRIORITY", 6))
            prog = text(r.get("SYSLOG_IDENTIFIER") or r.get("_COMM"))
            pid = text(r.get("SYSLOG_PID") or r.get("_PID"))
            msg = text(r["MESSAGE"])
        except (ValueError, KeyError, TypeError, OverflowError):
            print("journal-lines.py: not a journal record: " + raw[:200], file=sys.stderr)
            rc = 1
            continue
        sev = SEVERITY[pri] if 0 <= pri < len(SEVERITY) else "???"
        print(f"{when.strftime('%b %d %H:%M:%S')} {text(r.get('_HOSTNAME'))} {prog}[{pid}]({sev}): {msg}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
