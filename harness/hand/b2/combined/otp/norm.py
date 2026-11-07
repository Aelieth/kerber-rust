#!/usr/bin/env python3
"""norm.py FILE VIEW: one view of a lab cell's record, with what must differ between runs removed, for parity.sh.

FILE is a cell file of the OTP4 leg (driver.sh): the client's part (vmctl.sh kcell: the exit status, then sections under "== " headings), then
"# end of cell output", then "# KDC log lines added by this cell" (and, in the MIT stage, the RADIUS stub's lines). VIEW is one of
  rc          the exit status line
  stdin       the number of bytes the cell offered (not the bytes)
  stdout      the od -c dump, the byte count and the sha256 of what the kinit printed on stdout
  stderr      what it printed on stderr
  trace       the KRB5_TRACE lines
  ccache      "ccache written" or "no ccache was written"
  klist-C     MIT's klist -C of the ticket cache (the config entries: fast_avail, pa_type, pa_config_data)
  klist-fe    MIT's klist -f -e (flags and enctypes; the ticket times removed)
  klist-ours  our klist -C of the same ticket cache
  kvno        MIT's kvno of the require_auth service with that cache
  klog        the KDC's log lines the cell added, only those about otpuser@ (the VM's own background traffic lands in the same time window); the client's etype list in
              "AS_REQ (N etypes {...})" is masked here and listed by the etypes view
  etypes      the etype lists the client put in its AS_REQs (from the same KDC log lines): a client default, listed by parity.sh and not judged
  sizes       the sizes of the requests and answers, "Sending request (N bytes)" / "Received answer (N bytes)": listed by parity.sh, never judged
What is removed: pids and epoch stamps, byte counts ("(N bytes)", except in the sizes view), ccache names, MEMORY ids, the KDC's cookie bytes, the encrypted timestamp's time, the SPAKE
ephemeral public keys, ticket times, and in the KDC log the program name, pid, time, fd numbers, authtime and the client's address. Nothing else is normalized: whatever still differs
is listed by parity.sh."""
import os
import re
import sys

SECTIONS = {
    "stdin": "== stdin",
    "stdout": "== stdout (od -c)",
    "stderr": "== stderr",
    "trace": "== trace",
    "ccache": "== ccache",
    "klist-C": "== klist -C",
    "klist-fe": "== klist -f -e",
    "klist-ours": "== our klist -C",
    "kvno": "== kvno ",
}


def client_part(path):
    lines = []
    for raw in open(path, errors="replace"):
        line = raw.rstrip("\n")
        if line.startswith("# end of cell output"):
            break
        lines.append(line)
    return lines


def kdc_part(path):
    out, on = [], False
    for raw in open(path, errors="replace"):
        line = raw.rstrip("\n")
        if line.startswith("# KDC log lines added"):
            on = True
            continue
        if line.startswith("# RADIUS stub log lines"):
            break
        if on:
            out.append(line)
    return out


def section(lines, head):
    out, on = [], False
    for line in lines:
        if line.startswith("== "):
            on = line.startswith(head) if head.endswith(" ") else line == head
            continue
        if on:
            out.append(line)
    return out


def common(line):
    line = re.sub(r"^\[\d+\] \d+\.\d+: ", "", line)
    line = re.sub(r"\(\d+ bytes\)", "(N bytes)", line)
    line = re.sub(r"/[^ ]*/[A-Za-z0-9_.-]+\.cc", "<CC>", line)
    line = re.sub(r"MEMORY:\w+", "MEMORY:ID", line)
    line = re.sub(r"Received cookie: .*", "Received cookie: <opaque>", line)
    line = re.sub(r"\(for [0-9.]+\)", "(for T)", line)
    line = re.sub(r"\d\d/\d\d/\d{2,4} \d\d:\d\d:\d\d", "<time>", line)
    line = re.sub(r"(SPAKE (challenge received with group \d+,|key generated with) pubkey )[0-9A-Fa-f]{64}", r"\1<key>", line)
    return line


def klog_line(line, mask_etypes=True):
    line = re.sub(r"^[A-Z][a-z]{2} +\d+ [\d:]+ [^ ]+ [^ []+\[\d+\]", "", line)
    if mask_etypes:
        line = re.sub(r"^\((info)\): (AS_REQ|TGS_REQ) \(\d+ etypes \{[^}]*\}\)", r"(\1): \2 (etypes masked)", line)
    line = re.sub(r"fd \d+", "fd N", line)
    line = re.sub(r"authtime \d+", "authtime T", line)
    line = re.sub(re.escape(os.environ["FIELD_LAB_NET"]) + r"\.2[12]|127\.0\.0\.1", "CLIENT", line)
    return line


def main():
    path, view = sys.argv[1], sys.argv[2]
    if view == "rc":
        out = [line for line in client_part(path) if re.match(r"^\[rc=\d+\]$", line)][:1]
    elif view == "klog":
        out = [klog_line(line) for line in kdc_part(path)
               if re.match(r"^[A-Z][a-z]{2} +\d+ ", line) and "otpuser@" in line]
    elif view == "etypes":
        out = []
        for line in kdc_part(path):
            m = re.search(r"(AS_REQ|TGS_REQ) \((\d+) etypes \{([^}]*)\}\) \S+ (\w+): otpuser@", line)
            if m:
                out.append("%s %s etypes {%s} %s" % (m.group(1), m.group(2), m.group(3), m.group(4)))
    elif view == "sizes":
        out = []
        for line in section(client_part(path), SECTIONS["trace"]):
            m = re.search(r"(Sending request|Received answer) \((\d+) bytes\)", line)
            if m:
                out.append("%s %s" % (m.group(1), m.group(2)))
    elif view == "stdout":   # the od -c dump and the digest hold no stamp, nothing to remove
        out = section(client_part(path), SECTIONS[view])
    elif view in SECTIONS:
        out = [common(line) for line in section(client_part(path), SECTIONS[view])]
    else:
        print("norm.py: unknown view %s" % view, file=sys.stderr)
        return 2
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
