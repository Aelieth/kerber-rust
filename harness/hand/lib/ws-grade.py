#!/usr/bin/env python3
"""WS's grade over a record (REC/<leg>/win): one row per cell, ours against MIT's.

usage: ws-grade.py oracle REC | grade REC
oracle: MIT's leg shows what each cell expects; grade: ours' rows equal MIT's.
Cites are Microsoft Learn pages under https://learn.microsoft.com/en-us/windows/win32/ (W32) and
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ (CMD). A string no page
shows is marked as Windows' own text; MIT's leg is its oracle.
"""
import re
import sys
from datetime import datetime
from pathlib import Path

# W32 com/com-error-codes-4 (winerror.h); SEC_E_OK: W32 secauthn/initializesecuritycontext--kerberos.
SEC_I_CONTINUE_NEEDED = "0x00090312"
SEC_E_OK = "0x00000000"
SEC_E_LOGON_DENIED = "0x8009030C"
CELLS = ["W1", "W2-W4", "S-mit", "S-ours", "P1", "P2", "R1c", "K1", "L1", "KDC"]
TIME = re.compile(r"(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2})")
TIMED = ("Start Time", "End Time", "Renew Time", "StartTime", "EndTime", "RenewUntil")


def read(d, name):
    p = d / name
    return p.read_text(errors="replace").splitlines() if p.exists() else ["MISSING:" + name]


def when(line):
    m = TIME.search(line)
    return datetime.strptime(m.group(1), "%m/%d/%Y %H:%M:%S") if m else None


def klist(lines):
    """klist's text with each ticket's times as lifetimes; the logon id and time skew are per run."""
    out, times = [], {}

    def flush():
        if "start" in times:
            for label, key in (("Lifetime", "end"), ("Renewable", "renew")):
                if key in times:
                    secs = int((times[key] - times["start"]).total_seconds())
                    out.append("%s: %ds" % (label, round(secs / 60) * 60))
        times.clear()

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("Current LogonId") or line.startswith("TimeSkew") or line.startswith("exitcode"):
            continue
        label = line.split(":", 1)[0].strip()
        if label in TIMED:
            key = {"Start Time": "start", "StartTime": "start", "End Time": "end", "EndTime": "end"}.get(label, "renew")
            if when(line):
                times[key] = when(line)
            continue
        if line.startswith("#") or line.startswith("==") or line.startswith("Cached TGT"):
            flush()
        out.append(re.sub(r"\s+", " ", line))
    flush()
    return out


def picked(lines, prefixes):
    return [ln.strip() for ln in lines if ln.strip().startswith(prefixes)]


def acceptor(lines):
    rows = []
    for ln in lines:
        ln = ln.strip()
        if not ln or "listening" in ln:
            continue
        ln = re.sub(r"lifetime=\d+", "lifetime=N", ln)
        # A wrap token's octets 8-15 are its sequence number, random per context.
        ln = re.sub(r"(hdr=\[(?:[0-9a-f]{2}, ){8})[^\]]*\]", r"\1...]", ln)
        rows.append(ln)
    return rows


def kdc(lines):
    """Each logged request once per time it was logged, under its program's name."""
    rows = []
    for ln in lines:
        m = re.search(r"(\S+)\[\d+\]\([^)]*\): (.*)$", ln)
        if m:
            rows.append("%s: %s" % (m.group(1), re.sub(r"authtime \d+", "authtime N", m.group(2))))
    return sorted(rows)


TICKET = ("ACQUIRE_RC:", "ISC_RC:", "ISC_OUT:")


def rows(d):
    r = {}
    r["W1"] = picked(read(d, "w1.txt"), ("DNS_A:", "TCP88:")) + [
        re.sub(r"\s+", " ", ln.strip()) for ln in read(d, "w1-ksetup.txt") if ln.strip() and not ln.startswith("exitcode")
    ]
    w2 = read(d, "w2.txt")
    r["W2-W4"] = picked(w2, ("CREATE:", "WAIT:")) + klist([ln for ln in w2 if not ln.startswith(("CREATE:", "WAIT:", "PS_DONE"))])
    for kind in ("mit", "ours"):
        r["S-" + kind] = [ln.strip() for ln in read(d, "s-%s.txt" % kind) if ln.strip() and ln.strip() != "PS_DONE" and not ln.startswith("exitcode")]
        r["S-" + kind] += ["acceptor " + ln for ln in acceptor(read(d, "acc-%s.log" % kind))]
    r["P1"] = picked(read(d, "p1.txt"), ("LSA_", "CHPW_")) + ["new " + x for x in picked(read(d, "p1-new.txt"), TICKET)]
    r["P1"] += ["old " + x for x in picked(read(d, "p1-old.txt"), TICKET)]
    r["P2"] = []
    for c in ("wrong", "pwexp", "exp"):
        r["P2"] += [c + " " + x for x in picked(read(d, "p2-%s.txt" % c), TICKET)]
    r["R1c"] = picked(read(d, "r1c-set.txt"), ("exitcode",)) + picked(read(d, "r1c.txt"), TICKET) + picked(read(d, "r1c-del.txt"), ("exitcode",))
    k1 = read(d, "k1.txt")
    r["K1"] = picked(k1, ("CREATE:", "WAIT:", "HTTP_")) + klist(k1[next((i for i, ln in enumerate(k1) if ln.startswith("==KLIST")), len(k1)):])
    l1 = read(d, "l1.txt")
    r["L1"] = picked(l1, ("CREATE:", "WAIT:")) + klist([ln for ln in l1 if not ln.startswith(("CREATE:", "WAIT:", "PS_DONE"))])
    r["KDC"] = kdc(read(d, "kdc.log"))
    return r


def has(lines, text):
    return any(text in ln for ln in lines)


def code(lines, prefix="ISC_RC:0:"):
    return next((ln[len(prefix):] for ln in lines if ln.startswith(prefix)), "none")


def oracle(rec):
    d = rec / "mit" / "win"
    r = rows(d)
    w1k = r["W1"]
    t = {}
    # ksetup with no option lists the settings (CMD ksetup, ksetup-addkdc, ksetup-mapuser); its text is Windows' own.
    t["W1"] = has(w1k, "TCP88:open") and has(w1k, "kdc = kdc.kerber.test") and has(w1k, "Mapping cm-win@KERBER.TEST to winuser.")
    # klist get and its labels (CMD klist); the launch (W32 api/winbase/nf-winbase-createprocesswithlogonw).
    w = r["W2-W4"]
    t["W2-W4"] = has(w, "CREATE:True") and has(w, "==KLIST_GET_RC 0") and has(w, "Server: host/cm.kerber.test @ KERBER.TEST") \
        and has(w, "Server: krbtgt/KERBER.TEST @ KERBER.TEST") and has(w, "KerbTicket Encryption Type:")
    for kind, tag in (("mit", "mit-gss"), ("ours", "gss-accept")):
        s = r["S-" + kind]
        t["S-" + kind] = has(s, "ISC_RC:0:" + SEC_I_CONTINUE_NEEDED) and has(s, "ISC_RC:1:" + SEC_E_OK) \
            and has(s, "REPLY_TEXT:hello-from-acceptor") and has(s, "VERIFY_RC:" + SEC_E_OK) and has(s, "SSPI_DONE") \
            and has(s, "acceptor %s verify_mic ok" % tag) and has(s, "hello-mic-from-win-sspi") \
            and has(s, "hello-from-win-sspi") and has(s, "acceptor %s reply sent" % tag)
    # W32 api/ntsecapi/ns-ntsecapi-kerb_changepassword_request, nf-ntsecapi-lsacallauthenticationpackage:
    # the call's status and ProtocolStatus are STATUS_SUCCESS.
    p1, kd = r["P1"], r["KDC"]
    # MIT's AS statuses (kdc_log.c:87 prints them): PREAUTH_FAILED do_as_req.c:442,
    # CLIENT EXPIRED kdc_util.c:734, CLIENT KEY EXPIRED kdc_util.c:745.
    t["P1"] = has(p1, "CHPW_LSA:" + SEC_E_OK) and has(p1, "CHPW_PROTOCOL:" + SEC_E_OK) \
        and has(p1, "new ISC_RC:0:" + SEC_I_CONTINUE_NEEDED) and has(p1, "old ISC_RC:0:" + SEC_E_LOGON_DENIED) \
        and has(kd, "PREAUTH_FAILED: cm-win-file-chpw@KERBER.TEST")
    # A refused logon is an ISC failure; only the wrong password's code is named on Learn.
    p2 = r["P2"]
    refused = [code([x[len(c) + 1:] for x in p2 if x.startswith(c + " ")]) for c in ("wrong", "pwexp", "exp")]
    t["P2"] = refused[0] == SEC_E_LOGON_DENIED and all(c not in (SEC_E_OK, SEC_I_CONTINUE_NEEDED, "none") for c in refused) \
        and has(kd, "PREAUTH_FAILED: cm-win-kcm-chpw@KERBER.TEST") and has(kd, "CLIENT KEY EXPIRED: cm-win-file-pwexp@KERBER.TEST") \
        and has(kd, "CLIENT EXPIRED: cm-win-file-exp@KERBER.TEST")
    # R1c's status isn't settled on paper (BAD_ENCRYPTION_TYPE do_as_req.c:646, or a preauth one): any refusal.
    r1 = code(r["R1c"])
    kt = [ln for ln in kd if " cm-win-kt@KERBER.TEST for " in ln]
    t["R1c"] = r1 not in (SEC_E_OK, SEC_I_CONTINUE_NEEDED, "none") and r["R1c"].count("exitcode 0") == 2 \
        and bool(kt) and not any(": ISSUE: " in ln for ln in kt)
    # Keycloak's 302 with code=, as services.sh grades it; HttpWebRequest's default credentials.
    k = r["K1"]
    t["K1"] = has(k, "CREATE:True") and has(k, "HTTP_STATUS:302") and has(k, "HTTP_CODE:yes") and has(k, "Server: HTTP/services.kerber.test @ KERBER.TEST")
    lo = r["L1"]
    t["L1"] = has(lo, "CREATE:True") and has(lo, "Client: cm-win @ KERBER.TEST") and has(lo, "Server: krbtgt/KERBER.TEST @ KERBER.TEST")
    t["KDC"] = has(kd, "ISSUE") and has(kd, "cm-win@KERBER.TEST for krbtgt/KERBER.TEST@KERBER.TEST") and has(kd, "for host/cm.kerber.test@KERBER.TEST")
    for c in CELLS:
        print("ORACLE:%s:%s" % (c, "ok" if t[c] else "fail"))
    ok = all(t.values())
    print("ORACLE:%s" % ("ok" if ok else "fail"))
    return 0 if ok else 1


def grade(rec):
    mit, ours = rows(rec / "mit" / "win"), rows(rec / "ours" / "win")
    equal = 0
    for c in CELLS:
        if mit[c] == ours[c]:
            equal += 1
            print("ROW %s equal (%d lines)" % (c, len(mit[c])))
            continue
        print("ROW %s differ" % c)
        for i in range(max(len(mit[c]), len(ours[c]))):
            a = mit[c][i] if i < len(mit[c]) else "<none>"
            b = ours[c][i] if i < len(ours[c]) else "<none>"
            if a != b:
                print("  mit:  %s\n  ours: %s" % (a, b))
    print("WS_ROWS %d equal %d differ %d" % (len(CELLS), equal, len(CELLS) - equal))
    print("WS_GRADE:%s" % ("yes" if equal == len(CELLS) else "no"))
    return 0 if equal == len(CELLS) else 1


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("oracle", "grade"):
        sys.stderr.write(__doc__)
        return 2
    rec = Path(sys.argv[2])
    return oracle(rec) if sys.argv[1] == "oracle" else grade(rec)


if __name__ == "__main__":
    sys.exit(main())
