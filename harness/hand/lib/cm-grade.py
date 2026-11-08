#!/usr/bin/env python3
"""cm-grade.py: CM's grade, over the record rp-cm.sh writes (REC/<leg>/<tag>/<cache>/cell<n>.{out,rc}).

  cm-grade.py oracle REC TAG...   MIT's leg shows what the client's tools print for each cell; exit 1 if not
  cm-grade.py grade REC TAG...    ours against MIT per (tag, cache, cell): rc and text with times masked;
                                  both legs renew in cell 8; exit 1 on any difference
  cm-grade.py scan REC TSV        no generated password (TSV: name TAB value) in any file under REC

The tag hm is HM's suite: Heimdal's cells 1-5 under FILE:, no renewals. Lines starting INFO_ are recorded, not
graded. Cross-distro differences on MIT's leg print as CM_VERSION
(information, not graded). Prints names and counts, never a password.
"""
import difflib
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
REALM = "KERBER.TEST"
CACHES = ("file", "kcm")
TIMES = [
    re.compile(r"\d{2}/\d{2}/\d{2}(?:\d{2})? \d{2}:\d{2}:\d{2}(?: [AP]M)?"),
    re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"),
    re.compile(r"[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?: [A-Z]{2,5})? \d{4}"),
]
# Heimdal's klist prints ctime + 4, 20 characters (kuser/klist.c:40-64); only hm rows use it.
HM_TIME = re.compile(r"[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}")
HM = "hm"
KCM_NAME = re.compile(r"KCM:(\d+):\d+")
TAGGED = re.compile(r"\b(cmu?)-(f44|rocky|deb|ub)\b")


def cells(tag):
    if tag == HM:
        for n in range(1, 6):
            yield HM, n
        return
    for cache in CACHES:
        for n in range(1, 9):
            yield cache, n
    yield "k9", 9


def read(rec, leg, tag, cache, n):
    d = rec / leg / tag / cache
    out = d / f"cell{n}.out"
    rc = d / f"cell{n}.rc"
    if not out.exists() or not rc.exists():
        return None, None
    return rc.read_text().strip(), out.read_text(errors="replace")


def mask(text, tag):
    kept = []
    for ln in text.splitlines(True):
        if ln.startswith("INFO_"):
            # The guest's mark() writes a blank line before each marker; it goes with its INFO_ line.
            if kept and kept[-1].strip() == "":
                kept.pop()
            continue
        kept.append(ln)
    text = "".join(kept)
    for p in TIMES:
        text = p.sub("<TIME>", text)
    if tag == HM:
        text = HM_TIME.sub("<TIME>", text)
    return KCM_NAME.sub(r"KCM:\1:<N>", text)


def lines_matching(text, rx):
    return len(re.findall(rx, text, re.M))


def expect_hm(n):
    """HM's cells on MIT's leg; each string cites its Heimdal printer (Debian's heimdal 7.8.0, patches applied)."""
    q = re.escape(f"@{REALM}")
    if n == 1:
        # Heimdal: `print_tickets` (kuser/klist.c:262-263)
        # Heimdal: `print_cred_verbose` (kuser/klist.c:155)
        # Heimdal: `print_cred_verbose` (kuser/klist.c:171-180)
        # Heimdal: `print_cred_verbose` (kuser/klist.c:212)
        return "0", [
            (rf"^ *Principal: cm-hm{q}$", 1),
            (rf"^Server: krbtgt/KERBER\.TEST{q}$", 1),
            (r"^Ticket etype: aes256-cts-hmac-sha1-96, kvno \d+$", 1),
            (r"^Ticket flags: ", 1),
        ]
    if n == 2:
        # Heimdal: `print_tickets` (kuser/klist.c:262-263)
        return "0", [(rf"^ *Principal: cm-hm-kt{q}$", 1)]
    if n == 3:
        # Heimdal: `print_cred_verbose` (kuser/klist.c:155)
        return "0", [(rf"^Server: host/cm\.kerber\.test{q}$", 1), (r"^KGETCRED_RC:0$", 1)]
    if n == 4:
        # Heimdal: `krb5_get_init_creds_password` (lib/krb5/init_creds_pw.c:2696)
        # Heimdal: `change_password` (kpasswd/kpasswd.c:74)
        # Heimdal: `UI_UTIL_read_pw_string` (lib/hcrypto/ui.c:203)
        # Heimdal: `change_password` (kpasswd/kpasswd.c:105)
        return "0", [
            (rf"cm-hm-file-chpw{q}'s Password: ", 1),
            (r"New password: ", 2),
            (r"Verify password - New password: ", 1),
            (r"Success( : [^\n]*)?$", 1),
            (r"^KINIT2_RC:0$", 1),
        ]
    # Heimdal: `get_new_tickets` (kuser/kinit.c:729)
    # Heimdal: `get_new_tickets` (kuser/kinit.c:738)
    # Heimdal: `krb5_error_from_rd_error` (lib/krb5/rd_error.c:77-80)
    # MIT: `process_as_req` (kdc/do_as_req.c:582)
    # MIT: `prepare_error_as` (kdc/do_as_req.c:808)
    return "1", [
        (r"^kinit\.heimdal: Password incorrect$", 1),
        (r"^kinit\.heimdal: krb5_get_init_creds: CLIENT_NOT_FOUND$", 1),
    ]


def expect(tag, cache, n):
    """(rc, [(regex, count or None for at least once)]) for MIT's leg; each string cites its MIT printer."""
    if tag == HM:
        return expect_hm(n)
    p = f"cm-{tag}"
    q = re.escape(f"@{REALM}")
    c = f"cm-{tag}-{cache}"
    if n == 1:
        # MIT: `show_ccache` (clients/klist/klist.c:489)
        # MIT: `show_credential` (clients/klist/klist.c:749)
        # MIT: `show_credential` (clients/klist/klist.c:764)
        return "0", [(rf"^Default principal: {p}{q}$", None), (r"Flags: ", None), (r"Etype \(skey, tkt\): ", None)]
    if n == 2:
        # MIT: `show_ccache` (clients/klist/klist.c:489)
        return "0", [(rf"^Default principal: {p}-kt{q}$", None)]
    if n == 3:
        # MIT: `kvno` (clients/kvno/kvno.c:381)
        return "0", [(rf"^host/cm\.kerber\.test{q}: kvno = \d+$", 1)]
    if n == 4:
        # MIT: `show_credential` (clients/klist/klist.c:737)
        return "0", [(r"renew until ", None), (r"^RENEW_TILL_KEPT:yes$", 1)]
    if n == 5:
        # MIT: `main` (clients/kpasswd/kpasswd.c:175)
        return "0", [(r"Password changed\.$", 1), (r"^KINIT2_RC:0$", 1)]
    if n == 6:
        # MIT: `KRB5KDC_ERR_NAME_EXP` (lib/krb5/error_tables/krb5_err.et:42)
        # MIT: `k5_kinit` (clients/kinit/kinit.c:792)
        # MIT: `krb5_get_init_creds_password` (lib/krb5/krb/gic_pwd.c:253)
        return "0", [
            (r"Client's entry in database has expired while getting initial credentials$", 1),
            (r"Password expired\.  You must change it now\.", 1),
            (r"^KINIT_PWEXP_RC:0$", 1),
        ]
    if n == 7:
        # MIT: `k5_kinit` (clients/kinit/kinit.c:789)
        # MIT: `KRB5KDC_ERR_CLIENT_REVOKED` (lib/krb5/error_tables/krb5_err.et:59)
        # MIT: `kadmin_modprinc` (kadmin/cli/kadmin.c:1428)
        return "0", [
            (r"Password incorrect while getting initial credentials$", 3),
            (r"Client's credentials have been revoked while getting initial credentials$", 1),
            (rf'Principal "{c}-lock{q}" modified\.$', 1),
            (r"^KINIT_UNLOCKED_RC:0$", 1),
        ]
    if n == 8:
        return "0", [(r"^LOGIN:yes$", 1), (r"^RENEWED:yes$", 1), (r"^RENEW_TILL_KEPT:yes$", 1), (r"^SSSD_CONFIG_CHECK:0$", 1)]
    # MIT: `kadmin_getprinc` (kadmin/cli/kadmin.c:1482)
    # MIT: `kadmin_addprinc` (kadmin/cli/kadmin.c:1355)
    # MIT: `kadmin_delprinc` (kadmin/cli/kadmin.c:704)
    # MIT: `kadmin_getprincs` (kadmin/cli/kadmin.c:1591)
    return "0", [
        (rf"Principal: {p}{q}$", 1),
        (rf'Principal "{p}-k9{q}" created\.$', 1),
        (rf'Principal "{p}-k9{q}" deleted\.$', 1),
        (rf"(^|: ){p}-k9{q}$", 1),
    ]


def oracle(rec, tags):
    bad = 0
    for tag in tags:
        for cache, n in cells(tag):
            rc, text = read(rec, "mit", tag, cache, n)
            want_rc, pats = expect(tag, cache, n)
            why = []
            if rc is None:
                why.append("missing")
            else:
                if rc != want_rc:
                    why.append("rc=" + rc)
                for rx, count in pats:
                    got = lines_matching(text, rx)
                    if (count is None and got == 0) or (count is not None and got != count):
                        why.append("%s x%d" % (rx, got))
            if why:
                bad += 1
                print("ORACLE_FAIL:%s:%s:cell%d:%s" % (tag, cache, n, " | ".join(why)))
    print("ORACLE:%s" % ("ok" if bad == 0 else "fail"))
    return 1 if bad else 0


def grade(rec, tags):
    rows = differ = 0
    renew_ok = True
    for tag in tags:
        for cache, n in cells(tag):
            rows += 1
            a = read(rec, "mit", tag, cache, n)
            b = read(rec, "ours", tag, cache, n)
            if a[0] is None or b[0] is None:
                differ += 1
                print("CM_ROW %s %s %d missing" % (tag, cache, n))
                continue
            ma, mb = mask(a[1], tag), mask(b[1], tag)
            if a[0] == b[0] and ma == mb:
                print("CM_ROW %s %s %d equal" % (tag, cache, n))
                continue
            differ += 1
            print("CM_ROW %s %s %d differ rc=%s:%s" % (tag, cache, n, a[0], b[0]))
            (rec / f"diff-{tag}-{cache}-cell{n}.txt").write_text("".join(difflib.unified_diff(
                ma.splitlines(True), mb.splitlines(True),
                fromfile=f"mit/{tag}/{cache}/cell{n}", tofile=f"ours/{tag}/{cache}/cell{n}")))
        if tag == HM:
            continue
        for cache in CACHES:
            for leg in ("mit", "ours"):
                _, text = read(rec, leg, tag, cache, 8)
                ok = text is not None and lines_matching(text, r"^RENEWED:yes$") == 1
                renew_ok = renew_ok and ok
                print("CM_RENEW %s %s %s %s" % (leg, tag, cache, "yes" if ok else "no"))
    clients = [t for t in tags if t != HM]
    for cache, n in cells(clients[0]) if clients else ():
        seen = {}
        for tag in clients:
            _, text = read(rec, "mit", tag, cache, n)
            if text is not None:
                seen.setdefault(TAGGED.sub(r"\1-<T>", mask(text, tag)), []).append(tag)
        if len(seen) > 1:
            print("CM_VERSION %s %d %s" % (cache, n, " / ".join(",".join(v) for v in seen.values())))
    print("CM_ROWS %d equal %d differ %d" % (rows, rows - differ, differ))
    ok = differ == 0 and renew_ok and rows == sum(len(list(cells(t))) for t in tags)
    print("CM_GRADE:%s" % ("yes" if ok else "no"))
    return 0 if ok else 1


def scan(rec, tsv):
    values = []
    for line in Path(tsv).read_text().splitlines():
        name, _, value = line.partition("\t")
        if value:
            values.append(value.encode())
    hits = 0
    for path in sorted(p for p in rec.rglob("*") if p.is_file()):
        data = path.read_bytes()
        if any(v in data or v.decode().encode("utf-16-le") in data for v in values):
            hits += 1
            print("CM_SECRET_HIT_PATH:%s" % path)
    print("CM_SECRET_VALUES:%d" % len(values))
    print("CM_SECRET_HITS:%d" % hits)
    return 1 if hits or not values else 0


def main(argv):
    if len(argv) >= 4 and argv[1] == "scan":
        return scan(Path(argv[2]), argv[3])
    if len(argv) >= 4 and argv[1] in ("oracle", "grade"):
        rec, tags = Path(argv[2]), argv[3:]
        return oracle(rec, tags) if argv[1] == "oracle" else grade(rec, tags)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
