#!/usr/bin/env python3
"""Compare test-fn bodies between two trees (SHA or directory).

Links old → new by `--renames` / `--duplicates` (the same maps
`hygiene-diff.py` uses), normalises whitespace, comments, crate-path
prefixes, and a helper-substitution table, then reports:

  pairs, identical, helper-only, differing, assertion-line changes,
  request-shape changes, dropped, added

Fails when an assertion-line change is not in `--accept` (with a reason)
or a dropped test is not covered by the duplicates map.

Usage:
  python3 scripts/hygiene-body-diff.py --old SHA --new SHA \\
      --renames map.txt --duplicates map.txt [--accept accept.txt]
"""
from __future__ import annotations

import argparse
import collections
import difflib
import io
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _hygiene_diff():
    import importlib.util

    path = ROOT / "scripts" / "hygiene-diff.py"
    spec = importlib.util.spec_from_file_location("hygiene_diff", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load scripts/hygiene-diff.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_HD = _hygiene_diff()
apply_rename = _HD.apply_rename
load_duplicates_map = _HD.load_duplicates_map
load_map = _HD.load_map

HELPERS = (
    "issue_tgt",
    "issue_tgt_password",
    "issue_tgt_renewable",
    "user_as",
    "user_as_bits",
    "status",
    "expect_status",
    "protocol_code",
    "proto_code",
    "proto",
    "err_of",
    "err_of_cname",
    "password_key",
    "pref_etypes",
    "aes_key",
    "host_tgt",
    "attach_pac",
    "scratch_dir",
    "temp_dir",
    "reseal",
    "reseal_with",
    "reseal_ticket",
    "reseal_mut",
    "reseal_store",
    "reseal_tgt",
    "reseal_incoming",
    "s4u_tgs",
    "s4u_self",
    "s4u_admin",
    "s4u_req",
    "evidence_for_user",
    "wrap_if_relevant",
    "user",
    "admin",
    "krbtgt",
    "cname",
    "krbtgt_name",
    "documented_host",
    "bootstrap_documented",
    "inet",
    "decrypt_ticket_part",
    "unique_dir",
)
PATHPFX = re.compile(
    r"\b(?:krb5_testkit|testkit|common|crate::common|self::common|"
    r"krb5_kdc|krb5_admin|krb5_protocol|krb5_client|krb5_gss|krb5_config|"
    r"super|crate)::"
)
ASSERT_RE = re.compile(r"\bassert(?:_eq|_ne|_matches)?!")
REQ_RE = re.compile(
    r"\betypes?\b|\bnonce\b|\brealm\b|\bprincipal\b|kdc_options|KdcOptions|"
    r"\bflags\b|till|rtime|from|starttime|endtime|addresses|caddr|padata|"
    r"PaData|PA_|sname|cname|second_ticket|additional_tickets|lifetime|"
    r"renew|forwardable|proxiable|postdated"
)
TEST_ATTR = re.compile(r"#\[\s*(?:tokio::test|test|test_case|rstest|proptest)")
FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MOD_RE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
STAMP_RE = re.compile(r"^(?:====.*====|[a-z_][a-z0-9_]*=.*)$")


class BodyDiffError(Exception):
    """Assertion weakened/changed or a dropped test with no map entry."""


def strip_for_scan(src: str) -> str:
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    j += 2
                elif src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "r" and i + 1 < n and src[i + 1] in '#"':
            prev = src[i - 1] if i else ""
            prev_ok = not (prev.isalnum() or prev == "_") or (
                prev == "b" and (i < 2 or not (src[i - 2].isalnum() or src[i - 2] == "_"))
            )
            m = re.match(r'r(#*)"', src[i:])
            if prev_ok and m:
                term = '"' + m.group(1)
                j = src.find(term, i + len(m.group(0)))
                j = n if j < 0 else j + len(term)
                for k in range(i, j):
                    if out[k] != "\n":
                        out[k] = " "
                i = j
                continue
            i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "'":
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                for k in range(i, i + len(m.group(0))):
                    out[k] = " "
                i += len(m.group(0))
                continue
            i += 1
        else:
            i += 1
    return "".join(out)


def extract(root: pathlib.Path) -> list[dict]:
    results: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            path = pathlib.Path(dirpath) / fn
            rel = path.relative_to(root).as_posix()
            parts = rel.split("/")
            if not parts or len(parts) < 3:
                continue
            if parts[0] == "crates":
                crate, kind = parts[1], parts[2]
            elif parts[0] == "examples":
                crate, kind = parts[1], parts[2] if len(parts) > 2 else "src"
            else:
                continue
            if kind not in ("src", "tests"):
                continue
            src = path.read_text(encoding="utf-8", errors="replace")
            scan = strip_for_scan(src)
            events: list[tuple[int, str, re.Match[str]]] = []
            for m in MOD_RE.finditer(scan):
                events.append((m.start(), "mod", m))
            for m in re.finditer(r"#\[", scan):
                events.append((m.start(), "attr", m))
            for m in FN_RE.finditer(scan):
                events.append((m.start(), "fn", m))
            events.sort()
            ev_idx = 0
            pending_attrs: list[tuple[str, int, int]] = []
            stack: list[tuple[int, str]] = []
            depth = 0
            n = len(scan)
            p = 0
            while p < n:
                while ev_idx < len(events) and events[ev_idx][0] == p:
                    _, typ, m = events[ev_idx]
                    if typ == "mod":
                        stack.append((depth, m.group(1)))
                    elif typ == "attr":
                        d2, q = 0, m.start()
                        while q < n:
                            if scan[q] == "[":
                                d2 += 1
                            elif scan[q] == "]":
                                d2 -= 1
                                if d2 == 0:
                                    break
                            q += 1
                        pending_attrs.append((src[m.start() : q + 1], m.start(), q + 1))
                    elif typ == "fn":
                        attrs: list[str] = []
                        if pending_attrs:
                            k = len(pending_attrs) - 1
                            last_end = m.start()
                            run: list[str] = []
                            while k >= 0:
                                txt, _s0, e0 = pending_attrs[k]
                                gap = scan[e0:last_end]
                                if re.fullmatch(
                                    r"[\s]*(?:pub(?:\([^)]*\))?\s*)?(?:async\s*)?"
                                    r"(?:unsafe\s*)?(?:extern\s*\"[^\"]*\"\s*)?",
                                    gap,
                                ):
                                    run.append(txt)
                                    last_end = _s0
                                    k -= 1
                                else:
                                    break
                            attrs = list(reversed(run))
                        istest = any(
                            TEST_ATTR.search(a.replace(" ", "")) or re.match(r"#\[\s*(?:tokio::)?test", a)
                            for a in attrs
                        )
                        if istest:
                            q = m.end()
                            d2 = 1
                            while q < n and d2 > 0:
                                if scan[q] == "(":
                                    d2 += 1
                                elif scan[q] == ")":
                                    d2 -= 1
                                q += 1
                            while q < n and scan[q] != "{":
                                q += 1
                            start_body, d3 = q, 0
                            while q < n:
                                if scan[q] == "{":
                                    d3 += 1
                                elif scan[q] == "}":
                                    d3 -= 1
                                    if d3 == 0:
                                        break
                                q += 1
                            results.append(
                                {
                                    "crate": crate,
                                    "file": rel,
                                    "name": m.group(1),
                                    "leaf": m.group(1),
                                    "body": src[start_body : q + 1],
                                    "mods": [s[1] for s in stack],
                                }
                            )
                        pending_attrs = []
                    ev_idx += 1
                ch = scan[p]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    while stack and stack[-1][0] >= depth:
                        stack.pop()
                p += 1
    return results


def strip_comments(body: str) -> str:
    out: list[str] = []
    for line in body.splitlines():
        idx = None
        inq = False
        i = 0
        while i < len(line):
            c = line[i]
            if c == "\\" and inq:
                i += 2
                continue
            if c == '"':
                inq = not inq
            elif c == "/" and i + 1 < len(line) and line[i + 1] == "/" and not inq:
                idx = i
                break
            i += 1
        if idx is not None:
            line = line[:idx]
        out.append(line)
    return "\n".join(out)


def load_subst(path: pathlib.Path | None, extra: list[str] | None) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if path is not None and path.is_file():
        in_stamp = True
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if in_stamp and STAMP_RE.match(line):
                continue
            in_stamp = False
            if "=" not in line:
                continue
            a, b = line.split("=", 1)
            pairs.append((a.strip(), b.strip()))
    for raw in extra or []:
        if "=" not in raw:
            raise SystemExit(f"bad --subst {raw!r} (want old=new)")
        a, b = raw.split("=", 1)
        pairs.append((a.strip(), b.strip()))
    return pairs


def load_accept(path: pathlib.Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    out: dict[str, str] = {}
    in_stamp = True
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if in_stamp and STAMP_RE.match(line):
            continue
        in_stamp = False
        if "=" not in line:
            raise SystemExit(f"bad --accept line {line!r}")
        k, reason = line.split("=", 1)
        if not reason.strip():
            raise SystemExit(f"--accept {k!r} needs a reason")
        out[k.strip()] = reason.strip()
    return out


def norm_line(line: str) -> str:
    return re.sub(r"\s+", " ", PATHPFX.sub("", line)).strip()


def norm_body(body: str) -> list[str]:
    lines = [norm_line(x) for x in strip_comments(body).splitlines()]
    return [x for x in lines if x]


def apply_subst(lines: list[str], subst: list[tuple[str, str]]) -> list[str]:
    out = []
    for line in lines:
        for old, new in subst:
            line = re.sub(rf"\b{re.escape(old)}\b", new, line)
        out.append(line)
    return out


def smash_helpers(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        for h in HELPERS:
            line = re.sub(rf"\b{h}\b", "HELPER", line)
        line = re.sub(r"HELPER\s*\(\s*&?[^)]*\)(?:\.\d+)?", "HELPER", line)
        out.append(line)
    return out


def materialize(spec: str, dest: pathlib.Path, git_cwd: pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(spec)
    if p.is_dir():
        return p.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "archive", spec],
        cwd=git_cwd,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(f"git archive {spec} failed: {proc.stderr[-400:]}")
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
        tar.extractall(dest, filter="data")
    return dest


def mapped_leaves(t: dict, renames: dict[str, str], dups: dict[str, str]) -> set[str]:
    leaves = {t["leaf"]}
    for key in (t["name"], t["leaf"]):
        if key in renames:
            leaves.add(renames[key].split("::")[-1].split("\t")[-1])
        for lhs, rhs in dups.items():
            if lhs.split("\t")[-1].split("::")[-1] == key or lhs.endswith(f"\t{key}") or lhs == key:
                leaves.add(rhs.split("\t")[-1].split("::")[-1])
        for lhs, rhs in renames.items():
            if lhs.split("\t")[-1].split("::")[-1] == key or lhs.endswith(f"\t{key}"):
                leaves.add(rhs.split("\t")[-1].split("::")[-1])
    return leaves


def link(
    old: list[dict],
    new: list[dict],
    renames: dict[str, str],
    dups: dict[str, str],
) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    new_by: dict[tuple[str, str], list[dict]] = collections.defaultdict(list)
    for t in new:
        new_by[(t["crate"], t["leaf"])].append(t)
    used: set[int] = set()
    pairs: list[tuple[dict, dict]] = []
    unmatched_old: list[dict] = []

    def sim(a: list[str], b: list[str]) -> float:
        return difflib.SequenceMatcher(None, "\n".join(a), "\n".join(b)).ratio()

    old = sorted(
        old,
        key=lambda t: (
            "parent" in t["file"] or "/r10_" in t["file"],
            t["file"],
            t["leaf"],
        ),
    )
    for t in old:
        cands: list[dict] = []
        for leaf in mapped_leaves(t, renames, dups):
            for n in new_by.get((t["crate"], leaf), []):
                if id(n) not in used:
                    cands.append(n)
        if not cands:
            for leaf in mapped_leaves(t, renames, dups):
                for (c, l), lst in new_by.items():
                    if l == leaf:
                        for n in lst:
                            if id(n) not in used:
                                cands.append(n)
        if not cands:
            unmatched_old.append(t)
            continue
        best = cands[0] if len(cands) == 1 else max(cands, key=lambda n: sim(norm_body(t["body"]), norm_body(n["body"])))
        used.add(id(best))
        pairs.append((t, best))
    unmatched_new = [n for n in new if id(n) not in used]
    return pairs, unmatched_old, unmatched_new


def dup_covers(t: dict, dups: dict[str, str]) -> bool:
    leaf = t["leaf"]
    for lhs in dups:
        if lhs.split("\t")[-1].split("::")[-1] == leaf or lhs.endswith(f"\t{leaf}"):
            return True
    return False


def accept_key(t: dict) -> str:
    return t["leaf"]


def compare_trees(
    old_root: pathlib.Path,
    new_root: pathlib.Path,
    renames: dict[str, str],
    dups: dict[str, str],
    subst: list[tuple[str, str]],
    accept: dict[str, str],
) -> dict[str, object]:
    old, new = extract(old_root), extract(new_root)
    pairs, unmatched_old, unmatched_new = link(old, new, renames, dups)
    identical = helper_only = 0
    differ: list[tuple[dict, dict, list[str], list[str]]] = []
    assert_changes: list[tuple[dict, dict]] = []
    req_changes: list[tuple[dict, dict]] = []
    for o, n in pairs:
        ol, nl = apply_subst(norm_body(o["body"]), subst), apply_subst(norm_body(n["body"]), subst)
        if ol == nl:
            identical += 1
            continue
        so, sn = smash_helpers(ol), smash_helpers(nl)
        if so == sn:
            helper_only += 1
            continue
        def flatten_code(lines: list[str]) -> str:
            text = re.sub(r"\s+", " ", " ".join(lines))
            text = re.sub(r"\(\s+", "(", text)
            text = re.sub(r"\s+\)", ")", text)
            text = re.sub(r",\s*\)", ")", text)
            text = re.sub(r"\s+,", ",", text)
            return re.sub(r",\s*", ", ", text)

        if flatten_code(so) == flatten_code(sn):
            helper_only += 1
            continue
        differ.append((o, n, ol, nl))
        def assert_blob(lines: list[str]) -> str:
            text = re.sub(r"\s+", " ", " ".join(lines))
            blobs: list[str] = []
            for m in ASSERT_RE.finditer(text):
                i = m.start()
                # take the macro and its top-level (...)
                j = text.find("(", m.end() - 1)
                if j < 0:
                    blobs.append(text[i : m.end()])
                    continue
                depth = 0
                k = j
                while k < len(text):
                    if text[k] == "(":
                        depth += 1
                    elif text[k] == ")":
                        depth -= 1
                        if depth == 0:
                            k += 1
                            break
                    k += 1
                blob = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", "CALL(", text[i:k])
                blob = re.sub(r"\s+", " ", blob)
                blob = re.sub(r"\(\s+", "(", blob)
                blob = re.sub(r"\s+\)", ")", blob)
                blob = re.sub(r",\s*\)", ")", blob)
                blob = re.sub(r"\s+,", ",", blob)
                blob = re.sub(r",\s*", ", ", blob)
                blobs.append(blob.strip())
            return " | ".join(blobs)

        if assert_blob(so) != assert_blob(sn):
            assert_changes.append((o, n))
        orq = [l for l in so if REQ_RE.search(l)]
        nrq = [l for l in sn if REQ_RE.search(l)]
        if orq != nrq and re.sub(r"\s+", " ", " ".join(orq)) != re.sub(r"\s+", " ", " ".join(nrq)):
            req_changes.append((o, n))
    dropped_unmapped = [t for t in unmatched_old if not dup_covers(t, dups)]
    unaccepted = []
    accepted = []
    for o, n in assert_changes:
        reason = accept.get(accept_key(o)) or accept.get(accept_key(n))
        if reason:
            accepted.append((o, n, reason))
        else:
            unaccepted.append((o, n))
    report = {
        "old": len(old),
        "new": len(new),
        "pairs": len(pairs),
        "identical": identical,
        "helper_only": helper_only,
        "differ": len(differ),
        "assertion_changes": len(assert_changes),
        "assertion_accepted": len(accepted),
        "request_shape_changes": len(req_changes),
        "dropped": len(unmatched_old),
        "dropped_unmapped": len(dropped_unmapped),
        "added": len(unmatched_new),
        "unaccepted": unaccepted,
        "dropped_unmapped_tests": dropped_unmapped,
        "accepted": accepted,
    }
    return report


def render(report: dict[str, object]) -> str:
    lines = [
        f"pairs {report['pairs']}",
        f"identical {report['identical']}",
        f"helper-only {report['helper_only']}",
        f"differ {report['differ']}",
        f"assertion-line changes {report['assertion_changes']}",
        f"assertion accepted {report['assertion_accepted']}",
        f"request-shape changes {report['request_shape_changes']}",
        f"dropped {report['dropped']}",
        f"dropped unmapped {report['dropped_unmapped']}",
        f"added {report['added']}",
        f"old {report['old']}",
        f"new {report['new']}",
    ]
    for o, n, reason in report["accepted"]:  # type: ignore[misc]
        lines.append(f"accepted {o['leaf']} -> {n['leaf']}: {reason}")
    return "\n".join(lines) + "\n"


def evaluate(report: dict[str, object]) -> None:
    errs: list[str] = []
    for o, n in report["unaccepted"]:  # type: ignore[misc]
        errs.append(f"assertion-line change not in --accept: {o['file']} {o['leaf']} -> {n['leaf']}")
    for t in report["dropped_unmapped_tests"]:  # type: ignore[misc]
        errs.append(f"dropped test not in --duplicates: {t['file']} {t['leaf']}")
    if errs:
        raise BodyDiffError("; ".join(errs[:8]))


def _self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        old, new = root / "old", root / "new"
        src_o = old / "crates" / "demo" / "tests"
        src_n = new / "crates" / "demo" / "tests"
        src_o.mkdir(parents=True)
        src_n.mkdir(parents=True)
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 1);\n    let _ = user_as();\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 2);\n    let _ = user_as();\n}\n",
            encoding="utf-8",
        )
        red = compare_trees(old, new, {}, {}, [], {})
        try:
            evaluate(red)
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: assert_eq! literal change must fail")
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(\n        1,\n        1,\n    );\n    let _ = issue_tgt();\n}\n",
            encoding="utf-8",
        )
        green = compare_trees(old, new, {}, {}, [("user_as", "issue_tgt")], {})
        evaluate(green)
        if green["assertion_changes"] != 0:
            raise SystemExit("hygiene-body-diff --self-test: rustfmt wrap of assert_eq! must pass")
        if green["helper_only"] != 1 and green["identical"] != 1:
            # smash_helpers should also pass without subst
            smashed = compare_trees(old, new, {}, {}, [], {})
            evaluate(smashed)
            if smashed["helper_only"] != 1:
                raise SystemExit("hygiene-body-diff --self-test: helper rename must pass")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--self-test"]:
        _self_test()
        print("hygiene-body-diff: self-test ok")
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--old", required=True, help="SHA or directory")
    ap.add_argument("--new", required=True, help="SHA or directory")
    ap.add_argument("--renames", type=pathlib.Path)
    ap.add_argument("--duplicates", type=pathlib.Path)
    ap.add_argument("--accept", type=pathlib.Path)
    ap.add_argument("--subst", action="append", default=[], metavar="OLD=NEW")
    ap.add_argument("--subst-file", type=pathlib.Path)
    ap.add_argument("--git-dir", type=pathlib.Path, default=ROOT)
    ns = ap.parse_args(argv)
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        _self_test()
    renames = load_map(ns.renames, "->")
    try:
        dups = load_duplicates_map(ns.duplicates)
    except SystemExit:
        # Body-diff may run with a name-only historical map; treat as leaf=leaf.
        raw = load_map(ns.duplicates, "=")
        dups = raw
    subst = load_subst(ns.subst_file, ns.subst)
    accept = load_accept(ns.accept)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = pathlib.Path(tmp)
        old_root = materialize(ns.old, tmp_p / "old", ns.git_dir)
        new_root = materialize(ns.new, tmp_p / "new", ns.git_dir)
        report = compare_trees(old_root, new_root, renames, dups, subst, accept)
    sys.stdout.write(render(report))
    try:
        evaluate(report)
    except BodyDiffError as e:
        print(f"hygiene-body-diff: {e}", file=sys.stderr)
        return 1
    print("hygiene-body-diff: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
