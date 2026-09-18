#!/usr/bin/env python3
"""Compare test-fn bodies between two trees (SHA or directory).

Links old → new by `--renames` / `--duplicates` (the same maps
`hygiene-diff.py` uses), normalises whitespace, comments, crate-path
prefixes, and a helper-substitution table, then reports:

  pairs, identical, helper-only, differing, assertion-line changes,
  dropped, added

`--subst` rewrites only call positions of names in the declared helper
list (never constants, numerics, or string literals). `--accept` is keyed
`binary<TAB>name` and pins the accepted old→new assertion-blob hashes;
an unused entry or a blob mismatch fails. There is no request-shape
column (no canonical built-request form).

Fails when an assertion-line change is not in `--accept` (with a matching
blob pin), a `#[ignore]` / `#[should_panic]` attribute is added or
removed, or a dropped test is not covered by the duplicates map (keyed,
target must exist).

Usage:
  python3 scripts/hygiene-body-diff.py --old SHA --new SHA \\
      --renames map.txt --duplicates map.txt [--accept accept.txt]
"""
from __future__ import annotations

import argparse
import collections
import difflib
import hashlib
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
load_renames_map = _HD.load_renames_map
load_map = _HD.load_map
strip_merged = _HD.strip_merged

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
    "ret_code",
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
TEST_ATTR = re.compile(r"#\[\s*(?:tokio::test|test|test_case|rstest|proptest)")
SPECIAL_ATTR_RE = re.compile(r"#\[\s*(?:ignore|should_panic)")
ACCEPT_RHS_RE = re.compile(
    r"^(?P<new>[^\s|]+(?:\t[^\s|]+))\s*\|\s*"
    r"sha256:(?P<oldh>[0-9a-f]{64})\s*\|\s*"
    r"sha256:(?P<newh>[0-9a-f]{64})\s*\|\s*"
    r"(?P<reason>.+)$"
)
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
            file_results: list[dict] = []
            file_fns: list[str] = []
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
                        file_fns.append(m.group(1))
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
                            attr_block = "".join(a + "\n" for a in attrs)
                            file_results.append(
                                {
                                    "crate": crate,
                                    "file": rel,
                                    "name": m.group(1),
                                    "leaf": m.group(1),
                                    "body": attr_block + src[start_body : q + 1],
                                    "attrs": attrs,
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
            tests = {t["leaf"] for t in file_results}
            locals_ = [n for n in file_fns if n not in tests]
            for t in file_results:
                t["local_helpers"] = locals_
            results.extend(file_results)
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
    for old, new in pairs:
        if old not in HELPERS:
            raise SystemExit(f"--subst {old} is not a declared helper")
        if not new:
            raise SystemExit(f"--subst {old}= needs a replacement")
    return pairs


def load_accept(path: pathlib.Path | None) -> dict[str, dict[str, str]]:
    """Keyed `binary<TAB>name = binary<TAB>name | sha256:old | sha256:new | reason`."""
    if path is None or not path.is_file():
        return {}
    out: dict[str, dict[str, str]] = {}
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
        k, rest = line.split("=", 1)
        key = k.strip()
        if "\t" not in key:
            raise SystemExit(f"--accept LHS must be binary<TAB>name: {key!r}")
        m = ACCEPT_RHS_RE.match(rest.strip())
        if not m:
            raise SystemExit(
                f"--accept {key!r} needs `binary<TAB>name | sha256:<64> | sha256:<64> | reason`"
            )
        out[key] = {
            "new": m.group("new"),
            "old_hash": m.group("oldh"),
            "new_hash": m.group("newh"),
            "reason": m.group("reason").strip(),
        }
        if not out[key]["reason"]:
            raise SystemExit(f"--accept {key!r} needs a reason")
    return out


def norm_line(line: str) -> str:
    return re.sub(r"\s+", " ", PATHPFX.sub("", line)).strip()


def norm_body(body: str) -> list[str]:
    lines = [norm_line(x) for x in strip_comments(body).splitlines()]
    return [x for x in lines if x]


def _rewrite_helper_calls(line: str, old: str, new: str) -> str:
    """Replace `old(` / `old!(` outside string literals. Never rewrite constants."""
    pat = re.compile(rf"\b{re.escape(old)}\s*(?=[(!])")
    out: list[str] = []
    i, n = 0, len(line)
    in_str = False
    while i < n:
        c = line[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        m = pat.match(line, i)
        if m and not (i > 0 and line[i - 1] == "."):
            out.append(new)
            i = m.end()
            continue
        out.append(c)
        i += 1
    return "".join(out)


def apply_subst(lines: list[str], subst: list[tuple[str, str]]) -> list[str]:
    out = []
    for line in lines:
        for old, new in subst:
            if old not in HELPERS:
                continue
            line = _rewrite_helper_calls(line, old, new)
        out.append(line)
    return out


def smash_helpers(lines: list[str], extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Smash declared and same-file helpers at bare call positions only.

    `user_as()` / `host_part(` become HELPER; `store.policy()` and the word
    `realm` inside a string stay. Never rewrite constants or field names.
    """
    names = list(dict.fromkeys([*HELPERS, *extra]))
    out = []
    for line in lines:
        for h in names:
            line = _rewrite_helper_calls(line, h, "HELPER")
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


def test_id(t: dict) -> str:
    return f"{t['crate']}\t{t['leaf']}"


def _lhs_matches(lhs: str, t: dict) -> bool:
    if "\t" not in lhs:
        return False
    name = lhs.split("\t", 1)[1]
    leaf = name.split("::")[-1]
    return leaf == t["leaf"] or name == t["leaf"] or lhs.endswith(f"\t{t['leaf']}")


def _rhs_exists(rhs: str, new_tests: list[dict]) -> bool:
    key = strip_merged(rhs)
    if "\t" not in key:
        return False
    name = key.split("\t", 1)[1]
    leaf = name.split("::")[-1]
    return any(n["leaf"] == leaf or n["leaf"] == name for n in new_tests)


def dup_covers(t: dict, dups: dict[str, str], new_tests: list[dict]) -> bool:
    """True only when a keyed LHS matches and the RHS target exists in new."""
    for lhs, rhs in dups.items():
        if _lhs_matches(lhs, t):
            return _rhs_exists(rhs, new_tests)
    return False


def accept_key(t: dict) -> str:
    return test_id(t)


def special_attrs(t: dict) -> list[str]:
    out: list[str] = []
    for a in t.get("attrs") or []:
        compact = re.sub(r"\s+", "", a)
        if SPECIAL_ATTR_RE.search(compact):
            out.append(compact)
    return out


def blob_hash(blob: str) -> str:
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def compare_trees(
    old_root: pathlib.Path,
    new_root: pathlib.Path,
    renames: dict[str, str],
    dups: dict[str, str],
    subst: list[tuple[str, str]],
    accept: dict[str, dict[str, str]],
) -> dict[str, object]:
    old, new = extract(old_root), extract(new_root)
    pairs, unmatched_old, unmatched_new = link(old, new, renames, dups)
    identical = helper_only = 0
    differ: list[tuple[dict, dict, list[str], list[str]]] = []
    assert_changes: list[tuple[dict, dict, str, str]] = []
    attr_changes: list[tuple[dict, dict]] = []
    for o, n in pairs:
        ol, nl = apply_subst(norm_body(o["body"]), subst), apply_subst(norm_body(n["body"]), subst)
        if ol == nl:
            identical += 1
            continue
        so, sn = smash_helpers(ol, o.get("local_helpers") or ()), smash_helpers(nl, n.get("local_helpers") or ())
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
                blob = re.sub(r"\s+", " ", text[i:k])
                blob = re.sub(r"\(\s+", "(", blob)
                blob = re.sub(r"\s+\)", ")", blob)
                blob = re.sub(r",\s*\)", ")", blob)
                blob = re.sub(r"\s+,", ",", blob)
                blob = re.sub(r",\s*", ", ", blob)
                blobs.append(blob.strip())
            return " | ".join(blobs)

        if special_attrs(o) != special_attrs(n):
            attr_changes.append((o, n))
        ob, nb = assert_blob(so), assert_blob(sn)
        if ob != nb:
            assert_changes.append((o, n, blob_hash(ob), blob_hash(nb)))
    dropped_unmapped = [t for t in unmatched_old if not dup_covers(t, dups, new)]
    unaccepted = []
    accepted = []
    used_accept: set[str] = set()
    for o, n, oh, nh in assert_changes:
        entry = accept.get(accept_key(o)) or accept.get(accept_key(n))
        key = accept_key(o) if accept_key(o) in accept else accept_key(n)
        if (
            entry
            and entry["old_hash"] == oh
            and entry["new_hash"] == nh
        ):
            used_accept.add(key)
            accepted.append((o, n, entry["reason"]))
        else:
            unaccepted.append((o, n, oh, nh, entry))
    unused_accept = [k for k in accept if k not in used_accept]
    report = {
        "old": len(old),
        "new": len(new),
        "pairs": len(pairs),
        "identical": identical,
        "helper_only": helper_only,
        "differ": len(differ),
        "assertion_changes": len(assert_changes),
        "assertion_accepted": len(accepted),
        "dropped": len(unmatched_old),
        "dropped_unmapped": len(dropped_unmapped),
        "added": len(unmatched_new),
        "unaccepted": unaccepted,
        "dropped_unmapped_tests": dropped_unmapped,
        "accepted": accepted,
        "attr_changes": attr_changes,
        "unused_accept": unused_accept,
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
    for row in report["unaccepted"]:  # type: ignore[misc]
        o, n = row[0], row[1]
        entry = row[4] if len(row) > 4 else None
        if entry:
            errs.append(
                f"assertion-line change blob mismatch: {o['file']} {o['leaf']} -> {n['leaf']}"
            )
        else:
            errs.append(f"assertion-line change not in --accept: {o['file']} {o['leaf']} -> {n['leaf']}")
    for o, n in report["attr_changes"]:  # type: ignore[misc]
        errs.append(f"#[ignore]/#[should_panic] change: {o['file']} {o['leaf']} -> {n['leaf']}")
    for t in report["dropped_unmapped_tests"]:  # type: ignore[misc]
        errs.append(f"dropped test not in --duplicates: {t['file']} {t['leaf']}")
    for key in report["unused_accept"]:  # type: ignore[misc]
        errs.append(f"--accept entry unused: {key}")
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
        assert red["assertion_changes"] == 1
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
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(26, BADOPTION);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(26, SERVER_NOMATCH);\n}\n",
            encoding="utf-8",
        )
        const_red = compare_trees(old, new, {}, {}, [], {})
        try:
            evaluate(const_red)
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: constant assertion change must fail")
        # --subst must not rewrite a constant, even if asked
        try:
            load_subst(None, ["BADOPTION=SERVER_NOMATCH"])
        except SystemExit:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: --subst of a non-helper must fail")
        sneak = compare_trees(old, new, {}, {}, [("BADOPTION", "SERVER_NOMATCH")], {})
        try:
            evaluate(sneak)
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: subst must not hide BADOPTION")
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(foo(), 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(bar(), 1);\n}\n",
            encoding="utf-8",
        )
        callee = compare_trees(old, new, {}, {}, [], {})
        try:
            evaluate(callee)
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: callee name change must fail")
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\n#[ignore]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        ignored = compare_trees(old, new, {}, {}, [], {})
        try:
            evaluate(ignored)
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: #[ignore] added must fail")
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn gone() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn kept() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        missing_tgt = compare_trees(
            old, new, {}, {"demo\tgone": "demo\tno_such"}, [], {}
        )
        try:
            evaluate(missing_tgt)
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: missing dup target must fail")
        unkeyed = pathlib.Path(tmp) / "unkeyed.txt"
        unkeyed.write_text("gone = kept\n", encoding="utf-8")
        try:
            load_duplicates_map(unkeyed)
        except SystemExit:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: unkeyed map must fail")
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 2);\n}\n",
            encoding="utf-8",
        )
        pin = compare_trees(old, new, {}, {}, [], {})
        o, n, oh, nh, _ent = pin["unaccepted"][0]  # type: ignore[misc]
        good_accept = {
            "demo\tsample": {
                "new": "demo\tsample",
                "old_hash": oh,
                "new_hash": nh,
                "reason": "fixture",
            }
        }
        ok = compare_trees(old, new, {}, {}, [], good_accept)
        evaluate(ok)
        if ok["assertion_accepted"] != 1:
            raise SystemExit("hygiene-body-diff --self-test: matching accept blob must pass")
        bad_blob = {
            "demo\tsample": {
                "new": "demo\tsample",
                "old_hash": "0" * 64,
                "new_hash": "1" * 64,
                "reason": "wrong pin",
            }
        }
        try:
            evaluate(compare_trees(old, new, {}, {}, [], bad_blob))
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: blob mismatch must fail")
        unused = {
            "demo\tsample": {
                "new": "demo\tsample",
                "old_hash": oh,
                "new_hash": nh,
                "reason": "fixture",
            },
            "demo\tother": {
                "new": "demo\tother",
                "old_hash": "a" * 64,
                "new_hash": "b" * 64,
                "reason": "unused",
            },
        }
        try:
            evaluate(compare_trees(old, new, {}, {}, [], unused))
        except BodyDiffError:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: unused accept must fail")


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
    renames = load_renames_map(ns.renames)
    dups = load_duplicates_map(ns.duplicates)
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
