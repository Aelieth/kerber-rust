#!/usr/bin/env python3
"""Compare test-fn bodies between two trees (SHA or directory).

Links old → new by `--renames` / `--duplicates` (the same maps
`hygiene-diff.py` uses), normalises whitespace, comments, crate-path
prefixes, and a helper-substitution table (code spans only; string,
byte-string, raw-string and char literals pass through whole, using
`hygiene-fn-diff.py`'s `_literal_spans`), then reports:

  pairs, identical, helper-only, differing, assertion-line changes,
  dropped, added

`--subst` rewrites only call positions of names in the declared helper
list (never constants, numerics, or string literals). Same-file helpers
are smashed only when the name exists on both sides of a pair; a rename
compares the helper bodies. `--accept` is keyed nextest
`binary<TAB>name` (one entry, one pair) and pins the accepted old→new
assertion-blob hashes; the RHS must exist in the new tree, and an unused
entry or a blob mismatch fails. Helper-call arguments stay in the blob
(smash the callee name only). There is no request-shape column (no
canonical built-request form).

Fails when an assertion-line change is not in `--accept` (with a matching
blob pin), a `#[ignore]` / `#[should_panic]` attribute is added or
removed, or a dropped test is not covered by the duplicates map (keyed,
target must exist).

Usage:
  python3 scripts/hygiene-body-diff.py --old SHA --new SHA \\
      --renames map.txt --duplicates map.txt [--accept accept.txt] [--params map.txt]
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


def _hygiene_fn_diff():
    import importlib.util

    path = ROOT / "scripts" / "hygiene-fn-diff.py"
    spec = importlib.util.spec_from_file_location("hygiene_fn_diff", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load scripts/hygiene-fn-diff.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_FN = _hygiene_fn_diff()
_literal_spans = _FN._literal_spans

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
    "documented_kadmin",
    "documented_changepw",
    "documented_history",
    "harness_master_etype",
    "inet",
    "decrypt_ticket_part",
    "unique_dir",
)
# `testrealm::` / `principals::` strip only after `krb5_kdc::`, `crate::`,
# or `super::`. A bare `testrealm::` is left alone.
PATHPFX = re.compile(
    r"\b(?:krb5_testkit|testkit|common|crate::common|self::common|"
    r"krb5_admin|krb5_protocol|krb5_client|krb5_gss|krb5_config|"
    r"(?:krb5_kdc|super|crate)(?:::(?:testrealm|principals))?)"
    r"::"
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
            helper_bodies: dict[str, str] = {}
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
                        q = m.end()
                        d2 = 1
                        while q < n and d2 > 0:
                            if scan[q] == "(":
                                d2 += 1
                            elif scan[q] == ")":
                                d2 -= 1
                            q += 1
                        while q < n and scan[q] not in "{;":
                            q += 1
                        body = ""
                        if q < n and scan[q] == "{":
                            start_body, d3 = q, 0
                            while q < n:
                                if scan[q] == "{":
                                    d3 += 1
                                elif scan[q] == "}":
                                    d3 -= 1
                                    if d3 == 0:
                                        break
                                q += 1
                            body = src[start_body : q + 1]
                        if istest:
                            attr_block = "".join(a + "\n" for a in attrs)
                            file_results.append(
                                {
                                    "crate": crate,
                                    "file": rel,
                                    "name": m.group(1),
                                    "leaf": m.group(1),
                                    "body": attr_block + body,
                                    "attrs": attrs,
                                    "mods": [s[1] for s in stack],
                                }
                            )
                        elif body:
                            helper_bodies[m.group(1)] = body
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
                t["helper_bodies"] = helper_bodies
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


def _collapse_code_horizontal(text: str) -> str:
    """Collapse horizontal whitespace in a code span; keep newlines."""
    text = PATHPFX.sub("", text)
    parts: list[str] = []
    for line in text.splitlines(keepends=True):
        nl = line.endswith("\n")
        core = line[:-1] if nl else line
        core = re.sub(r"[ \t]+", " ", core).strip()
        parts.append(core + ("\n" if nl else ""))
    return "".join(parts)


def _spans_norm(src: str) -> str:
    """Collapse whitespace in code spans; pass literals through verbatim."""
    out: list[str] = []
    for is_code, span in _literal_spans(src):
        out.append(_collapse_code_horizontal(span) if is_code else span)
    return "".join(out)


def norm_line(line: str) -> str:
    """Normalise one line; literals keep interior whitespace."""
    return _spans_norm(line).strip()


def norm_body(body: str) -> list[str]:
    """Line list of a test body. Literal interiors keep newlines and indent.

    Empty lines that sit inside a string / raw-string / byte-string /
    char literal are kept (an asserted raw-string interior blank line
    is a change). Empty code lines are dropped.
    """
    pieces: list[tuple[bool, str]] = []
    for is_code, span in _literal_spans(strip_comments(body)):
        pieces.append((is_code, _collapse_code_horizontal(span) if is_code else span))
    combined = "".join(p[1] for p in pieces)
    mask: list[bool] = []
    for is_code, span in pieces:
        mask.extend([not is_code] * len(span))
    lines: list[str] = []
    start = 0
    n = len(combined)
    i = 0
    while i <= n:
        if i == n or combined[i] == "\n":
            line = combined[start:i]
            # A zero-length interior line is start == i; its literal-ness
            # is the newline's own span, not the empty slice.
            if i < n and combined[i] == "\n":
                lit = mask[i]
            elif i > start:
                lit = any(mask[start:i])
            else:
                lit = False
            if line.strip() or lit:
                lines.append(line)
            start = i + 1
        i += 1
    return lines


def _rewrite_helper_calls(line: str, old: str, new: str) -> str:
    """Replace `old(` / `old!(` outside string literals. Never rewrite constants."""
    pat = re.compile(rf"\b{re.escape(old)}\s*(?=[(!])")
    out: list[str] = []
    for is_code, text in _literal_spans(line):
        if not is_code:
            out.append(text)
            continue
        i, n = 0, len(text)
        while i < n:
            m = pat.match(text, i)
            if m and not (i > 0 and text[i - 1] == "."):
                out.append(new)
                i = m.end()
                continue
            out.append(text[i])
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
    """Smash declared and extra helper callee names at bare call positions.

    Arguments stay (`status(&a, 13)` → `HELPER(&a, 13)`). `store.policy()` and
    the word `realm` inside a string stay. Never rewrite constants or fields.
    Same-file helpers belong in `extra` only when the name exists on both
    sides of a pair.
    """
    names = list(dict.fromkeys([*HELPERS, *extra]))
    out = []
    for line in lines:
        for h in names:
            line = _rewrite_helper_calls(line, h, "HELPER")
        # Adapter shape only: `HELPER(&err)` / `HELPER(err).0` after a
        # declared-helper subst (`proto_code` → `status`). Numeric and
        # other arguments stay so `status(&a, 13)` vs `status(&a, 0)` is
        # still an assertion change.
        line = re.sub(r"HELPER\s*\(\s*&", "HELPER(", line)
        line = re.sub(r"(HELPER\s*\([^)]*\))\s*\.\d+", r"\1", line)
        out.append(line)
    return out


def _flatten_code_span(text: str) -> str:
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\(\s+", "(", text)
    text = re.sub(r"\s+\)", ")", text)
    text = re.sub(r",\s*\)", ")", text)
    text = re.sub(r"\s+,", ",", text)
    return re.sub(r",\s*", ", ", text)


def flatten_code(lines: list[str]) -> str:
    """Join lines and collapse whitespace in code spans only."""
    out: list[str] = []
    for is_code, span in _literal_spans("\n".join(lines)):
        out.append(_flatten_code_span(span) if is_code else span)
    return "".join(out)


def _match_paren(src: str, open_idx: int) -> int:
    """Index past the `)` matching `src[open_idx] == '('`, skipping literals."""
    depth = 0
    pos = 0
    for is_code, text in _literal_spans(src):
        for i, c in enumerate(text):
            here = pos + i
            if here < open_idx:
                continue
            if not is_code:
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return here + 1
        pos += len(text)
    return len(src)


def _name_called(lines: list[str], name: str) -> bool:
    return any(_rewrite_helper_calls(line, name, "HELPER") != line for line in lines)


def helper_norm(body: str, own: str) -> str:
    return flatten_code(smash_helpers(norm_body(body), [own]))


def smash_pair(
    o: dict,
    n: dict,
    ol: list[str],
    nl: list[str],
) -> tuple[list[str], list[str], bool]:
    """Smash shared same-file helpers; pair renamed locals by helper body.

    A name change whose helper bodies differ is not helper-only (the
    smashed blobs keep the distinct callee names, so it is an assertion
    change). Byte-identical bodies modulo the name stay helper-only.
    """
    helpers = set(HELPERS)
    old_locals = list(o.get("local_helpers") or [])
    new_locals = list(n.get("local_helpers") or [])
    old_used = [h for h in old_locals if h not in helpers and _name_called(ol, h)]
    new_used = [h for h in new_locals if h not in helpers and _name_called(nl, h)]
    # Smash a same-file name only when both sides *call* it. A split that
    # keeps the old name in the new file unused must still pair the used
    # rename by helper body (tgt_part → tgt_part_issue_acl_ap).
    shared_used = [h for h in old_used if h in set(new_used)]
    so = smash_helpers(ol, shared_used)
    sn = smash_helpers(nl, shared_used)
    if so == sn or flatten_code(so) == flatten_code(sn):
        return so, sn, True
    old_bodies = o.get("helper_bodies") or {}
    new_bodies = n.get("helper_bodies") or {}
    old_only = [h for h in old_used if h not in shared_used]
    new_only = [h for h in new_used if h not in shared_used]
    unmatched = list(old_only)
    paired_old: list[str] = []
    paired_new: list[str] = []
    for nh in new_only:
        nb = helper_norm(new_bodies.get(nh, ""), nh)
        match = next(
            (oh for oh in unmatched if helper_norm(old_bodies.get(oh, ""), oh) == nb),
            None,
        )
        if match is None:
            # Leftovers on both sides whose bodies differ: assertion change.
            if old_only and new_only:
                return so, sn, False
            break
        unmatched.remove(match)
        paired_old.append(match)
        paired_new.append(nh)
    so2 = smash_helpers(so, paired_old)
    sn2 = smash_helpers(sn, paired_new)
    if so2 == sn2 or flatten_code(so2) == flatten_code(sn2):
        return so2, sn2, True
    leftover_old = [h for h in unmatched]
    leftover_new = [h for h in new_only if h not in paired_new]
    if leftover_old and leftover_new:
        return so2, sn2, False
    # One-sided leftover (local `code` vs declared `protocol_code`): smash
    # the leftover name and re-compare. Both-sided leftovers already failed.
    so3 = smash_helpers(so2, leftover_old)
    sn3 = smash_helpers(sn2, leftover_new)
    if so3 == sn3 or flatten_code(so3) == flatten_code(sn3):
        return so3, sn3, True
    return so3, sn3, False


def nextest_binary(t: dict) -> str:
    """Nextest rust-suite id: `crate`, `crate::stem`, or `crate::bin/name`."""
    parts = t["file"].split("/")
    crate = t["crate"]
    if len(parts) >= 4 and parts[2] == "tests":
        stem = parts[3][:-3] if parts[3].endswith(".rs") else parts[3]
        return f"{crate}::{stem}"
    if len(parts) >= 5 and parts[2] == "src" and parts[3] == "bin":
        name = parts[4][:-3] if parts[4].endswith(".rs") else parts[4]
        return f"{crate}::bin/{name}"
    return crate


def nextest_name(t: dict) -> str:
    """Nextest testcase name: file-module path + nested mods + leaf."""
    parts = t["file"].split("/")
    mods = list(t.get("mods") or [])
    leaf = t["leaf"]
    if len(parts) >= 3 and parts[2] == "src":
        rest = parts[3:]
        if rest and rest[0] == "bin":
            file_mods: list[str] = []
        elif rest:
            fname = rest[-1]
            dirs = rest[:-1]
            if fname in ("lib.rs", "main.rs", "mod.rs"):
                file_mods = dirs
            else:
                file_mods = [*dirs, pathlib.Path(fname).stem]
        else:
            file_mods = []
        return "::".join([*file_mods, *mods, leaf])
    return "::".join([*mods, leaf]) if mods else leaf


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
    return f"{nextest_binary(t)}\t{nextest_name(t)}"


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
    params: dict[str, tuple[str, list[str]]] | None = None,
) -> dict[str, object]:
    old, new = extract(old_root), extract(new_root)
    structs: dict[str, list[str]] = {}
    steps: dict[str, tuple] = {}
    survivor: dict[str, str] = {}
    if params:
        old_fns = _FN.extract(old_root)
        new_fns = _FN.extract(new_root)
        structs, steps, survivor = _FN.prepare_params(old_fns, new_fns, params, {})
    pairs, unmatched_old, unmatched_new = link(old, new, renames, dups)
    identical = helper_only = 0
    differ: list[tuple[dict, dict, list[str], list[str]]] = []
    assert_changes: list[tuple[dict, dict, str, str]] = []
    attr_changes: list[tuple[dict, dict]] = []
    for o, n in pairs:
        obody, nbody = o["body"], n["body"]
        if params:
            obody = _FN.expand_forwards(obody, steps, survivor)
            nbody = _FN._INV.params_rewrite_new(nbody, structs)
        ol, nl = apply_subst(norm_body(obody), subst), apply_subst(norm_body(nbody), subst)
        if ol == nl:
            identical += 1
            continue
        so, sn, helper = smash_pair(o, n, ol, nl)
        if helper:
            helper_only += 1
            continue
        differ.append((o, n, ol, nl))
        def assert_blob(lines: list[str]) -> str:
            text = flatten_code(lines)
            blobs: list[str] = []
            for m in ASSERT_RE.finditer(text):
                i = m.start()
                j = text.find("(", m.end() - 1)
                if j < 0:
                    blobs.append(text[i : m.end()])
                    continue
                k = _match_paren(text, j)
                blobs.append(text[i:k].strip())
            return " | ".join(blobs)

        if special_attrs(o) != special_attrs(n):
            attr_changes.append((o, n))
        ob, nb = assert_blob(so), assert_blob(sn)
        if ob != nb:
            assert_changes.append((o, n, blob_hash(ob), blob_hash(nb)))
    dropped_unmapped = [t for t in unmatched_old if not dup_covers(t, dups, new)]
    new_ids = {test_id(t) for t in new}
    missing_rhs = [
        strip_merged(entry["new"])
        for entry in accept.values()
        if strip_merged(entry["new"]) not in new_ids
    ]
    unaccepted = []
    accepted = []
    used_accept: set[str] = set()
    for o, n, oh, nh in assert_changes:
        key = accept_key(o) if accept_key(o) in accept else accept_key(n)
        entry = accept.get(key)
        rhs_ok = entry is not None and strip_merged(entry["new"]) == accept_key(n)
        if (
            entry
            and rhs_ok
            and entry["old_hash"] == oh
            and entry["new_hash"] == nh
            and key not in used_accept
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
        "missing_accept_rhs": missing_rhs,
        "differ_items": [
            {
                "file": o["file"],
                "leaf": o["leaf"],
                "new_file": n["file"],
                "new_leaf": n["leaf"],
                "assertion": any(o is a[0] and n is a[1] for a in assert_changes),
            }
            for o, n, _ol, _nl in differ
        ],
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
    for item in report.get("differ_items") or []:
        kind = "assertion" if item["assertion"] else "body"
        lines.append(f"differ {kind} {item['file']} {item['leaf']}")
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
    for rhs in report.get("missing_accept_rhs") or []:  # type: ignore[misc]
        errs.append(f"--accept RHS missing in new tree: {rhs}")
    if errs:
        raise BodyDiffError("; ".join(errs[:8]))


def _must_red(report: dict[str, object], label: str) -> None:
    try:
        evaluate(report)
    except BodyDiffError:
        return
    raise SystemExit(f"hygiene-body-diff --self-test: {label} must fail")


def _self_test() -> int:
    n = 0
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
        if red["assertion_changes"] != 1:
            raise SystemExit("hygiene-body-diff --self-test: assert_eq!(1, 2) must be an assertion change")
        _must_red(red, "assert_eq! literal change")
        n += 1
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(\n        1,\n        1,\n    );\n    let _ = issue_tgt();\n}\n",
            encoding="utf-8",
        )
        green = compare_trees(old, new, {}, {}, [("user_as", "issue_tgt")], {})
        evaluate(green)
        if green["assertion_changes"] != 0:
            raise SystemExit("hygiene-body-diff --self-test: rustfmt wrap of assert_eq! must pass")
        n += 1
        smashed = compare_trees(old, new, {}, {}, [], {})
        evaluate(smashed)
        if smashed["helper_only"] != 1:
            raise SystemExit("hygiene-body-diff --self-test: helper rename must pass")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(26, BADOPTION);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(26, SERVER_NOMATCH);\n}\n",
            encoding="utf-8",
        )
        _must_red(compare_trees(old, new, {}, {}, [], {}), "constant assertion change")
        n += 1
        try:
            load_subst(None, ["BADOPTION=SERVER_NOMATCH"])
        except SystemExit:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: --subst of a non-helper must fail")
        n += 1
        sneak = compare_trees(old, new, {}, {}, [("BADOPTION", "SERVER_NOMATCH")], {})
        _must_red(sneak, "subst must not hide BADOPTION")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(foo(), 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(bar(), 1);\n}\n",
            encoding="utf-8",
        )
        _must_red(compare_trees(old, new, {}, {}, [], {}), "callee name change")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\n#[ignore]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        _must_red(compare_trees(old, new, {}, {}, [], {}), "#[ignore] added")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn gone() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn kept() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        _must_red(
            compare_trees(old, new, {}, {"demo\tgone": "demo\tno_such"}, [], {}),
            "missing dup target",
        )
        n += 1
        unkeyed = pathlib.Path(tmp) / "unkeyed.txt"
        unkeyed.write_text("gone = kept\n", encoding="utf-8")
        try:
            load_duplicates_map(unkeyed)
        except SystemExit:
            pass
        else:
            raise SystemExit("hygiene-body-diff --self-test: unkeyed map must fail")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(1, 2);\n}\n",
            encoding="utf-8",
        )
        pin = compare_trees(old, new, {}, {}, [], {})
        _o, _n, oh, nh, _ent = pin["unaccepted"][0]  # type: ignore[misc]
        pin_id = "demo::t\tsample"
        good_accept = {
            pin_id: {
                "new": pin_id,
                "old_hash": oh,
                "new_hash": nh,
                "reason": "fixture",
            }
        }
        ok = compare_trees(old, new, {}, {}, [], good_accept)
        evaluate(ok)
        if ok["assertion_accepted"] != 1:
            raise SystemExit("hygiene-body-diff --self-test: matching accept blob must pass")
        n += 1
        bad_blob = {
            pin_id: {
                "new": pin_id,
                "old_hash": "0" * 64,
                "new_hash": "1" * 64,
                "reason": "wrong pin",
            }
        }
        _must_red(compare_trees(old, new, {}, {}, [], bad_blob), "blob mismatch")
        n += 1
        unused = {
            pin_id: {
                "new": pin_id,
                "old_hash": oh,
                "new_hash": nh,
                "reason": "fixture",
            },
            "demo::t\tother": {
                "new": "demo::t\tother",
                "old_hash": "a" * 64,
                "new_hash": "b" * 64,
                "reason": "unused",
            },
        }
        _must_red(compare_trees(old, new, {}, {}, [], unused), "unused accept")
        n += 1
        ghost = {
            pin_id: {
                "new": "demo::t\tno_such",
                "old_hash": oh,
                "new_hash": nh,
                "reason": "ghost",
            }
        }
        _must_red(compare_trees(old, new, {}, {}, [], ghost), "accept RHS missing")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "fn strict_verify(x: i32) -> bool { x == 13 }\n"
            "#[test]\nfn sample() {\n    assert!(strict_verify(13));\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "fn loose_verify(x: i32) -> bool { true }\n"
            "#[test]\nfn sample() {\n    assert!(loose_verify(13));\n}\n",
            encoding="utf-8",
        )
        weaker = compare_trees(old, new, {}, {}, [], {})
        if weaker["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: weaker same-file helper rename must be an assertion change"
            )
        _must_red(weaker, "weaker same-file helper rename")
        n += 1
        src_n.joinpath("t.rs").write_text(
            "fn loose_verify(x: i32) -> bool { x == 13 }\n"
            "#[test]\nfn sample() {\n    assert!(loose_verify(13));\n}\n",
            encoding="utf-8",
        )
        renamed = compare_trees(old, new, {}, {}, [], {})
        evaluate(renamed)
        if renamed["helper_only"] != 1 or renamed["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: identical helper body modulo name must be helper-only"
            )
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert!(status(&a, 13));\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert!(status(&a, 0));\n}\n",
            encoding="utf-8",
        )
        args = compare_trees(old, new, {}, {}, [], {})
        if args["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: helper-call argument change must be an assertion change"
            )
        _must_red(args, "helper-call argument change")
        n += 1
        twin = (
            "#[test]\nfn sample() {\n    assert_eq!(1, 1);\n}\n",
            "#[test]\nfn sample() {\n    assert_eq!(1, 2);\n}\n",
        )
        src_o.joinpath("t.rs").write_text(twin[0], encoding="utf-8")
        src_n.joinpath("t.rs").write_text(twin[1], encoding="utf-8")
        src_o.joinpath("u.rs").write_text(twin[0], encoding="utf-8")
        src_n.joinpath("u.rs").write_text(twin[1], encoding="utf-8")
        two = compare_trees(old, new, {}, {}, [], {})
        if two["assertion_changes"] != 2:
            raise SystemExit(
                "hygiene-body-diff --self-test: two (crate, leaf) pairs must both be assertion changes"
            )
        one_entry = {
            pin_id: {
                "new": pin_id,
                "old_hash": two["unaccepted"][0][2],  # type: ignore[index]
                "new_hash": two["unaccepted"][0][3],  # type: ignore[index]
                "reason": "covers only demo::t",
            }
        }
        covered = compare_trees(old, new, {}, {}, [], one_entry)
        if covered["assertion_accepted"] != 1 or not covered["unaccepted"]:
            raise SystemExit(
                "hygiene-body-diff --self-test: one accept entry must cover exactly one pair"
            )
        _must_red(covered, "one accept entry covering two (crate, leaf) pairs")
        n += 1
        src_o.joinpath("u.rs").unlink()
        src_n.joinpath("u.rs").unlink()
        src_o.joinpath("t.rs").write_text(
            '#[test]\nfn sample() {\n    assert_eq!(s, "a  b");\n}\n',
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            '#[test]\nfn sample() {\n    assert_eq!(s, "a b");\n}\n',
            encoding="utf-8",
        )
        spaced = compare_trees(old, new, {}, {}, [], {})
        if spaced["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: whitespace inside an asserted string must be an assertion change"
            )
        _must_red(spaced, "whitespace inside asserted string")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(s, r\"\n    indented\n\");\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(s, r\"\nindented\n\");\n}\n",
            encoding="utf-8",
        )
        raw = compare_trees(old, new, {}, {}, [], {})
        if raw["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: whitespace inside an asserted raw-string interior must be an assertion change"
            )
        _must_red(raw, "whitespace inside asserted raw-string interior")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(c, ' ');\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(c, '\\t');\n}\n",
            encoding="utf-8",
        )
        ch = compare_trees(old, new, {}, {}, [], {})
        if ch["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: char literal space vs tab must be an assertion change"
            )
        _must_red(ch, "char literal space vs tab")
        n += 1
        src_o.joinpath("t.rs").write_text(
            '#[test]\nfn sample() {\n    let x = 1;\n    assert_eq!(s, "a  b");\n}\n',
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            '#[test]\nfn sample() {\nlet x = 1;\nassert_eq!(s, "a  b");\n}\n',
            encoding="utf-8",
        )
        deindented = compare_trees(old, new, {}, {}, [], {})
        evaluate(deindented)
        if deindented["identical"] != 1 or deindented["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: a de-indented test body whose literals are untouched must be identical"
            )
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    let v = foo(1, 2);\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    let v = foo(\n        1,\n        2,\n    );\n    assert_eq!(1, 1);\n}\n",
            encoding="utf-8",
        )
        rewrap = compare_trees(old, new, {}, {}, [], {})
        evaluate(rewrap)
        if rewrap["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: a code-only rewrap must pass"
            )
        if rewrap["identical"] != 1 and rewrap["helper_only"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: a code-only rewrap must be identical or helper-only"
            )
        n += 1
        src_o.joinpath("t.rs").write_text(
            '#[test]\nfn sample() {\n    assert_eq!(s, r"a\n\nb");\n}\n',
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            '#[test]\nfn sample() {\n    assert_eq!(s, r"a\nb");\n}\n',
            encoding="utf-8",
        )
        blank = compare_trees(old, new, {}, {}, [], {})
        if blank["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: a zero-length interior line of an asserted literal must be an assertion change"
            )
        _must_red(blank, "zero-length interior literal line")
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(krb5_kdc::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(krb5_kdc::testrealm::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        realm = compare_trees(old, new, {}, {}, [], {})
        evaluate(realm)
        if realm["identical"] != 1 or realm["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: krb5_kdc::testrealm:: must normalise like krb5_kdc::"
            )
        n += 1
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(crate::principals::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(crate::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        princ = compare_trees(old, new, {}, {}, [], {})
        evaluate(princ)
        if princ["identical"] != 1 or princ["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: crate::principals:: must normalise like crate::"
            )
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert!(super::documented_host());\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert!(super::testrealm::documented_host());\n}\n",
            encoding="utf-8",
        )
        host = compare_trees(old, new, {}, {}, [], {})
        evaluate(host)
        if host["identical"] != 1 and host["helper_only"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: super::testrealm:: must normalise like super::"
            )
        if host["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: super::testrealm:: must not be an assertion change"
            )
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(krb5_kdc::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(krb5_kdc::other::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        missing_seg = compare_trees(old, new, {}, {}, [], {})
        if missing_seg["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: an undeclared module segment must be an assertion change"
            )
        _must_red(missing_seg, "path segment absent")
        n += 1
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(testrealm::TEST_REALM, 1);\n}\n",
            encoding="utf-8",
        )
        bare = compare_trees(old, new, {}, {}, [], {})
        if bare["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: a bare testrealm:: path must stay an assertion change"
            )
        _must_red(bare, "bare testrealm::")
        n += 1
        declared = load_subst(
            None,
            [
                "documented_kadmin=kadmin_admin",
                "documented_changepw=kadmin_changepw",
                "documented_history=kadmin_history",
                "harness_master_etype=default_master_etype",
            ],
        )
        if declared != [
            ("documented_kadmin", "kadmin_admin"),
            ("documented_changepw", "kadmin_changepw"),
            ("documented_history", "kadmin_history"),
            ("harness_master_etype", "default_master_etype"),
        ]:
            raise SystemExit(
                "hygiene-body-diff --self-test: the four renames must be declared helpers"
            )
        n += 1
        try:
            load_subst(None, ["documented_kiprop=kiprop"])
        except SystemExit:
            pass
        else:
            raise SystemExit(
                "hygiene-body-diff --self-test: an undeclared helper subst must fail"
            )
        n += 1
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert!(krb5_kdc::documented_kadmin());\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert!(krb5_kdc::principals::kadmin_admin());\n}\n",
            encoding="utf-8",
        )
        renamed_path = compare_trees(
            old, new, {}, {}, [("documented_kadmin", "kadmin_admin")], {}
        )
        evaluate(renamed_path)
        if renamed_path["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: path segment plus declared rename must pass"
            )
        n += 1
        (old / "crates" / "demo" / "src").mkdir(parents=True, exist_ok=True)
        (new / "crates" / "demo" / "src").mkdir(parents=True, exist_ok=True)
        (old / "crates" / "demo" / "src" / "lib.rs").write_text(
            "fn g(a: i32, b: i32) {}\n", encoding="utf-8"
        )
        (new / "crates" / "demo" / "src" / "lib.rs").write_text(
            "fn g(a: i32, b: i32) {}\n", encoding="utf-8"
        )
        pmap = {"demo\tg": ("S", ["a", "b"])}
        src_o.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(g(x, y), 1);\n}\n",
            encoding="utf-8",
        )
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(g(S { a: x, b: y }), 1);\n}\n",
            encoding="utf-8",
        )
        param_ok = compare_trees(old, new, {}, {}, [], {}, pmap)
        evaluate(param_ok)
        if param_ok["differ"] != 0 or param_ok["assertion_changes"] != 0:
            raise SystemExit(
                "hygiene-body-diff --self-test: --params test body must be identical: "
                f"{param_ok}"
            )
        n += 1
        src_n.joinpath("t.rs").write_text(
            "#[test]\nfn sample() {\n    assert_eq!(g(S { b: y, a: x }), 1);\n}\n",
            encoding="utf-8",
        )
        param_swap = compare_trees(old, new, {}, {}, [], {}, pmap)
        if param_swap["assertion_changes"] != 1:
            raise SystemExit(
                "hygiene-body-diff --self-test: swapped fields in a test must differ: "
                f"{param_swap}"
            )
        _must_red(param_swap, "swapped fields in a test body")
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["--self-test"]:
        n = _self_test()
        print(f"hygiene-body-diff: self-test ok ({n} cases)")
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--old", required=True, help="SHA or directory")
    ap.add_argument("--new", required=True, help="SHA or directory")
    ap.add_argument("--renames", type=pathlib.Path)
    ap.add_argument("--duplicates", type=pathlib.Path)
    ap.add_argument("--accept", type=pathlib.Path)
    ap.add_argument("--subst", action="append", default=[], metavar="OLD=NEW")
    ap.add_argument("--subst-file", type=pathlib.Path)
    ap.add_argument("--params", type=pathlib.Path, help="struct field map shared with hygiene-fn-diff")
    ap.add_argument("--git-dir", type=pathlib.Path, default=ROOT)
    ns = ap.parse_args(argv)
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        _self_test()
    renames = load_renames_map(ns.renames)
    dups = load_duplicates_map(ns.duplicates)
    subst = load_subst(ns.subst_file, ns.subst)
    accept = load_accept(ns.accept)
    params = _FN.load_params(ns.params)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = pathlib.Path(tmp)
        old_root = materialize(ns.old, tmp_p / "old", ns.git_dir)
        new_root = materialize(ns.new, tmp_p / "new", ns.git_dir)
        report = compare_trees(old_root, new_root, renames, dups, subst, accept, params)
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
