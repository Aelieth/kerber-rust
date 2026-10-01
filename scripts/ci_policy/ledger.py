"""Checks on the MIT parity ledger and the diffsend case lists."""

from __future__ import annotations

import os
import pathlib
import re
import sys

from .common import ROOT, SCRIPTS, _die, _hygiene_inventory

DIFFSEND_CASES = frozenset(
    {
        "garbage-pdu",
        "unknown-cname",
        "etype-nosupp",
        "as-session-enctype",
        "wrong-realm",
        "pauser-no-preauth",
        "as-needpreauth-hints-unpermitted",
        "skewed-timestamp",
        "unknown-sname",
        "as-success",
        "tgs-success",
        "tgs-not-a-tgt",
        "tgt-expired",
        "tgt-nyv",
        "tgt-nyv-no-starttime",
        "fast-armor-no-subkey",
        "armor-ap-req-as-pa-tgs-req",
        "tgs-ad-fx-armor-authenticator",
        "as-bad-msg-type",
        "as-bad-pvno",
        "tgs-bad-msg-type",
        "as-service-not-allowed",
        "tgs-ap-options",
        "tgs-header-kvno-zero",
        "as-hw-preauth",
        "as-spake-round1",
        "u2u-2nd-ticket-unknown-server",
        "u2u-2nd-ticket-bad-etype",
        "u2u-2nd-ticket-corrupt",
        "tgs-pac-client-mismatch",
        "tgs-pac-corrupt-before-sname",
        "tgs-pac-request-false",
        "tgs-from-pacless-tgt",
        "tgs-renew-service-ticket",
        "tgs-proxy-krbtgt",
        "tgs-canonicalize-renew",
        "tgs-expired-vs-unknown-sname",
        "s4u2self-no-pac",
        "s4u2self-pac-client-mismatch",
        "pa-s4u-x509-user-bad-checksum",
        "pa-s4u-x509-user-nonce",
        "pa-for-user-only",
        "pa-s4u-x509-user-empty",
        "pa-for-user-undecodable",
        "pa-s4u-x509-user",
        "s4u2proxy-no-2nd-tkt",
        "s4u2proxy-not-forwardable",
        "s4u2proxy-u2u-combo",
        "s4u2proxy-tgs-target",
        "s4u2proxy-no-header-pac",
        "s4u2proxy-header-pac",
        "s4u2proxy-no-stkt-pac",
        "s4u2proxy-evidence-mismatch",
        "s4u2proxy-local-stkt-pac",
        "u2u-no-2nd-tkt",
        "u2u-2nd-ticket-not-tgs",
        "u2u-2nd-ticket-mismatch",
        "u2u-2nd-ticket-bad-pac",
        "u2u-bad-etype",
        "u2u-success",
        "tgs-addr-mismatch",
        "tgs-forwarded-addresses",
        "u2u-2nd-ticket-foreign-realm",
        "s4u2self-renew-options",
        "pa-s4u-x509-user-truncated",
        "s4u2self-krbtgt-other",
        "tgs-locked-pac-mismatch",
        "u2u-dup-skey-tgt-based",
        "tgs-expired-addr-mismatch",
        "tgs-expired-badmatch",
        "u2u-2nd-ticket-kvno-miss",
        "u2u-2nd-ticket-disallow-svr",
        "s4u2self-cert-only",
        "tgs-forwarded-tgt-addresses",
        "as-needchange",
        "as-invalid-opts",
        "as-validate-before-preauth",
        "as-locked-out",
        "as-optimistic-encts-wrong-etype",
        "as-retransmit",
        "as-request-anonymous",
        "tgs-pac-server-cksum-wrong-enctype",
        "u2u-2nd-ticket-pac-wrong-enctype",
        "u2u-success-offered",
        "tgs-forwarded-on-non-f-tgt",
        "tgs-proxy-on-non-p-tgt",
        "tgs-postdate-on-non-postdatable",
        "tgs-postdated-is-invalid",
        "tgs-validate-invalid-non-renewable",
        "tgs-till-in-past",
        "tgs-service-expired-require-auth",
        "tgs-postdated-from",
        "tgs-no-preauth-flag",
        "tgs-hw-preauth-flag",
        "tgs-nyv-inside-skew",
        "tgs-body-authdata",
        "tgs-ad-mandatory-for-kdc",
        "tgs-body-authdata-kdc-issued-stripped",
        "tgs-body-authdata-subkey",
        "tgs-body-authdata-session-ku5",
        "tgs-tgt-and-or-kept",
        "tgs-truncated-cammac",
        "ec-outside-fast",
        "tgs-rbcd-pac-options",
        "tgs-renew-header-end-before-start",
        "as-anonymous-unsigned-authpack-named-client",
        "as-fast-hide-error-client",
        "tgs-fast-hide-client",
        "pkinit-stale-freshness",
        "tgs-referral-no-dot",
        "tgs-alternate-tgs-hierarchical",
        "tgs-renew-postdated-from",
    }
)
_LEDGER_GATE = re.compile(r"(?:scripts/)?([A-Za-z0-9._-]+-gate(?:\.sh)?)")
_LEDGER_DIFFSEND = re.compile(r"diffsend `([^`]+)`")


def _split_ledger_row(line: str) -> list[str]:
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return [p.strip() for p in re.split(r"(?<!\\)\|", inner)]


_LEDGER_KEYS = ("A1", "A2", "A3", "A4", "A5", "B1")
_PARITY_FILE = re.compile(r"^(?P<key>[ab][1-9])-[a-z0-9][a-z0-9-]*\.md$")


def _ledger_rows(text: str) -> list[tuple[int, str, list[str]]]:
    """(line number, line, cells) of every ledger table row (seven or more cells, not a header)."""
    rows = []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.startswith("|") or "MIT file:line" in line or line.startswith("| ---"):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7 or cols[5] == "verdict":
            continue
        rows.append((i, line, cols))
    return rows


def ledger_sources(root: pathlib.Path | None = None) -> list[tuple[str, str, str | None]]:
    """The ledger as (repo path, text, section key) triples, in reading order.

    Split layout, once `docs/parity/` holds section files: `docs/parity/README.md` first (the
    header: counts, verdict tally, the live diffsend list; no rows; key None), then every
    `docs/parity/<a1..a5|b1>-*.md` in sorted order, keyed by its file name. Single layout
    otherwise: `docs/mit-parity-ledger.md`, key None (its `## A1` ... headings give the sections).
    Red: a split with no README, a section file whose name or first heading gives no section or
    the wrong one, two files for one section, rows in the README, and rows left in
    `docs/mit-parity-ledger.md` beside the split.
    """
    root = ROOT if root is None else root
    single = root / "docs" / "mit-parity-ledger.md"
    parity = root / "docs" / "parity"
    sections = sorted(p for p in parity.glob("*.md") if p.name != "README.md") if parity.is_dir() else []
    if not sections:
        if not single.is_file():
            _die("missing docs/mit-parity-ledger.md (or docs/parity/)")
        return [("docs/mit-parity-ledger.md", single.read_text(encoding="utf-8"), None)]
    readme = parity / "README.md"
    if not readme.is_file():
        _die("docs/parity/ has section files but no README.md (the ledger header)")
    head = readme.read_text(encoding="utf-8")
    if _ledger_rows(head):
        _die("docs/parity/README.md holds ledger rows; rows live in the section files")
    if single.is_file() and _ledger_rows(single.read_text(encoding="utf-8")):
        _die("docs/mit-parity-ledger.md still holds rows beside docs/parity/; it must be a pointer")
    out: list[tuple[str, str, str | None]] = [("docs/parity/README.md", head, None)]
    seen: dict[str, str] = {}
    for path in sections:
        m = _PARITY_FILE.match(path.name)
        key = m.group("key").upper() if m else None
        if key not in _LEDGER_KEYS:
            _die(f"docs/parity/{path.name} names no ledger section (want a1..a5 or b1)")
        if key in seen:
            _die(f"docs/parity/{path.name} and docs/parity/{seen[key]} both hold section {key}")
        seen[key] = path.name
        text = path.read_text(encoding="utf-8")
        first = next((line for line in text.splitlines() if line.startswith("# ")), "")
        if not re.match(rf"^# {key}\b", first):
            _die(f"docs/parity/{path.name}: first heading {first!r} does not name section {key}")
        out.append((f"docs/parity/{path.name}", text, key))
    return out


def check_ledger_layout(root: pathlib.Path | None = None) -> None:
    """The ledger's files are well formed (`ledger_sources`) and no row appears twice.

    A row is identified by its MIT cite and check cells, so a moved row left behind in its old file,
    or one row copied into two files, is red in either layout.
    """
    seen: dict[tuple[str, str], str] = {}
    for name, text, _key in ledger_sources(root):
        for i, _line, cols in _ledger_rows(text):
            ident = (cols[0], cols[1])
            if ident in seen:
                _die(f"{name}:{i} repeats the ledger row at {seen[ident]}")
            seen[ident] = f"{name}:{i}"


def check_ledger_proof_column(text: str | None = None, name: str = "docs/mit-parity-ledger.md") -> None:
    """Proof cells may name existing diffsend cases / *-gate.sh or `proposed`."""
    if text is None:
        for src_name, src_text, _key in ledger_sources():
            check_ledger_proof_column(src_text, src_name)
        return
    existing = {p.name for p in SCRIPTS.glob("*-gate.sh")}
    for i, line in enumerate(text.splitlines(), 1):
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7:
            continue
        proof = cols[6]
        for clause in (c.strip() for c in proof.split(";") if c.strip()):
            proposed = bool(re.search(r"\bpropose(?:d)?\b", clause, re.I))
            for m in _LEDGER_DIFFSEND.finditer(clause):
                case = m.group(1)
                if case not in DIFFSEND_CASES and not proposed:
                    _die(
                        f"{name}:{i} proof names diffsend `{case}` "
                        "which is not a live case (use proposed)"
                    )
            for m in _LEDGER_GATE.finditer(clause):
                gate = m.group(1)
                if not gate.endswith(".sh"):
                    gate = gate + ".sh"
                if gate not in existing and not proposed:
                    _die(
                        f"{name}:{i} proof names {gate} "
                        "which is not in scripts/ (use proposed)"
                    )


_LEDGER_CASES_HDR = re.compile(
    r"The [\w-]+ live `diffsend` cases are ((?:`[^`]+`(?:,\s*)?)+)",
    re.S,
)


DIFFSEND_SRC = ROOT / "crates/krb5-tools/src/bin/diffsend.rs"


def diffsend_source_cases(src: str) -> set[str]:
    """Copy 1 of the case list: every `expect_*(&cfg, "name"` call and every
    `"case":"name"` literal the driver prints itself."""
    names = set(re.findall(r'expect_\w+\(\s*&cfg,\s*"([^"]+)"', src, re.S))
    names |= set(re.findall(r'"case":"([^"{]+)"', src))
    return names


def check_diffsend_cases(
    ledger: str | None = None, gate: str | None = None, src: str | None = None
) -> None:
    """The four copies of the diffsend case list agree: the driver's names
    (copy 1), DIFFSEND_CASES here, the ledger header, and the gate — which
    must grep every case and pin the same ratchet the driver's summary
    claims (W1-Z Z3.3)."""
    if ledger is None:
        ledger = ledger_sources()[0][1]
    gate_path = SCRIPTS / "differential-gate.sh"
    if gate is None:
        if not gate_path.is_file():
            _die("missing scripts/differential-gate.sh")
        gate = gate_path.read_text()
    if src is None:
        if not DIFFSEND_SRC.is_file():
            _die(f"missing {DIFFSEND_SRC.relative_to(ROOT)}")
        src = DIFFSEND_SRC.read_text()
    hdr = _LEDGER_CASES_HDR.search(ledger)
    if not hdr:
        _die("the ledger header (docs/parity/README.md or docs/mit-parity-ledger.md) missing live diffsend cases list")
    names = set(re.findall(r"`([^`]+)`", hdr.group(1)))
    if names != set(DIFFSEND_CASES):
        missing = sorted(DIFFSEND_CASES - names)
        extra = sorted(names - DIFFSEND_CASES)
        _die(
            f"DIFFSEND_CASES vs ledger header: missing {missing} extra {extra}"
        )
    src_names = diffsend_source_cases(src)
    if src_names != set(DIFFSEND_CASES):
        _die(
            "diffsend.rs case names vs DIFFSEND_CASES: "
            f"only in diffsend.rs {sorted(src_names - DIFFSEND_CASES)}; "
            f"only in DIFFSEND_CASES {sorted(DIFFSEND_CASES - src_names)}"
        )
    m = re.search(r"^DIFFSEND_RATCHET=(\d+)\s*$", gate, re.M)
    if not m:
        _die("scripts/differential-gate.sh missing DIFFSEND_RATCHET=N")
    n = int(m.group(1))
    if n != len(DIFFSEND_CASES):
        _die(
            f"scripts/differential-gate.sh DIFFSEND_RATCHET={n} != "
            f"DIFFSEND_CASES {len(DIFFSEND_CASES)}"
        )
    if '"case":"[^"]*","outcome":"ok"' not in gate or "$CASES_SEEN" not in gate:
        _die("scripts/differential-gate.sh must count the distinct emitted ok cases against the ratchet")
    claimed = re.search(r'"outcome":"ok","cases":(\d+)\}', src)
    if not claimed or int(claimed.group(1)) != n:
        _die(
            "diffsend.rs summary line claims "
            f"{claimed.group(1) if claimed else 'no'} cases; the gate ratchet is {n}"
        )
    grepped = set(re.findall(r'"case":"([^"]+)"', gate))
    ungrepped = sorted(DIFFSEND_CASES - grepped)
    if ungrepped:
        _die(f"scripts/differential-gate.sh asserts no line for diffsend case(s) {ungrepped}")


_VERDICT_KEYS = (
    "stricter-documented",
    "exact",
    "deviation",
    "absent",
    "deferred",
)
_HEADER_EXACT = re.compile(
    r"exact\s+(\d+)\s*·\s*stricter-documented\s+(\d+)\s*·\s*deviation\s+(\d+)"
)
_HEADER_ABSENT = re.compile(r"absent\s+(\d+)\s*·\s*deferred\s+(\d+)")
_HEADER_TOTAL = re.compile(
    r"\*\*(\d+)\*\*\s*=\s*A1\s+(\d+)\s*\+\s*A2\s+(\d+)\s*\+\s*A3\s+(\d+)"
    r"(?:\s*\+\s*A4\s+(\d+))?(?:\s*\+\s*A5\s+(\d+))?(?:\s*\+\s*B1\s+(\d+))?"
)
_RUST_ANCHOR = re.compile(
    r"(?:`)?(?:(?P<crate>[A-Za-z0-9_-]+)/(?:src/)?)?(?P<file>[A-Za-z0-9_-]+\.rs)"
    r"\s+(?:`)?(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)(?:`)?"
    r"(?::(?P<symline>\d+))?"
)
_ITEM_DEF = re.compile(
    r"^(\s*)(?:pub(?:\([^)]+\))?\s+)*"
    r"(?:(?:(?:async|const|unsafe)\s+)+fn|fn|struct|enum|const|static)"
    r"\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_STATUS_QUOTE = re.compile(r"`([A-Z][A-Z0-9_][A-Z0-9_ /-]{1,})`")
_BARE_STATUS = re.compile(r"(?<![`\w])([A-Z][A-Z0-9]*_[A-Z0-9_]+)(?![`\w])")
_MIT_CITE = re.compile(r"\b[\w.-]+\.(?:c|h|y|et|x|hin)\b")
_MIT_NA = re.compile(r"^\s*(?:n/a|absent|—|-|RFC\s*\d)", re.I)
_PROOF_UNIT = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")
_PROOF_CASE = re.compile(r"`([a-z][a-z0-9]*(?:-[a-z0-9]+)+)`")
_PROOF_GATE = re.compile(r"\b([\w-]+-gate\.sh)\b")
_FN_NAMES: set[str] | None = None
_CASE_TEXT: str | None = None


def _status_tokens(text: str) -> list[str]:
    """Backticked ALL-CAPS status words plus bare `WORD_WORD` identifiers."""
    toks = _STATUS_QUOTE.findall(text)
    toks += _BARE_STATUS.findall(_STATUS_QUOTE.sub(" ", text))
    return toks


def _fn_names() -> set[str]:
    global _FN_NAMES
    if _FN_NAMES is None:
        names: set[str] = set()
        for src in (ROOT / "crates").rglob("*.rs"):
            names.update(re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", src.read_text(errors="replace")))
        _FN_NAMES = names
    return _FN_NAMES


def _case_text() -> str:
    global _CASE_TEXT
    if _CASE_TEXT is None:
        parts = [q.read_text(errors="replace") for q in (ROOT / "scripts").glob("*-gate.sh")]
        if DIFFSEND_SRC.is_file():
            parts.append(DIFFSEND_SRC.read_text(errors="replace"))
        _CASE_TEXT = "\n".join(parts)
    return _CASE_TEXT


def _proof_exists(proof: str) -> bool:
    if any(n in _fn_names() for n in _PROOF_UNIT.findall(proof)):
        return True
    if any((ROOT / "scripts" / g).is_file() for g in _PROOF_GATE.findall(proof)):
        return True
    return any(f'"{c}"' in _case_text() or f"'{c}'" in _case_text() for c in _PROOF_CASE.findall(proof))
_CRATE_ALIASES = {
    "kdc": "krb5-kdc",
    "admin": "krb5-admin",
    "gss": "krb5-gss",
    "types": "krb5-types",
    "protocol": "krb5-protocol",
    "crypto": "krb5-crypto",
    "client": "krb5-client",
    "asn1": "krb5-asn1",
    "log": "krb5-log",
    "config": "krb5-config",
}


def recount_ledger_sections(text: str) -> dict[str, int]:
    """Row counts under `## A1` ... `## A5` / `## B1` headings (the single-file layout)."""
    counts = {k: 0 for k in _LEDGER_KEYS}
    section: str | None = None
    for line in text.splitlines():
        m = re.match(r"^## (A1|A2|A3|A4|A5|B1)\b", line)
        if m:
            section = m.group(1)
            continue
        if re.match(r"^## ", line):
            section = None
            continue
        if section is None:
            continue
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7:
            continue
        if cols[5] == "verdict":
            continue
        counts[section] += 1
    return counts


def recount_ledger_verdicts(text: str) -> dict[str, int]:
    counts = {k: 0 for k in _VERDICT_KEYS}
    for line in text.splitlines():
        if (
            not line.startswith("|")
            or "MIT file:line" in line
            or line.startswith("| ---")
        ):
            continue
        cols = _split_ledger_row(line)
        if len(cols) < 7:
            continue
        verdict = cols[5]
        if verdict == "verdict":
            continue
        for key in _VERDICT_KEYS:
            if (
                verdict == key
                or verdict.startswith(key + " ")
                or verdict.startswith(key + "(")
            ):
                counts[key] += 1
                break
    return counts


def check_ledger_tally(text: str | None = None, root: pathlib.Path | None = None) -> None:
    """Header verdict counts must equal a recount of the table cells, in total and per section.

    `text` is a single-file ledger (the fixtures); otherwise the layout `ledger_sources` finds is
    read, the header from its first file and the per-section counts from the section files.
    """
    sources = [("docs/mit-parity-ledger.md", text, None)] if text is not None else ledger_sources(root)
    hname, head, _key = sources[0]
    got = {k: 0 for k in _VERDICT_KEYS}
    for _name, body, _k in sources:
        for k, v in recount_ledger_verdicts(body).items():
            got[k] += v
    exact = _HEADER_EXACT.search(head)
    absent = _HEADER_ABSENT.search(head)
    if not exact or not absent:
        _die(f"{hname} missing verdict header tally")
    want = {
        "exact": int(exact.group(1)),
        "stricter-documented": int(exact.group(2)),
        "deviation": int(exact.group(3)),
        "absent": int(absent.group(1)),
        "deferred": int(absent.group(2)),
    }
    if got != want:
        _die(
            f"{hname} tally header "
            f"{want} != recount {got}"
        )
    total = _HEADER_TOTAL.search(head)
    if not total:
        _die(f"{hname} missing A1/A2/A3 total line")
    header_n = int(total.group(1))
    a1, a2, a3 = (int(total.group(i)) for i in (2, 3, 4))
    a4 = int(total.group(5) or 0)
    a5 = int(total.group(6) or 0)
    b1 = int(total.group(7) or 0)
    n = sum(got.values())
    parts = a1 + a2 + a3 + a4 + a5 + b1
    if header_n != n or header_n != parts:
        _die(
            f"{hname} total {header_n} "
            f"= A1 {a1} + A2 {a2} + A3 {a3} + A4 {a4} + A5 {a5} + B1 {b1} != recount {n}"
        )
    if all(key is None for _name, _body, key in sources):
        sec = recount_ledger_sections(head)
    else:
        sec = {k: 0 for k in _LEDGER_KEYS}
        for _name, body, key in sources:
            if key is not None:
                sec[key] += len(_ledger_rows(body))
    want_sec = {"A1": a1, "A2": a2, "A3": a3, "A4": a4, "A5": a5, "B1": b1}
    if sec != want_sec:
        _die(
            f"{hname} section split "
            f"header {want_sec} != recount {sec}"
        )


def _is_exact_verdict(verdict: str) -> bool:
    return (
        verdict == "exact"
        or verdict.startswith("exact ")
        or verdict.startswith("exact(")
    )


def _normalize_crate(name: str | None) -> str | None:
    if not name:
        return None
    return _CRATE_ALIASES.get(name, name)


def _src_index(
    crates: pathlib.Path | None = None,
) -> tuple[dict[str, dict[str, pathlib.Path]], dict[str, list[str]]]:
    """`crates/<crate>/src/**/*.rs` keyed by crate then basename.

    A `src/**` file its parent declares `#[cfg(test)] mod` is test scope
    (`kadm5/tests/policy.rs`): never a rust-site anchor, and no collision
    with the product file of the same basename (`kadm5/policy.rs`).
    """
    by_crate: dict[str, dict[str, pathlib.Path]] = {}
    by_base: dict[str, list[str]] = {}
    crates = ROOT / "crates" if crates is None else crates
    if not crates.is_dir():
        return by_crate, by_base
    inv = _hygiene_inventory()
    for crate_dir in sorted(crates.iterdir()):
        src = crate_dir / "src"
        if not crate_dir.is_dir() or not src.is_dir():
            continue
        crate = crate_dir.name
        src_test = {crate_dir / rel for rel in inv.cfg_test_files_in_pkg(crate_dir)}
        for p in src.rglob("*.rs"):
            if p in src_test:
                continue
            files = by_crate.setdefault(crate, {})
            prev = files.get(p.name)
            if prev is not None and prev != p:
                _die(f"duplicate {p.name} under crates/{crate}/src")
            files[p.name] = p
            if crate not in by_base.setdefault(p.name, []):
                by_base[p.name].append(crate)
    return by_crate, by_base


def _code_without_line_comment(line: str) -> str:
    out: list[str] = []
    in_str = False
    quote = ""
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c in "\"'":
            in_str = True
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _item_spans(path: pathlib.Path, symbol: str) -> list[tuple[int, int, str]]:
    """Every brace-matched definition of `symbol` in `path`, in file order."""
    lines = path.read_text(errors="replace").splitlines()
    starts = [i for i, line in enumerate(lines, 1) if (m := _ITEM_DEF.match(line)) and m.group(2) == symbol]
    return [_span_from(lines, s) for s in starts]


def _item_span(path: pathlib.Path, symbol: str) -> tuple[int, int, str] | None:
    spans = _item_spans(path, symbol)
    return spans[0] if len(spans) == 1 else None


def _span_from(lines: list[str], start: int) -> tuple[int, int, str]:
    depth = 0
    seen_brace = False
    end = start
    for i, line in enumerate(lines[start - 1 :], start):
        code = _code_without_line_comment(line)
        if not seen_brace and "{" not in code:
            if ";" in code:
                end = i
                break
            end = i
            continue
        for c in code:
            if c == "{":
                depth += 1
                seen_brace = True
            elif c == "}":
                depth -= 1
        end = i
        if seen_brace and depth <= 0:
            break
    body = "\n".join(lines[start - 1 : end])
    return start, end, body


def _resolve_src(
    crate: str | None,
    fname: str,
    by_crate: dict[str, dict[str, pathlib.Path]],
    by_base: dict[str, list[str]],
    where: str,
) -> pathlib.Path:
    crate_n = _normalize_crate(crate)
    if crate_n:
        files = by_crate.get(crate_n)
        if not files or fname not in files:
            _die(f"{where} {crate_n}/{fname} not under crates/{crate_n}/src")
        return files[fname]
    crates_for = by_base.get(fname) or []
    if not crates_for:
        _die(f"{where} {fname} not under crates/*/src")
    if len(crates_for) > 1:
        opts = ", ".join(f"{c}/{fname}" for c in sorted(crates_for))
        _die(f"{where} {fname} is ambiguous; qualify as {opts}")
    return by_crate[crates_for[0]][fname]


def check_ledger_anchors(text: str | None = None, name: str = "docs/mit-parity-ledger.md") -> None:
    """Every rust-site `file.rs symbol[:N]` resolves to one item; exact rows verify their claim.

    The MIT column must cite a MIT file (or say n/a / absent). An `exact` row's
    e_text status words (backticked, or bare `WORD_WORD` identifiers) must occur
    in the anchored item body; a row with no such word must name a proof unit,
    diffsend case or gate that exists. A symbol defined more than once in a file
    needs `:N` inside the intended definition.
    """
    checking_file = text is None
    sources = ledger_sources() if text is None else [(name, text, None)]
    by_crate, by_base = _src_index()
    n_quote = 0
    rows = [(src_name, i, cols) for src_name, body, _key in sources for i, _line, cols in _ledger_rows(body)]
    for src_name, i, cols in rows:
        site, etext = cols[3], cols[4]
        where = f"{src_name}:{i}"
        if not (_MIT_CITE.search(cols[0]) or _MIT_NA.match(cols[0])):
            _die(f"{where} MIT column names no MIT file: {cols[0].strip()}")
        bodies: list[str] = []
        saw_symbol = False
        for m in _RUST_ANCHOR.finditer(site):
            fname = m.group("file")
            symbol = m.group("symbol")
            lineno = m.group("symline")
            if not symbol:
                continue
            saw_symbol = True
            path = _resolve_src(m.group("crate"), fname, by_crate, by_base, where)
            spans = _item_spans(path, symbol)
            if not spans:
                _die(f"{where} {fname} {symbol} is not an item in {path}")
            if lineno:
                n = int(lineno)
                inside = [s for s in spans if s[0] <= n <= s[1]]
                if not inside:
                    ranges = ", ".join(f"{s[0]}-{s[1]}" for s in spans)
                    _die(f"{where} {fname}:{n} is not inside {symbol} ({ranges})")
                spans = inside
            if len(spans) > 1:
                starts = ", ".join(str(s[0]) for s in spans)
                _die(
                    f"{where} {fname} {symbol} is defined {len(spans)} times "
                    f"(lines {starts}); add :N inside the intended item"
                )
            bodies.append(spans[0][2])
        if _is_exact_verdict(cols[5]):
            if not saw_symbol:
                _die(f"{where} exact row has no rust-site anchor")
            joined = "\n".join(bodies)
            checked = 0
            for q in _status_tokens(etext):
                ident = re.sub(r"[^A-Z0-9]+", "_", q).strip("_")
                checked += 1
                if q not in joined and ident not in joined:
                    _die(f"{where} `{q}` not in rust-site item body")
            n_quote += checked
            if checked == 0 and not _proof_exists(cols[6]):
                _die(f"{where} exact row verifies nothing: no e_text status word, no existing proof unit or cell")
    if checking_file and n_quote == 0:
        _die("the ledger executed no quote checks")


_MIT_CITE_FILE = re.compile(r"\b([\w.-]+\.(?:c|h|y|et|x|hin))\b")
_MIT_IDENTS: dict[str, tuple[set[str], set[str], set[str]]] = {}


def _mit_index(src: pathlib.Path) -> tuple[set[str], set[str], set[str]]:
    """Basenames, identifiers and quoted status strings of a MIT source tree."""
    key = str(src)
    if key not in _MIT_IDENTS:
        names: set[str] = set()
        idents: set[str] = set()
        strings: set[str] = set()
        suffixes: set[str] = set()
        for f in src.rglob("*"):
            if f.suffix not in {".c", ".h", ".y", ".et", ".x", ".hin"} or not f.is_file():
                continue
            names.add(f.name)
            body = f.read_text(errors="replace")
            idents.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))
            strings.update(re.findall(r'"([A-Z][A-Z0-9 _/-]+)"', body))
        for ident in idents:
            parts = ident.split("_")
            suffixes.update("_".join(parts[k:]) for k in range(1, len(parts)))
        _MIT_IDENTS[key] = (names, idents | suffixes, strings)
    return _MIT_IDENTS[key]


def check_ledger_mit_cites(
    text: str | None = None, src: pathlib.Path | None = None, name: str = "docs/mit-parity-ledger.md"
) -> None:
    """Every MIT cite names a file of the tree; every MIT status word is an identifier there, a `_`-suffix of one, or a status string."""
    if src is None:
        env = os.environ.get("KERBER_MIT_SRC")
        if not env:
            # R2-T8: don't skip the MIT-anchor verification silently.
            print(
                "ci-policy: KERBER_MIT_SRC unset — skipping MIT-anchor "
                "verification (ledger-mit job sets it)",
                file=sys.stderr,
            )
            return
        src = pathlib.Path(env)
    if not src.is_dir():
        _die(f"KERBER_MIT_SRC {src} is not a directory")
    sources = ledger_sources() if text is None else [(name, text, None)]
    names, idents, strings = _mit_index(src)
    rows = [(src_name, i, cols) for src_name, body, _key in sources for i, _line, cols in _ledger_rows(body)]
    for src_name, i, cols in rows:
        where = f"{src_name}:{i}"
        for f in _MIT_CITE_FILE.findall(cols[0]):
            if f not in names:
                _die(f"{where} MIT cite {f} is not a file under {src}")
        for tok in _status_tokens(cols[2]):
            ident = re.sub(r"[^A-Z0-9]+", "_", tok).strip("_")
            if tok not in strings and ident not in idents and tok.strip() not in idents:
                _die(f"{where} MIT status `{tok}` is neither an identifier nor a status string in {src}")


# W1-K M2b: after the differential oracle's whitelist mechanism is deleted, no
# case may be excused by name. Ban the mechanism identifiers from the diffsend
# driver and the gate scripts. The tokens are case-precise so a gate's runtime
# assertion that the output has no `"whitelist"` key is not itself flagged.
_CASE_WHITELIST = re.compile(r"\bWhitelist\b|whitelisted|whitelist_hits|skip_cases|known_diff")


def check_no_case_whitelists(text: str | None = None, name: str = "diffsend.rs") -> None:
    """Fail if a differential whitelist mechanism reappears."""

    def scan(txt: str, rel: str) -> None:
        for i, line in enumerate(txt.splitlines(), 1):
            m = _CASE_WHITELIST.search(line)
            if m:
                _die(f"{rel}:{i} banned differential whitelist token {m.group(0)!r} (M2b)")

    if text is not None:
        scan(text, name)
        return
    if DIFFSEND_SRC.is_file():
        scan(DIFFSEND_SRC.read_text(), str(DIFFSEND_SRC.relative_to(ROOT)))
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
    # R2-T7: the differential compare itself (diff.rs) and the shared gate
    # helpers are where a case-name whitelist would most plausibly reappear, so
    # scan them too, not only the driver and the top-level gates.
    for path in sorted((ROOT / "crates/krb5-protocol/src").glob("*.rs")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
    for path in sorted((SCRIPTS / "lib").glob("*.sh")):
        scan(path.read_text(), str(path.relative_to(ROOT)))
