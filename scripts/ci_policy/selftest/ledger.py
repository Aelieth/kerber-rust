"""The self-test of the parity-ledger and diffsend checks."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

from ..common import ROOT, SCRIPTS, _die, _scratch_root
from ..ledger import (
    DIFFSEND_CASES, _item_span, _item_spans, _src_index, check_diffsend_cases, check_ledger_anchors,
    check_ledger_layout, check_ledger_mit_cites, check_ledger_proof_column, check_ledger_tally,
    check_no_case_whitelists, ledger_sources,
)
from .common import _must_die, _must_die_msg


def _self_test_ledger() -> None:
    ledger_ok = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname`; `scripts/expire-gate.sh` |\n"
        "| kdc_util.c:2 | x | y | z | w | absent | proposed: diffsend `no-such-case`; proposed kdc-lookaside-gate.sh |\n"
    )
    check_ledger_proof_column(ledger_ok)
    ledger_bad_case = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `no-such-case` |\n"
    )
    _must_die(check_ledger_proof_column, ledger_bad_case)
    ledger_bad_gate = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | kdc-lookaside-gate.sh |\n"
    )
    _must_die(check_ledger_proof_column, ledger_bad_gate)
    ledger_proposed_sibling = (
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | proposed: diffsend `no-such-case`; kdc-lookaside-gate.sh |\n"
    )
    _must_die(check_ledger_proof_column, ledger_proposed_sibling)
    cases_hdr = (
        "The thirty-three live `diffsend` cases are "
        + ", ".join(f"`{c}`" for c in sorted(DIFFSEND_CASES))
        + ".\n"
    )
    gate_n = (
        f"DIFFSEND_RATCHET={len(DIFFSEND_CASES)}\n"
        "CASES_SEEN=\"$(grep -o '\"case\":\"[^\"]*\",\"outcome\":\"ok\"' <<<\"$DIFF\" | sort -u | wc -l)\"\n"
        '[ "$CASES_SEEN" = "$DIFFSEND_RATCHET" ] || die "x"\n'
        + "".join(f"grep -q '\"case\":\"{c}\"' <<<\"$DIFF\" || die x\n" for c in sorted(DIFFSEND_CASES))
    )
    src_n = (
        "".join(f'expect_error(&cfg, "{c}", &req, 1)?;\n' for c in sorted(DIFFSEND_CASES))
        + f'println!(r#"{{{{"event":"diffsend","outcome":"ok","cases":{len(DIFFSEND_CASES)}}}}}"#);\n'
    )
    check_diffsend_cases(cases_hdr, gate_n, src_n)
    _must_die(check_diffsend_cases, "no header here", gate_n, src_n)
    _must_die(check_diffsend_cases, cases_hdr, 'echo "no cases pin"\n', src_n)
    gate_short = gate_n.replace(f"DIFFSEND_RATCHET={len(DIFFSEND_CASES)}", "DIFFSEND_RATCHET=29")
    _must_die(check_diffsend_cases, cases_hdr, gate_short, src_n)
    # Z3.3: the gate must count, not trust the literal; must grep every case;
    # the driver's names and its summary literal must match the ratchet.
    _must_die(check_diffsend_cases, cases_hdr, gate_n.replace("$CASES_SEEN", "$X"), src_n)
    _must_die(
        check_diffsend_cases, cases_hdr, gate_n.replace('"case":"garbage-pdu"', '"case":"gone"'), src_n
    )
    _must_die(check_diffsend_cases, cases_hdr, gate_n, src_n + 'expect_drop(&cfg, "stray-case", &req)?;\n')
    _must_die(
        check_diffsend_cases,
        cases_hdr,
        gate_n,
        src_n.replace(f'"cases":{len(DIFFSEND_CASES)}', '"cases":7'),
    )
    ledger_tally_ok = (
        "Counts:\n"
        "**1** = A1 1 + A2 0 + A3 0.\n"
        "exact 1 · stricter-documented 0 · deviation 0 ·\n"
        "absent 0 · deferred 0.\n"
        "## A1 — tgs\n"
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
        "## A2 — as\n"
        "## A3 — fast\n"
    )
    check_ledger_tally(ledger_tally_ok)
    ledger_tally_bad = ledger_tally_ok.replace(
        "exact 1 · stricter-documented 0 · deviation 0 ·",
        "exact 49 · stricter-documented 0 · deviation 95 ·",
    )
    _must_die(check_ledger_tally, ledger_tally_bad)
    ledger_tally_no_total = (
        "Counts:\n"
        "exact 1 · stricter-documented 0 · deviation 0 ·\n"
        "absent 0 · deferred 0.\n"
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
    )
    _must_die(check_ledger_tally, ledger_tally_no_total)
    ledger_tally_ok_sections = (
        "Counts:\n"
        "**1** = A1 1 + A2 0 + A3 0.\n"
        "exact 1 · stricter-documented 0 · deviation 0 ·\n"
        "absent 0 · deferred 0.\n"
        "## A1 — tgs\n"
        "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
        "## A2 — as\n"
        "## A3 — fast\n"
    )
    check_ledger_tally(ledger_tally_ok_sections)
    ledger_tally_wrong_split = ledger_tally_ok_sections.replace(
        "**1** = A1 1 + A2 0 + A3 0.",
        "**1** = A1 0 + A2 1 + A3 0.",
    )
    _must_die(check_ledger_tally, ledger_tally_wrong_split)
    # The ledger in either layout: one file, or docs/parity/ with a README header and one or more
    # files per section keyed by their names. A row's identity is its MIT cite and check cells.
    lroot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (lroot / "docs").mkdir()
        single = lroot / "docs" / "mit-parity-ledger.md"
        single.write_text(ledger_tally_ok_sections, encoding="utf-8")
        check_ledger_layout(lroot)
        check_ledger_tally(root=lroot)
        table = (
            "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
        )
        row_a1 = "| kdc_util.c:1 | x | y | z | w | exact | diffsend `unknown-cname` |\n"
        row_b1 = "| gic_pwd.c:2 | v | y | z | w | deviation | proposed |\n"
        head = (
            "Counts:\n**2** = A1 1 + A2 0 + A3 0 + A4 0 + A5 0 + B1 1.\n"
            "exact 1 · stricter-documented 0 · deviation 1 ·\nabsent 0 · deferred 0.\n"
        )
        parity = lroot / "docs" / "parity"
        parity.mkdir()
        (parity / "a1-tgs.md").write_text("# A1 — tgs\n\n" + table + row_a1, encoding="utf-8")
        (parity / "b1-client.md").write_text("# B1 — client\n\n" + table + row_b1, encoding="utf-8")
        _must_die_msg("but no README.md", ledger_sources, lroot)
        (parity / "README.md").write_text(head, encoding="utf-8")
        _must_die_msg("still holds rows beside docs/parity/", ledger_sources, lroot)
        single.write_text("The ledger is under docs/parity/.\n", encoding="utf-8")
        check_ledger_layout(lroot)
        check_ledger_tally(root=lroot)
        if [k for _n, _t, k in ledger_sources(lroot)] != [None, "A1", "B1"]:
            _die("ledger_sources must read the README, then the section files in order")
        (parity / "b1-client.md").write_text(
            "# B1 — client\n\n" + table + row_b1 + row_a1, encoding="utf-8"
        )
        _must_die_msg("repeats the ledger row at docs/parity/a1-tgs.md:5", check_ledger_layout, lroot)
        (parity / "b1-client.md").write_text("# B1 — client\n\n" + table + row_b1, encoding="utf-8")
        (parity / "a2-as.md").write_text("# A1 — as\n\n" + table, encoding="utf-8")
        _must_die_msg("does not name section A2", ledger_sources, lroot)
        (parity / "a2-as.md").unlink()
        (parity / "c1-other.md").write_text("# C1 — other\n\n" + table, encoding="utf-8")
        _must_die_msg("names no ledger section", ledger_sources, lroot)
        (parity / "c1-other.md").unlink()
        # A section may span files: A1 in a1-more.md and a1-tgs.md, read in name order, its count
        # summed over both. A row in both files, or a second file whose heading names another
        # section, stays red.
        row_a1b = "| kdc_util.c:3 | u | y | z | w | exact | diffsend `unknown-cname` |\n"
        (parity / "a1-more.md").write_text("# A1 — more\n\n" + table + row_a1b, encoding="utf-8")
        head2 = head.replace("**2** = A1 1", "**3** = A1 2").replace("exact 1 ·", "exact 2 ·")
        (parity / "README.md").write_text(head2, encoding="utf-8")
        check_ledger_layout(lroot)
        check_ledger_tally(root=lroot)
        if [n for n, _t, _k in ledger_sources(lroot)][1:3] != ["docs/parity/a1-more.md", "docs/parity/a1-tgs.md"] \
                or [k for _n, _t, k in ledger_sources(lroot)] != [None, "A1", "A1", "B1"]:
            _die("ledger_sources must read every file of a section, in name order")
        (parity / "README.md").write_text(head2.replace("A1 2 + A2 0", "A1 1 + A2 1"), encoding="utf-8")
        _must_die_msg("section split", check_ledger_tally, None, lroot)
        (parity / "README.md").write_text(head2, encoding="utf-8")
        (parity / "a1-more.md").write_text("# A1 — more\n\n" + table + row_a1b + row_a1, encoding="utf-8")
        _must_die_msg(
            "docs/parity/a1-tgs.md:5 repeats the ledger row at docs/parity/a1-more.md:6", check_ledger_layout, lroot
        )
        (parity / "a1-more.md").write_text("# A2 — more\n\n" + table + row_a1b, encoding="utf-8")
        _must_die_msg("a1-more.md: first heading '# A2 — more' does not name section A1", ledger_sources, lroot)
        (parity / "a1-more.md").unlink()
        (parity / "README.md").write_text(head + table + row_a1, encoding="utf-8")
        _must_die_msg("README.md holds ledger rows", ledger_sources, lroot)
        (parity / "README.md").write_text(head, encoding="utf-8")
        (parity / "README.md").write_text(head.replace("A1 1 + A2 0", "A1 0 + A2 1"), encoding="utf-8")
        _must_die_msg("section split", check_ledger_tally, None, lroot)
    finally:
        subprocess.run(["rm", "-rf", str(lroot)], check=False)
    def _row(site: str, etext: str = "—", verdict: str = "exact", proof: str = "none") -> str:
        return (
            "| MIT file:line | check | MIT | Rust | e_text | verdict | proof |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
            f"| kdc_util.c:1 | x | y | {site} | {etext} | {verdict} | {proof} |\n"
        )

    unit = "`udp_oversize_reply_is_response_too_big`"

    check_ledger_anchors(_row("none", verdict="absent"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", proof=unit))
    check_ledger_anchors(_row("krb5-kdc/listen.rs MAX_TCP_REQUEST", proof="`kdc-gate.sh:1`"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", proof="`as-success`"))
    check_ledger_anchors(
        _row("krb5-kdc/status.rs NEEDED_PREAUTH", "`NEEDED_PREAUTH`")
    )
    check_ledger_anchors(
        _row("krb5-kdc/preauth.rs armor_key_from_ap", "`NOT_US` / `TKT_NYV`")
    )
    _must_die(check_ledger_anchors, _row("missing.rs no_such_fn", "`PROCESS_TGS`"))
    fake_mit = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (fake_mit / "kdc").mkdir()
        (fake_mit / "kdc" / "kdc_util.c").write_text('int x = KRB_ERR_RESPONSE_TOO_BIG;\nstatus = "CLIENT KEY EXPIRED";\n')
        mit_row = _row("krb5-kdc/listen.rs handle_tcp", proof=unit).replace("| x | y |", "| x | `KRB_ERR_RESPONSE_TOO_BIG` `CLIENT KEY EXPIRED` |")
        check_ledger_mit_cites(mit_row, fake_mit)
        check_ledger_mit_cites(mit_row.replace("KRB_ERR_RESPONSE_TOO_BIG", "RESPONSE_TOO_BIG"), fake_mit)
        _must_die(check_ledger_mit_cites, mit_row.replace("KRB_ERR_RESPONSE_TOO_BIG", "RESPONSE_TOO_BI"), fake_mit)
        _must_die(check_ledger_mit_cites, mit_row.replace("CLIENT KEY EXPIRED", "CLIENT KEY EXPIRE"), fake_mit)
        _must_die(check_ledger_mit_cites, mit_row.replace("kdc_util.c:1", "no_such.c:1"), fake_mit)
    finally:
        subprocess.run(["rm", "-rf", str(fake_mit)], check=False)
    _must_die(check_ledger_anchors, _row("krb5-kdc/plugins.rs advertise", verdict="absent"))
    # Several impls define advertise. Pin a line inside one of them rather
    # than a fixed number, so a module-header shift does not move the pin
    # out of the item.
    advertise_spans = _item_spans(ROOT / "crates/krb5-kdc/src/plugins.rs", "advertise")
    advertise_at = next(s[0] for s in advertise_spans if s[1] - s[0] > 5)
    check_ledger_anchors(
        _row(f"krb5-kdc/plugins.rs advertise:{advertise_at}", verdict="absent")
    )
    _must_die(check_ledger_anchors, _row("krb5-kdc/plugins.rs advertise:1", verdict="absent"))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp", "no status word"))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp", proof="`no_such_unit_anywhere`"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", "no status word", proof=unit))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp", "NOT_A_REAL_STATUS 60"))
    check_ledger_anchors(_row("krb5-kdc/listen.rs handle_tcp", "FIELD_TOOLONG 52"))
    _must_die(
        check_ledger_anchors,
        _row("krb5-kdc/listen.rs handle_tcp", "`TKT_NYV`").replace("| kdc_util.c:1 |", "| issue.rs:1 |"),
    )
    check_ledger_anchors(
        _row("krb5-kdc/listen.rs handle_tcp", "x", "absent").replace("| kdc_util.c:1 |", "| n/a (harness) |")
    )
    _must_die(check_ledger_anchors, _row("issue.rs no_such_fn_at_all"))
    _must_die(check_ledger_anchors, _row("krb5-kdc/listen.rs handle_tcp:1"))
    _must_die(check_ledger_anchors, _row("listen.rs handle_tcp"))
    _must_die(check_ledger_anchors, _row("lib.rs propagate", verdict="deviation"))
    _must_die(check_ledger_anchors, _row("none"))
    _must_die(
        check_ledger_anchors,
        _row("krb5-kdc/listen.rs handle_tcp", "`TKT_NYV`"),
    )
    handle_span = _item_span(ROOT / "crates/krb5-kdc/src/listen.rs", "handle_tcp")
    if handle_span is None or not handle_span[2].startswith("fn handle_tcp(") or not handle_span[2].rstrip().endswith("}") or handle_span[1] - handle_span[0] < 20:
        raise AssertionError(f"handle_tcp must resolve to a brace-matched fn body, got {handle_span}")
    max_span = _item_span(ROOT / "crates/krb5-kdc/src/listen.rs", "MAX_TCP_REQUEST")
    if max_span is None:
        raise AssertionError("MAX_TCP_REQUEST const must resolve")
    # a `#[cfg(test)] mod` child that shares a basename with a product file
    # (`kadm5/tests/policy.rs` next to `kadm5/policy.rs`): the index keeps the
    # product file only; without the cfg(test) the twin is a duplicate
    fake_crates = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        a = fake_crates / "x" / "src" / "a"
        (a / "tests").mkdir(parents=True)
        (fake_crates / "x" / "src" / "lib.rs").write_text("mod a;\n")
        (fake_crates / "x" / "src" / "a.rs").write_text("mod policy;\n#[cfg(test)]\nmod tests;\n")
        (a / "policy.rs").write_text("pub(super) fn policy_mask_err() {}\n")
        (a / "tests" / "mod.rs").write_text("mod policy;\n")
        (a / "tests" / "policy.rs").write_text("#[test]\nfn t() {}\n")
        by_crate, by_base = _src_index(fake_crates)
        if by_crate["x"].get("policy.rs") != a / "policy.rs" or by_base.get("policy.rs") != ["x"]:
            raise AssertionError("src index must keep the product policy.rs and skip its cfg(test) twin")
        if "mod.rs" in by_crate["x"]:
            raise AssertionError("src index must skip a cfg(test) tests/mod.rs")
        (fake_crates / "x" / "src" / "a.rs").write_text("mod policy;\nmod tests;\n")
        _must_die(_src_index, fake_crates)
    finally:
        subprocess.run(["rm", "-rf", str(fake_crates)], check=False)
    check_no_case_whitelists(
        'compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt)?;\n'
        'if echo "$DIFF" | grep -q \'"whitelist"\'; then die "banned"; fi\n',
        "ok-diffsend.rs",
    )
    _must_die(
        check_no_case_whitelists,
        "let wl = Whitelist::default();\n",
        "wl-diffsend.rs",
    )
    _must_die(
        check_no_case_whitelists,
        'println!("whitelist:{:?}", ok.whitelisted);\n',
        "field-diffsend.rs",
    )
    _must_die(
        check_no_case_whitelists,
        "for c in skip_cases; do :; done\n",
        "skip-gate.sh",
    )

    env = os.environ.copy()
    env.update({"ROOT": str(ROOT), "KERBER_NO_IMAGE": "1"})
    dirty_refuse = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; dirty=yes; unit_guard_dirty',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )
    if dirty_refuse.returncode != 1:
        _die("unit_guard_dirty must refuse dirty=yes without KERBER_UNIT_ALLOW_DIRTY")
    dirty_allow = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; dirty=yes; '
            "KERBER_UNIT_ALLOW_DIRTY=1 unit_guard_dirty",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )
    if dirty_allow.returncode != 0 or "override=KERBER_UNIT_ALLOW_DIRTY" not in (
        dirty_allow.stdout or ""
    ):
        _die("unit_guard_dirty must stamp override=KERBER_UNIT_ALLOW_DIRTY when allowed")
    dirty_ok = subprocess.run(
        [
            "bash",
            "-c",
            '. "$ROOT/scripts/lib/unit-evidence.sh"; dirty=no; unit_guard_dirty',
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
    )
    if dirty_ok.returncode != 0:
        _die("unit_guard_dirty must accept dirty=no")

    red_py = SCRIPTS / "lib" / "unit-red-check.py"
    if not red_py.is_file():
        _die("missing scripts/lib/unit-red-check.py")
    red_fail = subprocess.run(
        [sys.executable, str(red_py), "foo"],
        input="test foo ... FAILED\n",
        capture_output=True,
        check=False,
        text=True,
    )
    if red_fail.returncode != 0:
        _die("unit-red-check.py must accept all FAILED")
    red_pass = subprocess.run(
        [sys.executable, str(red_py), "foo"],
        input="test foo ... ok\n",
        capture_output=True,
        check=False,
        text=True,
    )
    if red_pass.returncode != 1 or "vacuous red" not in (red_pass.stderr or ""):
        _die("unit-red-check.py must reject a passed test")
    red_empty = subprocess.run(
        [sys.executable, str(red_py), "foo"],
        input="",
        capture_output=True,
        check=False,
        text=True,
    )
    if red_empty.returncode != 1:
        _die("unit-red-check.py must reject empty cargo output")

    hdr_mismatch = "The thirty-three live `diffsend` cases are `garbage-pdu`.\n"
    _must_die(check_diffsend_cases, hdr_mismatch, gate_n, src_n)
