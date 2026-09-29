"""The self-test of the public-docs checks."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile

from ..common import ROOT, _die, _scratch_root
from ..docs import (
    DOCS_SIZE_LIMIT, check_changelog_headings, check_doc_file_cites, check_doc_links, check_docs_size,
    check_no_plan_section_names, check_testing_doc_budgets, doc_link_violations, gate_doc_violations, gate_placements,
)
from ..workflows import Workflow
from .common import _must_die, _must_die_msg, good_toml


def _self_test_docs() -> None:
    check_doc_file_cites({"docs/testing.md": "see `crates/krb5-kdc/src/lib.rs`\n"}, ROOT)
    _must_die(
        check_doc_file_cites,
        {"docs/testing.md": "see `crates/krb5-kdc/tests/ad_pac.rs`\n"},
        ROOT,
    )
    # The S5 doc checks on a temp tree: links and anchors, recursive cites, the CHANGELOG
    # headings, the size limits, and docs/gates.md against the scripts and workflows.
    droot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (droot / "docs" / "sub").mkdir(parents=True)
        (droot / "docs" / "a.md").write_text("# A\n\n## Setup — first\n\n## Setup — first\n", encoding="utf-8")
        readme = droot / "README.md"
        readme.write_text(
            "See [a](docs/a.md), [setup](docs/a.md#setup--first), [again](docs/a.md#setup--first-1),\n"
            "[site](https://example.org/x) and `[code](nowhere.md)`.\n\n```\n[fenced](nowhere.md)\n```\n",
            encoding="utf-8",
        )
        if doc_link_violations(droot):
            _die(f"check_doc_links must accept files, slugs, repeats, URLs and code: {doc_link_violations(droot)}")
        readme.write_text("See [gone](docs/gone.md).\n", encoding="utf-8")
        _must_die_msg("docs/gone.md (no such file)", check_doc_links, droot)
        readme.write_text("See [bad](docs/a.md#setup).\n", encoding="utf-8")
        _must_die_msg("docs/a.md#setup (no such anchor)", check_doc_links, droot)
        readme.write_text("See [a](docs/a.md).\n", encoding="utf-8")
        (droot / "docs" / "sub" / "deep.md").write_text("see `docs/missing.md`\n", encoding="utf-8")
        _must_die_msg("docs/sub/deep.md: `docs/missing.md`", check_doc_file_cites, None, droot)
        (droot / "docs" / "sub" / "deep.md").write_text("see `docs/a.md`\n", encoding="utf-8")
        (droot / "CONTRIBUTING.md").write_text("see `scripts/none.sh`\n", encoding="utf-8")
        _must_die_msg("CONTRIBUTING.md: `scripts/none.sh`", check_doc_file_cites, None, droot)
        (droot / "CONTRIBUTING.md").write_text("see `docs/a.md`\n", encoding="utf-8")
        check_doc_file_cites(None, droot)
        log = "## [Unreleased]\n\n### Added\n\n### Tests and CI\n\n### How to add an entry\n\n### W3-S4 comments\n"
        check_changelog_headings(log, allow=1)
        _must_die_msg("1 ### headings outside", check_changelog_headings, log, allow=0)
        check_changelog_headings(log.replace("### W3-S4 comments\n", ""), allow=0)
        _must_die_msg("1 ### headings outside", check_changelog_headings, "### Added in W3\n### How to add one\n", allow=0)
        check_changelog_headings("### Added\n### Tests and CI\n### How to add an entry\n", allow=0)
        (droot / "docs" / "big.md").write_text("x" * (DOCS_SIZE_LIMIT + 1), encoding="utf-8")
        check_docs_size(droot, allow=1, changelog_max=10)
        _must_die_msg("1 docs file(s) over", check_docs_size, droot, allow=0, changelog_max=10)
        (droot / "docs" / "big.md").unlink()
        (droot / "CHANGELOG.md").write_text("y" * 11, encoding="utf-8")
        _must_die_msg("over its ceiling 10", check_docs_size, droot, allow=0, changelog_max=10)
        check_docs_size(droot, allow=0, changelog_max=11)
    finally:
        subprocess.run(["rm", "-rf", str(droot)], check=False)
    gates = ["a-gate.sh", "b-gate.sh", "s-gate.sh", "w-gate.sh"]
    places = {
        "a-gate.sh": [("ci:harness", "fail-red")],
        "b-gate.sh": [("ci:soak", "soft"), ("soak:soak", "nightly")],
    }
    stubs_fx = frozenset({"s-gate.sh", "w-gate.sh"})
    head = "| Gate | Oracle | Workflow | Lane | Asserts |\n| --- | --- | --- | --- | --- |\n"
    rows_ok = {
        "a": "| `scripts/a-gate.sh` | MIT | `ci:harness` | fail-red | the wire code |\n",
        "b": "| `scripts/b-gate.sh` | none | `ci:soak`, `soak:soak` | soft, nightly | no leak |\n",
        "s": "| `scripts/s-gate.sh` | Windows | stub | — | exits 2 |\n",
        "w": "| `scripts/w-gate.sh` | MIT | stub | — | runs a and b |\n",
    }
    good_doc = head + "".join(rows_ok.values())
    got = gate_doc_violations(good_doc, gates, places, stubs_fx)
    if got:
        _die(f"check_gate_documented must accept a true table: {got}")
    for label, doc, needle in (
        ("missing row", head + rows_ok["a"] + rows_ok["b"] + rows_ok["s"], "w-gate.sh: no row"),
        ("two rows", good_doc + rows_ok["a"], "a-gate.sh: two rows"),
        ("wrong workflow", good_doc.replace("`ci:harness` | fail-red", "`ci:harness-2` | fail-red"), "a-gate.sh: workflow"),
        ("wrong lane", good_doc.replace("soft, nightly", "fail-red"), "b-gate.sh: lane"),
        ("bad oracle", good_doc.replace("| MIT | `ci:harness`", "| Kerberos | `ci:harness`"), "a-gate.sh: oracle"),
        ("empty asserts", good_doc.replace("the wire code", " "), "a-gate.sh: empty assertion"),
        ("unknown gate", good_doc + "| `scripts/z-gate.sh` | MIT | stub | — | x |\n", "z-gate.sh: row for a gate"),
        ("cell count", good_doc.replace("| exits 2 |", "|"), "s-gate.sh: 4 cells"),
    ):
        if not any(needle in v for v in gate_doc_violations(doc, gates, places, stubs_fx)):
            _die(f"check_gate_documented must flag {label}")
    if gate_placements()["kdc-gate.sh"] != [("ci:harness", "fail-red")]:
        _die(f"gate_placements must read kdc-gate.sh as ci:harness fail-red: {gate_placements()['kdc-gate.sh']}")
    # Every lane gate_placements reads, and the wrapper row of a DOCUMENTED_STUBS wrapper.
    lanes_wf = [
        Workflow(pathlib.Path("ci.yml"),
                 "name: ci\non:\n  push:\n    branches: [main]\njobs:\n  harness:\n    steps:\n"
                 "      - run: ./scripts/red-gate.sh\n      - run: skip2 ./scripts/two-gate.sh\n"
                 "  slo:\n    continue-on-error: true\n    steps:\n      - run: ./scripts/soft-gate.sh\n"),
        Workflow(pathlib.Path("peers.yml"),
                 "name: peers\non:\n  schedule:\n    - cron: '0 3 * * *'\njobs:\n  lab:\n    steps:\n"
                 "      - run: ./scripts/night-gate.sh\n"),
    ]
    lanes_want = {
        "red-gate.sh": [("ci:harness", "fail-red")], "two-gate.sh": [("ci:harness", "skip2")],
        "soft-gate.sh": [("ci:slo", "soft")], "night-gate.sh": [("peers:lab", "nightly")],
    }
    if gate_placements(lanes_wf) != lanes_want:
        _die(f"gate_placements must read fail-red, skip2, soft and nightly: {gate_placements(lanes_wf)}")
    wrap_row = "| `scripts/kadmin-gate.sh` | MIT | wrapper | — | runs the kadmin legs |\n"
    wrap_gates = {"kadmin-gate.sh": "#!/bin/sh\n"}
    if gate_doc_violations(head + wrap_row, wrap_gates, {}, frozenset({"kadmin-gate.sh"})):
        _die("a wrapper's row must name `wrapper`")
    if not any("kadmin-gate.sh: workflow" in v for v in gate_doc_violations(
            head + wrap_row.replace("| wrapper |", "| stub |"), wrap_gates, {}, frozenset({"kadmin-gate.sh"}))):
        _die("a wrapper's row that says `stub` must be flagged")
    check_doc_file_cites({"CHANGELOG.md": "see `crates/missing/nope.rs`\n"}, ROOT)
    good_docs = (
        "Tier 1 test harness mit-extra msrv audit ledger-mit mit-image doc "
        "ci-budget.toml 270\nTier 2 slo chaos soak\nTier 3 budget.yml\n"
    )
    check_testing_doc_budgets(good_docs, "see ci-budget.toml tier rule\n", good_toml)
    _must_die(
        check_testing_doc_budgets,
        "no tiers here\n",
        "see ci-budget.toml\n",
        good_toml,
    )
    # No working-plan section name in a public doc; an RFC section is not one.
    ps_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (ps_root / "docs").mkdir()
        (ps_root / "docs" / "x.md").write_text("RFC 4120 \u00a75.4.1 applies.\n", encoding="utf-8")
        check_no_plan_section_names(ps_root)
        (ps_root / "docs" / "x.md").write_text("Moved to \u00a7 Deferred.\n", encoding="utf-8")
        _must_die_msg("1 working-plan section name(s)", check_no_plan_section_names, ps_root)
        (ps_root / "docs" / "x.md").write_text('See \u00a7 "S6 brief".\n', encoding="utf-8")
        _must_die_msg("1 working-plan section name(s)", check_no_plan_section_names, ps_root)
    finally:
        subprocess.run(["rm", "-rf", str(ps_root)], check=False)
