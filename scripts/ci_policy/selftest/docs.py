"""The self-test of the public-docs checks."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile

from ..common import ROOT, _die, _scratch_root
from ..docs import (
    DOCS_SIZE_LIMIT, check_changelog_headings, check_cited_scripts, check_doc_file_cites, check_doc_links,
    check_docs_size, doc_link_violations,
)
from .common import _die, _must_die, _must_die_msg


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
        section = "## [Unreleased]\n\n"
        (droot / "CHANGELOG.md").write_text(section + "## [1.0.0]\n" + ("y" * 4000), encoding="utf-8")
        cap = len(section.encode())
        _must_die_msg(f"over its ceiling {cap - 1}", check_docs_size, droot, allow=0, changelog_max=cap - 1)
        check_docs_size(droot, allow=0, changelog_max=cap)
    finally:
        subprocess.run(["rm", "-rf", str(droot)], check=False)
    check_doc_file_cites({"CHANGELOG.md": "see `crates/missing/nope.rs`\n"}, ROOT)
    check_doc_file_cites({"docs/parity/a1-tgs.md": "see `scripts/no-such-gate.sh`\n"}, ROOT)
    check_cited_scripts({"docs/parity/a1-tgs.md": "see `scripts/differential-gate.sh`\n"}, ROOT)
    _must_die_msg(
        "docs/parity/a1-tgs.md: `scripts/no-such-gate.sh`",
        check_cited_scripts,
        {"docs/parity/a1-tgs.md": "see `scripts/no-such-gate.sh`\n"},
        ROOT,
    )
    _must_die_msg(
        "docs/gates.md: `scripts/no-such-gate.sh`",
        check_cited_scripts,
        {"docs/gates.md": "see scripts/no-such-gate.sh\n"},
        ROOT,
    )
