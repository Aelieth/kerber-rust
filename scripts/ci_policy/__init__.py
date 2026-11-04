"""ci-policy's entry point: `main()` runs the self-test, then the kept checks."""

from __future__ import annotations

import os
import sys
import tempfile

from .comments import (
    check_mit_anchor_form, check_mit_anchor_truth, check_no_docs_process_tags, check_no_process_history,
)
from .common import WORKFLOWS, _die, _scratch_root, reported_git_vars, scrub_git_env
from .docs import (
    check_changelog_headings, check_cited_scripts, check_doc_file_cites, check_doc_links, check_docs_size,
)
from .golden import check_golden_dump_unique_keys
from .hygiene import (
    check_autotests_registered, check_form_ratios, check_isolate_test_krb5, check_mit_cites,
    check_python_compiles, check_release_clean,
)
from .ledger import (
    check_diffsend_cases, check_ledger_anchors, check_ledger_layout, check_ledger_mit_cites,
    check_ledger_proof_column, check_ledger_tally, check_no_case_whitelists, fix_ledger_tally,
)
from .selftest import _self_test
from .workflows import (
    Workflow, check_all_timeouts, check_makefile_matches_ci, check_msrv_pinned, check_nextest,
    check_workflow_exec_bits, check_workflow_hardening, check_working_gitignored,
)


def main() -> None:
    fix = False
    if sys.argv[1:] == ["--fix-tally"]:
        fix = True
    elif sys.argv[1:]:
        _die("usage: ci-policy.py [--fix-tally]")
    # Every git command this run makes is about this checkout or a scratch repository a self-test
    # builds. An inherited GIT_* that names a repository or carries git configuration is reported
    # and dropped before either runs.
    named = reported_git_vars(scrub_git_env())
    if named:
        print(f"ci-policy: ignoring the inherited {', '.join(named)}", file=sys.stderr)
    os.environ.setdefault("KERBER_SCRATCH", str(_scratch_root()))
    if not os.environ.get("TMPDIR"):
        os.environ["TMPDIR"] = os.environ["KERBER_SCRATCH"]
        tempfile.tempdir = None
    _self_test()
    if fix:
        print(fix_ledger_tally())
        return
    if not WORKFLOWS.is_dir():
        _die(f"missing {WORKFLOWS}")
    workflows = [Workflow(p, p.read_text()) for p in sorted(WORKFLOWS.glob("*.yml"))]
    if not workflows:
        _die("no workflow YAML")
    check_nextest()
    check_all_timeouts(workflows)
    check_workflow_exec_bits(workflows)
    check_no_case_whitelists()
    check_isolate_test_krb5()
    check_makefile_matches_ci()
    check_msrv_pinned()
    check_workflow_hardening()
    check_python_compiles()
    check_autotests_registered()
    check_working_gitignored()
    check_release_clean()
    check_ledger_layout()
    check_ledger_proof_column()
    check_diffsend_cases()
    check_doc_file_cites()
    check_cited_scripts()
    check_doc_links()
    check_changelog_headings()
    check_docs_size()
    check_golden_dump_unique_keys()
    check_ledger_tally()
    check_ledger_anchors()
    check_ledger_mit_cites()
    check_mit_anchor_form()
    check_mit_anchor_truth()
    check_no_process_history()
    check_no_docs_process_tags()
    check_mit_cites()
    check_form_ratios()
    print("ci-policy: ok")
