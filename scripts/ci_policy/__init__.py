"""ci-policy's entry point: `main()` runs the self-test, then every check in order."""

from __future__ import annotations

import os
import sys
import tempfile

from .comments import (
    check_mit_anchor_form, check_mit_anchor_truth, check_no_docs_process_tags, check_no_process_history,
)
from .common import WORKFLOWS, _die, _scratch_root, reported_git_vars, scrub_git_env
from .docs import (
    check_changelog_headings, check_doc_file_cites, check_doc_links, check_docs_size, check_gate_doc_tokens,
    check_gate_documented,
    check_no_plan_section_names, check_no_script_line_cites, check_testing_doc_budgets,
)
from .evidence import (
    check_ci_status_save, check_claim_audit, check_evidence_check_tool, check_no_red_target_trees,
    check_red_at_sha_build, check_red_at_sha_inject, check_red_at_sha_overlay_order, check_red_at_sha_target_trap,
    check_settle_helper, check_unit_evidence_helper,
)
from .gates import (
    check_capture_env_only, check_docker_cp_cargo_target, check_gate_common_sourced, check_gate_provenance,
    check_gate_unit_index, check_gate_wall, check_golden_dump_unique_keys, check_kcm_stop_before_run, check_log_arity,
    check_need_bins_strict, check_no_gate_cargo_build, check_peers_unavailable_convention,
    check_prod_gate_tcpdump_cleanup, check_provenance_memo, check_samba_kdc_respawn, check_sleep_classifiers_agree,
    check_sleep_ratchet, check_stock_boots_per_job, check_trace_dst,
)
from .hygiene import (
    check_autotests_registered, check_claim_remap_self_test, check_hygiene_body_diff_self_test,
    check_hygiene_diff_self_test, check_hygiene_fn_diff_self_test, check_hygiene_inventory_cfg_test,
    check_isolate_test_krb5, check_policy_module_attrs, check_py_move_self_test, check_python_compiles,
)
from .ledger import (
    check_diffsend_cases, check_ledger_anchors, check_ledger_layout, check_ledger_mit_cites, check_ledger_proof_column,
    check_ledger_tally, check_no_case_whitelists,
)
from .kadmin_q import check_kadmin_q_via_lib
from .selftest import _self_test
from .shell import (
    check_no_dead_shell_functions, check_no_duplicate_functions, check_no_host_tmp_writes,
    check_no_informational_gates,
)
from .workflows import (
    Workflow, check_all_timeouts, check_build_profile, check_ci, check_ci_budgets, check_ci_nextest_split,
    check_ci_no_workspace_cargo_test, check_env_read, check_full_run_scheduled, check_gate_membership,
    check_makefile_matches_ci, check_msrv_pinned, check_nextest, check_nextest_profile, check_nightly,
    check_prod_image_once, check_rust_cache_shared_key, check_workflow_hardening, check_working_gitignored,
)


def main() -> None:
    # Every git command this run makes, or a script it runs makes, is about this checkout or a scratch
    # repository a self-test builds. An inherited GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE or any other GIT_*
    # would point it at another repository, so none survives into the run; the ones that name a repository
    # or carry git configuration are reported.
    named = reported_git_vars(scrub_git_env())
    if named:
        print(f"ci-policy: ignoring the inherited {', '.join(named)}", file=sys.stderr)
    # The scripts the checks run stamp through provenance.sh, and the self-tests make temp trees: give
    # both this run's scratch as KERBER_SCRATCH and, unless the caller set one, as TMPDIR, never host /tmp.
    os.environ.setdefault("KERBER_SCRATCH", str(_scratch_root()))
    if not os.environ.get("TMPDIR"):
        os.environ["TMPDIR"] = os.environ["KERBER_SCRATCH"]
        tempfile.tempdir = None
    _self_test()
    if not WORKFLOWS.is_dir():
        _die(f"missing {WORKFLOWS}")
    workflows = [
        Workflow(p, p.read_text())
        for p in sorted(WORKFLOWS.glob("*.yml"))
    ]
    if not workflows:
        _die("no workflow YAML")
    ci = [w for w in workflows if w.path.name == "ci.yml"]
    if len(ci) != 1:
        _die("expected .github/workflows/ci.yml")
    check_ci(ci[0])
    check_ci_nextest_split(ci[0])
    check_ci_no_workspace_cargo_test(ci[0])
    check_nightly(workflows)
    check_nextest()
    check_nextest_profile(workflows)
    check_all_timeouts(workflows)
    check_full_run_scheduled(workflows)
    check_gate_membership(workflows)
    check_no_informational_gates()
    check_no_case_whitelists()
    check_gate_provenance()
    check_provenance_memo()
    check_docker_cp_cargo_target()
    check_no_host_tmp_writes()
    check_no_duplicate_functions()
    check_no_dead_shell_functions()
    check_kadmin_q_via_lib()
    check_isolate_test_krb5()
    check_unit_evidence_helper()
    check_settle_helper()
    check_evidence_check_tool()
    check_ci_status_save()
    check_makefile_matches_ci()
    check_msrv_pinned()
    check_rust_cache_shared_key()
    check_workflow_hardening()
    check_prod_image_once()
    check_build_profile()
    check_env_read()
    check_peers_unavailable_convention()
    check_samba_kdc_respawn()
    check_log_arity()
    check_hygiene_diff_self_test()
    check_hygiene_body_diff_self_test()
    check_hygiene_fn_diff_self_test()
    check_py_move_self_test()
    check_claim_remap_self_test()
    check_python_compiles()
    check_hygiene_inventory_cfg_test()
    check_policy_module_attrs()
    check_autotests_registered()
    check_kcm_stop_before_run()
    check_prod_gate_tcpdump_cleanup()
    check_gate_common_sourced()
    check_no_gate_cargo_build()
    check_trace_dst()
    check_stock_boots_per_job()
    check_gate_wall()
    check_sleep_ratchet()
    check_sleep_classifiers_agree()
    check_ci_budgets()
    check_need_bins_strict()
    check_testing_doc_budgets()
    check_red_at_sha_inject()
    check_red_at_sha_overlay_order()
    check_red_at_sha_target_trap()
    check_red_at_sha_build()
    if "--checkpoint" in sys.argv[1:]:
        # W1-Z Z3.4: the local evidence tree is gitignored, so only the
        # checkpoint runner (`ci-policy.py --checkpoint`) can see it.
        check_no_red_target_trees()
    check_working_gitignored()
    check_ledger_layout()
    check_ledger_proof_column()
    check_diffsend_cases()
    check_gate_unit_index()
    check_doc_file_cites()
    check_doc_links()
    check_no_plan_section_names()
    check_changelog_headings()
    check_docs_size()
    check_gate_documented()
    check_gate_doc_tokens()
    check_no_script_line_cites()
    check_capture_env_only()
    check_golden_dump_unique_keys()
    check_ledger_tally()
    check_ledger_anchors()
    check_ledger_mit_cites()
    check_claim_audit()
    check_mit_anchor_form()
    check_mit_anchor_truth()
    check_no_process_history()
    check_no_docs_process_tags()
    print("ci-policy: ok")
