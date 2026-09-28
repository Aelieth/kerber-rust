"""ci-policy's entry point: `main()` runs the self-test, then every check in order."""

from __future__ import annotations

import sys

from .comments import check_mit_anchor_form, check_mit_anchor_truth, check_no_process_history
from .common import WORKFLOWS, _die
from .docs import (
    check_changelog_headings, check_doc_file_cites, check_doc_links, check_docs_size, check_gate_documented,
    check_testing_doc_budgets,
)
from .evidence import (
    check_ci_status_save, check_claim_audit, check_evidence_check_tool, check_no_red_target_trees,
    check_red_at_sha_inject, check_red_at_sha_overlay_order, check_red_at_sha_target_trap, check_settle_helper,
    check_unit_evidence_helper,
)
from .gates import (
    check_capture_env_only, check_docker_cp_cargo_target, check_gate_common_sourced, check_gate_provenance,
    check_gate_unit_index, check_gate_wall, check_golden_dump_unique_keys, check_kcm_stop_before_run, check_log_arity,
    check_need_bins_strict, check_no_gate_cargo_build, check_peers_unavailable_convention,
    check_prod_gate_tcpdump_cleanup, check_samba_kdc_respawn, check_sleep_classifiers_agree, check_sleep_ratchet,
    check_stock_boots_per_job, check_trace_dst,
)
from .hygiene import (
    check_autotests_registered, check_claim_remap_self_test, check_hygiene_body_diff_self_test,
    check_hygiene_diff_self_test, check_hygiene_fn_diff_self_test, check_hygiene_inventory_cfg_test,
    check_isolate_test_krb5, check_policy_module_attrs, check_py_move_self_test,
)
from .ledger import (
    check_diffsend_cases, check_ledger_anchors, check_ledger_layout, check_ledger_mit_cites, check_ledger_proof_column,
    check_ledger_tally, check_no_case_whitelists,
)
from .selftest import _self_test
from .shell import check_no_host_tmp_writes, check_no_informational_gates
from .workflows import (
    Workflow, check_all_timeouts, check_build_profile, check_ci, check_ci_budgets, check_ci_nextest_split,
    check_ci_no_workspace_cargo_test, check_env_read, check_full_run_scheduled, check_gate_membership,
    check_makefile_matches_ci, check_msrv_pinned, check_nextest, check_nextest_profile, check_nightly,
    check_prod_image_once, check_rust_cache_shared_key, check_workflow_hardening, check_working_gitignored,
)


def main() -> None:
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
    check_docker_cp_cargo_target()
    check_no_host_tmp_writes()
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
    check_changelog_headings()
    check_docs_size()
    check_gate_documented()
    check_capture_env_only()
    check_golden_dump_unique_keys()
    check_ledger_tally()
    check_ledger_anchors()
    check_ledger_mit_cites()
    check_claim_audit()
    check_mit_anchor_form()
    check_mit_anchor_truth()
    check_no_process_history()
    print("ci-policy: ok")
