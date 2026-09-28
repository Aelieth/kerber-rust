"""ci-policy's self-test: every check against its green and red fixtures."""

from __future__ import annotations

import importlib.util
import inspect
import io
import os
import pathlib
import signal
import subprocess
import sys
import tempfile

from .comments import (
    _check_ambiguous_pin, check_mit_anchor_form, check_mit_anchor_truth, check_no_process_history,
    mit_anchor_truth_violations,
)
from .common import ROOT, SCRIPTS, _die, _scratch_root
from .docs import (
    DOCS_SIZE_LIMIT, check_changelog_headings, check_doc_file_cites, check_doc_links, check_docs_size,
    check_testing_doc_budgets, doc_link_violations, gate_doc_violations, gate_placements,
)
from .evidence import (
    _claim_audit_module, check_ci_status_save, check_evidence_check_tool, check_index_check_scratch,
    check_no_red_target_trees, check_red_at_sha_inject, check_red_at_sha_overlay_order, check_red_at_sha_target_trap,
    check_settle_helper, check_unit_evidence_helper,
)
from .gates import (
    GATE_COMMON_NEEDLES, _gate_unit_index, check_capture_env_only, check_gate_cargo_leftover, check_gate_common_sourced,
    check_gate_no_exit_trap, check_gate_provenance, check_gate_unit_index, check_gate_wall,
    check_golden_dump_unique_keys, check_kadmin_glob_lib, check_kadmin_split_snaps, check_kcm_need_image,
    check_kcm_stop_before_run, check_log_arity, check_need_bins_strict, check_no_gate_cargo_build,
    check_peers_unavailable_convention, check_prod_gate_tcpdump_cleanup, check_s4_shared_boots, check_samba_kdc_respawn,
    check_sleep_classifiers_agree, check_sleep_ratchet, check_stock_boots_per_job, check_trace_dst,
)
from .hygiene import (
    _PY_MOVE_KINDS, _blank_rust, _cfg_test_ranges, check_autotests_registered, check_claim_remap_self_test,
    check_hygiene_body_diff_self_test, check_hygiene_diff_self_test, check_hygiene_fn_diff_self_test,
    check_isolate_test_krb5, check_policy_module_attrs, check_py_move_self_test,
)
from .ledger import (
    DIFFSEND_CASES, _item_span, _item_spans, _src_index, check_diffsend_cases, check_ledger_anchors,
    check_ledger_layout, check_ledger_mit_cites, check_ledger_proof_column, check_ledger_tally,
    check_no_case_whitelists, ledger_sources,
)
from .shell import _join_shell_continuations, check_no_host_tmp_writes, informational_if_starts
from .workflows import (
    SHELLCHECK_CMD, Workflow, check_all_timeouts, check_build_profile, check_ci, check_ci_budgets,
    check_ci_nextest_split, check_ci_no_workspace_cargo_test, check_env_read, check_full_run_scheduled,
    check_gate_membership, check_makefile_matches_ci, check_msrv_pinned, check_nextest_profile, check_nightly,
    check_prod_image_once, check_rust_cache_shared_key, check_workflow_hardening,
)


def _must_die(fn, *args) -> None:
    err = sys.stderr
    sys.stderr = open("/dev/null", "w", encoding="utf-8")
    try:
        fn(*args)
        died = False
    except SystemExit:
        died = True
    finally:
        sys.stderr.close()
        sys.stderr = err
    if not died:
        raise AssertionError(f"{fn.__name__} must fail closed")


def _must_die_msg(needle: str, fn, *args, **kwargs) -> None:
    buf = io.StringIO()
    err = sys.stderr
    sys.stderr = buf
    try:
        fn(*args, **kwargs)
        died = False
    except SystemExit:
        died = True
    finally:
        sys.stderr = err
    text = buf.getvalue()
    name = getattr(fn, "__name__", "callable")
    if not died:
        raise AssertionError(f"{name} must fail closed")
    if needle not in text:
        raise AssertionError(f"{name} died without {needle!r}: {text!r}")


def _self_test() -> None:
    snippet = """name: ci
on:
  push:
    branches: [main]
jobs:
  harness:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - run: ./scripts/spake-gate.sh
  slo:
    continue-on-error: true
    timeout-minutes: 30
    steps:
      - run: ./scripts/stress-gate.sh
"""
    wf = Workflow(pathlib.Path("ci.yml"), snippet)
    assert wf.per_push and not wf.scheduled
    assert not wf.jobs["harness"].continue_on_error
    assert wf.jobs["slo"].continue_on_error
    assert wf.jobs["harness"].timeout_minutes == 45
    assert "spake-gate.sh" in wf.jobs["harness"].scripts
    assert "stress-gate.sh" in wf.jobs["slo"].scripts

    no_timeout = Workflow(
        pathlib.Path("notimeout.yml"),
        "name: fuzz\non:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )
    _must_die(check_all_timeouts, [no_timeout])

    sched = Workflow(
        pathlib.Path("full-test.yml"),
        "name: full-test\non:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  test-release:\n    timeout-minutes: 40\n    steps:\n      - run: cargo nextest run --workspace --release --profile ci\n  msrv-test:\n    timeout-minutes: 30\n    steps:\n      - run: cargo test --workspace --locked\n",
    )
    check_full_run_scheduled([sched])
    check_nextest_profile([sched])
    check_all_timeouts([sched])

    echo_if = 'if ! grep -F foo /tmp/x; then\n    echo "informational fallback"\nfi\n'
    if not informational_if_starts(echo_if):
        raise AssertionError("informational echo if must be a violation")
    ok_if = 'if ! grep -F foo /tmp/x; then\n    exit 1\nfi\n'
    if informational_if_starts(ok_if):
        raise AssertionError("if with exit must pass")
    gss_shape = 'if [ "$ok" != 1 ]; then\n    echo "settled live"\nfi\n'
    if not informational_if_starts(gss_shape):
        raise AssertionError("if [ ] echo-only must be a violation")
    quoted_return = 'if true; then\n    echo "return from helper"\nfi\n'
    if not informational_if_starts(quoted_return):
        raise AssertionError("return inside quotes must not excuse echo-only")
    else_echo = 'if true; then\n    :\nelse\n    echo only\nfi\n'
    if not informational_if_starts(else_echo):
        raise AssertionError("else echo-only must be a violation")
    nested = 'if true; then\n    if false; then\n        echo inner\n    fi\n    exit 1\nfi\n'
    nested_hits = informational_if_starts(nested)
    if not nested_hits:
        raise AssertionError("nested echo-only if must be a violation")
    if nested_hits[0] == 1:
        raise AssertionError("nested fi must not pop the outer if")
    colon_if = 'if true; then\n    :\nfi\n'
    if not informational_if_starts(colon_if):
        raise AssertionError("colon-only if must be a violation")
    oneliner = 'if [ "$ok" != 1 ]; then echo settled; fi\n'
    if not informational_if_starts(oneliner):
        raise AssertionError("one-liner echo-only must be a violation")
    mixed = 'if X; then\n    exit 1\nelif Y; then\n    echo only\nfi\n'
    if not informational_if_starts(mixed):
        raise AssertionError("mixed exit/echo chain must be a violation")
    echo_else_exit = 'if true; then\n    echo only\nelse\n    exit 0\nfi\n'
    if not informational_if_starts(echo_else_exit):
        raise AssertionError("echo then else exit must be a violation")
    multi = 'if [ "$a" = 1 ] ||\n   [ "$b" = 2 ]; then\n    echo hi\nfi\n'
    if not informational_if_starts(multi):
        raise AssertionError("multi-line condition echo-only must be a violation")
    helper_snip = 'if ! wait_ready; then\n    echo skip\nfi\n'
    if not informational_if_starts(helper_snip):
        raise AssertionError("helper-file echo-only snippet must be a violation")
    ok_mixed_no_echo = 'if X; then\n    exit 1\nelif Y; then\n    exit 2\nfi\n'
    if informational_if_starts(ok_mixed_no_echo):
        raise AssertionError("exit/exit chain must pass")
    oneliner_elif = (
        'if X; then exit 1; elif Y; then echo hi; elif Z; then exit 2; fi\n'
    )
    if informational_if_starts(oneliner_elif) != [1]:
        raise AssertionError("one-line ≥2-elif middle echo must be a hit")
    tee_echo = 'if true; then\n    echo skip | tee /tmp/x\nfi\n'
    if not informational_if_starts(tee_echo):
        raise AssertionError("echo | tee without assert must be a violation")
    redir_echo = 'if true; then\n    echo skip > /tmp/x\nfi\n'
    if not informational_if_starts(redir_echo):
        raise AssertionError("echo > file without assert must be a violation")
    assign_echo = 'if true; then\n    n=1\n    echo skip\nfi\n'
    if not informational_if_starts(assign_echo):
        raise AssertionError("assignment must not excuse echo-only")
    brace_echo = 'if true; then\n    { echo x; } > /tmp/x\nfi\n'
    if not informational_if_starts(brace_echo):
        raise AssertionError("{ echo; } redirect must be a violation")
    subshell_echo = 'if true; then\n    ( echo x ) > /tmp/x\nfi\n'
    if not informational_if_starts(subshell_echo):
        raise AssertionError("( echo ) redirect must be a violation")
    heredoc = 'if true; then\n    cat <<EOF > /tmp/x\nhi\nEOF\nfi\n'
    if not informational_if_starts(heredoc):
        raise AssertionError("heredoc arm must be a violation")
    cmp_ok = 'if true; then\n    cmp -s a b\nfi\n'
    if informational_if_starts(cmp_ok):
        raise AssertionError("cmp arm must assert")
    test_ok = 'if true; then\n    [ "$x" = 1 ]\nfi\n'
    if informational_if_starts(test_ok):
        raise AssertionError("[ ] arm must assert")
    unavail_ok = 'if true; then\n    unavailable "x"\nfi\n'
    if informational_if_starts(unavail_ok):
        raise AssertionError("unavailable arm must assert")
    for i, snippet in enumerate(
        (
            'if true; then\n    y=$( grep foo bar )\n    echo skip\nfi\n',
            'if true; then\n    echo see grep output\nfi\n',
            'if true; then\n    echo skip > test.log\nfi\n',
            'if true; then\n    echo run test suite\nfi\n',
            'if true; then\n    echo tcpdump unavailable\nfi\n',
            'if true; then\n    echo will exit later\nfi\n',
            'if true; then\n    ( exit 1 ) || true\n    echo skip\nfi\n',
            'if true; then\n    echo skip | grep -q skip\nfi\n',
            'if true; then\n    echo skip\n    test -n "x"\nfi\n',
            'if true; then\n    echo skip\n    cmp -s /dev/null /dev/null\nfi\n',
            'if true; then\n    echo skip | tee /tmp/x\n    [ -s /tmp/x ]\nfi\n',
        )
    ):
        if not informational_if_starts(snippet):
            raise AssertionError(f"counter-example {i} must be informational")
    for i, snippet in enumerate(
        (
            'if true; then\n    grep -q x f || { echo skip; }\nfi\n',
            'if true; then\n    grep -q x f || :\nfi\n',
            'if true; then\n    echo skip > "$OUT/x.log"\n    grep -q skip "$OUT/x.log"\nfi\n',
            'if true; then\n    /bin/echo skip\nfi\n',
            'if true; then\n    log_info "skipping"\nfi\n',
            'if true; then\n    [ -n "$x" ] && echo skip\nfi\n',
            'case "$x" in\n    *) echo skip ;;\nesac\n',
            'case "$x" in\n    a)\n        echo skip\n        ;;\n    *) die x ;;\nesac\n',
        )
    ):
        if not informational_if_starts(snippet):
            raise AssertionError(f"round-2 counter-example {i} must be informational")
    for i, snippet in enumerate(
        (
            'if true; then\n    grep -q x f || die x\nfi\n',
            'if true; then\n    [ -n "$x" ] && exit 1\nfi\n',
            'if true; then\n    docker exec c true > "$OUT/x.log"\n    grep -q ok "$OUT/x.log"\nfi\n',
            'if true; then\n    grep -q x f || { log "g" "error" x; exit 1; }\nfi\n',
            'case "$x" in\n    *) die x ;;\nesac\n',
        )
    ):
        if informational_if_starts(snippet):
            raise AssertionError(f"round-2 positive control {i} must assert")
    skip_scoped = (
        'if [ "${KERBER_REQUIRE_NETEM:-0}" = 1 ]; then\n'
        '    die "required"\n'
        "fi\n"
        "if true; then\n"
        '    log "g" "skip" "foo missing"\n'
        "fi\n"
    )
    if not informational_if_starts(skip_scoped):
        raise AssertionError("a skip that names no enforced requirement must be informational")
    skip_require = (
        'if [ "${KERBER_REQUIRE_NETEM:-0}" = 1 ]; then\n'
        '    die "required"\n'
        "fi\n"
        "if true; then\n"
        '    log "g" "skip" "netem"\n'
        "    echo hi\n"
        "fi\n"
    )
    if informational_if_starts(skip_require):
        raise AssertionError("log skip with REQUIRE die must pass")
    skip_bare = 'if true; then\n    log "g" "skip" "netem"\n    echo hi\nfi\n'
    if not informational_if_starts(skip_bare):
        raise AssertionError("log skip without REQUIRE die must be informational")

    class _Alarm(Exception):
        pass

    def _on_alarm(_signum, _frame) -> None:
        raise _Alarm

    three_or = (
        'if [ "$a" = 1 ] ||\n'
        '   [ "$b" = 2 ] ||\n'
        '   [ "$c" = 3 ]; then\n'
        " echo hi\n"
        "fi\n"
    )
    old = signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(5)
    try:
        three_hits = informational_if_starts(three_or)
    except _Alarm as exc:
        raise AssertionError("3-way || join hung") from exc
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    if three_hits != [1]:
        raise AssertionError(f"3-way || must be [1], got {three_hits}")
    joined = _join_shell_continuations("a &&\nb &&\nc\n")
    if "a && b && c" not in joined.replace("\n", " "):
        raise AssertionError(f"3-way && join failed: {joined!r}")

    missing_profile = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace\n",
    )
    _must_die(check_nextest_profile, [missing_profile])

    cargo_test = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, cargo_test)
    doc_tests = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace --doc\n",
    )
    check_ci_no_workspace_cargo_test(doc_tests)
    doc_then_unit = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace --doc && cargo test --workspace\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, doc_then_unit)
    docs_word = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --workspace --docs\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, docs_word)

    no_junit = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace --profile ci --no-run\n",
    )
    _must_die(check_ci_nextest_split, no_junit)

    no_norun = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace --profile ci\n      - uses: actions/upload-artifact@v4\n        with:\n          path: target/nextest/ci/junit.xml\n",
    )
    _must_die(check_ci_nextest_split, no_norun)

    no_upload = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo nextest run --workspace --profile ci --no-run\n      - run: echo junit.xml\n",
    )
    _must_die(check_ci_nextest_split, no_upload)

    mentions_nextest = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: echo nextest is great\n",
    )
    _must_die(check_nextest_profile, [mentions_nextest])

    cargo_test_all = Workflow(
        pathlib.Path("ci.yml"),
        "name: ci\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: cargo test --all\n",
    )
    _must_die(check_ci_no_workspace_cargo_test, cargo_test_all)

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

    with tempfile.TemporaryDirectory() as tmp:
        troot = pathlib.Path(tmp)
        testdir = troot / "crates" / "demo" / "tests"
        testdir.mkdir(parents=True)
        (testdir / "twin.rs").write_text(
            "#[test]\n// oracle: differential-gate.sh unknown-sname\n"
            "fn as_unknown_sname_is_server_not_found() {}\n",
            encoding="utf-8",
        )
        gui = _gate_unit_index()
        cell_gate = (
            'grep -q \'"case":"unknown-sname","outcome":"ok","error_code":7,'
            '"e_text":"SERVER_NOT_FOUND"\' <<<"$DIFF"\n'
        )
        good_doc = gui.verify(troot, cell_gate, None)
        check_gate_unit_index(troot, cell_gate, good_doc)
        _must_die(check_gate_unit_index, troot, cell_gate, good_doc + "stale\n")
        _must_die(check_gate_unit_index, troot, cell_gate.replace("unknown-sname", "other-case"), good_doc)
        (testdir / "twin.rs").write_text(
            "#[test]\nfn other() {}\n"
            "// oracle: differential-gate.sh unknown-sname\n"
            "fn as_unknown_sname_is_server_not_found() {}\n",
            encoding="utf-8",
        )
        _must_die(check_gate_unit_index, troot, cell_gate, good_doc)
        (testdir / "twin.rs").write_text(
            "#[test]\nfn as_unknown_sname_is_server_not_found() {}\n",
            encoding="utf-8",
        )
        _must_die(check_gate_unit_index, troot, cell_gate, good_doc)

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

    check_capture_env_only(
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"kdc-gate.sh": "KERBER_CAPTURE_DIR=/tmp/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_SCRATCH");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "log() {\n    :\n}\n",
        {},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"kdc-gate.sh": "KERBER_CAPTURE_DIR=$ROOT/tests/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"ci.yml": "KERBER_CAPTURE_DIR: $ROOT/tests/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var_os("KERBER_SCRATCH");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {},
    )
    check_capture_env_only(
        'pub fn capture_pdu() {\n    let _ = std::env::var_os("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"kdc-gate.sh": "KERBER_CAPTURE_DIR=/tmp/traces\n"},
    )
    _must_die(
        check_capture_env_only,
        'pub fn capture_pdu() {\n    let _ = std::env::var("KERBER_CAPTURE_DIR");\n}\n',
        "refuse_golden_capture_dir() {\n    :\n}\n",
        {"harness/prod/env-up.sh": "refuse_golden_capture_dir() {\n    :\n}\n"},
    )
    check_doc_file_cites({"CHANGELOG.md": "see `crates/missing/nope.rs`\n"}, ROOT)

    def _princ_line(name: str, *keyhexes: str) -> str:
        namelen = str(len(name))
        parts = [
            "princ",
            "38",
            namelen,
            "0",
            str(len(keyhexes)),
            "0",
            name,
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
        ]
        for keyhex in keyhexes:
            klen = str(len(keyhex) // 2)
            parts.extend(["1", "1", "17", klen, keyhex])
        parts.append("-1")
        return "\t".join(parts) + "\n"

    dump_unique = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "ba", "bb", "bc", "bd")
        + _princ_line("hwuser@KERBER.TEST", "ca", "cb", "cc", "cd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    check_golden_dump_unique_keys(dump_unique)
    dump_clone_user = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("hwuser@KERBER.TEST", "ca", "cb", "cc", "cd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    _must_die(check_golden_dump_unique_keys, dump_clone_user)
    dump_clone_hw = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa", "ab", "ac", "ad")
        + _princ_line("nosvr@KERBER.TEST", "ba", "bb", "bc", "bd")
        + _princ_line("hwuser@KERBER.TEST", "da", "db", "dc", "dd")
        + _princ_line("pwprau@KERBER.TEST", "da", "db", "dc", "dd")
    )
    _must_die(check_golden_dump_unique_keys, dump_clone_hw)
    dump_missing = (
        "kdb5_util load_dump version 7\n"
        + _princ_line("user@KERBER.TEST", "aa")
        + _princ_line("nosvr@KERBER.TEST", "ba")
    )
    _must_die(check_golden_dump_unique_keys, dump_missing)
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
    # The ledger in either layout: one file, or docs/parity/ with a README header and one file
    # per section keyed by its name. A row's identity is its MIT cite and check cells.
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
    not_ci = Workflow(
        pathlib.Path("not-ci.yml"),
        "name: x\non:\n  push:\njobs:\n  test:\n    timeout-minutes: 1\n    steps:\n      - run: echo hi\n",
    )
    check_ci(not_ci)
    check_ci_nextest_split(not_ci)
    check_ci_no_workspace_cargo_test(not_ci)

    # R2-T2: red fixtures for check_ci's rules and check_nightly. The not_ci
    # call above returns at the ci.yml name guard and exercised none of the
    # _die rules; these (named ci.yml to pass that guard) do.
    def _ci(body: str) -> Workflow:
        return Workflow(pathlib.Path("ci.yml"), body)

    _soft = (
        "jobs:\n  slo:\n    continue-on-error: true\n"
        "  chaos:\n    continue-on-error: true\n"
        "  soak:\n    continue-on-error: true\n"
    )
    _must_die(check_ci, _ci("on:\n  workflow_dispatch:\n" + _soft))  # not push/PR
    _must_die(
        check_ci,
        _ci("on:\n  push:\n  schedule:\n    - cron: '0 0 * * *'\n" + _soft),
    )  # scheduled
    _must_die(
        check_ci,
        _ci("on:\n  push:\n" + _soft + "  rogue:\n    continue-on-error: true\n"),
    )  # extra continue-on-error job
    _must_die(
        check_ci,
        _ci("on:\n  push:\njobs:\n  test:\n    timeout-minutes: 30\n"),
    )  # missing the soft jobs
    _must_die(check_ci, _ci("on:\n  push:\n" + _soft))  # missing timeout job 'test'
    _must_die(check_nightly, [])  # no scheduled workflow runs a nightly-blocking gate

    _ci_push = Workflow(
        pathlib.Path("ci.yml"),
        "on:\n  push:\njobs:\n  harness:\n    timeout-minutes: 20\n"
        "    steps:\n      - run: ./scripts/kadmin-rust-gate.sh\n",
    )
    check_gate_membership(
        [_ci_push],
        ("kadmin-rust-gate.sh",),
        frozenset(),
        ["kadmin-rust-gate.sh"],
    )
    _ci_soft = Workflow(
        pathlib.Path("ci.yml"),
        "on:\n  push:\njobs:\n  soak:\n    continue-on-error: true\n"
        "    steps:\n      - run: ./scripts/kadmin-rust-gate.sh\n",
    )
    _must_die(
        check_gate_membership,
        [_ci_soft],
        ("kadmin-rust-gate.sh",),
        frozenset(),
        ["kadmin-rust-gate.sh"],
    )
    _ci_no_kadmin = Workflow(
        pathlib.Path("ci.yml"),
        "on:\n  push:\njobs:\n  harness:\n    timeout-minutes: 20\n"
        "    steps:\n      - run: ./scripts/spake-gate.sh\n",
    )
    _nightly_kadmin = Workflow(
        pathlib.Path("peers.yml"),
        "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  peers:\n"
        "    steps:\n      - run: ./scripts/kadmin-rust-gate.sh\n",
    )
    _must_die(
        check_gate_membership,
        [_ci_no_kadmin, _nightly_kadmin],
        ("kadmin-rust-gate.sh",),
        frozenset(),
        ["kadmin-rust-gate.sh"],
    )

    check_gate_provenance('. "$ROOT/scripts/lib/provenance.sh"\n', "ok-gate.sh")
    _must_die(check_gate_provenance, "#!/bin/bash\necho hi\n", "no-prov-gate.sh")
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
    check_no_host_tmp_writes(
        'SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-x-gate}"\n'
        "docker exec n sh -c 'cat >/tmp/in-container'\n",
        "ok-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cc -o x x.c 2>/tmp/kadm5-cc.err\n",
        "kadmin-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cp x /tmp/foo\n",
        "cp-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "tee /tmp/out.log\n",
        "tee-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "echo $(cat >/tmp/x)\n",
        "subshell-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "python3 -c '\nprint(1)\n'\necho x > /tmp/after-multiline\n",
        "multiline-quote-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "docker exec n sh -c 'cat >/tmp/in <<EOF\nbody\nEOF'\necho x > /tmp/after-heredoc\n",
        "quoted-heredoc-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        None,
        "lib",
        {"lib/gate-common.sh": "echo x > /tmp/host-out\n"},
    )
    _must_die(
        check_no_host_tmp_writes,
        "docker exec n sh -c 'true' >/tmp/host-out\n",
        "docker-host-redir-tmp-gate.sh",
    )
    check_gate_cargo_leftover("need_bins krb5-kdc krb5-kvno\n", "ok-bins-gate.sh")
    _must_die(
        check_gate_cargo_leftover,
        "    -p krb5-client --bin krb5-kvno\n",
        "leftover-cargo-gate.sh",
    )
    check_gate_no_exit_trap("register_cleanup 'docker rm -f \"$NAME\"'\n", "ok-trap-gate.sh")
    _must_die(
        check_gate_no_exit_trap,
        "trap 'cleanup; mit_cleanup' EXIT\n",
        "exit-trap-gate.sh",
    )
    _four_boots = (
        "boot-stock-mit.sh\nboot-shell.sh\n"
        "boot-stock-mit.sh\nboot-shell.sh\n"
        "boot-stock-mit.sh\nboot-shell.sh\n"
        "boot-stock-mit.sh\nboot-shell.sh\n"
    )
    check_s4_shared_boots(_four_boots)
    _must_die(check_s4_shared_boots, "boot-shell.sh\nboot-shell.sh\n")
    check_stock_boots_per_job(_four_boots)
    _must_die(check_stock_boots_per_job, "boot-stock-mit.sh\n")
    check_gate_wall("# empty\n", "gate\trun\tgate_rc\twall_s\nkdc-gate\trun1\t0\t12\n")
    _must_die(check_gate_wall, "kadmin-gate\n", "gate\trun\tgate_rc\twall_s\n")
    _must_die(
        check_gate_wall,
        "# empty\n",
        "gate\trun\tgate_rc\twall_s\nkdc-gate\trun1\t2\t1\n",
    )
    _must_die(
        check_gate_wall,
        "# empty\n",
        "gate\trun\tgate_rc\twall_s\nkpasswd-gate\trun1\t0\t46\n",
    )
    ok_sleep = "sleep 2 # proto: ticket age\n"
    check_sleep_ratchet({"renew-gate.sh": ok_sleep}, unit_sleep_count=5)
    long_poll = "for _ in $(seq 1 200); do\nsleep 0.1\ndone\n"
    check_sleep_ratchet({"kdc-gate.sh": long_poll}, unit_sleep_count=5)
    check_sleep_classifiers_agree()
    _must_die(
        check_sleep_ratchet,
        {"pad-gate.sh": "sleep 3\n"},
        5,
    )
    _must_die(
        check_sleep_ratchet,
        {"pad-gate.sh": "sleep 3 # leftover\n"},
        5,
    )
    _must_die(
        check_sleep_ratchet,
        {"renew-gate.sh": "sleep 40 # proto: ticket age\n"},
        5,
    )
    _must_die(check_sleep_ratchet, {"renew-gate.sh": ok_sleep}, 15)
    good_toml = (
        "[jobs]\n"
        "test = 300\nharness = 270\nmit-extra = 180\ndoc = 90\n"
        "msrv = 120\naudit = 240\nledger-mit = 60\nmit-image = 90\n"
        "[push]\nrun_wall = 360\n"
    )
    check_ci_budgets(
        good_toml,
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        "[jobs]\ntest = 300\n[push]\nrun_wall = 540\n",
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        good_toml,
        "no check flag\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        good_toml,
        "--check-budget\nbudget_overruns\n",
        ["ci.yml"],
    )
    _must_die(
        check_ci_budgets,
        (
            "[jobs]\n"
            "test = 300\nharness = 500\nmit-extra = 180\ndoc = 90\n"
            "msrv = 120\naudit = 240\nledger-mit = 60\nmit-image = 90\n"
            "[push]\nrun_wall = 360\n"
        ),
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
    )
    _must_die(
        check_ci_budgets,
        good_toml,
        "--check-budget\nbudget_overruns\n",
        ["ci.yml", "budget.yml"],
        ["harness-2"],
    )
    check_need_bins_strict(
        "KERBER_NEED_BINS_STRICT: \"1\"\n",
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
        {
            "peers.yml": (
                'scripts/samba-ad-gate.sh\nbuild-bins.sh\n'
                'KERBER_NEED_BINS_STRICT: "1"\n'
            )
        },
    )
    _must_die(
        check_need_bins_strict,
        'KERBER_NEED_BINS_STRICT: "1"\n',
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
        {"peers.yml": "scripts/samba-ad-gate.sh\n"},
    )
    _must_die(
        check_need_bins_strict,
        'KERBER_NEED_BINS_STRICT: "1"\n',
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
        {"peers.yml": "scripts/samba-ad-gate.sh\nbuild-bins.sh\n"},
    )
    _must_die(
        check_need_bins_strict,
        "no strict env\n",
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
    )
    _must_die(
        check_need_bins_strict,
        "KERBER_NEED_BINS_STRICT: \"1\"\n",
        "no export\n",
        "KERBER_NEED_BINS_STRICT\nneed_bins: building\n",
    )
    _must_die(
        check_need_bins_strict,
        "KERBER_NEED_BINS_STRICT: \"1\"\n",
        "export KERBER_NEED_BINS_STRICT=1\n",
        "KERBER_NEED_BINS_STRICT\n",
    )
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
    dst_ok = 'TRACE_DST="${KERBER_TRACE_DST:-${KERBER_SCRATCH}/traces}"\n'
    check_trace_dst({"kdc-gate.sh": dst_ok, "client-gate.sh": dst_ok})
    _must_die(
        check_trace_dst,
        {
            "kdc-gate.sh": 'TRACE_DST="${KERBER_TRACE_DST:-$ROOT/tests/traces}"\n',
            "client-gate.sh": dst_ok,
        },
    )
    prod_ok = (
        "jobs:\n"
        "  mit-image:\n"
        "    steps:\n"
        "      - run: docker build -f harness/prod/Dockerfile -t prod .\n"
        "        hashFiles('harness/prod/Dockerfile')\n"
    )
    check_prod_image_once(prod_ok)
    _must_die(
        check_prod_image_once,
        "jobs:\n  mit-image:\n    steps:\n      - run: echo no prod\n",
    )
    _must_die(
        check_prod_image_once,
        "docker build -f harness/prod/Dockerfile\n"
        "docker build -f harness/prod/Dockerfile\n"
        "jobs:\n  mit-image:\n    steps:\n      - run: harness/prod/Dockerfile\n"
        "hashFiles('harness/prod/Dockerfile')\n",
    )
    check_build_profile(
        'debug = "line-tables-only"\nsplit-debuginfo = "unpacked"\n',
        "fuse-ld=lld\n",
        "apt-get install -y lld\n",
    )
    _must_die(
        check_build_profile,
        "debug = 2\nsplit-debuginfo = \"unpacked\"\n",
        "fuse-ld=lld\n",
        "apt-get install -y lld\n",
    )
    cache_ok = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: Swatinem/rust-cache@v2\n"
        "        with:\n"
        "          shared-key: kerber\n"
        "      - run: cargo nextest run\n"
    )
    check_rust_cache_shared_key({"ci.yml": cache_ok})
    sha = "c" * 40
    sc_pin = f"    env:\n      SHELLCHECK_VERSION: v0.11.0\n      SHELLCHECK_SHA256: {'8' * 64}\n"
    hard_ci = (
        "name: ci\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: g\n  cancel-in-progress: true\n\n"
        f"on:\n  push:\njobs:\n  shellcheck:\n{sc_pin}    steps:\n"
        f"      - uses: actions/checkout@{sha} # v5.1.0\n"
        '      - run: echo "$SHELLCHECK_SHA256  $f" | sha256sum --check\n'
        f"      - run: {SHELLCHECK_CMD}\n"
    )
    hard_soak = "name: soak\n\npermissions:\n  contents: read\n\non:\n  schedule:\njobs:\n  soak:\n    steps:\n      - uses: ./.github/actions/rust-preamble\n"
    hard_action = {"rust-preamble/action.yml": f"runs:\n  steps:\n    - uses: Swatinem/rust-cache@{sha} # v2.9.2\n"}
    hard_bot = 'updates:\n  - package-ecosystem: "github-actions"\n  - package-ecosystem: "cargo"\n'
    hard_pins = {"Makefile": "koalaman/shellcheck:v0.11.0 -S style\n", "hygiene_inventory.py": 'SHELLCHECK_IMAGE = "koalaman/shellcheck:v0.11.0"\n'}
    check_workflow_hardening({"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak.replace("permissions:\n  contents: read\n\n", "")}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak.replace("on:", "concurrency:\n  cancel-in-progress: true\non:")}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace("concurrency:\n  group: g\n  cancel-in-progress: true\n\n", ""), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(f"@{sha} # v5.1.0", "@v5"), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(" # v5.1.0", ""), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, {"rust-preamble/action.yml": "runs:\n  steps:\n    - uses: Swatinem/rust-cache@v2\n"}, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, 'updates:\n  - package-ecosystem: "cargo"\n', "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(SHELLCHECK_CMD, "shellcheck scripts/*.sh"), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, hard_bot, "disable=SC2329\n", hard_pins)
    # The shellcheck job on the runner's package (no version pin), an unverified tarball, a stale fallback image.
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace(sc_pin, ""), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci.replace("sha256sum --check", "tar -xJf"), "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", hard_pins)
    _must_die(check_workflow_hardening, {"ci.yml": hard_ci, "soak.yml": hard_soak}, hard_action, hard_bot, "external-sources=true\n", {**hard_pins, "Makefile": "koalaman/shellcheck:stable -S style\n"})
    cache_via_preamble = cache_ok.replace(
        "      - uses: Swatinem/rust-cache@v2\n        with:\n          shared-key: kerber\n",
        "      - uses: ./.github/actions/rust-preamble\n",
    )
    preamble_ok = "steps:\n  - uses: Swatinem/rust-cache@" + "b" * 40 + " # v2\n    with:\n      shared-key: kerber\n"
    check_rust_cache_shared_key({"ci.yml": cache_via_preamble}, preamble_ok)
    _must_die(check_rust_cache_shared_key, {"ci.yml": cache_via_preamble}, "steps:\n  - run: true\n")
    msrv_wf = (
        "jobs:\n"
        "  {job}:\n"
        "    env:\n"
        '      RUSTUP_TOOLCHAIN: "1.95"\n'
        "    steps:\n"
        "      - uses: dtolnay/rust-toolchain@1.95\n"
        "      - run: cargo build --workspace --locked\n"
    )
    msrv_ok = {
        "ci.yml": msrv_wf.format(job="msrv"),
        "full-test.yml": msrv_wf.format(job="msrv-test"),
    }
    manifest_ok = '[package]\nrust-version = "1.95"\n'
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "stable"\n', msrv_ok)
    sha_pinned = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: dtolnay/rust-toolchain@" + "a" * 40 + " # stable\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "stable"\n', {"ci.yml": sha_pinned, "full-test.yml": msrv_ok["full-test.yml"]})
    via_preamble = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: ./.github/actions/rust-preamble\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "stable"\n', {"ci.yml": via_preamble, "full-test.yml": msrv_ok["full-test.yml"]})
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": via_preamble.replace('          toolchain: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": sha_pinned.replace('          toolchain: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
    )
    _must_die(check_msrv_pinned, '[package]\nrust-version = "1.90"\n', manifest_ok, 'channel = "stable"\n', msrv_ok)
    _must_die(check_msrv_pinned, manifest_ok, "[package]\n", 'channel = "stable"\n', msrv_ok)
    _must_die(check_msrv_pinned, manifest_ok, manifest_ok, 'channel = "1.95.0"\n', msrv_ok)
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": msrv_wf.format(job="msrv").replace('      RUSTUP_TOOLCHAIN: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "stable"\n',
        {"ci.yml": msrv_ok["ci.yml"], "full-test.yml": msrv_ok["full-test.yml"].replace("@1.95", "@stable")},
    )
    _must_die(
        check_rust_cache_shared_key,
        {
            "ci.yml": (
                "jobs:\n"
                "  test:\n"
                "    steps:\n"
                "      - run: cargo nextest run\n"
            )
        },
    )
    mf_ok = (
        "safety: fmt clippy test policy\n"
        "cargo fmt --all\n"
        "cargo clippy --workspace --all-targets --all-features\n"
        "cargo nextest run --workspace --profile ci\n"
        "python3 scripts/ci-policy.py\n"
        "cargo doc --workspace --no-deps\n"
    )
    ci_ok = (
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: cargo fmt --all\n"
        "      - run: cargo clippy --workspace --all-targets --all-features\n"
        "      - run: cargo nextest run --workspace --profile ci\n"
        "      - run: python3 scripts/ci-policy.py\n"
        "  doc:\n"
        "    steps:\n"
        "      - run: cargo doc --workspace --no-deps\n"
    )
    check_makefile_matches_ci(mf_ok, ci_ok)
    _must_die(
        check_makefile_matches_ci,
        "safety:\ncargo fmt --all\n",
        ci_ok,
    )
    _must_die(
        check_makefile_matches_ci,
        mf_ok,
        "jobs:\n  test:\n    steps:\n      - run: cargo fmt --all\n"
        "      - run: cargo clippy --workspace --all-targets --all-features\n"
        "      - run: cargo nextest run --workspace --profile ci\n"
        "      - run: python3 scripts/ci-policy.py\n"
        "      - run: cargo doc --workspace --no-deps\n"
        "  doc:\n    steps:\n      - run: cargo doc --workspace --no-deps\n",
    )
    check_env_read(
        {"ci.yml": "  env:\n    KERBER_READ: 1\n"},
        "KERBER_READ is used here\n",
    )
    _must_die(
        check_env_read,
        {"ci.yml": "  env:\n    KERBER_UNREAD_XYZ: 1\n"},
        "no reader for that name\n",
    )
    check_peers_unavailable_convention(
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
    )
    _must_die(
        check_peers_unavailable_convention,
        "echo no rc check\n",
        "run-peer-step.sh\n",
        "exit 1\n",
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ]\n',
        "no wrapper\n",
        "exit 1\n",
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ]\n',
        "run-peer-step.sh\n",
        'unavailable "kinit failed"\nexit 1\n',
    )
    check_peers_unavailable_convention(
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "peers.yml": (
                "scripts/samba-ad-gate.sh\nkerber-rust-mit-kdc.tar\n"
                "unavailable=\nfailed=\n"
            ),
            "kcm-opcode.yml": (
                "scripts/kcm-opcode-gate.sh\nkerber-rust-mit-kdc.tar\n"
                "lld\nrun-peer-step.sh\n"
            ),
        },
        {"ad-s4u-gate.sh": "docker run -d --name n img\nrun_rc=$?\nregister_cleanup x\n"},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {"peers.yml": "scripts/samba-ad-gate.sh\n"},
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "peers.yml": (
                "scripts/samba-ad-gate.sh\nkerber-rust-mit-kdc.tar\n"
            )
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "kcm-opcode.yml": (
                "scripts/kcm-opcode-gate.sh\nkerber-rust-mit-kdc.tar\nlld\n"
            )
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "kcm-opcode.yml": (
                "scripts/kcm-opcode-gate.sh\nKERBER_NO_IMAGE\n"
                "lld\nrun-peer-step.sh\n"
            )
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {
            "peers.yml": "scripts/samba-ad-gate.sh\nkerber-rust-mit-kdc.tar\nunavailable=\nfailed=\n",
            "kcm-opcode.yml": "scripts/kcm-opcode-gate.sh\nkerber-rust-mit-kdc.tar\nrun-peer-step.sh\n",
        },
        {},
    )
    _must_die(
        check_peers_unavailable_convention,
        '[ "$rc" -eq 2 ] && exit 0\n',
        "run-peer-step.sh\n",
        "kinit failed; exit 1\n",
        {},
        {
            "ad-s4u-gate.sh": (
                "docker run -d --name n img\n"
                "register_cleanup x\n"
                "run_rc=$?\n"
            )
        },
    )
    check_samba_kdc_respawn(
        'samba_kdc_respawn_in "$NAME" || die x\n',
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        'wait_gone_in "$NAME" 88 || die x\n',
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        'samba_kdc_respawn_in "$NAME" || die x\n',
        'wait_gone_in "$NAME_A" 88 || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        "echo no helper\n",
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    _must_die(
        check_samba_kdc_respawn,
        'samba_kdc_respawn_in "$NAME" || die "Samba KDC did not rebind :88 after worker kill"\n',
        'samba_kdc_respawn_in "$NAME_A" || die x\n',
    )
    common_ok = "\n".join(GATE_COMMON_NEEDLES) + "\nGITHUB_ACTIONS\n::error file=\n::notice file=\n"
    gate_ok = "scripts/lib/gate-common.sh\nneed_bins krb5-kdc\n"
    _must_die(check_gate_common_sourced, "\n".join(GATE_COMMON_NEEDLES) + "\n", {"ok-gate.sh": gate_ok})
    _must_die(
        check_gate_common_sourced,
        "\n".join(GATE_COMMON_NEEDLES) + "\nGITHUB_ACTIONS\n::error file=\n",
        {"ok-gate.sh": gate_ok},
    )
    check_log_arity(
        'log() {\n    if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then\n'
        '        echo "log: expected 2-3 args, got $#" >&2\n        return 1\n    fi\n}\n'
    )
    _must_die(check_log_arity, "log() {\n    printf '%s' \"$1\"\n}\n")
    check_hygiene_diff_self_test(
        "def load_duplicates_map():\n    return {'merged:'}\n"
        "def load_renames_map():\n    return {}\n"
        "def _self_test_duplicates():\n    pass\n"
        "def _self_test():\n    pass\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-diff: self-test ok (36 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
        "    return _compare()\n"
    )
    _must_die(
        check_hygiene_diff_self_test,
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n        return 0\n",
    )
    _must_die(
        check_hygiene_diff_self_test,
        "def _self_test():\n    pass\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    _self_test()\n    return _compare()\n",
    )
    _must_die(
        check_hygiene_diff_self_test,
        'def load_duplicates_map():\n    return {"merged:"}\n'
        "def load_renames_map():\n    return {}\n"
        "def _self_test_duplicates():\n    pass\n"
        "def _self_test():\n"
        '    """merged: load_duplicates_map load_renames_map _self_test_duplicates"""\n'
        "    return None\n"
        "def main() -> int:\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-diff: self-test ok (36 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
        "    return _compare()\n",
    )
    check_hygiene_body_diff_self_test(
        'def _self_test():\n    assert_eq!(1, 2) vs user_as helper "a  b" r"a\\n\\nb"\n'
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-body-diff: self-test ok (41 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    _must_die(check_hygiene_body_diff_self_test, "def main():\n    return 0\n")
    _must_die(
        check_hygiene_body_diff_self_test,
        "def _self_test():\n    assert_eq! vs user_as helper\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    _must_die(
        check_hygiene_body_diff_self_test,
        "def _self_test():\n"
        '    """assert_eq!(1, 2) vs user_as helper "a  b" r"a\\n\\nb" """\n'
        "    return None\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-body-diff: self-test ok (32 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    check_hygiene_fn_diff_self_test(
        "def _self_test():\n    x + 2 phase_b pub(crate)\n"
        "    # unused-accept fixture must be otherwise green\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-fn-diff: self-test ok (142 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    _must_die(check_hygiene_fn_diff_self_test, "def main():\n    return 0\n")
    _must_die(
        check_hygiene_fn_diff_self_test,
        "def _self_test():\n    x + 2 phase_b pub(crate)\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    _must_die(
        check_hygiene_fn_diff_self_test,
        "def _self_test():\n"
        '    """x + 2 phase_b pub(crate)"""\n'
        "    return None\n"
        "def main():\n    if argv[1] == '--self-test':\n        _self_test()\n"
        "        print('hygiene-fn-diff: self-test ok (64 cases)')\n"
        "        return 0\n    with redirect_stdout(sys.stderr):\n        _self_test()\n",
    )
    py_move_ok = (
        "def _self_test():\n    cases = [" + "".join(f'("x", {{}}, s, a, "{k}"),' for k in _PY_MOVE_KINDS) + "]\n"
        "def main(argv):\n    if argv == ['--self-test']:\n        _self_test()\n"
        "        print('py-move-check: self-test ok (18 cases)')\n"
        "        return 0\n    with contextlib.redirect_stdout(sys.stderr):\n        _self_test()\n"
    )
    check_py_move_self_test(py_move_ok)
    _must_die_msg("self-test ok (N cases)", check_py_move_self_test, py_move_ok.replace("(18 cases)", "(17 cases)"))
    _must_die_msg(
        "must not be gutted",
        check_py_move_self_test,
        'def _self_test():\n    """' + "".join(f'"{k}"),' for k in _PY_MOVE_KINDS) + '"""\n    return None\n'
        + py_move_ok[py_move_ok.index("def main(argv):"):],
    )
    _must_die_msg("before a compare run", check_py_move_self_test,
                  py_move_ok.replace("with contextlib.redirect_stdout(sys.stderr):\n        _self_test()\n", "pass\n"))
    _must_die_msg("the shim finding", check_py_move_self_test, py_move_ok.replace('"shim"),', '"other"),'))
    remap_ok = (
        "def _self_test():\n    n = 7\n    return n\n"
        "def main(argv):\n    if argv == ['--self-test']:\n"
        "        print(f'claim-remap: self-test ok ({_self_test()} cases)')\n        return 0\n"
        "    _self_test()\n    return main_remap(argv)\n# self-test ok (7 cases)\n"
    )
    check_claim_remap_self_test(remap_ok)
    _must_die_msg("self-test ok (N cases)", check_claim_remap_self_test, remap_ok.replace("(7 cases)", "(6 cases)"))
    _must_die_msg("must not be gutted", check_claim_remap_self_test,
                  remap_ok.replace("    n = 7\n    return n\n", "    return None\n"))
    _must_die_msg("before a remap run", check_claim_remap_self_test,
                  remap_ok.replace("    _self_test()\n    return main_remap", "    return main_remap"))
    with tempfile.TemporaryDirectory() as tmp:
        demo = pathlib.Path(tmp) / "crates" / "demo"
        (demo / "tests" / "common").mkdir(parents=True)
        (demo / "tests" / "listed.rs").write_text("fn main() {}\n", encoding="utf-8")
        (demo / "tests" / "common" / "mod.rs").write_text("", encoding="utf-8")
        (demo / "Cargo.toml").write_text(
            "[package]\nname = \"demo\"\nautotests = false\n\n"
            "[[test]]\nname = \"listed\"\npath = \"tests/listed.rs\"\n",
            encoding="utf-8",
        )
        check_autotests_registered(pathlib.Path(tmp))
        (demo / "tests" / "orphan.rs").write_text("", encoding="utf-8")
        _must_die(check_autotests_registered, pathlib.Path(tmp))
    check_gate_common_sourced(common_ok, {"ok-gate.sh": gate_ok})
    _must_die(
        check_gate_common_sourced,
        common_ok.replace("wait_port_in", "no-wait"),
        {"ok-gate.sh": gate_ok},
    )
    _must_die(
        check_gate_common_sourced,
        common_ok,
        {"bad-gate.sh": "scripts/lib/gate-common.sh\ncargo build -p krb5-kdc\n"},
    )
    check_no_gate_cargo_build({"ok-gate.sh": "need_bins krb5-kdc\n"})
    _must_die(
        check_no_gate_cargo_build,
        {"bad-gate.sh": "cargo build -p krb5-kdc\n"},
    )
    _must_die(
        check_no_gate_cargo_build,
        {"leftover-gate.sh": "    -p krb5-client --bin krb5-kvno\n"},
    )
    check_kadmin_glob_lib("hist_shape() { cat; }\nalias_cells() { :; }\n")
    _must_die(check_kadmin_glob_lib, "glob_cells() { :; }\n")
    _must_die(check_kadmin_glob_lib, "hist_shape() { cat; }\n")
    check_kadmin_split_snaps("save_rust_snap HIST_GET\n", "kadmin-rust-gate.sh")
    _must_die(check_kadmin_split_snaps, "echo no snap\n", "kadmin-rust-gate.sh")
    check_kadmin_split_snaps("load_rust_snap HIST_GET\n", "kadmin-mit-gate.sh")
    _must_die(check_kadmin_split_snaps, "echo no load\n", "kadmin-mit-gate.sh")
    check_kadmin_split_snaps(
        "./scripts/kadmin-rust-gate.sh\n./scripts/kadmin-rust-acl-gate.sh\n"
        "./scripts/kadmin-both-gate.sh\nKERBER_SCRATCH=\n",
        "kadmin-gate.sh",
    )
    check_kadmin_split_snaps("save_rust_snap GETPRIVS\n", "kadmin-rust-acl-gate.sh")
    _must_die(check_kadmin_split_snaps, "echo no snap\n", "kadmin-rust-acl-gate.sh")
    _must_die(
        check_kadmin_split_snaps,
        "./scripts/kadmin-rust-gate.sh\n./scripts/kadmin-both-gate.sh\n",
        "kadmin-gate.sh",
    )
    _must_die(
        check_kadmin_split_snaps,
        "./scripts/kadmin-rust-gate.sh\nKERBER_SCRATCH=\n",
        "kadmin-gate.sh",
    )
    check_kcm_need_image(
        'KCM_IMAGE="${KCM_IMAGE:-kerber-rust-sssd-kcm:f43}"\nneed_image\n',
        "ok-kcm-gate.sh",
    )
    _must_die(
        check_kcm_need_image,
        'IMAGE="${KCM_IMAGE:-kerber-rust-sssd-kcm:f43}"\nneed_image\n',
        "bad-kcm-gate.sh",
    )
    check_kcm_stop_before_run(
        "register_cleanup './scripts/stop-harness.sh'\n./scripts/run-harness.sh\n",
        "ok-kcm-gate.sh",
    )
    _must_die(
        check_kcm_stop_before_run,
        "./scripts/run-harness.sh\nregister_cleanup './scripts/stop-harness.sh'\n",
        "bad-kcm-gate.sh",
    )
    check_prod_gate_tcpdump_cleanup(
        'register_cleanup \'kill $KDC_PID 2>/dev/null || true; '
        'if [ -n "$TCPDUMP_PID" ]; then sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || true; fi\'\n'
    )
    check_prod_gate_tcpdump_cleanup(
        "prod_cleanup() {\n"
        '    kill "$KDC_PID" 2>/dev/null || true\n'
        '    if [ -n "$TCPDUMP_PID" ]; then sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || true; fi\n'
        "}\nregister_cleanup prod_cleanup\n"
    )
    _must_die(
        check_prod_gate_tcpdump_cleanup,
        "register_cleanup 'kill $KDC_PID $TCPDUMP_PID 2>/dev/null || true'\n",
    )
    _must_die(
        check_prod_gate_tcpdump_cleanup,
        'prod_cleanup() {\n    kill "$KDC_PID" 2>/dev/null || true\n}\nregister_cleanup prod_cleanup\n',
    )
    _must_die(check_no_host_tmp_writes, 'tmp="$(mktemp -d)"\n', "bare-mktemp.sh")
    _must_die(check_no_host_tmp_writes, "t=$(mktemp)\n", "bare-mktemp-file.sh")
    check_no_host_tmp_writes(
        'TMP="$(mktemp -d "${KERBER_SCRATCH:-${TMPDIR:-/tmp}}/x.XXXXXX")"\n'
        'idx="$(mktemp "$dir/kerber-prov.XXXXXX")"\n'
        'd="$(mktemp -d -p "$SCRATCH")"\n'
        "docker exec n sh -c 'mktemp -d'\n",
        "ok-mktemp.sh",
    )
    check_no_host_tmp_writes(
        "docker exec n sh -c 'kill /tmp/krb5-kdc; : >/tmp/in-container'\n"
        "docker exec -d n \\\n"
        "    sh -c '/tmp/krb5-kdc >/tmp/kdc-r18.log 2>&1'\n",
        "ok-r18-kill-tmp-gate.sh",
    )
    _probe_dir = ROOT / "working" / "logs" / "w1-sweep" / "a2-r2-audit" / "scan-probe"
    for _probe_name in (
        "differential-gate.sh",
        "kadmin-gate.sh",
        "renew-gate.sh",
        "s4u-mit-gate.sh",
    ):
        _probe = _probe_dir / _probe_name
        if _probe.is_file():
            _must_die(check_no_host_tmp_writes, _probe.read_text(), _probe_name)
        _must_die(
            check_no_host_tmp_writes,
            (SCRIPTS / _probe_name).read_text()
            + f"\necho probe > /tmp/host-probe-{_probe_name}\n",
            f"probe-{_probe_name}",
        )
    _must_die(
        check_no_host_tmp_writes,
        "# ignore <<EOF in a comment\necho x > /tmp/after-comment-heredoc\n",
        "comment-heredoc-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cat <<<ignored\necho x > /tmp/after-herestring\n",
        "herestring-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        'echo >"/tmp/quoted-redir"\n',
        "quoted-redir-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        'cp x "/tmp/quoted-cp"\n',
        "quoted-cp-tmp-gate.sh",
    )
    check_no_host_tmp_writes(
        'echo "cat <<EOF"\necho ok\ncat <<<hello\n# <<EOF\n',
        "ok-quoted-and-comment-heredoc.sh",
    )
    # S3.4d: tokenise via strip_noncode, scan testenv.rs whole, cfg(test)
    # anywhere on the line including cfg(all|any(..., test, ...)). Missing
    # tests.rs dies on the production is_file() branch (a ROOT-like tree
    # under scratch, text=None).
    _isolate_ok = (
        "fn isolate_scratch_dir() -> PathBuf {\n    PathBuf::from(\"target\").join(\"test-krb5\")\n}\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
    )
    check_isolate_test_krb5(_isolate_ok)
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        "pub fn isolate_test_krb5() {\n"
        "    let path = std::env::temp_dir().join(\"kerber-test-krb5-1.conf\");\n"
        "}\n",
    )
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        "fn isolate_scratch_dir() -> PathBuf { PathBuf::from(\"target/test-krb5\") }\n"
        "pub fn isolate_test_krb5() {\n    let dir = isolate_scratch_dir();\n}\n"
        "#[cfg(test)]\nmod tests {\n    fn f() { let _ = std::env::temp_dir(); }\n}\n",
    )
    # C1 / C2: a private helper after isolate_test_krb5 is still testenv.rs
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        _isolate_ok + "fn helper_dir() -> PathBuf {\n    std::env::temp_dir()\n}\n",
    )
    _must_die_msg(
        "isolate_test_krb5 writes host /tmp",
        check_isolate_test_krb5,
        _isolate_ok
        + "fn helper_dir() -> PathBuf {\n    PathBuf::from(\"/tmp/kerber-test-krb5\")\n}\n",
    )
    # product temp_dir() after a cfg(test) use is not a cfg(test) item
    # (sibling file: testenv.rs is scanned whole)
    check_isolate_test_krb5(
        _isolate_ok,
        src_files={
            "kdcconf.rs": (
                "#[cfg(test)]\nuse foo::bar;\n"
                "fn product() { let _ = std::env::temp_dir(); }\n"
            )
        },
    )
    # temp_dir() inside a string literal in a cfg(test) mod is not a call
    check_isolate_test_krb5(
        _isolate_ok,
        src_files={
            "kdcconf.rs": (
                "#[cfg(test)]\nmod t {\n"
                '    fn f() { let _ = "temp_dir()"; }\n'
                "}\n"
            )
        },
    )

    def _isolate_src_file(name: str, src: str) -> None:
        check_isolate_test_krb5(_isolate_ok, src_files={name: src})

    # U1: lifetime + &'static before the temp_dir() fn (quote scanner ate it)
    _must_die_msg(
        "u1.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u1.rs",
        "#[cfg(test)]\nmod t {\n"
        " fn a<'x>(v: &str) { let r: &'static str = \"k\"; }\n"
        " fn f(){ std::env::temp_dir(); }\n}\n",
    )
    # U3: // comment containing }
    _must_die_msg(
        "u3.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u3.rs",
        "#[cfg(test)]\nmod t {\n // closes } here\n fn f(){ std::env::temp_dir(); }\n}\n",
    )
    # U6: #[cfg(test)] after code on the same line
    _must_die_msg(
        "u6.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u6.rs",
        "fn p(){} #[cfg(test)] mod t { fn f(){ std::env::temp_dir(); } }\n",
    )
    # U4: cfg(all(test, …)) / cfg(any(test, …))
    _must_die_msg(
        "u4.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u4.rs",
        "#[cfg(all(test, unix))]\nmod t {\n fn f(){ std::env::temp_dir(); }\n}\n",
    )
    _must_die_msg(
        "u4any.rs cfg(test) writes host /tmp via temp_dir()",
        _isolate_src_file,
        "u4any.rs",
        "#[cfg(any(test, windows))]\nmod t {\n fn f(){ std::env::temp_dir(); }\n}\n",
    )

    def _isolate_missing_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        src = fake / "crates/krb5-config/src"
        src.mkdir(parents=True)
        (src / "testenv.rs").write_text(_isolate_ok)
        check_isolate_test_krb5(root=fake)

    def _isolate_tree_with_tests() -> None:
        fake = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
        src = fake / "crates/krb5-config/src"
        src.mkdir(parents=True)
        (src / "testenv.rs").write_text(_isolate_ok)
        (src / "tests.rs").write_text("// no temp_dir\n")
        check_isolate_test_krb5(root=fake)

    def _isolate_tests_rs_temp_dir() -> None:
        check_isolate_test_krb5(
            _isolate_ok,
            tests_text="fn f() { let _ = std::env::temp_dir(); }\n",
        )

    def _isolate_src_cfg_test_temp_dir() -> None:
        check_isolate_test_krb5(
            _isolate_ok,
            src_files={
                "kdcconf.rs": (
                    "#[cfg(test)]\nmod tests {\n"
                    "    fn f() { let _ = std::env::temp_dir(); }\n"
                    "}\n"
                )
            },
        )

    _iso_src = inspect.getsource(check_isolate_test_krb5)
    _blank_src = inspect.getsource(_blank_rust)
    _range_src = inspect.getsource(_cfg_test_ranges)
    if "if not tests_path.is_file():" not in _iso_src:
        raise AssertionError("missing tests.rs must go through is_file()")
    if "tests_missing" in _iso_src:
        raise AssertionError("tests_missing short-circuit must stay gone")
    if "strip_noncode" not in _blank_src:
        raise AssertionError("must tokenise via strip_noncode")
    if "except" not in _blank_src:
        raise AssertionError("strip_noncode failure must die")
    if "in_str" in _iso_src or "in_str" in _range_src:
        raise AssertionError("hand-rolled string scanner must stay gone")
    if "isolate_scratch_dir" in _iso_src:
        raise AssertionError("testenv.rs must be scanned whole, not as an isolate chunk")
    _must_die_msg(
        "missing crates/krb5-config/src/tests.rs",
        _isolate_missing_tests,
    )
    _isolate_tree_with_tests()
    _must_die(_isolate_tests_rs_temp_dir)
    _must_die(_isolate_src_cfg_test_temp_dir)
    check_isolate_test_krb5()
    check_unit_evidence_helper()
    check_settle_helper()
    check_evidence_check_tool()
    check_ci_status_save()
    check_red_at_sha_inject()
    check_red_at_sha_overlay_order(
        'cp "$ROOT/scripts/"*.sh "$WT/scripts/"\nTREE="$(git write-tree)"\n'
    )
    _must_die(
        check_red_at_sha_overlay_order,
        'TREE="$(git write-tree)"\ncp "$ROOT/scripts/"*.sh "$WT/scripts/"\n',
    )
    _must_die(
        check_red_at_sha_inject,
        '--inject\nTREE="$(git write-tree)"\ncp "$ROOT/$rel" "$WT/$rel"\n',
    )
    check_red_at_sha_target_trap()
    _trap_ok = (
        'cleanup() {\n    rm -rf "$WT"\n    if [ "${KERBER_KEEP_RED_TARGET:-}" != "1" ]; then\n'
        '        rm -rf "$TARGET"\n    fi\n}\ntrap cleanup EXIT\necho "red-at-parent=1"\n'
    )
    check_red_at_sha_target_trap(_trap_ok)
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace('rm -rf "$TARGET"', "true"))
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace("KERBER_KEEP_RED_TARGET", "X"))
    _must_die(check_red_at_sha_target_trap, _trap_ok.replace('echo "red-at-parent=1"', ""))
    _rt = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        check_no_red_target_trees(_rt)
        (_rt / "z9" / "scratch" / "red-target-0123456789ab" / "debug").mkdir(parents=True)
        _must_die(check_no_red_target_trees, _rt)
        subprocess.run(["rm", "-rf", str(_rt / "z9")], check=True)
        (_rt / "z9" / "scratch" / "tgt" / "debug").mkdir(parents=True)
        (_rt / "z9" / "scratch" / "tgt" / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55")
        _must_die(check_no_red_target_trees, _rt)
    finally:
        subprocess.run(["rm", "-rf", str(_rt)], check=False)
    check_index_check_scratch()

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

    spec = importlib.util.spec_from_file_location("ci_status_r14", SCRIPTS / "ci-status.py")
    if spec is None or spec.loader is None:
        _die("missing scripts/ci-status.py")
    cistat = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cistat)
    cistat.time.sleep = lambda _s: None
    out_dir = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:

        def _inprog(*_a, **_k):
            return [
                {
                    "id": 1,
                    "run_number": 1,
                    "status": "in_progress",
                    "conclusion": None,
                    "head_sha": "abc1234deadbeef",
                }
            ]

        import io
        import urllib.error as _ue
        from email.message import Message

        def _quiet_save(*args, **kwargs):
            sink = io.StringIO()
            oldout, olderr = sys.stdout, sys.stderr
            try:
                sys.stdout = sink
                sys.stderr = sink
                return cistat.save_run(*args, **kwargs)
            finally:
                sys.stdout = oldout
                sys.stderr = olderr

        cistat.fetch_runs = _inprog
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=2)
        if rc != 2 or (out_dir / "ci-abc1234.txt").exists():
            _die("ci-status --save must exit 2 and write no file for in_progress")

        def _403(*_a, **_k):
            raise _ue.HTTPError(
                "https://api.github.com",
                403,
                "rate limit",
                Message(),
                io.BytesIO(b""),
            )

        cistat.fetch_runs = _403
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=3)
        if rc != 2 or (out_dir / "ci-abc1234.txt").exists():
            _die("ci-status --save must exit 2 and write no file after 403 ×N")

        def _done(*_a, **_k):
            return [
                {
                    "id": 9,
                    "run_number": 2,
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "abc1234deadbeef",
                }
            ]

        cistat.fetch_runs = _done
        cistat.format_run = lambda *_a, **_k: ["run ok"]
        rc = _quiet_save("o/r", "ci", "abc1234", str(out_dir), retries=1)
        saved = out_dir / "ci-abc1234.txt"
        if rc != 0 or not saved.is_file() or "head_sha=" not in saved.read_text():
            _die("ci-status --save must exit 0 with head_sha= for a completed run")
    finally:
        subprocess.run(["rm", "-rf", str(out_dir)], check=False)

    camod = _claim_audit_module()
    croot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (croot / "scripts").mkdir()
        pad = 'echo "---- pad ----"\n' * 4
        (croot / "scripts" / "fx-gate.sh").write_text(
            'NAME="rust"\nNAME_MIT="mit"\n'
            + pad
            + 'echo "==== value ===="  # MIT omits NULL\nOUT="$(docker exec "$NAME" true)"\n'
            + "echo \"$OUT\" | grep -F 'value=1'\n"
            + pad
            + 'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            + "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
        )
        ev = croot / "logs"
        ev.mkdir()
        stamp = "head_sha=0\ntree_sha=0\n"
        (ev / "x-unit-red.log").write_text(stamp + "dirty=yes\nvalue=1\n")
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"
        bullet = (
            "- **Text excuse only:** `value=1` at `scripts/fx-gate.sh:9` / `:15`; "
            "Red at parent `x-unit-red.log`.\n"
        )
        rows = camod.audit_text(head + bullet, croot, ev)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must not take a parent-red text excuse without red-at-parent=")
        (ev / "x-unit-red.log").write_text(
            stamp + "dirty=yes\nred-at-parent=1\nvalue=1\n"
        )
        rows = camod.audit_text(head + bullet, croot, ev)
        if any(r[1] != "ok" for r in rows):
            _die(f"claim-audit refused a dirty unit-red with red-at-parent=: {rows}")
    finally:
        subprocess.run(["rm", "-rf", str(croot)], check=False)

    # W1-Z Z3.1 freeze rule: a `Frozen-at: <sha>` summary resolves its cites at
    # that commit, so a later gate edit that drops the assertion does not
    # re-open the closed summary; the same bullet without the header is red.
    froot = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (froot / "scripts").mkdir()
        gate = froot / "scripts" / "fx-gate.sh"
        asserting = (
            'NAME="rust"\nNAME_MIT="mit"\n'
            'OUT="$(docker exec "$NAME" true)"\n'
            "echo \"$OUT\" | grep -F 'value=1'\n"
            'MIT_OUT="$(docker exec "$NAME_MIT" true)"\n'
            "echo \"$MIT_OUT\" | grep -F 'value=1'\n"
        )
        gate.write_text(asserting)
        genv = {
            **os.environ,
            "GIT_AUTHOR_NAME": "fx",
            "GIT_AUTHOR_EMAIL": "fx@x",
            "GIT_COMMITTER_NAME": "fx",
            "GIT_COMMITTER_EMAIL": "fx@x",
        }
        for cmd in (
            ["git", "init", "-q"],
            ["git", "add", "-A"],
            ["git", "commit", "-q", "-m", "fx"],
        ):
            subprocess.run(cmd, cwd=froot, check=True, env=genv, capture_output=True)
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=froot, check=True, capture_output=True, text=True
        ).stdout.strip()
        gate.write_text(asserting.replace("grep -F 'value=1'", "cat"))
        fev = froot / "logs"
        fev.mkdir()
        head = "## Settled live (every bullet names the asserting cell on both legs)\n\n"
        bullet = "- **Frozen cite:** `value=1` at `scripts/fx-gate.sh:4` / `:6`.\n"
        if camod.frozen_at(f"# T\n\nFrozen-at: `{sha[:12]}`\n\n" + head + bullet) != sha[:12]:
            _die("claim-audit frozen_at must read the `Frozen-at:` header")
        rows = camod.audit_text(head + bullet, froot, fev)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must read the working tree when no Frozen-at is given")
        rows = camod.audit_text(head + bullet, froot, fev, sha)
        if any(r[1] != "ok" for r in rows):
            _die(f"claim-audit must resolve a frozen cite at its sha: {rows}")
        rows = camod.audit_text(head + bullet, froot, fev, "0" * 40)
        if not any(r[1] != "ok" for r in rows):
            _die("claim-audit must fail a cite frozen at an unknown sha")
    finally:
        subprocess.run(["rm", "-rf", str(froot)], check=False)

    anchor_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        src = anchor_root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        tests_dir = anchor_root / "crates" / "demo" / "tests"
        tests_dir.mkdir(parents=True)
        good = src / "lib.rs"
        in_tests = tests_dir / "t.rs"
        in_tests.write_text("", encoding="utf-8")
        accepted = {
            "fn-anchor": "/// MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "line-comment": "// MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "inner-doc": "//! MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "block": "/* MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay */\n",
            "header-anchor": "/// MIT `krb5_get_init_creds_opt` (`krb5.hin:6839-6851`): the option block\n",
            "et-anchor": "/// MIT `KADM5_UNK_PRINC` (`kadm_err.et:54-54`): an unknown principal\n",
            "type-anchor": "/// MIT `struct extended_options` (`krb/gic_opt.c:19-32`): the option tail\n",
            "qualified-basename": "// MIT `init_realm` (`kdc/main.c:286-345`): the realm stanza wins\n",
            "mention": "/// MIT `KRB5_KDB_DISALLOW_TGT_BASED`.\n",
            "file-mention": "//! Context establishment (`init_sec_context.c`, `accept_sec_context.c`).\n",
            "file-and-mention": "/// MIT `pac.c` `MAX_BUFFERS`.\n",
            "bare-file-mention": "// The loop mirrors gic_pwd.c.\n",
            "anchor-and-mention": "/// MIT `f` (`a.c:1-2`): calls `g` in `b.c` first\n",
            "backtick-guarantee": "/// MIT `f` (`a.c:1-2`): `KDC_ERR_X` on a bad key\n",
        }
        for body in accepted.values():
            good.write_text(body, encoding="utf-8")
            check_mit_anchor_form(anchor_root, allow=0)
        good.write_text("", encoding="utf-8")
        in_tests.write_text(accepted["fn-anchor"], encoding="utf-8")
        check_mit_anchor_form(anchor_root, allow=0)
        in_tests.write_text("", encoding="utf-8")
        rejected = {
            "file-range-only": "/// (`do_as_req.c:10-20`)\n",
            "name-and-range": "/// MIT `krb5_rd_req` (`do_as_req.c:10-20`)\n",
            "file-point-only": "/// (`do_as_req.c:10`)\n",
            "bare-file": "/// MIT do_as_req.c:10 sets the flag\n",
            "name-and-point": "/// MIT `krb5_rd_req` (`do_as_req.c:10`)\n",
            "mit-backtick-point": "/// MIT `do_as_req.c:10` sets the flag\n",
            "prose-range": "// the check at do_tgs_req.c:10-20 runs first\n",
            "header-point": "// the rock (`kdc_util.h:422`)\n",
            "hin-range": "/// the option block (krb5.hin:6839-6851)\n",
            "et-point": "/// `kadm_err.et:54` names it\n",
            "multi-range": "/// (`server_stubs.c:478,519`)\n",
            "leftover-beside-anchor": "/// MIT `f` (`a.c:1-2`): checks first, see b.c:3\n",
            "two-anchors": "/// MIT `f` (`a.c:1-2`): x; MIT `g` (`b.c:3-4`): y\n",
            "no-guarantee": "/// MIT `f` (`a.c:1-2`):\n",
            "empty-guarantee": "/// MIT `f` (`a.c:1-2`): \n",
            "punct-guarantee": "/// MIT `stub_setup` (`server_stubs.c:296-301`): -638).\n",
            "paren-guarantee": "/// MIT `f` (`a.c:1-2`): (`g`,.\n",
            "same-check": "/// MIT `f` (`a.c:1-2`): same check.\n",
            "mit-guarantee": "/// MIT `f` (`a.c:1-2`): MIT.\n",
            "name-guarantee": "/// MIT `strdur` (`kadmin.c:118-138`): strdur.\n",
            "ambiguous-anchor": "// MIT `init_realm` (`main.c:286-345`): the realm stanza wins\n",
            "ambiguous-mention": "//! Principal names (`str_conv.c`).\n",
            "block-cite": "/* see do_as_req.c:10 */\n",
            "doc-block-cite": "/**\n * the check (`do_as_req.c:10-20`)\n */\n",
            "inner-doc-cite": "//! the check (`do_as_req.c:10-20`)\n",
            "line-comment-cite": "// the check (`do_as_req.c:10-20`)\n",
        }
        for shape, body in rejected.items():
            good.write_text(body, encoding="utf-8")
            _must_die_msg(
                "mit anchor lines 1 != allow 0",
                check_mit_anchor_form,
                anchor_root,
                allow=0,
            )
        good.write_text("", encoding="utf-8")
        in_tests.write_text(rejected["file-range-only"], encoding="utf-8")
        _must_die_msg(
            "mit anchor lines 1 != allow 0", check_mit_anchor_form, anchor_root, allow=0
        )
        check_mit_anchor_form(anchor_root, allow=1)
        _must_die_msg(
            "mit anchor lines 1 != allow 2",
            check_mit_anchor_form,
            anchor_root,
            allow=2,
        )
        # The shape names are part of the fixture, so a deleted shape is a
        # missing key, not a silent pass.
        if len(accepted) != 14 or len(rejected) != 26:
            _die("mit anchor fixtures dropped a shape")
    finally:
        subprocess.run(["rm", "-rf", str(anchor_root)], check=False)

    truth_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        fake = truth_root / "mit"
        for rel, text in {
            "lib/krb5/krb/gic_pwd.c": (
                "/* a file comment */\n\nstatic int\nhelper(int x)\n{\n    return callee(x);\n}\n\n"
                "/*\n * The password loop.\n */\nkrb5_error_code\n"
                "krb5_get_init_creds_password(int a)\n{\n    int r = helper(a);\n"
                "    if (isflagset(a, 1))\n        r = 1;\n    return r;\n}\n\n"
                "static const char *names[] = {\n    \"a\",\n};\n\nDEFFIELD(error_7, x, 7);\n"
            ),
            "include/k5-int.h": (
                "#define isflagset(flags, flag) \\\n    ((flags) & (flag))\n"
                "struct opt_tail {\n    int x;\n};\ntypedef struct {\n    int y;\n} opt_head;\n"
            ),
            "lib/kadm5/t_kadm5.c": "static void\nkinit(int x)\n{\n}\n",
            "kdc/main.c": "static void\ninit_realm(void)\n{\n}\n",
            "clients/ksu/main.c": "static void\ninit_realm(void)\n{\n}\n",
            "lib/kadm5/kadm_err.et": "error_table ovk\nerror_code KADM5_FAILURE, \"Operation failed\"\n",
            "kdc/fast_util.c": (
                "static krb5_error_code armor_ap_request\n(struct state *s)\n{\n"
                "    return 0;\n}\n"
            ),
            "include/k5-inline.h": (
                "/* Verify a key. */\nstatic inline int\nverify_key(int k)\n{\n    return k;\n}\n"
            ),
            "include/plugin.h": (
                "/* The handle method. */\ntypedef int\n(*handle_fn)(int context,\n"
                "                int flags);\n"
            ),
            "lib/kadm5/internal.h": (
                "typedef struct _handle_t {\n    int magic;\n} handle_rec, *handle_t;\n"
            ),
            "include/iprop.h": (
                "struct kdb_last_t {\n    int sno;\n};\ntypedef struct kdb_last_t kdb_last_t;\n"
            ),
            "lib/krb5/asn.1/asn1_k_encode.c": (
                "/*\n * SecureCookie ::= SEQUENCE {\n *     time INTEGER\n * }\n */\n"
                "DEFSEQTYPE(secure_cookie, krb5_secure_cookie, fields);\n"
            ),
        }.items():
            (fake / rel).parent.mkdir(parents=True, exist_ok=True)
            (fake / rel).write_text(text, encoding="utf-8")
        crate_src = truth_root / "crates" / "demo" / "src"
        crate_tests = truth_root / "crates" / "demo" / "tests"
        crate_src.mkdir(parents=True)
        crate_tests.mkdir(parents=True)

        def truth(body: str, in_tests: bool = False) -> int:
            (crate_src / "lib.rs").write_text("" if in_tests else body, encoding="utf-8")
            (crate_tests / "t.rs").write_text(body if in_tests else "", encoding="utf-8")
            return len(mit_anchor_truth_violations(truth_root, fake))

        holds = {
            "fn-body": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:14-18`): loops\n",
            "doc-block": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:9-19`): documented\n",
            "slack": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:6-19`): slack\n",
            "type": "// MIT `struct opt_tail` (`k5-int.h:3-5`): the tail\n",
            "typedef-tail": "// MIT `opt_head` (`k5-int.h:6-8`): the head\n",
            "header-macro": "// MIT `isflagset` (`k5-int.h:1-2`): tests a flag\n",
            "data": "// MIT `names` (`gic_pwd.c:21-23`): the table\n",
            "macro-gen": "// MIT `error_7` (`gic_pwd.c:25-25`): the field\n",
            "errcode": "// MIT `KADM5_FAILURE` (`kadm_err.et:2-2`): unspecified\n",
            "qualified": "// MIT `init_realm` (`kdc/main.c:2-4`): realm first\n",
            "mention": "//! Mirrors `gic_pwd.c` and `kdc/main.c`.\n",
            "split-declarator": "// MIT `armor_ap_request` (`fast_util.c:3-5`): armor first\n",
            "static-inline": "// MIT `verify_key` (`k5-inline.h:1-6`): the key check\n",
            "fn-pointer-typedef": "// MIT `handle_fn` (`plugin.h:1-4`): the method\n",
            "typedef-list-tail": "// MIT `handle_rec` (`internal.h:3-3`): the handle\n",
            "rpcgen-typedef": "// MIT `kdb_last_t` (`iprop.h:1-4`): the last entry\n",
            "asn1-comment": "// MIT `SecureCookie` (`asn1_k_encode.c:2-4`): the cookie\n",
        }
        for label, body in holds.items():
            if truth(body) != 0:
                _die(f"check_mit_anchor_truth must accept {label}: {mit_anchor_truth_violations(truth_root, fake)}")
        if truth("// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n", in_tests=True) != 0:
            _die("check_mit_anchor_truth must accept a test citing MIT test code")
        breaks = {
            "callee": "// MIT `callee` (`gic_pwd.c:6-6`): calls\n",
            "macro-slot": "// MIT `isflagset` (`gic_pwd.c:16-16`): tests\n",
            "wrong-fn": "// MIT `helper` (`gic_pwd.c:15-15`): helps\n",
            "lead-overhang": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:5-19`): early\n",
            "tail-overhang": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:14-20`): late\n",
            "test-from-src": "// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n",
            "ambiguous": "// MIT `init_realm` (`main.c:2-4`): realm first\n",
            "unknown-file": "// MIT `f` (`nosuch.c:1-2`): gone\n",
            "mention-unknown": "//! Mirrors `nosuch.c`.\n",
            "mention-ambiguous": "//! Mirrors `main.c`.\n",
        }
        for label, body in breaks.items():
            if truth(body) != 1:
                _die(f"check_mit_anchor_truth must flag {label} once: {mit_anchor_truth_violations(truth_root, fake)}")
        truth(breaks["callee"])
        check_mit_anchor_truth(truth_root, fake, allow=1)
        _must_die_msg("mit anchor truth 1 != allow 0", check_mit_anchor_truth, truth_root, fake, allow=0)
        _must_die_msg("_AMBIGUOUS_MIT_BASENAMES differs", _check_ambiguous_pin, fake)
        if len(holds) != 17 or len(breaks) != 10:
            _die("mit anchor truth fixtures dropped a case")
    finally:
        subprocess.run(["rm", "-rf", str(truth_root)], check=False)

    tag_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        src = tag_root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        good = src / "lib.rs"
        for body in (
            "// the parent principal stays\n",
            "/// the magic word `deadbeef` and `0x12345678`\n",
            "/// each item is checked; networking/ is not a path here\n",
            "/// a SHA-256 digest; B-frames; F-strings\n",
        ):
            good.write_text(body, encoding="utf-8")
            check_no_process_history(tag_root, allow=0)
        good.write_text('fn f() {\n    let s = "// R12 in a string";\n}\n', encoding="utf-8")
        check_no_process_history(tag_root, allow=0)
        tagged = {
            "R12": "// R12 left the suppression\n",
            "A-prime": "// A\u2032-3 item 14\n",
            "W0": "// W0e H7\n",
            "W1": "// W1-Z follow-up\n",
            "Round": "// Round 2\n",
            "parent": "// parent abcdef0\n",
            "R2-S3": "// limit (R2-S3).\n",
            "B3": "// referral (B3).\n",
            "Y0": "// the Y0 mismatch\n",
            "Z": "// before Z6.3 the wire code was 60\n",
            "sha": "//! the check landed in `59c363b`.\n",
            "parent-red": "//! the unit is (parent-red).\n",
            "compiles-at": "//! Compiles at the parent and fails there.\n",
            "item": "/// order stays item 15.\n",
            "S-section": "// Helpers moved here in S2.3.\n",
            "Z-leftover": "//! Z8 leftover: the stamp.\n",
            "B-F": "//! F4 hierarchical referral.\n",
            "the-parent": "//! at the parent `abcdef0` it fails.\n",
            "working": "//! see `working/logs/x.log`.\n",
        }
        for body in tagged.values():
            good.write_text(body, encoding="utf-8")
            _must_die_msg(
                "process-history lines 1 != allow 0",
                check_no_process_history,
                tag_root,
                allow=0,
            )
        good.write_text(tagged["B3"], encoding="utf-8")
        check_no_process_history(tag_root, allow=1)
        if len(tagged) != 19:
            _die("process-history fixtures dropped a tag")
    finally:
        subprocess.run(["rm", "-rf", str(tag_root)], check=False)

    # S6-14: the module-attribute consumers, each missing name and each shape red.
    check_policy_module_attrs()
    mod_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        full = {
            "ROOT": "import pathlib\nROOT = pathlib.Path('/nonexistent')\n",
            "_dump_key_hexes": "def _dump_key_hexes(line):\n    return None\n",
            "check_golden_dump_unique_keys": "def check_golden_dump_unique_keys():\n    pass\n",
            "DIFFSEND_CASES": f"DIFFSEND_CASES = frozenset({sorted(DIFFSEND_CASES)!r})\n",
            "ledger_sources": "def ledger_sources(root=None):\n    return [('docs/parity/README.md', '', None)]\n",
            "recount_ledger_verdicts": "def recount_ledger_verdicts(text):\n    return {}\n",
            "_split_ledger_row": "def _split_ledger_row(line):\n    return []\n",
        }
        fake = mod_root / "ci-policy.py"
        fake.write_text("".join(full.values()), encoding="utf-8")
        check_policy_module_attrs(fake)
        for gone, consumer in (("_dump_key_hexes", "kdb-dump-gate.sh"), ("ledger_sources", "hygiene_inventory.py")):
            fake.write_text("".join(v for k, v in full.items() if k != gone), encoding="utf-8")
            _must_die_msg(f"lacks {gone}, which scripts/", check_policy_module_attrs, fake)
            _must_die_msg(consumer, check_policy_module_attrs, fake)
        fake.write_text("".join(full.values()).replace(full["DIFFSEND_CASES"], "DIFFSEND_CASES = frozenset({'x'})\n"),
                        encoding="utf-8")
        _must_die_msg("holds 1 DIFFSEND_CASES", check_policy_module_attrs, fake)
        fake.write_text(
            "".join(full.values()).replace("docs/parity/README.md", "docs/mit-parity-ledger.md"), encoding="utf-8"
        )
        _must_die_msg("not the docs/parity/ split", check_policy_module_attrs, fake)
        fake.write_text("raise SystemExit('no import')\n", encoding="utf-8")
        _must_die_msg("does not load as a module from cwd=/", check_policy_module_attrs, fake)
    finally:
        subprocess.run(["rm", "-rf", str(mod_root)], check=False)
