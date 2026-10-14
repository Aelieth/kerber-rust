"""The self-test of the workflow, Makefile, nextest and CI-budget checks."""

from __future__ import annotations

import pathlib

from ..workflows import (
    SHELLCHECK_CMD, Workflow, check_all_timeouts, check_build_profile, check_ci, check_ci_budgets,
    check_ci_nextest_split, check_ci_no_workspace_cargo_test, check_env_read, check_full_run_scheduled,
    check_gate_membership, check_makefile_matches_ci, check_msrv_pinned, check_nextest_profile, check_nightly,
    check_prod_image_once, check_rust_cache_shared_key, check_workflow_hardening,
)
from .common import _must_die, good_toml


def _self_test_workflows() -> None:
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
    preamble_pin = (
        "inputs:\n  toolchain:\n    description: rustup toolchain\n    required: false\n"
        '    default: "1.99.0"\n  components:\n    default: ""\n'
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "1.99.0"\n', msrv_ok, preamble_pin)
    sha_pinned = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: dtolnay/rust-toolchain@" + "a" * 40 + " # stable\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "1.99.0"\n', {"ci.yml": sha_pinned, "full-test.yml": msrv_ok["full-test.yml"]}, preamble_pin)
    via_preamble = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: ./.github/actions/rust-preamble\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "1.99.0"\n', {"ci.yml": via_preamble, "full-test.yml": msrv_ok["full-test.yml"]}, preamble_pin)
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": via_preamble.replace('          toolchain: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
        preamble_pin,
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": sha_pinned.replace('          toolchain: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
        preamble_pin,
    )
    _must_die(check_msrv_pinned, '[package]\nrust-version = "1.90"\n', manifest_ok, 'channel = "1.99.0"\n', msrv_ok, preamble_pin)
    _must_die(check_msrv_pinned, manifest_ok, "[package]\n", 'channel = "1.99.0"\n', msrv_ok, preamble_pin)
    # A floating channel, a two-part version, and a pin the preamble does not install.
    _must_die(check_msrv_pinned, manifest_ok, manifest_ok, 'channel = "stable"\n', msrv_ok, preamble_pin)
    _must_die(check_msrv_pinned, manifest_ok, manifest_ok, 'channel = "1.99"\n', msrv_ok, preamble_pin)
    _must_die(check_msrv_pinned, manifest_ok, manifest_ok, 'channel = "1.98.0"\n', msrv_ok, preamble_pin)
    _must_die(
        check_msrv_pinned, manifest_ok, manifest_ok, 'channel = "1.99.0"\n', msrv_ok,
        preamble_pin.replace('default: "1.99.0"', "default: stable"),
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": msrv_wf.format(job="msrv").replace('      RUSTUP_TOOLCHAIN: "1.95"\n', ""), "full-test.yml": msrv_ok["full-test.yml"]},
        preamble_pin,
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": msrv_ok["ci.yml"], "full-test.yml": msrv_ok["full-test.yml"].replace("@1.95", "@stable")},
        preamble_pin,
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
