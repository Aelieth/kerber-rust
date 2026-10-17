"""The self-test of the kept workflow, Makefile, nextest and MSRV checks."""

from __future__ import annotations

import pathlib

from ..workflows import (
    SHELLCHECK_CMD, Workflow, check_all_timeouts, check_makefile_matches_ci, check_msrv_pinned,
    check_nextest, check_workflow_hardening, check_working_gitignored,
)
from .common import _must_die


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
        "nightly.yml": msrv_wf.format(job="msrv-test"),
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
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "1.99.0"\n', {"ci.yml": sha_pinned, "nightly.yml": msrv_ok["nightly.yml"]}, preamble_pin)
    via_preamble = msrv_ok["ci.yml"].replace(
        "      - uses: dtolnay/rust-toolchain@1.95\n",
        "      - uses: ./.github/actions/rust-preamble\n        with:\n          toolchain: \"1.95\"\n",
    )
    check_msrv_pinned(manifest_ok, manifest_ok, 'channel = "1.99.0"\n', {"ci.yml": via_preamble, "nightly.yml": msrv_ok["nightly.yml"]}, preamble_pin)
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": via_preamble.replace('          toolchain: "1.95"\n', ""), "nightly.yml": msrv_ok["nightly.yml"]},
        preamble_pin,
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": sha_pinned.replace('          toolchain: "1.95"\n', ""), "nightly.yml": msrv_ok["nightly.yml"]},
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
        {"ci.yml": msrv_wf.format(job="msrv").replace('      RUSTUP_TOOLCHAIN: "1.95"\n', ""), "nightly.yml": msrv_ok["nightly.yml"]},
        preamble_pin,
    )
    _must_die(
        check_msrv_pinned,
        manifest_ok,
        manifest_ok,
        'channel = "1.99.0"\n',
        {"ci.yml": msrv_ok["ci.yml"], "nightly.yml": msrv_ok["nightly.yml"].replace("@1.95", "@stable")},
        preamble_pin,
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
    check_nextest()
    check_working_gitignored()
