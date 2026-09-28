"""The self-test of the gate-script checks."""

from __future__ import annotations

import pathlib
import tempfile

from ..gates import (
    GATE_COMMON_NEEDLES, _gate_unit_index, check_capture_env_only, check_gate_cargo_leftover, check_gate_common_sourced,
    check_gate_no_exit_trap, check_gate_provenance, check_gate_unit_index, check_gate_wall,
    check_golden_dump_unique_keys, check_kadmin_glob_lib, check_kadmin_split_snaps, check_kcm_need_image,
    check_kcm_stop_before_run, check_log_arity, check_need_bins_strict, check_no_gate_cargo_build,
    check_peers_unavailable_convention, check_prod_gate_tcpdump_cleanup, check_provenance_memo, check_s4_shared_boots,
    check_samba_kdc_respawn, check_sleep_classifiers_agree, check_sleep_ratchet, check_stock_boots_per_job,
    check_trace_dst,
)
from .common import _must_die, _must_die_msg


def _self_test_gates_1() -> None:
    check_provenance_memo()
    memo_ok = {
        "scripts/lib/provenance.sh": 'if [ -n "${KERBER_PROV_MEMO:-}" ]; then read -r id sha <"$KERBER_PROV_MEMO"; fi\n',
        "scripts/checkpoint.sh": 'KERBER_PROV_MEMO="$(mktemp "$KERBER_SCRATCH/prov-memo.XXXXXX")"\nrm -f "$KERBER_PROV_MEMO"\n',
        "scripts/red-at-sha.sh": 'KERBER_PROV_MEMO="$(mktemp "$KERBER_SCRATCH/prov-memo.XXXXXX")"\nrm -f "$KERBER_PROV_MEMO"\n',
        "scripts/ci_policy/__init__.py": 'os.environ.setdefault("KERBER_SCRATCH", str(_scratch_root()))\n',
    }
    check_provenance_memo(memo_ok)
    _must_die_msg("never a prov-<image> file", check_provenance_memo,
                  {**memo_ok, "scripts/lib/provenance.sh": '_memo="${_prov_dir}/prov-${_img_key}"\nKERBER_PROV_MEMO\n'})
    _must_die_msg("scripts/checkpoint.sh must make KERBER_PROV_MEMO", check_provenance_memo,
                  {**memo_ok, "scripts/checkpoint.sh": memo_ok["scripts/checkpoint.sh"].replace("rm -f", "true")})
    _must_die_msg("scripts/red-at-sha.sh must make KERBER_PROV_MEMO", check_provenance_memo,
                  {**memo_ok, "scripts/red-at-sha.sh": 'KERBER_PROV_MEMO="$(mktemp)"\nrm -f "$KERBER_PROV_MEMO"\n'})
    _must_die_msg("give the scripts it runs a KERBER_SCRATCH", check_provenance_memo,
                  {**memo_ok, "scripts/ci_policy/__init__.py": ""})
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

    check_gate_provenance('. "$ROOT/scripts/lib/provenance.sh"\n', "ok-gate.sh")
    _must_die(check_gate_provenance, "#!/bin/bash\necho hi\n", "no-prov-gate.sh")
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


def _self_test_gates_2() -> None:
    dst_ok = 'TRACE_DST="${KERBER_TRACE_DST:-${KERBER_SCRATCH}/traces}"\n'
    check_trace_dst({"kdc-gate.sh": dst_ok, "client-gate.sh": dst_ok})
    _must_die(
        check_trace_dst,
        {
            "kdc-gate.sh": 'TRACE_DST="${KERBER_TRACE_DST:-$ROOT/tests/traces}"\n',
            "client-gate.sh": dst_ok,
        },
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
