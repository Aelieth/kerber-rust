"""Checks on the gate scripts: gate-common, shared boots, sleeps and walls, helpers, peers, captures."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import tempfile

from .common import ROOT, SCRIPTS, WORKFLOWS, _die, _hygiene_inventory, _scratch_root
from .workflows import RUST_PREAMBLE, Workflow

GATE_WALL_MAX = 45
GATE_PROTO_SLEEP_MAX = 26.0
UNIT_SLEEP_MAX = 14
EXCEPTIONS_REL = "scripts/gate-wall-exceptions.txt"


_PROVENANCE_SRC = re.compile(
    r"""\.\s+["']\$ROOT/scripts/lib/provenance\.sh["']"""
)


def check_gate_provenance(text: str | None = None, name: str = "gate.sh") -> None:
    """Every *-gate.sh and red-at-sha.sh must source the stamp helper."""
    if text is not None:
        if not _PROVENANCE_SRC.search(text):
            _die(f"{name} must source scripts/lib/provenance.sh")
        return
    missing: list[str] = []
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        if not _PROVENANCE_SRC.search(path.read_text()):
            missing.append(path.name)
    ras = SCRIPTS / "red-at-sha.sh"
    if ras.is_file() and not _PROVENANCE_SRC.search(ras.read_text()):
        missing.append(ras.name)
    if missing:
        _die(f"must source scripts/lib/provenance.sh: {missing}")


_PROV_MEMO_RUNNERS = ("scripts/checkpoint.sh", "scripts/red-at-sha.sh")
_PROV_MEMO_MAKE = 'KERBER_PROV_MEMO="$(mktemp "$KERBER_SCRATCH/prov-memo.XXXXXX")"'


def check_provenance_memo(texts: dict[str, str] | None = None) -> None:
    """provenance.sh writes no file of its own that outlives it: the MIT image's kadm5.acl memo is
    only the KERBER_PROV_MEMO file a runner (checkpoint.sh, red-at-sha.sh) makes with mktemp under
    its KERBER_SCRATCH and removes on exit, and ci-policy gives the scripts it runs a scratch. The
    old memo, `prov-<image>` in `${KERBER_SCRATCH:-${TMPDIR:-/tmp}}`, was left in host /tmp by any
    run with neither variable set."""
    live = texts is None
    if texts is None:
        names = ["scripts/lib/provenance.sh", *_PROV_MEMO_RUNNERS, "scripts/ci_policy/__init__.py"]
        texts = {n: (ROOT / n).read_text(encoding="utf-8") for n in names}
    prov = texts.get("scripts/lib/provenance.sh", "")
    if "/prov-${" in prov or "KERBER_PROV_MEMO" not in prov:
        _die("provenance.sh must memoise only through KERBER_PROV_MEMO, never a prov-<image> file of its own")
    for runner in _PROV_MEMO_RUNNERS:
        text = texts.get(runner, "")
        if _PROV_MEMO_MAKE not in text or 'rm -f "$KERBER_PROV_MEMO"' not in text:
            _die(f"{runner} must make KERBER_PROV_MEMO with mktemp under KERBER_SCRATCH and remove it on exit")
    if 'os.environ.setdefault("KERBER_SCRATCH"' not in texts.get("scripts/ci_policy/__init__.py", ""):
        _die("ci-policy must give the scripts it runs a KERBER_SCRATCH")
    if not live:
        return
    probe = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        env = {k: v for k, v in os.environ.items() if k not in ("KERBER_SCRATCH", "KERBER_PROV_MEMO")}
        env.update({"TMPDIR": str(probe), "KERBER_NO_IMAGE": "1"})
        r = subprocess.run(["bash", "-c", ". scripts/lib/provenance.sh"], cwd=ROOT, env=env, capture_output=True,
                           text=True, check=False)
        if r.returncode != 0:
            _die(f"provenance.sh failed with no scratch set: {(r.stdout + r.stderr)[-300:]}")
        left = sorted(p.name for p in probe.iterdir())
        if left:
            _die(f"provenance.sh with no KERBER_SCRATCH left files in TMPDIR: {left}")
    finally:
        subprocess.run(["rm", "-rf", str(probe)], check=False)


def check_docker_cp_cargo_target() -> None:
    """Gate docker cp must use ${CARGO_TARGET_DIR:-target}/debug (not a bare target/debug)."""
    bare: list[str] = []
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        text = path.read_text()
        if "docker cp target/debug/" in text:
            bare.append(path.name)
        if "docker cp" in text and "CARGO_TARGET_DIR:-target" not in text:
            # Some gates only docker cp fixtures; require the expansion when copying binaries.
            if re.search(r"docker cp .*krb5-|docker cp .*diffsend|docker cp .*examples/", text):
                bare.append(path.name)
    if bare:
        _die(
            "docker cp of cargo binaries must use "
            "${CARGO_TARGET_DIR:-target}/debug: "
            f"{sorted(set(bare))}"
        )


def _gate_unit_index():
    spec = importlib.util.spec_from_file_location(
        "gate_unit_index", SCRIPTS / "lib" / "gate_unit_index.py"
    )
    if spec is None or spec.loader is None:
        _die("cannot load scripts/lib/gate_unit_index.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CAPTURE_ENV_RE = re.compile(r"""(?:env::var(?:_os)?|option_env!)\(\s*"([^"]+)"\s*\)""")
_CAPTURE_ASSIGN_RE = re.compile(r"""KERBER_CAPTURE_DIR\s*[=:]\s*([^\s\\#'"]+|['"][^'"]+['"])""")


def _capture_product(text: str) -> str:
    i = text.find("#[cfg(test)]")
    return text if i < 0 else text[:i]


def _is_golden_capture_path(val: str) -> bool:
    norm = val.strip().strip("\"'").replace("\\", "/")
    parts = [p for p in norm.split("/") if p and p != "$ROOT"]
    return any(
        parts[i] == "tests" and parts[i + 1] == "traces" for i in range(len(parts) - 1)
    )


def check_capture_env_only(
    capture_text: str | None = None,
    common_text: str | None = None,
    script_texts: dict[str, str] | None = None,
) -> None:
    """capture.rs reads no env but KERBER_CAPTURE_DIR; no script sets it under tests/traces."""
    if capture_text is None:
        path = ROOT / "crates" / "krb5-protocol" / "src" / "capture.rs"
        if not path.is_file():
            _die("missing crates/krb5-protocol/src/capture.rs")
        capture_text = path.read_text(encoding="utf-8")
    product = _capture_product(capture_text)
    envs = set(_CAPTURE_ENV_RE.findall(product))
    if envs != {"KERBER_CAPTURE_DIR"}:
        _die(
            "capture.rs product must read only KERBER_CAPTURE_DIR, got "
            + ", ".join(sorted(envs) or ["<none>"])
        )
    if "KERBER_SCRATCH" in product or "CARGO_TARGET_DIR" in product:
        _die("capture.rs product must not name KERBER_SCRATCH or CARGO_TARGET_DIR")
    if common_text is None:
        common = SCRIPTS / "lib" / "gate-common.sh"
        if not common.is_file():
            _die("missing scripts/lib/gate-common.sh")
        common_text = common.read_text(encoding="utf-8")
    if "refuse_golden_capture_dir" not in common_text:
        _die("gate-common.sh must define refuse_golden_capture_dir")
    live_scan = script_texts is None
    if script_texts is None:
        script_texts = {}
        for p in sorted(SCRIPTS.glob("*.sh")) + sorted((SCRIPTS / "lib").glob("*.sh")):
            script_texts[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
        harness = ROOT / "harness"
        if harness.is_dir():
            for p in sorted(harness.rglob("*.sh")):
                script_texts[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
        wf = ROOT / ".github" / "workflows"
        if wf.is_dir():
            for p in sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))):
                script_texts[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
    if live_scan or any(rel in script_texts for rel in _REQUIRED_REFUSE_CALLERS):
        for rel in _REQUIRED_REFUSE_CALLERS:
            if not live_scan and rel not in script_texts:
                continue
            caller = script_texts.get(rel, "")
            if not _REFUSE_CALL_RE.search(caller):
                _die(f"{rel} must call refuse_golden_capture_dir")
    for name, text in script_texts.items():
        for m in _CAPTURE_ASSIGN_RE.finditer(text):
            if _is_golden_capture_path(m.group(1)):
                _die(f"{name} sets KERBER_CAPTURE_DIR under tests/traces")


def check_gate_unit_index(
    root: pathlib.Path | None = None,
    gate: str | None = None,
    doc: str | None = None,
) -> None:
    """Every differential-gate.sh status-word cell has a tagged unit twin."""
    mod = _gate_unit_index()
    root = pathlib.Path(root) if root is not None else ROOT
    if gate is None:
        path = SCRIPTS / "differential-gate.sh"
        if not path.is_file():
            _die("missing scripts/differential-gate.sh")
        gate = path.read_text(encoding="utf-8")
    if doc is None:
        doc_path = root / "docs" / "gate-unit-index.md"
        if not doc_path.is_file():
            _die("missing docs/gate-unit-index.md")
        doc = doc_path.read_text(encoding="utf-8")
    try:
        mod.verify(root, gate, doc)
    except mod.GateIndexError as e:
        _die(str(e))


def _dump_key_hexes(line: str) -> tuple[str, tuple[str, ...]] | None:
    """Name and every key_data slot-0 hex from a princ dump line, or None."""
    if not line.startswith("princ\t"):
        return None
    f = line.rstrip(";").split("\t")
    if len(f) < 16:
        return None
    try:
        n_tl = int(f[3])
        n_key = int(f[4])
    except ValueError:
        return None
    i = 15 + 3 * n_tl
    hexes: list[str] = []
    for _ in range(n_key):
        if i + 4 >= len(f):
            return None
        try:
            ver = int(f[i])
        except ValueError:
            return None
        # ver, kvno, then ver × (type, length, hex); slot 0 is the key.
        i += 2
        if i + 2 >= len(f):
            return None
        hexes.append(f[i + 2])
        i += 3 * ver
    if not hexes:
        return None
    return f[6], tuple(hexes)


def check_golden_dump_unique_keys(text: str | None = None) -> None:
    """Golden dump nosvr/hwuser key blobs are MIT-derived, not clones of user/pwprau."""
    if text is None:
        path = ROOT / "tests" / "traces" / "kdb" / "mit-dump-v7.txt"
        if not path.is_file():
            _die("missing tests/traces/kdb/mit-dump-v7.txt")
        text = path.read_text()
    keys: dict[str, tuple[str, ...]] = {}
    for line in text.splitlines():
        parsed = _dump_key_hexes(line)
        if parsed is None:
            continue
        name, hexes = parsed
        keys[name] = hexes
    for need in (
        "user@KERBER.TEST",
        "nosvr@KERBER.TEST",
        "hwuser@KERBER.TEST",
        "pwprau@KERBER.TEST",
    ):
        if need not in keys:
            _die(f"golden dump missing {need}")
    if keys["nosvr@KERBER.TEST"] == keys["user@KERBER.TEST"]:
        _die("nosvr keys clone user")
    if keys["hwuser@KERBER.TEST"] == keys["pwprau@KERBER.TEST"]:
        _die("hwuser keys clone pwprau")


def check_trace_dst(texts: dict[str, str] | None = None) -> None:
    """Gate captures must not default into tests/traces (S5)."""
    names = ("kdc-gate.sh", "client-gate.sh")
    if texts is None:
        texts = {}
        for name in names:
            path = SCRIPTS / name
            if not path.is_file():
                _die(f"missing scripts/{name}")
            texts[name] = path.read_text(encoding="utf-8")
    for name in names:
        text = texts.get(name, "")
        if 'KERBER_TRACE_DST:-$ROOT/tests/traces' in text:
            _die(f"{name} must not default TRACE_DST to tests/traces")
        if "KERBER_SCRATCH" not in text or "TRACE_DST" not in text:
            _die(f"{name} must default TRACE_DST under KERBER_SCRATCH")


GATE_COMMON_NEEDLES = (
    "log()",
    "die()",
    "unavailable()",
    "need_bins",
    "need_image",
    "gate_wall_s=",
    "wait_port_in",
    "require_listen",
    "require_log",
    "require_port_in",
    "retry_until",
    "wait_udp_in",
    "wait_tcp_bound_in",
    "wait_gone_in",
    "wait_pid_gone",
    "stock_mit_kdc",
    "shell_container",
    "mit_live_guard",
    "mit_conf_restore",
    "find /tmp -mindepth 1 -maxdepth 1",
    "! -name 'build'",
    "kdb5_util destroy",
    "krb5.conf.kerber-stock",
    "kill_proxy_py_in",
    "wait_bound_free_in",
    "samba_kdc_respawn_in",
)


def check_log_arity(common_text: str | None = None) -> None:
    """log() refuses a call that is not 2 or 3 args (W2-Y5)."""
    if common_text is None:
        path = SCRIPTS / "lib" / "gate-common.sh"
        if not path.is_file():
            _die("missing scripts/lib/gate-common.sh")
        common_text = path.read_text(encoding="utf-8")
    m = re.search(r"^log\(\) \{.*?\n\}", common_text, re.M | re.S)
    if not m:
        _die("gate-common.sh must define log()")
    body = m.group(0)
    if '"$#"' not in body:
        _die("log() must check $# arity")
    if "expected 2-3" not in body:
        _die("log() must refuse arity other than 2-3")
_REFUSE_CALL_RE = re.compile(r"^\s*refuse_golden_capture_dir\s+\S", re.M)
_REQUIRED_REFUSE_CALLERS = (
    "scripts/lib/prod-realm-common.sh",
    "harness/prod/env-up.sh",
)


def check_gate_common_sourced(
    common_text: str | None = None,
    gate_texts: dict[str, str] | None = None,
) -> None:
    """Every gate sources gate-common.sh; no private log()/cleanup(); no cargo build."""
    if common_text is None:
        common = SCRIPTS / "lib" / "gate-common.sh"
        if not common.is_file():
            _die("missing scripts/lib/gate-common.sh")
        common_text = common.read_text(encoding="utf-8")
    for needle in GATE_COMMON_NEEDLES:
        if needle not in common_text:
            _die(f"gate-common.sh missing {needle}")
    if "pkill -f -- '-proxy.py'" in (common_text or "") and "kill_proxy_py_in" not in common_text:
        _die("gate-common.sh must pin kill_proxy_py_in, not only pkill")
    if "GITHUB_ACTIONS" not in common_text or "::error file=" not in common_text:
        _die("die must print ::error file=… when GITHUB_ACTIONS is set")
    if "::notice file=" not in common_text:
        _die("unavailable must print ::notice file=… when GITHUB_ACTIONS is set")
    if gate_texts is None:
        items = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*-gate.sh"))
        }
        live = True
    else:
        items = gate_texts
        live = False
    for name, text in items.items():
        if "scripts/lib/gate-common.sh" not in text:
            _die(f"{name} must source scripts/lib/gate-common.sh")
        if re.search(r"^log\(\)", text, re.M):
            _die(f"{name} still defines a private log()")
        if re.search(r"^cleanup\(\)", text, re.M):
            _die(f"{name} still defines a private cleanup()")
        check_gate_no_exit_trap(text, name)
        if name in ("kadmin-rust-gate.sh", "kadmin-rust-acl-gate.sh", "kadmin-mit-gate.sh", "kadmin-both-gate.sh") and "kadmin-glob-cells.sh" not in text:
            _die(f"{name} must source scripts/lib/kadmin-glob-cells.sh")
        if name in ("kadmin-rust-gate.sh", "kadmin-mit-gate.sh"):
            if re.search(r'wait_port_in\s+"\$NAME(_MIT)?"\s+1749', text):
                _die(f"{name} tamper proxy is single-accept; use wait_tcp_bound_in, not wait_port_in")
            if "wait_tcp_bound_in" not in text:
                _die(f"{name} must wait_tcp_bound_in for the integrity tamper proxy")
        check_kadmin_split_snaps(text, name)
        if name == "kcm-gate.sh":
            check_kcm_need_image(text)
            check_kcm_stop_before_run(text, name)
        if name == "prod-gate.sh":
            check_prod_gate_tcpdump_cleanup(text)
        if re.search(r"krb5kdc -n >/tmp/mit-kdc.log 2>&1 & cat", text):
            _die(f"{name} must wait_log for krb5kdc -n, not cat the log immediately")
    check_no_gate_cargo_build(items)
    idx = common_text.find("samba_kdc_respawn_in()")
    end = common_text.find("wait_pid_gone()", idx) if idx >= 0 else -1
    if idx >= 0 and end > idx and "wait_udp_in" in common_text[idx:end]:
        _die("samba_kdc_respawn_in must wait for a new task[kdc] pid, not wait_udp_in :88")
    if live:
        ci_yml = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        if "gate-attach-reset-selftest.sh" not in ci_yml:
            _die("ci.yml must run gate-attach-reset-selftest.sh")
        check_kadmin_glob_lib()
        check_s4_shared_boots()
        check_build_bins_examples()


def check_s4_shared_boots(ci_text: str | None = None) -> None:
    """harness and mit-extra boot one stock MIT KDC and one shell per job."""
    if ci_text is None:
        ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    if "boot-stock-mit.sh" not in ci_text:
        _die("ci.yml must run scripts/lib/boot-stock-mit.sh")
    if "boot-shell.sh" not in ci_text:
        _die("ci.yml must run scripts/lib/boot-shell.sh")
    if ci_text.count("boot-stock-mit.sh") < 4:
        _die("ci.yml must boot stock MIT in harness, harness-2, mit-extra, and mit-extra-2")
    if ci_text.count("boot-shell.sh") < 4:
        _die("ci.yml must boot a shared shell in harness, harness-2, mit-extra, and mit-extra-2")


def check_stock_boots_per_job(ci_text: str | None = None) -> None:
    """Plan name for the S4 shared-boot contract."""
    check_s4_shared_boots(ci_text)


def classify_gate_sleeps(text: str) -> list[tuple[str, float]]:
    inv = _hygiene_inventory()
    return [(kind, float(sec)) for _ln, sec, kind in inv.classify_sleeps(text)]


def check_sleep_classifiers_agree(text: str | None = None) -> None:
    """ci-policy and the snapshot must book the same kind for each sleep."""
    inv = _hygiene_inventory()

    def one(label: str, body: str) -> None:
        policy = classify_gate_sleeps(body)
        inventory = [(kind, float(sec)) for _ln, sec, kind in inv.classify_sleeps(body)]
        if policy != inventory:
            _die(f"sleep classifiers disagree in {label}: policy={policy} inventory={inventory}")

    if text is not None:
        one("fixture", text)
        return
    one(
        "self",
        "for _ in $(seq 1 10); do\n"
        "    sleep 0.1\n"
        "done\n"
        "sleep 0.1 # proto: krb5kdc pid reuse\n"
        + ("# pad\n" * 40)
        + "sleep 0.1 # proto: far from any loop\n",
    )
    for path in sorted(SCRIPTS.glob("*-gate.sh")):
        one(path.name, path.read_text(encoding="utf-8"))
    common = SCRIPTS / "lib" / "gate-common.sh"
    if common.is_file():
        one(common.name, common.read_text(encoding="utf-8"))


def check_gate_wall(
    exceptions_text: str | None = None,
    timings_text: str | None = None,
) -> None:
    """Checkpoint gate walls ≤ 45 s; exceptions file must be empty."""
    if exceptions_text is None:
        path = ROOT / EXCEPTIONS_REL
        if not path.is_file():
            _die(f"missing {EXCEPTIONS_REL}")
        exceptions_text = path.read_text(encoding="utf-8")
    for i, line in enumerate(exceptions_text.splitlines(), 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            _die(f"{EXCEPTIONS_REL}:{i} must be empty (no gate-wall exceptions)")
    texts: list[str] = []
    if timings_text is not None:
        texts = [timings_text]
    else:
        args = sys.argv[1:]
        if "--timings" in args:
            idx = args.index("--timings")
            if idx + 1 >= len(args):
                _die("--timings needs a path")
            tpath = pathlib.Path(args[idx + 1])
            if not tpath.is_file():
                _die(f"missing timings file {tpath}")
            texts = [tpath.read_text(encoding="utf-8")]
        elif "--checkpoint" in args:
            log_root = ROOT / "working" / "logs"
            texts = [
                p.read_text(encoding="utf-8")
                for p in log_root.rglob("timings.tsv")
                if p.is_file()
            ]
        else:
            return
    for text in texts:
        n_rows = 0
        n_rc0 = 0
        for i, line in enumerate(text.splitlines()):
            if i == 0 and line.startswith("gate"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            try:
                wall = int(parts[3])
                rc = int(parts[2])
            except ValueError:
                continue
            n_rows += 1
            if rc == 0:
                n_rc0 += 1
            if wall > GATE_WALL_MAX:
                _die(f"gate {parts[0]} wall_s={wall} exceeds {GATE_WALL_MAX}")
        if n_rows and n_rc0 == 0:
            _die("checkpoint timings have zero gate_rc=0 rows")


def check_sleep_ratchet(
    gate_texts: dict[str, str] | None = None,
    unit_sleep_count: int | None = None,
) -> None:
    """Gate proto sleeps ≤ GATE_PROTO_SLEEP_MAX all tagged; unit sleep( ≤ UNIT_SLEEP_MAX."""
    if gate_texts is None:
        gate_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*-gate.sh"))
        }
        common = SCRIPTS / "lib" / "gate-common.sh"
        if common.is_file():
            gate_texts[common.name] = common.read_text(encoding="utf-8")
    proto = 0.0
    for name, text in gate_texts.items():
        for kind, sec in classify_gate_sleeps(text):
            if kind == "padding":
                _die(f"{name} has an untagged padding sleep {sec}s")
            if kind == "proto":
                proto += sec
    if proto > GATE_PROTO_SLEEP_MAX:
        _die(f"proto sleeps sum {proto:.1f}s exceeds {GATE_PROTO_SLEEP_MAX}")
    if unit_sleep_count is None:
        n = 0
        for path in (ROOT / "crates").glob("*/tests/**/*.rs"):
            n += path.read_text(encoding="utf-8", errors="replace").count("sleep(")
        unit_sleep_count = n
    if unit_sleep_count > UNIT_SLEEP_MAX:
        _die(f"unit sleep( count {unit_sleep_count} exceeds {UNIT_SLEEP_MAX}")


def check_kadmin_glob_lib(text: str | None = None) -> None:
    """hist_shape lives in the sourced lib so both-gate can diff getprinc output."""
    if text is None:
        path = SCRIPTS / "lib" / "kadmin-glob-cells.sh"
        if not path.is_file():
            _die("missing scripts/lib/kadmin-glob-cells.sh")
        text = path.read_text(encoding="utf-8")
    if "hist_shape" not in text:
        _die("kadmin-glob-cells.sh must define hist_shape for rust/MIT getprinc diffs")
    if "alias_cells" not in text:
        _die("kadmin-glob-cells.sh must define alias_cells")


def check_kadmin_split_snaps(text: str, name: str) -> None:
    """KEEP preserves containers, not shell vars; rust snapshots must cross the process boundary."""
    if name == "kadmin-rust-gate.sh" and "save_rust_snap" not in text:
        _die("kadmin-rust-gate.sh must persist rust snapshots for mit-gate diffs")
    if name == "kadmin-rust-acl-gate.sh" and "save_rust_snap" not in text:
        _die("kadmin-rust-acl-gate.sh must persist rust snapshots for mit-gate diffs")
    if name == "kadmin-mit-gate.sh" and "load_rust_snap" not in text:
        _die("kadmin-mit-gate.sh must load rust snapshots (KEEP does not preserve shell vars)")
    if name == "kadmin-gate.sh":
        if "kadmin-rust-gate.sh" not in text or "kadmin-both-gate.sh" not in text:
            _die("kadmin-gate.sh must wrap rust+mit+both legs")
        if "kadmin-rust-acl-gate.sh" not in text:
            _die("kadmin-gate.sh must wrap rust-acl after rust")
        if "KERBER_SCRATCH" not in text:
            _die("kadmin-gate.sh must export KERBER_SCRATCH so rust/mit/both share snapshots")


def check_kcm_need_image(text: str, name: str = "kcm-gate.sh") -> None:
    """need_image inspects $IMAGE; the Fedora KCM tag is not the MIT image."""
    if re.search(r'^\s*IMAGE=.*sssd-kcm', text, re.M) and "need_image" in text:
        _die(f"{name} must not set IMAGE to sssd-kcm before need_image (KERBER_SKIP_MIT_BUILD)")
    if "KCM_IMAGE" not in text:
        _die(f"{name} must use KCM_IMAGE for the Fedora sssd-kcm tag")


def check_kcm_stop_before_run(text: str | None = None, name: str = "kcm-gate.sh") -> None:
    """kcm-gate registers stop-harness before run-harness so a failed boot still stops."""
    if text is None:
        path = SCRIPTS / "kcm-gate.sh"
        if not path.is_file():
            _die("missing scripts/kcm-gate.sh")
        text = path.read_text(encoding="utf-8")
    stop = text.find("stop-harness.sh")
    run = text.find("run-harness.sh")
    if run < 0:
        _die(f"{name} must call run-harness.sh")
    if stop < 0:
        _die(f"{name} must register stop-harness.sh")
    if stop > run:
        _die(f"{name} must register stop-harness before run-harness")


def check_prod_gate_tcpdump_cleanup(text: str | None = None) -> None:
    """Registered cleanup kills root tcpdump with sudo -n kill; KDC with plain kill."""
    if text is None:
        path = SCRIPTS / "prod-gate.sh"
        if not path.is_file():
            _die("missing scripts/prod-gate.sh")
        text = path.read_text(encoding="utf-8")
    # The cleanup is a quoted string or a named function; read the body either way.
    bodies = re.findall(r"register_cleanup\s+'([^']*)'", text)
    for fn in re.findall(r"^register_cleanup\s+([A-Za-z_]\w*)\s*$", text, re.M):
        m = re.search(rf"^{re.escape(fn)}\(\)\s*\{{\n(.*?)^\}}", text, re.M | re.S)
        if m:
            bodies.append(m.group(1))
    if not bodies:
        _die("prod-gate.sh must register_cleanup")
    joined = "\n".join(bodies)
    if "sudo -n kill" not in joined or "TCPDUMP_PID" not in joined:
        _die("prod-gate.sh cleanup must sudo -n kill TCPDUMP_PID")
    if re.search(r"kill \$KDC_PID \$TCPDUMP_PID", joined):
        _die("prod-gate.sh must not plain-kill the root tcpdump with the KDC")
    if "kill $KDC_PID" not in joined and 'kill "$KDC_PID"' not in joined:
        _die("prod-gate.sh cleanup must plain-kill KDC_PID")


def check_gate_no_exit_trap(text: str, name: str = "gate.sh") -> None:
    """Gates must not replace gate-common's EXIT trap (register_cleanup)."""
    if re.search(r"^\s*trap\b.*\bEXIT\b", text, re.M):
        _die(f"{name} must not set an EXIT trap (use register_cleanup)")


def check_build_bins_examples() -> None:
    """build-bins.sh must build krb5-tools and name the seven harness bins."""
    path = SCRIPTS / "lib" / "build-bins.sh"
    if not path.is_file():
        _die("missing scripts/lib/build-bins.sh")
    text = path.read_text(encoding="utf-8")
    if "krb5-tools" not in text:
        _die("build-bins.sh must build -p krb5-tools")
    for ex in (
        "kprop-expired-apreq",
        "ccache-probe",
        "loadgen",
        "krb5-vfy-increds",
        "krb5-forge-tgt",
        "krb5-pac-extract",
        "diffsend",
    ):
        if ex not in text:
            _die(f"build-bins.sh must name harness bin {ex}")


def check_gate_cargo_leftover(text: str, name: str = "gate.sh") -> None:
    """S2 converter residue: a cargo-build argument line with no cargo build."""
    if re.search(r"^\s+-p\s+krb5-", text, re.M):
        _die(f"{name} still has leftover cargo-build argument lines")


def check_need_bins_strict(
    ci_text: str | None = None,
    checkpoint_text: str | None = None,
    common_text: str | None = None,
    workflow_texts: dict[str, str] | None = None,
) -> None:
    """CI, checkpoint, and every gate-running workflow set STRICT=1 and build-bins."""
    if ci_text is None:
        ci_text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    if "KERBER_NEED_BINS_STRICT" not in ci_text:
        _die("ci.yml must set KERBER_NEED_BINS_STRICT")
    if checkpoint_text is None:
        checkpoint_text = (SCRIPTS / "checkpoint.sh").read_text(encoding="utf-8")
    if "KERBER_NEED_BINS_STRICT=1" not in checkpoint_text:
        _die("checkpoint.sh must export KERBER_NEED_BINS_STRICT=1")
    if common_text is None:
        common_text = (SCRIPTS / "lib" / "gate-common.sh").read_text(encoding="utf-8")
    if "KERBER_NEED_BINS_STRICT" not in common_text:
        _die("need_bins must honour KERBER_NEED_BINS_STRICT")
    if "need_bins: building" not in common_text:
        _die("need_bins must log when it builds (lenient local path)")
    if workflow_texts is None:
        workflow_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(WORKFLOWS.glob("*.yml"))
        }
    for name, text in workflow_texts.items():
        if not re.search(r"scripts/[A-Za-z0-9._-]+-gate\.sh", text):
            continue
        if "build-bins.sh" not in text:
            _die(f"{name} runs a gate but has no build-bins.sh step")
        if 'KERBER_NEED_BINS_STRICT: "1"' not in text:
            _die(f'{name} runs a gate but lacks KERBER_NEED_BINS_STRICT: "1"')


def check_no_gate_cargo_build(gate_texts: dict[str, str] | None = None) -> None:
    """Named S6 rule: no scripts/*-gate.sh may run cargo build (use need_bins)."""
    if gate_texts is None:
        gate_texts = {
            p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*-gate.sh"))
        }
    for name, text in gate_texts.items():
        if re.search(r"\bcargo\s+build\b", text):
            _die(f"{name} must not run cargo build (use need_bins)")
        check_gate_cargo_leftover(text, name)


PEER_CAPTURE_GATES = (
    "ad-s4u-gate.sh",
    "ad-windows-gate.sh",
    "samba-ad-gate.sh",
    "samba-crossrealm-gate.sh",
    "samba-pac-l2-gate.sh",
    "samba-pac-verify-gate.sh",
)


def _run_rc_adjacent_to_docker_run(text: str) -> bool:
    """`run_rc=$?` must follow `docker run` with no `register_cleanup` in between."""
    lines = text.splitlines()
    saw = False
    for i, line in enumerate(lines):
        if not re.search(r"\bdocker\s+run\b", line.split("#", 1)[0]):
            continue
        for j in range(i + 1, min(len(lines), i + 12)):
            code = lines[j].split("#", 1)[0]
            if re.search(r"\brun_rc=\$\?", code):
                saw = True
                between = "\n".join(lines[i + 1 : j])
                if "register_cleanup" in between:
                    return False
                break
    return saw


def check_peers_unavailable_convention(
    wrapper_text: str | None = None,
    peers_text: str | None = None,
    ad_text: str | None = None,
    nightly_texts: dict[str, str] | None = None,
    capture_texts: dict[str, str] | None = None,
) -> None:
    """peers.yml maps gate exit 2 to step success; live kinit/kvno failures are exit 1."""
    live = wrapper_text is None and peers_text is None and ad_text is None
    if wrapper_text is None:
        wrapper = SCRIPTS / "lib" / "run-peer-step.sh"
        if not wrapper.is_file():
            _die("missing scripts/lib/run-peer-step.sh")
        wrapper_text = wrapper.read_text(encoding="utf-8")
    if "[ \"$rc\" -eq 2 ]" not in wrapper_text and "[ \"$rc\" -eq 2 ]" not in wrapper_text.replace(" ", ""):
        if 'rc" -eq 2' not in wrapper_text:
            _die("run-peer-step.sh must treat exit 2 as unavailable (not a job failure)")
    if peers_text is None:
        peers_text = (WORKFLOWS / "peers.yml").read_text(encoding="utf-8")
    if "run-peer-step.sh" not in peers_text:
        _die("peers.yml must wrap peer gates with run-peer-step.sh")
    if ad_text is None:
        ad_text = (SCRIPTS / "samba-ad-gate.sh").read_text(encoding="utf-8")
    if 'unavailable "kinit' in ad_text:
        _die("samba-ad-gate.sh kinit failure against a listening KDC must exit 1, not unavailable")
    if "exit 1" not in ad_text:
        _die("samba-ad-gate.sh must exit 1 on live kinit/kvno failure")
    if live:
        nightly_texts = {}
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if Workflow(path, text).scheduled:
                nightly_texts[path.name] = text
        capture_texts = {
            name: (SCRIPTS / name).read_text(encoding="utf-8")
            for name in PEER_CAPTURE_GATES
            if (SCRIPTS / name).is_file()
        }
    if nightly_texts:
        for name, text in nightly_texts.items():
            if not re.search(r"scripts/[A-Za-z0-9._-]+-gate\.sh", text):
                continue
            if "kerber-rust-mit-kdc.tar" not in text and "KERBER_NO_IMAGE" not in text:
                _die(
                    f"{name} runs a gate but neither restores the MIT tar "
                    "nor sets KERBER_NO_IMAGE"
                )
        for name in ("peers.yml", "kcm-opcode.yml"):
            text = nightly_texts.get(name, "")
            if not text:
                continue
            if "kerber-rust-mit-kdc.tar" not in text:
                _die(f"{name} must restore kerber-rust-mit-kdc.tar (KERBER_NO_IMAGE is not a substitute)")
            if name == "kcm-opcode.yml" and "lld" not in text and RUST_PREAMBLE not in text:
                _die("kcm-opcode.yml must install lld (inline or via the rust-preamble composite)")
            if name == "kcm-opcode.yml" and "run-peer-step.sh" not in text:
                _die("kcm-opcode.yml must wrap the gate with run-peer-step.sh")
        if "peers.yml" in nightly_texts:
            pt = nightly_texts["peers.yml"]
            if "unavailable=" not in pt or "failed=" not in pt:
                _die("peers.yml must print unavailable=N failed=M")
    if capture_texts:
        for name, text in capture_texts.items():
            if not _run_rc_adjacent_to_docker_run(text):
                _die(f"{name} run_rc=$? must sit adjacent to docker run")


_SAMBA_GONE_88 = re.compile(r'wait_gone_in\s+"\$NAME(_A)?"\s+88')


def check_samba_kdc_respawn(
    cross_text: str | None = None,
    trust_text: str | None = None,
) -> None:
    """Samba PAC L3/realtrust respawn task[kdc] workers; UDP :88 stays bound."""
    if cross_text is None:
        path = SCRIPTS / "samba-crossrealm-gate.sh"
        if not path.is_file():
            _die("missing scripts/samba-crossrealm-gate.sh")
        cross_text = path.read_text(encoding="utf-8")
    if trust_text is None:
        path = SCRIPTS / "samba-realtrust-gate.sh"
        if not path.is_file():
            _die("missing scripts/samba-realtrust-gate.sh")
        trust_text = path.read_text(encoding="utf-8")
    for name, text in (
        ("samba-crossrealm-gate.sh", cross_text),
        ("samba-realtrust-gate.sh", trust_text),
    ):
        if "samba_kdc_respawn_in" not in text:
            _die(f"{name} must call samba_kdc_respawn_in after task[kdc] kill")
        if _SAMBA_GONE_88.search(text):
            _die(f"{name} must not wait_gone_in :88 (Samba keeps the port)")
        if "rebind :88" in text:
            _die(f"{name} Samba die must not say rebind :88 (UDP 88 stays bound)")
