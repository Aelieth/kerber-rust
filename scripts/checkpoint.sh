#!/usr/bin/env bash
# Generalised W2 checkpoint: nextest + ci-policy + gates with timings.tsv.
# Usage:
#   scripts/checkpoint.sh --out DIR [--twice g1,g2] [--peers] [--gates g1,g2]
#                         [--skip-nextest] [--skip-harness] [--skip-policy]
#   scripts/checkpoint.sh --plan ...     (print index/gate/label, do not run)
#   scripts/checkpoint.sh --self-test
# Exit 1 when a step fails: nextest rc != 0, ci-policy rc != 0, run-harness.sh rc != 0, a gate rc
# other than 0 or 2 (2 is a lab that is not up), or the `ci-policy --checkpoint` gate-wall check.
# Every step still runs; $OUT/CHECKPOINT_RC.txt (stamped) holds checkpoint_rc= and one fail= line
# per failure. The MIT image is a precondition: a missing or stale one, or no docker, stops the run
# with exit 2 before any step, unless KERBER_NO_IMAGE=1 (every stamp then says image=unavailable).
# The self-test's fixtures swap the steps through KERBER_CHECKPOINT_NEXTEST (a bash command),
# KERBER_CHECKPOINT_POLICY (a script run in place of ci-policy.py), KERBER_CHECKPOINT_HARNESS (a bash
# command run in place of run-harness.sh) and KERBER_CHECKPOINT_GATE_DIR (where the *-gate.sh files
# are read); 00-head.txt records any that is set. The fixtures run under a docker that always
# fails, so the self-test needs neither docker nor the MIT image.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

OUT=""
TWICE=""
PEERS=0
GATES=""
SKIP_NEXTEST=0
SKIP_HARNESS=0
SKIP_POLICY=0
PLAN=0
STAMP=""

# KEEP / twice / peers legs use dedicated index ranges so they cannot
# collide with the alphabetical pass (W2 close-audit: kadmin KEEP reused 51–54).
KEEP_INDEX_START=200
KPASSWD_KEEP_INDEX_START=210
CLIENT_DIFF_KEEP_INDEX_START=220
TWICE_INDEX_START=300
PEERS_INDEX_START=400

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --twice) TWICE="$2"; shift 2 ;;
        --peers) PEERS=1; shift ;;
        --gates) GATES="$2"; shift 2 ;;
        --skip-nextest) SKIP_NEXTEST=1; shift ;;
        --skip-harness) SKIP_HARNESS=1; shift ;;
        --skip-policy) SKIP_POLICY=1; shift ;;
        --plan) PLAN=1; shift ;;
        --self-test) CHECKPOINT_SELF_TEST=1; shift ;;
        *) echo "usage: $0 --out DIR [--twice g1,g2] [--peers] [--gates g1,g2]" >&2; exit 2 ;;
    esac
done

GATE_DIR="${KERBER_CHECKPOINT_GATE_DIR:-scripts}"
FAILS=()
fail() { FAILS+=("$1"); }
run_nextest() {
    if [ -n "${KERBER_CHECKPOINT_NEXTEST:-}" ]; then
        bash -c "$KERBER_CHECKPOINT_NEXTEST"
    else
        KRB5_CONFIG="$ROOT/harness/nextest-krb5.conf" cargo nextest run --workspace --profile ci
    fi
}
run_policy() {
    if [ -n "${KERBER_CHECKPOINT_POLICY:-}" ]; then
        bash "$KERBER_CHECKPOINT_POLICY" "$@"
    else
        python3 scripts/ci-policy.py "$@"
    fi
}
run_harness() {
    if [ -n "${KERBER_CHECKPOINT_HARNESS:-}" ]; then
        bash -c "$KERBER_CHECKPOINT_HARNESS"
    else
        KERBER_SKIP_MIT_BUILD=1 ./scripts/run-harness.sh
    fi
}
# A step log's stamp. provenance.sh runs in a subshell, so its exit (the image changed during the
# run) is a failed step, not the end of the run.
stamp_log() {
    local rc=0
    (. scripts/lib/provenance.sh) || rc=$?
    [ "$rc" = 0 ] || fail "stamp $1 provenance_rc=$rc"
}

# A gate that is running, not a process that merely names one: the command line
# must be a shell interpreter with `scripts/<name>-gate.sh` as its script
# argument (`bash scripts/kdc-gate.sh`, as checkpoint.sh's own `timeout 1200
# bash scripts/…` runs them, or `/usr/bin/bash ./scripts/…`). `shellcheck
# scripts/*-gate.sh`, `cat`, `tail -f`, an editor or ci-policy.py reading the
# file do not match (W3-S1 audit R4: they aborted five checkpoints).
GATE_PROCESS_RE='^([^ ]*/)?(ba|da)?sh( -[a-zA-Z]+)* ([^ ]*/)?scripts/[a-z0-9-]+-gate\.sh( |$)'

# 0 when a gate or cargo is running (the checkpoint must not share the ports,
# the containers or the target dir with either).
gate_or_cargo_running() {
    pgrep -f "$GATE_PROCESS_RE" >/dev/null || pgrep -x cargo >/dev/null
}

# The KEEP chains and the harness-attached gates run whatever --gates says; the self-test's fixture
# directory needs a gate for each.
KADMIN_KEEP_NAMES="kadmin-rust-gate kadmin-rust-acl-gate kadmin-mit-gate kadmin-both-gate kpasswd-rust-gate kpasswd-mit-gate client-differential-flows-gate client-differential-cli-gate"
HARNESS_ATTACH="knobs-gate ccache-gate client-gate config-include-gate"

if [ "${CHECKPOINT_SELF_TEST:-0}" = 1 ]; then
    scratch_parent="${KERBER_SCRATCH:-${TMPDIR:-/tmp}}"
    mkdir -p "$scratch_parent"
    t=$(mktemp -d "$scratch_parent/checkpoint-selftest.XXXXXX") || exit 1
    # Busy guard: a quiet machine is a precondition of the checkpoint itself.
    if gate_or_cargo_running; then
        echo "checkpoint.sh --self-test: a gate or cargo is already running; the busy-guard cases need a quiet machine" >&2
        rm -rf "$t"
        exit 1
    fi
    tail -f scripts/kdc-gate.sh >/dev/null 2>&1 &
    reader_pid=$!
    if gate_or_cargo_running; then
        echo "checkpoint.sh --self-test: a process that only reads a gate script (tail -f scripts/kdc-gate.sh) must not trip the busy guard" >&2
        kill "$reader_pid" 2>/dev/null
        rm -rf "$t"
        exit 1
    fi
    mkdir -p "$t/scripts"
    printf '#!/usr/bin/env bash\ntrap "exit 0" TERM\nwhile :; do sleep 1; done\n' >"$t/scripts/probe-gate.sh"
    bash "$t/scripts/probe-gate.sh" &
    probe_pid=$!
    sleep 0.2
    if ! gate_or_cargo_running; then
        echo "checkpoint.sh --self-test: a running gate (bash …/scripts/probe-gate.sh) must trip the busy guard" >&2
        kill "$probe_pid" "$reader_pid" 2>/dev/null
        rm -rf "$t"
        exit 1
    fi
    kill "$probe_pid" "$reader_pid" 2>/dev/null
    wait "$probe_pid" "$reader_pid" 2>/dev/null
    if gate_or_cargo_running; then
        echo "checkpoint.sh --self-test: busy guard still tripped after the probe gate exited" >&2
        rm -rf "$t"
        exit 1
    fi
    mkdir -p "$t/full"
    echo x >"$t/full/a"
    if "$0" --out "$t/full" --skip-nextest --skip-harness --skip-policy; then
        echo "checkpoint.sh --self-test: nonempty --out must be refused" >&2
        rm -rf "$t"
        exit 1
    fi
    plan=$("$0" --plan --out "$t/empty" --peers)
    peers_n=$(printf '%s\n' "$plan" | grep -c 'samba-ad-gate' || true)
    if [ "$peers_n" -ne 1 ]; then
        echo "checkpoint.sh --self-test: peers gate ran $peers_n times (want 1)" >&2
        printf '%s\n' "$plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$plan" | grep -q '^201 kadmin-rust-gate'; then
        echo "checkpoint.sh --self-test: kadmin KEEP must start at 201" >&2
        printf '%s\n' "$plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$plan" | grep -q '^211 kpasswd-rust-gate'; then
        echo "checkpoint.sh --self-test: kpasswd KEEP must start at 211" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$plan" | grep -q '^221 client-differential-flows-gate'; then
        echo "checkpoint.sh --self-test: client-diff KEEP must start at 221" >&2
        printf '%s\n' "$plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$plan" | grep -q '^401 samba-ad-gate peers'; then
        echo "checkpoint.sh --self-test: peers KEEP range must start at 401" >&2
        rm -rf "$t"
        exit 1
    fi
    twice_plan=$("$0" --plan --out "$t/empty" --twice kpasswd-mit-gate,kadmin-mit-gate,client-differential-cli-gate,pkinit-gate)
    rust_n=$(printf '%s\n' "$twice_plan" | grep -c 'kpasswd-rust-gate' || true)
    if [ "$rust_n" -ne 2 ]; then
        echo "checkpoint.sh --self-test: --twice kpasswd-mit must KEEP-pair rust (got $rust_n)" >&2
        printf '%s\n' "$twice_plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$twice_plan" | grep -q 'kpasswd-rust-gate run2'; then
        echo "checkpoint.sh --self-test: --twice kpasswd-mit must emit kpasswd-rust-gate run2" >&2
        printf '%s\n' "$twice_plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$twice_plan" | grep -q 'kadmin-rust-gate run2'; then
        echo "checkpoint.sh --self-test: --twice kadmin-mit must re-run the kadmin KEEP pair" >&2
        printf '%s\n' "$twice_plan" >&2
        rm -rf "$t"
        exit 1
    fi
    flows_n=$(printf '%s\n' "$twice_plan" | grep -c 'client-differential-flows-gate' || true)
    if [ "$flows_n" -ne 2 ]; then
        echo "checkpoint.sh --self-test: --twice client-differential-cli must KEEP-pair flows (got $flows_n)" >&2
        printf '%s\n' "$twice_plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$twice_plan" | grep -q 'client-differential-flows-gate run2'; then
        echo "checkpoint.sh --self-test: --twice client-differential-cli must emit flows run2" >&2
        printf '%s\n' "$twice_plan" >&2
        rm -rf "$t"
        exit 1
    fi
    if ! printf '%s\n' "$twice_plan" | grep -q 'pkinit-gate run2'; then
        echo "checkpoint.sh --self-test: --twice pkinit-gate must stay a generic run2" >&2
        printf '%s\n' "$twice_plan" >&2
        rm -rf "$t"
        exit 1
    fi
    # Exit semantics, on fixture steps: every step runs, and a failed one makes the exit 1 and is
    # named in CHECKPOINT_RC.txt; a gate that exits 2 (its lab is not up) is not a failure.
    fx="$t/fx"
    mkdir -p "$fx/gates" "$fx/nodocker"
    # A docker that always fails, as on the GitHub test job (docker without the MIT image): the
    # fixture runs need neither, and stamp image=unavailable under KERBER_NO_IMAGE=1.
    printf '#!/bin/sh\nexit 1\n' >"$fx/nodocker/docker"
    chmod +x "$fx/nodocker/docker"
    # A docker whose MIT image answers provenance.sh's three calls of the precondition, then is gone.
    mkdir -p "$fx/vanish-docker"
    cat >"$fx/vanish-docker/docker" <<'FAKE'
#!/bin/sh
n=$(($(cat "$FX_DOCKER_COUNT" 2>/dev/null || echo 0) + 1))
echo "$n" >"$FX_DOCKER_COUNT"
[ "$n" -le 3 ] || exit 1
case "$*" in
    "image inspect kerber-rust-mit-kdc:1.22.2") exit 0 ;;
    "image inspect kerber-rust-mit-kdc:1.22.2 --format"*) echo "sha256:fixture 2026-01-01T00:00:00Z"; exit 0 ;;
    "run --rm --entrypoint cat kerber-rust-mit-kdc:1.22.2 /var/kerberos/krb5kdc/kadm5.acl") cat harness/kadm5.acl; exit 0 ;;
esac
exit 1
FAKE
    chmod +x "$fx/vanish-docker/docker"
    for g in $KADMIN_KEEP_NAMES $HARNESS_ATTACH green-gate; do
        printf '#!/usr/bin/env bash\nexit 0\n' >"$fx/gates/$g.sh"
    done
    printf '#!/usr/bin/env bash\nexit 2\n' >"$fx/gates/nolab-gate.sh"
    printf '#!/usr/bin/env bash\nexit 1\n' >"$fx/gates/red-gate.sh"
    cat >"$fx/policy.sh" <<'FAKE'
#!/usr/bin/env bash
case " $* " in *" --checkpoint "*) exit "${FX_WALL_RC:-0}" ;; esac
exit "${FX_POLICY_RC:-0}"
FAKE
    # fx_run NAME GATES [VAR=VALUE ...]: a checkpoint on the fixtures, under the failing docker and
    # KERBER_NO_IMAGE=1; prints its rc. A KERBER_CHECKPOINT_HARNESS= argument runs the harness step.
    fx_run() {
        local name="$1" gates="$2" skip="--skip-harness"
        shift 2
        case " $* " in *" KERBER_CHECKPOINT_HARNESS="*) skip="" ;; esac
        env PATH="$fx/nodocker:$PATH" KERBER_NO_IMAGE=1 KERBER_ALLOW_HOST_REALM=1 KERBER_CHECKPOINT_GATE_DIR="$fx/gates" \
            KERBER_CHECKPOINT_POLICY="$fx/policy.sh" KERBER_CHECKPOINT_NEXTEST="exit 0" \
            KERBER_SCRATCH="$fx/$name-scratch" "$@" \
            "$0" --out "$fx/$name" ${skip:+"$skip"} --gates "$gates" >"$fx/$name.out" 2>&1
        echo $?
    }
    fx_fail() {
        echo "checkpoint.sh --self-test: $1" >&2
        [ -f "$fx/$2.out" ] && cat "$fx/$2.out" >&2
        rm -rf "$t"
        exit 1
    }
    [ "$(fx_run green green-gate,nolab-gate)" = 0 ] || fx_fail "an all-green run (a gate at rc 2 included) must exit 0" green
    grep -qx 'checkpoint_rc=0' "$fx/green/CHECKPOINT_RC.txt" || fx_fail "a green run must write checkpoint_rc=0" green
    grep -qx 'CHECKPOINT_DONE' "$fx/green.out" || fx_fail "a green run must end CHECKPOINT_DONE" green
    grep -qx 'image=unavailable' "$fx/green/03-ci-policy.log" || fx_fail "a fixture step must stamp image=unavailable" green
    [ "$(fx_run nextest green-gate KERBER_CHECKPOINT_NEXTEST='exit 1')" = 1 ] || fx_fail "nextest rc 1 must exit 1" nextest
    grep -qx 'fail=nextest nextest_rc=1' "$fx/nextest/CHECKPOINT_RC.txt" || fx_fail "nextest rc 1 must be named" nextest
    grep -q '^green-gate' "$fx/nextest/timings.tsv" || fx_fail "the gates must still run after a red nextest" nextest
    [ "$(fx_run gate green-gate,red-gate)" = 1 ] || fx_fail "a gate at rc 1 must exit 1" gate
    grep -q '^fail=gate [0-9]*-red-gate gate_rc=1$' "$fx/gate/CHECKPOINT_RC.txt" || fx_fail "the red gate must be named" gate
    grep -qx 'checkpoint_rc=1' "$fx/gate/CHECKPOINT_RC.txt" || fx_fail "a red run must write checkpoint_rc=1" gate
    [ "$(fx_run policy green-gate FX_POLICY_RC=1)" = 1 ] || fx_fail "ci-policy rc 1 must exit 1" policy
    grep -qx 'fail=ci-policy rc=1' "$fx/policy/CHECKPOINT_RC.txt" || fx_fail "ci-policy rc 1 must be named" policy
    [ "$(fx_run wall green-gate FX_WALL_RC=1)" = 1 ] || fx_fail "a failed gate-wall check must exit 1" wall
    grep -q '^fail=gate-wall ' "$fx/wall/CHECKPOINT_RC.txt" || fx_fail "the gate-wall failure must be named" wall
    grep -q 'self_test_hook=KERBER_CHECKPOINT_GATE_DIR' "$fx/wall/00-head.txt" || fx_fail "00-head.txt must record the hooks" wall
    [ "$(fx_run harness green-gate KERBER_CHECKPOINT_HARNESS='exit 1')" = 1 ] || fx_fail "run-harness.sh rc 1 must exit 1" harness
    grep -qx 'fail=harness harness_rc=1' "$fx/harness/CHECKPOINT_RC.txt" || fx_fail "run-harness.sh rc 1 must be named" harness
    grep -q '^knobs-gate' "$fx/harness/timings.tsv" || fx_fail "the harness gates must still run after a red harness" harness
    grep -q 'self_test_hook=KERBER_CHECKPOINT_HARNESS' "$fx/harness/00-head.txt" || fx_fail "00-head.txt must record the harness hook" harness
    # Without KERBER_NO_IMAGE=1 the missing image is a precondition: exit 2, named, before any step.
    [ "$(fx_run noimage green-gate KERBER_NO_IMAGE=)" = 2 ] || fx_fail "a run without the MIT image must exit 2" noimage
    grep -q 'the MIT image is a precondition: MIT image kerber-rust-mit-kdc:1.22.2 missing' "$fx/noimage.out" \
        || fx_fail "the missing MIT image must be named" noimage
    [ ! -e "$fx/noimage/00-head.txt" ] || fx_fail "no step may run before the MIT image precondition" noimage
    # An image that is gone after the precondition: a step's stamp fails as a named step, and the run
    # still ends with CHECKPOINT_RC.txt.
    [ "$(fx_run vanish green-gate KERBER_NO_IMAGE= PATH="$fx/vanish-docker:$PATH" FX_DOCKER_COUNT="$fx/vanish.count")" = 1 ] \
        || fx_fail "an image gone after the precondition must exit 1" vanish
    grep -qx 'fail=stamp 03-ci-policy provenance_rc=2' "$fx/vanish/CHECKPOINT_RC.txt" \
        || fx_fail "a stamp that fails must be a named step" vanish
    grep -qx 'CHECKPOINT_FAILED: 2 step(s) failed' "$fx/vanish.out" || fx_fail "both step stamps must fail and the run end" vanish
    rm -rf "$t"
    echo "checkpoint.sh: self-test ok"
    exit 0
fi

if [ -z "$OUT" ]; then
    echo "checkpoint.sh: --out DIR is required" >&2
    exit 2
fi
if [ "$PLAN" != 1 ]; then
    if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
        echo "checkpoint.sh: refusing non-empty --out $OUT" >&2
        exit 2
    fi
    # Lab realm only (W3-S1): never a host whose /etc/krb5.conf names a real realm.
    # shellcheck source=lib/lab-realm.sh
    . scripts/lib/lab-realm.sh
    require_lab_realm "$HOST_KRB5_CONF"
    # The MIT image is a precondition, checked once before any step: a missing or stale image, or no
    # docker, stops the run here and names why, never halfway with no CHECKPOINT_RC.txt.
    # KERBER_NO_IMAGE=1 runs without it, and every stamp then says image=unavailable.
    if [ "${KERBER_NO_IMAGE:-}" != 1 ]; then
        if ! image_err="$(bash -c '. scripts/lib/provenance.sh' 2>&1 >/dev/null)"; then
            echo "checkpoint.sh: the MIT image is a precondition: ${image_err%%$'\n'*} (KERBER_NO_IMAGE=1 runs without it)" >&2
            exit 2
        fi
    fi
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
    export KERBER_SCRATCH="${KERBER_SCRATCH:-$OUT/scratch}"
    mkdir -p "$KERBER_SCRATCH"
    # One memo of the MIT image's kadm5.acl hash for every stamp of the run (provenance.sh).
    KERBER_PROV_MEMO="$(mktemp "$KERBER_SCRATCH/prov-memo.XXXXXX")"
    export KERBER_PROV_MEMO
    trap 'rm -f "$KERBER_PROV_MEMO"' EXIT
    export KERBER_NEED_BINS_STRICT=1

    if gate_or_cargo_running; then
        echo "ABORT: a gate or cargo is already running" >&2
        exit 3
    fi

    # The bookkeeping files this script writes itself carry the same stamp as
    # the gate logs (evidence-check.py wants head_sha= and tree_sha= in each).
    STAMP="$(KERBER_NO_IMAGE=1 bash -c '. scripts/lib/provenance.sh' 2>/dev/null)" || STAMP=""
    if [ -z "$STAMP" ]; then
        STAMP="$(printf '==== provenance ====\nhead_sha=%s\ntree_sha=%s\ndirty=%s\ncaptured_at=%s' \
            "$(git rev-parse HEAD)" "$(git rev-parse 'HEAD^{tree}')" \
            "$(if git status --porcelain -- ':!working' | grep -q .; then echo yes; else echo no; fi)" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    fi

    {
        printf '%s\n' "$STAMP"
        echo "dirty_files=$(git status --porcelain | wc -l)"
        echo "started=$(date -Is)"
        echo "host_krb5_default_realm=$(host_default_realm "$HOST_KRB5_CONF")"
        echo "lab_realm_override=$(lab_realm_override "$HOST_KRB5_CONF")"
        echo "nproc=$(nproc)"
        for hook in KERBER_CHECKPOINT_NEXTEST KERBER_CHECKPOINT_POLICY KERBER_CHECKPOINT_HARNESS KERBER_CHECKPOINT_GATE_DIR; do
            [ -n "${!hook:-}" ] && echo "self_test_hook=$hook"
        done
    } >"$OUT/00-head.txt"

    { printf '%s\n' "$STAMP"; echo "==== progress ===="; } >"$OUT/02-progress.txt"
    { printf '%s\n' "$STAMP"; printf 'gate\trun\tgate_rc\twall_s\n'; } >"$OUT/timings.tsv"
    prog() { echo "$1 $2 $3 $(date +%H:%M:%S)" >>"$OUT/02-progress.txt"; }
else
    SKIP_NEXTEST=1
    SKIP_HARNESS=1
    SKIP_POLICY=1
    prog() { :; }
fi

rungate() {
    # $1=index $2=gate-stem $3=run-label
    local log s e rc
    if [ "$PLAN" = 1 ]; then
        echo "$1 $2 ${3:-run1}"
        return 0
    fi
    log="$OUT/$1-$2${3:+-$3}.log"
    echo "==== $2 ($3): scripts/$2.sh ====" >"$log"
    s=$(date +%s)
    timeout 1200 bash "$GATE_DIR/$2.sh" >>"$log" 2>&1
    rc=$?
    e=$(date +%s)
    wall=$((e - s))
    gw=$(awk -F= '/^gate_wall_s=/{v=$2} END{print v}' "$log")
    if [ -n "$gw" ] && [ "$gw" -eq "$gw" ] 2>/dev/null; then
        wall=$gw
    fi
    echo "gate_rc=$rc" >>"$log"
    echo "wall_s=$wall" >>"$log"
    printf '%s\t%s\t%s\t%s\n' "$2" "${3:-run1}" "$rc" "$wall" >>"$OUT/timings.tsv"
    prog "$1" "$2${3:+-$3}" "gate_rc=$rc wall_s=$wall"
    case "$rc" in
        0 | 2) ;;
        *) fail "gate $1-$2${3:+-$3} gate_rc=$rc" ;;
    esac
}

SKIP_ALWAYS="chaos-gate soak-gate stress-gate prod-gate prod-realm-gate nfs-krb5p-gate sssd-renew-gate ad-mit-trust-gate"
PEERS_GATES="samba-ad-gate ad-windows-gate ad-s4u-gate samba-pac-verify-gate samba-pac-l2-gate samba-crossrealm-gate samba-realtrust-gate heimdal-gate"
# CI runs these KEEP-attached; local checkpoint runs them in that order
# with KERBER_KADMIN_KEEP=1 so each wall_s is a CI leg, not the wrapper.
KADMIN_KEEP="kadmin-rust-gate kadmin-rust-acl-gate kadmin-mit-gate kadmin-both-gate"
KPASSWD_KEEP="kpasswd-rust-gate kpasswd-mit-gate"
CLIENT_DIFF_KEEP="client-differential-flows-gate client-differential-cli-gate"

if [ "$SKIP_POLICY" != 1 ]; then
    { stamp_log 03-ci-policy; echo "label=python3 scripts/ci-policy.py"; run_policy; policy_rc=$?; echo "rc=$policy_rc"; } \
        >"$OUT/03-ci-policy.log" 2>&1
    prog 03 ci-policy "rc=$policy_rc"
    [ "$policy_rc" = 0 ] || fail "ci-policy rc=$policy_rc"
fi

if [ "$SKIP_NEXTEST" != 1 ]; then
    { stamp_log 01-nextest-isolated; echo "label=cargo nextest run --workspace --profile ci (isolated)"; } \
        >"$OUT/01-nextest-isolated.log" 2>&1
    s=$(date +%s)
    run_nextest >>"$OUT/01-nextest-isolated.log" 2>&1
    rc=$?
    e=$(date +%s)
    echo "nextest_rc=$rc" >>"$OUT/01-nextest-isolated.log"
    echo "wall_s=$((e - s))" >>"$OUT/01-nextest-isolated.log"
    prog 01 nextest-isolated "nextest_rc=$rc wall_s=$((e - s))"
    [ "$rc" = 0 ] || fail "nextest nextest_rc=$rc"
fi

if [ "$SKIP_HARNESS" != 1 ]; then
    docker rm -f kerber-rust-mit-kdc >/dev/null 2>&1 || true
    { stamp_log 07-run-harness; echo "label=KERBER_SKIP_MIT_BUILD=1 ./scripts/run-harness.sh"; s=$(date +%s)
      run_harness; harness_rc=$?; echo "harness_rc=$harness_rc"; echo "wall_s=$(($(date +%s) - s))"; } \
        >"$OUT/07-run-harness.log" 2>&1
    prog 07 run-harness "harness_rc=$harness_rc"
    [ "$harness_rc" = 0 ] || fail "harness harness_rc=$harness_rc"
    i=10
    for g in $HARNESS_ATTACH; do
        i=$((i + 1))
        rungate "$i" "$g" harness
    done
    docker rm -f kerber-rust-mit-kdc >/dev/null 2>&1 || true
    prog 07 harness stopped
fi

wanted() {
    local g="$1"
    case " $SKIP_ALWAYS " in *" $g "*) return 1 ;; esac
    case " $HARNESS_ATTACH " in *" $g "*) return 1 ;; esac
    case " $KADMIN_KEEP " in *" $g "*) return 1 ;; esac
    case " $KPASSWD_KEEP " in *" $g "*) return 1 ;; esac
    case " $CLIENT_DIFF_KEEP " in *" $g "*) return 1 ;; esac
    case "$g" in kadmin-gate|kpasswd-gate|client-differential-gate) return 1 ;; esac
    # Peers gates never run in the alphabetical pass; --peers uses PEERS_INDEX_START.
    case " $PEERS_GATES " in *" $g "*) return 1 ;; esac
    if [ -n "$GATES" ]; then
        case ",$GATES," in *",$g,"*) return 0 ;; *) return 1 ;; esac
    fi
    return 0
}

i=20
for f in "$GATE_DIR"/*-gate.sh; do
    g=$(basename "$f" .sh)
    wanted "$g" || continue
    i=$((i + 1))
    rungate "$i" "$g" ""
done

i=$KEEP_INDEX_START
export KERBER_KADMIN_KEEP=1
for g in $KADMIN_KEEP; do
    i=$((i + 1))
    rungate "$i" "$g" ""
done
unset KERBER_KADMIN_KEEP
if [ "$PLAN" != 1 ]; then
    docker rm -f kerber-rust-kadmin-gate kerber-rust-kadmin-mit >/dev/null 2>&1 || true
fi

i=$KPASSWD_KEEP_INDEX_START
export KERBER_KPASSWD_KEEP=1
for g in $KPASSWD_KEEP; do
    i=$((i + 1))
    rungate "$i" "$g" ""
done
unset KERBER_KPASSWD_KEEP
if [ "$PLAN" != 1 ]; then
    docker rm -f kerber-rust-kpasswd-gate >/dev/null 2>&1 || true
fi

i=$CLIENT_DIFF_KEEP_INDEX_START
export KERBER_CLIENT_DIFF_KEEP=1
for g in $CLIENT_DIFF_KEEP; do
    i=$((i + 1))
    rungate "$i" "$g" ""
done
unset KERBER_CLIENT_DIFF_KEEP
if [ "$PLAN" != 1 ]; then
    docker rm -f kerber-rust-mit-kdc >/dev/null 2>&1 || true
fi

if [ -n "$TWICE" ]; then
    i=$TWICE_INDEX_START
    IFS=',' read -r -a twice_arr <<<"$TWICE"
    did_kpasswd=0
    did_kadmin=0
    did_client_diff=0
    for g in "${twice_arr[@]}"; do
        g=${g%.sh}
        [ -n "$g" ] || continue
        case " $KPASSWD_KEEP " in
            *" $g "*)
                if [ "$did_kpasswd" = 0 ]; then
                    did_kpasswd=1
                    export KERBER_KPASSWD_KEEP=1
                    for kg in $KPASSWD_KEEP; do
                        i=$((i + 1))
                        rungate "$i" "$kg" run2
                    done
                    unset KERBER_KPASSWD_KEEP
                    if [ "$PLAN" != 1 ]; then
                        docker rm -f kerber-rust-kpasswd-gate >/dev/null 2>&1 || true
                    fi
                fi
                continue
                ;;
        esac
        case " $KADMIN_KEEP " in
            *" $g "*)
                if [ "$did_kadmin" = 0 ]; then
                    did_kadmin=1
                    export KERBER_KADMIN_KEEP=1
                    for kg in $KADMIN_KEEP; do
                        i=$((i + 1))
                        rungate "$i" "$kg" run2
                    done
                    unset KERBER_KADMIN_KEEP
                    if [ "$PLAN" != 1 ]; then
                        docker rm -f kerber-rust-kadmin-gate kerber-rust-kadmin-mit >/dev/null 2>&1 || true
                    fi
                fi
                continue
                ;;
        esac
        case " $CLIENT_DIFF_KEEP client-differential-gate " in
            *" $g "*)
                if [ "$did_client_diff" = 0 ]; then
                    did_client_diff=1
                    export KERBER_CLIENT_DIFF_KEEP=1
                    for kg in $CLIENT_DIFF_KEEP; do
                        i=$((i + 1))
                        rungate "$i" "$kg" run2
                    done
                    unset KERBER_CLIENT_DIFF_KEEP
                    if [ "$PLAN" != 1 ]; then
                        docker rm -f kerber-rust-mit-kdc >/dev/null 2>&1 || true
                    fi
                fi
                continue
                ;;
        esac
        i=$((i + 1))
        rungate "$i" "$g" run2
    done
fi

if [ "$PEERS" = 1 ]; then
    i=$PEERS_INDEX_START
    for g in $PEERS_GATES; do
        i=$((i + 1))
        rungate "$i" "$g" peers
    done
fi

if [ "$PLAN" = 1 ]; then
    exit 0
fi
echo "finished=$(date -Is)" >>"$OUT/00-head.txt"

# Every file in the output directory named by its own INDEX.md (index-check.py).
write_index() {
    local f n what
    {
        echo "# checkpoint at $(git rev-parse --short HEAD) — scripts/checkpoint.sh"
        echo
        echo "| File | What |"
        echo "|---|---|"
        for f in "$OUT"/*; do
            [ -f "$f" ] || continue
            n="${f##*/}"
            case "$n" in
                INDEX.md) continue ;;
                00-head.txt) what="provenance stamp; dirty_files / started / host_krb5_default_realm / lab_realm_override / nproc / finished" ;;
                01-nextest-isolated.log) what="\`cargo nextest run --workspace --profile ci\` under \`harness/nextest-krb5.conf\`" ;;
                02-progress.txt) what="per-step progress lines (stamped)" ;;
                03-ci-policy.log) what="\`ci-policy.py\` on the checkout" ;;
                04-gate-wall.log) what="\`ci-policy.py --checkpoint --timings timings.tsv\` (stamped)" ;;
                07-run-harness.log) what="harness image build/run" ;;
                timings.tsv) what="gate / run / gate_rc / wall_s (stamped)" ;;
                CHECKPOINT_RC.txt) what="checkpoint_rc= and one fail= line per failed step (stamped)" ;;
                *) what="gate log (stamped by provenance.sh)" ;;
            esac
            echo "| \`$n\` | $what |"
        done
        echo "| \`scratch/\` | gate \`KERBER_SCRATCH\` (skipped by index-check) |"
    } >"$OUT/INDEX.md"
    # Taken into a hygiene snapshot directory (the W3 shape: <snap>/checkpoint/)?
    # Then the snapshot's INDEX.md predates this run; have its writer name us.
    local parent="${OUT%/*}"
    if [ -f "$parent/INDEX.md" ] && [ "$(head -n1 "$parent/INDEX.md")" = "# hygiene snapshot" ]; then
        python3 scripts/lib/hygiene_inventory.py --reindex "$parent" \
            || echo "checkpoint: snapshot reindex of $parent failed (INDEX.md rows must be added by hand)" >&2
    fi
}

if [ "$SKIP_POLICY" != 1 ]; then
    { printf '%s\n' "$STAMP"; echo "==== ci-policy --checkpoint ===="; } >"$OUT/04-gate-wall.log"
    if ! run_policy --checkpoint --timings "$OUT/timings.tsv" >>"$OUT/04-gate-wall.log" 2>&1; then
        fail "gate-wall ci-policy --checkpoint failed (04-gate-wall.log)"
        cat "$OUT/04-gate-wall.log" >&2
    fi
fi
checkpoint_rc=0
[ "${#FAILS[@]}" -eq 0 ] || checkpoint_rc=1
{
    printf '%s\n' "$STAMP"
    echo "checkpoint_rc=$checkpoint_rc"
    for f in "${FAILS[@]}"; do echo "fail=$f"; done
} >"$OUT/CHECKPOINT_RC.txt"
write_index
if [ "$checkpoint_rc" != 0 ]; then
    echo "CHECKPOINT_FAILED: ${#FAILS[@]} step(s) failed" >&2
    printf '  %s\n' "${FAILS[@]}" >&2
    exit 1
fi
echo CHECKPOINT_DONE
