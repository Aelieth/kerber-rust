#!/usr/bin/env bash
# Generalised W2 checkpoint: nextest + ci-policy + gates with timings.tsv.
# Usage:
#   scripts/checkpoint.sh --out DIR [--twice g1,g2] [--peers] [--gates g1,g2]
#                         [--skip-nextest] [--skip-harness] [--skip-policy]
#   scripts/checkpoint.sh --plan ...     (print index/gate/label, do not run)
#   scripts/checkpoint.sh --self-test
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
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
    export KERBER_SCRATCH="${KERBER_SCRATCH:-$OUT/scratch}"
    mkdir -p "$KERBER_SCRATCH"
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
    timeout 1200 bash "scripts/$2.sh" >>"$log" 2>&1
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
}

SKIP_ALWAYS="chaos-gate soak-gate stress-gate prod-gate prod-realm-gate nfs-krb5p-gate sssd-renew-gate ad-mit-trust-gate"
PEERS_GATES="samba-ad-gate ad-windows-gate ad-s4u-gate samba-pac-verify-gate samba-pac-l2-gate samba-crossrealm-gate samba-realtrust-gate heimdal-gate"
HARNESS_ATTACH="knobs-gate ccache-gate client-gate config-include-gate"
# CI runs these KEEP-attached; local checkpoint runs them in that order
# with KERBER_KADMIN_KEEP=1 so each wall_s is a CI leg, not the wrapper.
KADMIN_KEEP="kadmin-rust-gate kadmin-rust-acl-gate kadmin-mit-gate kadmin-both-gate"
KPASSWD_KEEP="kpasswd-rust-gate kpasswd-mit-gate"
CLIENT_DIFF_KEEP="client-differential-flows-gate client-differential-cli-gate"

if [ "$SKIP_POLICY" != 1 ]; then
    { . scripts/lib/provenance.sh; echo "label=python3 scripts/ci-policy.py"; python3 scripts/ci-policy.py; echo "rc=$?"; } \
        >"$OUT/03-ci-policy.log" 2>&1
    prog 03 ci-policy "done"
fi

if [ "$SKIP_NEXTEST" != 1 ]; then
    { . scripts/lib/provenance.sh; echo "label=cargo nextest run --workspace --profile ci (isolated)"; } \
        >"$OUT/01-nextest-isolated.log" 2>&1
    s=$(date +%s)
    KRB5_CONFIG="$ROOT/harness/nextest-krb5.conf" cargo nextest run --workspace --profile ci \
        >>"$OUT/01-nextest-isolated.log" 2>&1
    rc=$?
    e=$(date +%s)
    echo "nextest_rc=$rc" >>"$OUT/01-nextest-isolated.log"
    echo "wall_s=$((e - s))" >>"$OUT/01-nextest-isolated.log"
    prog 01 nextest-isolated "nextest_rc=$rc wall_s=$((e - s))"
fi

if [ "$SKIP_HARNESS" != 1 ]; then
    docker rm -f kerber-rust-mit-kdc >/dev/null 2>&1 || true
    { . scripts/lib/provenance.sh; echo "label=KERBER_SKIP_MIT_BUILD=1 ./scripts/run-harness.sh"; s=$(date +%s)
      KERBER_SKIP_MIT_BUILD=1 ./scripts/run-harness.sh; echo "harness_rc=$?"; echo "wall_s=$(($(date +%s) - s))"; } \
        >"$OUT/07-run-harness.log" 2>&1
    prog 07 run-harness "done"
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
for f in scripts/*-gate.sh; do
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
    if ! python3 scripts/ci-policy.py --checkpoint --timings "$OUT/timings.tsv" \
        >>"$OUT/04-gate-wall.log" 2>&1; then
        write_index
        echo "checkpoint: gate-wall check failed" >&2
        cat "$OUT/04-gate-wall.log" >&2
        exit 1
    fi
fi
write_index
echo CHECKPOINT_DONE
