#!/usr/bin/env bash
# Generalised W2 checkpoint: nextest + ci-policy + gates with timings.tsv.
# Usage:
#   scripts/checkpoint.sh --out DIR [--twice g1,g2] [--peers] [--gates g1,g2]
#                         [--skip-nextest] [--skip-harness] [--skip-policy]
#   scripts/checkpoint.sh --plan ...     (print index/gate/label, do not run)
#   scripts/checkpoint.sh --self-test
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT=""
TWICE=""
PEERS=0
GATES=""
SKIP_NEXTEST=0
SKIP_HARNESS=0
SKIP_POLICY=0
PLAN=0

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

if [ "${CHECKPOINT_SELF_TEST:-0}" = 1 ]; then
    t=$(mktemp -d)
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
    mkdir -p "$OUT"
    OUT="$(cd "$OUT" && pwd)"
    export KERBER_SCRATCH="${KERBER_SCRATCH:-$OUT/scratch}"
    mkdir -p "$KERBER_SCRATCH"
    export KERBER_NEED_BINS_STRICT=1

    if pgrep -f 'scripts/[a-z0-9-]*-gate\.sh' >/dev/null || pgrep -x cargo >/dev/null; then
        echo "ABORT: a gate or cargo is already running" >&2
        exit 3
    fi

    {
        echo "head_sha=$(git rev-parse HEAD)"
        echo "dirty_files=$(git status --porcelain | wc -l)"
        echo "started=$(date -Is)"
        echo "host_krb5_default_realm=$(/usr/bin/grep -m1 default_realm /etc/krb5.conf 2>/dev/null || true)"
        echo "nproc=$(nproc)"
    } >"$OUT/00-head.txt"

    : >"$OUT/02-progress.txt"
    printf 'gate\trun\tgate_rc\twall_s\n' >"$OUT/timings.tsv"
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
    prog 03 ci-policy done
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
    prog 07 run-harness done
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
if [ "$SKIP_POLICY" != 1 ]; then
    python3 scripts/ci-policy.py --checkpoint --timings "$OUT/timings.tsv" \
        >"$OUT/04-gate-wall.log" 2>&1 || {
        echo "checkpoint: gate-wall check failed" >&2
        cat "$OUT/04-gate-wall.log" >&2
        exit 1
    }
fi
echo CHECKPOINT_DONE
