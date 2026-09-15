#!/usr/bin/env bash
# Generalised W2 checkpoint: nextest + ci-policy + gates with timings.tsv.
# Usage:
#   scripts/checkpoint.sh --out DIR [--twice g1,g2] [--peers] [--gates g1,g2]
#                         [--skip-nextest] [--skip-harness] [--skip-policy]
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

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --twice) TWICE="$2"; shift 2 ;;
        --peers) PEERS=1; shift ;;
        --gates) GATES="$2"; shift 2 ;;
        --skip-nextest) SKIP_NEXTEST=1; shift ;;
        --skip-harness) SKIP_HARNESS=1; shift ;;
        --skip-policy) SKIP_POLICY=1; shift ;;
        *) echo "usage: $0 --out DIR [--twice g1,g2] [--peers] [--gates g1,g2]" >&2; exit 2 ;;
    esac
done
if [ -z "$OUT" ]; then
    echo "checkpoint.sh: --out DIR is required" >&2
    exit 2
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export KERBER_SCRATCH="${KERBER_SCRATCH:-$OUT/scratch}"
mkdir -p "$KERBER_SCRATCH"

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

rungate() {
    # $1=index $2=gate-stem $3=run-label
    local log s e rc
    log="$OUT/$1-$2${3:+-$3}.log"
    echo "==== $2 ($3): scripts/$2.sh ====" >"$log"
    s=$(date +%s)
    timeout 1200 bash "scripts/$2.sh" >>"$log" 2>&1
    rc=$?
    e=$(date +%s)
    echo "gate_rc=$rc" >>"$log"
    echo "wall_s=$((e - s))" >>"$log"
    printf '%s\t%s\t%s\t%s\n' "$2" "${3:-run1}" "$rc" "$((e - s))" >>"$OUT/timings.tsv"
    prog "$1" "$2${3:+-$3}" "gate_rc=$rc wall_s=$((e - s))"
}

SKIP_ALWAYS="chaos-gate soak-gate stress-gate prod-gate prod-realm-gate nfs-krb5p-gate sssd-renew-gate ad-mit-trust-gate"
PEERS_GATES="samba-ad-gate ad-windows-gate ad-s4u-gate samba-pac-verify-gate samba-pac-l2-gate samba-crossrealm-gate samba-realtrust-gate heimdal-gate"
HARNESS_ATTACH="knobs-gate ccache-gate client-gate config-include-gate"

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
    if [ "$PEERS" != 1 ]; then
        case " $PEERS_GATES " in *" $g "*) return 1 ;; esac
    fi
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

if [ -n "$TWICE" ]; then
    i=70
    IFS=',' read -r -a twice_arr <<<"$TWICE"
    for g in "${twice_arr[@]}"; do
        g=${g%.sh}
        [ -n "$g" ] || continue
        i=$((i + 1))
        rungate "$i" "$g" run2
    done
fi

if [ "$PEERS" = 1 ]; then
    i=80
    for g in $PEERS_GATES; do
        i=$((i + 1))
        rungate "$i" "$g" peers
    done
fi

echo "finished=$(date -Is)" >>"$OUT/00-head.txt"
echo CHECKPOINT_DONE
