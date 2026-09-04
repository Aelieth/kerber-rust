#!/usr/bin/env bash
# C2a: concurrent wire AS+TGS against the multi-host realm + MIT sampling +
# p99/throughput/error/panic SLO from KDC JSON logs.
# Isolation: docker network; never touches host /etc/krb5.conf.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/prod-realm-common.sh"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-stress-gate}"
OUT="$SCRATCH/stress-gate"
mkdir -p "$OUT"

P99_MAX_US="${KERBER_SLO_P99_MAX_US:-50000}"
THROUGHPUT_MIN="${KERBER_SLO_THROUGHPUT_MIN:-8}"
DEGRADE_FACTOR="${KERBER_SLO_DEGRADE_FACTOR:-2.5}"
export KERBER_LOAD_WORKERS="${KERBER_LOAD_WORKERS:-8}"
export KERBER_LOAD_ITERS="${KERBER_LOAD_ITERS:-8}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"stress-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}
die() {
    log "stress.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}
unavailable() {
    log "stress.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/stress-gate-unavailable.log"
    exit 2
}
cleanup() {
    "$ROOT/harness/prod/env-down.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || unavailable "docker not available"

python3 "$ROOT/scripts/lib/analyze-kdc-slo.py" --self-test \
    || die "SLO analyzer self-test failed"

cargo build -p krb5-kdc -p krb5-admin --bins -q
cargo build -p krb5-client --example loadgen -q

echo "==== env-up $REALM ===="
"$ROOT/harness/prod/env-up.sh" | tee "$OUT/env-up.log"
grep -q 'SMOKE OK' "$OUT/env-up.log" || die "env-up smoke did not pass"

PIP="$(prod_ip_of "$PRIMARY")"
[ -n "$PIP" ] || die "primary IP missing"
prod_stage_loadgen || die "stage loadgen"

echo "==== MIT sample before load ===="
prod_mit_sample before || die "MIT kinit/kvno failed before load"
# Cold PAC-sized AS-REP and first worker burst are bring-up, not the load
# p99 (GHA first-window ~100 ms). Snapshot after a discarded warmup run.
echo "==== warmup loadgen ===="
prod_loadgen "$PIP" >"$OUT/loadgen-warmup.log" 2>&1 || die "warmup loadgen failed"
grep -q '"err":0' "$OUT/loadgen-warmup.log" || die "warmup loadgen reported errors"
docker cp "$PRIMARY":/tmp/kdc.log "$OUT/kdc-warmup.log"

echo "==== wire loadgen workers=${KERBER_LOAD_WORKERS} iters=${KERBER_LOAD_ITERS} ===="
MID_RC_FILE="$OUT/mid.rc"
echo 1 >"$MID_RC_FILE"
(
    sleep 0.4
    if ! prod_mit_sample mid; then
        echo 1 >"$MID_RC_FILE"
        exit 1
    fi
    echo 0 >"$MID_RC_FILE"
) &
MID_PID=$!
set +e
START=$(date +%s)
prod_loadgen "$PIP" | tee "$OUT/loadgen.log"
LG_RC=${PIPESTATUS[0]}
END=$(date +%s)
set -e
wait "$MID_PID" || true
[ "$LG_RC" = 0 ] || die "loadgen failed (see $OUT/loadgen.log)"
[ "$(cat "$MID_RC_FILE")" = 0 ] || die "MIT kinit/kvno failed mid-load"
grep -q '"event":"loadgen"' "$OUT/loadgen.log" || die "loadgen missing JSON summary"
grep -q '"err":0' "$OUT/loadgen.log" || die "loadgen reported errors"

echo "==== MIT sample after load ===="
prod_mit_sample after || die "MIT kinit/kvno failed after load"

docker cp "$PRIMARY":/tmp/kdc.log "$OUT/kdc1.log"
WALL=$((END - START))
[ "$WALL" -lt 1 ] && WALL=1

python3 "$ROOT/scripts/lib/analyze-kdc-slo.py" \
    --log "$OUT/kdc1.log" \
    --warmup-log "$OUT/kdc-warmup.log" \
    --out "$OUT/slo.json" \
    --p99-max-us "$P99_MAX_US" \
    --throughput-min "$THROUGHPUT_MIN" \
    --max-error-rate 0 \
    --min-issue-ok 16 \
    --elapsed-s "$WALL" \
    --windows 2 \
    --degrade-factor "$DEGRADE_FACTOR" \
    || die "SLO analysis failed"

echo "slo_p99_max_us=$P99_MAX_US throughput_min=$THROUGHPUT_MIN degrade_factor=$DEGRADE_FACTOR" | tee "$OUT/slo.bounds"
log "stress.gate" "ok" \
    ",\"realm\":\"$REALM\",\"p99_max_us\":$P99_MAX_US,\"throughput_min\":$THROUGHPUT_MIN,\"degrade_factor\":$DEGRADE_FACTOR"
exit 0
