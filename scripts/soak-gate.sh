#!/usr/bin/env bash
# C2c: bounded soak over harness/prod — moderate wire load, RSS leak check,
# non-degrading duration_us, error-rate flat, archived logs/pcap/RSS.
# Isolation: docker network; never touches host /etc/krb5.conf.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/prod-realm-common.sh"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-soak-gate}"
OUT="$SCRATCH/soak-gate"
mkdir -p "$OUT"

SOAK_S="${KERBER_SOAK_SECONDS:-70}"
export KERBER_LOAD_WORKERS="${KERBER_LOAD_WORKERS:-2}"
export KERBER_LOAD_SECONDS="$SOAK_S"
unset KERBER_LOAD_ITERS || true
P99_MAX_US="${KERBER_SLO_P99_MAX_US:-500000}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"soak-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}
die() {
    log "soak.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}
unavailable() {
    log "soak.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/soak-gate-unavailable.log"
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
# PDU files in the KDC cgroup inflate docker stats via page cache; RSS
# leak detection needs process RSS, not capture artifacts.
export KERBER_CAPTURE=0
"$ROOT/harness/prod/env-up.sh" | tee "$OUT/env-up.log"
grep -q 'SMOKE OK' "$OUT/env-up.log" || die "env-up smoke did not pass"
PIP="$(prod_ip_of "$PRIMARY")"
[ -n "$PIP" ] || die "primary IP missing"
prod_stage_loadgen || die "stage loadgen"

CAP=0
if docker exec "$CLIENT" sh -c 'command -v tcpdump >/dev/null'; then
    docker exec -d "$CLIENT" sh -c \
        'tcpdump -i eth0 -n -U -s 0 -w /tmp/soak.pcap "port 88 or (ip[6:2] & 0x1fff != 0)" >/tmp/tcpdump.log 2>&1 & echo $! >/tmp/tcpdump.pid'
    sleep 0.5
    CAP=1
fi
if [ "${KERBER_REQUIRE_REAL_PCAP:-0}" = "1" ] && [ "$CAP" != 1 ]; then
    die "KERBER_REQUIRE_REAL_PCAP=1 but tcpdump is not available on the client"
fi

echo "==== soak ${SOAK_S}s workers=${KERBER_LOAD_WORKERS} ===="
: >"$OUT/rss.tsv"
echo "# epoch_s rss_mib" >>"$OUT/rss.tsv"
START=$(date +%s)
echo "$START $(prod_rss_mib)" | tee -a "$OUT/rss.tsv"
prod_loadgen "$PIP" >"$OUT/loadgen.log" 2>&1 &
LG_PID=$!
SAMPLED=0
while kill -0 "$LG_PID" 2>/dev/null; do
    NOW=$(date +%s)
    RSS="$(prod_rss_mib)"
    echo "$NOW $RSS" | tee -a "$OUT/rss.tsv"
    if [ "$SAMPLED" = 0 ] && [ $((NOW - START)) -ge 8 ]; then
        prod_mit_sample soak-mid | tee -a "$OUT/mit-soak.log" \
            || die "MIT kinit/kvno failed mid-soak"
        SAMPLED=1
    fi
    sleep 5
done
wait "$LG_PID" || die "loadgen failed during soak"
[ "$SAMPLED" = 1 ] || die "MIT mid-soak sample did not run"
ELAPSED=$(( $(date +%s) - START ))
[ "$ELAPSED" -lt 1 ] && ELAPSED=1

prod_mit_sample soak-end || die "MIT kinit/kvno failed after soak"
grep -q '"event":"loadgen"' "$OUT/loadgen.log" || die "loadgen missing JSON summary"
grep -q '"err":0' "$OUT/loadgen.log" || die "loadgen reported errors during soak"

if [ "$CAP" = 1 ]; then
    docker exec "$CLIENT" sh -c 'kill -INT "$(cat /tmp/tcpdump.pid 2>/dev/null)" 2>/dev/null; sleep 0.3' || true
    if ! docker cp "$CLIENT":/tmp/soak.pcap "$OUT/soak.pcap" 2>/dev/null; then
        if [ "${KERBER_REQUIRE_REAL_PCAP:-0}" = "1" ]; then
            die "KERBER_REQUIRE_REAL_PCAP=1 but soak pcap was not archived"
        fi
    fi
fi
if [ "${KERBER_REQUIRE_REAL_PCAP:-0}" = "1" ]; then
    [ -f "$OUT/soak.pcap" ] || die "KERBER_REQUIRE_REAL_PCAP=1 but no soak pcap was archived"
    PSZ="$(wc -c <"$OUT/soak.pcap" | tr -d ' ')"
    [ "$PSZ" -gt 24 ] || die "KERBER_REQUIRE_REAL_PCAP=1 but soak pcap is empty"
fi
docker cp "$PRIMARY":/tmp/kdc.log "$OUT/kdc1.log"

python3 "$ROOT/scripts/lib/analyze-kdc-slo.py" \
    --log "$OUT/kdc1.log" \
    --out "$OUT/slo.json" \
    --p99-max-us "$P99_MAX_US" \
    --max-error-rate 0 \
    --min-issue-ok 8 \
    --elapsed-s "$ELAPSED" \
    --windows 2 \
    --degrade-factor 2.5 \
    --rss-series "$OUT/rss.tsv" \
    --min-rss-samples 5 \
    --rss-max-growth "${KERBER_SLO_RSS_MAX_GROWTH:-1.5}" \
    --rss-max-extra-mib "${KERBER_SLO_RSS_MAX_EXTRA_MIB:-8}" \
    --rss-max-slope-mib-s "${KERBER_SLO_RSS_MAX_SLOPE_MIB_S:-0.05}" \
    || die "soak SLO/RSS analysis failed"

python3 - "$OUT/kdc1.log" "$OUT/latency.tsv" <<'PY'
import json, pathlib, sys
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
rows = ["# seq duration_us"]
n = 0
for line in src.read_text(errors="replace").splitlines():
    if not line.startswith("{"):
        continue
    try:
        o = json.loads(line)
    except json.JSONDecodeError:
        continue
    fields = o.get("fields") or {}
    if (fields.get("event") or o.get("event")) != "kdc.issue":
        continue
    if (fields.get("outcome") or o.get("outcome")) != "ok":
        continue
    dur = fields.get("duration_us", o.get("duration_us"))
    if dur is None:
        continue
    rows.append(f"{n} {dur}")
    n += 1
dst.write_text("\n".join(rows) + "\n")
print(f"latency_samples={n}")
PY

echo "soak_seconds=$SOAK_S pcap=$CAP" | tee "$OUT/soak.stat"
log "soak.gate" "ok" ",\"realm\":\"$REALM\",\"seconds\":$SOAK_S"
exit 0
