#!/usr/bin/env bash
# C2b: netem flakiness, low-memory under load, failover-under-load over
# harness/prod. Isolation: docker network; never touches host /etc/krb5.conf.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/prod-realm-common.sh"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-chaos-gate}"
OUT="$SCRATCH/chaos-gate"
mkdir -p "$OUT"

export KERBER_LOAD_WORKERS="${KERBER_LOAD_WORKERS:-4}"
export KERBER_LOAD_ITERS="${KERBER_LOAD_ITERS:-4}"
MEM_CAP="${KERBER_CHAOS_MEM:-128m}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"chaos-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}
die() {
    log "chaos.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}
unavailable() {
    log "chaos.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/chaos-gate-unavailable.log"
    exit 2
}
cleanup() {
    "$ROOT/harness/prod/env-down.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || unavailable "docker not available"
cargo build -p krb5-kdc -p krb5-admin --bins -q
cargo build -p krb5-client --example loadgen -q

echo "==== env-up $REALM ===="
"$ROOT/harness/prod/env-up.sh" | tee "$OUT/env-up.log"
grep -q 'SMOKE OK' "$OUT/env-up.log" || die "env-up smoke did not pass"
PIP="$(prod_ip_of "$PRIMARY")"
RIP="$(prod_ip_of "$REPLICA")"
[ -n "$PIP" ] && [ -n "$RIP" ] || die "IP discovery failed"
prod_stage_loadgen || die "stage loadgen"

echo "==== netem delay/loss/reorder on primary eth0 ===="
NETEM_OK=0
if docker exec "$PRIMARY" sh -c 'command -v tc >/dev/null'; then
    if docker exec "$PRIMARY" tc qdisc add dev eth0 root netem delay 50ms 10ms loss 2% reorder 5% 25% 2>"$OUT/netem.err"; then
        NETEM_OK=1
        echo "netem applied" | tee "$OUT/netem.log"
        if ! prod_mit_sample netem | tee "$OUT/mit-netem.log"; then
            docker exec "$PRIMARY" tc qdisc del dev eth0 root 2>/dev/null || true
            die "MIT kinit/kvno failed under netem"
        fi
        echo "MIT completed under netem" | tee -a "$OUT/netem.log"
        docker exec "$PRIMARY" tc qdisc del dev eth0 root 2>/dev/null || true
        echo "netem: MIT ok, no panic" | tee -a "$OUT/netem.log"
    else
        echo "NETEM_UNAVAILABLE: tc qdisc failed (need CAP_NET_ADMIN)" | tee "$OUT/netem-unavailable.log"
        cat "$OUT/netem.err" >>"$OUT/netem-unavailable.log" || true
        [ -s "$OUT/netem-unavailable.log" ]
    fi
else
    echo "NETEM_UNAVAILABLE: tc not installed in node" | tee "$OUT/netem-unavailable.log"
    [ -s "$OUT/netem-unavailable.log" ]
fi
docker cp "$PRIMARY":/tmp/kdc.log "$OUT/kdc-netem.log" 2>/dev/null || true
if grep -qi panic "$OUT/kdc-netem.log" 2>/dev/null; then
    die "panic under netem"
fi
if [ "${KERBER_REQUIRE_NETEM:-0}" = "1" ] && [ "$NETEM_OK" != "1" ]; then
    die "KERBER_REQUIRE_NETEM=1 but netem was not applied"
fi

echo "==== low memory cap $MEM_CAP under load ===="
if docker update --memory "$MEM_CAP" --memory-swap "$MEM_CAP" "$PRIMARY" 2>"$OUT/mem-update.err"; then
    echo "memory cap $MEM_CAP" | tee "$OUT/memory.log"
    set +e
    prod_loadgen "$PIP" | tee "$OUT/loadgen-mem.log"
    LG_RC=${PIPESTATUS[0]}
    set -e
    OOM="$(docker inspect -f '{{.State.OOMKilled}}' "$PRIMARY" 2>/dev/null || echo false)"
    echo "oom_killed=$OOM loadgen_rc=$LG_RC" | tee -a "$OUT/memory.log"
    docker cp "$PRIMARY":/tmp/kdc.log "$OUT/kdc-mem.log"
    if grep -qi panic "$OUT/kdc-mem.log"; then
        docker update --memory "$KERBER_KDC_MEM" "$PRIMARY" >/dev/null 2>&1 || true
        die "panic under low memory"
    fi
    [ "$OOM" != "true" ] || die "container OOM-killed under $MEM_CAP"
    prod_mit_sample memory || die "MIT kinit/kvno failed under low memory"
    docker update --memory "$KERBER_KDC_MEM" --memory-swap "$KERBER_KDC_MEM" "$PRIMARY" >/dev/null 2>&1 || true
else
    echo "memory update failed: $(cat "$OUT/mem-update.err")" >&2
    die "docker update --memory $MEM_CAP failed"
fi

echo "==== kprop then failover under load ===="
prod_kprop_replica || {
    docker exec "$REPLICA" cat /tmp/kpropd.log >&2 || true
    die "kprop/replica KDC failed"
}
export KERBER_LOAD_SECONDS=8
export KERBER_LOAD_ITERS=999
prod_loadgen "$PIP" >"$OUT/loadgen-failover.log" 2>&1 &
LG_PID=$!
sleep 1.5
docker kill "$PRIMARY" >/dev/null
RUNNING="$(docker inspect -f '{{.State.Running}}' "$PRIMARY" 2>/dev/null || echo missing)"
echo "primary_running=$RUNNING" | tee "$OUT/primary-after-kill.txt"
[ "$RUNNING" = "false" ] || die "primary still running after docker kill (running=$RUNNING)"
prod_point_client_at "$RIP"
prod_client kdestroy -A >/dev/null 2>&1 || true
prod_client sh -c "printf '%s\n' '$KERBER_PROD_USER_PW' | kinit user@$REALM" \
    | tee "$OUT/kinit-replica.log"
prod_client kvno "${HOST_SMOKE}@$REALM" | tee -a "$OUT/kinit-replica.log"
prod_client kvno "${HOST_APP}@$REALM" | tee "$OUT/kvno-app-replica.log"
KL="$(prod_client klist 2>&1 | tee "$OUT/klist-replica.txt")"
echo "$KL"
echo "$KL" | grep -q "krbtgt/${REALM}" || die "replica klist missing krbtgt after failover"
echo "$KL" | grep -q "testhost.${DNS_DOMAIN}" || die "replica klist missing smoke host"
echo "$KL" | grep -q "app.${DNS_DOMAIN}" || die "replica klist missing kadmin host after failover"
wait "$LG_PID" || true
docker cp "$REPLICA":/tmp/kdc.log "$OUT/kdc-replica.log"
if grep -qi panic "$OUT/kdc-replica.log"; then
    die "panic on replica after failover"
fi

log "chaos.gate" "ok" \
    ",\"realm\":\"$REALM\",\"netem\":$NETEM_OK,\"memory\":\"$MEM_CAP\",\"failover\":\"ok\""
exit 0
