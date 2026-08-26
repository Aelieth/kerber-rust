#!/usr/bin/env bash
# C1 multi-host prod realm: MIT client vs Rust primary + kprop to replica +
# primary-kill failover. Isolation: docker network; never touches host
# /etc/krb5.conf. Loopback `prod-gate.sh` stays; this is the named-realm gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/prod-realm-common.sh"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-prod-realm-gate}"
OUT="$SCRATCH/prod-realm-gate"
mkdir -p "$OUT"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"prod-realm-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    log "prod.realm.gate" "error" ",\"error\":\"$1\""
    echo "$1" | tee "$SCRATCH/prod-realm-gate-unavailable.log"
    exit 2
}

die() {
    log "prod.realm.gate" "error" ",\"error\":\"$1\""
    echo "FATAL: $1" >&2
    exit 1
}

cleanup() {
    "$ROOT/harness/prod/env-down.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi

cargo build -p krb5-kdc -p krb5-admin -q

if ! docker image inspect "$KERBER_PROD_IMAGE" >/dev/null 2>&1; then
    if docker image inspect "$KERBER_PROD_IMAGE_FALLBACK" >/dev/null 2>&1; then
        echo "building $KERBER_PROD_IMAGE from $KERBER_PROD_IMAGE_FALLBACK"
        docker build -f harness/prod/Dockerfile -t "$KERBER_PROD_IMAGE" "$ROOT" \
            || die "prod-node capture image build failed"
    else
        unavailable "neither $KERBER_PROD_IMAGE nor $KERBER_PROD_IMAGE_FALLBACK is built"
    fi
fi

echo "==== env-up $REALM ===="
"$ROOT/harness/prod/env-up.sh" | tee "$OUT/env-up.log"
grep -q 'SMOKE OK' "$OUT/env-up.log" || die "env-up smoke did not pass"

PIP="$(prod_ip_of "$PRIMARY")"; RIP="$(prod_ip_of "$REPLICA")"; CIP="$(prod_ip_of "$CLIENT")"
[ -n "$PIP" ] && [ -n "$RIP" ] && [ -n "$CIP" ] || die "IP discovery failed"

analyze_logs() {
    local src="$1" dest="$2"
    python3 - "$src" "$dest" <<'PY'
import json, sys, pathlib
log_path, out_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
issues = []
n_json = 0
n_issue_ok = 0
n_cid = 0
panics = 0
for line in log_path.read_text(errors="replace").splitlines():
    if "panic" in line.lower():
        panics += 1
        issues.append("panic")
    if not line.startswith("{"):
        continue
    try:
        o = json.loads(line)
    except json.JSONDecodeError:
        issues.append("bad_json")
        continue
    n_json += 1
    fields = o.get("fields") or {}
    cid = fields.get("correlation_id") or o.get("correlation_id")
    if cid:
        n_cid += 1
    event = fields.get("event") or o.get("event")
    outcome = fields.get("outcome") or o.get("outcome")
    if event == "kdc.issue" and outcome == "ok":
        n_issue_ok += 1
        if not cid or cid == "none":
            issues.append("issue_without_correlation_id")
    if outcome == "error" and event not in (None,):
        if isinstance(event, str) and event.startswith("kdc.") and "skipped" not in json.dumps(fields):
            issues.append(f"error_event:{event}")
rep = {
    "event": "prod.realm.gate.logs",
    "json_lines": n_json,
    "correlation_id_fields": n_cid,
    "kdc_issue_ok": n_issue_ok,
    "panics": panics,
    "issues": issues,
    "outcome": "ok" if n_issue_ok >= 1 and panics == 0 and not issues else "error",
}
out_path.write_text(json.dumps(rep) + "\n")
print(json.dumps(rep))
if rep["outcome"] != "ok":
    sys.exit(1)
PY
}

CAP=0
if docker exec "$PRIMARY" sh -c 'command -v tcpdump >/dev/null'; then
    docker exec -d "$PRIMARY" sh -c \
        'tcpdump -i eth0 -n -U -s 0 -w /tmp/prod-realm.pcap "port 88 or port 754 or (ip[6:2] & 0x1fff != 0)" >/tmp/tcpdump.log 2>&1 & echo $! >/tmp/tcpdump.pid'
    sleep 0.8
    CAP=1
fi
if [ "${KERBER_REQUIRE_REAL_PCAP:-0}" = "1" ] && [ "$CAP" != 1 ]; then
    die "KERBER_REQUIRE_REAL_PCAP=1 but tcpdump is not available on the primary"
fi

echo "==== MIT kinit/kvno against primary ===="
prod_client kdestroy -A >/dev/null 2>&1 || true
prod_client sh -c "printf '%s\n' '$KERBER_PROD_USER_PW' | kinit user@$REALM" \
    | tee "$OUT/kinit-primary.log"
KVNO1="$(prod_client kvno "${HOST_SMOKE}@$REALM" 2>&1 | tee -a "$OUT/kinit-primary.log")"
echo "$KVNO1"
KL1="$(prod_client klist 2>&1 | tee "$OUT/klist-primary.txt")"
echo "$KL1"
echo "$KL1" | grep -q "krbtgt/${REALM}" || die "klist missing krbtgt/$REALM"
echo "$KL1" | grep -q "testhost.${DNS_DOMAIN}" || die "klist missing $HOST_SMOKE"

echo "==== kprop primary -> replica (shared helper) ===="
prod_kprop_replica || {
    docker exec "$REPLICA" cat /tmp/kpropd.log >&2 || true
    die "kprop/replica KDC failed"
}
docker exec "$REPLICA" grep -q 'kprop ok' /tmp/kpropd.log \
    || die "kpropd log missing kprop ok"
docker exec "$REPLICA" test -f /tmp/replica.db || die "replica db missing after kprop"
docker exec "$REPLICA" head -1 /tmp/replica.db | grep -q 'kdb5_util load_dump version 7' \
    || die "replica db is not dump version 7"

echo "==== MIT kvno kadmin host on primary ===="
prod_client kvno "${HOST_APP}@$REALM" | tee "$OUT/kvno-app.log"
KLAPP="$(prod_client klist 2>&1 | tee "$OUT/klist-app.txt")"
echo "$KLAPP" | grep -q "app.${DNS_DOMAIN}" || die "klist missing $HOST_APP after kadmin"

docker cp "$PRIMARY":/tmp/kdc.log "$OUT/kdc1.log"
analyze_logs "$OUT/kdc1.log" "$OUT/kdc1-log-analysis.json"

if [ "$CAP" = 1 ]; then
    sleep 0.8
    docker exec "$PRIMARY" sh -c 'kill -INT "$(cat /tmp/tcpdump.pid 2>/dev/null)" 2>/dev/null; sleep 0.4' || true
    docker cp "$PRIMARY":/tmp/prod-realm.pcap "$OUT/prod-realm.pcap" 2>/dev/null || \
        docker cp "$PRIMARY":/tmp/prod.pcap "$OUT/prod-realm.pcap" 2>/dev/null || true
fi

echo "==== kill primary; MIT kinit/kvno against replica ===="
docker kill "$PRIMARY" >/dev/null
prod_point_client_at "$RIP"

prod_client kdestroy -A >/dev/null 2>&1 || true
prod_client sh -c "printf '%s\n' '$KERBER_PROD_USER_PW' | kinit user@$REALM" \
    | tee "$OUT/kinit-replica.log"
prod_client kvno "${HOST_SMOKE}@$REALM" | tee -a "$OUT/kinit-replica.log"
prod_client kvno "${HOST_APP}@$REALM" | tee -a "$OUT/kinit-replica.log"
KL2="$(prod_client klist 2>&1 | tee "$OUT/klist-replica.txt")"
echo "$KL2"
echo "$KL2" | grep -q "krbtgt/${REALM}" || die "replica klist missing krbtgt"
echo "$KL2" | grep -q "testhost.${DNS_DOMAIN}" || die "replica klist missing smoke host"
echo "$KL2" | grep -q "app.${DNS_DOMAIN}" || die "replica klist missing kadmin host"

docker cp "$REPLICA":/tmp/kdc.log "$OUT/kdc2.log"
analyze_logs "$OUT/kdc2.log" "$OUT/kdc2-log-analysis.json"
docker cp "$REPLICA":/tmp/kpropd.log "$OUT/kpropd.log" 2>/dev/null || true

echo "==== pcap ===="
if [ -f "$OUT/prod-realm.pcap" ]; then
    PSZ="$(wc -c <"$OUT/prod-realm.pcap" | tr -d ' ')"
    echo "pcap_source=eth0 pcap_bytes=$PSZ" | tee "$OUT/pcap.stat"
    [ "$PSZ" -gt 24 ] || die "pcap empty"
    if command -v tshark >/dev/null 2>&1; then
        MSG="$(tshark -r "$OUT/prod-realm.pcap" -d udp.port==88,kerberos -d tcp.port==88,kerberos \
            -Y kerberos -T fields -e kerberos.msg_type 2>/dev/null | tr ',' '\n' | sort -un | tr '\n' ' ')"
        echo "kerberos_msg_types=$MSG" | tee -a "$OUT/pcap.stat"
        echo "$MSG" | grep -qw 10 || die "pcap missing AS-REQ (10)"
        echo "$MSG" | grep -qw 11 || die "pcap missing AS-REP (11)"
        echo "$MSG" | grep -qw 12 || die "pcap missing TGS-REQ (12)"
        echo "$MSG" | grep -qw 13 || die "pcap missing TGS-REP (13)"
    else
        docker cp "$OUT/prod-realm.pcap" "$REPLICA":/tmp/prod-realm.pcap
        MSG="$(docker exec "$REPLICA" sh -c \
            'tshark -r /tmp/prod-realm.pcap -d udp.port==88,kerberos -d tcp.port==88,kerberos -Y kerberos -T fields -e kerberos.msg_type 2>/dev/null | tr "," "\n" | sort -un | tr "\n" " "')"
        echo "kerberos_msg_types=$MSG" | tee -a "$OUT/pcap.stat"
        echo "$MSG" | grep -qw 10 || die "pcap missing AS-REQ (10)"
        echo "$MSG" | grep -qw 11 || die "pcap missing AS-REP (11)"
        echo "$MSG" | grep -qw 12 || die "pcap missing TGS-REQ (12)"
        echo "$MSG" | grep -qw 13 || die "pcap missing TGS-REP (13)"
    fi
else
    if [ "${KERBER_REQUIRE_REAL_PCAP:-0}" = "1" ]; then
        die "KERBER_REQUIRE_REAL_PCAP=1 but no eth0 pcap was archived"
    fi
    echo "pcap_source=reconstructed" | tee "$OUT/pcap.stat"
    docker cp "$PRIMARY":/tmp/pdus "$OUT/pdus" 2>/dev/null || docker cp "$REPLICA":/tmp/pdus "$OUT/pdus" 2>/dev/null || true
    PCAP="$OUT/prod-realm.pcap"
    python3 - "$OUT/pdus" "$PCAP" <<'PY'
import pathlib, struct, sys, time
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
if not src.is_dir():
    print("reconstructed pdu dir missing", file=sys.stderr)
    sys.exit(1)
files = sorted(src.glob("*.der"))
gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
pkts = []
ts = time.time()
sport = 50000
types = set()
for i, f in enumerate(files):
    payload = f.read_bytes()
    if not payload:
        continue
    tag = payload[0]
    if 0x60 <= tag <= 0x7F:
        types.add(tag - 0x60)
    sip, dip = (b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01")
    sp, dp = (sport, 88) if "req" in f.name else (88, sport)
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, i + 1, 0, 64, 17, 0, sip, dip)
    udp = struct.pack("!HHHH", sp, dp, udp_len, 0) + payload
    pkt = ip + udp
    sec = int(ts)
    usec = int((ts - sec) * 1e6) + i
    pkts.append(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt)
need = {10, 11, 12, 13}
if not need.issubset(types):
    print(f"reconstructed PDUs missing AS/TGS; have={sorted(types)} need={sorted(need)}", file=sys.stderr)
    sys.exit(1)
dst.write_bytes(gh + b"".join(pkts))
print(f"pcap_pdus={len(pkts)} pcap_bytes={dst.stat().st_size} msg_types={' '.join(str(t) for t in sorted(types))}")
PY
    echo "pcap_source=reconstructed" | tee -a "$OUT/pcap.stat"
    if [ "$CAP" = 1 ]; then
        die "NET_RAW capture was started but no pcap was archived"
    fi
fi

log "prod.realm.gate" "ok" \
    ",\"realm\":\"$REALM\",\"primary\":\"$PIP\",\"replica\":\"$RIP\",\"kprop\":\"ok\""
exit 0
