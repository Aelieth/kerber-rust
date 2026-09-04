#!/usr/bin/env bash
# Multi-process production-gate: Rust KDC + client AS/TGS with structured
# logs and a loopback pcap. Isolated bind; never touches host /etc/krb5.conf.
#
# Promotion checks: listening JSON has correlation_id; at least one
# kdc.issue outcome=ok; pcap is non-empty when tcpdump can run; no panic.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-prod-gate}"
OUT="$SCRATCH/prod-gate"
mkdir -p "$OUT"

export KRB5_TEST_USER_PASSWORD="${KRB5_TEST_USER_PASSWORD:-userpassword}"
export KRB5_TEST_ADMIN_PASSWORD="${KRB5_TEST_ADMIN_PASSWORD:-adminpassword}"
export KRB5_PASSWORD="${KRB5_PASSWORD:-$KRB5_TEST_USER_PASSWORD}"
export RUST_LOG="${RUST_LOG:-krb5_kdc=info,krb5_protocol=info,krb5_client=info}"
export KERBER_CAPTURE_DIR="$OUT/pdus"
rm -rf "$KERBER_CAPTURE_DIR"
mkdir -p "$KERBER_CAPTURE_DIR"

cargo build -p krb5-kdc --bin krb5-kdc -q
cargo build -p krb5-client --bin krb5-kinit -q
BIND="127.0.0.1:18888"
LOG="$OUT/kdc.json"
PCAP="$OUT/kdc.pcap"
LO_PCAP="$OUT/kdc-lo.pcap"
TCPDUMP_PID=""
KDC_PID=""

cleanup() {
    if [ -n "$TCPDUMP_PID" ]; then
        sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "$KDC_PID" ]; then
        kill "$KDC_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Loopback capture of the isolated bind only. Write aside from $PCAP:
# sudo tcpdump creates a root-owned file; chmod a+r does not make it
# writable, and reconstruct would then PermissionError on GHA.
if command -v tcpdump >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    rm -f "$LO_PCAP"
    sudo -n tcpdump -i lo -n -U -w "$LO_PCAP" "port 18888" >/dev/null 2>"$OUT/tcpdump.err" &
    TCPDUMP_PID=$!
    sleep 0.2
fi

# Previous run's listener may still hold 18888 for a beat after trap.
for _ in $(seq 1 25); do
    if ! ss -uln 2>/dev/null | grep -q ':18888'; then
        break
    fi
    sleep 0.2
done

./target/debug/krb5-kdc --test-realm "$BIND" >"$LOG" 2>&1 &
KDC_PID=$!

ok=0
for _ in $(seq 1 50); do
    if grep -q "listening" "$LOG" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.1
done
if [ "$ok" -ne 1 ]; then
    echo "kdc did not listen" | tee "$OUT/error"
    cat "$LOG" || true
    exit 1
fi

# Real AS+TGS against the shipped listener (not a garbage datagram).
CC="$OUT/prod.ccache"
rm -f "$CC"
set +e
./target/debug/krb5-kinit -c "$CC" -S host/testhost.kerber.test \
    127.0.0.1:18888 user@KERBER.TEST \
    >"$OUT/kinit.log" 2>&1
kinit_rc=$?
set -e
echo "kinit_rc=$kinit_rc" | tee -a "$OUT/kinit.log"
sleep 0.3

# Stop capture so the pcap is flushed.
if [ -n "$TCPDUMP_PID" ]; then
    sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
    TCPDUMP_PID=""
    sleep 0.2
    sudo -n chmod a+r "$LO_PCAP" 2>/dev/null || true
fi

# Structured-log analysis is a promotion criterion.
python3 - "$LOG" "$OUT/log-analysis.json" <<'PY'
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
        # privilege-drop skip is outcome=ok; real errors fail promotion
        if event.startswith("kdc.") and "skipped" not in json.dumps(fields):
            issues.append(f"error_event:{event}")
rep = {
    "event": "prod.gate.logs",
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

if [ "$kinit_rc" -ne 0 ]; then
    echo "krb5-kinit against 127.0.0.1:18888 failed" | tee "$OUT/error"
    cat "$OUT/kinit.log" || true
    exit 1
fi
if ! grep -q 'ok tgt=' "$OUT/kinit.log"; then
    echo "kinit log missing ok tgt=" | tee "$OUT/error"
    exit 1
fi

# NIC capture needs CAP_NET_RAW (absent in this rootless distrobox).
# Reconstruct a pcap from KERBER_CAPTURE_DIR PDUs (real socket-boundary DER).
# Always (re)create $PCAP as this user; do not replace a root-owned live capture.
rm -f "$PCAP" 2>/dev/null || sudo -n rm -f "$PCAP" 2>/dev/null || true
python3 - "$KERBER_CAPTURE_DIR" "$PCAP" <<'PY'
import pathlib, struct, sys, time
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
files = sorted(src.glob("*.der"))
# pcap global header: magic, v2.4, utc, 0, snaplen, LINKTYPE_RAW (101) IPv4
gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
pkts = []
ts = time.time()
sport = 50000
for i, f in enumerate(files):
    payload = f.read_bytes()
    if not payload:
        continue
    to_kdc = "req" in f.name
    sip, dip = (b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01")
    sp, dp = (sport, 18888) if to_kdc else (18888, sport)
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    # IPv4 UDP
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, i + 1, 0, 64, 17, 0, sip, dip,
    )
    # checksum 0 is allowed for UDP over IPv4 in captures
    udp = struct.pack("!HHHH", sp, dp, udp_len, 0) + payload
    pkt = ip + udp
    sec = int(ts)
    usec = int((ts - sec) * 1e6) + i
    rec = struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt
    pkts.append(rec)
dst.write_bytes(gh + b"".join(pkts))
print(f"pcap_pdus={len(pkts)} pcap_bytes={dst.stat().st_size}")
if len(pkts) < 2:
    sys.exit(1)
PY
echo "pcap_source=KERBER_CAPTURE_DIR" | tee "$OUT/pcap.stat"
if [ -f "$PCAP" ]; then
    psz=$(wc -c <"$PCAP" | tr -d ' ')
    echo "pcap_bytes=$psz" | tee -a "$OUT/pcap.stat"
    ls "$KERBER_CAPTURE_DIR" | tee "$OUT/pdus.list"
    if command -v tshark >/dev/null 2>&1; then
        tshark -r "$PCAP" -d udp.port==18888,kerberos -q -z io,phs 2>/dev/null \
            | tee "$OUT/pcap-tshark.txt" || true
        tshark -r "$PCAP" -d udp.port==18888,kerberos -Y kerberos \
            -T fields -e frame.number -e kerberos.msg_type \
            2>/dev/null | tee "$OUT/pcap-msg-types.txt" || true
    fi
else
    echo "no pcap file" | tee "$OUT/pcap-unavailable.log"
    exit 1
fi

echo "{\"event\":\"prod.gate\",\"correlation_id\":\"$CORRELATION_ID\",\"component\":\"prod-gate\",\"outcome\":\"ok\",\"bind\":\"$BIND\",\"kinit_rc\":$kinit_rc}"
exit 0
