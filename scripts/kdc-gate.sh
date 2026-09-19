#!/usr/bin/env bash
# Production-gate: MIT 1.22.2 kinit + kvno against the Rust KDC.
# Copies the Rust binary into a client-only MIT image so UDP stays on 127.0.0.1
# (host Docker publish of port 88 is unreliable).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-mit-client"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "kdc.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

shell_container
if ! docker exec "$NAME" test -f /usr/lib/krb5/plugins/audit/k5audit_test.so; then
    echo "MIT image lacks k5audit_test.so; rebuilding" >&2
    if [ -n "${KERBER_SHELL:-}" ]; then
        log "kdc.gate" "error" ',"error":"k5audit_test.so missing in shared shell image"'
        exit 1
    fi
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
    docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
    if ! docker exec "$NAME" test -f /usr/lib/krb5/plugins/audit/k5audit_test.so; then
        log "kdc.gate" "error" ',"error":"k5audit_test.so missing after rebuild"'
        exit 1
    fi
fi

if ! docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc; then
    log "kdc.gate" "error" ',"error":"docker cp krb5-kdc failed"'
    exit 1
fi
docker exec "$NAME" chmod +x /tmp/krb5-kdc

# Bind 88 inside the container (root). Fall back to 8888 via the binary.
docker exec "$NAME" mkdir -p /tmp/traces
docker exec "$NAME" chmod 0777 /tmp/traces
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KERBER_CAPTURE_DIR=/tmp/traces \
    -e KRB5_KDC_AUDIT=test \
    -e KRB5_KDC_AUDIT_LOG=/tmp/au-rust.log \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1 || /tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/kdc.log 2>&1'

require_listen "$NAME" /tmp/kdc.log "rust KDC listening in /tmp/kdc.log"

echo "==== rust KDC log ===="
docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true

LISTEN="$(docker exec "$NAME" grep '^listening ' /tmp/kdc.log | tail -1)"
PORT=88
case "$LISTEN" in
    *:8888*) PORT=8888 ;;
esac

if [ "$PORT" != 88 ]; then
    docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1/kdc = 127.0.0.1:${PORT}/' /etc/krb5.conf"
fi

echo "==== MIT kinit ===="
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    log "kdc.gate" "error" ',"error":"MIT kinit failed"'
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLIST1="$(docker exec "$NAME" klist)"
echo "$KLIST1"
echo "$KLIST1" | grep -q 'user@KERBER.TEST'
echo "$KLIST1" | grep -Ei 'Flags:|flags:' || echo "$KLIST1" | grep -q krbtgt

echo "==== MIT kvno host/testhost.kerber.test ===="
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" kvno host/testhost.kerber.test; then
    log "kdc.gate" "error" ',"error":"MIT kvno failed"'
    docker exec "$NAME" klist || true
    echo "==== rust KDC log after kvno ===="
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLIST2="$(docker exec "$NAME" klist)"
echo "$KLIST2"
echo "$KLIST2" | grep -q 'user@KERBER.TEST'
echo "$KLIST2" | grep -q 'host/testhost.kerber.test'

echo "==== rust KDC ISSUE tuple after kinit + kvno ===="
require_log "$NAME" /tmp/kdc.log 'ISSUE' "ISSUE in /tmp/kdc.log"
require_log "$NAME" /tmp/kdc.log 'krbtgt/KERBER.TEST' "krbtgt/KERBER.TEST in /tmp/kdc.log"
require_log "$NAME" /tmp/kdc.log 'host/testhost.kerber.test' "host/testhost.kerber.test in /tmp/kdc.log"
RUSTLOG="$(docker exec "$NAME" cat /tmp/kdc.log)"
echo "$RUSTLOG"
echo "$RUSTLOG" | grep -q 'ISSUE' # RUST_issue_as
echo "$RUSTLOG" | grep -q 'user@KERBER.TEST'
echo "$RUSTLOG" | grep -q 'krbtgt/KERBER.TEST'
echo "$RUSTLOG" | grep -F 'etypes {rep='
echo "$RUSTLOG" | grep -q 'host/testhost.kerber.test' # RUST_issue_tgs
echo "$RUSTLOG" | grep -F 'tkt='
echo "$RUSTLOG" | grep -F 'ses='

echo "==== MIT kinit -a then kvno via 127.0.0.1 is BADADDR ===="
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" sh -c 'printf "userpassword\n" | kinit -a user@KERBER.TEST'; then
    log "kdc.gate" "error" ',"error":"MIT kinit -a failed"'
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLISTA="$(docker exec "$NAME" klist -a -n)"
echo "$KLISTA"
echo "$KLISTA" | grep -qE 'Addresses: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
set +e
KVNOA="$(docker exec -e KRB5_TRACE=/dev/stderr "$NAME" kvno host/testhost.kerber.test 2>&1)"
KVNOA_RC=$?
set -e
echo "$KVNOA"
if [ "$KVNOA_RC" -eq 0 ]; then
    log "kdc.gate" "error" ',"error":"kinit -a kvno via 127.0.0.1 unexpectedly succeeded"'
    exit 1
fi
echo "$KVNOA" | grep -qiE "Incorrect net address|BADADDR|KRB5KRB_AP_ERR_BADADDR"

echo "==== MIT kinit -a + kvno via bridge address ===="
BRIDGE="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
if [ -z "$BRIDGE" ]; then
    log "kdc.gate" "error" ',"error":"no docker bridge address"'
    exit 1
fi
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) 2>/dev/null || true'
wait_pid_gone "$NAME" krb5-kdc || true
docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KERBER_CAPTURE_DIR=/tmp/traces \
    -e KRB5_KDC_AUDIT=test \
    -e KRB5_KDC_AUDIT_LOG=/tmp/au-rust.log \
    "$NAME" sh -c "/tmp/krb5-kdc --test-realm 0.0.0.0:${PORT} >/tmp/kdc-bridge.log 2>&1"
require_listen "$NAME" /tmp/kdc-bridge.log "rust KDC listening on 0.0.0.0 in /tmp/kdc-bridge.log"
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec "$NAME" sh -c "sed -i 's/kdc = 127.0.0.1.*/kdc = ${BRIDGE}:${PORT}/' /etc/krb5.conf"
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" sh -c 'printf "userpassword\n" | kinit -a user@KERBER.TEST'; then
    log "kdc.gate" "error" ',"error":"MIT kinit -a via bridge failed"'
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
if ! docker exec -e KRB5_TRACE=/dev/stderr "$NAME" kvno host/testhost.kerber.test; then
    log "kdc.gate" "error" ',"error":"MIT kvno via bridge failed"'
    docker exec "$NAME" klist -a -n || true
    docker exec "$NAME" cat /tmp/kdc.log 2>/dev/null || true
    exit 1
fi
KLISTB="$(docker exec "$NAME" klist -a -n)"
echo "$KLISTB"
echo "$KLISTB" | grep -q 'host/testhost.kerber.test'
echo "$KLISTB" | grep -qE 'Addresses: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

TRACE_DST="${KERBER_TRACE_DST:-${KERBER_SCRATCH:-$ROOT/target}/traces}"
refuse_golden_capture_dir "$TRACE_DST"
refuse_golden_capture_dir "${KERBER_CAPTURE_DIR:-}"
mkdir -p "$TRACE_DST"
docker cp "$NAME":/tmp/traces/. "$TRACE_DST/" 2>/dev/null || true

echo "==== MIT krb5kdc ISSUE + audit test plugin ===="
docker exec "$NAME" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kdc" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill -9 "$pid" 2>/dev/null || true
    fi
done
'
wait_gone_in "$NAME" 88 40 || die "rust kdc still bound :88"
docker exec -i "$NAME" python3 - <<'PY'
from pathlib import Path
p = Path("/etc/krb5.conf")
t = p.read_text()
out = []
sec = ""
for line in t.splitlines():
    s = line.strip()
    if s.startswith("[") and s.endswith("]"):
        sec = s
    if sec == "[realms]" and s.startswith("kdc ="):
        out.append("        kdc = 127.0.0.1")
        continue
    if sec == "[logging]" and s.startswith("kdc ="):
        out.append("    kdc = FILE:/tmp/mit-issue.log")
        continue
    out.append(line)
text = "\n".join(out) + "\n"
if "k5audit_test.so" not in text:
    text += """
[plugins]
    audit = {
        module = test:/usr/lib/krb5/plugins/audit/k5audit_test.so
    }
"""
p.write_text(text)
print("krb5.conf-ok")
PY
docker exec "$NAME" sh -c '
kdb5_util destroy -f >/dev/null 2>&1 || true
kdb5_util create -s -P masterpassword
kadmin.local -q "addprinc -pw userpassword user"
kadmin.local -q "addprinc -randkey host/testhost.kerber.test"
rm -f /tmp/au.log /tmp/mit-issue.log
'
docker exec -d \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    "$NAME" sh -c 'cd /tmp && krb5kdc -n >/tmp/mit-kdc-stdout.log 2>&1'
if ! wait_port_in "$NAME" 88 80; then
    docker exec "$NAME" cat /tmp/mit-kdc-stdout.log >&2 || true
    die "MIT krb5kdc listening on :88 never appeared"
fi
docker exec "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/mit-issue.log >&2 || true
    log "kdc.gate" "error" ',"error":"MIT kinit vs MIT KDC failed"'
    exit 1
fi
if ! docker exec "$NAME" kvno host/testhost.kerber.test; then
    docker exec "$NAME" cat /tmp/mit-issue.log >&2 || true
    log "kdc.gate" "error" ',"error":"MIT kvno vs MIT KDC failed"'
    exit 1
fi
require_log "$NAME" /tmp/mit-issue.log 'ISSUE' "ISSUE in /tmp/mit-issue.log"
require_log "$NAME" /tmp/mit-issue.log 'krbtgt/KERBER.TEST' "krbtgt/KERBER.TEST in /tmp/mit-issue.log"
require_log "$NAME" /tmp/mit-issue.log 'host/testhost.kerber.test' "host/testhost.kerber.test in /tmp/mit-issue.log"
MITLOG="$(docker exec "$NAME" cat /tmp/mit-issue.log 2>/dev/null || true)"
echo "$MITLOG"
echo "$MITLOG" | grep -q 'ISSUE' # MIT_issue_as
echo "$MITLOG" | grep -q 'user@KERBER.TEST'
echo "$MITLOG" | grep -q 'krbtgt/KERBER.TEST'
echo "$MITLOG" | grep -F 'etypes {rep='
echo "$MITLOG" | grep -q 'host/testhost.kerber.test' # MIT_issue_tgs
echo "$MITLOG" | grep -F 'tkt='
echo "$MITLOG" | grep -F 'ses='

echo "==== audit field names both legs ===="
# /tmp/au.log is rewritten by the live MIT audit plugin after rm -f.
# Wait until the rows both python reads need exist (AS/TGS finish + TGS seed).
_au_ready=0
for _ in $(seq 1 80); do
    if docker exec -i "$NAME" python3 - <<'PY'
import json, sys
try:
    text = open("/tmp/au.log").read()
except OSError:
    sys.exit(1)
rows = []
for line in text.splitlines():
    line = line.strip()
    if not line or line == "state is NULL":
        continue
    try:
        rows.append(json.loads(line))
    except json.JSONDecodeError:
        continue
def finish(name):
    return any(
        r.get("event_name") == name
        and r.get("event_success") in (True, 1)
        and r.get("tkt_out_id")
        for r in rows
    )
def tgs_seed():
    return any(
        r.get("event_name") == "TGS_REQ"
        and r.get("event_success") in (True, 1)
        and not r.get("tkt_out_id")
        and r.get("stage") == 1
        for r in rows
    )
sys.exit(0 if finish("AS_REQ") and finish("TGS_REQ") and tgs_seed() else 1)
PY
    then
        _au_ready=1
        break
    fi
    sleep 0.1
done
if [ "$_au_ready" != 1 ]; then
    docker exec "$NAME" cat /tmp/au.log >&2 || true
    die "expected rows in /tmp/au.log never appeared"
fi
docker exec -i "$NAME" python3 - <<'PY'
import json, re, sys
def rows(path):
    out = []
    try:
        text = open(path).read()
    except OSError as e:
        print(f"missing {path}: {e}", file=sys.stderr)
        raise SystemExit(1)
    for line in text.splitlines():
        line = line.strip()
        if not line or line == "state is NULL":
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
mit = rows("/tmp/au.log")
rust = rows("/tmp/au-rust.log")
def first(rows, name):
    # MIT AS seeds kau_as_req(TRUE) at AUTHN_REQ_CL with no tkt_out_id
    # (do_as_req.c:520). Compare the ENCR_REP issue record.
    for r in rows:
        if (
            r.get("event_name") == name
            and r.get("event_success") in (True, 1)
            and r.get("tkt_out_id")
        ):
            return r
    print(f"no success {name} with tkt_out_id", file=sys.stderr)
    raise SystemExit(1)
keys = ["event_name", "event_success", "stage", "tkt_out_id", "req_id", "fromport"]
for name in ("AS_REQ", "TGS_REQ"):
    m = first(mit, name)
    r = first(rust, name)
    for k in keys:
        if k not in m or k not in r:
            print(f"{name} missing {k} mit={k in m} rust={k in r}", file=sys.stderr)
            raise SystemExit(1)
    for side, rec in (("MIT", m), ("RUST", r)):
        tkt = rec["tkt_out_id"]
        if not re.fullmatch(r"[0-9A-F]{64}", str(tkt)):
            print(f"{side} {name} tkt_out_id {tkt}", file=sys.stderr)
            raise SystemExit(1)
        rid = str(rec["req_id"])
        if not re.fullmatch(r"[0-9A-Za-z]{31}", rid):
            print(f"{side} {name} req_id {rid}", file=sys.stderr)
            raise SystemExit(1)
    if m["stage"] != r["stage"]:
        print(f"{name} stage mit={m['stage']} rust={r['stage']}", file=sys.stderr)
        raise SystemExit(1)
print("audit-fields-ok")
PY
echo "RUST_audit_fields" # TestAudit /tmp/au-rust.log
echo "MIT_audit_fields" # k5audit_test.so /tmp/au.log

echo "==== TGS audit seed both legs ===="
docker exec -i "$NAME" python3 - <<'PY'
import json, sys
def rows(path):
    out = []
    try:
        text = open(path).read()
    except OSError as e:
        print(f"missing {path}: {e}", file=sys.stderr)
        raise SystemExit(1)
    for line in text.splitlines():
        line = line.strip()
        if not line or line == "state is NULL":
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
def finish(rows):
    for r in rows:
        if (
            r.get("event_name") == "TGS_REQ"
            and r.get("event_success") in (True, 1)
            and r.get("tkt_out_id")
        ):
            return r
    print("no TGS ENCR_REP", file=sys.stderr)
    raise SystemExit(1)
def seed(rows):
    for r in rows:
        if (
            r.get("event_name") == "TGS_REQ"
            and r.get("event_success") in (True, 1)
            and not r.get("tkt_out_id")
            and r.get("stage") == 1
        ):
            return r
    print("no TGS AUTHN_REQ_CL seed", file=sys.stderr)
    raise SystemExit(1)
for side, path in (("MIT", "/tmp/au.log"), ("RUST", "/tmp/au-rust.log")):
    recs = rows(path)
    s = seed(recs)
    f = finish(recs)
    if s.get("req_id") != f.get("req_id"):
        print(f"{side} TGS seed req_id {s.get('req_id')} != {f.get('req_id')}", file=sys.stderr)
        raise SystemExit(1)
print("tgs-audit-seed-ok")
PY
echo "MIT_tgs_audit_seed"
echo "RUST_tgs_audit_seed"

log "kdc.gate" "ok" ",\"principal\":\"user@KERBER.TEST\",\"service\":\"host/testhost.kerber.test\",\"issue\":true,\"audit\":true"
