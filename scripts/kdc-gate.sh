#!/usr/bin/env bash
# Production-gate: MIT 1.22.2 kinit + kvno against the Rust KDC, with the Rust
# binaries copied into one MIT container (the shared shell, or its own one started
# without a KDC) so UDP stays on 127.0.0.1 (host Docker publish of port 88 is
# unreliable). MIT's own krb5kdc with the audit test plugin runs there too, for the
# audit cells; the last cell starts the examples/configs KDC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
need_bins krb5-kdc krb5-kdb krb5-kadmind

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
    json_log_on "$NAME"
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
wait_gone_in "$NAME" 88 100 || die "rust kdc still bound :88"
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
docker exec "$NAME" kdb5_util destroy -f >/dev/null 2>&1 || true
docker exec "$NAME" kdb5_util create -s -P masterpassword
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -pw userpassword user"
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -randkey host/testhost.kerber.test"
docker exec "$NAME" rm -f /tmp/au.log /tmp/mit-issue.log
docker exec -d \
    -e KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    "$NAME" sh -c 'cd /tmp && krb5kdc -n >/tmp/mit-kdc-stdout.log 2>&1'
require_port_in "$NAME" 88 "MIT krb5kdc listening on :88"
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
_au_rows_ready() {
    docker exec -i "$NAME" python3 - <<'PY'
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
}
retry_until --log "$NAME" /tmp/au.log -- 200 "expected rows in /tmp/au.log" _au_rows_ready
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

# examples/configs as written: krb5-kdb creates EXAMPLE.COM from kdc.conf,
# krb5-kdc and krb5-kadmind start on kdc.conf and krb5.conf alone (its
# default_realm is their realm, as MIT's), MIT kadmin adds principals through
# kadm5.acl, and MIT kinit + kvno read krb5.conf.
echo "==== example configuration (examples/configs) ===="
EXAMPLE="$ROOT/examples/configs"
for f in kdc.conf krb5.conf kadm5.acl; do
    [ -f "$EXAMPLE/$f" ] || die "examples/configs/$f is missing"
done
# The MIT krb5kdc of the audit cell above still holds :88.
docker exec "$NAME" sh -c 'kill $(pidof krb5kdc) $(pidof krb5-kdc) $(pidof krb5-kadmind) 2>/dev/null; true'
wait_gone_in "$NAME" 88 || die "a KDC still holds port 88 before the example cell"
docker exec "$NAME" sh -c 'rm -rf /etc/kerber-rust /var/lib/kerber-rust /tmp/example-cc && mkdir -p /etc/kerber-rust /var/lib/kerber-rust'
for f in kdc.conf krb5.conf kadm5.acl; do
    docker cp "$EXAMPLE/$f" "$NAME":/etc/kerber-rust/"$f"
done
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdb /tmp/krb5-kadmind
docker exec "$NAME" sh -c 'grep -q " kdc.example.com$" /etc/hosts || echo "127.0.0.1 kdc.example.com" >>/etc/hosts'
docker exec -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5_KDC_PROFILE=/etc/kerber-rust/kdc.conf \
    -e KRB5_TEST_USER_PASSWORD=example-user \
    -e KRB5_TEST_ADMIN_PASSWORD=example-admin \
    "$NAME" /tmp/krb5-kdb -r EXAMPLE.COM -P example-master create -s \
    || die "example: krb5-kdb -r EXAMPLE.COM create -s failed"
docker exec -d -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5_KDC_PROFILE=/etc/kerber-rust/kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc -n >/tmp/example-kdc.log 2>&1'
require_listen "$NAME" /tmp/example-kdc.log "the example KDC (kdc.conf kdc_listen)"
docker exec -d -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5_KDC_PROFILE=/etc/kerber-rust/kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kadmind -nofork >/tmp/example-kadmind.log 2>&1'
require_listen "$NAME" /tmp/example-kadmind.log "the example kadmind (kdc.conf acl_file)"
echo "RUST_example_kdc_kadmind"
# ex: a MIT client in the container on the example krb5.conf and its own cache.
ex() {
    docker exec -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5CCNAME=FILE:/tmp/example-cc "$NAME" "$@"
}
# ex_addprinc ARGS PRINC: MIT kadmin -q exits 0 when the query is refused
# (kadmin_rc= records it), so the "created" line is the proof.
ex_addprinc() {
    local out rc=0
    out="$(mit_kadmin -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5CCNAME=FILE:/tmp/example-cc "$NAME" -- \
        -p admin@EXAMPLE.COM -w example-admin -q "addprinc $1" 2>&1)" || rc=$?
    echo "$out"
    echo "kadmin_rc=$rc"
    [ "$rc" = 0 ] || die "example: MIT kadmin addprinc $2 failed"
    grep -q "Principal \"$2\" created" <<<"$out" || die "example: MIT kadmin did not create $2"
}
ex_addprinc '-pw alice-secret alice' alice@EXAMPLE.COM
ex_addprinc '-randkey host/kdc.example.com' host/kdc.example.com@EXAMPLE.COM
ex sh -c 'printf "alice-secret\n" | kinit alice@EXAMPLE.COM' || die "example: MIT kinit alice@EXAMPLE.COM failed"
ex kvno host/kdc.example.com || die "example: MIT kvno host/kdc.example.com failed"
KLISTX="$(ex klist)"
echo "$KLISTX"
grep -q 'Default principal: alice@EXAMPLE.COM' <<<"$KLISTX" || die "example: klist does not name alice@EXAMPLE.COM"
grep -q 'host/kdc.example.com@EXAMPLE.COM' <<<"$KLISTX" || die "example: klist has no host/kdc.example.com ticket"
echo "MIT_example_kadmin_kinit_kvno"

# The same realm restarted on KLLDAP's kdc.conf shape: [kdcdefaults] kdc_ports =
# 750,88 and no listener relation for kadmind or kpasswd. MIT reads a bare port
# as every local address (net-server.c loop_add_addresses), so MIT kinit reaches
# the KDC over the container's own non-loopback address on TCP 88 and UDP 750,
# and MIT kadmin reaches kadmind there on 749.
echo "==== kdc_ports = 750,88 on every local address (KLLDAP kdc.conf shape) ===="
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) $(pidof krb5-kadmind) 2>/dev/null; true'
wait_gone_in "$NAME" 88 || die "the example KDC still holds port 88"
docker exec "$NAME" sh -c 'sed -i "s/^    kdc_listen = .*/    kdc_ports = 750,88/" /etc/kerber-rust/kdc.conf'
docker exec "$NAME" grep -q '^    kdc_ports = 750,88$' /etc/kerber-rust/kdc.conf \
    || die "listen: kdc.conf was not rewritten to kdc_ports = 750,88"
LIP="$(docker exec "$NAME" hostname -i | tr ' ' '\n' | grep -v '^127\.' | grep -v ':' | head -1)"
[ -n "$LIP" ] || die "listen: the container has no non-loopback IPv4 address"
docker exec -d -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5_KDC_PROFILE=/etc/kerber-rust/kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc -n >/tmp/listen-kdc.log 2>&1'
require_listen "$NAME" /tmp/listen-kdc.log "the KDC on kdc_ports = 750,88"
docker exec -d -e KRB5_CONFIG=/etc/kerber-rust/krb5.conf -e KRB5_KDC_PROFILE=/etc/kerber-rust/kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kadmind -nofork >/tmp/listen-kadmind.log 2>&1'
require_listen "$NAME" /tmp/listen-kadmind.log "kadmind on its default listeners"
docker exec "$NAME" cat /tmp/listen-kdc.log /tmp/listen-kadmind.log | grep -E '^(listening|kpasswd) '
# lconf PORT UDP_LIMIT: a client krb5.conf naming the KDC and kadmind by address.
lconf() {
    docker exec "$NAME" sh -c "sed -e 's/kdc = kdc.example.com:88/kdc = $LIP:$1/' \
        -e 's/admin_server = kdc.example.com:749/admin_server = $LIP:749/' \
        -e 's/^\[libdefaults\]/[libdefaults]\n    udp_preference_limit = $2/' \
        /etc/kerber-rust/krb5.conf >/tmp/listen-krb5-$1.conf"
}
lconf 88 1
lconf 750 4096
lx() {
    local conf=$1
    shift
    docker exec -e KRB5_CONFIG="$conf" -e KRB5CCNAME=FILE:/tmp/listen-cc -e KRB5_TRACE=/dev/stdout "$NAME" "$@"
}
TCP88="$(lx /tmp/listen-krb5-88.conf sh -c 'printf "alice-secret\n" | kinit alice@EXAMPLE.COM' 2>&1)" \
    || { echo "$TCP88" >&2; die "listen: MIT kinit over TCP to $LIP:88 failed"; }
grep -q "stream $LIP:88" <<<"$TCP88" || { echo "$TCP88" >&2; die "listen: kinit did not use TCP $LIP:88"; }
echo "MIT_kinit_tcp_${LIP}_88"
UDP750="$(lx /tmp/listen-krb5-750.conf sh -c 'printf "alice-secret\n" | kinit alice@EXAMPLE.COM' 2>&1)" \
    || { echo "$UDP750" >&2; die "listen: MIT kinit over UDP to $LIP:750 failed"; }
grep -q "dgram $LIP:750" <<<"$UDP750" || { echo "$UDP750" >&2; die "listen: kinit did not use UDP $LIP:750"; }
grep -q "Received answer" <<<"$UDP750" || { echo "$UDP750" >&2; die "listen: no UDP answer from $LIP:750"; }
echo "MIT_kinit_udp_${LIP}_750"
KAD="$(mit_kadmin -e KRB5_CONFIG=/tmp/listen-krb5-88.conf -e KRB5CCNAME=FILE:/tmp/listen-cc "$NAME" -- \
    -p admin@EXAMPLE.COM -w example-admin -q 'addprinc -randkey host/listen.example.com' 2>&1)" || true
echo "$KAD"
grep -q 'Principal "host/listen.example.com@EXAMPLE.COM" created' <<<"$KAD" \
    || die "listen: MIT kadmin addprinc over $LIP:749 failed"
KTA="$(mit_kadmin -e KRB5_CONFIG=/tmp/listen-krb5-88.conf -e KRB5CCNAME=FILE:/tmp/listen-cc "$NAME" -- \
    -p admin@EXAMPLE.COM -w example-admin -q 'ktadd -k /tmp/listen.keytab host/listen.example.com' 2>&1)" || true
echo "$KTA"
grep -q 'Entry for principal host/listen.example.com with kvno 2' <<<"$KTA" \
    || die "listen: MIT kadmin ktadd over $LIP:749 failed"
lx /tmp/listen-krb5-88.conf kinit -k -t /tmp/listen.keytab host/listen.example.com >/dev/null \
    || die "listen: MIT kinit -k with the ktadd keytab failed"
echo "MIT_kadmin_${LIP}_749_addprinc_ktadd_kinit_k"
docker exec "$NAME" rm -f /tmp/listen-cc /tmp/listen.keytab /tmp/listen-krb5-88.conf /tmp/listen-krb5-750.conf
docker exec "$NAME" sh -c 'kill $(pidof krb5-kdc) $(pidof krb5-kadmind) 2>/dev/null; rm -rf /etc/kerber-rust /var/lib/kerber-rust /tmp/example-cc; true'

log "kdc.gate" "ok" ",\"principal\":\"user@KERBER.TEST\",\"service\":\"host/testhost.kerber.test\",\"issue\":true,\"audit\":true"
