#!/usr/bin/env bash
# MIT 1.22.2 kprop → Rust kpropd (dump version 7) then MIT kinit.
# Isolated: docker --entrypoint sleep; never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kprop-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kprop-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kprop-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

kpropd_asn1_ap_req() {
    local port=$1
    docker exec "$NAME" python3 -c '
import socket, struct, sys
port = int(sys.argv[1])

def wr(s, data):
    s.sendall(struct.pack(">I", len(data)) + data)

def rd(s):
    hdr = s.recv(4)
    assert len(hdr) == 4, hdr
    n = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk, "eof"
        data += chunk
    return data

def tlv(data, i=0):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + l], i + l

def krb_error(der):
    _, inner, _ = tlv(der)
    _, seqb, _ = tlv(inner)
    i = 0
    fields = {}
    while i < len(seqb):
        t, v, i = tlv(seqb, i)
        n = t & 0x1F
        if t & 0x20 and v:
            _, inner2, _ = tlv(v)
            fields[n] = inner2
        else:
            fields[n] = v
    code = int.from_bytes(fields.get(6, b"\x00"), "big")
    return code, fields.get(11, b"")

s = socket.create_connection(("127.0.0.1", port), 2)
wr(s, b"KRB5_SENDAUTH_V1.0\0")
wr(s, b"kprop5_01\0")
ack = s.recv(1)
assert ack == b"\x00", ack
wr(s, b"\x6e\x00")
msg = rd(s)
print("tag=%02x len=%d" % (msg[0], len(msg)))
assert msg[:1] == b"\x7e", msg[:8]
code, etext = krb_error(msg)
print("error_code=%d" % code)
print("e_text_hex=" + etext.hex())
print("e_text=" + etext.decode("ascii", "replace"))
assert code == 60, code
assert etext.rstrip(b"\x00") == b"ASN.1 encoding ended unexpectedly", etext
' "$port"
}

kpropd_expired_ap_req() {
    local port=$1
    docker exec "$NAME" sh -c 'hn=$(hostname); /tmp/kprop-expired-apreq /tmp/host.keytab "host/${hn}" KERBER.TEST >/tmp/expired.apreq'
    docker exec "$NAME" python3 -c '
import socket, struct, sys
port = int(sys.argv[1])
ap = open("/tmp/expired.apreq", "rb").read()
assert ap[:1] == b"\x6e", ap[:8]

def wr(s, data):
    s.sendall(struct.pack(">I", len(data)) + data)

def rd(s):
    hdr = s.recv(4)
    assert len(hdr) == 4, hdr
    n = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk, "eof"
        data += chunk
    return data

def tlv(data, i=0):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + l], i + l

def krb_error(der):
    _, inner, _ = tlv(der)
    _, seqb, _ = tlv(inner)
    i = 0
    fields = {}
    while i < len(seqb):
        t, v, i = tlv(seqb, i)
        n = t & 0x1F
        if t & 0x20 and v:
            _, inner2, _ = tlv(v)
            fields[n] = inner2
        else:
            fields[n] = v
    code = int.from_bytes(fields.get(6, b"\x00"), "big")
    return code, fields.get(11, b"")

s = socket.create_connection(("127.0.0.1", port), 2)
wr(s, b"KRB5_SENDAUTH_V1.0\0")
wr(s, b"kprop5_01\0")
ack = s.recv(1)
assert ack == b"\x00", ack
wr(s, ap)
msg = rd(s)
print("tag=%02x len=%d" % (msg[0], len(msg)))
assert msg[:1] == b"\x7e", msg[:8]
code, etext = krb_error(msg)
print("error_code=%d" % code)
print("e_text_hex=" + etext.hex())
print("e_text=" + etext.decode("ascii", "replace"))
assert code == 32, code
assert etext == b"Ticket expired\x00", etext
print("expired_ticket=32")
' "$port"
}

kpropd_junk_ap_req() {
    local port=$1
    docker exec "$NAME" python3 -c '
import socket, struct, sys
port = int(sys.argv[1])

def wr(s, data):
    s.sendall(struct.pack(">I", len(data)) + data)

def rd(s):
    hdr = s.recv(4)
    assert len(hdr) == 4, hdr
    n = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        assert chunk, "eof"
        data += chunk
    return data

def tlv(data, i=0):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[i : i + n], "big")
        i += n
    return tag, data[i : i + l], i + l

def krb_error(der):
    _, inner, _ = tlv(der)
    _, seqb, _ = tlv(inner)
    i = 0
    fields = {}
    while i < len(seqb):
        t, v, i = tlv(seqb, i)
        n = t & 0x1F
        if t & 0x20 and v:
            _, inner2, _ = tlv(v)
            fields[n] = inner2
        else:
            fields[n] = v
    code = int.from_bytes(fields.get(6, b"\x00"), "big")
    return code, fields.get(11, b"")

s = socket.create_connection(("127.0.0.1", port), 2)
wr(s, b"KRB5_SENDAUTH_V1.0\0")
wr(s, b"kprop5_01\0")
ack = s.recv(1)
assert ack == b"\x00", ack
wr(s, b"\xff\x00\x01")
msg = rd(s)
print("tag=%02x len=%d" % (msg[0], len(msg)))
assert msg[:1] == b"\x7e", msg[:8]
code, etext = krb_error(msg)
print("error_code=%d" % code)
print("e_text_hex=" + etext.hex())
assert code == 40, code
assert etext == b"Invalid message type\x00", etext
' "$port"
}

kill_comm() {
    local comm="$1"
    docker exec "$NAME" sh -c '
comm="'"$comm"'"
for f in /proc/[0-9]*/comm; do
    [ -f "$f" ] || continue
    read -r name < "$f" || continue
    if [ "$name" = "$comm" ]; then
        pid=${f#/proc/}
        pid=${pid%/comm}
        kill -9 "$pid" 2>/dev/null || true
    fi
done
'
}

if ! command -v docker >/dev/null 2>&1; then
    log "kprop.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/kprop-gate-unavailable.log"
    exit 2
fi

cargo build -p krb5-kdc --bin krb5-kdc -p krb5-admin --bin krb5-kpropd --example kprop-expired-apreq

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "kprop.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/kprop-gate-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! docker exec "$NAME" sh -c 'command -v kprop >/dev/null'; then
    log "kprop.gate" "error" ',"error":"kprop binary missing"'
    echo "kprop binary missing in $IMAGE" >"$SCRATCH/kprop-gate-unavailable.log"
    exit 2
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-kpropd "$NAME":/tmp/krb5-kpropd
docker cp target/debug/examples/kprop-expired-apreq "$NAME":/tmp/kprop-expired-apreq
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kpropd /tmp/kprop-expired-apreq

docker exec "$NAME" sh -c 'cat >/tmp/kprop-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kprop
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== MIT realm + dump ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kadmin.local -q 'addprinc -pw userpassword user'
HN="$(docker exec "$NAME" hostname)"
docker exec "$NAME" kadmin.local -q "addprinc -randkey host/localhost"
docker exec "$NAME" kadmin.local -q "addprinc -randkey host/${HN}"
docker exec "$NAME" kadmin.local -q "ktadd -k /tmp/host.keytab host/localhost host/${HN}"
docker exec "$NAME" kdb5_util dump /tmp/dump
docker exec "$NAME" sh -c "printf 'host/localhost@KERBER.TEST\\nhost/${HN}@KERBER.TEST\\n' >/tmp/kpropd.acl"
docker exec "$NAME" sh -c 'sleep 0.2; touch /tmp/dump.dump_ok'
DUMP_HEAD="$(docker exec "$NAME" head -1 /tmp/dump)"
echo "$DUMP_HEAD"
echo "$DUMP_HEAD" | grep -q 'kdb5_util load_dump version 7'

echo "==== MIT krb5kdc for kprop tickets ===="
kill_comm krb5kdc
kill_comm krb5-kdc
STARTLOG="$(docker exec "$NAME" sh -c 'krb5kdc; sleep 0.4' 2>&1 || true)"
echo "$STARTLOG"
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kprop.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

echo "==== Rust kpropd on 754 ===="
kill_comm krb5-kpropd
kill_comm kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    -e KRB5_KPROP_ACL=/tmp/kpropd.acl \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd 127.0.0.1:754 >/tmp/kpropd.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kpropd.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "kprop.gate" "error" ',"error":"kpropd did not listen"'
    exit 1
fi

echo "==== Rust kpropd junk AP-REQ is KRB-ERROR ===="
kpropd_junk_ap_req 754
echo "==== Rust kpropd APPLICATION-14 ASN.1 fail is 60 ===="
kpropd_asn1_ap_req 754
echo "==== Rust kpropd expired AP-REQ is 32 Ticket expired ===="
kpropd_expired_ap_req 754

echo "==== MIT kprop localhost ===="
KPROP="$(docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$KPROP"
echo "==== kpropd.log ===="
docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true
echo "$KPROP" | grep -q 'SUCCEEDED'
docker exec "$NAME" test -f /tmp/replica

echo "==== stop MIT krb5kdc; Rust KDC on replica ===="
kill_comm krb5kdc
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
if [ "$free" != 1 ]; then
    log "kprop.gate" "error" ',"error":":88 still occupied"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:88 >/tmp/kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "kprop.gate" "error" ',"error":"rust replica kdc did not listen"'
    exit 1
fi

echo "==== MIT kinit user against replica ===="
docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    docker exec "$NAME" cat /tmp/kpropd.log >&2 || true
    log "kprop.gate" "error" ',"error":"MIT kinit after kprop failed"'
    exit 1
fi
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

echo "==== MIT kpropd junk AP-REQ is KRB-ERROR ===="
kill_comm krb5-kpropd
kill_comm kpropd
docker exec -d -e KRB5_CONFIG=/tmp/kprop-krb5.conf "$NAME" sh -c 'kpropd -S -d -s /tmp/host.keytab -a /tmp/kpropd.acl -P 1754 -f /tmp/from_junk.dump -p "$(command -v kdb5_util)" >/tmp/kpropd-mit.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -Eq 'ready|waiting for a kprop' /tmp/kpropd-mit.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd-mit.log >&2 || true
    log "kprop.gate" "error" ',"error":"MIT kpropd did not listen"'
    exit 1
fi
kpropd_junk_ap_req 1754
echo "==== MIT kpropd APPLICATION-14 ASN.1 fail is 60 ===="
kpropd_asn1_ap_req 1754
echo "==== MIT kpropd expired AP-REQ is 32 Ticket expired ===="
kpropd_expired_ap_req 1754

log "kprop.gate" "ok" ',"dump_version":7,"direction":"mit-kprop-to-rust-kpropd"'
exit 0
