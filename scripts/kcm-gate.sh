#!/usr/bin/env bash
# Rust KCM client vs sssd-kcm, content-asserted with MIT 1.22.2 klist.
# Shares the MIT harness network namespace so 127.0.0.1:88 is the KDC.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kcm-gate}"
mkdir -p "$SCRATCH"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kcm-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

MIT="kerber-rust-mit-kdc"
KCM="kerber-rust-sssd-kcm"
IMAGE="${KCM_IMAGE:-kerber-rust-sssd-kcm:f43}"
F43_DIGEST="sha256:96b2a05f8ce3111e10c236abe8055b01500880d95ee7c2f92fa30847fdbb667b"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not available" | tee "$SCRATCH/kcm-gate-unavailable.log"
    log "kcm.gate" "unavailable" ',"error":"docker not available"'
    exit 2
fi
STOP_MIT=0
if ! docker ps -q --filter "name=^${MIT}$" | grep -q .; then
    ./scripts/run-harness.sh
    STOP_MIT=1
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/kcm/Dockerfile --build-arg "FEDORA_DIGEST=${F43_DIGEST}" \
        -t "$IMAGE" "$ROOT"
fi

cargo build -p krb5-client --bin krb5-kinit --bin krb5-klist --bin krb5-kdestroy --bin krb5-kswitch

docker rm -f "$KCM" >/dev/null 2>&1 || true
docker run -d --name "$KCM" --network "container:${MIT}" "$IMAGE" >/dev/null
cleanup() {
    docker rm -f "$KCM" >/dev/null 2>&1 || true
    if [ "$STOP_MIT" = 1 ]; then
        ./scripts/stop-harness.sh >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
for _ in $(seq 1 50); do
    if docker exec "$KCM" test -S /run/.heim_org.h5l.kcm-socket; then
        break
    fi
    sleep 0.2
done
if ! docker exec "$KCM" test -S /run/.heim_org.h5l.kcm-socket; then
    docker logs "$KCM" >&2 || true
    log "kcm.gate" "error" ',"error":"sssd-kcm socket missing"'
    exit 1
fi

docker cp target/debug/krb5-kinit "$KCM":/tmp/krb5-kinit
docker cp target/debug/krb5-klist "$KCM":/tmp/krb5-klist
docker cp target/debug/krb5-kdestroy "$KCM":/tmp/krb5-kdestroy
docker cp target/debug/krb5-kswitch "$KCM":/tmp/krb5-kswitch
docker cp "$ROOT/harness/kcm/krb5.conf" "$KCM":/etc/krb5.conf
docker exec "$KCM" chmod +x /tmp/krb5-kinit /tmp/krb5-klist /tmp/krb5-kdestroy /tmp/krb5-kswitch

docker exec "$MIT" kadmin.local -q 'addprinc -pw extrapass extra' >/dev/null 2>&1 || true

kcm_exec() {
    docker exec -e KRB5_CONFIG=/etc/krb5.conf -e KRB5CCNAME=KCM: "$KCM" "$@"
}

echo "==== KEYRING still unknown ===="
UNK="$(docker exec "$KCM" /tmp/krb5-klist -c 'KEYRING:user:foo' 2>&1 || true)"
echo "$UNK"
echo "$UNK" | grep -q 'Unknown credential cache type'
if echo "$UNK" | grep -q 'G8'; then
    echo "KEYRING error leaked G8" >&2
    exit 1
fi

echo "==== Rust kinit into KCM; MIT klist names user@KERBER.TEST ===="
kcm_exec /tmp/krb5-kdestroy >/dev/null 2>&1 || true
kcm_exec sh -c 'echo userpassword | /tmp/krb5-kinit -c KCM: user@KERBER.TEST'
MIT1="$(kcm_exec klist -c KCM:)"
echo "$MIT1"
echo "$MIT1" | grep -q 'user@KERBER.TEST'
echo "$MIT1" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'
RUST1="$(kcm_exec /tmp/krb5-klist -c KCM:)"
echo "$RUST1"
echo "$RUST1" | grep -q 'user@KERBER.TEST'

echo "==== MIT kinit into KCM; Rust klist names extra@KERBER.TEST ===="
kcm_exec sh -c 'echo extrapass | kinit -c KCM: extra@KERBER.TEST'
MIT2="$(kcm_exec klist -c KCM:)"
echo "$MIT2"
echo "$MIT2" | grep -q 'extra@KERBER.TEST'
RUST2="$(kcm_exec /tmp/krb5-klist -c KCM:)"
echo "$RUST2"
echo "$RUST2" | grep -q 'extra@KERBER.TEST'

echo "==== two-principal collection + kswitch ===="
# sssd-kcm rejects arbitrary residuals (MIT kinit -c KCM:user is FCC_INTERNAL).
# Second cache is a GEN_NEW name (uid:random), matching krb5_cc_new_unique.
kcm_exec sh -c 'echo userpassword | /tmp/krb5-kinit -c KCM: user@KERBER.TEST'
SECOND="$(docker exec -i "$KCM" python3 - <<'PY'
import socket, struct
def i32(u):
    return u - 0x100000000 if u >= 0x80000000 else u
def readn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SystemExit("kcm closed")
        b += c
    return b
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/.heim_org.h5l.kcm-socket")
payload = bytes([2, 0]) + struct.pack(">H", 3)
s.sendall(struct.pack(">I", len(payload)) + payload)
n, outer = struct.unpack(">II", readn(s, 8))
body = readn(s, n) if n else b""
print(body[4:].split(b"\0", 1)[0].decode())
PY
)"
echo "second_cache=$SECOND"
kcm_exec sh -c "echo extrapass | /tmp/krb5-kinit -c 'KCM:${SECOND}' extra@KERBER.TEST"
kcm_exec /tmp/krb5-kswitch -c KCM:0
SW1="$(kcm_exec klist -c KCM:)"
echo "$SW1"
echo "$SW1" | grep -q 'user@KERBER.TEST'
kcm_exec /tmp/krb5-kswitch -p extra@KERBER.TEST
SW2="$(kcm_exec /tmp/krb5-klist -c KCM:)"
echo "$SW2"
echo "$SW2" | grep -q 'extra@KERBER.TEST'

echo "==== kdestroy second cache ===="
kcm_exec /tmp/krb5-kdestroy -c "KCM:${SECOND}"
set +e
GONE="$(kcm_exec klist -c "KCM:${SECOND}" 2>&1)"
grc=$?
set -e
echo "$GONE"
if [ "$grc" -eq 0 ] && echo "$GONE" | grep -q 'extra@KERBER.TEST'; then
    echo "MIT klist still names extra after kdestroy" >&2
    exit 1
fi
kcm_exec /tmp/krb5-kswitch -c KCM:0 >/dev/null 2>&1 || true

echo "==== sssd-kcm restart (container stop/start = reboot cell) ===="
docker restart "$KCM" >/dev/null
for _ in $(seq 1 50); do
    if docker exec "$KCM" test -S /run/.heim_org.h5l.kcm-socket; then
        break
    fi
    sleep 0.2
done
RST="$(kcm_exec klist -c KCM:)"
echo "$RST"
echo "$RST" | grep -q 'user@KERBER.TEST'

echo "==== re-prime default KCM: ===="
kcm_exec /tmp/krb5-kdestroy -c KCM: >/dev/null 2>&1 || true
kcm_exec sh -c 'echo userpassword | /tmp/krb5-kinit -c KCM: user@KERBER.TEST'
PRIME="$(kcm_exec klist -c KCM:)"
echo "$PRIME"
echo "$PRIME" | grep -q 'user@KERBER.TEST'

log "kcm.gate" "ok" ''
echo "kcm-gate ok"
