#!/usr/bin/env bash
# Live MIT 1.22.2 DOMAIN-X500-COMPRESS: 4-hop A.EX.COM→EX.COM→B.EX.COM→C.EX.COM
# must emit tr-type 1 contents EX.COM,B. and expand to B.EX.COM.
# Isolation: throwaway container only. Host /etc and host /tmp are not written.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-capaths-compress"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
XR_PW="xrpassword"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"capaths-compress-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "capaths.compress" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-pac-extract -q

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker exec "$NAME" chmod +x /tmp/krb5-pac-extract

docker exec -i "$NAME" bash -s <<'CONF'
set -euo pipefail
write_client() {
    local cap="$1" dest="$2"
    cat >"$dest" <<EOF
[libdefaults]
    default_realm = A.EX.COM
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_s2
[realms]
    A.EX.COM = {
        kdc = 127.0.0.1:88
    }
    EX.COM = {
        kdc = 127.0.0.1:89
    }
    B.EX.COM = {
        kdc = 127.0.0.1:90
    }
    C.EX.COM = {
        kdc = 127.0.0.1:91
    }
${cap}
EOF
}
write_client "
[capaths]
    A.EX.COM = {
        EX.COM = .
        B.EX.COM = EX.COM
        C.EX.COM = EX.COM
        C.EX.COM = B.EX.COM
    }
    C.EX.COM = {
        A.EX.COM = B.EX.COM
        A.EX.COM = EX.COM
    }
" /tmp/client.conf
write_client "" /tmp/client-nocapaths.conf
write_kdc() {
    local realm="$1" port="$2" db="$3" f="$4"
    mkdir -p "$db"
    cat >"$f" <<EOF
[kdcdefaults]
    kdc_ports = ${port}
    kdc_tcp_ports = ${port}
[realms]
    ${realm} = {
        database_name = ${db}/principal
        key_stash_file = ${db}/.k5.${realm}
        acl_file = /var/kerberos/krb5kdc/kadm5.acl
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }
EOF
}
write_kdc A.EX.COM 88 /tmp/db-a /tmp/kdc-a.conf
write_kdc EX.COM 89 /tmp/db-x /tmp/kdc-x.conf
write_kdc B.EX.COM 90 /tmp/db-b /tmp/kdc-b.conf
write_kdc C.EX.COM 91 /tmp/db-c /tmp/kdc-c.conf
CONF

kad() {
    local profile="$1" realm="$2"
    shift 2
    docker exec -e KRB5_CONFIG=/tmp/client.conf -e KRB5_KDC_PROFILE="$profile" \
        "$NAME" kadmin.local -r "$realm" -q "$*"
}

echo "==== kdb5_util ===="
for spec in "A.EX.COM /tmp/kdc-a.conf" "EX.COM /tmp/kdc-x.conf" "B.EX.COM /tmp/kdc-b.conf" "C.EX.COM /tmp/kdc-c.conf"; do
    set -- $spec
    docker exec -e KRB5_CONFIG=/tmp/client.conf -e KRB5_KDC_PROFILE="$2" \
        "$NAME" kdb5_util -r "$1" create -s -P masterpassword >/dev/null
done

echo "==== principals ===="
kad /tmp/kdc-a.conf A.EX.COM "addprinc -pw userpassword user"
kad /tmp/kdc-a.conf A.EX.COM "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/EX.COM@A.EX.COM"
kad /tmp/kdc-x.conf EX.COM "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/EX.COM@A.EX.COM"
kad /tmp/kdc-x.conf EX.COM "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/B.EX.COM@EX.COM"
kad /tmp/kdc-b.conf B.EX.COM "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/B.EX.COM@EX.COM"
kad /tmp/kdc-b.conf B.EX.COM "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/C.EX.COM@B.EX.COM"
kad /tmp/kdc-c.conf C.EX.COM "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/C.EX.COM@B.EX.COM"
kad /tmp/kdc-c.conf C.EX.COM "addprinc -randkey host/svc.c.ex.com"
kad /tmp/kdc-c.conf C.EX.COM "ktadd -k /tmp/mit-c.host.kt host/svc.c.ex.com"

start_mit() {
    local realm="$1" profile="$2" log="$3" pidf="$4" conf="${5:-/tmp/client.conf}"
    docker exec -e KRB5_CONFIG="$conf" -e KRB5_KDC_PROFILE="$profile" \
        "$NAME" sh -c "krb5kdc -n -r ${realm} >${log} 2>&1 & echo \$! >${pidf}"
}
wait_port() {
    local port="$1" i
    for i in $(seq 1 80); do
        if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',${port}),0.3)" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

echo "==== start MIT KDCs ===="
start_mit A.EX.COM /tmp/kdc-a.conf /tmp/mit-a.log /tmp/mit-a.pid
start_mit EX.COM /tmp/kdc-x.conf /tmp/mit-x.log /tmp/mit-x.pid
start_mit B.EX.COM /tmp/kdc-b.conf /tmp/mit-b.log /tmp/mit-b.pid
start_mit C.EX.COM /tmp/kdc-c.conf /tmp/mit-c.log /tmp/mit-c.pid
wait_port 88 && wait_port 89 && wait_port 90 && wait_port 91 || {
    docker exec "$NAME" sh -c 'cat /tmp/mit-a.log /tmp/mit-x.log /tmp/mit-b.log /tmp/mit-c.log' || true
    log "capaths.compress" "error" ',"error":"MIT KDCs did not listen"'
    exit 1
}

echo "==== MIT kvno (permitted, compressed transited) ===="
set +e
CHASE="$(docker exec -e KRB5_CONFIG=/tmp/client.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_s2 user@A.EX.COM && kvno -c /tmp/krb5cc_s2 host/svc.c.ex.com@C.EX.COM" 2>&1)"
rc=$?
set -e
echo "$CHASE"
if [ "$rc" -ne 0 ]; then
    docker exec "$NAME" sh -c 'cat /tmp/mit-a.log /tmp/mit-x.log /tmp/mit-b.log /tmp/mit-c.log' || true
    log "capaths.compress" "error" ',"error":"MIT 4-hop kvno failed","rc":'"$rc"
    exit 1
fi
echo "$CHASE" | grep -q 'host/svc.c.ex.com@C.EX.COM: kvno ='
DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/mit-c.host.kt --ccache /tmp/krb5cc_s2 --print-transited)"
echo "$DUMP"
echo "$DUMP" | grep -q '^transited_tr_type=1$'
echo "$DUMP" | grep -q '^transited_contents=EX.COM,B.$'
echo "$DUMP" | grep -q '^transited_realms=EX.COM,B.EX.COM$'
echo "$DUMP" | grep -q '^transited_policy_checked=1$'
FLAGS="$(docker exec -e KRB5_CONFIG=/tmp/client.conf "$NAME" klist -f -c /tmp/krb5cc_s2)"
echo "$FLAGS"
echo "$FLAGS" | awk '/host\/svc.c.ex.com/{p=1;next} p&&/Flags:/{print;exit}' | grep -q T

echo "==== MIT C without [capaths] rejects the extra B.EX.COM hop ===="
docker exec "$NAME" sh -c 'kill -9 $(cat /tmp/mit-c.pid) 2>/dev/null || true'
for _ in $(seq 1 20); do
    if docker exec "$NAME" python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', 91), 0.15)
    s.close()
    raise SystemExit(0)
except OSError:
    raise SystemExit(1)
" 2>/dev/null; then
        sleep 0.25
        continue
    fi
    break
done
start_mit C.EX.COM /tmp/kdc-c.conf /tmp/mit-c-deny.log /tmp/mit-c.pid /tmp/client-nocapaths.conf
wait_port 91 || {
    docker exec "$NAME" cat /tmp/mit-c-deny.log || true
    log "capaths.compress" "error" ',"error":"deny C did not listen"'
    exit 1
}
docker exec -e KRB5_CONFIG=/tmp/client.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_deny user@A.EX.COM" >/dev/null
set +e
DENY="$(docker exec -e KRB5_CONFIG=/tmp/client.conf "$NAME" \
    kvno -c /tmp/krb5cc_deny host/svc.c.ex.com@C.EX.COM 2>&1)"
drc=$?
set -e
echo "$DENY"
test "$drc" -ne 0
# Live MIT 1.22.2 on this hierarchy prints POLICY, not PATH_NOT_ACCEPTED.
echo "$DENY" | grep -q 'KDC policy rejects request'

log "capaths.compress" "ok" \
    ',"contents":"EX.COM,B.","expanded":"EX.COM,B.EX.COM","denied":true'
exit 0
