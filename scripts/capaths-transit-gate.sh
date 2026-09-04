#!/usr/bin/env bash
# Three-hop A.TEST → B.TEST → C.TEST. MIT 1.22.2 KDCs are the transited-field
# oracle; MIT kvno is the client. Isolation: throwaway container only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-capaths-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
XR_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
XR_PW="xrpassword"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"capaths-transit-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "capaths.gate" "error" ',"error":"docker not available"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract --bin krb5-forge-tgt
cargo build -p krb5-client --bin krb5-kvno

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker cp target/debug/krb5-forge-tgt "$NAME":/tmp/krb5-forge-tgt
docker cp target/debug/krb5-kvno "$NAME":/tmp/krb5-kvno
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract /tmp/krb5-forge-tgt /tmp/krb5-kvno

docker exec -i "$NAME" bash -s <<'CONF'
set -euo pipefail
cat >/tmp/client-capaths.conf <<EOF
[libdefaults]
    default_realm = A.TEST
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    forwardable = true
    default_ccache_name = FILE:/tmp/krb5cc_capaths
[realms]
    A.TEST = {
        kdc = 127.0.0.1:88
    }
    B.TEST = {
        kdc = 127.0.0.1:89
    }
    C.TEST = {
        kdc = 127.0.0.1:90
    }
[domain_realm]
    .a.test = A.TEST
    .b.test = B.TEST
    .c.test = C.TEST
[capaths]
    A.TEST = {
        C.TEST = B.TEST
        B.TEST = .
    }
    C.TEST = {
        A.TEST = B.TEST
    }
EOF
write_kdc_conf() {
    local realm="$1" port="$2" db="$3" klog="$4"
    cat >"/tmp/kdc-${realm%%.*}.conf" <<EOF
[kdcdefaults]
    kdc_ports = ${port}
    kdc_tcp_ports = ${port}
[logging]
    kdc = FILE:${klog}
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
mkdir -p /tmp/db-a /tmp/db-b /tmp/db-c
write_kdc_conf A.TEST 88 /tmp/db-a /tmp/mit-a.log
write_kdc_conf B.TEST 89 /tmp/db-b /tmp/mit-b.log
write_kdc_conf C.TEST 90 /tmp/db-c /tmp/mit-c.log
sed 's/supported_enctypes.*/reject_bad_transit = false\n        supported_enctypes = aes256-cts-hmac-sha1-96:normal/' \
    /tmp/kdc-C.conf > /tmp/kdc-C-lax.conf
cat >/tmp/kdc-c-allow.conf <<EOF
[libdefaults]
    default_realm = C.TEST
    dns_lookup_kdc = false
[capaths]
    A.TEST = {
        C.TEST = B.TEST D.TEST
    }
EOF
cat >/tmp/kdc-c-deny.conf <<EOF
[libdefaults]
    default_realm = C.TEST
    dns_lookup_kdc = false
[realms]
    A.TEST = {
        kdc = 127.0.0.1:88
    }
    B.TEST = {
        kdc = 127.0.0.1:89
    }
    C.TEST = {
        kdc = 127.0.0.1:90
    }
EOF
cat >/tmp/client-garbage.conf <<EOF
[libdefaults]
    default_realm = A.TEST
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    canonicalize = false
    forwardable = true
[realms]
    A.TEST = {
        kdc = 127.0.0.1:88
    }
    B.TEST = {
        kdc = 127.0.0.1:89
    }
    C.TEST = {
        kdc = 127.0.0.1:90
    }
    GARBAGE.EXAMPLE = {
        kdc = 127.0.0.1:90
    }
EOF
CONF

setup_mit_realm() {
    local realm="$1" profile="$2"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_KDC_PROFILE="$profile" \
        "$NAME" kdb5_util -r "$realm" create -s -P masterpassword >/dev/null
}

echo "==== MIT kdb5_util A/B/C ===="
setup_mit_realm A.TEST /tmp/kdc-A.conf
setup_mit_realm B.TEST /tmp/kdc-B.conf
setup_mit_realm C.TEST /tmp/kdc-C.conf

docker exec -i -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" bash -s <<EOF
set -euo pipefail
kad() {
    local profile="\$1"
    local realm="\$2"
    shift 2
    KRB5_KDC_PROFILE="\$profile" kadmin.local -r "\$realm" -q "\$*"
}
kad /tmp/kdc-A.conf A.TEST "addprinc -pw userpassword user"
kad /tmp/kdc-A.conf A.TEST "addprinc -randkey host/svc.a.test"
kad /tmp/kdc-A.conf A.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/B.TEST@A.TEST"
kad /tmp/kdc-B.conf B.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/B.TEST@A.TEST"
kad /tmp/kdc-B.conf B.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/C.TEST@B.TEST"
kad /tmp/kdc-C.conf C.TEST "addprinc -e aes256-cts-hmac-sha1-96:normal -pw ${XR_PW} krbtgt/C.TEST@B.TEST"
kad /tmp/kdc-C.conf C.TEST "addprinc -randkey user"
kad /tmp/kdc-C.conf C.TEST "addprinc -randkey host/svc.c.test"
kad /tmp/kdc-C.conf C.TEST "ktadd -k /tmp/mit-c.host.kt host/svc.c.test"
EOF

start_mit() {
    local realm="$1" profile="$2" log="$3" pidf="$4"
    docker exec \
        -e KRB5_CONFIG=/tmp/client-capaths.conf \
        -e KRB5_KDC_PROFILE="$profile" \
        "$NAME" sh -c "krb5kdc -n -r ${realm} >${log} 2>&1 & echo \$! >${pidf}"
}

wait_port() {
    local port="$1"
    local i
    for i in $(seq 1 80); do
        if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',${port}),0.3)" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

echo "==== MIT krb5kdc A/B/C ===="
start_mit A.TEST /tmp/kdc-A.conf /tmp/mit-a.log /tmp/mit-a.pid
start_mit B.TEST /tmp/kdc-B.conf /tmp/mit-b.log /tmp/mit-b.pid
start_mit C.TEST /tmp/kdc-C.conf /tmp/mit-c.log /tmp/mit-c.pid
wait_port 88
wait_port 89
wait_port 90 || {
    echo "==== MIT KDC logs ===="
    docker exec "$NAME" sh -c 'cat /tmp/mit-a.log /tmp/mit-b.log /tmp/mit-c.log' || true
    log "capaths.gate" "error" ',"error":"MIT KDCs did not listen"'
    exit 1
}

chase() {
    local cc="$1"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        sh -c "printf 'userpassword\n' | kinit -c ${cc} user@A.TEST"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
        kvno -c "$cc" host/svc.c.test@C.TEST
}

kinit_a() {
    local cc="$1"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        sh -c "printf 'userpassword\n' | kinit -c ${cc} user@A.TEST" >/dev/null
}

# Cache krbtgt/C.TEST via MIT kvno so rust kvno can TGS the dest hop.
seed_c_tgt() {
    local cc="$1"
    kinit_a "$cc"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        kvno -c "$cc" krbtgt/C.TEST@C.TEST >/dev/null
}

# MIT kvno cannot set DISABLE-TRANSITED-CHECK (bit 26).
skip_kvno() {
    local cc="$1"
    local svc="$2"
    docker exec \
        -e KRB5_CONFIG=/tmp/client-capaths.conf \
        "$NAME" /tmp/krb5-kvno --disable-transited-check -c "$cc" "$svc"
}

expect_skip_policy() {
    local label="$1"
    local cc="$2"
    local svc="$3"
    local klog="$4"
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(skip_kvno "$cc" "$svc" 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -eq 0 ]; then
        echo "$label: skip must be POLICY, got success" >&2
        exit 1
    fi
    echo "$out" | grep -q 'KDC policy rejects request'
    if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog} | grep -q BAD_TRANSIT"; then
        echo "$label: new lines of ${klog} missing BAD_TRANSIT" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$label new ${klog} lines (from $((n + 1))):"
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" || true
}

expect_forge_reject() {
    local label="$1"
    local cc="$2"
    local klog="$3"
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        kvno -c "$cc" host/svc.c.test@C.TEST 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -eq 0 ]; then
        echo "$label: forged ticket.realm must not issue" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog} | grep -q PROCESS_TGS"; then
        echo "$label: new lines of ${klog} missing PROCESS_TGS" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$label new ${klog} lines (from $((n + 1))):"
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" || true
}

forge_mit_tgt() {
    local in_cc="$1"
    local out_cc="$2"
    local claimed="$3"
    docker exec "$NAME" /tmp/krb5-forge-tgt \
        --ccache "$in_cc" --out "$out_cc" --claim-realm "$claimed" \
        --tgt krbtgt/C.TEST \
        --password "${XR_PW}" --principal 'krbtgt/C.TEST@B.TEST'
}

forge_mit_lineage() {
    local in_cc="$1"
    local out_cc="$2"
    docker exec "$NAME" /tmp/krb5-forge-tgt \
        --ccache "$in_cc" --out "$out_cc" --claim-realm B.TEST \
        --claim-crealm C.TEST \
        --tgt krbtgt/C.TEST \
        --password "${XR_PW}" --principal 'krbtgt/C.TEST@B.TEST'
}

forge_rust_tgt() {
    local in_cc="$1"
    local out_cc="$2"
    local claimed="$3"
    docker exec "$NAME" /tmp/krb5-forge-tgt \
        --ccache "$in_cc" --out "$out_cc" --claim-realm "$claimed" \
        --tgt krbtgt/C.TEST \
        --key-hex "${XR_KEY}"
}

forge_rust_lineage() {
    local in_cc="$1"
    local out_cc="$2"
    docker exec "$NAME" /tmp/krb5-forge-tgt \
        --ccache "$in_cc" --out "$out_cc" --claim-realm B.TEST \
        --claim-crealm C.TEST \
        --tgt krbtgt/C.TEST \
        --key-hex "${XR_KEY}"
}

expect_get_local_tgt() {
    local label="$1"
    local cc="$2"
    local klog="$3"
    docker exec "$NAME" /tmp/krb5-forge-tgt \
        --ccache "$cc" --out "${cc}_garbage" --tgt krbtgt/C.TEST \
        --alias-as 'krbtgt/C.TEST@B.TEST'
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(docker exec -e KRB5_CONFIG=/tmp/client-garbage.conf "$NAME" \
        /tmp/krb5-kvno --body-realm GARBAGE.EXAMPLE -c "${cc}_garbage" 127.0.0.1:90 host/svc.c.test@GARBAGE.EXAMPLE 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -eq 0 ]; then
        echo "$label: GARBAGE.EXAMPLE must not issue" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog} | grep -q GET_LOCAL_TGT"; then
        echo "$label: new lines of ${klog} missing GET_LOCAL_TGT" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$label new ${klog} lines (from $((n + 1))):"
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" || true
}

seed_c_tgt_renewable() {
    local cc="$1"
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        sh -c "printf 'userpassword\n' | kinit -r 7d -c ${cc} user@A.TEST" >/dev/null
    docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        kvno -c "$cc" krbtgt/C.TEST@C.TEST >/dev/null
}

expect_lineage() {
    local label="$1"
    local cc="$2"
    local klog="$3"
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        /tmp/krb5-kvno --body-realm C.TEST -c "$cc" 127.0.0.1:90 host/svc.c.test@C.TEST 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -eq 0 ]; then
        echo "$label: lineage must not issue" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog} | grep -q 'INVALID LINEAGE'"; then
        echo "$label: new lines of ${klog} missing INVALID LINEAGE" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$label new ${klog} lines (from $((n + 1))):"
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" || true
}

expect_s4u_mismatch() {
    local label="$1"
    local cc="$2"
    local klog="$3"
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        /tmp/krb5-kvno -U victim@A.TEST -c "$cc" 127.0.0.1:90 user@C.TEST 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -eq 0 ]; then
        echo "$label: S4U2Self name-collision must not issue" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$out" | grep -qiE "Ticket/authenticator don't match|BADMATCH|INVALID_S4U2SELF"
    if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog} | grep -q 'INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH'"; then
        echo "$label: new lines of ${klog} missing INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$label new ${klog} lines (from $((n + 1))):"
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" || true
}

expect_dest_renew_get_local_tgt() {
    local label="$1"
    local cc="$2"
    local klog="$3"
    local n
    n="$(docker exec "$NAME" sh -c "wc -l < ${klog}" | tr -d '[:space:]')"
    set +e
    local out rc
    out="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
        /tmp/krb5-kvno --renew --body-realm B.TEST -c "$cc" 127.0.0.1:90 krbtgt/C.TEST@C.TEST 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -eq 0 ]; then
        echo "$label: dest RENEW with issuer body.realm must not issue" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog} | grep -q GET_LOCAL_TGT"; then
        echo "$label: new lines of ${klog} missing GET_LOCAL_TGT" >&2
        docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" >&2 || true
        exit 1
    fi
    echo "$label new ${klog} lines (from $((n + 1))):"
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) ${klog}" || true
}

expect_skip_accept_t0() {
    local label="$1"
    local cc="$2"
    local svc="$3"
    local kt="$4"
    set +e
    local out rc
    out="$(skip_kvno "$cc" "$svc" 2>&1)"
    rc=$?
    set -e
    echo "$out"
    if [ "$rc" -ne 0 ]; then
        echo "$label: skip + reject_bad_transit=false must succeed" >&2
        exit 1
    fi
    echo "$out" | grep -q "${svc}: kvno ="
    local dump
    dump="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab "$kt" --ccache "$cc" --print-transited)"
    echo "$dump"
    echo "$dump" | grep -q '^transited_policy_checked=0$'
}

echo "==== MIT kvno vs MIT KDCs (permitted) ===="
set +e
MIT_CHASE="$(chase /tmp/krb5cc_mit 2>&1)"
mit_rc=$?
set -e
echo "$MIT_CHASE"
if [ "$mit_rc" -ne 0 ]; then
    docker exec "$NAME" sh -c 'cat /tmp/mit-a.log /tmp/mit-b.log /tmp/mit-c.log' || true
    log "capaths.gate" "error" ',"error":"MIT KDC 3-hop kvno failed","rc":'"$mit_rc"
    exit 1
fi
echo "$MIT_CHASE" | grep -q 'host/svc.c.test@C.TEST: kvno ='
MIT_FLAGS="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -f -c /tmp/krb5cc_mit)"
echo "$MIT_FLAGS"
echo "$MIT_FLAGS" | awk '/host\/svc.c.test/{p=1;next} p&&/Flags:/{print;exit}' | grep -q T
MIT_DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/mit-c.host.kt --ccache /tmp/krb5cc_mit --print-transited)"
echo "$MIT_DUMP"
echo "$MIT_DUMP" | grep -q '^transited_policy_checked=1$'
MIT_TR_TYPE="$(echo "$MIT_DUMP" | sed -n 's/^transited_tr_type=//p')"
MIT_TR_CONTENTS="$(echo "$MIT_DUMP" | sed -n 's/^transited_contents=//p')"
test "$MIT_TR_TYPE" = "1"
test "$MIT_TR_CONTENTS" = "B.TEST"

echo "==== Rust kvno bare A TGT chases MIT A/B/C ===="
kinit_a /tmp/krb5cc_rust_bare
na="$(docker exec "$NAME" sh -c 'wc -l < /tmp/mit-a.log' | tr -d '[:space:]')"
nb="$(docker exec "$NAME" sh -c 'wc -l < /tmp/mit-b.log' | tr -d '[:space:]')"
nc="$(docker exec "$NAME" sh -c 'wc -l < /tmp/mit-c.log' | tr -d '[:space:]')"
set +e
BARE="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    /tmp/krb5-kvno -c /tmp/krb5cc_rust_bare host/svc.c.test@C.TEST 2>&1)"
bare_rc=$?
set -e
echo "$BARE"
if [ "$bare_rc" -ne 0 ]; then
    echo "bare A TGT rust kvno must chase MIT A/B/C" >&2
    docker exec "$NAME" sh -c "tail -n +$((na + 1)) /tmp/mit-a.log; tail -n +$((nb + 1)) /tmp/mit-b.log; tail -n +$((nc + 1)) /tmp/mit-c.log" >&2 || true
    log "capaths.gate" "error" ',"error":"bare A TGT rust kvno failed","rc":'"$bare_rc"
    exit 1
fi
echo "$BARE" | grep -q 'host/svc.c.test@C.TEST: kvno ='
if ! docker exec "$NAME" sh -c "tail -n +$((na + 1)) /tmp/mit-a.log | grep -q 'krbtgt/B.TEST'"; then
    echo "bare chase: MIT A new lines missing krbtgt/B.TEST" >&2
    docker exec "$NAME" sh -c "tail -n +$((na + 1)) /tmp/mit-a.log" >&2 || true
    exit 1
fi
if ! docker exec "$NAME" sh -c "tail -n +$((nb + 1)) /tmp/mit-b.log | grep -q 'krbtgt/C.TEST'"; then
    echo "bare chase: MIT B new lines missing krbtgt/C.TEST" >&2
    docker exec "$NAME" sh -c "tail -n +$((nb + 1)) /tmp/mit-b.log" >&2 || true
    exit 1
fi
if ! docker exec "$NAME" sh -c "tail -n +$((nc + 1)) /tmp/mit-c.log | grep -q 'host/svc.c.test'"; then
    echo "bare chase: MIT C new lines missing host/svc.c.test" >&2
    docker exec "$NAME" sh -c "tail -n +$((nc + 1)) /tmp/mit-c.log" >&2 || true
    exit 1
fi
if docker exec "$NAME" sh -c "tail -n +$((na + 1)) /tmp/mit-a.log | grep -q GET_LOCAL_TGT"; then
    echo "bare chase: MIT A must not GET_LOCAL_TGT (foreign body.realm)" >&2
    docker exec "$NAME" sh -c "tail -n +$((na + 1)) /tmp/mit-a.log" >&2 || true
    exit 1
fi
echo "==== path-TGT cache equals MIT kvno ===="
MITKL="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -c /tmp/krb5cc_mit)"
RUSTKL="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -c /tmp/krb5cc_rust_bare)"
echo "$MITKL"
echo "$RUSTKL"
echo "$MITKL" | grep -q 'krbtgt/C.TEST@B.TEST'
echo "$RUSTKL" | grep -q 'krbtgt/C.TEST@B.TEST'
if echo "$MITKL" | grep -q 'krbtgt/B.TEST@A.TEST'; then
    echo "MIT cached unasked B TGT" >&2
    exit 1
fi
if echo "$RUSTKL" | grep -q 'krbtgt/B.TEST@A.TEST'; then
    echo "Rust cached unasked B TGT" >&2
    exit 1
fi

echo "==== MIT C rejects forged ticket.realm on B-sealed TGT ===="
seed_c_tgt /tmp/krb5cc_mit_forge
forge_mit_tgt /tmp/krb5cc_mit_forge /tmp/krb5cc_mit_forge_a A.TEST
expect_forge_reject "MIT forge A.TEST" /tmp/krb5cc_mit_forge_a /tmp/mit-c.log
forge_mit_tgt /tmp/krb5cc_mit_forge /tmp/krb5cc_mit_forge_c C.TEST
expect_forge_reject "MIT forge C.TEST" /tmp/krb5cc_mit_forge_c /tmp/mit-c.log

echo "==== MIT C GARBAGE.EXAMPLE local sname is GET_LOCAL_TGT ===="
seed_c_tgt /tmp/krb5cc_mit_garbage
expect_get_local_tgt "MIT GARBAGE.EXAMPLE" /tmp/krb5cc_mit_garbage /tmp/mit-c.log

echo "==== MIT dest RENEW with issuer body.realm is GET_LOCAL_TGT ===="
seed_c_tgt_renewable /tmp/krb5cc_mit_renew
expect_dest_renew_get_local_tgt "MIT dest RENEW issuer realm" /tmp/krb5cc_mit_renew /tmp/mit-c.log

echo "==== MIT C lineage local user on foreign TGT is INVALID LINEAGE ===="
seed_c_tgt /tmp/krb5cc_mit_lineage
forge_mit_lineage /tmp/krb5cc_mit_lineage /tmp/krb5cc_mit_lineage_out
expect_lineage "MIT lineage" /tmp/krb5cc_mit_lineage_out /tmp/mit-c.log

echo "==== MIT C S4U2Self foreign user named like local server is BADMATCH ===="
seed_c_tgt /tmp/krb5cc_mit_s4u
expect_s4u_mismatch "MIT S4U mismatch" /tmp/krb5cc_mit_s4u /tmp/mit-c.log

echo "==== MIT C DISALLOW_ALL_TIX on inbound krbtgt is PROCESS_TGS ===="
seed_c_tgt /tmp/krb5cc_mit_disallow
docker exec \
    -e KRB5_CONFIG=/tmp/client-capaths.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C.conf \
    "$NAME" kadmin.local -r C.TEST -q "modprinc -allow_tix krbtgt/C.TEST@B.TEST"
n="$(docker exec "$NAME" sh -c 'wc -l < /tmp/mit-c.log' | tr -d '[:space:]')"
set +e
MITDIS="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    kvno -c /tmp/krb5cc_mit_disallow host/svc.c.test@C.TEST 2>&1)"
mitdis_rc=$?
set -e
echo "$MITDIS"
if [ "$mitdis_rc" -eq 0 ]; then
    echo "MIT disallow krbtgt must not issue" >&2
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/mit-c.log" >&2 || true
    exit 1
fi
echo "$MITDIS" | grep -qiE "not found in Kerberos database|PROCESS_TGS"
if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/mit-c.log | grep -q PROCESS_TGS"; then
    echo "MIT disallow: new mit-c.log lines missing PROCESS_TGS" >&2
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/mit-c.log" >&2 || true
    exit 1
fi
docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/mit-c.log" || true
docker exec \
    -e KRB5_CONFIG=/tmp/client-capaths.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C.conf \
    "$NAME" kadmin.local -r C.TEST -q "modprinc +allow_tix krbtgt/C.TEST@B.TEST"

echo "==== MIT skip same-realm default is POLICY ===="
kinit_a /tmp/krb5cc_mit_skip_a
expect_skip_policy "MIT A skip" /tmp/krb5cc_mit_skip_a host/svc.a.test@A.TEST /tmp/mit-a.log

echo "==== MIT skip capaths-permitted default is POLICY ===="
seed_c_tgt /tmp/krb5cc_mit_skip_d
expect_skip_policy "MIT C skip" /tmp/krb5cc_mit_skip_d host/svc.c.test@C.TEST /tmp/mit-c.log
docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    klist -c /tmp/krb5cc_mit_skip_d | grep -q 'krbtgt/C.TEST@B.TEST'

echo "==== MIT C without [capaths] rejects ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/mit-c.pid)" 2>/dev/null || true'
for _ in $(seq 1 20); do
    if docker exec "$NAME" python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', 90), 0.15)
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
docker exec \
    -e KRB5_CONFIG=/tmp/kdc-c-deny.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C.conf \
    "$NAME" sh -c "krb5kdc -n -r C.TEST >/tmp/mit-c-deny.log 2>&1 & echo \$! >/tmp/mit-c.pid"
wait_port 90 || {
    docker exec "$NAME" cat /tmp/mit-c-deny.log 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"MIT deny C did not listen"'
    exit 1
}
docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_mit_deny user@A.TEST" >/dev/null
set +e
MIT_DENY="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    kvno -c /tmp/krb5cc_mit_deny host/svc.c.test@C.TEST 2>&1)"
mit_drc=$?
set -e
echo "$MIT_DENY"
test "$mit_drc" -ne 0
# Live MIT 1.22.2 prints POLICY ("rejects request") on this deny.
echo "$MIT_DENY" | grep -q 'KDC policy rejects request'

echo "==== MIT C reject_bad_transit=false accepts without T ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/mit-c.pid)" 2>/dev/null || true'
for _ in $(seq 1 20); do
    if docker exec "$NAME" python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', 90), 0.15)
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
docker exec \
    -e KRB5_CONFIG=/tmp/kdc-c-deny.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C-lax.conf \
    "$NAME" sh -c "krb5kdc -n -r C.TEST >/tmp/mit-c-lax.log 2>&1 & echo \$! >/tmp/mit-c.pid"
wait_port 90 || {
    docker exec "$NAME" cat /tmp/mit-c-lax.log 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"MIT lax C did not listen"'
    exit 1
}
docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_mit_lax user@A.TEST" >/dev/null
set +e
MIT_LAX="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    kvno -c /tmp/krb5cc_mit_lax host/svc.c.test@C.TEST 2>&1)"
mit_lax_rc=$?
set -e
echo "$MIT_LAX"
test "$mit_lax_rc" -eq 0
echo "$MIT_LAX" | grep -q 'host/svc.c.test@C.TEST: kvno ='
MIT_LAX_FLAGS="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -f -c /tmp/krb5cc_mit_lax)"
echo "$MIT_LAX_FLAGS"
MIT_LAX_FL="$(echo "$MIT_LAX_FLAGS" | awk '/host\/svc.c.test/{p=1;next} p&&/Flags:/{print;exit}')"
echo "lax_host_flags=$MIT_LAX_FL"
echo "$MIT_LAX_FL" | grep -q T && {
    echo "reject_bad_transit=false must not set T" >&2
    exit 1
}
MIT_LAX_DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/mit-c.host.kt --ccache /tmp/krb5cc_mit_lax --print-transited)"
echo "$MIT_LAX_DUMP"
echo "$MIT_LAX_DUMP" | grep -q '^transited_policy_checked=0$'

echo "==== MIT C capaths + reject_bad_transit=false skip accepts without T ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/mit-c.pid)" 2>/dev/null || true'
for _ in $(seq 1 20); do
    if docker exec "$NAME" python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', 90), 0.15)
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
docker exec \
    -e KRB5_CONFIG=/tmp/client-capaths.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C-lax.conf \
    "$NAME" sh -c "krb5kdc -n -r C.TEST >/tmp/mit-c-skip-lax.log 2>&1 & echo \$! >/tmp/mit-c.pid"
wait_port 90 || {
    docker exec "$NAME" cat /tmp/mit-c-skip-lax.log 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"MIT skip-lax C did not listen"'
    exit 1
}
seed_c_tgt /tmp/krb5cc_mit_skip_b
expect_skip_accept_t0 "MIT skip lax" /tmp/krb5cc_mit_skip_b host/svc.c.test@C.TEST /tmp/mit-c.host.kt

echo "==== stop MIT KDCs ===="
docker exec "$NAME" sh -c 'kill -9 $(cat /tmp/mit-a.pid /tmp/mit-b.pid /tmp/mit-c.pid 2>/dev/null) 2>/dev/null || true'
for _ in $(seq 1 20); do
    if docker exec "$NAME" python3 -c "
import socket
for p in (88, 89, 90):
    try:
        s = socket.create_connection(('127.0.0.1', p), 0.15)
        s.close()
        raise SystemExit(0)
    except OSError:
        pass
raise SystemExit(1)
" 2>/dev/null; then
        sleep 0.25
        continue
    fi
    break
done

start_ab() {
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=A.TEST \
        -e KRB5_TEST_FOREIGN_REALM=B.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.a.test \
        "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc-a.log 2>&1'
    docker exec -d \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=B.TEST \
        -e KRB5_TEST_FOREIGN_REALM=A.TEST,C.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.b.test \
        "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:89 >/tmp/kdc-b.log 2>&1'
}

start_c() {
    local conf="$1"
    local log="$2"
    docker exec \
        -e KRB5_CONFIG="$conf" \
        -e KRB5_TEST_USER_PASSWORD=userpassword \
        -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
        -e KRB5_TEST_REALM=C.TEST \
        -e KRB5_TEST_FOREIGN_REALM=B.TEST \
        -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
        -e KRB5_TEST_HOST=svc.c.test \
        -e KRB5_EXPORT_KEYTAB=/tmp/rust-c.host.kt \
        -e KRB5_TEST_DISALLOW_TIX="${KRB5_TEST_DISALLOW_TIX:-}" \
        -e KRB5_TEST_DISALLOW_SVR="${KRB5_TEST_DISALLOW_SVR:-}" \
        "$NAME" sh -c "/tmp/krb5-kdc --test-realm 127.0.0.1:90 >$log 2>&1 & echo \$! >/tmp/kdc-c.pid"
}

wait_listen() {
    local log="$1"
    local i
    for i in $(seq 1 80); do
        if docker exec "$NAME" grep -q '^listening ' "$log" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

start_ab
start_c /tmp/kdc-c-allow.conf /tmp/kdc-c-allow.log
wait_listen /tmp/kdc-a.log
wait_listen /tmp/kdc-b.log
wait_listen /tmp/kdc-c-allow.log
echo "==== KDC A ===="
docker exec "$NAME" cat /tmp/kdc-a.log 2>/dev/null || true
echo "==== KDC B ===="
docker exec "$NAME" cat /tmp/kdc-b.log 2>/dev/null || true
echo "==== KDC C allow ===="
docker exec "$NAME" cat /tmp/kdc-c-allow.log 2>/dev/null || true

echo "==== MIT kvno vs Rust KDCs (permitted) ===="
set +e
RUST_CHASE="$(chase /tmp/krb5cc_rust 2>&1)"
rc=$?
set -e
echo "$RUST_CHASE"
if [ "$rc" -ne 0 ]; then
    log "capaths.gate" "error" ',"error":"permitted path kvno failed","rc":'"$rc"
    exit 1
fi
echo "$RUST_CHASE" | grep -q 'host/svc.c.test@C.TEST: kvno ='
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" klist -f -c /tmp/krb5cc_rust 2>/dev/null || true)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@A.TEST'
echo "$KLIST" | grep -q 'krbtgt/B.TEST'
echo "$KLIST" | grep -q 'krbtgt/C.TEST'
echo "$KLIST" | grep -q 'host/svc.c.test'
echo "$KLIST" | awk '/host\/svc.c.test/{p=1;next} p&&/Flags:/{print;exit}' | grep -q T
RUST_DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/rust-c.host.kt --ccache /tmp/krb5cc_rust --print-transited)"
echo "$RUST_DUMP"
echo "$RUST_DUMP" | grep -q '^transited_policy_checked=1$'
RUST_TR_TYPE="$(echo "$RUST_DUMP" | sed -n 's/^transited_tr_type=//p')"
RUST_TR_CONTENTS="$(echo "$RUST_DUMP" | sed -n 's/^transited_contents=//p')"

echo "==== MIT vs Rust transited field ===="
echo "mit  tr_type=${MIT_TR_TYPE} contents=${MIT_TR_CONTENTS}"
echo "rust tr_type=${RUST_TR_TYPE} contents=${RUST_TR_CONTENTS}"
test "$MIT_TR_TYPE" = "$RUST_TR_TYPE"
test "$MIT_TR_CONTENTS" = "$RUST_TR_CONTENTS"

echo "==== Rust C rejects forged ticket.realm on B-sealed TGT ===="
seed_c_tgt /tmp/krb5cc_rust_forge
forge_rust_tgt /tmp/krb5cc_rust_forge /tmp/krb5cc_rust_forge_a A.TEST
expect_forge_reject "Rust forge A.TEST" /tmp/krb5cc_rust_forge_a /tmp/kdc-c-allow.log
forge_rust_tgt /tmp/krb5cc_rust_forge /tmp/krb5cc_rust_forge_c C.TEST
expect_forge_reject "Rust forge C.TEST" /tmp/krb5cc_rust_forge_c /tmp/kdc-c-allow.log

echo "==== Rust C GARBAGE.EXAMPLE local sname is GET_LOCAL_TGT ===="
seed_c_tgt /tmp/krb5cc_rust_garbage
expect_get_local_tgt "Rust GARBAGE.EXAMPLE" /tmp/krb5cc_rust_garbage /tmp/kdc-c-allow.log

echo "==== Rust dest RENEW with issuer body.realm is GET_LOCAL_TGT ===="
seed_c_tgt_renewable /tmp/krb5cc_rust_renew
expect_dest_renew_get_local_tgt "Rust dest RENEW issuer realm" /tmp/krb5cc_rust_renew /tmp/kdc-c-allow.log

echo "==== Rust C lineage local user on foreign TGT is INVALID LINEAGE ===="
seed_c_tgt /tmp/krb5cc_rust_lineage
forge_rust_lineage /tmp/krb5cc_rust_lineage /tmp/krb5cc_rust_lineage_out
expect_lineage "Rust lineage" /tmp/krb5cc_rust_lineage_out /tmp/kdc-c-allow.log

echo "==== Rust C S4U2Self foreign user named like local server is BADMATCH ===="
seed_c_tgt /tmp/krb5cc_rust_s4u
expect_s4u_mismatch "Rust S4U mismatch" /tmp/krb5cc_rust_s4u /tmp/kdc-c-allow.log

echo "==== Rust C DISALLOW_ALL_TIX on inbound krbtgt is PROCESS_TGS ===="
seed_c_tgt /tmp/krb5cc_rust_disallow
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',90),0.15)" 2>/dev/null; then
        sleep 0.2
        continue
    fi
    ok=1
    break
done
[ "$ok" = 1 ]
KRB5_TEST_DISALLOW_TIX=krbtgt/B.TEST start_c /tmp/kdc-c-allow.conf /tmp/kdc-c-disallow.log
if ! wait_listen /tmp/kdc-c-disallow.log; then
    docker exec "$NAME" cat /tmp/kdc-c-disallow.log >&2 || true
    log "capaths.gate" "error" ',"error":"disallow KDC C did not listen"'
    exit 1
fi
n="$(docker exec "$NAME" sh -c 'wc -l < /tmp/kdc-c-disallow.log' | tr -d '[:space:]')"
set +e
RUSTDIS="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    kvno -c /tmp/krb5cc_rust_disallow host/svc.c.test@C.TEST 2>&1)"
rustdis_rc=$?
set -e
echo "$RUSTDIS"
if [ "$rustdis_rc" -eq 0 ]; then
    echo "Rust disallow krbtgt must not issue" >&2
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/kdc-c-disallow.log" >&2 || true
    exit 1
fi
echo "$RUSTDIS" | grep -qiE "not found in Kerberos database|PROCESS_TGS"
if ! docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/kdc-c-disallow.log | grep -q PROCESS_TGS"; then
    echo "Rust disallow: new kdc-c-disallow.log lines missing PROCESS_TGS" >&2
    docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/kdc-c-disallow.log" >&2 || true
    exit 1
fi
docker exec "$NAME" sh -c "tail -n +$((n + 1)) /tmp/kdc-c-disallow.log" || true
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',90),0.15)" 2>/dev/null; then
        sleep 0.2
        continue
    fi
    ok=1
    break
done
[ "$ok" = 1 ]
unset KRB5_TEST_DISALLOW_TIX
start_c /tmp/kdc-c-allow.conf /tmp/kdc-c-allow.log
if ! wait_listen /tmp/kdc-c-allow.log; then
    docker exec "$NAME" cat /tmp/kdc-c-allow.log >&2 || true
    log "capaths.gate" "error" ',"error":"restored KDC C did not listen"'
    exit 1
fi

echo "==== Rust skip same-realm default is POLICY ===="
kinit_a /tmp/krb5cc_rust_skip_a
expect_skip_policy "Rust A skip" /tmp/krb5cc_rust_skip_a host/svc.a.test@A.TEST /tmp/kdc-a.log

echo "==== Rust skip capaths-permitted default is POLICY ===="
seed_c_tgt /tmp/krb5cc_rust_skip_d
expect_skip_policy "Rust C skip" /tmp/krb5cc_rust_skip_d host/svc.c.test@C.TEST /tmp/kdc-c-allow.log
docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    klist -c /tmp/krb5cc_rust_skip_d | grep -q 'krbtgt/C.TEST@B.TEST'

echo "==== restart C without capaths (rejected path) ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
sleep 1
start_c /tmp/kdc-c-deny.conf /tmp/kdc-c-deny.log
if ! wait_listen /tmp/kdc-c-deny.log; then
    echo "==== KDC C deny (did not listen) ===="
    docker exec "$NAME" cat /tmp/kdc-c-deny.log 2>/dev/null || true
    docker exec "$NAME" cat /tmp/kdc-c.pid 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"deny KDC C did not listen"'
    exit 1
fi
echo "==== KDC C deny ===="
docker exec "$NAME" cat /tmp/kdc-c-deny.log 2>/dev/null || true

docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_deny user@A.TEST" >/dev/null
set +e
DENY="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno -c /tmp/krb5cc_deny host/svc.c.test@C.TEST 2>&1)"
drc=$?
set -e
echo "$DENY"
test "$drc" -ne 0
echo "$DENY" | grep -q 'KDC policy rejects request'

echo "==== Rust C reject_bad_transit=false accepts without T ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
sleep 1
docker exec \
    -e KRB5_CONFIG=/tmp/kdc-c-deny.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C-lax.conf \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_REALM=C.TEST \
    -e KRB5_TEST_FOREIGN_REALM=B.TEST \
    -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
    -e KRB5_TEST_HOST=svc.c.test \
    -e KRB5_EXPORT_KEYTAB=/tmp/rust-c-lax.kt \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:90 >/tmp/kdc-c-lax.log 2>&1 & echo $! >/tmp/kdc-c.pid'
wait_listen /tmp/kdc-c-lax.log || {
    docker exec "$NAME" cat /tmp/kdc-c-lax.log 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"Rust lax C did not listen"'
    exit 1
}
docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    sh -c "printf 'userpassword\n' | kinit -c /tmp/krb5cc_rust_lax user@A.TEST" >/dev/null
set +e
RUST_LAX="$(docker exec -e KRB5_CONFIG=/tmp/client-capaths.conf "$NAME" \
    kvno -c /tmp/krb5cc_rust_lax host/svc.c.test@C.TEST 2>&1)"
rust_lax_rc=$?
set -e
echo "$RUST_LAX"
test "$rust_lax_rc" -eq 0
echo "$RUST_LAX" | grep -q 'host/svc.c.test@C.TEST: kvno ='
RUST_LAX_DUMP="$(docker exec "$NAME" /tmp/krb5-pac-extract --keytab /tmp/rust-c-lax.kt --ccache /tmp/krb5cc_rust_lax --print-transited)"
echo "$RUST_LAX_DUMP"
echo "$RUST_LAX_DUMP" | grep -q '^transited_policy_checked=0$'

echo "==== Rust C capaths + reject_bad_transit=false skip accepts without T ===="
docker exec "$NAME" sh -c 'kill -9 "$(cat /tmp/kdc-c.pid)" 2>/dev/null || true'
sleep 1
docker exec \
    -e KRB5_CONFIG=/tmp/kdc-c-allow.conf \
    -e KRB5_KDC_PROFILE=/tmp/kdc-C-lax.conf \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_REALM=C.TEST \
    -e KRB5_TEST_FOREIGN_REALM=B.TEST \
    -e KRB5_TEST_INTERREALM_KEY="$XR_KEY" \
    -e KRB5_TEST_HOST=svc.c.test \
    -e KRB5_EXPORT_KEYTAB=/tmp/rust-c-skip-lax.kt \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:90 >/tmp/kdc-c-skip-lax.log 2>&1 & echo $! >/tmp/kdc-c.pid'
wait_listen /tmp/kdc-c-skip-lax.log || {
    docker exec "$NAME" cat /tmp/kdc-c-skip-lax.log 2>/dev/null || true
    log "capaths.gate" "error" ',"error":"Rust skip-lax C did not listen"'
    exit 1
}
seed_c_tgt /tmp/krb5cc_rust_skip_b
expect_skip_accept_t0 "Rust skip lax" /tmp/krb5cc_rust_skip_b host/svc.c.test@C.TEST /tmp/rust-c-skip-lax.kt

log "capaths.gate" "ok" \
    ",\"path\":\"A.TEST>B.TEST>C.TEST\",\"permitted\":true,\"rejected\":true,\"transited_tr_type\":${MIT_TR_TYPE},\"transited_contents\":\"${MIT_TR_CONTENTS}\",\"transited_policy_checked\":true,\"reject_bad_transit_false\":true,\"disable_transited_check\":true"
exit 0
