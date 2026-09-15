#!/usr/bin/env bash
# MIT kprop as an unauthorized GSS peer is refused by Rust kpropd; host
# sender still loads. Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc krb5-kpropd krb5-kadmind

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-prop-acl-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-prop-acl-gate}"
mkdir -p "$SCRATCH"

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

need_image

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
register_cleanup 'docker rm -f "$NAME" >/dev/null 2>&1 || true'

if ! docker exec "$NAME" sh -c 'command -v kprop >/dev/null'; then
    log "propacl.gate" "error" ',"error":"kprop binary missing"'
    exit 2
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpropd" "$NAME":/tmp/krb5-kpropd
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kpropd /tmp/krb5-kadmind

docker exec "$NAME" sh -c 'cat >/tmp/prop-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_propacl
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
docker exec "$NAME" sh -c 'printf "" >/tmp/kpropd.acl.empty'
docker exec "$NAME" sh -c "printf 'host/localhost@KERBER.TEST\\nhost/${HN}@KERBER.TEST\\n' >/tmp/kpropd.acl"

echo "==== MIT krb5kdc ===="
kill_comm krb5kdc
kill_comm krb5-kdc
docker exec "$NAME" sh -c 'krb5kdc; sleep 0.4' >/dev/null 2>&1 || true
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "propacl.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi

echo "==== Rust kpropd unset ACL (deny even host/ peers) ===="
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
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
    log "propacl.gate" "error" ',"error":"kpropd (unset ACL) did not listen"'
    exit 1
fi

echo "==== unauthorized MIT kprop (ACL unset) ===="
UNSET="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$UNSET"
UNSET_LOG="$(docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true)"
echo "$UNSET_LOG"
if echo "$UNSET" | grep -q 'SUCCEEDED'; then
    echo "unset-ACL kprop succeeded" >&2
    exit 1
fi
# kpropd.c:540-543 syslog text (the Rust kpropd prints the same line).
echo "$UNSET_LOG" | grep -F "Rejected connection from unauthorized principal host/${HN}@KERBER.TEST"
if docker exec "$NAME" test -f /tmp/replica; then
    echo "unset-ACL kprop wrote a replica dump" >&2
    exit 1
fi

echo "==== Rust kpropd empty ACL (deny all MIT GSS peers) ===="
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    -e KRB5_KPROP_ACL=/tmp/kpropd.acl.empty \
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
    log "propacl.gate" "error" ',"error":"kpropd did not listen"'
    exit 1
fi

echo "==== unauthorized MIT kprop (empty allowlist) ===="
BAD="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$BAD"
KPD="$(docker exec "$NAME" cat /tmp/kpropd.log 2>/dev/null || true)"
echo "$KPD"
if echo "$BAD" | grep -q 'SUCCEEDED'; then
    echo "empty-ACL kprop succeeded" >&2
    exit 1
fi
echo "$KPD" | grep -F "Rejected connection from unauthorized principal host/${HN}@KERBER.TEST"
if docker exec "$NAME" test -f /tmp/replica; then
    echo "unauthorized kprop wrote a replica dump" >&2
    exit 1
fi

echo "==== Rust kpropd with host allowlist ===="
kill_comm krb5-kpropd
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
    log "propacl.gate" "error" ',"error":"kpropd (allowlist) did not listen"'
    exit 1
fi

echo "==== authorized MIT kprop as host ===="
GOOD="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d localhost 2>&1 || true)"
echo "$GOOD"
echo "$GOOD" | grep -q 'SUCCEEDED'
docker exec "$NAME" test -f /tmp/replica

echo "==== C2 kpropd.acl semantics, MIT kpropd vs Rust kpropd (kpropd.c:1298-1348 authorized_principal) ===="
# authorized_principal: fopen per connection; a line matches when it starts
# with the unparsed client (strncmp) and the next byte is NUL/isspace; the
# optional remainder must be a krb5_string_to_enctype name equal to the
# ticket enctype, otherwise the line is skipped. No globs, no leading
# whitespace, no comments. The check runs after recvauth (kpropd.c:528), so
# MIT kprop has its AP-REP and dies with `Broken pipe while sending database
# block starting at 0`. Both kpropds read the same ACL file per connection.
# MIT kprop's target is host/${HN} on both legs (MIT kpropd's own name).
kill_comm kpropd
docker exec "$NAME" sh -c 'rm -f /tmp/mit-rep.dump; : >/tmp/kpropd.acl.case'
docker exec -d -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" sh -c 'kpropd -S -d -s /tmp/host.keytab -a /tmp/kpropd.acl.case -P 1754 -f /tmp/mit-rep.dump -p /bin/true >/tmp/kpropd-mit.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -aEq 'ready|waiting for a kprop' /tmp/kpropd-mit.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kpropd-mit.log >&2 || true
    log "propacl.gate" "error" ',"error":"MIT kpropd (acl matrix) did not listen"'
    exit 1
fi
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KPROP_KEYTAB=/tmp/host.keytab \
    -e KRB5_KPROP_ACL=/tmp/kpropd.acl.case \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
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
    log "propacl.gate" "error" ',"error":"kpropd (acl matrix) did not listen"'
    exit 1
fi
# kprop's verdict line, with the block offset normalised (MIT's own exit(1)
# races kprop's writes; the size SAFE lands, the first PRIV block gets EPIPE).
# `-p /bin/true` stands in for kdb5_util on the MIT leg so the received dump
# is not loaded over the live MIT realm (kpropd.c:1584 execv, exit 0 → ack).
kprop_verdict() { tr -d '\r' | grep -aE 'SUCCEEDED|^kprop: ' | sed -e 's/ to [^:]*: SUCCEEDED/: SUCCEEDED/' -e 's/while sending database.*/while sending database/' || true; }
acl_case() {
    # acl_case <name> <printf-format for the ACL file> <expect: allow|deny>
    local name=$1 fmt=$2 expect=$3 mit rust mit_log rust_log
    docker exec "$NAME" sh -c "printf '$fmt' >/tmp/kpropd.acl.case; rm -f /tmp/mit-rep.dump /tmp/replica"
    mit="$( (docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 1754 -d "$HN" 2>&1 || true) | kprop_verdict)"
    rust="$( (docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d "$HN" 2>&1 || true) | kprop_verdict)"
    sleep 0.3
    mit_log="$(docker exec "$NAME" grep -ac "Rejected connection from unauthorized principal host/${HN}@KERBER.TEST" /tmp/kpropd-mit.log || true)"
    rust_log="$(docker exec "$NAME" grep -ac "Rejected connection from unauthorized principal host/${HN}@KERBER.TEST" /tmp/kpropd.log || true)"
    echo "acl-$name mit=[$mit] rust=[$rust] rejected_lines mit=$mit_log rust=$rust_log"
    if [ "$mit" != "$rust" ]; then
        echo "acl-$name: MIT kpropd and Rust kpropd disagree" >&2
        exit 1
    fi
    case "$expect" in
        allow)
            echo "$mit" | grep -q 'SUCCEEDED'
            docker exec "$NAME" test -f /tmp/mit-rep.dump
            docker exec "$NAME" test -f /tmp/replica
            ;;
        deny)
            echo "$mit" | grep -qF 'kprop: Broken pipe while sending database'
            if docker exec "$NAME" test -f /tmp/mit-rep.dump || docker exec "$NAME" test -f /tmp/replica; then
                echo "acl-$name: a refused kprop wrote a dump" >&2
                exit 1
            fi
            ;;
    esac
    # Both kpropds log the refusal once more per denied case (cumulative counts).
    ACL_DENIED_SO_FAR=${ACL_DENIED_SO_FAR:-0}
    if [ "$expect" = deny ]; then
        ACL_DENIED_SO_FAR=$((ACL_DENIED_SO_FAR + 1))
    fi
    [ "$mit_log" = "$ACL_DENIED_SO_FAR" ] && [ "$rust_log" = "$ACL_DENIED_SO_FAR" ]
}
# The MIT KDC issues the host/${HN} ticket with the strongest key of the
# service: aes256-cts-hmac-sha384-192 (kpropd -d prints `etype ==`).
acl_case exact "host/${HN}@KERBER.TEST\\n" allow
acl_case other-principal "host/other@KERBER.TEST\\n" deny
acl_case glob-lines "*@KERBER.TEST\\nhost/*@KERBER.TEST\\n*\\n" deny
acl_case leading-space "  host/${HN}@KERBER.TEST\\n" deny
acl_case trailing-space "host/${HN}@KERBER.TEST\\t \\n" allow
acl_case no-realm "host/${HN}\\n" deny
acl_case longer-name "host/${HN}@KERBER.TESTX\\n" deny
acl_case hash-comment "# host/${HN}@KERBER.TEST\\n" deny
acl_case etype-match "host/${HN}@KERBER.TEST aes256-cts-hmac-sha384-192\\n" allow
acl_case etype-alias-case "host/${HN}@KERBER.TEST AES256-SHA2\\n" allow
acl_case etype-mismatch "host/${HN}@KERBER.TEST aes128-cts\\n" deny
acl_case etype-unknown "host/${HN}@KERBER.TEST nosuch\\n" deny
acl_case etype-number "host/${HN}@KERBER.TEST 20\\n" deny
acl_case etype-two "host/${HN}@KERBER.TEST aes128-cts aes256-sha2\\n" deny
acl_case etype-crlf "host/${HN}@KERBER.TEST aes256-sha2\\r\\n" deny
acl_case name-crlf "host/${HN}@KERBER.TEST\\r\\n" allow
acl_case no-final-newline "host/other@KERBER.TEST nosuch\\nhost/${HN}@KERBER.TEST" allow
MIT_ETYPE="$(docker exec "$NAME" grep -a 'authenticated client' /tmp/kpropd-mit.log | head -1 || true)"
echo "$MIT_ETYPE"
echo "$MIT_ETYPE" | grep -F "authenticated client: host/${HN}@KERBER.TEST (etype == aes256-cts-hmac-sha384-192)"
kill_comm kpropd
echo "c2_kpropd_acl_semantics=identical"

echo "==== MIT kinit user against replica ===="
kill_comm krb5kdc
kill_comm krb5-kpropd
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
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
    log "propacl.gate" "error" ',"error":"replica kdc did not listen"'
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
KLIST="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'

log "propacl.gate" "ok" ',"unauthorized_refused":true,"unset_acl_refused":true,"authorized_kprop":true'
exit 0
