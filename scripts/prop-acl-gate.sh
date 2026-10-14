#!/usr/bin/env bash
# MIT kprop as an unauthorized GSS peer is refused by Rust kpropd; host
# sender still loads. Isolated: never touches host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/proc-common.sh"
need_bins krb5-kdc krb5-kpropd krb5-kadmind

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-prop-acl-gate"
# The Rust kpropd's ACL without -a: kpropd.acl in the KDC directory the build compiled in.
DEFAULT_ACL="${KERBER_KDC_DIR:-/var/kerberos/krb5kdc}/kpropd.acl"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"

need_image

# A host name with a dot, as the shared shell's: kpropd's own name is then the hostname as it is.
shell_container 3600 testhost.kerber.test

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
kadmin_q_ok mit_kadmin_local "$NAME" -- -q 'addprinc -pw userpassword user'
HN="$(docker exec "$NAME" hostname)"
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -randkey host/localhost"
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -randkey host/${HN}"
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "ktadd -k /tmp/host.keytab host/localhost host/${HN}"
docker exec "$NAME" kdb5_util dump /tmp/dump
docker exec "$NAME" sh -c 'printf "" >/tmp/kpropd.acl.empty'
docker exec "$NAME" sh -c "printf 'host/localhost@KERBER.TEST\\nhost/${HN}@KERBER.TEST\\n' >/tmp/kpropd.acl"

echo "==== MIT krb5kdc ===="
kill_comm krb5kdc
kill_comm krb5-kdc
docker exec "$NAME" sh -c 'krb5kdc' >/dev/null 2>&1 || true
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

echo "==== Rust kpropd without -a and no kpropd.acl in the KDC directory (deny even host/ peers) ===="
# MIT `acl_file_name` (kpropd.c:137): without -a the ACL is KPROPD_ACL_FILE, KDC_DIR/kpropd.acl,
# here the debug build's /var/kerberos/krb5kdc/kpropd.acl. None is there, so nobody is authorized.
docker exec "$NAME" rm -f "$DEFAULT_ACL"
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd -s /tmp/host.keytab 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
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

echo "==== unauthorized MIT kprop (no -a, no default kpropd.acl) ===="
UNSET="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d "$HN" 2>&1 || true)"
echo "$UNSET"
require_log "$NAME" /tmp/kpropd.log 'Rejected connection from unauthorized principal' "unauthorized reject in /tmp/kpropd.log"
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
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd -s /tmp/host.keytab -a /tmp/kpropd.acl.empty 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
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
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d "$HN" 2>&1 || true)"
echo "$BAD"
require_log "$NAME" /tmp/kpropd.log 'Rejected connection from unauthorized principal' "unauthorized reject in /tmp/kpropd.log"
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
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd -s /tmp/host.keytab -a /tmp/kpropd.acl 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
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
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d "$HN" 2>&1 || true)"
echo "$GOOD"
echo "$GOOD" | grep -q 'SUCCEEDED'
docker exec "$NAME" test -f /tmp/replica

echo "==== Rust kpropd without -a, the host allowlist in the KDC directory's kpropd.acl ===="
docker exec "$NAME" sh -c "cp /tmp/kpropd.acl '$DEFAULT_ACL'; rm -f /tmp/replica"
kill_comm krb5-kpropd
docker exec -d \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd -s /tmp/host.keytab 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
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
    log "propacl.gate" "error" ',"error":"kpropd (default ACL) did not listen"'
    exit 1
fi
DEF="$(docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf \
    "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P 754 -d "$HN" 2>&1 || true)"
echo "$DEF"
echo "$DEF" | grep -q 'SUCCEEDED'
docker exec "$NAME" test -f /tmp/replica
docker exec "$NAME" rm -f "$DEFAULT_ACL"

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
    -e KRB5_KDC_DB=/tmp/replica \
    -e KRB5_KDC_STASH=/tmp/replica.stash \
    -e KRB5_TEST_REALM=KERBER.TEST \
    "$NAME" sh -c '/tmp/krb5-kpropd -s /tmp/host.keytab -a /tmp/kpropd.acl.case 0.0.0.0:754 >/tmp/kpropd.log 2>&1'
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
    _acl_rejected_counts() {
        mit_log="$(docker exec "$NAME" grep -ac "Rejected connection from unauthorized principal host/${HN}@KERBER.TEST" /tmp/kpropd-mit.log || true)"
        rust_log="$(docker exec "$NAME" grep -ac "Rejected connection from unauthorized principal host/${HN}@KERBER.TEST" /tmp/kpropd.log || true)"
        [ "$mit_log" = "$ACL_DENIED_SO_FAR" ] && [ "$rust_log" = "$ACL_DENIED_SO_FAR" ]
    }
    retry_until --log "$NAME" /tmp/kpropd-mit.log /tmp/kpropd.log -- 200 "acl-$name rejected_lines=$ACL_DENIED_SO_FAR" _acl_rejected_counts
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
retry_until --log "$NAME" /tmp/kpropd-mit.log -- 200 "MIT kpropd etype line" \
    docker exec "$NAME" grep -aqF "authenticated client: host/${HN}@KERBER.TEST (etype == aes256-cts-hmac-sha384-192)" /tmp/kpropd-mit.log
MIT_ETYPE="$(docker exec "$NAME" grep -a 'authenticated client' /tmp/kpropd-mit.log | head -1 || true)"
echo "$MIT_ETYPE"
echo "$MIT_ETYPE" | grep -F "authenticated client: host/${HN}@KERBER.TEST (etype == aes256-cts-hmac-sha384-192)"

echo "==== a ticket for host/localhost, whose key the keytab holds, is refused by both kpropds ===="
# kpropd.c:1258: recvauth takes kpropd's own principal, host/${HN}, as the server, so a ticket for
# another principal of the keytab is KRB5KRB_AP_ERR_NOT_US; nothing is received.
# The replica the MIT kinit leg below serves is set aside, so a written one would show.
docker exec "$NAME" sh -c 'rm -f /tmp/mit-rep.dump; mv /tmp/replica /tmp/replica.kept'
for port in 1754 754; do
    other="$( (docker exec -e KRB5_CONFIG=/tmp/prop-krb5.conf "$NAME" kprop -f /tmp/dump -s /tmp/host.keytab -P "$port" -d localhost 2>&1 || true) | tr -d '\r')"
    echo "kprop to localhost:$port: $other"
    echo "$other" | grep -qF "The ticket isn't for us signalled from server" \
        || die "kpropd on $port did not refuse a ticket for host/localhost as MIT's"
done
if docker exec "$NAME" test -f /tmp/mit-rep.dump || docker exec "$NAME" test -f /tmp/replica; then
    die "a refused ticket wrote a dump"
fi
docker exec "$NAME" mv /tmp/replica.kept /tmp/replica
kill_comm kpropd
echo "c2_kpropd_acl_semantics=identical"

echo "==== a short hostname: both kpropds answer as its qualified name ===="
# MIT `sn2princ_realm` (kprop_util.c:33-55) through `expand_hostname` (sn2princ.c:121-144): without
# DNS (the image's krb5.conf sets dns_canonicalize_hostname = false) a hostname without a dot gains
# qualify_shortname, else the resolver's first search domain, and is lowercased. A replica named
# kdc2 whose resolv.conf searches kerber.test answers as host/kdc2.kerber.test, and with kdc.conf's
# qualify_shortname = "" as host/kdc2, which its keytab lacks. MIT kprop runs on the replica as
# host/kdc2.kerber.test, its tickets from the MIT KDC above.
SHORT="${NAME}-short"
docker rm -f "$SHORT" >/dev/null 2>&1 || true
docker run -d --name "$SHORT" --hostname kdc2 --dns-search kerber.test \
    --add-host kdc2.kerber.test:127.0.0.1 --entrypoint sleep "$IMAGE" 900 >/dev/null
register_cleanup "docker rm -f '$SHORT' >/dev/null 2>&1 || true"
MAIN_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -randkey host/kdc2.kerber.test"
docker exec "$NAME" rm -f /tmp/kdc2.keytab
kadmin_q_ok mit_kadmin_local "$NAME" -- -q "ktadd -k /tmp/kdc2.keytab host/kdc2.kerber.test"
for f in kdc2.keytab dump; do
    docker exec "$NAME" cat "/tmp/$f" | docker exec -i "$SHORT" sh -c "cat >/tmp/$f"
done
# MIT kprop sends a dump only beside a dump_ok file no older than it (kprop.c:369-382).
docker exec "$SHORT" touch /tmp/dump.dump_ok
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpropd" "$SHORT":/tmp/krb5-kpropd
docker exec "$SHORT" sh -c "chmod +x /tmp/krb5-kpropd
    printf 'host/kdc2.kerber.test@KERBER.TEST\\n' >/tmp/kpropd.acl
    sed 's/127.0.0.1/$MAIN_IP/' /etc/krb5.conf >/tmp/kprop-krb5.conf
    cp /etc/krb5kdc/kdc.conf /tmp/kdc-noq.conf"
docker exec -i "$SHORT" sh -c 'cat >>/tmp/kdc-noq.conf' <<'KDCEOF'

[libdefaults]
    qualify_shortname = ""
KDCEOF
docker exec "$SHORT" sh -c 'hostname; grep -E "^(search|domain)" /etc/resolv.conf; grep dns_canonicalize_hostname /etc/krb5.conf; tail -2 /tmp/kdc-noq.conf'
# short_kpropds <kdc profile> <MIT port> <Rust port>: MIT kpropd and the Rust kpropd on the replica.
short_kpropds() {
    local prof=$1 mport=$2 rport=$3
    docker exec -d -e KRB5_KDC_PROFILE="$prof" "$SHORT" sh -c "kpropd -S -d -s /tmp/kdc2.keytab -a /tmp/kpropd.acl -P $mport -f /tmp/mit-rep-$mport.dump -p /bin/true >/tmp/kpropd-mit-$mport.log 2>&1"
    docker exec -d -e KRB5_KDC_PROFILE="$prof" \
        -e KRB5_MASTER_PASSWORD=masterpassword \
        -e KRB5_KDC_DB="/tmp/replica-$rport" \
        -e KRB5_KDC_STASH="/tmp/replica-$rport.stash" \
        -e KRB5_TEST_REALM=KERBER.TEST \
        "$SHORT" sh -c "/tmp/krb5-kpropd -s /tmp/kdc2.keytab -a /tmp/kpropd.acl 0.0.0.0:$rport >/tmp/kpropd-$rport.log 2>&1"
    require_log "$SHORT" "/tmp/kpropd-mit-$mport.log" 'ready|waiting for a kprop' "MIT kpropd on $mport"
    require_log "$SHORT" "/tmp/kpropd-$rport.log" '^listening ' "Rust kpropd on $rport"
}
short_kprop() {
    (docker exec -e KRB5_CONFIG=/tmp/kprop-krb5.conf "$SHORT" kprop -f /tmp/dump -s /tmp/kdc2.keytab -P "$1" -d kdc2.kerber.test 2>&1 || true) | tr -d '\r'
}
short_kpropds /etc/krb5kdc/kdc.conf 1754 754
short_kpropds /tmp/kdc-noq.conf 1755 755
for port in 1754 754; do
    out="$(short_kprop "$port")"
    echo "kprop to kdc2.kerber.test:$port (resolv.conf's search domain): $out"
    echo "$out" | grep -q 'SUCCEEDED' || die "kpropd on $port did not answer as host/kdc2.kerber.test"
done
docker exec "$SHORT" test -f /tmp/mit-rep-1754.dump
docker exec "$SHORT" test -f /tmp/replica-754
docker exec "$SHORT" grep -aF 'krb5_recvauth(4, kprop5_01, host/kdc2.kerber.test@KERBER.TEST' /tmp/kpropd-mit-1754.log
for port in 1755 755; do
    out="$(short_kprop "$port")"
    echo "kprop to kdc2.kerber.test:$port (qualify_shortname = \"\"): $out"
    echo "$out" | grep -qF 'Service key not available signalled from server' \
        || die "kpropd on $port did not refuse as host/kdc2"
done
if docker exec "$SHORT" test -f /tmp/mit-rep-1755.dump || docker exec "$SHORT" test -f /tmp/replica-755; then
    die "a kpropd that is host/kdc2 took a ticket for host/kdc2.kerber.test"
fi
docker exec "$SHORT" grep -aF 'krb5_recvauth(4, kprop5_01, host/kdc2@KERBER.TEST' /tmp/kpropd-mit-1755.log

echo "==== a profile MIT's context refuses stops both kpropds; one it reads past starts both ===="
# MIT `krb5_init_context_profile` (init_ctx.c:219-281): in order, a boolean the context reads that
# is none (PROF_BAD_BOOLEAN), a dns_canonicalize_hostname neither a boolean nor fallback (EINVAL), a
# request_timeout that is no interval (KRB5_DELTAT_BADFORMAT) or a plugin_base_dir whose tokens do
# not expand (EINVAL) fails it, and kpropd prints the error `while initializing krb5` and exits 1.
# It reads only top-level [libdefaults] relations by their exact names (prof_tree.c:586-616), so one
# in a realm's subsection, or spelled otherwise, refuses nothing: both kpropds start.
docker exec "$SHORT" sh -c 'for v in tri:"dns_canonicalize_hostname = sometimes" bool:"allow_weak_crypto = maybe" \
        timeout:"request_timeout = bogus" plugin:"plugin_base_dir = %{bogus}/x" case:"Allow_Weak_Crypto = maybe" \
        sub:"KERBER.TEST = {
        allow_weak_crypto = maybe
    }"; do
        cp /etc/krb5kdc/kdc.conf "/tmp/kdc-${v%%:*}.conf"
        printf "\n[libdefaults]\n    %s\n" "${v#*:}" >>"/tmp/kdc-${v%%:*}.conf"
    done'
for c in "tri:Invalid argument" "bool:Invalid boolean value" \
    "timeout:Invalid format of Kerberos lifetime or clock skew string" "plugin:Invalid argument" \
    "sub:" "case:"; do
    prof="/tmp/kdc-${c%%:*}.conf"
    text="${c#*:}"
    mit="$(docker exec -e KRB5_KDC_PROFILE="$prof" "$SHORT" sh -c \
        'timeout 3 kpropd -S -d -s /tmp/kdc2.keytab -P 1756 2>&1; echo "rc=$?"' | tr -d '\r')"
    rust="$(docker exec -e KRB5_KDC_PROFILE="$prof" "$SHORT" sh -c \
        'timeout 3 /tmp/krb5-kpropd -s /tmp/kdc2.keytab 0.0.0.0:756 2>&1; echo "rc=$?"')"
    echo "$prof: MIT [$mit] Rust [$rust]"
    if [ -n "$text" ]; then
        want="$text while initializing krb5"
        { echo "$mit" | grep -qxF "kpropd: $want" && echo "$mit" | grep -qx 'rc=1'; } \
            || die "MIT kpropd did not stop on $prof"
        { echo "$rust" | grep -qxF "/tmp/krb5-kpropd: $want" && echo "$rust" | grep -qx 'rc=1'; } \
            || die "Rust kpropd did not stop on $prof"
    else
        echo "$mit" | grep -qx 'rc=124' || die "MIT kpropd did not start on $prof"
        echo "$rust" | grep -qx 'rc=124' || die "Rust kpropd did not start on $prof"
    fi
done
docker rm -f "$SHORT" >/dev/null 2>&1 || true

echo "==== MIT kinit user against replica ===="
kill_comm krb5kdc
kill_comm krb5-kpropd
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
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

log "propacl.gate" "ok" ',"unauthorized_refused":true,"unset_acl_refused":true,"authorized_kprop":true,"default_acl_authorized":true,"other_principal_refused":true,"short_hostname_qualified":true,"bad_context_refused":true'
exit 0
