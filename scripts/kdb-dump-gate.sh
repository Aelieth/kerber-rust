#!/usr/bin/env bash
# MIT 1.22.2 kdb5_util dump/load oracle. Isolated: never touches host /etc/krb5.conf.
#
# Half A: MIT dump → Rust load → Rust KDC → MIT kinit + klist.
# Half B: Rust dump → MIT kdb5_util load → MIT krb5kdc → MIT kinit + klist.
# MIT kinit is the promotion criterion (never a Rust-vs-Rust stand-in).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kdb-dump-gate"
GOLDEN="tests/traces/kdb/mit-dump-v7.txt"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-kdb-dump-gate}"
mkdir -p "$SCRATCH"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"kdb-dump-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

if ! command -v docker >/dev/null 2>&1; then
    log "kdb.dump.gate" "error" ',"error":"docker not available"'
    echo "docker not available" >"$SCRATCH/kdb-dump-unavailable.log"
    exit 2
fi

if [ ! -f "$GOLDEN" ]; then
    log "kdb.dump.gate" "error" ',"error":"missing golden dump"'
    exit 1
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-kdb -p krb5-admin --bin krb5-kadmin-local

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "kdb.dump.gate" "error" ',"error":"MIT image unavailable"'
    echo "MIT image unavailable" >"$SCRATCH/kdb-dump-unavailable.log"
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" 3600 >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker cp "$GOLDEN" "$NAME":/tmp/mit.dump
echo "==== golden dump nosvr/hwuser keys (kdb5_util dump) are MIT-derived, not clones of user/pwprau ===="
if ! python3 - "$ROOT/scripts/ci-policy.py" <<'PY'
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("ci_policy", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.check_golden_dump_unique_keys()
print("nosvr_keys_eq_user=False")
print("hwuser_keys_eq_pwprau=False")
PY
then
    echo "nosvr/hwuser keys clone user/pwprau" >&2
    exit 1
fi
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kadmin-local
rust_local() {
    docker exec -e KRB5_MASTER_PASSWORD=masterpassword -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
        "$NAME" /tmp/krb5-kadmin-local -q "$1" 2>&1
}
hist_shape() { grep -E '^(Expiration date|Password expiration date|Maximum ticket life|Maximum renewable life|Attributes|Number of keys|Key: vno|MKey: vno|Policy):?' ; }

docker exec "$NAME" sh -c 'cat >/tmp/kdb-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kdb
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF'

echo "==== half A: MIT kadmin.local aliases user, kdb5_util re-dumps ===="
docker exec "$NAME" kdb5_util create -s -P masterpassword
docker exec "$NAME" kdb5_util load /tmp/mit.dump
docker exec "$NAME" kadmin.local -q 'alias a1 user' 2>&1 | grep -F 'Principal "a1@KERBER.TEST" aliased to "user@KERBER.TEST".'
echo "==== half A: MIT records a password history (KADM_DATA old_keys under kadmin/history) ===="
docker exec "$NAME" kadmin.local -q 'addpol -history 3 hp' 2>&1 | grep -v dictionary
docker exec "$NAME" kadmin.local -q 'addprinc -pw s3cret1 -policy hp histee' 2>&1 | grep -F 'Principal "histee@KERBER.TEST" created.'
docker exec "$NAME" kadmin.local -q 'cpw -pw s3cret2 histee' 2>&1 | grep -F 'Password for "histee@KERBER.TEST" changed.'
MIT_HIST_A="$(docker exec "$NAME" kadmin.local -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$MIT_HIST_A"
echo "$MIT_HIST_A" | grep -F 'Principal: kadmin/history@KERBER.TEST'
docker exec "$NAME" kdb5_util dump /tmp/mit-alias.dump
ALIAS_LINE="$(docker exec "$NAME" grep -F 'a1@KERBER.TEST' /tmp/mit-alias.dump)"
echo "$ALIAS_LINE"
echo "$ALIAS_LINE" | grep -qE '^princ	38	14	3	0	0	a1@KERBER.TEST	64	0	0	0	0	0	0	0	'
echo "$ALIAS_LINE" | grep -q '	12	17	75736572404b45524245522e5445535400	'
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1'

echo "==== half A: krb5-kdb load MIT dump (with the alias) ===="
LOAD_A="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kdb load /tmp/mit-alias.dump)"
echo "$LOAD_A"
echo "$LOAD_A" | grep -q 'ok load version=7'
echo "$LOAD_A" | grep -q 'realm=KERBER.TEST'

echo "==== half A: Rust reads MIT's history — the old password is a reuse, the policy is bound, kadmin/history keeps MIT's shape ===="
REUSE_A="$(rust_local 'cpw -pw s3cret1 histee' || true)"
echo "$REUSE_A"
echo "$REUSE_A" | grep -F 'Cannot reuse password while changing password for "histee@KERBER.TEST".'
if rust_local 'cpw -pw s3cret1 histee' | grep -qF 'changed.'; then
    echo "Rust accepted MIT's old password s3cret1" >&2
    exit 1
fi
GETH_A="$(rust_local 'getprinc histee')"
echo "$GETH_A"
echo "$GETH_A" | grep -F 'Policy: hp'
RUST_HIST_A="$(rust_local 'getprinc kadmin/history')"
echo "$RUST_HIST_A"
diff <(echo "$RUST_HIST_A" | hist_shape) <(echo "$MIT_HIST_A" | hist_shape)
rust_local 'cpw -pw s3cret3 histee' | grep -F 'changed.'

echo "==== Rust stash is keytab format; MIT klist -k reads the K/M entry ===="
# krb5_db_def_fetch_mkey: the stash is a FILE keytab with one K/M@REALM entry.
docker exec "$NAME" sh -c 'head -c2 /tmp/stash | od -An -tx1' | grep -q '05 02'
KMKT="$(docker exec "$NAME" klist -k -e -t -K /tmp/stash 2>&1)"
echo "$KMKT" | sed 's/(0x[0-9a-f]*)/(0x<redacted>)/'
echo "$KMKT" | grep -q 'K/M@KERBER.TEST'
echo "$KMKT" | grep -q 'aes256-cts-hmac-sha384-192'
# krb5-kdb stash rewrites the same file idempotently.
STASHCMD="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kdb stash 2>&1 || true)"
echo "$STASHCMD"
echo "$STASHCMD" | grep -q 'ok stash realm=KERBER.TEST'
docker exec "$NAME" klist -k -t -K /tmp/stash 2>&1 | grep -q 'K/M@KERBER.TEST'

echo "==== Rust KDC loads the keytab stash with no ERROR log ===="
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
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
    log "kdb.dump.gate" "error" ',"error":"rust kdc did not listen"'
    exit 1
fi

if docker exec "$NAME" grep -q '"level":"ERROR"' /tmp/kdc.log 2>/dev/null; then
    docker exec "$NAME" grep '"level":"ERROR"' /tmp/kdc.log >&2 || true
    log "kdb.dump.gate" "error" ',"error":"rust KDC logged ERROR loading the keytab stash"'
    exit 1
fi

echo "==== half A: MIT kinit user against Rust KDC ===="
if ! docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kdb.dump.gate" "error" ',"error":"half A MIT kinit user failed"'
    exit 1
fi
KLIST_A="$(docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist)"
echo "$KLIST_A"
echo "$KLIST_A" | grep -q 'user@KERBER.TEST'
log "kdb.dump.half_a" "ok" ',"principal":"user@KERBER.TEST","kdc":"rust"'

echo "==== half A: MIT kinit pauser (REQUIRES_PRE_AUTH) ===="
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "preauthpw\n" | kinit pauser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kdb.dump.gate" "error" ',"error":"half A MIT kinit pauser failed"'
    exit 1
fi
KLIST_AP="$(docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist)"
echo "$KLIST_AP"
echo "$KLIST_AP" | grep -q 'pauser@KERBER.TEST'

echo "==== half A: MIT kinit a1 (MIT-written alias stub) against Rust KDC ===="
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\n" | kinit a1@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "kdb.dump.gate" "error" ',"error":"half A MIT kinit a1 failed"'
    exit 1
fi
KLIST_A1="$(docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist)"
echo "$KLIST_A1"
echo "$KLIST_A1" | grep -F 'Default principal: a1@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" sh -c 'printf "userpassword\n" | kinit -C a1@KERBER.TEST'
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist | grep -F 'Default principal: user@KERBER.TEST'

echo "==== half B: MIT load of the running KDC at-rest file ===="
# Stop the Rust KDC so MIT krb5kdc can bind :88. Match /proc/PID/comm only
# (a shell whose script text mentions the binary must not be killed).
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
free=0
for _ in $(seq 1 40); do
    if ! docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.2)" 2>/dev/null; then
        free=1
        break
    fi
    sleep 0.25
done
if [ "$free" != 1 ]; then
    docker exec "$NAME" sh -c 'ps aux || ps' >&2 || true
    log "kdb.dump.gate" "error" ',"error":"rust kdc still bound :88"'
    exit 1
fi
HEADER_B="$(docker exec "$NAME" head -1 /tmp/principal)"
echo "$HEADER_B"
[ "$HEADER_B" = "kdb5_util load_dump version 7" ]
docker exec "$NAME" grep -q 'princ	' /tmp/principal
docker exec "$NAME" grep -q 'user@KERBER.TEST' /tmp/principal
docker exec "$NAME" grep -q 'pauser@KERBER.TEST' /tmp/principal
docker exec "$NAME" grep -q 'host/testhost.kerber.test@KERBER.TEST' /tmp/principal

echo "==== half B: seed policy line on Rust dump ===="
ADDPOL="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kdb addpol lockme 2>&1 || true)"
echo "$ADDPOL"
echo "$ADDPOL" | grep -q 'ok addpol name=lockme'
docker exec "$NAME" grep -q '^policy	lockme	' /tmp/principal
docker exec "$NAME" grep -q 'user@KERBER.TEST' /tmp/principal

echo "==== half B: seed TL 0x000b string attr on Rust dump ===="
SETSTR="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kdb setstr user note hello-g3d 2>&1 || true)"
echo "$SETSTR"
echo "$SETSTR" | grep -q 'ok setstr user note'
docker exec "$NAME" grep -q '6e6f74650068656c6c6f2d67336400' /tmp/principal

echo "==== half B: seed a Rust-written alias stub on the Rust dump ===="
ALIAS_B="$(docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kdb alias a2 user 2>&1 || true)"
echo "$ALIAS_B"
echo "$ALIAS_B" | grep -q 'ok alias a2 user'
docker exec "$NAME" grep -E '^princ	38	14	3	0	0	a2@KERBER.TEST	64	0	0	0	0	0	0	0	' /tmp/principal | grep -q '	12	17	75736572404b45524245522e5445535400	'

echo "==== half B: seed a Rust-written password history on the Rust dump ===="
rust_local 'addpol -history 3 hpb' | grep -v dictionary || true
rust_local 'addprinc -pw b3cret1 -policy hpb histb' | grep -F 'Principal "histb@KERBER.TEST" created.'
rust_local 'cpw -pw b3cret2 histb' | grep -F 'Password for "histb@KERBER.TEST" changed.'
RUST_HIST_B="$(rust_local 'getprinc kadmin/history')"
echo "$RUST_HIST_B"
echo "$RUST_HIST_B" | grep -F 'Principal: kadmin/history@KERBER.TEST'
docker exec "$NAME" grep -q 'histb@KERBER.TEST' /tmp/principal

echo "==== half B: MIT kdb5_util load + krb5kdc ===="
docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1 || true'
docker exec "$NAME" kdb5_util create -s -P masterpassword
LOAD_B="$(docker exec "$NAME" kdb5_util load /tmp/principal 2>&1 || true)"
echo "$LOAD_B"
echo "$LOAD_B" | grep -qiE 'error|fail' && {
    log "kdb.dump.gate" "error" ',"error":"MIT kdb5_util load rejected policy dump"'
    exit 1
}
GETPOL="$(docker exec "$NAME" kadmin.local -q 'getpol lockme' 2>&1 || true)"
echo "$GETPOL"
echo "$GETPOL" | grep -q 'Policy: lockme'
GETSTRS="$(docker exec "$NAME" kadmin.local -q 'getstrs user' 2>&1 || true)"
echo "$GETSTRS"
echo "$GETSTRS" | grep -q 'note: hello-g3d'
GETA2="$(docker exec "$NAME" kadmin.local -q 'getprinc a2' 2>&1 || true)"
echo "$GETA2"
echo "$GETA2" | grep -F 'Principal: user@KERBER.TEST'

echo "==== half B: MIT reads Rust's history — the old password is a reuse, the policy is bound, kadmin/history has the Rust shape ===="
REUSE_B="$(docker exec "$NAME" kadmin.local -q 'cpw -pw b3cret1 histb' 2>&1 || true)"
echo "$REUSE_B"
echo "$REUSE_B" | grep -F 'Cannot reuse password while changing password for "histb@KERBER.TEST".'
GETH_B="$(docker exec "$NAME" kadmin.local -q 'getprinc histb' 2>&1 || true)"
echo "$GETH_B"
echo "$GETH_B" | grep -F 'Policy: hpb'
MIT_HIST_B="$(docker exec "$NAME" kadmin.local -q 'getprinc kadmin/history' 2>&1 || true)"
echo "$MIT_HIST_B"
diff <(echo "$MIT_HIST_B" | hist_shape) <(echo "$RUST_HIST_B" | hist_shape)
docker exec "$NAME" kadmin.local -q 'cpw -pw b3cret3 histb' 2>&1 | grep -F 'changed.'
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
    log "kdb.dump.gate" "error" ',"error":"MIT krb5kdc did not listen"'
    exit 1
fi
if echo "$STARTLOG" | grep -q 'Address already in use'; then
    log "kdb.dump.gate" "error" ',"error":"MIT krb5kdc could not bind :88"'
    exit 1
fi
if ! echo "$STARTLOG" | grep -q 'setting up network'; then
    log "kdb.dump.gate" "error" ',"error":"MIT krb5kdc did not start"'
    exit 1
fi

echo "==== half B: MIT kinit user against MIT KDC on Rust dump ===="
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf -e KRB5_TRACE=/dev/stderr \
    "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    log "kdb.dump.gate" "error" ',"error":"half B MIT kinit user failed"'
    exit 1
fi
KLIST_B="$(docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist)"
echo "$KLIST_B"
echo "$KLIST_B" | grep -q 'user@KERBER.TEST'
# MIT krb5kdc tickets are renewable; the Rust klist in half A is not.
echo "$KLIST_B" | grep -q 'renew until'
log "kdb.dump.half_b" "ok" ',"principal":"user@KERBER.TEST","kdc":"mit"'

echo "==== half B: MIT kinit pauser ===="
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf \
    "$NAME" sh -c 'printf "preauthpw\n" | kinit pauser@KERBER.TEST'; then
    log "kdb.dump.gate" "error" ',"error":"half B MIT kinit pauser failed"'
    exit 1
fi
KLIST_BP="$(docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist)"
echo "$KLIST_BP"
echo "$KLIST_BP" | grep -q 'pauser@KERBER.TEST'

echo "==== half B: MIT kinit a2 (Rust-written alias stub) against MIT KDC ===="
docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf \
    "$NAME" sh -c 'printf "userpassword\n" | kinit a2@KERBER.TEST'; then
    log "kdb.dump.gate" "error" ',"error":"half B MIT kinit a2 failed"'
    exit 1
fi
KLIST_B2="$(docker exec -e KRB5_CONFIG=/tmp/kdb-krb5.conf "$NAME" klist)"
echo "$KLIST_B2"
echo "$KLIST_B2" | grep -F 'Default principal: a2@KERBER.TEST'

log "kdb.dump.gate" "ok" ',"dump_version":7,"halves":"A+B","alias":"both directions"'
