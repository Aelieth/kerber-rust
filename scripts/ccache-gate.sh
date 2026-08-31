#!/usr/bin/env bash
# Live MIT 1.22.2 FILE/DIR/MEMORY ccache oracle. Requires the harness.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
log() {
    printf '{"event":"%s","correlation_id":"%s","component":"ccache-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}
NAME="kerber-rust-mit-kdc"
if ! docker ps -q --filter "name=^${NAME}$" | grep -q .; then
    echo "start the harness first: ./scripts/run-harness.sh" >&2
    exit 1
fi

cargo build -p krb5-client --bin krb5-kinit --bin krb5-klist --bin krb5-kdestroy --bin krb5-kvno --bin krb5-kswitch
cargo build -p krb5-protocol --example ccache-probe
docker cp target/debug/krb5-kinit "$NAME":/tmp/krb5-kinit
docker cp target/debug/krb5-klist "$NAME":/tmp/krb5-klist
docker cp target/debug/krb5-kdestroy "$NAME":/tmp/krb5-kdestroy
docker cp target/debug/krb5-kswitch "$NAME":/tmp/krb5-kswitch
docker cp target/debug/examples/ccache-probe "$NAME":/tmp/ccache-probe
docker cp "$ROOT/scripts/ccache-mit-remove.c" "$NAME":/tmp/ccache-mit-remove.c
docker exec "$NAME" chmod +x /tmp/krb5-kinit /tmp/krb5-klist /tmp/krb5-kdestroy /tmp/krb5-kswitch /tmp/ccache-probe
if ! docker exec "$NAME" cc -o /tmp/ccache-mit-remove /tmp/ccache-mit-remove.c -lkrb5; then
    log "ccache.gate" "error" ',"error":"cc ccache-mit-remove failed"'
    exit 1
fi

docker exec "$NAME" kadmin.local -q 'addprinc -pw extrapass extra' >/dev/null 2>&1 || true

echo "==== FILE parse→to_bytes identity of MIT kinit cache ===="
docker exec "$NAME" sh -c 'echo userpassword | kinit -c /tmp/krb5cc_ident user@KERBER.TEST'
IDENT="$(docker exec "$NAME" /tmp/ccache-probe identity /tmp/krb5cc_ident)"
echo "$IDENT"
echo "$IDENT" | grep -q '^identity_ok bytes='

echo "==== FILE identity of committed kinit -a + u2u golden ===="
docker cp "$ROOT/tests/traces/ccache-mit-addr-u2u.bin" "$NAME":/tmp/ccache-mit-addr-u2u.bin
GOLD="$(docker exec "$NAME" /tmp/ccache-probe identity /tmp/ccache-mit-addr-u2u.bin)"
echo "$GOLD"
echo "$GOLD" | grep -q '^identity_ok bytes='

echo "==== MIT remove_cred on Rust FILE; klist both ways ===="
docker exec -e KRB5_PASSWORD=userpassword "$NAME" \
    /tmp/krb5-kinit 127.0.0.1 user@KERBER.TEST /tmp/krb5cc_rust \
    host/testhost.kerber.test
docker exec "$NAME" klist -c /tmp/krb5cc_rust | grep -q 'host/testhost.kerber.test'
docker exec "$NAME" /tmp/ccache-mit-remove FILE:/tmp/krb5cc_rust \
    'host/testhost.kerber.test@KERBER.TEST'
MK="$(docker exec "$NAME" klist -c /tmp/krb5cc_rust)"
echo "$MK"
echo "$MK" | grep -q 'user@KERBER.TEST'
echo "$MK" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'
if echo "$MK" | grep -q 'host/testhost.kerber.test'; then
    echo "MIT klist still shows host ticket after remove" >&2
    exit 1
fi
RK="$(docker exec "$NAME" /tmp/krb5-klist -c /tmp/krb5cc_rust)"
echo "$RK"
echo "$RK" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'
if echo "$RK" | grep -q 'host/testhost.kerber.test'; then
    echo "Rust klist still shows host ticket after MIT remove" >&2
    exit 1
fi

echo "==== Rust remove_cred on MIT FILE; klist both ways ===="
docker exec "$NAME" sh -c 'echo userpassword | kinit -c /tmp/krb5cc_mit user@KERBER.TEST'
docker exec "$NAME" kvno -c /tmp/krb5cc_mit host/testhost.kerber.test
docker exec "$NAME" klist -c /tmp/krb5cc_mit | grep -q 'host/testhost.kerber.test'
docker exec "$NAME" /tmp/ccache-probe remove /tmp/krb5cc_mit \
    'host/testhost.kerber.test@KERBER.TEST'
MK2="$(docker exec "$NAME" klist -c /tmp/krb5cc_mit)"
echo "$MK2"
echo "$MK2" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'
if echo "$MK2" | grep -q 'host/testhost.kerber.test'; then
    echo "MIT klist still shows host ticket after Rust remove" >&2
    exit 1
fi
RK2="$(docker exec "$NAME" /tmp/krb5-klist -c /tmp/krb5cc_mit)"
echo "$RK2"
if echo "$RK2" | grep -q 'host/testhost.kerber.test'; then
    echo "Rust klist still shows host ticket after Rust remove" >&2
    exit 1
fi
KCONF="$(docker exec "$NAME" klist -C -c /tmp/krb5cc_mit)"
echo "$KCONF"
echo "$KCONF" | grep -q '^config:'

echo "==== MEMORY consumes MIT FILE ===="
MEM="$(docker exec "$NAME" /tmp/ccache-probe memory-from /tmp/krb5cc_ident)"
echo "$MEM"
echo "$MEM" | grep -q 'memory_ok principal=user@KERBER.TEST'

echo "==== DIR list of missing path does not create ===="
docker exec "$NAME" rm -rf /tmp/dcc-missing
set +e
DIRMISS="$(docker exec "$NAME" /tmp/krb5-klist -c DIR:/tmp/dcc-missing 2>&1)"
drc=$?
set -e
echo "$DIRMISS"
test "$drc" -ne 0
docker exec "$NAME" sh -c 'test ! -e /tmp/dcc-missing'

echo "==== DIR collection MIT kinit + kswitch both ways ===="
docker exec "$NAME" rm -rf /tmp/dcc
docker exec "$NAME" mkdir -m 700 /tmp/dcc
docker exec -e KRB5CCNAME=DIR:/tmp/dcc "$NAME" sh -c 'echo userpassword | kinit user@KERBER.TEST'
docker exec -e KRB5CCNAME=DIR:/tmp/dcc "$NAME" sh -c 'echo extrapass | kinit extra@KERBER.TEST'
echo "---- after two MIT kinit (primary should be extra) ----"
MITDIR="$(docker exec "$NAME" klist -c DIR:/tmp/dcc)"
echo "$MITDIR"
echo "$MITDIR" | grep -q 'extra@KERBER.TEST'
RUSTDIR="$(docker exec "$NAME" /tmp/krb5-klist -c DIR:/tmp/dcc)"
echo "$RUSTDIR"
echo "$RUSTDIR" | grep -q 'extra@KERBER.TEST'
docker exec -e KRB5CCNAME=DIR:/tmp/dcc "$NAME" kswitch -p user@KERBER.TEST
echo "---- after MIT kswitch -p user ----"
MITU="$(docker exec "$NAME" klist -c DIR:/tmp/dcc)"
echo "$MITU"
echo "$MITU" | grep -q 'user@KERBER.TEST'
RUSTU="$(docker exec "$NAME" /tmp/krb5-klist -c DIR:/tmp/dcc)"
echo "$RUSTU"
echo "$RUSTU" | grep -q 'user@KERBER.TEST'
# Subsidiary of extra for Rust kswitch.
EXTRA_SUB=
for f in $(docker exec "$NAME" ls /tmp/dcc); do
    [ "$f" = "primary" ] && continue
    case "$f" in
        tkt*) ;;
        *) continue ;;
    esac
    text="$(docker exec "$NAME" klist -c "DIR::/tmp/dcc/${f}" 2>/dev/null || true)"
    if echo "$text" | grep -q 'Default principal: extra@KERBER.TEST'; then
        EXTRA_SUB="$f"
        break
    fi
done
if [ -z "$EXTRA_SUB" ]; then
    echo "could not find extra subsidiary in /tmp/dcc" >&2
    docker exec "$NAME" ls -la /tmp/dcc >&2
    exit 1
fi
echo "extra_sub=$EXTRA_SUB"
docker exec "$NAME" /tmp/krb5-kswitch -c "DIR::/tmp/dcc/${EXTRA_SUB}"
echo "---- after Rust kswitch to extra ----"
MITE="$(docker exec "$NAME" klist -c DIR:/tmp/dcc)"
echo "$MITE"
echo "$MITE" | grep -q 'extra@KERBER.TEST'
RUSTE="$(docker exec "$NAME" /tmp/krb5-klist -c DIR:/tmp/dcc)"
echo "$RUSTE"
echo "$RUSTE" | grep -q 'extra@KERBER.TEST'

echo "==== R8 unknown type (Rust klist) ===="
set +e
UNK="$(docker exec "$NAME" /tmp/krb5-klist -c 'KEYRING:user:foo' 2>&1)"
urc=$?
set -e
echo "$UNK"
test "$urc" -ne 0
echo "$UNK" | grep -q 'Unknown credential cache type'
echo "$UNK" | grep -qv 'G8'

log "ccache.gate" "ok" ',"principal":"user@KERBER.TEST"'
exit 0
