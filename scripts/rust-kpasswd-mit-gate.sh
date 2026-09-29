#!/usr/bin/env bash
# Rust krb5-kpasswd against MIT kadmind (TCP 464). New password kinit; old fails.
# Rust krb5-kinit KEY_EXP with KRB5_NEW_PASSWORD against the same kadmind: stderr
# is byte-equal to 0d5fa7f4's on a full success (K1) and when the ccache write
# fails after the change (K2).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
need_bins krb5-kpasswd krb5-kinit

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kpasswd-mit-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "kpasswd.mit.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

stock_mit_kdc
mit_live_guard

docker exec -d "$NAME" kadmind
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',464),0.3)" 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    log "kpasswd.mit.gate" "error" ',"error":"MIT kadmind 464 did not listen"'
    exit 1
fi

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kpasswd" "$NAME":/tmp/krb5-kpasswd
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kinit" "$NAME":/tmp/krb5-kinit
docker exec "$NAME" chmod +x /tmp/krb5-kpasswd /tmp/krb5-kinit

echo "==== Rust kpasswd vs MIT kadmind ===="
docker exec -e KRB5_PASSWORD=userpassword -e KRB5_NEW_PASSWORD=mit-rust-pw \
    "$NAME" /tmp/krb5-kpasswd 127.0.0.1 user@KERBER.TEST
docker exec "$NAME" sh -c 'printf "mit-rust-pw\n" | kinit user@KERBER.TEST'
KLIST="$(docker exec "$NAME" klist)"
echo "$KLIST"
echo "$KLIST" | grep -q 'user@KERBER.TEST'
set +e
docker exec "$NAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
old=$?
set -e
if [ "$old" -eq 0 ]; then
    log "kpasswd.mit.gate" "error" ',"error":"old password still works"'
    exit 1
fi

# keyexp_run TAG PRINCIPAL CCACHE: Rust krb5-kinit with an expired password and
# KRB5_NEW_PASSWORD; stdout, stderr and rc land in /tmp/TAG.{out,err,rc}.
keyexp_run() {
    kadmin_q_try mit_kadmin_local "$NAME" -- -q "delprinc -force $2" >/dev/null 2>&1 
    kadmin_q_ok mit_kadmin_local "$NAME" -- -q "addprinc -pw exp-old -pwexpire 2020-01-01 $2" >/dev/null
    docker exec -e KRB5_PASSWORD=exp-old -e KRB5_NEW_PASSWORD=exp-new "$NAME" \
        sh -c "/tmp/krb5-kinit -c $3 $2@KERBER.TEST >/tmp/$1.out 2>/tmp/$1.err; echo \$? >/tmp/$1.rc"
    echo "$1: rc=$(docker exec "$NAME" cat "/tmp/$1.rc")"
    docker exec "$NAME" sed "s/^/  $1 stderr| /" "/tmp/$1.err"
}
# keyexp_stderr_is TAG TEXT: /tmp/TAG.err is byte-equal to TEXT (printf format).
keyexp_stderr_is() {
    docker exec "$NAME" sh -c "printf '$2' | cmp -s - /tmp/$1.err"
}
BANNER='Password expired.  You must change it now.\n'

echo "==== K1 Rust krb5-kinit KEY_EXP change, whole kinit succeeds: stderr is the banner alone ===="
keyexp_run s4kx1 s4kx1 /tmp/cc_s4kx1
[ "$(docker exec "$NAME" cat /tmp/s4kx1.rc)" = 0 ] || die "K1 krb5-kinit failed"
keyexp_stderr_is s4kx1 "$BANNER" || die "K1 stderr is not exactly the banner"
docker exec "$NAME" grep -q '^ok tgt=' /tmp/s4kx1.out || die "K1 stdout has no ok tgt= line"
docker exec "$NAME" sh -c 'printf "exp-new\n" | kinit -c /tmp/cc_s4kx1_mit s4kx1@KERBER.TEST' \
    || die "K1 MIT kinit with the new password failed"
echo "RUST_kinit_keyexp_banner_success"

echo "==== K2 Rust krb5-kinit KEY_EXP change, then the ccache write fails: banner, then the error ===="
keyexp_run s4kx2 s4kx2 /tmp/nonexistent-dir/cc
[ "$(docker exec "$NAME" cat /tmp/s4kx2.rc)" = 1 ] || die "K2 krb5-kinit did not fail on the ccache write"
keyexp_stderr_is s4kx2 "${BANNER}kinit failed: No such file or directory (os error 2)\n" \
    || die "K2 stderr differs from 0d5fa7f4 (banner, then kinit failed: No such file or directory)"
docker exec "$NAME" sh -c 'printf "exp-new\n" | kinit -c /tmp/cc_s4kx2_mit s4kx2@KERBER.TEST' \
    || die "K2 MIT kinit with the new password failed (the change did not land)"
echo "RUST_kinit_keyexp_banner_store_fail"

log "kpasswd.mit.gate" "ok" ',"principal":"user@KERBER.TEST","oracle":"mit-kadmind"'
exit 0
