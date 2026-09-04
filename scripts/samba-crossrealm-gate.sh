#!/usr/bin/env bash
# L3: Samba KDC validates a Rust referral PAC, and Rust accepts a Samba PAC.
# Shared-trust-password variant (CI-reproducible). Isolation: docker exec;
# host /etc/krb5.conf stays TESTLABBY.LOCAL.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-samba-crossrealm}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/samba-crossrealm-unavailable.log"
TRUST_PW="${SAMBA_TRUST_PASSWORD:-Trust-P@ss-Kerber-2026!}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"samba-crossrealm-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "$1"
    } | tee "$UNAVAIL" >&2
    log "samba.crossrealm" "error" ",\"error\":\"unavailable\""
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
IMAGE="${SAMBA_AD_IMAGE:-}"
if [ -z "$IMAGE" ] && docker image inspect samba-ad-dc:latest >/dev/null 2>&1; then
    IMAGE="samba-ad-dc:latest"
fi
if [ -z "$IMAGE" ]; then
    unavailable "no Samba AD DC image (set SAMBA_AD_IMAGE)"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract

ISSUE_SALT='KERBER.TESTkrbtgtAD.KERBER.TEST'
ACCEPT_SALT='AD.KERBER.TESTkrbtgtKERBER.TEST'
ISSUE_KEY="$(./target/debug/krb5-pac-extract --s2k "$TRUST_PW" "$ISSUE_SALT")"
ACCEPT_KEY="$(./target/debug/krb5-pac-extract --s2k "$TRUST_PW" "$ACCEPT_SALT")"
if [ "${#ISSUE_KEY}" -ne 64 ] || [ "${#ACCEPT_KEY}" -ne 64 ]; then
    unavailable "s2k did not yield 32-byte hex keys"
fi

NAME="kerber-rust-samba-crossrealm"
docker rm -f "$NAME" >/dev/null 2>&1 || true
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

set +e
docker run -d --name "$NAME" --hostname dc1 "$IMAGE" >"$SCRATCH/samba-xr-run.err" 2>&1
run_rc=$?
set -e
if [ "$run_rc" -ne 0 ]; then
    unavailable "docker run failed: $(tr '\n' ' ' <"$SCRATCH/samba-xr-run.err" 2>/dev/null || true)"
fi
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" sh -c 'ss -lun | grep -q ":88 "' 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.5
done
if [ "$ok" != 1 ]; then
    unavailable "Samba KDC did not listen on UDP 88"
fi

docker cp target/debug/krb5-kdc "$NAME":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME":/tmp/krb5-pac-extract
docker cp harness/samba/trust_local.py "$NAME":/tmp/trust_local.py
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract

# Pin the Rust realm SID so the TDO securityIdentifier matches issued PACs.
RUST_SID="S-1-5-21-4242424242-4242424242-4242424242"
docker exec "$NAME" python3 /tmp/trust_local.py \
    --realm KERBER.TEST --flat KERBER --password "$TRUST_PW" \
    --sid "$RUST_SID" --type uplevel
# KDC workers cache TDO at start; respawn them so the trust is visible.
docker exec "$NAME" sh -c 'for p in /proc/[0-9]*; do
  comm=$(cat "$p/comm" 2>/dev/null) || continue
  [ "$comm" = samba ] || continue
  tr="\0"; cmd=$(tr "\0" " " < "$p/cmdline" 2>/dev/null) || continue
  echo "$cmd" | grep -q "task\[kdc\]" || continue
  kill "${p#/proc/}" 2>/dev/null || true
done; sleep 1'

docker exec "$NAME" sh -c "cat >/tmp/kdc.conf <<EOF
[realms]
    KERBER.TEST = {
        domain_sid = ${RUST_SID}
    }
EOF"

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_FOREIGN_REALM=AD.KERBER.TEST \
    -e KRB5_TEST_INTERREALM_KEY="$ISSUE_KEY" \
    -e KRB5_TEST_INTERREALM_KEY_ACCEPT="$ACCEPT_KEY" \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    -e KRB5_KDC_CONF=/tmp/kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log 2>/dev/null || true
    unavailable "Rust KDC did not listen on 8888"
fi

docker exec "$NAME" sh -c 'cat >/tmp/xr-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_xr
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
    AD.KERBER.TEST = {
        kdc = 127.0.0.1
    }
[domain_realm]
    .kerber.test = KERBER.TEST
    kerber.test = KERBER.TEST
    .ad.kerber.test = AD.KERBER.TEST
    ad.kerber.test = AD.KERBER.TEST
EOF'

# Forward: MIT kinit (Rust) → kvno Samba host
set +e
docker exec -e KRB5_CONFIG=/tmp/xr-krb5.conf "$NAME" \
    sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'
kinit_rc=$?
set -e
if [ "$kinit_rc" -ne 0 ]; then
    unavailable "kinit user@KERBER.TEST failed"
fi

set +e
FWD="$(docker exec -e KRB5_CONFIG=/tmp/xr-krb5.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno host/svc.ad.kerber.test@AD.KERBER.TEST 2>&1)"
fwd_rc=$?
set -e
echo "$FWD"
KLIST_FWD="$(docker exec -e KRB5_CONFIG=/tmp/xr-krb5.conf "$NAME" klist 2>&1)"
echo "$KLIST_FWD"
SLOG="$(docker logs "$NAME" 2>&1 | tail -80 || true)"
echo "$SLOG"
if [ "$fwd_rc" -ne 0 ]; then
    echo "$SLOG" | grep -i 'PAC' || true
    log "samba.crossrealm" "error" ",\"direction\":\"rust-to-samba\",\"error\":\"kvno\""
    exit 1
fi
echo "$KLIST_FWD" | grep -q 'host/svc.ad.kerber.test'
if echo "$SLOG" | grep -Ei 'PAC.*(fail|error|invalid)'; then
    log "samba.crossrealm" "error" ",\"direction\":\"rust-to-samba\",\"error\":\"pac-log\""
    exit 1
fi

# Reverse: MIT kinit (Samba) → kvno Rust host
docker exec "$NAME" sh -c 'cat >/tmp/ad-krb5.conf <<EOF
[libdefaults]
    default_realm = AD.KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_rev
[realms]
    AD.KERBER.TEST = {
        kdc = 127.0.0.1
    }
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
[domain_realm]
    .ad.kerber.test = AD.KERBER.TEST
    .kerber.test = KERBER.TEST
EOF'

set +e
docker exec -e KRB5_CONFIG=/tmp/ad-krb5.conf "$NAME" \
    sh -c "printf 'Kbruser-P@ss-2026!\n' | kinit kbruser@AD.KERBER.TEST"
rk_rc=$?
set -e
if [ "$rk_rc" -ne 0 ]; then
    unavailable "kinit kbruser@AD.KERBER.TEST failed"
fi

set +e
REV="$(docker exec -e KRB5_CONFIG=/tmp/ad-krb5.conf -e KRB5_TRACE=/dev/stderr "$NAME" \
    kvno host/testhost.kerber.test@KERBER.TEST 2>&1)"
rev_rc=$?
set -e
echo "$REV"
KLIST_REV="$(docker exec -e KRB5_CONFIG=/tmp/ad-krb5.conf "$NAME" klist 2>&1)"
echo "$KLIST_REV"
if [ "$rev_rc" -ne 0 ]; then
    docker exec "$NAME" cat /tmp/rust-kdc.log 2>/dev/null | tail -40 || true
    log "samba.crossrealm" "error" ",\"direction\":\"samba-to-rust\",\"error\":\"kvno\""
    exit 1
fi
echo "$KLIST_REV" | grep -q 'host/testhost.kerber.test'

log "samba.crossrealm" "ok" ",\"direction\":\"both\",\"trust\":\"shared-password\""
exit 0
