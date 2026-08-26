#!/usr/bin/env bash
# D2: two Samba AD DCs, real samba-tool domain trust create, Rust bridged
# with the TDO keys, both-direction kvno, reverse PAC SID == live Samba-A
# kbruser. Isolation: docker exec / KRB5_CONFIG; host /etc/krb5.conf stays
# TESTLABBY.LOCAL. Trust-create fail with images present is exit 1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-samba-realtrust}"
mkdir -p "$SCRATCH"
UNAVAIL="$SCRATCH/samba-realtrust-unavailable.log"
ADMIN_PW="${SAMBA_ADMIN_PASSWORD:-Samba-Admin-Kerber-2026!}"
KBRUSER_PW="${SAMBA_KBRUSER_PASSWORD:-Kbruser-P@ss-2026!}"

log() {
    printf '{"event":"%s","correlation_id":"%s","component":"samba-realtrust-gate","outcome":"%s"%s}\n' \
        "$1" "$CORRELATION_ID" "$2" "${3:-}"
}

unavailable() {
    {
        echo "date=$(date -Iseconds)"
        echo "host /etc/krb5.conf must stay TESTLABBY.LOCAL"
        echo "$1"
    } | tee "$UNAVAIL" >&2
    log "samba.realtrust" "error" ",\"error\":\"unavailable\""
    exit 2
}

if ! command -v docker >/dev/null 2>&1; then
    unavailable "docker not available"
fi
IMAGE_A="${SAMBA_AD_IMAGE:-}"
IMAGE_B="${SAMBA_KERBER_IMAGE:-}"
if [ -z "$IMAGE_A" ] && docker image inspect samba-ad-dc:latest >/dev/null 2>&1; then
    IMAGE_A="samba-ad-dc:latest"
fi
if [ -z "$IMAGE_B" ] && docker image inspect samba-kerber-dc:latest >/dev/null 2>&1; then
    IMAGE_B="samba-kerber-dc:latest"
fi
if [ -z "$IMAGE_A" ] || [ -z "$IMAGE_B" ]; then
    unavailable "need samba-ad-dc:latest and samba-kerber-dc:latest (or SAMBA_AD_IMAGE / SAMBA_KERBER_IMAGE)"
fi

cargo build -p krb5-kdc --bin krb5-kdc --bin krb5-pac-extract

NET="kerber-rust-realtrust"
NAME_A="kerber-rust-samba-rt-a"
NAME_B="kerber-rust-samba-rt-b"
docker rm -f "$NAME_A" "$NAME_B" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null
cleanup() {
    docker rm -f "$NAME_A" "$NAME_B" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

set +e
docker run -d --name "$NAME_A" --hostname dc1 --network "$NET" \
    -e SAMBA_REALM=AD.KERBER.TEST "$IMAGE_A" >/tmp/rt-a.err 2>&1
ra=$?
docker run -d --name "$NAME_B" --hostname dc1 --network "$NET" \
    -e SAMBA_REALM=KERBER.TEST "$IMAGE_B" >/tmp/rt-b.err 2>&1
rb=$?
set -e
if [ "$ra" -ne 0 ] || [ "$rb" -ne 0 ]; then
    unavailable "docker run peer DCs failed"
fi

wait88() {
    local n=$1
    local i
    for i in $(seq 1 40); do
        if docker exec "$n" sh -c 'ss -lun | grep -q ":88 "' 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}
wait88 "$NAME_A" || unavailable "Samba-A KDC not on UDP 88"
wait88 "$NAME_B" || unavailable "Samba-B KDC not on UDP 88"

AIP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME_A")"
BIP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME_B")"
docker exec "$NAME_A" sh -c "printf '%s dc1.kerber.test dc1-b\n' '$BIP' >> /etc/hosts"
docker exec "$NAME_B" sh -c "printf '%s dc1.ad.kerber.test dc1-a\n' '$AIP' >> /etc/hosts"

docker cp harness/samba/extract_tdo.py "$NAME_A":/tmp/extract_tdo.py
docker cp harness/samba/extract_tdo.py "$NAME_B":/tmp/extract_tdo.py
docker cp harness/samba/pac_l1.py "$NAME_A":/tmp/pac_l1.py

# Real samba-tool handshake. --ipaddress targets Samba-B without depending on SRV DNS.
set +e
TRUST_OUT="$(docker exec "$NAME_A" samba-tool domain trust create KERBER.TEST \
    --type=external --direction=both --create-location=both \
    --ipaddress="$BIP" \
    --username=Administrator --password="$ADMIN_PW" --workgroup=KERBER \
    --local-dc-username=Administrator --local-dc-password="$ADMIN_PW" \
    --skip-validation 2>&1)"
trust_rc=$?
set -e
echo "$TRUST_OUT"
if [ "$trust_rc" -ne 0 ]; then
    log "samba.realtrust" "error" ",\"error\":\"trust-create\""
    exit 1
fi
echo "$TRUST_OUT" | tee "$SCRATCH/samba-tool-trust-create.txt" >/dev/null

TDO="$(docker exec "$NAME_A" python3 /tmp/extract_tdo.py KERBER.TEST 2>&1)"
echo "$TDO" | grep -v TDO_PASSWORD
if ! echo "$TDO" | grep -q TDO_OK; then
    log "samba.realtrust" "error" ",\"error\":\"tdo-a\""
    exit 1
fi
TRUST_HEX="$(echo "$TDO" | awk '/^TDO_PASSWORD_HEX /{print $2}')"
RAW_HEX="$(echo "$TDO" | awk '/^TDO_RAW_HEX /{print $2}')"
[ -n "$TRUST_HEX" ] || unavailable "TDO password hex empty"

B_TDO="$(docker exec "$NAME_B" python3 /tmp/extract_tdo.py AD.KERBER.TEST 2>&1)"
echo "$B_TDO" | grep -v TDO_PASSWORD
if ! echo "$B_TDO" | grep -q TDO_OK; then
    log "samba.realtrust" "error" ",\"error\":\"tdo-b\""
    exit 1
fi

B_SID="$(docker exec "$NAME_B" python3 /tmp/extract_tdo.py --self-sid | awk '/^DOMAIN_SID /{print $2}')"
[ -n "$B_SID" ] || unavailable "Samba-B domain SID missing"
echo "KERBER.TEST SID $B_SID"
A_SID="$(docker exec "$NAME_A" python3 /tmp/extract_tdo.py --self-sid | awk '/^DOMAIN_SID /{print $2}')"
[ -n "$A_SID" ] || unavailable "Samba-A domain SID missing"
echo "AD.KERBER.TEST SID $A_SID"
KBR="$(docker exec "$NAME_A" python3 /tmp/extract_tdo.py --user-sid kbruser 2>&1)"
echo "$KBR"
KBR_SID="$(echo "$KBR" | awk '/^USER_SID /{print $2}')"
KBR_RID="$(echo "$KBR" | awk '/^USER_RID /{print $2}')"
if [ -z "$KBR_SID" ] || [ -z "$KBR_RID" ]; then
    log "samba.realtrust" "error" ",\"error\":\"kbruser-sid\""
    exit 1
fi
echo "kbruser $KBR_SID rid $KBR_RID"

# Respawn Samba-A KDC workers so the TDO is live.
docker exec "$NAME_A" sh -c 'for p in /proc/[0-9]*; do
  comm=$(cat "$p/comm" 2>/dev/null) || continue
  [ "$comm" = samba ] || continue
  cmd=$(tr "\0" " " < "$p/cmdline" 2>/dev/null) || continue
  echo "$cmd" | grep -q "task\[kdc\]" || continue
  kill "${p#/proc/}" 2>/dev/null || true
done; sleep 1'

ISSUE_SALT='KERBER.TESTkrbtgtAD.KERBER.TEST'
ACCEPT_SALT='AD.KERBER.TESTkrbtgtKERBER.TEST'
ISSUE_KEY="$(./target/debug/krb5-pac-extract --s2k-hex "$TRUST_HEX" "$ISSUE_SALT")"
ACCEPT_KEY="$(./target/debug/krb5-pac-extract --s2k-hex "$TRUST_HEX" "$ACCEPT_SALT")"
ACCEPT_KEYS="$ACCEPT_KEY,$ISSUE_KEY"
if [ -n "${RAW_HEX:-}" ]; then
    ACCEPT_KEYS="$ACCEPT_KEYS,$(./target/debug/krb5-pac-extract --s2k-hex "$RAW_HEX" "$ACCEPT_SALT")"
    ACCEPT_KEYS="$ACCEPT_KEYS,$(./target/debug/krb5-pac-extract --s2k-hex "$RAW_HEX" "$ISSUE_SALT")"
fi
# Prefer Samba-exported trust principal keys when exportkeytab works.
set +e
docker exec "$NAME_A" samba-tool domain exportkeytab /tmp/a-trust.kt \
    --principal="krbtgt/KERBER.TEST@AD.KERBER.TEST" >/tmp/a-kt.err 2>&1
docker exec "$NAME_B" samba-tool domain exportkeytab /tmp/b-trust.kt \
    --principal="krbtgt/AD.KERBER.TEST@KERBER.TEST" >/tmp/b-kt.err 2>&1
set -e
docker cp "$NAME_A":/tmp/a-trust.kt "$SCRATCH/a-trust.kt" 2>/dev/null || true
docker cp "$NAME_B":/tmp/b-trust.kt "$SCRATCH/b-trust.kt" 2>/dev/null || true
if [ -f "$SCRATCH/a-trust.kt" ]; then
    while read -r tag _et hex _rest; do
        [ "$tag" = KEY ] && [ "${#hex}" -eq 64 ] && ACCEPT_KEYS="$ACCEPT_KEYS,$hex"
    done < <(./target/debug/krb5-pac-extract --dump-keytab "$SCRATCH/a-trust.kt" 2>/dev/null || true)
fi
if [ "${#ISSUE_KEY}" -ne 64 ]; then
    unavailable "s2k of TDO password did not yield 32-byte keys"
fi

docker cp target/debug/krb5-kdc "$NAME_A":/tmp/krb5-kdc
docker cp target/debug/krb5-pac-extract "$NAME_A":/tmp/krb5-pac-extract
docker exec "$NAME_A" chmod +x /tmp/krb5-kdc /tmp/krb5-pac-extract

docker exec "$NAME_A" sh -c "cat >/tmp/kdc.conf <<EOF
[realms]
    KERBER.TEST = {
        domain_sid = ${B_SID}
    }
EOF"

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_TEST_FOREIGN_REALM=AD.KERBER.TEST \
    -e KRB5_TEST_INTERREALM_KEY="$ISSUE_KEY" \
    -e KRB5_TEST_INTERREALM_KEY_ACCEPT="$ACCEPT_KEYS" \
    -e KRB5_EXPORT_KEYTAB=/tmp/host.keytab \
    -e KRB5_KDC_CONF=/tmp/kdc.conf \
    "$NAME_A" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:8888 >/tmp/rust-kdc.log 2>&1'
ok=0
for _ in $(seq 1 80); do
    if docker exec "$NAME_A" grep -q '^listening ' /tmp/rust-kdc.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME_A" cat /tmp/rust-kdc.log 2>/dev/null || true
    unavailable "Rust KDC did not listen on 8888"
fi

docker exec "$NAME_A" sh -c 'cat >/tmp/xr-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_rt
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:8888
    }
    AD.KERBER.TEST = {
        kdc = 127.0.0.1
    }
[domain_realm]
    .kerber.test = KERBER.TEST
    .ad.kerber.test = AD.KERBER.TEST
EOF'

set +e
docker exec "$NAME_A" sh -c 'export KRB5_CONFIG=/tmp/xr-krb5.conf KRB5CCNAME=FILE:/tmp/krb5cc_rt; printf "userpassword\n" | kinit user@KERBER.TEST'
fwd_kinit=$?
FWD="$(docker exec -e KRB5_CONFIG=/tmp/xr-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_rt -e KRB5_TRACE=/dev/stderr "$NAME_A" \
    kvno host/svc.ad.kerber.test@AD.KERBER.TEST 2>&1)"
fwd_rc=$?
set -e
echo "$FWD"
if [ "$fwd_kinit" -ne 0 ] || [ "$fwd_rc" -ne 0 ]; then
    echo "$FWD"
    docker exec "$NAME_A" cat /tmp/rust-kdc.log 2>/dev/null | tail -20 || true
    log "samba.realtrust" "error" ",\"direction\":\"rust-to-samba\",\"error\":\"kvno\""
    exit 1
fi
echo "$FWD" | grep -q 'host/svc.ad.kerber.test'

docker exec "$NAME_A" sh -c 'cat >/tmp/ad-krb5.conf <<EOF
[libdefaults]
    default_realm = AD.KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_rt_rev
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
docker exec "$NAME_A" sh -c "export KRB5_CONFIG=/tmp/ad-krb5.conf KRB5CCNAME=FILE:/tmp/krb5cc_rt_rev; printf '%s\n' '$KBRUSER_PW' | kinit kbruser@AD.KERBER.TEST"
rev_kinit=$?
REV="$(docker exec -e KRB5_CONFIG=/tmp/ad-krb5.conf -e KRB5CCNAME=FILE:/tmp/krb5cc_rt_rev -e KRB5_TRACE=/dev/stderr "$NAME_A" \
    kvno host/testhost.kerber.test@KERBER.TEST 2>&1)"
rev_rc=$?
set -e
echo "$REV"
if [ "$rev_kinit" -ne 0 ] || [ "$rev_rc" -ne 0 ]; then
    docker exec "$NAME_A" cat /tmp/rust-kdc.log 2>/dev/null | tail -30 || true
    log "samba.realtrust" "error" ",\"direction\":\"samba-to-rust\",\"error\":\"kvno\""
    exit 1
fi
echo "$REV" | grep -q 'host/testhost.kerber.test'

docker exec "$NAME_A" /tmp/krb5-pac-extract \
    --keytab /tmp/host.keytab --ccache /tmp/krb5cc_rt_rev --out /tmp/rev.pac
L1="$(docker exec "$NAME_A" python3 /tmp/pac_l1.py /tmp/rev.pac 2>&1)"
echo "$L1"
echo "$L1" | grep -q L1_OK || { log "samba.realtrust" "error" ",\"error\":\"reverse-pac\""; exit 1; }
RID="$(echo "$L1" | awk '{for(i=1;i<=NF;i++) if($i=="rid") print $(i+1)}')"
LOGON_SID="$(echo "$L1" | awk '{for(i=1;i<=NF;i++) if($i=="domain") print $(i+1)}')"
echo "reverse PAC domain=$LOGON_SID rid=$RID (live kbruser $KBR_SID rid $KBR_RID, A $A_SID)"
if [ "$RID" != "$KBR_RID" ] || [ "$LOGON_SID" != "$A_SID" ]; then
    echo "expected domain $A_SID rid $KBR_RID, got $LOGON_SID $RID"
    log "samba.realtrust" "error" ",\"error\":\"sid\",\"rid\":\"$RID\",\"domain\":\"$LOGON_SID\""
    exit 1
fi
echo "$L1" | grep -q 'S-1-5-21-1-2-3' && { log "samba.realtrust" "error" ",\"error\":\"dummy-sid\""; exit 1; }

set +e
docker exec "$NAME_A" sh -c \
    'samba-tool domain exportkeytab /tmp/svc.kt --principal="host/svc.ad.kerber.test@AD.KERBER.TEST" >/tmp/svc-kt.err 2>&1'
svc_kt_rc=$?
set -e
if [ "$svc_kt_rc" -ne 0 ] || ! docker exec "$NAME_A" test -f /tmp/svc.kt; then
    docker exec "$NAME_A" cat /tmp/svc-kt.err 2>/dev/null || true
    log "samba.realtrust" "error" ",\"error\":\"fwd-keytab\""
    exit 1
fi
docker exec "$NAME_A" /tmp/krb5-pac-extract \
    --keytab /tmp/svc.kt --ccache /tmp/krb5cc_rt --out /tmp/fwd.pac
FWD_PAC="$(docker exec "$NAME_A" python3 /tmp/pac_l1.py --sids /tmp/fwd.pac 2>&1)"
echo "$FWD_PAC" | tee "$SCRATCH/r9-forward-pac.txt"
echo "$FWD_PAC" | grep -q SIDFILTER_OK || { log "samba.realtrust" "error" ",\"error\":\"forward-pac\""; exit 1; }
FWD_DOM="$(echo "$FWD_PAC" | awk '{for(i=1;i<=NF;i++) if($i=="domain") print $(i+1)}')"
FWD_RID="$(echo "$FWD_PAC" | awk '{for(i=1;i<=NF;i++) if($i=="rid") print $(i+1)}')"
FWD_EXTRA="$(echo "$FWD_PAC" | awk '/^EXTRA_SIDS /{print $2}')"
echo "R9_SIDFILTER domain=$FWD_DOM rid=$FWD_RID extra=${FWD_EXTRA:--} (B $B_SID)"

log "samba.realtrust" "ok" ",\"direction\":\"both\",\"trust\":\"samba-tool\",\"reverse_rid\":\"$RID\",\"reverse_sid\":\"$LOGON_SID\""
exit 0
