#!/usr/bin/env bash
# MIT 1.22.2 kinit -R / kinit -p vs Rust KDC. Isolated: never touches
# host /etc/krb5.conf.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc krb5-kadmind

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-renew-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-renew-gate}"
mkdir -p "$SCRATCH"

need_image

shell_container

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kadmind

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" sh -c '/tmp/krb5-kdc --test-realm 127.0.0.1:88 >/tmp/kdc.log 2>&1'

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
    log "renew.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    "$NAME" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind.log 2>&1'
ok=0
for _ in $(seq 1 40); do
    if docker exec "$NAME" grep -q '^listening ' /tmp/kadmind.log 2>/dev/null; then
        ok=1
        break
    fi
    sleep 0.25
done
if [ "$ok" != 1 ]; then
    docker exec "$NAME" cat /tmp/kadmind.log >&2 || true
    log "renew.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/renew-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_renew
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

kadmin_q() {
    docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

echo "==== kinit admin ===="
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'

echo "==== addprinc renewuser; four-term defaults ===="
kadmin_q 'addprinc -pw renew-secret renewuser'
KRBTGT_P="$(kadmin_q 'getprinc krbtgt/KERBER.TEST')"
USER_P="$(kadmin_q 'getprinc renewuser')"
echo "$KRBTGT_P"
echo "$USER_P"
# New-principal default copies realm policy (7d), so maxrenewlife is not 0.
echo "$KRBTGT_P" | grep -E 'Maximum renewable life:' | grep -qvE '0 days 00:00:00'
echo "$USER_P" | grep -E 'Maximum renewable life:' | grep -qvE '0 days 00:00:00'
kadmin_q 'modprinc -maxrenewlife "7 days" renewuser'
kadmin_q 'modprinc -maxrenewlife "7 days" krbtgt/KERBER.TEST'

echo "==== MIT kinit -r 7d -l 10h (renew until ≈ start + 7d) ===="
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -r 7d -l 10h renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -r failed"'
    exit 1
fi
BEFORE="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$BEFORE"
echo "$BEFORE" | grep -q 'renewuser@KERBER.TEST'
FLAGBITS="$(echo "$BEFORE" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "flagbits=$FLAGBITS"
echo "$FLAGBITS" | grep -q R
EXP1="$(echo "$BEFORE" | awk '/krbtgt\//{print $3, $4; exit}')"
REN1="$(echo "$BEFORE" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "exp1=$EXP1 renew1=$REN1"
[ -n "$EXP1" ] && [ -n "$REN1" ]
START1="$(echo "$BEFORE" | awk '/krbtgt\//{print $1, $2; exit}')"
echo "start1=$START1"
S_UNIX="$(date -d "$START1" +%s)"
R_UNIX="$(date -d "$REN1" +%s)"
DELTA=$((R_UNIX - S_UNIX))
echo "renew_delta_secs=$DELTA"
test "$DELTA" -ge 590400
test "$DELTA" -le 619200

sleep 2 # proto: ticket age
echo "==== MIT kinit -R ===="
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -R failed"'
    exit 1
fi
AFTER="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$AFTER"
EXP2="$(echo "$AFTER" | awk '/krbtgt\//{print $3, $4; exit}')"
REN2="$(echo "$AFTER" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "exp2=$EXP2 renew2=$REN2"
[ "$REN1" = "$REN2" ]
[ "$EXP1" != "$EXP2" ]
FLAG2="$(echo "$AFTER" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "flagbits2=$FLAG2"
echo "$FLAG2" | grep -q R

echo "==== DISALLOW_RENEWABLE: kinit -R strips R ===="
kadmin_q 'modprinc -allow_renewable renewuser'
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -R after DISALLOW_RENEWABLE failed"'
    exit 1
fi
STRIP="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$STRIP"
STRIPBITS="$(echo "$STRIP" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "stripbits=$STRIPBITS"
echo "$STRIPBITS" | grep -qv R
if echo "$STRIP" | grep -q 'renew until'; then
    echo "DISALLOW_RENEWABLE renew kept renew until" >&2
    exit 1
fi

echo "==== second kinit -R after strip must fail ===="
AGAIN="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R 2>&1 || true)"
echo "$AGAIN"
echo "$AGAIN" | grep -qiE "can't fulfill requested option|BADOPTION"
if echo "$AGAIN" | grep -qiE 'Authenticated|Ticket cache'; then
    echo "second kinit -R after strip succeeded" >&2
    exit 1
fi

echo "==== MIT kinit -p shows P ===="
kadmin_q 'modprinc +allow_renewable renewuser'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -p renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -p failed"'
    exit 1
fi
PFLAGS="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$PFLAGS"
PBITS="$(echo "$PFLAGS" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "pbits=$PBITS"
echo "$PBITS" | grep -q P

echo "==== NON-RENEWABLE TICKET: kvno after kinit -r vs -allow_renewable (rust) ===="
kadmin_q 'addprinc -randkey host/norenew.kerber.test'
kadmin_q 'modprinc -allow_renewable host/norenew.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -r 7d renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -r before NON-RENEWABLE rust failed"'
    exit 1
fi
set +e
NORENEW_RUST="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" kvno host/norenew.kerber.test 2>&1)"
set -e
echo "$NORENEW_RUST"
echo "$NORENEW_RUST" | grep -qF "KDC policy rejects request" || {
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"rust kvno against -allow_renewable did not POLICY"'
    exit 1
}

echo "==== NON-RENEWABLE TICKET: kvno after kinit -r vs -allow_renewable (mit) ===="
MITNAME="kerber-rust-renew-mit-oracle"
_saved=$NAME
stock_mit_kdc "$MITNAME"
MITNAME=$NAME
NAME=$_saved
if [ "${KERBER_LIVE:-}" = 1 ]; then
    mit_conf_snapshot "$MITNAME"
    register_cleanup "mit_conf_restore '$MITNAME'"
fi
docker exec "$MITNAME" kadmin.local -q "addprinc -randkey host/norenew.kerber.test"
docker exec "$MITNAME" kadmin.local -q "modprinc -allow_renewable host/norenew.kerber.test"
docker exec "$MITNAME" sh -c 'cat >/tmp/renew-mit-oracle.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_renew_mit
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOF'
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -r 7d user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT kinit -r before NON-RENEWABLE failed"'
    exit 1
fi
set +e
NORENEW_MIT="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" kvno host/norenew.kerber.test 2>&1)"
set -e
echo "$NORENEW_MIT"
echo "$NORENEW_MIT" | grep -qF "KDC policy rejects request" || {
    log "renew.gate" "error" ',"error":"MIT kvno against -allow_renewable did not POLICY"'
    exit 1
}

echo "==== MIT kinit -p shows P (mit oracle) ===="
docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -p user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT oracle kinit -p failed"'
    exit 1
fi
MIT_PFLAGS="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" klist -f)"
echo "$MIT_PFLAGS"
MIT_PBITS="$(echo "$MIT_PFLAGS" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "mit_pbits=$MIT_PBITS"
echo "$MIT_PBITS" | grep -q P || {
    log "renew.gate" "error" ',"error":"MIT oracle kinit -p missing P"'
    exit 1
}

echo "==== max_renewable_life 0: renew until = start; kinit -R is 32 (rust) ===="
kadmin_q 'modprinc -maxrenewlife 0 renewuser'
ZERO_P="$(kadmin_q 'getprinc renewuser')"
echo "$ZERO_P"
echo "$ZERO_P" | grep -E 'Maximum renewable life:' | grep -qE '0 days 00:00:00'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -r 7d renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -r after maxrenewlife 0 failed"'
    exit 1
fi
ZERO="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$ZERO"
ZSTART="$(echo "$ZERO" | awk '/krbtgt\//{print $1, $2; exit}')"
ZREN="$(echo "$ZERO" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "zero_start=$ZSTART zero_renew=$ZREN"
ZDELTA=$(($(date -d "$ZREN" +%s) - $(date -d "$ZSTART" +%s)))
echo "zero_renew_delta_secs=$ZDELTA"
test "$ZDELTA" -ge 0
test "$ZDELTA" -le 120
sleep 2 # proto: ticket age
set +e
ZAGAIN="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kinit -R 2>&1)"
set -e
echo "$ZAGAIN"
echo "$ZAGAIN" | grep -qiE 'expired|TKT_EXPIRED' || {
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -R after maxrenewlife 0 did not expire"'
    exit 1
}

echo "==== max_renewable_life 1 day (rust kadm5 write) ===="
kadmin_q 'modprinc -maxrenewlife "1 day" renewuser'
ONE_P="$(kadmin_q 'getprinc renewuser')"
echo "$ONE_P"
echo "$ONE_P" | grep -E 'Maximum renewable life:' | grep -qE '1 day 00:00:00'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -r 7d renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit -r after maxrenewlife 1d failed"'
    exit 1
fi
ONED="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$ONED"
OSTART="$(echo "$ONED" | awk '/krbtgt\//{print $1, $2; exit}')"
OREN="$(echo "$ONED" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "one_start=$OSTART one_renew=$OREN"
ODELTA=$(($(date -d "$OREN" +%s) - $(date -d "$OSTART" +%s)))
echo "one_renew_delta_secs=$ODELTA"
test "$ODELTA" -ge 85200
test "$ODELTA" -le 87600

echo "==== -requires_preauth TGT has no A; +requires_preauth host is NO PREAUTH (rust) ===="
kadmin_q 'modprinc -requires_preauth renewuser'
kadmin_q 'modprinc +requires_preauth host/testhost.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"kinit after -requires_preauth failed"'
    exit 1
fi
NA="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$NA"
NABITS="$(echo "$NA" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "nabits=$NABITS"
echo "$NABITS" | grep -qv A || {
    log "renew.gate" "error" ',"error":"rust -requires_preauth TGT still has A"'
    exit 1
}
set +e
NOPA="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$NOPA"
echo "$NOPA" | grep -qiE 'Generic error|KDC policy rejects request|NO PREAUTH' || {
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"rust kvno against +requires_preauth host did not fail"'
    exit 1
}
docker exec "$NAME" grep -q 'NO PREAUTH' /tmp/kdc.log || {
    docker exec "$NAME" cat /tmp/kdc.log >&2 || true
    log "renew.gate" "error" ',"error":"rust KDC log missing NO PREAUTH"'
    exit 1
}

echo "==== max_renewable_life 0 / 1 day / no A (mit oracle) ===="
docker exec "$MITNAME" kadmin.local -q 'modprinc -maxrenewlife 0 user'
MZERO_P="$(docker exec "$MITNAME" kadmin.local -q 'getprinc user')"
echo "$MZERO_P"
echo "$MZERO_P" | grep -E 'Maximum renewable life:' | grep -qE '0 days 00:00:00'
docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -r 7d user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT kinit -r after maxrenewlife 0 failed"'
    exit 1
fi
MZERO="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" klist -f)"
echo "$MZERO"
MZSTART="$(echo "$MZERO" | awk '/krbtgt\//{print $1, $2; exit}')"
MZREN="$(echo "$MZERO" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "mit_zero_start=$MZSTART mit_zero_renew=$MZREN"
MZDELTA=$(($(date -d "$MZREN" +%s) - $(date -d "$MZSTART" +%s)))
echo "mit_zero_renew_delta_secs=$MZDELTA"
test "$MZDELTA" -ge 0
test "$MZDELTA" -le 120
sleep 2 # proto: ticket age
set +e
MZAGAIN="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kinit -R 2>&1)"
set -e
echo "$MZAGAIN"
echo "$MZAGAIN" | grep -qiE 'expired|TKT_EXPIRED' || {
    log "renew.gate" "error" ',"error":"MIT kinit -R after maxrenewlife 0 did not expire"'
    exit 1
}
docker exec "$MITNAME" kadmin.local -q 'modprinc -maxrenewlife "1 day" user'
MONE_P="$(docker exec "$MITNAME" kadmin.local -q 'getprinc user')"
echo "$MONE_P"
echo "$MONE_P" | grep -E 'Maximum renewable life:' | grep -qE '1 day 00:00:00'
docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -r 7d user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT kinit -r after maxrenewlife 1d failed"'
    exit 1
fi
MONED="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" klist -f)"
echo "$MONED"
MOSTART="$(echo "$MONED" | awk '/krbtgt\//{print $1, $2; exit}')"
MOREN="$(echo "$MONED" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
echo "mit_one_start=$MOSTART mit_one_renew=$MOREN"
MODELT=$(($(date -d "$MOREN" +%s) - $(date -d "$MOSTART" +%s)))
echo "mit_one_renew_delta_secs=$MODELT"
test "$MODELT" -ge 85200
test "$MODELT" -le 87600
docker exec "$MITNAME" kadmin.local -q 'modprinc -requires_preauth user'
docker exec "$MITNAME" kadmin.local -q 'modprinc +requires_preauth host/testhost.kerber.test'
docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit user@KERBER.TEST'; then
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT kinit after -requires_preauth failed"'
    exit 1
fi
MNA="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" klist -f)"
echo "$MNA"
MNABITS="$(echo "$MNA" | awk -F'Flags: ' '/Flags:/{print $2}' | tail -1 | tr -d '[:space:]')"
echo "mit_nabits=$MNABITS"
echo "$MNABITS" | grep -qv A || {
    log "renew.gate" "error" ',"error":"MIT -requires_preauth TGT still has A"'
    exit 1
}
set +e
MNOPA="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" kvno host/testhost.kerber.test 2>&1)"
set -e
echo "$MNOPA"
echo "$MNOPA" | grep -qiE 'Generic error|KDC policy rejects request|NO PREAUTH' || {
    log "renew.gate" "error" ',"error":"MIT kvno against +requires_preauth host did not fail"'
    exit 1
}
MITLOG="$(docker exec "$MITNAME" sh -c 'cat /var/log/krb5kdc.log /tmp/krb5kdc.log 2>/dev/null; true')"
MITLOG="$MITLOG$(docker logs "$MITNAME" 2>&1)"
echo "$MITLOG$MNOPA" | grep -q 'NO PREAUTH' || {
    echo "$MITLOG" >&2
    log "renew.gate" "error" ',"error":"MIT KDC log and kvno missing NO PREAUTH"'
    exit 1
}

echo "==== Z7.1 omitted max_renewable_life is a 7d realm cap (kdc/main.c:316-319) ===="
# Stock kdc.conf writes max_renewable_life = 7d. Strip only that relation,
# set max_life = 1h, restart both KDCs, set principals to 10 d, then
# kinit -r 8d -l 1h. MIT's realm_maxrlife default is 7 d, so 8 d is
# clipped to 7 d. Do not substring-match max_life when stripping (z66
# pitfall).
z71_profile() {
    docker exec "$1" sh -c '
python3 - <<PY
from pathlib import Path
src_path = Path("/etc/krb5kdc/kdc.conf")
if src_path.exists():
    src = src_path.read_text().splitlines(True)
    out = []
    seen_life = False
    for ln in src:
        key = ln.split("=", 1)[0].strip()
        if key == "max_renewable_life":
            continue
        if key == "max_life":
            indent = ln[: len(ln) - len(ln.lstrip())]
            out.append(f"{indent}max_life = 1h\n")
            seen_life = True
            continue
        out.append(ln)
    if not seen_life:
        text = "".join(out)
        needle = "    }\n"
        insert = "        max_life = 1h\n"
        if needle in text:
            text = text.replace(needle, insert + needle, 1)
        else:
            text += "[realms]\n    KERBER.TEST = {\n        max_life = 1h\n    }\n"
        Path("/tmp/z71-kdc.conf").write_text(text)
    else:
        Path("/tmp/z71-kdc.conf").write_text("".join(out))
else:
    Path("/tmp/z71-kdc.conf").write_text(
        "[realms]\n    KERBER.TEST = {\n        max_life = 1h\n    }\n"
    )
PY
test -f /tmp/z71-kdc.conf
if grep -E "^[[:space:]]*max_renewable_life[[:space:]]*=" /tmp/z71-kdc.conf; then
    echo "z71-kdc.conf still has max_renewable_life" >&2
    exit 1
fi
grep -q "max_life = 1h" /tmp/z71-kdc.conf
'
}

z71_wait_port() {
    local ctn=$1 want=$2
    for _ in $(seq 1 40); do
        if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
            [ "$want" = up ] && return 0
        else
            [ "$want" = down ] && return 0
        fi
        sleep 0.25
    done
    return 1
}

z71_kill_comm() {
    local ctn=$1 comm=$2
    docker exec "$ctn" sh -c '
comm_want='"$comm"'
for f in /proc/[0-9]*/comm; do
    [ -f "$f" ] || continue
    read -r name < "$f" || continue
    if [ "$name" = "$comm_want" ]; then
        pid=${f#/proc/}
        pid=${pid%/comm}
        kill -9 "$pid" 2>/dev/null || true
    fi
done
'
}

z71_profile "$NAME"
z71_profile "$MITNAME"
z71_kill_comm "$NAME" krb5-kdc
if ! z71_wait_port "$NAME" down; then
    docker exec "$NAME" cat /tmp/kdc.log /tmp/kdc-z71.log >&2 || true
    log "renew.gate" "error" ',"error":"Rust KDC still listening after z71 kill"'
    exit 1
fi
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_PROFILE=/tmp/z71-kdc.conf \
    "$NAME" sh -c '/tmp/krb5-kdc 127.0.0.1:88 >/tmp/kdc-z71.log 2>&1'
if ! z71_wait_port "$NAME" up; then
    docker exec "$NAME" cat /tmp/kdc-z71.log >&2 || true
    log "renew.gate" "error" ',"error":"Rust KDC did not listen for z71"'
    exit 1
fi
z71_kill_comm "$MITNAME" krb5kdc
if ! z71_wait_port "$MITNAME" down; then
    docker exec "$MITNAME" cat /tmp/krb5kdc-z71.log >&2 || true
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT KDC still listening after z71 kill"'
    exit 1
fi
docker exec -d -e KRB5_KDC_PROFILE=/tmp/z71-kdc.conf \
    "$MITNAME" sh -c 'krb5kdc -n >/tmp/krb5kdc-z71.log 2>&1'
if ! z71_wait_port "$MITNAME" up; then
    docker exec "$MITNAME" cat /tmp/krb5kdc-z71.log >&2 || true
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT KDC did not listen for z71"'
    exit 1
fi

# Principals at 10 d so they do not clip first; -r 8d is above the 7 d
# realm cap (`kdc/main.c:316-319` `KRB5_KDB_MAX_RLIFE`).
kadmin_q 'modprinc -maxrenewlife 10d renewuser'
kadmin_q 'modprinc -maxrenewlife 10d krbtgt/KERBER.TEST'
docker exec "$MITNAME" kadmin.local -q 'modprinc -maxrenewlife 10d user'
docker exec "$MITNAME" kadmin.local -q 'modprinc -maxrenewlife 10d krbtgt/KERBER.TEST'

docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf \
    "$NAME" sh -c 'printf "renew-secret\n" | kinit -l 1h -r 8d renewuser@KERBER.TEST'; then
    docker exec "$NAME" cat /tmp/kdc-z71.log >&2 || true
    log "renew.gate" "error" ',"error":"Rust kinit -r 8d after omitted rlife failed"'
    exit 1
fi
RLIST="$(docker exec -e KRB5_CONFIG=/tmp/renew-krb5.conf "$NAME" klist -f)"
echo "$RLIST"
RSTART="$(echo "$RLIST" | awk '/krbtgt\//{print $1, $2; exit}')"
RREN="$(echo "$RLIST" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
RDELT=$(($(date -d "$RREN" +%s) - $(date -d "$RSTART" +%s)))
echo "rust_z71_start=$RSTART rust_z71_renew=$RREN rust_z71_delta=$RDELT"
test "$RDELT" -ge 604500
test "$RDELT" -le 605100

docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" kdestroy -A >/dev/null 2>&1 || true
if ! docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf \
    "$MITNAME" sh -c 'printf "userpassword\n" | kinit -l 1h -r 8d user@KERBER.TEST'; then
    docker exec "$MITNAME" cat /tmp/krb5kdc-z71.log >&2 || true
    docker logs "$MITNAME" >&2 || true
    log "renew.gate" "error" ',"error":"MIT kinit -r 8d after omitted rlife failed"'
    exit 1
fi
MLIST="$(docker exec -e KRB5_CONFIG=/tmp/renew-mit-oracle.conf "$MITNAME" klist -f)"
echo "$MLIST"
MSTART="$(echo "$MLIST" | awk '/krbtgt\//{print $1, $2; exit}')"
MREN="$(echo "$MLIST" | awk -F'renew until ' '/renew until/{print $2}' | awk -F, '{print $1}')"
MDELT=$(($(date -d "$MREN" +%s) - $(date -d "$MSTART" +%s)))
echo "mit_z71_start=$MSTART mit_z71_renew=$MREN mit_z71_delta=$MDELT"
test "$MDELT" -ge 604500
test "$MDELT" -le 605100
echo "MIT_z71_omitted_rlife_seven_day_cap"
echo "RUST_z71_omitted_rlife_seven_day_cap"

log "renew.gate" "ok" ',"kinit_r":true,"renew_till_preserved":true,"disallow_strips":true,"proxiable":true,"non_renewable":true,"max_rlife_zero":true,"pre_authent":true,"z71_realm_cap":true'
exit 0
