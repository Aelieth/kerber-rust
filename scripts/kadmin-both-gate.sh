#!/usr/bin/env bash
# Both-kadmind diff cells of kadmin-gate (GSS-RPC 749). KEEP-attach in CI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
. "$ROOT/scripts/lib/kadmin-q.sh"
. "$ROOT/scripts/lib/kadmin-glob-cells.sh"
. "$ROOT/scripts/lib/kadmin-common.sh"
need_bins krb5-kdc krb5-kdb krb5-kadmind krb5-kadmin-local

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-gate"
NAME_MIT="kerber-rust-kadmin-mit"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID
mkdir -p "$SCRATCH"

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

if ! docker inspect "$NAME" >/dev/null 2>&1 || ! docker inspect "$NAME_MIT" >/dev/null 2>&1; then
    die "kadmin-both-gate needs rust+mit containers (run rust then mit with KERBER_KADMIN_KEEP=1)"
fi
register_cleanup "docker rm -f '$NAME' '$NAME_MIT' >/dev/null 2>&1 || true"
mit_oracle_brand "$NAME" /tmp/kadm5-changepw-rpc
mit_oracle_brand "$NAME_MIT" /tmp/kadm5-changepw-rpc
echo "==== kadm5 modify reserved TL type and nonzero failcount both kadminds ===="
kadm5_modify_validate() {
    local ctn=$1 client=$2 conf=$3 princ=$4
    local tl fc before after
    tl="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-tl-reserved "$princ" 2>&1 || true)"
    echo "$ctn tl: $tl"
    echo "$tl" | grep -q 'modify_code=43787567' || {
        echo "$ctn reserved TL did not return KADM5_BAD_TL_TYPE: $tl" >&2
        exit 1
    }
    before="$(echo "$tl" | sed -n 's/.*get_before_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    after="$(echo "$tl" | sed -n 's/.*get_after_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    [ -n "$before" ] && [ "$before" = "$after" ] || {
        echo "$ctn reserved TL changed max_life: $tl" >&2
        exit 1
    }
    fc="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-failcount "$princ" 2>&1 || true)"
    echo "$ctn failcount: $fc"
    echo "$fc" | grep -q 'modify_code=43787563' || {
        echo "$ctn failcount did not return KADM5_BAD_SERVER_PARAMS: $fc" >&2
        exit 1
    }
    before="$(echo "$fc" | sed -n 's/.*get_before_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    after="$(echo "$fc" | sed -n 's/.*get_after_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    [ -n "$before" ] && [ "$before" = "$after" ] || {
        echo "$ctn failcount changed max_life: $fc" >&2
        exit 1
    }
    local mask
    mask="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-policy-clr "$princ" 2>&1 || true)"
    echo "$ctn policy-clr: $mask"
    echo "$mask" | grep -q 'modify_code=43787534' || {
        echo "$ctn POLICY|POLICY_CLR did not return KADM5_BAD_MASK: $mask" >&2
        exit 1
    }
    before="$(echo "$mask" | sed -n 's/.*get_before_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    after="$(echo "$mask" | sed -n 's/.*get_after_code=0 max_life=\([0-9][0-9]*\).*/\1/p')"
    [ -n "$before" ] && [ "$before" = "$after" ] || {
        echo "$ctn POLICY|POLICY_CLR changed max_life: $mask" >&2
        exit 1
    }
    local create
    create="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-failcount-mask "r9mask@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-failcount-mask: $create"
    echo "$create" | grep -q 'create_code=43787534' || {
        echo "$ctn create FAIL_AUTH_COUNT mask did not return KADM5_BAD_MASK: $create" >&2
        exit 1
    }
    local ctl ok
    ctl="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-tl-reserved "r9tlbad@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-tl-reserved: $ctl"
    echo "$ctl" | grep -q 'create_code=43787567' || {
        echo "$ctn create reserved TL did not return KADM5_BAD_TL_TYPE: $ctl" >&2
        exit 1
    }
    ok="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-tl-500 "r9tl500@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-tl-500: $ok"
    echo "$ok" | grep -q 'create_code=0' || {
        echo "$ctn create TL 500 did not succeed: $ok" >&2
        exit 1
    }
    echo "$ok" | grep -q 'tl_type=500' || {
        echo "$ctn create TL 500 missing on getprinc: $ok" >&2
        exit 1
    }
}
kadm5_modify_validate "$NAME" admin /tmp/kadmin-krb5.conf user@KERBER.TEST
kadm5_modify_validate "$NAME_MIT" admin/admin /etc/krb5.conf user@KERBER.TEST

echo "==== both kadminds reject -x db_args; ACL before mask; KEY_DATA mask ===="
kadm5_r12_restart_with_ro() {
    local ctn=$1 is_mit=$2
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec "$ctn" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *" "admin@KERBER.TEST *" "ro@KERBER.TEST i" > /var/krb5kdc/kadm5.acl'
        docker exec -d "$ctn" sh -c 'kadmind -nofork >/tmp/kadmind-r12.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-r12.log >&2 || true; echo "MIT kadmind did not listen for r12" >&2; exit 1; }
    else
        docker exec "$ctn" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
        wait_gone_in "$ctn" 749 || die "kadmind still bound :749 after kill"
        docker exec "$ctn" sh -c 'printf "%s\n" "admin@KERBER.TEST *" "ro@KERBER.TEST i" > /tmp/kadm5.acl'
        docker exec -d \
            -e KRB5_KDC_DB=/tmp/principal \
            -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_ACL_FILE=/tmp/kadm5.acl \
            "$ctn" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-r12.log 2>&1'
        local ok=0 i
        for i in $(seq 1 40); do
            if docker exec "$ctn" grep -q '^listening ' /tmp/kadmind-r12.log 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-r12.log >&2 || true; echo "Rust kadmind did not listen for r12" >&2; exit 1; }
    fi
}
kadm5_r12_db_args() {
    local ctn=$1 client=$2 conf=$3 is_mit=$4
    local userline before after mod add getx ro kd
    kadm() { mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword -q "$1" 2>&1 || true; }
    before="$(kadm 'getprinc user' | grep -v -e '^Authenticating' -e 'No dictionary')"
    mod="$(kadm 'modprinc -x foo=bar user')"
    echo "$ctn modprinc -x: $mod"
    echo "$mod" | grep -F 'Invalid argument while modifying "user@KERBER.TEST"' || {
        echo "$ctn modprinc -x did not print Invalid argument: $mod" >&2
        exit 1
    }
    after="$(kadm 'getprinc user' | grep -v -e '^Authenticating' -e 'No dictionary')"
    [ "$before" = "$after" ] || {
        echo "$ctn getprinc user changed after modprinc -x" >&2
        printf '%s\n' "$before" "$after" >&2
        exit 1
    }
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" kdb5_util dump /tmp/r12.dump
    else
        docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_MASTER_PASSWORD=masterpassword \
            "$ctn" /tmp/krb5-kdb dump /tmp/r12.dump
    fi
    userline="$(docker exec "$ctn" grep -F $'\tuser@KERBER.TEST\t' /tmp/r12.dump || true)"
    echo "$ctn user dump: $userline"
    [ -n "$userline" ] || {
        echo "$ctn dump missing user@KERBER.TEST" >&2
        exit 1
    }
    echo "$userline" | grep -F $'\t32767\t' && {
        echo "$ctn dump still has TL 32767 on user" >&2
        exit 1
    }
    add="$(kadm 'addprinc -pw x -x foo=bar r12x')"
    echo "$ctn addprinc -x: $add"
    echo "$add" | grep -F 'Invalid argument while creating' || {
        echo "$ctn addprinc -x did not print Invalid argument: $add" >&2
        exit 1
    }
    getx="$(kadm 'getprinc r12x')"
    echo "$ctn getprinc r12x: $getx"
    echo "$getx" | grep -qiE 'does not exist|not found|UNK_PRINC|Unknown' || {
        echo "$ctn r12x exists after failed addprinc -x: $getx" >&2
        exit 1
    }
    ro="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin ro@KERBER.TEST ro-secret KERBER.TEST \
        modify-policy-clr user@KERBER.TEST 2>&1 || true)"
    echo "$ctn ro modify-policy-clr: $ro"
    echo "$ro" | grep -q 'modify_code=43787523' || {
        echo "$ctn ro POLICY|POLICY_CLR was not KADM5_AUTH_MODIFY: $ro" >&2
        exit 1
    }
    kd="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        create-key-data-mask "r12key@KERBER.TEST" 2>&1 || true)"
    echo "$ctn create-key-data-mask: $kd"
    echo "$kd" | grep -q 'create_code=43787534' || {
        echo "$ctn KEY_DATA mask did not return KADM5_BAD_MASK: $kd" >&2
        exit 1
    }
}
kadm5_r12_restart_with_ro "$NAME" rust
kadm5_r12_restart_with_ro "$NAME_MIT" mit
kadm5_r12_db_args "$NAME" admin /tmp/kadmin-krb5.conf rust
kadm5_r12_db_args "$NAME_MIT" admin/admin /etc/krb5.conf mit

echo "==== glob lists: Rust kadmind vs MIT kadmind ===="
diff "$SCRATCH/glob-rust.txt" "$SCRATCH/glob-mit.txt" || { echo "glob lists differ between the Rust kadmind and MIT kadmind" >&2; exit 1; }

echo "==== no-GET modify-raw: lookup before ACL and mask (both kadminds) ===="
kadm5_modify_raw() {
    local ctn=$1 client=$2 conf=$3
    local ro_ns adm_ns adm_user
    ro_ns="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin ro@KERBER.TEST ro-secret KERBER.TEST \
        modify-raw nosuch@KERBER.TEST maxlife 2>&1 || true)"
    echo "$ctn ro modify-raw nosuch maxlife: $ro_ns"
    echo "$ro_ns" | grep -q 'modify_code=43787532' || {
        echo "$ctn ro no-GET modify nosuch was not KADM5_UNK_PRINC: $ro_ns" >&2
        exit 1
    }
    adm_ns="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-raw nosuch@KERBER.TEST policyclr 2>&1 || true)"
    echo "$ctn admin modify-raw nosuch policyclr: $adm_ns"
    echo "$adm_ns" | grep -q 'modify_code=43787532' || {
        echo "$ctn admin no-GET policyclr nosuch was not KADM5_UNK_PRINC: $adm_ns" >&2
        exit 1
    }
    adm_user="$(docker exec -e KRB5_CONFIG="$conf" "$ctn" \
        /tmp/kadm5-changepw-rpc --service kadmin/admin "$client" adminpassword KERBER.TEST \
        modify-raw user@KERBER.TEST policyclr 2>&1 || true)"
    echo "$ctn admin modify-raw user policyclr: $adm_user"
    echo "$adm_user" | grep -q 'modify_code=43787534' || {
        echo "$ctn admin no-GET policyclr user was not KADM5_BAD_MASK: $adm_user" >&2
        exit 1
    }
}
kadm5_modify_raw "$NAME" admin /tmp/kadmin-krb5.conf
kadm5_modify_raw "$NAME_MIT" admin/admin /etc/krb5.conf

echo "==== Z1.1 kadm5_create_principal_3 field application + impose_restrictions (both kadminds, MIT kadmin RPC) ===="
# svr_principal.c:376-420 applies every masked field of the request record;
# kadmin/server/auth.c:205-272 imposes the ACL line's restrictions on the
# request *before* the create/modify runs (server_stubs.c:478,519,630), so a
# `-policy P` restriction is enforced by P's floors, an in-mask 0 is kept, a
# value above the cap is lowered and a field absent from the mask takes the
# cap outright. Each leg restarts its kadmind with the same ACL lines (the
# `modprinc` actor needs `i`: MIT kadmin_modprinc gets the entry first,
# kadmin.c:1395-1401, and sends only the parsed args in the mask).
# The container's kdc.conf plus the two `params.*` stanzas a bare `addprinc`
# takes (`alt_prof.c:580-632`): `default_principal_flags` (over
# `KRB5_KDB_DEF_FLAGS` 0) and `default_principal_expiration`
# (`krb5_string_to_timestamp`, local time — the containers run UTC).
z11_profile() {
    docker exec "$1" sh -c '
python3 - <<PY
from pathlib import Path
src = Path("/etc/krb5kdc/kdc.conf").read_text().splitlines(True)
out = []
for ln in src:
    out.append(ln)
    if ln.strip().startswith("KERBER.TEST") and ln.rstrip().endswith("{"):
        out.append("        default_principal_flags = +disallow_svr\n")
        out.append("        default_principal_expiration = 20300102030405\n")
Path("/tmp/z11-kdc.conf").write_text("".join(out))
PY
grep -q default_principal_expiration /tmp/z11-kdc.conf'
}
z11_restart() {
    local ctn=$1 is_mit=$2
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec "$ctn" sh -c 'printf "%s\n" "*/admin@KERBER.TEST *" "admin@KERBER.TEST *" \
            "z1pol@KERBER.TEST a *@KERBER.TEST -policy shortpol" \
            "z1rl@KERBER.TEST a *@KERBER.TEST -maxrenewlife 1d" \
            "z1ml@KERBER.TEST aim *@KERBER.TEST -maxlife 1h" > /var/krb5kdc/kadm5.acl'
        z11_profile "$ctn"
        docker exec -d -e KRB5_KDC_PROFILE=/tmp/z11-kdc.conf "$ctn" sh -c 'kadmind -nofork >/tmp/kadmind-z11.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-z11.log >&2 || true; echo "MIT kadmind did not listen for z11" >&2; exit 1; }
    else
        docker exec "$ctn" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
        wait_gone_in "$ctn" 749 || die "kadmind still bound :749 after kill"
        docker exec "$ctn" sh -c 'printf "%s\n" "admin@KERBER.TEST *" \
            "admin/admin@KERBER.TEST *" \
            "*/admin@KERBER.TEST *" \
            "z1pol@KERBER.TEST a *@KERBER.TEST -policy shortpol" \
            "z1rl@KERBER.TEST a *@KERBER.TEST -maxrenewlife 1d" \
            "z1ml@KERBER.TEST aim *@KERBER.TEST -maxlife 1h" > /tmp/kadm5.acl'
        z11_profile "$ctn"
        docker exec -d \
            -e KRB5_KDC_DB=/tmp/principal \
            -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_ACL_FILE=/tmp/kadm5.acl \
            -e KRB5_KDC_PROFILE=/tmp/z11-kdc.conf \
            "$ctn" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-z11.log 2>&1'
        local ok=0 i
        for i in $(seq 1 40); do
            if docker exec "$ctn" grep -q '^listening ' /tmp/kadmind-z11.log 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-z11.log >&2 || true; echo "Rust kadmind did not listen for z11" >&2; exit 1; }
    fi
}
z11_leg() {
    local ctn=$1 fixture=$2 client=$3 conf=$4 leg=$5
    local out shape pwx
    kadm() {
        mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$1" -w "$2" -q "$3" 2>&1 \
            | grep -v -e '^Authenticating' -e 'No dictionary' -e 'No policy specified' || true
    }
    # Fixtures before the restart: the restricted actors, the two policies.
    # The rust dump has `admin@`, not `admin/admin@`; create the RPC actor
    # used after restart so Z6.4's modifier is `admin/admin@KERBER.TEST`
    # on both legs.
    kadm "$fixture" adminpassword 'addprinc -pw z1pol-secret z1pol' | grep -F 'Principal "z1pol@KERBER.TEST" created.'
    kadm "$fixture" adminpassword 'addprinc -pw z1rl-secret z1rl' | grep -F 'Principal "z1rl@KERBER.TEST" created.'
    kadm "$fixture" adminpassword 'addprinc -pw z1ml-secret z1ml' | grep -F 'Principal "z1ml@KERBER.TEST" created.'
    kadmin_q_ok kadm "$fixture" adminpassword 'addpol -minlength 8 shortpol'
    kadmin_q_ok kadm "$fixture" adminpassword 'addpol -maxlife 30d z1pw'
    if [ "$leg" = rust ]; then
        kadmin_q_try kadm "$fixture" adminpassword 'addprinc -pw adminpassword admin/admin'
    fi
    z11_restart "$ctn" "$leg"

    echo "---- $leg: every masked field lands (getprinc shape to $SCRATCH/z11-$leg.txt) ----"
    out="$(kadm "$client" adminpassword 'addprinc -pw x -maxlife 1h -maxrenewlife 0 -expire "2030-01-01 00:00:00 UTC" -pwexpire "2031-01-01 00:00:00 UTC" -kvno 7 +disallow_all_tix +requires_preauth z1u')"
    echo "$out"
    echo "$out" | grep -F 'Principal "z1u@KERBER.TEST" created.'
    shape="$(kadm "$client" adminpassword 'getprinc z1u')"
    echo "$shape"
    echo "$shape" | hist_shape > "$SCRATCH/z11-$leg.txt"
    echo "$shape" | grep -F 'Expiration date: Tue Jan 01 00:00:00 UTC 2030'
    echo "$shape" | grep -F 'Password expiration date: Wed Jan 01 00:00:00 UTC 2031'
    echo "$shape" | grep -F 'Maximum ticket life: 0 days 01:00:00'
    echo "$shape" | grep -F 'Maximum renewable life: 0 days 00:00:00'
    echo "$shape" | grep -E '^Attributes: DISALLOW_ALL_TIX REQUIRES_PRE_AUTH$'
    echo "$shape" | grep -E '^Key: vno 7, ' >/dev/null
    if echo "$shape" | grep -E '^Key: vno ' | grep -vq '^Key: vno 7, '; then
        echo "$leg: a key is not at kvno 7: $shape" >&2
        exit 1
    fi
    echo "$shape" | grep -E '^Last modified: .* \(admin/admin@KERBER.TEST\)$'

    echo "---- $leg: default_principal_flags / default_principal_expiration are params.flags / params.expiration for a bare addprinc ----"
    kadm "$client" adminpassword 'addprinc -pw x z1def' | grep -F 'Principal "z1def@KERBER.TEST" created.'
    out="$(kadm "$client" adminpassword 'getprinc z1def')"
    echo "$out"
    echo "$out" | grep -F 'Expiration date: Wed Jan 02 03:04:05 UTC 2030'
    echo "$out" | grep -E '^Attributes: DISALLOW_SVR$'

    echo "---- $leg: -policy with pw_max_life sets Password expiration date ----"
    kadm "$client" adminpassword 'addprinc -pw z1pwu-secret -policy z1pw z1pwu' | grep -F 'Principal "z1pwu@KERBER.TEST" created.'
    pwx="$(kadm "$client" adminpassword 'getprinc z1pwu' | grep -E '^Password expiration date: ')"
    echo "$pwx"
    if echo "$pwx" | grep -qF '[never]'; then
        echo "$leg: policy pw_max_life did not set the password expiration" >&2
        exit 1
    fi
    # now + 30d, to the day (the two legs run seconds apart).
    docker exec "$ctn" sh -c "date -u -d '+30 days' '+%a %b %d'" | grep -qF "$(echo "$pwx" | sed -E 's/^Password expiration date: ([A-Za-z]+ [A-Za-z]+ [0-9]+) .*/\1/')" || {
        echo "$leg: password expiration is not now + 30d: $pwx" >&2
        exit 1
    }

    echo "---- $leg: ACL -policy shortpol is enforced on addprinc (Password is too short; nothing created) ----"
    out="$(kadm z1pol z1pol-secret 'addprinc -pw abc z1short')"
    echo "$out"
    echo "$out" | grep -F 'add_principal: Password is too short while creating "z1short@KERBER.TEST".'
    out="$(kadm "$client" adminpassword 'getprinc z1short')"
    echo "$out"
    echo "$out" | grep -F 'get_principal: Principal does not exist while retrieving "z1short@KERBER.TEST".'
    out="$(kadm z1pol z1pol-secret 'addprinc -pw longenough z1long')"
    echo "$out"
    echo "$out" | grep -F 'Principal "z1long@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1long' | grep -E '^Policy: shortpol$'

    echo "---- $leg: ACL -maxrenewlife 1d keeps an in-mask 0 and lowers 30d ----"
    kadm z1rl z1rl-secret 'addprinc -pw x -maxrenewlife 0 z1r0' | grep -F 'Principal "z1r0@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1r0' | grep -F 'Maximum renewable life: 0 days 00:00:00'
    kadm z1rl z1rl-secret 'addprinc -pw x -maxrenewlife 30d z1r30' | grep -F 'Principal "z1r30@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1r30' | grep -F 'Maximum renewable life: 1 day 00:00:00'

    echo "---- $leg: ACL -maxlife 1h: a modify without -maxlife takes the cap (auth.c:259-263) ----"
    kadm z1ml z1ml-secret 'addprinc -pw x -maxlife 30m z1mu' | grep -F 'Principal "z1mu@KERBER.TEST" created.'
    kadm "$client" adminpassword 'getprinc z1mu' | grep -F 'Maximum ticket life: 0 days 00:30:00'
    kadm z1ml z1ml-secret 'modprinc +requires_preauth z1mu' | grep -F 'Principal "z1mu@KERBER.TEST" modified.'
    kadm "$client" adminpassword 'getprinc z1mu' | grep -F 'Maximum ticket life: 0 days 01:00:00'
}
z11_leg "$NAME" admin admin/admin /tmp/kadmin-krb5.conf rust
z11_leg "$NAME_MIT" admin/admin admin/admin /etc/krb5.conf mit
echo "---- Z1.1 getprinc z1u shape: Rust vs MIT ----"
sed 's/^/rust: /' "$SCRATCH/z11-rust.txt"
sed 's/^/mit:  /' "$SCRATCH/z11-mit.txt"
diff "$SCRATCH/z11-rust.txt" "$SCRATCH/z11-mit.txt" || { echo "Z1.1: getprinc z1u differs between the Rust kadmind and MIT kadmind" >&2; exit 1; }

# W1-Z Z1b.1: the AUTH_GSSAPI GSSAPI_INIT arg-version switch
# (svc_auth_gssapi.c:326-341) against both kadminds on 749 with a forged
# init (empty token): 1/2 → init_res.version 1, 3/4 echoed, 5 → AUTH_BADCRED.
echo "==== Z1b.1 AUTH_GSSAPI init-arg version switch (svc_auth_gssapi.c:326-341): Rust kadmind vs MIT kadmind ===="
z1b1_leg() {
    local ctn=$1 leg=$2 v out
    docker cp "$ROOT/scripts/lib/auth-gssapi-init-probe.py" "$ctn":/tmp/auth-gssapi-init-probe.py
    for v in 1 2 3 4 5 0; do
        out="$(docker exec "$ctn" python3 /tmp/auth-gssapi-init-probe.py 127.0.0.1:749 "$v")"
        echo "$leg: init-arg version $v -> $out"
        case $v in
            1|2) echo "$out" | grep -q '^accepted version=1 ' || { echo "$leg: version $v was not answered with init_res.version 1" >&2; exit 1; } ;;
            3|4) echo "$out" | grep -q "^accepted version=$v " || { echo "$leg: version $v was not echoed" >&2; exit 1; } ;;
            *)   echo "$out" | grep -q '^denied auth_stat=1 AUTH_BADCRED$' || { echo "$leg: version $v was not AUTH_BADCRED" >&2; exit 1; } ;;
        esac
    done
}
z1b1_leg "$NAME" rust
z1b1_leg "$NAME_MIT" mit

echo "==== Z6.5 RPC create honours ks_tuple (svr_principal.c:444-447) ===="
# MIT kadmin addprinc -randkey -e against both kadminds (still up after z11).
# Date-bearing lines are dropped; only Key: lines are compared.
z65_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -randkey -e aes128-cts-hmac-sha1-96:normal z65' 2>&1 \
        | grep -F 'Principal "z65@KERBER.TEST" created.'
    local keys
    keys="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getprinc z65' | grep '^Key:')"
    echo "$leg: $keys"
    echo "$keys" | grep -Fx 'Key: vno 1, aes128-cts-hmac-sha1-96' >/dev/null
    [ "$(echo "$keys" | grep -c '^Key:')" = 1 ] || {
        echo "$leg: z65 has more than the requested keysalt: $keys" >&2
        exit 1
    }
    echo "$keys" > "$SCRATCH/z65-$leg.txt"
}
z65_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z65_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z65-rust.txt" "$SCRATCH/z65-mit.txt" || {
    echo "Z6.5: getprinc z65 Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z6.6 params.max_life default is 24 h (alt_prof.c:574-575) ===="
# Stock kdc.conf writes max_life = 10h. Strip only that relation (not
# max_renewable_life) and restart both kadminds so an unmasked create
# takes MIT's 24 h default.
z66_profile() {
    # python must run *inside* the container (z11_profile): `docker exec`
    # without `-i` does not forward the host heredoc, so the file was never
    # written and rust kadmind exited on a missing KRB5_KDC_PROFILE.
    docker exec "$1" sh -c '
python3 - <<PY
from pathlib import Path
src = Path("/etc/krb5kdc/kdc.conf").read_text().splitlines(True)
out = []
for ln in src:
    key = ln.split("=", 1)[0].strip()
    if key == "max_life":
        continue
    out.append(ln)
Path("/tmp/z66-kdc.conf").write_text("".join(out))
PY
test -f /tmp/z66-kdc.conf
grep -q max_renewable_life /tmp/z66-kdc.conf
if grep -E "^[[:space:]]*max_life[[:space:]]*=" /tmp/z66-kdc.conf; then
    echo "z66-kdc.conf still has max_life" >&2
    exit 1
fi
'
}
z66_restart() {
    local ctn=$1 is_mit=$2
    if [ "$is_mit" = mit ]; then
        docker exec "$ctn" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec -d -e KRB5_KDC_PROFILE=/tmp/z66-kdc.conf "$ctn" sh -c 'kadmind -nofork >/tmp/kadmind-z66.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" cat /tmp/kadmind-z66.log >&2 || true; echo "MIT kadmind did not listen for z66" >&2; exit 1; }
    else
        docker exec "$ctn" sh -c '
for comm in /proc/[0-9]*/comm; do
    [ -f "$comm" ] || continue
    read -r name < "$comm" || continue
    if [ "$name" = "krb5-kadmind" ]; then
        pid=${comm#/proc/}
        pid=${pid%/comm}
        kill "$pid" 2>/dev/null || true
    fi
done
'
        local i
        for i in $(seq 1 40); do
            if ! docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                break
            fi
            sleep 0.25
        done
        docker exec -d \
            -e KRB5_KDC_DB=/tmp/principal \
            -e KRB5_KDC_STASH=/tmp/stash \
            -e KRB5_ACL_FILE=/tmp/kadm5.acl \
            -e KRB5_KDC_PROFILE=/tmp/z66-kdc.conf \
            "$ctn" sh -c '/tmp/krb5-kadmind 127.0.0.1:749 >/tmp/kadmind-z66.log 2>&1'
        local ok=0
        for i in $(seq 1 40); do
            if docker exec "$ctn" python3 -c "import socket;s=socket.create_connection(('127.0.0.1',749),0.3)" 2>/dev/null; then
                ok=1
                break
            fi
            sleep 0.25
        done
        [ "$ok" = 1 ] || { docker exec "$ctn" sh -c 'echo ---- z66-kdc.conf ----; cat /tmp/z66-kdc.conf; echo ---- kadmind-z66.log ----; cat /tmp/kadmind-z66.log' >&2 || true; echo "Rust kadmind did not listen for z66" >&2; exit 1; }
    fi
}
z66_profile "$NAME"
z66_profile "$NAME_MIT"
z66_restart "$NAME" rust
z66_restart "$NAME_MIT" mit
z66_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -pw x z66' 2>&1 | grep -F 'Principal "z66@KERBER.TEST" created.'
    local life
    life="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getprinc z66' | grep '^Maximum ticket life:')"
    echo "$leg: $life"
    echo "$life" | grep -Fx 'Maximum ticket life: 1 day 00:00:00'
    echo "$life" > "$SCRATCH/z66-$leg.txt"
}
z66_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z66_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z66-rust.txt" "$SCRATCH/z66-mit.txt" || {
    echo "Z6.6: getprinc z66 Maximum ticket life differs between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z7.2 RPC chpass/randkey honour ks_tuple (svr_principal.c:1259,1425) ===="
z72_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -pw z72old z72c' 2>&1 \
        | grep -F 'Principal "z72c@KERBER.TEST" created.'
    mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'cpw -pw z72new -e aes128-cts-hmac-sha1-96:normal z72c' 2>&1 \
        | grep -F 'Password for "z72c@KERBER.TEST" changed.'
    local keys
    keys="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getprinc z72c' | grep '^Key:')"
    echo "$leg cpw -e: $keys"
    echo "$keys" | grep -Fx 'Key: vno 2, aes128-cts-hmac-sha1-96' >/dev/null
    [ "$(echo "$keys" | grep -c '^Key:')" = 1 ] || {
        echo "$leg: z72c has more than the requested keysalt: $keys" >&2
        exit 1
    }
    echo "$keys" > "$SCRATCH/z72c-$leg.txt"
    mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -randkey z72r' 2>&1 \
        | grep -F 'Principal "z72r@KERBER.TEST" created.'
    mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'cpw -randkey -e aes128-cts-hmac-sha1-96:normal z72r' 2>&1 \
        | grep -F 'Key for "z72r@KERBER.TEST" randomized.'
    keys="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getprinc z72r' | grep '^Key:')"
    echo "$leg cpw -randkey -e: $keys"
    echo "$keys" | grep -Fx 'Key: vno 2, aes128-cts-hmac-sha1-96' >/dev/null
    [ "$(echo "$keys" | grep -c '^Key:')" = 1 ] || {
        echo "$leg: z72r has more than the requested keysalt: $keys" >&2
        exit 1
    }
    echo "$keys" > "$SCRATCH/z72r-$leg.txt"
    kadmin_q_ok mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addpol -allowedkeysalts aes256-cts:normal z72ks' >/dev/null
    local refuse
    refuse="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -policy z72ks -e aes128-cts:normal -pw ValidPass1 z72ksbad' 2>&1 || true)"
    echo "$leg refuse: $refuse"
    echo "$refuse" | grep -F 'Invalid key/salt tuples'
    echo "$refuse" > "$SCRATCH/z72ks-$leg.txt"
}
z72_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z72_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z72c-rust.txt" "$SCRATCH/z72c-mit.txt" || {
    echo "Z7.2: getprinc z72c Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
diff "$SCRATCH/z72r-rust.txt" "$SCRATCH/z72r-mit.txt" || {
    echo "Z7.2: getprinc z72r Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
diff "$SCRATCH/z72ks-rust.txt" "$SCRATCH/z72ks-mit.txt" || {
    echo "Z7.2: addprinc -policy -e refusal differs between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z8.3 bootstrap actors: kadmin/changepw kdb5_util@ (kadm5_create.c:100) ===="
# kadmin/changepw is never successfully modified in this gate (the
# lockdown_keys cell is a privilege denial), so both legs still show
# kadm5_create's kdb5_util@REALM. krbtgt is purgekeys'd earlier
# (admin@ on rust, admin/admin@ on MIT — fixture princstr); bootstrap
# db_creation@ is z8_bootstrap_mod.rs.
z83_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
R83="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    -- -p admin/admin -w adminpassword -q 'getprinc kadmin/changepw')"
M83="$(mit_kadmin -e KRB5_CONFIG=/etc/krb5.conf "$NAME_MIT" \
    -- -p admin/admin -w adminpassword -q 'getprinc kadmin/changepw')"
echo "$R83" | hist_shape | sed 's/^/rust kadmin\/changepw: /'
echo "$M83" | hist_shape | sed 's/^/mit kadmin\/changepw: /'
R83MOD="$(echo "$R83" | z83_mod)"
M83MOD="$(echo "$M83" | z83_mod)"
echo "rust kadmin/changepw modifier=$R83MOD"
echo "mit  kadmin/changepw modifier=$M83MOD"
[ "$R83MOD" = "kdb5_util@KERBER.TEST" ]
[ "$M83MOD" = "kdb5_util@KERBER.TEST" ]
[ "$R83MOD" = "$M83MOD" ]
R83T="$(mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    -- -p admin/admin -w adminpassword -q 'getprinc krbtgt/KERBER.TEST')"
M83T="$(mit_kadmin -e KRB5_CONFIG=/etc/krb5.conf "$NAME_MIT" \
    -- -p admin/admin -w adminpassword -q 'getprinc krbtgt/KERBER.TEST')"
R83TMOD="$(echo "$R83T" | z83_mod)"
M83TMOD="$(echo "$M83T" | z83_mod)"
echo "rust krbtgt modifier=$R83TMOD (purgekeys caller)"
echo "mit  krbtgt modifier=$M83TMOD (purgekeys caller)"
[ "$R83TMOD" = "admin@KERBER.TEST" ]
[ "$M83TMOD" = "admin/admin@KERBER.TEST" ]
echo "MIT_z83_bootstrap_actors"
echo "RUST_z83_bootstrap_actors"

echo "==== Z8.4 addpol/modpol unknown keysalt matches MIT (string_to_keysalts skips) ===="
# Live MIT kadmin.local addpol -allowedkeysalts bogus:normal succeeds
# (str_conv.c:341-343 discards unrecognized; validate only rejects a tab).
z84_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    local add mod get
    add="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addpol -allowedkeysalts bogus:normal z8pol' 2>&1 || true)"
    echo "$leg addpol: $add"
    if echo "$add" | grep -qF 'Invalid key/salt tuples'; then
        echo "$leg: addpol bogus:normal was refused" >&2
        exit 1
    fi
    get="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getpol z8pol' | grep -E '^(Policy|Allowed key/salt)')"
    echo "$leg getpol: $get"
    echo "$get" | grep -F 'Policy: z8pol'
    echo "$get" | grep -F 'Allowed key/salt types: bogus:normal'
    echo "$get" > "$SCRATCH/z84get-$leg.txt"
    kadmin_q_ok mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addpol z8mod' >/dev/null
    mod="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'modpol -allowedkeysalts bogus:normal z8mod' 2>&1 || true)"
    echo "$leg modpol: $mod"
    if echo "$mod" | grep -qF 'Invalid key/salt tuples'; then
        echo "$leg: modpol bogus:normal was refused" >&2
        exit 1
    fi
}
z84_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z84_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z84get-rust.txt" "$SCRATCH/z84get-mit.txt" || {
    echo "Z8.4: getpol z8pol differs between the Rust kadmind and MIT kadmind" >&2
    exit 1
}

echo "==== Z8.5 weak/deprecated -e on both kadminds (allow_weak_crypto = false) ===="
z85_leg() {
    local ctn=$1 client=$2 conf=$3 leg=$4
    local des3 rc4 keys
    des3="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -randkey -e des3-cbc-sha1:normal z8des3' 2>&1 || true)"
    rc4="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'addprinc -randkey -e arcfour-hmac:normal z8rc4' 2>&1 || true)"
    echo "$leg des3: $des3"
    echo "$leg rc4: $rc4"
    echo "$des3" | grep -F 'Principal "z8des3@KERBER.TEST" created.'
    echo "$rc4" | grep -F 'Principal "z8rc4@KERBER.TEST" created.'
    keys="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getprinc z8des3' | grep '^Key:')"
    echo "$leg des3 keys: $keys"
    echo "$keys" > "$SCRATCH/z85des3-$leg.txt"
    keys="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" -- -p "$client" -w adminpassword \
        -q 'getprinc z8rc4' | grep '^Key:')"
    echo "$leg rc4 keys: $keys"
    echo "$keys" > "$SCRATCH/z85rc4-$leg.txt"
}
z85_leg "$NAME" admin/admin /tmp/kadmin-krb5.conf rust
z85_leg "$NAME_MIT" admin/admin /etc/krb5.conf mit
diff "$SCRATCH/z85des3-rust.txt" "$SCRATCH/z85des3-mit.txt" || {
    echo "Z8.5: getprinc z8des3 Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
diff "$SCRATCH/z85rc4-rust.txt" "$SCRATCH/z85rc4-mit.txt" || {
    echo "Z8.5: getprinc z8rc4 Key: lines differ between the Rust kadmind and MIT kadmind" >&2
    exit 1
}
echo "MIT_z85_des3_rc4_ks_tuple"
echo "RUST_z85_des3_rc4_ks_tuple"

echo "==== Z8 leftover: kadm5_create max_life (kadm5_create.c:54-55,207-213) ===="
z8life() {
    local ctn=$1 client=$2 conf=$3 princ=$4 want=$5
    local life
    life="$(mit_kadmin -e KRB5_CONFIG="$conf" "$ctn" \
        -- -p "$client" -w adminpassword -q "getprinc $princ" \
        | grep '^Maximum ticket life:')"
    echo "$ctn $princ: $life"
    echo "$life" | grep -Fx "$want"
}
z8life "$NAME" admin/admin /tmp/kadmin-krb5.conf kadmin/admin \
    'Maximum ticket life: 0 days 03:00:00'
z8life "$NAME_MIT" admin/admin /etc/krb5.conf kadmin/admin \
    'Maximum ticket life: 0 days 03:00:00'
z8life "$NAME" admin/admin /tmp/kadmin-krb5.conf kadmin/changepw \
    'Maximum ticket life: 0 days 00:05:00'
z8life "$NAME_MIT" admin/admin /etc/krb5.conf kadmin/changepw \
    'Maximum ticket life: 0 days 00:05:00'
echo "MIT_z8_kadm5_create_max_life"
echo "RUST_z8_kadm5_create_max_life"

echo "==== Z8 leftover: setstr stamps current_caller (svr_principal.c:2022-2043) ===="
# RPC create stamps the kadmind caller; local setstr must restamp
# like kdb_put_entry (Z7.2 local princstr is root/admin@ both legs).
mit_kadmin -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    -- -p admin/admin -w adminpassword -q 'addprinc -pw z8str-secret z8str' \
    | grep -F 'Principal "z8str@KERBER.TEST" created.'
mit_kadmin -e KRB5_CONFIG=/etc/krb5.conf "$NAME_MIT" \
    -- -p admin/admin -w adminpassword -q 'addprinc -pw z8str-secret z8str' \
    | grep -F 'Principal "z8str@KERBER.TEST" created.'
kadmin_q_ok rust_kadmin_local \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" -- -p root/admin -q 'setstr z8str note leftover'
kadmin_q_ok mit_kadmin_local "$NAME_MIT" -- -p root/admin -q 'setstr z8str note leftover'
z8str_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
RSTR="$(rust_kadmin_local \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" -- -p root/admin -q 'getprinc z8str')"
MSTR="$(mit_kadmin_local "$NAME_MIT" -- -p root/admin -q 'getprinc z8str')"
echo "$RSTR" | hist_shape | sed 's/^/rust z8str: /'
echo "$MSTR" | hist_shape | sed 's/^/mit  z8str: /'
RSTRMOD="$(echo "$RSTR" | z8str_mod)"
MSTRMOD="$(echo "$MSTR" | z8str_mod)"
echo "rust z8str modifier=$RSTRMOD"
echo "mit  z8str modifier=$MSTRMOD"
[ "$RSTRMOD" = "root/admin@KERBER.TEST" ]
[ "$MSTRMOD" = "root/admin@KERBER.TEST" ]
echo "MIT_z8_setstr_stamps_caller"
echo "RUST_z8_setstr_stamps_caller"

log "kadmin.gate" "ok" ',"principal":"extra@KERBER.TEST","op":"addprinc+cpw+get+list+mod+chrand+norandkey+lockdown+purgekeys+setstr+renprinc+del+alias"'
exit 0

