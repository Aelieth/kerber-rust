#!/usr/bin/env bash
# Rust kadmin.local mutates the dump; MIT kadmin getprinc/listprincs is the oracle.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_bins krb5-kdc krb5-kdb krb5-kadmind krb5-kadmin-local

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-kadmin-local-gate"
CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"
export CORRELATION_ID

if ! command -v docker >/dev/null 2>&1; then
    log "kadmin.local.gate" "error" ',"error":"docker not available"'
    exit 1
fi

need_image

shell_container

docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdc" "$NAME":/tmp/krb5-kdc
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kdb" "$NAME":/tmp/krb5-kdb
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmind" "$NAME":/tmp/krb5-kadmind
docker cp "${CARGO_TARGET_DIR:-target}/debug/krb5-kadmin-local" "$NAME":/tmp/krb5-kadmin-local
docker exec "$NAME" chmod +x /tmp/krb5-kdc /tmp/krb5-kdb /tmp/krb5-kadmind /tmp/krb5-kadmin-local

docker exec -d \
    -e KRB5_TEST_USER_PASSWORD=userpassword \
    -e KRB5_TEST_ADMIN_PASSWORD=adminpassword \
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
    log "kadmin.local.gate" "error" ',"error":"kdc did not listen"'
    exit 1
fi

echo "==== Rust kadmin.local addprinc/listprincs/getprinc ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=extra-local \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc extra2'
LIST="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'listprincs')"
echo "$LIST"
echo "$LIST" | grep -q 'extra2@KERBER.TEST'
GET="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc extra2')"
echo "$GET"
echo "$GET" | grep -q 'Principal: extra2@KERBER.TEST'

echo "==== Rust kadmin.local addprinc host/slashhost ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=slash-local \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc host/slashhost'
SLASH="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc host/slashhost')"
echo "$SLASH"
echo "$SLASH" | grep -q 'Principal: host/slashhost@KERBER.TEST'

echo "==== addprinc -randkey / ktadd principals before kadmind ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey randsvc'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey ktone'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey kttwo'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc -requires_preauth extra2'
set +e
UNK="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -bogus nosuch' 2>&1)"
unkrc=$?
set -e
echo "$UNK"
test "$unkrc" -ne 0
echo "$UNK" | grep -qi 'unknown flag'

echo "==== kadmin.local addpol flags + getpol layout ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addpol floors1'
GETF="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getpol floors1')"
echo "$GETF"
echo "$GETF" | grep -F 'Policy: floors1'
if echo "$GETF" | grep -q 'Policy: Policy:'; then
    echo "doubled Policy: prefix: $GETF" >&2
    exit 1
fi
echo "$GETF" | grep -F 'Minimum password length: 1'
echo "$GETF" | grep -F 'Minimum number of password character classes: 1'
echo "$GETF" | grep -F 'Number of old keys kept: 1'
echo "$GETF" | grep -F 'Maximum password life: 0 days 00:00:00'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addpol -minlength 8 -minclasses 2 -history 3 -maxlife 1d -minlife 1h pflags'
GETP="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getpol pflags')"
echo "$GETP"
echo "$GETP" | grep -F 'Minimum password length: 8'
echo "$GETP" | grep -F 'Minimum number of password character classes: 2'
echo "$GETP" | grep -F 'Number of old keys kept: 3'
echo "$GETP" | grep -F 'Maximum password life: 1 day 00:00:00'
echo "$GETP" | grep -F 'Minimum password life: 0 days 01:00:00'
if echo "$GETF" | grep -q 'Allowed key/salt types:'; then
    echo "getpol floors1 printed Allowed key/salt types (MIT omits NULL): $GETF" >&2
    exit 1
fi
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addpol -allowedkeysalts aes256-cts:normal ksalt'
GETK="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getpol ksalt')"
echo "$GETK"
echo "$GETK" | grep -F 'Allowed key/salt types: aes256-cts:normal'
echo "==== kadmin.local modpol/listpols/delpol ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modpol -minlength 10 pflags'
GETPM="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getpol pflags')"
echo "$GETPM"
echo "$GETPM" | grep -F 'Minimum password length: 10'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addpol extra'
LISTP="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'listpols')"
echo "$LISTP"
echo "$LISTP" | grep -F 'pflags'
echo "$LISTP" | grep -F 'extra'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'delpol -force extra'
LISTP2="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'listpols')"
echo "$LISTP2"
if echo "$LISTP2" | grep -Fx extra; then
    echo "delpol extra left extra in listpols: $LISTP2" >&2
    exit 1
fi

echo "==== MIT kadmin.local: identical addpol/getpol/modpol/listpols/delpol sequence, diffed ===="
docker exec "$NAME" sh -c 'kdb5_util create -s -P masterpassword >/dev/null 2>&1'
mit_local() {
    # kadmin.local prints the "Authenticating as principal ... with password."
    # banner to stdout and com_err errors to stderr; under 2>&1 the banner can
    # interleave into the middle of an error line on a loaded runner, which the
    # old line-start grep could not strip (the cause of the CI kadmin-local
    # flake). `sed -z` removes both artefacts wherever they land, rejoining a
    # line the banner split, and leaves interactive prompts (no trailing
    # newline) intact.
    docker exec "$NAME" kadmin.local -q "$1" 2>&1 \
        | sed -z -e 's/Authenticating as principal [^\n]*with password\.\n//g' \
                 -e 's/[^\n]*No dictionary file specified[^\n]*\n//g'
}
mit_local 'addpol floors1' >/dev/null
diff <(echo "$GETF" | grep -v '^Authenticating') <(mit_local 'getpol floors1')
mit_local 'addpol -minlength 8 -minclasses 2 -history 3 -maxlife 1d -minlife 1h pflags' >/dev/null
diff <(echo "$GETP" | grep -v '^Authenticating') <(mit_local 'getpol pflags')
mit_local 'addpol -allowedkeysalts aes256-cts:normal ksalt' >/dev/null
diff <(echo "$GETK" | grep -v '^Authenticating') <(mit_local 'getpol ksalt')
mit_local 'modpol -minlength 10 pflags' >/dev/null
diff <(echo "$GETPM" | grep -v '^Authenticating') <(mit_local 'getpol pflags')
mit_local 'addpol extra' >/dev/null
diff <(echo "$LISTP" | grep -v '^Authenticating' | sort) <(mit_local 'listpols' | sort)
mit_local 'delpol -force extra' >/dev/null
diff <(echo "$LISTP2" | grep -v '^Authenticating' | sort) <(mit_local 'listpols' | sort)
echo "mit_kadmin_local_diff=identical"

echo "==== deltat trailing whitespace: \"1d \" accepted, \"42 \" refused, on both legs ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addpol -maxlife "1d " tws'
TWS="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getpol tws')"
echo "$TWS"
echo "$TWS" | grep -F 'Maximum password life: 1 day 00:00:00'
mit_local 'addpol -maxlife "1d " tws' >/dev/null
diff <(echo "$TWS" | grep -v '^Authenticating') <(mit_local 'getpol tws')
TWSBAD="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addpol -maxlife "42 " tws2' 2>&1)"
echo "$TWSBAD"
# MIT prints the date error and continues (exit 0); the first line is identical.
echo "$TWSBAD" | grep -Fx 'Invalid date specification "42 ".'
diff <(echo "$TWSBAD" | head -1) <(mit_local 'addpol -maxlife "42 " tws2' 2>&1 | head -1)
LISTT="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'listpols')"
diff <(echo "$LISTT" | grep -v '^Authenticating' | sort) <(mit_local 'listpols' | sort)
echo "$LISTT" | grep -Fx tws
if echo "$LISTT" | grep -Fx tws2; then
    echo "addpol -maxlife \"42 \" created tws2: $LISTT" >&2
    exit 1
fi

echo "==== delpol/delprinc prompt: EOF reply keeps the object, yes deletes, on both legs ===="
rust_local() {
    docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
        "$NAME" /tmp/krb5-kadmin-local -q "$1" 2>&1
}
prompt_lines() { sed 's/(yes\/no): /(yes\/no): \n/' | sed '/^$/d' | sort; }
# Diff two already-captured strings; on any mismatch print BOTH legs (cat -A,
# newlines as |) in one ::error annotation the public CI API can show, then
# die. Sequential capture removes concurrent process-substitution as a variable.
dl() {
    if [ "$2" != "$3" ]; then
        printf '::error file=scripts/kadmin-local-gate.sh::%s differs: rust=[%s] mit=[%s]\n' \
            "$1" "$(printf '%s' "$2" | cat -A | tr '\n' '|')" "$(printf '%s' "$3" | cat -A | tr '\n' '|')" >&2
        exit 1
    fi
}
PDEL="$(rust_local 'delpol tws')"
echo "$PDEL"
diff <(echo "$PDEL" | prompt_lines | grep -F 'not deleted') <(mit_local 'delpol tws' | prompt_lines | grep -F 'not deleted')
echo "$PDEL" | grep -F 'Policy "tws" not deleted.'
rust_local 'addprinc -pw delme-secret delme' >/dev/null
mit_local 'addprinc -pw delme-secret delme' >/dev/null
PDELP="$(rust_local 'delprinc delme')"
echo "$PDELP"
diff <(echo "$PDELP" | prompt_lines | grep -F 'not deleted') <(mit_local 'delprinc delme' | prompt_lines | grep -F 'not deleted')
echo "$PDELP" | grep -F 'Principal "delme@KERBER.TEST" not deleted'
YDEL="$(printf 'yes\n' | docker exec -i -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'delprinc delme' 2>&1)"
echo "$YDEL"
MIT_YDEL="$(printf 'yes\n' | docker exec -i "$NAME" kadmin.local -q 'delprinc delme' 2>&1 \
    | { grep -v -e '^Authenticating' -e 'No dictionary file' || true; })"
diff <(echo "$YDEL" | prompt_lines) <(echo "$MIT_YDEL" | prompt_lines)
echo "$YDEL" | grep -F 'Principal "delme@KERBER.TEST" deleted.'
printf 'yes\n' | docker exec -i -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'delpol tws' >/dev/null
printf 'yes\n' | docker exec -i "$NAME" kadmin.local -q 'delpol tws' >/dev/null 2>&1
LISTD="$(rust_local 'listpols')"
diff <(echo "$LISTD" | sort) <(mit_local 'listpols' | sort)
if echo "$LISTD" | grep -Fx tws; then
    echo "delpol tws answered yes left tws: $LISTD" >&2
    exit 1
fi

echo "==== C1 passwd_check: empty / princ / realm / dict modules, rust vs MIT kadmin.local ===="
# MIT passwd_check (server_misc.c:110-135) runs the built-in pwqual modules
# dict, empty, princ after the policy floors; dict/princ skip principals with
# no policy, empty never does. MIT also klogs
# "password quality module X rejected password for P: text" to stderr, so
# only the com_err / created lines are compared.
pwq_lines() { grep -e '^add_principal:' -e '^change_password:' -e '^get_principal:' -e '^Principal ' -e '^Password ' || true; }
rust_local 'addpol pq' >/dev/null
mit_local 'addpol pq' >/dev/null
dl pwq-empty-nopolicy "$(rust_local 'addprinc -pw "" pqempty' | pwq_lines)" "$(mit_local 'addprinc -pw "" pqempty' | pwq_lines)"
dl pwq-princ-component "$(rust_local 'addprinc -pw PQNAME -policy pq pqname' | pwq_lines)" "$(mit_local 'addprinc -pw PQNAME -policy pq pqname' | pwq_lines)"
dl pwq-realm "$(rust_local 'addprinc -pw kerber.test -policy pq pqrealm' | pwq_lines)" "$(mit_local 'addprinc -pw kerber.test -policy pq pqrealm' | pwq_lines)"
dl pwq-nopolicy-name-ok "$(rust_local 'addprinc -pw pqfree pqfree' | pwq_lines)" "$(mit_local 'addprinc -pw pqfree pqfree' | pwq_lines)"
# A rejected create left nothing behind on either side.
dl pwq-rejected-not-created "$(rust_local 'getprinc pqname' | pwq_lines)" "$(mit_local 'getprinc pqname' | pwq_lines)"
rust_local 'getprinc pqname' | grep -F 'get_principal: Principal does not exist while retrieving "pqname@KERBER.TEST".'
rust_local 'addprinc -pw "" pqempty' | grep -F 'add_principal: Empty passwords are not allowed while creating "pqempty@KERBER.TEST".'
rust_local 'addprinc -pw PQNAME -policy pq pqname' | grep -F 'add_principal: Password may not match principal name while creating "pqname@KERBER.TEST".'
rust_local 'addprinc -pw kerber.test -policy pq pqrealm' | grep -F 'add_principal: Password is in the password dictionary while creating "pqrealm@KERBER.TEST".'
# cpw goes through the same passwd_check (svr_principal.c:1282).
dl pwq-cpw-empty "$(rust_local 'cpw -pw "" pqfree' | pwq_lines)" "$(mit_local 'cpw -pw "" pqfree' | pwq_lines)"
rust_local 'modprinc -policy pq pqfree' >/dev/null
mit_local 'modprinc -policy pq pqfree' >/dev/null
dl pwq-cpw-princ "$(rust_local 'cpw -pw PqFree pqfree' | pwq_lines)" "$(mit_local 'cpw -pw PqFree pqfree' | pwq_lines)"
rust_local 'cpw -pw PqFree pqfree' | grep -F 'change_password: Password may not match principal name while changing password for "pqfree@KERBER.TEST".'
# [realms] dict_file (alt_prof.c:513; pwqual_dict.c): exact word, strcasecmp,
# only with a policy. Both kadmin.locals read the container's kdc.conf.
docker exec "$NAME" sh -c 'printf "zebra\ncorrecthorse\napple\n" >/tmp/dict.txt && sed -i "s#^\(\s*\)max_life = #\1dict_file = /tmp/dict.txt\n\1max_life = #" /etc/krb5kdc/kdc.conf && grep -q "dict_file = /tmp/dict.txt" /etc/krb5kdc/kdc.conf'
dl pwq-dict-word "$(rust_local 'addprinc -pw CorrectHorse -policy pq pqdict' | pwq_lines)" "$(mit_local 'addprinc -pw CorrectHorse -policy pq pqdict' | pwq_lines)"
rust_local 'addprinc -pw CorrectHorse -policy pq pqdict' | grep -F 'add_principal: Password is in the password dictionary while creating "pqdict@KERBER.TEST".'
dl pwq-dict-nopolicy-ok "$(rust_local 'addprinc -pw correcthorse pqdictnp' | pwq_lines)" "$(mit_local 'addprinc -pw correcthorse pqdictnp' | pwq_lines)"
dl pwq-dict-substring-ok "$(rust_local 'addprinc -pw correcthorse1 -policy pq pqdictsub' | pwq_lines)" "$(mit_local 'addprinc -pw correcthorse1 -policy pq pqdictsub' | pwq_lines)"
rust_local 'getprinc pqdictsub' | grep -F 'Principal: pqdictsub@KERBER.TEST'
docker exec "$NAME" sh -c 'sed -i "/dict_file = \/tmp\/dict.txt/d" /etc/krb5kdc/kdc.conf'
echo "c1_pwqual_modules=identical"

docker exec "$NAME" sh -c 'kdb5_util destroy -f >/dev/null 2>&1'

echo "==== kadmin.local ignores KRB5_ACL_FILE ===="
set +e
ACLOK="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/no-such-acl \
    "$NAME" /tmp/krb5-kadmin-local -q 'listprincs' 2>&1)"
aclrc=$?
set -e
echo "$ACLOK"
test "$aclrc" -eq 0
echo "$ACLOK" | grep -F 'user@KERBER.TEST'

docker exec "$NAME" sh -c 'cat >/tmp/kadm5.acl <<EOF
admin@KERBER.TEST *e
EOF'

docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen"'
    exit 1
fi

docker exec "$NAME" sh -c 'cat >/tmp/kadmin-krb5.conf <<EOF
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_kadmin
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        admin_server = 127.0.0.1
    }
EOF'

echo "==== MIT kadmin getprinc/listprincs extra2 ===="
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" sh -c 'printf "adminpassword\n" | kinit admin@KERBER.TEST'
MITGET="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra2')"
echo "$MITGET"
echo "$MITGET" | grep -q 'extra2@KERBER.TEST'
MITLIST="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'listprincs extra2*')"
echo "$MITLIST"
echo "$MITLIST" | grep -q 'extra2@KERBER.TEST'

echo "==== MIT kadmin getprinc host/slashhost ===="
MITSLASH="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc host/slashhost')"
echo "$MITSLASH"
echo "$MITSLASH" | grep -q 'Principal: host/slashhost@KERBER.TEST'
echo "$MITSLASH" | grep -qi 'does not exist' && {
    log "kadmin.local.gate" "error" ',"error":"MIT did not find host/slashhost as two components"'
    exit 1
}

echo "==== MIT getprinc randsvc (vno 1) + kinit -k ===="
MITRAND="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc randsvc')"
echo "$MITRAND"
echo "$MITRAND" | grep -q 'randsvc@KERBER.TEST'
echo "$MITRAND" | grep -Eq '^Key: vno[[:space:]]*1'
echo "$MITGET" | grep -q 'REQUIRES_PRE_AUTH' && {
    echo "extra2 should have been cleared of REQUIRES_PRE_AUTH before kadmind" >&2
    exit 1
}
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -norandkey -k /tmp/rand.keytab randsvc'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kinit -k -t /tmp/rand.keytab randsvc@KERBER.TEST
echo "kinit -k randsvc ok"

echo "==== modprinc +requires_preauth and ktadd merge ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +requires_preauth extra2'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/both.keytab ktone'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/both.keytab kttwo'
KLISTK="$(docker exec "$NAME" klist -k /tmp/both.keytab)"
echo "$KLISTK"
echo "$KLISTK" | grep -q 'ktone@KERBER.TEST'
echo "$KLISTK" | grep -q 'kttwo@KERBER.TEST'

docker exec "$NAME" sh -c 'kill $(pidof krb5-kadmind) 2>/dev/null || true; for _ in $(seq 1 40); do pidof krb5-kadmind >/dev/null || break; sleep 0.25; done; rm -f /tmp/kadmind.log'
docker exec "$NAME" sh -c '! pidof krb5-kadmind >/dev/null'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen after restart"'
    exit 1
fi
MITPRE="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc extra2')"
echo "$MITPRE"
echo "$MITPRE" | grep -q 'REQUIRES_PRE_AUTH'
MITKV="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc ktone')"
echo "$MITKV"
echo "$MITKV" | grep -Eq '^Key: vno[[:space:]]*2'

echo "==== local setstr does not clobber concurrent kadmind create ===="
docker exec "$NAME" sh -c '
  set -e
  rm -f /tmp/klfifo
  mkfifo /tmp/klfifo
  env KRB5_KDC_DB=/tmp/principal KRB5_KDC_STASH=/tmp/stash \
    /tmp/krb5-kadmin-local </tmp/klfifo >/tmp/kl.out 2>/tmp/kl.err &
  echo $! >/tmp/kl.pid
  exec 3>/tmp/klfifo
  # The background local session must load the store before the concurrent
  # kadmind create. Probe: the kadmin-local pid is alive.
  while ! kill -0 "$(cat /tmp/kl.pid)" 2>/dev/null; do sleep 0.05; done
  env KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    kadmin -p admin@KERBER.TEST -w adminpassword -q "addprinc -pw race-pw raceprinc"
  echo "setstr extra2 racek racev" >&3
  echo q >&3
  exec 3>&-
  wait "$(cat /tmp/kl.pid)"
'
RACE="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc raceprinc')"
echo "$RACE"
echo "$RACE" | grep -q 'raceprinc@KERBER.TEST'
echo "$RACE" | grep -qi 'does not exist' && {
    log "kadmin.local.gate" "error" ',"error":"local setstr clobbered concurrent kadmind principal"'
    exit 1
}
RACESTR="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getstrs extra2')"
echo "$RACESTR"
echo "$RACESTR" | grep -q 'racek: racev'

echo "==== MIT kadmin.local lockdown oracle ===="
docker exec "$NAME" sh -c '
set -e
kdb5_util create -s -P masterpassword -r KERBER.TEST
kadmin.local -r KERBER.TEST -q "addprinc -randkey lockee@KERBER.TEST"
kadmin.local -r KERBER.TEST -q "modprinc +lockdown_keys lockee@KERBER.TEST"
echo "---- getprinc lockee before ktadd ----"
kadmin.local -r KERBER.TEST -q "getprinc lockee@KERBER.TEST"
kadmin.local -r KERBER.TEST -q "ktadd -k /tmp/mit-lockee.keytab lockee@KERBER.TEST"
echo mit_lockee_ktadd_rc=$?
echo "---- getprinc lockee after ktadd ----"
kadmin.local -r KERBER.TEST -q "getprinc lockee@KERBER.TEST"
kadmin.local -r KERBER.TEST -q "ktadd -k /tmp/mit-krbtgt.keytab krbtgt/KERBER.TEST"
echo mit_krbtgt_ktadd_rc=$?
echo "---- getprinc krbtgt after ktadd ----"
kadmin.local -r KERBER.TEST -q "getprinc krbtgt/KERBER.TEST"
echo "---- klist -k ----"
klist -k /tmp/mit-lockee.keytab
klist -k /tmp/mit-krbtgt.keytab
'
MITL="$(docker exec "$NAME" kadmin.local -r KERBER.TEST -q 'getprinc lockee@KERBER.TEST')"
echo "$MITL"
echo "$MITL" | grep -qi LOCKDOWN
echo "$MITL" | grep -Eq '^Key: vno[[:space:]]*2'
docker exec "$NAME" test -s /tmp/mit-lockee.keytab
docker exec "$NAME" test -s /tmp/mit-krbtgt.keytab
MITKGT="$(docker exec "$NAME" kadmin.local -r KERBER.TEST -q 'getprinc krbtgt/KERBER.TEST')"
echo "$MITKGT"
echo "$MITKGT" | grep -qi LOCKDOWN
echo "$MITKGT" | grep -Eq '^Key: vno[[:space:]]*2'

echo "==== Rust ktadd on +lockdown_keys (test-realm) ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey lockee'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +lockdown_keys lockee'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/lockee.keytab lockee'
LK="$(docker exec "$NAME" klist -k /tmp/lockee.keytab)"
echo "$LK"
echo "$LK" | grep -q 'lockee@KERBER.TEST'
docker exec "$NAME" sh -c 'kill $(pidof krb5-kadmind) 2>/dev/null || true; for _ in $(seq 1 40); do pidof krb5-kadmind >/dev/null || break; sleep 0.25; done; rm -f /tmp/kadmind.log'
docker exec "$NAME" sh -c '! pidof krb5-kadmind >/dev/null'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen after lockdown ktadd"'
    exit 1
fi
MITLOCK="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc lockee')"
echo "$MITLOCK"
echo "$MITLOCK" | grep -qi LOCKDOWN
echo "$MITLOCK" | grep -Eq '^Key: vno[[:space:]]*2'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" \
    kinit -k -t /tmp/lockee.keytab lockee@KERBER.TEST
echo "kinit -k lockee ok"

echo "==== golden dump ktadd lockdown + krbtgt footgun ===="
docker cp tests/traces/kdb/mit-dump-v7.txt "$NAME":/tmp/mit.dump
docker exec \
    -e KRB5_MASTER_PASSWORD=masterpassword \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kdb load /tmp/mit.dump
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey gldlock'
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'modprinc +lockdown_keys gldlock'
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/gld.locktab gldlock'
GLD="$(docker exec "$NAME" klist -k /tmp/gld.locktab)"
echo "$GLD"
echo "$GLD" | grep -q 'gldlock@KERBER.TEST'
docker exec \
    -e KRB5_KDC_DB=/tmp/golden-principal \
    -e KRB5_KDC_STASH=/tmp/golden-stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'ktadd -k /tmp/gld-krbtgt.keytab krbtgt/KERBER.TEST'
GTGT="$(docker exec "$NAME" klist -k /tmp/gld-krbtgt.keytab)"
echo "$GTGT"
echo "$GTGT" | grep -q 'krbtgt/KERBER.TEST@KERBER.TEST'

echo "==== setstr does not clobber concurrent kadmind create ===="
docker exec "$NAME" sh -c '
  set -e
  rm -f /tmp/m5fifo
  mkfifo /tmp/m5fifo
  env KRB5_KDC_DB=/tmp/principal KRB5_KDC_STASH=/tmp/stash \
    /tmp/krb5-kadmin-local </tmp/m5fifo >/tmp/m5.out 2>/tmp/m5.err &
  echo $! >/tmp/m5.pid
  exec 3>/tmp/m5fifo
  while ! kill -0 "$(cat /tmp/m5.pid)" 2>/dev/null; do sleep 0.05; done
  env KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    kadmin -p admin@KERBER.TEST -w adminpassword -q "addprinc -pw m5-pw m5race"
  echo "setstr extra2 m5k m5v" >&3
  echo q >&3
  exec 3>&-
  wait "$(cat /tmp/m5.pid)"
'
echo "---- m5.err ----"
docker exec "$NAME" cat /tmp/m5.err || true
M5R="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc m5race')"
echo "$M5R"
echo "$M5R" | grep -q 'm5race@KERBER.TEST'
echo "$M5R" | grep -qi 'does not exist' && {
    log "kadmin.local.gate" "error" ',"error":"setstr clobbered concurrent kadmind principal"'
    exit 1
}
M5S="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getstrs extra2')"
echo "$M5S"
echo "$M5S" | grep -q 'm5k: m5v'
M5E="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc extra2')"
echo "$M5E"
echo "$M5E" | grep -q 'extra2@KERBER.TEST'

echo "==== local addprinc then remote cpw keeps both ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_PASSWORD=n7-pw \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc n7local'
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'cpw -pw extra-n7 extra2'
N7L="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc n7local')"
echo "$N7L"
echo "$N7L" | grep -q 'n7local@KERBER.TEST'
N7E="$(docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc extra2')"
echo "$N7E"
echo "$N7E" | grep -q 'extra2@KERBER.TEST'

echo "==== addprinc -randkey kadmin/changepw keeps PWCHANGE_SERVICE ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'delprinc -force kadmin/changepw'
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey kadmin/changepw'
docker exec "$NAME" sh -c 'kill $(pidof krb5-kadmind) 2>/dev/null || true; for _ in $(seq 1 40); do pidof krb5-kadmind >/dev/null || break; sleep 0.25; done; rm -f /tmp/kadmind.log'
docker exec "$NAME" sh -c '! pidof krb5-kadmind >/dev/null'
docker exec -d \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    -e KRB5_ACL_FILE=/tmp/kadm5.acl \
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
    log "kadmin.local.gate" "error" ',"error":"kadmind did not listen after changepw recreate"'
    exit 1
fi
MITCPW="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'getprinc kadmin/changepw')"
echo "$MITCPW"
echo "$MITCPW" | grep -q 'PWCHANGE_SERVICE'

echo "==== local cpw then remote ktadd -norandkey uses new key ===="
docker exec \
    -e KRB5_KDC_DB=/tmp/principal \
    -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'cpw -pw o3-new-secret user'
KTN="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q 'ktadd -norandkey -k /tmp/o3user.keytab user' 2>&1 || true)"
echo "$KTN"
echo "$KTN" | grep -qi 'added to keytab'
if echo "$KTN" | grep -qiE 'extract-keys|AUTH_EXTRACT|Operation requires|while adding'; then
    echo "ktadd -norandkey after local cpw failed: $KTN" >&2
    exit 1
fi
docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf \
    "$NAME" kinit -k -t /tmp/o3user.keytab user@KERBER.TEST
O3L="$(docker exec -e KRB5_CONFIG=/tmp/kadmin-krb5.conf "$NAME" klist)"
echo "$O3L"
echo "$O3L" | grep -q 'user@KERBER.TEST'

echo "==== kadmin.local alias verb, identical to MIT ===="
docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -pw canon-secret canon' >/dev/null
mit_local 'addprinc -pw canon-secret canon' >/dev/null
RAL="$(rust_local 'alias av1 canon')"
echo "$RAL"
echo "$RAL" | grep -Fx 'Principal "av1@KERBER.TEST" aliased to "canon@KERBER.TEST".'
dl alias-first "$RAL" "$(mit_local 'alias av1 canon')"
# getprinc through the alias returns the target's record on each leg (the full
# MIT-format getprinc printer is M4c; compare alias vs target within a leg).
dl getprinc-alias-rust "$(rust_local 'getprinc av1')" "$(rust_local 'getprinc canon')"
dl getprinc-alias-mit "$(mit_local 'getprinc av1')" "$(mit_local 'getprinc canon')"
dl alias-dup "$(rust_local 'alias av1 canon' 2>&1)" "$(mit_local 'alias av1 canon' 2>&1)"
dl alias-badrealm "$(rust_local 'alias bad x@OTHER.REALM' 2>&1)" "$(mit_local 'alias bad x@OTHER.REALM' 2>&1)"
dl alias-justone "$(rust_local 'alias justone' 2>&1)" "$(mit_local 'alias justone' 2>&1)"

echo "==== policy validation order and texts, identical to MIT ===="
# min>max BEFORE length (MIT kadm5_create_policy), and the exact kadm_err texts.
dl addpol-order "$(rust_local 'addpol -minlength 0 -minlife 2h -maxlife 1h ordr' 2>&1)" "$(mit_local 'addpol -minlength 0 -minlife 2h -maxlife 1h ordr' 2>&1)"
dl addpol-minclasses "$(rust_local 'addpol -minclasses 6 cls' 2>&1)" "$(mit_local 'addpol -minclasses 6 cls' 2>&1)"
dl addpol-history0 "$(rust_local 'addpol -history 0 h0' 2>&1)" "$(mit_local 'addpol -history 0 h0' 2>&1)"
rust_local 'addpol mpol' >/dev/null
mit_local 'addpol mpol' >/dev/null
dl modpol-order "$(rust_local 'modpol -minlife 2h -maxlife 1h mpol' 2>&1)" "$(mit_local 'modpol -minlife 2h -maxlife 1h mpol' 2>&1)"
dl modpol-nosuch "$(rust_local 'modpol nosuchpol' 2>&1)" "$(mit_local 'modpol nosuchpol' 2>&1)"
for pol in ordr cls h0; do
    if rust_local 'listpols' | grep -Fx "$pol"; then
        echo "rejected policy $pol was created" >&2
        exit 1
    fi
done

echo "==== getprinc names a deleted bound policy [does not exist], both legs ===="
for leg in rust_local mit_local; do
    "$leg" 'addpol gonep' >/dev/null
    "$leg" 'addprinc -pw dnp-secret -policy gonep dnepu' >/dev/null
    "$leg" 'delpol -force gonep' >/dev/null
done
dl getprinc-dead-policy \
    "$(rust_local 'getprinc dnepu' | grep '^Policy:')" \
    "$(mit_local 'getprinc dnepu' | grep '^Policy:')"
rust_local 'getprinc dnepu' | grep -Fx 'Policy: gonep [does not exist]'

echo "==== listprincs / listpols glob filters, identical to MIT ===="
for pr in ga1 ga2 gb1; do
    rust_local "addprinc -pw gx $pr" >/dev/null
    mit_local "addprinc -pw gx $pr" >/dev/null
done
for g in 'ga*' 'g?1' '*1' '[gb]a*' 'ga1@*' 'ga.1' '[[:digit:]]*'; do
    dl "listprincs-$g" "$(rust_local "listprincs $g" | grep -v '^Authenticating' | sort)" "$(mit_local "listprincs $g" | sort)"
done
dl listprincs-malformed-bracket \
    "$(rust_local 'listprincs [abc' 2>&1 | grep -F 'Invalid argument')" \
    "$(mit_local 'listprincs [abc' 2>&1 | grep -F 'Invalid argument')"
dl 'listprincs-ga-backslash' "$(rust_local 'listprincs ga\\' 2>&1 | grep -v '^Authenticating')" "$(mit_local 'listprincs ga\\' 2>&1)"
for pl in gpol1 gpolx gp2; do
    rust_local "addpol $pl" >/dev/null
    mit_local "addpol $pl" >/dev/null
done
for g in 'gpol*' '*x' 'gp?' 'gpol1' '*@*'; do
    dl "listpols-$g" "$(rust_local "listpols $g" | grep -v '^Authenticating' | sort)" "$(mit_local "listpols $g" | sort)"
done

echo "==== Z6.4 kadmin.local stamps princstr (kadmin.c:455-536) ===="
# uid 0 with USER unset is getpwuid → root → root/admin@REALM. The date is
# dropped; only the modifier is compared (both legs, MIT kadmin.local vs
# Rust krb5-kadmin.local).
z64l_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
# Do not pass `-e USER=`: MIT `getenv("USER")` treats a set-but-empty
# value as a name and stamps `/admin@REALM`. An unset USER falls through
# to getpwuid (uid 0 → root) like `kadmin.c:519-527`.
RUST64="$(docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'addprinc -randkey z64l' 2>&1 || true)"
echo "$RUST64"
echo "$RUST64" | grep -F 'Principal "z64l@KERBER.TEST" created.'
R64GET="$(docker exec -e KRB5_KDC_DB=/tmp/principal -e KRB5_KDC_STASH=/tmp/stash \
    "$NAME" /tmp/krb5-kadmin-local -q 'getprinc z64l')"
echo "$R64GET"
R64MOD="$(echo "$R64GET" | z64l_mod)"
echo "rust modifier=$R64MOD"
[ "$R64MOD" = "root/admin@KERBER.TEST" ] || {
    echo "Rust kadmin.local modifier is not root/admin@KERBER.TEST: $R64GET" >&2
    exit 1
}
MIT64="$(docker exec "$NAME" kadmin.local -q 'addprinc -randkey z64l' 2>&1 || true)"
echo "$MIT64"
echo "$MIT64" | grep -F 'Principal "z64l@KERBER.TEST" created.'
M64GET="$(docker exec "$NAME" kadmin.local -q 'getprinc z64l')"
echo "$M64GET"
M64MOD="$(echo "$M64GET" | z64l_mod)"
echo "mit modifier=$M64MOD"
[ "$M64MOD" = "root/admin@KERBER.TEST" ] || {
    echo "MIT kadmin.local modifier is not root/admin@KERBER.TEST: $M64GET" >&2
    exit 1
}
[ "$R64MOD" = "$M64MOD" ] || {
    echo "Z6.4 kadmin.local modifier differs: rust=$R64MOD mit=$M64MOD" >&2
    exit 1
}

echo "==== Z7.2 local ktadd/unlock stamp princstr; addprinc -policy -e keysalt ===="
z72l_mod() { sed -n -E 's/^Last modified: .* \((.*)\)$/\1/p'; }
# USER unset → getpwuid uid 0 → root/admin@ like Z6.4.
rust_local 'addprinc -randkey z72kt' >/dev/null
mit_local 'addprinc -randkey z72kt' >/dev/null
rust_local 'ktadd -k /tmp/z72.kt z72kt' >/dev/null
mit_local 'ktadd -k /tmp/z72-mit.kt z72kt' >/dev/null
R72KT="$(echo "$(rust_local 'getprinc z72kt')" | z72l_mod)"
M72KT="$(echo "$(mit_local 'getprinc z72kt')" | z72l_mod)"
echo "ktadd rust modifier=$R72KT mit=$M72KT"
[ "$R72KT" = "root/admin@KERBER.TEST" ] || {
    echo "Rust ktadd modifier is not root/admin@KERBER.TEST" >&2
    exit 1
}
[ "$R72KT" = "$M72KT" ] || {
    echo "Z7.2 ktadd modifier differs: rust=$R72KT mit=$M72KT" >&2
    exit 1
}
rust_local 'addprinc -pw z72ul-secret z72ul' >/dev/null
mit_local 'addprinc -pw z72ul-secret z72ul' >/dev/null
rust_local 'modprinc -unlock z72ul' >/dev/null
mit_local 'modprinc -unlock z72ul' >/dev/null
R72UL="$(echo "$(rust_local 'getprinc z72ul')" | z72l_mod)"
M72UL="$(echo "$(mit_local 'getprinc z72ul')" | z72l_mod)"
echo "unlock rust modifier=$R72UL mit=$M72UL"
[ "$R72UL" = "root/admin@KERBER.TEST" ] || {
    echo "Rust unlock modifier is not root/admin@KERBER.TEST" >&2
    exit 1
}
[ "$R72UL" = "$M72UL" ] || {
    echo "Z7.2 unlock modifier differs: rust=$R72UL mit=$M72UL" >&2
    exit 1
}
rust_local 'addpol -allowedkeysalts aes256-cts:normal z72ks' >/dev/null
mit_local 'addpol -allowedkeysalts aes256-cts:normal z72ks' >/dev/null
dl z72-local-ks \
    "$(rust_local 'addprinc -policy z72ks -e aes128-cts:normal -pw ValidPass1 z72ksbad' 2>&1 | grep -F 'Invalid key/salt tuples')" \
    "$(mit_local 'addprinc -policy z72ks -e aes128-cts:normal -pw ValidPass1 z72ksbad' 2>&1 | grep -F 'Invalid key/salt tuples')"
if rust_local 'getprinc z72ksbad' 2>&1 | grep -q '^Principal: z72ksbad@'; then
    echo "rejected local keysalt create left an entry" >&2
    exit 1
fi

log "kadmin.local.gate" "ok" ',"principal":"extra2@KERBER.TEST,host/slashhost@KERBER.TEST,randsvc,ktone,kttwo,raceprinc,lockee,gldlock,krbtgt","verb":"alias+policy-order+glob"'
exit 0
