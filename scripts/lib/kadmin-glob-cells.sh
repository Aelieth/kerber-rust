#!/usr/bin/env bash
# kadmin-gate cells shared by both legs (sourced; keeps the gate's cell lines stable).
# shellcheck shell=bash

# Drop Last-modified date so rust/MIT getprinc diffs see the modifier only.
hist_shape() {
    grep -E '^(Expiration date|Password expiration date|Maximum ticket life|Maximum renewable life|Attributes|Number of keys|Key: vno|MKey: vno|Policy|Last modified):?' \
        | sed -E 's/^(Last modified): .* \((.*)\)$/\1: (\2)/'
}

# Principal aliases on one leg, like MIT tests/t_alias.py + t_kadmin_acl.py
# (server_stubs.c:1727-1758, auth_acl.c:723-734, svr_principal.c:2051-2087,
# do_as_req.c:681-687, do_tgs_req.c:1029). Texts settled live in
# working/logs/audit-polish-0902/w1k/m3a-settle-mit-alias.log.
alias_cells() {
    local ctn=$1 conf=$2 admin=$3 leg=$4
    kq() {
        docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$1" -w "$2" -q "$3" 2>&1 || true
    }
    kadm() { kq "$admin" adminpassword "$1"; }
    kinit_alias() {
        docker exec -e KRB5_CONFIG="$conf" "$ctn" \
            sh -c "printf 'userpassword\n' | kinit -c /tmp/alias.cc $1" 2>&1 || true
    }
    klist_alias() { docker exec -e KRB5_CONFIG="$conf" "$ctn" klist -c /tmp/alias.cc 2>&1 || true; }
    kvno_alias() { docker exec -e KRB5_CONFIG="$conf" "$ctn" kvno -c /tmp/alias.cc "$@" 2>&1 || true; }
    local out get
    echo "==== $leg alias: actors ===="
    kadm 'addprinc -pw pw some_alias' | grep -F 'Principal "some_alias@KERBER.TEST" created.'
    kadm 'addprinc -pw pw restricted_alias' | grep -F 'Principal "restricted_alias@KERBER.TEST" created.'
    kadm 'addprinc -pw pw none' | grep -F 'Principal "none@KERBER.TEST" created.'

    echo "==== $leg alias: admin creates a1 -> user, getprinc resolves to the target ===="
    out="$(kadm 'alias a1 user')"
    echo "$out"
    echo "$out" | grep -F 'Principal "a1@KERBER.TEST" aliased to "user@KERBER.TEST".'
    get="$(kadm 'getprinc a1')"
    echo "$get"
    echo "$get" | grep -F 'Principal: user@KERBER.TEST'
    # getprinc through the alias returns the target's whole record verbatim.
    diff <(kadm 'getprinc a1' | grep -v -e '^Authenticating' -e 'No dictionary') \
         <(kadm 'getprinc user' | grep -v -e '^Authenticating' -e 'No dictionary')
    kadm 'listprincs' | grep -Fx 'a1@KERBER.TEST'

    echo "==== $leg alias: duplicate, addprinc over an alias, cross-realm target ===="
    out="$(kadm 'alias a1 user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Principal or policy already exists while aliasing principal "a1@KERBER.TEST" to "user@KERBER.TEST"'
    out="$(kadm 'addprinc -pw x a1')"
    echo "$out"
    echo "$out" | grep -F 'add_principal: Principal or policy already exists while creating "a1@KERBER.TEST".'
    out="$(kadm 'alias x y@OTHER.REALM')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Alias target must be within the same realm while aliasing principal "x@KERBER.TEST" to "y@OTHER.REALM"'
    kadm 'getprinc x' | grep -F 'get_principal: Principal does not exist while retrieving "x@KERBER.TEST".'

    echo "==== $leg alias: dangling target is legal and the name stays creatable ===="
    kadm 'alias xa1 nosuch' | grep -F 'Principal "xa1@KERBER.TEST" aliased to "nosuch@KERBER.TEST".'
    kadm 'getprinc xa1' | grep -F 'get_principal: Principal does not exist while retrieving "xa1@KERBER.TEST".'
    kadm 'addprinc -pw x xa1' | grep -F 'Principal "xa1@KERBER.TEST" created.'
    kadm 'getprinc xa1' | grep -F 'Principal: xa1@KERBER.TEST'

    echo "==== $leg alias: renprinc of an alias is unsupported; delprinc removes the stub only ===="
    out="$(kadm 'renprinc -force a1 b1')"
    echo "$out"
    echo "$out" | grep -F 'rename_principal: Operation unsupported on alias principal name while renaming principal "a1@KERBER.TEST" to "b1@KERBER.TEST"'
    kadm 'getprinc b1' | grep -F 'Principal does not exist'
    kadm 'alias tmpalias user' | grep -F 'aliased to "user@KERBER.TEST".'
    kadm 'delprinc -force tmpalias' | grep -F 'Principal "tmpalias@KERBER.TEST" deleted.'
    kadm 'getprinc tmpalias' | grep -F 'get_principal: Principal does not exist while retrieving "tmpalias@KERBER.TEST".'
    kadm 'getprinc user' | grep -F 'Principal: user@KERBER.TEST'

    echo "==== $leg alias: acl_addalias = add on the alias without restrictions AND modify on the target ===="
    kq some_alias pw 'alias aliasname user' | grep -F 'Principal "aliasname@KERBER.TEST" aliased to "user@KERBER.TEST".'
    out="$(kq some_alias pw 'alias other user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "other@KERBER.TEST" to "user@KERBER.TEST"'
    out="$(kq some_alias pw 'alias aliasname2 host/testhost.kerber.test')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "aliasname2@KERBER.TEST" to "host/testhost.kerber.test@KERBER.TEST"'
    out="$(kq restricted_alias pw 'alias r1 user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "r1@KERBER.TEST" to "user@KERBER.TEST"'
    out="$(kq none pw 'alias n1 user')"
    echo "$out"
    echo "$out" | grep -F 'add_alias: Insufficient authorization for operation while aliasing principal "n1@KERBER.TEST" to "user@KERBER.TEST"'
    for denied in other aliasname2 r1 n1; do
        kadm "getprinc $denied" | grep -F "get_principal: Principal does not exist while retrieving \"$denied@KERBER.TEST\"."
    done

    echo "==== $leg alias: kinit keeps the requested name, -C canonicalizes, kvno keeps the requested sname ===="
    out="$(kinit_alias a1)"
    echo "$out"
    out="$(klist_alias)"
    echo "$out"
    echo "$out" | grep -F 'Default principal: a1@KERBER.TEST'
    echo "$out" | grep -F 'krbtgt/KERBER.TEST@KERBER.TEST'
    out="$(kvno_alias a1 aliasname)"
    echo "$out"
    echo "$out" | grep -E '^a1@KERBER.TEST: kvno = [0-9]+$'
    echo "$out" | grep -E '^aliasname@KERBER.TEST: kvno = [0-9]+$'
    klist_alias | grep -F ' a1@KERBER.TEST'
    out="$(kinit_alias '-C a1')"
    echo "$out"
    out="$(klist_alias)"
    echo "$out"
    echo "$out" | grep -F 'Default principal: user@KERBER.TEST'

    echo "==== $leg alias: chains resolve to depth 10; 11 and a self-alias are not found ===="
    local i
    for i in $(seq 2 11); do
        kadm "alias a$i a$((i - 1))" | grep -F "aliased to \"a$((i - 1))@KERBER.TEST\"."
    done
    kadm 'alias selfalias selfalias' | grep -F 'Principal "selfalias@KERBER.TEST" aliased to "selfalias@KERBER.TEST".'
    out="$(kvno_alias a10)"
    echo "$out"
    echo "$out" | grep -E '^a10@KERBER.TEST: kvno = [0-9]+$'
    out="$(kvno_alias a11)"
    echo "$out"
    echo "$out" | grep -F 'kvno: Server a11@KERBER.TEST not found in Kerberos database while getting credentials for a11@KERBER.TEST'
    out="$(kvno_alias selfalias)"
    echo "$out"
    echo "$out" | grep -F 'kvno: Server selfalias@KERBER.TEST not found in Kerberos database while getting credentials for selfalias@KERBER.TEST'
    out="$(kinit_alias a11)"
    echo "$out"
    echo "$out" | grep -F "kinit: Client 'a11@KERBER.TEST' not found in Kerberos database while getting initial credentials"
    kadm 'getprinc a10' | grep -F 'Principal: user@KERBER.TEST'
    kadm 'getprinc a11' | grep -F 'get_principal: Principal does not exist while retrieving "a11@KERBER.TEST".'
    docker exec "$ctn" rm -f /tmp/alias.cc
}

# svr_iters.c glob_to_regexp over the kadm5 RPC: listprincs/listpols patterns
# (`?*[]`, anchored, implicit `@*`) are expanded by the server, so the MIT
# kadmin client must see identical lists from the Rust kadmind and MIT's.
glob_cells() {
    local ctn=$1 conf=$2 admin=$3 leg=$4 out=$5
    kg() {
        docker exec -e KRB5_CONFIG="$conf" "$ctn" kadmin -p "$admin" -w adminpassword -q "$1" 2>&1 || true
    }
    echo "==== $leg glob: fixtures ===="
    for pr in ga1 ga2 gb1 gaa ga.1; do
        kg "addprinc -pw pw $pr" | grep -F "Principal \"$pr@KERBER.TEST\" created."
    done
    for pol in gpol1 gpolx gp1; do
        kg "addpol $pol" | grep -v '^Authenticating' || true
    done
    echo "==== $leg glob: listprincs / listpols patterns ===="
    : >"$out"
    for g in 'ga*' 'g?1' '[gb]a*' 'ga1@*' 'ga.1' "ga\\\\" '[[:digit:]]*'; do
        {
            echo "== listprincs $g"
            kg "listprincs $g" | { grep -v '^Authenticating' || true; } | sort
        } >>"$out"
    done
    for g in 'gpol*' 'gp?' 'gpol1'; do
        {
            echo "== listpols $g"
            kg "listpols $g" | { grep -v '^Authenticating' || true; } | sort
        } >>"$out"
    done
    cat "$out"
    grep -qx 'ga1@KERBER.TEST' "$out"
    # R2-T8: the malformed glob 'ga\' (after ss_parse unescaping) is EINVAL on
    # both legs; assert the MIT diagnostic text is actually present, not merely
    # that the two legs' output happens to match (which a silent empty would).
    grep -qF 'Invalid argument' "$out"
}

