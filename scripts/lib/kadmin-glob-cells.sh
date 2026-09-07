#!/usr/bin/env bash
# kadmin-gate cells shared by both legs (sourced; keeps the gate's cell lines stable).
# shellcheck shell=bash

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
    for g in 'ga*' 'g?1' '[gb]a*' 'ga1@*' 'ga.1' 'ga\\' '[[:digit:]]*'; do
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
}

