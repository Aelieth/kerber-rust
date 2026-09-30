#!/usr/bin/env bash
# The gates' kadmin query paths. Sourced after gate-common.sh. kadmin_q / kadmin_q_as / kinit_try run MIT
# clients through the gate's client config inside $NAME: a gate sets KADMIN_Q_CONF (and GATE_CLIENT_CONF for
# kinit_try) to its config's path in the container. Every other query a gate or a scripts/lib file runs goes
# through a runner below (the keyed container sites of ci_policy/kadmin_q.py aside). A query whose output the cell
# does not check itself goes through kadmin_q_ok, unless kadmin_q_try marks it best-effort (a cleanup, or a setup
# that may already have run on a shared container), which runs it with no success check.
# shellcheck shell=bash

# kadmin_q QUERY: MIT kadmin as admin@KERBER.TEST; output and errors on stdout, never a failing rc.
kadmin_q() {
    docker exec -e KRB5_CONFIG="${KADMIN_Q_CONF:?kadmin_q: set KADMIN_Q_CONF}" \
        "$NAME" kadmin -p admin@KERBER.TEST -w adminpassword -q "$1" 2>&1 || true
}

# kadmin_q_as PRINCIPAL PASSWORD QUERY: the same as another principal.
kadmin_q_as() {
    docker exec -e KRB5_CONFIG="${KADMIN_Q_CONF:?kadmin_q_as: set KADMIN_Q_CONF}" \
        "$NAME" kadmin -p "$1" -w "$2" -q "$3" 2>&1 || true
}

# kinit_try SCRIPT: a client shell command in $NAME through the gate's client config; never a failing rc.
kinit_try() {
    docker exec -e KRB5_CONFIG="${GATE_CLIENT_CONF:?kinit_try: set GATE_CLIENT_CONF}" \
        "$NAME" sh -c "$1" 2>&1 || true
}

# The thin runners every direct query goes through: RUNNER [DOCKER-EXEC-OPTIONS...] CONTAINER -- KADMIN-ARGS...
# runs the kadmin program in CONTAINER with those arguments; its streams and exit status pass through untouched.
_kadmin_run() {
    local prog=$1 opts=()
    shift
    while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
        opts+=("$1")
        shift
    done
    if [ "$#" -eq 0 ] || [ "${#opts[@]}" -eq 0 ]; then
        echo "$prog: usage: [docker exec options] CONTAINER -- ARGS" >&2
        return 2
    fi
    shift
    docker exec "${opts[@]}" "$prog" "$@"
}
mit_kadmin_local() { _kadmin_run kadmin.local "$@"; }
mit_kadmin() { _kadmin_run kadmin "$@"; }
rust_kadmin_local() { _kadmin_run /tmp/krb5-kadmin-local "$@"; }

# The query of a query command: the argument after -q, else the last argument (the wrappers take it last).
_kadmin_query_of() {
    local prev='' a
    for a in "$@"; do
        if [ "$prev" = -q ]; then
            printf '%s' "$a"
            return 0
        fi
        prev=$a
    done
    printf '%s' "${!#}"
}

# _kadmin_with_query QUERY CMD ARGS...: run the query command with QUERY in place of its own.
_kadmin_with_query() {
    local q=$1 args=() prev='' a i=0 at=-1
    shift
    for a in "$@"; do
        [ "$prev" = -q ] && at=$i
        args+=("$a")
        prev=$a
        i=$((i + 1))
    done
    [ "$at" -ge 0 ] || at=$((${#args[@]} - 1))
    args[at]=$q
    "${args[@]}"
}

# The container of a query command: the argument before `--` of a runner, else $NAME.
_kadmin_container_of() {
    local prev=$NAME a
    for a in "$@"; do
        if [ "$a" = -- ]; then
            printf '%s' "$prev"
            return 0
        fi
        prev=$a
    done
    printf '%s' "$NAME"
}

# _kadmin_words QUERY: split a query into the global array KW the way kadmin's own parser does (words, with '…' and
# "…" quoting; no escapes).
_kadmin_words() {
    local s=$1 i c q='' w='' in=0
    KW=()
    for ((i = 0; i < ${#s}; i++)); do
        c=${s:i:1}
        if [ -n "$q" ]; then
            if [ "$c" = "$q" ]; then q=''; else w+=$c; fi
        elif [ "$c" = "'" ] || [ "$c" = '"' ]; then
            q=$c
            in=1
        elif [ "$c" = ' ' ] || [ "$c" = $'\t' ]; then
            [ "$in" = 1 ] && KW+=("$w")
            w='' in=0
        else
            w+=$c
            in=1
        fi
    done
    [ "$in" = 1 ] && KW+=("$w")
    return 0
}

# An ERE matching a literal string.
_kadmin_lit() { printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|]/\\&/g'; }

# A principal name as an ERE; a name without a realm matches the printed name with any realm.
_kadmin_ere() {
    local e
    e=$(_kadmin_lit "$1")
    [[ $1 == *@* ]] || e+='(@[^"]*)?'
    printf '%s' "$e"
}

# The ERE of MIT's success line for QUERY (kadmin.c / keytab.c texts, which the Rust kadmind prints too),
# naming the query's principal; empty for a verb that prints nothing on success.
_kadmin_success_ere() {
    local verb p n last ere=''
    _kadmin_words "$1"
    n=${#KW[@]}
    verb=${KW[0]:-}
    last=${KW[n - 1]:-}
    p=$(_kadmin_ere "$last")
    case "$verb" in
        addprinc | add_principal | ank) ere="^Principal \"$p\" created\\.$" ;;
        delprinc | delete_principal) ere="^Principal \"$p\" deleted\\.$" ;;
        modprinc | modify_principal) ere="^Principal \"$p\" modified\\.$" ;;
        cpw | change_password) ere="^Password for \"$p\" changed\\.$" ;;
        setstr | set_string) ere="^Attribute set for principal \"$(_kadmin_ere "${KW[1]:-}")\"\\.$" ;;
        delstr | del_string) ere="^Attribute removed from principal \"$(_kadmin_ere "${KW[1]:-}")\"\\.$" ;;
        ktadd | xst)
            ere="^Entry for principal $(_kadmin_lit "$last") with kvno [0-9]+, encryption type .* added to keytab "
            ;;
        ktremove | ktrem) ere="^Entry for principal $(_kadmin_lit "$last") with kvno [0-9]+ removed from keytab " ;;
        purgekeys) ere="^Old keys for principal \"$p\" purged\\.$" ;;
        renprinc | rename_principal) ere="^Principal \"$(_kadmin_ere "${KW[n - 2]}")\" renamed to \"$p\"\\.$" ;;
        alias) ere="^Principal \"$(_kadmin_ere "${KW[1]:-}")\" aliased to \"$p\"\\.$" ;;
        getprinc | get_principal) ere="^Principal: $p$" ;;
        getpol | get_policy) ere="^Policy: $(_kadmin_lit "$last")$" ;;
        getstrs | get_strings) ere='^(\(No string attributes\.\)|[^ :]+: .*)$' ;;
        getprivs | get_privs | get_privileges) ere='^current privileges:' ;;
        listprincs | list_principals | listpols | list_policies) ere='.' ;;
        *) ;;
    esac
    [[ $verb == cpw || $verb == change_password ]] && [[ " ${KW[*]} " == *" -randkey "* ]] \
        && ere="^Key for \"$p\" randomized\\.$"
    [[ $verb == purgekeys ]] && [[ " ${KW[*]} " == *" -all "* ]] && ere="^All keys for principal \"$p\" removed\\.$"
    printf '%s' "$ere"
}

# A duration as kadmin prints it (kadmin.c strdur: "D day(s) HH:MM:SS"), from N, Ns, Nm, Nh, Nd, N day(s); empty for
# any other spelling.
_kadmin_strdur() {
    local n u t
    [[ $1 =~ ^([0-9]+)\ ?(s|m|h|d|day|days)?$ ]] || return 0
    n=${BASH_REMATCH[1]} u=${BASH_REMATCH[2]}
    t=$n
    [[ $u == m ]] && t=$((n * 60))
    [[ $u == h ]] && t=$((n * 3600))
    [[ $u == d* ]] && t=$((n * 86400))
    n=$((t / 86400))
    u=days
    [ "$n" = 1 ] && u=day
    printf '%d %s %02d:%02d:%02d' "$n" "$u" $((t % 86400 / 3600)) $((t % 3600 / 60)) $((t % 60))
}

# The MIT output name of a modprinc flag (str_conv.c ftbl / outflags) and whether `+` sets it (1) or clears it (0).
_kadmin_flag() {
    local r=''
    case "$1" in
        allow_postdated | postdateable) r='DISALLOW_POSTDATED 0' ;;
        disallow_postdated) r='DISALLOW_POSTDATED 1' ;;
        allow_forwardable | forwardable) r='DISALLOW_FORWARDABLE 0' ;;
        disallow_forwardable) r='DISALLOW_FORWARDABLE 1' ;;
        allow_tgs_req | tgt_based) r='DISALLOW_TGT_BASED 0' ;;
        disallow_tgt_based) r='DISALLOW_TGT_BASED 1' ;;
        allow_renewable | renewable) r='DISALLOW_RENEWABLE 0' ;;
        disallow_renewable) r='DISALLOW_RENEWABLE 1' ;;
        allow_proxiable | proxiable) r='DISALLOW_PROXIABLE 0' ;;
        disallow_proxiable) r='DISALLOW_PROXIABLE 1' ;;
        allow_dup_skey | dup_skey) r='DISALLOW_DUP_SKEY 0' ;;
        disallow_dup_skey) r='DISALLOW_DUP_SKEY 1' ;;
        allow_tickets | allow_tix) r='DISALLOW_ALL_TIX 0' ;;
        disallow_all_tix) r='DISALLOW_ALL_TIX 1' ;;
        preauth | requires_pre_auth | requires_preauth) r='REQUIRES_PRE_AUTH 1' ;;
        hwauth | requires_hw_auth | requires_hwauth) r='REQUIRES_HW_AUTH 1' ;;
        needchange | pwchange | requires_pwchange) r='REQUIRES_PWCHANGE 1' ;;
        allow_svr | service) r='DISALLOW_SVR 0' ;;
        disallow_svr) r='DISALLOW_SVR 1' ;;
        password_changing_service | pwchange_service | pwservice) r='PWCHANGE_SERVICE 1' ;;
        ok_as_delegate) r='OK_AS_DELEGATE 1' ;;
        ok_to_auth_as_delegate) r='OK_TO_AUTH_AS_DELEGATE 1' ;;
        no_auth_data_required) r='NO_AUTH_DATA_REQUIRED 1' ;;
        lockdown_keys) r='LOCKDOWN_KEYS 1' ;;
        *) return 1 ;;
    esac
    echo "$r"
}

# _kadmin_effects QUERY: the read-only checks that prove a silent verb's effect, one per line as
# "QUERY<TAB>ERE" (the ERE must match that query's output; a leading ! means it must not), or
# "keytab<TAB>FILE<TAB>PRINCIPAL" (klist -k -e FILE holds PRINCIPAL at the kvno getprinc reports); a part of the
# query with no derivable check is a line "?<TAB>PART".
_kadmin_effects() {
    local verb pname n i o v d f line out=''
    _kadmin_words "$1"
    n=${#KW[@]}
    verb=${KW[0]:-}
    pname=${KW[n - 1]:-}
    case "$verb" in
        addpol | add_policy | modpol | modify_policy)
            [ "$n" -gt 2 ] || out=$(printf 'getpol %s\t^Policy: %s$' "$pname" "$(_kadmin_lit "$pname")")
            for ((i = 1; i < n - 1; i += 2)); do
                o=${KW[i]} v=${KW[i + 1]:-} f='' d=''
                case "$o" in
                    -minlength) f='Minimum password length' d=$v ;;
                    -minclasses) f='Minimum number of password character classes' d=$v ;;
                    -history) f='Number of old keys kept' d=$v ;;
                    -maxfailure) f='Maximum password failures before lockout' d=$v ;;
                    -allowedkeysalts) f='Allowed key/salt types' d=$v ;;
                    -maxlife) f='Maximum password life' d=$(_kadmin_strdur "$v") ;;
                    -minlife) f='Minimum password life' d=$(_kadmin_strdur "$v") ;;
                    -failurecountinterval) f='Password failure count reset interval' d=$(_kadmin_strdur "$v") ;;
                    -lockoutduration) f='Password lockout duration' d=$(_kadmin_strdur "$v") ;;
                    *) ;;
                esac
                line=$(printf '?\t%s %s' "$o" "$v")
                [[ -n $f && $d =~ ^[0-9A-Za-z:\ ,_-]+$ ]] \
                    && line=$(printf 'getpol %s\t^%s: %s$' "$pname" "$f" "$(_kadmin_lit "$d")")
                out+=${out:+$'\n'}$line
            done
            ;;
        delpol | delete_policy) out=$(printf 'getpol %s\t!^Policy: %s$' "$pname" "$(_kadmin_lit "$pname")") ;;
        modprinc | modify_principal)
            for ((i = 1; i < n - 1; i++)); do
                o=${KW[i]} v=${KW[i + 1]:-} line=''
                if [[ $o == [+-]* ]] && read -r f d < <(_kadmin_flag "${o:1}"); then
                    [ "${o:0:1}" = - ] && d=$((1 - d))
                    line=$(printf 'getprinc %s\t^Attributes:.* %s( |$)' "$pname" "$f")
                    [ "$d" = 1 ] || line=$(printf 'getprinc %s\t!^Attributes:.* %s( |$)' "$pname" "$f")
                    out+=${out:+$'\n'}$line
                    continue
                fi
                case "$o" in
                    -maxlife | -maxrenewlife)
                        f='Maximum ticket life'
                        [ "$o" = -maxrenewlife ] && f='Maximum renewable life'
                        d=$(_kadmin_strdur "$v")
                        line=$(printf 'getprinc %s\t^%s: %s$' "$pname" "$f" "$d")
                        [ -n "$d" ] || line=$(printf '?\t%s %s' "$o" "$v")
                        i=$((i + 1))
                        ;;
                    -policy)
                        line=$(printf 'getprinc %s\t^Policy: %s$' "$pname" "$(_kadmin_lit "$v")")
                        i=$((i + 1))
                        ;;
                    -clearpolicy) line=$(printf 'getprinc %s\t^Policy: \\[none\\]$' "$pname") ;;
                    -unlock) line=$(printf 'getprinc %s\t^Failed password attempts: 0$' "$pname") ;;
                    -kvno) line=$(printf 'getprinc %s\t^Key: vno %s,' "$pname" "$v") && i=$((i + 1)) ;;
                    [+-]*) line=$(printf '?\t%s %s' "$o" "$v") && i=$((i + 1)) ;;
                    *) line=$(printf '?\t%s' "$o") ;;
                esac
                out+=${out:+$'\n'}$line
            done
            ;;
        setstr | set_string)
            [ "$n" = 4 ] || return 1
            out=$(printf 'getstrs %s\t^%s: %s$' "${KW[1]}" "$(_kadmin_lit "${KW[2]}")" "$(_kadmin_lit "${KW[3]}")")
            ;;
        ktadd | xst)
            f=''
            for ((i = 1; i < n - 1; i++)); do
                case "${KW[i]}" in
                    -k | -keytab) f=${KW[i + 1]} && i=$((i + 1)) ;;
                    -norandkey | -q) ;;
                    -e) i=$((i + 1)) ;;
                    *) return 1 ;;
                esac
            done
            [ -n "$f" ] || return 1
            out=$(printf 'keytab\t%s\t%s' "$f" "$pname")
            ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$out"
}

# _kadmin_check Q EREs CMD ARGS...: run the read-only Q once through the query command; every ERE in the
# newline-separated EREs (each ERE, or !ERE for absence) must hold on its output.
_kadmin_check() {
    local q=$1 eres=$2 out ere
    shift 2
    out=$(_kadmin_with_query "$q" "$@" 2>&1) || true
    printf '%s\n' "$out"
    while IFS= read -r ere; do
        [ -n "$ere" ] || continue
        if [ "${ere:0:1}" = '!' ]; then
            ! grep -Eq -- "${ere:1}" <<<"$out" || _kadmin_q_fail "$_KADMIN_Q" "follow-up $q: a line matches /${ere:1}/" "$out"
        else
            grep -Eq -- "$ere" <<<"$out" || _kadmin_q_fail "$_KADMIN_Q" "follow-up $q: no line /$ere/" "$out"
        fi
    done <<<"$eres"
}

# _kadmin_keytab FILE PRINCIPAL CMD ARGS...: klist -k -e FILE in the command's container holds PRINCIPAL at the
# highest kvno getprinc reports.
_kadmin_keytab() {
    local f=$1 p=$2 out kvno
    shift 2
    out=$(_kadmin_with_query "getprinc $p" "$@" 2>&1) || true
    printf '%s\n' "$out"
    kvno=$(sed -n 's/^Key: vno \([0-9]*\),.*/\1/p' <<<"$out" | sort -n | tail -1)
    [ -n "$kvno" ] || _kadmin_q_fail "$_KADMIN_Q" "follow-up getprinc $p: no key" "$out"
    out=$(docker exec "$(_kadmin_container_of "$@")" klist -k -e "$f" 2>&1) || true
    printf '%s\n' "$out"
    grep -Eq "^ *$kvno $(_kadmin_ere "$p") \\(" <<<"$out" \
        || _kadmin_q_fail "$_KADMIN_Q" "follow-up klist -k -e $f: no $p at kvno $kvno" "$out"
}

# kadmin_q_ok [--then QUERY ERE]... CMD ARGS...: run a query command (a runner or a query wrapper) with exit status 0
# and require its effect: the verb's MIT success line naming the query's principal; or, for a verb silent on
# success (the policy verbs on every leg; modprinc / setstr / ktadd on the Rust krb5-kadmin-local), no output but
# the authentication and dictionary notices and delpol's confirmation prompt (kadmin.c:1763), and the effect read
# back by read-only follow-ups derived from the query (_kadmin_effects). --then adds a follow-up by hand (ERE, or
# !ERE for absence) for what the query alone does not say; each distinct follow-up query runs once. --next-asserts
# skips the derived read-back, and only it, where the cell's very next command reads the same object back and
# asserts every field the query set. The output goes to stdout; a failure prints it with the reason on the gate's
# stderr and dies.
kadmin_q_ok() {
    local thens=() out rc=0 ere effects line q e f next=0 queries=() eres=()
    while [ "${1:-}" = --then ] || [ "${1:-}" = --next-asserts ]; do
        if [ "$1" = --next-asserts ]; then
            next=1
            shift
            continue
        fi
        thens+=("$2" "$3")
        shift 3
    done
    _KADMIN_Q=$(_kadmin_query_of "$@")
    out=$("$@" 2>&1) || rc=$?
    printf '%s\n' "$out"
    [ "$rc" -eq 0 ] || _kadmin_q_fail "$_KADMIN_Q" "exit $rc" "$out"
    ere=$(_kadmin_success_ere "$_KADMIN_Q")
    if [ -z "$ere" ] || ! grep -Eq "$ere" <<<"$out"; then
        if grep -Ev -e '^Authenticating as principal ' -e 'No dictionary file specified' -e '^$' \
            -e '^Are you sure you want to delete the policy "[^"]*"\? \(yes/no\): $' <<<"$out" | grep -q .; then
            _kadmin_q_fail "$_KADMIN_Q" "no line /${ere:-(silent verb)}/" "$out"
        fi
        [ "$next" = 1 ] && return 0
        effects=$(_kadmin_effects "$_KADMIN_Q") || _kadmin_q_fail "$_KADMIN_Q" "no derivable effect; pass --then" "$out"
        if grep -q $'^?\t' <<<"$effects" && [ "${#thens[@]}" -eq 0 ]; then
            f=$(sed -n $'s/^?\t//p' <<<"$effects" | paste -sd,)
            _kadmin_q_fail "$_KADMIN_Q" "no derivable effect for: $f; pass --then" "$out"
        fi
        while IFS=$'\t' read -r q e f; do
            [ -n "$q" ] && [ "$q" != '?' ] || continue
            if [ "$q" = keytab ]; then
                _kadmin_keytab "$e" "$f" "$@"
                continue
            fi
            _kadmin_queue "$q" "$e"
        done <<<"$effects"
    fi
    for ((line = 0; line < ${#thens[@]}; line += 2)); do
        _kadmin_queue "${thens[line]}" "${thens[line + 1]}"
    done
    for ((line = 0; line < ${#queries[@]}; line++)); do
        _kadmin_check "${queries[line]}" "${eres[line]}" "$@"
    done
}

# _kadmin_queue Q ERE: add ERE to kadmin_q_ok's checks of the follow-up Q (one run per distinct Q).
_kadmin_queue() {
    local k
    for ((k = 0; k < ${#queries[@]}; k++)); do
        if [ "${queries[k]}" = "$1" ]; then
            eres[k]+=$'\n'$2
            return 0
        fi
    done
    queries+=("$1")
    eres+=("$2")
}

# A failure reaches the gate's stderr as it was when this file was sourced, whatever the call site redirects.
exec {_KADMIN_Q_STDERR}>&2
_kadmin_q_fail() {
    {
        printf '%s\n' "$3"
        die "kadmin_q_ok: $1: $2"
    } >&"$_KADMIN_Q_STDERR"
}

# kadmin_q_try CMD ARGS...: a best-effort cleanup query; streams pass through, never a failing rc.
kadmin_q_try() {
    "$@" || true
}
