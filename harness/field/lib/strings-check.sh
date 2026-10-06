#!/bin/sh
# strings-check.sh [--control | --manifest <install-manifest> | <file>...]: R1's strings check, run on a VM
# (a scenario pipes it to `sh -s -- ...`). `strings -n 4 <file> | grep -oE '<pattern>'`, matched anywhere,
# plus `userpassword` case-insensitive: the test-only names a release build must not carry. Prints each file
# with its hits and their counts, or "none"; exits 1 when any file has a hit.
#   --manifest <file>  every program a kerber-rust install manifest lists (`<sha256>  <path>` lines; an entry
#                      in a bin or sbin directory), each of which must be an ELF file: none is skipped
#   --control          the planted control: a file carrying planted names must go red; exits 0 when it does
P='KRB5_TEST_[A-Z0-9_]*|--test-realm|testrealm|KRB5_MASTER_PASSWORD|KRB5_NEW_PASSWORD|KRB5_PASSWORD|KERBER_CAPTURE_DIR|KRB5_KDC_DB_LIBRARY|KRB5_KDC_DB|KRB5_KDC_STASH|KRB5_MASTER_ETYPE|KRB5_ACL_FILE|KRB5_KDC_CONF|KRB5_EXPORT_[A-Z_]*|KRB5_ENABLE_PKINIT|KRB5_KDC_BIND|KRB5_KDC_USER|KRB5_KDC_AUDIT[A-Z_]*|KRB5_KDCPOLICY|KERBER_KDC_GREET|KRB5_KPASSWD_BIND|KRB5_KPASSWD_TARGET|KCM_SOCKET|disable-transited-check|body-realm|renew-ticket|armor-ccache|pkinit-anchors|ok tgt='

# Names a release build no longer reads, where MIT's program reads none; one line per change.
P="$P|GSS_DELEG_CCACHE" # the gss acceptor's copy of a delegated credential (kadmind)

# check_files <file>...: the check proper.
check_files() {
    status=0
    for f in "$@"; do
        hits=$( { strings -n 4 "$f" | grep -oE -- "$P"; strings -n 4 "$f" | grep -oiE -- 'userpassword'; } \
            | sort | uniq -c | awk '{ n = $1; sub(/^ *[0-9]+ /, ""); printf " %s x%s", $0, n }')
        [ -n "$hits" ] && status=1
        printf '%s (%s bytes):%s\n' "$f" "$(stat -c %s "$f")" "${hits:- none}"
    done
    return "$status"
}

is_elf() { [ "$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')" = 7f454c46 ]; }

command -v strings >/dev/null 2>&1 || { echo "strings-check.sh: strings (binutils) is not installed" >&2; exit 1; }
case ${1:-} in
--control)
    d=$(mktemp -d /var/tmp/strings-control.XXXXXX) || exit 1
    printf 'x\0KRB5_TEST_PLANTED\0ab--test-realmcd\0UserPassword\0KRB5_EXPORT_KRBTGT_KEYTAB\0KRB5_KDC_DB_LIBRARY\0xxbody-realmyy\0ok tgt=2\0yGSS_DELEG_CCACHEz\0' \
        > "$d/planted.bin"
    out=$(check_files "$d/planted.bin")
    rc=$?
    rm -rf "$d"
    printf '%s\n' "$out"
    for name in KRB5_TEST_PLANTED --test-realm UserPassword KRB5_EXPORT_KRBTGT_KEYTAB KRB5_KDC_DB_LIBRARY body-realm 'ok tgt=' GSS_DELEG_CCACHE; do
        case $out in
            *" $name x1"*) ;;
            *) echo "control: $name not found: the check is broken"; exit 1 ;;
        esac
    done
    [ "$rc" -eq 1 ] || { echo "control: exit $rc on the planted file: the check is broken"; exit 1; }
    echo "control: red on the planted file (exit 1), as it must"
    ;;
--manifest)
    m=${2:-}
    [ -r "$m" ] || { echo "strings-check.sh: cannot read the manifest '$m'" >&2; exit 1; }
    # Every entry in a bin or sbin directory is a program: it must be an ELF file, and each one is checked.
    awk '{ print $2 }' "$m" | {
        progs=0 checked=0 all=0
        while IFS= read -r f; do
            case $f in */bin/* | */sbin/*) ;; *) continue ;; esac
            progs=$((progs + 1))
            if ! is_elf "$f"; then
                echo "$f: not a readable ELF file"
                all=1
                continue
            fi
            checked=$((checked + 1))
            check_files "$f" || all=1
        done
        if [ "$progs" -eq 0 ] || [ "$checked" -ne "$progs" ]; then
            echo "programs in $m: $progs, checked: $checked (they must be equal, and not 0)"
            exit 1
        fi
        echo "programs in $m: $progs, all $checked checked"
        exit "$all"
    }
    ;;
'' | -*)
    echo "usage: strings-check.sh --control | --manifest <install-manifest> | <file>..." >&2
    exit 1
    ;;
*)
    check_files "$@"
    ;;
esac
