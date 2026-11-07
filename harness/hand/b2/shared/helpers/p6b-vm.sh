#!/bin/bash
# p6b-vm.sh SUBCOMMAND ARGS: the VM-side steps of P6b's multi-command cells (b2-client; module mod/p6b.sh; spec/p6b.md). Pushed to $VMD/p6b-vm.sh, run by `b2c-vm.sh run` as the lab user (never as root: the cells show what the
# unprivileged user sees). The password lines come on stdin and are only ever piped into a kinit; nothing here prints them.
#   start WHEN KINIT KLIST CACHE      `kinit -s <stamp> alice` with the stamp `date -u -d WHEN`, then `klist -f`: prints START:<stamp>, the prompt, [kinit rc=N], the klist block, [klist rc=N]
#   skinit KINIT KLIST CACHE          `kinit -S kadmin/changepw -c FILE:CACHE alice`, then `klist -c`
#   kdestroy KDESTROY CACHE           `kdestroy -c FILE:CACHE`; says whether the cache is gone
#   kswitch DIR KINIT KSWITCH KLIST   a DIR collection with alice (stdin line 1) and p6bsw (line 2) made by KINIT, then KSWITCH -p alice, -p p6bsw, -p nobody; KLIST (MIT's) shows the primary after each
set -u
sub=${1:-}
[ $# -gt 0 ] && shift
case $sub in
start)
    when=$1; kin=$2; kls=$3; cc=$4
    s=$(date -u -d "$when" +%Y%m%d%H%M%S)
    echo "START:$s"
    "$kin" -s "$s" -c "FILE:$cc" alice
    echo "[kinit rc=$?]"
    "$kls" -f -c "FILE:$cc"
    echo "[klist rc=$?]"
    ;;
skinit)
    kin=$1; kls=$2; cc=$3
    "$kin" -S kadmin/changepw -c "FILE:$cc" alice
    echo "[kinit rc=$?]"
    "$kls" -c "FILE:$cc"
    echo "[klist rc=$?]"
    ;;
kdestroy)
    kds=$1; cc=$2
    "$kds" -c "FILE:$cc"
    echo "[kdestroy rc=$?]"
    if test -e "$cc"; then echo CACHE_STILL_THERE; else echo CACHE_GONE; fi
    ;;
kswitch)
    d=$1; kin=$2; ksw=$3; kls=$4
    IFS= read -r pa; IFS= read -r pb
    rm -rf "$d"; mkdir -p "$d"; chmod 700 "$d"
    printf '%s\n' "$pa" | KRB5CCNAME="DIR:$d" "$kin" alice > /dev/null 2>&1; echo "[kinit alice rc=$?]"      # no -c: the collection's own rule, a cache per principal (kinit.c: cache match, else a new unique one)
    printf '%s\n' "$pb" | KRB5CCNAME="DIR:$d" "$kin" p6bsw > /dev/null 2>&1; echo "[kinit p6bsw rc=$?]"
    echo "== klist -l"
    out=$(KRB5CCNAME="DIR:$d" "$kls" -l 2>&1); rc=$?
    printf '%s\n' "$out" | sed -n 1,2p; printf '%s\n' "$out" | sed 1,2d | sort      # the body sorted: the collection is listed in directory order, which the random cache names change
    echo "[klist rc=$rc]"
    for p in alice p6bsw nobody; do
        echo "== kswitch -p $p"; KRB5CCNAME="DIR:$d" "$ksw" -p "$p"; echo "[kswitch rc=$?]"
        KRB5CCNAME="DIR:$d" "$kls" 2> /dev/null | sed -n 2p
    done
    rm -rf "$d"
    ;;
*)
    echo "p6b-vm.sh: unknown subcommand '$sub'" >&2
    exit 2
    ;;
esac
