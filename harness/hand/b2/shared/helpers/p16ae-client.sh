#!/bin/bash
# p16ae-client.sh ROLE LABEL PRINC [ARG]: the client-side cells of P16a-edges, run on client1 (MIT kadmin) and client2 (MIT kpasswd, kinit); not as root. The record format is CELL name / RC:n / output / CELL_END.
#   cpw LABEL PRINC PWFMT        stdin line 1: the admin/admin password (line 2: a throwaway password when PWFMT is @STDIN2@). MIT `kadmin -p admin/admin -q 'cpw -pw "<PWFMT>" PRINC'` (the password for
#                                kadmin on its stdin); PWFMT goes through printf, so a byte is written as an octal escape (caf\351) and never crosses the host's ssh as a raw non-UTF-8 byte
#   kpasswd LABEL PRINC NEWFMT   stdin line 1: PRINC's current password (line 2: the new one when NEWFMT is @STDIN2@). MIT `kpasswd PRINC` with current / new / new on its stdin
#   kinit LABEL PRINC PWFMT      MIT kinit PRINC with PWFMT (through printf) on its stdin: KINIT_RC and the stderr line (the prompt, on stdout, is dropped)
#   kf LABEL PRINC               stdin line 1: PRINC's password. OUR kinit ($VMCTL_D/ours/kinit, the ship build's) against the stage's KDC: its rc, stdout, stderr; "ok" and JSON lines counted (KF: ee8aa5)
# Source: {mit,rust}.txt (CPW label=... princ=... rc=..., KPASSWD label=... rc=...); the command lines were not recorded: rewritten from them.
set -u
D=${VMCTL_D:-/var/tmp/otp3}
ROLE=${1:?role}; LABEL=${2:?label}; PRINC=${3:?princ}; ARG=${4:-}
REALM=${B2A_REALM:-KERBER.TEST}
IFS= read -r PW1 || true
IFS= read -r PW2 || true
case $ROLE in kinit) ;; *) [ -n "$PW1" ] || { echo "P16AE_ABORT no password on stdin"; exit 2; } ;; esac
filt() { grep -v -e '^Authenticating as principal ' | sed 's/^Password for admin\/admin@[^:]*: //' | grep -v '^$' || true; }   # kadmin's own banner and its password prompt (stdout, no newline) are not part of the reply
cc=$D/p16ae-$$-$RANDOM.cc
echo "CELL $LABEL"
case $ROLE in
cpw)
    if [ "$ARG" = @STDIN2@ ]; then pw=$PW2; else pw=$(printf '%b' "$ARG"); fi      # a throwaway password comes as stdin line 2, never as an argument
    out=$(printf '%s\n' "$PW1" | kadmin -p "admin/admin@$REALM" -q "cpw -pw \"$pw\" $PRINC" 2>&1); rc=$?
    echo "RC:$rc"; printf '%s\n' "$out" | filt
    ;;
kpasswd)
    if [ "$ARG" = @STDIN2@ ]; then ARG=$PW2; fi
    out=$(printf "%s\n$ARG\n$ARG\n" "$PW1" | kpasswd "$PRINC" 2>&1); rc=$?
    echo "RC:$rc"; printf '%s\n' "$out" | filt
    ;;
kinit)
    pw=$(printf '%b' "$ARG")
    err=$(printf '%s\n' "$pw" | KRB5CCNAME=FILE:$cc kinit "$PRINC" 2>&1 > /dev/null); rc=$?
    echo "KINIT_RC:$rc"; echo "ERR:$(printf '%s' "$err" | tr '\n' ' ')"
    KRB5CCNAME=FILE:$cc kdestroy > /dev/null 2>&1
    ;;
kf)
    kin=$D/ours/kinit
    [ -x "$kin" ] || { echo "RC:127"; echo "kf: no $kin"; echo "CELL_END $LABEL"; exit 0; }
    so=$(mktemp "$D/kf-out.XXXXXX.txt"); se=$(mktemp "$D/kf-err.XXXXXX.txt")
    printf '%s\n' "$PW1" | KRB5CCNAME=FILE:$cc "$kin" "$PRINC" > "$so" 2> "$se"; rc=$?
    echo "RC:$rc"
    echo "STDOUT:$(tr '\n' '|' < "$so")"
    echo "STDERR:$(tr '\n' '|' < "$se")"
    echo "OK_LINES:$(cat "$so" "$se" | grep -c '^ok')"
    echo "JSON_LINES:$(cat "$so" "$se" | grep -c '^{"')"
    KRB5CCNAME=FILE:$cc "$D/ours/kdestroy" > /dev/null 2>&1 || KRB5CCNAME=FILE:$cc kdestroy > /dev/null 2>&1
    rm -f "$so" "$se"
    ;;
*) echo "RC:2"; echo "p16ae-client.sh: unknown role '$ROLE'" ;;
esac
rm -f "$cc"
echo "CELL_END $LABEL"
