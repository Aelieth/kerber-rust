#!/bin/bash
# stage.sh: the kdc half of the KA2 production leg, run as root on the kdc VM:
#   sudo env STAGE=mit  bash /var/tmp/ka2/stage.sh     (MIT's kadmind answers; before the install)
#   sudo env STAGE=rust bash /var/tmp/ka2/stage.sh     (the ship build's kadmind answers)
#   sudo env STAGE=clean bash /var/tmp/ka2/stage.sh    (shred the keytab)
# The refused-key cell: a ticket forged in each key of kadmin/admin (the keytab `ktadd -norandkey` writes, 0600, on this VM only) and
# sent as an INIT call to kadmind on 127.0.0.1:749 by `rd-sweep kadmind-init`, over RPCSEC_GSS and over AUTH_GSSAPI. The first key
# completes the context; every later one is refused. No key is printed or copied out; only the lines of the tool are.
set -u
: "${STAGE:?STAGE=mit|rust|clean}"
D=${D:-/var/tmp/ka2}
cd "$D" || exit 2
if [ "$STAGE" = clean ]; then
    shred -u admin.keytab 2>/dev/null
    left=$(find "$D" -maxdepth 1 -name '*keytab*' -ls)
    if [ -n "$left" ]; then echo "$left"; else echo "CLEAN_OK (no keytab left)"; fi
    exit 0
fi
[ -s rd-sweep ] || { echo "STAGE_ABORT missing rd-sweep"; exit 2; }
sha256sum rd-sweep
echo "==== $STAGE: the daemon ($(date -u +%T))"
systemctl is-active krb5kdc kadmin
ss -H -lnt 'sport = :749'
rm -f admin.keytab
( umask 077; kadmin.local -q "ktadd -norandkey -k $D/admin.keytab kadmin/admin" 2>&1 | sed 's/^/ktadd: /' )
[ -s admin.keytab ] || { echo "STAGE_ABORT no keytab"; exit 2; }
n=0
for flavor in rpcsec agss; do
    echo "==== $STAGE: the first key of kadmin/admin, $flavor"
    out=$(./rd-sweep kadmind-init 127.0.0.1:749 admin.keytab ka2user "flavor=$flavor" 2>&1); echo "$out"
    echo "$out" | grep -qF "flavor=$flavor: ACCEPTED gss_major=0 GSS_S_COMPLETE" || { echo "CELL_FAIL first key $flavor"; n=1; }
    e=1
    while out=$(./rd-sweep kadmind-init 127.0.0.1:749 admin.keytab ka2user "entry=$e" "flavor=$flavor" 2>&1); do
        echo "==== $STAGE: key $e of kadmin/admin, $flavor"; echo "$out"
        if [ "$flavor" = rpcsec ]; then want='DENIED auth_stat=2 AUTH_REJECTEDCRED'; else want='ACCEPTED gss_major=851968 GSS_S_FAILURE'; fi
        echo "$out" | grep -qF "flavor=$flavor: $want" || { echo "CELL_FAIL key $e $flavor"; n=1; }
        e=$((e + 1))
    done
    echo "==== $STAGE: no key $e: $out"
    [ "$e" -ge 2 ] || { echo "CELL_FAIL the keytab has one key only"; n=1; }
done
[ "$n" = 0 ] && echo "CELLS_OK" || echo "CELLS_FAIL"
echo "==== $STAGE: kadmind.log (INIT lines)"
tail -n 40 /var/log/kadmind.log 2>/dev/null | grep -aE "INIT|context|Authentication|bad service|Miscellaneous|authentication" | tail -n 12
echo "==== $STAGE done"
