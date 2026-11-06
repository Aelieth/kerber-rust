#!/bin/bash
# stage.sh: one stage of the RA r4 acceptor production leg, run as root on the kdc VM (or in a rehearsal container):
#   sudo env STAGE=mit  bash /var/tmp/ra4/stage.sh      (MIT's kadmind answers; then the install)
#   sudo env STAGE=rust bash /var/tmp/ra4/stage.sh      (the ship build's kadmind answers)
#   sudo env STAGE=clean bash /var/tmp/ra4/stage.sh     (shred the keytab, cases and frames)
# Inputs in $D (pushed by the driver, sha256-checked there): rd-priv-oracle (the Fedora build of the final tree's rd-priv-oracle.c),
# rd-sweep (the final ship build), kpwsend.py, frames-nokey.tsv (mkframes.py). Outputs in $D: acc-$STAGE.tsv,
# $STAGE-{udp,tcp}[-setpw].tsv, judge.txt (rust stage). ONLY=<file of ids> sends just those cells (the rerun of a part): outputs get the suffix .rerun.
# GEN is the frame generator, the final tree's `rd-sweep kpasswd`. No key is printed or copied out; the keytab stays here, 0600.
set -u
: "${STAGE:?STAGE=mit|rust|clean}"
D=${D:-/var/tmp/ra4}; SIP=${SIP-}; LOG=${LOG:-/var/log/kadmind.log}
GEN=${GEN:-"$D/rd-sweep kpasswd"}; KAL=${KAL:-kadmin.local}
cd "$D" || exit 2
if [ "$STAGE" = clean ]; then
    shred -u cpw.keytab cases.tsv frames.tsv frames-setpw.tsv frames-all.tsv frames-sel.tsv frames-setpw-sel.tsv 2>/dev/null
    left=$(find "$D" -maxdepth 1 \( -name '*keytab*' -o -name '*cases*' -o -name '*frames*' \) ! -name '*frames-nokey*' -ls)
    if [ -n "$left" ]; then echo "$left"; else echo "CLEAN_OK (no keytab, cases or frames file left)"; fi
    exit 0
fi
: "${SIP:?SIP=<the kdc address>}"
for f in rd-priv-oracle rd-sweep kpwsend.py frames-nokey.tsv; do
    [ -s "$f" ] || { echo "STAGE_ABORT missing input $f"; exit 2; }
done
SUF=""; [ -n "${ONLY:-}" ] && SUF=".rerun"
say() { echo "==== $STAGE $* ($(date -u +%T))"; }
TAB=$(printf '\t')
sha256sum rd-priv-oracle rd-sweep kpwsend.py frames-nokey.tsv

say "principal and key (the keytab stays here, 0600)"
$KAL -q 'addprinc -randkey ra4user' 2>&1 | tail -1
rm -f cpw.keytab
( umask 077; $KAL -q "ktadd -norandkey -k $D/cpw.keytab kadmin/changepw" 2>&1 | tail -1 )
[ -s cpw.keytab ] || { echo "STAGE_ABORT no keytab"; exit 2; }

say "library acceptor: the VM's MIT answers the sweep"
./rd-sweep cases > cases.tsv || { echo "STAGE_ABORT rd-sweep cases"; exit 2; }
KRB5RCACHETYPE=none ./rd-priv-oracle < cases.tsv > "acc-$STAGE$SUF.tsv"
n=$(wc -l < "acc-$STAGE$SUF.tsv"); z=$(grep -c "${TAB}0\$" "acc-$STAGE$SUF.tsv"); p=$(grep -c "/pristine${TAB}0\$" "acc-$STAGE$SUF.tsv")
echo "acceptor rows=$n accepts=$z pristine_ok=$p (want 646 69 3)"
[ "$n" = 646 ] && [ "$z" = 69 ] && [ "$p" = 3 ] || echo "ACCEPTOR_ASSERT_FAIL"
if [ "$STAGE" = rust ]; then
    ./rd-sweep judge cases.tsv "acc-$STAGE$SUF.tsv" > "judge$SUF.txt"; echo "judge_rc=$?"; tail -1 "judge$SUF.txt"
fi

say "kpasswd frames"
$GEN cpw.keytab ra4user raddr="$SIP" > frames.tsv || { echo "STAGE_ABORT generator v1"; exit 2; }
$GEN cpw.keytab ra4user setpw raddr="$SIP" > frames-setpw.tsv || { echo "STAGE_ABORT generator setpw"; exit 2; }
for ra in none:absent 127.0.0.1:loopback 203.0.113.77:foreign; do
    v=${ra%%:*}; name=${ra#*:}
    if [ "$v" = none ]; then a=""; else a="raddr=$v"; fi
    $GEN cpw.keytab ra4user ${a:+"$a"} 2>/dev/null | grep "^krb-priv/pristine" | sed "s|^krb-priv/pristine|raddr/$name|" >> frames.tsv
done
k=1                                   # one cell per further key of kadmin/changepw (MIT accepts only entry 0)
while $GEN cpw.keytab ra4user raddr="$SIP" entry="$k" >/dev/null 2>&1; do
    $GEN cpw.keytab ra4user raddr="$SIP" entry="$k" 2>/dev/null | grep "^ap-req/pristine" | sed "s|^ap-req/pristine|keysel/entry$k|" >> frames.tsv
    k=$((k + 1))
done
cat frames-nokey.tsv frames.tsv > frames-all.tsv
if [ -n "${ONLY:-}" ]; then           # a rerun: only the ids in $ONLY (one per line)
    awk -F'\t' 'NR == FNR { want[$1] = 1; next } ($1 in want)' "$ONLY" frames-all.tsv > frames-sel.tsv
    awk -F'\t' 'NR == FNR { want[$1] = 1; next } ($1 in want)' "$ONLY" frames-setpw.tsv > frames-setpw-sel.tsv
    mv frames-sel.tsv frames-all.tsv; mv frames-setpw-sel.tsv frames-setpw.tsv
fi
wc -l frames-all.tsv frames-setpw.tsv

for proto in udp tcp; do
    say "kpasswd $proto"
    python3 kpwsend.py --proto $proto --host 127.0.0.1 --log "$LOG" --timeout 1.0 frames-all.tsv > "$STAGE-$proto$SUF.tsv"
    python3 kpwsend.py --proto $proto --host 127.0.0.1 --log "$LOG" --timeout 1.0 frames-setpw.tsv > "$STAGE-$proto-setpw$SUF.tsv"
done

if [ -z "${ONLY:-}" ]; then
    say "sanity (abort the leg, do not compare, when one of these is wrong)"
    bad=0
    for id in ap-req/pristine krb-priv/pristine; do
        grep -q "^$id${TAB}udp${TAB}REP${TAB}.*: success\$" "$STAGE-udp.tsv" || { echo "BAD pristine $id"; bad=1; }
    done
    # Row 50 (368e126f, after FULL-r2): ours drops frame/aplen-zero, so rust has 11 UDP DROPs. MIT still has 10.
    drops=$(grep -c "^frame/.*${TAB}DROP:" "$STAGE-udp.tsv" || true)
    if [ "$STAGE" = rust ]; then want=11; else want=10; fi
    [ "$drops" = "$want" ] || { echo "BAD frame DROP count ($drops want $want)"; bad=1; }
    [ "$bad" = 0 ] && echo "SANITY_OK" || echo "SANITY_FAIL"
fi
say "done"
