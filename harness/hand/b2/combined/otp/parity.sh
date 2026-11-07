#!/bin/bash
# parity.sh RECDIR: the cells of one OTP4 leg, compared. Output on stdout; the lines that start with PARITY are for driver.sh (PARITY VIEW CELL WHO VERDICT N),
# the rest is for the reader.
#   within a stage (M = MIT's KDC, O = ours), per client and per cell C1..C4: MIT's kinit (kmit) against ours (kours), view by view (norm.py): rc, stdout (the bytes: od -c,
#   length, sha256), stderr, trace (the KRB5_TRACE lines), ccache, klist-C (fast_avail, pa_type, pa_config_data), klist-fe, kvno, klog (the KDC's log lines about otpuser@).
#   klist-tool: in each cell with a ccache, our klist -C against MIT's klist -C on the same ticket cache.
#   xstage: the same kinit against MIT's KDC and against ours (recorded, not judged: the KDCs are different programs).
#   control: cells that must differ (the comparison must be able to fail).
# VERDICT EQ = no differing line; DIFF = the differing lines follow (MIT's kinit or MIT's KDC first); MISSING = a cell file is absent; DIFFER/SAME = a control.
# Sizes of the requests and answers (the sizes view) are listed for the reader and never judged; so are the etype lists the kinits put in their AS_REQs (info-etypes).
set -u
R=${1:?records dir}
N=$(dirname "$0")/norm.py
CLIENTS="client1 client2"
CELLS="C1 C2 C3 C4"
VIEWS="rc stdout stderr trace ccache klist-C klist-fe kvno klog"

v() { python3 -B -I "$N" "$1" "$2"; }

compare() {   # compare KIND CELL WHO VIEW FILE1 FILE2
    local kind=$1 cell=$2 who=$3 view=$4 f1=$5 f2=$6 n verdict
    if [ ! -e "$f1" ] || [ ! -e "$f2" ]; then printf 'PARITY %s %s %s MISSING 0\n' "$kind" "$cell" "$who"; return; fi
    n=$(v "$f1" "$view" | wc -l)
    if diff <(v "$f1" "$view") <(v "$f2" "$view") > /dev/null; then verdict=EQ; else verdict=DIFF; fi
    printf 'PARITY %s %s %s %s %s\n' "$kind" "$cell" "$who" "$verdict" "$n"
    if [ "$verdict" = DIFF ]; then
        echo "  differing lines of $kind $cell $who (1st file <, 2nd file >; $(basename "$f1") / $(basename "$f2")):"
        diff <(v "$f1" "$view") <(v "$f2" "$view") | head -60 | sed 's/^/    /'
    fi
}

control() {   # control NAME WHO VIEW FILE1 FILE2: two cells that must differ in this view
    local name=$1 who=$2 view=$3 f1=$4 f2=$5 verdict
    if [ ! -e "$f1" ] || [ ! -e "$f2" ]; then printf 'PARITY control %s %s MISSING 0\n' "$name" "$who"; return; fi
    if diff <(v "$f1" "$view") <(v "$f2" "$view") > /dev/null; then verdict=SAME; else verdict=DIFFER; fi
    printf 'PARITY control %s %s %s 0\n' "$name" "$who" "$verdict"
}

echo "# within a stage: MIT's kinit and ours, view by view (norm.py: pids, stamps, byte counts, ccache names, MEMORY ids, cookie bytes, the encrypted timestamp's time, the SPAKE keys, ticket times, and"
echo "# in the KDC log the program name, pid, time, fd, authtime, the client's address removed; the KDC log reduced to the lines about otpuser@)"
for s in M O; do
    for c in $CLIENTS; do
        for k in $CELLS; do
            for view in $VIEWS; do
                compare "$view" "$s$k" "$c" "$view" "$R/$s$k-kmit-$c.txt" "$R/$s$k-kours-$c.txt"
            done
        done
    done
done
echo
echo "# the etype lists the two kinits put in their AS_REQs (from the KDC's log lines): a client default, recorded and not judged"
for s in M O; do
    for c in $CLIENTS; do
        for k in $CELLS; do
            compare "info-etypes" "$s$k" "$c" etypes "$R/$s$k-kmit-$c.txt" "$R/$s$k-kours-$c.txt"
        done
    done
done
echo
echo "# our klist -C against MIT's klist -C on the same ticket cache (the cells that wrote one)"
for s in M O; do
    for c in $CLIENTS; do
        for kk in kmit kours; do
            for k in C1 C4; do
                f=$R/$s$k-$kk-$c.txt
                [ -e "$f" ] || { printf 'PARITY klist-tool %s%s-%s %s MISSING 0\n' "$s" "$k" "$kk" "$c"; continue; }
                n=$(v "$f" klist-C | wc -l)
                if diff <(v "$f" klist-C) <(v "$f" klist-ours) > /dev/null; then verdict=EQ; else verdict=DIFF; fi
                printf 'PARITY klist-tool %s%s-%s %s %s %s\n' "$s" "$k" "$kk" "$c" "$verdict" "$n"
                [ "$verdict" = DIFF ] && { echo "  differing lines (MIT's klist <, ours >):"; diff <(v "$f" klist-C) <(v "$f" klist-ours) | head -30 | sed 's/^/    /'; }
            done
        done
    done
done
echo
echo "# the same kinit against MIT's KDC (M) and against ours (O): recorded, not judged"
for kk in kmit kours; do
    for c in $CLIENTS; do
        for k in $CELLS; do
            for view in rc stdout stderr ccache klist-C kvno; do
                compare "xstage-$kk-$view" "$k" "$c" "$view" "$R/M$k-$kk-$c.txt" "$R/O$k-$kk-$c.txt"
            done
        done
    done
done
echo
echo "# the sizes of the requests and answers as the client saw them (not normalized, not judged): MIT's kinit / ours"
for s in M O; do
    for c in $CLIENTS; do
        for k in $CELLS; do
            printf '%s%s %-8s MIT: %-60s ours: %s\n' "$s" "$k" "$c" "$(v "$R/$s$k-kmit-$c.txt" sizes 2>/dev/null | tr '\n' ',' | sed 's/Sending request /S/g; s/Received answer /R/g')" \
                "$(v "$R/$s$k-kours-$c.txt" sizes 2>/dev/null | tr '\n' ',' | sed 's/Sending request /S/g; s/Received answer /R/g')"
        done
    done
done
echo
echo "# controls (the comparisons must be able to fail): different cells of the same kinit and stage"
for s in M O; do
    for kk in kmit kours; do
        c=client1
        control "$s-C1-vs-C2-rc-$kk" "$c" rc "$R/${s}C1-$kk-$c.txt" "$R/${s}C2-$kk-$c.txt"
        control "$s-C1-vs-C2-ccache-$kk" "$c" ccache "$R/${s}C1-$kk-$c.txt" "$R/${s}C2-$kk-$c.txt"
        control "$s-C2-vs-C3-stderr-$kk" "$c" stderr "$R/${s}C2-$kk-$c.txt" "$R/${s}C3-$kk-$c.txt"
        control "$s-C3-vs-C4-stdout-$kk" "$c" stdout "$R/${s}C3-$kk-$c.txt" "$R/${s}C4-$kk-$c.txt"
        control "$s-C1-vs-C3-trace-$kk" "$c" trace "$R/${s}C1-$kk-$c.txt" "$R/${s}C3-$kk-$c.txt"
        control "$s-C1-vs-C3-klog-$kk" "$c" klog "$R/${s}C1-$kk-$c.txt" "$R/${s}C3-$kk-$c.txt"
    done
done
