#!/bin/bash
# parity-m3o3.sh RECDIR: OTP2's M3 / O3 comparison (the bad [otp] stanza: the otp module out), read the way OTP2's own record reads it (its parity-post.sh, the accepted reading: parity-post.txt),
# with its compare() and control() unchanged. The login cells M3-<client>-login and O3-<client>-login (the client's transcript through norm-otp2.py, the SPAKE ephemeral public keys masked: they are random per exchange,
# like the cookie bytes norm-otp2.py already masks; the KDC's log lines reduced to the cell's own principal, otpuser@: the others are the VM's own background traffic landing in the cell's window) and the KDC's startup lines
# (M3-restart against O3-restart, every line, as OTP2's parity.sh read them) are compared; the controls compare cells that must differ. Output on stdout: PARITY lines for driver.sh (PARITY KIND PAIR WHO VERDICT N),
# the rest for the reader.
set -u
R=${1:?records dir}
: "${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}"
NETRX=${FIELD_LAB_NET//./\\.}
N=$(dirname "$0")/norm-otp2.py
CLIENTS="client1 client2"

tx() { python3 -B -I "$N" "$1" | sed -E 's/(SPAKE (challenge received with group [0-9]+,|key generated with) pubkey )[0-9A-Fa-f]{64}/\1<key>/'; }
slog() { sed -n '/^# KDC log lines added/,/^# RADIUS stub log lines/p' "$1" | grep -E '^[A-Z][a-z]{2} +[0-9]+ ' |
    sed -E 's/^[A-Z][a-z]{2} +[0-9]+ [0-9:]+ [^ ]+ [^ []+\[[0-9]+\]//; s/fd [0-9]+/fd N/; s/authtime [0-9]+/authtime T/; s/setsockopt\([0-9]+,/setsockopt(N,/; s/'"$NETRX"'\.2[12]/CLIENT/; s/127\.0\.0\.1/CLIENT/'; }   # every line (the startup lines)
klog() { slog "$1" | grep -E 'otpuser@' ; }   # a login cell: only the lines about the cell's own principal

compare() {   # compare KIND PAIR WHO FUNCTION FILE1 FILE2
    local kind=$1 pair=$2 who=$3 fn=$4 f1=$5 f2=$6 n verdict
    if [ ! -e "$f1" ] || [ ! -e "$f2" ]; then printf 'PARITY %s %s %s MISSING 0\n' "$kind" "$pair" "$who"; return; fi
    n=$($fn "$f1" | wc -l)
    if diff <($fn "$f1") <($fn "$f2") > /dev/null; then verdict=EQ; else verdict=DIFF; fi
    printf 'PARITY %s %s %s %s %s\n' "$kind" "$pair" "$who" "$verdict" "$n"
    if [ "$verdict" = DIFF ]; then
        echo "  differing lines of $kind $pair $who (MIT <, ours >), unnormalized:"
        diff <($fn "$f1") <($fn "$f2") | head -60 | sed 's/^/    /'
    fi
}
control() {   # control PAIR WHO FUNCTION FILE1 FILE2: two cells that must differ
    local pair=$1 who=$2 fn=$3 f1=$4 f2=$5 verdict
    if [ ! -e "$f1" ] || [ ! -e "$f2" ]; then printf 'PARITY control %s %s MISSING 0\n' "$pair" "$who"; return; fi
    if diff <($fn "$f1") <($fn "$f2") > /dev/null; then verdict=SAME; else verdict=DIFFER; fi
    printf 'PARITY control %s %s %s 0\n' "$pair" "$who" "$verdict"
}

echo "# OTP2's bad-[otp] cells: the client's transcript, the KDC's log lines, the startup lines; MIT's stage (M3) against ours (O3)"
for c in $CLIENTS; do
    compare transcript "M3-O3" "$c" tx "$R/M3-$c-login.txt" "$R/O3-$c-login.txt"
    compare klog "M3-O3" "$c" klog "$R/M3-$c-login.txt" "$R/O3-$c-login.txt"
done
compare startup M3-O3 kdc slog "$R/M3-restart.txt" "$R/O3-restart.txt"
echo "# controls: a bad [otp] against a good one must differ"
control M3-vs-M1restart startup:kdc slog "$R/M3-restart.txt" "$R/L2-mit-restart-M1.txt"
control O3-vs-O1start startup:kdc slog "$R/O3-restart.txt" "$R/O1-embed-start.txt"
control M3-vs-C1 transcript:client1 tx "$R/M3-client1-login.txt" "$R/MC1-kmit-client1.txt"
control O3-vs-C1 transcript:client1 tx "$R/O3-client1-login.txt" "$R/OC1-kours-client1.txt"
