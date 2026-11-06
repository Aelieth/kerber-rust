#!/usr/bin/env bash
# harness/field/scenarios/load.sh --leg mit|rust: the leg's KDC as upgrade.sh left it on kdc, under load for
# FIELD_LOAD_SECONDS (default 600; 3600 when the run id ends in -load-long) from client2: loadgen (FIELD_LOADGEN, the
# ref's release build, on both legs) kinit + TGS at FIELD_LOAD_WORKERS workers, MIT kadmin adding lt-NNNNN principals
# at FIELD_LOAD_WRITES per second through one session, MIT kinit + kvno before, mid-load and after, and the KDC's
# anonymous RSS every 5 s. Graded: no loadgen error, every add acknowledged and listed, no restart, both daemons
# active, no panic in the journal, the RSS series reaching the load's end; the rust leg's RSS bounded (cap, and the
# slope, which must settle when the load runs 1200 s or more). The MIT leg is the oracle: its RSS is INFO.
# vms: kdc client2
# legs: mit rust
# field-limit scenario=5400
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: load.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}" "${FIELD_RUN:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE ADMIN

case $FIELD_RUN in
    *-load-long) SECS=${FIELD_LOAD_SECONDS:-3600} ;;
    *) SECS=${FIELD_LOAD_SECONDS:-600} ;;
esac
WORKERS=${FIELD_LOAD_WORKERS:-8}
WRITES=${FIELD_LOAD_WRITES:-2}
for v in "$SECS" "$WORKERS" "$WRITES"; do
    [[ $v =~ ^[1-9][0-9]*$ ]] || { note "FIELD_LOAD_SECONDS, _WORKERS and _WRITES must be positive integers"; exit 1; }
done

R=${REALM//./\\.}
KH=kdc.${REALM,,}
SVC=host/client2.${REALM,,}
LG=${FIELD_LOADGEN:-}
WC="\$HOME/ld"
KW=/var/tmp/ld
KA="kadmin -p admin/admin@$REALM"
LTLIST="sudo kadmin.local -q 'listprincs lt-*' 2>&1"
LTCLEAN="$LTLIST | grep -oE '^lt-[0-9]+@[^ ]+' | sed 's/^/delprinc -force /' | sudo kadmin.local > /dev/null 2>&1"

# The next leg's upgrade resets kdc, but the last leg and this leg's later scenarios share the database: delete.
cleanup() {
    timeout -k 5 60 "$LAB" ssh client2 -- "for f in load writer; do [ -f $WC/\$f.pid ] && kill -- -\"\$(cat \
        $WC/\$f.pid)\" 2> /dev/null; done; sleep 1; rm -rf $WC; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo touch $KW/stop; [ -f $KW/rss.pid ] && sudo kill -- -\"\$(sudo cat \
        $KW/rss.pid)\" 2> /dev/null; sudo rm -rf $KW; true" < /dev/null > /dev/null 2>&1
    timeout -k 5 600 "$LAB" ssh kdc -- "$LTCLEAN; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# client2: the loadgen wrapper, args: workers seconds kdc-host principal service; the password is stdin's first line.
loadsh() {
    cat <<'EOF'
#!/bin/bash
D=$(cd "$(dirname "$0")" && pwd)
echo $$ > "$D/load.pid"
IFS= read -r KRB5_PASSWORD
export KRB5_PASSWORD TMPDIR="$D/tmp" KERBER_LOAD_WORKERS="$1" KERBER_LOAD_SECONDS="$2"
"$D/loadgen" "$3" "$4" "$5" > "$D/load.out" 2> "$D/load.err"
echo $? > "$D/load.rc"
EOF
}
# client2: the paced writer, args: seconds writes-per-second admin-principal; stdin's first line is the password.
writersh() {
    cat <<'EOF'
#!/bin/bash
D=$(cd "$(dirname "$0")" && pwd)
echo $$ > "$D/writer.pid"
IFS= read -r pw
gap=$(awk -v w="$2" 'BEGIN { printf "%.4f", 1 / w }')
{
    printf '%s\n' "$pw"
    n=0
    while [ "$SECONDS" -lt "$1" ]; do
        n=$((n + 1))
        printf 'addprinc -randkey lt-%05d\n' "$n"
        sleep "$gap"
    done
    echo "$n" > "$D/attempted"
} | kadmin -p "$3" > "$D/writer.out" 2> "$D/writer.err"
echo $? > "$D/writer.rc"
EOF
}
# kdc: the unit's main process's RssAnon (/proc/PID/status) every 5 s into a file until stop; args: seconds file unit.
rsssh() {
    cat <<'EOF'
#!/bin/bash
D=$(cd "$(dirname "$0")" && pwd)
echo $$ > "$D/rss.pid"
pid=$(systemctl show -p MainPID --value "$3")
end=$((SECONDS + $1))
while :; do
    printf '%s %s\n' "$(date +%s)" "$(awk '/^RssAnon:/ { print $2 }' "/proc/$pid/status")" >> "$2"
    if [ -e "$D/stop" ] || [ "$SECONDS" -ge "$end" ]; then break; fi
    sleep 5
done
EOF
}
# host: the series (epoch, KiB) in MiB: first, last, max, the cap (last <= first * 1.5 + 33), the slope from 300 s.
rssawk() {
    cat <<'EOF'
NF == 2 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {
    if (n == 0) t0 = $1
    n++
    t[n] = $1 - t0
    m[n] = $2 / 1024
}
END {
    if (n == 0) { print "rss: no samples"; exit 1 }
    max = m[1]
    for (i = 2; i <= n; i++) if (m[i] > max) max = m[i]
    printf "rss: n=%d span=%d first=%.1f last=%.1f max=%.1f MiB\n", n, t[n], m[1], m[n], max
    lim = m[1] * 1.5 + 33
    printf "%s: last=%.1f limit=%.1f MiB\n", (m[n] <= lim ? "cap ok" : "cap exceeded"), m[n], lim
    for (i = 1; i <= n; i++) {
        if (t[i] < 300) continue
        if (k == 0) w0 = t[i]
        k++
        sx += t[i]; sy += m[i]; sxx += t[i] * t[i]; sxy += t[i] * m[i]
    }
    span = t[n] - w0
    if (k < 2 || span < 300) {
        printf "slope unsettled: samples from 300 s span %d s, under 300 s\n", k ? span : 0
    } else {
        s = (k * sxy - sx * sy) / (k * sxx - sx * sx)
        v = (s <= 0.05 ? "slope ok" : "slope exceeded")
        printf "%s: %.4f MiB/s over %d samples, %d s (limit 0.05)\n", v, s, k, span
    }
}
EOF
}

# rssrow <check> <line prefix> <graded: 1 | 0>: the series summary's line, a check row on the rust leg, INFO otherwise.
rssrow() {
    local l res=INFO
    l=$(grep -m1 "^$2" "$STATE/rss.sum" || echo "no $2 line")
    if [ "$3" = 1 ] && [ "$LEG" = rust ]; then
        case $l in
            "cap ok:"* | "slope ok:"*) res=PASS ;;
            "cap exceeded:"* | "slope exceeded:"* | "no "*) res=FAIL ;;
            "slope unsettled:"*) [ "$SECS" -lt 1200 ] || res=FAIL ;;
        esac
    fi
    _checkrow "$1" "$res" "$2" 0 "$l"
}
# sample <name>: MIT kinit (alice, password on stdin) + kvno of the host service on client2.
sample() {
    check "LD.sample.$1" ': kvno = [0-9]+$' runin client2 "alice's password ($ALICE)" \
        "export KRB5CCNAME=FILE:$WC/sample.cc; kinit alice@$REALM && kvno $SVC; rc=\$?; kdestroy -q; exit \$rc" < \
            <(once "$ALICE")
}
# restarts: both daemons' NRestarts.
restarts() {
    run kdc "printf 'restarts: kdc %s admin %s\n' \$(systemctl show -p NRestarts --value $UNIT_KDC) \$(systemctl \
        show -p NRestarts --value $UNIT_ADMIN)"
}

section "load --leg $LEG: $SECS s of $WORKERS loadgen workers and $WRITES kadmin adds/s on the $LEG KDC, RSS sampled"
observe LD.input.seconds 'seconds=[0-9]+' host "echo seconds=$SECS"
observe LD.input.workers 'workers=[0-9]+' host "echo workers=$WORKERS"
observe LD.input.writes 'writes_per_s=[0-9]+' host "echo writes_per_s=$WRITES"
kdcis
resetvm client2

section "1. loadgen: FIELD_LOADGEN, the ref's target/release/loadgen, copied to client2"
check lg.given '^loadgen: [0-9a-f]{64}$' host "f=$(printf '%q' "$LG"); if [ -n \"\$f\" ] && [ -s \"\$f\" ]; then \
    echo \"loadgen: \$(sha256sum < \"\$f\" | cut -c1-64)\"; else echo 'set FIELD_LOADGEN to the ref'\''s \
    target/release/loadgen'; exit 1; fi"
LGH=$(sed -n 's/^loadgen: \([0-9a-f]\{64\}\)$/\1/p' "$LAST_OUT")
check client2.dir rc run client2 "rm -rf $WC; mkdir -m 0700 $WC $WC/tmp && echo 'client2: ~/ld made'"
check client2.loadgen "^client2: loadgen ${LGH:-none}\$" host "cat $(printf '%q' "$LG") | $LABQ ssh client2 -- \
    'cat > $WC/loadgen && chmod 0755 $WC/loadgen && echo \"client2: loadgen \$(sha256sum < $WC/loadgen | cut -c1-64)\"'"
check client2.load.sh rc runin client2 "load.sh" "cat > $WC/load.sh" < <(loadsh)
check client2.writer.sh rc runin client2 "writer.sh" "cat > $WC/writer.sh" < <(writersh)
check kdc.rss.sh rc runin kdc "rss.sh" "sudo install -d -m 0755 $KW && sudo tee $KW/rss.sh > /dev/null" < <(rsssh)
if awk -F'\t' '$2 == "FAIL"' "$CHECKS" | grep -q .; then
    note "a setup check failed: the leg stops here, before any load"
    finish
    exit 1
fi

section "2. before: lt-* principals cleared, marks, one MIT sample"
check setup.clean '^left: 0$' run kdc "$LTCLEAN; l=\$($LTLIST); rc=\$?; printf '%s\n' \"\$l\" | grep -c '^lt-' | \
    sed 's/^/left: /'; echo \"listprincs rc=\$rc\"; [ \$rc = 0 ]"
check mark.restarts '^restarts: kdc [0-9]+ admin [0-9]+$' restarts
RB=$(grep -m1 '^restarts:' "$LAST_OUT")
check mark.journal '^[0-9]{10}$' run kdc "date +%s"
JT=$(grep -m1 -E '^[0-9]{10}$' "$LAST_OUT")
check LD.rss.base '^rss-anon: ([1-9][0-9]*\.[0-9]|0\.[1-9]) MiB$' run kdc "sudo bash $KW/rss.sh 0 $KW/base.txt \
    $UNIT_KDC; sudo awk '{ printf \"rss-anon: %.1f MiB\\n\", \$2 / 1024 }' $KW/base.txt"
sample before

section "3. the load: loadgen, the writer and the RSS sampler, started in the background and polled"
check rss.start '^samples: [1-9]' run kdc "sudo sh -c \
    'setsid bash $KW/rss.sh $((SECS + 600)) $KW/rss.txt $UNIT_KDC > /dev/null 2>&1 < /dev/null &'; sleep 7; echo \
    \"samples: \$(sudo cat $KW/rss.txt | wc -l)\""
check load.start '^started: loadgen$' runin client2 "alice's password ($ALICE)" \
    "IFS= read -r p; printf '%s\n' \"\$p\" | setsid bash $WC/load.sh $WORKERS $SECS $KH alice@$REALM $SVC > \
        /dev/null 2>&1 & sleep 2; kill -0 \"\$(cat $WC/load.pid)\" && echo 'started: loadgen'" < <(once "$ALICE")
check writer.start '^started: writer$' runin client2 "admin/admin's password ($ADMIN)" \
    "IFS= read -r p; printf '%s\n' \"\$p\" | setsid bash $WC/writer.sh $SECS $WRITES admin/admin@$REALM > /dev/null \
        2>&1 & sleep 2; kill -0 \"\$(cat $WC/writer.pid)\" && echo 'started: writer'" < <(once "$ADMIN")
T0=$(date +%s)
MID=0
while :; do
    EL=$(( $(date +%s) - T0 ))
    if [ "$MID" = 0 ] && [ "$EL" -ge $((SECS / 2)) ]; then
        MID=1
        sample mid
    fi
    run client2 "if [ -e $WC/load.rc ]; then echo 'loadgen: finished'; else echo 'loadgen: running'; fi"
    grep -qx 'loadgen: finished' "$LAST_OUT" && break
    if [ "$EL" -gt $((SECS + 300)) ]; then
        note "loadgen has not finished $((EL - SECS)) s after its time: grading what there is"
        break
    fi
    if [ -n "${FIELD_DEADLINE:-}" ] && [ "$(date +%s)" -ge "$FIELD_DEADLINE" ]; then break; fi
    S=60
    if [ "$MID" = 0 ] && [ $((SECS / 2 - EL)) -lt "$S" ]; then S=$((SECS / 2 - EL)); fi
    if [ $((SECS - EL)) -le 120 ]; then S=10; fi
    sleep "$((S > 1 ? S : 1))"
done
check mark.loadend '^[0-9]{10}$' run kdc "date +%s"
LEND=$(grep -m1 -E '^[0-9]{10}$' "$LAST_OUT")
[ "$MID" = 1 ] || sample mid
run client2 "for i in \$(seq 1 60); do [ -e $WC/writer.rc ] && break; sleep 2; done; ls $WC | paste -sd' ' -; echo \
    \"writer.rc=\$(cat $WC/writer.rc 2> /dev/null)\""
run kdc "sudo touch $KW/stop; for i in \$(seq 1 20); do sudo kill -0 \"\$(sudo cat $KW/rss.pid)\" 2> /dev/null || \
    break; sleep 1; done; echo 'sampler: stopped'"

section "4. after: the MIT sample, loadgen's summary, the writes, the daemons"
sample after
check LD.load.err '^ok=[0-9]+ err=0 ' run client2 "cat $WC/load.out $WC/load.err; rc=\$(cat $WC/load.rc); echo \
    \"loadgen rc=\$rc\"; [ \"\$rc\" = 0 ]"
checklast LD.load.ok '^ok=(1[6-9]|[2-9][0-9]|[0-9]{3,}) '
observelast LD.load.throughput 'throughput=[0-9.]+'
check LD.writes.acked '^writes: acked=([1-9][0-9]*) attempted=\1$' run client2 "printf \
    'writes: acked=%s attempted=%s\n' \"\$(grep -oE 'Principal \"lt-[0-9]{5,}@$R\" created\\.' $WC/writer.out | wc \
    -l)\" \"\$(cat $WC/attempted 2> /dev/null)\"; [ \"\$(cat $WC/writer.rc 2> /dev/null)\" = 0 ]"
ACKED=$(sed -n 's/^writes: acked=\([0-9][0-9]*\) .*/\1/p' "$LAST_OUT")
check LD.writes.list "^lt-principals: ${ACKED:-none}\$" runin client2 "admin/admin's password ($ADMIN)" \
    "$KA -q 'listprincs lt-*' 2>&1 | grep -cE '^lt-[0-9]{5,}@$R\$' | sed 's/^/lt-principals: /'" < <(once "$ADMIN")
check LD.restarts "line:$RB" restarts
check LD.active '^active active$' run kdc "systemctl is-active $UNIT_KDC $UNIT_ADMIN | paste -sd' ' -"
check LD.panic '^panic lines: 0 \(journal readable: [1-9][0-9]* lines\)$' run kdc "j() { sudo journalctl -u \
    $UNIT_KDC -u $UNIT_ADMIN --no-pager -o cat \"\$@\"; }; echo \"panic lines: \$(j --since @${JT:-0} | grep -ci \
    panic) (journal readable: \$(j | wc -l) lines)\""

section "5. the RSS series: first, last, max; the rust leg's cap and slope"
check LD.rss.fetch rc host "$LABQ ssh kdc -- 'sudo cat $KW/rss.txt' > $(printf '%q' "$STATE/rss.series")"
cp "$STATE/rss.series" "$REC_DIR/rss.series"
rssawk > "$STATE/rss.awk"
check LD.rss.series '^rss: n=[1-9][0-9]* span=' host "awk -f $(printf '%q' "$STATE/rss.awk") $(printf '%q' \
    "$STATE/rss.series")"
cp "$LAST_OUT" "$STATE/rss.sum"
check LD.rss.span '^rss span: last sample -?[0-9]+ s before the load end, within 30$' host "l=\$(awk 'NF == 2 \
    { t = \$1 } END { print t + 0 }' $(printf '%q' "$STATE/rss.series")); d=\$(( ${LEND:-0} - l )); \
    echo \"rss span: last sample \$d s before the load end, within 30\"; [ ${LEND:-0} -gt 0 ] && [ \$d -le 30 ]"
observelast LD.rss.first 'first=[0-9.]+'
observelast LD.rss.last 'last=[0-9.]+'
observelast LD.rss.max 'max=[0-9.]+'
rssrow LD.rss.cap 'cap ' 1
rssrow LD.rss.slope 'slope ' 1

finish
