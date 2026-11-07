#!/usr/bin/env bash
# harness/field/scenarios/kdc-hostile.sh --leg mit|rust: hostile input at the leg's KDC listener on kdc (port 88),
# the same bytes on both legs from client2 (lib/kdc-hostile.py): a TCP length past the cap and with the high bit, 46
# idle connections then a request, UDP garbage and a cut AS-REQ, 20000 PA-DATA and an inner length past the frame.
# Each cell must be sent (an outcome line); its outcome and log lines are INFO rows compared with MIT's leg. After
# each cell the KDC is graded: the same process, active, no restart, RssAnon grown under 64 MiB, a MIT kinit served.
# vms: kdc client2
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kdc-hostile.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE

KH=kdc.${REALM,,}
CELLS=(K1a K1b K2 K3 K4a K4b K5a K5b)
# The KDC's main process, active state, restarts and RssAnon (KiB), on one line.
STATE_CMD="pid=\$(systemctl show -p MainPID --value $UNIT_KDC); printf 'kdc: pid %s %s restarts %s rss %s\n' \"\$pid\" \
\"\$(systemctl is-active $UNIT_KDC)\" \"\$(systemctl show -p NRestarts --value $UNIT_KDC)\" \"\$(sudo awk \
'/^RssAnon:/ { print \$2 }' /proc/\$pid/status)\""
# A cell's log lines without time, pid or client port, so the two legs compare.
NORM="sed -E 's/^.*\\]\\(([A-Za-z]+)\\): /(\\1): /; s/[0-9]+(\\.[0-9]+){3}[.:][0-9]+/ADDR/g; \
    s/authtime [0-9]+/authtime T/' | sort -u"

cleanup() {
    timeout -k 5 60 "$LAB" ssh client2 -- "rm -rf \$HOME/kh; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

section "kdc-hostile --leg $LEG: ${#CELLS[*]} cells of hostile input at $KH:88, each then the KDC's state, a kinit"
kdcis
resetvm client2
check kh.dir rc run client2 "rm -rf \$HOME/kh; mkdir -m 0700 \$HOME/kh"
check kh.state.before '^kdc: pid [1-9][0-9]* active restarts [0-9]+ rss [1-9][0-9]*$' run kdc "$STATE_CMD"
read -r _ _ PID0 _ _ R0 _ RSS0 < "$LAST_OUT"

for c in "${CELLS[@]}"; do
    section "$c"
    kdcmark "$c"
    observe "KH.$c" "^$c: .*" runin client2 "lib/kdc-hostile.py" \
        "python3 - $c $KH $REALM alice" < "$FIELD_LIB/kdc-hostile.py"
    checklast "KH.$c.sent" "^$c: (reply|silence|close|reset)"
    if [ "$c" = K3 ]; then observelast KH.K3.closed 'closed: [0-9]+, refused: [0-9]+'; fi
    kdcsince "$c"
    cp "$LAST_OUT" "$STATE/kh.log"
    observe "KH.$c.log" '.*' host "grep -v '^--- kadmind.log$' $(printf '%q' "$STATE/kh.log") | $NORM | paste -sd'|' - \
        | grep . || echo '(no log line)'"
    check "KH.$c.state" "^kdc: pid $PID0 active restarts $R0 rss [1-9][0-9]*\$" run kdc "$STATE_CMD"
    read -r _ _ _ _ _ _ _ RSS < "$LAST_OUT"
    check "KH.$c.rss" '^rss growth: -?[0-9]+ KiB, under 65536$' host \
        "g=\$(( ${RSS:-0} - ${RSS0:-0} )); echo \"rss growth: \$g KiB, under 65536\"; [ \"\$g\" -lt 65536 ]"
    check "KH.$c.kinit" '^kinit: rc=0$' runin client2 "alice's password ($ALICE)" \
        "KRB5CCNAME=FILE:\$HOME/kh/cc kinit alice@$REALM > /dev/null; echo \"kinit: rc=\$?\"; kdestroy -q \
        -c FILE:\$HOME/kh/cc 2> /dev/null; true" < <(once "$ALICE")
done

finish
