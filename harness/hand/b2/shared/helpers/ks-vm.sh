#!/bin/bash
# ks-vm.sh SUB: KS's client-side steps on client2, as root (`sudo bash ks-vm.sh skew-on [SECONDS]|skew-off|facts`). (lab-agent; module mod/ks.sh; VM-LEG.md cell T3)
#   skew-on N   the clock of this VM N seconds ahead (default 600): the true time and the uptime are kept in $D/ks/skew.state, the time-sync services that run (chronyd, systemd-timesyncd) are stopped so that
#               nothing steps the clock back in the middle of a cell, then `date -s @<true+N>`. Prints SKEW_ON, the clock before and after. Refuses when a skew is already on (SKEW_ALREADY_ON).
#   skew-off    the clock put back: true time = the kept time + the uptime that passed (the uptime does not move with date -s), then the stopped services started again. Prints SKEW_OFF with the drift in
#               seconds between the clock afterwards and the expected true time (within 3 s is back; the cell rows judge it) and the services' states. Nothing to undo prints SKEW_NOT_ON.
#   facts       the tools and the clock services the skew cell relies on (date, systemctl, the two time-sync units' states, the epoch now).
# No secret passes through this file. The clock is also restored by the reset to the rest snapshot at the end of the leg in any case; this file puts it back right after the cells that need it.
set -u
D=${VMCTL_D:-/var/tmp/otp3}
W=$D/ks
ST=$W/skew.state
sub=${1:-}
[ $# -gt 0 ] && shift
upt() { awk '{ printf "%.2f", $1 }' /proc/uptime; }
units() { echo chronyd.service systemd-timesyncd.service; }

case $sub in
skew-on)
    n=${1:-600}
    case $n in ''|*[!0-9]*) echo "ks-vm.sh: skew-on needs whole seconds" >&2; exit 2 ;; esac
    install -d -m 0700 "$W" || exit 1
    if [ -e "$ST" ]; then echo "SKEW_ALREADY_ON"; cat "$ST"; exit 1; fi
    t0=$(date +%s); u0=$(upt); stopped=""
    for u in $(units); do
        if systemctl is-active --quiet "$u" 2> /dev/null; then systemctl stop "$u" 2> /dev/null && stopped="$stopped $u"; fi
    done
    printf 'T0=%s\nU0=%s\nN=%s\nSTOPPED="%s"\n' "$t0" "$u0" "$n" "${stopped# }" > "$ST"
    echo "SKEW_BEFORE epoch=$t0 stopped=[${stopped# }]"
    date -s "@$((t0 + n))" > /dev/null 2>&1; rc=$?
    if [ "$rc" != 0 ]; then
        echo "SKEW_FAILED date -s refused (rc $rc)"
        for u in $stopped; do systemctl start "$u" 2> /dev/null; done
        rm -f "$ST"
        exit 1
    fi
    now=$(date +%s)
    echo "SKEW_ON offset=$n now=$now ahead=$((now - t0))"
    ;;
skew-off)
    if [ ! -e "$ST" ]; then echo "SKEW_NOT_ON"; exit 0; fi
    # shellcheck disable=SC1090  # the state file skew-on wrote
    . "$ST"
    u1=$(upt)
    want=$(awk -v t0="$T0" -v u0="$U0" -v u1="$u1" 'BEGIN { printf "%d", t0 + (u1 - u0) + 0.5 }')
    date -s "@$want" > /dev/null 2>&1 || echo "SKEW_OFF_FAILED date -s refused (rc $?)"
    for u in ${STOPPED:-}; do systemctl start "$u" 2> /dev/null; done
    now=$(date +%s)
    echo "SKEW_OFF expected=$want now=$now drift=$((now - want)) started=[${STOPPED:-}]"
    for u in $(units); do echo "UNIT $u $(systemctl is-active "$u" 2> /dev/null)"; done
    rm -f "$ST"
    ;;
facts)
    echo "date: $(command -v date 2>&1)"
    echo "epoch: $(date +%s)"
    echo "uptime: $(upt)"
    for u in $(units); do echo "UNIT $u $(systemctl is-active "$u" 2> /dev/null)"; done
    echo "timedatectl: $(timedatectl show -p NTP -p NTPSynchronized 2> /dev/null | paste -sd' ' -)"
    echo "skew-state: $([ -e "$ST" ] && echo present || echo absent)"
    ;;
*)
    echo "ks-vm.sh: unknown subcommand '${sub}'" >&2; exit 2 ;;
esac
