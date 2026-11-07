#!/usr/bin/env bash
# harness/field/scenarios/kadmind-start.sh --leg mit|rust: kadmind's two foreground start-up failures on
# kdc, as upgrade.sh left it (MIT's packaged kadmind on the mit leg, kerber-rust's on the rust leg; the
# same /usr/sbin/kadmind path). Both legs must fail the same way, MIT first (hand record f-AL1-start).
# The running kadmind service is left up; it holds 464 and 749, which cell A1c needs.
#   A1b: an unreadable dict_file (a symlink loop, ELOOP) stops kadmind in the foreground before the
#        network: exit 1 with "... while initializing, aborting" on stderr and in the daemon log, no pid
#        file written, no daemon left.
#   A1c: the kadm5 program's port 749 is already in use (the service holds it), so the network set-up
#        fails: exit 1 after MIT's "Error setting up network" line in the daemon log, nothing on stderr. MIT 1.21
#        sets SO_REUSEPORT on Linux (net-server.c:81-85; 1.22.2 only on macOS, :95-101), so there a second kadmind
#        binds beside the service and runs until the probe's timeout (rc 124): MIT's leg on a 1.21 distro.
# vms: kdc
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: kadmind-start.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
# The MIT version this leg's kadmind is held to: MIT's leg the distro's, ours always 1.22.
KV=1.22
[ "$LEG" != mit ] || KV=$MIT_VERSION
A1C_RC=1 A1C_PID=absent A1C_LOG='Error setting up network'
[ "$KV" != 1.21 ] || A1C_RC=124 A1C_PID=present A1C_LOG='kadmind\[[0-9]+\]\(info\): starting$'

# On any exit: no throwaway profile left in the KDC config dir, no probe script on kdc.
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- "sudo rm -rf $KDCDIR/al1-start.* ~/field/al1-start-probe.sh; true" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

R=$REALM
PD=
[ "$KDC_FAMILY" = rpm ] || PD=" $KDCDIR"
section "kadmind-start --leg $LEG: foreground start-up failures on kdc, realm $R (the service stays up, holding 464 and 749)"
kdcis
check kadmin.active '^active$' run kdc "systemctl is-active $UNIT_ADMIN"
hostin "lib/al1-start-probe.sh" "$LABQ ssh kdc -- 'rm -f ~/field/al1-start-probe.sh && install -d -m 0700 ~/field && cat > ~/field/al1-start-probe.sh && chmod 0755 ~/field/al1-start-probe.sh'" < "$FIELD_LIB/al1-start-probe.sh"

section "A1b: an unreadable dict_file stops kadmind in the foreground, before the network"
kdcmark a1b
run kdc "sudo bash ~/field/al1-start-probe.sh $(printf '%q' "$R") dict$PD"
checklast a1b.rc '^rc=1$'
checklast a1b.stderr.abort '^stderr-abort: [1-9]'
checklast a1b.stderr.noneterr '^stderr-neterr: 0$'
checklast a1b.pidfile '^pidfile: absent$'
observelast a1b.procs 'kadmind-procs: [0-9]+'
kdcsince a1b 'while initializing, aborting'
checklast a1b.log 'while initializing, aborting'

section "A1c: port 749 already in use: kadmind stops after 'Error setting up network' (1.21: binds beside it), nothing on stderr"
kdcmark a1c
run kdc "sudo bash ~/field/al1-start-probe.sh $(printf '%q' "$R") port$PD"
checklast a1c.rc "^rc=$A1C_RC\$"
checklast a1c.stderr.noneterr '^stderr-neterr: 0$'
checklast a1c.stderr.noabort '^stderr-abort: 0$'
checklast a1c.pidfile "^pidfile: $A1C_PID\$"
observelast a1c.procs 'kadmind-procs: [0-9]+'
kdcsince a1c "$A1C_LOG"
checklast a1c.log "$A1C_LOG"

finish
