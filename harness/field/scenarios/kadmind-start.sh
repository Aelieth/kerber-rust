#!/usr/bin/env bash
# harness/field/scenarios/kadmind-start.sh --leg mit|rust: kadmind's two foreground start-up failures on
# kdc, as upgrade.sh left it (MIT's packaged kadmind on the mit leg, kerber-rust's on the rust leg; the
# same /usr/sbin/kadmind path). Both legs must fail the same way, MIT first (hand record f-AL1-start).
# The running kadmind service is left up; it holds 464 and 749, which cell A1c needs.
#   A1b: an unreadable dict_file (a symlink loop, ELOOP) stops kadmind in the foreground before the
#        network: exit 1 with "... while initializing, aborting" on stderr and in the daemon log, no pid
#        file written, no daemon left.
#   A1c: the kadm5 program's port 749 is already in use (the service holds it), so the network set-up
#        fails: exit 1 after MIT's "Error setting up network" line in the daemon log, nothing on stderr.
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

# On any exit: no throwaway profile left in the KDC config dir, no probe script on kdc.
cleanup() {
    timeout -k 5 60 "$LAB" ssh kdc -- 'sudo rm -rf /var/kerberos/krb5kdc/al1-start.* ~/field/al1-start-probe.sh; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

R=$REALM
section "kadmind-start --leg $LEG: foreground start-up failures on kdc, realm $R (the service stays up, holding 464 and 749)"
kdcis
check kadmin.active '^active$' run kdc "systemctl is-active kadmin"
hostin "lib/al1-start-probe.sh" "$LABQ ssh kdc -- 'rm -f ~/field/al1-start-probe.sh && install -d -m 0700 ~/field && cat > ~/field/al1-start-probe.sh && chmod 0755 ~/field/al1-start-probe.sh'" < "$FIELD_LIB/al1-start-probe.sh"

section "A1b: an unreadable dict_file stops kadmind in the foreground, before the network"
kdcmark a1b
run kdc "sudo bash ~/field/al1-start-probe.sh $(printf '%q' "$R") dict"
checklast a1b.rc '^rc=1$'
checklast a1b.stderr.abort '^stderr-abort: [1-9]'
checklast a1b.stderr.noneterr '^stderr-neterr: 0$'
checklast a1b.pidfile '^pidfile: absent$'
observelast a1b.procs 'kadmind-procs: [0-9]+'
kdcsince a1b 'while initializing, aborting'
checklast a1b.log 'while initializing, aborting'

section "A1c: port 749 already in use stops kadmind after 'Error setting up network', nothing on stderr"
kdcmark a1c
run kdc "sudo bash ~/field/al1-start-probe.sh $(printf '%q' "$R") port"
checklast a1c.rc '^rc=1$'
checklast a1c.stderr.noneterr '^stderr-neterr: 0$'
checklast a1c.stderr.noabort '^stderr-abort: 0$'
checklast a1c.pidfile '^pidfile: absent$'
observelast a1c.procs 'kadmind-procs: [0-9]+'
kdcsince a1c 'Error setting up network'
checklast a1c.log 'Error setting up network'

finish
