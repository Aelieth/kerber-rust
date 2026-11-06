#!/bin/bash
# p18-quiet.sh WT: print klldap's running containers and dnf-makecache.timer, which the p18 legs
# leave as they are, so the record says how the sessions ran.
WT=${1:?checkout}
s=$(bash "$WT/harness/field/lab.sh" ssh klldap -- 'bash -s' << 'EOS'
if c=$(sudo -n docker ps --format '{{.Names}}' 2>/dev/null); then c=$(paste -sd, - <<< "$c"); c=${c:-none}; else c=unknown; fi
m=$(systemctl is-active dnf-makecache.timer 2>/dev/null)
echo "container=$c makecache=${m:-unknown}"
EOS
)
echo "P18_QUIET ${s:-unknown}"
