#!/usr/bin/env bash
# Start sssd_kcm on the Heimdal KCM unix socket. No systemd.
set -euo pipefail
mkdir -p /var/lib/sss/secrets /var/log/sssd /var/lib/sss/db /run
chmod 700 /var/lib/sss/secrets
rm -f /run/.heim_org.h5l.kcm-socket
exec /usr/libexec/sssd/sssd_kcm --logger=stderr
