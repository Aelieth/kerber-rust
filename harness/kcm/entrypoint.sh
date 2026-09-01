#!/usr/bin/env bash
# Start sssd_kcm on the Heimdal KCM unix socket. No systemd.
# Runs as in-container root: sssd_kcm needs root for /var/lib/sss/secrets.
# Host isolation is the throwaway container, not useradd 4242.
set -euo pipefail
mkdir -p /var/lib/sss/secrets /var/log/sssd /var/lib/sss/db /run
chmod 700 /var/lib/sss/secrets
rm -f /run/.heim_org.h5l.kcm-socket
exec /usr/libexec/sssd/sssd_kcm --logger=stderr
