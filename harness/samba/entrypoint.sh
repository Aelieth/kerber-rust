#!/bin/sh
# Samba AD DC entrypoint. The domain is already provisioned in the image; this
# only ensures FQDN resolution and starts samba in the foreground (PID 1).
# Emits one JSON line on start (matching the MIT harness structured-log style).
set -eu

REALM="${SAMBA_REALM:-AD.KERBER.TEST}"
FQDN="dc1.$(printf '%s' "$REALM" | tr 'A-Z' 'a-z')"

# Make the DC's own FQDN resolve to the container IP before samba starts
# (Docker only seeds the short hostname; Samba's internal DNS is not up yet).
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "${IP:-}" ] || IP=127.0.0.1
if ! grep -q "$FQDN" /etc/hosts 2>/dev/null; then
    printf '%s %s dc1\n' "$IP" "$FQDN" >> /etc/hosts 2>/dev/null || true
fi

printf '{"event":"samba.start","correlation_id":"%s","component":"samba-harness","realm":"%s","outcome":"ok"}\n' \
    "${CORRELATION_ID:-none}" "$REALM"

exec samba --foreground --no-process-group --debug-stdout
