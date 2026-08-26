#!/bin/sh
# Heimdal KDC already provisioned in the image; start it in the foreground.
set -eu

REALM="${HEIMDAL_REALM:-KERBER.TEST}"
KDC_BIN="$(cat /etc/heimdal-kdc/kdc.path 2>/dev/null || true)"
[ -n "$KDC_BIN" ] && [ -x "$KDC_BIN" ] || KDC_BIN=/usr/lib/heimdal-servers/kdc
[ -x "$KDC_BIN" ] || {
    echo "ERROR: Heimdal kdc not executable: $KDC_BIN" >&2
    exit 1
}

printf '{"event":"heimdal.start","correlation_id":"%s","component":"heimdal-harness","realm":"%s","kdc":"%s","outcome":"ok"}\n' \
    "${CORRELATION_ID:-none}" "$REALM" "$KDC_BIN"

exec "$KDC_BIN" --config-file=/etc/heimdal-kdc/kdc.conf
