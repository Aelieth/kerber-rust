#!/bin/sh
# MIT 1.22.2 KDC entrypoint. Emits one JSON object per line (structured logs).
set -eu

new_cid() {
    od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
}

CORRELATION_ID="${CORRELATION_ID:-$(new_cid)}"
REALM="KERBER.TEST"
PRINCIPAL="user@${REALM}"
PASSWORD="userpassword"
MASTER_PW="masterpassword"

log() {
    event="$1"
    outcome="$2"
    extra="$3"
    printf '{"event":"%s","correlation_id":"%s","component":"harness","outcome":"%s","realm":"%s"%s}\n' \
        "$event" "$CORRELATION_ID" "$outcome" "$REALM" "$extra"
}

log "harness.start" "ok" ',"kdc_port":88'

if [ ! -f /var/lib/krb5kdc/principal ]; then
    kdb5_util create -s -P "$MASTER_PW"
    kadmin.local -q "addprinc -pw ${PASSWORD} user"
    kadmin.local -q "ktadd -k /etc/krb5kdc/kdc.keytab kadmin/admin" >/dev/null 2>&1 || true
fi

krb5kdc
sleep 0.3

i=0
while [ "$i" -lt 50 ]; do
    if python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),0.3)" 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 0.2
done

if ! python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),1)" 2>/dev/null; then
    log "harness.kdc.ready" "error" ',"error":"kdc not listening on 88"'
    exit 1
fi

log "harness.kdc.ready" "ok" ',"kdc_port":88'

KRB5CCNAME="/tmp/krb5cc_harness"
export KRB5CCNAME
if printf '%s\n' "$PASSWORD" | kinit "$PRINCIPAL"; then
    klist -c "$KRB5CCNAME" >/tmp/klist.out || true
    log "harness.kinit" "ok" ",\"principal\":\"${PRINCIPAL}\""
else
    log "harness.kinit" "error" ",\"principal\":\"${PRINCIPAL}\""
    exit 1
fi

# Stay in the foreground so the container does not exit.
# krb5kdc daemonizes; follow its log file if present, else sleep.
if [ -f /var/log/krb5kdc.log ]; then
    tail -f /var/log/krb5kdc.log
else
    while true; do
        sleep 3600
    done
fi
