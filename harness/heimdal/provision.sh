#!/bin/sh
# Build-time HDB: realm KERBER.TEST, master key aes256-cts-hmac-sha1-96.
set -eu

REALM="${HEIMDAL_REALM:-KERBER.TEST}"
USER_PRINC="${HEIMDAL_USER:-user}"
USER_PW="${HEIMDAL_USER_PASSWORD:-userpassword}"
HOST_PRINC="${HEIMDAL_HOST:-host/testhost.kerber.test}"
ETYPE="aes256-cts-hmac-sha1-96"
HDB_DIR=/var/lib/heimdal-kdc
MKEY="$HDB_DIR/m-key"

KDC_BIN=""
for p in /usr/lib/heimdal-servers/kdc /usr/sbin/kdc /usr/libexec/heimdal/kdc; do
    if [ -x "$p" ]; then
        KDC_BIN="$p"
        break
    fi
done
[ -n "$KDC_BIN" ] || {
    echo "ERROR: Heimdal kdc binary not found" >&2
    ls -l /usr/lib/heimdal-servers /usr/sbin 2>/dev/null || true
    exit 1
}
echo "$KDC_BIN" > /etc/heimdal-kdc/kdc.path
chmod 0644 /etc/heimdal-kdc/kdc.path

if command -v dpkg >/dev/null 2>&1 && dpkg -l krb5-user 2>/dev/null | grep -q '^ii'; then
    echo "ERROR: krb5-user must not be installed (MIT kinit collision)" >&2
    exit 1
fi
kinit --version 2>&1 | grep -qi heimdal || {
    echo "ERROR: kinit is not Heimdal" >&2
    kinit --version 2>&1 || true
    exit 1
}

mkdir -p "$HDB_DIR" /etc/heimdal-kdc /var/log
rm -f "$HDB_DIR"/heimdal* "$MKEY"
if [ ! -e "$HDB_DIR/kdc.conf" ]; then
    ln -s /etc/heimdal-kdc/kdc.conf "$HDB_DIR/kdc.conf"
fi
: >/var/log/heimdal-kdc.log
chmod 0600 /var/log/heimdal-kdc.log
touch /etc/heimdal-kdc/kadmind.acl

kstash --random-key --enctype="$ETYPE" --key-file="$MKEY"
kadmin -l init --realm-max-ticket-life=unlimited --realm-max-renewable-life=unlimited "$REALM"
kadmin -l add --password="$USER_PW" --use-defaults "$USER_PRINC"
kadmin -l add --random-key --use-defaults "$HOST_PRINC"
kadmin -l ext_keytab -k /etc/heimdal-kdc/testhost.keytab "$HOST_PRINC"
chmod 0600 "$MKEY" /etc/heimdal-kdc/testhost.keytab

echo "==== heimdal provision ===="
echo "kdc_bin=$KDC_BIN"
echo "hdb_dir=$HDB_DIR"
echo "mkey=$MKEY"
ls -l "$KDC_BIN" "$MKEY" "$HDB_DIR"
kadmin -l get "$USER_PRINC"
kadmin -l get "$HOST_PRINC"
kadmin -l get "krbtgt/${REALM}"
if ! kadmin -l get "$USER_PRINC" | grep -q "$ETYPE"; then
    echo "ERROR: user key is not $ETYPE" >&2
    exit 1
fi
touch /etc/heimdal-kdc/.configured
echo "provision ok realm=$REALM etype=$ETYPE"
