#!/bin/bash
# P18 vm-setup.sh (klldap VM, root; `sudo bash -s`): the scratch realm's layout, plus
# /srv/p18/kdc-iprop.conf (the same kdc.conf with iprop_enable) for the iprop-on runs.
# One krb5.conf and one kdc.conf serve both legs byte for byte: the KDC directory is the same
# path for MIT's daemons and ours, and only one leg runs at a time. The kdc.conf is KLLDAP's
# field kdc.conf (f-F3 vm-swap leg-ii configs/klldap/kdc.conf: aes256 master key, aes256:normal
# keys, no iprop) plus explicit paths and private ports, so nothing collides with KLLDAP's 88/749.
set -euo pipefail
B=/srv/p18
mkdir -p $B/seed $B/run/kdc $B/out $B/tmp
chmod 0700 $B
cat > $B/krb5.conf <<'EOF'
[libdefaults]
    default_realm = P18.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    P18.TEST = {
        kdc = 127.0.0.1:18888
        admin_server = 127.0.0.1:18749
        kpasswd_server = 127.0.0.1:18464
    }
EOF
cat > $B/kdc.conf <<'EOF'
[kdcdefaults]
    kdc_ports = 18888
    kdc_tcp_ports = 18888

[realms]
    P18.TEST = {
        database_name = /srv/p18/run/kdc/principal
        key_stash_file = /srv/p18/run/kdc/.k5.P18.TEST
        acl_file = /srv/p18/run/kdc/kadm5.acl
        kadmind_port = 18749
        kpasswd_port = 18464
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }

[logging]
    kdc = FILE:/srv/p18/run/kdc/krb5kdc.log
    admin_server = FILE:/srv/p18/run/kdc/kadmind.log
EOF
sed 's|^        supported_enctypes = aes256-cts-hmac-sha1-96:normal$|&\n        iprop_enable = true\n        iprop_port = 18751|' $B/kdc.conf > $B/kdc-iprop.conf
printf 'admin/admin@P18.TEST *\n' > $B/kadm5.acl
chmod 0600 $B/kdc.conf $B/kdc-iprop.conf $B/kadm5.acl
ls -la $B
echo "--- krb5.conf"; cat $B/krb5.conf
echo "--- kdc.conf"; cat $B/kdc.conf
echo "--- kdc-iprop.conf"; cat $B/kdc-iprop.conf
echo "--- kadm5.acl"; cat $B/kadm5.acl
findmnt -no SOURCE,FSTYPE,OPTIONS -T $B
