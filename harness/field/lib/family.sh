# harness/field/lib/family.sh: the KDC VM's per-family names, sourced by rec.sh (FIELD_KDC_FAMILY = rpm | rocky | deb).
# shellcheck shell=bash
KDC_FAMILY=${FIELD_KDC_FAMILY:-rpm}
case $KDC_FAMILY in
    rpm | rocky)
        UNIT_KDC=krb5kdc UNIT_ADMIN=kadmin UNIT_KPROP=kprop
        KDCDIR=/var/kerberos/krb5kdc KDCDATADIR=/var/kerberos/krb5kdc
        ENVDIR=/etc/sysconfig MAC=selinux RESTORECON=restorecon
        ARGS_ADMIN=KADMIND_ARGS
        SERVER_PKG=krb5-server MIT_SERVER_PKGS=krb5-server MIT_VERIFY_PKGS='krb5-server krb5-libs' MIT_CLIENT_PKG=krb5-workstation
        PKG_VERIFY='rpm -V' PKG_INSTALL='dnf install -y' PKG_INSTALL_Q='dnf -y -q install' PKG_QUERY='rpm -q' PKG_HAS='rpm -q' LIBDIR_RE=lib64
        DOC_PREREQ='## Prerequisites' DOC_REPLACE='### Replacing krb5-server' DOC_KRB5CONF=
        DOC_UPGRADE='## Upgrading kerber-rust' LOGSRC=file KDC_SOCKETS=4
        # Rocky has Fedora's layout; its rustup comes from the installer (docs/install.md, Rocky Linux).
        if [ "$KDC_FAMILY" = rocky ]; then DOC_PREREQ='### Rocky Linux'; fi ;;
    deb)
        UNIT_KDC=krb5-kdc UNIT_ADMIN=krb5-admin-server UNIT_KPROP=krb5-kpropd
        KDCDIR=/etc/krb5kdc KDCDATADIR=/var/lib/krb5kdc
        ENVDIR=/etc/default MAC=none RESTORECON=true
        ARGS_ADMIN=DAEMON_ARGS
        SERVER_PKG=krb5-kdc MIT_SERVER_PKGS='krb5-kdc krb5-admin-server krb5-kpropd' MIT_CLIENT_PKG=krb5-user
        PKG_VERIFY='dpkg --verify' PKG_HAS='dpkg -s'
        LIBDIR_RE=lib/x86_64-linux-gnu
        DOC_PREREQ='### Debian and Ubuntu' DOC_REPLACE='### Replacing krb5-kdc on Debian and Ubuntu'
        DOC_KRB5CONF='### krb5.conf on Debian and Ubuntu'
        # Debian's units leave /var/log read-only, so the daemons log to the journal (lib/journal-lines.py).
        DOC_UPGRADE='## Upgrading kerber-rust on Debian and Ubuntu' LOGSRC=journal
        # Debian's kdc.conf has kdc_ports = 750,88, which 1.22.2's TCP takes too (kdc/main.c:969-970): 8 sockets.
        KDC_SOCKETS=8
        # Each runs as one command under sudo, the lists refreshed first; a query of a package not
        # installed prints nothing and fails, as rpm -q does.
        read -r PKG_INSTALL <<'EOF'
sh -c 'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"' sh
EOF
        read -r PKG_INSTALL_Q <<'EOF'
sh -c 'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@"' sh
EOF
        read -r PKG_QUERY <<'EOF'
sh -c 'dpkg -s "$1" > /dev/null 2>&1 && dpkg-query -W -f="\${Package}-\${Version}\n" "$1"' sh
EOF
        # The library packages, by the files the VM has (expanded there, not here).
        read -r MIT_VERIFY_PKGS <<'EOF'
krb5-kdc krb5-admin-server krb5-kpropd $(dpkg -S /usr/lib/x86_64-linux-gnu/libkrb5.so.3 /usr/lib/x86_64-linux-gnu/libkdb5.so.10 /usr/lib/x86_64-linux-gnu/libkadm5srv_mit.so.12 | cut -d: -f1 | sort -u)
EOF
        ;;
    *) printf 'family.sh: FIELD_KDC_FAMILY must be rpm, rocky or deb\n' >&2; return 1 ;;
esac
# A shell line for the KDC VM: the realm's stash, kdc.conf's key_stash_file or MIT's default.
read -r STASH_SH <<'EOF'
stash=$(sudo sed -n 's/^[[:space:]]*key_stash_file[[:space:]]*=[[:space:]]*//p' @/kdc.conf | head -n 1); stash=${stash:-@/.k5.$REALM}
EOF
STASH_SH=${STASH_SH//@/$KDCDIR}
# The role VM's distro MIT, which MIT's leg is held to where 1.21 and 1.22 differ (ds/<vm>.env); ours is always 1.22.
MIT_VERSION=${FIELD_MIT_VERSION:-1.22}
export KDC_FAMILY UNIT_KDC UNIT_ADMIN UNIT_KPROP KDCDIR KDCDATADIR ENVDIR MAC RESTORECON \
    ARGS_ADMIN SERVER_PKG MIT_SERVER_PKGS MIT_VERIFY_PKGS MIT_CLIENT_PKG PKG_VERIFY PKG_HAS PKG_INSTALL PKG_INSTALL_Q PKG_QUERY LIBDIR_RE \
    DOC_PREREQ DOC_REPLACE DOC_KRB5CONF DOC_UPGRADE LOGSRC STASH_SH KDC_SOCKETS MIT_VERSION
