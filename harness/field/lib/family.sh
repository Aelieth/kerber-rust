# harness/field/lib/family.sh: the KDC VM's per-family names, sourced by rec.sh (FIELD_KDC_FAMILY = rpm | deb).
# shellcheck shell=bash
KDC_FAMILY=${FIELD_KDC_FAMILY:-rpm}
case $KDC_FAMILY in
    rpm)
        UNIT_KDC=krb5kdc UNIT_ADMIN=kadmin UNIT_KPROP=kprop
        KDCDIR=/var/kerberos/krb5kdc KDCDATADIR=/var/kerberos/krb5kdc
        ENVDIR=/etc/sysconfig MAC=selinux RESTORECON=restorecon
        ARGS_ADMIN=KADMIND_ARGS
        SERVER_PKG=krb5-server MIT_SERVER_PKGS=krb5-server MIT_VERIFY_PKGS='krb5-server krb5-libs' MIT_CLIENT_PKG=krb5-workstation
        PKG_VERIFY='rpm -V' PKG_INSTALL='dnf install -y' PKG_INSTALL_Q='dnf -y -q install' PKG_QUERY='rpm -q' PKG_HAS='rpm -q' LIBDIR_RE=lib64
        DOC_PREREQ='## Prerequisites' DOC_REPLACE='### Replacing krb5-server' DOC_KRB5CONF= ;;
    deb)
        UNIT_KDC=krb5-kdc UNIT_ADMIN=krb5-admin-server UNIT_KPROP=krb5-kpropd
        KDCDIR=/etc/krb5kdc KDCDATADIR=/var/lib/krb5kdc
        ENVDIR=/etc/default MAC=none RESTORECON=true
        ARGS_ADMIN=DAEMON_ARGS
        SERVER_PKG=krb5-kdc MIT_SERVER_PKGS='krb5-kdc krb5-admin-server krb5-kpropd' MIT_CLIENT_PKG=krb5-user
        PKG_VERIFY='dpkg --verify' PKG_HAS='dpkg -s' PKG_INSTALL='env DEBIAN_FRONTEND=noninteractive apt-get install -y'
        PKG_INSTALL_Q='env DEBIAN_FRONTEND=noninteractive apt-get install -y -q'
        LIBDIR_RE=lib/x86_64-linux-gnu
        DOC_PREREQ='### Debian and Ubuntu' DOC_REPLACE='### Replacing krb5-kdc on Debian and Ubuntu'
        DOC_KRB5CONF='### krb5.conf on Debian and Ubuntu'
        read -r PKG_QUERY <<'EOF'
dpkg-query -W -f='${Package}-${Version}\n'
EOF
        # The library packages, by the files the VM has (expanded there, not here).
        read -r MIT_VERIFY_PKGS <<'EOF'
krb5-kdc krb5-admin-server krb5-kpropd $(dpkg -S /usr/lib/x86_64-linux-gnu/libkrb5.so.3 /usr/lib/x86_64-linux-gnu/libkdb5.so.10 /usr/lib/x86_64-linux-gnu/libkadm5srv_mit.so.12 | cut -d: -f1 | sort -u)
EOF
        ;;
    *) printf 'family.sh: FIELD_KDC_FAMILY must be rpm or deb\n' >&2; return 1 ;;
esac
export KDC_FAMILY UNIT_KDC UNIT_ADMIN UNIT_KPROP KDCDIR KDCDATADIR ENVDIR MAC RESTORECON \
    ARGS_ADMIN SERVER_PKG MIT_SERVER_PKGS MIT_VERIFY_PKGS MIT_CLIENT_PKG PKG_VERIFY PKG_HAS PKG_INSTALL PKG_INSTALL_Q PKG_QUERY LIBDIR_RE \
    DOC_PREREQ DOC_REPLACE DOC_KRB5CONF
