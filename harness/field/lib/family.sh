# harness/field/lib/family.sh: the KDC VM's per-family names, sourced by rec.sh (FIELD_KDC_FAMILY = rpm | deb).
# shellcheck shell=bash
KDC_FAMILY=${FIELD_KDC_FAMILY:-rpm}
case $KDC_FAMILY in
    rpm)
        UNIT_KDC=krb5kdc UNIT_ADMIN=kadmin UNIT_KPROP=kprop
        KDCDIR=/var/kerberos/krb5kdc KDCDATADIR=/var/kerberos/krb5kdc
        ENVDIR=/etc/sysconfig MAC=selinux RESTORECON=restorecon ;;
    deb)
        UNIT_KDC=krb5-kdc UNIT_ADMIN=krb5-admin-server UNIT_KPROP=krb5-kpropd
        KDCDIR=/etc/krb5kdc KDCDATADIR=/var/lib/krb5kdc
        ENVDIR=/etc/default MAC=none RESTORECON=true ;;
    *) printf 'family.sh: FIELD_KDC_FAMILY must be rpm or deb\n' >&2; return 1 ;;
esac
export KDC_FAMILY UNIT_KDC UNIT_ADMIN UNIT_KPROP KDCDIR KDCDATADIR ENVDIR MAC RESTORECON
