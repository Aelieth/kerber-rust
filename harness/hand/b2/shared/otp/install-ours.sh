#!/bin/bash
# install-ours.sh: docs/install.md "Upgrading an MIT realm" on the kdc VM, as root (the OTP4 lab leg; the OTP1 leg's script, RA r4's, with its work directory changed again), with the ship build's dist/install.sh in place of
# `make install PREFIX=/usr` (so no `dnf install make`), and with the docs' modprinc +requires_preauth step after the load. Inputs: /var/tmp/otp3/ship/{release,dist}. Prints INSTALL_START / INSTALL_DONE.
set -eu
D=/var/tmp/otp3; SHIP=$D/ship; KDCDIR=/var/kerberos/krb5kdc
# shellcheck source=../../../lib/install-env.sh # staged beside this script on the VM
. "$(dirname "$0")/install-env.sh"
install_check "$SHIP"   # before any change on the VM
echo "INSTALL_START $(date -u +%FT%TZ)"
echo "MIT before: $(rpm -q krb5-server krb5-libs | tr '\n' ' ')"
systemctl stop krb5kdc kadmin
kdb5_util dump "$KDCDIR/mit-realm.dump"
echo "dump: $(wc -c < "$KDCDIR/mit-realm.dump") bytes, $(grep -c '^princ' "$KDCDIR/mit-realm.dump") principals"
dnf remove -y --no-autoremove krb5-server
for f in "$KDCDIR/kdc.conf" "$KDCDIR/kadm5.acl" /etc/sysconfig/krb5kdc /etc/sysconfig/kadmin /etc/logrotate.d/krb5kdc /etc/logrotate.d/kadmind; do
    if [ -e "$f.rpmsave" ]; then mv "$f.rpmsave" "$f"; echo "RESTORED:$f"; fi
done
install_run "$SHIP" install
mkdir -p "$KDCDIR/mit-db2"
for f in principal principal.kadm5 principal.ulog; do
    if [ -e "$KDCDIR/$f" ]; then mv "$KDCDIR/$f" "$KDCDIR/mit-db2/"; fi
done
kdb5_util load "$KDCDIR/mit-realm.dump"
restorecon -Rv "$KDCDIR"
kadmin.local -q listprincs
systemctl enable --now krb5kdc kadmin
# docs/install.md, the paragraph after the load (it was not in RA r4's script, so not in OTP1's leg): a loaded principal keeps its attributes,
# so each principal that logs in with a password gets REQUIRES_PRE_AUTH once
kadmin.local -q listprincs | grep -e '^[^/ ]*@' -e '^[^/ ]*/admin@' | grep -v '^kadmin/' |
    while read -r p; do kadmin.local -q "modprinc +requires_preauth $p" </dev/null; done
sleep 2
echo "active: $(systemctl is-active krb5kdc kadmin | tr '\n' ' ')"
ss -H -lntu 'sport = :464' || true
sha256sum /usr/sbin/krb5kdc /usr/sbin/kadmind /usr/sbin/kadmin.local /usr/sbin/kdb5_util /usr/sbin/kprop /usr/sbin/kpropd
rpm -qf /usr/sbin/kadmind 2>&1 || true
echo "INSTALL_DONE $(date -u +%FT%TZ)"
