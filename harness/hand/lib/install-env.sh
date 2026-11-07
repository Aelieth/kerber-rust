#!/bin/bash
# install-env.sh: what `make install PREFIX=/usr` passes dist/install.sh on an rpm-family host (the Makefile's
# INSTALLER), for the hand legs that run install.sh without make. Sourced on the VM, beside install-ours.sh.

# install_vars SHIP: the variables, one NAME=VALUE a line.
install_vars() {
    printf '%s\n' "RELEASE=$1/release" "DIST=$1/dist" DESTDIR= BINDIR=/usr/bin SBINDIR=/usr/sbin \
        SYSCONFIGDIR=/etc/sysconfig LOGROTATEDIR=/etc/logrotate.d UNITDIR=/usr/lib/systemd/system \
        TMPFILESDIR=/usr/lib/tmpfiles.d KDCDIR=/var/kerberos/krb5kdc KDCDATADIR=/var/kerberos/krb5kdc FAMILY=rpm \
        MANIFEST=/usr/share/kerber-rust/install-manifest
}

# install_check SHIP: each variable SHIP's install.sh requires is set (and not empty, for ${X:?}); run before any change.
install_check() {
    local vars name v
    vars=$(install_vars "$1")
    [ -r "$1/dist/install.sh" ] || { echo "install-env: no $1/dist/install.sh"; return 1; }
    while IFS= read -r name; do
        v=$(printf '%s\n' "$vars" | sed -n "s/^${name%:}=//p")
        printf '%s\n' "$vars" | grep -q "^${name%:}=" || { echo "install-env: install.sh needs ${name%:}, which is not set"; return 1; }
        case $name in *:) [ -n "$v" ] || { echo "install-env: install.sh needs ${name%:} set and not empty"; return 1; } ;; esac
    done < <(grep -o "[\$]{[A-Z_][A-Z0-9_]*:\{0,1\}?}" "$1/dist/install.sh" | sed 's/[^A-Z0-9_:]//g' | sort -u)
}

# install_run SHIP ACTION: install.sh ACTION with exactly those variables.
install_run() {
    local s=$1 kv
    shift
    (
        while IFS= read -r kv; do export "${kv?}"; done < <(install_vars "$s")
        exec sh "$s/dist/install.sh" "$@"
    )
}
