#!/bin/sh
# What `make install`, `make install-clients` and `make uninstall` run: the release programs
# under MIT's command names, laid out as the family's own MIT packages lay out MIT's: FAMILY=rpm
# as Fedora's and Rocky's krb5-server, FAMILY=deb as Debian's and Ubuntu's krb5-kdc,
# krb5-admin-server and krb5-kpropd (docs/install.md). It never builds; the Makefile passes every
# path, and no path may contain white space.
#
#   sh dist/install.sh install | install-clients | uninstall
#
# On a live system (DESTDIR empty, or one that resolves to /) it behaves as an RPM transaction
# would: a file a package owns is neither replaced nor removed, a config file that exists is
# kept, nothing in the KDC directory but the two templates is ever written, and afterwards the
# tmpfiles entry is created, SELinux labels are restored and systemd reloads its units.
# Every file install writes but the config and the two logs goes in the manifest (MANIFEST) with its SHA-256;
# uninstall removes only the manifest's files that are still as install wrote them.
set -eu

action=${1-}
case $action in
    install | install-clients | uninstall) ;;
    *)
        printf 'usage: sh dist/install.sh install | install-clients | uninstall (the Makefile runs it)\n' >&2
        exit 2
        ;;
esac
: "${RELEASE:?}" "${DIST:?}" "${BINDIR:?}" "${SBINDIR:?}" "${SYSCONFIGDIR:?}"
: "${LOGROTATEDIR:?}" "${UNITDIR:?}" "${TMPFILESDIR:?}" "${KDCDIR:?}" "${MANIFEST:?}"
: "${KDCDATADIR:?}" "${FAMILY?}"
DESTDIR=${DESTDIR-}
# A DESTDIR that resolves to / is the live system, and gets the live system's checks.
if [ -n "$DESTDIR" ] && [ "$(realpath -m -- "$DESTDIR")" = / ]; then
    DESTDIR=
fi

# The cargo binary, then the MIT name it is installed under.
KDC_PROGS='krb5-kdc:krb5kdc krb5-kadmind:kadmind krb5-kadmin-local:kadmin.local krb5-kdb:kdb5_util krb5-kprop:kprop krb5-kpropd:kpropd'
CLIENT_PROGS='krb5-kinit:kinit krb5-klist:klist krb5-kdestroy:kdestroy krb5-kswitch:kswitch krb5-kvno:kvno krb5-kpasswd:kpasswd krb5-ktutil:ktutil'
# The family's units, environment files and modes, as its MIT packages have them.
# rpm: Fedora's kprop.service runs MIT's kpropd as a forking daemon; krb5-kpropd never detaches, so
# our kprop.service is Type=simple (the one deviation; docs/mit-deviations.md).
# deb: Debian ships no environment file but the one debconf writes, no tmpfiles or logrotate
# entry and no [logging]; its kdc.conf and kadm5.acl are 0644 and its two KDC directories 0700.
case $FAMILY in
    rpm)
        UNITS='krb5kdc kadmin kprop'
        UNITSRC=$DIST/systemd
        KDCSRC=$DIST/krb5kdc
        ENVFILES='krb5kdc kadmin kprop'
        CONFMODE=0600
        DIRMODE=0755
        REMOVE='sudo dnf remove --setopt=clean_requirements_on_remove=False krb5-server'
        ;;
    deb)
        UNITS='krb5-kdc krb5-admin-server krb5-kpropd'
        UNITSRC=$DIST/deb/systemd
        KDCSRC=$DIST/deb/krb5kdc
        ENVFILES=
        CONFMODE=0644
        DIRMODE=0700
        PACKAGES='krb5-kdc, krb5-admin-server, krb5-kpropd'
        REMOVE='sudo apt-get remove krb5-kdc krb5-admin-server krb5-kpropd'
        ;;
    *)
        # The client programs' layout is the same on every family.
        if [ "$action" != install-clients ]; then
            printf 'make %s: FAMILY is "%s": set FAMILY=rpm (Fedora, Rocky) or FAMILY=deb (Debian, Ubuntu)\n' \
                "$action" "$FAMILY" >&2
            exit 2
        fi
        ;;
esac
TMPFILE=$TMPFILESDIR/krb5-krb5kdc.conf

say() { printf '%s\n' "$*"; }
die() {
    printf 'make %s: %s\n' "$action" "$*" >&2
    exit 1
}

live() { [ -z "$DESTDIR" ]; }
systemd_running() { live && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }
selinux=0
if live && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    selinux=1
fi

# The package that owns a path on this system (rpm, else dpkg); empty for a DESTDIR tree.
owner() {
    live || return 0
    if command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$1" 2>/dev/null); then
        printf '%s\n' "$pkg" | head -n 1
    elif command -v dpkg-query >/dev/null 2>&1 && pkg=$(dpkg-query -S "$1" 2>/dev/null); then
        printf '%s\n' "$pkg" | sed -n '1s/: .*//p'
    fi
}

# The programs of a list, in the directory given, one per line.
dests() {
    for p in $1; do
        say "$2/${p#*:}"
    done
}

# Refuse before anything is written when any of the paths (one per line) belongs to a package.
refuse_owned() {
    owned=
    while IFS= read -r f <&3; do
        [ -n "$f" ] || continue
        pkg=$(owner "$f")
        if [ -n "$pkg" ]; then
            owned="$owned
  $f ($pkg)"
        fi
    done 3<<EOF
$1
EOF
    [ -z "$owned" ] && return 0
    if [ "$action" = install ]; then
        if [ "$FAMILY" = rpm ]; then
            hint="Remove the package first (MIT's krb5-server: $REMOVE),
or install beside it with another PREFIX, e.g. PREFIX=/usr/local (docs/install.md)."
        else
            hint="Remove the packages first (MIT's $PACKAGES: $REMOVE),
or install beside them with another PREFIX, e.g. PREFIX=/usr/local (docs/install.md)."
        fi
    else
        hint="install-clients is for hosts without these client tools: keep the package's,
or install beside them with another PREFIX, e.g. PREFIX=/usr/local (docs/install.md)."
    fi
    die "these paths belong to installed packages, which this install will not replace:$owned
$hint"
}

label() {
    if [ "$selinux" = 1 ]; then
        restorecon "$1" || say "restorecon $1 failed: its SELinux label is not the policy's"
    fi
}

# MODE SOURCE DEST: a copy (a new file, as install(1) makes it).
put() {
    install -D -m "$1" "$2" "$DESTDIR$3"
    label "$3"
    say "installed $3"
}

# MODE SOURCE DEST: SOURCE with the @SBINDIR@, @SYSCONFIGDIR@, @KDCDIR@ and @KDCDATADIR@ paths
# filled in.
render() {
    mkdir -p "$DESTDIR$(dirname "$3")"
    rm -f "$DESTDIR$3"
    (umask 077 && sed -e "s|@SBINDIR@|$SBINDIR|g" -e "s|@SYSCONFIGDIR@|$SYSCONFIGDIR|g" \
        -e "s|@KDCDIR@|$KDCDIR|g" -e "s|@KDCDATADIR@|$KDCDATADIR|g" "$2" >"$DESTDIR$3")
    chmod "$1" "$DESTDIR$3"
    label "$3"
    say "installed $3"
}

# PATH: a daemon log, made empty at 0640 (the mode MIT's daemons make it with) when missing, and
# labelled when it exists or not, so an upgrade repairs a wrong label. Never in the manifest.
logfile() {
    if [ -e "$DESTDIR$1" ] || [ -L "$DESTDIR$1" ]; then
        say "kept $1 (it exists)"
    else
        install -D -m 0640 /dev/null "$DESTDIR$1"
        say "installed $1"
    fi
    label "$1"
}

# MODE SOURCE DEST [render]: a config file, installed only when nothing is at DEST (the RPM's
# noreplace), so an admin's file survives every reinstall. Config is never in the manifest.
config() {
    if [ -e "$DESTDIR$3" ] || [ -L "$DESTDIR$3" ]; then
        say "kept $3 (it exists)"
    elif [ "${4-}" = render ]; then
        render "$1" "$2" "$3"
    else
        put "$1" "$2" "$3"
    fi
}

# The SHA-256 of a file.
checksum() {
    s=$(sha256sum <"$1")
    say "${s%% *}"
}

# The manifest lines ("SHA-256  PATH") of the files this run wrote.
written=

record() {
    written="$written$(checksum "$DESTDIR$1")  $1
"
}

# Write the manifest: its earlier lines for the paths this run did not write, then this run's,
# into a new file renamed over the old one, so the manifest is never half-written. Run on exit,
# so a failed install still records what it wrote.
save_manifest() {
    [ -n "$written" ] || return 0
    m=$DESTDIR$MANIFEST
    mkdir -p "$(dirname "$m")"
    tmp=$m.new.$$
    {
        if [ -f "$m" ]; then
            printf '%s' "$written" | awk 'NR == FNR { w[$2] = 1; next } !($2 in w)' - "$m"
        fi
        printf '%s' "$written"
    } >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$m"
    label "$MANIFEST"
    written=
}
trap save_manifest EXIT

need_programs() {
    for p in $1; do
        [ -x "$RELEASE/${p%%:*}" ] || die "$RELEASE/${p%%:*} is missing: run 'make build' first"
    done
}

install_programs() {
    for p in $1; do
        put 0755 "$RELEASE/${p%%:*}" "$2/${p#*:}"
        record "$2/${p#*:}"
    done
}

# DIR: a KDC directory at the family's mode, made when missing (never in the manifest).
kdcdir() {
    if [ ! -d "$DESTDIR$1" ]; then
        mkdir -p "$DESTDIR$(dirname "$1")"
        install -d -m "$DIRMODE" "$DESTDIR$1"
        label "$1"
        say "installed $1/"
    fi
}

do_install() {
    units=
    for u in $UNITS; do
        units="$units$UNITDIR/$u.service
"
    done
    [ "$FAMILY" = rpm ] && units="$units$TMPFILE"
    refuse_owned "$(dests "$KDC_PROGS" "$SBINDIR")
$units"
    need_programs "$KDC_PROGS"
    install_programs "$KDC_PROGS" "$SBINDIR"
    for u in $UNITS; do
        render 0644 "$UNITSRC/$u.service.in" "$UNITDIR/$u.service"
        record "$UNITDIR/$u.service"
    done
    if [ "$FAMILY" = rpm ]; then
        put 0644 "$DIST/tmpfiles.d/krb5-krb5kdc.conf" "$TMPFILE"
        record "$TMPFILE"
    fi
    for s in $ENVFILES; do
        config 0644 "$DIST/sysconfig/$s" "$SYSCONFIGDIR/$s"
    done
    if [ "$FAMILY" = rpm ]; then
        for l in krb5kdc kadmind; do
            config 0644 "$DIST/logrotate.d/$l" "$LOGROTATEDIR/$l"
        done
        logfile /var/log/krb5kdc.log
        logfile /var/log/kadmind.log
    fi
    kdcdir "$KDCDIR"
    kdcdir "$KDCDATADIR"
    config "$CONFMODE" "$KDCSRC/kdc.conf.in" "$KDCDIR/kdc.conf" render
    config "$CONFMODE" "$KDCSRC/kadm5.acl" "$KDCDIR/kadm5.acl"
    save_manifest
    if [ "$FAMILY" = rpm ] && live && command -v systemd-tmpfiles >/dev/null 2>&1; then
        systemd-tmpfiles --create "$TMPFILE" || say "systemd-tmpfiles --create $TMPFILE failed"
    fi
    if systemd_running; then
        systemctl daemon-reload || say "systemctl daemon-reload failed: run it before starting the units"
        for u in $UNITS; do
            if systemctl -q is-active "$u.service"; then
                say "$u.service is still running the programs it started with: systemctl restart $u"
            fi
        done
    fi
}

do_install_clients() {
    refuse_owned "$(dests "$CLIENT_PROGS" "$BINDIR")"
    need_programs "$CLIENT_PROGS"
    install_programs "$CLIENT_PROGS" "$BINDIR"
}

# SUM PATH: PATH is a regular file whose SHA-256 is still SUM.
unchanged() {
    if [ ! -f "$DESTDIR$2" ] || [ -L "$DESTDIR$2" ]; then
        return 1
    fi
    [ "$(checksum "$DESTDIR$2")" = "$1" ]
}

do_uninstall() {
    m=$DESTDIR$MANIFEST
    if [ ! -f "$m" ]; then
        say "no manifest at $MANIFEST, so nothing make install wrote is known here: nothing removed"
        return 0
    fi
    while read -r sum path <&3; do
        case $path in
            "$UNITDIR"/*.service)
                if systemd_running && unchanged "$sum" "$path"; then
                    systemctl --no-reload disable --now "${path##*/}" || true
                fi
                ;;
        esac
    done 3<"$m"
    while read -r sum path <&3; do
        [ -n "$path" ] || continue
        if [ ! -e "$DESTDIR$path" ] && [ ! -L "$DESTDIR$path" ]; then
            continue
        fi
        pkg=$(owner "$path")
        if [ -n "$pkg" ]; then
            say "kept $path (it belongs to $pkg)"
        elif unchanged "$sum" "$path"; then
            rm -f "$DESTDIR$path"
            say "removed $path"
        else
            say "kept $path (it is not the file make install wrote)"
        fi
    done 3<"$m"
    rm -f "$m"
    rmdir "$(dirname "$m")" 2>/dev/null || true
    if systemd_running; then
        systemctl daemon-reload || say "systemctl daemon-reload failed"
    fi
    if [ "$FAMILY" = rpm ]; then
        say "left in place: $KDCDIR (the database, stash, kdc.conf and kadm5.acl), $SYSCONFIGDIR/{krb5kdc,kadmin,kprop} $LOGROTATEDIR/{krb5kdc,kadmind} and /var/log/{krb5kdc,kadmind}.log"
    else
        say "left in place: $KDCDIR (kdc.conf, kadm5.acl and the stash) and $KDCDATADIR (the database)"
    fi
}

case $action in
    install) do_install ;;
    install-clients) do_install_clients ;;
    uninstall) do_uninstall ;;
esac
