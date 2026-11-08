#!/bin/bash
# b2ctl.sh SUBCOMMAND [args]: the B2 hold's helper on a lab VM, run as root (sudo bash b2ctl.sh ...). Pushed to /var/tmp/otp3 by driver-b2.sh at L1 (stdin, sha256 checked on both sides).
# It sits beside otp/vmctl.sh (byte for byte hold B's) and adds what the module hooks need. Nothing is installed by it; no secret passes through it.
#   snapshot-conf               keep, once, the sha256 of the VM's krb5 config files (/etc/krb5.conf, /etc/krb5.conf.d/*, and on the kdc kdc.conf and kadm5.acl) and a copy of kdc.conf; on the kdc also the
#                               realm database's fingerprint (below): prints SNAPSHOT_OK
#   state                       the VM's state for the shell's rows after each module: SELinux mode, the kdc's two units, whether the config files are as snapshot-conf found them, and (kdc) whether the
#                               realm database is as found: the sorted `kadmin.local -q listprincs` and `listpols` and the key version numbers of alice, bob and admin/admin, the same words from MIT's
#                               kadmin.local and from ours; a principal, a policy or a password change a module left behind is named in the diff
#   rebaseline                  make the VM's current config sums (and on the kdc the current realm fingerprint) the ones `state` compares with: the shell calls it after a module's boundary row went red,
#                               so that the NEXT module is not blamed for what this one left
#   alog-size | alog-since M    the kadmind log (/var/log/kadmind.log): its mark, and the bytes after it, through a logrotate
#   kdcconf-save TAG            keep kdc.conf as $D/kdc.conf.TAG
#   kdcconf-restore TAG         put the kept kdc.conf back (in place: the same inode, so the label and the mode stay); TAG "pristine" is the file snapshot-conf kept
# The paths are the Fedora VM's; VMCTL_* override them for the rehearsals on the host (the same variables as vmctl.sh, plus VMCTL_ALOG).
set -u
D=${VMCTL_D:-/var/tmp/otp3}
KDCDIR=${VMCTL_KDCDIR:-/var/kerberos/krb5kdc}
KDCCONF=${VMCTL_KDCCONF:-$KDCDIR/kdc.conf}
ALOG=${VMCTL_ALOG:-/var/log/kadmind.log}
LOGSINCE=${VMCTL_LOGSINCE:-$(dirname "$0")/log-since.sh}   # pushed beside this script
KRB5CONF=${VMCTL_KRB5CONF:-/etc/krb5.conf}
KRB5CONFD=${VMCTL_KRB5CONFD:-/etc/krb5.conf.d}
P=$D/pristine
sub=${1:-}
[ $# -gt 0 ] && shift

conf_files() {   # the config files this hold watches, one per line, in a fixed order
    local f
    for f in "$KRB5CONF" "$KRB5CONFD"/* "$KDCCONF" "$KDCDIR/kadm5.acl"; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done | LC_ALL=C sort -u
}
conf_sums() {    # sha256 and path of each watched file
    local f
    conf_files | while IFS= read -r f; do printf '%s  %s\n' "$(sha256sum < "$f" | cut -d' ' -f1)" "$f"; done
}

realm_fp() {   # the realm database's fingerprint, to stdout (kdc only): sorted principals, sorted policies, key version numbers of the lab realm's three standing principals
    local p
    command -v kadmin.local > /dev/null 2>&1 || { echo "(no kadmin.local)"; return 0; }
    echo "== listprincs"
    kadmin.local -q listprincs < /dev/null 2>&1 | grep -v -e '^Authenticating as principal ' | LC_ALL=C sort
    echo "== listpols"
    kadmin.local -q listpols < /dev/null 2>&1 | grep -v -e '^Authenticating as principal ' | LC_ALL=C sort
    echo "== key version numbers"
    for p in alice bob admin/admin; do
        printf '%s: %s\n' "$p" "$(kadmin.local -q "getprinc $p" < /dev/null 2>&1 | sed -n 's/^Key: vno \([0-9]*\),.*/\1/p' | sort -un | paste -sd, -)"
    done
}

realm_line() {   # realm_line FILE: the fingerprint file in one line: the sha256 of the sorted principals, of the sorted policies, and the key version numbers
    local f=$1 sec sums=""
    for sec in listprincs listpols; do
        sums="$sums $sec=$(awk -v h="== $sec" '$0 == h { x = 1; next } /^== / { x = 0 } x' "$f" | sha256sum | cut -d' ' -f1)"
    done
    printf 'sha256%s; key version numbers %s\n' "$sums" "$(awk '/^== key version numbers$/ { x = 1; next } /^== / { x = 0 } x' "$f" | paste -sd' ' -)"
}

case $sub in
snapshot-conf)
    install -d -m 0700 "$P"
    if [ ! -s "$P/sums" ]; then
        conf_sums > "$P/sums"
        [ -f "$KDCCONF" ] && cp -p "$KDCCONF" "$D/kdc.conf.pristine"
        [ -f "$KDCCONF" ] && realm_fp > "$P/realm.txt"
        echo "kept the config files' sha256 ($(wc -l < "$P/sums") files):"
        cat "$P/sums"
        [ -s "$P/realm.txt" ] && echo "kept the realm database's fingerprint: $(grep -c . "$P/realm.txt") lines: $(realm_line "$P/realm.txt")"
    else
        echo "already kept ($(wc -l < "$P/sums") files)"
    fi
    echo "SNAPSHOT_OK $(wc -l < "$P/sums") files"
    ;;
state)
    echo "host: $(hostname -s)"
    echo "selinux: $(getenforce 2>&1)"
    if [ -f "$KDCCONF" ]; then echo "units: krb5kdc=$(systemctl is-active krb5kdc 2>&1) kadmin=$(systemctl is-active kadmin 2>&1)"; fi
    if [ ! -s "$P/sums" ]; then
        echo "config: NO SNAPSHOT (snapshot-conf has not run on this VM)"
    elif conf_sums | diff -q "$P/sums" - > /dev/null; then
        echo "config: same as found"
    else
        echo "config: DIFFERS from what was found:"
        conf_sums | diff "$P/sums" - | grep '^[<>]' | sed 's/^/    /'
    fi
    if [ -f "$KDCCONF" ]; then
        if [ ! -s "$P/realm.txt" ]; then
            echo "realm: NO SNAPSHOT (snapshot-conf has not run on this kdc)"
        else
            realm_fp > "$P/realm.now"
            echo "realm-now: $(realm_line "$P/realm.now")"
            if cmp -s "$P/realm.txt" "$P/realm.now"; then
                echo "realm: same as found"
            else
                echo "realm: DIFFERS from what was found (< found, > now):"
                diff "$P/realm.txt" "$P/realm.now" | grep '^[<>]' | head -n 30 | sed 's/^/    /'
            fi
        fi
    fi
    ;;
rebaseline)
    [ -s "$P/sums" ] || { echo "rebaseline: no snapshot"; exit 1; }
    conf_sums > "$P/sums"
    [ -f "$KDCCONF" ] && realm_fp > "$P/realm.txt"
    echo "REBASELINED $(wc -l < "$P/sums") files$([ -s "$P/realm.txt" ] && echo ", realm $(sha256sum < "$P/realm.txt" | cut -c1-16)")"
    ;;
alog-size)   sh "$LOGSINCE" mark "$ALOG" ;;
alog-since)  sh "$LOGSINCE" since "${1:?mark}" "$ALOG" c ;;
kdcconf-save)
    tag=${1:?tag}
    cp -p "$KDCCONF" "$D/kdc.conf.$tag" || exit 1
    echo "kdc.conf kept as $D/kdc.conf.$tag sha256 $(sha256sum < "$D/kdc.conf.$tag" | cut -d' ' -f1)"
    ;;
kdcconf-restore)
    tag=${1:?tag}
    [ -f "$D/kdc.conf.$tag" ] || { echo "no kept kdc.conf.$tag"; exit 1; }
    cat "$D/kdc.conf.$tag" > "$KDCCONF" || exit 1
    echo "kdc.conf put back from $tag sha256 $(sha256sum < "$KDCCONF" | cut -d' ' -f1)"
    ;;
*)
    echo "b2ctl.sh: unknown subcommand '$sub'" >&2
    exit 2
    ;;
esac
