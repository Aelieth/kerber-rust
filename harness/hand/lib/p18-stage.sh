#!/bin/bash
# p18-stage.sh WT [--build]: stage what the p18 legs need on klldap, only where it is absent: the
# p18 scripts from this harness's tree, the prerequisites from WT's docs/install.md (the build
# under test); then check again and stop on anything missing.
# Prints P18_STAGED:yes|no, and P18_SENT <script> <sha256> for each script it ran or copied.
# A new seed is a new P18.TEST realm (seed.sh draws its passwords in its own pipe).
set -u
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
WT=${1:?checkout}
BUILD=${2:-}
LAB=$WT/harness/field/lab.sh
H=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
P=$H/field/p18
DOC=$H/field/lib/docblocks.py
lab() { bash "$LAB" "$@"; }
# MIT 1.22.2's server and client, strace and eatmydata, as the P18 record installed them.
PKGS='krb5-server krb5-workstation strace libeatmydata python3'
staged=no
sent() { staged=yes; echo "P18_SENT $1 $(sha256sum "$2" | awk '{ print $1 }')"; }

missing() {
    lab ssh klldap -- 'sudo -n bash -s' << 'EOS'
for f in /srv/p18/krb5.conf /srv/p18/kdc-off.conf /srv/p18/kdc-iprop.conf /srv/p18/kadm5.acl; do
    [ -s "$f" ] || echo "layout:$f"
done
for n in 10 100 1000 5000; do [ -s "/srv/p18/seed/N$n.dump" ] || echo "seed:N$n.dump"; done
[ -s /srv/p18/seed/admin.keytab ] || echo "seed:admin.keytab"
for f in session.sh probe-session.sh; do [ -x "/var/tmp/p18/$f" ] || echo "script:$f"; done
echo P18_CHECKED
EOS
}
# The absent items, one per line; stops when the remote check did not finish.
need() {
    local out
    out=$(missing)
    grep -qx P18_CHECKED <<< "$out" || { echo "P18_STOP check"; exit 2; }
    grep -vx P18_CHECKED <<< "$out" || true
}

require_files "$LAB" "$P/vm-setup.sh" "$P/seed.sh" "$P/session.sh" "$P/probe-session.sh"
[ "$BUILD" != --build ] || require_files "$DOC" "$WT/docs/install.md"
lab ssh klldap -- true > /dev/null 2>&1 || { echo "P18_STOP klldap ssh"; exit 2; }
if ! lab ssh klldap -- "rpm -q $PKGS" > /dev/null 2>&1; then
    if ! dnf_out=$(lab ssh klldap -- "sudo -n dnf -y -q install $PKGS" 2>&1); then
        tail -n 20 <<< "$dnf_out"
        echo "P18_STOP dnf"
        exit 2
    fi
    staged=yes
    echo "P18_DNF $PKGS"
fi
mit=$(lab ssh klldap -- "rpm -q --qf '%{VERSION}' krb5-server" 2> /dev/null)
[ "$mit" = 1.22.2 ] || { echo "P18_STOP mit $mit"; exit 2; }
echo "P18_PKG $(lab ssh klldap -- "rpm -q $PKGS" 2> /dev/null | paste -sd' ' -)"

list=$(need) || { echo "$list"; exit 2; }
# seed.sh reads kdc.conf, which a leg may have left as the iprop copy: the layout is rewritten first.
if grep -q '^layout:\|^seed:' <<< "$list"; then
    lab ssh klldap -- 'sudo -n bash -s' < "$P/vm-setup.sh" > /dev/null || { echo "P18_STOP vm-setup"; exit 2; }
    sent vm-setup.sh "$P/vm-setup.sh"
fi
if grep -q '^seed:' <<< "$list"; then
    lab ssh klldap -- 'sudo -n bash -s' < "$P/seed.sh" > /dev/null || { echo "P18_STOP seed"; exit 2; }
    sent seed.sh "$P/seed.sh"
fi
for f in session.sh probe-session.sh; do
    if grep -qx "script:$f" <<< "$list"; then
        lab ssh klldap -- "mkdir -p /var/tmp/p18 && cat > /var/tmp/p18/$f && chmod 755 /var/tmp/p18/$f" < "$P/$f" \
            || { echo "P18_STOP copy $f"; exit 2; }
        sent "$f" "$P/$f"
    else
        got=$(lab ssh klldap -- "sha256sum /var/tmp/p18/$f" 2> /dev/null | awk '{ print $1 }')
        [ "$got" = "$(sha256sum "$P/$f" | awk '{ print $1 }')" ] \
            || { echo "P18_STOP /var/tmp/p18/$f is not the tree's ($got)"; exit 2; }
    fi
done

if [ "$BUILD" = --build ] && ! lab ssh klldap -- "test -f \"\$HOME/.cargo/env\""; then
    pre=$(mktemp "${TMPDIR:-/var/tmp}/p18-pre.XXXXXX")
    out=$(mktemp "${TMPDIR:-/var/tmp}/p18-pre-out.XXXXXX")
    python3 -B "$DOC" script "$WT/docs/install.md" '## Prerequisites' 1 > "$pre" \
        || { rm -f "$pre" "$out"; echo "P18_STOP prerequisites block"; exit 2; }
    lab ssh klldap -- 'bash -s' < "$pre" > "$out" 2>&1
    sent install.md-prerequisites "$pre"
    bad=$(python3 -B "$DOC" results "$out" | awk -F'\t' '$2 != 0' | wc -l)
    rm -f "$pre" "$out"
    [ "$bad" = 0 ] || { echo "P18_STOP prerequisites: $bad unit(s) failed"; exit 2; }
fi

list=$(need) || { echo "$list"; exit 2; }
[ -z "$list" ] || { echo "P18_STOP missing $(paste -sd' ' - <<< "$list")"; exit 2; }
if [ "$BUILD" = --build ]; then
    lab ssh klldap -- "test -f \"\$HOME/.cargo/env\"" || { echo "P18_STOP missing rust toolchain"; exit 2; }
fi
echo "P18_STAGED:$staged"
