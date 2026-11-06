#!/bin/bash
# DS's baselines on one distro VM, deb13 (Debian 13) or rocky10 (Rocky Linux 10).
# Arguments: <landed sha> <vm> [phases: base,mit,rust]. Each phase makes one offline snapshot of the VM, never
# over an existing name:
#   base  ds-base-<vm>     base, the hostname kdc.kerber.test, the dictionary install.sh's kdc.conf names; no krb5
#   mit   mit-oracle-<vm>  the distro's MIT KDC (mit-server-<vm>, RC R1) holding f4-mit-f44's realm
#   rust  rust-base-<vm>   kerber-rust at RUST_PIN (a3a9e051, the oldest sha whose install both families proved),
#                          replacing mit-server-<vm>'s MIT by that sha's own docs/install.md blocks, as MD's smoke did,
#                          and holding rust-field-p12-f44's realm, so `upgrade` steps a real version gap
# A realm moves from Fedora's kdc by that KDC's own kdb5_util dump piped into the distro's kdb5_util load, and its
# stash the same way: neither reaches a file off the two VMs. Before a snapshot: listprincs and getprinc of alice
# and krbtgt equal the source's, the stash's enctype equals the source's, both units are active after a reboot,
# and MIT's kinit on client2 gets alice a TGT through `lab.sh takeover`. Needs HAND_WT (a checkout of the sha) and
# HAND_REC. kdc ends shut off and the takeover released, also on an early exit.
set -u
set +x
umask 077
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC

SHA=${1:-}
VM=${2:-}
PHASES=${3:-base,mit,rust}
case $VM in
    deb13)
        FAM=deb PREREQ='### Debian and Ubuntu' START=2 KDCCONF='### kdc.conf and kadm5.acl on Debian and Ubuntu'
        BASE_PKGS='wamerican python3 strace openssl' MIT_PKGS='krb5-kpropd krb5-pkinit' ;;
    rocky10)
        FAM=rpm PREREQ='### Rocky Linux' START=1 KDCCONF='### kdc.conf and kadm5.acl'
        BASE_PKGS='words python3 strace openssl' MIT_PKGS='krb5-pkinit' ;;
    *) echo "DSB_STOP vm: deb13 or rocky10"; exit 2 ;;
esac
printf '%s\n' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "DSB_STOP sha"; exit 2; }

WT=$HAND_WT
REC=$HAND_REC/$SHA/ds-baselines/$VM
LAB=$WT/harness/field/lab.sh
HERE=$(dirname "$LAB")
DOCB=$HERE/lib/docblocks.py
DOCS=$WT/docs/install.md
SCAN=$HERE/lib/scan-secrets.py
SECRETS=$LAB_HOME/secrets
REALM=KERBER.TEST
FKDC=/var/kerberos/krb5kdc
RUST_PIN=a3a9e05199541b321aabc62a55bff60d38c7e38c
CO=kerber-rust-${RUST_PIN:0:12}
CARGO_ENV=". \"\$HOME/.cargo/env\""
REALM_VARS=(--session "REALM=$REALM" --session 'DOMAIN=kerber.test' --session 'KDC_HOST=kdc.kerber.test')
CAP_MIB=$((32 * 1024))
# shellcheck source=../field/baseline.env
. "$HERE/baseline.env"
FIELD_KDC_FAMILY=$FAM
case $FAM in
    deb)
        PKG_LIST="dpkg-query -W -f='\${Package}-\${Version}\n' 'krb5-*' 'libkrb5*' 'libkadm5*' 'libkdb5*' 2> /dev/null"
        PKG_LIST="$PKG_LIST | grep -v -- '-\$'" ;;
    *) PKG_LIST="rpm -qa 'krb5*' | LC_ALL=C sort" ;;
esac
# shellcheck source=../field/lib/family.sh
. "$HERE/lib/family.sh"
# kill-loop.py's stash_enctype: the enctype of a keytab-format stash's first entry, else 0.
PYMKT='import sys
b = sys.stdin.buffer.read(4096)
o = 8
if b[:2] == b"\x05\x02":
    for _ in range(int.from_bytes(b[6:8], "big") + 1):
        o += 2 + int.from_bytes(b[o:o + 2], "big")
    print(int.from_bytes(b[o + 9:o + 11], "big"))
else:
    print(0)'

ok=yes
booted=''
took=0
snapped=''

stop() { echo "DSB_STOP $*"; exit 2; }
vsh() {
    if command -v virsh > /dev/null 2>&1; then
        virsh -q -c qemu:///system "$@"
    else
        (cd "$HERE" && distrobox-host-exec virsh -q -c qemu:///system "$@")
    fi
}
domstate() { vsh domstate "kerber-$1" 2> /dev/null || echo missing; }
has_snap() { vsh snapshot-list "kerber-$1" --name 2> /dev/null | grep -qx "$2"; }
bad() { echo "DSB_FAIL:$*"; ok=no; }

# park: release a takeover this run made, and shut down what it booted; nothing else.
park() {
    local v rc
    if [ "$took" = 1 ]; then
        "$LAB" release > "$REC/release.out" 2>&1
        rc=$?
        echo "RELEASE_RC:$rc"
        if [ "$rc" = 0 ]; then took=0; else bad "release"; fi
    fi
    for v in $booted; do
        "$LAB" down "$v" > "$REC/down-$v.out" 2>&1
        echo "DOWN_RC:$v:$?"
    done
    booted=''
}
trap park EXIT

boot() {
    local v=$1 snap=$2 rc
    case " $booted " in *" $v "*) ;; *) booted="$booted $v" ;; esac
    "$LAB" reset "$v" "$snap" > "$REC/reset-$v-$snap.out" 2>&1
    rc=$?
    echo "RESET_RC:$v:$snap:$rc"
    [ "$rc" = 0 ] && wait_ntp "$v"
}
wait_ntp() {
    local i=0 val=''
    while [ "$i" -lt 90 ]; do
        val=$("$LAB" ssh "$1" -- 'timedatectl show -p NTPSynchronized --value' 2> /dev/null < /dev/null | head -n 1)
        [ "$val" = yes ] && { echo "NTP:$1:yes"; return 0; }
        sleep 2
        i=$((i + 1))
    done
    echo "NTP:$1:${val:-missing}"
    return 1
}
on() { "$LAB" ssh "$1" -- "$2" < /dev/null; }
# units <vm> <kdc unit> <admin unit>: both active within 60 s.
units() {
    local i=0
    while [ "$i" -lt 30 ]; do
        [ "$(on "$1" "systemctl is-active $2 $3 | paste -sd' ' -" 2> /dev/null)" = 'active active' ] && return 0
        sleep 2
        i=$((i + 1))
    done
    return 1
}

# doc <vm> <name> <heading> <n> [docblocks options]: block n of a docs/install.md section, run on the VM as the
# field harness runs it; every unit must exit 0.
doc() {
    local vm=$1 name=$2 rc bad_units
    shift 2
    if ! python3 -B "$DOCB" script "$DOCS" "$@" > "$REC/$PH/$name.sh" 2> "$REC/$PH/$name.err"; then
        bad "$PH:doc:$name:script"
        return 1
    fi
    if ! "$LAB" ssh "$vm" -- 'install -d -m 0700 ~/dsb && rm -f ~/dsb/block.sh && cat > ~/dsb/block.sh' \
        < "$REC/$PH/$name.sh" > "$REC/$PH/$name.upload" 2>&1; then
        bad "$PH:doc:$name:upload"
        return 1
    fi
    "$LAB" ssh "$vm" -- 'bash ~/dsb/block.sh' < /dev/null > "$REC/$PH/$name.out" 2>&1
    rc=$?
    python3 -B "$DOCB" results "$REC/$PH/$name.out" > "$REC/$PH/$name.results" 2>&1
    bad_units=$(awk -F'\t' '$2 != "0"' "$REC/$PH/$name.results" | head -n 3 | tr '\t\n' ' |')
    echo "DOC:$PH:$name:rc=$rc:units=$(wc -l < "$REC/$PH/$name.results")"
    if [ "$rc" != 0 ] || [ ! -s "$REC/$PH/$name.results" ] || [ -n "$bad_units" ]; then
        bad "$PH:doc:$name:${bad_units:-rc=$rc}"
        return 1
    fi
}

# realm <vm> <dir> <label>: listprincs (sorted), getprinc of alice and krbtgt, and the stash's enctype, from the
# KDC whose kdc.conf is in <dir>; the stash goes from the file to python3 on that VM only.
realm() {
    local vm=$1 dir=$2 label=$3 p
    on "$vm" "sudo kadmin.local -q listprincs 2>&1 | grep -v '^Authenticating as' | LC_ALL=C sort" \
        > "$REC/$PH/$label.listprincs"
    for p in alice "krbtgt/$REALM"; do
        on "$vm" "sudo kadmin.local -q 'getprinc $p' 2>&1 | grep -v '^Authenticating as'" \
            > "$REC/$PH/$label.getprinc.${p%%/*}"
    done
    on "$vm" "p=\$(sudo sed -n 's/^[[:space:]]*key_stash_file[[:space:]]*=[[:space:]]*//p' $dir/kdc.conf | head -n 1); \
        sudo cat \"\${p:-$dir/.k5.$REALM}\" | python3 -c '$PYMKT'" > "$REC/$PH/$label.mkt" 2>&1
    echo "REALM:$PH:$label:princs=$(wc -l < "$REC/$PH/$label.listprincs"):mkt=$(head -n 1 "$REC/$PH/$label.mkt")"
}
# real <label>: the side's realm read back, not an error: both principals listed and no kadmin.local error line,
# both getprinc outputs a principal's, the stash's enctype a number other than 0.
real() {
    local f=$REC/$PH/$1 bad_side=''
    grep -qx "alice@$REALM" "$f.listprincs" && grep -qx "krbtgt/$REALM@$REALM" "$f.listprincs" &&
        ! grep -q '^kadmin.local:' "$f.listprincs" || bad_side="listprincs"
    grep -q '^Principal: ' "$f.getprinc.alice" && grep -q '^Principal: ' "$f.getprinc.krbtgt" ||
        bad_side="$bad_side getprinc"
    grep -Eqx '[1-9][0-9]*' "$f.mkt" || bad_side="$bad_side mkt"
    if [ -n "$bad_side" ]; then bad "$PH:$1:not-a-realm:${bad_side# }"; else echo "REAL:$PH:$1"; fi
}
same() {
    if cmp -s "$REC/$PH/src.$1" "$REC/$PH/tgt.$1"; then
        echo "SAME:$PH:$1"
    else
        diff "$REC/$PH/src.$1" "$REC/$PH/tgt.$1" > "$REC/$PH/diff.$1"
        bad "$PH:differs:$1"
    fi
}

# move <src kdc snapshot>: the stash, then the dump, from kdc to the VM, by pipe only.
move() {
    local rcs
    on "$VM" "sudo systemctl stop $UNIT_KDC $UNIT_ADMIN 2> /dev/null; true" > /dev/null 2>&1
    "$LAB" ssh kdc -- "p=\$(sudo sed -n 's/^[[:space:]]*key_stash_file[[:space:]]*=[[:space:]]*//p' $FKDC/kdc.conf | \
        head -n 1); sudo cat \"\${p:-$FKDC/.k5.$REALM}\"" < /dev/null 2> "$REC/$PH/stash-src.err" |
        "$LAB" ssh "$VM" -- "p=\$(sudo sed -n 's/^[[:space:]]*key_stash_file[[:space:]]*=[[:space:]]*//p' \
        $KDCDIR/kdc.conf | head -n 1); p=\${p:-$KDCDIR/.k5.$REALM}; sudo install -m 0600 -o root -g root /dev/stdin \
        \"\$p\" && echo \"stash: \$p \$(sudo stat -c '%a %s' \"\$p\")\"" > "$REC/$PH/stash.out" 2>&1
    rcs="${PIPESTATUS[0]} ${PIPESTATUS[1]}"
    echo "STASH:$PH:rc=$rcs:$(head -n 1 "$REC/$PH/stash.out")"
    [ "$rcs" = '0 0' ] || { bad "$PH:stash:$rcs"; return 1; }
    "$LAB" ssh kdc -- 'sudo kdb5_util dump' < /dev/null 2> "$REC/$PH/dump.err" |
        "$LAB" ssh "$VM" -- 'sudo kdb5_util load /dev/stdin' > "$REC/$PH/load.out" 2>&1
    rcs="${PIPESTATUS[0]} ${PIPESTATUS[1]}"
    echo "LOAD:$PH:rc=$rcs"
    [ "$rcs" = '0 0' ] || { bad "$PH:load:$rcs"; return 1; }
    on "$VM" "sudo $RESTORECON -R $KDCDIR $KDCDATADIR" > "$REC/$PH/restorecon.out" 2>&1 || bad "$PH:restorecon"
}

# kinit_through <client2 snapshot> <alice's secret file>: kdc off, the VM takes over kdc.kerber.test, MIT's kinit
# on client2 (the password on stdin), then the release.
kinit_through() {
    "$LAB" down kdc > "$REC/$PH/down-kdc.out" 2>&1
    took=1
    "$LAB" takeover "$VM" > "$REC/$PH/takeover.out" 2>&1 || { bad "$PH:takeover"; return 1; }
    boot client2 "$1" || { bad "$PH:client2"; return 1; }
    "$LAB" ssh client2 -- "c=FILE:\$HOME/dsb.cc; kinit -c \"\$c\" alice@$REALM > /dev/null; echo \"kinit rc=\$?\";
        klist -c \"\$c\"; kdestroy -q -c \"\$c\"" < "$SECRETS/$2" > "$REC/$PH/kinit.out" 2>&1
    if "$LAB" release > "$REC/$PH/release.out" 2>&1; then took=0; else bad "$PH:release"; fi
    "$LAB" down client2 > "$REC/$PH/down-client2.out" 2>&1
    if grep -qx 'kinit rc=0' "$REC/$PH/kinit.out" && grep -qx "Default principal: alice@$REALM" "$REC/$PH/kinit.out" &&
        grep -q "krbtgt/$REALM@$REALM\$" "$REC/$PH/kinit.out"; then
        echo "KINIT:$PH:yes"
    else
        bad "$PH:kinit"
    fi
}

# The hostname kdc, as Fedora's kdc has (MIT logs gethostname(), logger.c:506-512), kept by cloud-init across
# boots; `hostname -f` gives kdc.kerber.test (Debian's 127.0.1.1 line, else the lab's DNS).
set_hostname() {
    on "$VM" "sudo hostnamectl set-hostname kdc && { [ ! -d /etc/cloud/cloud.cfg.d ] || echo \
        'preserve_hostname: true' | sudo tee /etc/cloud/cloud.cfg.d/99-ds-hostname.cfg > /dev/null; } && \
        { ! grep -q '^127\.0\.1\.1[[:space:]]' /etc/hosts || sudo sed -i \
        's/^127\.0\.1\.1[[:space:]].*/127.0.1.1 kdc.kerber.test kdc/' /etc/hosts; }" > "$REC/$PH/hostname.out" 2>&1 ||
        bad "$PH:set-hostname"
}
pkgs() {
    # shellcheck disable=SC2086 # the package lists split into words
    on "$VM" "sudo $PKG_INSTALL $*" > "$REC/$PH/pkgs.out" 2>&1 || bad "$PH:packages"
    versions "$*"
}
# versions <packages>: each one's version in the record, and the krb5 packages the VM has (L2).
versions() {
    on "$VM" "for p in $1; do sudo $PKG_QUERY \$p; done; $PKG_LIST" > "$REC/$PH/pkg-versions.out" 2>&1
    sed 's/^/PKG:'"$PH"':/' "$REC/$PH/pkg-versions.out"
}
# reboot_check <units: yes|no>: down, up, then the hostname and, if asked, both units.
reboot_check() {
    local h
    "$LAB" down "$VM" > "$REC/$PH/reboot-down.out" 2>&1
    "$LAB" up "$VM" > "$REC/$PH/reboot-up.out" 2>&1 || bad "$PH:reboot"
    wait_ntp "$VM" > /dev/null || bad "$PH:ntp-after-reboot"
    h=$(on "$VM" "echo \"\$(hostname) \$(hostname -f)\"" 2> /dev/null)
    echo "HOSTNAME:$PH:$h"
    [ "$h" = 'kdc kdc.kerber.test' ] || bad "$PH:hostname:$h"
    if [ "$1" = yes ]; then
        if units "$VM" "$UNIT_KDC" "$UNIT_ADMIN"; then echo "UNITS:$PH:active"; else bad "$PH:units-after-reboot"; fi
    fi
}
snap() {
    snapped=$PH
    if [ "$ok" != yes ]; then echo "SNAPSHOT:$PH:$1:not-taken"; return 1; fi
    has_snap "$VM" "$1" && { bad "$PH:exists:$1"; return 1; }
    on "$VM" 'rm -rf ~/dsb' > /dev/null 2>&1
    "$LAB" snapshot "$VM" "$1" > "$REC/$PH/snapshot.out" 2>&1 || { bad "$PH:snapshot"; return 1; }
    echo "SNAPSHOT:$PH:$1:taken"
    "$LAB" down "$VM" > /dev/null 2>&1
}

# The sources' realms, read on Fedora's kdc before each move.
source_realm() {
    boot kdc "$1" || { bad "$PH:kdc"; return 1; }
    units kdc krb5kdc kadmin || { bad "$PH:kdc-units"; return 1; }
    realm kdc "$FKDC" src
}

phase_base() {
    PH=base
    mkdir -p "$REC/$PH"
    boot "$VM" base || { bad "$PH:boot"; return; }
    set_hostname
    # shellcheck disable=SC2086
    pkgs $BASE_PKGS
    reboot_check no
    snap "ds-base-$VM"
}

phase_mit() {
    PH=mit
    mkdir -p "$REC/$PH"
    source_realm f4-mit-f44 || return
    boot "$VM" "mit-server-$VM" || { bad "$PH:boot"; return; }
    set_hostname
    # shellcheck disable=SC2086
    pkgs $BASE_PKGS $MIT_PKGS
    if [ "$FAM" = deb ]; then doc "$VM" krb5conf-deb "$DOC_KRB5CONF" 1 || return; fi
    doc "$VM" krb5conf '### krb5.conf' 1 "${REALM_VARS[@]}" || return
    doc "$VM" kdcconf "$KDCCONF" 1 "${REALM_VARS[@]}" || return
    move || return
    doc "$VM" start '### Start' "$START" || return
    units "$VM" "$UNIT_KDC" "$UNIT_ADMIN" || bad "$PH:units"
    realm "$VM" "$KDCDIR" tgt
    real src; real tgt
    same listprincs; same getprinc.alice; same getprinc.krbtgt; same mkt
    versions "$MIT_SERVER_PKGS $MIT_CLIENT_PKG"
    kinit_through "$MIT_SNAPSHOT_CLIENT2" "$MIT_SECRET_ALICE"
    reboot_check yes
    snap "mit-oracle-$VM"
}

phase_rust() {
    local rcs
    PH=rust
    mkdir -p "$REC/$PH"
    source_realm rust-field-p12-f44 || return
    boot "$VM" "mit-server-$VM" || { bad "$PH:boot"; return; }
    set_hostname
    # shellcheck disable=SC2086
    pkgs $BASE_PKGS
    DOCS=$REC/$PH/install.md
    GIT_OPTIONAL_LOCKS=0 git -C "$WT" show "$RUST_PIN:docs/install.md" > "$DOCS" || { bad "$PH:pin-docs"; return; }
    echo "PIN:$PH:$RUST_PIN"
    GIT_OPTIONAL_LOCKS=0 git -C "$WT" archive --format=tar --prefix="$CO/" "$RUST_PIN" |
        "$LAB" ssh "$VM" -- "rm -rf ~/$CO && tar -x -C ~ && find ~/$CO -type f | wc -l" > "$REC/$PH/tree.out" 2>&1
    rcs="${PIPESTATUS[0]} ${PIPESTATUS[1]}"
    echo "TREE:$PH:rc=$rcs:files=$(head -n 1 "$REC/$PH/tree.out")"
    [ "$rcs" = '0 0' ] || { bad "$PH:tree:$rcs"; return; }
    doc "$VM" prereq "$PREREQ" 1 || return
    doc "$VM" build '## Build' 1 --drop '^git clone ' --drop '^cd kerber-rust$' --session "$CARGO_ENV" \
        --session "cd ~/$CO" || return
    doc "$VM" replace "$DOC_REPLACE" 1 --session "$CARGO_ENV" --session "cd ~/$CO" || return
    if [ "$FAM" = deb ]; then doc "$VM" krb5conf-deb "$DOC_KRB5CONF" 1 || return; fi
    doc "$VM" krb5conf '### krb5.conf' 1 "${REALM_VARS[@]}" || return
    doc "$VM" kdcconf "$KDCCONF" 1 "${REALM_VARS[@]}" || return
    "$LAB" ssh "$VM" -- "sh -s -- ~/$CO" < "$HERE/lib/install-check.sh" > "$REC/$PH/install-check.out" 2>&1 ||
        bad "$PH:install-check"
    move || return
    doc "$VM" start '### Start' "$START" || return
    units "$VM" "$UNIT_KDC" "$UNIT_ADMIN" || bad "$PH:units"
    on "$VM" 'sudo sha256sum -c --quiet /usr/share/kerber-rust/install-manifest && echo manifest: ok' \
        > "$REC/$PH/manifest.out" 2>&1 || bad "$PH:manifest"
    realm "$VM" "$KDCDIR" tgt
    real src; real tgt
    same listprincs; same getprinc.alice; same getprinc.krbtgt; same mkt
    versions "$MIT_CLIENT_PKG"
    kinit_through "$RUST_SNAPSHOT_CLIENT2" "$RUST_SECRET_ALICE"
    reboot_check yes
    snap "rust-base-$VM"
}

# Before anything changes: the checkout, the VMs and snapshots, the names to make, and the RAM.
[ "$(git -C "$WT" rev-parse HEAD 2> /dev/null)" = "$SHA" ] || stop "HAND_WT is not at $SHA"
mkdir -p "$REC" && chmod 700 "$REC"
for need in "kdc f4-mit-f44" "kdc rust-field-p12-f44" "$VM base" "$VM mit-server-$VM" \
    "client2 $MIT_SNAPSHOT_CLIENT2" "client2 $RUST_SNAPSHOT_CLIENT2"; do
    read -r nvm nsnap <<< "$need"
    [ "$(domstate "$nvm")" != missing ] || stop "no VM $nvm"
    has_snap "$nvm" "$nsnap" || stop "no snapshot $nsnap on $nvm"
done
case ${TMPDIR:-} in '' | /tmp | /tmp/*) stop "TMPDIR is unset or under /tmp" ;; esac
[ ! -e "$LAB_HOME/state/takeover" ] || stop "a takeover is held ($(cat "$LAB_HOME/state/takeover"))"
for v in kdc "$VM" client2; do
    [ "$(domstate "$v")" = 'shut off' ] || stop "$v is not shut off ($(domstate "$v")): the lab is in use"
done
IFS=, read -r -a PH_LIST <<< "$PHASES"
[ "$(printf '%s\n' "${PH_LIST[@]}" | sort | uniq -d)" = '' ] || stop "a phase named twice: $PHASES"
for p in "${PH_LIST[@]}"; do
    case $p in
        mit) [ -r "$SECRETS/$MIT_SECRET_ALICE" ] || stop "no readable secret file for MIT_SECRET_ALICE" ;;
        rust) [ -r "$SECRETS/$RUST_SECRET_ALICE" ] || stop "no readable secret file for RUST_SECRET_ALICE" ;;
    esac
    case $p in
        base) has_snap "$VM" "ds-base-$VM" && stop "ds-base-$VM exists" ;;
        mit) has_snap "$VM" "mit-oracle-$VM" && stop "mit-oracle-$VM exists" ;;
        rust) has_snap "$VM" "rust-base-$VM" && stop "rust-base-$VM exists" ;;
        *) stop "phase $p" ;;
    esac
done
sum=0
for name in kdc client2 "$VM" klldap; do
    st=$(domstate "$name")
    [ "$name" = klldap ] && [ "$st" != running ] && continue
    kb=$(vsh dominfo "kerber-$name" | awk '/Max memory:/ { print $3 }')
    case $kb in '' | *[!0-9]*) stop "no memory for $name" ;; esac
    sum=$((sum + kb / 1024))
done
echo "RAM_SUM_MIB $sum CAP_MIB $CAP_MIB"
[ "$sum" -le "$CAP_MIB" ] || stop "ram $sum"
echo "DSB_VM:$VM:$FAM DSB_SHA:$SHA DSB_PHASES:$PHASES"

for p in "${PH_LIST[@]}"; do
    snapped=''
    "phase_$p"
    [ "$snapped" = "$p" ] || echo "SNAPSHOT:$p:not-taken"
    [ "$ok" = yes ] || break
done
park
trap - EXIT
if [ -e "$LAB_HOME/state/takeover" ]; then bad "takeover-left:$(cat "$LAB_HOME/state/takeover")"; fi
python3 -B "$SCAN" "$REC" > "$REC/scan.out" 2>&1
src=$?
echo "SECRET_SCAN:$src"
[ "$src" = 0 ] || ok=no
echo "DSB_PASS:$ok"
echo "DSB_DONE"
