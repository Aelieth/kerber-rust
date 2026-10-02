#!/usr/bin/env bash
# harness/field/lab.sh: the kerber-rust KVM field lab (section F0).
#
# Builds, runs and resets five VMs on libvirt qemu:///system: kdc, services,
# client1 (Fedora Kinoite 43), client2 and klldap (the Docker host for
# KLLDAP). They sit on the NAT network kerber-lab (192.168.177.0/24, DNS
# domain kerber.test). kdc also has a LAN NIC (macvtap) so the AD test DC can
# reach it. See harness/field/README.md.
#
# Runs on the host, or in a distrobox where virsh is not on PATH. In that
# case every host command (virsh, virt-install, xorriso, ip) goes through
# distrobox-host-exec. Images, the SSH key, the console password and
# rendered seeds live in $KERBER_LAB_HOME (default ~/kerber-lab, mode 0700).
# They never enter git.
#
# Commands:
#   up [vm...]              define and start the network, the pool and the VMs.
#                           A missing VM is built, provisioned and given snapshot
#                           'base'. Idempotent.
#   down [vm...]            shut VMs down (the network stays up)
#   destroy --yes           remove the lab VMs, their volumes, the pool and the
#                           network (only kerber-lab objects; images stay)
#   rebuild <vm> --yes      remove one VM with its disks and snapshots, then
#                           build it again from the templates (as up does)
#   reset <vm|all> [snap]   revert to snapshot 'base' (or snap) and boot
#   snapshot <vm> <name>    offline snapshot: shut down, snapshot, start again
#   ssh <vm> [--] [cmd...]  ssh to the VM as 'lab' with the lab key
#   ip <vm> [lan]           print the VM's lab address, or kdc's LAN address
#   status                  network, pool, VMs, addresses, snapshots
#   check [vm...]           ssh, DNS + reverse DNS, time sync, internet; kdc's LAN
#                           NIC, its inbound filter, routes and the AD DC's port 88;
#                           client1's SDDM
#   collect <vm> <dir> [file...]
#                           copy journald (last $COLLECT_MINUTES minutes, default
#                           60) and the listed files into <dir>/<vm>/
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_HOME="${KERBER_LAB_HOME:-$HOME/kerber-lab}"
URI=qemu:///system
NET=kerber-lab
POOL=kerber-lab
POOL_DIR=/var/lib/libvirt/images/kerber-lab
DNS_DOMAIN=kerber.test
SSH_KEY="$LAB_HOME/ssh/lab_ed25519"
KNOWN_HOSTS="$LAB_HOME/ssh/known_hosts"
PASSWD_FILE="$LAB_HOME/secrets/lab-console-password"
AD_DC=10.10.38.38

# Fedora 43 media, checked against Fedora's signed CHECKSUM files.
REL=43-1.6
MIRROR=https://download.fedoraproject.org/pub/fedora/linux/releases/43
CLOUD_IMG=Fedora-Cloud-Base-Generic-$REL.x86_64.qcow2
CLOUD_SUMS=Fedora-Cloud-$REL-x86_64-CHECKSUM
KINOITE_ISO=Fedora-Kinoite-ostree-x86_64-$REL.iso
KINOITE_SUMS=Fedora-Kinoite-$REL-x86_64-CHECKSUM
KINOITE_LABEL=Fedora-Knt-ostree-x86_64-43
FEDORA_KEY=/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-43-primary
FEDORA_KEY_FPR=C6E7F081CF80E13146676E88829B606631645531
BASE_VOL=fedora-43-cloud-base-1.6.qcow2
ISO_VOL=fedora-kinoite-43-1.6.iso

# The VM table. The MACs must match network-kerber-lab.xml.
ALL_VMS=(kdc services client1 client2 klldap)
declare -A KIND=([kdc]=cloud [services]=cloud [client1]=kinoite [client2]=cloud [klldap]=cloud)
declare -A CPUS=([kdc]=2 [services]=4 [client1]=4 [client2]=2 [klldap]=2)
declare -A MEM=([kdc]=2048 [services]=6144 [client1]=6144 [client2]=3072 [klldap]=3072)
declare -A DISK=([kdc]=20 [services]=40 [client1]=40 [client2]=20 [klldap]=30)
declare -A IP=([kdc]=192.168.177.10 [services]=192.168.177.11 [client1]=192.168.177.21
               [client2]=192.168.177.22 [klldap]=192.168.177.30)
declare -A MAC=([kdc]=52:54:00:4b:52:0a [services]=52:54:00:4b:52:0b
                [client1]=52:54:00:4b:52:15 [client2]=52:54:00:4b:52:16
                [klldap]=52:54:00:4b:52:1e)
KDC_LAN_MAC=52:54:00:4b:4c:0a

say()  { printf '[lab] %s\n' "$*"; }
warn() { printf '[lab] WARN: %s\n' "$*" >&2; }
die()  { printf '[lab] ERROR: %s\n' "$*" >&2; exit 1; }

# Host commands: direct on the host, through distrobox-host-exec in a distrobox.
if command -v virsh >/dev/null 2>&1; then
    hx() { "$@"; }
elif command -v distrobox-host-exec >/dev/null 2>&1; then
    hx() { distrobox-host-exec "$@"; }
else
    die "virsh is not on PATH and distrobox-host-exec is missing"
fi
vsh() { hx virsh -q -c "$URI" "$@"; }
# xo <args...>: xorriso on the host; its banner is shown only when it fails.
xo() {
    local out
    out=$(hx xorriso "$@" 2>&1) || { printf '%s\n' "$out" >&2; die "xorriso $1 failed"; }
}

dom() { printf 'kerber-%s' "$1"; }
known_vm() { [ -n "${KIND[$1]:-}" ] || die "unknown VM '$1' (one of: ${ALL_VMS[*]})"; }
dom_exists() { vsh dominfo "$(dom "$1")" >/dev/null 2>&1; }
dom_state() { vsh domstate "$(dom "$1")" 2>/dev/null || echo absent; }
vol_exists() { vsh vol-info --pool "$POOL" "$1" >/dev/null 2>&1; }
has_snapshot() { vsh snapshot-info "$(dom "$1")" --snapshotname "$2" >/dev/null 2>&1; }
# in_install <vm>: the domain still boots the installer kernel (client1 before its first boot).
in_install() { [ "$(vsh dumpxml --inactive "$(dom "$1")" | awk '/<kernel>/ { n++ } END { print n + 0 }')" -gt 0 ]; }

# select_vms <args...>: SEL = the named VMs, or every VM when none (or 'all') is named.
SEL=()
select_vms() {
    SEL=()
    if [ $# -eq 0 ] || [ "$1" = all ]; then
        SEL=("${ALL_VMS[@]}")
        return 0
    fi
    local vm
    for vm in "$@"; do
        known_vm "$vm"
        SEL+=("$vm")
    done
}

# wait_until <timeout-s> <what> <command...>: poll every 5 s.
wait_until() {
    local timeout=$1 what=$2 t=0
    shift 2
    until "$@" >/dev/null 2>&1; do
        [ "$t" -ge "$timeout" ] && { warn "timed out after ${timeout}s waiting for $what"; return 1; }
        sleep 5
        t=$((t + 5))
    done
}
is_state() { [ "$(dom_state "$1")" = "$2" ]; }

# ---------------------------------------------------------------- ssh

ssh_args() {
    local vm=$1
    printf '%s\n' -i "$SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes \
        -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new \
        -o HostKeyAlias="$vm.$DNS_DOMAIN" -o ConnectTimeout=5 -o LogLevel=ERROR \
        -o ServerAliveInterval=15
}
lssh() {
    local vm=$1
    shift
    local args
    mapfile -t args < <(ssh_args "$vm")
    # shellcheck disable=SC2029  # callers pass a remote command line on purpose
    ssh "${args[@]}" "lab@${IP[$vm]}" "$@"
}
forget_host_key() {
    if [ -f "$KNOWN_HOSTS" ]; then
        ssh-keygen -q -R "$1.$DNS_DOMAIN" -f "$KNOWN_HOSTS" >/dev/null 2>&1 || true
    fi
    rm -f "$KNOWN_HOSTS.old"
}
wait_ssh() { wait_until "${2:-600}" "ssh to $1" lssh "$1" true; }

# ---------------------------------------------------------------- lab objects

ensure_lab_home() {
    (
        umask 077
        mkdir -p "$LAB_HOME"/{images,ssh,seeds,state,secrets}
        chmod 0700 "$LAB_HOME"
        [ -f "$SSH_KEY" ] || ssh-keygen -q -t ed25519 -N '' -C kerber-lab -f "$SSH_KEY"
        if [ ! -f "$PASSWD_FILE" ]; then
            openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-20 > "$PASSWD_FILE"
        fi
        [ -f "$PASSWD_FILE.sha512" ] || openssl passwd -6 -stdin < "$PASSWD_FILE" > "$PASSWD_FILE.sha512"
    )
}

ensure_net() {
    if ! vsh net-info "$NET" >/dev/null 2>&1; then
        say "defining network $NET"
        vsh net-define "$HERE/network-kerber-lab.xml" >/dev/null
    fi
    vsh net-autostart "$NET" >/dev/null
    # (No 'grep -q' in pipelines: with pipefail its early exit fails the pipe.)
    if [ "$(vsh net-info "$NET" | awk '$1 == "Active:" { print $2 }')" != yes ]; then
        vsh net-start "$NET" >/dev/null
    fi
}

ensure_pool() {
    if ! vsh pool-info "$POOL" >/dev/null 2>&1; then
        say "defining storage pool $POOL at $POOL_DIR"
        vsh pool-define-as "$POOL" dir --target "$POOL_DIR" >/dev/null
        vsh pool-build "$POOL" >/dev/null
    fi
    vsh pool-autostart "$POOL" >/dev/null
    if [ "$(vsh pool-info "$POOL" | awk '$1 == "State:" { print $2 }')" != running ]; then
        vsh pool-start "$POOL" >/dev/null 2>&1 || { vsh pool-build "$POOL" >/dev/null; vsh pool-start "$POOL" >/dev/null; }
    fi
}

# fetch_verified <mirror-dir-url> <file> <sums-file>: download into
# $LAB_HOME/images when missing, check the signature on the sums file and the
# file's SHA-256.
fetch_verified() {
    local url=$1 file=$2 sums=$3 dir="$LAB_HOME/images"
    [ -r "$FEDORA_KEY" ] || die "missing $FEDORA_KEY (package fedora-gpg-keys)"
    [ -f "$dir/$sums" ] || curl -fsSL --retry 5 -o "$dir/$sums" "$url/$sums"
    local keyring="$LAB_HOME/state/fedora-43-primary.gpg"
    gpg --batch --dearmor < "$FEDORA_KEY" > "$keyring"
    local status
    status=$(gpgv --status-fd 1 --keyring "$keyring" "$dir/$sums" 2>/dev/null) || true
    case $status in
        *"VALIDSIG "*"$FEDORA_KEY_FPR"*) ;;
        *) die "$sums: no valid signature by the Fedora 43 key $FEDORA_KEY_FPR" ;;
    esac
    if [ ! -f "$dir/$file" ]; then
        say "downloading $file"
        curl -fSL --retry 5 -C - -o "$dir/$file.part" "$url/$file"
        mv "$dir/$file.part" "$dir/$file"
    fi
    local want have
    want=$(awk -v f="($file)" '$1 == "SHA256" && $2 == f { print $4 }' "$dir/$sums")
    [ -n "$want" ] || die "$file is not listed in $sums"
    have=$(sha256sum "$dir/$file" | cut -d' ' -f1)
    [ "$want" = "$have" ] || die "$file: sha256 $have does not match $sums ($want)"
    say "verified $file (sha256 $want, signed by $FEDORA_KEY_FPR)"
}

# upload_vol <local-file> <volume> <format>: (re)create a pool volume from a file.
upload_vol() {
    local src=$1 vol=$2 fmt=$3
    if vol_exists "$vol"; then vsh vol-delete --pool "$POOL" "$vol" >/dev/null; fi
    vsh vol-create-as "$POOL" "$vol" "$(stat -c %s "$src")" --format "$fmt" >/dev/null
    vsh vol-upload --pool "$POOL" "$vol" "$src"
    vsh pool-refresh "$POOL" >/dev/null
}

ensure_base_vol() {
    vol_exists "$BASE_VOL" && return 0
    fetch_verified "$MIRROR/Cloud/x86_64/images" "$CLOUD_IMG" "$CLOUD_SUMS"
    say "uploading $CLOUD_IMG to pool volume $BASE_VOL"
    upload_vol "$LAB_HOME/images/$CLOUD_IMG" "$BASE_VOL" qcow2
}

ensure_iso_vol() {
    vol_exists "$ISO_VOL" && return 0
    fetch_verified "$MIRROR/Kinoite/x86_64/iso" "$KINOITE_ISO" "$KINOITE_SUMS"
    say "uploading $KINOITE_ISO to pool volume $ISO_VOL"
    upload_vol "$LAB_HOME/images/$KINOITE_ISO" "$ISO_VOL" raw
}

# The host NIC for kdc's macvtap: $KERBER_LAB_LAN_IF, else the wired
# interface of the lowest-metric default route.
lan_if() {
    local ifc=${KERBER_LAB_LAN_IF:-} d cands
    if [ -z "$ifc" ]; then
        mapfile -t cands < <(hx ip -o route show default | awk '{
                m = 0; d = "";
                for (i = 1; i < NF; i++) { if ($i == "dev") d = $(i+1); if ($i == "metric") m = $(i+1) }
                print m, d }' | sort -n | awk '{ print $2 }')
        for d in "${cands[@]}"; do
            if ! hx test -d "/sys/class/net/$d/wireless"; then ifc=$d; break; fi
        done
    fi
    [ -n "$ifc" ] || die "no wired default-route interface for kdc's LAN NIC; set KERBER_LAB_LAN_IF"
    if hx test -d "/sys/class/net/$ifc/wireless"; then
        die "$ifc is wireless; macvtap needs a wired NIC (set KERBER_LAB_LAN_IF)"
    fi
    printf '%s\n' "$ifc"
}

# render <template> <out> <vm>: fill in the placeholders; the result stays in $LAB_HOME.
render() {
    local tpl=$1 out=$2 vm=$3 pub hash
    pub=$(cat "$SSH_KEY.pub")
    hash=$(cat "$PASSWD_FILE.sha512")
    (
        umask 077
        sed -e "s|@SSH_PUBKEY@|$pub|g" -e "s|@LAB_PASSWD_HASH@|$hash|g" \
            -e "s|@LAN_MAC@|$KDC_LAN_MAC|g" -e "s|@LAB_MAC@|${MAC[$vm]}|g" "$tpl" > "$out"
    )
    if grep -Eq '@[A-Z_]+@' "$out"; then die "unfilled placeholder in $out"; fi
}

# ---------------------------------------------------------------- building VMs

# Cloud VMs: a qcow2 overlay on the Fedora Cloud base plus a NoCloud seed ISO.
create_cloud() {
    local vm=$1 d s
    d=$(dom "$vm")
    s="$LAB_HOME/seeds/$vm"
    ensure_base_vol
    (umask 077; mkdir -p "$s")
    render "$HERE/cloud-init/$vm.user-data" "$s/user-data" "$vm"
    local nc=single
    [ "$vm" = kdc ] && nc=kdc
    render "$HERE/cloud-init/network-config.$nc" "$s/network-config" "$vm"
    printf 'instance-id: kerber-%s-%s\nlocal-hostname: %s.%s\n' \
        "$vm" "$(date -u +%Y%m%dT%H%M%SZ)" "$vm" "$DNS_DOMAIN" > "$s/meta-data"
    rm -f "$s/seed.iso"
    xo -as mkisofs -output "$s/seed.iso" -volid cidata -joliet -rock \
        "$s/user-data" "$s/meta-data" "$s/network-config"
    upload_vol "$s/seed.iso" "$d-seed.iso" raw
    # The domain does not exist, so any disk left behind is stale: start clean.
    if vol_exists "$d.qcow2"; then vsh vol-delete --pool "$POOL" "$d.qcow2" >/dev/null; fi
    vsh vol-create-as "$POOL" "$d.qcow2" "${DISK[$vm]}G" --format qcow2 \
        --backing-vol "$BASE_VOL" --backing-vol-format qcow2 >/dev/null
    local nets=(--network "network=$NET,mac=${MAC[$vm]},model=virtio") lif
    if [ "$vm" = kdc ]; then
        lif=$(lan_if)
        nets+=(--network "type=direct,source=$lif,source_mode=bridge,mac=$KDC_LAN_MAC,model=virtio")
    fi
    forget_host_key "$vm"
    say "creating $d (${CPUS[$vm]} vCPU, ${MEM[$vm]} MiB, ${DISK[$vm]} GiB, Fedora 43 Cloud)"
    hx virt-install --connect "$URI" --name "$d" --osinfo fedora43 \
        --metadata "description=kerber-rust field lab: $vm.$DNS_DOMAIN (harness/field)" \
        --vcpus "${CPUS[$vm]}" --memory "${MEM[$vm]}" --cpu host-passthrough \
        --disk "vol=$POOL/$d.qcow2,bus=virtio,discard=unmap" \
        --disk "vol=$POOL/$d-seed.iso,device=cdrom" \
        "${nets[@]}" \
        --graphics none --console pty,target_type=serial --rng /dev/urandom \
        --import --noautoconsole >/dev/null
}

finish_cloud() {
    local vm=$1
    is_state "$vm" running || vsh start "$(dom "$vm")" >/dev/null
    wait_ssh "$vm" 900 || die "$vm: no ssh"
    say "$vm: waiting for cloud-init (package upgrade included)"
    local rc=0
    lssh "$vm" sudo cloud-init status --wait >/dev/null 2>&1 || rc=$?
    case $rc in
        0) say "$vm: cloud-init done" ;;
        2) warn "$vm: cloud-init finished with recoverable errors:"
           lssh "$vm" sudo cloud-init status --long >&2 || true ;;
        *) lssh "$vm" sudo cloud-init status --long >&2 || true
           die "$vm: cloud-init failed (exit $rc)" ;;
    esac
}

# client1: Fedora Kinoite 43 from the ISO. The installer kernel boots
# directly with the kickstart on an OEMDRV-labelled ISO, and the kickstart
# powers off at the end. Then the install media are removed and the VM boots
# from disk.
create_kinoite() {
    local vm=client1 d s
    d=$(dom "$vm")
    s="$LAB_HOME/seeds/$vm"
    ensure_iso_vol
    (umask 077; mkdir -p "$s")
    rm -f "$s/vmlinuz" "$s/initrd.img" "$s/ks.iso"
    xo -osirrox on -indev "$LAB_HOME/images/$KINOITE_ISO" \
        -extract /images/pxeboot/vmlinuz "$s/vmlinuz" \
        -extract /images/pxeboot/initrd.img "$s/initrd.img"
    upload_vol "$s/vmlinuz" "$d-install-vmlinuz" raw
    upload_vol "$s/initrd.img" "$d-install-initrd.img" raw
    render "$HERE/kickstart/client1-kinoite.ks" "$s/ks.cfg" "$vm"
    xo -as mkisofs -output "$s/ks.iso" -volid OEMDRV -joliet -rock "$s/ks.cfg"
    upload_vol "$s/ks.iso" "$d-ks.iso" raw
    if vol_exists "$d.qcow2"; then vsh vol-delete --pool "$POOL" "$d.qcow2" >/dev/null; fi
    vsh vol-create-as "$POOL" "$d.qcow2" "${DISK[$vm]}G" --format qcow2 >/dev/null
    forget_host_key "$vm"
    local kargs="inst.stage2=hd:LABEL=$KINOITE_LABEL inst.ks=hd:LABEL=OEMDRV:/ks.cfg inst.text"
    kargs="$kargs console=ttyS0,115200 console=tty0"
    say "creating $d (${CPUS[$vm]} vCPU, ${MEM[$vm]} MiB, ${DISK[$vm]} GiB, Fedora Kinoite 43): installing"
    hx virt-install --connect "$URI" --name "$d" --osinfo fedora43 \
        --metadata "description=kerber-rust field lab: $vm.$DNS_DOMAIN - Fedora Kinoite 43 (harness/field)" \
        --vcpus "${CPUS[$vm]}" --memory "${MEM[$vm]}" --cpu host-passthrough \
        --disk "vol=$POOL/$d.qcow2,bus=virtio,discard=unmap" \
        --disk "vol=$POOL/$ISO_VOL,device=cdrom" \
        --disk "vol=$POOL/$d-ks.iso,device=cdrom" \
        --network "network=$NET,mac=${MAC[$vm]},model=virtio" \
        --graphics spice --video virtio --rng /dev/urandom \
        --boot "hd,kernel=$POOL_DIR/$d-install-vmlinuz,initrd=$POOL_DIR/$d-install-initrd.img,kernel_args=\"$kargs\"" \
        --noautoconsole >/dev/null
}

finish_kinoite() {
    local vm=client1 d x
    d=$(dom "$vm")
    if in_install "$vm"; then
        if is_state "$vm" "shut off"; then
            # Never restart an install that ended while nobody watched: check it.
            warn "$vm: found the installer shut off; checking the disk boots"
        else
            say "$vm: waiting for the Kinoite install to power off (up to 90 min)"
            wait_until 5400 "$vm install" is_state "$vm" "shut off" || die "$vm: install did not finish"
        fi
        # Boot from disk from now on: drop the installer kernel, eject the media.
        x="$LAB_HOME/state/$d.xml"
        vsh dumpxml --inactive "$d" | sed -e '/<kernel>/d' -e '/<initrd>/d' -e '/<cmdline>/d' > "$x"
        vsh define "$x" >/dev/null
        local tgt
        for tgt in $(vsh domblklist "$d" --details | awk '$2 == "cdrom" && $4 != "-" { print $3 }'); do
            vsh change-media "$d" "$tgt" --eject --config >/dev/null
        done
        local vol
        for vol in "$d-install-vmlinuz" "$d-install-initrd.img" "$d-ks.iso"; do
            if vol_exists "$vol"; then vsh vol-delete --pool "$POOL" "$vol" >/dev/null; fi
        done
    fi
    is_state "$vm" running || vsh start "$d" >/dev/null
    wait_ssh "$vm" 900 || die "$vm: no ssh after install"
    say "$vm: installed and reachable over ssh"
    # Bring the deployment up to date, as the fleet's machines are, so the kit's
    # rpm-ostree layering resolves against the current repos. With
    # KERBER_LAB_KINOITE_UPGRADE=0 the ISO's own deployment stays.
    if [ "${KERBER_LAB_KINOITE_UPGRADE:-1}" = 1 ]; then
        say "$vm: rpm-ostree upgrade"
        if lssh "$vm" sudo rpm-ostree upgrade; then
            shutdown_vm "$vm"
            vsh start "$d" >/dev/null
            wait_ssh "$vm" 900 || die "$vm: no ssh after the upgrade"
        else
            warn "$vm: rpm-ostree upgrade failed; keeping the ISO's deployment"
        fi
    fi
    lssh "$vm" rpm-ostree status
}

# snapshot_offline <vm> <name>: a disk-only internal snapshot of the shut-off
# VM. A revert is then a cold boot with a fresh clock (Kerberos needs one).
snapshot_offline() {
    local vm=$1 name=$2 d was
    d=$(dom "$vm")
    was=$(dom_state "$vm")
    if vsh snapshot-info "$d" --snapshotname "$name" >/dev/null 2>&1; then
        die "$vm already has snapshot '$name' (virsh -c $URI snapshot-delete $d $name)"
    fi
    if [ "$was" != "shut off" ]; then shutdown_vm "$vm"; fi
    vsh snapshot-create-as "$d" --name "$name" \
        --description "kerber-lab $vm: $name ($(date -u +%FT%TZ))" --atomic >/dev/null
    say "$vm: snapshot '$name' taken"
    if [ "$was" = running ]; then vsh start "$d" >/dev/null; fi
}

shutdown_vm() {
    local vm=$1 d
    d=$(dom "$vm")
    is_state "$vm" running || return 0
    vsh shutdown "$d" >/dev/null 2>&1 || true
    if ! wait_until 300 "$vm to shut down" is_state "$vm" "shut off"; then
        warn "$vm: forcing power off"
        vsh destroy "$d" >/dev/null
    fi
}

# ---------------------------------------------------------------- commands

cmd_up() {
    local vms vm new_cloud=() new_kinoite=()
    select_vms "$@"
    vms=("${SEL[@]}")
    ensure_lab_home
    ensure_net
    ensure_pool
    for vm in "${vms[@]}"; do
        if ! dom_exists "$vm"; then
            if [ "${KIND[$vm]}" = kinoite ]; then create_kinoite; else create_cloud "$vm"; fi
        elif has_snapshot "$vm" base; then
            if ! is_state "$vm" running; then
                say "starting $(dom "$vm")"
                vsh start "$(dom "$vm")" >/dev/null
            fi
            continue
        else
            say "$vm exists without snapshot 'base': finishing its build"
        fi
        if [ "${KIND[$vm]}" = kinoite ]; then new_kinoite+=("$vm"); else new_cloud+=("$vm"); fi
    done
    # The cloud VMs provision while the Kinoite install runs; finish them first.
    for vm in "${new_cloud[@]}"; do
        finish_cloud "$vm"
        snapshot_offline "$vm" base
    done
    for vm in "${new_kinoite[@]}"; do
        finish_kinoite
        snapshot_offline "$vm" base
    done
    for vm in "${vms[@]}"; do
        wait_ssh "$vm" 600 || die "$vm: no ssh"
    done
    cmd_status
}

cmd_down() {
    local vms vm
    select_vms "$@"
    vms=("${SEL[@]}")
    for vm in "${vms[@]}"; do
        dom_exists "$vm" || continue
        if is_state "$vm" running; then vsh shutdown "$(dom "$vm")" >/dev/null 2>&1 || true; fi
    done
    for vm in "${vms[@]}"; do
        dom_exists "$vm" || continue
        shutdown_vm "$vm"
        say "$vm: $(dom_state "$vm")"
    done
}

cmd_destroy() {
    [ "${1:-}" = --yes ] || die "destroy removes every lab VM, volume, the pool and the network; run: lab.sh destroy --yes"
    local vm d vol
    for vm in "${ALL_VMS[@]}"; do
        d=$(dom "$vm")
        dom_exists "$vm" || continue
        if is_state "$vm" running; then vsh destroy "$d" >/dev/null; fi
        vsh undefine "$d" --snapshots-metadata >/dev/null
        forget_host_key "$vm"
        say "removed VM $d"
    done
    if vsh pool-info "$POOL" >/dev/null 2>&1; then
        vsh pool-start "$POOL" >/dev/null 2>&1 || true
        for vol in $(vsh vol-list --pool "$POOL" | awk 'NF { print $1 }'); do
            vsh vol-delete --pool "$POOL" "$vol" >/dev/null
            say "removed volume $vol"
        done
        vsh pool-destroy "$POOL" >/dev/null 2>&1 || true
        vsh pool-delete "$POOL" >/dev/null 2>&1 || true
        vsh pool-undefine "$POOL" >/dev/null
        say "removed pool $POOL"
    fi
    if vsh net-info "$NET" >/dev/null 2>&1; then
        vsh net-destroy "$NET" >/dev/null 2>&1 || true
        vsh net-undefine "$NET" >/dev/null
        say "removed network $NET"
    fi
    if [ -d "$LAB_HOME/seeds" ]; then chmod -R u+w "$LAB_HOME/seeds"; rm -rf "$LAB_HOME/seeds"; fi
    say "kept $LAB_HOME/images, ssh and secrets"
}

cmd_rebuild() {
    if [ $# -ne 2 ] || [ "$2" != --yes ]; then
        die "usage: lab.sh rebuild <vm> --yes (removes the VM, its disks and snapshots, then builds it again)"
    fi
    known_vm "$1"
    local vm=$1 d vol
    d=$(dom "$vm")
    if dom_exists "$vm"; then
        if ! is_state "$vm" "shut off"; then vsh destroy "$d" >/dev/null; fi
        vsh undefine "$d" --snapshots-metadata >/dev/null
        say "removed VM $d"
    fi
    if vsh pool-info "$POOL" >/dev/null 2>&1; then
        for vol in "$d.qcow2" "$d-seed.iso" "$d-ks.iso" "$d-install-vmlinuz" "$d-install-initrd.img"; do
            if vol_exists "$vol"; then
                vsh vol-delete --pool "$POOL" "$vol" >/dev/null
                say "removed volume $vol"
            fi
        done
    fi
    forget_host_key "$vm"
    cmd_up "$vm"
}

cmd_reset() {
    [ $# -ge 1 ] || die "usage: lab.sh reset <vm|all> [snapshot]"
    local snap=${2:-base} vms vm d
    select_vms "$1"
    vms=("${SEL[@]}")
    for vm in "${vms[@]}"; do
        d=$(dom "$vm")
        dom_exists "$vm" || die "$vm does not exist (lab.sh up)"
        if ! is_state "$vm" "shut off"; then vsh destroy "$d" >/dev/null 2>&1 || true; fi
        vsh snapshot-revert "$d" --snapshotname "$snap" >/dev/null
        vsh start "$d" >/dev/null
        say "$vm: reverted to '$snap', booting"
    done
    for vm in "${vms[@]}"; do
        wait_ssh "$vm" 600 || die "$vm: no ssh after reset"
        say "$vm: up"
    done
}

cmd_snapshot() {
    [ $# -eq 2 ] || die "usage: lab.sh snapshot <vm> <name>"
    known_vm "$1"
    dom_exists "$1" || die "$1 does not exist (lab.sh up)"
    snapshot_offline "$1" "$2"
    if [ "$(dom_state "$1")" = running ]; then wait_ssh "$1" 600 || true; fi
}

cmd_ssh() {
    [ $# -ge 1 ] || die "usage: lab.sh ssh <vm> [--] [cmd...]"
    known_vm "$1"
    local vm=$1 args
    shift
    [ "${1:-}" = -- ] && shift
    mapfile -t args < <(ssh_args "$vm")
    if [ $# -eq 0 ] && [ -t 0 ]; then
        exec ssh -t "${args[@]}" "lab@${IP[$vm]}"
    fi
    exec ssh "${args[@]}" "lab@${IP[$vm]}" "$@"
}

kdc_lan_ip() {
    local a
    a=$(vsh domifaddr "$(dom kdc)" --source agent --full 2>/dev/null |
        awk -v m="$KDC_LAN_MAC" '$2 == m && $3 == "ipv4" && !n++ { sub(/\/.*/, "", $4); print $4 }') || true
    if [ -z "$a" ]; then
        a=$(lssh kdc "ip -j -4 addr show | jq -r '.[] | select(.address == \"$KDC_LAN_MAC\") | .addr_info[0].local // empty'" 2>/dev/null) || true
    fi
    printf '%s\n' "$a"
}

cmd_ip() {
    [ $# -ge 1 ] || die "usage: lab.sh ip <vm> [lan]"
    [ -n "${IP[$1]:-}" ] || die "unknown VM '$1'"
    if [ "${2:-}" = lan ]; then
        [ "$1" = kdc ] || die "only kdc has a LAN NIC"
        local a
        a=$(kdc_lan_ip)
        [ -n "$a" ] || die "kdc has no LAN address (is it running?)"
        printf '%s\n' "$a"
    else
        printf '%s\n' "${IP[$1]}"
    fi
}

cmd_status() {
    local vm d snaps
    printf 'network %s: %s\n' "$NET" "$(vsh net-info "$NET" 2>/dev/null | awk '/^Active:/ { print ($2 == "yes" ? "active" : "inactive") }' || true)"
    printf 'pool    %s: %s\n' "$POOL" "$(vsh pool-info "$POOL" 2>/dev/null | awk '/^State:/ { print $2 }' || true)"
    printf '%-9s %-16s %-16s %-10s %s\n' VM ADDRESS DOMAIN STATE SNAPSHOTS
    for vm in "${ALL_VMS[@]}"; do
        d=$(dom "$vm")
        snaps=$(vsh snapshot-list "$d" --name 2>/dev/null | sed '/^$/d' | paste -sd, - || true)
        printf '%-9s %-16s %-16s %-10s %s\n' "$vm" "${IP[$vm]}" "$d" "$(dom_state "$vm")" "${snaps:--}"
    done
    if is_state kdc running; then
        printf 'kdc LAN address (macvtap, DHCP from the LAN): %s\n' "$(kdc_lan_ip || true)"
    fi
}

# check_vm <vm>: the F0 acceptance checks for one VM; prints PASS/FAIL lines.
check_vm() {
    local vm=$1 fails=0 other out
    pass() { printf '  PASS %s\n' "$*"; }
    fail() { printf '  FAIL %s\n' "$*"; fails=$((fails + 1)); }
    printf '%s (%s):\n' "$vm" "${IP[$vm]}"
    if ! lssh "$vm" true 2>/dev/null; then fail "ssh"; return 1; fi
    pass "ssh lab@${IP[$vm]} with the lab key"
    out=$(lssh "$vm" 'hostname -f; cat /etc/os-release | grep -E "^(VARIANT_ID|VERSION_ID)="' 2>/dev/null | paste -sd' ' -)
    pass "hostname/os: $out"
    for other in kdc services client1 client2 klldap; do
        if [ "$vm" = "$other" ]; then
            # The VM's own name is answered locally (nss-myhostname / resolved) with
            # its own addresses, in getaddrinfo order: any local address is right.
            out=$(lssh "$vm" "getent ahosts $other.$DNS_DOMAIN" 2>/dev/null | awk '!seen[$1]++ { print $1 }' | paste -sd' ' -)
            if [ -n "$out" ]; then pass "resolves itself $other.$DNS_DOMAIN -> $out"; else fail "resolves itself $other.$DNS_DOMAIN"; fi
            continue
        fi
        out=$(lssh "$vm" "getent hosts $other.$DNS_DOMAIN" 2>/dev/null | awk 'NR == 1 { print $1 }')
        if [ "$out" = "${IP[$other]}" ]; then pass "resolves $other.$DNS_DOMAIN -> $out"
        else fail "resolves $other.$DNS_DOMAIN (got '${out}', want ${IP[$other]})"; fi
        out=$(lssh "$vm" "getent hosts ${IP[$other]}" 2>/dev/null | awk 'NR == 1 { print $2 }')
        if [ "$out" = "$other.$DNS_DOMAIN" ]; then pass "reverse ${IP[$other]} -> $out"
        else fail "reverse ${IP[$other]} (got '${out}', want $other.$DNS_DOMAIN)"; fi
    done
    # A VM that just booted gets up to a minute to sync before this counts as a failure.
    out=$(lssh "$vm" "chronyc -n waitsync 12 0 0 5 >/dev/null 2>&1; timedatectl show -p NTPSynchronized --value; chronyc -n tracking | sed -n 's/^Leap status *: //p; s/^System time *: //p'" 2>/dev/null | paste -sd' ' -)
    case $out in yes*Normal*) pass "time synced (chrony): $out" ;; *) fail "time sync: $out" ;; esac
    out=$(lssh "$vm" "curl -sSI -m 20 -o /dev/null -w '%{http_code}' https://fedoraproject.org/" 2>/dev/null || true)
    case $out in 2??|3??) pass "internet: https://fedoraproject.org/ -> HTTP $out" ;; *) fail "internet: '$out'" ;; esac
    if [ "${KIND[$vm]}" = kinoite ]; then
        out=$(lssh "$vm" "systemctl get-default; systemctl is-active display-manager" 2>/dev/null | paste -sd' ' -)
        case $out in "graphical.target active") pass "desktop: $out (SDDM)" ;; *) fail "desktop: $out" ;; esac
    fi
    if [ "$vm" = kdc ]; then
        out=$(kdc_lan_ip)
        if [ -n "$out" ]; then pass "LAN NIC address $out"; else fail "LAN NIC has no address"; fi
        # The inbound filter on the LAN NIC (kerber-lab-lan-nic, kdc.user-data).
        out=$(lssh kdc "systemctl is-enabled kerber-lab-lan-filter.service; sudo nft list table inet kerber_lab_lan" 2>/dev/null || true)
        case $out in
            enabled*'iifname "'*'" jump lan_in'*'udp sport 67 udp dport 68'*'ip saddr 10.10.38.38 tcp dport 88'*'ip saddr 10.10.38.38 udp dport 88'*'ip saddr 10.10.38.38 tcp dport 80'*'drop comment'*)
                pass "LAN inbound filter loaded on $(printf '%s\n' "$out" | sed -n 's/.*iifname "\([^"]*\)".*/\1/p'): established, DHCP replies, $AD_DC -> tcp/udp 88 + tcp 80; rest dropped" ;;
            *) fail "LAN inbound filter (kerber-lab-lan-filter / table inet kerber_lab_lan) missing or changed" ;;
        esac
        out=$(lssh kdc "ip -4 route show default" 2>/dev/null | paste -sd';' -)
        case $out in *192.168.177.1*) pass "default route on the lab NIC: $out" ;; *) fail "default route: $out" ;; esac
        if lssh kdc "timeout 3 bash -c '</dev/tcp/$AD_DC/88'" 2>/dev/null; then
            pass "AD DC $AD_DC:88 reachable (route: $(lssh kdc "ip -4 route get $AD_DC" 2>/dev/null | awk 'NR == 1'))"
        else
            fail "AD DC $AD_DC:88 not reachable"
        fi
    fi
    return $((fails > 0))
}

cmd_check() {
    local vms vm rc=0
    select_vms "$@"
    vms=("${SEL[@]}")
    for vm in "${vms[@]}"; do check_vm "$vm" || rc=1; done
    return $rc
}

cmd_collect() {
    [ $# -ge 2 ] || die "usage: lab.sh collect <vm> <dir> [file...]"
    known_vm "$1"
    local vm=$1 out="$2/$1" min=${COLLECT_MINUTES:-60} f quoted=()
    shift 2
    mkdir -p "$out"
    lssh "$vm" "sudo journalctl --since -${min}min --no-pager -o short-iso-precise" > "$out/journal.txt"
    {
        printf 'vm: %s.%s (%s)\n' "$vm" "$DNS_DOMAIN" "${IP[$vm]}"
        printf 'collected: %s\n' "$(date -u +%FT%TZ)"
        printf 'journal: last %s minutes\n' "$min"
        printf 'files: %s\n' "${*:-none}"
    } > "$out/collect.txt"
    if [ $# -gt 0 ]; then
        for f in "$@"; do quoted+=("$(printf '%q' "${f#/}")"); done
        mkdir -p "$out/files"
        lssh "$vm" "sudo tar -C / -h --ignore-failed-read -cf - ${quoted[*]}" | tar -C "$out/files" -xf -
    fi
    say "collected $vm into $out"
}

usage() { sed -n '2,/^set -euo/{ /^set -euo/d; s/^# \{0,1\}//; p; }' "${BASH_SOURCE[0]}"; }

main() {
    local cmd=${1:-}
    [ $# -gt 0 ] && shift
    case $cmd in
        up) cmd_up "$@" ;;
        down) cmd_down "$@" ;;
        destroy) cmd_destroy "$@" ;;
        rebuild) cmd_rebuild "$@" ;;
        reset) cmd_reset "$@" ;;
        snapshot) cmd_snapshot "$@" ;;
        ssh) cmd_ssh "$@" ;;
        ip) cmd_ip "$@" ;;
        status) cmd_status ;;
        check) cmd_check "$@" ;;
        collect) cmd_collect "$@" ;;
        -h|--help|help|'') usage ;;
        *) usage >&2; die "unknown command '$cmd'" ;;
    esac
}

main "$@"; exit
