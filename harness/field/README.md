# `harness/field/`: the KVM field lab (section F0)

Section F proves kerber-rust against real systems: Fedora clients (SSSD,
gssproxy, NFS, sshd, Firefox), Keycloak, Windows/AD and KLLDAP. Every scenario
runs first against a stock Fedora MIT `krb5-server` realm (the oracle), then
against kerber-rust. This directory builds the lab those scenarios run in:
four libvirt VMs on this host, on a private NAT network with its own DNS.

`lab.sh` is a harness. It drives libvirt, cloud-init and Anaconda, and it
asserts nothing about Kerberos. The VMs carry no Kerberos server software and
no realm. The field scenarios install those (`working/logs/f-<scenario>/`).

## Address plan

Network `kerber-lab`: NAT on `192.168.177.0/24`, bridge `virbr-kerber`.
Gateway, DHCP and DNS are on `192.168.177.1` (libvirt's dnsmasq).

| Name | Address | libvirt domain | OS | vCPU / RAM / disk | Role |
| --- | --- | --- | --- | --- | --- |
| `kdc.kerber.test` | `.10` + a LAN NIC | `kerber-kdc` | Fedora 43 Cloud | 2 / 2 GiB / 20 GB | MIT `krb5-server` (oracle), then kerber-rust |
| `services.kerber.test` | `.11` | `kerber-services` | Fedora 43 Cloud | 4 / 6 GiB / 40 GB | rootful podman: Ganesha NFS, Keycloak, lldap |
| `client1.kerber.test` | `.21` | `kerber-client1` | Fedora Kinoite 43 | 4 / 6 GiB / 40 GB | the fleet's client type (satomlin-kit twin), SPICE desktop |
| `client2.kerber.test` | `.22` | `kerber-client2` | Fedora 43 Cloud | 2 / 3 GiB / 20 GB | sshd target, second NFS client, headless checks |
| `klldap.kerber.test` | `.30` | not built yet | | | reserved for F3 |

- **DHCP:** static leases by MAC (`network-kerber-lab.xml`, the table in
  `lab.sh`). Other machines get `.100`–`.199`.
- **DNS:** forward and reverse records for every name above. `kerber.test` is
  local only, so unknown names get NXDOMAIN and nothing leaks upstream.
  Everything else is forwarded upstream.
- **AD:** `ad.kerber.test` is forwarded to the AD test DC `10.10.38.38`, so the
  VMs resolve `test-server.ad.kerber.test` (F2-AD). The realm is `KERBER.TEST`.
- **Own name:** a VM's own name resolves locally (systemd-resolved /
  nss-myhostname), not through DNS. In `getaddrinfo` order the answer is the
  IPv6 link-local address, then the lab address, and on kdc then the LAN
  address. This is stock Fedora. A client running on kdc itself tries
  `fe80::…%2` first.

### kdc's LAN NIC (macvtap)

`kdc` has a second NIC: macvtap in bridge mode on the host's wired NIC (the
lowest-metric wired default route; override with `KERBER_LAB_LAN_IF`). It
takes a DHCP address from the user's real LAN. Its only job is to let the AD
DC (`10.10.38.38`) reach the KDC, and RA3's SPNEGO target, which runs on kdc.

`/usr/local/sbin/kerber-lab-lan-nic` confines the NIC. The kdc user-data's
`bootcmd` writes the script and runs it once. That stage runs before sshd
starts, so nothing listens on the LAN unfiltered.

- **Inbound filter:** nftables table `inet kerber_lab_lan`, on that NIC only.
  - It accepts established/related traffic, DHCP replies (`udp sport 67 dport
    68`, so the lease renews), and `10.10.38.38` to tcp/udp 88 and tcp 80.
  - It drops everything else from the LAN, including 22, 464, 749 and ICMP.
  - The lab NIC and loopback are not filtered.
  - `kerber-lab-lan-filter.service` loads `/etc/nftables/kerber-lab-lan.nft`
    before `network-pre.target` on every boot, including after a `reset`.
- **Routes and DNS:** the NIC carries no default route, no DHCP routes, no
  DNS and no IPv6 (`never-default`, `ignore-auto-routes`, `ignore-auto-dns`,
  `ipv6.method disabled`). Traffic to `10.10.0.0/16` leaves through it
  on-link. Everything else, internet included, goes through the lab NAT.
- **Check it:**
  - `lab.sh check kdc` asserts the table and its unit.
  - `lab.sh ssh kdc sudo nft list table inet kerber_lab_lan` shows the rules
    with their counters.
  - To open the NIC for a moment: `sudo nft delete table inet kerber_lab_lan`.
    `sudo systemctl restart kerber-lab-lan-filter` closes it again.
  - A firewall added to kdc later must leave this table in place.
- **Verified from the DC:** `working/logs/f-F0/lan-filter.txt` holds the
  WinRM `Test-NetConnection` record (2026-10-01).

- **Host to kdc:** by design, macvtap does not carry traffic between the host
  and its own guest. Reach kdc from the host at `192.168.177.10`.
- **LAN address:** `lab.sh ip kdc lan` reads it from the guest agent.
- **Lab subnet:** the other VMs are not reachable from the LAN. kdc is the only
  VM exposed to it, which is why RA3's SPNEGO target runs on kdc (tcp 80).

## Usage

Run from the repo root, on the host or inside the `rust-dev` distrobox. In the
distrobox, `lab.sh` sends host commands through `distrobox-host-exec`. It
needs membership in the `libvirt` group and no sudo.

```sh
harness/field/lab.sh up                 # build or start everything; idempotent
harness/field/lab.sh status             # VMs, addresses, snapshots, kdc's LAN address
harness/field/lab.sh check              # ssh, DNS + reverse, time sync, internet; kdc LAN + filter + AD DC :88; client1 SDDM
harness/field/lab.sh ssh kdc            # shell as 'lab' (passwordless sudo)
harness/field/lab.sh ssh client2 -- sudo dnf -y install krb5-workstation
harness/field/lab.sh ip kdc             # 192.168.177.10   (ip kdc lan: the LAN address)
harness/field/lab.sh snapshot kdc mit-oracle   # offline snapshot (shut down, snapshot, start)
harness/field/lab.sh reset all          # revert every VM to 'base' and boot it
harness/field/lab.sh reset kdc mit-oracle
harness/field/lab.sh collect kdc working/logs/f-r1 /var/log/krb5kdc.log /etc/krb5.conf
harness/field/lab.sh down               # shut the VMs down (the network stays up)
harness/field/lab.sh rebuild kdc --yes  # one VM from scratch (after a template change)
harness/field/lab.sh destroy --yes      # remove the VMs, volumes, pool and network
```

- **`up`:** builds each missing VM, waits for provisioning and takes snapshot
  `base`.
  - Timing: about 20 minutes from nothing with the images already downloaded
    (measured 2026-10-01). Most of it is the Kinoite install and upgrade and
    the cloud VMs' package upgrade. Downloading the 4.5 GB of Fedora media
    first took 6 minutes more.
  - `reset all` brings every VM back at `base` in about 30 seconds.
  - Interruptions: a VM without `base` is finished from whatever state it is
    in. An install that ended is never booted again.
  - Later runs only start stopped VMs.
- **`collect <vm> <dir> [file...]`:** writes `<dir>/<vm>/journal.txt` (the last
  `COLLECT_MINUTES`, default 60), `collect.txt`, and the listed files under
  `<dir>/<vm>/files/`.
- **Snapshots:** taken offline (internal qcow2), so a revert is a cold boot.
  chrony then steps the clock at start. A memory snapshot would resume with a
  stale clock, and Kerberos needs synced time.
- **`destroy`:** touches only lab objects: the `kerber-*` domains, every volume
  in pool `kerber-lab`, the pool and the network. It keeps the downloaded
  images, the SSH key and the console password.

## What `up` builds

- **Cloud VMs (`kdc`, `services`, `client2`):**
  - Disk: a qcow2 overlay on the Fedora 43 Cloud Base image (`43-1.6`).
  - Seed: a NoCloud ISO (`cidata`) rendered from `cloud-init/<vm>.user-data`
    and `cloud-init/network-config.*`.
  - cloud-init sets the FQDN hostname and timezone UTC. It creates user `lab`
    (wheel, NOPASSWD sudo, the lab key, a console password; no SSH password
    login), upgrades all packages, and installs `chrony qemu-guest-agent
    tcpdump jq bind-utils tar rsync`. `services` also gets `podman`, and
    `kdc` gets `nftables` plus its LAN NIC confinement.
  - chronyd and the guest agent are enabled.
- **`client1`:**
  - Installed unattended from the Fedora Kinoite 43 ISO with
    `kickstart/client1-kinoite.ks`. Its payload is the ISO's embedded ostree
    repo, the same `ostreesetup` line as the ISO's own
    `interactive-defaults.ks`.
  - The installer kernel boots directly with `inst.ks=hd:LABEL=OEMDRV:/ks.cfg`,
    and the kickstart rides on a small ISO labelled `OEMDRV`. The kickstart
    powers off at the end. `lab.sh` then drops the direct kernel boot, ejects
    the media and boots from disk.
  - Same `lab` user and key; `sshd` and `chronyd` enabled.
  - `xconfig --startxonboot` makes it boot to SDDM like a graphical install.
    Kinoite is KDE, so the plan's "GDM" is SDDM here.
  - After the first boot, `lab.sh` runs `rpm-ostree upgrade` and reboots,
    because the fleet runs updated deployments. The ISO's deployment stays as
    the rollback. Set `KERBER_LAB_KINOITE_UPGRADE=0` to skip this.
  - No packages are layered, so client1 is the stock Kinoite deployment until
    the kit layers its own. That means no guest agent, tcpdump or jq.
- **Media:** checked against Fedora's CHECKSUM files. `lab.sh` verifies the
  signature with the Fedora 43 key (`C6E7F081CF80E13146676E88829B606631645531`)
  and then the SHA-256, before it uploads anything into the pool.
- **Firmware:** every VM boots with SeaBIOS (BIOS), so internal snapshots work.
  libvirt does not take internal snapshots of UEFI/pflash guests.

### The VMs at snapshot `base` (built 2026-10-01)

| | kdc / services / client2 | client1 |
| --- | --- | --- |
| OS | Fedora 43 Cloud (`VARIANT_ID=cloud`), `dnf upgrade`d | Fedora Kinoite `43.20261001.0` (ostree `fedora:fedora/43/x86_64/kinoite`), rollback `43.1.6` |
| Kernel | 7.2.8-100.fc43 | 7.2.8-100.fc43 |
| MIT krb5 | `krb5-libs-1.22.2-4.fc43` only (no server, no workstation) | `krb5-libs-1.22.2-4.fc43`; `/etc/krb5.conf` has `includedir`, default ccache `KCM:` |
| Related packages | `sssd-client`, `openssh-server`, `podman` (Fedora Cloud ships podman) | `gssproxy-0.9.2`, `nfs-utils-2.8.7`, `sssd-client` (no `sssd`/`sssd-krb5`), Firefox 156, SDDM |
| Firewall | none (Fedora Cloud has no firewalld) | firewalld, zone `FedoraWorkstation` |
| SELinux | enforcing | enforcing |
| Time | UTC, chronyd on `2.fedora.pool.ntp.org` (through the NAT) | same |

## Where things live

| What | Where | In git |
| --- | --- | --- |
| Network XML, cloud-init and kickstart templates, `lab.sh` | `harness/field/` | yes |
| Verified Fedora images, signed CHECKSUM files | `~/kerber-lab/images/` | no |
| Lab SSH key (`lab_ed25519`, 0600) and `known_hosts` | `~/kerber-lab/ssh/` | no |
| Console password and its SHA-512 crypt | `~/kerber-lab/secrets/` | no |
| Rendered seeds and kickstart (they hold the key and the hash) | `~/kerber-lab/seeds/` | no |
| VM disks, seed ISOs, the base image, the Kinoite ISO | pool `kerber-lab`, `/var/lib/libvirt/images/kerber-lab/` (root) | no |

- **`~/kerber-lab`:** mode 0700. Set `KERBER_LAB_HOME` to move it; it must be a
  path the host sees too (anything under `$HOME` is).
- **Templates:** they hold only placeholders (`@SSH_PUBKEY@`,
  `@LAB_PASSWD_HASH@`, `@LAB_MAC@`, `@LAN_MAC@`).
- **Console password:** for `virsh console` or the SPICE desktop when ssh is
  not an option. SSH accepts only the key.

## Isolation

- **Host:** the lab never touches the host's `/etc/krb5.conf` (realm
  `TESTLABBY.LOCAL`), the libvirt `default` network, other VMs, or host
  networking. libvirt's own firewall rules for `virbr-kerber` are the only
  host-side network change.
- **Secrets:** none enter git or field records.
- **Libvirt objects:** every one is named `kerber-lab` or `kerber-*`.
  `pool-build` created the standard libvirt directory `/var/lib/libvirt/images`
  as the pool's parent. `destroy` leaves it, empty.
