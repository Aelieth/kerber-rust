# client1.kerber.test: Fedora Kinoite 43, the satomlin fleet's client type.
# Unattended install from the Kinoite 43 ISO's embedded ostree repo. The
# ostreesetup line is the ISO's own interactive-defaults.ks payload, so the
# result is the system a person gets from that ISO. The satomlin-kit twin
# later layers its packages with rpm-ostree.
#
# lab.sh renders this template to ~/kerber-lab/seeds/client1/ks.cfg (outside
# git), puts it on an ISO labelled OEMDRV, and boots the installer with
# inst.ks=hd:LABEL=OEMDRV:/ks.cfg. Placeholders:
#   @SSH_PUBKEY@        the lab public key, ~/kerber-lab/ssh/lab_ed25519.pub
#   @LAB_PASSWD_HASH@   SHA-512 crypt of the console password, ~/kerber-lab/secrets
text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --device=link --bootproto=dhcp --activate --hostname=client1.kerber.test

ostreesetup --nogpg --osname=fedora --remote=fedora --url=file:///ostree/repo --ref=fedora/43/x86_64/kinoite
firewall --use-system-defaults
# A text-mode install would leave multi-user.target. The fleet boots to SDDM.
xconfig --startxonboot

ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel --drives=vda
autopart --type=btrfs --noswap
bootloader --location=mbr --boot-drive=vda --append="console=tty0 console=ttyS0,115200"

rootpw --lock
user --name=lab --groups=wheel --gecos="kerber-lab operator" --iscrypted --password=@LAB_PASSWD_HASH@
sshkey --username=lab "@SSH_PUBKEY@"
services --enabled=sshd,chronyd

# Power off, not reboot: the install boots a direct kernel, which lab.sh
# removes before the first real boot.
poweroff

%post --erroronfail
# As the ISO's interactive-defaults.ks does.
cp /etc/skel/.bash* /root
# The lab operator. This is the lab VM, not the host.
echo 'lab ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-kerber-lab
chmod 0440 /etc/sudoers.d/90-kerber-lab
%end
