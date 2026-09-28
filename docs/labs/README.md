# Labs

The live interop labs behind the Samba, AD and KCM gates, and what each one
decided. Every lab runs in containers or an `~/adlab` environment sandbox; none
touches the host `/etc/krb5.conf` or SSSD.

- [ad-lab.md](ad-lab.md): the AD interop lab, its topology, accounts (names
  only), fixtures and the safe re-test protocol.
- [samba-lab.md](samba-lab.md): the Samba 4 AD DC that serves as the live
  `AD.KERBER.TEST` oracle for the nightly `peers` gates.
- [kcm-nfs-verdict.md](kcm-nfs-verdict.md): the KCM and NFS test matrix, and
  why the fleet default ccache stays FILE.
