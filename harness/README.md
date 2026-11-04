# harness

The container images and configs the gates run against. The scripts that
drive them live in `scripts/`; the gates are listed in
[docs/gates.md](../docs/gates.md) and the realms in
[docs/testing.md](../docs/testing.md).

| Path | What it is |
| --- | --- |
| `Dockerfile`, `entrypoint.sh` | the MIT 1.22.2 KDC image (`kerber-rust-mit-kdc:1.22.2`) |
| `kdc.conf`, `krb5.conf`, `kadm5.acl` | the MIT harness realm `KERBER.TEST` |
| `krb5-sha2.conf` | the etype-20-only profile copied into the image |
| `client-krb5.conf` | a host-side client profile for the harness realm |
| `nextest-krb5.conf` | the `KRB5_CONFIG` the unit tests run under |
| `samba/` | the Samba 4 AD DC image and the PAC oracles for the `samba-*` gates |
| `field/` | the KVM field lab for section F: libvirt network, VMs, `lab.sh` ([field/README.md](field/README.md)) |
