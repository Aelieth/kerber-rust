# harness

The container images and configs the gates run against. The scripts that
drive them live in `scripts/`; the gates are listed in
[docs/gates.md](../docs/gates.md) and the realms in
[docs/testing.md](../docs/testing.md).

| Path | What it is |
| --- | --- |
| `Dockerfile`, `entrypoint.sh` | the MIT 1.22.2 KDC image (`kerber-rust-mit-kdc:1.22.2`) |
| `docker-compose.yml` | an optional Compose wrapper for that image |
| `kdc.conf`, `krb5.conf`, `kadm5.acl` | the MIT harness realm `KERBER.TEST` |
| `krb5-sha2.conf` | the etype-20-only profile `sha2-gate.sh` uses |
| `client-krb5.conf` | a host-side client profile for the harness realm |
| `nextest-krb5.conf` | the `KRB5_CONFIG` the unit tests run under |
| `heimdal/` | the Heimdal 7.8 KDC image for `heimdal-gate.sh` |
| `samba/` | the Samba 4 AD DC image and the PAC oracles for the `samba-*` gates |
| `kcm/` | the Fedora `sssd-kcm` image and opcode probe for the KCM gates |
| `prod/` | the multi-host prod-realm substrate ([prod/README.md](prod/README.md)) |
