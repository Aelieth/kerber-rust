# examples

| Path | What it is |
| --- | --- |
| [configs/](configs/README.md) | a working one-realm `kdc.conf`, `krb5.conf` and `kadm5.acl` for the Rust daemons and client tools; `scripts/kdc-gate.sh` runs them as written |
| `consumer/` | `krb5-consumer`: calls the public `krb5-crypto` encrypt and `krb5-asn1` DER APIs with published vectors, as a downstream crate would; not a Kerberos client |
| `kdc-consumer/` | `krb5-kdc-consumer`: calls the `krb5-kdc` issue path, keytab export and AP-REQ verify without binding a socket |
| [otp-kdc/](otp-kdc/README.md) | `krb5-otp-kdc-example`: the KDC run in-process through the embed API, with a TOTP `OtpVerifier` registered; the KLLDAP seam in miniature, not a shipped product |
| [embed-realm/](embed-realm/README.md) | `krb5-embed-realm-example`: kadmind run in-process through the embed API (`Kadmind::new`, `Listeners::bind`, `serve(&Shutdown)`); the admin-service half of the KLLDAP seam, not a shipped product |

The four crates are workspace members, so `make safety` builds and lints them.
