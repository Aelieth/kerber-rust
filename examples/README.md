# examples

| Path | What it is |
| --- | --- |
| [configs/](configs/README.md) | a working one-realm `kdc.conf`, `krb5.conf` and `kadm5.acl` for the Rust daemons and client tools; `scripts/kdc-gate.sh` runs them as written |
| `consumer/` | `krb5-consumer`: calls the public `krb5-crypto` encrypt and `krb5-asn1` DER APIs with published vectors, as a downstream crate would; not a Kerberos client |
| `kdc-consumer/` | `krb5-kdc-consumer`: calls the `krb5-kdc` issue path, keytab export and AP-REQ verify without binding a socket |
| [embed-realm/](embed-realm/README.md) | `krb5-embed-realm-example`: two in-process embedders — `krb5-embed-realm` (kadmind via `Kadmind::new`, `Listeners::bind`, `serve(&Shutdown)`) and `krb5-otp-kdc` (the KDC with a TOTP `OtpVerifier` and the `require_mfa` policy); both halves of the KLLDAP seam, not a shipped product |

The three crates are workspace members, so `make safety` builds and lints them.
