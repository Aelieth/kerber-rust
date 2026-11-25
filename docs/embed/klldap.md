# KLLDAP

[KLLDAP](https://github.com/Aelieth/klldap) (AGPL-3.0-only) runs kerber-rust as its KDC and its
kadmind. This page covers what that build uses of kerber-rust, as of KLLDAP's 0.8.2 branch, which
pins a 1.2.4 tag. Everything else about KLLDAP is in KLLDAP's own docs.

The combined program is AGPL because of KLLDAP. kerber-rust's own license doesn't change.

## Shape

KLLDAP is one program with one database:
- It links kerber-rust's crates into its own server binary. There is no FFI wrapper, no second
  process and no kdb file.
- The realm's rows live in the directory's database (SQLite, PostgreSQL or MySQL/MariaDB), and
  KLLDAP's code writes them.
- kerber-rust reads and writes those rows only through the host traits in
  [host-contract.md](host-contract.md).

## Crates and build

- **Crates:** `krb5-admin` and `krb5-kdc` (both with default features off), `krb5-asn1`,
  `krb5-config`, `krb5-crypto`, `krb5-gss`, `krb5-log`, `krb5-protocol` and `krb5-types`. They all
  come from this repository by `git`, at one tag.
- **rasn:** a `[patch.crates-io] rasn` from this repository, at the same tag. kerber-rust vendors
  rasn 0.28.14 with a patch, and an embedder must carry it.
- **P-384:** an embedder's own build needs `--cfg p384_backend="fiat"`, for example in its
  `.cargo/config.toml`, because our cargo config doesn't reach it. Without the cfg, kerber-rust
  refuses P-384 rather than use p384's default field, which isn't constant-time.
- **jiff:** KLLDAP takes `jiff` 1.0.1 with `std` only. It never asks jiff for the system zone or
  for a zone by name.

## What KLLDAP implements and calls

| kerber-rust interface | KLLDAP's use |
|---|---|
| `host::KerberosStore` (`load`, `commit_change`, `prepare`) | its SQL realm |
| `admission::HostAdmission` (`check_as`, `as_notice`, `check_tgs`) | its admission. The rules it applies are KLLDAP's |
| `KdcPolicy` | its live-clients policy |
| Opening | `PrincipalStore`, `SharedStore`, `SharedDump`, `HostPaths`, `AdminSpec` and the profile types. For its one-time import from KLLDAP 0.7.2: `load_dump_with_stash_path`, `parse_dump` and `create_lockout_file` |
| Serving | `serve_all_until` for the KDC and `krb5_admin::Kadmind` for kadmind, each on a thread of its own |
| Writing from its own doors | shape C: `change_committing`, `change_password_shared_committing_then` and `create_password_shared_committing_then` |
| Logging | `KdcLog` |

## Its directory users

- A directory user's principal carries the host mark.
- KLLDAP's own doors write in shape C ([password-interface.md](password-interface.md)).
- A kadmin `cpw` of a directory user takes shape P. KLLDAP refuses a `-e` key/salt list there
  with `KADM5_BAD_KEYSALTS`.

KLLDAP's other rules for its users, and what it does when the realm can't open, are in KLLDAP's
docs.
