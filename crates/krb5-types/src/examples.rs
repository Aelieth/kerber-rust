//! Pure parsers. These examples do not talk to a KDC.
//!
//! A service principal joins its components with `/`:
//!
//! ```
//! use krb5_types::PrincipalName;
//! let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "REALM"]);
//! assert_eq!(name.components_joined(), "krbtgt/REALM");
//! ```
//!
//! A realm is appended with `@`:
//!
//! ```
//! use krb5_types::PrincipalName;
//! let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
//! assert_eq!(name.unparse_with_realm("REALM"), "user@REALM");
//! ```
//!
//! One hour is 3600 seconds:
//!
//! ```
//! use krb5_types::deltat::parse;
//! let secs = parse("1h")?;
//! assert_eq!(secs, 3600);
//! Ok::<(), krb5_types::deltat::DeltatError>(())
//! ```
//!
//! Three days is 259200 seconds:
//!
//! ```
//! use krb5_types::deltat::parse;
//! let secs = parse("3d")?;
//! assert_eq!(secs, 3 * 24 * 3600);
//! Ok::<(), krb5_types::deltat::DeltatError>(())
//! ```
//!
//! A bare number is already seconds:
//!
//! ```
//! use krb5_types::deltat::parse;
//! let secs = parse("42")?;
//! assert_eq!(secs, 42);
//! Ok::<(), krb5_types::deltat::DeltatError>(())
//! ```
//!
//! `KerberosTime` round-trips a POSIX timestamp:
//!
//! ```
//! use krb5_types::KerberosTime;
//! let t = KerberosTime::from_unix_seconds(1_500_000_000);
//! assert_eq!(t.unix_seconds(), 1_500_000_000);
//! ```
