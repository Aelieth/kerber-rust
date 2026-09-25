//! DER round-trips of pure values. These examples do not talk to a KDC.
//!
//! A principal encodes and decodes as the same value:
//!
//! ```
//! use krb5_asn1::{decode, encode, PrincipalName};
//! let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
//! let bytes = encode(&name)?;
//! let back: PrincipalName = decode(&bytes)?;
//! assert_eq!(back, name);
//! Ok::<(), krb5_asn1::Error>(())
//! ```
//!
//! `KerberosTime` survives a DER round-trip:
//!
//! ```
//! use krb5_asn1::{decode, encode, KerberosTime};
//! let t = KerberosTime::from_unix_seconds(1_500_000_000);
//! let bytes = encode(&t)?;
//! let back: KerberosTime = decode(&bytes)?;
//! assert_eq!(back.unix_seconds(), t.unix_seconds());
//! Ok::<(), krb5_asn1::Error>(())
//! ```
