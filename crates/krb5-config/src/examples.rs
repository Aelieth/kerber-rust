//! Profile parsing. These examples do not talk to a KDC.
//!
//! `default_realm` is the `[libdefaults]` value:
//!
//! ```
//! use krb5_config::Krb5Conf;
//! let conf = Krb5Conf::parse("[libdefaults]\ndefault_realm = TESTLABBY.LOCAL\n")?;
//! assert_eq!(conf.default_realm.as_deref(), Some("TESTLABBY.LOCAL"));
//! Ok::<(), krb5_config::Error>(())
//! ```
//!
//! `clockskew` is a duration in seconds:
//!
//! ```
//! use krb5_config::Krb5Conf;
//! let conf = Krb5Conf::parse("[libdefaults]\nclockskew = 120\n")?;
//! assert_eq!(conf.clockskew, 120);
//! Ok::<(), krb5_config::Error>(())
//! ```
