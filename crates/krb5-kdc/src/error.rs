//! KDC and admin errors.

use std::fmt;

/// Failure from issue, ACL, or the principal store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Crypto layer.
    Crypto(String),
    /// DER codec.
    Asn1(String),
    /// RFC 4120 KRB-ERROR / KDC error code.
    Protocol {
        /// Error code.
        code: i32,
        /// Optional text (MIT status word on the wire).
        text: Option<String>,
        /// Optional KRB-ERROR `e-data` (METHOD-DATA / TD-DH-PARAMETERS).
        e_data: Option<Vec<u8>>,
        /// MIT `k5_setmsg` text for `kdc.issue` `detail` (not on the wire).
        detail: Option<String>,
    },
    /// Actor is not permitted this admin operation.
    AclDenied,
    /// kadm5.acl load failed (`acl_init`).
    AclParse(String),
    /// Principal already exists.
    AlreadyExists,
    /// Principal is not in the store.
    NotFound,
    /// `KADM5_ALIAS_REALM`: alias and target realms differ.
    AliasRealm,
    /// `KRB5_KDB_ALIAS_UNSUPPORTED`: the operation's source is an alias stub.
    AliasUnsupported,
    /// CSPRNG failed.
    Rng,
    /// Password rejected by named policy.
    PasswordPolicy(String),
    /// `KADM5_BAD_KEYSALTS`: requested `-e` is outside `allowed_keysalts`.
    BadKeysalts,
    /// `KADM5_PASS_TOOSOON`: min_life not elapsed. `until` is unix seconds.
    PassTooSoon {
        /// `last_pwd_change + pw_min_life`.
        until: u32,
    },
    /// The principal database, its update log or its stash could not be read or written: an
    /// I/O failure with the system's own text (`strerror`), or a file that does not load.
    Db {
        /// What failed: `PermissionDenied` for a writer that may not write the database.
        kind: std::io::ErrorKind,
        /// The system's text for it, without Rust's `(os error N)`, or the format failure.
        text: String,
    },
    /// `EINVAL` from `krb5_db_put_principal` / DB2 `db_args`.
    /// MIT `krb5_db2_put_principal` (`kdb_db2.c:817-822`): any `db_args` is `EINVAL`,
    /// since DB2 supports no DB arguments for a principal.
    InvalidArgument(String),
    /// Request PDU was not AS-REQ or TGS-REQ.
    UnexpectedPdu,
    /// Client must retry with PA-ENC-TIMESTAMP; `e_data` is METHOD-DATA.
    PreauthRequired {
        /// DER METHOD-DATA (ETYPE-INFO2).
        e_data: Vec<u8>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(s) => write!(f, "crypto: {s}"),
            Self::Asn1(s) => write!(f, "asn1: {s}"),
            Self::Protocol { code, text, .. } => match text {
                Some(t) => write!(f, "KDC error {code}: {t}"),
                None => write!(f, "KDC error {code}"),
            },
            Self::AclDenied => write!(f, "ACL denied"),
            Self::AclParse(s) => write!(f, "ACL parse: {s}"),
            Self::AlreadyExists => write!(f, "principal exists"),
            Self::NotFound => write!(f, "principal not found"),
            Self::AliasRealm => write!(f, "Alias target must be within the same realm"),
            Self::AliasUnsupported => {
                write!(f, "Operation unsupported on alias principal name")
            }
            Self::Rng => write!(f, "rng failed"),
            Self::PasswordPolicy(s) => write!(f, "password policy: {s}"),
            Self::BadKeysalts => write!(f, "Invalid key/salt tuples"),
            Self::PassTooSoon { .. } => {
                write!(f, "Current password's minimum life has not expired")
            }
            Self::Db { text, .. } | Self::InvalidArgument(text) => write!(f, "{text}"),
            Self::UnexpectedPdu => write!(f, "unexpected PDU"),
            Self::PreauthRequired { .. } => write!(f, "preauth required"),
        }
    }
}

impl std::error::Error for Error {}

impl From<krb5_crypto::Error> for Error {
    fn from(e: krb5_crypto::Error) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<crate::persist::PersistError> for Error {
    fn from(e: crate::persist::PersistError) -> Self {
        use crate::persist::PersistError;
        match e {
            PersistError::Io(e) => Self::Db {
                kind: e.kind(),
                text: strerror(&e),
            },
            PersistError::Crypto(s) => Self::Crypto(s),
            PersistError::Format(text) => Self::Db {
                kind: std::io::ErrorKind::InvalidData,
                text,
            },
            PersistError::UnknownDbLibrary(name) => Self::Db {
                kind: std::io::ErrorKind::Unsupported,
                text: format!("unknown db_library: {name}"),
            },
        }
    }
}

/// The system's text for `e` (`strerror`): Rust's display without its ` (os error N)`.
fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}

impl From<krb5_asn1::Error> for Error {
    fn from(e: krb5_asn1::Error) -> Self {
        Self::Asn1(e.to_string())
    }
}

impl From<krb5_protocol::Error> for Error {
    fn from(e: krb5_protocol::Error) -> Self {
        match e {
            krb5_protocol::Error::KrbError { code, text } => Self::Protocol {
                code: errcode_to_protocol(code),
                text,
                e_data: None,
                detail: None,
            },
            other => Self::Crypto(other.to_string()),
        }
    }
}

/// MIT `errcode_to_protocol` (`kdc_util.c:691-697`): the code past the krb5 table base is
/// kept when it is 0 to 128, and anything else is `KRB_ERR_GENERIC`.
#[must_use]
pub fn errcode_to_protocol(code: i32) -> i32 {
    if (0..=128).contains(&code) {
        code
    } else {
        krb5_types::err::GENERIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::PersistError;

    #[test]
    fn a_refused_save_is_a_database_error_with_the_system_text() {
        let e = Error::from(PersistError::Io(std::io::Error::from_raw_os_error(13)));
        assert_eq!(
            e,
            Error::Db {
                kind: std::io::ErrorKind::PermissionDenied,
                text: "Permission denied".into(),
            }
        );
        assert_eq!(e.to_string(), "Permission denied");
        let e = Error::from(PersistError::Crypto(
            "stash is not a usable master key".into(),
        ));
        assert_eq!(e.to_string(), "crypto: stash is not a usable master key");
    }
}
