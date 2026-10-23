//! KDC and admin errors.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Crypto(String),
    // MIT: `krb5_k_decrypt` (lib/crypto/krb/decrypt.c:45-46)
    BadEnctype,
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    DesBadParity,
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    DesWeakKey,
    Asn1(String),
    Protocol {
        code: i32,
        text: Option<String>,
        e_data: Option<Vec<u8>>,
        detail: Option<String>,
    },
    AclDenied,
    AclParse(String),
    AlreadyExists,
    NotFound,
    AliasRealm,
    AliasUnsupported,
    Rng,
    PasswordPolicy(String),
    BadKeysalts,
    PassTooSoon {
        until: u32,
    },
    Db {
        kind: std::io::ErrorKind,
        text: String,
    },
    // MIT: `krb5_db2_put_principal` (kdb_db2.c:817-822)
    InvalidArgument(String),
    UnexpectedPdu,
    PreauthRequired {
        e_data: Vec<u8>,
    },
    // MIT: `k5_get_error` (util/support/errors.c:68-95)
    PreauthModule {
        code: i32,
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(s) => write!(f, "crypto: {s}"),
            Self::BadEnctype => write!(f, "Bad encryption type"),
            // MIT: `KRB5DES_BAD_KEYPAR` (krb5_err.et:251-251)
            Self::DesBadParity => write!(f, "DES key has bad parity"),
            // MIT: `KRB5DES_WEAK_KEY` (krb5_err.et:252-252)
            Self::DesWeakKey => write!(f, "DES key is a weak key"),
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
            Self::PreauthModule { message, .. } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<krb5_crypto::Error> for Error {
    fn from(e: krb5_crypto::Error) -> Self {
        match e {
            krb5_crypto::Error::BadEnctype(_) => Self::BadEnctype,
            krb5_crypto::Error::DesBadParity => Self::DesBadParity,
            krb5_crypto::Error::DesWeakKey => Self::DesWeakKey,
            e => Self::Crypto(e.to_string()),
        }
    }
}

impl Error {
    // MIT: `KRB5DES_BAD_KEYPAR` (krb5_err.et:251-251)
    // MIT: `KRB5DES_WEAK_KEY` (krb5_err.et:252-252)
    #[must_use]
    /// Parity is base plus 186; weak is base plus 187.
    pub(crate) fn des_key_code(&self) -> Option<i64> {
        match self {
            Self::DesBadParity => Some(-1_765_328_198),
            Self::DesWeakKey => Some(-1_765_328_197),
            _ => None,
        }
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
            PersistError::Lock(e) => Self::Db {
                kind: e.kind(),
                text: e.to_string(),
            },
            e @ PersistError::Unopenable { .. } => Self::Db {
                kind: std::io::ErrorKind::InvalidData,
                text: e.to_string(),
            },
        }
    }
}

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

// MIT: `errcode_to_protocol` (kdc_util.c:691-697)
#[must_use]
/// The table base is not subtracted.
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
