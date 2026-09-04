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
    /// CSPRNG failed.
    Rng,
    /// Password rejected by named policy.
    PasswordPolicy(String),
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
            Self::Rng => write!(f, "rng failed"),
            Self::PasswordPolicy(s) => write!(f, "password policy: {s}"),
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

/// MIT `kdc_util.c:691-697` `errcode_to_protocol`.
#[must_use]
pub fn errcode_to_protocol(code: i32) -> i32 {
    if (0..=128).contains(&code) {
        code
    } else {
        krb5_types::err::GENERIC
    }
}
