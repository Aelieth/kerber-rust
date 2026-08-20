//! Protocol errors.

use std::fmt;

/// Failure of an AS/TGS exchange or transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Crypto layer failed.
    Crypto(String),
    /// DER codec failed.
    Asn1(String),
    /// UDP/TCP I/O or timeout.
    Io(String),
    /// KDC returned KRB-ERROR with this RFC 4120 code.
    KrbError {
        /// RFC 4120 error-code.
        code: i32,
        /// Optional e-text.
        text: Option<String>,
    },
    /// Reply tag was not AS-REP, TGS-REP, or KRB-ERROR.
    UnexpectedPdu,
    /// Encrypted reply nonce did not match the request.
    NonceMismatch,
    /// No overlapping etype with the KDC.
    NoEtype,
    /// Reply too short to classify.
    TruncatedReply,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(s) => write!(f, "crypto: {s}"),
            Self::Asn1(s) => write!(f, "asn1: {s}"),
            Self::Io(s) => write!(f, "transport: {s}"),
            Self::KrbError { code, text } => match text {
                Some(t) => write!(f, "KRB-ERROR {code}: {t}"),
                None => write!(f, "KRB-ERROR {code}"),
            },
            Self::UnexpectedPdu => write!(f, "unexpected Kerberos PDU tag"),
            Self::NonceMismatch => write!(f, "AS/TGS nonce mismatch"),
            Self::NoEtype => write!(f, "no mutually supported etype"),
            Self::TruncatedReply => write!(f, "KDC reply truncated"),
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
