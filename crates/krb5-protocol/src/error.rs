//! Protocol errors.

use std::io;
use thiserror::Error;

/// Failure of an AS/TGS/AP exchange or transport.
#[derive(Debug, Error)]
pub enum Error {
    /// Crypto layer failed.
    #[error("crypto: {0}")]
    Crypto(String),
    /// DER codec failed.
    #[error("asn1: {0}")]
    Asn1(String),
    /// UDP/TCP I/O or timeout.
    #[error("transport: {message}")]
    Io {
        /// Display text.
        message: String,
        /// std I/O kind.
        kind: io::ErrorKind,
        /// Whether a retry/failover may help.
        retryable: bool,
    },
    /// KDC returned KRB-ERROR with this RFC 4120 code.
    #[error("KRB-ERROR {code}{}", text.as_ref().map(|t| format!(": {t}")).unwrap_or_default())]
    KrbError {
        /// RFC 4120 error-code.
        code: i32,
        /// Optional e-text.
        text: Option<String>,
    },
    /// Reply tag was not AS-REP, TGS-REP, AP-REP, or KRB-ERROR.
    #[error("unexpected Kerberos PDU tag")]
    UnexpectedPdu,
    /// Encrypted reply nonce did not match the request.
    #[error("AS/TGS nonce mismatch")]
    NonceMismatch,
    /// Returned principal / sname / etype / flags did not match the request.
    #[error("reply validation: {0}")]
    ReplyMismatch(String),
    /// Referral TGT presented as a service ticket.
    #[error("referral TGT cannot be used as the requested service ticket")]
    Referral,
    /// No overlapping etype with the KDC.
    #[error("no mutually supported etype")]
    NoEtype,
    /// Reply too short to classify.
    #[error("KDC reply truncated")]
    TruncatedReply,
    /// I/O from keytab/ccache.
    #[error("file: {0}")]
    File(#[from] io::Error),
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            Self::Crypto(s) => Self::Crypto(s.clone()),
            Self::Asn1(s) => Self::Asn1(s.clone()),
            Self::Io {
                message,
                kind,
                retryable,
            } => Self::Io {
                message: message.clone(),
                kind: *kind,
                retryable: *retryable,
            },
            Self::KrbError { code, text } => Self::KrbError {
                code: *code,
                text: text.clone(),
            },
            Self::UnexpectedPdu => Self::UnexpectedPdu,
            Self::NonceMismatch => Self::NonceMismatch,
            Self::ReplyMismatch(s) => Self::ReplyMismatch(s.clone()),
            Self::Referral => Self::Referral,
            Self::NoEtype => Self::NoEtype,
            Self::TruncatedReply => Self::TruncatedReply,
            Self::File(e) => Self::Io {
                message: e.to_string(),
                kind: e.kind(),
                retryable: false,
            },
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for Error {}

impl Error {
    /// Transport timeout / refused / interrupted.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io { retryable, .. } => *retryable,
            Self::KrbError { code, .. } => matches!(
                *code,
                krb5_types::err::SVC_UNAVAILABLE | krb5_types::err::RESPONSE_TOO_BIG
            ),
            _ => false,
        }
    }

    /// Preauth-related KRB-ERROR (25/24).
    #[must_use]
    pub fn is_preauth(&self) -> bool {
        matches!(
            self,
            Self::KrbError {
                code: krb5_types::err::PREAUTH_REQUIRED | krb5_types::err::PREAUTH_FAILED,
                ..
            }
        )
    }

    /// Transport failure from a formatted message (retryable by default).
    #[must_use]
    pub fn transport_msg(msg: impl Into<String>) -> Self {
        Self::Io {
            message: msg.into(),
            kind: io::ErrorKind::Other,
            retryable: true,
        }
    }

    /// Wrap an I/O error, classifying retryable kinds.
    #[must_use]
    pub fn from_io(e: io::Error) -> Self {
        let kind = e.kind();
        let retryable = matches!(
            kind,
            io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
        );
        Self::Io {
            message: e.to_string(),
            kind,
            retryable,
        }
    }
}

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
