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
        /// Optional e-text. For a TGS request's unknown server that came with e-text, MIT's
        /// message in its place, naming the error's server.
        /// MIT `krb5int_process_tgs_reply` (`lib/krb5/krb/gc_via_tkt.c:195-216`): an unknown server's error with e-text sets the message "Server <the error's server> not found in Kerberos database"; without e-text no message is set.
        text: Option<String>,
    },
    /// Reply tag was not AS-REP, TGS-REP, AP-REP, or KRB-ERROR.
    #[error("unexpected Kerberos PDU tag")]
    UnexpectedPdu,
    /// The KDC-REP enc-part did not verify under the client's key — MIT
    /// `krb5_kdc_rep_decrypt_proc` → `krb5_c_decrypt` returns
    /// `KRB5KRB_AP_ERR_BAD_INTEGRITY` (31), the "wrong password" of a password AS.
    /// MIT `k5_kinit` (`kinit.c:787-787`): kinit reports `KRB5KRB_AP_ERR_BAD_INTEGRITY` as
    /// "Password incorrect".
    #[error("Decrypt integrity check failed")]
    ReplyIntegrity,
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
    /// The KDC's etype-info names an enctype this client has, but none the request asked for.
    /// MIT `KRB5_CONFIG_ETYPE_NOSUPP` (`krb5_err.et:326-326`): the code and text.
    #[error("No supported encryption types (config file error?)")]
    ConfigEtypeNosupp,
    /// The KDC's etype-info names no enctype this client has.
    /// MIT `KRB5_PROG_ETYPE_NOSUPP` (`krb5_err.et:204-204`): the code and text.
    #[error("Program lacks support for encryption type")]
    ProgEtypeNosupp,
    /// An EncryptedData whose enctype is not its key's.
    /// MIT `KRB5_BAD_ENCTYPE` (`krb5_err.et:254-254`): the code and text, which `krb5_k_decrypt` returns.
    #[error("Bad encryption type")]
    BadEnctype,
    /// The KDB keytab has no key to give for the ticket: the server's first permitted key at the
    /// ticket's kvno is not of the ticket's enctype, or no key at it is of a permitted enctype.
    /// MIT `KRB5_KDB_NO_PERMITTED_KEY` (`lib/krb5/error_tables/kdb5_err.et:72-72`): the code and text.
    /// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:171-178`): returns it for a ticket whose enctype is not similar to the key's, and `keytab_fetch_error` passes it on.
    #[error("No matching key in entry having a permitted enctype")]
    KdbNoPermittedKey,
    /// A checksum type the library does not implement.
    /// MIT `KRB5_PROG_SUMTYPE_NOSUPP` (`krb5_err.et:207-207`): the code and text, which `read_krbsafe` returns for a KRB-SAFE's.
    #[error("Program lacks support for checksum type")]
    ProgSumtypeNosupp,
    /// An AP-REQ's session key or subkey is of an enctype the acceptor does not permit; the
    /// text names it.
    /// MIT `negotiate_etype` (`lib/krb5/krb/rd_req_dec.c:878-886`): `KRB5_NOPERM_ETYPE` with the enctype's name.
    #[error("{0}")]
    NopermEtype(String),
    /// A real preauthentication type failed, the password's read among them: MIT's
    /// `KRB5_PREAUTH_FAILED`, its message wrapping the cause.
    /// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:716-723`): with no real type answered, the first type's failure is wrapped as "Pre-authentication failed: \<its message\>".
    #[error("Pre-authentication failed: {0}")]
    PreauthFailed(Box<Error>),
    /// Reply too short to classify.
    #[error("KDC reply truncated")]
    TruncatedReply,
    /// The KDC's error carried PA-FX-FAST and this request had an armor cache but no armor key.
    /// MIT `k5_upgrade_to_fast_p` (`lib/krb5/krb/fast.c:677-688`): that answer restarts the exchange with FAST. `as_exchange` does not return it.
    #[error("FAST upgrade")]
    FastUpgrade,
    /// Encrypted timestamp is off for the client realm.
    /// MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:68-73`): `KRB5_PREAUTH_FAILED`, "Encrypted timestamp is disabled".
    #[error("Encrypted timestamp is disabled")]
    EnctsDisabled,
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
            Self::ReplyIntegrity => Self::ReplyIntegrity,
            Self::NonceMismatch => Self::NonceMismatch,
            Self::ReplyMismatch(s) => Self::ReplyMismatch(s.clone()),
            Self::Referral => Self::Referral,
            Self::NoEtype => Self::NoEtype,
            Self::ConfigEtypeNosupp => Self::ConfigEtypeNosupp,
            Self::ProgEtypeNosupp => Self::ProgEtypeNosupp,
            Self::BadEnctype => Self::BadEnctype,
            Self::KdbNoPermittedKey => Self::KdbNoPermittedKey,
            Self::ProgSumtypeNosupp => Self::ProgSumtypeNosupp,
            Self::NopermEtype(s) => Self::NopermEtype(s.clone()),
            Self::PreauthFailed(e) => Self::PreauthFailed(e.clone()),
            Self::TruncatedReply => Self::TruncatedReply,
            Self::FastUpgrade => Self::FastUpgrade,
            Self::EnctsDisabled => Self::EnctsDisabled,
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
    #[allow(clippy::needless_pass_by_value)] // owns the `io::Error` from `map_err`
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
        match e {
            krb5_crypto::Error::BadEnctype(_) => Self::BadEnctype,
            e => Self::Crypto(e.to_string()),
        }
    }
}

impl From<krb5_asn1::Error> for Error {
    fn from(e: krb5_asn1::Error) -> Self {
        decode_error(&e)
    }
}

/// A decode failure as the caller of MIT's decoder sees it.
/// MIT `krb5_version` (`lib/krb5/asn.1/asn1_k_encode.c:30-30`): a pvno or vno that is not 5 fails the decode with KRB5KDC_ERR_BAD_PVNO, not an ASN.1 error.
fn decode_error(e: &krb5_asn1::Error) -> Error {
    let text = e.to_string();
    if text.contains("KRB5KDC_ERR_BAD_PVNO") {
        return Error::KrbError {
            code: krb5_types::err::BAD_PVNO,
            text: Some("Protocol version mismatch".into()),
        };
    }
    Error::Asn1(text)
}
