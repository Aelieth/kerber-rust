//! Protocol errors.

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A des3 key MIT refuses is DesBadParity or DesWeakKey, not this.
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("asn1: {0}")]
    Asn1(String),
    #[error("transport: {message}")]
    Io {
        message: String,
        kind: io::ErrorKind,
        retryable: bool,
    },
    #[error("KRB-ERROR {code}{}", text.as_ref().map(|t| format!(": {t}")).unwrap_or_default())]
    KrbError {
        code: i32,
        // MIT: `krb5int_process_tgs_reply` (lib/krb5/krb/gc_via_tkt.c:195-216)
        /// With e-text, an unknown server is named; without it, no message is set.
        text: Option<String>,
    },
    #[error("unexpected Kerberos PDU tag")]
    UnexpectedPdu,
    /// KRB5KRB_AP_ERR_BAD_INTEGRITY. kinit reports it as "Password incorrect".
    // MIT: `k5_kinit` (kinit.c:787-787)
    #[error("Decrypt integrity check failed")]
    ReplyIntegrity,
    #[error("AS/TGS nonce mismatch")]
    NonceMismatch,
    #[error("reply validation: {0}")]
    ReplyMismatch(String),
    /// An AS starttime outside skew, only when kdc_timesync is off.
    // MIT: `verify_as_reply` (get_in_tkt.c:264-269)
    /// KRB5_KDCREP_SKEW.
    #[error("Clock skew too great in KDC reply")]
    KdcReplySkew,
    #[error("referral TGT cannot be used as the requested service ticket")]
    Referral,
    #[error("no mutually supported etype")]
    NoEtype,
    /// An enctype this client has, but not one the request asked for.
    // MIT: `KRB5_CONFIG_ETYPE_NOSUPP` (krb5_err.et:326-326)
    #[error("No supported encryption types (config file error?)")]
    ConfigEtypeNosupp,
    /// No enctype this client has.
    // MIT: `KRB5_PROG_ETYPE_NOSUPP` (krb5_err.et:204-204)
    #[error("Program lacks support for encryption type")]
    ProgEtypeNosupp,
    /// The ciphertext's enctype is not the key's.
    // MIT: `KRB5_BAD_ENCTYPE` (krb5_err.et:254-254)
    #[error("Bad encryption type")]
    BadEnctype,
    /// Even parity on a des3 key, wherever that key is used.
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    /// KRB5DES_BAD_KEYPAR, from every use of that key.
    #[error("DES key has bad parity")]
    DesBadParity,
    #[error("DES key is a weak key")]
    /// A weak or semi-weak DES key among the three.
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    /// KRB5DES_WEAK_KEY.
    DesWeakKey,
    /// No permitted key at the ticket's kvno is the ticket's enctype.
    // MIT: `KRB5_KDB_NO_PERMITTED_KEY` (lib/krb5/error_tables/kdb5_err.et:72-72)
    // MIT: `krb5_ktkdb_get_entry` (lib/kdb/keytab.c:171-178)
    #[error("No matching key in entry having a permitted enctype")]
    KdbNoPermittedKey,
    // MIT: `KRB5_PROG_SUMTYPE_NOSUPP` (krb5_err.et:207-207)
    /// KRB5_PROG_SUMTYPE_NOSUPP, for a KRB-SAFE's unknown checksum.
    #[error("Program lacks support for checksum type")]
    ProgSumtypeNosupp,
    /// The text names the enctype the acceptor does not permit.
    // MIT: `negotiate_etype` (lib/krb5/krb/rd_req_dec.c:878-886)
    /// KRB5_NOPERM_ETYPE.
    #[error("{0}")]
    NopermEtype(String),
    /// A real preauth failure, its message wrapped around the cause.
    // MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:716-723)
    /// With no real type answered, the first failure is that message.
    #[error("Pre-authentication failed: {0}")]
    PreauthFailed(Box<Error>),
    // MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:716-723)
    #[error("Generic preauthentication failure")]
    PreauthNoMech,
    #[error("KDC reply truncated")]
    TruncatedReply,
    /// The KDC offered FAST, and this request had armor but no armor key.
    // MIT: `k5_upgrade_to_fast_p` (lib/krb5/krb/fast.c:677-688)
    /// The exchange restarts. as_exchange does not return this.
    #[error("FAST upgrade")]
    FastUpgrade,
    /// Encrypted timestamp is off for this realm.
    // MIT: `encts_process` (lib/krb5/krb/preauth_encts.c:68-73)
    #[error("Encrypted timestamp is disabled")]
    EnctsDisabled,
    /// Shown as itself. PreauthFailed wraps it when a module fails.
    #[error("{0}")]
    Message(String),
    #[error("{text}")]
    PkinitReply { code: i64, text: String },
    /// An unreadable keytab, once a key is asked of it.
    // MIT: `get_as_key_keytab` (lib/krb5/krb/gic_keytab.c:33-80)
    /// `code` is the errno or KRB5_KEYTAB_BADVNO; `text` is its message.
    #[error("{text}")]
    Keytab { code: i64, text: String },
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
            Self::KdcReplySkew => Self::KdcReplySkew,
            Self::Referral => Self::Referral,
            Self::NoEtype => Self::NoEtype,
            Self::ConfigEtypeNosupp => Self::ConfigEtypeNosupp,
            Self::ProgEtypeNosupp => Self::ProgEtypeNosupp,
            Self::BadEnctype => Self::BadEnctype,
            Self::DesBadParity => Self::DesBadParity,
            Self::DesWeakKey => Self::DesWeakKey,
            Self::KdbNoPermittedKey => Self::KdbNoPermittedKey,
            Self::ProgSumtypeNosupp => Self::ProgSumtypeNosupp,
            Self::NopermEtype(s) => Self::NopermEtype(s.clone()),
            Self::PreauthFailed(e) => Self::PreauthFailed(e.clone()),
            Self::PreauthNoMech => Self::PreauthNoMech,
            Self::TruncatedReply => Self::TruncatedReply,
            Self::FastUpgrade => Self::FastUpgrade,
            Self::EnctsDisabled => Self::EnctsDisabled,
            Self::Message(s) => Self::Message(s.clone()),
            Self::PkinitReply { code, text } => Self::PkinitReply {
                code: *code,
                text: text.clone(),
            },
            Self::Keytab { code, text } => Self::Keytab {
                code: *code,
                text: text.clone(),
            },
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
    #[must_use]
    pub(crate) const fn preauth_no_mech() -> Self {
        Self::PreauthNoMech
    }

    /// A transport failure, or SVC_UNAVAILABLE or RESPONSE_TOO_BIG.
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

    #[must_use]
    pub fn transport_msg(msg: impl Into<String>) -> Self {
        Self::Io {
            message: msg.into(),
            kind: io::ErrorKind::Other,
            retryable: true,
        }
    }

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
            krb5_crypto::Error::DesBadParity => Self::DesBadParity,
            krb5_crypto::Error::DesWeakKey => Self::DesWeakKey,
            e => Self::Crypto(e.to_string()),
        }
    }
}

impl From<krb5_asn1::Error> for Error {
    fn from(e: krb5_asn1::Error) -> Self {
        decode_error(&e)
    }
}

// MIT: `krb5_version` (lib/krb5/asn.1/asn1_k_encode.c:30-30)
/// A pvno other than 5 is BAD_PVNO, not an ASN.1 error.
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
