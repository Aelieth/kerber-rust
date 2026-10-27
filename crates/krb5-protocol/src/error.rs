use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// MIT refuses a des3 key as DesBadParity or DesWeakKey, not this.
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("asn1: {0}")]
    Asn1(String),
    // MIT: `k5_locate_server` (lib/krb5/os/locate_kdc.c:871-876)
    #[error("Cannot find KDC for realm")]
    RealmUnknown,
    // MIT: `locate_srv_conf_1` (lib/krb5/os/locate_kdc.c:319-320)
    #[error("Invalid argument")]
    InvalidArgument,
    // MIT: `profile_parse_boolean` (util/profile/prof_get.c:347-369)
    #[error("Invalid boolean value")]
    BadBoolean,
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
        /// E-text names an unknown server; without it, no message.
        text: Option<String>,
    },
    #[error("unexpected Kerberos PDU tag")]
    UnexpectedPdu,
    /// `KRB5KRB_AP_ERR_BAD_INTEGRITY`; kinit shows "Password incorrect".
    // MIT: `k5_kinit` (kinit.c:787-787)
    #[error("Decrypt integrity check failed")]
    ReplyIntegrity,
    #[error("AS/TGS nonce mismatch")]
    NonceMismatch,
    #[error("reply validation: {0}")]
    ReplyMismatch(String),
    // MIT: `verify_as_reply` (get_in_tkt.c:264-269)
    #[error("Clock skew too great in KDC reply")]
    KdcReplySkew,
    #[error("referral TGT cannot be used as the requested service ticket")]
    Referral,
    #[error("no mutually supported etype")]
    NoEtype,
    // MIT: `KRB5_CC_NOT_KTYPE` (krb5_err.et:268-268)
    #[error("No credentials found with supported encryption types")]
    CcNotKtype,
    // MIT: `KRB5_CONFIG_ETYPE_NOSUPP` (krb5_err.et:326-326)
    #[error("No supported encryption types (config file error?)")]
    ConfigEtypeNosupp,
    // MIT: `KRB5_PROG_ETYPE_NOSUPP` (krb5_err.et:204-204)
    #[error("Program lacks support for encryption type")]
    ProgEtypeNosupp,
    // MIT: `KRB5_BAD_ENCTYPE` (krb5_err.et:254-254)
    #[error("Bad encryption type")]
    BadEnctype,
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    #[error("DES key has bad parity")]
    DesBadParity,
    #[error("DES key is a weak key")]
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    DesWeakKey,
    // MIT: `KRB5_KDB_NO_PERMITTED_KEY` (lib/krb5/error_tables/kdb5_err.et:72-72)
    // MIT: `krb5_ktkdb_get_entry` (lib/kdb/keytab.c:171-178)
    #[error("No matching key in entry having a permitted enctype")]
    KdbNoPermittedKey,
    // MIT: `KRB5_PROG_SUMTYPE_NOSUPP` (krb5_err.et:207-207)
    #[error("Program lacks support for checksum type")]
    ProgSumtypeNosupp,
    /// The text names the unpermitted enctype, hence `{{0}}`.
    // MIT: `negotiate_etype` (lib/krb5/krb/rd_req_dec.c:878-886)
    #[error("{0}")]
    NopermEtype(String),
    // MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:716-723)
    #[error("Pre-authentication failed: {0}")]
    PreauthFailed(Box<Error>),
    // MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:716-723)
    #[error("Generic preauthentication failure")]
    PreauthNoMech,
    #[error("KDC reply truncated")]
    TruncatedReply,
    // MIT: `k5_upgrade_to_fast_p` (lib/krb5/krb/fast.c:677-688)
    #[error("FAST upgrade")]
    FastUpgrade(Box<crate::AsRestart>),
    // MIT: `is_referral` (lib/krb5/krb/get_in_tkt.c:1450-1458)
    #[error("KRB-ERROR {code}: client referral to {realm}")]
    ClientReferral {
        code: i32,
        realm: String,
        restart: Box<crate::AsRestart>,
    },
    // MIT: `encts_process` (lib/krb5/krb/preauth_encts.c:68-73)
    #[error("Encrypted timestamp is disabled")]
    EnctsDisabled,
    #[error("{0}")]
    Message(String),
    #[error("{text}")]
    PkinitReply { code: i64, text: String },
    // MIT: `get_as_key_keytab` (lib/krb5/krb/gic_keytab.c:33-80)
    /// The errno or `KRB5_KEYTAB_BADVNO`, plus text.
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
            Self::RealmUnknown => Self::RealmUnknown,
            Self::InvalidArgument => Self::InvalidArgument,
            Self::BadBoolean => Self::BadBoolean,
            Self::UnexpectedPdu => Self::UnexpectedPdu,
            Self::ReplyIntegrity => Self::ReplyIntegrity,
            Self::NonceMismatch => Self::NonceMismatch,
            Self::ReplyMismatch(s) => Self::ReplyMismatch(s.clone()),
            Self::KdcReplySkew => Self::KdcReplySkew,
            Self::Referral => Self::Referral,
            Self::NoEtype => Self::NoEtype,
            Self::CcNotKtype => Self::CcNotKtype,
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
            Self::FastUpgrade(r) => Self::FastUpgrade(r.clone()),
            Self::ClientReferral {
                code,
                realm,
                restart,
            } => Self::ClientReferral {
                code: *code,
                realm: realm.clone(),
                restart: restart.clone(),
            },
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
/// A pvno other than 5 is `BAD_PVNO`, not an ASN.1 error.
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
