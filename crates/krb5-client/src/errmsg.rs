use std::fmt;
use std::io;
use std::path::Path;

// MIT: `default_com_err_proc` (com_err.c:47-96)
#[macro_export]
macro_rules! com_err {
    ($prog:expr, $err:expr, $($ctx:tt)*) => {{
        eprintln!("{}: {} {}", $prog, $err.table_text(), format_args!($($ctx)*));
    }};
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Krb5Error {
    pub code: Code,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Kdc(i32),
    BadIntegrity,
    FccNofile,
    FccPerm,
    CcNotfound,
    CcUnknownType,
    KtUnknownType,
    WrongPrinc,
    TktInvalid,
    KdcUnreach,
    RealmUnknown,
    ParseMalformed,
    NoDefRealm,
    Profile(krb5_config::ProfileError),
    FccInternal,
    KdcrepModified,
    KdcrepSkew,
    CcIo,
    CcFormat,
    CcBadVno,
    KcmNoServer,
    Enoent,
    Einval,
    PreauthFailed,
    PwdInterrupted,
    Other,
}

impl fmt::Display for Krb5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Krb5Error {}

impl Krb5Error {
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn of(code: Code) -> Self {
        Self::new(code, code_text(code))
    }

    #[must_use]
    pub fn table_text(&self) -> String {
        match self.code {
            Code::Kdc(n) => kdc_error_text(n),
            Code::Other => self.message.clone(),
            code => code_text(code).to_owned(),
        }
    }

    // MIT: `k5_sendto_kdc` (sendto_kdc.c:523-529)
    #[must_use]
    pub fn from_protocol(e: &krb5_protocol::Error, realm: &str) -> Self {
        match e {
            krb5_protocol::Error::KrbError { code, .. }
            | krb5_protocol::Error::ClientReferral { code, .. } => {
                Self::new(Code::Kdc(*code), kdc_error_text(*code))
            }
            krb5_protocol::Error::PreauthFailed(inner) => Self::new(
                Code::PreauthFailed,
                format!("Pre-authentication failed: {inner}"),
            ),
            krb5_protocol::Error::PreauthNoMech => Self::new(Code::PreauthFailed, e.to_string()),
            krb5_protocol::Error::ReplyIntegrity => Self::of(Code::BadIntegrity),
            // MIT: `krb5_ktfileint_open` (lib/krb5/keytab/kt_file.c:730-808)
            krb5_protocol::Error::Keytab { code: 2, text } => Self::new(Code::Enoent, text.clone()),
            krb5_protocol::Error::InvalidArgument => Self::of(Code::Einval),
            krb5_protocol::Error::Io { .. } => Self::new(
                Code::KdcUnreach,
                format!("Cannot contact any KDC for realm '{realm}'"),
            ),
            other => Self::new(Code::Other, other.to_string()),
        }
    }

    // MIT: `verify_as_reply` (lib/krb5/krb/get_in_tkt.c:206-272)
    // MIT: `init_creds_step_reply` (get_in_tkt.c:1762-1766)
    // A KDC error, code 60 included, is the table text; the e-text rewrite is TGS-only.
    // MIT: `krb5_init_creds_step` (get_in_tkt.c:1936-1946)
    #[must_use]
    pub fn from_as(e: &krb5_protocol::Error, client: &str, realm: &str) -> Self {
        use krb5_protocol::Error as E;
        if let E::KrbError {
            code: krb5_types::err::C_PRINCIPAL_UNKNOWN,
            ..
        } = e
        {
            return Self::new(
                Code::Kdc(krb5_types::err::C_PRINCIPAL_UNKNOWN),
                format!("Client '{client}' not found in Kerberos database"),
            );
        }
        match e {
            E::KdcReplySkew => Self::of(Code::KdcrepSkew),
            E::NonceMismatch | E::ReplyMismatch(_) | E::Referral => Self::of(Code::KdcrepModified),
            E::EnctsDisabled | E::PreauthNoMech => Self::new(Code::PreauthFailed, e.to_string()),
            _ => Self::from_protocol(e, realm),
        }
    }

    // MIT: `krb5int_process_tgs_reply` (lib/krb5/krb/gc_via_tkt.c:193-216)
    // An unknown server's error with e-text sets the message "Server <the error's server> not found
    // in Kerberos database"; a generic error with e-text sets "KDC returned error string:
    // \<text\>".
    #[must_use]
    pub fn from_tgs(e: &krb5_protocol::Error, realm: &str) -> Self {
        use krb5_protocol::Error as E;
        if let krb5_protocol::Error::KrbError {
            code: krb5_types::err::S_PRINCIPAL_UNKNOWN,
            text: Some(t),
        } = e
            && !t.is_empty()
        {
            return Self::new(Code::Kdc(krb5_types::err::S_PRINCIPAL_UNKNOWN), t.clone());
        }
        if let krb5_protocol::Error::KrbError {
            code,
            text: Some(t),
        } = e
            && *code == krb5_types::err::GENERIC
            && !t.is_empty()
        {
            return Self::new(Code::Kdc(*code), format!("KDC returned error string: {t}"));
        }
        match e {
            // MIT: `krb5int_fast_process_response` (lib/krb5/krb/fast.c:534-546)
            // These two replies set their own text.
            E::ReplyMismatch(m)
                if m == "Ticket modified in KDC reply"
                    || m.starts_with("FAST response missing finish message") =>
            {
                Self::new(Code::KdcrepModified, m.clone())
            }
            // MIT: `krb5int_process_tgs_reply` (lib/krb5/krb/gc_via_tkt.c:225-306)
            E::NonceMismatch => Self::of(Code::KdcrepModified),
            E::ReplyMismatch(m) if m != "host realm unknown" => Self::of(Code::KdcrepModified),
            // MIT: `step_referrals` (lib/krb5/krb/get_creds.c:561-583)
            E::Referral => Self::of(Code::KdcUnreach),
            _ => Self::from_protocol(e, realm),
        }
    }

    #[must_use]
    pub fn from_sname(e: &krb5_config::SnameError) -> Self {
        match e {
            krb5_config::SnameError::UnsupportedNameType => Self::new(Code::Other, e.to_string()),
            krb5_config::SnameError::NoDefaultRealm => Self::of(Code::NoDefRealm),
            krb5_config::SnameError::Name(_) => Self::of(Code::ParseMalformed),
        }
    }

    // MIT: `krb5_cc_default` (ccdefault.c:48-53)
    #[must_use]
    pub fn from_ccname(e: &krb5_config::Error) -> Self {
        match e {
            krb5_config::Error::Ccache(m) if m == krb5_config::KRB5_CC_UNKNOWN_TYPE => {
                Self::of(Code::CcUnknownType)
            }
            krb5_config::Error::Ccache(_) => Self::of(Code::FccInternal),
            other => Self::new(Code::Other, other.to_string()),
        }
    }

    // MIT: `krb5_os_localaddr` (lib/krb5/os/localaddr.c:1311-1315)
    #[must_use]
    pub fn from_local_addresses(e: &krb5_protocol::Error) -> Self {
        match e {
            krb5_protocol::Error::Io { message, .. } => Self::new(Code::Other, message.clone()),
            other => Self::new(Code::Other, other.to_string()),
        }
    }

    #[must_use]
    pub fn from_os(e: &io::Error) -> Self {
        let text = e.to_string();
        let text = text
            .rsplit_once(" (os error ")
            .map_or(text.as_str(), |(t, _)| t)
            .to_owned();
        Self::new(Code::Other, text)
    }

    // MIT: `kcmio_unix_socket_connect` (cc_kcm.c:313-330)
    #[must_use]
    pub fn from_kcm(e: &io::Error) -> Self {
        if krb5_protocol::kcm_no_server(e) {
            Self::of(Code::KcmNoServer)
        } else if e.raw_os_error().is_some() {
            Self::from_os(e)
        } else {
            Self::new(Code::Other, e.to_string())
        }
    }

    // MIT: `set_errmsg_filename` (cc_file.c:117-124)
    // "\<message\> (filename: \<path\>)".
    // MIT: `open_cache_file` (cc_file.c:347-352)
    // A lock failure is the lock's errno, not `interpret_errno`'s code.
    #[must_use]
    pub fn from_file_cache(e: &io::Error, path: &Path) -> Self {
        let code = match krb5_protocol::FccFailure::of(e) {
            Some(krb5_protocol::FccFailure::Lock(_)) => Code::Other,
            Some(krb5_protocol::FccFailure::Format) => Code::CcFormat,
            Some(krb5_protocol::FccFailure::BadVersion) => Code::CcBadVno,
            Some(krb5_protocol::FccFailure::ShortWrite) => Code::CcIo,
            None => interpret_errno(e),
        };
        let text = if code == Code::Other {
            e.to_string()
        } else {
            code_text(code).to_owned()
        };
        Self::new(code, format!("{text} (filename: {})", path.display()))
    }

    // MIT: `fcc_replace` (cc_file.c:1286-1337)
    #[must_use]
    pub fn from_cache_write(e: &io::Error) -> Self {
        match interpret_errno(e) {
            Code::Other => Self::new(Code::Other, e.to_string()),
            code => Self::of(code),
        }
    }
}

// MIT: `interpret_errno` (cc_file.c:1346-1389)
fn interpret_errno(e: &io::Error) -> Code {
    use nix::errno::Errno;
    let Some(n) = e.raw_os_error() else {
        return match e.kind() {
            io::ErrorKind::NotFound => Code::FccNofile,
            io::ErrorKind::PermissionDenied => Code::FccPerm,
            _ => Code::Other,
        };
    };
    match Errno::from_raw(n) {
        Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP | Errno::ENAMETOOLONG => Code::FccNofile,
        Errno::EPERM | Errno::EACCES | Errno::EISDIR | Errno::EROFS => Code::FccPerm,
        Errno::EINVAL | Errno::EEXIST | Errno::EFAULT | Errno::EBADF | Errno::EWOULDBLOCK => {
            Code::FccInternal
        }
        _ => Code::CcIo,
    }
}

fn code_text(code: Code) -> &'static str {
    match code {
        Code::Kdc(_) | Code::Other => "Unknown code",
        // MIT: `KRB5KRB_AP_ERR_BAD_INTEGRITY` (lib/krb5/error_tables/krb5_err.et:74-74)
        Code::BadIntegrity => "Decrypt integrity check failed",
        // MIT: `KRB5_FCC_NOFILE` (lib/krb5/error_tables/krb5_err.et:263-263)
        Code::FccNofile => "No credentials cache found",
        // MIT: `KRB5_FCC_PERM` (krb5_err.et:262-262)
        Code::FccPerm => "Credentials cache permissions incorrect",
        // MIT: `KRB5_CC_NOTFOUND` (lib/krb5/error_tables/krb5_err.et:191-191)
        Code::CcNotfound => "Matching credential not found",
        // MIT: `KRB5_CC_UNKNOWN_TYPE` (lib/krb5/error_tables/krb5_err.et:190-190)
        Code::CcUnknownType => "Unknown credential cache type",
        // MIT: `KRB5_KT_UNKNOWN_TYPE` (krb5_err.et:244-244)
        Code::KtUnknownType => "Unknown Key table type",
        // MIT: `KRB5KRB_AP_WRONG_PRINC` (krb5_err.et:196-196)
        Code::WrongPrinc => "Wrong principal in request",
        // MIT: `KRB5KRB_AP_ERR_TKT_INVALID` (lib/krb5/error_tables/krb5_err.et:197-197)
        Code::TktInvalid => "Ticket has invalid flag set",
        // MIT: `KRB5_KDC_UNREACH` (lib/krb5/error_tables/krb5_err.et:211-211)
        Code::KdcUnreach => "Cannot contact any KDC for requested realm",
        // MIT: `KRB5_REALM_UNKNOWN` (lib/krb5/error_tables/krb5_err.et:209-209)
        Code::RealmUnknown => "Cannot find KDC for requested realm",
        // MIT: `KRB5_PARSE_MALFORMED` (krb5_err.et:181-181)
        Code::ParseMalformed => "Malformed representation of principal",
        // MIT: `KRB5_CONFIG_NODEFREALM` (krb5_err.et:310-310)
        Code::NoDefRealm => "Configuration file does not specify default realm",
        Code::Profile(p) => p.text(),
        // MIT: `KRB5_FCC_INTERNAL` (krb5_err.et:264-264)
        Code::FccInternal => "Internal credentials cache error",
        // MIT: `KRB5_KDCREP_MODIFIED` (lib/krb5/error_tables/krb5_err.et:200-200)
        Code::KdcrepModified => "KDC reply did not match expectations",
        // MIT: `KRB5_KDCREP_SKEW` (krb5_err.et:201-201)
        Code::KdcrepSkew => "Clock skew too great in KDC reply",
        // MIT: `KRB5_CC_IO` (krb5_err.et:261-261)
        Code::CcIo => "Credentials cache I/O operation failed",
        // MIT: `KRB5_CC_FORMAT` (lib/krb5/error_tables/krb5_err.et:267-267)
        Code::CcFormat => "Bad format in credentials cache",
        // MIT: `KRB5_CCACHE_BADVNO` (krb5_err.et:292-292)
        Code::CcBadVno => "Unsupported credentials cache format version number",
        // MIT: `KRB5_KCM_NO_SERVER` (lib/krb5/error_tables/k5e1_err.et:44-44)
        Code::KcmNoServer => "No KCM server found",
        Code::Enoent => "No such file or directory",
        Code::Einval => "Invalid argument",
        // MIT: `KRB5_PREAUTH_FAILED` (lib/krb5/error_tables/krb5_err.et:287-287)
        Code::PreauthFailed => "Generic preauthentication failure",
        // MIT: `KRB5_LIBOS_PWDINTR` (lib/krb5/error_tables/krb5_err.et:178-178)
        Code::PwdInterrupted => "Password read interrupted",
    }
}

#[must_use]
pub fn kdc_error_text(code: i32) -> String {
    let text = match code {
        0 => "No error",
        1 => "Client's entry in database has expired",
        2 => "Server's entry in database has expired",
        3 => "Requested protocol version not supported",
        4 => "Client's key is encrypted in an old master key",
        5 => "Server's key is encrypted in an old master key",
        6 => "Client not found in Kerberos database",
        7 => "Server not found in Kerberos database",
        8 => "Principal has multiple entries in Kerberos database",
        9 => "Client or server has a null key",
        10 => "Ticket is ineligible for postdating",
        11 => "Requested effective lifetime is negative or too short",
        12 => "KDC policy rejects request",
        13 => "KDC can't fulfill requested option",
        14 => "KDC has no support for encryption type",
        15 => "KDC has no support for checksum type",
        16 => "KDC has no support for padata type",
        17 => "KDC has no support for transited type",
        18 => "Client's credentials have been revoked",
        19 => "Credentials for server have been revoked",
        20 => "TGT has been revoked",
        21 => "Client not yet valid - try again later",
        22 => "Server not yet valid - try again later",
        23 => "Password has expired",
        24 => "Preauthentication failed",
        25 => "Additional pre-authentication required",
        26 => "Requested server and ticket don't match",
        27 => "Server principal valid for user2user only",
        28 => "KDC policy rejects transited path",
        29 => "A service is not available that is required to process the request",
        31 => "Decrypt integrity check failed",
        32 => "Ticket expired",
        33 => "Ticket not yet valid",
        34 => "Request is a replay",
        35 => "The ticket isn't for us",
        36 => "Ticket/authenticator don't match",
        37 => "Clock skew too great",
        38 => "Incorrect net address",
        39 => "Protocol version mismatch",
        40 => "Invalid message type",
        41 => "Message stream modified",
        42 => "Message out of order",
        43 => "Illegal cross-realm ticket",
        44 => "Key version is not available",
        45 => "Service key not available",
        46 => "Mutual authentication failed",
        47 => "Incorrect message direction",
        48 => "Alternative authentication method required",
        49 => "Incorrect sequence number in message",
        50 => "Inappropriate type of checksum in message",
        51 => "Policy rejects transited path",
        52 => "Response too big for UDP, retry with TCP",
        60 => "Generic error (see e-text)",
        61 => "Field is too long for this implementation",
        62 => "Client not trusted",
        63 => "KDC not trusted",
        64 => "Invalid signature",
        65 => "Key parameters not accepted",
        66 => "Certificate mismatch",
        67 => "No ticket granting ticket",
        68 => "Realm not local to KDC",
        69 => "User to user required",
        70 => "Can't verify certificate",
        71 => "Invalid certificate",
        72 => "Revoked certificate",
        73 => "Revocation status unknown",
        74 => "Revocation status unavailable",
        75 => "Client name mismatch",
        76 => "KDC name mismatch",
        77 => "Inconsistent key purpose",
        78 => "Digest in certificate not accepted",
        79 => "Checksum must be included",
        80 => "Digest in signed-data not accepted",
        81 => "Public key encryption not supported",
        85 => "The IAKERB proxy could not find a KDC",
        86 => "The KDC did not respond to the IAKERB proxy",
        90 => "Preauthentication expired",
        91 => "More preauthentication data is required",
        93 => "An unsupported critical FAST option was requested",
        _ => return format!("KRB5 error code {code}"),
    };
    text.to_owned()
}
