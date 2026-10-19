//! MIT's error texts as the client tools print them: the `krb5_err.et` table and the messages the
//! library sets in their place (`krb5_get_error_message`).

use std::fmt;
use std::io;
use std::path::Path;

/// `com_err` with its default hook, as `kdestroy` and `kswitch` keep it: `prog: `, the error's
/// table text, a space, the context, then `\n`, as Fedora's MIT prints it (built with the system
/// com_err). MIT's own com_err, which the gates' MIT image is built with, ends the line `\r\n`.
/// MIT `default_com_err_proc` (`com_err.c:47-96`): `error_message(code)`, not the extended
/// message.
#[macro_export]
macro_rules! com_err {
    ($prog:expr, $err:expr, $($ctx:tt)*) => {{
        eprintln!("{}: {} {}", $prog, $err.table_text(), format_args!($($ctx)*));
    }};
}

/// A failure carrying the MIT error code the tools branch on and MIT's whole message for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Krb5Error {
    /// The code.
    pub code: Code,
    /// `krb5_get_error_message`: the table text, or the message the library set instead.
    pub message: String,
}

/// The MIT error codes the client tools tell apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// A KDC error (`ERROR_TABLE_BASE_krb5` plus the RFC 4120 code).
    Kdc(i32),
    /// `KRB5KRB_AP_ERR_BAD_INTEGRITY`.
    BadIntegrity,
    /// `KRB5_FCC_NOFILE`.
    FccNofile,
    /// `KRB5_FCC_PERM`.
    FccPerm,
    /// `KRB5_CC_NOTFOUND`.
    CcNotfound,
    /// `KRB5_CC_UNKNOWN_TYPE`.
    CcUnknownType,
    /// `KRB5_KT_UNKNOWN_TYPE`.
    KtUnknownType,
    /// `KRB5KRB_AP_WRONG_PRINC`.
    WrongPrinc,
    /// `KRB5KRB_AP_ERR_TKT_INVALID`.
    TktInvalid,
    /// `KRB5_KDC_UNREACH`.
    KdcUnreach,
    /// `KRB5_REALM_UNKNOWN`.
    RealmUnknown,
    /// `KRB5_PARSE_MALFORMED`.
    ParseMalformed,
    /// `KRB5_CONFIG_NODEFREALM`.
    NoDefRealm,
    /// A profile MIT's `krb5_init_context` refuses.
    Profile(krb5_config::ProfileError),
    /// `KRB5_FCC_INTERNAL`.
    FccInternal,
    /// `KRB5_KDCREP_MODIFIED`.
    KdcrepModified,
    /// `KRB5_KDCREP_SKEW`.
    KdcrepSkew,
    /// `KRB5_CC_IO`.
    CcIo,
    /// `KRB5_CC_FORMAT`.
    CcFormat,
    /// `KRB5_CCACHE_BADVNO`.
    CcBadVno,
    /// `KRB5_KCM_NO_SERVER`.
    KcmNoServer,
    /// errno `ENOENT`.
    Enoent,
    /// errno `EINVAL`.
    Einval,
    /// `KRB5_PREAUTH_FAILED`.
    PreauthFailed,
    /// `KRB5_LIBOS_PWDINTR`: a password prompt that `SIGINT` interrupted.
    PwdInterrupted,
    /// Any other failure, under its own text.
    Other,
}

impl fmt::Display for Krb5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Krb5Error {}

impl Krb5Error {
    /// A failure with `code` and `message`.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The code under its table text.
    #[must_use]
    pub fn of(code: Code) -> Self {
        Self::new(code, code_text(code))
    }

    /// MIT `error_message`: the code's table text, without the message the library set in its
    /// place; what `com_err`'s default hook prints.
    #[must_use]
    pub fn table_text(&self) -> String {
        match self.code {
            Code::Kdc(n) => kdc_error_text(n),
            Code::Other => self.message.clone(),
            code => code_text(code).to_owned(),
        }
    }

    /// MIT `krb5_get_error_message` of a protocol failure; `realm` names the realm whose KDC was
    /// asked. A KDC error is its table text. The e-text rewrite of a generic error is TGS-only,
    /// in [`Self::from_tgs`].
    /// MIT `k5_sendto_kdc` (`sendto_kdc.c:523-529`): no answer is "Cannot contact any KDC for
    /// realm '\<realm\>'".
    #[must_use]
    pub fn from_protocol(e: &krb5_protocol::Error, realm: &str) -> Self {
        match e {
            krb5_protocol::Error::KrbError { code, .. } => {
                Self::new(Code::Kdc(*code), kdc_error_text(*code))
            }
            krb5_protocol::Error::PreauthFailed(inner) => Self::new(
                Code::PreauthFailed,
                format!("Pre-authentication failed: {inner}"),
            ),
            krb5_protocol::Error::ReplyIntegrity => Self::of(Code::BadIntegrity),
            // MIT `krb5_ktfileint_open` (`kt_file.c:753-760`): a keytab file that is not there is `ENOENT` with its own message.
            krb5_protocol::Error::Keytab { code: 2, text } => Self::new(Code::Enoent, text.clone()),
            krb5_protocol::Error::Io { .. } => Self::new(
                Code::KdcUnreach,
                format!("Cannot contact any KDC for realm '{realm}'"),
            ),
            other => Self::new(Code::Other, other.to_string()),
        }
    }

    /// [`Self::from_protocol`] for an AS exchange.
    /// MIT `verify_as_reply` (`get_in_tkt.c:257-269`): skew is `KRB5_KDCREP_SKEW` and any other
    /// mismatch is `KRB5_KDCREP_MODIFIED`, with no message set, so the table text is what prints.
    /// MIT `init_creds_step_reply` (`get_in_tkt.c:1762-1766`): a KDC error, including code 60, is the
    /// table text. The e-text rewrite is TGS-only.
    /// MIT `krb5_init_creds_step` (`get_in_tkt.c:1936-1946`): an unknown client is "Client
    /// '\<client\>' not found in Kerberos database".
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
            E::EnctsDisabled => Self::new(Code::PreauthFailed, e.to_string()),
            _ => Self::from_protocol(e, realm),
        }
    }

    /// [`Self::from_protocol`] for a TGS exchange: an unknown server is the message the reply's
    /// processing set, which names the error's server, when the error came with e-text, else the
    /// table's text. A generic KDC error with e-text is that rewrite, not the table text.
    /// MIT `krb5int_process_tgs_reply` (`lib/krb5/krb/gc_via_tkt.c:193-216`): an unknown server's error with e-text sets the message "Server <the error's server> not found in Kerberos database"; a generic error with e-text sets "KDC returned error string: \<text\>".
    #[must_use]
    pub fn from_tgs(e: &krb5_protocol::Error, realm: &str) -> Self {
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
        Self::from_protocol(e, realm)
    }

    /// A host-based name that [`krb5_config::sname_to_principal`] or a candidate of
    /// [`krb5_config::CanonPrinc`] could not make: MIT's code for it, and
    /// `KRB5_PARSE_MALFORMED` for a name this port's principal names cannot hold.
    #[must_use]
    pub fn from_sname(e: &krb5_config::SnameError) -> Self {
        match e {
            krb5_config::SnameError::UnsupportedNameType => Self::new(Code::Other, e.to_string()),
            krb5_config::SnameError::NoDefaultRealm => Self::of(Code::NoDefRealm),
            krb5_config::SnameError::Name(_) => Self::of(Code::ParseMalformed),
        }
    }

    /// The failure of a cache name that does not resolve.
    /// MIT `krb5_cc_default` (`ccdefault.c:48-53`): a default name whose `%{token}` does not expand
    /// leaves no name, `KRB5_FCC_INTERNAL`; a type no cache is built for is `KRB5_CC_UNKNOWN_TYPE`.
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

    /// The failure of `krb5_os_localaddr`: the errno's text, as `com_err` prints it.
    /// MIT `krb5_os_localaddr` (`lib/krb5/os/localaddr.c:1311-1315`): the call returns the errno of a failed `getifaddrs`.
    #[must_use]
    pub fn from_local_addresses(e: &krb5_protocol::Error) -> Self {
        match e {
            krb5_protocol::Error::Io { message, .. } => Self::new(Code::Other, message.clone()),
            other => Self::new(Code::Other, other.to_string()),
        }
    }

    /// An OS error under its `strerror` text, as `com_err` prints an errno.
    #[must_use]
    pub fn from_os(e: &io::Error) -> Self {
        let text = e.to_string();
        let text = text
            .rsplit_once(" (os error ")
            .map_or(text.as_str(), |(t, _)| t)
            .to_owned();
        Self::new(Code::Other, text)
    }

    /// A KCM request's failure: no KCM daemon is `KRB5_KCM_NO_SERVER`, an OS error its errno.
    /// MIT `kcmio_unix_socket_connect` (`cc_kcm.c:313-330`): a socket that is not there, or a
    /// `kcm_socket` of `-`, is `KRB5_KCM_NO_SERVER`; any other failure to connect is its errno.
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

    /// A FILE cache's read or store failure, with the file name as MIT adds it.
    /// MIT `set_errmsg_filename` (`cc_file.c:117-124`): "\<message\> (filename: \<path\>)".
    /// MIT `open_cache_file` (`cc_file.c:347-352`): a lock failure is the lock's errno, not `interpret_errno`'s code.
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

    /// A cache file's write failure.
    /// MIT `fcc_replace` (`cc_file.c:1286-1337`): the error of the write that replaces a cache
    /// names no file.
    #[must_use]
    pub fn from_cache_write(e: &io::Error) -> Self {
        match interpret_errno(e) {
            Code::Other => Self::new(Code::Other, e.to_string()),
            code => Self::of(code),
        }
    }
}

/// The cache code of an I/O error: an OS error by its errno, any other by its kind, or none.
/// MIT `interpret_errno` (`cc_file.c:1346-1389`): a missing path is `KRB5_FCC_NOFILE`, a refused
/// one `KRB5_FCC_PERM`, a bad argument or descriptor `KRB5_FCC_INTERNAL`, the rest `KRB5_CC_IO`.
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

/// The table text of `code`.
fn code_text(code: Code) -> &'static str {
    match code {
        Code::Kdc(_) | Code::Other => "Unknown code",
        // MIT `KRB5KRB_AP_ERR_BAD_INTEGRITY` (`krb5_err.et:74-74`): the text.
        Code::BadIntegrity => "Decrypt integrity check failed",
        // MIT `KRB5_FCC_NOFILE` (`krb5_err.et:263-263`): the text.
        Code::FccNofile => "No credentials cache found",
        // MIT `KRB5_FCC_PERM` (`krb5_err.et:262-262`): the text.
        Code::FccPerm => "Credentials cache permissions incorrect",
        // MIT `KRB5_CC_NOTFOUND` (`krb5_err.et:191-191`): the text.
        Code::CcNotfound => "Matching credential not found",
        // MIT `KRB5_CC_UNKNOWN_TYPE` (`krb5_err.et:190-190`): the text.
        Code::CcUnknownType => "Unknown credential cache type",
        // MIT `KRB5_KT_UNKNOWN_TYPE` (`krb5_err.et:244-244`): the text.
        Code::KtUnknownType => "Unknown Key table type",
        // MIT `KRB5KRB_AP_WRONG_PRINC` (`krb5_err.et:196-196`): the text.
        Code::WrongPrinc => "Wrong principal in request",
        // MIT `KRB5KRB_AP_ERR_TKT_INVALID` (`krb5_err.et:197-197`): the text.
        Code::TktInvalid => "Ticket has invalid flag set",
        // MIT `KRB5_KDC_UNREACH` (`krb5_err.et:211-211`): the text.
        Code::KdcUnreach => "Cannot contact any KDC for requested realm",
        // MIT `KRB5_REALM_UNKNOWN` (`krb5_err.et:209-209`): the text.
        Code::RealmUnknown => "Cannot find KDC for requested realm",
        // MIT `KRB5_PARSE_MALFORMED` (`krb5_err.et:181-181`): the text.
        Code::ParseMalformed => "Malformed representation of principal",
        // MIT `KRB5_CONFIG_NODEFREALM` (`krb5_err.et:310-310`): the text.
        Code::NoDefRealm => "Configuration file does not specify default realm",
        Code::Profile(p) => p.text(),
        // MIT `KRB5_FCC_INTERNAL` (`krb5_err.et:264-264`): the text.
        Code::FccInternal => "Internal credentials cache error",
        // MIT `KRB5_KDCREP_MODIFIED` (`krb5_err.et:200-200`): the text.
        Code::KdcrepModified => "KDC reply did not match expectations",
        // MIT `KRB5_KDCREP_SKEW` (`krb5_err.et:201-201`): the text.
        Code::KdcrepSkew => "Clock skew too great in KDC reply",
        // MIT `KRB5_CC_IO` (`krb5_err.et:261-261`): the text.
        Code::CcIo => "Credentials cache I/O operation failed",
        // MIT `KRB5_CC_FORMAT` (`krb5_err.et:267-267`): the text.
        Code::CcFormat => "Bad format in credentials cache",
        // MIT `KRB5_CCACHE_BADVNO` (`krb5_err.et:292-292`): the text.
        Code::CcBadVno => "Unsupported credentials cache format version number",
        // MIT `KRB5_KCM_NO_SERVER` (`k5e1_err.et:44-44`): the text.
        Code::KcmNoServer => "No KCM server found",
        Code::Enoent => "No such file or directory",
        Code::Einval => "Invalid argument",
        // MIT `KRB5_PREAUTH_FAILED` (`krb5_err.et:287-287`): the text.
        Code::PreauthFailed => "Generic preauthentication failure",
        // MIT `KRB5_LIBOS_PWDINTR` (`krb5_err.et:178-178`): the text.
        Code::PwdInterrupted => "Password read interrupted",
    }
}

/// The text of a KDC error code.
/// The KDC codes' texts of MIT's `lib/krb5/error_tables/krb5_err.et`, whose unnamed slots read
/// "KRB5 error code N".
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
