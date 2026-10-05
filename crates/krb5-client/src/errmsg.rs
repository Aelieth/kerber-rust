//! MIT's error texts as the client tools print them: the `krb5_err.et` table and the messages the
//! library sets in their place (`krb5_get_error_message`).

use std::fmt;
use std::io;
use std::path::Path;

/// `com_err` with its default hook, as `kdestroy` and `kswitch` keep it: `prog: `, the error's
/// table text, a space, the context, then `\r\n`.
/// MIT `default_com_err_proc` (`com_err.c:47-96`): `error_message(code)`, not the extended
/// message, and a carriage return before the newline.
#[macro_export]
macro_rules! com_err {
    ($prog:expr, $err:expr, $($ctx:tt)*) => {{
        eprint!("{}: {} {}\r\n", $prog, $err.table_text(), format_args!($($ctx)*));
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
    /// `KRB5_CC_IO`.
    CcIo,
    /// errno `ENOENT`.
    Enoent,
    /// errno `EINVAL`.
    Einval,
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
    /// asked.
    /// MIT `krb5int_process_tgs_reply` (`gc_via_tkt.c:194-201`): a generic KDC error with an
    /// e-text is "KDC returned error string: \<text\>"; every other KDC error is its table text.
    /// MIT `k5_sendto_kdc` (`sendto_kdc.c:523-529`): no answer is "Cannot contact any KDC for
    /// realm '\<realm\>'".
    #[must_use]
    pub fn from_protocol(e: &krb5_protocol::Error, realm: &str) -> Self {
        match e {
            krb5_protocol::Error::KrbError { code, text } => {
                if *code == krb5_types::err::GENERIC
                    && let Some(t) = text.as_deref().filter(|t| !t.is_empty())
                {
                    return Self::new(Code::Kdc(*code), format!("KDC returned error string: {t}"));
                }
                Self::new(Code::Kdc(*code), kdc_error_text(*code))
            }
            krb5_protocol::Error::ReplyIntegrity => Self::of(Code::BadIntegrity),
            krb5_protocol::Error::Io { .. } => Self::new(
                Code::KdcUnreach,
                format!("Cannot contact any KDC for realm '{realm}'"),
            ),
            other => Self::new(Code::Other, other.to_string()),
        }
    }

    /// [`Self::from_protocol`] for an AS exchange.
    /// MIT `krb5_init_creds_step` (`get_in_tkt.c:1936-1946`): an unknown client is "Client
    /// '\<client\>' not found in Kerberos database".
    #[must_use]
    pub fn from_as(e: &krb5_protocol::Error, client: &str, realm: &str) -> Self {
        if let krb5_protocol::Error::KrbError {
            code: krb5_types::err::C_PRINCIPAL_UNKNOWN,
            ..
        } = e
        {
            return Self::new(
                Code::Kdc(krb5_types::err::C_PRINCIPAL_UNKNOWN),
                format!("Client '{client}' not found in Kerberos database"),
            );
        }
        Self::from_protocol(e, realm)
    }

    /// [`Self::from_protocol`] for a TGS exchange for `server`.
    /// MIT `krb5int_process_tgs_reply` (`gc_via_tkt.c:202-210`): an unknown server is "Server
    /// \<server\> not found in Kerberos database".
    #[must_use]
    pub fn from_tgs(e: &krb5_protocol::Error, server: &str, realm: &str) -> Self {
        if let krb5_protocol::Error::KrbError {
            code: krb5_types::err::S_PRINCIPAL_UNKNOWN,
            ..
        } = e
        {
            return Self::new(
                Code::Kdc(krb5_types::err::S_PRINCIPAL_UNKNOWN),
                format!("Server {server} not found in Kerberos database"),
            );
        }
        Self::from_protocol(e, realm)
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

    /// A FILE cache's read failure, with the file name as MIT adds it.
    /// MIT `set_errmsg_filename` (`cc_file.c:117-124`): "\<message\> (filename: \<path\>)".
    #[must_use]
    pub fn from_file_cache(e: &io::Error, path: &Path) -> Self {
        let code = interpret_errno(e);
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
        // MIT `KRB5_CC_IO` (`krb5_err.et:261-261`): the text.
        Code::CcIo => "Credentials cache I/O operation failed",
        Code::Enoent => "No such file or directory",
        Code::Einval => "Invalid argument",
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Live MIT 1.22.2: the texts the tools print.
    #[test]
    fn mit_texts_of_the_settled_failures() {
        let unknown = krb5_protocol::Error::KrbError {
            code: krb5_types::err::C_PRINCIPAL_UNKNOWN,
            text: Some("CLIENT_NOT_FOUND".into()),
        };
        assert_eq!(
            Krb5Error::from_as(&unknown, "nosuch@KERBER.TEST", "KERBER.TEST").message,
            "Client 'nosuch@KERBER.TEST' not found in Kerberos database"
        );
        let server = krb5_protocol::Error::KrbError {
            code: krb5_types::err::S_PRINCIPAL_UNKNOWN,
            text: Some("LOOKING_UP_SERVER".into()),
        };
        let svc = "nfs/zima-nas.kerber.test@KERBER.TEST";
        assert_eq!(
            Krb5Error::from_tgs(&server, svc, "KERBER.TEST").message,
            format!("Server {svc} not found in Kerberos database")
        );
        let preauth = krb5_protocol::Error::KrbError {
            code: krb5_types::err::PREAUTH_FAILED,
            text: None,
        };
        assert_eq!(
            Krb5Error::from_protocol(&preauth, "R").message,
            "Preauthentication failed"
        );
        let generic = krb5_protocol::Error::KrbError {
            code: krb5_types::err::GENERIC,
            text: Some("why".into()),
        };
        assert_eq!(
            Krb5Error::from_protocol(&generic, "R").message,
            "KDC returned error string: why"
        );
        let nofile = io::Error::from(io::ErrorKind::NotFound);
        let e = Krb5Error::from_file_cache(&nofile, Path::new("/tmp/none"));
        assert_eq!(e.code, Code::FccNofile);
        assert_eq!(
            e.message,
            "No credentials cache found (filename: /tmp/none)"
        );
        assert_eq!(kdc_error_text(30), "KRB5 error code 30");
        assert_eq!(
            Krb5Error::of(Code::WrongPrinc).to_string(),
            "Wrong principal in request"
        );
    }

    /// Live MIT 1.22.2: a default cache name with an unterminated `%{` is "Internal credentials
    /// cache error"; a type no cache is built for is "Unknown credential cache type".
    #[test]
    fn mit_texts_of_a_cache_name_that_does_not_resolve() {
        let unterminated = krb5_config::expand_ccache_params("FILE:/tmp/x_%{uid").unwrap_err();
        let e = Krb5Error::from_ccname(&unterminated);
        assert_eq!(e.code, Code::FccInternal);
        assert_eq!(e.message, "Internal credentials cache error");
        let unknown = krb5_config::parse_ccspec("NOSUCHTYPE:x").unwrap_err();
        assert_eq!(
            Krb5Error::from_ccname(&unknown).message,
            "Unknown credential cache type"
        );
        assert_eq!(
            Krb5Error::from_os(&io::Error::from_raw_os_error(13)).message,
            "Permission denied"
        );
        assert_eq!(
            Krb5Error::of(Code::KdcrepModified).message,
            "KDC reply did not match expectations"
        );
    }

    /// Live MIT 1.22.2 `kinit -c /tmp/nonexistent-dir/cc`: "Failed to store credentials: No
    /// credentials cache found", no file name; MIT's errno table for the rest.
    #[test]
    fn a_cache_write_error_is_its_errno_code_without_the_file() {
        let write = |n| Krb5Error::from_cache_write(&io::Error::from_raw_os_error(n)).message;
        assert_eq!(write(2), "No credentials cache found");
        assert_eq!(write(20), "No credentials cache found");
        assert_eq!(write(13), "Credentials cache permissions incorrect");
        assert_eq!(write(30), "Credentials cache permissions incorrect");
        assert_eq!(write(17), "Internal credentials cache error");
        assert_eq!(write(28), "Credentials cache I/O operation failed");
        assert_eq!(
            Krb5Error::from_file_cache(&io::Error::from_raw_os_error(21), Path::new("/x")).message,
            "Credentials cache permissions incorrect (filename: /x)"
        );
    }
}
