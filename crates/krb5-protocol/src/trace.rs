//! MIT's trace log, `KRB5_TRACE`: the file it names, the line format, the `{word}` formatter,
//! and the trace points of `include/k5-trace.h` and `plugins/preauth/spake/trace.h` that the
//! client paths reach ([`points`], re-exported here).
//!
//! The file is MIT's own environment input, read in a release build too. Nothing goes to
//! standard output or standard error unless `KRB5_TRACE` names one of them. No line carries key,
//! password or seed bytes: a key prints as its enctype and a 16-bit hash, as MIT prints it, and
//! the one MIT point that prints a secret in the clear, the SPAKE algorithm result, prints the
//! same hash instead ([`points::spake_result`]).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_types::{PaData, PrincipalName};
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

pub mod cc;
mod krb5_err;
pub mod points;

pub use cc::{get_config, random_string, store_creds, write_out_ccache};
pub use points::*;

/// The open trace file of this process, or `None` when `KRB5_TRACE` is unset or does not open.
static SINK: OnceLock<Option<File>> = OnceLock::new();

/// MIT `k5_init_trace` (`lib/krb5/os/trace.c:384-392`): the context's trace file is the one
/// `KRB5_TRACE` names, read with `secure_getenv`.
/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:209-217`): it is opened once the
/// profile has loaded, before anything is traced. A tool calls this where MIT's makes its context,
/// so the file is created even when nothing is traced; a later trace point opens it otherwise.
pub fn init() {
    let _ = sink();
}

/// Whether trace lines are written.
#[must_use]
pub fn enabled() -> bool {
    #[cfg(test)]
    if CAPTURE.with(|c| c.borrow().is_some()) {
        return true;
    }
    sink().is_some()
}

#[cfg(test)]
thread_local! {
    /// The messages a unit test captures in place of the file.
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f`, returning the trace messages it wrote on this thread.
#[cfg(test)]
pub(crate) fn capture(f: impl FnOnce()) -> Vec<String> {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    f();
    CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default()
}

fn sink() -> Option<&'static File> {
    SINK.get_or_init(|| secure_getenv("KRB5_TRACE").and_then(|name| set_trace_filename(&name)))
        .as_ref()
}

/// MIT `krb5_set_trace_filename` (`lib/krb5/os/trace.c:449-465`): write-only, appended to,
/// created 0600; a file that does not open leaves tracing off.
fn set_trace_filename(name: &std::ffi::OsStr) -> Option<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(name)
        .ok()
}

/// glibc's `secure_getenv`: nothing in a program the kernel marks secure (`AT_SECURE`, a setuid,
/// setgid or file-capability exec), so such a program never writes a file its caller names. The
/// kernel is asked only when the variable is set.
fn secure_getenv(name: &str) -> Option<OsString> {
    let value = std::env::var_os(name)?;
    (!secure_exec()).then_some(value)
}

/// The kernel's `AT_SECURE` from `/proc/self/auxv`, else differing real and effective ids.
fn secure_exec() -> bool {
    std::fs::read("/proc/self/auxv").map_or_else(
        |_| {
            nix::unistd::getuid() != nix::unistd::geteuid()
                || nix::unistd::getgid() != nix::unistd::getegid()
        },
        |auxv| at_secure(&auxv),
    )
}

/// Whether an auxiliary vector (pairs of native-endian words) holds a nonzero `AT_SECURE` (23).
fn at_secure(auxv: &[u8]) -> bool {
    const AT_SECURE: usize = 23;
    let w = std::mem::size_of::<usize>();
    let word =
        |b: &[u8]| <[u8; std::mem::size_of::<usize>()]>::try_from(b).map(usize::from_ne_bytes);
    auxv.chunks_exact(2 * w).any(|pair| {
        let (k, v) = pair.split_at(w);
        word(k).is_ok_and(|k| k == AT_SECURE) && word(v).is_ok_and(|v| v != 0)
    })
}

/// MIT `krb5int_trace` (`lib/krb5/os/trace.c:394-420`): `[pid] sec.usec: message`, one line per
/// point, written whole; nothing is formatted when tracing is off.
pub fn krb5int_trace(fmt: &str, args: &[Arg<'_>]) {
    #[cfg(test)]
    if CAPTURE.with(|c| c.borrow().is_some()) {
        let msg = trace_format(fmt, args);
        CAPTURE.with(|c| c.borrow_mut().as_mut().map(|v| v.push(msg)));
        return;
    }
    let Some(mut file) = sink() else {
        return;
    };
    let msg = trace_format(fmt, args);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let line = format!(
        "[{}] {}.{:06}: {msg}\n",
        std::process::id(),
        now.as_secs(),
        now.subsec_micros()
    );
    let _ = file.write_all(line.as_bytes());
}

thread_local! {
    /// The keytab the running initial-credentials request takes its keys from.
    static GAK_KEYTAB: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with `name()` (`TYPE:residual`) as the keytab of the initial-credentials request it
/// makes, so that the AS exchange traces each key lookup as MIT's `get_as_key_keytab` does. The
/// name is made only when tracing is on.
pub fn with_gak_keytab<T>(name: impl FnOnce() -> String, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let prev = GAK_KEYTAB.with(|k| k.replace(Some(name())));
    let out = f();
    GAK_KEYTAB.with(|k| *k.borrow_mut() = prev);
    out
}

/// The keytab [`with_gak_keytab`] named, if any.
#[must_use]
pub fn gak_keytab() -> Option<String> {
    GAK_KEYTAB.with(|k| k.borrow().clone())
}

/// A principal as `{princ}` prints it: its name and its realm.
#[derive(Clone, Copy, Debug)]
pub struct Princ<'a> {
    /// The name.
    pub name: &'a PrincipalName,
    /// The realm.
    pub realm: &'a [u8],
}

impl<'a> Princ<'a> {
    /// `name` in `realm`.
    #[must_use]
    pub const fn new(name: &'a PrincipalName, realm: &'a [u8]) -> Self {
        Self { name, realm }
    }

    /// MIT `krb5_unparse_name`: the quoted components, `@`, the quoted realm.
    #[must_use]
    pub fn unparse(&self) -> String {
        self.name
            .unparse_with_realm(&String::from_utf8_lossy(self.realm))
    }
}

/// A key as `{keyblock}` and `{key}` print it: only its enctype and a hash of it.
#[derive(Clone, Copy)]
pub struct Key<'a> {
    /// The enctype number.
    pub etype: i32,
    /// The key bytes; never printed.
    pub bytes: &'a [u8],
}

impl std::fmt::Debug for Key<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("etype", &self.etype)
            .finish_non_exhaustive()
    }
}

impl<'a> From<&'a krb5_crypto::ProtocolKey> for Key<'a> {
    fn from(k: &'a krb5_crypto::ProtocolKey) -> Self {
        Self {
            etype: k.etype().to_iana(),
            bytes: k.as_bytes(),
        }
    }
}

impl<'a> From<&'a krb5_types::EncryptionKey> for Key<'a> {
    fn from(k: &'a krb5_types::EncryptionKey) -> Self {
        Self {
            etype: k.keytype,
            bytes: k.keyvalue.as_ref(),
        }
    }
}

/// MIT `struct remote_address`'s transport as `{raddr}` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// `UDP`: `dgram`.
    Udp,
    /// `TCP`: `stream`.
    Tcp,
}

/// MIT `struct remote_address`: a transport and a socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteAddr {
    /// The transport.
    pub transport: Transport,
    /// The address.
    pub addr: SocketAddr,
}

/// One argument of a trace point, by the `{word}` that prints it.
#[derive(Clone, Copy)]
pub enum Arg<'a> {
    /// `{int}`.
    Int(i64),
    /// `{long}`.
    Long(i64),
    /// `{str}`: `None` is a null pointer.
    Str(Option<&'a [u8]>),
    /// `{lenstr}`: `None` is a null pointer with a length.
    LenStr(Option<&'a [u8]>),
    /// `{hexlenstr}`.
    HexLenStr(Option<&'a [u8]>),
    /// `{hashlenstr}`.
    HashLenStr(Option<&'a [u8]>),
    /// `{raddr}`.
    Raddr(&'a RemoteAddr),
    /// `{data}`.
    Data(Option<&'a [u8]>),
    /// `{hexdata}`.
    HexData(Option<&'a [u8]>),
    /// `{errno}`.
    Errno(i32),
    /// `{kerr}`: the code, and the message the library set for it when there is one.
    Kerr(i64, Option<&'a str>),
    /// `{keyblock}`.
    Keyblock(Option<Key<'a>>),
    /// `{key}`.
    Key(Option<Key<'a>>),
    /// `{cksum}`: the checksum type and value.
    Cksum(i32, &'a [u8]),
    /// `{princ}`: `None` is a principal that does not unparse.
    Princ(Option<Princ<'a>>),
    /// `{princ}` of a principal kept unparsed, as a cache's configuration entry keeps it.
    PrincName(Option<&'a str>),
    /// `{ptype}`.
    Ptype(i32),
    /// `{patypes}`.
    Patypes(&'a [PaData]),
    /// `{patype}`.
    Patype(i32),
    /// `{etype}`.
    Etype(i32),
    /// `{etypes}`.
    Etypes(&'a [i32]),
    /// `{ccache}`: `TYPE:name`.
    Ccache(&'a str),
    /// `{keytab}`: the keytab's name.
    Keytab(&'a str),
    /// `{creds}`: client and server; no client is a lookup that matches any, which prints empty.
    Creds(Option<Princ<'a>>, Princ<'a>),
}

/// The length of bytes that are not shown.
struct Withheld(usize);

impl std::fmt::Debug for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

/// As derived, except that a `{hashlenstr}` shows only its length, never its bytes, and a key
/// only its enctype ([`Key`]'s own).
impl std::fmt::Debug for Arg<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Int(v) => f.debug_tuple("Int").field(&v).finish(),
            Self::Long(v) => f.debug_tuple("Long").field(&v).finish(),
            Self::Str(p) => f.debug_tuple("Str").field(&p).finish(),
            Self::LenStr(p) => f.debug_tuple("LenStr").field(&p).finish(),
            Self::HexLenStr(p) => f.debug_tuple("HexLenStr").field(&p).finish(),
            Self::HashLenStr(p) => f
                .debug_tuple("HashLenStr")
                .field(&p.map(|b| Withheld(b.len())))
                .finish(),
            Self::Raddr(ra) => f.debug_tuple("Raddr").field(ra).finish(),
            Self::Data(p) => f.debug_tuple("Data").field(&p).finish(),
            Self::HexData(p) => f.debug_tuple("HexData").field(&p).finish(),
            Self::Errno(e) => f.debug_tuple("Errno").field(&e).finish(),
            Self::Kerr(code, msg) => f.debug_tuple("Kerr").field(&code).field(&msg).finish(),
            Self::Keyblock(k) => f.debug_tuple("Keyblock").field(&k).finish(),
            Self::Key(k) => f.debug_tuple("Key").field(&k).finish(),
            Self::Cksum(t, v) => f.debug_tuple("Cksum").field(&t).field(&v).finish(),
            Self::Princ(p) => f.debug_tuple("Princ").field(&p).finish(),
            Self::PrincName(p) => f.debug_tuple("PrincName").field(&p).finish(),
            Self::Ptype(t) => f.debug_tuple("Ptype").field(&t).finish(),
            Self::Patypes(list) => f.debug_tuple("Patypes").field(&list).finish(),
            Self::Patype(t) => f.debug_tuple("Patype").field(&t).finish(),
            Self::Etype(e) => f.debug_tuple("Etype").field(&e).finish(),
            Self::Etypes(list) => f.debug_tuple("Etypes").field(&list).finish(),
            Self::Ccache(c) => f.debug_tuple("Ccache").field(&c).finish(),
            Self::Keytab(k) => f.debug_tuple("Keytab").field(&k).finish(),
            Self::Creds(client, server) => f
                .debug_tuple("Creds")
                .field(&client)
                .field(&server)
                .finish(),
        }
    }
}

/// MIT `trace_format` (`lib/krb5/os/trace.c:173-366`): the text up to each `{word}`, then the
/// next argument as the word prints it. An unknown word prints nothing and takes no argument; a
/// `{` without its `}`, or a word over 199 bytes, ends the message.
#[must_use]
pub fn trace_format(fmt: &str, args: &[Arg<'_>]) -> String {
    let mut buf = String::new();
    let mut args = args.iter();
    let mut rest = fmt;
    loop {
        let Some(open) = rest.find('{') else {
            buf.push_str(rest);
            break;
        };
        buf.push_str(&rest[..open]);
        rest = &rest[open + 1..];
        let Some(close) = rest.find('}') else {
            break;
        };
        if close > 199 {
            break;
        }
        let word = &rest[..close];
        rest = &rest[close + 1..];
        if is_word(word)
            && let Some(arg) = args.next()
        {
            format_word(&mut buf, word, arg);
        }
    }
    buf
}

const WORDS: [&str; 23] = [
    "int",
    "long",
    "str",
    "lenstr",
    "hexlenstr",
    "hashlenstr",
    "raddr",
    "data",
    "hexdata",
    "errno",
    "kerr",
    "keyblock",
    "key",
    "cksum",
    "princ",
    "ptype",
    "patypes",
    "patype",
    "etype",
    "etypes",
    "ccache",
    "keytab",
    "creds",
];

fn is_word(word: &str) -> bool {
    WORDS.contains(&word)
}

/// One `{word}` of [`trace_format`]; an argument of another kind prints nothing.
fn format_word(buf: &mut String, word: &str, arg: &Arg<'_>) {
    match (word, *arg) {
        ("int" | "long", Arg::Int(v) | Arg::Long(v)) => {
            let _ = write!(buf, "{v}");
        }
        ("str", Arg::Str(p)) => add_printable(buf, p.unwrap_or(b"(null)")),
        ("lenstr", Arg::LenStr(p)) | ("data", Arg::Data(p)) => match p {
            Some(p) => add_printable(buf, p),
            None => buf.push_str("(null)"),
        },
        ("hexlenstr", Arg::HexLenStr(p)) | ("hexdata", Arg::HexData(p)) => match p {
            Some(p) => add_hex(buf, p),
            None => buf.push_str("(null)"),
        },
        ("hashlenstr", Arg::HashLenStr(p)) => match p {
            Some(p) => buf.push_str(&hash_bytes(p)),
            None => buf.push_str("(null)"),
        },
        ("raddr", Arg::Raddr(ra)) => {
            buf.push_str(match ra.transport {
                Transport::Udp => "dgram",
                Transport::Tcp => "stream",
            });
            let _ = write!(buf, " {}", ra.addr);
        }
        ("errno", Arg::Errno(e)) => {
            let _ = write!(buf, "{e}/{}", strerror(e));
        }
        ("kerr", Arg::Kerr(code, msg)) => {
            let _ = write!(buf, "{code}/");
            if code == 0 {
                buf.push_str("Success");
            } else {
                match msg {
                    Some(m) => buf.push_str(m),
                    None => buf.push_str(&error_message(code)),
                }
            }
        }
        ("keyblock", Arg::Keyblock(k)) | ("key", Arg::Key(k)) => match k {
            Some(k) => {
                add_etype(buf, k.etype);
                buf.push('/');
                buf.push_str(&hash_bytes(k.bytes));
            }
            None => buf.push_str("(null)"),
        },
        ("cksum", Arg::Cksum(t, v)) => {
            let _ = write!(buf, "{t}/");
            add_hex(buf, v);
        }
        ("princ", Arg::Princ(Some(p))) => buf.push_str(&p.unparse()),
        ("princ", Arg::PrincName(Some(p))) => buf.push_str(p),
        ("ptype", Arg::Ptype(t)) => buf.push_str(principal_type_string(t)),
        ("patypes", Arg::Patypes(list)) => {
            if list.is_empty() {
                buf.push_str("(empty)");
            }
            for (i, pa) in list.iter().enumerate() {
                if i > 0 {
                    buf.push_str(", ");
                }
                add_patype(buf, pa.padata_type);
            }
        }
        ("patype", Arg::Patype(t)) => add_patype(buf, t),
        ("etype", Arg::Etype(e)) => add_etype(buf, e),
        ("etypes", Arg::Etypes(list)) => {
            if list.is_empty() {
                buf.push_str("(empty)");
            }
            for (i, e) in list.iter().enumerate() {
                if i > 0 {
                    buf.push_str(", ");
                }
                add_etype(buf, *e);
            }
        }
        ("ccache", Arg::Ccache(name)) | ("keytab", Arg::Keytab(name)) => buf.push_str(name),
        ("creds", Arg::Creds(client, server)) => {
            let client = client.map(|c| c.unparse()).unwrap_or_default();
            let _ = write!(buf, "{client} -> {}", server.unparse());
        }
        _ => {}
    }
}

/// MIT `buf_add_printable_len` (`lib/krb5/os/trace.c:60-79`): bytes 32 to 126 as they are, any
/// other as `\xNN`.
fn add_printable(buf: &mut String, p: &[u8]) {
    for &b in p {
        if (32..=126).contains(&b) {
            buf.push(char::from(b));
        } else {
            let _ = write!(buf, "\\x{b:02x}");
        }
    }
}

fn add_hex(buf: &mut String, p: &[u8]) {
    for b in p {
        let _ = write!(buf, "{b:02X}");
    }
}

/// MIT `hash_bytes` (`lib/krb5/os/trace.c:89-103`): the first two bytes of the SHA-1 of the bytes,
/// as four upper-case hex digits. The rest of the digest is wiped.
fn hash_bytes(p: &[u8]) -> String {
    let mut digest: [u8; 20] = Sha1::digest(p).into();
    let s = format!("{:02X}{:02X}", digest[0], digest[1]);
    digest.zeroize();
    s
}

fn add_patype(buf: &mut String, t: i32) {
    match padata_type_string(t) {
        Some(name) => {
            let _ = write!(buf, "{name} ({t})");
        }
        None => {
            let _ = write!(buf, "{t}");
        }
    }
}

fn add_etype(buf: &mut String, e: i32) {
    match enctype_shortest_name(e) {
        Some(name) => buf.push_str(name),
        None => {
            let _ = write!(buf, "{e}");
        }
    }
}

/// MIT `principal_type_string` (`lib/krb5/os/trace.c:105-124`): the name of a principal type.
#[must_use]
pub const fn principal_type_string(t: i32) -> &'static str {
    match t {
        0 => "unknown",
        1 => "principal",
        2 => "service instance",
        3 => "service with host as instance",
        4 => "service with host as components",
        5 => "unique ID",
        6 => "X.509",
        7 => "SMTP email",
        10 => "Windows 2000 UPN",
        11 => "well-known",
        -128 => "Windows 2000 UPN and SID",
        -129 => "NT 4 style name",
        -130 => "NT 4 style name and SID",
        _ => "?",
    }
}

/// MIT `padata_type_string` (`lib/krb5/os/trace.c:126-171`): the name of a padata type.
#[must_use]
pub const fn padata_type_string(t: i32) -> Option<&'static str> {
    Some(match t {
        1 => "PA-TGS-REQ",
        2 => "PA-ENC-TIMESTAMP",
        3 => "PA-PW-SALT",
        5 => "PA-ENC-UNIX-TIME",
        6 => "PA-SANDIA-SECUREID",
        7 => "PA-SESAME",
        8 => "PA-OSF-DCE",
        9 => "PA-CYBERSAFE-SECUREID",
        10 => "PA-AFS3-SALT",
        11 => "PA-ETYPE-INFO",
        12 => "PA-SAM-CHALLENGE",
        13 => "PA-SAM-RESPONSE",
        14 => "PA-PK-AS-REQ_OLD",
        15 => "PA-PK-AS-REP_OLD",
        16 => "PA-PK-AS-REQ",
        17 => "PA-PK-AS-REP",
        19 => "PA-ETYPE-INFO2",
        20 => "PA-SVR-REFERRAL-INFO",
        21 => "PA-SAM-REDIRECT",
        22 => "PA-GET-FROM-TYPED-DATA",
        30 => "PA-SAM-CHALLENGE2",
        31 => "PA-SAM-RESPONSE2",
        128 => "PA-PAC-REQUEST",
        129 => "PA-FOR_USER",
        130 => "PA-FOR-X509-USER",
        132 => "PA-AS-CHECKSUM",
        133 => "PA-FX-COOKIE",
        136 => "PA-FX-FAST",
        137 => "PA-FX-ERROR",
        138 => "PA-ENCRYPTED-CHALLENGE",
        141 => "PA-OTP-CHALLENGE",
        142 => "PA-OTP-REQUEST",
        144 => "PA-OTP-PIN-CHANGE",
        147 => "PA-PKINIT-KX",
        149 => "PA-REQ-ENC-PA-REP",
        150 => "PA_AS_FRESHNESS",
        151 => "PA-SPAKE",
        152 => "PA-REDHAT-IDP-OAUTH2",
        153 => "PA-REDHAT-PASSKEY",
        _ => return None,
    })
}

/// MIT `krb5_enctype_to_name` (`lib/crypto/krb/enctype_util.c:129-160`): asked for the shortest,
/// the shortest of an enctype's name and aliases, and the names of the DES types it no longer has.
#[must_use]
pub const fn enctype_shortest_name(e: i32) -> Option<&'static str> {
    Some(match e {
        1 => "des-cbc-crc",
        2 => "des-cbc-md4",
        3 => "des-cbc-md5",
        4 => "des-cbc-raw",
        8 => "des-hmac-sha1",
        6 => "des3-cbc-raw",
        16 => "des3-cbc-sha1",
        23 => "rc4-hmac",
        24 => "rc4-hmac-exp",
        17 => "aes128-cts",
        18 => "aes256-cts",
        25 => "camellia128-cts",
        26 => "camellia256-cts",
        19 => "aes128-sha2",
        20 => "aes256-sha2",
        _ => return None,
    })
}

/// `ERROR_TABLE_BASE_krb5`.
pub const ERROR_TABLE_BASE_KRB5: i64 = -1_765_328_384;
/// MIT `KRB5_CC_NOTFOUND`.
pub const KRB5_CC_NOTFOUND: i64 = ERROR_TABLE_BASE_KRB5 + 141;
/// MIT `KRB5_KDCREP_MODIFIED`.
pub const KRB5_KDCREP_MODIFIED: i64 = ERROR_TABLE_BASE_KRB5 + 147;
/// MIT `KRB5_KDC_UNREACH`.
pub const KRB5_KDC_UNREACH: i64 = ERROR_TABLE_BASE_KRB5 + 156;
/// MIT `KRB5_KT_NOTFOUND`.
pub const KRB5_KT_NOTFOUND: i64 = ERROR_TABLE_BASE_KRB5 + 181;
/// MIT `KRB5_FCC_NOFILE`.
pub const KRB5_FCC_NOFILE: i64 = ERROR_TABLE_BASE_KRB5 + 195;

/// MIT `error_message`, as `krb5_get_error_message` returns it when the library set no message
/// of its own: the `krb5` table's text, `strerror` for an errno value, else `Unknown code`.
#[must_use]
pub fn error_message(code: i64) -> String {
    if let Some(off) = code
        .checked_sub(ERROR_TABLE_BASE_KRB5)
        .and_then(|o| usize::try_from(o).ok())
        && let Some(text) = krb5_err::TEXTS.get(off)
    {
        return (*text).to_owned();
    }
    match i32::try_from(code) {
        Ok(e) if (1..4096).contains(&e) => strerror(e),
        _ => format!("Unknown code {code}"),
    }
}

/// `strerror`, without Rust's ` (os error N)`.
fn strerror(e: i32) -> String {
    let s = std::io::Error::from_raw_os_error(e).to_string();
    let suffix = format!(" (os error {e})");
    s.strip_suffix(&suffix)
        .map_or_else(|| s.clone(), str::to_owned)
}

/// The MIT code of a KDC error number (`ERROR_TABLE_BASE_krb5 + code`).
#[must_use]
pub fn kdc_code(code: i32) -> i64 {
    ERROR_TABLE_BASE_KRB5 + i64::from(code)
}

#[cfg(test)]
mod tests;
