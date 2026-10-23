//! KRB5_TRACE names the file, and a release build reads it too.
//! Nothing is written to standard output or standard error unless that name is one of them.
//! No line carries key, password or seed bytes.
//! A key is its enctype and a 16-bit hash. SPAKE prints that hash, not the secret.

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

pub use cc::{get_config, store_creds, write_out_ccache};
pub use points::*;

static SINK: OnceLock<Option<File>> = OnceLock::new();

// MIT: `k5_init_trace` (lib/krb5/os/trace.c:384-392)
/// The file KRB5_TRACE names, read with secure_getenv.
// MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:209-217)
/// Opened after the profile loads and before any trace, even when nothing is traced.
pub fn init() {
    let _ = sink();
}

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
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

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

// MIT: `krb5_set_trace_filename` (lib/krb5/os/trace.c:449-465)
/// Write-only, appended, created 0600. A file that does not open leaves tracing off.
fn set_trace_filename(name: &std::ffi::OsStr) -> Option<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(name)
        .ok()
}

/// A setuid, setgid or file-capability exec gets nothing, so it never writes a caller-named file.
#[allow(
    clippy::disallowed_methods,
    reason = "MIT reads KRB5_TRACE as each context is made"
)]
fn secure_getenv(name: &str) -> Option<OsString> {
    let value = std::env::var_os(name)?;
    (!secure_exec()).then_some(value)
}

fn secure_exec() -> bool {
    std::fs::read("/proc/self/auxv").map_or_else(
        |_| {
            nix::unistd::getuid() != nix::unistd::geteuid()
                || nix::unistd::getgid() != nix::unistd::getegid()
        },
        |auxv| at_secure(&auxv),
    )
}

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

// MIT: `krb5int_trace` (lib/krb5/os/trace.c:394-420)
/// Nothing is formatted when tracing is off.
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
    static GAK_KEYTAB: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The keytab name is built only when tracing is on.
pub fn with_gak_keytab<T>(name: impl FnOnce() -> String, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let prev = GAK_KEYTAB.with(|k| k.replace(Some(name())));
    let out = f();
    GAK_KEYTAB.with(|k| *k.borrow_mut() = prev);
    out
}

#[must_use]
pub fn gak_keytab() -> Option<String> {
    GAK_KEYTAB.with(|k| k.borrow().clone())
}

#[derive(Clone, Copy, Debug)]
pub struct Princ<'a> {
    pub name: &'a PrincipalName,
    pub realm: &'a [u8],
}

impl<'a> Princ<'a> {
    #[must_use]
    pub const fn new(name: &'a PrincipalName, realm: &'a [u8]) -> Self {
        Self { name, realm }
    }

    #[must_use]
    pub fn unparse(&self) -> String {
        self.name
            .unparse_with_realm(&String::from_utf8_lossy(self.realm))
    }
}

#[derive(Clone, Copy)]
pub struct Key<'a> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteAddr {
    pub transport: Transport,
    pub addr: SocketAddr,
}

#[derive(Clone, Copy)]
pub enum Arg<'a> {
    Int(i64),
    Long(i64),
    Str(Option<&'a [u8]>),
    LenStr(Option<&'a [u8]>),
    HexLenStr(Option<&'a [u8]>),
    HashLenStr(Option<&'a [u8]>),
    Raddr(&'a RemoteAddr),
    Data(Option<&'a [u8]>),
    HexData(Option<&'a [u8]>),
    Errno(i32),
    Kerr(i64, Option<&'a str>),
    Keyblock(Option<Key<'a>>),
    Key(Option<Key<'a>>),
    Cksum(i32, &'a [u8]),
    Princ(Option<Princ<'a>>),
    PrincName(Option<&'a str>),
    Ptype(i32),
    Patypes(&'a [PaData]),
    Patype(i32),
    Etype(i32),
    Etypes(&'a [i32]),
    Ccache(&'a str),
    Keytab(&'a str),
    Creds(Option<Princ<'a>>, Princ<'a>),
}

struct Withheld(usize);

impl std::fmt::Debug for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

/// A hash shows its length, never its bytes. A key shows only its enctype.
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

// MIT: `trace_format` (lib/krb5/os/trace.c:173-366)
/// An unknown word prints nothing and takes no argument. A word over 199 bytes ends the message.
/// A brace with no close ends the message.
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

// MIT: `k5_print_addr_port` (lib/krb5/os/addr.c:94-110)
/// IPv6 is bracketed. A scope id prints as the interface name, or its number.
fn print_addr_port(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => {
            let port = v6.port();
            let host = v6.ip();
            let scope = v6.scope_id();
            if scope == 0 {
                format!("[{host}]:{port}")
            } else {
                format!("[{host}%{}]:{port}", scope_name(scope))
            }
        }
    }
}

fn scope_name(id: u32) -> String {
    nix::net::if_::if_indextoname(id).map_or_else(
        |_| id.to_string(),
        |name| name.into_string().unwrap_or_else(|_| id.to_string()),
    )
}

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
            let _ = write!(buf, " {}", print_addr_port(&ra.addr));
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

// MIT: `buf_add_printable_len` (lib/krb5/os/trace.c:60-79)
/// bytes 32 to 126 as they are, any other as `\xNN`.
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

// MIT: `hash_bytes` (lib/krb5/os/trace.c:89-103)
/// Four hex digits from the first two SHA-1 bytes. The rest of the digest is wiped.
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

// MIT: `principal_type_string` (lib/krb5/os/trace.c:105-124)
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

// MIT: `padata_type_string` (lib/krb5/os/trace.c:126-171)
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

// MIT: `krb5_enctype_to_name` (lib/crypto/krb/enctype_util.c:129-160)
/// The shortest name, including DES types this build no longer has.
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

pub const ERROR_TABLE_BASE_KRB5: i64 = -1_765_328_384;
pub const KRB5_CC_NOTFOUND: i64 = ERROR_TABLE_BASE_KRB5 + 141;
pub const KRB5_KDCREP_MODIFIED: i64 = ERROR_TABLE_BASE_KRB5 + 147;
pub const KRB5_KDC_UNREACH: i64 = ERROR_TABLE_BASE_KRB5 + 156;
pub const KRB5_KT_NOTFOUND: i64 = ERROR_TABLE_BASE_KRB5 + 181;
pub const KRB5_FCC_NOFILE: i64 = ERROR_TABLE_BASE_KRB5 + 195;

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

fn strerror(e: i32) -> String {
    let s = std::io::Error::from_raw_os_error(e).to_string();
    let suffix = format!(" (os error {e})");
    s.strip_suffix(&suffix)
        .map_or_else(|| s.clone(), str::to_owned)
}

pub fn pkinit_match(t: krb5_types::pkinit::MatchTrace<'_>) {
    use krb5_types::pkinit::MatchTrace;
    let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    match t {
        MatchTrace::Rule(rule) => pkinit_cert_rule(rule),
        MatchTrace::RuleInvalid(rule) => pkinit_cert_rule_invalid(rule),
        MatchTrace::Regexp {
            matched,
            keyword,
            rule,
            value,
            cert,
        } => {
            let number = count(cert).saturating_add(1);
            if matched {
                pkinit_regexp_match(keyword, rule, value, number);
            } else {
                pkinit_regexp_nomatch(keyword, rule, value, number);
            }
        }
        MatchTrace::Checked { certs, matches } => {
            pkinit_cert_num_matching(count(certs), count(matches));
        }
        MatchTrace::NoMatch => pkinit_no_matching_cert(),
        MatchTrace::NoDefault(n) => pkinit_no_default_cert(count(n)),
    }
}

#[must_use]
pub fn kdc_code(code: i32) -> i64 {
    ERROR_TABLE_BASE_KRB5 + i64::from(code)
}

#[cfg(test)]
mod tests;
