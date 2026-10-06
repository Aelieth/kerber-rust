//! MIT KCM unix-socket client (Heimdal protocol, FILE v4 creds).
//!
//! Wire (cc_kcm.c): request is 4-byte length plus payload (major, minor,
//! opcode, args). Reply is 4-byte length, 4-byte status, then that many
//! bytes starting with another status. sssd-kcm 2.11/2.12 implements
//! GET_CRED_LIST; RETRIEVE and REPLACE return FCC_INTERNAL.
//! Empty-residual `kinit -c KCM:` re-INITIALIZEs the collection default
//! (same as MIT `kinit`). A second principal uses GEN_NEW (kcm-gate)
//! rather than MIT `krb5_cc_new_unique` on a plain `KCM:` residual.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use krb5_types::{PrincipalName, Realm};

use crate::ccache::FileCcache;
use crate::ccmarshal::{
    CcacheCred, Writer, marshal_cred, marshal_princ, unmarshal_cred, unmarshal_princ,
};

const MAJOR: u8 = 2;
const MINOR: u8 = 0;
const UUID_LEN: usize = 16;
const MAX_REPLY: usize = 10 * 1024 * 1024;

const OP_GEN_NEW: u16 = 3;
const OP_INITIALIZE: u16 = 4;
const OP_DESTROY: u16 = 5;
const OP_STORE: u16 = 6;
const OP_GET_PRINCIPAL: u16 = 8;
const OP_GET_CRED_UUID_LIST: u16 = 9;
const OP_GET_CRED_BY_UUID: u16 = 10;
const OP_GET_CACHE_UUID_LIST: u16 = 18;
const OP_GET_CACHE_BY_UUID: u16 = 19;
const OP_GET_DEFAULT_CACHE: u16 = 20;
const OP_SET_DEFAULT_CACHE: u16 = 21;
const OP_GET_CRED_LIST: u16 = 13_001;

const KRB5_CC_NOSUPP: i32 = -1_765_328_137;
const KRB5_CC_IO: i32 = -1_765_328_183;
const KRB5_FCC_INTERNAL: i32 = -1_765_328_188;
const KRB5_FCC_NOFILE: i32 = -1_765_328_189;
// MIT `KRB5_KCM_NO_SERVER` (`k5e1_err.et:44-44`): the code for no KCM daemon on the socket.
const KRB5_KCM_NO_SERVER: i32 = -1_750_600_181;

/// The KCM socket when `kcm_socket` names none.
/// MIT `DEFAULT_KCM_SOCKET_PATH` (`kcm.h:43-43`): the path.
pub const KCM_SOCKET_DEFAULT: &str = "/var/run/.heim_org.h5l.kcm-socket";

/// `sizeof(struct sockaddr_un.sun_path)` on Linux.
const SUN_PATH_LEN: usize = 108;

struct KcmIo {
    stream: UnixStream,
}

impl KcmIo {
    /// MIT `kcmio_unix_socket_connect` (`cc_kcm.c:313-330`): a `kcm_socket` of `-`, or a socket
    /// that is not there, is `KRB5_KCM_NO_SERVER`; any other failure to connect is its errno.
    /// The path is cut to `sun_path`, as MIT's `strlcpy` cuts it.
    fn connect() -> io::Result<Self> {
        let path = kcm_socket_path();
        if path.as_os_str() == "-" {
            return Err(kcm_status(KRB5_KCM_NO_SERVER));
        }
        let bytes = path.as_os_str().as_bytes();
        let stream = if bytes.is_empty() {
            connect_unnamed()
        } else {
            UnixStream::connect(Path::new(OsStr::from_bytes(
                &bytes[..bytes.len().min(SUN_PATH_LEN - 1)],
            )))
        }
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                kcm_status(KRB5_KCM_NO_SERVER)
            } else {
                e
            }
        })?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
        Ok(Self { stream })
    }

    fn reconnect(&mut self) -> io::Result<()> {
        *self = Self::connect()?;
        Ok(())
    }

    fn call(&mut self, opcode: u16, args: &[u8]) -> io::Result<Vec<u8>> {
        match self.call_once(opcode, args) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.reconnect()?;
                self.call_once(opcode, args)
            }
            other => other,
        }
    }

    fn call_once(&mut self, opcode: u16, args: &[u8]) -> io::Result<Vec<u8>> {
        self.stream.write_all(&request_frame(opcode, args))?;
        let mut hdr = [0u8; 8];
        self.stream.read_exact(&mut hdr)?;
        let n = u32::from_be_bytes(hdr[0..4].try_into().unwrap_or([0; 4])) as usize;
        let outer = i32::from_be_bytes(hdr[4..8].try_into().unwrap_or([0; 4]));
        if outer != 0 {
            return Err(kcm_status(outer));
        }
        if n > MAX_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KCM reply too big",
            ));
        }
        let mut body = vec![0u8; n];
        if n > 0 {
            self.stream.read_exact(&mut body)?;
        }
        if body.len() < 4 {
            return Ok(body);
        }
        let inner = i32::from_be_bytes(body[0..4].try_into().unwrap_or([0; 4]));
        if inner != 0 {
            return Err(kcm_status(inner));
        }
        Ok(body[4..].to_vec())
    }
}

#[derive(Debug)]
struct KcmStatus(i32);

impl std::fmt::Display for KcmStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            KRB5_FCC_NOFILE => f.write_str("No credentials cache found"),
            KRB5_CC_NOSUPP | KRB5_FCC_INTERNAL => {
                write!(f, "KCM operation unsupported ({})", self.0)
            }
            KRB5_CC_IO => write!(f, "KCM I/O ({})", self.0),
            KRB5_KCM_NO_SERVER => f.write_str("No KCM server found"),
            c => write!(f, "KCM error {c}"),
        }
    }
}

impl std::error::Error for KcmStatus {}

fn kcm_status(code: i32) -> io::Error {
    let kind = if code == KRB5_FCC_NOFILE {
        io::ErrorKind::NotFound
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, KcmStatus(code))
}

fn kcm_code(err: &io::Error) -> Option<i32> {
    err.get_ref()?.downcast_ref::<KcmStatus>().map(|s| s.0)
}

/// Whether `err` is MIT's `KRB5_KCM_NO_SERVER`: no KCM daemon on the socket.
#[must_use]
pub fn kcm_no_server(err: &io::Error) -> bool {
    kcm_code(err) == Some(KRB5_KCM_NO_SERVER)
}

fn unsupported(err: &io::Error) -> bool {
    matches!(
        kcm_code(err),
        Some(KRB5_CC_NOSUPP | KRB5_FCC_INTERNAL | KRB5_CC_IO)
    )
}

fn cstring(bytes: &[u8]) -> io::Result<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn zname(name: &str) -> Vec<u8> {
    let mut v = name.as_bytes().to_vec();
    v.push(0);
    v
}

fn marshal_primary(realm: &Realm, name: &PrincipalName) -> Vec<u8> {
    let mut w = Writer::default();
    marshal_princ(&mut w, realm, name);
    w.buf
}

fn marshal_one_cred(c: &CcacheCred) -> Vec<u8> {
    let mut w = Writer::default();
    marshal_cred(&mut w, c);
    w.buf
}

#[cfg(test)]
thread_local! {
    static SOCKET_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The KCM socket: `[libdefaults] kcm_socket`, else [`KCM_SOCKET_DEFAULT`]; `-` names none.
/// MIT `kcmio_unix_socket_connect` (`cc_kcm.c:308-310`): the profile's `kcm_socket`, with
/// `DEFAULT_KCM_SOCKET_PATH` its default; no environment variable is read.
#[must_use]
pub fn kcm_socket_path() -> PathBuf {
    #[cfg(test)]
    if let Some(p) = SOCKET_OVERRIDE.with(|s| s.borrow().clone()) {
        return p;
    }
    socket_path_from(krb5_config::load_krb5_conf().and_then(|c| c.kcm_socket))
}

fn socket_path_from(kcm_socket: Option<String>) -> PathBuf {
    PathBuf::from(kcm_socket.unwrap_or_else(|| KCM_SOCKET_DEFAULT.to_owned()))
}

/// The connect MIT makes for an empty value, `kcm_socket = ""`: its `sun_path` all zero, given
/// with the whole `sizeof(addr)`, is the abstract socket named by 107 NUL bytes, which nothing
/// binds, so the connect is refused (`ECONNREFUSED`); where there are no abstract sockets, that
/// refusal is returned as is.
/// MIT `kcmio_unix_socket_connect` (`cc_kcm.c:324-328`): `strlcpy` of the path into a zeroed
/// address, then `connect` with `sizeof(addr)`.
fn connect_unnamed() -> io::Result<UnixStream> {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt as _;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name([0u8; SUN_PATH_LEN - 1])?;
        UnixStream::connect_addr(&addr)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
    }
}

/// A connection to the KCM daemon, made and closed: what MIT's `kcm_resolve` checks first.
/// MIT `kcm_resolve` (`cc_kcm.c:750-752`): a cache name resolves only with a KCM daemon to ask.
///
/// # Errors
///
/// As the connection's: `KRB5_KCM_NO_SERVER` ([`kcm_no_server`]) or the connect's errno.
pub fn kcm_reachable() -> io::Result<()> {
    KcmIo::connect().map(drop)
}

fn request_frame(opcode: u16, args: &[u8]) -> Vec<u8> {
    let mut payload = vec![MAJOR, MINOR];
    payload.extend_from_slice(&opcode.to_be_bytes());
    payload.extend_from_slice(args);
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(u32::try_from(payload.len()).unwrap_or(0)).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn default_or(io: &mut KcmIo, residual: &str) -> io::Result<String> {
    if residual.is_empty() {
        cstring(&io.call(OP_GET_DEFAULT_CACHE, &[])?)
    } else {
        Ok(residual.to_owned())
    }
}

fn default_or_create(io: &mut KcmIo, residual: &str) -> io::Result<String> {
    if !residual.is_empty() {
        return Ok(residual.to_owned());
    }
    match io.call(OP_GET_DEFAULT_CACHE, &[]) {
        Ok(b) => cstring(&b),
        Err(e) if e.kind() == io::ErrorKind::NotFound => cstring(&io.call(OP_GEN_NEW, &[])?),
        Err(e) => Err(e),
    }
}

fn initialize(io: &mut KcmIo, name: &str, cc: &FileCcache) -> io::Result<()> {
    let mut args = zname(name);
    args.extend_from_slice(&marshal_primary(&cc.primary.0, &cc.primary.1));
    io.call(OP_INITIALIZE, &args).map(|_| ())
}

fn store_one(io: &mut KcmIo, name: &str, cred: &CcacheCred) -> io::Result<()> {
    let mut args = zname(name);
    args.extend_from_slice(&marshal_one_cred(cred));
    io.call(OP_STORE, &args).map(|_| ())
}

fn creds_via_list(io: &mut KcmIo, name: &str) -> io::Result<Vec<CcacheCred>> {
    parse_cred_list(&io.call(OP_GET_CRED_LIST, &zname(name))?)
}

fn parse_cred_list(body: &[u8]) -> io::Result<Vec<CcacheCred>> {
    if body.len() < 4 {
        return Ok(Vec::new());
    }
    let count = u32::from_be_bytes(body[0..4].try_into().unwrap_or([0; 4])) as usize;
    let rest = body.len() - 4;
    if count > rest / 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KCM GET_CRED_LIST count",
        ));
    }
    let mut i = 4;
    let mut out = Vec::new();
    for _ in 0..count {
        if 4 > body.len().saturating_sub(i) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KCM GET_CRED_LIST truncated",
            ));
        }
        let n = u32::from_be_bytes(body[i..i + 4].try_into().unwrap_or([0; 4])) as usize;
        i += 4;
        if n == 0 || n > body.len().saturating_sub(i) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KCM GET_CRED_LIST cred truncated",
            ));
        }
        let mut j = 0;
        out.push(unmarshal_cred(&body[i..i + n], &mut j)?);
        i += n;
    }
    Ok(out)
}

fn creds_via_uuid(io: &mut KcmIo, name: &str) -> io::Result<Vec<CcacheCred>> {
    let uuids = io.call(OP_GET_CRED_UUID_LIST, &zname(name))?;
    if uuids.len() % UUID_LEN != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KCM UUID list length",
        ));
    }
    let mut out = Vec::new();
    for chunk in uuids.chunks(UUID_LEN) {
        let mut args = zname(name);
        args.extend_from_slice(chunk);
        let raw = io.call(OP_GET_CRED_BY_UUID, &args)?;
        let mut j = 0;
        out.push(unmarshal_cred(&raw, &mut j)?);
    }
    Ok(out)
}

fn get_principal(io: &mut KcmIo, name: &str) -> io::Result<(Realm, PrincipalName)> {
    let raw = io.call(OP_GET_PRINCIPAL, &zname(name))?;
    let mut i = 0;
    unmarshal_princ(&raw, &mut i)
}

/// Load `KCM:residual` (empty residual is the default cache).
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` for a `KRB5_FCC_NOFILE` status (no such cache) and
/// `ErrorKind::Other` for any other nonzero status; `ErrorKind::InvalidData` or
/// `UnexpectedEof` for a reply over 10 MiB, a non-UTF-8 default name, or a malformed or
/// truncated principal or credential list.
pub fn kcm_load(residual: &str) -> io::Result<FileCcache> {
    let mut io = KcmIo::connect()?;
    let name = default_or(&mut io, residual)?;
    let primary = get_principal(&mut io, &name)?;
    let creds = match creds_via_list(&mut io, &name) {
        Ok(c) => c,
        Err(e) if unsupported(&e) => creds_via_uuid(&mut io, &name)?,
        Err(e) => return Err(e),
    };
    Ok(FileCcache::new(primary, creds))
}

/// Store a FILE v4 cache into `KCM:residual` and make it the collection default.
///
/// sssd-kcm 2.11/2.12 has no REPLACE; this is INITIALIZE then STORE.
/// INITIALIZE-then-STORE is a transient empty window vs MIT's append.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` (`KRB5_FCC_NOFILE`) or `ErrorKind::Other` for a nonzero
/// status on GEN_NEW, INITIALIZE, STORE, or the default-cache lookup (a missing default is
/// created); `ErrorKind::InvalidData` for a reply over 10 MiB or a non-UTF-8 cache name. A
/// failed SET_DEFAULT_CACHE is ignored.
pub fn kcm_store(residual: &str, cc: &FileCcache) -> io::Result<()> {
    kcm_put(residual, cc, true)
}

/// [`kcm_store`] without `SET_DEFAULT_CACHE` (kvno store-back).
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` (`KRB5_FCC_NOFILE`) or `ErrorKind::Other` for a nonzero
/// status on GEN_NEW, INITIALIZE, STORE, or the default-cache lookup (a missing default is
/// created); `ErrorKind::InvalidData` for a reply over 10 MiB or a non-UTF-8 cache name.
pub fn kcm_store_keep_default(residual: &str, cc: &FileCcache) -> io::Result<()> {
    kcm_put(residual, cc, false)
}

/// The collection's primary cache name.
/// MIT `k5_kcm_primary_name` (`cc_kcm.c:770-793`): the GET_DEFAULT_CACHE answer.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` or `ErrorKind::Other` for a nonzero status;
/// `ErrorKind::InvalidData` for a reply over 10 MiB or a non-UTF-8 name.
pub fn kcm_primary_name() -> io::Result<String> {
    let mut io = KcmIo::connect()?;
    cstring(&io.call(OP_GET_DEFAULT_CACHE, &[])?)
}

/// Add `creds` to `KCM:residual` (empty is the primary), leaving its other credentials.
/// MIT `kcm_store` (`cc_kcm.c:865-875`): one STORE request per credential.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` (`KRB5_FCC_NOFILE`) or `ErrorKind::Other` for a nonzero
/// status on the default-cache lookup or a STORE; `ErrorKind::InvalidData` for a reply over
/// 10 MiB or a non-UTF-8 cache name.
pub fn kcm_store_creds(residual: &str, creds: &[CcacheCred]) -> io::Result<()> {
    let mut io = KcmIo::connect()?;
    let name = default_or(&mut io, residual)?;
    for c in creds {
        store_one(&mut io, &name, c)?;
    }
    Ok(())
}

fn kcm_put(residual: &str, cc: &FileCcache, set_default: bool) -> io::Result<()> {
    let mut io = KcmIo::connect()?;
    let name = default_or_create(&mut io, residual)?;
    initialize(&mut io, &name, cc)?;
    for c in cc.creds.iter().filter(|c| !c.is_removed()) {
        store_one(&mut io, &name, c)?;
    }
    if set_default {
        let _ = io.call(OP_SET_DEFAULT_CACHE, &zname(&name));
    }
    Ok(())
}

/// Destroy `KCM:residual`.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` when the cache (or, for an empty residual, a default)
/// does not exist (`KRB5_FCC_NOFILE`) and `ErrorKind::Other` for any other nonzero status;
/// `ErrorKind::InvalidData` for a reply over 10 MiB or a non-UTF-8 default name.
pub fn kcm_destroy(residual: &str) -> io::Result<()> {
    let mut io = KcmIo::connect()?;
    let name = default_or(&mut io, residual)?;
    io.call(OP_DESTROY, &zname(&name)).map(|_| ())
}

/// `kswitch -c KCM:name` (SET_DEFAULT_CACHE).
///
/// # Errors
///
/// `ErrorKind::InvalidInput` when `residual` is empty; the OS error when the KCM socket cannot
/// be connected or a read or write on it fails or times out; `ErrorKind::NotFound` for a
/// `KRB5_FCC_NOFILE` status and `ErrorKind::Other` for any other nonzero status;
/// `ErrorKind::InvalidData` for a reply over 10 MiB.
pub fn kcm_switch(residual: &str) -> io::Result<()> {
    if residual.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kswitch -c needs KCM:name",
        ));
    }
    let mut io = KcmIo::connect()?;
    io.call(OP_SET_DEFAULT_CACHE, &zname(residual)).map(|_| ())
}

/// Names of caches this uid can see.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::Other` for a nonzero status other than `KRB5_FCC_NOFILE` (a missing
/// list reads as empty, a missing cache is skipped); `ErrorKind::InvalidData` for a reply over
/// 10 MiB, a UUID list that is not a multiple of 16 bytes, or a non-UTF-8 cache name.
pub fn kcm_cache_names() -> io::Result<Vec<String>> {
    let mut io = KcmIo::connect()?;
    let uuids = match io.call(OP_GET_CACHE_UUID_LIST, &[]) {
        Ok(u) => u,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if uuids.len() % UUID_LEN != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KCM cache UUID list length",
        ));
    }
    let mut names = Vec::new();
    for chunk in uuids.chunks(UUID_LEN) {
        match io.call(OP_GET_CACHE_BY_UUID, chunk) {
            Ok(b) => names.push(cstring(&b)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(names)
}

/// The default principal of the cache `name`.
/// MIT `kcm_get_princ` (`cc_kcm.c:932-954`): a GET_PRINCIPAL request; a cache that is not
/// initialized is `KRB5_FCC_NOFILE`.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` (`KRB5_FCC_NOFILE`, also for an empty answer) or
/// `ErrorKind::Other` for a nonzero status; `ErrorKind::InvalidData` or `UnexpectedEof` for a
/// malformed principal.
pub fn kcm_principal(name: &str) -> io::Result<(Realm, PrincipalName)> {
    let mut io = KcmIo::connect()?;
    let raw = io.call(OP_GET_PRINCIPAL, &zname(name))?;
    if raw.is_empty() {
        return Err(kcm_status(KRB5_FCC_NOFILE));
    }
    let mut i = 0;
    unmarshal_princ(&raw, &mut i)
}

/// A new cache in the collection, not yet initialized.
/// MIT `kcm_gen_new` (`cc_kcm.c:795-822`): the GEN_NEW answer names it.
///
/// # Errors
///
/// The OS error when the KCM socket cannot be connected or a read or write on it fails or
/// times out; `ErrorKind::NotFound` or `ErrorKind::Other` for a nonzero status;
/// `ErrorKind::InvalidData` for a reply over 10 MiB or a non-UTF-8 name.
pub fn kcm_gen_new() -> io::Result<String> {
    let mut io = KcmIo::connect()?;
    cstring(&io.call(OP_GEN_NEW, &[])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zname_is_nul_terminated() {
        assert_eq!(KCM_SOCKET_DEFAULT, "/var/run/.heim_org.h5l.kcm-socket");
        assert_eq!(zname("0"), b"0\0");
    }

    #[test]
    fn get_cred_list_huge_count_is_invalid_data() {
        let body = [0xff, 0xff, 0xff, 0xff];
        match parse_cred_list(&body) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("huge GET_CRED_LIST count must be InvalidData"),
        }
        assert!(parse_cred_list(&[]).unwrap().is_empty());
        let truncated = [0, 0, 0, 1, 0, 0, 0, 8, 1, 2, 3];
        match parse_cred_list(&truncated) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("truncated GET_CRED_LIST cred must be InvalidData"),
        }
    }

    #[test]
    fn unsupported_is_structured_status_not_substring() {
        assert!(unsupported(&kcm_status(KRB5_FCC_INTERNAL)));
        assert!(unsupported(&kcm_status(KRB5_CC_NOSUPP)));
        assert!(!unsupported(&io::Error::other(format!(
            "unrelated {KRB5_FCC_INTERNAL}"
        ))));
    }

    fn dummy_cc() -> FileCcache {
        FileCcache::new(
            (
                krb5_types::ascii("KERBER.TEST"),
                PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            ),
            Vec::new(),
        )
    }

    fn record_store(set_default: bool) -> Vec<u16> {
        use std::os::unix::net::UnixListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        // The listener thread and the KCM client below run in this process, where the descriptor path of
        // `sock` is valid; it keeps the path short whatever the scratch root's length.
        let sock = krb5_testkit::socket_path(&krb5_testkit::scratch_dir("kcm"), "s");
        let path = sock.path().to_path_buf();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let ops = Arc::new(Mutex::new(Vec::new()));
        let ops2 = Arc::clone(&ops);
        let th = thread::spawn(move || {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            loop {
                let mut hdr = [0u8; 4];
                if s.read_exact(&mut hdr).is_err() {
                    break;
                }
                let n = u32::from_be_bytes(hdr) as usize;
                let mut payload = vec![0u8; n];
                if s.read_exact(&mut payload).is_err() {
                    break;
                }
                if payload.len() >= 4 {
                    ops2.lock()
                        .unwrap()
                        .push(u16::from_be_bytes([payload[2], payload[3]]));
                }
                let mut rep = Vec::new();
                rep.extend_from_slice(&4u32.to_be_bytes());
                rep.extend_from_slice(&0i32.to_be_bytes());
                rep.extend_from_slice(&0i32.to_be_bytes());
                if s.write_all(&rep).is_err() {
                    break;
                }
            }
        });
        SOCKET_OVERRIDE.with(|s| *s.borrow_mut() = Some(path.clone()));
        let cc = dummy_cc();
        if set_default {
            kcm_store("t", &cc).unwrap();
        } else {
            kcm_store_keep_default("t", &cc).unwrap();
        }
        SOCKET_OVERRIDE.with(|s| *s.borrow_mut() = None);
        drop(th.join());
        let _ = std::fs::remove_file(&path);
        drop(sock);
        ops.lock().unwrap().clone()
    }

    #[test]
    fn kcm_store_is_initialize_then_store_and_kvno_skips_set_default() {
        let kinit_ops = record_store(true);
        assert_eq!(kinit_ops.first().copied(), Some(OP_INITIALIZE));
        assert!(
            kinit_ops.contains(&OP_SET_DEFAULT_CACHE),
            "kinit store sets collection default: {kinit_ops:?}"
        );
        assert!(
            !kinit_ops.contains(&13_002),
            "sssd path must not probe REPLACE: {kinit_ops:?}"
        );
        let kvno_ops = record_store(false);
        assert_eq!(kvno_ops.first().copied(), Some(OP_INITIALIZE));
        assert!(
            !kvno_ops.contains(&OP_SET_DEFAULT_CACHE),
            "kvno store-back must not SET_DEFAULT_CACHE: {kvno_ops:?}"
        );
    }

    #[test]
    fn request_frame_is_len_major_minor_opcode_args() {
        let args = zname("0");
        let f = request_frame(OP_GET_CRED_LIST, &args);
        let n = u32::from_be_bytes(f[0..4].try_into().unwrap()) as usize;
        assert_eq!(n, f.len() - 4);
        assert_eq!(f[4], MAJOR);
        assert_eq!(f[5], MINOR);
        assert_eq!(&f[6..8], &OP_GET_CRED_LIST.to_be_bytes());
        assert_eq!(&f[8..], args.as_slice());
    }

    /// Live MIT 1.22.2 (cc_kcm.c): `kcm_socket` names the socket, else the compiled default.
    #[test]
    fn kcm_socket_is_the_relation_else_the_default() {
        assert_eq!(
            socket_path_from(Some("/tmp/conf.sock".into())),
            PathBuf::from("/tmp/conf.sock")
        );
        assert_eq!(
            socket_path_from(None),
            PathBuf::from("/var/run/.heim_org.h5l.kcm-socket")
        );
    }

    /// Live MIT 1.22.2: `kcm_socket = -` and a socket that is not there are "No KCM server
    /// found"; a path that is no socket, or none, is its errno.
    #[test]
    fn no_socket_is_no_kcm_server() {
        let dir = krb5_testkit::scratch_dir("kcm-no-server");
        for path in ["-".into(), dir.join("none.sock")] {
            SOCKET_OVERRIDE.with(|s| *s.borrow_mut() = Some(path));
            let e = kcm_primary_name().unwrap_err();
            assert!(kcm_no_server(&e), "{e}");
            assert_eq!(e.to_string(), "No KCM server found");
        }
        // A path that is no socket. /dev/null is short on every host; a scratch file's path can pass
        // sun_path's 107 bytes and be cut, as MIT cuts it, to a path that is not there.
        SOCKET_OVERRIDE.with(|s| *s.borrow_mut() = Some(PathBuf::from("/dev/null")));
        let e = kcm_primary_name().unwrap_err();
        assert!(!kcm_no_server(&e), "{e}");
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        // Live MIT 1.22.2: an empty value (`kcm_socket = ""`) is "Connection refused" too.
        SOCKET_OVERRIDE.with(|s| *s.borrow_mut() = Some(PathBuf::new()));
        let e = kcm_primary_name().unwrap_err();
        assert!(!kcm_no_server(&e), "{e}");
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        SOCKET_OVERRIDE.with(|s| *s.borrow_mut() = None);
    }

    #[test]
    fn get_cred_list_round_trips_ccmarshal_cred() {
        let cred = CcacheCred {
            client: (
                krb5_types::ascii("KERBER.TEST"),
                PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            ),
            server: (
                krb5_types::ascii("KERBER.TEST"),
                PrincipalName::krbtgt("KERBER.TEST"),
            ),
            key: crate::CcacheKeyblock {
                etype: 18,
                contents: vec![0x11; 32],
            },
            authtime: 10,
            starttime: 10,
            endtime: 20,
            renew_till: 0,
            is_skey: 0,
            ticket_flags: 0x4000_0000,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: vec![0x61, 0x03, 1, 2, 3],
            second_ticket: Vec::new(),
        };
        let raw = marshal_one_cred(&cred);
        let mut body = 1u32.to_be_bytes().to_vec();
        body.extend_from_slice(&(u32::try_from(raw.len()).unwrap()).to_be_bytes());
        body.extend_from_slice(&raw);
        let list = parse_cred_list(&body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key.etype, 18);
        assert_eq!(list[0].key.contents, cred.key.contents);
        assert_eq!(list[0].ticket, cred.ticket);
        assert_eq!(list[0].endtime, 20);
    }
}
