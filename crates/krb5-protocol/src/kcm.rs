//! MIT KCM client. Credentials are FILE v4.
//! A request is a 4-byte length, then major, minor, opcode and args.
//! A reply is a 4-byte length and a status, then that many bytes, starting with another status.
//! sssd-kcm answers GET_CRED_LIST. RETRIEVE and REPLACE return FCC_INTERNAL.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use krb5_config::Krb5Conf;
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
const OP_GET_KDC_OFFSET: u16 = 22;
const OP_SET_KDC_OFFSET: u16 = 23;
const OP_GET_CRED_LIST: u16 = 13_001;

const KRB5_CC_NOSUPP: i32 = -1_765_328_137;
const KRB5_CC_IO: i32 = -1_765_328_183;
const KRB5_FCC_INTERNAL: i32 = -1_765_328_188;
const KRB5_FCC_NOFILE: i32 = -1_765_328_189;
// MIT: `KRB5_KCM_NO_SERVER` (k5e1_err.et:44-44)
// the code for no KCM daemon on the socket.
const KRB5_KCM_NO_SERVER: i32 = -1_750_600_181;

/// The KCM socket when `kcm_socket` names none.
// MIT: `DEFAULT_KCM_SOCKET_PATH` (kcm.h:43-43)
pub const KCM_SOCKET_DEFAULT: &str = "/var/run/.heim_org.h5l.kcm-socket";

const SUN_PATH_LEN: usize = 108;

struct KcmIo {
    stream: UnixStream,
    path: PathBuf,
}

impl KcmIo {
    // MIT: `kcmio_unix_socket_connect` (cc_kcm.c:313-330)
    /// A socket of "-", or one that is not there, is KRB5_KCM_NO_SERVER.
    /// Any other failure to connect is its errno.
    fn connect(profile: &Krb5Conf) -> io::Result<Self> {
        Self::connect_to(kcm_socket_path(profile))
    }

    fn connect_to(path: PathBuf) -> io::Result<Self> {
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
        Ok(Self { stream, path })
    }

    fn reconnect(&mut self) -> io::Result<()> {
        *self = Self::connect_to(self.path.clone())?;
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

#[must_use]
pub fn kcm_socket_path(profile: &Krb5Conf) -> PathBuf {
    #[cfg(test)]
    if let Some(p) = SOCKET_OVERRIDE.with(|s| s.borrow().clone()) {
        return p;
    }
    socket_path_from(profile.kcm_socket.clone())
}

fn socket_path_from(kcm_socket: Option<String>) -> PathBuf {
    PathBuf::from(kcm_socket.unwrap_or_else(|| KCM_SOCKET_DEFAULT.to_owned()))
}

/// An empty kcm_socket is the abstract socket of 107 NUL bytes, which nothing binds.
/// With no abstract sockets, that refusal is returned as is.
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

/// A name resolves only when a KCM daemon answers.
// MIT: `kcm_resolve` (cc_kcm.c:750-752)
pub fn kcm_reachable(profile: &Krb5Conf) -> io::Result<()> {
    KcmIo::connect(profile).map(drop)
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

/// An empty residual is the default cache.
pub fn kcm_load(profile: &Krb5Conf, residual: &str) -> io::Result<FileCcache> {
    let mut io = KcmIo::connect(profile)?;
    let name = default_or(&mut io, residual)?;
    let primary = get_principal(&mut io, &name)?;
    let creds = match creds_via_list(&mut io, &name) {
        Ok(c) => c,
        Err(e) if unsupported(&e) => creds_via_uuid(&mut io, &name)?,
        Err(e) => return Err(e),
    };
    let mut cc = FileCcache::new(primary, creds);
    // MIT: `get_kdc_offset` (lib/krb5/ccache/cc_kcm.c:683-701)
    if let Ok(body) = io.call(OP_GET_KDC_OFFSET, &zname(&name))
        && body.len() >= 4
    {
        let sec = i32::from_be_bytes(body[..4].try_into().unwrap_or([0; 4]));
        let off = i64::from(sec);
        cc.set_deltatime(off);
        cc.kcm_offset = Some(off);
    }
    Ok(cc)
}

/// Stored, and made the collection default.
pub fn kcm_store(profile: &Krb5Conf, residual: &str, cc: &FileCcache) -> io::Result<()> {
    kcm_put(profile, residual, cc, true)
}

/// No SET_DEFAULT_CACHE. A kvno stores back into the same cache.
pub fn kcm_store_keep_default(
    profile: &Krb5Conf,
    residual: &str,
    cc: &FileCcache,
) -> io::Result<()> {
    kcm_put(profile, residual, cc, false)
}

// MIT: `k5_kcm_primary_name` (cc_kcm.c:770-793)
/// The GET_DEFAULT_CACHE answer.
pub fn kcm_primary_name(profile: &Krb5Conf) -> io::Result<String> {
    let mut io = KcmIo::connect(profile)?;
    cstring(&io.call(OP_GET_DEFAULT_CACHE, &[])?)
}

/// The cache's other credentials stay.
// MIT: `kcm_store` (cc_kcm.c:865-875)
/// One STORE request per credential.
pub fn kcm_store_creds(profile: &Krb5Conf, residual: &str, creds: &[CcacheCred]) -> io::Result<()> {
    let mut io = KcmIo::connect(profile)?;
    let name = default_or(&mut io, residual)?;
    for c in creds {
        store_one(&mut io, &name, c)?;
    }
    Ok(())
}

fn kcm_put(
    profile: &Krb5Conf,
    residual: &str,
    cc: &FileCcache,
    set_default: bool,
) -> io::Result<()> {
    let mut io = KcmIo::connect(profile)?;
    let name = default_or_create(&mut io, residual)?;
    initialize(&mut io, &name, cc)?;
    // MIT: `set_kdc_offset` (lib/krb5/ccache/cc_kcm.c:705-715)
    if profile.kdc_timesync
        && let Some(sec) = cc.deltatime_seconds()
    {
        let bits = i32::try_from(sec).unwrap_or(if sec < 0 { i32::MIN } else { i32::MAX });
        let mut args = zname(&name);
        args.extend_from_slice(&bits.to_be_bytes());
        let _ = io.call(OP_SET_KDC_OFFSET, &args);
    }
    for c in cc.creds.iter().filter(|c| !c.is_removed()) {
        store_one(&mut io, &name, c)?;
    }
    if set_default {
        let _ = io.call(OP_SET_DEFAULT_CACHE, &zname(&name));
    }
    Ok(())
}

pub fn kcm_destroy(profile: &Krb5Conf, residual: &str) -> io::Result<()> {
    let mut io = KcmIo::connect(profile)?;
    let name = default_or(&mut io, residual)?;
    io.call(OP_DESTROY, &zname(&name)).map(|_| ())
}

/// SET_DEFAULT_CACHE.
pub fn kcm_switch(profile: &Krb5Conf, residual: &str) -> io::Result<()> {
    if residual.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kswitch -c needs KCM:name",
        ));
    }
    let mut io = KcmIo::connect(profile)?;
    io.call(OP_SET_DEFAULT_CACHE, &zname(residual)).map(|_| ())
}

pub fn kcm_cache_names(profile: &Krb5Conf) -> io::Result<Vec<String>> {
    let mut io = KcmIo::connect(profile)?;
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

// MIT: `kcm_get_princ` (cc_kcm.c:932-954)
/// A cache that is not initialized is KRB5_FCC_NOFILE.
pub fn kcm_principal(profile: &Krb5Conf, name: &str) -> io::Result<(Realm, PrincipalName)> {
    let mut io = KcmIo::connect(profile)?;
    let raw = io.call(OP_GET_PRINCIPAL, &zname(name))?;
    if raw.is_empty() {
        return Err(kcm_status(KRB5_FCC_NOFILE));
    }
    let mut i = 0;
    unmarshal_princ(&raw, &mut i)
}

/// Not yet initialized.
// MIT: `kcm_gen_new` (cc_kcm.c:795-822)
/// The GEN_NEW answer names it.
pub fn kcm_gen_new(profile: &Krb5Conf) -> io::Result<String> {
    let mut io = KcmIo::connect(profile)?;
    cstring(&io.call(OP_GEN_NEW, &[])?)
}
