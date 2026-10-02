//! Persistent principal database: stash + MIT dump version 7 at rest.
//!
//! New writes are dump text (`kdb5_util load_dump version 7`). SID/RID live
//! in dump `tl_data` (`TL_KERBER_SID`). Legacy `KDB1`/`KDB2`/`KDB3`
//! ciphertext still loads for one release. The stash is a keytab-format
//! `.k5.REALM` (a single `K/M@REALM` entry, MIT `krb5_def_store_mkey_list`);
//! a legacy raw-key stash still loads (`krb5_db_def_fetch_mkey`) and is
//! rewritten in keytab format on the next save the writer may make to it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::kdb_dump::{load_dump_mkey, write_dump};
use crate::mkey::master_key_from_password;
use crate::store::{KeyEntry, Principal, PrincipalStore, S2K_ITERS, UlogEntry};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_protocol::{
    Keytab, check_secret_file_writable, write_fresh_secret_file, write_secret_file,
};
use krb5_types::pac::RpcSid;
use krb5_types::{PrincipalName, parse_name};

const DUMP_PREFIX: &[u8] = b"kdb5_util load_dump version ";

/// Persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// I/O.
    #[error("persist io: {0}")]
    Io(#[from] std::io::Error),
    /// Crypto.
    #[error("persist crypto: {0}")]
    Crypto(String),
    /// Format.
    #[error("persist format: {0}")]
    Format(String),
    /// `db_library` is not a supported backend.
    #[error("unknown db_library: {0}")]
    UnknownDbLibrary(String),
}

impl From<Error> for PersistError {
    fn from(e: Error) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<crate::kdb_dump::DumpError> for PersistError {
    fn from(e: crate::kdb_dump::DumpError) -> Self {
        match e {
            crate::kdb_dump::DumpError::Io(e) => Self::Io(e),
            crate::kdb_dump::DumpError::Crypto(s) => Self::Crypto(s),
            crate::kdb_dump::DumpError::Format(s) => Self::Format(s),
        }
    }
}

/// Load a store from `db_path` using the master key in `stash_path`.
///
/// Dump version 6/7 text is the canonical format. `KDB1`/`KDB2`/`KDB3`
/// ciphertext is still accepted.
///
/// # Errors
///
/// [`PersistError::Io`] when the stash or the database cannot be read (a missing file included);
/// [`PersistError::Format`] when a dump is not UTF-8, a legacy database has no KDB magic or a
/// malformed record, or the `.ulog` file beside it is malformed; [`PersistError::Crypto`] when no
/// key from the stash loads the dump (a malformed dump included) or decrypts a legacy database,
/// or a legacy key is unusable.
pub fn load_store(db_path: &Path, stash_path: &Path) -> Result<PrincipalStore, PersistError> {
    let stash = fs::read(stash_path)?;
    let blob = fs::read(db_path)?;
    let mut store = if blob.starts_with(DUMP_PREFIX) {
        let text = std::str::from_utf8(&blob)
            .map_err(|_| PersistError::Format("dump is not utf-8".into()))?;
        load_dump_with_stash(text, &stash)?
    } else {
        load_kdb_blob(&blob, &stash)?
    };
    store.persist_paths = Some((db_path.to_path_buf(), stash_path.to_path_buf()));
    if let Ok(meta) = std::fs::metadata(db_path) {
        store.db_stamp = Some((meta.modified().ok(), meta.len()));
    }
    load_ulog(&mut store, db_path)?;
    Ok(store)
}

/// Save `store` as MIT dump version 7. Creates `stash_path` if needed.
///
/// The database, its `.ulog` and a rewritten stash keep the owner, group and mode of the files
/// they replace (`write_secret_file`), so `kadmind` as root and `kadmin.local` as another user
/// can share them. A writer that may not write the database or its `.ulog` changes nothing.
///
/// A new stash holds the store's `K/M` key when the store has one (the master key its dump
/// was loaded with); otherwise a random key of the realm's `master_key_type`
/// ([`crate::master_etype`]), or with the `test-hooks` feature one derived from
/// `KRB5_MASTER_PASSWORD` when that is set.
///
/// # Errors
///
/// [`PersistError::Io`] when the stash cannot be read or the stash, database or `.ulog` file
/// cannot be written (an existing one the writer may not open read-write is refused before any
/// file changes); [`PersistError::Crypto`] when an existing stash is not a usable master key,
/// `master_key_type` names no supported enctype, a new master key cannot be derived or
/// generated, or a key cannot be wrapped; [`PersistError::Format`] when a new stash is needed
/// and the KDC profile cannot be read or the realm is not ASCII.
pub fn save_store(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    save_store_as(store, db_path, stash_path, DbWrite::InPlace)
}

/// Save `store` as a full load leaves it: the database is a new 0600 file owned by the writer,
/// whatever it replaces; the `.ulog` and the stash are handled as [`save_store`] handles them.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1490-1508`): a full load is written to a temporary database.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1551-1569`): the temporary database is then made live.
///
/// # Errors
///
/// As [`save_store`], except that the database itself need not be writable: only its directory.
pub fn save_store_fresh(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    save_store_as(store, db_path, stash_path, DbWrite::Fresh)
}

fn save_store_as(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
    how: DbWrite,
) -> Result<(), PersistError> {
    // MIT `ulog_map` (`lib/kdb/kdb_log.c:525-526`): an existing update log is reopened `O_RDWR` as the database is.
    // Both are checked before either changes, so a refused writer leaves no half-saved store.
    check_writable(db_path, how)?;
    let master = master_for_save(store, db_path, stash_path)?;
    save_store_with_master(store, db_path, &master, how)
}

/// How [`save_store_with_master`] replaces the database file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbWrite {
    /// An update in place: the database keeps its owner, group and mode, and a writer that may
    /// not write it is refused ([`write_secret_file`]).
    InPlace,
    /// A new 0600 file owned by the writer ([`write_fresh_secret_file`]), as a full load leaves.
    Fresh,
}

fn check_writable(db_path: &Path, how: DbWrite) -> Result<(), PersistError> {
    if how == DbWrite::InPlace {
        check_secret_file_writable(db_path)?;
    }
    check_secret_file_writable(&ulog_path(db_path))?;
    Ok(())
}

/// Save `store` with every key wrapped under `master`; the stash is not read or written.
///
/// The `.ulog` beside the database is always updated in place.
///
/// # Errors
///
/// [`PersistError::Io`] when the database or `.ulog` cannot be written (for
/// [`DbWrite::InPlace`], an existing database the writer may not open read-write is refused
/// before any file changes); [`PersistError::Crypto`] when a key cannot be wrapped.
pub fn save_store_with_master(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    how: DbWrite,
) -> Result<(), PersistError> {
    check_writable(db_path, how)?;
    let text = write_dump(store, master)?;
    match how {
        DbWrite::InPlace => write_secret_file(db_path, text.as_bytes())?,
        DbWrite::Fresh => write_fresh_secret_file(db_path, text.as_bytes())?,
    }
    save_ulog(store, db_path)?;
    Ok(())
}

/// Write `text`, dump text with no principal record, as the database: a full load
/// ([`DbWrite::Fresh`]) leaves it as a new file beside an empty `.ulog`, an update
/// ([`DbWrite::InPlace`]) rewrites the database alone. No key is wrapped, so no master key is
/// needed.
///
/// # Errors
///
/// [`PersistError::Io`] when the database or `.ulog` cannot be written (for
/// [`DbWrite::InPlace`], an existing database the writer may not open read-write is refused
/// before any file changes).
pub fn save_dump_text(db_path: &Path, text: &str, how: DbWrite) -> Result<(), PersistError> {
    check_writable(db_path, how)?;
    match how {
        DbWrite::InPlace => write_secret_file(db_path, text.as_bytes())?,
        DbWrite::Fresh => {
            write_fresh_secret_file(db_path, text.as_bytes())?;
            write_secret_file(&ulog_path(db_path), b"ulog 1\n")?;
        }
    }
    Ok(())
}

/// Why [`create_store`] wrote nothing.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The database path could not be created: it exists (`AlreadyExists`), its directory does
    /// not (`NotFound`), or the OS refused.
    #[error("{0}")]
    Create(std::io::Error),
    /// The database was reserved but could not be written.
    #[error(transparent)]
    Persist(#[from] PersistError),
}

/// Write a new database for `store` under `master`, as `kdb5_util create` makes one.
///
/// The path is reserved first with an exclusive create, so an existing database (or any file
/// there) is never replaced; then the dump and its `.ulog` are written as new 0600 files owned
/// by the writer. The stash is the caller's ([`write_stash`]).
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:718-720`): the database is opened `O_RDWR | O_CREAT | O_EXCL`, mode 0600.
///
/// # Errors
///
/// [`CreateError::Create`] when the database path cannot be created exclusively (nothing is
/// written); [`CreateError::Persist`] when the dump or `.ulog` cannot be written or a key cannot
/// be wrapped (the reservation is removed again).
pub fn create_store(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
) -> Result<(), CreateError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(db_path).map_err(CreateError::Create)?;
    let written = write_dump(store, master)
        .map_err(PersistError::from)
        .and_then(|text| Ok(write_fresh_secret_file(db_path, text.as_bytes())?))
        .and_then(|()| {
            let ulog = ulog_text(store);
            Ok(write_fresh_secret_file(
                &ulog_path(db_path),
                ulog.as_bytes(),
            )?)
        });
    if let Err(e) = written {
        let _ = fs::remove_file(db_path);
        return Err(e.into());
    }
    Ok(())
}

/// Write the master-key stash: a FILE keytab with one `K/M@realm` entry at `kvno`, as a new
/// 0600 file owned by the writer, whatever it replaces.
/// MIT `krb5_def_store_mkey_list` (`lib/kdb/kdb_default.c:111-213`): the stash is a keytab holding the master key list.
///
/// # Errors
///
/// [`PersistError::Format`] when `realm` is not ASCII; [`PersistError::Io`] when the file
/// cannot be written.
pub fn write_stash(
    path: &Path,
    realm: &str,
    master: &ProtocolKey,
    kvno: u32,
) -> Result<(), PersistError> {
    let realm_a = krb5_types::try_ascii(realm).map_err(|e| PersistError::Format(e.to_string()))?;
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    let bytes = Keytab::single(realm_a, name, kvno, master.clone()).to_bytes();
    write_fresh_secret_file(path, &bytes)?;
    Ok(())
}

/// The master key a stash holds: its `K/M` entry, else (a legacy raw stash) the raw key that
/// opens the database at `db_path`.
/// MIT `krb5_db_def_fetch_mkey` (`lib/kdb/kdb_default.c:356-393`): the keytab form first, then the old stash form.
///
/// # Errors
///
/// [`PersistError::Io`] when the stash cannot be read (a missing file included);
/// [`PersistError::Crypto`] when it holds no usable master key.
pub fn read_stash(stash_path: &Path, db_path: &Path) -> Result<ProtocolKey, PersistError> {
    existing_stash_key(db_path, stash_path)
}

/// The master keys stash bytes may hold: the `K/M` entry of a keytab stash, else each enctype a
/// legacy raw stash may be. Empty when the bytes are neither.
#[must_use]
pub fn stash_keys(bytes: &[u8]) -> Vec<ProtocolKey> {
    if let Some(k) = stash_keytab_key(bytes) {
        return vec![k];
    }
    stash_etypes()
        .into_iter()
        .filter_map(|etype| ProtocolKey::from_bytes(etype, bytes).ok())
        .collect()
}

fn ulog_path(db_path: &Path) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(".ulog");
    PathBuf::from(s)
}

fn ulog_text(store: &PrincipalStore) -> String {
    let mut text = String::from("ulog 1\n");
    for e in store.ulog() {
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}",
            e.sno,
            e.time,
            u32::from(e.deleted),
            e.name
        );
    }
    text
}

fn save_ulog(store: &PrincipalStore, db_path: &Path) -> Result<(), PersistError> {
    write_secret_file(&ulog_path(db_path), ulog_text(store).as_bytes())?;
    Ok(())
}

/// MIT `ulog_map` (`kdb_log.c:514-518`): a missing update log is not a corrupt log.
/// A file whose first line is not the ulog header is not loaded, and a missing file leaves the
/// store's log empty.
fn load_ulog(store: &mut PrincipalStore, db_path: &Path) -> Result<(), PersistError> {
    let path = ulog_path(db_path);
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let mut lines = text.lines();
    let Some(hdr) = lines.next() else {
        return Ok(());
    };
    if !hdr.starts_with("ulog ") {
        return Err(PersistError::Format("ulog header".into()));
    }
    let mut entries = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut f = line.splitn(4, '\t');
        let sno: u32 = f
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| PersistError::Format("ulog sno".into()))?;
        let time: u32 = f
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| PersistError::Format("ulog time".into()))?;
        let deleted = f.next() == Some("1");
        let name = f
            .next()
            .ok_or_else(|| PersistError::Format("ulog name".into()))?
            .to_owned();
        let princ = if deleted {
            None
        } else {
            store.get(&name).cloned()
        };
        entries.push(UlogEntry {
            sno,
            time,
            name,
            deleted,
            princ,
        });
    }
    store.restore_ulog(entries);
    Ok(())
}

/// Write a KDB3 ciphertext (one-release load tests / migration helper).
///
/// New production writes use [`save_store`] (dump v7). This remains so a
/// generated legacy blob can prove `load_store` still reads KDB3.
///
/// # Errors
///
/// [`PersistError::Io`] when an existing stash cannot be read or the stash or database cannot be
/// written; [`PersistError::Crypto`] when an existing stash is not a 32-byte key, a new one cannot
/// be generated, or the encryption fails.
pub fn save_store_legacy_kdb3(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = if stash_path.exists() {
        load_stash_etype(stash_path, EncryptionType::Aes256CtsHmacSha196)?
    } else {
        // The KDB3 stash is a raw aes256-cts-hmac-sha1-96 key by format.
        let m = crate::store::random_key(EncryptionType::Aes256CtsHmacSha196)
            .map_err(|e| PersistError::Crypto(e.to_string()))?;
        write_secret_file(stash_path, m.as_bytes())?;
        m
    };
    let plain = serialize_plain(store);
    let usage = KeyUsage::new(2).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let cipher =
        encrypt(&master, usage, &plain).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let mut out = b"KDB3".to_vec();
    out.extend_from_slice(&cipher);
    write_secret_file(db_path, &out)?;
    Ok(())
}

/// Master key from a keytab-format stash (`krb5_db_def_fetch_mkey_keytab`):
/// the `K/M@REALM` entry, etype embedded. `None` for a legacy raw stash.
pub(crate) fn stash_keytab_key(bytes: &[u8]) -> Option<ProtocolKey> {
    let kt = Keytab::parse(bytes).ok()?;
    let km = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    kt.entries.into_iter().find(|e| e.name == km).map(|e| e.key)
}

/// Keytab-format stash bytes for `master` (`krb5_def_store_mkey_list`): one
/// `K/M@REALM` entry at kvno 1.
fn stash_keytab_bytes(realm: &str, master: &ProtocolKey) -> Result<Vec<u8>, PersistError> {
    let realm_a = krb5_types::try_ascii(realm).map_err(|e| PersistError::Format(e.to_string()))?;
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    Ok(Keytab::single(realm_a, name, 1, master.clone()).to_bytes())
}

/// Load dump text whose keys the master key in `stash` (stash file bytes) opens: the keytab
/// form's `K/M` entry, else each enctype a legacy raw stash may be.
///
/// # Errors
///
/// [`PersistError::Crypto`] when no key the stash holds loads the dump (a malformed dump
/// included).
pub fn load_dump_with_stash(text: &str, stash: &[u8]) -> Result<PrincipalStore, PersistError> {
    // krb5_db_def_fetch_mkey: keytab format first (etype known, one decrypt),
    // then the legacy raw stash (trial over the two harness etypes).
    if let Some(mkey) = stash_keytab_key(stash)
        && let Ok(store) = load_dump_mkey(text, &mkey)
    {
        return Ok(store);
    }
    for etype in stash_etypes() {
        let Ok(mkey) = ProtocolKey::from_bytes(etype, stash) else {
            continue;
        };
        if let Ok(store) = load_dump_mkey(text, &mkey) {
            return Ok(store);
        }
    }
    Err(PersistError::Crypto(
        "stash master key did not decrypt dump key_data".into(),
    ))
}

fn load_kdb_blob(blob: &[u8], stash: &[u8]) -> Result<PrincipalStore, PersistError> {
    if blob.len() < 4 {
        return Err(PersistError::Format("missing KDB magic".into()));
    }
    let magic = &blob[..4];
    let v2 = magic == b"KDB2";
    let v3 = magic == b"KDB3";
    if !v2 && !v3 && magic != b"KDB1" {
        return Err(PersistError::Format(
            "missing dump header or KDB1/KDB2/KDB3 magic".into(),
        ));
    }
    let master = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, stash)
        .map_err(|e| PersistError::Crypto(e.to_string()))?;
    let usage = KeyUsage::new(2).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let plain =
        decrypt(&master, usage, &blob[4..]).map_err(|e| PersistError::Crypto(e.to_string()))?;
    parse_plain(&plain, v2, v3)
}

fn master_for_save(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<ProtocolKey, PersistError> {
    if stash_path.exists() {
        let master = existing_stash_key(db_path, stash_path)?;
        // A legacy raw-key stash is rewritten in keytab format when the writer may write it. The
        // rewrite is optional: a stash the writer may only read still serves this save.
        if stash_keytab_key(&fs::read(stash_path)?).is_none()
            && check_secret_file_writable(stash_path).is_ok()
        {
            write_secret_file(stash_path, &stash_keytab_bytes(store.realm(), &master)?)?;
        }
        return Ok(master);
    }
    // MIT `add_principal` (`kadmin/dbutil/kdb5_create.c:409-424`): `K/M`'s key is the master key, so a new stash holds it.
    let realm = store.realm();
    let km = store
        .get(&format!("K/M@{realm}"))
        .and_then(|km| km.keys.first())
        .map(|k| k.key.clone());
    let master = if let Some(key) = km {
        key
    } else {
        let etype = persist_master_etype(realm)?;
        // MIT `kdb5_create` (`kadmin/dbutil/kdb5_create.c:200-220`): the master password is `-P` or typed, never the environment; the gates' variable is a test hook.
        #[cfg(feature = "test-hooks")]
        let hooked = std::env::var("KRB5_MASTER_PASSWORD")
            .ok()
            .map(zeroize::Zeroizing::new);
        #[cfg(not(feature = "test-hooks"))]
        let hooked: Option<zeroize::Zeroizing<String>> = None;
        match hooked {
            Some(pw) => master_key_from_password(realm, pw.as_bytes(), etype)?,
            None => crate::store::random_key(etype)?,
        }
    };
    write_secret_file(stash_path, &stash_keytab_bytes(realm, &master)?)?;
    Ok(master)
}

fn existing_stash_key(db_path: &Path, stash_path: &Path) -> Result<ProtocolKey, PersistError> {
    let bytes = fs::read(stash_path)?;
    if let Some(mkey) = stash_keytab_key(&bytes) {
        return Ok(mkey);
    }
    if let Ok(blob) = fs::read(db_path)
        && blob.starts_with(DUMP_PREFIX)
        && let Ok(text) = std::str::from_utf8(&blob)
    {
        for etype in stash_etypes() {
            let Ok(mkey) = ProtocolKey::from_bytes(etype, &bytes) else {
                continue;
            };
            if load_dump_mkey(text, &mkey).is_ok() {
                return Ok(mkey);
            }
        }
    }
    for etype in stash_etypes() {
        if let Ok(mkey) = ProtocolKey::from_bytes(etype, &bytes) {
            return Ok(mkey);
        }
    }
    Err(PersistError::Crypto(
        "stash is not a usable master key".into(),
    ))
}

/// The master key type of a new stash for `realm`: the name
/// [`krb5_config::KdcPaths::master_key_type`] resolves for it (the realm's kdc.conf
/// `master_key_type`, or what overrides that resolver takes), else
/// [`crate::default_master_etype`], as `krb5-kdb` resolves it.
fn persist_master_etype(realm: &str) -> Result<EncryptionType, PersistError> {
    let paths = krb5_config::KdcPaths::resolve(Some(realm))
        .map_err(|e| PersistError::Format(format!("kdc.conf: {e}")))?;
    crate::mkey::master_etype(paths.master_key_type.as_deref())
        .map_err(|e| PersistError::Crypto(format!("master_key_type {e}")))
}

fn stash_etypes() -> [EncryptionType; 2] {
    [
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes256CtsHmacSha196,
    ]
}

fn load_stash_etype(path: &Path, etype: EncryptionType) -> Result<ProtocolKey, PersistError> {
    let bytes = fs::read(path)?;
    ProtocolKey::from_bytes(etype, &bytes).map_err(|e| PersistError::Crypto(e.to_string()))
}

fn serialize_plain(store: &PrincipalStore) -> Vec<u8> {
    let mut out = Vec::new();
    let realm = store.realm();
    put_str(&mut out, realm);
    let n = u32::try_from(store_debug_count(store)).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    for p in store_iter(store) {
        put_str(&mut out, &p.name.unparse());
        out.extend_from_slice(&p.name.name_type.to_be_bytes());
        put_bytes(&mut out, &p.salt);
        out.push(u8::from(p.requires_preauth));
        out.extend_from_slice(&p.max_life.to_be_bytes());
        let nk = u32::try_from(p.keys.len()).unwrap_or(0);
        out.extend_from_slice(&nk.to_be_bytes());
        for k in &p.keys {
            out.extend_from_slice(&k.etype.to_iana().to_be_bytes());
            out.extend_from_slice(&k.kvno.to_be_bytes());
            put_bytes(&mut out, k.key.as_bytes());
        }
        out.push(u8::from(p.locked));
        out.extend_from_slice(&p.pw_expire.to_be_bytes());
    }
    out.extend_from_slice(b"SID1");
    put_str(&mut out, &store.domain_sid().to_sddl());
    out.extend_from_slice(&store.next_rid().to_be_bytes());
    let nr = u32::try_from(store_debug_count(store)).unwrap_or(0);
    out.extend_from_slice(&nr.to_be_bytes());
    for p in store_iter(store) {
        put_str(&mut out, &p.id());
        out.extend_from_slice(&p.rid.to_be_bytes());
    }
    out
}

/// MIT `krb5_decode_princ_entry` (`db2/kdb_xdr.c:253-256`): a record shorter than the base
/// principal is truncated and not loaded.
/// An unknown etype or a key of the wrong length fails the whole store, so a partial
/// database is not opened.
fn parse_plain(plain: &[u8], v2: bool, v3: bool) -> Result<PrincipalStore, PersistError> {
    let mut i = 0;
    let realm = take_str(plain, &mut i)?;
    let mut store = PrincipalStore::new(realm);
    let n = take_u32(plain, &mut i)?;
    for _ in 0..n {
        let name_s = take_str(plain, &mut i)?;
        let ntype = take_i32(plain, &mut i)?;
        let salt = take_bytes(plain, &mut i)?;
        let requires_preauth = take_u8(plain, &mut i)? != 0;
        let max_life = take_u64(plain, &mut i)?;
        let nk = take_u32(plain, &mut i)?;
        let mut keys = Vec::new();
        for _ in 0..nk {
            let et = take_i32(plain, &mut i)?;
            let kvno = take_u32(plain, &mut i)?;
            let kb = take_bytes(plain, &mut i)?;
            let etype =
                EncryptionType::known(et).map_err(|e| PersistError::Crypto(e.to_string()))?;
            let key = ProtocolKey::from_bytes(etype, &kb)
                .map_err(|e| PersistError::Crypto(e.to_string()))?;
            keys.push(KeyEntry::new(etype, key, kvno));
        }
        let (comps, _) =
            parse_name(&name_s, "").map_err(|e| PersistError::Format(e.to_string()))?;
        let name = PrincipalName::try_new(ntype, comps)
            .map_err(|e| PersistError::Format(e.to_string()))?;
        if v2 && i < plain.len() {
            // KDB2 stored a unused SPAKE `w`; skip the length-prefixed blob.
            let _ = take_bytes(plain, &mut i)?;
        }
        let (locked, pw_expire) = if v2 || v3 {
            (take_u8(plain, &mut i)? != 0, take_u32(plain, &mut i)?)
        } else {
            (false, 0)
        };
        let p = Principal::from_keys(
            name,
            store.realm().to_owned(),
            keys,
            salt,
            crate::store::PrincipalFields {
                requires_preauth,
                max_life,
                locked,
                pw_expire,
            },
        );
        store_insert(&mut store, p);
        let _ = S2K_ITERS;
    }
    if i + 4 <= plain.len() && &plain[i..i + 4] == b"SID1" {
        i += 4;
        let sddl = take_str(plain, &mut i)?;
        let Some(sid) = RpcSid::from_sddl(&sddl) else {
            return Err(PersistError::Format(format!(
                "SID1 trailer is not valid SDDL: {sddl}"
            )));
        };
        store.set_domain_sid(sid);
        let next = take_u32(plain, &mut i)?;
        let nrid = take_u32(plain, &mut i)?;
        for _ in 0..nrid {
            let id = take_str(plain, &mut i)?;
            let rid = take_u32(plain, &mut i)?;
            store.set_principal_rid(&id, rid);
        }
        store.set_next_rid(next);
    }
    Ok(store)
}

fn store_debug_count(store: &PrincipalStore) -> usize {
    store_iter(store).count()
}

fn store_iter(store: &PrincipalStore) -> impl Iterator<Item = &Principal> {
    store.debug_principals()
}

fn store_insert(store: &mut PrincipalStore, p: Principal) {
    store.debug_insert(p);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let n = u32::try_from(b.len()).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
}

fn take_u8(b: &[u8], i: &mut usize) -> Result<u8, PersistError> {
    if *i >= b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = b[*i];
    *i += 1;
    Ok(v)
}

fn take_u32(b: &[u8], i: &mut usize) -> Result<u32, PersistError> {
    if *i + 4 > b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = u32::from_be_bytes(
        b[*i..*i + 4]
            .try_into()
            .map_err(|_| PersistError::Format("u32".into()))?,
    );
    *i += 4;
    Ok(v)
}

fn take_i32(b: &[u8], i: &mut usize) -> Result<i32, PersistError> {
    Ok(i32::from_be_bytes(take_u32(b, i)?.to_be_bytes()))
}

fn take_u64(b: &[u8], i: &mut usize) -> Result<u64, PersistError> {
    if *i + 8 > b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = u64::from_be_bytes(
        b[*i..*i + 8]
            .try_into()
            .map_err(|_| PersistError::Format("u64".into()))?,
    );
    *i += 8;
    Ok(v)
}

fn take_bytes(b: &[u8], i: &mut usize) -> Result<Vec<u8>, PersistError> {
    let n = take_u32(b, i)? as usize;
    if *i + n > b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = b[*i..*i + n].to_vec();
    *i += n;
    Ok(v)
}

fn take_str(b: &[u8], i: &mut usize) -> Result<String, PersistError> {
    let v = take_bytes(b, i)?;
    String::from_utf8(v).map_err(|_| PersistError::Format("utf8".into()))
}

#[cfg(test)]
mod tests {
    use crate::mkey::{default_master_etype, master_etype};
    use krb5_crypto::EncryptionType;

    #[test]
    fn master_key_type_is_honored_and_defaults_to_mits() {
        // MIT's DEFAULT_KDC_ENCTYPE (master_key_type unset) is aes256-cts-hmac-sha1-96
        // (settled live: `getprinc K/M` of a realm created with no master_key_type).
        assert_eq!(master_etype(None), Ok(default_master_etype()));
        assert_eq!(master_etype(None), Ok(EncryptionType::Aes256CtsHmacSha196));
        // A configured master_key_type is honored on the persist path and by krb5-kdb.
        assert_eq!(
            master_etype(Some("aes256-cts-hmac-sha1-96")),
            Ok(EncryptionType::Aes256CtsHmacSha196)
        );
        assert_eq!(
            master_etype(Some("aes256-cts-hmac-sha384-192")),
            Ok(EncryptionType::Aes256CtsHmacSha384192)
        );
        // A name that is no enctype makes no master key, as in MIT.
        assert!(master_etype(Some("no-such-enctype")).is_err());
    }
}
