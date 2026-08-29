//! Persistent principal database: stash + MIT dump version 7 at rest.
//!
//! New writes are dump text (`kdb5_util load_dump version 7`). SID/RID live
//! in dump `tl_data` (`TL_KERBER_SID`). Legacy `KDB1`/`KDB2`/`KDB3`
//! ciphertext still loads for one release. The stash remains the raw master
//! key; it is not rewritten as MIT `.k5.REALM`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::kdb_dump::{load_dump_mkey, write_dump};
use crate::mkey::{harness_master_etype, master_key_from_password};
use crate::store::{KeyEntry, Principal, PrincipalStore, S2K_ITERS, UlogEntry};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_protocol::write_secret_file;
use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;

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
/// I/O or decrypt failures. A missing db is [`PersistError::Format`].
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
/// When `KRB5_MASTER_PASSWORD` is set and the stash is new, the master key
/// is derived with the harness etype (MIT `aes256-cts-hmac-sha384-192`) so
/// `kdb5_util load` of the live file succeeds after `create -s -P`.
///
/// # Errors
///
/// I/O or dump crypto failures.
pub fn save_store(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = master_for_save(store, db_path, stash_path)?;
    let text = write_dump(store, &master)?;
    write_secret_file(db_path, text.as_bytes())?;
    save_ulog(store, db_path)?;
    Ok(())
}

fn ulog_path(db_path: &Path) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(".ulog");
    PathBuf::from(s)
}

fn save_ulog(store: &PrincipalStore, db_path: &Path) -> Result<(), PersistError> {
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
    write_secret_file(&ulog_path(db_path), text.as_bytes())?;
    Ok(())
}

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
/// I/O or encrypt failures.
pub fn save_store_legacy_kdb3(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = if stash_path.exists() {
        load_stash_etype(stash_path, EncryptionType::Aes256CtsHmacSha196)?
    } else {
        let m = random_master()?;
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

fn load_dump_with_stash(text: &str, stash: &[u8]) -> Result<PrincipalStore, PersistError> {
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
        return existing_stash_key(db_path, stash_path);
    }
    let master = if let Ok(pw) = std::env::var("KRB5_MASTER_PASSWORD") {
        let etype = persist_master_etype();
        master_key_from_password(store.realm(), pw.as_bytes(), etype)?
    } else {
        random_master()?
    };
    write_secret_file(stash_path, master.as_bytes())?;
    Ok(master)
}

fn existing_stash_key(db_path: &Path, stash_path: &Path) -> Result<ProtocolKey, PersistError> {
    let bytes = fs::read(stash_path)?;
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

fn persist_master_etype() -> EncryptionType {
    std::env::var("KRB5_MASTER_ETYPE")
        .ok()
        .and_then(|s| EncryptionType::from_mit_name(&s).ok())
        .unwrap_or_else(harness_master_etype)
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

fn random_master() -> Result<ProtocolKey, PersistError> {
    crate::store::random_key(EncryptionType::Aes256CtsHmacSha196)
        .map_err(|e| PersistError::Crypto(e.to_string()))
}

fn serialize_plain(store: &PrincipalStore) -> Vec<u8> {
    let mut out = Vec::new();
    let realm = store.realm();
    put_str(&mut out, realm);
    let n = u32::try_from(store_debug_count(store)).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    for p in store_iter(store) {
        put_str(&mut out, &p.name.components_joined());
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
        let parts: Vec<&str> = name_s.split('/').collect();
        let name = PrincipalName::try_new(ntype, parts)
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
            requires_preauth,
            max_life,
            locked,
            pw_expire,
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
