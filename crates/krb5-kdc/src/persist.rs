//! Persistent principal database: stash + at-rest encrypted JSON.

use std::fs;
use std::path::Path;

use crate::error::Error;
use crate::store::{KeyEntry, Principal, PrincipalStore, S2K_ITERS};
use krb5_crypto::{decrypt, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_protocol::write_secret_file;
use krb5_types::pac::RpcSid;
use krb5_types::PrincipalName;

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
}

impl From<Error> for PersistError {
    fn from(e: Error) -> Self {
        Self::Crypto(e.to_string())
    }
}

/// Load a store from `db_path` using the master key in `stash_path`.
///
/// # Errors
///
/// I/O or decrypt failures. A missing db is [`PersistError::Format`].
pub fn load_store(db_path: &Path, stash_path: &Path) -> Result<PrincipalStore, PersistError> {
    let master = load_stash(stash_path)?;
    let blob = fs::read(db_path)?;
    if blob.len() < 4 {
        return Err(PersistError::Format("missing KDB magic".into()));
    }
    let magic = &blob[..4];
    let v2 = magic == b"KDB2";
    let v3 = magic == b"KDB3";
    if !v2 && !v3 && magic != b"KDB1" {
        return Err(PersistError::Format("missing KDB1/KDB2/KDB3 magic".into()));
    }
    let usage = KeyUsage::new(2).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let plain =
        decrypt(&master, usage, &blob[4..]).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let mut store = parse_plain(&plain, v2, v3)?;
    store.persist_paths = Some((db_path.to_path_buf(), stash_path.to_path_buf()));
    if let Ok(meta) = std::fs::metadata(db_path) {
        store.db_stamp = Some((meta.modified().ok(), meta.len()));
    }
    Ok(store)
}

/// Save `store` to `db_path`, creating `stash_path` if needed.
///
/// # Errors
///
/// I/O or encrypt failures.
pub fn save_store(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = if stash_path.exists() {
        load_stash(stash_path)?
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

fn load_stash(path: &Path) -> Result<ProtocolKey, PersistError> {
    let bytes = fs::read(path)?;
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &bytes)
        .map_err(|e| PersistError::Crypto(e.to_string()))
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
        if let Some(sid) = RpcSid::from_sddl(&sddl) {
            store.set_domain_sid(sid);
        }
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
