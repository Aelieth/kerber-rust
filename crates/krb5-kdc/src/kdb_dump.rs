//! MIT `kdb5_util` dump version 6/7 textual codec.
//!
//! Grammar (MIT `k5beta7_common` / `process_k5beta7_princ`):
//! `princ\tlen\tnamelen\tn_tl_data\tn_key_data\te_length\tname\t`
//! `attributes\tmax_life\tmax_renewable_life\texpiration\t`
//! `pw_expiration\tlast_success\tlast_failed\tfail_auth_count`
//! then `n_tl_data` × `\ttype\tlength\thex`, a tab, then `n_key_data` ×
//! `ver\tkvno\t` and `ver` × `type\tlength\thex\t`, then `e_data` (`-1` if
//! empty) and `;`.
//!
//! MIT 1.22.2 default dump is version **7** (`-r18` is version 6; princ
//! records are the same). Field-count/order/hex mismatches fail parse.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use krb5_crypto::{kdb_decrypt_key, kdb_encrypt_key, EncryptionType, ProtocolKey};
use krb5_protocol::write_secret_file;
use krb5_types::pac::RpcSid;
use krb5_types::PrincipalName;

use crate::error::Error as KdcError;
use crate::mkey::{harness_master_etype, master_key_from_password, MASTER_NAME};
use crate::store::{
    KeyEntry, Principal, PrincipalStore, TlData, KDB_DISALLOW_ALL_TIX, KDB_LOCKDOWN_KEYS,
    KDB_REQUIRES_PRE_AUTH,
};

/// MIT 1.22.2 default (`kdb5_util load_dump version 7`).
pub const KDB_DUMP_VERSION: u32 = 7;
/// Older `-r18` header. Princ records match version 7.
pub const KDB_DUMP_VERSION_R18: u32 = 6;

/// `KRB5_TL_LAST_PWD_CHANGE`.
pub const TL_LAST_PWD_CHANGE: i32 = 1;
/// `KRB5_TL_MOD_PRINC`.
pub const TL_MOD_PRINC: i32 = 2;
/// `KRB5_TL_KADM_DATA`.
pub const TL_KADM_DATA: i32 = 3;
/// `KRB5_TL_MKVNO`.
pub const TL_MKVNO: i32 = 8;
/// `KRB5_TL_ACTKVNO`.
pub const TL_ACTKVNO: i32 = 9;
/// Private `tl_data` type: domain SID + RID (MIT has no SID; opaque round-trip).
pub const TL_KERBER_SID: i32 = 0x4B01;
/// `KRB5_KDB_SALTTYPE_NORMAL`.
pub const SALTTYPE_NORMAL: i32 = 0;
/// `KRB5_KDB_SALTTYPE_SPECIAL`.
pub const SALTTYPE_SPECIAL: i32 = 4;

/// Dump/load failure.
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// Grammar / field-count / hex.
    #[error("dump format: {0}")]
    Format(String),
    /// Master-key or `key_data` crypto.
    #[error("dump crypto: {0}")]
    Crypto(String),
    /// I/O.
    #[error("dump io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<KdcError> for DumpError {
    fn from(e: KdcError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<krb5_crypto::Error> for DumpError {
    fn from(e: krb5_crypto::Error) -> Self {
        Self::Crypto(e.to_string())
    }
}

/// Parsed dump file.
#[derive(Clone, Debug)]
pub struct DumpFile {
    /// Header version (`6` or `7`).
    pub version: u32,
    /// Principal records in file order.
    pub princs: Vec<DumpPrincipal>,
    /// Opaque `policy\t…` lines (passthrough; golden has none).
    pub policies: Vec<String>,
}

/// One `princ` record (encrypted `key_data` still wrapped).
#[derive(Clone, Debug)]
pub struct DumpPrincipal {
    /// MIT `entry->len` (`KRB5_KDB_V1_BASE_LENGTH` = 38).
    pub db_len: u32,
    /// Unparsed `name@REALM`.
    pub name: String,
    /// KDB attributes bitfield.
    pub attributes: u32,
    /// Max ticket life seconds.
    pub max_life: u32,
    /// Max renewable life seconds.
    pub max_renewable_life: u32,
    /// Expiration unix seconds (0 = never).
    pub expiration: u32,
    /// Password expiration unix seconds.
    pub pw_expiration: u32,
    /// Last success unix seconds.
    pub last_success: u32,
    /// Last failure unix seconds.
    pub last_failed: u32,
    /// Failed password attempts.
    pub fail_auth_count: u32,
    /// Tagged list.
    pub tl_data: Vec<TlData>,
    /// Encrypted key blocks.
    pub keys: Vec<DumpKeyData>,
    /// Extra data (`-1` when empty).
    pub e_data: Vec<u8>,
}

/// One `key_data` block (`ver` 1 = key only, `ver` 2 = key + salt).
#[derive(Clone, Debug)]
pub struct DumpKeyData {
    /// `key_data_ver`.
    pub ver: i32,
    /// Key version number.
    pub kvno: u32,
    /// `ver` slots: type + contents.
    pub slots: Vec<DumpKeySlot>,
}

/// One `key_data` slot (key or salt).
#[derive(Clone, Debug)]
pub struct DumpKeySlot {
    /// `key_data_type[i]` (enctype or salt type).
    pub ty: i32,
    /// Encrypted key bytes or salt bytes.
    pub contents: Vec<u8>,
}

impl DumpFile {
    /// Realm taken from the first principal name.
    ///
    /// # Errors
    ///
    /// No principals, or a name without `@`.
    pub fn realm(&self) -> Result<&str, DumpError> {
        let name = self
            .princs
            .first()
            .map(|p| p.name.as_str())
            .ok_or_else(|| DumpError::Format("dump has no princ records".into()))?;
        name.rsplit_once('@')
            .map(|(_, r)| r)
            .filter(|r| !r.is_empty())
            .ok_or_else(|| DumpError::Format(format!("missing realm in {name}")))
    }

    /// Find a principal by unparsed name.
    #[must_use]
    pub fn princ(&self, unparsed: &str) -> Option<&DumpPrincipal> {
        self.princs.iter().find(|p| p.name == unparsed)
    }

    /// Decrypt `key_data` into a [`PrincipalStore`].
    ///
    /// # Errors
    ///
    /// Crypto or name-parse failures.
    pub fn into_store(self, mkey: &ProtocolKey) -> Result<PrincipalStore, DumpError> {
        let realm = self.realm()?.to_owned();
        let mut store = PrincipalStore::new(realm);
        let mut domain: Option<RpcSid> = None;
        for p in self.princs {
            let is_km = p.name.starts_with("K/M@");
            let (princ, sid) = p.into_principal(mkey)?;
            if is_km {
                if let Some(s) = sid {
                    domain = Some(s);
                }
            } else if domain.is_none() {
                domain = sid;
            }
            store.debug_insert(princ);
        }
        if let Some(sid) = domain {
            store.set_domain_sid(sid);
        }
        Ok(store)
    }
}

impl DumpPrincipal {
    fn into_principal(self, mkey: &ProtocolKey) -> Result<(Principal, Option<RpcSid>), DumpError> {
        let (name, realm) = parse_unparsed(&self.name)?;
        let mut keys = Vec::new();
        let mut princ_salt: Option<Vec<u8>> = None;
        for kd in &self.keys {
            if kd.slots.is_empty() {
                return Err(DumpError::Format(format!(
                    "{}: key_data with no slots",
                    self.name
                )));
            }
            let key_slot = &kd.slots[0];
            let etype =
                EncryptionType::known(key_slot.ty).map_err(|e| DumpError::Crypto(e.to_string()))?;
            let raw = kdb_decrypt_key(mkey, &key_slot.contents)?;
            let key = ProtocolKey::from_bytes(etype, &raw)
                .map_err(|e| DumpError::Crypto(e.to_string()))?;
            let (salt_type, kdb_salt) = if kd.ver >= 2 && kd.slots.len() >= 2 {
                let s = &kd.slots[1];
                if princ_salt.is_none()
                    && (s.ty == SALTTYPE_NORMAL || s.ty == SALTTYPE_SPECIAL)
                    && !s.contents.is_empty()
                {
                    princ_salt = Some(s.contents.clone());
                }
                (Some(s.ty), Some(s.contents.clone()))
            } else {
                (None, None)
            };
            keys.push(KeyEntry {
                etype,
                key,
                kvno: kd.kvno,
                salt_type,
                kdb_salt,
            });
        }
        if name.components_joined() == "K/M" {
            if let Some(first) = keys.first() {
                if first.key.as_bytes() != mkey.as_bytes() {
                    return Err(DumpError::Crypto(
                        "K/M key_data does not match derived master key".into(),
                    ));
                }
            }
        }
        let salt = princ_salt.unwrap_or_else(|| name.default_salt(&realm));
        let mkvno = mkvno_from_tl(&self.tl_data);
        let requires_preauth = self.attributes & KDB_REQUIRES_PRE_AUTH != 0;
        let locked = self.attributes & KDB_DISALLOW_ALL_TIX != 0;
        let (sid, rid) = parse_sid_tl(&self.tl_data);
        Ok((
            Principal {
                name,
                realm,
                keys,
                salt,
                requires_preauth,
                max_life: u64::from(self.max_life),
                locked,
                pw_expire: self.pw_expiration,
                attributes: self.attributes,
                max_renewable_life: u64::from(self.max_renewable_life),
                expiration: self.expiration,
                last_success: self.last_success,
                last_failed: self.last_failed,
                fail_auth_count: self.fail_auth_count,
                mkvno,
                db_entry_len: self.db_len,
                tl_data: self.tl_data,
                e_data: self.e_data,
                rid,
            },
            sid,
        ))
    }
}

/// Parse a MIT dump (header + `princ` / `policy` records).
///
/// # Errors
///
/// Truncated lines, unknown version, or field-count mismatch.
pub fn parse_dump(text: &str) -> Result<DumpFile, DumpError> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| DumpError::Format("empty dump".into()))?;
    let version = parse_header(header)?;
    let mut princs = Vec::new();
    let mut policies = Vec::new();
    for (idx, line) in lines.enumerate() {
        let lineno = idx + 2;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("policy\t") {
            policies.push(rest.to_owned());
            continue;
        }
        if let Some(rest) = line.strip_prefix("princ\t") {
            princs.push(parse_princ_line(rest, lineno)?);
            continue;
        }
        return Err(DumpError::Format(format!(
            "line {lineno}: unknown record type"
        )));
    }
    if princs.is_empty() {
        return Err(DumpError::Format("dump has no princ records".into()));
    }
    Ok(DumpFile {
        version,
        princs,
        policies,
    })
}

/// Load a dump: parse, derive the master key, decrypt `key_data`.
///
/// # Errors
///
/// Parse or crypto failures.
pub fn load_dump(text: &str, master_password: &[u8]) -> Result<PrincipalStore, DumpError> {
    load_dump_etype(text, master_password, harness_master_etype())
}

/// [`load_dump`] with an explicit master-key etype.
///
/// # Errors
///
/// Parse or crypto failures.
pub fn load_dump_etype(
    text: &str,
    master_password: &[u8],
    etype: EncryptionType,
) -> Result<PrincipalStore, DumpError> {
    let dump = parse_dump(text)?;
    let realm = dump.realm()?.to_owned();
    let mkey = master_key_from_password(&realm, master_password, etype)?;
    dump.into_store(&mkey)
}

/// Load from a path.
///
/// # Errors
///
/// I/O, parse, or crypto failures.
pub fn load_dump_path(path: &Path, master_password: &[u8]) -> Result<PrincipalStore, DumpError> {
    let text = fs::read_to_string(path)?;
    load_dump(&text, master_password)
}

/// Write a version-7 dump, re-encrypting keys under the derived master key.
///
/// Missing `K/M` is synthesized. Empty `tl_data` is filled with
/// `KRB5_TL_LAST_PWD_CHANGE` and `KRB5_TL_MOD_PRINC` (and `KRB5_TL_MKVNO`).
///
/// # Errors
///
/// Crypto failures.
pub fn dump_store(store: &PrincipalStore, master_password: &[u8]) -> Result<String, DumpError> {
    dump_store_etype(store, master_password, harness_master_etype())
}

/// [`dump_store`] with an explicit master-key etype.
///
/// # Errors
///
/// Crypto failures.
pub fn dump_store_etype(
    store: &PrincipalStore,
    master_password: &[u8],
    etype: EncryptionType,
) -> Result<String, DumpError> {
    let mkey = master_key_from_password(store.realm(), master_password, etype)?;
    write_dump(store, &mkey)
}

/// Write dump text from an already-derived master key.
///
/// # Errors
///
/// Crypto failures.
pub fn write_dump(store: &PrincipalStore, mkey: &ProtocolKey) -> Result<String, DumpError> {
    let now = unix_now();
    let mut princs: Vec<&Principal> = store.debug_principals().collect();
    princs.sort_by_key(|p| {
        (
            p.name.components_joined() != "K/M",
            p.name.components_joined(),
        )
    });
    let mut out = format!("kdb5_util load_dump version {KDB_DUMP_VERSION}\n");
    let has_km = princs.iter().any(|p| p.name.components_joined() == "K/M");
    if !has_km {
        let km = synthesize_km(store.realm(), mkey, now);
        write_princ_record(&mut out, &km, mkey, store)?;
    }
    for p in princs {
        write_princ_record(&mut out, p, mkey, store)?;
    }
    Ok(out)
}

/// Write a dump file (0600).
///
/// # Errors
///
/// Crypto or I/O failures.
pub fn write_dump_path(
    store: &PrincipalStore,
    path: &Path,
    master_password: &[u8],
) -> Result<(), DumpError> {
    write_dump_path_etype(store, path, master_password, harness_master_etype())
}

/// [`write_dump_path`] with an explicit master-key etype.
///
/// # Errors
///
/// Crypto or I/O failures.
pub fn write_dump_path_etype(
    store: &PrincipalStore,
    path: &Path,
    master_password: &[u8],
    etype: EncryptionType,
) -> Result<(), DumpError> {
    let text = dump_store_etype(store, master_password, etype)?;
    write_secret_file(path, text.as_bytes())?;
    Ok(())
}

fn parse_header(line: &str) -> Result<u32, DumpError> {
    const PREFIX: &str = "kdb5_util load_dump version ";
    let rest = line
        .strip_prefix(PREFIX)
        .ok_or_else(|| DumpError::Format(format!("bad dump header: {line}")))?;
    let version: u32 = rest
        .trim()
        .parse()
        .map_err(|_| DumpError::Format(format!("bad dump version: {rest}")))?;
    if version != KDB_DUMP_VERSION && version != KDB_DUMP_VERSION_R18 {
        return Err(DumpError::Format(format!(
            "unsupported dump version {version}"
        )));
    }
    Ok(version)
}

fn parse_princ_line(rest: &str, lineno: usize) -> Result<DumpPrincipal, DumpError> {
    let mut raw: Vec<&str> = rest.split('\t').collect();
    if let Some(last) = raw.last_mut() {
        *last = last.strip_suffix(';').unwrap_or(last);
    }
    if raw.last().is_some_and(|s| s.is_empty()) {
        raw.pop();
    }
    let mut c = Cursor {
        f: raw,
        i: 0,
        line: lineno,
    };
    let db_len = c.u32()?;
    let namelen = c.usize()?;
    let n_tl = c.usize()?;
    let n_key = c.usize()?;
    let e_len = c.usize()?;
    let name = c.take()?.to_owned();
    if name.len() != namelen {
        return Err(c.err(&format!("name length {} != header {namelen}", name.len())));
    }
    let attributes = c.u32()?;
    let max_life = c.u32()?;
    let max_renewable_life = c.u32()?;
    let expiration = c.u32()?;
    let pw_expiration = c.u32()?;
    let last_success = c.u32()?;
    let last_failed = c.u32()?;
    let fail_auth_count = c.u32()?;
    let mut tl_data = Vec::with_capacity(n_tl);
    for _ in 0..n_tl {
        let ty = c.i32()?;
        let len = c.usize()?;
        let contents = c.hex(len)?;
        tl_data.push(TlData { ty, contents });
    }
    let mut keys = Vec::with_capacity(n_key);
    for _ in 0..n_key {
        let ver = c.i32()?;
        if !(1..=2).contains(&ver) {
            return Err(c.err(&format!("unsupported key_data_ver {ver}")));
        }
        let kvno = c.u32()?;
        let nslots = usize::try_from(ver).map_err(|_| c.err("key_data_ver"))?;
        let mut slots = Vec::with_capacity(nslots);
        for _ in 0..nslots {
            let ty = c.i32()?;
            let len = c.usize()?;
            let contents = c.hex(len)?;
            slots.push(DumpKeySlot { ty, contents });
        }
        keys.push(DumpKeyData { ver, kvno, slots });
    }
    let e_data = c.hex(e_len)?;
    c.finish()?;
    Ok(DumpPrincipal {
        db_len,
        name,
        attributes,
        max_life,
        max_renewable_life,
        expiration,
        pw_expiration,
        last_success,
        last_failed,
        fail_auth_count,
        tl_data,
        keys,
        e_data,
    })
}

struct Cursor<'a> {
    f: Vec<&'a str>,
    i: usize,
    line: usize,
}

impl<'a> Cursor<'a> {
    fn err(&self, msg: &str) -> DumpError {
        DumpError::Format(format!("line {}: {msg}", self.line))
    }

    fn take(&mut self) -> Result<&'a str, DumpError> {
        let s = self
            .f
            .get(self.i)
            .ok_or_else(|| self.err("truncated princ record"))?;
        self.i += 1;
        Ok(*s)
    }

    fn u32(&mut self) -> Result<u32, DumpError> {
        let s = self.take()?;
        s.parse()
            .map_err(|_| self.err(&format!("not an integer: {s}")))
    }

    fn usize(&mut self) -> Result<usize, DumpError> {
        usize::try_from(self.u32()?).map_err(|_| self.err("length overflow"))
    }

    fn i32(&mut self) -> Result<i32, DumpError> {
        let s = self.take()?;
        s.parse()
            .map_err(|_| self.err(&format!("not an integer: {s}")))
    }

    fn hex(&mut self, len: usize) -> Result<Vec<u8>, DumpError> {
        let s = self.take()?;
        if len == 0 {
            if s != "-1" {
                return Err(self.err("empty blob must be -1"));
            }
            return Ok(Vec::new());
        }
        let b = decode_hex(s).map_err(|e| self.err(&e))?;
        if b.len() != len {
            return Err(self.err(&format!("hex decoded {} bytes, header {len}", b.len())));
        }
        Ok(b)
    }

    fn finish(self) -> Result<(), DumpError> {
        if self.i == self.f.len() {
            Ok(())
        } else {
            Err(self.err(&format!(
                "extra fields after princ record ({} leftover)",
                self.f.len() - self.i
            )))
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("bad hex: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("bad hex: {s}")))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-1".into();
    }
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn parse_unparsed(s: &str) -> Result<(PrincipalName, String), DumpError> {
    let (left, realm) = s
        .rsplit_once('@')
        .ok_or_else(|| DumpError::Format(format!("missing realm in {s}")))?;
    if realm.is_empty() || left.is_empty() {
        return Err(DumpError::Format(format!("empty principal {s}")));
    }
    let parts: Vec<&str> = left.split('/').collect();
    let ntype = match parts.as_slice() {
        ["host", _] => PrincipalName::NT_SRV_HST,
        [_] | ["K", "M"] => PrincipalName::NT_PRINCIPAL,
        _ => PrincipalName::NT_SRV_INST,
    };
    let name =
        PrincipalName::try_new(ntype, parts).map_err(|e| DumpError::Format(e.to_string()))?;
    Ok((name, realm.to_owned()))
}

fn mkvno_from_tl(tl: &[TlData]) -> u16 {
    tl.iter()
        .find(|t| t.ty == TL_MKVNO && t.contents.len() == 2)
        .map_or(1, |t| u16::from_le_bytes([t.contents[0], t.contents[1]]))
}

fn unix_now() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(u32::MAX)
}

fn dump_attributes(p: &Principal) -> u32 {
    let mut a = p.attributes;
    if p.requires_preauth {
        a |= KDB_REQUIRES_PRE_AUTH;
    } else {
        a &= !KDB_REQUIRES_PRE_AUTH;
    }
    if p.locked {
        a |= KDB_DISALLOW_ALL_TIX;
    } else {
        a &= !KDB_DISALLOW_ALL_TIX;
    }
    a
}

fn write_princ_record(
    out: &mut String,
    p: &Principal,
    mkey: &ProtocolKey,
    store: &PrincipalStore,
) -> Result<(), DumpError> {
    let name = format!("{}@{}", p.name.components_joined(), p.realm);
    let max_life = if p.max_life == 0 {
        u32::try_from(store.policy.max_life).unwrap_or(u32::MAX)
    } else {
        u32::try_from(p.max_life).unwrap_or(u32::MAX)
    };
    let max_rlife = if p.max_renewable_life == 0 {
        u32::try_from(store.policy.max_renewable_life).unwrap_or(u32::MAX)
    } else {
        u32::try_from(p.max_renewable_life).unwrap_or(u32::MAX)
    };
    let mut tl = if p.tl_data.is_empty() {
        synthesize_tl(
            &p.realm,
            unix_now(),
            p.mkvno,
            p.name.components_joined() == "K/M",
        )
    } else {
        p.tl_data.clone()
    };
    merge_sid_tl(&mut tl, store.domain_sid(), p.rid);
    let mut keys = Vec::new();
    for k in &p.keys {
        let enc = kdb_encrypt_key(mkey, k.key.as_bytes())?;
        let mut slots = vec![DumpKeySlot {
            ty: k.etype.to_iana(),
            contents: enc,
        }];
        let ver = if let (Some(st), Some(sb)) = (k.salt_type, k.kdb_salt.as_ref()) {
            slots.push(DumpKeySlot {
                ty: st,
                contents: sb.clone(),
            });
            2
        } else {
            1
        };
        keys.push(DumpKeyData {
            ver,
            kvno: k.kvno,
            slots,
        });
    }
    let _ = write!(
        out,
        "princ\t{}\t{}\t{}\t{}\t{}\t{}\t",
        p.db_entry_len,
        name.len(),
        tl.len(),
        keys.len(),
        p.e_data.len(),
        name
    );
    let _ = write!(
        out,
        "{}\t{max_life}\t{max_rlife}\t{}\t{}\t{}\t{}\t{}",
        dump_attributes(p),
        p.expiration,
        p.pw_expire,
        p.last_success,
        p.last_failed,
        p.fail_auth_count
    );
    for t in &tl {
        let _ = write!(
            out,
            "\t{}\t{}\t{}",
            t.ty,
            t.contents.len(),
            encode_hex(&t.contents)
        );
    }
    out.push('\t');
    for k in &keys {
        let _ = write!(out, "{}\t{}\t", k.ver, k.kvno);
        for s in &k.slots {
            let _ = write!(
                out,
                "{}\t{}\t{}\t",
                s.ty,
                s.contents.len(),
                encode_hex(&s.contents)
            );
        }
    }
    let _ = write!(out, "{};", encode_hex(&p.e_data));
    out.push('\n');
    Ok(())
}

fn merge_sid_tl(tl: &mut Vec<TlData>, domain: &RpcSid, rid: u32) {
    tl.retain(|t| t.ty != TL_KERBER_SID);
    tl.push(encode_sid_tl(domain, rid));
}

fn encode_sid_tl(domain: &RpcSid, rid: u32) -> TlData {
    let mut contents = Vec::with_capacity(16 + domain.sub_authority.len() * 4);
    contents.push(1);
    contents.extend_from_slice(&rid.to_le_bytes());
    contents.push(domain.revision);
    contents.push(u8::try_from(domain.sub_authority.len()).unwrap_or(0));
    contents.extend_from_slice(&domain.identifier_authority);
    for s in &domain.sub_authority {
        contents.extend_from_slice(&s.to_le_bytes());
    }
    TlData {
        ty: TL_KERBER_SID,
        contents,
    }
}

fn parse_sid_tl(tl: &[TlData]) -> (Option<RpcSid>, u32) {
    let Some(t) = tl.iter().find(|t| t.ty == TL_KERBER_SID) else {
        return (None, 0);
    };
    if t.contents.len() < 13 || t.contents[0] != 1 {
        return (None, 0);
    }
    let rid = u32::from_le_bytes([t.contents[1], t.contents[2], t.contents[3], t.contents[4]]);
    let revision = t.contents[5];
    let n = usize::from(t.contents[6]);
    if t.contents.len() < 13 + n * 4 {
        return (None, 0);
    }
    let mut identifier_authority = [0u8; 6];
    identifier_authority.copy_from_slice(&t.contents[7..13]);
    let mut sub_authority = Vec::with_capacity(n);
    let mut off = 13;
    for _ in 0..n {
        sub_authority.push(u32::from_le_bytes([
            t.contents[off],
            t.contents[off + 1],
            t.contents[off + 2],
            t.contents[off + 3],
        ]));
        off += 4;
    }
    (
        Some(RpcSid {
            revision,
            identifier_authority,
            sub_authority,
        }),
        rid,
    )
}

fn synthesize_tl(realm: &str, now: u32, mkvno: u16, is_km: bool) -> Vec<TlData> {
    let mut tl = Vec::new();
    if is_km {
        let mut act = Vec::with_capacity(8);
        act.extend_from_slice(&1u16.to_le_bytes());
        act.extend_from_slice(&1u16.to_le_bytes());
        act.extend_from_slice(&0u32.to_le_bytes());
        tl.push(TlData {
            ty: TL_ACTKVNO,
            contents: act,
        });
    }
    let mut modp = Vec::new();
    modp.extend_from_slice(&now.to_le_bytes());
    modp.extend_from_slice(format!("db_creation@{realm}").as_bytes());
    modp.push(0);
    tl.push(TlData {
        ty: TL_MOD_PRINC,
        contents: modp,
    });
    tl.push(TlData {
        ty: TL_MKVNO,
        contents: mkvno.to_le_bytes().to_vec(),
    });
    tl.push(TlData {
        ty: TL_LAST_PWD_CHANGE,
        contents: now.to_le_bytes().to_vec(),
    });
    tl
}

fn synthesize_km(realm: &str, mkey: &ProtocolKey, now: u32) -> Principal {
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
    let salt = name.default_salt(realm);
    let mut p = Principal::from_keys(
        name,
        realm.to_owned(),
        vec![KeyEntry::new(mkey.etype(), mkey.clone(), 1)],
        salt,
        false,
        36_000,
        true,
        0,
    );
    p.attributes = KDB_DISALLOW_ALL_TIX | KDB_LOCKDOWN_KEYS;
    p.max_renewable_life = 604_800;
    p.tl_data = synthesize_tl(realm, now, 1, true);
    p
}
