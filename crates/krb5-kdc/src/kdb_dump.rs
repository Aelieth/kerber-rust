//! MIT `kdb5_util` dump version 6/7 textual codec.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};

use krb5_crypto::{EncryptionType, ProtocolKey, kdb_decrypt_key, kdb_encrypt_key};
use krb5_protocol::write_fresh_secret_file;
use krb5_types::pac::RpcSid;
use krb5_types::{PrincipalName, infer_name_type, parse_name};
use subtle::ConstantTimeEq;

use crate::error::Error as KdcError;
use crate::mkey::{MASTER_NAME, default_master_etype, master_key_from_password};
use crate::osa::OsaPrincEnt;
use crate::store::{
    IPROP_NIL, IPROP_OK, KDB_DISALLOW_ALL_TIX, KDB_LOCKDOWN_KEYS, KadmData, KeyEntry, NamedPolicy,
    Principal, PrincipalStore, TlData,
};
use crate::ulog::UlogLast;

pub const KDB_DUMP_VERSION: u32 = 7;
pub(crate) const KDB_DUMP_VERSION_R18: u32 = 6;

// MIT: `extract_db_args_from_tl_data` (kdb5.c:893-945)
/// Each `KRB5_TL_DB_ARGS` entry: removed, passed on as a database argument.
pub const TL_DB_ARGS: i32 = 0x7fff;
pub const TL_LAST_PWD_CHANGE: i32 = 1;
pub const TL_LAST_ADMIN_UNLOCK: i32 = 0x0700;
pub const TL_MOD_PRINC: i32 = 2;

// MIT: `krb5_dbe_lookup_mod_princ_data` (kdb5.c:1637-1663)
/// `KRB5_TL_MOD_PRINC` is a 4-byte LE time and a NUL-terminated principal.
#[must_use]
pub(crate) fn tl_mod_princ(contents: &[u8]) -> Option<(u32, String)> {
    if contents.len() < 5 || contents.last() != Some(&0) {
        return None;
    }
    let ts = u32::from_le_bytes(contents[0..4].try_into().ok()?);
    let name = std::str::from_utf8(&contents[4..contents.len() - 1])
        .ok()?
        .to_owned();
    Some((ts, name))
}

#[must_use]
pub fn tl_mod_princ_name(tl: &[TlData]) -> Option<String> {
    tl.iter()
        .find(|t| t.ty == TL_MOD_PRINC)
        .and_then(|t| tl_mod_princ(&t.contents).map(|(_, n)| n))
}
pub const TL_KADM_DATA: i32 = 3;
pub(crate) const TL_MKVNO: i32 = 8;
pub const TL_STRING_ATTRS: i32 = 0x000b;
/// `KRB5_TL_ALIAS_TARGET` is a NUL-terminated target name.
pub const TL_ALIAS_TARGET: i32 = 0x000c;
pub(crate) const TL_ACTKVNO: i32 = 9;
/// The private SID type is ours; MIT has no domain SID.
pub const TL_KERBER_SID: i32 = 0x4B01;
pub(crate) const TL_KERBER_POLICY: i32 = 0x4B02;
pub const TL_KERBER_SERIAL: i32 = 0x4B03;
pub const TL_KERBER_HIST: i32 = 0x4B04;
pub const TL_KERBER_RID_HWM: i32 = 0x4B05;
// MIT: `KRB5_TL_CONSTRAINED_DELEGATION_ACL` (include/kdb.h:271)
pub const TL_CONSTRAINED_DELEGATION: i32 = 0x0400;
pub const TL_KERBER_S4U_FROM: i32 = 0x4B06;
pub const SALTTYPE_NORMAL: i32 = 0;
pub(crate) const SALTTYPE_NOREALM: i32 = 2;
pub(crate) const SALTTYPE_ONLYREALM: i32 = 3;
pub(crate) const SALTTYPE_SPECIAL: i32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    #[error("dump format: {0}")]
    Format(String),
    #[error("dump crypto: {0}")]
    Crypto(String),
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

#[derive(Clone, Debug)]
pub struct DumpFile {
    pub version: u32,
    pub princs: Vec<DumpPrincipal>,
    pub policies: Vec<String>,
    pub(crate) records: usize,
    pub(crate) applied_len: usize,
    pub(crate) seen_rid: u32,
}

#[derive(Clone, Debug)]
pub struct DumpPrincipal {
    pub db_len: u32,
    pub name: String,
    pub attributes: u32,
    pub max_life: u32,
    pub max_renewable_life: u32,
    /// Unix seconds; 0 is never.
    pub expiration: u32,
    pub pw_expiration: u32,
    pub last_success: u32,
    pub last_failed: u32,
    pub fail_auth_count: u32,
    pub tl_data: Vec<TlData>,
    pub keys: Vec<DumpKeyData>,
    pub e_data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DumpKeyData {
    pub ver: i32,
    pub kvno: u32,
    pub slots: Vec<DumpKeySlot>,
}

#[derive(Clone, Debug)]
pub struct DumpKeySlot {
    pub ty: i32,
    pub contents: Vec<u8>,
}

impl DumpFile {
    #[must_use]
    pub(crate) fn text(&self) -> String {
        let mut out = format!("kdb5_util load_dump version {}\n", self.version);
        for p in &self.princs {
            out.push_str(&p.record());
            out.push('\n');
        }
        for rest in &self.policies {
            let _ = writeln!(out, "policy\t{rest}");
        }
        out
    }

    #[must_use]
    pub fn policy_records(&self) -> Vec<String> {
        self.policies
            .iter()
            .map(|rest| policy_line(&parse_policy_rest(rest)))
            .collect()
    }

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

    #[must_use]
    pub fn princ(&self, unparsed: &str) -> Option<&DumpPrincipal> {
        self.princs.iter().find(|p| p.name == unparsed)
    }

    // MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:409-424)
    /// `K/M`'s one key is the master key.
    #[must_use]
    pub fn master_etype(&self) -> Option<EncryptionType> {
        let realm = self.realm().ok()?;
        let km = self.princ(&format!("K/M@{realm}"))?;
        let ty = km.keys.first()?.slots.first()?.ty;
        EncryptionType::known(ty).ok()
    }

    pub fn into_store_with_key(self, mkey: &ProtocolKey) -> Result<PrincipalStore, DumpError> {
        self.into_store(mkey)
    }

    /// Version 7 = r1.11; version 6 = r1.8 (nine counters).
    // MIT: `dump_r1_8_policy` (kadmin/dbutil/dump.c:404-413)
    // MIT: `dump_k5beta7_policy` (kadmin/dbutil/dump.c:394-401)
    #[must_use]
    pub fn policy_record(rest: &str, version: u32) -> String {
        if version == KDB_DUMP_VERSION {
            return format!("policy\t{rest}");
        }
        if version <= 5 {
            let fields: Vec<&str> = rest.split('\t').take(6).collect();
            return format!("policy\t{}\t0", fields.join("\t"));
        }
        let fields: Vec<&str> = rest.split('\t').take(10).collect();
        format!("policy\t{}", fields.join("\t"))
    }

    pub(crate) fn into_store(self, mkey: &ProtocolKey) -> Result<PrincipalStore, DumpError> {
        for p in &self.princs {
            if let Some(e) = crate::store::db_args_put_error(&p.tl_data) {
                return Err(DumpError::Format(format!("{e} while storing {}", p.name)));
            }
        }
        let realm = self.realm()?.to_owned();
        let mut store = PrincipalStore::try_new(realm.clone())?;
        store.loaded_span = Some((
            u64::try_from(self.records).unwrap_or(u64::MAX),
            u64::try_from(self.applied_len).unwrap_or(u64::MAX),
        ));
        let mut domain: Option<RpcSid> = None;
        let mut hwm = None;
        let mut seen_rid: HashMap<u32, String> = HashMap::new();
        for p in self.princs {
            let is_km = p.name.starts_with("K/M@");
            if is_km {
                hwm = rid_hwm_of(&p.tl_data);
            }
            let (princ, sid) = p.into_principal(mkey)?;
            if princ.rid != 0
                && princ.name.components_joined() != "K/M"
                && let Some(owner) = seen_rid.insert(princ.rid, princ.id())
            {
                return Err(DumpError::Format(format!(
                    "duplicate RID {} on {owner} and {}",
                    princ.rid,
                    princ.id()
                )));
            }
            if is_km {
                if let Some(s) = sid {
                    domain = Some(s);
                }
            } else if domain.is_none() {
                domain = sid;
            }
            store.debug_insert(princ);
        }
        for line in &self.policies {
            store.load_policy(parse_policy_rest(line));
        }
        store.resolve_history_all();
        if let Some(sid) = domain {
            store.set_domain_sid(sid);
        }
        if let Some(next) = hwm {
            store.raise_next_rid(next);
        }
        store.raise_next_rid(self.seen_rid.saturating_add(1));
        Ok(store)
    }
}

impl DumpPrincipal {
    // MIT: `k5beta7_common` (kadmin/dbutil/dump.c:334-368)
    #[must_use]
    pub fn record(&self) -> String {
        let mut out = format!(
            "princ\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.db_len,
            self.name.len(),
            self.tl_data.len(),
            self.keys.len(),
            self.e_data.len(),
            self.name,
            self.attributes,
            self.max_life,
            self.max_renewable_life,
            self.expiration,
            self.pw_expiration,
            self.last_success,
            self.last_failed,
            self.fail_auth_count
        );
        for t in &self.tl_data {
            let _ = write!(
                out,
                "\t{}\t{}\t{}",
                t.ty,
                t.contents.len(),
                encode_hex(&t.contents)
            );
        }
        out.push('\t');
        for k in &self.keys {
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
        let _ = write!(out, "{};", encode_hex(&self.e_data));
        out
    }

    // MIT: `krb5_def_fetch_mkey_list` (lib/kdb/kdb_default.c:431-437)
    #[must_use]
    pub fn opens_with(&self, mkey: &ProtocolKey) -> bool {
        self.keys
            .first()
            .and_then(|k| k.slots.first())
            .is_some_and(|s| {
                s.ty == mkey.etype().to_iana() && kdb_decrypt_key(mkey, &s.contents).is_ok()
            })
    }

    // MIT: `process_k5beta7_princ` (dump.c:702-723)
    /// A policy binds only from a decodable `KRB5_TL_KADM_DATA` naming one.
    pub(crate) fn into_principal(
        self,
        mkey: &ProtocolKey,
    ) -> Result<(Principal, Option<RpcSid>), DumpError> {
        let (name, realm) = parse_unparsed(&self.name)?;
        let mut keys = Vec::new();
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
        if name.components_joined() == "K/M"
            && let Some(first) = keys.first()
            && first.key.as_bytes().ct_eq(mkey.as_bytes()).unwrap_u8() != 1
        {
            return Err(DumpError::Crypto(
                "K/M key_data does not match derived master key".into(),
            ));
        }
        let salt = salt_of_keys(&keys, &name, &realm);
        let mkvno = mkvno_from_tl(&self.tl_data);
        let (sid, rid) = parse_sid_tl(&self.tl_data)?;
        let osa = OsaPrincEnt::from_tl(&self.tl_data)
            .map_err(|e| DumpError::Format(format!("{}: {e}", self.name)))?;
        let pw_policy = osa
            .as_ref()
            .and_then(|o| o.bound_policy().map(str::to_owned))
            .or_else(|| policy_from_tl(&self.tl_data));
        let kadm = osa.as_ref().map(KadmData::from_osa).unwrap_or_default();
        let string_attrs = attrs_from_tl(&self.tl_data);
        let s4u_allowed_from = nul_tl_names(&self.tl_data, TL_KERBER_S4U_FROM);
        let s4u_allowed_to = nul_tl_names(&self.tl_data, TL_CONSTRAINED_DELEGATION);
        let key_history = hist_from_tl(&self.tl_data, mkey)?;
        let tl_data = self
            .tl_data
            .into_iter()
            .filter(|t| !is_s4u_name_tl(t) && t.ty != TL_KERBER_RID_HWM)
            .collect();
        Ok((
            Principal {
                name,
                realm,
                keys,
                key_history,
                salt,
                max_life: u64::from(self.max_life),
                pw_expire: self.pw_expiration,
                attributes: self.attributes,
                max_renewable_life: u64::from(self.max_renewable_life),
                expiration: self.expiration,
                last_success: self.last_success,
                last_failed: self.last_failed,
                fail_auth_count: self.fail_auth_count,
                mkvno,
                db_entry_len: self.db_len,
                tl_data,
                e_data: self.e_data,
                rid,
                s4u_allowed_from,
                s4u_allowed_to,
                pw_policy,
                kadm,
                string_attrs,
            },
            sid,
        ))
    }
}

// MIT: `restore_dump` (kadmin/dbutil/dump.c:1364-1379)
pub fn parse_dump(text: &str) -> Result<DumpFile, DumpError> {
    let mut lines = text_lines(text, 0);
    let header = lines
        .next()
        .ok_or_else(|| DumpError::Format("empty dump".into()))?;
    let version = parse_header(header.text)?;
    let mut fold = Fold::default();
    let mut applied_len = text.len();
    while let Some(line) = lines.next() {
        if line.text != JOURNAL_BEGIN {
            fold.record(&line)?;
            continue;
        }
        match read_batch(text, &line, &mut lines) {
            Some((records, end)) => {
                for r in &records {
                    fold.record(r)?;
                }
                applied_len = end;
            }
            None if lines.any(|l| l.text == JOURNAL_BEGIN) => {
                return Err(DumpError::Format(format!(
                    "line {}: appended change does not check",
                    line.no
                )));
            }
            None => {
                applied_len = line.start;
                break;
            }
        }
    }
    Ok(DumpFile {
        version,
        princs: fold.princs.into_iter().flatten().collect(),
        records: fold.records,
        policies: fold.policies.into_iter().flatten().collect(),
        applied_len,
        seen_rid: fold.max_rid,
    })
}

const JOURNAL_BEGIN: &str = "begin";
const JOURNAL_END: &str = "end\t";
const JOURNAL_DEL: &str = "del\t";

struct Line<'a> {
    text: &'a str,
    no: usize,
    start: usize,
    end: usize,
    whole: bool,
}

fn text_lines(text: &str, from: usize) -> impl Iterator<Item = Line<'_>> {
    let mut at = from;
    let mut no = 0;
    std::iter::from_fn(move || {
        if at >= text.len() {
            return None;
        }
        let rest = &text[at..];
        let (raw, whole) = rest
            .find('\n')
            .map_or((rest, false), |i| (&rest[..i], true));
        let start = at;
        at += raw.len() + usize::from(whole);
        no += 1;
        Some(Line {
            text: raw.strip_suffix('\r').unwrap_or(raw),
            no,
            start,
            end: at,
            whole,
        })
    })
}

fn read_batch<'a>(
    text: &'a str,
    begin: &Line<'a>,
    lines: &mut impl Iterator<Item = Line<'a>>,
) -> Option<(Vec<Line<'a>>, usize)> {
    let mut records = Vec::new();
    for line in lines.by_ref() {
        if !line.whole {
            return None;
        }
        if let Some(crc) = line.text.strip_prefix(JOURNAL_END) {
            let body = text.get(begin.end..line.start)?.as_bytes();
            let ok = u32::from_str_radix(crc, 16).ok() == Some(crate::lockout::crc32(body));
            return ok.then_some((records, line.end));
        }
        records.push(line);
    }
    None
}

#[derive(Default)]
struct Fold {
    princs: Vec<Option<DumpPrincipal>>,
    princ_at: HashMap<String, usize>,
    policies: Vec<Option<String>>,
    policy_at: HashMap<String, usize>,
    records: usize,
    max_rid: u32,
}

impl Fold {
    fn record(&mut self, line: &Line<'_>) -> Result<(), DumpError> {
        let text = line.text;
        if text.is_empty() {
            return Ok(());
        }
        if let Some(rest) = text.strip_prefix("policy\t") {
            let name = rest.split('\t').next().unwrap_or_default().to_owned();
            put_last(
                &mut self.policies,
                &mut self.policy_at,
                name,
                rest.to_owned(),
            );
            return Ok(());
        }
        if let Some(rest) = text.strip_prefix("princ\t") {
            let p = parse_princ_line(rest, line.no)?;
            let (_, rid) = parse_sid_tl(&p.tl_data)?;
            self.max_rid = self.max_rid.max(rid);
            put_last(&mut self.princs, &mut self.princ_at, p.name.clone(), p);
            self.records += 1;
            return Ok(());
        }
        if let Some(name) = text.strip_prefix(JOURNAL_DEL) {
            if let Some(i) = self.princ_at.remove(name) {
                self.princs[i] = None;
            }
            self.records += 1;
            return Ok(());
        }
        Err(DumpError::Format(format!(
            "line {}: unknown record type",
            line.no
        )))
    }
}

fn put_last<T>(items: &mut Vec<Option<T>>, at: &mut HashMap<String, usize>, name: String, v: T) {
    if let Some(&i) = at.get(&name) {
        items[i] = Some(v);
    } else {
        at.insert(name, items.len());
        items.push(Some(v));
    }
}

pub(crate) fn journal_batch(
    store: &PrincipalStore,
    mkey: &ProtocolKey,
    ids: &[String],
) -> Result<String, DumpError> {
    let mut body = String::new();
    for id in ids {
        match store.principal_by_id(id) {
            Some(p) => write_princ_record(&mut body, p, mkey, store, false)?,
            None => {
                let _ = writeln!(body, "{JOURNAL_DEL}{id}");
            }
        }
    }
    let crc = crate::lockout::crc32(body.as_bytes());
    Ok(format!("{JOURNAL_BEGIN}\n{body}{JOURNAL_END}{crc:08x}\n"))
}

pub(crate) enum JournalOp {
    Put(Box<DumpPrincipal>),
    Del(String),
}

/// A torn last change is skipped.
pub(crate) fn parse_journal_tail(tail: &str) -> Result<Option<(Vec<JournalOp>, usize)>, DumpError> {
    let mut ops = Vec::new();
    let mut used = 0;
    let mut lines = text_lines(tail, 0);
    while let Some(line) = lines.next() {
        if line.text != JOURNAL_BEGIN {
            return Ok(None);
        }
        let Some((records, end)) = read_batch(tail, &line, &mut lines) else {
            if lines.any(|l| l.text == JOURNAL_BEGIN) {
                return Ok(None);
            }
            break;
        };
        for r in records {
            if let Some(rest) = r.text.strip_prefix("princ\t") {
                ops.push(JournalOp::Put(Box::new(parse_princ_line(rest, r.no)?)));
            } else if let Some(name) = r.text.strip_prefix(JOURNAL_DEL) {
                ops.push(JournalOp::Del(name.to_owned()));
            } else if !r.text.is_empty() {
                return Ok(None);
            }
        }
        used = end;
    }
    Ok(Some((ops, used)))
}

pub fn load_dump(text: &str, master_password: &[u8]) -> Result<PrincipalStore, DumpError> {
    let dump = parse_dump(text)?;
    let realm = dump.realm()?.to_owned();
    let etype = dump.master_etype().unwrap_or_else(default_master_etype);
    let mkey = master_key_from_password(&realm, master_password, etype)?;
    dump.into_store(&mkey)
}

// MIT: `process_k5beta7_princ` (kadmin/dbutil/dump.c:775-779)
// MIT: `process_k5beta7_policy` (kadmin/dbutil/dump.c:820-825)
pub fn update_store(
    store: &mut PrincipalStore,
    loaded: &PrincipalStore,
    order: &[&str],
) -> Result<(), KdcError> {
    let mut put = std::collections::HashSet::new();
    for name in order {
        if let Some(p) = loaded.get_raw(name)
            && put.insert(p.id())
        {
            store.put_principal(p.clone())?;
        }
    }
    for id in loaded.ids() {
        if let Some(p) = loaded.get_raw(&id)
            && put.insert(id)
        {
            store.put_principal(p.clone())?;
        }
    }
    for pol in loaded.policies().values() {
        store.put_policy(pol.clone())?;
    }
    Ok(())
}

pub fn load_dump_with_key(text: &str, mkey: &ProtocolKey) -> Result<PrincipalStore, DumpError> {
    load_dump_mkey(text, mkey)
}

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

pub(crate) fn load_dump_mkey(text: &str, mkey: &ProtocolKey) -> Result<PrincipalStore, DumpError> {
    parse_dump(text)?.into_store(mkey)
}

pub fn load_dump_path(path: &Path, master_password: &[u8]) -> Result<PrincipalStore, DumpError> {
    let text = fs::read_to_string(path)?;
    load_dump(&text, master_password)
}

pub fn dump_store(store: &PrincipalStore, master_password: &[u8]) -> Result<String, DumpError> {
    let etype = store
        .get(&format!("K/M@{}", store.realm()))
        .and_then(|km| km.keys.first())
        .map_or_else(default_master_etype, |k| k.etype);
    dump_store_etype(store, master_password, etype)
}

pub fn dump_store_with_key(
    store: &PrincipalStore,
    mkey: &ProtocolKey,
) -> Result<String, DumpError> {
    write_dump(store, mkey)
}

pub(crate) fn dump_store_etype(
    store: &PrincipalStore,
    master_password: &[u8],
    etype: EncryptionType,
) -> Result<String, DumpError> {
    let mkey = master_key_from_password(store.realm(), master_password, etype)?;
    write_dump(store, &mkey)
}

pub(crate) fn write_dump(store: &PrincipalStore, mkey: &ProtocolKey) -> Result<String, DumpError> {
    write_dump_nra(store, mkey, false)
}

// MIT: `k5beta7_common` (kadmin/dbutil/dump.c:342-344)
/// With `omit_nra` the three lockout attributes are written as 0.
fn write_dump_nra(
    store: &PrincipalStore,
    mkey: &ProtocolKey,
    omit_nra: bool,
) -> Result<String, DumpError> {
    let now = krb5_types::unix_now();
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
        let km = synthesize_km(
            store.realm(),
            mkey,
            now,
            store.policy.max_life,
            store.policy.max_renewable_life,
        );
        write_princ_record(&mut out, &km, mkey, store, omit_nra)?;
    }
    for p in princs {
        write_princ_record(&mut out, p, mkey, store, omit_nra)?;
    }
    let mut names: Vec<_> = store.policies().keys().cloned().collect();
    names.sort();
    for n in names {
        if let Some(pol) = store.policies().get(&n) {
            out.push_str(&policy_line(pol));
            out.push('\n');
        }
    }
    Ok(out)
}

fn policy_line(pol: &NamedPolicy) -> String {
    let ks = pol.allowed_keysalts.as_deref().unwrap_or("-");
    format!(
        "policy\t{}\t{}\t{}\t{}\t{}\t{}\t0\t{}\t{}\t{}\t0\t0\t0\t{ks}\t0",
        pol.name,
        pol.pw_min_life,
        pol.pw_max_life,
        pol.min_length,
        pol.min_classes,
        pol.history,
        pol.max_fail,
        pol.pw_failcnt_interval,
        pol.pw_lockout_duration
    )
}

pub fn write_dump_path_etype(
    store: &PrincipalStore,
    path: &Path,
    master_password: &[u8],
    etype: EncryptionType,
) -> Result<(), DumpError> {
    let text = dump_store_etype(store, master_password, etype)?;
    write_fresh_secret_file(path, text.as_bytes())?;
    Ok(())
}

fn parse_policy_rest(rest: &str) -> NamedPolicy {
    let parts: Vec<&str> = rest.split('\t').collect();
    let num = |i: usize| parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
    let ks = parts.get(13).copied().unwrap_or("-");
    NamedPolicy {
        name: parts.first().copied().unwrap_or("").to_owned(),
        pw_min_life: num(1),
        pw_max_life: num(2),
        min_length: num(3),
        min_classes: num(4),
        history: num(5),
        max_fail: num(7),
        pw_failcnt_interval: num(8),
        pw_lockout_duration: num(9),
        allowed_keysalts: if ks.is_empty() || ks == "-" {
            None
        } else {
            Some(ks.to_owned())
        },
    }
}

fn parse_header(line: &str) -> Result<u32, DumpError> {
    const PREFIX: &str = "kdb5_util load_dump version ";
    if line.starts_with("ipropx ") || line.starts_with("iprop ") {
        return Ok(KDB_DUMP_VERSION);
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpropHeaderError {
    NotIprop,
    UnknownVersion(u32),
    Short,
}

// MIT: `parse_iprop_header` (kadmin/dbutil/dump.c:1069-1107)
pub fn parse_iprop_header(line: &str) -> Result<(bool, UlogLast), IpropHeaderError> {
    let mut words = line.split_whitespace();
    let head = words.next().ok_or(IpropHeaderError::NotIprop)?;
    let nums: Vec<u32> = words.map_while(|w| w.parse().ok()).take(4).collect();
    let (x1, rest) = match head {
        "ipropx" if nums.len() == 4 => match nums[0] {
            0 => (false, &nums[1..]),
            1 => (true, &nums[1..]),
            v => return Err(IpropHeaderError::UnknownVersion(v)),
        },
        "iprop" if nums.len() == 3 => (false, &nums[..]),
        "ipropx" | "iprop" => return Err(IpropHeaderError::Short),
        _ => return Err(IpropHeaderError::NotIprop),
    };
    Ok((
        x1,
        UlogLast {
            sno: rest[0],
            time: crate::store::UlogTime {
                seconds: rest[1],
                useconds: rest[2],
            },
        },
    ))
}

const FGETS_BUFSIZ: u64 = 8192;

// MIT: `current_dump_sno_in_ulog` (kadmin/dbutil/dump.c:1111-1134)
#[must_use]
pub fn dump_current_in_ulog(dump_file: &Path, ulog: &crate::ulog::Ulog) -> bool {
    let Ok(file) = fs::File::open(dump_file) else {
        return false;
    };
    let mut line = Vec::new();
    if std::io::BufReader::new(file.take(FGETS_BUFSIZ))
        .read_until(b'\n', &mut line)
        .is_err()
    {
        return false;
    }
    let Ok((_, last)) = parse_iprop_header(&String::from_utf8_lossy(&line)) else {
        return false;
    };
    matches!(ulog.sno_status_of(last), IPROP_OK | IPROP_NIL)
}

// MIT: `dump_db` (kadmin/dbutil/dump.c:1176-1188)
// MIT: `dump_db` (kadmin/dbutil/dump.c:1318-1333)
/// The log's last serial is read before the database is iterated.
pub fn dump_store_iprop(
    store: &PrincipalStore,
    master_password: &[u8],
    last: UlogLast,
) -> Result<String, DumpError> {
    let etype = store
        .get(&format!("K/M@{}", store.realm()))
        .and_then(|km| km.keys.first())
        .map_or_else(default_master_etype, |k| k.etype);
    let mkey = master_key_from_password(store.realm(), master_password, etype)?;
    Ok(iprop_header(last, &write_dump_nra(store, &mkey, true)?))
}

pub fn dump_store_iprop_with_key(
    store: &PrincipalStore,
    mkey: &ProtocolKey,
    last: UlogLast,
) -> Result<String, DumpError> {
    Ok(iprop_header(last, &write_dump_nra(store, mkey, true)?))
}

// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:343-344)
// MIT: `dump_db` (kadmin/dbutil/dump.c:1173-1188)
pub fn conditional_iprop_dump(
    store: &PrincipalStore,
    dump_file: &Path,
    vers: u32,
) -> Result<(), DumpError> {
    match iprop_dump_text(store, dump_file, vers)? {
        Some(text) => write_iprop_dump(dump_file, &text),
        None => Ok(()),
    }
}

fn iprop_dump_text(
    store: &PrincipalStore,
    dump_file: &Path,
    vers: u32,
) -> Result<Option<String>, DumpError> {
    if let Some(ulog) = store.ulog()
        && dump_current_in_ulog(dump_file, ulog)
    {
        return Ok(None);
    }
    let mkey = store
        .journal_key()
        .ok_or_else(|| DumpError::Crypto("no master key for the iprop dump".to_owned()))?;
    let last = store.ulog_last().unwrap_or_default();
    let text = write_dump_nra(store, &mkey, true)?;
    Ok(Some(if vers == 0 {
        iprop_v0(last, &text)
    } else {
        iprop_header(last, &text)
    }))
}

fn write_iprop_dump(dump_file: &Path, text: &str) -> Result<(), DumpError> {
    write_dump_with_ok(dump_file, text.as_bytes()).map_err(|(_, e)| DumpError::Io(e))
}

// MIT: `dump_db` (kadmin/dbutil/dump.c:1318-1340)
/// Header and records: one fresh, locked view.
pub fn conditional_iprop_dump_fresh(
    store: &crate::SharedDump,
    dump_file: &Path,
    vers: u32,
) -> Result<(), DumpError> {
    for _ in 0..3 {
        let text = {
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match g.read_hold()? {
                None => Some(iprop_dump_text(&g, dump_file, vers)),
                Some((held, false)) => {
                    let text = iprop_dump_text(&g, dump_file, vers);
                    drop(held);
                    Some(text)
                }
                Some((held, true)) => {
                    drop(held);
                    None
                }
            }
        };
        if let Some(text) = text {
            return match text? {
                Some(text) => write_iprop_dump(dump_file, &text),
                None => Ok(()),
            };
        }
        store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reload_if_stale()?;
    }
    Err(DumpError::Format(
        "the database kept changing during the iprop dump".to_owned(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpOkStage {
    Create,
    Lock,
    Write,
}

// MIT: `prep_ok_file` (kadmin/dbutil/dump.c:171-208)
// MIT: `create_ofile` (kadmin/dbutil/dump.c:133-155)
// MIT: `finish_ofile` (kadmin/dbutil/dump.c:159-167)
// MIT: `update_ok_file` (kadmin/dbutil/dump.c:214-219)
pub fn write_dump_with_ok(path: &Path, text: &[u8]) -> Result<(), (DumpOkStage, std::io::Error)> {
    let mut ok_name = path.as_os_str().to_os_string();
    ok_name.push(".dump_ok");
    let ok_path = PathBuf::from(ok_name);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // `O_NOFOLLOW`: unlike MIT, a planted symlink is not emptied.
        opts.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let ok = krb5_protocol::create_labeled(&ok_path, || opts.open(&ok_path))
        .map_err(|e| (DumpOkStage::Create, e))?;
    let marked = crate::lock_file_exclusive(&ok).map_err(|e| (DumpOkStage::Lock, e))?;
    write_fresh_secret_file(path, text).map_err(|e| (DumpOkStage::Write, e))?;
    let _ = (&ok).write_all(&[0]);
    drop(marked);
    Ok(())
}

// MIT: `iprop_version` (kadmin/dbutil/dump.c:1046-1055)
fn iprop_v0(last: UlogLast, text: &str) -> String {
    let mut out = format!(
        "iprop {} {} {}\n",
        last.sno, last.time.seconds, last.time.useconds
    );
    for line in text.lines().skip(1) {
        match line.strip_prefix("policy\t") {
            Some(rest) => out.push_str(&DumpFile::policy_record(rest, 5)),
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

// MIT: `dump_db` (kadmin/dbutil/dump.c:1318-1329)
fn iprop_header(last: UlogLast, text: &str) -> String {
    let header = format!(
        "ipropx 1 {} {} {}\n",
        last.sno, last.time.seconds, last.time.useconds
    );
    text.replacen(
        &format!("kdb5_util load_dump version {KDB_DUMP_VERSION}\n"),
        &header,
        1,
    )
}

// MIT: `process_k5beta7_princ` (dump.c:615-628)
// MIT: `process_k5beta7_princ` (dump.c:666-674)
// MIT: `process_k5beta7_princ` (dump.c:676-690)
// MIT: `process_tl_data` (dump.c:566-594)
// MIT: `process_k5beta7_princ` (dump.c:729-762)
// MIT: `process_k5beta7_princ` (dump.c:766-770)
/// A name whose length is not the header count: not a principal.
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
    let bad = |msg: &str| DumpError::Format(format!("line {lineno}: {msg}"));
    let sizes =
        (|| Ok::<_, DumpError>((c.u32()?, c.usize()?, c.usize()?, c.usize()?, c.usize()?)))();
    let (db_len, namelen, n_tl, n_key, e_len) =
        sizes.map_err(|_| bad("cannot match size tokens"))?;
    let name = c
        .take()
        .ok()
        .filter(|n| n.len() == namelen)
        .ok_or_else(|| bad("cannot read name string"))?
        .to_owned();
    let attrs = (|| {
        Ok::<_, DumpError>([
            c.u32()?,
            c.u32()?,
            c.u32()?,
            c.u32()?,
            c.u32()?,
            c.u32()?,
            c.u32()?,
            c.u32()?,
        ])
    })()
    .map_err(|_| bad("cannot read principal attributes"))?;
    let [
        attributes,
        max_life,
        max_renewable_life,
        expiration,
        pw_expiration,
        last_success,
        last_failed,
        fail_auth_count,
    ] = attrs;
    let mut tl_data = Vec::with_capacity(n_tl.min(c.remaining()));
    for _ in 0..n_tl {
        let (ty, len) = (|| Ok::<_, DumpError>((c.i32()?, c.usize()?)))()
            .map_err(|_| bad("cannot read tagged data type and length"))?;
        let contents = c
            .hex(len)
            .map_err(|_| bad("cannot read tagged data contents"))?;
        tl_data.push(TlData { ty, contents });
    }
    let mut keys = Vec::with_capacity(n_key.min(c.remaining()));
    for _ in 0..n_key {
        let (ver, kvno) = (|| Ok::<_, DumpError>((c.i32()?, c.u32()?)))()
            .map_err(|_| bad("cannot read key size and version"))?;
        if !(1..=2).contains(&ver) {
            return Err(bad("unsupported key_data_ver version"));
        }
        if kvno > u32::from(u16::MAX) {
            return Err(bad("invalid kvno"));
        }
        let nslots = usize::try_from(ver).map_err(|_| bad("unsupported key_data_ver version"))?;
        let mut slots = Vec::with_capacity(nslots);
        for _ in 0..nslots {
            let (ty, len) = (|| Ok::<_, DumpError>((c.i32()?, c.usize()?)))()
                .map_err(|_| bad("cannot read key type and length"))?;
            let contents = c.hex(len).map_err(|_| bad("cannot read key data"))?;
            slots.push(DumpKeySlot { ty, contents });
        }
        keys.push(DumpKeyData { ver, kvno, slots });
    }
    let e_data = c.hex(e_len).map_err(|_| bad("cannot read extra data"))?;
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

    fn remaining(&self) -> usize {
        self.f.len().saturating_sub(self.i)
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
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
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
    let (comps, realm) =
        parse_name(s, "").map_err(|e| DumpError::Format(format!("principal {s}: {e}")))?;
    if realm.is_empty() || (comps.len() == 1 && comps[0].is_empty()) {
        return Err(DumpError::Format(format!("empty principal {s}")));
    }
    let ntype = if comps.len() == 2 && comps[0] == "host" {
        PrincipalName::NT_SRV_HST
    } else {
        infer_name_type(&comps)
    };
    let name =
        PrincipalName::try_new(ntype, comps).map_err(|e| DumpError::Format(e.to_string()))?;
    Ok((name, realm))
}

pub(crate) fn salt_of_keys(keys: &[KeyEntry], name: &PrincipalName, realm: &str) -> Vec<u8> {
    keys.first()
        .map_or_else(|| name.default_salt(realm), |k| key_salt(k, name, realm))
}

// MIT: `krb5_dbe_compute_salt` (lib/kdb/kdb5.c:2345-2388)
#[must_use]
pub fn key_salt(key: &KeyEntry, name: &PrincipalName, realm: &str) -> Vec<u8> {
    match key.salt_type.unwrap_or(SALTTYPE_NORMAL) {
        SALTTYPE_NOREALM => {
            let mut salt = Vec::new();
            for part in &name.name_string {
                salt.extend_from_slice(part.as_bytes());
            }
            salt
        }
        SALTTYPE_ONLYREALM => realm.as_bytes().to_vec(),
        SALTTYPE_SPECIAL => key.kdb_salt.clone().unwrap_or_default(),
        _ => name.default_salt(realm),
    }
}

fn known_salt(salt_type: Option<i32>) -> bool {
    matches!(
        salt_type.unwrap_or(SALTTYPE_NORMAL),
        SALTTYPE_NORMAL | SALTTYPE_NOREALM | SALTTYPE_ONLYREALM | SALTTYPE_SPECIAL
    )
}

// MIT: `krb5_dbe_specialize_salt` (lib/kdb/kdb5.c:2391-2419)
pub(crate) fn specialize_salts(p: &mut Principal) -> Result<(), KdcError> {
    if p.keys.iter().any(|k| !known_salt(k.salt_type)) {
        return Err(KdcError::InvalidArgument("Unsupported salt type".into()));
    }
    for k in &mut p.keys {
        let salt = key_salt(k, &p.name, &p.realm);
        k.salt_type = Some(SALTTYPE_SPECIAL);
        k.kdb_salt = Some(salt);
    }
    p.salt = p
        .keys
        .first()
        .and_then(|k| k.kdb_salt.clone())
        .unwrap_or_else(|| p.name.default_salt(&p.realm));
    Ok(())
}

pub(crate) fn mkvno_from_tl(tl: &[TlData]) -> u16 {
    tl.iter()
        .find(|t| t.ty == TL_MKVNO && t.contents.len() == 2)
        .map_or(1, |t| u16::from_le_bytes([t.contents[0], t.contents[1]]))
}

pub(crate) fn dump_attributes(p: &Principal) -> u32 {
    p.attributes
}

// MIT: `k5beta7_common` (dump.c:327-331)
/// A tagged-data count that mismatches the list is not written.
// MIT: `k5beta7_common` (kadmin/dbutil/dump.c:338-339)
/// A `max_life` of 0 is no limit of the principal's own.
fn write_princ_record(
    out: &mut String,
    p: &Principal,
    mkey: &ProtocolKey,
    store: &PrincipalStore,
    omit_nra: bool,
) -> Result<(), DumpError> {
    let name = p.id();
    let (max_life, max_rlife) = if p.alias_target().is_some() {
        (0, 0)
    } else {
        (
            u32::try_from(p.max_life).unwrap_or(u32::MAX),
            u32::try_from(p.max_renewable_life).unwrap_or(u32::MAX),
        )
    };
    let mut tl = if p.tl_data.is_empty() {
        synthesize_tl(
            &p.realm,
            krb5_types::unix_now(),
            p.mkvno,
            p.name.components_joined() == "K/M",
        )
    } else {
        p.tl_data.clone()
    };
    tl.retain(|t| t.ty != TL_DB_ARGS && t.ty != TL_KERBER_SERIAL);
    merge_sid_tl(&mut tl, store.domain_sid(), p.rid);
    let is_km = p.name.components_joined() == "K/M" && p.realm == store.realm();
    merge_rid_hwm(&mut tl, store.next_rid(), is_km);
    merge_s4u_tl(&mut tl, p);
    merge_kadm_tl(&mut tl, p);
    merge_string_attrs_tl(&mut tl, &p.string_attrs);
    if p.kadm.old_keys.is_empty() {
        merge_hist_tl(&mut tl, &p.key_history, mkey)?;
    }
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
    let lockout = if omit_nra {
        crate::Lockout::default()
    } else {
        store.lockout_kept(p)
    };
    let _ = write!(
        out,
        "{}\t{max_life}\t{max_rlife}\t{}\t{}\t{}\t{}\t{}",
        dump_attributes(p),
        p.expiration,
        p.pw_expire,
        lockout.last_success,
        lockout.last_failed,
        lockout.fail_auth_count
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
    if rid != 0 {
        tl.push(encode_sid_tl(domain, rid));
    }
}

fn merge_string_attrs_tl(tl: &mut Vec<TlData>, attrs: &[(String, String)]) {
    tl.retain(|t| t.ty != TL_STRING_ATTRS);
    if attrs.is_empty() {
        return;
    }
    let mut contents = Vec::new();
    for (k, v) in attrs {
        contents.extend_from_slice(k.as_bytes());
        contents.push(0);
        contents.extend_from_slice(v.as_bytes());
        contents.push(0);
    }
    tl.push(TlData {
        ty: TL_STRING_ATTRS,
        contents,
    });
}

pub(crate) fn attrs_from_tl(tl: &[TlData]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in tl {
        if t.ty != TL_STRING_ATTRS {
            continue;
        }
        let mut parts = t.contents.split(|b| *b == 0);
        while let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k.is_empty() {
                continue;
            }
            out.push((
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            ));
        }
    }
    out
}

pub(crate) fn merge_kadm_tl(tl: &mut Vec<TlData>, p: &Principal) {
    let has_kadm = tl.iter().any(|t| t.ty == TL_KADM_DATA);
    if has_kadm || p.pw_policy.is_none() && p.kadm.old_keys.is_empty() {
        return;
    }
    let mut fresh = p.clone();
    crate::store::refresh_kadm_tl(&mut fresh);
    tl.retain(|t| t.ty != TL_KERBER_POLICY);
    tl.extend(fresh.tl_data.into_iter().filter(|t| t.ty == TL_KADM_DATA));
}

fn merge_hist_tl(
    tl: &mut Vec<TlData>,
    hist: &[KeyEntry],
    mkey: &ProtocolKey,
) -> Result<(), DumpError> {
    tl.retain(|t| t.ty != TL_KERBER_HIST);
    if hist.is_empty() {
        return Ok(());
    }
    tl.push(TlData {
        ty: TL_KERBER_HIST,
        contents: encode_hist(hist, mkey)?,
    });
    Ok(())
}

fn encode_hist(keys: &[KeyEntry], mkey: &ProtocolKey) -> Result<Vec<u8>, DumpError> {
    let mut b = Vec::new();
    b.extend_from_slice(&(u32::try_from(keys.len()).unwrap_or(0)).to_be_bytes());
    for k in keys {
        b.extend_from_slice(&k.etype.to_iana().to_be_bytes());
        b.extend_from_slice(&k.kvno.to_be_bytes());
        let enc = kdb_encrypt_key(mkey, k.key.as_bytes())?;
        let n = u16::try_from(enc.len()).unwrap_or(u16::MAX);
        b.extend_from_slice(&n.to_be_bytes());
        b.extend_from_slice(&enc);
    }
    Ok(b)
}

fn hist_from_tl(tl: &[TlData], mkey: &ProtocolKey) -> Result<Vec<KeyEntry>, DumpError> {
    let Some(t) = tl.iter().find(|x| x.ty == TL_KERBER_HIST) else {
        return Ok(Vec::new());
    };
    decode_hist(&t.contents, mkey)
}

fn decode_hist(b: &[u8], mkey: &ProtocolKey) -> Result<Vec<KeyEntry>, DumpError> {
    if b.len() < 4 {
        return Err(DumpError::Format("short 0x4B04 hist tl_data".into()));
    }
    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let mut i = 4usize;
    // >= 10 bytes each.
    let mut out = Vec::with_capacity(n.min(b.len() / 10));
    for _ in 0..n {
        if i + 10 > b.len() {
            return Err(DumpError::Format("truncated 0x4B04 hist tl_data".into()));
        }
        let etype = i32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        i += 4;
        let kvno = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        i += 4;
        let ln = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        if i + ln > b.len() {
            return Err(DumpError::Format("truncated 0x4B04 hist key".into()));
        }
        let enc = &b[i..i + ln];
        i += ln;
        let et = EncryptionType::known(etype).map_err(|e| DumpError::Crypto(e.to_string()))?;
        let raw = kdb_decrypt_key(mkey, enc).map_err(|e| DumpError::Crypto(e.to_string()))?;
        let key =
            ProtocolKey::from_bytes(et, &raw).map_err(|e| DumpError::Crypto(e.to_string()))?;
        out.push(KeyEntry::new(et, key, kvno));
    }
    Ok(out)
}

fn policy_from_tl(tl: &[TlData]) -> Option<String> {
    tl.iter()
        .find(|t| t.ty == TL_KERBER_POLICY)
        .and_then(|t| std::str::from_utf8(&t.contents).ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn nul_name(t: &TlData) -> Option<String> {
    let raw = t.contents.strip_suffix(&[0])?;
    if raw.contains(&0) || raw.is_empty() {
        return None;
    }
    std::str::from_utf8(raw).ok().map(str::to_owned)
}

pub(crate) fn nul_tl_names(tl: &[TlData], ty: i32) -> Vec<String> {
    tl.iter()
        .filter(|t| t.ty == ty)
        .filter_map(nul_name)
        .collect()
}

pub(crate) fn is_s4u_name_tl(t: &TlData) -> bool {
    (t.ty == TL_CONSTRAINED_DELEGATION || t.ty == TL_KERBER_S4U_FROM) && nul_name(t).is_some()
}

pub(crate) fn absorb_identity_tl(p: &mut Principal) -> Option<u32> {
    let hwm = rid_hwm_of(&p.tl_data);
    absorb_s4u_tl(p);
    p.tl_data.retain(|t| t.ty != TL_KERBER_RID_HWM);
    hwm
}

pub(crate) fn absorb_s4u_tl(p: &mut Principal) {
    if p.tl_data
        .iter()
        .any(|t| is_s4u_name_tl(t) && t.ty == TL_CONSTRAINED_DELEGATION)
    {
        p.s4u_allowed_to = nul_tl_names(&p.tl_data, TL_CONSTRAINED_DELEGATION);
    }
    if p.tl_data
        .iter()
        .any(|t| is_s4u_name_tl(t) && t.ty == TL_KERBER_S4U_FROM)
    {
        p.s4u_allowed_from = nul_tl_names(&p.tl_data, TL_KERBER_S4U_FROM);
    }
    p.tl_data.retain(|t| !is_s4u_name_tl(t));
}

fn rid_hwm_of(tl: &[TlData]) -> Option<u32> {
    let bytes = tl
        .iter()
        .find(|t| t.ty == TL_KERBER_RID_HWM)?
        .contents
        .get(..4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn merge_rid_hwm(tl: &mut Vec<TlData>, next: u32, is_km: bool) {
    tl.retain(|t| t.ty != TL_KERBER_RID_HWM);
    if is_km {
        tl.push(TlData {
            ty: TL_KERBER_RID_HWM,
            contents: next.to_le_bytes().to_vec(),
        });
    }
}

pub(crate) fn merge_s4u_tl(tl: &mut Vec<TlData>, p: &Principal) {
    tl.retain(|t| !is_s4u_name_tl(t));
    for name in &p.s4u_allowed_to {
        tl.push(nul_tl(TL_CONSTRAINED_DELEGATION, name));
    }
    for name in &p.s4u_allowed_from {
        tl.push(nul_tl(TL_KERBER_S4U_FROM, name));
    }
}

pub(crate) fn nul_tl(ty: i32, name: &str) -> TlData {
    let mut contents = name.as_bytes().to_vec();
    contents.push(0);
    TlData { ty, contents }
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

fn parse_sid_tl(tl: &[TlData]) -> Result<(Option<RpcSid>, u32), DumpError> {
    let Some(t) = tl.iter().find(|t| t.ty == TL_KERBER_SID) else {
        return Ok((None, 0));
    };
    if t.contents.len() < 13 || t.contents[0] != 1 {
        return Err(DumpError::Format("corrupt 0x4B01 SID tl_data".into()));
    }
    let rid = u32::from_le_bytes([t.contents[1], t.contents[2], t.contents[3], t.contents[4]]);
    let revision = t.contents[5];
    let n = usize::from(t.contents[6]);
    if t.contents.len() < 13 + n * 4 {
        return Err(DumpError::Format("truncated 0x4B01 SID tl_data".into()));
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
    Ok((
        Some(RpcSid {
            revision,
            identifier_authority,
            sub_authority,
        }),
        rid,
    ))
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

fn synthesize_km(
    realm: &str,
    mkey: &ProtocolKey,
    now: u32,
    max_life: u64,
    max_renewable_life: u64,
) -> Principal {
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
    let salt = name.default_salt(realm);
    let mut p = Principal::from_keys(
        name,
        realm.to_owned(),
        vec![KeyEntry::new(mkey.etype(), mkey.clone(), 1)],
        salt,
        crate::store::PrincipalFields {
            requires_preauth: false,
            max_life,
            locked: true,
            pw_expire: 0,
        },
    );
    p.attributes = KDB_DISALLOW_ALL_TIX | KDB_LOCKDOWN_KEYS;
    p.max_renewable_life = max_renewable_life;
    p.tl_data = synthesize_tl(realm, now, 1, true);
    p
}
