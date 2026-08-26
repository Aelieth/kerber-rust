//! Compare MIT vs Rust KDC replies after masking volatiles.
//!
//! KRB-ERROR mask: `stime`/`susec`/`ctime`/`cusec`/`e_text`. PREAUTH_REQUIRED
//! `e_data` is structural (METHOD-DATA types, ETYPE-INFO2 etypes; salt/order
//! may differ). Success nulls session key, times, `last_req`, both
//! `enc_part.cipher`s, and PAC auth-data. [`Whitelist`] names known MIT
//! divergences; anything else is fail-red.

use krb5_asn1::decode;
use krb5_types::flag_bit;
use krb5_types::{
    err, pa, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EtypeInfo2, KdcRep,
    KrbError, MethodData, TicketFlags,
};

/// Named MIT/Rust divergences that must not fail the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Whitelist {
    /// MIT default policy issues renewable; Rust only when the client asks.
    pub mit_renewable_flags: bool,
    /// MIT adds PA-ETYPE-INFO2 / PA-SUPPORTED-ENCTYPES on AS/TGS replies.
    pub mit_as_padata: bool,
}

impl Default for Whitelist {
    fn default() -> Self {
        Self {
            mit_renewable_flags: true,
            mit_as_padata: true,
        }
    }
}

/// Stable-field mismatch (or decode failure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffError(pub String);

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DiffError {}

/// Result of a successful compare, including whitelist hits that fired.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompareOk {
    /// Whitelist entry names that actually differed (`mit-renewable-flags`, …).
    pub whitelisted: Vec<&'static str>,
    /// MIT AS enc-part used APPLICATION 26 (RFC 4120 is 25).
    pub mit_as_enc_app26: bool,
}

/// Stable KRB-ERROR fields (time/`e_text` stripped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableKrbError {
    /// Protocol version.
    pub pvno: i32,
    /// Message type (30).
    pub msg_type: i32,
    /// RFC 4120 error-code.
    pub error_code: i32,
    /// Error realm.
    pub realm: String,
    /// Error sname (`krbtgt/REALM` typically).
    pub sname: String,
}

/// Stable AS/TGS fields after volatile-null.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableRep {
    /// Protocol version.
    pub pvno: i32,
    /// 11 = AS-REP, 13 = TGS-REP.
    pub msg_type: i32,
    /// Client realm.
    pub crealm: String,
    /// Client name.
    pub cname: String,
    /// Ticket realm.
    pub ticket_realm: String,
    /// Ticket sname.
    pub ticket_sname: String,
    /// EncryptedData etype on the reply enc-part.
    pub enc_part_etype: i32,
    /// EncryptedData kvno on the reply enc-part.
    pub enc_part_kvno: Option<u32>,
    /// EncKDCRepPart srealm.
    pub srealm: String,
    /// EncKDCRepPart sname.
    pub sname: String,
    /// Transited encoding type.
    pub transited_tr_type: i32,
    /// Transited contents.
    pub transited_contents: Vec<u8>,
    /// TicketFlags with renewable cleared when whitelisted.
    pub flags: u32,
    /// Reply padata types after dropping whitelisted MIT types.
    pub padata_types: Vec<i32>,
    /// Ticket EncTicketPart crealm.
    pub tkt_crealm: String,
    /// Ticket EncTicketPart cname.
    pub tkt_cname: String,
}

fn ks(r: &krb5_types::KerberosString) -> String {
    String::from_utf8_lossy(r.as_bytes()).into_owned()
}

/// Mask time/`e_text` and keep `error_code` + `realm` + `sname`.
#[must_use]
pub fn stable_krb_error(e: &KrbError) -> StableKrbError {
    StableKrbError {
        pvno: e.pvno,
        msg_type: e.msg_type,
        error_code: e.error_code,
        realm: ks(&e.realm),
        sname: e.sname.components_joined(),
    }
}

/// Compare two KRB-ERRORs. PREAUTH_REQUIRED `e_data` is structural.
///
/// # Errors
///
/// Stable fields differ, or PREAUTH `e_data` is not structurally equal.
pub fn compare_krb_error(rust: &KrbError, mit: &KrbError) -> Result<CompareOk, DiffError> {
    let a = stable_krb_error(rust);
    let b = stable_krb_error(mit);
    if a != b {
        return Err(DiffError(format!(
            "krb-error stable mismatch rust={a:?} mit={b:?}"
        )));
    }
    if a.error_code == err::PREAUTH_REQUIRED {
        compare_preauth_e_data(
            rust.e_data.as_ref().map(std::convert::AsRef::as_ref),
            mit.e_data.as_ref().map(std::convert::AsRef::as_ref),
        )?;
    }
    Ok(CompareOk::default())
}

/// Structural METHOD-DATA / ETYPE-INFO2 compare (order and salt ignored).
///
/// # Errors
///
/// Missing `e_data`, decode failure, or etype/pa-type set mismatch.
pub fn compare_preauth_e_data(a: Option<&[u8]>, b: Option<&[u8]>) -> Result<(), DiffError> {
    let a = a.ok_or_else(|| DiffError("rust PREAUTH_REQUIRED missing e_data".into()))?;
    let b = b.ok_or_else(|| DiffError("mit PREAUTH_REQUIRED missing e_data".into()))?;
    let ma: MethodData = decode(a).map_err(|e| DiffError(format!("rust METHOD-DATA: {e}")))?;
    let mb: MethodData = decode(b).map_err(|e| DiffError(format!("mit METHOD-DATA: {e}")))?;
    let ta = pa_types(&ma);
    let tb = pa_types(&mb);
    // ENC_TIMESTAMP + ETYPE-INFO2 are the comparable hints. Extra types are
    // mechanism ads (Rust SPAKE 151 vs MIT FAST 133/136).
    for need in [pa::ENC_TIMESTAMP, pa::ETYPE_INFO2] {
        if !ta.contains(&need) || !tb.contains(&need) {
            return Err(DiffError(format!(
                "PREAUTH METHOD-DATA missing {need} rust={ta:?} mit={tb:?}"
            )));
        }
    }
    let ea = etype_info2_etypes(&ma)?;
    let eb = etype_info2_etypes(&mb)?;
    if ea.is_empty() || eb.is_empty() {
        return Err(DiffError(format!(
            "ETYPE-INFO2 empty rust={ea:?} mit={eb:?}"
        )));
    }
    // MIT lists the chosen etype; Rust lists every key. Require MIT ⊆ Rust.
    if eb.iter().any(|e| !ea.contains(e)) {
        return Err(DiffError(format!(
            "ETYPE-INFO2 mit not subset of rust rust={ea:?} mit={eb:?}"
        )));
    }
    Ok(())
}

fn pa_types(m: &MethodData) -> Vec<i32> {
    let mut v: Vec<i32> = m.iter().map(|p| p.padata_type).collect();
    v.sort_unstable();
    v
}

fn etype_info2_etypes(m: &MethodData) -> Result<Vec<i32>, DiffError> {
    let mut out = Vec::new();
    for p in m {
        if p.padata_type != pa::ETYPE_INFO2 {
            continue;
        }
        let info: EtypeInfo2 =
            decode(p.padata_value.as_ref()).map_err(|e| DiffError(format!("ETYPE-INFO2: {e}")))?;
        out.extend(info.iter().map(|e| e.etype));
    }
    out.sort_unstable();
    Ok(out)
}

/// Decode EncKDCRepPart, accepting APPLICATION 25, MIT's 26, or untagged.
///
/// # Errors
///
/// No recognized DER tag.
pub fn decode_enc_kdc_rep(plain: &[u8]) -> Result<(EncKdcRepPart, bool), DiffError> {
    if let Ok(EncAsRepPart(part)) = decode::<EncAsRepPart>(plain) {
        return Ok((part, false));
    }
    if plain.first() == Some(&0x7a) {
        if let Ok(EncTgsRepPart(part)) = decode::<EncTgsRepPart>(plain) {
            return Ok((part, true));
        }
    }
    if let Ok(part) = decode::<EncKdcRepPart>(plain) {
        return Ok((part, false));
    }
    Err(DiffError(format!(
        "enc-part der tag={:02x} len={}",
        plain.first().copied().unwrap_or(0),
        plain.len()
    )))
}

fn named_flag_mask(wl: &Whitelist) -> u32 {
    let mut m = 1u32 << (31 - flag_bit::CANONICALIZE);
    if wl.mit_renewable_flags {
        m |= 1 << (31 - flag_bit::RENEWABLE);
    }
    m
}

fn masked_flags(f: &TicketFlags, wl: &Whitelist) -> u32 {
    f.to_u32() & !named_flag_mask(wl)
}

fn padata_types_filtered(rep: &KdcRep, drop_mit: bool) -> Vec<i32> {
    let mut v: Vec<i32> = rep
        .padata
        .as_ref()
        .map(|p| {
            p.iter()
                .map(|d| d.padata_type)
                .filter(|t| !drop_mit || (*t != pa::ETYPE_INFO2 && *t != pa::SUPPORTED_ENCTYPES))
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

/// Null volatiles and project the stable AS/TGS set.
#[must_use]
pub fn stable_rep(
    rep: &KdcRep,
    enc: &EncKdcRepPart,
    ticket: &EncTicketPart,
    wl: &Whitelist,
) -> StableRep {
    StableRep {
        pvno: rep.pvno,
        msg_type: rep.msg_type,
        crealm: ks(&rep.crealm),
        cname: rep.cname.components_joined(),
        ticket_realm: ks(&rep.ticket.realm),
        ticket_sname: rep.ticket.sname.components_joined(),
        enc_part_etype: rep.enc_part.etype,
        enc_part_kvno: rep.enc_part.kvno,
        srealm: ks(&enc.srealm),
        sname: enc.sname.components_joined(),
        transited_tr_type: if ticket.transited.contents.as_ref().is_empty() {
            0
        } else {
            ticket.transited.tr_type
        },
        transited_contents: ticket.transited.contents.as_ref().to_vec(),
        flags: masked_flags(&enc.flags, wl),
        padata_types: padata_types_filtered(rep, wl.mit_as_padata),
        tkt_crealm: ks(&ticket.crealm),
        tkt_cname: ticket.cname.components_joined(),
    }
}

fn whitelist_hits(
    rust: &KdcRep,
    mit: &KdcRep,
    rust_enc: &EncKdcRepPart,
    mit_enc: &EncKdcRepPart,
    rust_tkt: &EncTicketPart,
    mit_tkt: &EncTicketPart,
    wl: &Whitelist,
) -> Vec<&'static str> {
    let mut hits = Vec::new();
    if wl.mit_renewable_flags {
        let rf = rust_enc.flags.renewable();
        let mf = mit_enc.flags.renewable();
        if rf != mf {
            hits.push("mit-renewable-flags");
        }
    }
    if wl.mit_as_padata {
        let raw_r = padata_types_filtered(rust, false);
        let raw_m = padata_types_filtered(mit, false);
        if raw_r != raw_m {
            hits.push("mit-as-padata");
        }
    }
    if rust_enc.flags.bit(flag_bit::CANONICALIZE) != mit_enc.flags.bit(flag_bit::CANONICALIZE) {
        hits.push("mit-extra-ticket-flags");
    }
    if rust.enc_part.kvno != mit.enc_part.kvno {
        hits.push("mit-as-enc-kvno");
    }
    if rust_tkt.transited.tr_type != mit_tkt.transited.tr_type
        && rust_tkt.transited.contents.as_ref().is_empty()
        && mit_tkt.transited.contents.as_ref().is_empty()
    {
        hits.push("mit-empty-transited-type");
    }
    hits
}

/// Compare decrypted AS/TGS replies under [`Whitelist`].
///
/// # Errors
///
/// Un-whitelisted stable-field mismatch.
pub fn compare_stable_rep(
    rust_rep: &KdcRep,
    rust_enc: &EncKdcRepPart,
    rust_tkt: &EncTicketPart,
    mit_rep: &KdcRep,
    mit_enc: &EncKdcRepPart,
    mit_tkt: &EncTicketPart,
    wl: &Whitelist,
) -> Result<CompareOk, DiffError> {
    let mut a = stable_rep(rust_rep, rust_enc, rust_tkt, wl);
    let mut b = stable_rep(mit_rep, mit_enc, mit_tkt, wl);
    if a.enc_part_kvno != b.enc_part_kvno
        && (a.enc_part_kvno.is_none() || b.enc_part_kvno.is_none())
    {
        a.enc_part_kvno = None;
        b.enc_part_kvno = None;
    }
    if a != b {
        return Err(DiffError(format!(
            "stable-rep mismatch rust={a:?} mit={b:?}"
        )));
    }
    Ok(CompareOk {
        whitelisted: whitelist_hits(rust_rep, mit_rep, rust_enc, mit_enc, rust_tkt, mit_tkt, wl),
        mit_as_enc_app26: false,
    })
}
