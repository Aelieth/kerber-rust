//! Compare MIT vs Rust KDC replies after masking volatiles.
//!
//! KRB-ERROR mask: `stime`/`susec`/`ctime`/`cusec`. `e_text` is compared.
//! PREAUTH / MORE_PREAUTH / TYPED-DATA `e_data` is structural (type
//! **multiset**; order stays item 15). Success nulls session key, times,
//! `last_req`, both `enc_part.cipher`s, and PAC auth-data. Any other field
//! difference is fail-red.

use krb5_asn1::decode;
use krb5_types::{
    EncKdcRepPart, EncTicketPart, EtypeInfo2, KdcRep, KrbError, MethodData, PaData, TypedDataList,
    err, pa,
};

/// Stable-field mismatch (or decode failure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffError(pub String);

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DiffError {}

/// Stable KRB-ERROR fields (times stripped; `e_text` is the MIT status word).
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
    /// MIT status word (`e_text`).
    pub e_text: String,
    /// Whether `crealm` is present (R4: omit with a missing client).
    pub has_crealm: bool,
    /// Whether `cname` is present.
    pub has_cname: bool,
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
    /// TicketFlags as a big-endian bitmask.
    pub flags: u32,
    /// Reply outer padata types, sorted.
    pub padata_types: Vec<i32>,
    /// Ticket EncTicketPart crealm.
    pub tkt_crealm: String,
    /// Ticket EncTicketPart cname.
    pub tkt_cname: String,
}

fn ks(r: &krb5_types::KerberosString) -> String {
    String::from_utf8_lossy(r.as_bytes()).into_owned()
}

/// Mask times; keep `error_code`, `realm`, `sname`, `e_text`, and client presence.
#[must_use]
pub fn stable_krb_error(e: &KrbError) -> StableKrbError {
    StableKrbError {
        pvno: e.pvno,
        msg_type: e.msg_type,
        error_code: e.error_code,
        realm: ks(&e.realm),
        sname: e.sname.components_joined(),
        e_text: e.e_text.as_ref().map(ks).unwrap_or_default(),
        has_crealm: e.crealm.is_some(),
        has_cname: e.cname.is_some(),
    }
}

/// Compare two KRB-ERRORs. PREAUTH / MORE_PREAUTH / TYPED e_data is structural.
///
/// # Errors
///
/// Stable fields differ, or e_data is not structurally equal.
pub fn compare_krb_error(rust: &KrbError, mit: &KrbError) -> Result<(), DiffError> {
    let a = stable_krb_error(rust);
    let b = stable_krb_error(mit);
    if a != b {
        return Err(DiffError(format!(
            "krb-error stable mismatch rust={a:?} mit={b:?}"
        )));
    }
    // MIT finish_preauth (do_as_req.c:443-447) attaches the get_preauth_hint_list
    // e_data to PREAUTH_FAILED (24) as well as PREAUTH_REQUIRED (25). 91 carries
    // module METHOD-DATA (+ maybe_add_etype_info2). 65 is TYPED-DATA.
    if matches!(
        a.error_code,
        err::PREAUTH_REQUIRED
            | err::PREAUTH_FAILED
            | err::MORE_PREAUTH_DATA_REQUIRED
            | err::DH_KEY_PARAMETERS_NOT_ACCEPTED
    ) {
        compare_preauth_e_data(
            rust.e_data.as_ref().map(std::convert::AsRef::as_ref),
            mit.e_data.as_ref().map(std::convert::AsRef::as_ref),
        )?;
    }
    Ok(())
}

fn decode_edata(ed: &[u8]) -> Result<MethodData, DiffError> {
    if let Ok(m) = decode::<MethodData>(ed)
        && !m.is_empty()
    {
        return Ok(m);
    }
    let td: TypedDataList = decode(ed).map_err(|e| DiffError(format!("TYPED-DATA: {e}")))?;
    if td.is_empty() {
        return Err(DiffError("empty e_data METHOD/TYPED-DATA".into()));
    }
    Ok(td
        .into_iter()
        .map(|t| PaData {
            padata_type: t.data_type,
            padata_value: t.data_value,
        })
        .collect())
}

fn type_multiset(m: &MethodData) -> Vec<i32> {
    let mut v: Vec<i32> = m.iter().map(|p| p.padata_type).collect();
    v.sort_unstable();
    v
}

/// Structural METHOD-DATA / TYPED-DATA compare for 25/24/91/65 e_data.
///
/// Both legs' padata type **multisets** must match (order is item 15). When
/// FX-FAST (136) is present (hint list), FX-COOKIE and ETYPE-INFO2 are
/// required and the ETYPE-INFO2 etype sets must be equal. ENC_TIMESTAMP
/// agreement is implied by the multiset.
///
/// # Errors
///
/// Missing `e_data`, decode failure, type-multiset mismatch, or etype mismatch.
pub fn compare_preauth_e_data(a: Option<&[u8]>, b: Option<&[u8]>) -> Result<(), DiffError> {
    let a = a.ok_or_else(|| DiffError("rust e_data missing".into()))?;
    let b = b.ok_or_else(|| DiffError("mit e_data missing".into()))?;
    let ma = decode_edata(a)?;
    let mb = decode_edata(b)?;
    let sa = type_multiset(&ma);
    let sb = type_multiset(&mb);
    if sa != sb {
        return Err(DiffError(format!(
            "PREAUTH e_data type multiset rust={sa:?} mit={sb:?}"
        )));
    }
    if sa.contains(&pa::FX_FAST) {
        // FAST-wrapped outer 25/24 is empty 136 only; cookie and ETYPE-INFO2
        // live inside FX-ERROR (kdc_fast.c / prepare_error_as).
        if sa == [pa::FX_FAST] {
            return Ok(());
        }
        if !sa.contains(&pa::FX_COOKIE) {
            return Err(DiffError(format!(
                "PREAUTH METHOD-DATA missing {} rust={sa:?} mit={sb:?}",
                pa::FX_COOKIE
            )));
        }
        if !sa.contains(&pa::ETYPE_INFO2) {
            return Err(DiffError(format!(
                "PREAUTH METHOD-DATA missing {} rust={sa:?} mit={sb:?}",
                pa::ETYPE_INFO2
            )));
        }
    }
    if sa.contains(&pa::ETYPE_INFO2) {
        let ea = etype_info2_etypes(&ma)?;
        let eb = etype_info2_etypes(&mb)?;
        if ea.is_empty() || eb.is_empty() {
            return Err(DiffError(format!(
                "ETYPE-INFO2 empty rust={ea:?} mit={eb:?}"
            )));
        }
        if ea != eb {
            return Err(DiffError(format!(
                "ETYPE-INFO2 etype set rust={ea:?} mit={eb:?}"
            )));
        }
    }
    Ok(())
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

/// Decode EncKDCRepPart: APPLICATION 26, then 25, then untagged.
///
/// # Errors
///
/// No recognized DER tag.
pub fn decode_enc_kdc_rep(plain: &[u8]) -> Result<EncKdcRepPart, DiffError> {
    krb5_asn1::decode_enc_kdc_rep_part(plain).map_err(|e| DiffError(e.to_string()))
}

fn padata_types(rep: &KdcRep) -> Vec<i32> {
    let mut v: Vec<i32> = rep
        .padata
        .as_ref()
        .map(|p| p.iter().map(|d| d.padata_type).collect())
        .unwrap_or_default();
    v.sort_unstable();
    v
}

/// Null volatiles and project the stable AS/TGS set.
#[must_use]
pub fn stable_rep(rep: &KdcRep, enc: &EncKdcRepPart, ticket: &EncTicketPart) -> StableRep {
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
        transited_tr_type: ticket.transited.tr_type,
        transited_contents: ticket.transited.contents.as_ref().to_vec(),
        flags: enc.flags.to_u32(),
        padata_types: padata_types(rep),
        tkt_crealm: ks(&ticket.crealm),
        tkt_cname: ticket.cname.components_joined(),
    }
}

/// Compare decrypted AS/TGS replies field by field.
///
/// # Errors
///
/// Any stable-field mismatch.
pub fn compare_stable_rep(
    rust_rep: &KdcRep,
    rust_enc: &EncKdcRepPart,
    rust_tkt: &EncTicketPart,
    mit_rep: &KdcRep,
    mit_enc: &EncKdcRepPart,
    mit_tkt: &EncTicketPart,
) -> Result<(), DiffError> {
    let mut a = stable_rep(rust_rep, rust_enc, rust_tkt);
    let mut b = stable_rep(mit_rep, mit_enc, mit_tkt);
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
    Ok(())
}
