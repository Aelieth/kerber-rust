//! Compare MIT and Rust KDC replies after the volatiles are masked.
//! KRB-ERROR times are masked. e_text is compared. Any other difference is fail-red.
//! PREAUTH e_data is a type multiset. The differential gate pins the wire order.
//! A success leaves out the session key, the times, last_req, both ciphers, and PAC.

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

/// Times are stripped. e_text stays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableKrbError {
    pub pvno: i32,
    pub msg_type: i32,
    pub error_code: i32,
    pub realm: String,
    pub sname: String,
    pub e_text: String,
    /// Presence only. A missing client omits it.
    pub has_crealm: bool,
    pub has_cname: bool,
}

/// The volatiles are left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableRep {
    pub pvno: i32,
    pub msg_type: i32,
    pub crealm: String,
    pub cname: String,
    pub ticket_realm: String,
    pub ticket_sname: String,
    pub enc_part_etype: i32,
    pub enc_part_kvno: Option<u32>,
    pub srealm: String,
    pub sname: String,
    pub transited_tr_type: i32,
    pub transited_contents: Vec<u8>,
    /// TicketFlags as a big-endian bitmask.
    pub flags: u32,
    /// Outer padata types, sorted.
    pub padata_types: Vec<i32>,
    pub tkt_crealm: String,
    pub tkt_cname: String,
}

fn ks(r: &krb5_types::KerberosString) -> String {
    String::from_utf8_lossy(r.as_bytes()).into_owned()
}

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

/// PREAUTH, MORE_PREAUTH and TYPED e_data are compared as structure.
pub fn compare_krb_error(rust: &KrbError, mit: &KrbError) -> Result<(), DiffError> {
    let a = stable_krb_error(rust);
    let b = stable_krb_error(mit);
    if a != b {
        return Err(DiffError(format!(
            "krb-error stable mismatch rust={a:?} mit={b:?}"
        )));
    }
    // MIT: `finish_preauth` (do_as_req.c:443-447)
    // PREAUTH_FAILED carries the hint list too. 91 is METHOD-DATA; 65 is TYPED-DATA.
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

/// The type multisets must match. The gate's proxy pins the wire order.
/// With FX-FAST, FX-COOKIE is required. ETYPE-INFO2 only when a leg listed it.
// MIT: `add_etype_info` (kdc_preauth.c:776-778)
/// No client key skips ETYPE-INFO2.
/// When both list it, the etype sets are equal. ENC-TIMESTAMP is the multiset.
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
        // The outer e_data of a FAST error is one PA-FX-FAST.
        // MIT: `prepare_error_as` (do_as_req.c:785-826)
        // MIT: `kdc_fast_handle_error` (kdc/fast_util.c:380-418)
        // Cookie and ETYPE-INFO2 live inside that encrypted response.
        if sa == [pa::FX_FAST] {
            return Ok(());
        }
        if !sa.contains(&pa::FX_COOKIE) {
            return Err(DiffError(format!(
                "PREAUTH METHOD-DATA missing {} rust={sa:?} mit={sb:?}",
                pa::FX_COOKIE
            )));
        }
        // The type multiset still has to match; do not require 19.
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

/// Tries APPLICATION 26, then 25, then untagged.
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

/// A kvno present on only one leg is not compared.
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
