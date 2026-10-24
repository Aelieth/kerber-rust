//! FAST, SPAKE, and PKINIT processing on the KDC.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, cksumtype_is_keyed, decrypt, decrypt_enc_data,
    derive_prfplus, encrypt, krb_fx_cf2, octetstring2key, pkinit_kdf_agile, verify_checksum_type,
};
use krb5_log::klog::{self, Severity};
use krb5_types::pkinit::{EkuCheck, KxGroup, KxKey, group_desc};
use krb5_types::{
    AsReq, EncryptedData, EncryptionKey, KdcReqBody, KerberosTime, MethodData, Microseconds,
    PaData, PrincipalName, TypedData, TypedDataList, err, flag_bit, ku, pa,
};
use zeroize::Zeroizing;

mod otp;
mod spake;

pub(crate) use otp::{otp_edata, process_otp, serve_start_diagnostics};
pub(crate) use spake::{SpakeStep, process_spake, spake_edata};

use crate::der::take_der;
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::status;
use crate::store::{KtkdbError, Principal, ktkdb_get_entry};

/// After armor, inner_body and inner_padata are the request; MIT frees the outer one.
pub(crate) struct FastOk {
    pub(crate) armor_key: ProtocolKey,
    pub(crate) inner_padata: Vec<PaData>,
    pub(crate) inner_body: Vec<u8>,
    pub(crate) nonce: u32,
    pub(crate) fast_options: krb5_types::fast::FastOptions,
}

pub(crate) fn unwrap_fast(
    store: &dyn PrincipalRead,
    req: &AsReq,
    body_der: &[u8],
) -> Result<Option<FastOk>, Error> {
    unwrap_fast_as(store, req.0.padata.as_deref(), body_der)
}

pub(crate) fn unwrap_fast_as(
    store: &dyn PrincipalRead,
    padata: Option<&[PaData]>,
    body_der: &[u8],
) -> Result<Option<FastOk>, Error> {
    kdc_find_fast(store, padata, body_der, None, None).map_err(map_fast_unwrap)
}

pub(crate) fn unwrap_fast_tgs(
    store: &dyn PrincipalRead,
    padata: Option<&[PaData]>,
    pa_tgs_raw: &[u8],
    subkey: Option<&EncryptionKey>,
    session: &ProtocolKey,
) -> Result<Option<FastOk>, Error> {
    kdc_find_fast(store, padata, pa_tgs_raw, subkey, Some(session)).map_err(map_fast_unwrap)
}

// MIT: `kdc_find_fast` (fast_util.c:126-247)
fn kdc_find_fast(
    store: &dyn PrincipalRead,
    padata: Option<&[PaData]>,
    checksummed_data: &[u8],
    tgs_subkey: Option<&EncryptionKey>,
    tgs_session: Option<&ProtocolKey>,
) -> Result<Option<FastOk>, Error> {
    let Some(raw) = find_pa(padata, pa::FX_FAST) else {
        return Ok(None);
    };
    let armored = match decode::<krb5_types::fast::PaFxFast>(raw) {
        Ok(krb5_types::fast::PaFxFast::ArmoredData(w)) => w,
        _ => decode::<krb5_types::fast::KrbFastArmoredReq>(raw)?,
    };
    let mut armor_key = None;
    if let Some(armor) = armored.armor.as_ref() {
        if armor.armor_type == krb5_types::fast::ARMOR_AP_REQUEST {
            if tgs_subkey.is_some() {
                return Err(proto_fast(
                    err::PREAUTH_FAILED,
                    "Ap-request armor not permitted with TGS",
                ));
            }
            armor_key = Some(armor_key_from_ap(store, armor.armor_value.as_ref())?);
        } else {
            return Err(proto_fast(
                err::PREAUTH_FAILED,
                format!("Unknown FAST armor type {}", armor.armor_type),
            ));
        }
    }
    let armor_key = match armor_key {
        Some(k) => k,
        None => match (tgs_subkey, tgs_session) {
            (Some(sub), Some(session)) => {
                let st = EncryptionType::from_iana(sub.keytype)
                    .or_else(|_| EncryptionType::known(sub.keytype))?;
                let subk = ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?;
                krb_fx_cf2(&subk, session, b"subkeyarmor", b"ticketarmor")?
            }
            _ => {
                return Err(proto_fast(
                    err::PREAUTH_FAILED,
                    "No armor key but FAST armored request present",
                ));
            }
        },
    };
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let plain = decrypt_enc_data(
        &armor_key,
        enc_usage,
        armored.enc_fast_req.etype,
        armored.enc_fast_req.cipher.as_ref(),
    )?;
    let inner: krb5_types::fast::KrbFastReq = decode(&plain)?;
    verify_fast_req_checksum(&armor_key, checksummed_data, &armored.req_checksum)?;
    let nonce = inner.req_body.nonce;
    let inner_body = fast_req_body_der(&plain).map_or_else(|| encode(&inner.req_body), Ok)?;
    Ok(Some(FastOk {
        armor_key,
        inner_padata: inner.padata,
        inner_body,
        nonce,
        fast_options: inner.fast_options,
    }))
}

fn fast_req_body_der(plain: &[u8]) -> Option<Vec<u8>> {
    let (t, seq, _) = take_der(plain)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = seq;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_der(cur)?;
        if tag == 0xa2 {
            return Some(inner.to_vec());
        }
        cur = rest;
    }
    None
}

fn verify_fast_req_checksum(
    armor_key: &ProtocolKey,
    ck_data: &[u8],
    ck: &krb5_types::Checksum,
) -> Result<(), Error> {
    // MIT: `kdc_find_fast` (fast_util.c:207-224)
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    match verify_checksum_type(
        armor_key,
        ck_usage,
        ck_data,
        ck.cksumtype,
        ck.checksum.as_ref(),
    ) {
        Ok(()) => {}
        Err(krb5_crypto::Error::UnsupportedChecksum(t)) => {
            let detail = if cksumtype_is_keyed(t) {
                "Bad encryption type"
            } else {
                "unknown checksum type"
            };
            return Err(proto_fast(err::GENERIC, detail));
        }
        Err(krb5_crypto::Error::BadChecksumSize) => {
            return Err(proto_fast(err::GENERIC, "checksum length"));
        }
        Err(_) => return Err(proto_fast(err::MODIFIED, "modified checksum")),
    }
    // Type 0 verifies as the key's checksum, then fails here as unkeyed.
    if !cksumtype_is_keyed(ck.cksumtype) {
        return Err(proto_fast(err::POLICY, "Unkeyed checksum used in fast_req"));
    }
    Ok(())
}

// MIT: `krb5_ktkdb_get_entry` (lib/kdb/keytab.c:117-185)
/// Only a missing kvno is BADKEYVER; any other key refusal is 60.
fn armor_ticket_key(
    store: &dyn PrincipalRead,
    p: &Principal,
    ticket: &krb5_types::Ticket,
) -> Result<ProtocolKey, Error> {
    let policy = store.policy();
    match ktkdb_get_entry(
        Some(p),
        &p.name,
        store.realm(),
        ticket.enc_part.kvno.unwrap_or(0),
        ticket.enc_part.etype,
        |e| policy.etype_permitted(e),
    ) {
        Ok(k) => Ok(k.key.clone()),
        Err(KtkdbError::KvnoNotFound) => Err(proto_fast(err::BADKEYVER, "FAST armor TGT")),
        Err(_) => Err(proto_fast(err::GENERIC, "FAST armor TGT")),
    }
}

// MIT: `krb5_ktkdb_get_entry` (kdb/keytab.c:157-163)
fn armor_key_from_ap(store: &dyn PrincipalRead, ap_raw: &[u8]) -> Result<ProtocolKey, Error> {
    let ap: krb5_types::ApReq = decode(ap_raw)?;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let cipher = ap.ticket.enc_part.cipher.as_ref();
    let ticket_realm = std::str::from_utf8(ap.ticket.realm.as_bytes())
        .map_err(|_| proto_fast(err::NOT_US, "FAST armor TGT"))?;
    if ticket_realm != store.realm() {
        return Err(proto_fast(err::NOT_US, "FAST armor TGT"));
    }
    let Some(p) = store.fetch_name(&ap.ticket.sname)? else {
        return Err(proto_fast(err::NOT_US, "FAST armor TGT"));
    };
    // MIT: `krb5_ktkdb_get_entry` (kdb/keytab.c:157-163)
    // MIT: `keytab_fetch_error` (rd_req_dec.c:137-147)
    let key = armor_ticket_key(store, &p, &ap.ticket)?;
    let enc_tkt = match decrypt_enc_data(&key, tkt_usage, ap.ticket.enc_part.etype, cipher) {
        Ok(plain) => decode::<krb5_types::EncTicketPart>(&plain)
            .map_err(|_| proto_fast(err::BAD_INTEGRITY, "FAST armor TGT"))?,
        // MIT: `errcode_to_protocol` (kdc_util.c:691-697)
        // A des3 armor key MIT refuses is 60, with the library message.
        Err(e @ (krb5_crypto::Error::DesBadParity | krb5_crypto::Error::DesWeakKey)) => {
            return Err(proto_fast(err::GENERIC, e.to_string()));
        }
        Err(_) => return Err(proto_fast(err::BAD_INTEGRITY, "FAST armor TGT")),
    };
    if enc_tkt.flags.invalid() {
        return Err(proto_fast(err::TKT_NYV, "FAST armor INVALID"));
    }
    let now = i64::from(krb5_types::KerberosTime::now().unix_seconds());
    let skew = store.policy().skew;
    let start = enc_tkt.starttime.as_ref().unwrap_or(&enc_tkt.authtime);
    if i64::from(start.unix_seconds()) > now + skew {
        return Err(proto_fast(err::TKT_NYV, "FAST armor NYV"));
    }
    if i64::from(enc_tkt.endtime.unix_seconds()) < now {
        return Err(proto_fast(err::TKT_EXPIRED, "FAST armor expired"));
    }
    let etype = EncryptionType::from_iana(enc_tkt.key.keytype)
        .or_else(|_| EncryptionType::known(enc_tkt.key.keytype))?;
    let session = ProtocolKey::from_bytes(etype, enc_tkt.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt_enc_data(
        &session,
        auth_usage,
        ap.authenticator.etype,
        ap.authenticator.cipher.as_ref(),
    )?;
    let authenticator: krb5_types::Authenticator = decode(&auth_plain)?;
    let then = i64::from(authenticator.ctime.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto_fast(err::SKEW, "FAST armor authenticator"));
    }
    // MIT: `rd_req_decoded_opt` (rd_req_dec.c:652-723)
    // An armor enctype the KDC does not permit is 60 FIND_FAST.
    krb5_protocol::negotiate_ap_req_etypes(
        &authenticator,
        enc_tkt.key.keytype,
        &store.policy().permitted_list(),
    )
    .map_err(|_| proto_fast(err::GENERIC, "FAST armor enctype not permitted"))?;
    // MIT: `armor_ap_request` (fast_util.c:51-68)
    // A local non-TGT is SERVER_NOMATCH only after the armor ticket is accepted.
    if !ap.ticket.sname.is_krbtgt_for(store.realm()) {
        return Err(proto_fast(err::SERVER_NOMATCH, "FAST armor TGT"));
    }
    let Some(sub) = authenticator.subkey else {
        return Err(proto_fast(err::POLICY, "ap-request armor without subkey"));
    };
    let st =
        EncryptionType::from_iana(sub.keytype).or_else(|_| EncryptionType::known(sub.keytype))?;
    let subk = ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?;
    krb_fx_cf2(&subk, &session, b"subkeyarmor", b"ticketarmor").map_err(Error::from)
}

const COOKIE_LIFETIME: i32 = 600;
const COOKIE_MAGIC: &[u8] = b"MIT1";
// MIT: `FRESHNESS_LIFETIME` (kdc_preauth.c:91-91)
/// A freshness token is valid for ten minutes.
pub(crate) const FRESHNESS_LIFETIME: i64 = 600;

pub(crate) fn mint_freshness_token(
    key: &ProtocolKey,
    kvno: u32,
    now: u32,
) -> Result<Vec<u8>, Error> {
    let ts = now.to_be_bytes();
    let mac = checksum(key, KeyUsage::new(ku::PA_AS_FRESHNESS)?, &ts)?;
    let mut out = Vec::with_capacity(8 + mac.len());
    out.extend_from_slice(&ts);
    out.extend_from_slice(&kvno.to_be_bytes());
    out.extend_from_slice(&mac);
    Ok(out)
}

pub(crate) fn mint_freshness_token_now(store: &dyn PrincipalRead) -> Result<Vec<u8>, Error> {
    let tgt = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    let key = store
        .policy()
        .first_current_key(&tgt)
        .map_err(|_| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    mint_freshness_token(&key.key, key.kvno, KerberosTime::now().unix_seconds())
}

pub(crate) fn check_freshness_token(
    store: &dyn PrincipalRead,
    token: &[u8],
    now: u32,
) -> Result<(), Error> {
    if token.len() <= 8 {
        return Err(proto(err::PREAUTH_EXPIRED, status::PREAUTH_FAILED));
    }
    let ts = u32::from_be_bytes(token[0..4].try_into().unwrap_or([0; 4]));
    let kvno = u32::from_be_bytes(token[4..8].try_into().unwrap_or([0; 4]));
    let mac = &token[8..];
    if i64::from(now) > i64::from(ts).saturating_add(FRESHNESS_LIFETIME) {
        return Err(proto(err::PREAUTH_EXPIRED, status::PREAUTH_FAILED));
    }
    let Some(tgt) = store.fetch_krbtgt().ok().flatten() else {
        return Err(proto(err::PREAUTH_EXPIRED, status::PREAUTH_FAILED));
    };
    // MIT: `check_freshness_token` (kdc_preauth.c:545-545)
    let Ok(key) = store.policy().find_enctype(&tgt, None, kvno) else {
        return Err(proto(err::PREAUTH_EXPIRED, status::PREAUTH_FAILED));
    };
    let usage = KeyUsage::new(ku::PA_AS_FRESHNESS)
        .map_err(|_| proto(err::PREAUTH_EXPIRED, status::PREAUTH_FAILED))?;
    match verify_checksum_type(&key.key, usage, &ts.to_be_bytes(), 0, mac) {
        Ok(()) => Ok(()),
        Err(_) => Err(proto(err::PREAUTH_EXPIRED, status::PREAUTH_FAILED)),
    }
}

fn derive_cookie_key(
    tgt_key: &ProtocolKey,
    client: &PrincipalName,
    realm: &str,
) -> Result<ProtocolKey, Error> {
    let princ = client.unparse_with_realm(realm);
    let mut seed = Vec::with_capacity(6 + princ.len());
    seed.extend_from_slice(b"COOKIE");
    seed.extend_from_slice(princ.as_bytes());
    derive_prfplus(tgt_key, &seed).map_err(Error::from)
}

// MIT: `kdc_fast_make_cookie` (fast_util.c:655-721)
pub(crate) fn make_cookie(
    store: &dyn PrincipalRead,
    client: &PrincipalName,
    contents: &[PaData],
) -> Result<Vec<u8>, Error> {
    let t = i32::try_from(KerberosTime::now().unix_seconds()).unwrap_or(0);
    make_cookie_at(store, client, contents, t)
}

pub(crate) fn make_cookie_at(
    store: &dyn PrincipalRead,
    client: &PrincipalName,
    contents: &[PaData],
    time: i32,
) -> Result<Vec<u8>, Error> {
    // Empty contents, or no krbtgt key, is the three-byte MIT cookie.
    if contents.is_empty() {
        return Ok(b"MIT".to_vec());
    }
    let Ok(Some(krbtgt_p)) = store.fetch_krbtgt() else {
        return Ok(b"MIT".to_vec());
    };
    let Ok(krbtgt) = store.policy().first_current_key(&krbtgt_p) else {
        return Ok(b"MIT".to_vec());
    };
    let key = derive_cookie_key(&krbtgt.key, client, store.realm())?;
    // MIT: `kdc_fast_make_cookie` (fast_util.c:714-717)
    // The cookie plaintext may hold SPAKE's scalar, so it is wiped.
    let der = Zeroizing::new(encode(&krb5_types::fast::SecureCookie {
        time,
        data: contents.to_vec(),
    })?);
    let usage = KeyUsage::new(ku::PA_FX_COOKIE)?;
    let cipher = encrypt(&key, usage, &der)?;
    let mut out = Vec::with_capacity(8 + cipher.len());
    out.extend_from_slice(COOKIE_MAGIC);
    out.extend_from_slice(&krbtgt.kvno.to_be_bytes());
    out.extend_from_slice(&cipher);
    Ok(out)
}

// MIT: `kdc_fast_read_cookie` (fast_util.c:545-611)
/// A cookie that does not read is empty, never a 24.
pub(crate) fn open_cookie(
    store: &dyn PrincipalRead,
    client: &PrincipalName,
    blob: &[u8],
) -> Vec<PaData> {
    if blob.len() <= 8 || !blob.starts_with(COOKIE_MAGIC) {
        return Vec::new();
    }
    let kvno = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
    let Ok(Some(krbtgt_p)) = store.fetch_krbtgt() else {
        return Vec::new();
    };
    // MIT: `get_cookie_key` (fast_util.c:506-516)
    let Ok(ke) = store.policy().find_enctype(&krbtgt_p, None, kvno) else {
        return Vec::new();
    };
    let Ok(key) = derive_cookie_key(&ke.key, client, store.realm()) else {
        return Vec::new();
    };
    let Ok(usage) = KeyUsage::new(ku::PA_FX_COOKIE) else {
        return Vec::new();
    };
    let Ok(plain) = decrypt(&key, usage, &blob[8..]) else {
        return Vec::new();
    };
    // MIT: `kdc_fast_read_cookie` (fast_util.c:604-610)
    let plain = Zeroizing::new(plain);
    let Ok(cookie) = decode::<krb5_types::fast::SecureCookie>(&plain) else {
        return Vec::new();
    };
    let now = i32::try_from(KerberosTime::now().unix_seconds()).unwrap_or(0);
    if now.saturating_sub(cookie.time) > COOKIE_LIFETIME {
        return Vec::new();
    }
    cookie.data
}

pub(crate) fn wrap_fast_rep(
    armor_key: &ProtocolKey,
    padata: Vec<PaData>,
    strengthen: Option<&ProtocolKey>,
    nonce: u32,
    finished: Option<krb5_types::fast::KrbFastFinished>,
) -> Result<PaData, Error> {
    let sk = strengthen.map(|k| EncryptionKey {
        keytype: k.etype().to_iana(),
        keyvalue: k.as_bytes().to_vec().into(),
    });
    let resp = krb5_types::fast::KrbFastResponse {
        padata,
        strengthen_key: sk,
        finished,
        nonce,
    };
    let der = encode(&resp)?;
    let usage = KeyUsage::new(ku::FAST_REP)?;
    let cipher = encrypt(armor_key, usage, &der)?;
    let armored = krb5_types::fast::KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok(PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFastRep::ArmoredData(armored))?.into(),
    })
}

// MIT: `finish_verify_padata` (kdc_preauth.c:1224-1228)
pub(crate) fn process_pkinit(
    store: &dyn PrincipalRead,
    client: &Principal,
    padata: Option<&[PaData]>,
    etype: EncryptionType,
    as_req_der: &[u8],
    body_der: &[u8],
    cname: &PrincipalName,
) -> Result<Option<(ProtocolKey, PaData, bool)>, Error> {
    let realm = store.realm();
    let Some(raw) = find_pa(padata, pa::PK_AS_REQ) else {
        return Ok(None);
    };
    let cms = match decode::<krb5_types::pkinit::PaPkAsReq>(raw) {
        Ok(req) => req.signed_auth_pack.as_ref().to_vec(),
        // MIT: `pkinit_server_verify_padata` (pkinit_srv.c:479-483)
        Err(_) => return Err(crate::asn1_text::preauth_decode_failure(raw, false)),
    };
    let kdc = store
        .pkinit()
        .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    let req_body = decode::<AsReq>(as_req_der).ok().map(|r| r.0.req_body);
    let req_cname = req_body
        .as_ref()
        .and_then(|b| b.cname.clone())
        .unwrap_or_else(|| cname.clone());
    let pack = krb5_types::pkinit::cms_signeddata_verify(
        &cms,
        &kdc.anchors,
        &kdc.pool,
        krb5_types::pkinit::CmsSigner::Client,
    )
    .map_err(|fault| cms_fault(store, kdc, cname, fault))?;
    let is_signed = pack.signer.is_some();
    if let Some(cert) = &pack.signer {
        authorize_cert(store, kdc, cert, client, &req_cname, realm)?;
    } else {
        // MIT: `pkinit_server_verify_padata` (pkinit_srv.c:508-516)
        // MIT: `process_as_req` (do_as_req.c:718-734)
        // An unsigned AuthPack must already be anonymous.
        let rewritten = decode::<KdcReqBody>(body_der)
            .is_ok_and(|b| b.kdc_options.bit(flag_bit::ANONYMOUS))
            && krb5_types::pkinit::is_anonymous_principal(cname);
        if !rewritten {
            return Err(proto_d(
                err::PREAUTH_FAILED,
                status::PREAUTH_FAILED,
                "Pkinit request not signed, but client not anonymous.",
            ));
        }
    }
    let inner = pack.e_content;
    let (ctime, _) = krb5_types::pkinit::parse_authpack_freshness(&inner).ok_or_else(|| {
        tracing::info!(
            event = krb5_log::events::KDC_PKINIT,
            component = "krb5-kdc",
            outcome = "denied",
            error = "pkinit ctime"
        );
        proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
    })?;
    // MIT: `pkinit_server_verify_padata` (plugins/preauth/pkinit/pkinit_srv.c:528-532)
    let now = i64::from(KerberosTime::now().unix_seconds());
    if (now - i64::from(ctime)).abs() > store.policy().skew {
        return Err(proto(err::SKEW, status::PREAUTH_FAILED));
    }
    let (nonce, spki) = krb5_types::pkinit::parse_authpack_maybe_dh(&inner).ok_or_else(|| {
        tracing::info!(
            event = krb5_log::events::KDC_PKINIT,
            component = "krb5-kdc",
            outcome = "denied",
            error = "AuthPack",
            inner_len = inner.len(),
            inner_tag = inner.first().copied().unwrap_or(0)
        );
        proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
    })?;
    let peer = match spki.as_deref() {
        Some(spki) => Some(server_check_dh(store, cname, spki, kdc.dh_min_bits)?),
        None if !is_signed => {
            return Err(proto_d(
                err::PREAUTH_FAILED,
                status::PREAUTH_FAILED,
                "Anonymous pkinit without DH public value not supported.",
            ));
        }
        None => None,
    };
    if let Err(e) = krb5_types::pkinit::authpack_pa_checksum_ok(&inner, body_der) {
        tracing::info!(
            event = krb5_log::events::KDC_PKINIT,
            component = "krb5-kdc",
            outcome = "denied",
            error = e
        );
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    let mut valid_freshness = false;
    if let Some(tok) = krb5_types::pkinit::parse_authpack_freshness_token(&inner) {
        check_freshness_token(store, &tok, KerberosTime::now().unix_seconds())?;
        valid_freshness = true;
    }
    if is_signed {
        check_log_freshness(store, &req_cname, realm, valid_freshness)?;
    }
    // MIT: `pkinit_server_return_padata` (plugins/preauth/pkinit/pkinit_srv.c:804-809)
    let Some(peer) = peer else {
        return Err(Error::PreauthModule {
            code: err::PREAUTH_FAILED,
            message: "Unsupported PKINIT RSA request".to_owned(),
        });
    };
    let agile = krb5_types::pkinit::authpack_wants_sha256_kdf(&inner);
    let (group, client_public) = peer;
    let kp =
        KxKey::generate(group).ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    let z = kp.shared(&client_public).ok_or_else(|| {
        proto_d(
            err::GENERIC,
            status::KDC_RETURN_PADATA,
            "Cannot allocate memory",
        )
    })?;
    let info = krb5_types::pkinit::encode_kdc_dh_key_info(kp.public(), nonce);
    let certs = kdc.own_chain().map_err(|message| Error::PreauthModule {
        code: err::PREAUTH_FAILED,
        message,
    })?;
    let wrapped_pub = krb5_types::pkinit::cms_sign_chain(
        &info,
        &kdc.identity.cert,
        &certs,
        kdc.identity.key(),
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .map_err(|_| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    let rep = krb5_types::pkinit::PaPkAsRep::DhInfo(krb5_types::pkinit::DhRepInfo {
        dh_signed_data: wrapped_pub.into(),
        server_dh_nonce: None,
    });
    let mut pa_bytes = encode(&rep)?;
    if agile {
        pa_bytes = krb5_types::pkinit::pa_pk_as_rep_with_kdf(
            &pa_bytes,
            krb5_types::pkinit::KDF_AH_SHA256_OID,
        )
        .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    }
    let reply_key = if agile {
        tracing::info!(
            event = krb5_log::events::KDC_PKINIT,
            component = "krb5-kdc",
            outcome = "ok",
            detail = "rfc8636 sha256 kdf",
        );
        let party_u = krb5_types::pkinit::encode_party_u(&req_cname, realm);
        let party_v = req_body
            .as_ref()
            .and_then(krb5_types::pkinit::encode_party_v)
            .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
        let supp =
            krb5_types::pkinit::encode_pkinit_supp_pub_info(etype.to_iana(), as_req_der, &pa_bytes);
        let other = krb5_types::pkinit::encode_rfc8636_other_info(
            krb5_types::pkinit::KDF_AH_SHA256_OID,
            &party_u,
            &party_v,
            &supp,
        );
        pkinit_kdf_agile(etype, &z, &other)?
    } else {
        octetstring2key(etype, &z)?
    };
    let pa = PaData {
        padata_type: pa::PK_AS_REP,
        padata_value: pa_bytes.into(),
    };
    Ok(Some((reply_key, pa, is_signed)))
}

// MIT: `cms_signeddata_verify` (plugins/preauth/pkinit/pkinit_crypto_openssl.c:2163-2209)
// MIT: `pkinit_create_edata` (plugins/preauth/pkinit/pkinit_srv.c:101-138)
fn cms_fault(
    store: &dyn PrincipalRead,
    kdc: &crate::pkinit::PkinitKdc,
    cname: &PrincipalName,
    fault: krb5_types::pkinit::CmsFault,
) -> Error {
    use krb5_types::pkinit::CmsFault;
    tracing::info!(
        event = krb5_log::events::KDC_PKINIT,
        component = "krb5-kdc",
        outcome = "denied",
        error = ?fault
    );
    let (code, message) = (fault.code(), fault.message());
    match fault {
        CmsFault::NoSigner | CmsFault::ContentType => {
            proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
        }
        CmsFault::Chain(_, cert) => {
            let (td, certs): (i32, Vec<&[u8]>) = if code == err::CANT_VERIFY_CERTIFICATE {
                (
                    pa::TD_TRUSTED_CERTIFIERS,
                    kdc.anchors.iter().map(Vec::as_slice).collect(),
                )
            } else {
                (
                    pa::TD_INVALID_CERTIFICATES,
                    std::iter::once(cert.as_slice())
                        .filter(|c| !c.is_empty())
                        .collect(),
                )
            };
            let e_data = (!certs.is_empty()).then(|| {
                let method = vec![PaData {
                    padata_type: td,
                    padata_value: krb5_types::pkinit::encode_td_certifiers(&certs).into(),
                }];
                encode_typed(&with_fx_cookie(store, Some(cname), method))
            });
            Error::Protocol {
                code,
                text: Some(status::PREAUTH_FAILED.to_owned()),
                e_data,
                detail: Some(message),
            }
        }
        _ => Error::PreauthModule { code, message },
    }
}

// MIT: `authorize_cert` (plugins/preauth/pkinit/pkinit_srv.c:319-388)
// MIT: `pkinit_san_authorize` (plugins/preauth/pkinit/pkinit_srv.c:1143-1168)
// MIT: `pkinit_eku_authorize` (plugins/preauth/pkinit/pkinit_srv.c:1171-1192)
// MIT: `dbmatch_authorize` (plugins/preauth/pkinit/pkinit_srv.c:1230-1258)
fn authorize_cert(
    store: &dyn PrincipalRead,
    kdc: &crate::pkinit::PkinitKdc,
    cert: &[u8],
    client: &Principal,
    req_client: &PrincipalName,
    realm: &str,
) -> Result<(), Error> {
    let denied = |code, error: &'static str| {
        tracing::info!(
            event = krb5_log::events::KDC_PKINIT,
            component = "krb5-kdc",
            outcome = "denied",
            error = error
        );
        proto(code, status::PREAUTH_FAILED)
    };
    let sans = krb5_types::pkinit::cert_sans(cert, kdc.allow_upn)
        .ok_or_else(|| denied(err::CLIENT_NAME_MISMATCH, "pkinit client san"))?;
    let mut accepted = false;
    if !sans.principals.is_empty() || !sans.upns.is_empty() {
        let named =
            |p: &PrincipalName, r: &str| match_client(store, client, req_client, realm, p, r);
        let by_san = sans.principals.iter().any(|(r, name_type, parts)| {
            named(
                &PrincipalName::new(*name_type, parts.iter().map(String::as_str)),
                r,
            )
        });
        // MIT: `verify_client_san` (plugins/preauth/pkinit/pkinit_srv.c:240-258)
        let by_upn = || {
            sans.upns.iter().any(|upn| {
                krb5_types::parse_name_ex(upn, realm, true).is_ok_and(|p| {
                    let parts = p.components.iter().map(String::as_str);
                    named(
                        &PrincipalName::new(PrincipalName::NT_ENTERPRISE, parts),
                        &p.realm,
                    )
                })
            })
        };
        if !(by_san || by_upn()) {
            return Err(denied(err::CLIENT_NAME_MISMATCH, "pkinit client san"));
        }
        accepted = true;
    }
    if kdc.require_eku {
        match krb5_types::pkinit::cert_eku(cert, false, kdc.accept_secondary_eku) {
            EkuCheck::Accepted => krb5_protocol::trace::pkinit_eku(),
            found => {
                if found == EkuCheck::NoDigitalSignature {
                    krb5_protocol::trace::pkinit_eku_no_ku();
                }
                return Err(denied(err::INCONSISTENT_KEY_PURPOSE, "pkinit client eku"));
            }
        }
    }
    if let Some((_, rule)) = client
        .string_attrs
        .iter()
        .find(|(k, _)| k == "pkinit_cert_match")
    {
        match krb5_types::pkinit::cert_match(rule, cert, &mut krb5_protocol::trace::pkinit_match) {
            Ok(true) => accepted = true,
            Ok(false) => return Err(denied(err::CERTIFICATE_MISMATCH, "pkinit_cert_match")),
            Err(e) => {
                tracing::info!(
                    event = krb5_log::events::KDC_PKINIT,
                    component = "krb5-kdc",
                    outcome = "denied",
                    error = %e
                );
                return Err(Error::PreauthModule {
                    code: err::PREAUTH_FAILED,
                    message: e.to_string(),
                });
            }
        }
    }
    if accepted {
        Ok(())
    } else {
        Err(denied(err::CLIENT_NAME_MISMATCH, "pkinit client san"))
    }
}

// MIT: `match_client` (kdc/kdc_preauth.c:477-497)
fn match_client(
    store: &dyn PrincipalRead,
    client: &Principal,
    req_client: &PrincipalName,
    req_realm: &str,
    name: &PrincipalName,
    realm: &str,
) -> bool {
    let parts = |n: &PrincipalName| -> Vec<Vec<u8>> {
        n.name_string
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .collect()
    };
    let read = |n: &PrincipalName, r: &str| -> (Vec<u8>, Vec<Vec<u8>>) {
        if n.name_type == PrincipalName::NT_ENTERPRISE
            && let Ok(p) = krb5_types::parse_name_ex(&n.unparse_no_realm(), r, false)
        {
            let comps = p.components.into_iter().map(String::into_bytes).collect();
            return (p.realm.into_bytes(), comps);
        }
        (r.as_bytes().to_vec(), parts(n))
    };
    let own = (client.realm.as_bytes().to_vec(), parts(&client.name));
    if read(name, realm) == read(req_client, req_realm)
        || (realm.as_bytes().to_vec(), parts(name)) == own
    {
        return true;
    }
    let id = crate::kdb::lookup_principal_id(name, realm);
    store
        .fetch(&id)
        .ok()
        .flatten()
        .is_some_and(|entry| (entry.realm.as_bytes().to_vec(), parts(&entry.name)) == own)
}

fn server_check_dh(
    store: &dyn PrincipalRead,
    cname: &PrincipalName,
    spki: &[u8],
    min_bits: u32,
) -> Result<(KxGroup, Vec<u8>), Error> {
    let Some((group, public)) = krb5_types::pkinit::decode_spki(spki) else {
        return Err(dh_params_not_accepted(store, cname, min_bits));
    };
    match group {
        Some(g) if g.bits() >= min_bits => {
            krb5_protocol::trace::pkinit_dh_received_group(g.desc());
            Ok((g, public))
        }
        g => {
            let desc = g.map_or("(unknown)", KxGroup::desc);
            krb5_protocol::trace::pkinit_dh_rejecting_group(desc, group_desc(min_bits));
            tracing::info!(
                event = krb5_log::events::KDC_PKINIT,
                component = "krb5-kdc",
                outcome = "denied",
                group = desc,
                min_bits
            );
            Err(dh_params_not_accepted(store, cname, min_bits))
        }
    }
}

// MIT: `check_log_freshness` (plugins/preauth/pkinit/pkinit_srv.c:392-412)
fn check_log_freshness(
    store: &dyn PrincipalRead,
    req_client: &PrincipalName,
    realm: &str,
    valid: bool,
) -> Result<(), Error> {
    let name = req_client.unparse_with_realm(realm);
    if store.policy().pkinit_require_freshness && !valid {
        klog::syslog(
            Severity::Info,
            &format!("PKINIT: no freshness token, rejecting auth from {name}"),
        );
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    let what = if valid {
        "freshness token received"
    } else {
        "no freshness token received"
    };
    klog::syslog(Severity::Info, &format!("PKINIT: {what} from {name}"));
    Ok(())
}

pub(crate) fn find_pa(padata: Option<&[PaData]>, ty: i32) -> Option<&[u8]> {
    padata?.iter().find_map(|p| {
        if p.padata_type == ty {
            Some(p.padata_value.as_ref())
        } else {
            None
        }
    })
}

pub(crate) fn proto(code: i32, status: &'static str) -> Error {
    Error::Protocol {
        code,
        text: Some(status.to_owned()),
        e_data: None,
        detail: None,
    }
}

pub(crate) fn proto_d(code: i32, status: &'static str, detail: impl Into<String>) -> Error {
    Error::Protocol {
        code,
        text: Some(status.to_owned()),
        e_data: None,
        detail: Some(detail.into()),
    }
}

pub(crate) fn proto_fast(code: i32, detail: impl Into<String>) -> Error {
    Error::Protocol {
        code,
        text: Some(crate::status::FIND_FAST.to_owned()),
        e_data: None,
        detail: Some(detail.into()),
    }
}

// MIT: `process_as_req` (do_as_req.c:531-535)
// MIT: `errcode_to_protocol` (kdc_util.c:691-698)
/// A FAST decrypt failure is 31; an ASN.1 failure is 60.
fn map_fast_unwrap(err: Error) -> Error {
    match err {
        Error::Crypto(d) => proto_fast(err::BAD_INTEGRITY, d),
        Error::Asn1(d) => proto_fast(err::GENERIC, d),
        p @ Error::Protocol { .. } => p,
        other => proto_fast(err::GENERIC, other.to_string()),
    }
}

fn dh_params_not_accepted(
    store: &dyn PrincipalRead,
    client: &PrincipalName,
    min_bits: u32,
) -> Error {
    let mut method: MethodData = vec![PaData {
        padata_type: pa::TD_DH_PARAMETERS,
        padata_value: krb5_types::pkinit::encode_td_dh_parameters(min_bits).into(),
    }];
    method = with_fx_cookie(store, Some(client), method);
    proto_e(
        err::DH_KEY_PARAMETERS_NOT_ACCEPTED,
        crate::status::PREAUTH_FAILED,
        encode_typed(&method),
    )
}

pub(crate) fn encode_typed(method: &MethodData) -> Vec<u8> {
    let td: TypedDataList = method
        .iter()
        .map(|p| TypedData {
            data_type: p.padata_type,
            data_value: p.padata_value.clone(),
        })
        .collect();
    encode(&td).unwrap_or_default()
}

pub(crate) fn decode_edata_padata(ed: &[u8]) -> MethodData {
    if let Ok(m) = decode::<MethodData>(ed)
        && !m.is_empty()
    {
        return m;
    }
    decode::<TypedDataList>(ed)
        .unwrap_or_default()
        .into_iter()
        .map(|t| PaData {
            padata_type: t.data_type,
            padata_value: t.data_value,
        })
        .collect()
}

pub(crate) fn pa_cookie_last(mut method: MethodData) -> MethodData {
    if let Some(i) = method.iter().position(|p| p.padata_type == pa::FX_COOKIE) {
        let c = method.remove(i);
        method.push(c);
    }
    method
}

pub(crate) fn with_fx_cookie(
    store: &dyn PrincipalRead,
    client: Option<&PrincipalName>,
    mut method: MethodData,
) -> MethodData {
    if method.iter().any(|p| p.padata_type == pa::FX_COOKIE) {
        return method;
    }
    let Some(c) = client else {
        return method;
    };
    if let Ok(cookie) = make_cookie(store, c, &[]) {
        method.push(PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        });
    }
    method
}

// MIT: `prepare_error_as` (do_as_req.c:785-814)
pub(crate) fn prepare_as_edata(
    store: &dyn PrincipalRead,
    client: Option<&PrincipalName>,
    ed: &[u8],
) -> Vec<u8> {
    if let Ok(m) = decode::<MethodData>(ed) {
        if m.len() == 1 && m.first().is_some_and(|p| p.padata_type == pa::FX_FAST) {
            return ed.to_vec();
        }
        if m.is_empty() {
            return ed.to_vec();
        }
        return encode(&with_fx_cookie(store, client, m)).unwrap_or_else(|_| ed.to_vec());
    }
    if let Ok(t) = decode::<TypedDataList>(ed) {
        let method: MethodData = t
            .into_iter()
            .map(|e| PaData {
                padata_type: e.data_type,
                padata_value: e.data_value,
            })
            .collect();
        let n = method.len();
        let method = with_fx_cookie(store, client, method);
        if method.len() == n {
            return ed.to_vec();
        }
        return encode_typed(&method);
    }
    ed.to_vec()
}

pub(crate) fn proto_e(code: i32, status: &'static str, e_data: Vec<u8>) -> Error {
    Error::Protocol {
        code,
        text: Some(status.to_owned()),
        e_data: Some(e_data),
        detail: None,
    }
}

pub(crate) fn fast_finished(
    armor_key: &ProtocolKey,
    ticket: &krb5_types::Ticket,
    cname: &PrincipalName,
    crealm: &str,
) -> Result<krb5_types::fast::KrbFastFinished, Error> {
    let tder = encode(ticket)?;
    let usage = KeyUsage::new(ku::FAST_FINISHED)?;
    let mic = checksum(armor_key, usage, &tder)?;
    Ok(krb5_types::fast::KrbFastFinished {
        timestamp: KerberosTime::now(),
        usec: Microseconds::ZERO,
        crealm: krb5_types::try_ascii(crealm)
            .map_err(|_| proto(err::GENERIC, status::UNKNOWN_REASON))?,
        cname: cname.clone(),
        ticket_checksum: krb5_types::Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
    })
}
