//! FAST, SPAKE, and PKINIT processing on the KDC.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, SPAKE_GROUP_P256, checksum, cksumtype_is_keyed, decrypt,
    derive_prfplus, dh_generate, dh_group_for_prime, dh_shared, encrypt, krb_fx_cf2,
    octetstring2key, p256_generate, p256_shared, pkinit_kdf_agile, spake_derive_key,
    spake_kdc_keygen, spake_result_wbytes, spake_thash_update, spake_wbytes, verify_checksum_type,
};
use krb5_protocol::{ReplayCache, ReplayKey};
use krb5_types::{
    AsReq, EncryptedData, EncryptionKey, KerberosTime, MethodData, Microseconds, PaData,
    PrincipalName, TypedData, TypedDataList, err, ku, pa,
};

use crate::error::Error;
use crate::kdb::{PrincipalRead, lookup_principal_id};
use crate::status;
use crate::store::Principal;

pub(crate) struct FastOk {
    pub armor_key: ProtocolKey,
    pub inner_padata: Vec<PaData>,
    pub inner_body: Vec<u8>,
    pub nonce: u32,
    pub fast_options: krb5_types::fast::FastOptions,
}

/// Unwrap PA-FX-FAST from an AS-REQ. `body_der` is the wire KDC-REQ-BODY.
pub(crate) fn unwrap_fast(
    store: &dyn PrincipalRead,
    req: &AsReq,
    body_der: &[u8],
) -> Result<Option<FastOk>, Error> {
    unwrap_fast_as(store, req.0.padata.as_deref(), body_der)
}

/// Unwrap PA-FX-FAST from AS padata. Checksum is the outer KDC-REQ-BODY only.
pub(crate) fn unwrap_fast_as(
    store: &dyn PrincipalRead,
    padata: Option<&[PaData]>,
    body_der: &[u8],
) -> Result<Option<FastOk>, Error> {
    kdc_find_fast(store, padata, body_der, None, None).map_err(map_fast_unwrap)
}

/// MIT `kdc_find_fast` for TGS: armor from the PA-TGS-REQ subkey, or
/// `armor_ap_request` when explicit AP-REQ armor is present without that subkey.
pub(crate) fn unwrap_fast_tgs(
    store: &dyn PrincipalRead,
    padata: Option<&[PaData]>,
    pa_tgs_raw: &[u8],
    subkey: Option<&EncryptionKey>,
    session: &ProtocolKey,
) -> Result<Option<FastOk>, Error> {
    kdc_find_fast(store, padata, pa_tgs_raw, subkey, Some(session)).map_err(map_fast_unwrap)
}

/// MIT `kdc_find_fast` (`fast_util.c:126-247`). Inner `msg_type` is the outer
/// APPLICATION tag in Rust (AS vs TGS dispatch already happened).
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
    let plain = decrypt(&armor_key, enc_usage, armored.enc_fast_req.cipher.as_ref())?;
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

fn take_der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (hlen, ln) = if first < 128 {
        (1usize, usize::from(first))
    } else if first == 0x81 && input.len() >= 3 {
        (2, usize::from(input[2]))
    } else if first == 0x82 && input.len() >= 4 {
        (3, usize::from(u16::from_be_bytes([input[2], input[3]])))
    } else {
        return None;
    };
    let start = 1 + hlen;
    let end = start.checked_add(ln)?;
    let inner = input.get(start..end)?;
    let rest = input.get(end..)?;
    Some((tag, inner, rest))
}

fn verify_fast_req_checksum(
    armor_key: &ProtocolKey,
    ck_data: &[u8],
    ck: &krb5_types::Checksum,
) -> Result<(), Error> {
    // MIT krb5_c_verify_checksum then krb5_c_is_keyed_cksum (fast_util.c:207-224).
    // Type 0 is not in the keyed/unkeyed tables; verify_checksum_type substitutes
    // the key's mandatory type, then is_keyed(0) is false → 12.
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
    if !cksumtype_is_keyed(ck.cksumtype) {
        return Err(proto_fast(err::POLICY, "Unkeyed checksum used in fast_req"));
    }
    Ok(())
}

fn armor_key_from_ap(store: &dyn PrincipalRead, ap_raw: &[u8]) -> Result<ProtocolKey, Error> {
    let ap: krb5_types::ApReq = decode(ap_raw)?;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let cipher = ap.ticket.enc_part.cipher.as_ref();
    let ticket_realm = std::str::from_utf8(ap.ticket.realm.as_bytes())
        .map_err(|_| proto_fast(err::NOT_US, "FAST armor TGT"))?;
    // MIT rd_req: unknown server (foreign realm or missing row) is NOT_US;
    // a local non-krbtgt armor ticket is SERVER_NOMATCH.
    if ticket_realm != store.realm() {
        return Err(proto_fast(err::NOT_US, "FAST armor TGT"));
    }
    let Some(p) = store.fetch_name(&ap.ticket.sname)? else {
        return Err(proto_fast(err::NOT_US, "FAST armor TGT"));
    };
    let mut enc_tkt: Option<krb5_types::EncTicketPart> = None;
    for k in &p.keys {
        if let Ok(plain) = decrypt(&k.key, tkt_usage, cipher)
            && let Ok(part) = decode::<krb5_types::EncTicketPart>(&plain)
        {
            enc_tkt = Some(part);
            break;
        }
    }
    let enc_tkt = enc_tkt.ok_or_else(|| proto_fast(err::BAD_INTEGRITY, "FAST armor TGT"))?;
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
    // MIT armor_ap_request: 26 only after rd_req decrypts (`fast_util.c:51-68`).
    if !ap.ticket.sname.is_krbtgt_for(store.realm()) {
        return Err(proto_fast(err::SERVER_NOMATCH, "FAST armor TGT"));
    }
    let etype = EncryptionType::from_iana(enc_tkt.key.keytype)
        .or_else(|_| EncryptionType::known(enc_tkt.key.keytype))?;
    let session = ProtocolKey::from_bytes(etype, enc_tkt.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: krb5_types::Authenticator = decode(&auth_plain)?;
    let then = i64::from(authenticator.ctime.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto_fast(err::SKEW, "FAST armor authenticator"));
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

/// MIT `kdc_fast_make_cookie` (`fast_util.c:655-721`). Empty contents → `MIT`.
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
    // MIT kdc_fast_make_cookie: empty contents or no TGT key → 3-byte MIT (`:673-676`).
    if contents.is_empty() {
        return Ok(b"MIT".to_vec());
    }
    let Ok(Some(krbtgt_p)) = store.fetch_krbtgt() else {
        return Ok(b"MIT".to_vec());
    };
    let Some(krbtgt) = krbtgt_p.first_current_key() else {
        return Ok(b"MIT".to_vec());
    };
    let key = derive_cookie_key(&krbtgt.key, client, store.realm())?;
    let der = encode(&krb5_types::fast::SecureCookie {
        time,
        data: contents.to_vec(),
    })?;
    let usage = KeyUsage::new(ku::PA_FX_COOKIE)?;
    let cipher = encrypt(&key, usage, &der)?;
    let mut out = Vec::with_capacity(8 + cipher.len());
    out.extend_from_slice(COOKIE_MAGIC);
    out.extend_from_slice(&krbtgt.kvno.to_be_bytes());
    out.extend_from_slice(&cipher);
    Ok(out)
}

/// MIT `kdc_fast_read_cookie` (`fast_util.c:545-611`): errors leave the
/// state empty and return 0 (never 24).
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
    let current = krbtgt_p.first_current_key();
    let ke = if current.is_some_and(|k| k.kvno == kvno) {
        current
    } else {
        krbtgt_p.first_key_at_kvno(kvno)
    };
    let Some(ke) = ke else {
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
    let Ok(cookie) = decode::<krb5_types::fast::SecureCookie>(&plain) else {
        return Vec::new();
    };
    let now = i32::try_from(KerberosTime::now().unix_seconds()).unwrap_or(0);
    if now.saturating_sub(cookie.time) > COOKIE_LIFETIME {
        return Vec::new();
    }
    cookie.data
}

/// Wrap KrbFastResponse into PA-FX-FAST padata.
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

/// SPAKE: support → challenge; response → shared key.
pub(crate) enum SpakeStep {
    /// Need a challenge (PREAUTH_REQUIRED).
    Challenge(Vec<u8>),
    /// Finished; key encrypts AS-REP.
    Done(ProtocolKey),
}

pub(crate) fn process_spake(
    store: &dyn PrincipalRead,
    client: &Principal,
    padata: Option<&[PaData]>,
    ikey: &ProtocolKey,
    body_der: &[u8],
) -> Result<Option<SpakeStep>, Error> {
    let Some(raw) = find_pa(padata, pa::SPAKE) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    let msg: krb5_types::spake::PaSpake = decode(raw)?;
    if let krb5_types::spake::PaSpake::Response(resp) = &msg {
        let cookie = find_pa(padata, pa::FX_COOKIE)
            .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
        let inner = open_cookie(store, &client.name, cookie);
        let secret = inner
            .iter()
            .find(|p| p.padata_type == pa::SPAKE)
            .map(|p| p.padata_value.as_ref())
            .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
        if secret.len() != 64 {
            return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&secret[..32]);
        let mut thash = [0u8; 32];
        thash.copy_from_slice(&secret[32..]);
        let wbytes = spake_wbytes(ikey, SPAKE_GROUP_P256)?;
        let result = spake_result_wbytes(&wbytes, &sec, resp.pubkey.as_ref(), true)?;
        let thash = spake_thash_update(&thash, resp.pubkey.as_ref(), &[]);
        let k1 = spake_derive_key(
            ikey,
            SPAKE_GROUP_P256,
            &wbytes,
            &result,
            &thash,
            body_der,
            1,
        )?;
        let usage = KeyUsage::new(ku::SPAKE)?;
        let factor_der = decrypt(&k1, usage, resp.factor.cipher.as_ref())
            .map_err(|_| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
        let factor = decode::<krb5_types::spake::SpakeSecondFactor>(&factor_der)
            .map_err(|_| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
        if factor.factor_type != 1 {
            return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
        }
        let k0 = spake_derive_key(
            ikey,
            SPAKE_GROUP_P256,
            &wbytes,
            &result,
            &thash,
            body_der,
            0,
        )?;
        return Ok(Some(SpakeStep::Done(k0)));
    }
    if let krb5_types::spake::PaSpake::Support(sup) = &msg {
        let group = sup
            .groups
            .iter()
            .copied()
            .find(|g| store.policy().spake_preauth_groups.contains(g));
        if group != Some(krb5_types::spake::GROUP_P256) {
            return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
        }
        return send_spake_challenge(store, &client.name, ikey, raw);
    }
    Ok(None)
}

fn send_spake_challenge(
    store: &dyn PrincipalRead,
    client: &PrincipalName,
    ikey: &ProtocolKey,
    support_der: &[u8],
) -> Result<Option<SpakeStep>, Error> {
    let wbytes = spake_wbytes(ikey, SPAKE_GROUP_P256)?;
    let (secret, pub_y) = spake_kdc_keygen(&wbytes)?;
    let challenge = krb5_types::spake::PaSpake::Challenge(krb5_types::spake::SpakeChallenge {
        group: krb5_types::spake::GROUP_P256,
        pubkey: pub_y.into(),
        factors: vec![krb5_types::spake::SpakeSecondFactor {
            factor_type: 1,
            data: None,
        }],
    });
    let chal_der = encode(&challenge)?;
    let z = [0u8; 32];
    let thash = spake_thash_update(&z, support_der, &chal_der);
    let mut cookie_pt = Vec::with_capacity(64);
    cookie_pt.extend_from_slice(&secret);
    cookie_pt.extend_from_slice(&thash);
    let cookie = make_cookie(
        store,
        client,
        &[PaData {
            padata_type: pa::SPAKE,
            padata_value: cookie_pt.into(),
        }],
    )?;
    let method: MethodData = vec![
        PaData {
            padata_type: pa::SPAKE,
            padata_value: chal_der.into(),
        },
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.into(),
        },
    ];
    Ok(Some(SpakeStep::Challenge(encode(&method)?)))
}

/// PKINIT: ECDH reply key from PA-PK-AS-REQ.
pub(crate) fn process_pkinit(
    store: &dyn PrincipalRead,
    padata: Option<&[PaData]>,
    etype: EncryptionType,
    as_req_der: &[u8],
    body_der: &[u8],
    cname: &PrincipalName,
    realm: &str,
) -> Result<Option<(ProtocolKey, PaData)>, Error> {
    let Some(raw) = find_pa(padata, pa::PK_AS_REQ) else {
        return Ok(None);
    };
    let cms = match decode::<krb5_types::pkinit::PaPkAsReq>(raw) {
        Ok(req) => req.signed_auth_pack.as_ref().to_vec(),
        Err(_) => krb5_types::pkinit::parse_pa_pk_as_req_cms(raw)
            .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?,
    };
    let ca = store
        .pkinit_ca()
        .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    let verified = krb5_types::pkinit::cms_verify_full(&cms, &ca.ca_cert).map_err(|e| {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = e,
            cms_len = cms.len()
        );
        proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
    })?;
    let req_cname = decode::<AsReq>(as_req_der)
        .ok()
        .and_then(|r| r.0.req_body.cname)
        .unwrap_or_else(|| cname.clone());
    if verified.e_content_type.as_slice() != krb5_types::pkinit::ECONTENT_AUTHDATA {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = "pkinit eContentType"
        );
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    if let Err(e) = krb5_types::pkinit::require_client_pkinit_cert(&verified.cert, cname, realm) {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = e
        );
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    let inner = verified.e_content;
    if let Err(e) = krb5_types::pkinit::authpack_pa_checksum_ok(&inner, body_der) {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = e
        );
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    let (ctime, cusec) = krb5_types::pkinit::parse_authpack_freshness(&inner).ok_or_else(|| {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = "pkinit ctime"
        );
        proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
    })?;
    let now = i64::from(KerberosTime::now().unix_seconds());
    if (now - i64::from(ctime)).abs() > store.policy().skew {
        return Err(proto(err::SKEW, status::PREAUTH_FAILED));
    }
    let rkey = ReplayKey {
        client: lookup_principal_id(cname, realm),
        server: format!("krbtgt/{realm}@{realm}"),
        ctime,
        cusec,
        auth_hash: ReplayCache::hash_authenticator(&cms),
    };
    if store.pa_replay().check_and_store(rkey) {
        return Err(proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED));
    }
    let (nonce, spki) = krb5_types::pkinit::parse_authpack(&inner).ok_or_else(|| {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = "AuthPack",
            inner_len = inner.len(),
            inner_tag = inner.first().copied().unwrap_or(0)
        );
        proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED)
    })?;
    let agile = krb5_types::pkinit::authpack_wants_sha256_kdf(&inner);
    let (z, info) = if let Some(peer) = krb5_types::pkinit::decode_ec_spki(&spki) {
        let kp = p256_generate()?;
        let shared = p256_shared(&kp.secret, &peer)?;
        let info = krb5_types::pkinit::encode_kdc_dh_key_info(&kp.public, nonce);
        (shared.to_vec(), info)
    } else if let Some((p, y)) = krb5_types::pkinit::parse_dh_spki(&spki) {
        let group = dh_group_for_prime(&p).ok_or_else(|| {
            tracing::error!(
                event = "kdc.pkinit",
                component = "krb5-kdc",
                outcome = "error",
                error = "unknown DH prime",
                p_len = p.len()
            );
            dh_params_not_accepted(store, cname)
        })?;
        tracing::info!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "ok",
            group = group.name,
            bits = group.bits
        );
        let kp = dh_generate(group)?;
        let shared = dh_shared(group, &kp.secret, &y)
            .map_err(|_| proto(err::DH_KEY_PARAMETERS_NOT_ACCEPTED, status::PREAUTH_FAILED))?;
        let z = pad_z(&shared, p.len());
        let info = krb5_types::pkinit::encode_kdc_dh_key_info(&kp.public_der, nonce);
        (z, info)
    } else {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = "SPKI",
            spki_len = spki.len(),
            spki_tag = spki.first().copied().unwrap_or(0)
        );
        return Err(dh_params_not_accepted(store, cname));
    };
    let wrapped_pub = ca
        .sign_cms_typed(&info, "krbtgt", krb5_types::pkinit::ECONTENT_DHKEY, realm)
        .ok_or_else(|| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
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
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "ok",
            detail = "rfc8636 sha256 kdf",
        );
        let parts: Vec<String> = req_cname
            .name_string
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
            .collect();
        let prefs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let party_u =
            krb5_types::pkinit::encode_krb5_principal_name(realm, req_cname.name_type, &prefs);
        let party_v = krb5_types::pkinit::encode_krb5_principal_name(
            realm,
            PrincipalName::NT_SRV_INST,
            &["krbtgt", realm],
        );
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
    Ok(Some((reply_key, pa)))
}

fn pad_z(shared: &[u8], modulus_len: usize) -> Vec<u8> {
    if shared.len() >= modulus_len {
        return shared.to_vec();
    }
    let mut z = vec![0u8; modulus_len];
    z[modulus_len - shared.len()..].copy_from_slice(shared);
    z
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

// MIT do_as_req.c:531-535 / kdc_util.c:691-698: any kdc_find_fast failure
// is status FIND_FAST; decrypt → 31, ASN.1 → 60.
fn map_fast_unwrap(err: Error) -> Error {
    match err {
        Error::Crypto(d) => proto_fast(err::BAD_INTEGRITY, d),
        Error::Asn1(d) => proto_fast(err::GENERIC, d),
        p @ Error::Protocol { .. } => p,
        other => proto_fast(err::GENERIC, other.to_string()),
    }
}

fn dh_params_not_accepted(store: &dyn PrincipalRead, client: &PrincipalName) -> Error {
    let mut method: MethodData = vec![PaData {
        padata_type: pa::TD_DH_PARAMETERS,
        padata_value: krb5_types::pkinit::encode_td_dh_p256().into(),
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

/// MIT `prepare_error_as` (`do_as_req.c:785-814`): append PA-FX-COOKIE to every
/// e_data-bearing AS error, then encode TYPED-DATA when the bytes already use
/// tags [0]/[1] (PA_TYPED_E_DATA modules). FAST-wrapped outer e_data is left
/// alone (`kdc_fast_handle_error` already replaced it).
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

/// FAST finished checksum of the ticket DER.
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
