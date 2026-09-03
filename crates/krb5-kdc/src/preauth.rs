//! FAST, SPAKE, and PKINIT processing on the KDC.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, SPAKE_GROUP_P256, checksum, cksumtype_is_keyed,
    cksumtype_is_unkeyed, decrypt, dh_generate, dh_group_for_prime, dh_shared, encrypt, krb_fx_cf2,
    octetstring2key, p256_generate, p256_shared, pkinit_kdf_agile, spake_derive_key,
    spake_kdc_keygen, spake_result_wbytes, spake_thash_update, spake_wbytes, verify_checksum_type,
};
use krb5_protocol::{ReplayCache, ReplayKey};
use krb5_types::{
    AsReq, EncryptedData, EncryptionKey, KerberosTime, MethodData, Microseconds, PaData,
    PrincipalName, err, ku, pa,
};

use crate::error::Error;
use crate::kdb::{PrincipalRead, lookup_principal_id};
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
    let Some(raw) = find_pa(padata, pa::FX_FAST) else {
        return Ok(None);
    };
    let armored = match decode::<krb5_types::fast::PaFxFast>(raw) {
        Ok(krb5_types::fast::PaFxFast::ArmoredData(w)) => w,
        _ => decode::<krb5_types::fast::KrbFastArmoredReq>(raw)?,
    };
    let armor_key = armor_key_from(store, &armored)?;
    verify_fast_req_checksum(&armor_key, body_der, &armored.req_checksum)?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let plain = decrypt(&armor_key, enc_usage, armored.enc_fast_req.cipher.as_ref())?;
    let inner: krb5_types::fast::KrbFastReq = decode(&plain)?;
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

/// MIT `kdc_find_fast` for TGS: armor from the PA-TGS-REQ decrypt, not a
/// second ticket unwrap. Explicit AP-REQ armor is PREAUTH_FAILED.
pub(crate) fn unwrap_fast_tgs(
    padata: Option<&[PaData]>,
    pa_tgs_raw: &[u8],
    subkey: Option<&EncryptionKey>,
    session: &ProtocolKey,
) -> Result<Option<FastOk>, Error> {
    let Some(raw) = find_pa(padata, pa::FX_FAST) else {
        return Ok(None);
    };
    let armored = match decode::<krb5_types::fast::PaFxFast>(raw) {
        Ok(krb5_types::fast::PaFxFast::ArmoredData(w)) => w,
        _ => decode::<krb5_types::fast::KrbFastArmoredReq>(raw)?,
    };
    if armored.armor.is_some() {
        return Err(proto_fast(
            err::PREAUTH_FAILED,
            "Ap-request armor not permitted with TGS",
        ));
    }
    let Some(sub) = subkey else {
        return Err(proto_fast(
            err::PREAUTH_FAILED,
            "No armor key but FAST armored request present",
        ));
    };
    let st =
        EncryptionType::from_iana(sub.keytype).or_else(|_| EncryptionType::known(sub.keytype))?;
    let subk = ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?;
    let armor_key = krb_fx_cf2(&subk, session, b"subkeyarmor", b"ticketarmor")?;
    verify_fast_req_checksum(&armor_key, pa_tgs_raw, &armored.req_checksum)?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let plain = decrypt(&armor_key, enc_usage, armored.enc_fast_req.cipher.as_ref())?;
    let inner: krb5_types::fast::KrbFastReq = decode(&plain)?;
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
    if !cksumtype_is_keyed(ck.cksumtype) && !cksumtype_is_unkeyed(ck.cksumtype) {
        return Err(proto_fast(err::GENERIC, "unknown checksum type"));
    }
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    match verify_checksum_type(
        armor_key,
        ck_usage,
        ck_data,
        ck.cksumtype,
        ck.checksum.as_ref(),
    ) {
        Ok(()) => {}
        Err(krb5_crypto::Error::UnsupportedChecksum(_)) => {
            return Err(proto_fast(err::GENERIC, "unknown checksum type"));
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

fn armor_key_from(
    store: &dyn PrincipalRead,
    armored: &krb5_types::fast::KrbFastArmoredReq,
) -> Result<ProtocolKey, Error> {
    let Some(armor) = armored.armor.as_ref() else {
        return Err(proto_fast(err::PREAUTH_FAILED, "FAST armor required"));
    };
    if armor.armor_type != krb5_types::fast::ARMOR_AP_REQUEST {
        return Err(proto_fast(
            err::PREAUTH_FAILED,
            format!("Unknown FAST armor type {}", armor.armor_type),
        ));
    }
    armor_key_from_ap(store, armor.armor_value.as_ref())
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
    if !ap.ticket.sname.is_krbtgt_for(store.realm()) {
        return Err(proto_fast(err::SERVER_NOMATCH, "FAST armor TGT"));
    }
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
    if i64::from(enc_tkt.endtime.unix_seconds()) < now {
        return Err(proto_fast(err::TKT_EXPIRED, "FAST armor expired"));
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
    if let Some(sub) = authenticator.subkey {
        let st = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        let subk = ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?;
        return krb_fx_cf2(&subk, &session, b"subkeyarmor", b"ticketarmor").map_err(Error::from);
    }
    Ok(session)
}

/// Encrypt a FAST cookie (client id + SPAKE secret or empty).
pub(crate) fn make_cookie(store: &dyn PrincipalRead, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let krbtgt = krbtgt_p
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let usage = KeyUsage::new(ku::FAST_COOKIE)?;
    encrypt(&krbtgt.key, usage, payload).map_err(Error::from)
}

pub(crate) fn open_cookie(store: &dyn PrincipalRead, blob: &[u8]) -> Result<Vec<u8>, Error> {
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let krbtgt = krbtgt_p
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let usage = KeyUsage::new(ku::FAST_COOKIE)?;
    decrypt(&krbtgt.key, usage, blob).map_err(|_| proto(err::PREAUTH_FAILED, "bad cookie"))
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
    _client: &Principal,
    padata: Option<&[PaData]>,
    ikey: &ProtocolKey,
    body_der: &[u8],
) -> Result<Option<SpakeStep>, Error> {
    let Some(raw) = find_pa(padata, pa::SPAKE) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return send_spake_challenge(store, ikey, &[]);
    }
    let msg: krb5_types::spake::PaSpake = decode(raw)?;
    if let krb5_types::spake::PaSpake::Response(resp) = &msg {
        let cookie = find_pa(padata, pa::FX_COOKIE)
            .ok_or_else(|| proto(err::PREAUTH_FAILED, "SPAKE cookie"))?;
        let secret = open_cookie(store, cookie)?;
        if secret.len() != 64 {
            return Err(proto(err::PREAUTH_FAILED, "SPAKE cookie"));
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
            .map_err(|_| proto(err::PREAUTH_FAILED, "SPAKE factor"))?;
        let factor = decode::<krb5_types::spake::SpakeSecondFactor>(&factor_der)
            .map_err(|_| proto(err::PREAUTH_FAILED, "SPAKE factor der"))?;
        if factor.factor_type != 1 {
            return Err(proto(err::PREAUTH_FAILED, "SPAKE factor type"));
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
    if matches!(msg, krb5_types::spake::PaSpake::Support(_)) {
        return send_spake_challenge(store, ikey, raw);
    }
    Ok(None)
}

fn send_spake_challenge(
    store: &dyn PrincipalRead,
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
    let cookie = make_cookie(store, &cookie_pt)?;
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
            .ok_or_else(|| proto(err::PREAUTH_FAILED, "PKINIT PA-PK-AS-REQ"))?,
    };
    let ca = store
        .pkinit_ca()
        .ok_or_else(|| proto(err::PREAUTH_FAILED, "PKINIT not configured"))?;
    let verified = krb5_types::pkinit::cms_verify_full(&cms, &ca.ca_cert).map_err(|e| {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = e,
            cms_len = cms.len()
        );
        proto(err::PREAUTH_FAILED, "PKINIT CMS")
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
        return Err(proto(err::PREAUTH_FAILED, "PKINIT eContentType"));
    }
    if let Err(e) = krb5_types::pkinit::require_client_pkinit_cert(&verified.cert, cname, realm) {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = e
        );
        return Err(proto(err::PREAUTH_FAILED, "PKINIT client cert"));
    }
    let inner = verified.e_content;
    if let Err(e) = krb5_types::pkinit::authpack_pa_checksum_ok(&inner, body_der) {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = e
        );
        return Err(proto(err::PREAUTH_FAILED, "PKINIT paChecksum"));
    }
    let (ctime, cusec) = krb5_types::pkinit::parse_authpack_freshness(&inner).ok_or_else(|| {
        tracing::error!(
            event = "kdc.pkinit",
            component = "krb5-kdc",
            outcome = "error",
            error = "pkinit ctime"
        );
        proto(err::PREAUTH_FAILED, "PKINIT AuthPack time")
    })?;
    let now = i64::from(KerberosTime::now().unix_seconds());
    if (now - i64::from(ctime)).abs() > store.policy().skew {
        return Err(proto(err::SKEW, "PKINIT ctime"));
    }
    let rkey = ReplayKey {
        client: lookup_principal_id(cname, realm),
        server: format!("krbtgt/{realm}@{realm}"),
        ctime,
        cusec,
        auth_hash: ReplayCache::hash_authenticator(&cms),
    };
    if store.pa_replay().check_and_store(rkey) {
        return Err(proto(err::PREAUTH_FAILED, "PKINIT replay"));
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
        proto(err::PREAUTH_FAILED, "PKINIT AuthPack")
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
            dh_params_not_accepted()
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
            .map_err(|_| proto(err::DH_KEY_PARAMETERS_NOT_ACCEPTED, "PKINIT DH peer"))?;
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
        return Err(dh_params_not_accepted());
    };
    let wrapped_pub = ca
        .sign_cms_typed(&info, "krbtgt", krb5_types::pkinit::ECONTENT_DHKEY, realm)
        .ok_or_else(|| proto(err::PREAUTH_FAILED, "PKINIT CMS wrap"))?;
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
        .ok_or_else(|| proto(err::PREAUTH_FAILED, "PKINIT kdf encode"))?;
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

pub(crate) fn proto(code: i32, text: &str) -> Error {
    Error::Protocol {
        code,
        text: Some(text.to_owned()),
        e_data: None,
        detail: None,
    }
}

pub(crate) fn proto_fast(code: i32, detail: impl Into<String>) -> Error {
    Error::Protocol {
        code,
        text: Some("FIND_FAST".into()),
        e_data: None,
        detail: Some(detail.into()),
    }
}

fn dh_params_not_accepted() -> Error {
    let method: MethodData = vec![PaData {
        padata_type: pa::TD_DH_PARAMETERS,
        padata_value: krb5_types::pkinit::encode_td_dh_p256().into(),
    }];
    proto_e(
        err::DH_KEY_PARAMETERS_NOT_ACCEPTED,
        "PKINIT SPKI",
        encode(&method).unwrap_or_default(),
    )
}

pub(crate) fn proto_e(code: i32, text: &str, e_data: Vec<u8>) -> Error {
    Error::Protocol {
        code,
        text: Some(text.to_owned()),
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
            .map_err(|_| proto(err::GENERIC, "non-ascii realm"))?,
        cname: cname.clone(),
        ticket_checksum: krb5_types::Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
    })
}
