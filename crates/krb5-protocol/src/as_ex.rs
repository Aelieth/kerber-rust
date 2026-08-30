//! AS-REQ / AS-REP with PA-ENC-TIMESTAMP, SPAKE, FAST, or PKINIT.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, p256_generate, string_to_key,
};
use krb5_types::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncryptedData, EtypeInfo, EtypeInfo2, KdcOptions,
    KdcReq, KdcReqBody, KerberosTime, KrbError, MethodData, PaData, PaEncTsEnc, PrincipalName, err,
    flag_bit, ku, pa,
};
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::error::Error;
use crate::preauth::{
    apply_strengthen, armor_key, attach_fast, build_fast_armor, pa_pk_as_req_signed,
    pa_spake_response, pa_spake_support, pkinit_reply_key_agile, unwrap_fast_rep,
};
use crate::transport::{KdcAddr, exchange};

/// Successful AS exchange: TGT plus session key.
#[derive(Clone, Debug)]
pub struct AsOutcome {
    /// AS-REP ticket (TGT).
    pub ticket: krb5_types::Ticket,
    /// Decrypted EncKDCRepPart.
    pub enc_part: EncKdcRepPart,
    /// Client long-term key used to unwrap the AS-REP.
    pub client_key: ProtocolKey,
    /// TGS session key.
    pub session_key: ProtocolKey,
    /// Client principal as returned by the KDC.
    pub cname: PrincipalName,
    /// Client realm as returned by the KDC.
    pub crealm: krb5_types::Realm,
}

/// Parameters for an AS-REQ.
pub struct AsRequest<'a> {
    /// Client name (without realm).
    pub cname: PrincipalName,
    /// Realm.
    pub realm: &'a str,
    /// Password octets (UTF-8).
    pub password: &'a [u8],
    /// KDC address.
    pub kdc: &'a KdcAddr,
    /// Use PA-SPAKE (151, P-256) instead of PA-ENC-TIMESTAMP.
    pub want_spake: bool,
    /// FAST armor (PA-FX-FAST). Inner preauth is still enc-timestamp.
    pub fast_armor: Option<&'a FastArmor>,
    /// PKINIT client identity (PA-PK-AS-REQ). Sent on the first AS-REQ.
    pub pkinit: Option<&'a PkinitClient>,
    /// RFC 6806 canonicalize (NT-ENTERPRISE client names).
    pub canonicalize: bool,
}

/// RFC 4556 client certificate + trust anchor for PKINIT.
pub struct PkinitClient {
    /// Leaf certificate (DER).
    pub cert: Vec<u8>,
    /// P-256 scalar matching `cert`.
    pub key: [u8; 32],
    /// CA certificate used to verify the KDC CMS (DER).
    pub ca_cert: Vec<u8>,
}

impl Drop for PkinitClient {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Ticket used as RFC 6113 FAST AP-REQUEST armor.
pub struct FastArmor {
    /// Armor ticket (usually a TGT).
    pub ticket: krb5_types::Ticket,
    /// Session key of `ticket`.
    pub session: ProtocolKey,
    /// Client realm in the armor authenticator.
    pub crealm: krb5_types::Realm,
    /// Client name in the armor authenticator.
    pub cname: PrincipalName,
}

/// Obtain a TGT. Sends a bare AS-REQ first; if the KDC requires preauth,
/// derives the client key from ETYPE-INFO2 and retries with PA-ENC-TIMESTAMP.
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
pub fn as_exchange(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    wrap_as(req, &[])
}

/// AS-REQ using long-term keys (keytab), not a password.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn as_exchange_key(
    cname: PrincipalName,
    realm: &str,
    keys: &[ProtocolKey],
    kdc: &KdcAddr,
) -> Result<AsOutcome, Error> {
    wrap_as(
        &AsRequest {
            cname,
            realm,
            password: b"",
            kdc,
            want_spake: false,
            fast_armor: None,
            pkinit: None,
            canonicalize: false,
        },
        keys,
    )
}

fn wrap_as(req: &AsRequest<'_>, keys: &[ProtocolKey]) -> Result<AsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = as_exchange_inner(req, keys);
    emit(
        krb5_log::events::PROTOCOL_AS,
        &correlation_id,
        started,
        result.as_ref().err(),
    );
    result
}

fn as_exchange_inner(req: &AsRequest<'_>, keys: &[ProtocolKey]) -> Result<AsOutcome, Error> {
    let _ = krb5_types::try_ascii(req.realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    let nonce = random_nonce()?;
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());

    if req.fast_armor.is_some() {
        return continue_fast(req, keys, nonce, till.clone(), &etypes, None);
    }
    if req.pkinit.is_some() {
        return continue_pkinit(req, nonce, till, &etypes);
    }
    let support = req.want_spake.then(pa_spake_support);
    let first_pa = support.clone().map(|s| vec![s]);
    let first = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        till.clone(),
        first_pa,
        &etypes,
        req.canonicalize,
    )?;
    let wire = encode(&first)?;
    let reply = exchange(req.kdc, &wire)?;

    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep_keys(
            rep,
            nonce,
            keys,
            req.password,
            &req.cname,
            req.realm,
            req.canonicalize,
        ),
        KdcMsg::Error(e) if e.error_code == err::SKEW => {
            // First-reply SKEW: resync from KDC stime and retry the bare AS-REQ.
            let skew_time = e.stime.clone();
            let first = build_as_req(
                &req.cname,
                req.realm,
                nonce,
                till.clone(),
                None,
                &etypes,
                req.canonicalize,
            )?;
            let wire = encode(&first)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => finish_as_rep_keys(
                    rep,
                    nonce,
                    keys,
                    req.password,
                    &req.cname,
                    req.realm,
                    req.canonicalize,
                ),
                KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED => {
                    if req.want_spake {
                        continue_spake(req, keys, nonce, till, &etypes, &e)
                    } else if req.fast_armor.is_some() {
                        continue_fast(req, keys, nonce, till, &etypes, Some(&e))
                    } else {
                        continue_preauth(req, keys, nonce, till, &etypes, &e, Some(&skew_time))
                    }
                }
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e)
            if req.want_spake
                && (e.error_code == err::PREAUTH_REQUIRED
                    || e.error_code == err::MORE_PREAUTH_DATA_REQUIRED) =>
        {
            continue_spake(req, keys, nonce, till, &etypes, &e)
        }
        KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED && req.fast_armor.is_some() => {
            continue_fast(req, keys, nonce, till, &etypes, Some(&e))
        }
        KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED => {
            continue_preauth(req, keys, nonce, till, &etypes, &e, None)
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn finish_as_rep_keys(
    rep: AsRep,
    nonce: u32,
    keys: &[ProtocolKey],
    password: &[u8],
    cname: &PrincipalName,
    realm: &str,
    canonicalize: bool,
) -> Result<AsOutcome, Error> {
    if keys.is_empty() {
        return finish_as_rep(
            rep,
            nonce,
            None,
            password,
            cname,
            realm,
            false,
            canonicalize,
        );
    }
    let want = EncryptionType::from_iana(rep.0.enc_part.etype).ok();
    if let Some(k) = pick_key(keys, want)
        && let Ok(out) = finish_as_rep(
            rep.clone(),
            nonce,
            Some(k),
            password,
            cname,
            realm,
            false,
            canonicalize,
        )
    {
        return Ok(out);
    }
    let mut last = Error::ReplyMismatch("no keytab key decrypted AS-REP".into());
    for k in keys {
        match finish_as_rep(
            rep.clone(),
            nonce,
            Some(k.clone()),
            password,
            cname,
            realm,
            false,
            canonicalize,
        ) {
            Ok(out) => return Ok(out),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn pick_key(keys: &[ProtocolKey], etype: Option<EncryptionType>) -> Option<ProtocolKey> {
    if keys.is_empty() {
        return None;
    }
    if let Some(et) = etype
        && let Some(k) = keys.iter().find(|k| k.etype() == et)
    {
        return Some(k.clone());
    }
    keys.first().cloned()
}

fn continue_preauth(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    till: KerberosTime,
    etypes: &[i32],
    preauth_err: &KrbError,
    skew_hint: Option<&KerberosTime>,
) -> Result<AsOutcome, Error> {
    let (etype, salt, params) = select_s2k(preauth_err, &salt_cname(&req.cname), req.realm)?;
    let client_key = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
    let padata = vec![match skew_hint {
        Some(t) => pa_enc_timestamp_at(&client_key, t)?,
        None => pa_enc_timestamp(&client_key)?,
    }];
    let second = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        till.clone(),
        Some(padata),
        etypes,
        req.canonicalize,
    )?;
    let wire = encode(&second)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep(
            rep,
            nonce,
            Some(client_key),
            req.password,
            &req.cname,
            req.realm,
            true,
            req.canonicalize,
        ),
        KdcMsg::Error(e) if e.error_code == err::SKEW => {
            let skew_time = e.stime.clone();
            let padata = vec![pa_enc_timestamp_at(&client_key, &skew_time)?];
            let third = build_as_req(
                &req.cname,
                req.realm,
                nonce,
                till,
                Some(padata),
                etypes,
                req.canonicalize,
            )?;
            let wire = encode(&third)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => finish_as_rep(
                    rep,
                    nonce,
                    Some(client_key),
                    req.password,
                    &req.cname,
                    req.realm,
                    true,
                    req.canonicalize,
                ),
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) if e.error_code == err::ETYPE_NOSUPP => {
            let etypes = vec![EncryptionType::Aes256CtsHmacSha196.to_iana()];
            let padata = vec![pa_enc_timestamp(&client_key)?];
            let retry = build_as_req(
                &req.cname,
                req.realm,
                nonce,
                till,
                Some(padata),
                &etypes,
                req.canonicalize,
            )?;
            let wire = encode(&retry)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => finish_as_rep(
                    rep,
                    nonce,
                    Some(client_key),
                    req.password,
                    &req.cname,
                    req.realm,
                    true,
                    req.canonicalize,
                ),
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn continue_fast(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    till: KerberosTime,
    etypes: &[i32],
    err: Option<&KrbError>,
) -> Result<AsOutcome, Error> {
    let armor = req
        .fast_armor
        .ok_or_else(|| Error::ReplyMismatch("FAST armor missing".into()))?;
    let mut raw = vec![0u8; armor.session.etype().key_len()];
    getrandom::getrandom(&mut raw).map_err(|e| Error::transport_msg(e.to_string()))?;
    let sub = ProtocolKey::from_bytes(armor.session.etype(), &raw)?;
    let ap = build_fast_armor(
        armor.ticket.clone(),
        &armor.session,
        &armor.crealm,
        &armor.cname,
        Some(&sub),
    )?;
    let akey = armor_key(&armor.session, Some(&sub))?;
    let (etype, salt, params) = match err {
        Some(e) => select_s2k(e, &salt_cname(&req.cname), req.realm)?,
        None => (
            EncryptionType::preferred()[0],
            salt_cname(&req.cname).default_salt(req.realm),
            None,
        ),
    };
    let client_key = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
    let inner = vec![pa_enc_timestamp(&client_key)?];
    let mut req2 = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        till,
        None,
        etypes,
        req.canonicalize,
    )?;
    attach_fast(&mut req2, &ap, &akey, inner)?;
    let wire = encode(&req2)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => {
            let fast = unwrap_fast_rep(&akey, &rep.0.padata)?;
            let reply_key = match &fast.strengthen_key {
                Some(sk) => apply_strengthen(sk, &client_key)?,
                None => client_key.clone(),
            };
            finish_as_rep(
                rep,
                nonce,
                Some(reply_key),
                req.password,
                &req.cname,
                req.realm,
                true,
                req.canonicalize,
            )
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn continue_spake(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    till: KerberosTime,
    etypes: &[i32],
    err: &KrbError,
) -> Result<AsOutcome, Error> {
    let support = pa_spake_support();
    let method = method_from_error(err)?;
    if spake_challenge(&method)?.is_some() {
        return send_spake_response(req, keys, nonce, till, etypes, err, &support);
    }
    let mut padata = vec![support.clone()];
    if let Some(c) = find_pa(&method, pa::FX_COOKIE) {
        padata.push(c.clone());
    }
    let second = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        till.clone(),
        Some(padata),
        etypes,
        req.canonicalize,
    )?;
    let wire = encode(&second)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep_keys(
            rep,
            nonce,
            keys,
            req.password,
            &req.cname,
            req.realm,
            req.canonicalize,
        ),
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED
                || e.error_code == err::MORE_PREAUTH_DATA_REQUIRED =>
        {
            send_spake_response(req, keys, nonce, till, etypes, &e, &support)
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn send_spake_response(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    till: KerberosTime,
    etypes: &[i32],
    err: &KrbError,
    support: &PaData,
) -> Result<AsOutcome, Error> {
    let method = method_from_error(err)?;
    let (spa, chal) = spake_challenge(&method)?
        .ok_or_else(|| Error::ReplyMismatch("SPAKE challenge missing".into()))?;
    if chal.group != krb5_types::spake::GROUP_P256 {
        return Err(Error::ReplyMismatch(format!(
            "SPAKE group {} (want P-256)",
            chal.group
        )));
    }
    let cookie = find_pa(&method, pa::FX_COOKIE)
        .cloned()
        .ok_or_else(|| Error::ReplyMismatch("SPAKE FX_COOKIE missing".into()))?;
    let (etype, salt, params) = select_s2k(err, &salt_cname(&req.cname), req.realm)?;
    let ikey = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
    let mut req2 = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        till,
        None,
        etypes,
        req.canonicalize,
    )?;
    let body_der = encode(&req2.0.req_body)?;
    let (resp, k0) = pa_spake_response(
        &ikey,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )?;
    req2.0.padata = Some(vec![resp, cookie]);
    let wire = encode(&req2)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep(
            rep,
            nonce,
            Some(k0),
            req.password,
            &req.cname,
            req.realm,
            true,
            req.canonicalize,
        ),
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn continue_pkinit(
    req: &AsRequest<'_>,
    nonce: u32,
    till: KerberosTime,
    etypes: &[i32],
) -> Result<AsOutcome, Error> {
    let pk = req
        .pkinit
        .ok_or_else(|| Error::ReplyMismatch("PKINIT identity missing".into()))?;
    let kp = p256_generate()?;
    let mut req2 = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        till,
        None,
        etypes,
        req.canonicalize,
    )?;
    let body_der = encode(&req2.0.req_body)?;
    let mut h = Sha1::new();
    h.update(&body_der);
    let sha1 = h.finalize();
    let pa = pa_pk_as_req_signed(&kp.public, &pk.cert, &pk.key, nonce, &sha1)?;
    req2.0.padata = Some(vec![pa]);
    let wire = encode(&req2)?;
    tracing::info!(
        event = "client.pkinit",
        component = "krb5-protocol",
        outcome = "ok",
        pa_type = pa::PK_AS_REQ,
    );
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => {
            let etype = EncryptionType::from_iana(rep.0.enc_part.etype)?;
            let reply_key = pkinit_reply_key_agile(
                &kp.secret,
                &rep.0.padata,
                etype,
                &pk.ca_cert,
                &wire,
                &req.cname,
                req.realm,
            )?;
            finish_as_rep(
                rep,
                nonce,
                Some(reply_key),
                req.password,
                &req.cname,
                req.realm,
                true,
                req.canonicalize,
            )
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn method_from_error(err: &KrbError) -> Result<MethodData, Error> {
    let Some(ed) = &err.e_data else {
        return Ok(Vec::new());
    };
    decode(ed.as_ref()).map_err(Error::from)
}

fn find_pa(method: &[PaData], ty: i32) -> Option<&PaData> {
    method.iter().find(|p| p.padata_type == ty)
}

fn spake_challenge(
    method: &[PaData],
) -> Result<Option<(PaData, krb5_types::spake::SpakeChallenge)>, Error> {
    let Some(p) = find_pa(method, pa::SPAKE) else {
        return Ok(None);
    };
    match decode::<krb5_types::spake::PaSpake>(p.padata_value.as_ref())? {
        krb5_types::spake::PaSpake::Challenge(c) => Ok(Some((p.clone(), c))),
        _ => Ok(None),
    }
}

fn classify_kdc_error(e: &KrbError) -> Result<AsOutcome, Error> {
    match e.error_code {
        err::SKEW => Err(Error::KrbError {
            code: err::SKEW,
            text: Some("clock skew; resync local clock and retry".into()),
        }),
        err::ETYPE_NOSUPP => Err(Error::KrbError {
            code: err::ETYPE_NOSUPP,
            text: Some("no common etype".into()),
        }),
        err::WRONG_REALM => {
            let realm = e.realm.as_bytes().to_vec();
            Err(Error::KrbError {
                code: err::WRONG_REALM,
                text: Some(format!(
                    "wrong realm; chase {}",
                    String::from_utf8_lossy(&realm)
                )),
            })
        }
        _ => krb_err(e),
    }
}

enum KdcMsg {
    AsRep(AsRep),
    TgsRep,
    Error(KrbError),
}

fn classify(bytes: &[u8]) -> Result<KdcMsg, Error> {
    if bytes.is_empty() {
        return Err(Error::TruncatedReply);
    }
    match bytes[0] {
        0x6b => Ok(KdcMsg::AsRep(decode(bytes)?)),
        0x6d => {
            let _: krb5_types::TgsRep = decode(bytes)?;
            Ok(KdcMsg::TgsRep)
        }
        0x7e => Ok(KdcMsg::Error(decode(bytes)?)),
        _ => Err(Error::UnexpectedPdu),
    }
}

fn krb_err(e: &KrbError) -> Result<AsOutcome, Error> {
    let text = e
        .e_text
        .as_ref()
        .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
        .map(str::to_owned);
    tracing::error!(
        event = krb5_log::events::PROTOCOL_KRB_ERROR,
        component = "krb5-protocol",
        outcome = "error",
        error_code = e.error_code,
        error = text.as_deref().unwrap_or(""),
    );
    Err(Error::KrbError {
        code: e.error_code,
        text,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_as_rep(
    rep: AsRep,
    nonce: u32,
    client_key: Option<ProtocolKey>,
    password: &[u8],
    cname: &PrincipalName,
    realm: &str,
    sent_preauth: bool,
    canonicalize: bool,
) -> Result<AsOutcome, Error> {
    let inner = rep.0;
    let had_preauth = sent_preauth;
    let etype = EncryptionType::from_iana(inner.enc_part.etype)?;
    let key = if let Some(k) = client_key {
        k
    } else {
        let salt = salt_cname(cname).default_salt(realm);
        string_to_key(etype, password, &salt, None)?
    };
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let plain = decrypt(&key, usage, inner.enc_part.cipher.as_ref())?;
    let enc_part = decode_enc_as(&plain)?;
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    if inner.cname != *cname {
        let enterprise = cname.name_type == PrincipalName::NT_ENTERPRISE;
        if !(canonicalize || enterprise) || inner.cname.name_string.is_empty() {
            return Err(Error::ReplyMismatch("AS-REP cname mismatch".into()));
        }
    }
    if inner.crealm.as_bytes() != realm.as_bytes() {
        return Err(Error::ReplyMismatch("AS-REP crealm mismatch".into()));
    }
    if enc_part.sname.components_joined() != inner.ticket.sname.components_joined() {
        return Err(Error::ReplyMismatch("AS-REP sname/ticket mismatch".into()));
    }
    if inner.enc_part.etype != key.etype().to_iana() && inner.enc_part.etype != enc_part.key.keytype
    {
        return Err(Error::ReplyMismatch("AS-REP etype mismatch".into()));
    }
    if !enc_part.flags.initial() || !enc_part.flags.pre_authent() {
        // Some KDCs omit INITIAL on service-ticket AS; require pre-authent when
        // we sent PA-ENC-TIMESTAMP (client_key is Some).
        if had_preauth && !enc_part.flags.pre_authent() {
            return Err(Error::ReplyMismatch("AS-REP missing PRE-AUTHENT".into()));
        }
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    check_as_rep_times(&enc_part, now, 300)?;
    if !enc_part.sname.is_krbtgt_for(realm) {
        return Err(Error::ReplyMismatch("AS-REP sname is not krbtgt".into()));
    }
    let requested: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    if !requested.contains(&enc_part.key.keytype) && !requested.contains(&inner.enc_part.etype) {
        return Err(Error::ReplyMismatch("AS-REP etype not in request".into()));
    }
    let session_etype = EncryptionType::from_iana(enc_part.key.keytype)
        .or_else(|_| EncryptionType::known(enc_part.key.keytype))?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    Ok(AsOutcome {
        ticket: inner.ticket,
        enc_part,
        client_key: key,
        session_key,
        cname: inner.cname,
        crealm: inner.crealm,
    })
}

pub(crate) fn check_as_rep_times(
    enc_part: &EncKdcRepPart,
    now: i64,
    skew: i64,
) -> Result<(), Error> {
    let end = i64::from(enc_part.endtime.unix_seconds());
    let auth = i64::from(enc_part.authtime.unix_seconds());
    if (auth - now).abs() > skew {
        return Err(Error::ReplyMismatch("AS-REP authtime outside skew".into()));
    }
    if end + skew < now {
        return Err(Error::ReplyMismatch("AS-REP ticket expired".into()));
    }
    if let Some(st) = &enc_part.starttime
        && i64::from(st.unix_seconds()) > now + skew
    {
        return Err(Error::ReplyMismatch("AS-REP ticket not yet valid".into()));
    }
    Ok(())
}

fn decode_enc_as(plain: &[u8]) -> Result<EncKdcRepPart, Error> {
    // RFC 4120 §5.4.2: EncASRepPart is APPLICATION 25 (0x79). MIT 1.22.2
    // kdc still wraps the AS enc-part as APPLICATION 26; accept that only
    // as a documented interop fallback, then the untagged SEQUENCE.
    if let Ok(EncAsRepPart(part)) = decode::<EncAsRepPart>(plain) {
        return Ok(part);
    }
    if plain.first() == Some(&0x7a)
        && let Ok(krb5_types::EncTgsRepPart(part)) = decode::<krb5_types::EncTgsRepPart>(plain)
    {
        return Ok(part);
    }
    if let Ok(part) = decode::<EncKdcRepPart>(plain) {
        return Ok(part);
    }
    Err(Error::Asn1(format!(
        "enc-part der tag={:02x} len={} (plaintext omitted)",
        plain.first().copied().unwrap_or(0),
        plain.len()
    )))
}

fn salt_cname(cname: &PrincipalName) -> PrincipalName {
    if cname.name_type != PrincipalName::NT_ENTERPRISE {
        return cname.clone();
    }
    let raw = cname.components_joined();
    let user = match raw.rsplit_once('@') {
        Some((u, _)) if !u.is_empty() => u,
        _ => raw.as_str(),
    };
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user])
}

fn build_as_req(
    cname: &PrincipalName,
    realm: &str,
    nonce: u32,
    till: KerberosTime,
    padata: Option<Vec<PaData>>,
    etypes: &[i32],
    canonicalize: bool,
) -> Result<AsReq, Error> {
    let realm_s = krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    let mut opts = KdcOptions::forwardable();
    if canonicalize {
        opts = opts.with_bit(flag_bit::CANONICALIZE, true);
    }
    Ok(AsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata,
        req_body: KdcReqBody {
            kdc_options: opts,
            cname: Some(cname.clone()),
            realm: realm_s,
            sname: Some(PrincipalName::krbtgt(realm)),
            from: None,
            till,
            rtime: None,
            nonce,
            etype: etypes.to_vec(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    }))
}

fn pa_enc_timestamp(key: &ProtocolKey) -> Result<PaData, Error> {
    pa_enc_timestamp_at(key, &KerberosTime::now())
}

fn pa_enc_timestamp_at(key: &ProtocolKey, now: &KerberosTime) -> Result<PaData, Error> {
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let ts = PaEncTsEnc {
        patimestamp: now.clone(),
        pausec: Some(krb5_types::Microseconds::from_subsec_micros(usec)),
    };
    let der = encode(&ts)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let cipher = encrypt(key, usage, &der)?;
    let enc = EncryptedData {
        etype: key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    Ok(PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&enc)?.into(),
    })
}

type S2kMaterial = (EncryptionType, Vec<u8>, Option<Vec<u8>>);

fn select_s2k(error: &KrbError, cname: &PrincipalName, realm: &str) -> Result<S2kMaterial, Error> {
    let default_salt = cname.default_salt(realm);
    let Some(edata) = &error.e_data else {
        return Ok((EncryptionType::Aes256CtsHmacSha384192, default_salt, None));
    };
    let method: MethodData = decode(edata.as_ref())?;
    for p in &method {
        if p.padata_type == pa::ETYPE_INFO2 {
            let info: EtypeInfo2 = decode(p.padata_value.as_ref())?;
            if let Some(found) = pick_info2(&info, &default_salt) {
                return Ok(found);
            }
        }
    }
    for p in &method {
        if p.padata_type == pa::ETYPE_INFO {
            let info: EtypeInfo = decode(p.padata_value.as_ref())?;
            if let Some(found) = pick_info(&info, &default_salt) {
                return Ok(found);
            }
        }
        if p.padata_type == pa::PW_SALT {
            return Ok((
                EncryptionType::Aes256CtsHmacSha384192,
                p.padata_value.as_ref().to_vec(),
                None,
            ));
        }
    }
    Ok((EncryptionType::Aes256CtsHmacSha384192, default_salt, None))
}

fn pick_info2(info: &EtypeInfo2, default_salt: &[u8]) -> Option<S2kMaterial> {
    for wanted in EncryptionType::preferred() {
        if let Some(ent) = info.iter().find(|e| e.etype == wanted.to_iana()) {
            let salt = ent
                .salt
                .as_ref()
                .map_or_else(|| default_salt.to_vec(), |s| s.as_bytes().to_vec());
            let params = ent.s2kparams.as_ref().map(|p| p.as_ref().to_vec());
            return Some((wanted, salt, params));
        }
    }
    None
}

fn pick_info(info: &EtypeInfo, default_salt: &[u8]) -> Option<S2kMaterial> {
    for wanted in EncryptionType::preferred() {
        if let Some(ent) = info.iter().find(|e| e.etype == wanted.to_iana()) {
            let salt = ent
                .salt
                .as_ref()
                .map_or_else(|| default_salt.to_vec(), |s| s.as_ref().to_vec());
            return Some((wanted, salt, None));
        }
    }
    None
}

fn random_nonce() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

fn emit(event: &'static str, correlation_id: &str, started: Instant, err: Option<&Error>) {
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Some(e) = err {
        tracing::error!(
            event,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        );
    } else {
        tracing::info!(
            event,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        );
    }
}

#[cfg(test)]
mod decode_enc_as_tests {
    use super::*;
    use krb5_types::{
        EncTgsRepPart, EncryptionKey, OctetString, TicketFlags, ascii, kerberos_time_from_utc_z,
    };

    fn sample_part() -> EncKdcRepPart {
        let t = kerberos_time_from_utc_z("20260819120000Z").expect("sample time");
        EncKdcRepPart {
            key: EncryptionKey {
                keytype: 18,
                keyvalue: OctetString::from(vec![1u8; 32]),
            },
            last_req: vec![],
            nonce: 7,
            key_expiration: None,
            flags: TicketFlags::none(),
            authtime: t.clone(),
            starttime: None,
            endtime: t,
            renew_till: None,
            srealm: ascii("KERBER.TEST"),
            sname: PrincipalName::krbtgt("KERBER.TEST"),
            caddr: None,
            encrypted_pa_data: None,
        }
    }

    #[test]
    fn prefers_rfc_application_25() {
        let part = sample_part();
        let der = encode(&EncAsRepPart(part.clone())).expect("encode 25");
        assert_eq!(der.first().copied(), Some(0x79), "APPLICATION 25");
        assert_eq!(decode_enc_as(&der).expect("decode 25"), part);
    }

    #[test]
    fn mit_application_26_only_when_tag_is_7a() {
        let part = sample_part();
        let der = encode(&EncTgsRepPart(part.clone())).expect("encode 26");
        assert_eq!(der.first().copied(), Some(0x7a), "APPLICATION 26");
        assert_eq!(decode_enc_as(&der).expect("MIT 26 fallback"), part);
        let other = [0x62, 0x03, 0x02, 0x01, 0x00];
        assert!(decode_enc_as(&other).is_err());
    }

    #[test]
    fn authtime_outside_skew_is_rejected() {
        let mut part = sample_part();
        let now_t = KerberosTime::now();
        let now = i64::from(now_t.unix_seconds());
        part.authtime = now_t.clone();
        part.endtime = now_t.add_hours(10).unwrap_or(now_t);
        super::check_as_rep_times(&part, now, 300).unwrap();
        part.authtime = kerberos_time_from_utc_z("20000101000000Z").expect("old");
        assert!(super::check_as_rep_times(&part, now, 300).is_err());
    }
}
