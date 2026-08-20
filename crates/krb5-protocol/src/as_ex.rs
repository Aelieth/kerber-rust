//! AS-REQ / AS-REP with PA-ENC-TIMESTAMP preauthentication.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{decrypt, encrypt, string_to_key, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ascii, err, ku, pa, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncryptedData, EtypeInfo,
    EtypeInfo2, KdcOptions, KdcReq, KdcReqBody, KerberosTime, KrbError, MethodData, PaData,
    PaEncTsEnc, PrincipalName,
};

use crate::error::Error;
use crate::transport::{exchange, KdcAddr};

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
}

/// Obtain a TGT. Sends a bare AS-REQ first; if the KDC requires preauth,
/// derives the client key from ETYPE-INFO2 and retries with PA-ENC-TIMESTAMP.
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
pub fn as_exchange(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = as_exchange_inner(req);
    emit(
        krb5_log::events::PROTOCOL_AS,
        &correlation_id,
        started,
        result.as_ref().err(),
    );
    result
}

fn as_exchange_inner(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    let nonce = random_nonce()?;
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());

    let first = build_as_req(&req.cname, req.realm, nonce, till.clone(), None, &etypes);
    let wire = encode(&first)?;
    let reply = exchange(req.kdc, &wire)?;

    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep(rep, nonce, None, req.password, &req.cname, req.realm),
        KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED => {
            let (etype, salt, params) = select_s2k(&e, &req.cname, req.realm)?;
            let client_key = string_to_key(etype, req.password, &salt, params.as_deref())?;
            let padata = vec![pa_enc_timestamp(&client_key)?];
            let second = build_as_req(
                &req.cname,
                req.realm,
                nonce,
                till.clone(),
                Some(padata),
                &etypes,
            );
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
                ),
                KdcMsg::Error(e) if e.error_code == err::SKEW => {
                    let skew_time = e.stime.clone();
                    let padata = vec![pa_enc_timestamp_at(&client_key, &skew_time)?];
                    let third =
                        build_as_req(&req.cname, req.realm, nonce, till, Some(padata), &etypes);
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
                        ),
                        KdcMsg::Error(e) => classify_kdc_error(&e),
                        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
                    }
                }
                KdcMsg::Error(e) if e.error_code == err::ETYPE_NOSUPP => {
                    let etypes = vec![EncryptionType::Aes256CtsHmacSha196.to_iana()];
                    let padata = vec![pa_enc_timestamp(&client_key)?];
                    let retry =
                        build_as_req(&req.cname, req.realm, nonce, till, Some(padata), &etypes);
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
                        ),
                        KdcMsg::Error(e) => classify_kdc_error(&e),
                        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
                    }
                }
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
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

fn finish_as_rep(
    rep: AsRep,
    nonce: u32,
    client_key: Option<ProtocolKey>,
    password: &[u8],
    cname: &PrincipalName,
    realm: &str,
) -> Result<AsOutcome, Error> {
    let inner = rep.0;
    let had_preauth = client_key.is_some();
    let etype = EncryptionType::from_iana(inner.enc_part.etype)?;
    let key = if let Some(k) = client_key {
        k
    } else {
        let salt = cname.default_salt(realm);
        string_to_key(etype, password, &salt, None)?
    };
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let plain = decrypt(&key, usage, inner.enc_part.cipher.as_ref())?;
    let enc_part = decode_enc_as(&plain)?;
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    if inner.cname != *cname {
        return Err(Error::ReplyMismatch("AS-REP cname mismatch".into()));
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
    let skew = 300i64;
    let end = i64::from(enc_part.endtime.unix_seconds());
    if end + skew < now {
        return Err(Error::ReplyMismatch("AS-REP ticket expired".into()));
    }
    if let Some(st) = &enc_part.starttime {
        if i64::from(st.unix_seconds()) > now + skew {
            return Err(Error::ReplyMismatch("AS-REP ticket not yet valid".into()));
        }
    }
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

fn decode_enc_as(plain: &[u8]) -> Result<EncKdcRepPart, Error> {
    // RFC 4120 §5.4.2: EncASRepPart is APPLICATION 25 (0x79). MIT 1.22.2
    // kdc still wraps the AS enc-part as APPLICATION 26; accept that only
    // as a documented interop fallback, then the untagged SEQUENCE.
    if let Ok(EncAsRepPart(part)) = decode::<EncAsRepPart>(plain) {
        return Ok(part);
    }
    if plain.first() == Some(&0x7a) {
        if let Ok(krb5_types::EncTgsRepPart(part)) = decode::<krb5_types::EncTgsRepPart>(plain) {
            return Ok(part);
        }
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

fn build_as_req(
    cname: &PrincipalName,
    realm: &str,
    nonce: u32,
    till: KerberosTime,
    padata: Option<Vec<PaData>>,
    etypes: &[i32],
) -> AsReq {
    AsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata,
        req_body: KdcReqBody {
            kdc_options: KdcOptions::forwardable(),
            cname: Some(cname.clone()),
            realm: ascii(realm),
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
    })
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
        kerberos_time_from_utc_z, EncTgsRepPart, EncryptionKey, OctetString, TicketFlags,
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
}
