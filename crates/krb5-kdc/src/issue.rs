//! AS and TGS ticket issuance as pure functions over the principal store.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{decrypt, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ascii, err, ku, pa, AsRep, AsReq, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    EncryptionKey, EtypeInfo2, EtypeInfo2Entry, KerberosTime, KrbError, LastReqValue, MethodData,
    OctetString, PaData, PaEncTsEnc, PrincipalName, TgsRep, TgsReq, Ticket, TicketFlags,
    TransitedEncoding,
};

use crate::error::Error;
use crate::store::{random_key, s2k_params, Principal, PrincipalStore};

/// Issued AS-REP plus the session key (for tests that decrypt the TGT).
#[derive(Debug)]
pub struct IssuedAs {
    /// Wire AS-REP.
    pub rep: AsRep,
    /// Session key placed in the ticket and EncKDCRepPart.
    pub session_key: ProtocolKey,
}

/// Issued TGS-REP plus the service session key.
#[derive(Debug)]
pub struct IssuedTgs {
    /// Wire TGS-REP.
    pub rep: TgsRep,
    /// Service session key.
    pub session_key: ProtocolKey,
}

/// Dispatch one UDP/TCP payload (AS-REQ or TGS-REQ) to the issue path.
///
/// On [`Error::PreauthRequired`] this returns a well-formed KRB-ERROR PDU
/// rather than bubbling the error, so a listener can write it as-is.
///
/// # Errors
///
/// Returns protocol or crypto failures other than preauth-required.
pub fn handle_request(store: &PrincipalStore, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = handle_inner(store, raw);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id,
            component = "krb5-kdc",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id,
            component = "krb5-kdc",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

fn handle_inner(store: &PrincipalStore, raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.is_empty() {
        return Err(Error::UnexpectedPdu);
    }
    match raw[0] {
        0x6a => {
            let req: AsReq = decode(raw)?;
            as_reply(store, &req)
        }
        0x6c => {
            let req: TgsReq = decode(raw)?;
            tgs_reply(store, &req)
        }
        _ => Err(Error::UnexpectedPdu),
    }
}

fn as_reply(store: &PrincipalStore, req: &AsReq) -> Result<Vec<u8>, Error> {
    match issue_as(store, req) {
        Ok(issued) => Ok(encode(&issued.rep)?),
        Err(Error::PreauthRequired { e_data }) => Ok(encode_krb_error(
            store,
            err::PREAUTH_REQUIRED,
            None,
            Some(e_data),
        )),
        Err(Error::Protocol { code, text }) => {
            Ok(encode_krb_error(store, code, text.as_deref(), None))
        }
        Err(e) => Err(e),
    }
}

fn tgs_reply(store: &PrincipalStore, req: &TgsReq) -> Result<Vec<u8>, Error> {
    match issue_tgs(store, req) {
        Ok(issued) => Ok(encode(&issued.rep)?),
        Err(Error::Protocol { code, text }) => {
            Ok(encode_krb_error(store, code, text.as_deref(), None))
        }
        Err(e) => Err(e),
    }
}

/// Issue an AS-REP for `req`, or [`Error::PreauthRequired`].
///
/// # Errors
///
/// Unknown client, bad preauth, or crypto/DER failures.
pub fn issue_as(store: &PrincipalStore, req: &AsReq) -> Result<IssuedAs, Error> {
    let body = &req.0.req_body;
    let cname = body
        .cname
        .clone()
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "no cname"))?;
    let client = store
        .get_name(&cname)
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "unknown client"))?;
    let etype = select_etype(&body.etype, client)?;
    let ckey = client
        .key_for(etype)
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "no client key"))?;

    match extract_enc_timestamp(&req.0.padata) {
        None => return Err(preauth_required(client)),
        Some(blob) => verify_enc_timestamp(&ckey.key, blob.as_ref())?,
    }

    let krbtgt = store
        .krbtgt()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let tgt_key = krbtgt
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt key"))?;
    let session = random_key(etype)?;
    let now = KerberosTime::now();
    let end = now.add_hours(10);
    let sname = PrincipalName::krbtgt(store.realm());
    let ticket = mint_ticket(
        &tgt_key.key,
        tgt_key.kvno,
        tgt_key.etype,
        &session,
        store.realm(),
        &sname,
        store.realm(),
        &cname,
        &now,
        &end,
        TicketFlags::initial_preauth(),
    )?;
    let enc_part = enc_rep_part(
        &session,
        body.nonce,
        &now,
        &end,
        store.realm(),
        &sname,
        TicketFlags::initial_preauth(),
    );
    // MIT 1.22.2 kinit decodes AS-REP enc-part as APPLICATION 26
    // (EncTGSRepPart). RFC 4120 assigns APPLICATION 25 to EncASRepPart.
    let enc_der = encode(&EncTgsRepPart(enc_part))?;
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let cipher = encrypt(&ckey.key, usage, &enc_der)?;
    let rep = AsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_AS_REP,
        padata: None,
        crealm: ascii(store.realm()),
        cname,
        ticket,
        enc_part: EncryptedData {
            etype: ckey.etype.to_iana(),
            kvno: Some(ckey.kvno),
            cipher: cipher.into(),
        },
    });
    Ok(IssuedAs {
        rep,
        session_key: session,
    })
}

/// Issue a TGS-REP for `req` using the TGT in PA-TGS-REQ.
///
/// # Errors
///
/// Bad authenticator, unknown server, or crypto/DER failures.
pub fn issue_tgs(store: &PrincipalStore, req: &TgsReq) -> Result<IssuedTgs, Error> {
    let body = &req.0.req_body;
    let ap_raw =
        extract_pa_tgs(&req.0.padata).ok_or_else(|| proto(err::PREAUTH_FAILED, "no PA-TGS-REQ"))?;
    let ap: krb5_types::ApReq = decode(ap_raw.as_ref())?;
    let krbtgt = store
        .krbtgt()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let tgt_key = krbtgt
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt key"))?;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let tkt_plain = decrypt(&tgt_key.key, tkt_usage, ap.ticket.enc_part.cipher.as_ref())?;
    let enc_tkt: EncTicketPart = decode(&tkt_plain)?;
    let sess_etype = EncryptionType::from_iana(enc_tkt.key.keytype)?;
    let tgt_session = ProtocolKey::from_bytes(sess_etype, enc_tkt.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&tgt_session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: krb5_types::Authenticator = decode(&auth_plain)?;
    if authenticator.cname != enc_tkt.cname {
        return Err(proto(err::BAD_INTEGRITY, "TGS authenticator mismatch"));
    }
    let sname = body
        .sname
        .clone()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no sname"))?;
    let server = store
        .get_name(&sname)
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "unknown server"))?;
    let skey = server
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no server key"))?;
    let session = random_key(skey.etype)?;
    let now = KerberosTime::now();
    let end = enc_tkt.endtime.clone();
    let ticket = mint_ticket(
        &skey.key,
        skey.kvno,
        skey.etype,
        &session,
        store.realm(),
        &sname,
        utf8_realm(&enc_tkt.crealm),
        &enc_tkt.cname,
        &now,
        &end,
        TicketFlags::none(),
    )?;
    let enc_part = enc_rep_part(
        &session,
        body.nonce,
        &now,
        &end,
        store.realm(),
        &sname,
        TicketFlags::none(),
    );
    let enc_der = encode(&EncTgsRepPart(enc_part))?;
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART)?;
    let cipher = encrypt(&tgt_session, usage, &enc_der)?;
    let rep = TgsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_TGS_REP,
        padata: None,
        crealm: enc_tkt.crealm,
        cname: enc_tkt.cname,
        ticket,
        enc_part: EncryptedData {
            etype: tgt_session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    });
    Ok(IssuedTgs {
        rep,
        session_key: session,
    })
}

#[allow(clippy::too_many_arguments)]
fn mint_ticket(
    service_key: &ProtocolKey,
    kvno: u32,
    service_etype: EncryptionType,
    session: &ProtocolKey,
    srealm: &str,
    sname: &PrincipalName,
    crealm: &str,
    cname: &PrincipalName,
    authtime: &KerberosTime,
    endtime: &KerberosTime,
    flags: TicketFlags,
) -> Result<Ticket, Error> {
    let part = EncTicketPart {
        flags,
        key: encryption_key(session),
        crealm: ascii(crealm),
        cname: cname.clone(),
        transited: TransitedEncoding::empty(),
        authtime: authtime.clone(),
        starttime: Some(authtime.clone()),
        endtime: endtime.clone(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let cipher = encrypt(service_key, usage, &der)?;
    Ok(Ticket {
        tkt_vno: Ticket::VNO,
        realm: ascii(srealm),
        sname: sname.clone(),
        enc_part: EncryptedData {
            etype: service_etype.to_iana(),
            kvno: Some(kvno),
            cipher: cipher.into(),
        },
    })
}

fn enc_rep_part(
    session: &ProtocolKey,
    nonce: u32,
    now: &KerberosTime,
    end: &KerberosTime,
    realm: &str,
    sname: &PrincipalName,
    flags: TicketFlags,
) -> EncKdcRepPart {
    EncKdcRepPart {
        key: encryption_key(session),
        last_req: vec![LastReqValue {
            lr_type: 0,
            lr_value: now.clone(),
        }],
        nonce,
        key_expiration: None,
        flags,
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: end.clone(),
        renew_till: None,
        srealm: ascii(realm),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    }
}

fn encryption_key(key: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: key.etype().to_iana(),
        keyvalue: OctetString::from(key.as_bytes().to_vec()),
    }
}

fn select_etype(requested: &[i32], princ: &Principal) -> Result<EncryptionType, Error> {
    for n in requested {
        if let Ok(e) = EncryptionType::from_iana(*n) {
            if princ.key_for(e).is_some() {
                return Ok(e);
            }
        }
    }
    princ
        .best_key()
        .map(|k| k.etype)
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "no etype"))
}

fn extract_enc_timestamp(padata: &Option<Vec<PaData>>) -> Option<&OctetString> {
    padata.as_ref()?.iter().find_map(|p| {
        if p.padata_type == pa::ENC_TIMESTAMP {
            Some(&p.padata_value)
        } else {
            None
        }
    })
}

fn extract_pa_tgs(padata: &Option<Vec<PaData>>) -> Option<&OctetString> {
    padata.as_ref()?.iter().find_map(|p| {
        if p.padata_type == pa::TGS_REQ {
            Some(&p.padata_value)
        } else {
            None
        }
    })
}

fn verify_enc_timestamp(key: &ProtocolKey, blob: &[u8]) -> Result<(), Error> {
    let enc: EncryptedData = decode(blob)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let plain = decrypt(key, usage, enc.cipher.as_ref())?;
    let ts: PaEncTsEnc = decode(&plain)?;
    let now = KerberosTime::now().unix_seconds() as i64;
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > 300 {
        return Err(proto(err::SKEW, "PA-ENC-TIMESTAMP skew"));
    }
    Ok(())
}

fn preauth_required(client: &Principal) -> Error {
    let salt =
        krb5_types::KerberosString::try_from(String::from_utf8_lossy(&client.salt).as_ref()).ok();
    let mut info: EtypeInfo2 = Vec::new();
    for k in &client.keys {
        info.push(EtypeInfo2Entry {
            etype: k.etype.to_iana(),
            salt: salt.clone(),
            s2kparams: Some(s2k_params().into()),
        });
    }
    let etype_info = PaData {
        padata_type: pa::ETYPE_INFO2,
        padata_value: encode(&info).map(Into::into).unwrap_or_default(),
    };
    // MIT kinit only attempts encrypted timestamp when PA-ENC-TIMESTAMP
    // appears in METHOD-DATA (empty value is the hint).
    let method: MethodData = vec![
        PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: OctetString::from(Vec::<u8>::new()),
        },
        etype_info,
    ];
    let e_data = encode(&method).unwrap_or_default();
    Error::PreauthRequired { e_data }
}

fn encode_krb_error(
    store: &PrincipalStore,
    code: i32,
    text: Option<&str>,
    e_data: Option<Vec<u8>>,
) -> Vec<u8> {
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: 0,
        error_code: code,
        crealm: None,
        cname: None,
        realm: ascii(store.realm()),
        sname: PrincipalName::krbtgt(store.realm()),
        e_text: text.map(ascii),
        e_data: e_data.map(Into::into),
    };
    encode(&pdu).unwrap_or_default()
}

fn proto(code: i32, text: &str) -> Error {
    Error::Protocol {
        code,
        text: Some(text.to_owned()),
    }
}

fn utf8_realm(r: &krb5_types::Realm) -> &str {
    std::str::from_utf8(r.as_bytes()).unwrap_or("KERBER.TEST")
}
