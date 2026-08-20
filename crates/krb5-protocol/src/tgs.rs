//! TGS-REQ / TGS-REP using an existing TGT.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{checksum, decrypt, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ascii, flag_bit, ku, pa, ApOptions, ApReq, Authenticator, Checksum, EncKdcRepPart,
    EncTgsRepPart, EncryptedData, KdcOptions, KdcReq, KdcReqBody, KerberosTime, PaData,
    PrincipalName, TgsRep, TgsReq, Ticket,
};

use crate::as_ex::AsOutcome;
use crate::error::Error;

use crate::transport::{exchange, KdcAddr};

/// Successful TGS exchange.
#[derive(Clone, Debug)]
pub struct TgsOutcome {
    /// Service ticket.
    pub ticket: Ticket,
    /// Decrypted EncKDCRepPart.
    pub enc_part: EncKdcRepPart,
    /// Session key for the service.
    pub session_key: ProtocolKey,
}

/// Request a service ticket with a TGT from [`AsOutcome`].
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
#[allow(clippy::needless_pass_by_value)]
pub fn tgs_exchange(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = tgs_inner(kdc, tgt, &sname, realm);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::info!(
            event = krb5_log::events::PROTOCOL_TGS,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::PROTOCOL_TGS,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

fn tgs_inner(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let mut cur_kdc = kdc.clone();
    let mut cur_tgt = tgt.clone();
    for _ in 0..8 {
        let out = tgs_once(&cur_kdc, &cur_tgt, sname.clone(), realm)?;
        if out.ticket.sname.is_krbtgt() && out.ticket.sname != *sname {
            let foreign = out
                .ticket
                .sname
                .name_string
                .get(1)
                .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
                .unwrap_or_default();
            if foreign.is_empty() || foreign == realm {
                return Err(Error::Referral);
            }
            cur_kdc = kdc_for_realm(&foreign, kdc);
            cur_tgt = AsOutcome {
                ticket: out.ticket,
                enc_part: out.enc_part,
                client_key: cur_tgt.client_key.clone(),
                session_key: out.session_key,
                cname: cur_tgt.cname.clone(),
                crealm: cur_tgt.crealm.clone(),
            };
            continue;
        }
        return Ok(out);
    }
    Err(Error::Referral)
}

fn kdc_for_realm(realm: &str, fallback: &KdcAddr) -> KdcAddr {
    let env_key = format!("KRB5_KDC_{}", realm.replace('.', "_"));
    if let Ok(v) = std::env::var(env_key) {
        if let Some((h, p)) = v.rsplit_once(':') {
            if let Ok(port) = p.parse() {
                return KdcAddr {
                    host: h.to_owned(),
                    port,
                };
            }
        }
        return KdcAddr::new(v);
    }
    if let Ok(path) = std::env::var("KRB5_CONFIG") {
        if let Ok(conf) = krb5_config::Krb5Conf::load_file(path) {
            if let Ok(list) = conf.kdcs_for(realm) {
                if let Some(ep) = list.first() {
                    return KdcAddr {
                        host: ep.host.clone(),
                        port: ep.port,
                    };
                }
            }
        }
    }
    fallback.clone()
}

fn tgs_once(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let nonce = random_nonce31()?;
    let till = KerberosTime(tgt.enc_part.endtime.0);
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();

    let requested = sname.clone();
    let body = KdcReqBody {
        kdc_options: KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        cname: None,
        realm: ascii(realm),
        sname: Some(sname),
        from: None,
        till,
        rtime: None,
        nonce,
        etype: etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_der = encode(&body)?;
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
    let mic = checksum(&tgt.session_key, cksum_usage, &body_der)?;
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        cksum: Some(Checksum {
            cksumtype: tgt.session_key.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: krb5_types::Microseconds::from_subsec_micros(usec),
        ctime: now,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let auth_der = encode(&authenticator)?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_cipher = encrypt(&tgt.session_key, auth_usage, &auth_der)?;
    let ap_req = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData {
            etype: tgt.session_key.etype().to_iana(),
            kvno: None,
            cipher: auth_cipher.into(),
        },
    };
    // FAST armor AP-REQ uses key-usage 11; PA-TGS-REQ uses usage 7. MIT
    // FIND_FAST fails if the armor AP-REQ is the TGS authenticator.
    let padata = vec![PaData {
        padata_type: pa::TGS_REQ,
        padata_value: encode(&ap_req)?.into(),
    }];
    let tgs = TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(padata),
        req_body: body,
    });
    let wire = encode(&tgs)?;
    let reply = exchange(kdc, &wire)?;
    if reply.is_empty() {
        return Err(Error::TruncatedReply);
    }
    if reply[0] == 0x7e {
        let e: krb5_types::KrbError = decode(&reply)?;
        let text = e
            .e_text
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
            .map(str::to_owned);
        return Err(Error::KrbError {
            code: e.error_code,
            text,
        });
    }
    if reply[0] != 0x6d {
        return Err(Error::UnexpectedPdu);
    }
    let TgsRep(inner) = decode::<TgsRep>(&reply)?;
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART)?;
    let plain = decrypt(&tgt.session_key, usage, inner.enc_part.cipher.as_ref())?;
    let enc_part = if let Ok(EncTgsRepPart(p)) = decode::<EncTgsRepPart>(&plain) {
        p
    } else {
        decode::<EncKdcRepPart>(&plain)?
    };
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    if inner.ticket.sname != requested && enc_part.sname != requested {
        if inner.ticket.sname.is_krbtgt() {
            return Err(Error::Referral);
        }
        return Err(Error::ReplyMismatch("TGS-REP sname mismatch".into()));
    }
    let session_etype = EncryptionType::from_iana(enc_part.key.keytype)
        .or_else(|_| EncryptionType::known(enc_part.key.keytype))?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    Ok(TgsOutcome {
        ticket: inner.ticket,
        enc_part,
        session_key,
    })
}

fn random_nonce31() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}
