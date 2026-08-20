//! TGS-REQ / TGS-REP using an existing TGT.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{checksum, decrypt, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ascii, ku, pa, ApOptions, ApReq, Authenticator, Checksum, EncKdcRepPart, EncTgsRepPart,
    EncryptedData, KdcOptions, KdcReq, KdcReqBody, KerberosTime, PaData, PrincipalName, TgsRep,
    TgsReq, Ticket,
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
pub fn tgs_exchange(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = tgs_inner(kdc, tgt, sname, realm);
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
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let nonce = {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).map_err(|e| Error::Io(e.to_string()))?;
        let n = u32::from_be_bytes(b);
        if n == 0 {
            1
        } else {
            n
        }
    };
    let till = KerberosTime(tgt.enc_part.endtime.0);
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();

    let body = KdcReqBody {
        kdc_options: KdcOptions::forwardable(),
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
        cusec: usec,
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
    let session_etype = EncryptionType::from_iana(enc_part.key.keytype)?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    Ok(TgsOutcome {
        ticket: inner.ticket,
        enc_part,
        session_key,
    })
}
