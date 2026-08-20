//! Client-side AS-REQ / TGS-REQ builders used by tests, the consumer, and tools.
//!
//! These construct RFC 4120 PDUs; they do not issue tickets.

use krb5_asn1::encode;
use krb5_crypto::{checksum, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ascii, ku, pa, ApOptions, ApReq, AsReq, Authenticator, Checksum, EncryptedData, KdcOptions,
    KdcReq, KdcReqBody, KerberosTime, PaData, PaEncTsEnc, PrincipalName, TgsReq, Ticket,
};

use crate::error::Error;

/// AS-REQ for `cname@realm` with optional padata.
#[must_use]
pub fn as_req(cname: PrincipalName, realm: &str, nonce: u32, padata: Option<Vec<PaData>>) -> AsReq {
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    AsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata,
        req_body: KdcReqBody {
            kdc_options: KdcOptions::forwardable(),
            cname: Some(cname),
            realm: ascii(realm),
            sname: Some(PrincipalName::krbtgt(realm)),
            from: None,
            till: KerberosTime::now().add_hours(10),
            rtime: None,
            nonce,
            etype: etypes,
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    })
}

/// PA-ENC-TIMESTAMP encrypted with the client long-term key (usage 1).
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn pa_enc_timestamp(key: &ProtocolKey) -> Result<PaData, Error> {
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let ts = PaEncTsEnc {
        patimestamp: now,
        pausec: Some(usec),
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

/// TGS-REQ with PA-TGS-REQ (AP-REQ wrapping `ticket`).
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn tgs_req(
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &str,
    cname: &PrincipalName,
    sname: PrincipalName,
    realm: &str,
    nonce: u32,
) -> Result<TgsReq, Error> {
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
        till: KerberosTime::now().add_hours(10),
        rtime: None,
        nonce,
        etype: etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_der = encode(&body)?;
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
    let mic = checksum(session, cksum_usage, &body_der)?;
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: ascii(crealm),
        cname: cname.clone(),
        cksum: Some(Checksum {
            cksumtype: session.etype().checksum_type(),
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
    let auth_cipher = encrypt(session, auth_usage, &auth_der)?;
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket,
        authenticator: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: auth_cipher.into(),
        },
    };
    Ok(TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(vec![PaData {
            padata_type: pa::TGS_REQ,
            padata_value: encode(&ap)?.into(),
        }]),
        req_body: body,
    }))
}
