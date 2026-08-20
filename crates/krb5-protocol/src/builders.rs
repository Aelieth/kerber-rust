//! AS-REQ / TGS-REQ / PA-ENC-TIMESTAMP builders (used by tests, KDC, client).

use krb5_asn1::encode;
use krb5_crypto::{checksum, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ascii, ku, pa, ApOptions, ApReq, AsReq, Authenticator, Checksum, EncryptedData, KdcOptions,
    KdcReq, KdcReqBody, KerberosTime, Microseconds, PaData, PaEncTsEnc, PrincipalName, TgsReq,
    Ticket,
};

use crate::error::Error;

/// AS-REQ for `cname@realm` with optional padata.
#[must_use]
pub fn as_req(cname: PrincipalName, realm: &str, nonce: u32, padata: Option<Vec<PaData>>) -> AsReq {
    as_req_sname(
        cname,
        realm,
        nonce,
        padata,
        PrincipalName::krbtgt(realm),
        EncryptionType::preferred()
            .iter()
            .map(|e| e.to_iana())
            .collect(),
    )
}

/// AS-REQ with an explicit `sname` and etype list.
#[must_use]
pub fn as_req_sname(
    cname: PrincipalName,
    realm: &str,
    nonce: u32,
    padata: Option<Vec<PaData>>,
    sname: PrincipalName,
    etypes: Vec<i32>,
) -> AsReq {
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());
    AsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata,
        req_body: KdcReqBody {
            kdc_options: KdcOptions::forwardable(),
            cname: Some(cname),
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
        },
    })
}

/// PA-ENC-TIMESTAMP encrypted with the client long-term key (usage 1).
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn pa_enc_timestamp(key: &ProtocolKey) -> Result<PaData, Error> {
    pa_enc_timestamp_at(key, &KerberosTime::now())
}

/// PA-ENC-TIMESTAMP with an explicit client time (SKEW retry).
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn pa_enc_timestamp_at(key: &ProtocolKey, now: &KerberosTime) -> Result<PaData, Error> {
    let ts = PaEncTsEnc {
        patimestamp: now.clone(),
        pausec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
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
    tgs_req_ex(
        ticket,
        session,
        crealm,
        cname,
        sname,
        realm,
        nonce,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
    )
}

/// TGS-REQ with explicit KDCOptions, additional-tickets, and extra padata.
///
/// # Errors
///
/// Returns crypto or DER failures.
#[allow(clippy::too_many_arguments)]
pub fn tgs_req_ex(
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &str,
    cname: &PrincipalName,
    sname: PrincipalName,
    realm: &str,
    nonce: u32,
    kdc_options: KdcOptions,
    additional_tickets: Option<Vec<Ticket>>,
    extra_padata: Vec<PaData>,
) -> Result<TgsReq, Error> {
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());
    let body = KdcReqBody {
        kdc_options,
        cname: None,
        realm: krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        sname: Some(sname),
        from: None,
        till,
        rtime: None,
        nonce,
        etype: etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets,
    };
    let body_der = encode(&body)?;
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
    let mic = checksum(session, cksum_usage, &body_der)?;
    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::try_ascii(crealm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        cname: cname.clone(),
        cksum: Some(Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros()),
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
    let mut padata = vec![PaData {
        padata_type: pa::TGS_REQ,
        padata_value: encode(&ap)?.into(),
    }];
    padata.extend(extra_padata);
    Ok(TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(padata),
        req_body: body,
    }))
}
