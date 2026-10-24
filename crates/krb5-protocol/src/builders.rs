//! AS-REQ / TGS-REQ / PA-ENC-TIMESTAMP builders (used by tests, KDC, client).

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, encrypt};
use krb5_types::{
    ApOptions, ApReq, AsReq, Authenticator, Checksum, EncryptedData, EncryptionKey, HostAddresses,
    KdcOptions, KdcReq, KdcReqBody, KerberosTime, Microseconds, PaData, PaEncTsEnc, PrincipalName,
    TgsReq, Ticket, ku, pa,
};

use crate::error::Error;

fn realm_string(realm: &str) -> Result<krb5_types::Realm, Error> {
    krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))
}

pub fn as_req(
    cname: PrincipalName,
    realm: &str,
    nonce: u32,
    padata: Option<Vec<PaData>>,
) -> Result<AsReq, Error> {
    let _ = realm_string(realm)?;
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

pub fn as_req_sname(
    cname: PrincipalName,
    realm: &str,
    nonce: u32,
    padata: Option<Vec<PaData>>,
    sname: PrincipalName,
    etypes: Vec<i32>,
) -> Result<AsReq, Error> {
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());
    Ok(AsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata,
        req_body: KdcReqBody {
            kdc_options: KdcOptions::forwardable(),
            cname: Some(cname),
            realm: realm_string(realm)?,
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
    }))
}

/// Encrypted under the long-term key, usage 1.
// MIT: `encts_process` (lib/krb5/krb/preauth_encts.c:87-89)
/// The time and its microseconds come from one reading.
pub fn pa_enc_timestamp(key: &ProtocolKey) -> Result<PaData, Error> {
    let (now, usec) = crate::auth_con::us_timeofday();
    pa_enc_timestamp_usec(key, &now, usec)
}

/// The microseconds are those of the given time.
pub fn pa_enc_timestamp_at(key: &ProtocolKey, now: &KerberosTime) -> Result<PaData, Error> {
    pa_enc_timestamp_usec(
        key,
        now,
        Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros()),
    )
}

// MIT: `pa_enc_ts_1` (lib/krb5/asn.1/asn1_k_encode.c:935-935)
/// pausec is omitted when 0.
fn pa_enc_timestamp_usec(
    key: &ProtocolKey,
    now: &KerberosTime,
    usec: Microseconds,
) -> Result<PaData, Error> {
    let ts = PaEncTsEnc {
        patimestamp: now.clone(),
        pausec: (usec.get() != 0).then_some(usec),
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

pub fn tgs_req(
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &str,
    cname: &PrincipalName,
    sname: PrincipalName,
    realm: &str,
    nonce: u32,
) -> Result<TgsReq, Error> {
    tgs_req_ex(TgsReqParams {
        ticket,
        session,
        crealm,
        cname,
        sname,
        realm,
        nonce,
        kdc_options: KdcOptions::forwardable(),
        additional_tickets: None,
        extra_padata: Vec::new(),
        etypes: EncryptionType::preferred()
            .iter()
            .map(|e| e.to_iana())
            .collect(),
        addresses: None,
        from: None,
        enc_authorization_data: None,
        till: None,
        subkey: None,
        time_offset: 0,
    })
}

// MIT: `k5_make_tgs_req` (lib/krb5/krb/send_tgs.c:119-119)
/// The parameter struct for tgs_req_ex, not a wire type.
pub struct TgsReqParams<'a> {
    pub ticket: Ticket,
    /// Checksums the body and encrypts the authenticator.
    pub session: &'a ProtocolKey,
    pub crealm: &'a str,
    pub cname: &'a PrincipalName,
    /// Owned because the body stores it.
    pub sname: PrincipalName,
    pub realm: &'a str,
    pub nonce: u32,
    pub kdc_options: KdcOptions,
    pub additional_tickets: Option<Vec<Ticket>>,
    /// Appended after the PA-TGS-REQ.
    pub extra_padata: Vec<PaData>,
    pub etypes: Vec<i32>,
    pub addresses: Option<HostAddresses>,
    pub from: Option<KerberosTime>,
    pub enc_authorization_data: Option<EncryptedData>,
    /// None is ten hours from now.
    pub till: Option<KerberosTime>,
    pub subkey: Option<&'a ProtocolKey>,
    pub time_offset: i64,
}

pub fn tgs_req_ex(p: TgsReqParams<'_>) -> Result<TgsReq, Error> {
    let TgsReqParams {
        ticket,
        session,
        crealm,
        cname,
        sname,
        realm,
        nonce,
        kdc_options,
        additional_tickets,
        extra_padata,
        etypes,
        addresses,
        from,
        enc_authorization_data,
        till,
        subkey,
        time_offset,
    } = p;

    let till = till.unwrap_or_else(|| {
        KerberosTime::now()
            .add_hours(10)
            .unwrap_or_else(|_| KerberosTime::now())
    });
    let body = KdcReqBody {
        kdc_options,
        cname: None,
        realm: krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        sname: Some(sname),
        from,
        till,
        rtime: None,
        nonce,
        etype: etypes,
        addresses,
        enc_authorization_data,
        additional_tickets,
    };
    let body_der = encode(&body)?;
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
    let mic = checksum(session, cksum_usage, &body_der)?;
    // MIT: `tgs_construct_ap_req` (lib/krb5/krb/send_tgs.c:82-82)
    let (now, usec) = crate::ap_req::stamped(time_offset);
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::try_ascii(crealm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        cname: cname.clone(),
        cksum: Some(Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: usec,
        ctime: now,
        subkey: subkey.map(|k| EncryptionKey {
            keytype: k.etype().to_iana(),
            keyvalue: k.as_bytes().to_vec().into(),
        }),
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
