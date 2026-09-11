//! A′-3 item 13: `handle_authdata` copy / filter / mandatory.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt};
use krb5_kdc::{
    Error, PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{
    ApReq, Authenticator, AuthorizationData, AuthorizationDataValue, Checksum, EncTicketPart,
    EncryptedData, KdcOptions, KdcReq, KdcReqBody, KerberosTime, Microseconds, PaData,
    PrincipalName, TgsReq, Ticket, err, ku, pa,
};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn user_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn cname() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn host_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let host = documented_host();
    let key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn wrap_if_relevant(inner: AuthorizationData) -> AuthorizationData {
    let wrapped = encode(&inner).unwrap();
    vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: wrapped.into(),
    }]
}

fn enc_ad(session: &ProtocolKey, ad: &AuthorizationData) -> EncryptedData {
    let usage = KeyUsage::new(ku::TGS_REQ_AD_SESSKEY).unwrap();
    let cipher = encrypt(session, usage, &encode(ad).unwrap()).unwrap();
    EncryptedData {
        etype: session.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    }
}

fn tgs_with_enc_ad(
    ticket: Ticket,
    session: &ProtocolKey,
    sname: PrincipalName,
    nonce: u32,
    enc_authorization_data: EncryptedData,
) -> TgsReq {
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());
    let body = KdcReqBody {
        kdc_options: KdcOptions::forwardable(),
        cname: None,
        realm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        sname: Some(sname),
        from: None,
        till,
        rtime: None,
        nonce,
        etype: vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
        addresses: None,
        enc_authorization_data: Some(enc_authorization_data),
        additional_tickets: None,
    };
    let body_der = encode(&body).unwrap();
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM).unwrap();
    let mic = checksum(session, cksum_usage, &body_der).unwrap();
    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        cname: cname(),
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
    let auth_der = encode(&authenticator).unwrap();
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_cipher = encrypt(session, auth_usage, &auth_der).unwrap();
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: krb5_types::ApOptions::none(),
        ticket,
        authenticator: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: auth_cipher.into(),
        },
    };
    TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(vec![PaData {
            padata_type: pa::TGS_REQ,
            padata_value: encode(&ap).unwrap().into(),
        }]),
        req_body: body,
    })
}

fn ad_has_payload(ad: &[AuthorizationDataValue], ad_type: i32, payload: &[u8]) -> bool {
    for e in ad {
        if e.ad_type == pa::AD_IF_RELEVANT {
            if let Ok(inner) = decode::<AuthorizationData>(e.ad_data.as_ref())
                && ad_has_payload(&inner, ad_type, payload)
            {
                return true;
            }
        } else if e.ad_type == ad_type && e.ad_data.as_ref() == payload {
            return true;
        }
    }
    false
}

#[test]
fn tgs_copies_if_relevant_body_authdata() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 13001);
    let blob = b"kerber-ad-copy";
    let ad = wrap_if_relevant(vec![AuthorizationDataValue {
        ad_type: pa::AD_AND_OR,
        ad_data: blob.to_vec().into(),
    }]);
    let tgs = tgs_with_enc_ad(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        13002,
        enc_ad(&issued.session_key, &ad),
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let ad = part.authorization_data.expect("ticket AD");
    assert!(
        ad_has_payload(&ad, pa::AD_AND_OR, blob),
        "copied AD missing: {ad:?}"
    );
}

#[test]
fn tgs_mandatory_for_kdc_is_handle_authdata() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 13011);
    let ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_MANDATORY_FOR_KDC,
        ad_data: Vec::<u8>::new().into(),
    }];
    let tgs = tgs_with_enc_ad(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        13012,
        enc_ad(&issued.session_key, &ad),
    );
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::POLICY, Some("HANDLE_AUTHDATA")));
}

#[test]
fn tgs_strips_kdc_issued_if_relevant_keeps_sibling() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 13021);
    let keep = b"keep-me";
    let mut ad = wrap_if_relevant(vec![AuthorizationDataValue {
        ad_type: pa::AD_WIN2K_PAC,
        ad_data: b"dummy-pac".to_vec().into(),
    }]);
    ad.extend(wrap_if_relevant(vec![AuthorizationDataValue {
        ad_type: pa::AD_AND_OR,
        ad_data: keep.to_vec().into(),
    }]));
    let tgs = tgs_with_enc_ad(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        13022,
        enc_ad(&issued.session_key, &ad),
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let ticket_ad = part.authorization_data.expect("ticket AD");
    assert!(
        ad_has_payload(&ticket_ad, pa::AD_AND_OR, keep),
        "sibling AD missing: {ticket_ad:?}"
    );
    assert!(
        !ad_has_payload(&ticket_ad, pa::AD_WIN2K_PAC, b"dummy-pac"),
        "KDC-issued IF-RELEVANT kept: {ticket_ad:?}"
    );
}

#[test]
fn tgs_body_ad_decrypt_fail_is_handle_authdata() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 13031);
    let tgs = tgs_with_enc_ad(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        13032,
        EncryptedData {
            etype: issued.session_key.etype().to_iana(),
            kvno: None,
            cipher: vec![0u8; 48].into(),
        },
    );
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BAD_INTEGRITY, Some("HANDLE_AUTHDATA")));
}
