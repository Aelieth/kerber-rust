//! TGS authorization data: `handle_authdata`'s copy, filter and mandatory checks,
//! `require_auth`, CAMMAC extraction, `GET_AUTH_INDICATORS`, the PAC at index 0, the greet
//! module's KDC-issued element, body AD under key usage 5, and a CAMMAC KDC verifier with an
//! unkeyed checksum skipped.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, unkeyed_checksum,
};
use krb5_kdc::testrealm::{GREET_AD_TYPE, GREET_TEXT, GreetAuth};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_host};
use krb5_kdc::{Error, PrincipalStore, issue_tgs};

use krb5_protocol::tgs_req;
use krb5_testkit::{krbtgt, status, user, user_as, wrap_if_relevant};
use krb5_types::cammac::{Cammac, VerifierMac};
use krb5_types::{
    ApReq, Authenticator, AuthorizationData, AuthorizationDataValue, Checksum, EncTicketPart,
    EncryptedData, EncryptionKey, KdcOptions, KdcReq, KdcReqBody, KerberosTime, Microseconds,
    PaData, PrincipalName, TgsReq, Ticket, err, ku, pa,
};
use std::sync::Arc;

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
        cname: user(),
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
    assert_eq!(status(&err), (err::BAD_INTEGRITY, Some("HANDLE_AUTHDATA")));
}

fn enc_ad_usage(key: &ProtocolKey, usage: u32, ad: &AuthorizationData) -> EncryptedData {
    let usage = KeyUsage::new(usage).unwrap();
    let cipher = encrypt(key, usage, &encode(ad).unwrap()).unwrap();
    EncryptedData {
        etype: key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    }
}

fn tgs_hand(
    ticket: Ticket,
    session: &ProtocolKey,
    sname: PrincipalName,
    nonce: u32,
    enc_authorization_data: Option<EncryptedData>,
    subkey: Option<&ProtocolKey>,
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
        enc_authorization_data,
        additional_tickets: None,
    };
    let body_der = encode(&body).unwrap();
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM).unwrap();
    let mic = checksum(session, cksum_usage, &body_der).unwrap();
    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        cname: user(),
        cksum: Some(Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros()),
        ctime: now,
        subkey: subkey.map(|k| EncryptionKey {
            keytype: k.etype().to_iana(),
            keyvalue: k.as_bytes().to_vec().into(),
        }),
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

fn ad_has_payload_a3_r28(ad: &[AuthorizationDataValue], ad_type: i32, payload: &[u8]) -> bool {
    for e in ad {
        if e.ad_type == pa::AD_IF_RELEVANT {
            if let Ok(inner) = decode::<AuthorizationData>(e.ad_data.as_ref())
                && ad_has_payload_a3_r28(&inner, ad_type, payload)
            {
                return true;
            }
        } else if e.ad_type == pa::AD_KDC_ISSUED {
            if e.ad_data
                .as_ref()
                .windows(payload.len())
                .any(|w| w == payload)
                && ad_type == GREET_AD_TYPE
            {
                return true;
            }
        } else if e.ad_type == ad_type && e.ad_data.as_ref() == payload {
            return true;
        }
    }
    false
}

fn first_is_pac(ad: &[AuthorizationDataValue]) -> bool {
    let Some(e) = ad.first() else {
        return false;
    };
    if e.ad_type != pa::AD_IF_RELEVANT {
        return false;
    }
    let Ok(inner) = decode::<AuthorizationData>(e.ad_data.as_ref()) else {
        return false;
    };
    inner.first().is_some_and(|i| i.ad_type == pa::AD_WIN2K_PAC)
}

fn if_relevant_inner_types(e: &AuthorizationDataValue) -> Vec<i32> {
    if e.ad_type != pa::AD_IF_RELEVANT {
        return Vec::new();
    }
    decode::<AuthorizationData>(e.ad_data.as_ref())
        .map(|inner| inner.iter().map(|i| i.ad_type).collect())
        .unwrap_or_default()
}

fn and_or_ad(blob: &[u8]) -> AuthorizationData {
    wrap_if_relevant(&[AuthorizationDataValue {
        ad_type: pa::AD_AND_OR,
        ad_data: blob.to_vec().into(),
    }])
}

#[test]
fn greet_is_kdc_issued() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.plugins.register_authdata(Arc::new(GreetAuth));
    let issued = user_as(&store, 28011);
    let tgs = tgs_hand(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        28012,
        None,
        None,
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let ticket_ad = part.authorization_data.expect("ticket AD");
    let has_issued = ticket_ad
        .iter()
        .any(|e| if_relevant_inner_types(e).contains(&pa::AD_KDC_ISSUED));
    assert!(has_issued, "greet not KDC-ISSUED: {ticket_ad:?}");
    assert!(
        ad_has_payload_a3_r28(&ticket_ad, GREET_AD_TYPE, GREET_TEXT),
        "greet text missing: {ticket_ad:?}"
    );
}

#[test]
fn greet_precedes_copied_ad() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.plugins.register_authdata(Arc::new(GreetAuth));
    let issued = user_as(&store, 28021);
    let blob = b"r28-greet-order";
    let ad = and_or_ad(blob);
    let tgs = tgs_hand(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        28022,
        Some(enc_ad_usage(
            &issued.session_key,
            ku::TGS_REQ_AD_SESSKEY,
            &ad,
        )),
        None,
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let ticket_ad = part.authorization_data.expect("ticket AD");
    let greet_i = ticket_ad
        .iter()
        .position(|e| if_relevant_inner_types(e).contains(&pa::AD_KDC_ISSUED));
    let copy_i = ticket_ad
        .iter()
        .position(|e| if_relevant_inner_types(e).contains(&pa::AD_AND_OR));
    assert!(
        greet_i.is_some() && copy_i.is_some() && greet_i < copy_i,
        "greet={greet_i:?} copy={copy_i:?} ad={ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}

#[test]
fn body_ad_subkey_ku5_is_copied() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 28031);
    let blob = b"r28-subkey-ku5";
    let ad = and_or_ad(blob);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).unwrap();
    let tgs = tgs_hand(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        28032,
        Some(enc_ad_usage(&sub, ku::TGS_REQ_AD_SUBKEY, &ad)),
        Some(&sub),
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let ticket_ad = part.authorization_data.expect("ticket AD");
    assert!(
        ad_has_payload_a3_r28(&ticket_ad, pa::AD_AND_OR, blob),
        "subkey ku5 AD missing: {ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}

fn tgt_key(store: &PrincipalStore) -> (ProtocolKey, u32) {
    let e = store
        .get_name(&krbtgt())
        .unwrap()
        .first_current_key()
        .unwrap();
    (e.key.clone(), e.kvno)
}

fn decrypt_tgt(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let (key, _) = tgt_key(store);
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    decode(&decrypt(&key, usage, issued.rep.0.ticket.enc_part.cipher.as_ref()).unwrap()).unwrap()
}

fn indicator_elements() -> AuthorizationData {
    vec![AuthorizationDataValue {
        ad_type: pa::AD_AUTH_INDICATOR,
        ad_data: encode(&vec!["pkinit".to_string()]).unwrap().into(),
    }]
}

fn kdcver_der(part: &EncTicketPart, elements: &[AuthorizationDataValue]) -> Vec<u8> {
    let mut ck = part.clone();
    ck.authorization_data = Some(elements.to_vec());
    encode(&ck).unwrap()
}

fn attach_cammac(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs, cksumtype: i32) -> Ticket {
    let (key, kvno) = tgt_key(store);
    let mut part = decrypt_tgt(store, issued);
    let elements = indicator_elements();
    let der = kdcver_der(&part, &elements);
    let usage = KeyUsage::new(ku::CAMMAC).unwrap();
    let mac = if cksumtype == 0 {
        checksum(&key, usage, &der).unwrap()
    } else {
        unkeyed_checksum(cksumtype, &der).unwrap()
    };
    let cammac = Cammac {
        elements,
        kdc_verifier: Some(VerifierMac {
            identifier: None,
            kvno: Some(kvno),
            enctype: None,
            mac: Checksum {
                cksumtype,
                checksum: mac.into(),
            },
        }),
        svc_verifier: None,
        other_verifiers: None,
    };
    let wrapped = wrap_if_relevant(&[AuthorizationDataValue {
        ad_type: pa::AD_CAMMAC,
        ad_data: encode(&cammac).unwrap().into(),
    }]);
    let mut ad = part.authorization_data.take().unwrap_or_default();
    ad.extend(wrapped);
    part.authorization_data = Some(ad);
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(&key, usage, &encode(&part).unwrap()).unwrap();
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = cipher.into();
    ticket
}

fn tgs_require_auth(
    store: &mut PrincipalStore,
    ticket: Ticket,
    session: &ProtocolKey,
    nonce: u32,
    req: &str,
) -> Result<krb5_kdc::IssuedTgs, Error> {
    store
        .set_string(&documented_host(), "require_auth", Some(req))
        .unwrap();
    let tgs = tgs_req(
        ticket,
        session,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap();
    issue_tgs(store, &tgs)
}

fn expect_higher(
    store: &mut PrincipalStore,
    issued: &krb5_kdc::IssuedAs,
    cksumtype: i32,
    nonce: u32,
) {
    let ticket = attach_cammac(store, issued, cksumtype);
    let err = tgs_require_auth(store, ticket, &issued.session_key, nonce, "pkinit").unwrap_err();
    assert_eq!(
        status(&err),
        (err::POLICY, Some("HIGHER_AUTHENTICATION_REQUIRED"))
    );
}

#[test]
fn cammac_rsa_md5_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29001);
    expect_higher(&mut store, &issued, 7, 29002);
}

#[test]
fn cammac_sha1_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29003);
    expect_higher(&mut store, &issued, 14, 29004);
}

#[test]
fn cammac_md4_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29005);
    expect_higher(&mut store, &issued, 2, 29006);
}

#[test]
fn cammac_nist_sha_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29007);
    expect_higher(&mut store, &issued, 9, 29008);
}

#[test]
fn cammac_cksumtype_zero_kdcver_is_skipped() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29009);
    expect_higher(&mut store, &issued, 0, 29010);
}

#[test]
fn cammac_unkeyed_does_not_satisfy_any_match() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 29011);
    let ticket = attach_cammac(&store, &issued, 7);
    let err = tgs_require_auth(
        &mut store,
        ticket,
        &issued.session_key,
        29012,
        "pkinit spake",
    )
    .unwrap_err();
    assert_eq!(
        status(&err),
        (err::POLICY, Some("HIGHER_AUTHENTICATION_REQUIRED"))
    );
}
