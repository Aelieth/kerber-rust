//! A′-3 R28: PAC at index 0, greet KDC-ISSUED, ku-5 body AD.

use std::sync::Arc;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt};
use krb5_kdc::{
    GREET_AD_TYPE, GREET_TEXT, GreetAuth, PrincipalStore, TEST_REALM, TEST_USER,
    bootstrap_documented, decrypt_ticket_part, documented_host, register_authdata,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{
    ApReq, Authenticator, AuthorizationData, AuthorizationDataValue, Checksum, EncTicketPart,
    EncryptedData, EncryptionKey, KdcOptions, KdcReq, KdcReqBody, KerberosTime, Microseconds,
    PaData, PrincipalName, TgsReq, Ticket, ku, pa,
};

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

fn wrap_if_relevant(inner: &[AuthorizationDataValue]) -> AuthorizationData {
    let wrapped = encode(&inner.to_vec()).unwrap();
    vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: wrapped.into(),
    }]
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
        cname: cname(),
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

fn ad_has_payload(ad: &[AuthorizationDataValue], ad_type: i32, payload: &[u8]) -> bool {
    for e in ad {
        if e.ad_type == pa::AD_IF_RELEVANT {
            if let Ok(inner) = decode::<AuthorizationData>(e.ad_data.as_ref())
                && ad_has_payload(&inner, ad_type, payload)
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
fn r28_pac_is_first_authdata() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 28001);
    let blob = b"r28-pac-first";
    let ad = and_or_ad(blob);
    let tgs = tgs_hand(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        28002,
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
    assert!(
        ad_has_payload(&ticket_ad, pa::AD_AND_OR, blob),
        "copied AD missing: {ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}

#[test]
fn r28_greet_is_kdc_issued() {
    register_authdata(Arc::new(GreetAuth));
    let (store, _) = bootstrap_documented().unwrap();
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
    let has_issued = ticket_ad.iter().any(|e| {
        if_relevant_inner_types(e)
            .iter()
            .any(|t| *t == pa::AD_KDC_ISSUED)
    });
    assert!(has_issued, "greet not KDC-ISSUED: {ticket_ad:?}");
    assert!(
        ad_has_payload(&ticket_ad, GREET_AD_TYPE, GREET_TEXT),
        "greet text missing: {ticket_ad:?}"
    );
}

#[test]
fn r28_greet_precedes_copied_ad() {
    register_authdata(Arc::new(GreetAuth));
    let (store, _) = bootstrap_documented().unwrap();
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
    let greet_i = ticket_ad.iter().position(|e| {
        if_relevant_inner_types(e)
            .iter()
            .any(|t| *t == pa::AD_KDC_ISSUED)
    });
    let copy_i = ticket_ad.iter().position(|e| {
        if_relevant_inner_types(e)
            .iter()
            .any(|t| *t == pa::AD_AND_OR)
    });
    assert!(
        greet_i.is_some() && copy_i.is_some() && greet_i < copy_i,
        "greet={greet_i:?} copy={copy_i:?} ad={ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}

#[test]
fn r28_body_ad_subkey_ku5_is_copied() {
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
        ad_has_payload(&ticket_ad, pa::AD_AND_OR, blob),
        "subkey ku5 AD missing: {ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}

#[test]
fn r28_body_ad_session_ku5_is_copied() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 28041);
    let blob = b"r28-session-ku5";
    let ad = and_or_ad(blob);
    let tgs = tgs_hand(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        documented_host(),
        28042,
        Some(enc_ad_usage(
            &issued.session_key,
            ku::TGS_REQ_AD_SUBKEY,
            &ad,
        )),
        None,
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    let ticket_ad = part.authorization_data.expect("ticket AD");
    assert!(
        ad_has_payload(&ticket_ad, pa::AD_AND_OR, blob),
        "session ku5 AD missing: {ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}

#[test]
fn r28_tgt_and_or_kept_through_tgs() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 28051);
    let keep = b"r28-tgt-keep";
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).unwrap();
    let mut ad = part.authorization_data.unwrap_or_default();
    ad.extend(and_or_ad(keep));
    part.authorization_data = Some(ad);
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = encrypt(&krbtgt.key, usage, &der).unwrap().into();
    let tgs = tgs_hand(
        ticket,
        &issued.session_key,
        documented_host(),
        28052,
        None,
        None,
    );
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let svc = host_part(&store, &out);
    let ticket_ad = svc.authorization_data.expect("ticket AD");
    assert!(
        ad_has_payload(&ticket_ad, pa::AD_AND_OR, keep),
        "TGT AND-OR not kept: {ticket_ad:?}"
    );
    assert!(first_is_pac(&ticket_ad), "PAC not first: {ticket_ad:?}");
}
