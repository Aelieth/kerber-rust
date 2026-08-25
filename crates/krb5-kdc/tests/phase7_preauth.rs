//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    decrypt, dh_generate, dh_shared, encrypt, octetstring2key, p256_generate, string_to_key,
    EncryptionType, KeyUsage, ProtocolKey, OAKLEY_2048,
};
use krb5_kdc::{
    as_req, bootstrap_documented, decrypt_ticket_part, documented_admin_id, documented_host,
    pa_enc_timestamp, pac_from_ticket_part, sign_pac, tgs_req, ticket_checksum_der, verify_pac,
    verify_pac_signatures, wrap_win2k_pac, Acl, AdminOp, Error, PrincipalStore, S2K_ITERS,
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
};
use krb5_protocol::{
    apply_strengthen, armor_key, as_req_sname, attach_fast, build_fast_armor, pa_for_user,
    pa_pac_options, pa_pk_as_req, pa_pk_as_req_agile, pa_pk_as_req_spki, pa_spake_response,
    pa_spake_support, pkinit_reply_key, pkinit_reply_key_agile, tgs_req_ex, unwrap_fast_rep,
};
use krb5_types::pac::{
    parse_kerb_validation_info, Pac, RpcSid, PAC_LOGON_INFO, PAC_SERVER_CHECKSUM,
    PAC_TICKET_CHECKSUM,
};
use krb5_types::{
    ascii, err, flag_bit, ku, pa, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart,
    KdcOptions, MethodData, PrincipalName,
};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    if let Ok(EncAsRepPart(p)) = decode::<EncAsRepPart>(plain) {
        return p;
    }
    if let Ok(EncTgsRepPart(p)) = decode::<EncTgsRepPart>(plain) {
        return p;
    }
    decode::<EncKdcRepPart>(plain).expect("enc-part")
}

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = password_key(name, password);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS")
}

#[test]
fn kpasswd_bumps_kvno_keeps_old_keys_and_switches_password() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let before = store.get_name(&cname).expect("user");
    let old_kvno = before.keys.iter().map(|k| k.kvno).max().expect("kvno");
    let old_count = before.keys.len();
    store
        .change_password(
            &acl,
            &format!("{TEST_ADMIN}@{TEST_REALM}"),
            &cname,
            b"brand-new-pass",
        )
        .expect("cpw");
    let after = store.get_name(&cname).expect("user");
    let new_kvno = after.keys.iter().map(|k| k.kvno).max().expect("kvno");
    assert_eq!(new_kvno, old_kvno + 1);
    assert!(after.keys.len() > old_count, "prior kvnos must remain");
    assert!(after.keys.iter().any(|k| k.kvno == old_kvno));

    let new_key = password_key(TEST_USER, b"brand-new-pass");
    let ok = as_req(
        cname.clone(),
        TEST_REALM,
        101,
        Some(vec![pa_enc_timestamp(&new_key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &ok).expect("AS with new password");

    let old = as_req(
        cname,
        TEST_REALM,
        102,
        Some(vec![pa_enc_timestamp(&user_key()).expect("pa")]),
    )
    .unwrap();
    match krb5_kdc::issue_as(&store, &old) {
        Err(
            Error::Crypto(_)
            | Error::Protocol {
                code: err::PREAUTH_FAILED,
                ..
            },
        ) => {}
        other => panic!("old password must fail AS, got {other:?}"),
    }
}

#[test]
fn kpasswd_denied_without_changepw_acl() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let acl = Acl::parse("admin@KERBER.TEST a\n");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let err = store
        .change_password(&acl, "admin@KERBER.TEST", &cname, b"x")
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    assert!(acl
        .check("admin@KERBER.TEST", AdminOp::ChangePassword)
        .is_err());
    let acl_c = Acl::parse("admin@KERBER.TEST c\n");
    store
        .change_password(&acl_c, "admin@KERBER.TEST", &cname, b"ok-pass")
        .expect("c bit allows cpw");
}

#[test]
fn fast_as_exchange_strengthen_and_finished() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 201);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let inner = vec![pa_enc_timestamp(&key).expect("pa")];
    let mut req = as_req(cname.clone(), TEST_REALM, 202, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    let issued = krb5_kdc::issue_as(&store, &req).expect("FAST AS");
    let fast = unwrap_fast_rep(&akey, &issued.rep.0.padata).expect("FAST rep");
    assert!(fast.finished.is_some(), "FAST finished required on AS-REP");
    let sk = fast.strengthen_key.expect("strengthen-key");
    let reply = apply_strengthen(&sk, &key).expect("CF2");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("AS enc");
    assert_eq!(plain.first().copied(), Some(0x79));
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 202);
    assert!(enc.flags.pre_authent());
}

#[test]
fn spake_challenge_then_as_rep() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 301, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie");
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let mut req2 = as_req(cname, TEST_REALM, 302, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, spake_key) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.padata_value.clone(),
        },
    ]);
    let issued = krb5_kdc::issue_as(&store, &req2).expect("SPAKE AS");
    assert_eq!(issued.as_rep_key.as_bytes(), spake_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&spake_key, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 302);
}

#[test]
fn pkinit_advertised_in_method_data_when_ca_enabled() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 400, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().any(|p| p.padata_type == pa::PK_AS_REQ),
        "PA-PK-AS-REQ must be advertised when the CA is provisioned: {method:?}"
    );
    assert!(method.iter().any(|p| p.padata_type == pa::ENC_TIMESTAMP));
    assert!(method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2));
}

#[test]
fn pkinit_not_advertised_without_ca() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    assert!(store.pkinit_ca.is_none());
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 399, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().all(|p| p.padata_type != pa::PK_AS_REQ),
        "PA-PK-AS-REQ must not be advertised without a CA"
    );
}

#[test]
fn pkinit_ecdh_reply_key() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca.as_ref().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa = pa_pk_as_req(&kp.public, &ca).expect("PA-PK-AS-REQ");
    let req = as_req(cname, TEST_REALM, 401, Some(vec![pa])).unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply =
        pkinit_reply_key(&kp.secret, &issued.rep.0.padata, et, &ca.ca_cert).expect("ECDH key");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 401);
}

#[test]
fn pkinit_ecdh_rfc8636_sha256_kdf() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca.as_ref().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa = pa_pk_as_req_agile(&kp.public, &ca).expect("PA-PK-AS-REQ agile");
    let req = as_req(cname.clone(), TEST_REALM, 411, Some(vec![pa])).unwrap();
    let as_req_der = encode(&req).expect("AS-REQ");
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS agile");
    let raw_rep = issued
        .rep
        .0
        .padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .expect("PA-PK-AS-REP");
    assert_eq!(
        krb5_types::pkinit::pa_pk_as_rep_kdf_oid(raw_rep.padata_value.as_ref()).as_deref(),
        Some(krb5_types::pkinit::KDF_AH_SHA256_OID)
    );
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply = pkinit_reply_key_agile(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    )
    .expect("agile ECDH key");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let o2k = pkinit_reply_key(&kp.secret, &issued.rep.0.padata, et, &ca.ca_cert);
    assert!(o2k.is_err(), "o2k helper must not silently decrypt agile");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 411);
}

#[test]
fn pkinit_modp14_reply_key() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca.as_ref().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = dh_generate(&OAKLEY_2048).expect("client DH");
    let spki = krb5_types::pkinit::encode_dh_spki(&OAKLEY_2048.prime_bytes(), &kp.public);
    let pa = pa_pk_as_req_spki(&spki, &ca).expect("PA-PK-AS-REQ");
    let req = as_req(cname, TEST_REALM, 404, Some(vec![pa])).unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT DH AS");
    let kdc_y = kdc_dh_public_from_rep(issued.rep.0.padata.as_deref(), &ca.ca_cert);
    let shared = dh_shared(&OAKLEY_2048, &kp.secret, &kdc_y).expect("DH");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply = octetstring2key(et, &shared).expect("o2k");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 404);
}

fn kdc_dh_public_from_rep(padata: Option<&[krb5_types::PaData]>, trust: &[u8]) -> Vec<u8> {
    let raw = padata
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .expect("PA-PK-AS-REP");
    let rep: krb5_types::pkinit::PaPkAsRep = decode(raw.padata_value.as_ref()).expect("rep");
    let info = match rep {
        krb5_types::pkinit::PaPkAsRep::DhInfo(i) => i,
        krb5_types::pkinit::PaPkAsRep::EncKeyPack(_) => panic!("encKeyPack"),
    };
    let inner =
        krb5_types::pkinit::cms_verify(info.dh_signed_data.as_ref(), trust).expect("KDC CMS");
    let payload = krb5_types::pkinit::decode_kdc_dh_point(&inner).expect("KdcDHKeyInfo");
    krb5_types::pkinit::der_integer_unsigned(&payload).expect("DH INTEGER")
}

#[test]
fn pkinit_forged_cms_is_rejected() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: krb5_types::Microseconds::ZERO,
            ctime: krb5_types::KerberosTime::now(),
            nonce: 1,
            pa_checksum: None,
        },
        client_public_value: Some(kp.public.clone().into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack).expect("authpack");
    let req_body = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: inner.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    let pa = krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&req_body).expect("pa").into(),
    };
    let req = as_req(cname, TEST_REALM, 402, Some(vec![pa])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("forged CMS");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_without_provisioned_ca_is_rejected() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    assert!(store.pkinit_ca.is_none());
    let ca = krb5_types::pkinit::PkinitCa::generate().expect("unrelated CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa = pa_pk_as_req(&kp.public, &ca).expect("PA-PK-AS-REQ");
    let req = as_req(cname, TEST_REALM, 403, Some(vec![pa])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("PKINIT off");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn as_and_tgs_tickets_carry_verifiable_pac() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 501);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let tgt_part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&tgt_part).expect("PAC on TGT");
    verify_pac(&pac, &krbtgt.key, &krbtgt.key).expect("TGT PAC");

    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        502,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &tgs_out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&svc).expect("PAC on service ticket");
    verify_pac(&pac, &host.key, &krbtgt.key).expect("service PAC");
    let ident = store.pac_identity(&cname, TEST_REALM);
    let signed = sign_pac(
        &cname,
        tgt_part.authtime.unix_seconds(),
        &host.key,
        &krbtgt.key,
        &[],
        &ident,
        None,
    )
    .expect("sign");
    verify_pac(&signed, &host.key, &krbtgt.key).expect("re-sign");
}

#[test]
fn s4u2self_impersonates_user() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 601);
    let pa = pa_for_user(&tgt.session_key, admin.clone(), TEST_REALM).expect("PA-FOR-USER");
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        602,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("S4U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Self");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    verify_pac(&pac, &host.key, &krbtgt.key).expect("S4U PAC");
}

#[test]
fn s4u2proxy_takes_cname_from_evidence() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 701);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        702,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 703);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        704,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Proxy");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    let pac = pac_from_ticket_part(&part).expect("copied PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_eq!(logon.user_id, store.get_name(&admin).unwrap().rid);
    assert_eq!(logon.effective_name.value, TEST_ADMIN);
}

#[test]
fn s4u2proxy_rejects_non_forwardable_evidence() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 711);
    let evidence_tgs = tgs_req_ex(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        712,
        KdcOptions::none(),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("non-forwardable evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_long = store.get_name(&user).unwrap().best_key().unwrap();
    let ev_part = decrypt_ticket_part(&user_long.key, &evidence.rep.0.ticket).expect("ev");
    assert!(
        !ev_part.flags.forwardable(),
        "fixture must be a non-forwardable evidence ticket"
    );
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 713);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        714,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("expected BADOPTION, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_rejects_malformed_pac_options() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 721);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        722,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 723);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let bad = krb5_types::PaData {
        padata_type: pa::PAC_OPTIONS,
        padata_value: b"not-der".to_vec().into(),
    };
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        724,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        vec![bad],
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("expected BADOPTION for malformed PA-PAC-OPTIONS, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_honors_pac_options_rbcd() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 731);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        732,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 733);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        734,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        vec![pa_pac_options(true).expect("PA-PAC-OPTIONS")],
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("RBCD without allow-list must deny, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_rbcd_allowed_from_succeeds() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_from(&documented_host(), &user.components_joined());
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 741);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        742,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 743);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        744,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        vec![pa_pac_options(true).expect("PA-PAC-OPTIONS")],
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("RBCD allowed");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
}

#[test]
fn u2u_encrypts_ticket_in_additional_tgt_session() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 801);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 802);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        803,
        opts,
        Some(vec![admin_tgt.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("U2U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("U2U");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    assert!(
        decrypt_ticket_part(&host.key, &out.rep.0.ticket).is_err(),
        "U2U ticket must not use the service long-term key"
    );
    let part = decrypt_ticket_part(&admin_tgt.session_key, &out.rep.0.ticket).expect("U2U enc");
    assert_eq!(part.cname.components_joined(), TEST_USER);
    assert_eq!(part.key.keyvalue.as_ref(), out.session_key.as_bytes());
}

#[test]
fn s4u2self_bad_checksum_rejected() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 901);
    let mut pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let mut for_user: krb5_types::s4u::PaForUser =
        decode(pa.padata_value.as_ref()).expect("PaForUser");
    let mut ck = for_user.cksum.checksum.to_vec();
    ck[0] ^= 0xff;
    for_user.cksum.checksum = ck.into();
    pa.padata_value = encode(&for_user).expect("re-encode").into();
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        902,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("TGS-REQ");
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::INAPP_CKSUM);
}

#[test]
fn as_wrong_realm_is_chaseable() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 50, None).unwrap();
    req.0.req_body.realm = ascii("OTHER.TEST");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::WRONG_REALM);
    assert_eq!(std::str::from_utf8(e.realm.as_bytes()).unwrap(), TEST_REALM);
}

#[test]
fn tgs_referral_uses_interrealm_key_and_transited() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 51);
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        other.clone(),
        TEST_REALM,
        52,
    )
    .expect("referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("referral");
    assert_eq!(out.rep.0.ticket.sname, other);
    let ir = store.get_name(&other).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&ir.key, &out.rep.0.ticket).expect("inter-realm enc");
    assert!(
        part.transited.realms().is_empty(),
        "first-hop referral transited excludes client realm: {:?}",
        part.transited.realms()
    );
}

#[test]
fn as_rep_advertises_supported_enctypes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 53);
    let pa = issued.rep.0.padata.as_ref().expect("padata");
    let raw = pa
        .iter()
        .find(|p| p.padata_type == pa::SUPPORTED_ENCTYPES)
        .expect("PA-SUPPORTED-ENCTYPES")
        .padata_value
        .as_ref();
    assert!(raw.len() >= 4);
    let bits = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap();
    let expect = user.supported_enctypes_mask();
    assert_eq!(bits, expect, "bits must match keys on the principal");
    assert_ne!(
        bits, 0x18,
        "must not be the static AES-SHA1 mask; SHA-2 keys are present"
    );
    assert_eq!(
        bits & 0x18,
        0x18,
        "AES-SHA1 17/18 still advertised when those keys exist"
    );
}

#[test]
fn pac_logon_info_is_ndr() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 54);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("parse");
    let logon = parsed
        .buffers
        .iter()
        .find(|b| b.kind == krb5_types::pac::PAC_LOGON_INFO)
        .expect("logon");
    let (c, r) = krb5_types::pac::parse_logon_info(&logon.data).expect("NDR");
    assert_eq!(c, TEST_USER);
    assert_eq!(r, TEST_REALM);
}

#[test]
fn tgs_canonicalize_issues_cross_realm_krbtgt() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 61);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        "OTHER.TEST",
        62,
        KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("cross-realm TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("referral TGS");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/OTHER.TEST"
    );
}

#[test]
fn tgs_referral_ad_kerber_test_issues_krbtgt() {
    // In-tree hop for the A5 realm names. Live AD.KERBER.TEST↔KERBER.TEST
    // trust is not configured on the DC; this is not that proof.
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "AD.KERBER.TEST",
            b"ad-interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 71);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.ad.kerber.test"]);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        "AD.KERBER.TEST",
        72,
        KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("AD referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("AD referral TGS");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/AD.KERBER.TEST"
    );
    let ir_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let ir = store.get_name(&ir_name).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&ir.key, &out.rep.0.ticket).expect("inter-realm enc");
    assert!(
        part.transited.realms().is_empty(),
        "first-hop referral transited excludes client realm: {:?}",
        part.transited.realms()
    );
}

#[test]
fn interrealm_issue_key_is_not_the_peer_accept_key() {
    // Windows TDO inbound/outbound AES keys differ by salt. Issue toward
    // AD with the inbound key; still decrypt AD-issued referrals with the
    // outbound key.
    let issue_bytes = [0x11u8; 32];
    let accept_bytes = [0x22u8; 32];
    let issue_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &issue_bytes)
            .expect("issue key");
    let accept_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &accept_bytes)
            .expect("accept key");
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "AD.KERBER.TEST", issue_key)
        .expect("issue");
    store
        .add_interrealm_decrypt_key(&acl, &documented_admin_id(), "AD.KERBER.TEST", accept_key)
        .expect("accept");
    let ir_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let ir = store.get_name(&ir_name).expect("ir");
    assert_eq!(ir.keys.len(), 2);
    assert_eq!(
        ir.best_key().unwrap().key.as_bytes(),
        issue_bytes.as_slice(),
        "TGS issue must use the inbound AD key"
    );
    assert!(ir.keys.iter().any(|k| k.key.as_bytes() == accept_bytes));
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 81);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.ad.kerber.test"]);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        "AD.KERBER.TEST",
        82,
        KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("AD referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("AD referral TGS");
    let issue_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &issue_bytes)
            .unwrap();
    let accept_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &accept_bytes)
            .unwrap();
    decrypt_ticket_part(&issue_key, &out.rep.0.ticket).expect("issue key must open the referral");
    assert!(
        decrypt_ticket_part(&accept_key, &out.rep.0.ticket).is_err(),
        "peer accept key must not open tickets we issue toward AD"
    );
    let part = decrypt_ticket_part(&issue_key, &out.rep.0.ticket).unwrap();
    let pac = pac_from_ticket_part(&part).expect("referral TGT must carry a PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        krb5_types::pac::RpcSid::dummy_domain().to_sddl()
    );
    let der = ticket_checksum_der(&part).expect("der");
    verify_pac_signatures(&pac, &issue_key, Some(&issue_key), Some(&der))
        .expect("referral PAC signed with inter-realm key");
}

#[test]
fn password_principal_has_rfc8009_keys() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .expect("user");
    assert!(user
        .key_for(EncryptionType::Aes256CtsHmacSha384192)
        .is_some());
    assert!(user
        .key_for(EncryptionType::Aes128CtsHmacSha256128)
        .is_some());
}

#[test]
fn krbtgt_and_host_have_rfc8009_keys() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let tgt = store.krbtgt().expect("krbtgt");
    assert!(tgt
        .key_for(EncryptionType::Aes256CtsHmacSha384192)
        .is_some());
    let host = store.get_name(&documented_host()).expect("host");
    assert!(host
        .key_for(EncryptionType::Aes256CtsHmacSha384192)
        .is_some());
}

#[test]
fn issue_as_and_tgs_with_etype_20_mint_sha2_tickets() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let sha2 = EncryptionType::Aes256CtsHmacSha384192;
    let key = string_to_key(
        sha2,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&krb5_kdc::s2k_params(sha2)),
    )
    .expect("sha2 s2k");
    let req = as_req_sname(
        cname.clone(),
        TEST_REALM,
        80,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
        PrincipalName::krbtgt(TEST_REALM),
        vec![sha2.to_iana()],
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS etype 20");
    assert_eq!(as_out.session_key.etype(), sha2);
    assert_eq!(
        as_out.rep.0.ticket.enc_part.etype,
        sha2.to_iana(),
        "TGT EncryptedData.etype must be 20, not best_key() SHA-1"
    );
    let tgs = tgs_req_ex(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        81,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
        vec![sha2.to_iana()],
    )
    .expect("TGS etype 20");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS etype 20");
    assert_eq!(tgs_out.session_key.etype(), sha2);
    assert_eq!(
        tgs_out.rep.0.ticket.enc_part.etype,
        sha2.to_iana(),
        "host ticket EncryptedData.etype must be 20"
    );
}

#[test]
fn same_realm_ticket_omits_transited_policy_checked() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 70);
    let tgt = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        documented_host(),
        TEST_REALM,
        71,
    )
    .expect("tgs");
    let out = krb5_kdc::issue_tgs(&store, &tgt).expect("issue");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert!(
        !part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "same-realm ticket must not set TRANSITED-POLICY-CHECKED"
    );
}

#[test]
fn ktadd_exports_all_kvnos_after_kpasswd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .change_password(&acl, &documented_admin_id(), &cname, b"second-pass")
        .expect("cpw");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &cname)
        .expect("ktadd");
    let kvnos: Vec<u32> = kt.entries.iter().map(|e| e.kvno).collect();
    assert!(kvnos.contains(&1) && kvnos.iter().any(|v| *v > 1));
}

fn two_realm_pac_stores() -> (PrincipalStore, PrincipalStore, ProtocolKey, PrincipalName) {
    let (mut local, acl_a) = bootstrap_documented().expect("local");
    local.set_domain_sid(RpcSid::nt_domain(9, 8, 7));
    let mut foreign = PrincipalStore::bootstrap(
        "OTHER.TEST",
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .expect("foreign");
    foreign.set_domain_sid(RpcSid::nt_domain(11, 12, 13));
    let actor_b = format!("{TEST_ADMIN}@OTHER.TEST");
    let acl_b = Acl::allow_admin(&actor_b);
    let host_b = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    foreign
        .create_host(&acl_b, &actor_b, &host_b)
        .expect("host");
    let ir =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("ir key");
    local
        .create_interrealm_key(&acl_a, &documented_admin_id(), "OTHER.TEST", ir.clone())
        .expect("A→B");
    foreign
        .create_interrealm_key(&acl_b, &actor_b, TEST_REALM, ir.clone())
        .expect("B→A");
    (local, foreign, ir, host_b)
}

fn referral_from_local(local: &PrincipalStore, nonce: u32) -> (krb5_kdc::IssuedTgs, PrincipalName) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(local, TEST_USER, TEST_USER_PASSWORD, nonce);
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        other.clone(),
        TEST_REALM,
        nonce + 1,
    )
    .expect("referral TGS-REQ");
    (
        krb5_kdc::issue_tgs(local, &tgs).expect("referral TGS"),
        cname,
    )
}

fn rewrap_ticket(
    ticket: &krb5_types::Ticket,
    part: &EncTicketPart,
    key: &ProtocolKey,
) -> krb5_types::Ticket {
    let der = encode(part).expect("enc-tkt DER");
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let cipher = encrypt(key, usage, &der).expect("encrypt");
    let mut out = ticket.clone();
    out.enc_part.cipher = cipher.into();
    out
}

fn flip_pac_sig(part: &mut EncTicketPart, kind: u32) {
    let pac = pac_from_ticket_part(part).expect("PAC");
    let mut parsed = Pac::parse(&pac).expect("parse");
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == kind)
        .expect("sig buffer");
    assert!(buf.data.len() > 4, "MAC bytes");
    buf.data[4] ^= 0xff;
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).expect("wrap"));
}

#[test]
fn tgs_copies_foreign_referral_pac_identity() {
    let (local, foreign, ir, host_b) = two_realm_pac_stores();
    assert_ne!(local.domain_sid().to_sddl(), foreign.domain_sid().to_sddl());
    let (referral, cname) = referral_from_local(&local, 9100);
    let ref_part = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    let ref_pac = pac_from_ticket_part(&ref_part).expect("referral PAC");
    let ref_logon = parse_kerb_validation_info(
        Pac::parse(&ref_pac)
            .expect("PAC")
            .buffer(PAC_LOGON_INFO)
            .expect("logon"),
    )
    .expect("NDR");
    assert_eq!(
        ref_logon.logon_domain_id.to_sddl(),
        local.domain_sid().to_sddl()
    );

    let tgs = tgs_req(
        referral.rep.0.ticket.clone(),
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b.clone(),
        "OTHER.TEST",
        9102,
    )
    .expect("foreign TGS-REQ");
    let out = krb5_kdc::issue_tgs(&foreign, &tgs).expect("foreign TGS");
    let host_key = foreign.get_name(&host_b).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&host_key.key, &out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&part).expect("svc PAC");
    let logon = parse_kerb_validation_info(
        Pac::parse(&pac)
            .expect("PAC")
            .buffer(PAC_LOGON_INFO)
            .expect("logon"),
    )
    .expect("NDR");
    assert_eq!(logon.user_id, ref_logon.user_id);
    assert_eq!(
        logon.logon_domain_id.to_sddl(),
        local.domain_sid().to_sddl(),
        "issued PAC must keep the foreign LOGON_INFO SID, not the local store SID"
    );
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        foreign.domain_sid().to_sddl()
    );
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        RpcSid::dummy_domain().to_sddl()
    );
}

#[test]
fn tgs_rejects_corrupt_foreign_referral_pac() {
    let (local, foreign, ir, host_b) = two_realm_pac_stores();
    let (referral, cname) = referral_from_local(&local, 9200);
    let mut part = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    flip_pac_sig(&mut part, PAC_SERVER_CHECKSUM);
    let bad_server = rewrap_ticket(&referral.rep.0.ticket, &part, &ir);
    let tgs = tgs_req(
        bad_server,
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b.clone(),
        "OTHER.TEST",
        9202,
    )
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&foreign, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BAD_INTEGRITY),
        other => panic!("corrupt server checksum must fail, got {other:?}"),
    }

    let mut part16 = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    flip_pac_sig(&mut part16, PAC_TICKET_CHECKSUM);
    let bad_16 = rewrap_ticket(&referral.rep.0.ticket, &part16, &ir);
    let tgs16 = tgs_req(
        bad_16,
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b,
        "OTHER.TEST",
        9203,
    )
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&foreign, &tgs16) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BAD_INTEGRITY),
        other => panic!("corrupt type-16 checksum must fail, got {other:?}"),
    }
}

#[test]
fn tgs_without_pac_still_issues() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 9300);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    assert!(pac_from_ticket_part(&part).is_some());
    part.authorization_data = None;
    let stripped = rewrap_ticket(&issued.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        stripped,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        9301,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("MIT TGT without PAC must still issue");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("svc");
    assert!(pac_from_ticket_part(&svc).is_some());
}
