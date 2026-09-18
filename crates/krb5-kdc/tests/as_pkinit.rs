//! A′-4 item 17 units that compile at `7470962` and fail there.
//! A′-4 item 17 units that need `pkinit_require_freshness` / token mint.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, OAKLEY_2048, ProtocolKey, checksum, decrypt, dh_generate, dh_shared,
    encrypt, octetstring2key, p256_generate,
};
use krb5_kdc::{
    Error, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_admin_id,
};
use krb5_protocol::{
    armor_key, attach_fast, build_fast_armor, pa_pk_as_req, pa_pk_as_req_agile, pa_pk_as_req_cn,
    pa_pk_as_req_signed, pa_pk_as_req_spki, pa_pk_as_req_unsigned, pkinit_reply_key,
    pkinit_reply_key_agile,
};
use krb5_testkit::{issue_tgt_password, user};
use krb5_types::{
    Checksum, EncKdcRepPart, EncryptedData, KerberosTime, MethodData, Microseconds, PaData,
    PrincipalName, ascii, err, flag_bit, ku, pa,
    pkinit::{ECONTENT_AUTHDATA, PaPkAsReq, cms_sign_leaf, cms_verify, parse_pa_pk_as_req_cms},
    pkinit::{kdc_req_body_checksum, parse_authpack_freshness_token},
};

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if let Ok(b) = u8::try_from(body.len()) {
        if b < 128 {
            out.push(b);
        } else {
            out.push(0x81);
            out.push(b);
        }
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(body.len()).unwrap_or(u16::MAX)).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn take_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (hlen, ln) = if first < 128 {
        (1, usize::from(first))
    } else if first == 0x81 && input.len() >= 3 {
        (2, usize::from(input[2]))
    } else if first == 0x82 && input.len() >= 4 {
        (3, usize::from(u16::from_be_bytes([input[2], input[3]])))
    } else {
        return None;
    };
    let start = 1 + hlen;
    let body = input.get(start..start + ln)?;
    let rest = input.get(start + ln..)?;
    Some((tag, body, rest))
}

fn inject_pkauth_freshness(authpack: &[u8], token: &[u8]) -> Vec<u8> {
    let (t, body, _) = take_tlv(authpack).expect("AuthPack");
    assert_eq!(t, 0x30);
    let mut out = Vec::new();
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_tlv(cur).expect("field");
        if tag == 0xa0 {
            let seq = if inner.first() == Some(&0x30) {
                take_tlv(inner).expect("pkauth").1
            } else {
                inner
            };
            let tok = tlv(0xa4, &tlv(0x04, token));
            out.extend(tlv(0xa0, &tlv(0x30, &[seq, tok.as_slice()].concat())));
        } else {
            out.extend(tlv(tag, inner));
        }
        cur = rest;
    }
    tlv(0x30, &out)
}

#[test]
fn empty_150_hint_carries_populated_token() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let mut req = as_req(user(), TEST_REALM, 1701, None).unwrap();
    req.0.padata = Some(vec![PaData {
        padata_type: pa::AS_FRESHNESS,
        padata_value: Vec::<u8>::new().into(),
    }]);
    let Error::PreauthRequired { e_data } = krb5_kdc::issue_as(&store, &req).unwrap_err() else {
        panic!("want PreauthRequired");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    let tok = method
        .iter()
        .find(|p| p.padata_type == pa::AS_FRESHNESS)
        .expect("PA-AS-FRESHNESS");
    assert!(
        tok.padata_value.as_ref().len() > 8,
        "hint 150 must be populated, types={types:?}"
    );
    let i150 = types.iter().position(|t| *t == pa::AS_FRESHNESS).unwrap();
    let i133 = types.iter().position(|t| *t == pa::FX_COOKIE).unwrap();
    assert!(i150 < i133, "150 before cookie, types={types:?}");
}

#[test]
fn stale_freshness_token_is_preauth_failed() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 1702, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    let honest = pa_pk_as_req(&kp.public, &ca, Some(&ck)).expect("PA-PK-AS-REQ");
    let cms0 = parse_pa_pk_as_req_cms(honest.padata_value.as_ref()).expect("cms");
    let inner = cms_verify(&cms0, &ca.ca_cert).expect("AuthPack");
    let mut stale = 0u32.wrapping_sub(601).to_be_bytes().to_vec();
    stale.extend_from_slice(&1u32.to_be_bytes());
    stale.extend_from_slice(&[0u8; 12]);
    let inner = inject_pkauth_freshness(&inner, &stale);
    let cms = cms_sign_leaf(&inner, &cert, &key, ECONTENT_AUTHDATA).expect("CMS");
    let pa = PaPkAsReq {
        signed_auth_pack: cms.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    req.0.padata = Some(vec![
        PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: encode(&pa).expect("PA-PK-AS-REQ").into(),
        },
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    let (code, _) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol 24, got {other:?}"),
    };
    assert_eq!(code, err::PREAUTH_FAILED);
}

fn wellknown_anonymous() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"])
}

fn hint_token(store: &krb5_kdc::PrincipalStore) -> Vec<u8> {
    let mut req = as_req(user(), TEST_REALM, 1710, None).unwrap();
    req.0.padata = Some(vec![PaData {
        padata_type: pa::AS_FRESHNESS,
        padata_value: Vec::<u8>::new().into(),
    }]);
    let Error::PreauthRequired { e_data } = krb5_kdc::issue_as(store, &req).unwrap_err() else {
        panic!("want PreauthRequired for token mint");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    method
        .iter()
        .find(|p| p.padata_type == pa::AS_FRESHNESS)
        .map(|p| p.padata_value.as_ref().to_vec())
        .filter(|v| v.len() > 8)
        .expect("populated 150")
}

#[test]
fn no_150_in_request_omits_token_from_hint() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let req = as_req(user(), TEST_REALM, 1711, None).unwrap();
    let Error::PreauthRequired { e_data } = krb5_kdc::issue_as(&store, &req).unwrap_err() else {
        panic!("want PreauthRequired");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        !method.iter().any(|p| p.padata_type == pa::AS_FRESHNESS),
        "must not mint 150 unless the request advertised it"
    );
}

#[test]
fn require_freshness_signed_without_token_is_preauth_failed() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    store.policy.pkinit_require_freshness = true;
    let ca = store.pkinit_ca().expect("CA").clone();
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 1712, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_signed(&kp.public, &cert, &key, 1712, &ck, None).expect("signed"),
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    let (code, _) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want 24, got {other:?}"),
    };
    assert_eq!(code, err::PREAUTH_FAILED);
}

#[test]
fn require_freshness_signed_with_token_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    store.policy.pkinit_require_freshness = true;
    let ca = store.pkinit_ca().expect("CA").clone();
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let token = hint_token(&store);
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(user(), TEST_REALM, 1713, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    let pa = pa_pk_as_req_signed(&kp.public, &cert, &key, 1713, &ck, Some(&token)).expect("signed");
    let cms = krb5_types::pkinit::parse_pa_pk_as_req_cms(pa.padata_value.as_ref()).expect("cms");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");
    assert_eq!(
        parse_authpack_freshness_token(&inner).as_deref(),
        Some(token.as_slice())
    );
    req.0.padata = Some(vec![
        pa,
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    krb5_kdc::issue_as(&store, &req).expect("signed PKINIT with freshness");
}

#[test]
fn require_freshness_unsigned_without_token_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    store.policy.pkinit_require_freshness = true;
    store
        .insert_new_password(
            &wellknown_anonymous(),
            TEST_REALM,
            b"anon",
            &[krb5_crypto::EncryptionType::Aes256CtsHmacSha196],
            "kadmin/admin@KERBER.TEST",
        )
        .expect("WELLKNOWN/ANONYMOUS");
    let kp = p256_generate().expect("ecdh");
    let mut req = as_req(wellknown_anonymous(), TEST_REALM, 1714, None).unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let body = encode(&req.0.req_body).expect("body");
    let ck = kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 1714, &ck, None).expect("unsigned"),
    ]);
    krb5_kdc::issue_as(&store, &req).expect("anonymous PKINIT without token");
}

fn pkinit_as_req(
    cname: PrincipalName,
    nonce: u32,
    make_pa: impl FnOnce(&[u8]) -> krb5_types::PaData,
) -> krb5_types::AsReq {
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![make_pa(&cksum)]);
    req
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
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

fn pkinit_rep_from_cms(cms: Vec<u8>) -> Option<Vec<krb5_types::PaData>> {
    let rep = krb5_types::pkinit::PaPkAsRep::DhInfo(krb5_types::pkinit::DhRepInfo {
        dh_signed_data: cms.into(),
        server_dh_nonce: None,
    });
    Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REP,
        padata_value: encode(&rep).ok()?.into(),
    }])
}

fn wrap_fast_split(
    req: &mut krb5_types::AsReq,
    armor: &krb5_types::ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<krb5_types::PaData>,
    inner_body: krb5_types::KdcReqBody,
) -> Result<(), krb5_protocol::Error> {
    wrap_fast_split_opts(
        req,
        armor,
        armor_key,
        inner_padata,
        inner_body,
        krb5_types::fast::fast_options_none(),
    )
}

fn wrap_fast_split_opts(
    req: &mut krb5_types::AsReq,
    armor: &krb5_types::ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<krb5_types::PaData>,
    inner_body: krb5_types::KdcReqBody,
    fast_options: krb5_types::fast::FastOptions,
) -> Result<(), krb5_protocol::Error> {
    let outer = encode(&req.0.req_body).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, &outer)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options,
        padata: inner_padata,
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: encode(armor)
                .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
                .into(),
        }),
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    }]);
    Ok(())
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
    assert!(
        method.iter().any(|p| p.padata_type == pa::FX_FAST),
        "PA-FX-FAST must be advertised so MIT kinit -T armors AS: {method:?}"
    );
}

#[test]
fn ca_enabled_preauth_required_method_data_types() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 401, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::PK_AS_REQ,
            pa::PKINIT_KX,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::FX_COOKIE,
        ],
        "CA-enabled METHOD-DATA types must pin [136, 19, 16, 147, 151, 2, 133]"
    );
    let again = encode(&method).expect("re-encode");
    let round: MethodData = decode(&again).expect("decode encode");
    assert_eq!(round, method);
    assert_eq!(again, e_data, "METHOD-DATA encode(decode) must be identity");
}

#[test]
fn pkinit_not_advertised_without_ca() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    assert!(store.pkinit_ca().is_none());
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
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname, 401, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply = pkinit_reply_key(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        TEST_REALM,
    )
    .expect("ECDH key");
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
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 411, |ck| {
        pa_pk_as_req_agile(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ agile")
    });
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
    let o2k = pkinit_reply_key(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        TEST_REALM,
    );
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
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = dh_generate(&OAKLEY_2048).expect("client DH");
    let spki = krb5_types::pkinit::encode_dh_spki(&OAKLEY_2048.prime_bytes(), &kp.public);
    let req = pkinit_as_req(cname, 404, |ck| {
        pa_pk_as_req_spki(&spki, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
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
            freshness_token: None,
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
    assert!(store.pkinit_ca().is_none());
    let ca = krb5_types::pkinit::PkinitCa::generate().expect("unrelated CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa = pa_pk_as_req(&kp.public, &ca, None).expect("PA-PK-AS-REQ");
    let req = as_req(cname, TEST_REALM, 403, Some(vec![pa])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("PKINIT off");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_client_rejects_non_kdc_signer() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 421, |ck| {
        pa_pk_as_req_agile(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let as_req_der = encode(&req).expect("AS-REQ");
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let ok = pkinit_reply_key_agile(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    )
    .expect("KPKdc reply");
    assert_eq!(ok.as_bytes(), issued.as_rep_key.as_bytes());

    let raw = issued
        .rep
        .0
        .padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .expect("PA-PK-AS-REP");
    let cms = krb5_types::pkinit::pa_pk_as_rep_dh_signed_data(raw.padata_value.as_ref())
        .expect("dhSignedData");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");

    let (ccert, ckey) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let rogue = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        &ccert,
        &ckey,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("rogue cms");
    let err = pkinit_reply_key_agile(
        &kp.secret,
        &pkinit_rep_from_cms(rogue),
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    );
    assert!(err.is_err(), "client-cert KDC CMS must be refused: {err:?}");

    let (wcert, wkey, _) = ca.kdc_identity_for("OTHER.TEST").expect("wrong realm");
    let wrong = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        &wcert,
        &wkey,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("wrong cms");
    let err = pkinit_reply_key_agile(
        &kp.secret,
        &pkinit_rep_from_cms(wrong),
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    );
    assert!(err.is_err(), "wrong-realm KDC SAN must be refused: {err:?}");

    let (kcert, kkey, _) = ca.kdc_identity_for(TEST_REALM).expect("kdc id");
    let bad_ct = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        &kcert,
        &kkey,
        krb5_types::pkinit::ECONTENT_AUTHDATA,
    )
    .expect("authdata cms");
    let err = pkinit_reply_key_agile(
        &kp.secret,
        &pkinit_rep_from_cms(bad_ct),
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    );
    assert!(
        err.is_err(),
        "eContentType AUTHDATA must be refused: {err:?}"
    );
}

#[test]
fn pkinit_san_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 422, |ck| {
        pa_pk_as_req_cn(&kp.public, &ca, "other@KERBER.TEST", Some(ck)).expect("other")
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("SAN mismatch");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_ok = pkinit_as_req(cname, 423, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("user")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("matching SAN");
}

#[test]
fn pkinit_pachecksum_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa_missing = pa_pk_as_req(&kp.public, &ca, None).expect("missing");
    let req_missing = as_req(cname.clone(), TEST_REALM, 424, Some(vec![pa_missing])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req_missing).expect_err("missing paChecksum");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_bad = pkinit_as_req(cname.clone(), 425, |ck| {
        let mut wrong = ck.to_vec();
        wrong[0] ^= 1;
        pa_pk_as_req(&kp.public, &ca, Some(&wrong)).expect("wrong")
    });
    let err = krb5_kdc::issue_as(&store, &req_bad).expect_err("bad paChecksum");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_ok = pkinit_as_req(cname, 426, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("ok")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("matching paChecksum");
}

#[test]
fn pkinit_signed_content_type_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req_ok = pkinit_as_req(cname.clone(), 427, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("ok")
    });
    let pa = req_ok
        .0
        .padata
        .as_ref()
        .and_then(|v| v.first())
        .expect("pa");
    let cms = krb5_types::pkinit::parse_pa_pk_as_req_cms(pa.padata_value.as_ref()).expect("cms");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let bad = krb5_types::pkinit::cms_sign_leaf_oids(
        &inner,
        &cert,
        &key,
        krb5_types::pkinit::ECONTENT_AUTHDATA,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("split oids");
    let wrapped = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: bad.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    let mut req = req_ok;
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&wrapped).expect("pa").into(),
    }]);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("content-type");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_two_authpacks_same_second_both_issue() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp1 = p256_generate().expect("ecdh1");
    let kp2 = p256_generate().expect("ecdh2");
    let req1 = pkinit_as_req(cname.clone(), 452, |ck| {
        pa_pk_as_req(&kp1.public, &ca, Some(ck)).expect("PA-PK-AS-REQ 1")
    });
    let req2 = pkinit_as_req(cname, 452, |ck| {
        pa_pk_as_req(&kp2.public, &ca, Some(ck)).expect("PA-PK-AS-REQ 2")
    });
    krb5_kdc::issue_as(&store, &req1).expect("first AuthPack");
    krb5_kdc::issue_as(&store, &req2).expect("second AuthPack same second");
}

#[test]
fn pkinit_replayed_authpack_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname, 440, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    krb5_kdc::issue_as(&store, &req).expect("first PKINIT");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("replay");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_stale_ctime_is_skew() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let mut req = as_req(cname, TEST_REALM, 441, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::from_unix_seconds(1),
            nonce: 1,
            pa_checksum: Some(cksum.into()),
            freshness_token: None,
        },
        client_public_value: Some(krb5_types::pkinit::encode_ec_spki(&kp.public).into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack).expect("AuthPack");
    let signed = ca.sign_cms(&inner, "user").expect("cms");
    let pa = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: signed.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&pa).expect("pa").into(),
    }]);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("stale ctime");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::SKEW),
        other => panic!("expected SKEW, got {other}"),
    }
}

#[test]
fn pkinit_under_fast_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 442);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x43u8; 32])
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
    let mut req = as_req(cname, TEST_REALM, 443, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    let inner = vec![pa_pk_as_req(&kp.public, &ca, Some(&ck)).expect("PA-PK-AS-REQ")];
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    krb5_kdc::issue_as(&store, &req).expect("PKINIT+FAST");
}

#[test]
fn pkinit_fast_inner_body_hash_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let armor_as = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 444);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44u8; 32])
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
    let mut req = as_req(cname, TEST_REALM, 445, None).unwrap();
    let outer = encode(&req.0.req_body).expect("outer");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&outer);
    let pa = pa_pk_as_req(&kp.public, &ca, Some(&ck)).expect("PA-PK-AS-REQ");
    let mut inner_body = req.0.req_body.clone();
    inner_body.nonce = inner_body.nonce.wrapping_add(1);
    wrap_fast_split(&mut req, &armor_ap, &akey, vec![pa], inner_body).expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("inner paChecksum");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_enterprise_san_binds_issued_cname() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let stored = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user@OTHER.TEST"]);
    store
        .create_password(&acl, &documented_admin_id(), &stored, b"foreign-pass")
        .expect("create");
    let ent = PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@OTHER.TEST"]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(ent.clone(), 428, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("san user")
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("SAN vs issued cname");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_ok = pkinit_as_req(ent, 429, |ck| {
        pa_pk_as_req_cn(&kp.public, &ca, "user@OTHER.TEST@KERBER.TEST", Some(ck))
            .expect("issued san")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("SAN matches issued cname");
}
