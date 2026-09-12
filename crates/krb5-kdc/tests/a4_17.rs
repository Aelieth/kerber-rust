//! A′-4 item 17 units that compile at `7470962` and fail there.

use krb5_asn1::{decode, encode};
use krb5_crypto::p256_generate;
use krb5_kdc::{Error, TEST_REALM, TEST_USER, as_req, bootstrap_documented};
use krb5_protocol::pa_pk_as_req;
use krb5_types::{
    MethodData, PaData, PrincipalName, err, pa,
    pkinit::{ECONTENT_AUTHDATA, PaPkAsReq, cms_sign_leaf, cms_verify, parse_pa_pk_as_req_cms},
};

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

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
fn a4_17_empty_150_hint_carries_populated_token() {
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
fn a4_17_stale_freshness_token_is_24() {
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
