//! Old-kvno cookie arm: a cookie minted under krbtgt kvno N still opens
//! after a keepold rollover (`fast_util.c:545-611` `first_key_at_kvno`).

use krb5_asn1::{decode, encode};
use krb5_crypto::EncryptionType;
use krb5_kdc::{Error, TEST_REALM, TEST_USER, as_req, bootstrap_documented};
use krb5_protocol::{pa_spake_response, pa_spake_support};
use krb5_types::{MethodData, PrincipalName, err, pa};

#[test]
fn cookie_survives_krbtgt_kvno_rollover() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 701, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        other => panic!("expected SPAKE 91, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2),
        "91 without cookie carries ETYPE-INFO2: {:?}",
        method.iter().map(|p| p.padata_type).collect::<Vec<_>>()
    );
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie")
        .padata_value
        .as_ref()
        .to_vec();
    assert!(cookie.starts_with(b"MIT1") && cookie.len() > 8);
    let old_kvno = u32::from_be_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]);
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };

    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    store.chrand_keepold_n(&krbtgt, 1).expect("keepold");
    let new_kvno = store
        .get_name(&krbtgt)
        .expect("krbtgt")
        .first_current_key()
        .expect("current")
        .kvno;
    assert_ne!(old_kvno, new_kvno, "rollover must advance kvno");
    assert!(
        store
            .get_name(&krbtgt)
            .expect("krbtgt")
            .first_key_at_kvno(old_kvno)
            .is_some(),
        "keepold retains the minting key"
    );

    let mut req2 = as_req(cname, TEST_REALM, 702, None).unwrap();
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
            padata_value: cookie.into(),
        },
    ]);
    let issued = krb5_kdc::issue_as(&store, &req2).expect("old-kvno cookie still opens");
    assert_eq!(issued.as_rep_key.as_bytes(), spake_key.as_bytes());
}
