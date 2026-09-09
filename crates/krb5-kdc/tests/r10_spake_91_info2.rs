//! SPAKE 91 carries ETYPE-INFO2 when the client has not yet seen a cookie
//! (`kdc_preauth.c:1141-1170 maybe_add_etype_info2`).

use krb5_asn1::{decode, encode};
use krb5_kdc::{TEST_REALM, TEST_USER, as_req, bootstrap_documented};
use krb5_protocol::pa_spake_support;
use krb5_types::{KrbError, MethodData, PrincipalName, err, pa};

#[test]
fn spake_91_without_cookie_carries_etype_info2() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 711, Some(vec![pa_spake_support()])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::MORE_PREAUTH_DATA_REQUIRED);
    let method: MethodData = decode(e.e_data.as_ref().expect("e_data").as_ref()).expect("METHOD");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::SPAKE)
            && types.contains(&pa::FX_COOKIE)
            && types.contains(&pa::ETYPE_INFO2),
        "91 without cookie: SPAKE+COOKIE+ETYPE-INFO2, got {types:?}"
    );
}
