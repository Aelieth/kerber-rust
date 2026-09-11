//! A′-3 item 15: SPAKE 91 e_data is module, ETYPE-INFO2, cookie.

use krb5_asn1::{decode, encode};
use krb5_kdc::{TEST_REALM, TEST_USER, as_req, bootstrap_documented};
use krb5_protocol::pa_spake_support;
use krb5_types::{KrbError, MethodData, PrincipalName, err, pa};

#[test]
fn as_spake_91_e_data_is_151_19_133() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 15007, Some(vec![pa_spake_support()])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::MORE_PREAUTH_DATA_REQUIRED);
    let method: MethodData = decode(e.e_data.as_ref().unwrap().as_ref()).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(types, vec![pa::SPAKE, pa::ETYPE_INFO2, pa::FX_COOKIE]);
}
