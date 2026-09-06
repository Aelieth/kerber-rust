//! W1-H J3: an unknown client's KRB-ERROR carries MIT's status word `CLIENT_NOT_FOUND` as `e_text`.

use krb5_asn1::{decode, encode};
use krb5_kdc::{TEST_REALM, as_req, bootstrap_documented};
use krb5_types::{KrbError, PrincipalName, err};

#[test]
fn unknown_client_e_text_is_client_not_found() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuchuser"]);
    let req = as_req(cname, TEST_REALM, 9, None).unwrap();
    let bytes = encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &bytes).unwrap();
    let e: KrbError = decode(&reply).unwrap();
    assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("CLIENT_NOT_FOUND"));
}
