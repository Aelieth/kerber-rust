//! TGS KRB-ERROR omits `crealm` when `errpkt.client` is NULL
//! (`do_tgs_req.c:201-204`, `asn1_k_encode.c:919`).

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, string_to_key};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_host, pa_enc_timestamp,
};
use krb5_types::{ApReq, KrbError, PrincipalName, err, pa};

fn issue_tgt() -> (krb5_kdc::PrincipalStore, krb5_kdc::IssuedAs, PrincipalName) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        801,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    (store, issued, cname)
}

fn no_client(e: &KrbError) {
    assert!(e.cname.is_none(), "no cname");
    assert!(e.crealm.is_none(), "no crealm when client is NULL");
}

#[test]
fn tgs_bad_msg_type_omits_crealm() {
    let (store, issued, cname) = issue_tgt();
    let mut tgs = krb5_protocol::tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        802,
    )
    .unwrap();
    tgs.0.msg_type = krb5_types::KdcReq::MSG_AS_REQ;
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::GENERIC);
    no_client(&e);
}

#[test]
fn tgs_ap_options_omits_crealm() {
    let (store, issued, cname) = issue_tgt();
    let mut tgs = krb5_protocol::tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        803,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .unwrap();
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).unwrap();
    ap.ap_options = krb5_types::ApOptions::mutual_required();
    pa.padata_value = encode(&ap).unwrap().into();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::POLICY);
    no_client(&e);
}
