//! TGS KRB-ERROR omits `crealm` when `errpkt.client` is NULL
//! (`do_tgs_req.c:201-204`, `asn1_k_encode.c:919`).

use krb5_asn1::{decode, encode};
use krb5_kdc::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host};
use krb5_testkit::issue_tgt_password;
use krb5_types::{ApReq, KrbError, PrincipalName, err, pa};

fn local_tgt() -> (krb5_kdc::PrincipalStore, krb5_kdc::IssuedAs, PrincipalName) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 801);
    (store, issued, cname)
}

fn no_client(e: &KrbError) {
    assert!(e.cname.is_none(), "no cname");
    assert!(e.crealm.is_none(), "no crealm when client is NULL");
}

#[test]
fn tgs_bad_msg_type_omits_crealm() {
    let (store, issued, cname) = local_tgt();
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
    let (store, issued, cname) = local_tgt();
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
