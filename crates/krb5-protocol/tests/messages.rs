//! Protocol message tests: AP-REP, SAFE/PRIV/CRED, DER tags.

use krb5_asn1::{decode, encode};
use krb5_crypto::{string_to_key, EncryptionType, KeyUsage};
use krb5_kdc::{
    as_req, bootstrap_documented, documented_host, pa_enc_timestamp, tgs_req, S2K_ITERS,
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
};
use krb5_protocol::{
    build_ap_rep, build_ap_req, build_krb_cred, build_krb_priv, build_krb_safe, unwrap_krb_priv,
    unwrap_krb_safe, verify_ap_rep, verify_ap_req, ReplayCache,
};
use krb5_types::{ascii, ku, EncAsRepPart, PrincipalName};

fn client_key() -> krb5_crypto::ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

#[test]
fn as_rep_enc_part_is_application_25() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname,
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    );
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = krb5_crypto::decrypt(&key, usage, issued.rep.0.enc_part.cipher.as_ref()).unwrap();
    assert_eq!(plain[0], 0x79, "APPLICATION 25");
    let _: EncAsRepPart = decode(&plain).expect("EncASRepPart");
}

#[test]
fn ap_rep_mutual_and_safe_priv() {
    let (store, acl) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        2,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    );
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        3,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
    )
    .unwrap();
    let raw = encode(&ap).unwrap();
    let kt = store
        .export_keytab(&acl, &krb5_kdc::documented_admin_id(), &documented_host())
        .unwrap();
    let ok = verify_ap_req(&raw, &kt.entries[0].key, &ReplayCache::new()).unwrap();
    let ap_rep = build_ap_rep(&tgs_out.session_key, &ok.authenticator, None, Some(1)).unwrap();
    let ap_rep_raw = encode(&ap_rep).unwrap();
    verify_ap_rep(&ap_rep_raw, &tgs_out.session_key, &ok.authenticator).unwrap();

    let safe = build_krb_safe(&tgs_out.session_key, b"safe-payload").unwrap();
    let got = unwrap_krb_safe(&tgs_out.session_key, &encode(&safe).unwrap()).unwrap();
    assert_eq!(got, b"safe-payload");
    let privm = build_krb_priv(&tgs_out.session_key, b"priv-payload").unwrap();
    let got = unwrap_krb_priv(&tgs_out.session_key, &encode(&privm).unwrap()).unwrap();
    assert_eq!(got, b"priv-payload");

    let cred = build_krb_cred(
        &tgs_out.session_key,
        vec![tgs_out.rep.0.ticket.clone()],
        vec![],
    )
    .unwrap();
    assert_eq!(encode(&cred).unwrap()[0], 0x76); // APPLICATION 22
}

#[test]
fn golden_application_tags() {
    use krb5_types::*;
    let t = Ticket {
        tkt_vno: 5,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: vec![0].into(),
        },
    };
    assert_eq!(encode(&t).unwrap()[0], 0x61);
    let e = KrbError {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: 6,
        crealm: None,
        cname: None,
        realm: ascii("R"),
        sname: PrincipalName::krbtgt("R"),
        e_text: None,
        e_data: None,
    };
    assert_eq!(encode(&e).unwrap()[0], 0x7e);
}
