//! A′-2 R17: S4U2Self keep-F default, is_referral, reply 130, policy cells.

use krb5_kdc::{
    TEST_ADMIN, TEST_REALM, bootstrap_documented, decrypt_ticket_part, documented_admin_id,
    documented_host,
};
use krb5_protocol::{pa_for_user, pa_s4u_x509_user, tgs_req_ex};
use krb5_testkit::{
    aes_key, attach_pac, expect_status, foreign, host_tgt, pref_etypes, reseal_incoming, s4u_tgs,
};
use krb5_types::{EncTicketPart, KdcOptions, PaData, PrincipalName, err, flag_bit, pa};

const FOREIGN: &str = "OTHER.TEST";

#[test]
fn a2_r17_create_host_has_no_s4u_to_targets() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = store.get_name(&documented_host()).expect("host");
    assert!(host.s4u_allowed_to.is_empty());
}

#[test]
fn a2_r17_s4u2self_keeps_f_without_clearing_targets() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17000);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(
        &store,
        &s4u_tgs(
            &tgt,
            documented_host(),
            vec![pa],
            17001,
            KdcOptions::forwardable(),
        ),
    )
    .unwrap();
    let hostk = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert!(part.flags.forwardable());
}

#[test]
fn a2_r17_explicit_cross_tgs_is_server_mismatch() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, aes_key(0x11))
        .unwrap();
    let tgt = host_tgt(&store, 17010);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let other = foreign();
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(
            &store,
            &s4u_tgs(&tgt, other, vec![pa], 17011, KdcOptions::forwardable()),
        )
        .unwrap_err(),
    );
    assert_eq!(c, err::BADMATCH);
    assert_eq!(
        text.as_deref(),
        Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
    );
}

#[test]
fn a2_r17_s4u2self_u2u_is_invalid_options() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17020);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(
            &store,
            &s4u_tgs(
                &tgt,
                documented_host(),
                vec![pa],
                17021,
                KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
            ),
        )
        .unwrap_err(),
    );
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("INVALID S4U2SELF OPTIONS"));
}

#[test]
fn a2_r17_truncated_x509_is_decode() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17030);
    let pa = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: b"\x30\x03\x01\x01".to_vec().into(),
    };
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(
            &store,
            &s4u_tgs(
                &tgt,
                documented_host(),
                vec![pa],
                17031,
                KdcOptions::forwardable(),
            ),
        )
        .unwrap_err(),
    );
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("DECODE_PA_S4U_X509_USER"));
}

#[test]
fn a2_r17_foreign_pac_client() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = aes_key(0x33);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    let tgt = host_tgt(&store, 17040);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    attach_pac(&ir, &mut part, &documented_host().components_joined());
    let header = reseal_incoming(&ir, &tgt, &part);
    let alice = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]);
    let pa = pa_for_user(&tgt.session_key, alice, FOREIGN).unwrap();
    let host = documented_host();
    let req = tgs_req_ex(
        header,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        17041,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("S4U2SELF_FOREIGN_PAC_CLIENT"));
}

#[test]
fn a2_r17_reply_130_has_no_subject_cert() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17050);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 17051).unwrap();
    let out = krb5_kdc::issue_tgs(
        &store,
        &s4u_tgs(
            &tgt,
            documented_host(),
            vec![pa],
            17051,
            KdcOptions::forwardable(),
        ),
    )
    .unwrap();
    let raw = out
        .rep
        .0
        .padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::FOR_X509_USER))
        .expect("reply 130");
    let rep: krb5_types::s4u::PaS4uX509User = krb5_asn1::decode(raw.padata_value.as_ref()).unwrap();
    assert!(rep.user_id.subject_cert.is_none());
}
