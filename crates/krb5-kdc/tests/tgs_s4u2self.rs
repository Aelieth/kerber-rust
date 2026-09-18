//! A′-2 item 7 S4U2Self units that fail at parent `2e5995a`.
//! A′-2 R17: S4U2Self keep-F default, is_referral, reply 130, policy cells.
//! Capaths transited check on the shipped `issue_tgs` path.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt};
use krb5_kdc::{
    Acl, Error, KDB_DISALLOW_ALL_TIX, KDB_OK_TO_AUTH_AS_DELEGATE, PacTicket, PrincipalStore,
    RID_FIRST_USER, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    as_req, bootstrap_documented, decrypt_ticket_part, documented_admin_id, documented_host,
    pa_enc_timestamp, pac_from_ticket_part, sign_reply_pac, tgs_req, ticket_checksum_der,
    verify_pac, wrap_win2k_pac,
};
use krb5_protocol::{pa_for_user, pa_s4u_x509_user};
use krb5_testkit::{
    TgsReqBuilder, aes_key, attach_pac, expect_status, foreign, host_tgt, issue_tgt_password,
    pref_etypes, reseal_incoming, reseal_mut, reseal_tgt, s4u_self, s4u_tgs,
};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_LOGON_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer,
    parse_kerb_validation_info,
};
use krb5_types::{ApReq, EncTicketPart, KdcOptions, PaData, PrincipalName, err, flag_bit, ku, pa};

fn attach_client_info_pac(store: &PrincipalStore, part: &mut EncTicketPart, info_name: &str) {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &krbtgt.key,
            kdc: &krbtgt.key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

#[test]
fn s4u2self_no_pac_is_tgt_revoked() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7100);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let tkt = reseal_tgt(&store, &tgt, &part);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let req = TgsReqBuilder::new(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        7101,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::TGT_REVOKED);
    assert_eq!(text.as_deref(), Some("S4U2SELF_NO_PAC"));
}

#[test]
fn s4u2self_local_pac_mismatch_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7102);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    attach_client_info_pac(&store, &mut part, TEST_ADMIN);
    let tkt = reseal_tgt(&store, &tgt, &part);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let req = TgsReqBuilder::new(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        7103,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("S4U2SELF_LOCAL_PAC_CLIENT"));
}

#[test]
fn s4u2self_x509_nonce_mismatch_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7110);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 0xdead).unwrap();
    let (c, text) =
        expect_status(krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7111)).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2SELF_CHECKSUM"));
}

#[test]
fn s4u2self_x509_bad_checksum_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7112);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let mut pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 7113).unwrap();
    let mut body: krb5_types::s4u::PaS4uX509User =
        krb5_asn1::decode(pa.padata_value.as_ref()).unwrap();
    let mut ck = body.cksum.checksum.to_vec();
    ck[0] ^= 0xff;
    body.cksum.checksum = ck.into();
    pa.padata_value = encode(&body).unwrap().into();
    let (c, text) =
        expect_status(krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7113)).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2SELF_CHECKSUM"));
}

#[test]
fn s4u2self_x509_empty_is_invalid_request() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7120);
    let empty = PrincipalName::new(PrincipalName::NT_UNKNOWN, std::iter::empty::<&str>());
    let pa = pa_s4u_x509_user(&tgt.session_key, empty, TEST_REALM, 7121).unwrap();
    let (c, text) =
        expect_status(krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7121)).unwrap_err());
    assert_eq!(c, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2SELF_REQUEST"));
}

#[test]
fn s4u2self_x509_cert_only_local_is_looking_up() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7122);
    let user_id = krb5_types::s4u::S4uUserId {
        nonce: 7123,
        user: None,
        realm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        subject_cert: Some(b"cert".to_vec().into()),
        options: Some(krb5_types::s4u::s4u_reply_key_usage_flags()),
    };
    let der = encode(&user_id).unwrap();
    let usage = KeyUsage::new(ku::PA_S4U_X509_USER_REQUEST).unwrap();
    let mic = checksum(&tgt.session_key, usage, &der).unwrap();
    let body = krb5_types::s4u::PaS4uX509User {
        user_id,
        cksum: krb5_types::Checksum {
            cksumtype: tgt.session_key.etype().checksum_type(),
            checksum: mic.into(),
        },
    };
    let pa = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&body).unwrap().into(),
    };
    let (c, text) =
        expect_status(krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7123)).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("LOOKING_UP_S4U2SELF_PRINCIPAL"));
}

#[test]
fn s4u2self_x509_issues_and_replies_130() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7130);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 7131).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7131)).unwrap();
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    assert!(
        out.rep
            .0
            .padata
            .as_ref()
            .is_some_and(|v| v.iter().any(|p| p.padata_type == pa::FOR_X509_USER))
    );
}

#[test]
fn s4u2self_x509_wins_over_for_user() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7132);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa130 = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 7133).unwrap();
    let pa129 = pa_for_user(&tgt.session_key, user, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa129, pa130], 7133)).unwrap();
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
}

#[test]
fn s4u2self_for_user_only_omits_reply_130() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7134);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7135)).unwrap();
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    assert!(
        out.rep
            .0
            .padata
            .as_ref()
            .is_none_or(|v| v.iter().all(|p| p.padata_type != pa::FOR_X509_USER))
    );
}

#[test]
fn s4u2self_pw_expired_user_still_issues() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store
        .apply_admin_fields(&admin, None, None, None, Some(1), None, false, None)
        .unwrap();
    let tgt = host_tgt(&store, 7140);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7141)).unwrap();
}

#[test]
fn s4u2self_keeps_forwardable_without_delegate_targets() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.clear_s4u_to(&documented_host());
    let tgt = host_tgt(&store, 7150);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7151)).unwrap();
    let host = documented_host();
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert!(part.flags.forwardable());
}

#[test]
fn s4u2self_for_user_undecodable_is_generic() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 7160);
    let pa = PaData {
        padata_type: pa::FOR_USER,
        padata_value: b"\x30\x03\x01\x01".to_vec().into(),
    };
    let (c, text) =
        expect_status(krb5_kdc::issue_tgs(&store, &s4u_self(&tgt, vec![pa], 7161)).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("DECODE_PA_FOR_USER"));
}

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
    let req = TgsReqBuilder::new(
        header,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        17041,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
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

fn realm_store(realm: &str, host: &str) -> (PrincipalStore, Acl, String, PrincipalName) {
    let mut store = PrincipalStore::bootstrap(
        realm,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .expect("bootstrap");
    let actor = format!("{TEST_ADMIN}@{realm}");
    let acl = Acl::allow_admin(&actor).expect("acl");
    let hostn = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host]);
    store.create_host(&acl, &actor, &hostn).expect("host");
    (store, acl, actor, hostn)
}

fn as_tgt(store: &PrincipalStore, realm: &str, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(realm);
    let key = krb5_crypto::string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname,
        realm,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS")
}

fn chase_tgs(
    store: &PrincipalStore,
    ticket: krb5_types::Ticket,
    session: &ProtocolKey,
    crealm: &str,
    sname: PrincipalName,
    realm: &str,
    nonce: u32,
) -> Result<krb5_kdc::IssuedTgs, Error> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(ticket, session, crealm, &cname, sname, realm, nonce).expect("tgs-req");
    krb5_kdc::issue_tgs(store, &req)
}

fn attach_client_info_pac_capaths(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str) {
    use krb5_kdc::{PacTicket, sign_reply_pac, ticket_checksum_der, wrap_win2k_pac};
    use krb5_types::pac::{
        PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer,
    };
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).expect("ph"));
    let der = ticket_checksum_der(part).expect("der");
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .expect("sign");
    part.authorization_data = Some(wrap_win2k_pac(&pac).expect("wrap"));
}

fn three_realm() -> (
    PrincipalStore,
    PrincipalStore,
    PrincipalStore,
    ProtocolKey,
    PrincipalName,
    krb5_kdc::IssuedTgs,
) {
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("ir");
    let (mut a, acl_a, actor_a, _) = realm_store("A.TEST", "svc.a.test");
    let (mut b, acl_b, actor_b, _) = realm_store("B.TEST", "svc.b.test");
    let (mut c, acl_c, actor_c, host_c) = realm_store("C.TEST", "svc.c.test");
    a.create_interrealm_key(&acl_a, &actor_a, "B.TEST", ir.clone())
        .expect("A→B");
    b.create_interrealm_key(&acl_b, &actor_b, "A.TEST", ir.clone())
        .expect("B→A");
    b.create_interrealm_key(&acl_b, &actor_b, "C.TEST", ir.clone())
        .expect("B→C");
    c.create_interrealm_key(&acl_c, &actor_c, "B.TEST", ir.clone())
        .expect("C→B");
    let mut cap = std::collections::BTreeMap::new();
    cap.entry("A.TEST".into())
        .or_insert_with(std::collections::BTreeMap::new)
        .insert("C.TEST".into(), vec!["B.TEST".into()]);
    c.set_capaths(cap);
    let tgt = as_tgt(&a, "A.TEST", 500);
    let ab = chase_tgs(
        &a,
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        501,
    )
    .expect("A→B");
    let bc = chase_tgs(
        &b,
        ab.rep.0.ticket.clone(),
        &ab.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        502,
    )
    .expect("B→C");
    (a, b, c, ir, host_c, bc)
}

fn tgs_code_text(res: Result<krb5_kdc::IssuedTgs, Error>) -> (i32, Option<String>) {
    match res {
        Err(Error::Protocol { code, text, .. }) => (code, text),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn s4u2self_referral_names_header_client() {
    let (a, b, _c, ir, _host_c, _bc) = three_realm();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = as_tgt(&a, "A.TEST", 980);
    let ab = chase_tgs(
        &a,
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        "A.TEST",
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "B.TEST"]),
        "A.TEST",
        981,
    )
    .expect("A B");
    let mut t = ab.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("ab");
    attach_client_info_pac_capaths(&ir, &mut part, &format!("{TEST_ADMIN}@A.TEST"));
    reseal_mut(&mut t, &part, &ir);
    let pa = pa_for_user(&ab.session_key, admin, "A.TEST").expect("PA-FOR-USER");
    let req = TgsReqBuilder::new(
        t,
        &ab.session_key,
        "A.TEST",
        &user,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "C.TEST"]),
        "B.TEST",
        982,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("s4u explicit TGS");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&b, &req));
    assert_eq!(code, err::BADMATCH);
    assert_eq!(
        text.as_deref(),
        Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
    );
}

#[test]
fn s4u2self_cross_tgt_local_user_local_server_is_not_cross_realm() {
    let (_a, _b, c, ir, host_c, bc) = three_realm();
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.cname = host_c.clone();
    part.crealm = krb5_types::try_ascii("C.TEST").expect("realm");
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &ir);
    let local = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let pa = pa_for_user(&bc.session_key, local, "C.TEST").expect("PA-FOR-USER");
    let req = TgsReqBuilder::new(
        t,
        &bc.session_key,
        "C.TEST",
        &host_c,
        host_c.clone(),
        "C.TEST",
        983,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("s4u");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("NOT_CROSS_REALM_REQUEST"));
}

#[test]
fn s4u2self_cross_tgt_foreign_client_named_like_local_server_is_badmatch() {
    let (_a, _b, c, _ir, _host_c, bc) = three_realm();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&bc.session_key, admin, "A.TEST").expect("PA-FOR-USER");
    let req = TgsReqBuilder::new(
        bc.rep.0.ticket.clone(),
        &bc.session_key,
        "A.TEST",
        &user,
        user.clone(),
        "C.TEST",
        986,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("s4u");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::BADMATCH);
    assert_eq!(
        text.as_deref(),
        Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
    );
}

#[test]
fn s4u2self_local_tgt_foreign_crealm_is_badmatch() {
    let (_a, _b, c, _ir, _host_c, _bc) = three_realm();
    let tgt = as_tgt(&c, "C.TEST", 984);
    let tgt_key = c.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut t = tgt.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&tgt_key, &t).expect("tgt");
    part.crealm = krb5_types::try_ascii("A.TEST").expect("realm");
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &tgt_key);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, "C.TEST").expect("PA-FOR-USER");
    let mut req = TgsReqBuilder::new(
        t,
        &tgt.session_key,
        "C.TEST",
        &user,
        user.clone(),
        "C.TEST",
        985,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("s4u");
    let tgs_pa = req
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(tgs_pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(
        &tgt.session_key,
        auth_usage,
        ap.authenticator.cipher.as_ref(),
    )
    .expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    authenticator.crealm = krb5_types::try_ascii("A.TEST").expect("realm");
    let auth_der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(&tgt.session_key, auth_usage, &auth_der)
        .expect("enc")
        .into();
    tgs_pa.padata_value = encode(&ap).expect("ap").into();
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::BADMATCH);
    assert_eq!(
        text.as_deref(),
        Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
    );
}

#[test]
fn s4u2self_cross_tgt_local_server_foreign_user_issues() {
    let (_a, _b, mut c, ir, host_c, bc) = three_realm();
    c.policy.reject_bad_transit = false;
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.cname = host_c.clone();
    part.crealm = krb5_types::try_ascii("C.TEST").expect("realm");
    attach_client_info_pac_capaths(&ir, &mut part, &format!("{TEST_ADMIN}@A.TEST"));
    reseal_mut(&mut t, &part, &ir);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&bc.session_key, admin, "A.TEST").expect("PA-FOR-USER");
    let req = TgsReqBuilder::new(
        t,
        &bc.session_key,
        "C.TEST",
        &host_c,
        host_c.clone(),
        "C.TEST",
        987,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("s4u");
    let out = krb5_kdc::issue_tgs(&c, &req).expect("MIT case 4");
    let host_key = c.get_name(&host_c).unwrap().best_key().unwrap().key.clone();
    let part = decrypt_ticket_part(&host_key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    assert_eq!(
        std::str::from_utf8(part.crealm.as_bytes()).unwrap(),
        "A.TEST"
    );
}

#[test]
fn s4u2self_cross_tgt_cert_only_empty_name_is_invalid_xrealm() {
    let (_a, _b, mut c, ir, host_c, bc) = three_realm();
    c.policy.reject_bad_transit = false;
    let mut t = bc.rep.0.ticket.clone();
    let mut part = decrypt_ticket_part(&ir, &t).expect("bc");
    part.cname = host_c.clone();
    part.crealm = krb5_types::try_ascii("C.TEST").expect("realm");
    part.authorization_data = None;
    reseal_mut(&mut t, &part, &ir);
    let user_id = krb5_types::s4u::S4uUserId {
        nonce: 988,
        user: None,
        realm: krb5_types::try_ascii("A.TEST").expect("realm"),
        subject_cert: Some(b"cert".to_vec().into()),
        options: Some(krb5_types::s4u::s4u_reply_key_usage_flags()),
    };
    let der = encode(&user_id).expect("id");
    let usage = KeyUsage::new(ku::PA_S4U_X509_USER_REQUEST).unwrap();
    let mic = checksum(&bc.session_key, usage, &der).expect("ck");
    let body = krb5_types::s4u::PaS4uX509User {
        user_id,
        cksum: krb5_types::Checksum {
            cksumtype: bc.session_key.etype().checksum_type(),
            checksum: mic.into(),
        },
    };
    let pa = krb5_types::PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&body).expect("130").into(),
    };
    let req = TgsReqBuilder::new(
        t,
        &bc.session_key,
        "C.TEST",
        &host_c,
        host_c.clone(),
        "C.TEST",
        988,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .expect("s4u");
    let (code, text) = tgs_code_text(krb5_kdc::issue_tgs(&c, &req));
    assert_eq!(code, err::POLICY);
    assert_eq!(text.as_deref(), Some("INVALID_XREALM_S4U2SELF_REQUEST"));
}

fn or_host_attr(store: &mut PrincipalStore, bit: u32) {
    let host = documented_host();
    let a = store.get_name(&host).unwrap().attributes | bit;
    store
        .apply_admin_fields(&host, Some(a), None, None, None, None, false, None)
        .unwrap();
}

fn s4u2self_tgs(store: &PrincipalStore, for_user: PrincipalName, nonce: u32) -> krb5_types::TgsReq {
    let host = documented_host();
    let tgt = host_tgt(store, nonce);
    let pa = pa_for_user(&tgt.session_key, for_user, TEST_REALM).expect("PA-FOR-USER");
    TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce + 1,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("S4U TGS-REQ")
}

fn s4u_code(e: Error) -> i32 {
    match e {
        Error::Protocol { code, .. } => code,
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn s4u2self_impersonates_user() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    or_host_attr(&mut store, KDB_OK_TO_AUTH_AS_DELEGATE);
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = host_tgt(&store, 601);
    let pa = pa_for_user(&tgt.session_key, admin.clone(), TEST_REALM).expect("PA-FOR-USER");
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        602,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("S4U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Self");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    assert!(part.flags.forwardable());
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    verify_pac(&pac, &hostk.key, &krbtgt.key, true).expect("S4U PAC");
    let parsed = Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_eq!(logon.user_id, store.get_name(&admin).unwrap().rid);
    assert_ne!(logon.user_id, RID_FIRST_USER);
}

#[test]
fn s4u2self_user_tgt_host_sname_is_badmatch() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 640);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        641,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("S4U TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::BADMATCH);
            assert_eq!(
                text.as_deref(),
                Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
            );
        }
        other => panic!("expected BADMATCH, got {other:?}"),
    }
}

#[test]
fn s4u2self_clears_forwardable_without_ok_to_auth() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    store.allow_s4u_to(&host, "host/other.kerber.test");
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = host_tgt(&store, 650);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        651,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("S4U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Self");
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).expect("enc");
    assert!(!part.flags.forwardable());
}

#[test]
fn s4u2self_explicit_cross_tgs_is_server_mismatch() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x11; 32]).unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "OTHER.TEST", ir)
        .expect("interrealm");
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = host_tgt(&store, 660);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]),
        TEST_REALM,
        661,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("S4U TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::BADMATCH);
            assert_eq!(
                text.as_deref(),
                Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
            );
        }
        other => panic!("expected 36 SERVER_MISMATCH, got {other:?}"),
    }
}

#[test]
fn s4u2self_local_tgt_foreign_user_is_not_ours() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let foreign = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]);
    let tgt = host_tgt(&store, 670);
    let pa = pa_for_user(&tgt.session_key, foreign, "OTHER.TEST").expect("PA-FOR-USER");
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        671,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("S4U TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("S4U2SELF_CLIENT_NOT_OURS"));
        }
        other => panic!("expected POLICY S4U2SELF_CLIENT_NOT_OURS, got {other:?}"),
    }
}

#[test]
fn s4u2self_unknown_for_user_is_refused() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let nosuch = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
    let err = krb5_kdc::issue_tgs(&store, &s4u2self_tgs(&store, nosuch, 610)).unwrap_err();
    assert_eq!(s4u_code(err), err::C_PRINCIPAL_UNKNOWN);
}

#[test]
fn s4u2self_disabled_for_user_is_revoked() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let a = store.get_name(&admin).unwrap().attributes | KDB_DISALLOW_ALL_TIX;
    store
        .apply_admin_fields(&admin, Some(a), None, None, None, None, false, None)
        .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &s4u2self_tgs(&store, admin, 620)).unwrap_err();
    assert_eq!(s4u_code(err), err::CLIENT_REVOKED);
}

#[test]
fn s4u2self_expired_for_user_is_name_exp() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store
        .apply_admin_fields(&admin, None, None, Some(1), None, None, false, None)
        .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &s4u2self_tgs(&store, admin, 630)).unwrap_err();
    assert_eq!(s4u_code(err), err::NAME_EXP);
}

#[test]
fn s4u2self_bad_checksum_rejected() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 901);
    let mut pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let mut for_user: krb5_types::s4u::PaForUser =
        decode(pa.padata_value.as_ref()).expect("PaForUser");
    let mut ck = for_user.cksum.checksum.to_vec();
    ck[0] ^= 0xff;
    for_user.cksum.checksum = ck.into();
    pa.padata_value = encode(&for_user).expect("re-encode").into();
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        902,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("TGS-REQ");
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::MODIFIED);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("INVALID_S4U2SELF_CHECKSUM"));
}

#[test]
fn s4u2self_unkeyed_cksumtype_is_inapp() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 903);
    let mut pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let mut for_user: krb5_types::s4u::PaForUser =
        decode(pa.padata_value.as_ref()).expect("PaForUser");
    for_user.cksum.cksumtype = 7;
    pa.padata_value = encode(&for_user).expect("re-encode").into();
    let tgs = TgsReqBuilder::new(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        904,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(vec![pa])
    .etypes(pref_etypes())
    .build()
    .expect("TGS-REQ");
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::INAPP_CKSUM);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some("INVALID_S4U2SELF_CHECKSUM"));
}
