//! TGS gather order: `is_crossrealm`, the constraint skeleton and its slots before the
//! service policy, the header PAC and PAC shape on the shipped issue path, and the rd_req
//! times after BADMATCH / BADADDR.
//! The remaining `GET_LOCAL_TGT` sites (the S4U2Proxy PAC in `ad.rs`) go out as 60, and a
//! kvno-0 header ticket in `kdc_rd_ap_req` decrypts under the previous kvno.
// MIT: `kdc_rd_ap_req` (kdc_util.c:325-346)
//! a kvno-0 ticket that fails to decrypt is
//! retried with the previous kvno's key.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented,
    documented_admin_id, documented_host,
};
use krb5_kdc::{KDB_DISALLOW_SVR, KeyEntry, PrincipalStore, decrypt_ticket_part, random_key};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{
    TgsReqBuilder, issue_tgt, issue_tgt_password, password_key, pref_etypes, status,
};
use krb5_types::{EncryptedData, KdcOptions, PrincipalName, Ticket, err, flag_bit, ku};

fn renewable_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let mut req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn host_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

#[test]
fn tgs_disallow_svr_service_header_is_process_tgs() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6070);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs(&as_out, 6071)).unwrap();
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | KDB_DISALLOW_SVR;
    store
        .apply_admin_fields(
            &host,
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let renew = TgsReqBuilder::new(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        TEST_REALM,
        &cname,
        host,
        TEST_REALM,
        6072,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &renew).unwrap_err();
    assert_eq!(
        status(&err),
        (err::S_PRINCIPAL_UNKNOWN, Some("PROCESS_TGS"))
    );
}

const FOREIGN: &str = "OTHER.TEST";

#[test]
fn lineage_before_u2u() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44; 32]).unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone(), None)
        .unwrap();
    let as_out = issue_tgt(&store, TEST_USER, 19030);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &as_out.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let header = Ticket {
        tkt_vno: as_out.rep.0.ticket.tkt_vno,
        realm: krb5_types::try_ascii(FOREIGN).unwrap(),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]),
        enc_part: EncryptedData {
            etype: ir.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(&ir, usage, &der).unwrap().into(),
        },
    };
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = {
        let key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            admin,
            TEST_REALM,
            19031,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap().rep.0.ticket
    };
    let req = TgsReqBuilder::new(
        header,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19032,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true))
    .additional_tickets(Some(vec![admin_tgt]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(status(&err), (err::POLICY, Some("INVALID LINEAGE")));
}

#[test]
fn renew_pac_service_after_krbtgt_enctype_rekey() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let as_out = {
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let mut req = as_req(
            user,
            TEST_REALM,
            19060,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let first = TgsReqBuilder::new(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19061,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let svc = krb5_kdc::issue_tgs(&store, &first).unwrap();
    let aes128 = random_key(EncryptionType::Aes128CtsHmacSha196).unwrap();
    store
        .set_keys(
            &PrincipalName::krbtgt(TEST_REALM),
            vec![KeyEntry::new(
                EncryptionType::Aes128CtsHmacSha196,
                aes128,
                0,
            )],
            1,
        )
        .unwrap();
    let renew = TgsReqBuilder::new(
        svc.rep.0.ticket,
        &svc.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19062,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    krb5_kdc::issue_tgs(&store, &renew).expect("RENEW after krbtgt enctype rekey");
}

#[test]
fn tgs_header_kvno_zero_decrypts_previous_kvno() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 751);
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    store.chrand_keepold_n(&krbtgt, 1).unwrap();
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.kvno = Some(0);
    let tgs = krb5_protocol::tgs_req(
        ticket,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        752,
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &tgs).expect("kvno 0 walks back to the previous key");
}
