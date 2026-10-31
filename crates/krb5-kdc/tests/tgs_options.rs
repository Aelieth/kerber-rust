//! TGS options: `get_ticket_flags`, `check_tgs_opts` and the deny options, with the gating
//! negatives.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_kdc::{KDB_DISALLOW_POSTDATED, KDB_OK_AS_DELEGATE, PrincipalStore};
use krb5_protocol::{as_req, pa_enc_timestamp};

use krb5_testkit::{TgsReqBuilder, user, user_as_bits};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, flag_bit, ku};

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(
            name,
            krb5_kdc::AdminFields {
                attributes: Some(a),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
}

fn host_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let host = documented_host();
    let key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

#[test]
fn tgs_proxy_sets_proxy() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11031, &[(flag_bit::PROXIABLE, true)]);
    let host_req = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11032,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::PROXIABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let host_out = krb5_kdc::issue_tgs(&store, &host_req).unwrap();
    assert!(host_part(&store, &host_out).flags.proxiable());
    let proxy = TgsReqBuilder::new(
        host_out.rep.0.ticket.clone(),
        &host_out.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11033,
    )
    .options(KdcOptions::none().with_bit(flag_bit::PROXY, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &proxy).unwrap();
    assert!(host_part(&store, &out).flags.bit(flag_bit::PROXY));
}

#[test]
fn tgs_postdated_bit_alone_does_not_deny_postdate() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    or_attr(&mut store, &host, KDB_DISALLOW_POSTDATED);
    let issued = user_as_bits(&store, 11051, &[(flag_bit::MAY_POSTDATE, true)]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        11052,
    )
    .options(KdcOptions::none().with_bit(flag_bit::POSTDATED, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("deny_opts keys only on ALLOW_POSTDATE");
    assert!(host_part(&store, &out).flags.invalid());
}

#[test]
fn tgs_renew_skips_ok_as_delegate() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    or_attr(&mut store, &krbtgt, KDB_OK_AS_DELEGATE);
    let issued = user_as_bits(&store, 11061, &[(flag_bit::RENEWABLE, true)]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        krbtgt,
        TEST_REALM,
        11062,
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
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(!tgt_part(&store, &out).flags.bit(flag_bit::OK_AS_DELEGATE));
}

#[test]
fn tgs_session_enctypes_attr_is_membership() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store
        .set_string(&documented_host(), "session_enctypes", Some("aes128-cts"))
        .expect("setstr");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        64,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = TgsReqBuilder::new(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        65,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![18, 17])
    .build()
    .expect("tgs");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    assert_eq!(
        tgs_out.session_key.etype(),
        EncryptionType::Aes128CtsHmacSha196
    );
}
