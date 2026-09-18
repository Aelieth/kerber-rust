//! A′-3 item 11: `get_ticket_flags` + `check_tgs_opts` + deny_opts.

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::{
    KDB_DISALLOW_POSTDATED, KDB_DISALLOW_RENEWABLE, KDB_OK_AS_DELEGATE, PrincipalStore, TEST_REALM,
    bootstrap_documented, documented_host,
};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, err, flag_bit, ku};

use krb5_testkit::{TgsReqBuilder, status, user, user_as_bits};
fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
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
fn tgs_postdate_without_may_postdate_is_tgt_not_postdatable() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11001, &[]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11002,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::MAY_POSTDATE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("TGT NOT POSTDATABLE")));
}

#[test]
fn tgs_renewable_against_disallow_is_non_renewable() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as_bits(&store, 11011, &[(flag_bit::RENEWABLE, true)]);
    or_attr(&mut store, &host, KDB_DISALLOW_RENEWABLE);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        11012,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::POLICY, Some("NON-RENEWABLE TICKET")));
}

#[test]
fn tgs_forwarded_sets_forwarded() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11021, &[]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        11022,
    )
    .options(KdcOptions::none().with_bit(flag_bit::FORWARDED, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(tgt_part(&store, &out).flags.bit(flag_bit::FORWARDED));
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
fn tgs_postdated_is_invalid() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as_bits(&store, 11041, &[(flag_bit::MAY_POSTDATE, true)]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        11042,
    )
    .options(
        KdcOptions::none()
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    assert!(part.flags.bit(flag_bit::POSTDATED));
    assert!(part.flags.invalid());
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
