//! A′-4 item 19 units that compile at `7403ec6` and fail there.

use krb5_asn1::decode_enc_kdc_rep_part;
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::{PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req_ex_from};
use krb5_types::{KdcOptions, KerberosTime, PrincipalName, flag_bit, ku};

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn user_as(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let key = store
        .get_name(&user())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn enc_as(issued: &krb5_kdc::IssuedAs) -> krb5_types::EncKdcRepPart {
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(
        &issued.as_rep_key,
        usage,
        issued.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode_enc_kdc_rep_part(&plain).unwrap()
}

fn ticket_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> krb5_types::EncTicketPart {
    let key = store
        .get_name(&PrincipalName::krbtgt(TEST_REALM))
        .unwrap()
        .best_key()
        .unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    krb5_asn1::decode(&plain).unwrap()
}

#[test]
fn a4_19_last_req_is_lrq_none_epoch() {
    let (store, _) = bootstrap_documented().unwrap();
    let enc = enc_as(&user_as(&store, 1901));
    assert_eq!(enc.last_req.len(), 1);
    assert_eq!(enc.last_req[0].lr_type, 0);
    assert_eq!(enc.last_req[0].lr_value.unix_seconds(), 0);
}

#[test]
fn a4_19_as_key_exp_is_min_of_expiration_and_pw_expire() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let now = KerberosTime::now().unix_seconds();
    store
        .apply_admin_fields(
            &user(),
            None,
            None,
            Some(now + 4 * 86400),
            Some(now + 2 * 86400),
            None,
            false,
            None,
        )
        .unwrap();
    let enc = enc_as(&user_as(&store, 1902));
    assert_eq!(
        enc.key_expiration.as_ref().map(KerberosTime::unix_seconds),
        Some(now + 2 * 86400)
    );
}

#[test]
fn a4_19_renew_postdated_starts_at_from() {
    let (store, _) = bootstrap_documented().unwrap();
    let key = store
        .get_name(&user())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        user(),
        TEST_REALM,
        1905,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true)
        .with_bit(flag_bit::MAY_POSTDATE, true);
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();
    let from = KerberosTime::now().add_seconds(3600).unwrap();
    let tgs = tgs_req_ex_from(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        1906,
        KdcOptions::none()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::POSTDATED, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
        None,
        Some(from.clone()),
        None,
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = ticket_part(&store, &out);
    assert_eq!(
        part.starttime
            .as_ref()
            .unwrap_or(&part.authtime)
            .unix_seconds(),
        from.unix_seconds()
    );
}
