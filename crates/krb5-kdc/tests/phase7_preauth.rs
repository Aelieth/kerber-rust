//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, OAKLEY_2048, ProtocolKey, checksum, decrypt, dh_generate, dh_shared,
    encrypt, krb_fx_cf2, octetstring2key, p256_generate, string_to_key,
};
use krb5_kdc::{
    Acl, AdminOp, Error, KDB_DISALLOW_ALL_TIX, KDB_OK_TO_AUTH_AS_DELEGATE, NamedPolicy,
    PrincipalStore, RID_FIRST_USER, S2K_ITERS, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM,
    TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_admin_id, documented_host, pa_enc_timestamp, pac_from_ticket_part, sign_pac,
    tgs_req, ticket_checksum_der, verify_pac, verify_pac_signatures, wrap_win2k_pac,
};
use krb5_protocol::{
    apply_strengthen, armor_key, as_req_sname, attach_fast, build_fast_armor, pa_for_user,
    pa_pac_options, pa_pk_as_req, pa_pk_as_req_agile, pa_pk_as_req_cn, pa_pk_as_req_spki,
    pa_spake_response, pa_spake_support, pkinit_reply_key, pkinit_reply_key_agile, tgs_req_ex,
    unwrap_fast_rep,
};
use krb5_types::pac::{
    PAC_LOGON_INFO, PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM, Pac, RpcSid,
    parse_kerb_validation_info, zero_pac_ad_data,
};
use krb5_types::{
    ApReq, Checksum, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    EncryptionKey, KdcOptions, KerberosTime, MethodData, Microseconds, PaData, PaEncTsEnc,
    PrincipalName, ascii, err, flag_bit, ku, pa,
};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn pkinit_as_req(
    cname: PrincipalName,
    nonce: u32,
    make_pa: impl FnOnce(&[u8]) -> krb5_types::PaData,
) -> krb5_types::AsReq {
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![make_pa(&cksum)]);
    req
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    if let Ok(EncAsRepPart(p)) = decode::<EncAsRepPart>(plain) {
        return p;
    }
    if let Ok(EncTgsRepPart(p)) = decode::<EncTgsRepPart>(plain) {
        return p;
    }
    decode::<EncKdcRepPart>(plain).expect("enc-part")
}

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = password_key(name, password);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS")
}

#[test]
fn kpasswd_bumps_kvno_single_active_and_switches_password() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let before = store.get_name(&cname).expect("user");
    let old_kvno = before.keys.iter().map(|k| k.kvno).max().expect("kvno");
    store
        .change_password(
            &acl,
            &format!("{TEST_ADMIN}@{TEST_REALM}"),
            &cname,
            b"brand-new-pass",
        )
        .expect("cpw");
    let after = store.get_name(&cname).expect("user");
    let new_kvno = after.keys.iter().map(|k| k.kvno).max().expect("kvno");
    assert_eq!(new_kvno, old_kvno + 1);
    assert!(
        after.keys.iter().all(|k| k.kvno == new_kvno),
        "keepold=false: one active kvno"
    );

    let new_key = password_key(TEST_USER, b"brand-new-pass");
    let ok = as_req(
        cname.clone(),
        TEST_REALM,
        101,
        Some(vec![pa_enc_timestamp(&new_key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &ok).expect("AS with new password");

    let old = as_req(
        cname,
        TEST_REALM,
        102,
        Some(vec![pa_enc_timestamp(&user_key()).expect("pa")]),
    )
    .unwrap();
    match krb5_kdc::issue_as(&store, &old) {
        Err(
            Error::Crypto(_)
            | Error::Protocol {
                code: err::PREAUTH_FAILED,
                ..
            },
        ) => {}
        other => panic!("old password must fail AS, got {other:?}"),
    }
}

#[test]
fn kpasswd_denied_without_changepw_acl() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let acl = Acl::parse("admin@KERBER.TEST a\n");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let err = store
        .change_password(&acl, "admin@KERBER.TEST", &cname, b"x")
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::ChangePassword)
            .is_err()
    );
    let acl_c = Acl::parse("admin@KERBER.TEST c\n");
    store
        .change_password(&acl_c, "admin@KERBER.TEST", &cname, b"ok-pass")
        .expect("c bit allows cpw");
}

#[test]
fn fast_as_exchange_strengthen_and_finished() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 201);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let inner = vec![pa_enc_timestamp(&key).expect("pa")];
    let mut req = as_req(cname.clone(), TEST_REALM, 202, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    let issued = krb5_kdc::issue_as(&store, &req).expect("FAST AS");
    let fast = unwrap_fast_rep(&akey, &issued.rep.0.padata).expect("FAST rep");
    assert!(fast.finished.is_some(), "FAST finished required on AS-REP");
    let sk = fast.strengthen_key.expect("strengthen-key");
    let reply = apply_strengthen(&sk, &key).expect("CF2");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("AS enc");
    assert_eq!(plain.first().copied(), Some(0x79));
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 202);
    assert!(enc.flags.pre_authent());
}

#[test]
fn fast_as_forged_armor_realm_is_not_us() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 210);
    let mut ticket = armor_as.rep.0.ticket.clone();
    ticket.realm = ascii("OTHER.TEST");
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        ticket,
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let inner = vec![pa_enc_timestamp(&key).expect("pa")];
    let mut req = as_req(cname, TEST_REALM, 211, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("forged armor realm");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::NOT_US);
            assert_eq!(text.as_deref(), Some("FAST armor TGT"));
        }
        other => panic!("expected 35 NOT_US FAST armor TGT, got {other:?}"),
    }
}

fn issue_code(err: Error) -> i32 {
    match err {
        Error::Protocol { code, .. } => code,
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn challenge_pa(long_term: &ProtocolKey, armor_key: &ProtocolKey, ts: &KerberosTime) -> PaData {
    let chal = krb_fx_cf2(
        armor_key,
        long_term,
        b"clientchallengearmor",
        b"challengelongterm",
    )
    .expect("cf2");
    let der = encode(&PaEncTsEnc {
        patimestamp: ts.clone(),
        pausec: None,
    })
    .expect("ts");
    let usage = KeyUsage::new(ku::ENC_CHALLENGE_CLIENT).unwrap();
    let cipher = encrypt(&chal, usage, &der).expect("enc");
    let enc = EncryptedData {
        etype: chal.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    PaData {
        padata_type: pa::ENCRYPTED_CHALLENGE,
        padata_value: encode(&enc).expect("ed").into(),
    }
}

struct ArmorTgt {
    ticket: krb5_types::Ticket,
    session: ProtocolKey,
    sub: ProtocolKey,
}

fn armor_tgt(store: &PrincipalStore, armor_nonce: u32) -> ArmorTgt {
    let armor_as = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, armor_nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x51u8; 32])
        .expect("subkey");
    ArmorTgt {
        ticket: armor_as.rep.0.ticket,
        session: armor_as.session_key,
        sub,
    }
}

fn armor_ap_key(armor: &ArmorTgt, salt: u8) -> (krb5_types::ApReq, ProtocolKey) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut bytes = armor.sub.as_bytes().to_vec();
    bytes[0] ^= salt;
    let sub = ProtocolKey::from_bytes(armor.sub.etype(), &bytes).expect("sub");
    let armor_ap = build_fast_armor(
        armor.ticket.clone(),
        &armor.session,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&armor.session, Some(&sub)).expect("akey");
    (armor_ap, akey)
}

fn fast_challenge_req_with(
    armor_ap: &krb5_types::ApReq,
    akey: &ProtocolKey,
    long_term: &ProtocolKey,
    ts: &KerberosTime,
    nonce: u32,
) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let inner = vec![challenge_pa(long_term, akey, ts)];
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    attach_fast(&mut req, armor_ap, akey, inner).expect("FAST wrap");
    req
}

fn fast_challenge_req(
    store: &PrincipalStore,
    long_term: &ProtocolKey,
    ts: &KerberosTime,
    nonce: u32,
    armor_nonce: u32,
) -> krb5_types::AsReq {
    let (armor_ap, akey) = armor_ap_key(&armor_tgt(store, armor_nonce), 0);
    fast_challenge_req_with(&armor_ap, &akey, long_term, ts, nonce)
}

#[test]
fn encrypted_challenge_wrong_key_locks_at_max_fail() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.put_policy(NamedPolicy {
        name: "chalock".into(),
        min_length: 0,
        min_classes: 0,
        history: 0,
        max_fail: 2,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
    });
    store
        .set_principal_policy(&user, Some("chalock".into()))
        .unwrap();
    let armor = armor_tgt(&store, 800);
    let zeros = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0u8; 32]).unwrap();
    let now = KerberosTime::now();
    let bad = |nonce: u32| {
        let (ap, akey) = armor_ap_key(&armor, u8::try_from(nonce).unwrap_or(1));
        fast_challenge_req_with(&ap, &akey, &zeros, &now, nonce)
    };
    let e1 = krb5_kdc::issue_as(&store, &bad(801)).expect_err("wrong key");
    assert_eq!(issue_code(e1), err::PREAUTH_FAILED);
    assert_eq!(store.fail_auth_of(store.get_name(&user).unwrap()), 1);
    let e2 = krb5_kdc::issue_as(&store, &bad(803)).expect_err("second fail");
    assert_eq!(issue_code(e2), err::PREAUTH_FAILED);
    assert_eq!(store.fail_auth_of(store.get_name(&user).unwrap()), 2);
    let e3 = krb5_kdc::issue_as(&store, &bad(805)).expect_err("locked");
    assert_eq!(issue_code(e3), err::CLIENT_REVOKED);
}

#[test]
fn encrypted_challenge_stale_ts_is_skew() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let key = user_key();
    let stale = KerberosTime::now().add_seconds(-10_000).unwrap();
    let err = krb5_kdc::issue_as(&store, &fast_challenge_req(&store, &key, &stale, 811, 810))
        .expect_err("skew");
    assert_eq!(issue_code(err), err::SKEW);
}

#[test]
fn encrypted_challenge_replayed_blob_is_repeat() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let key = user_key();
    let now = KerberosTime::now();
    let req = fast_challenge_req(&store, &key, &now, 821, 820);
    krb5_kdc::issue_as(&store, &req).expect("first challenge");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("replay");
    assert_eq!(issue_code(err), err::REPEAT);
}

fn e_data_has_fx_fast(err: &Error) -> bool {
    let ed = match err {
        Error::Protocol {
            e_data: Some(ed), ..
        }
        | Error::PreauthRequired { e_data: ed } => ed.as_slice(),
        _ => return false,
    };
    decode::<MethodData>(ed).is_ok_and(|m| m.iter().any(|p| p.padata_type == pa::FX_FAST))
}

#[test]
fn encrypted_challenge_skew_is_fast_wrapped() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let key = user_key();
    let stale = KerberosTime::now().add_seconds(-10_000).unwrap();
    let err = krb5_kdc::issue_as(&store, &fast_challenge_req(&store, &key, &stale, 831, 830))
        .expect_err("skew");
    assert_eq!(issue_code(err.clone()), err::SKEW);
    assert!(
        e_data_has_fx_fast(&err),
        "post-armor SKEW must be FAST-wrapped"
    );
}

fn wrap_as_fast_bit(
    store: &PrincipalStore,
    nonce: u32,
    bit: usize,
) -> Result<krb5_kdc::IssuedAs, Error> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x45u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("akey");
    let mut req = as_req(cname, TEST_REALM, nonce + 1, None).unwrap();
    let inner = req.0.req_body.clone();
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(bit, true);
    wrap_fast_split_opts(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        opts,
    )
    .expect("FAST wrap");
    krb5_kdc::issue_as(store, &req)
}

#[test]
fn unknown_critical_fast_option_is_refused() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let err = wrap_as_fast_bit(&store, 840, 2).expect_err("critical option");
    assert_eq!(issue_code(err), err::UNKNOWN_CRITICAL_FAST_OPTION);
}

#[test]
fn noncritical_fast_option_bit_16_is_ignored() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    wrap_as_fast_bit(&store, 842, 16).expect("bit 16 is not unknown-critical");
}

#[test]
fn hide_client_names_is_refused() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let err = wrap_as_fast_bit(&store, 844, 1).expect_err("bit 1 hide-client-names");
    assert_eq!(issue_code(err), err::UNKNOWN_CRITICAL_FAST_OPTION);
}

#[test]
fn explicit_as_armor_invalid_tgt_is_tkt_nyv() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        846,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true)
        .with_bit(flag_bit::POSTDATED, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("postdated AS");
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x46u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&issued.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 847, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("INVALID armor");
    assert_eq!(issue_code(err), err::TKT_NYV);
}

#[test]
fn fast_as_armor_for_host_ticket_is_server_nomatch() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 853);
    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        854,
    )
    .expect("TGS-REQ");
    let svc = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x49u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&svc.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 855, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("host armor");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::SERVER_NOMATCH);
            assert_eq!(text.as_deref(), Some("FAST armor TGT"));
        }
        other => panic!("expected 26 SERVER_NOMATCH, got {other:?}"),
    }
}

#[test]
fn explicit_as_armor_expired_tgt_is_tkt_expired() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 851);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    part.endtime = KerberosTime::now().add_seconds(-120).unwrap();
    let plain = encode(&part).expect("enc-tkt");
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let cipher = encrypt(&krbtgt.key, usage, &plain).expect("ticket");
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.cipher = cipher.into();
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x48u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        ticket,
        &issued.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor");
    let akey = armor_key(&issued.session_key, Some(&sub)).expect("akey");
    let mut fast_req = as_req(cname, TEST_REALM, 852, None).unwrap();
    let inner = fast_req.0.req_body.clone();
    wrap_fast_split_opts(
        &mut fast_req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
        inner,
        krb5_types::fast::fast_options_none(),
    )
    .expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &fast_req).expect_err("expired armor");
    assert_eq!(issue_code(err), err::TKT_EXPIRED);
}

#[test]
fn tgs_fast_inner_nonce_not_outer() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 850);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        100,
    )
    .unwrap();
    let mut inner_body = tgs.0.req_body.clone();
    inner_body.nonce = 200;
    let subkey = wrap_tgs_fast(&mut tgs, &issued.session_key, inner_body).expect("TGS FAST");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART_SUBKEY).unwrap();
    let plain = decrypt(&subkey, usage, out.rep.0.enc_part.cipher.as_ref()).expect("TGS enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(
        enc.nonce, 200,
        "EncTgsRepPart must echo the inner FAST nonce"
    );
}

#[test]
fn tgs_fast_validate_allows_invalid_tgt_armor() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let from = KerberosTime::now().add_seconds(2).unwrap();
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        860,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.from = Some(from);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::MAY_POSTDATE, true)
        .with_bit(flag_bit::POSTDATED, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("postdated AS");
    let mut tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        861,
        KdcOptions::forwardable().with_bit(flag_bit::VALIDATE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .expect("VALIDATE");
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    krb5_kdc::issue_tgs(&store, &tgs).expect("FAST VALIDATE");
}

fn wrap_tgs_fast(
    req: &mut krb5_types::TgsReq,
    session: &ProtocolKey,
    inner_body: krb5_types::KdcReqBody,
) -> Result<ProtocolKey, krb5_protocol::Error> {
    let padata = req
        .0
        .padata
        .as_mut()
        .ok_or_else(|| krb5_protocol::Error::Asn1("no padata".into()))?;
    let pa_tgs = padata
        .iter_mut()
        .find(|x| x.padata_type == pa::TGS_REQ)
        .ok_or_else(|| krb5_protocol::Error::Asn1("no PA-TGS-REQ".into()))?;
    let mut ap: ApReq = decode(pa_tgs.padata_value.as_ref())
        .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let mut authenticator: krb5_types::Authenticator =
        decode(&auth_plain).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let subkey = ProtocolKey::from_bytes(session.etype(), &[0x51u8; 32])
        .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    authenticator.subkey = Some(EncryptionKey {
        keytype: subkey.etype().to_iana(),
        keyvalue: subkey.as_bytes().to_vec().into(),
    });
    let auth_der = encode(&authenticator).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    ap.authenticator.cipher = encrypt(session, auth_usage, &auth_der)?.into();
    pa_tgs.padata_value = encode(&ap)
        .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
        .into();
    let ap_raw = pa_tgs.padata_value.as_ref().to_vec();
    let armor_key = krb_fx_cf2(&subkey, session, b"subkeyarmor", b"ticketarmor")?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(&armor_key, ck_usage, &ap_raw)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: Vec::new(),
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(&armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let pa = krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    };
    req.0.padata.get_or_insert_with(Vec::new).push(pa);
    Ok(subkey)
}

fn wrap_tgs_fast_no_subkey(
    req: &mut krb5_types::TgsReq,
    armor_key: &ProtocolKey,
    inner_body: krb5_types::KdcReqBody,
) -> Result<(), krb5_protocol::Error> {
    let ap_raw = req
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
        .map(|p| p.padata_value.as_ref().to_vec())
        .ok_or_else(|| krb5_protocol::Error::Asn1("no PA-TGS-REQ".into()))?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, &ap_raw)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: Vec::new(),
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let pa = krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    };
    req.0.padata.get_or_insert_with(Vec::new).push(pa);
    Ok(())
}

#[test]
fn tgs_fast_forged_ticket_realm_is_process_tgs() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 870);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        871,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    ap.ticket.realm = ascii("NOWHERE.TEST");
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("forged realm");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 7 PROCESS_TGS, got {other:?}"),
    }
}

#[test]
fn tgs_fast_explicit_armor_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 872);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        873,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let pa_tgs = tgs
        .0
        .padata
        .as_ref()
        .unwrap()
        .iter()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ")
        .padata_value
        .clone();
    let pa_fast = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::FX_FAST)
        .expect("FAST");
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(pa_fast.padata_value.as_ref()).expect("fast");
    armored.armor = Some(krb5_types::fast::KrbFastArmor {
        armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
        armor_value: pa_tgs,
    });
    pa_fast.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .expect("re-encode")
        .into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("explicit TGS armor");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::PREAUTH_FAILED);
            assert_eq!(
                text.as_deref(),
                Some("Ap-request armor not permitted with TGS")
            );
        }
        other => panic!("expected 24 PREAUTH_FAILED, got {other:?}"),
    }
}

#[test]
fn tgs_fast_without_subkey_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 874);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        875,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast_no_subkey(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("no subkey");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::PREAUTH_FAILED);
            assert_eq!(
                text.as_deref(),
                Some("No armor key but FAST armored request present")
            );
        }
        other => panic!("expected 24 PREAUTH_FAILED, got {other:?}"),
    }
}

fn map_fx_fast_as(
    req: &mut krb5_types::AsReq,
    f: impl FnOnce(&mut krb5_types::fast::KrbFastArmoredReq),
) {
    let pa = req
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::FX_FAST)
        .expect("FAST");
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(pa.padata_value.as_ref()).expect("fast");
    f(&mut armored);
    pa.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .expect("re-encode")
        .into();
}

fn map_fx_fast_tgs(
    req: &mut krb5_types::TgsReq,
    f: impl FnOnce(&mut krb5_types::fast::KrbFastArmoredReq),
) {
    let pa = req
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::FX_FAST)
        .expect("FAST");
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(pa.padata_value.as_ref()).expect("fast");
    f(&mut armored);
    pa.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .expect("re-encode")
        .into();
}

fn fast_as_prepared(store: &PrincipalStore, nonce: u32) -> (krb5_types::AsReq, ProtocolKey) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let armor_as = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x47u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let mut req = as_req(cname, TEST_REALM, nonce + 1, None).unwrap();
    attach_fast(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&key).expect("pa")],
    )
    .expect("FAST wrap");
    (req, akey)
}

fn fast_tgs_prepared(store: &PrincipalStore, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce + 1,
    )
    .unwrap();
    let inner = tgs.0.req_body.clone();
    wrap_tgs_fast(&mut tgs, &issued.session_key, inner).expect("TGS FAST");
    tgs
}

#[test]
fn fast_as_bad_req_checksum_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 890);
    map_fx_fast_as(&mut req, |a| {
        let mut ck = a.req_checksum.checksum.to_vec();
        ck[0] ^= 0xff;
        a.req_checksum.checksum = ck.into();
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("bad FAST checksum");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::MODIFIED);
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
        }
        other => panic!("expected 41 MODIFIED FIND_FAST, got {other:?}"),
    }
}

#[test]
fn fast_tgs_bad_req_checksum_is_modified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut tgs = fast_tgs_prepared(&store, 892);
    map_fx_fast_tgs(&mut tgs, |a| {
        let mut ck = a.req_checksum.checksum.to_vec();
        ck[0] ^= 0xff;
        a.req_checksum.checksum = ck.into();
    });
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("bad FAST checksum");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::MODIFIED);
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
        }
        other => panic!("expected 41 MODIFIED FIND_FAST, got {other:?}"),
    }
}

#[test]
fn fast_as_unkeyed_checksum_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 894);
    map_fx_fast_as(&mut req, |a| a.req_checksum.cksumtype = 1);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("unkeyed FAST checksum");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("Unkeyed checksum used in fast_req"));
        }
        other => panic!("expected 12 POLICY unkeyed, got {other:?}"),
    }
}

#[test]
fn fast_tgs_unkeyed_checksum_is_policy() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut tgs = fast_tgs_prepared(&store, 896);
    map_fx_fast_tgs(&mut tgs, |a| a.req_checksum.cksumtype = 7);
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("unkeyed FAST checksum");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("Unkeyed checksum used in fast_req"));
        }
        other => panic!("expected 12 POLICY unkeyed, got {other:?}"),
    }
}

#[test]
fn fast_as_unknown_armor_type_is_preauth_failed() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, _) = fast_as_prepared(&store, 898);
    map_fx_fast_as(&mut req, |a| {
        a.armor.as_mut().expect("armor").armor_type = 99;
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("unknown armor");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::PREAUTH_FAILED);
            assert_eq!(text.as_deref(), Some("Unknown FAST armor type 99"));
        }
        other => panic!("expected 24 Unknown FAST armor type, got {other:?}"),
    }
}

#[test]
fn fast_as_checksum_ignores_pa_tgs_req() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let (mut req, akey) = fast_as_prepared(&store, 900);
    let dummy = b"dummy-pa-tgs-req-not-the-body";
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).unwrap();
    let mic = checksum(&akey, ck_usage, dummy).expect("mic");
    map_fx_fast_as(&mut req, |a| {
        a.req_checksum.checksum = mic.into();
    });
    req.0.padata.as_mut().unwrap().insert(
        0,
        PaData {
            padata_type: pa::TGS_REQ,
            padata_value: dummy.to_vec().into(),
        },
    );
    let err = krb5_kdc::issue_as(&store, &req).expect_err("body-only FAST checksum");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::MODIFIED);
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
        }
        other => panic!("expected 41 MODIFIED FIND_FAST, got {other:?}"),
    }
}

#[test]
fn tgs_authenticator_cname_mismatch_is_badmatch() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 904);
    let mut tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        905,
    )
    .unwrap();
    let pa = tgs
        .0
        .padata
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p.padata_type == pa::TGS_REQ)
        .expect("PA-TGS-REQ");
    let mut ap: ApReq = decode(pa.padata_value.as_ref()).expect("ap");
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap();
    let auth_plain = decrypt(
        &issued.session_key,
        auth_usage,
        ap.authenticator.cipher.as_ref(),
    )
    .expect("auth");
    let mut authenticator: krb5_types::Authenticator = decode(&auth_plain).expect("authenticator");
    authenticator.cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let auth_der = encode(&authenticator).expect("auth der");
    ap.authenticator.cipher = encrypt(&issued.session_key, auth_usage, &auth_der)
        .expect("enc")
        .into();
    pa.padata_value = encode(&ap).expect("ap").into();
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("cname mismatch");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::BADMATCH);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("expected 36 BADMATCH PROCESS_TGS, got {other:?}"),
    }
}

#[test]
fn spake_challenge_then_as_rep() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .expect("user")
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .expect("aes256-sha1 key")
        .key
        .clone();
    let support = pa_spake_support();
    let req1 = as_req(cname.clone(), TEST_REALM, 301, Some(vec![support.clone()])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req1).unwrap_err();
    let e_data = match err {
        Error::Protocol {
            code,
            e_data: Some(e_data),
            ..
        } if code == err::MORE_PREAUTH_DATA_REQUIRED => e_data,
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let spa = method
        .iter()
        .find(|p| p.padata_type == pa::SPAKE)
        .expect("PA-SPAKE");
    let cookie = method
        .iter()
        .find(|p| p.padata_type == pa::FX_COOKIE)
        .expect("cookie");
    let msg: krb5_types::spake::PaSpake = decode(spa.padata_value.as_ref()).expect("PaSpake");
    let chal = match msg {
        krb5_types::spake::PaSpake::Challenge(c) => c,
        other => panic!("expected SPAKE challenge, got {other:?}"),
    };
    let mut req2 = as_req(cname, TEST_REALM, 302, None).unwrap();
    let body_der = encode(&req2.0.req_body).expect("body");
    let (resp, spake_key) = pa_spake_response(
        &key,
        support.padata_value.as_ref(),
        spa.padata_value.as_ref(),
        chal.pubkey.as_ref(),
        &body_der,
    )
    .expect("resp");
    req2.0.padata = Some(vec![
        resp,
        krb5_types::PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: cookie.padata_value.clone(),
        },
    ]);
    let issued = krb5_kdc::issue_as(&store, &req2).expect("SPAKE AS");
    assert_eq!(issued.as_rep_key.as_bytes(), spake_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&spake_key, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 302);
}

#[test]
fn pkinit_advertised_in_method_data_when_ca_enabled() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 400, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().any(|p| p.padata_type == pa::PK_AS_REQ),
        "PA-PK-AS-REQ must be advertised when the CA is provisioned: {method:?}"
    );
    assert!(method.iter().any(|p| p.padata_type == pa::ENC_TIMESTAMP));
    assert!(method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2));
    assert!(
        method.iter().any(|p| p.padata_type == pa::FX_FAST),
        "PA-FX-FAST must be advertised so MIT kinit -T armors AS: {method:?}"
    );
}

#[test]
fn ca_enabled_preauth_required_method_data_types() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 401, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![
            pa::FX_FAST,
            pa::PK_AS_REQ,
            pa::TD_DH_PARAMETERS,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::ETYPE_INFO2,
        ],
        "CA-enabled METHOD-DATA types must pin [136, 16, 109, 151, 2, 19]"
    );
    let again = encode(&method).expect("re-encode");
    let round: MethodData = decode(&again).expect("decode encode");
    assert_eq!(round, method);
    assert_eq!(again, e_data, "METHOD-DATA encode(decode) must be identity");
}

#[test]
fn pkinit_not_advertised_without_ca() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    assert!(store.pkinit_ca().is_none());
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 399, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let e_data = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    assert!(
        method.iter().all(|p| p.padata_type != pa::PK_AS_REQ),
        "PA-PK-AS-REQ must not be advertised without a CA"
    );
}

#[test]
fn pkinit_ecdh_reply_key() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname, 401, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply = pkinit_reply_key(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        TEST_REALM,
    )
    .expect("ECDH key");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 401);
}

#[test]
fn pkinit_ecdh_rfc8636_sha256_kdf() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 411, |ck| {
        pa_pk_as_req_agile(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ agile")
    });
    let as_req_der = encode(&req).expect("AS-REQ");
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS agile");
    let raw_rep = issued
        .rep
        .0
        .padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .expect("PA-PK-AS-REP");
    assert_eq!(
        krb5_types::pkinit::pa_pk_as_rep_kdf_oid(raw_rep.padata_value.as_ref()).as_deref(),
        Some(krb5_types::pkinit::KDF_AH_SHA256_OID)
    );
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply = pkinit_reply_key_agile(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    )
    .expect("agile ECDH key");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let o2k = pkinit_reply_key(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        TEST_REALM,
    );
    assert!(o2k.is_err(), "o2k helper must not silently decrypt agile");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 411);
}

#[test]
fn pkinit_modp14_reply_key() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = dh_generate(&OAKLEY_2048).expect("client DH");
    let spki = krb5_types::pkinit::encode_dh_spki(&OAKLEY_2048.prime_bytes(), &kp.public);
    let req = pkinit_as_req(cname, 404, |ck| {
        pa_pk_as_req_spki(&spki, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT DH AS");
    let kdc_y = kdc_dh_public_from_rep(issued.rep.0.padata.as_deref(), &ca.ca_cert);
    let shared = dh_shared(&OAKLEY_2048, &kp.secret, &kdc_y).expect("DH");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let reply = octetstring2key(et, &shared).expect("o2k");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 404);
}

fn kdc_dh_public_from_rep(padata: Option<&[krb5_types::PaData]>, trust: &[u8]) -> Vec<u8> {
    let raw = padata
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .expect("PA-PK-AS-REP");
    let rep: krb5_types::pkinit::PaPkAsRep = decode(raw.padata_value.as_ref()).expect("rep");
    let info = match rep {
        krb5_types::pkinit::PaPkAsRep::DhInfo(i) => i,
        krb5_types::pkinit::PaPkAsRep::EncKeyPack(_) => panic!("encKeyPack"),
    };
    let inner =
        krb5_types::pkinit::cms_verify(info.dh_signed_data.as_ref(), trust).expect("KDC CMS");
    let payload = krb5_types::pkinit::decode_kdc_dh_point(&inner).expect("KdcDHKeyInfo");
    krb5_types::pkinit::der_integer_unsigned(&payload).expect("DH INTEGER")
}

#[test]
fn pkinit_forged_cms_is_rejected() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: krb5_types::Microseconds::ZERO,
            ctime: krb5_types::KerberosTime::now(),
            nonce: 1,
            pa_checksum: None,
        },
        client_public_value: Some(kp.public.clone().into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack).expect("authpack");
    let req_body = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: inner.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    let pa = krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&req_body).expect("pa").into(),
    };
    let req = as_req(cname, TEST_REALM, 402, Some(vec![pa])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("forged CMS");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_without_provisioned_ca_is_rejected() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    assert!(store.pkinit_ca().is_none());
    let ca = krb5_types::pkinit::PkinitCa::generate().expect("unrelated CA");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa = pa_pk_as_req(&kp.public, &ca, None).expect("PA-PK-AS-REQ");
    let req = as_req(cname, TEST_REALM, 403, Some(vec![pa])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("PKINIT off");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

fn pkinit_rep_from_cms(cms: Vec<u8>) -> Option<Vec<krb5_types::PaData>> {
    let rep = krb5_types::pkinit::PaPkAsRep::DhInfo(krb5_types::pkinit::DhRepInfo {
        dh_signed_data: cms.into(),
        server_dh_nonce: None,
    });
    Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REP,
        padata_value: encode(&rep).ok()?.into(),
    }])
}

#[test]
fn pkinit_client_rejects_non_kdc_signer() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 421, |ck| {
        pa_pk_as_req_agile(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let as_req_der = encode(&req).expect("AS-REQ");
    let issued = krb5_kdc::issue_as(&store, &req).expect("PKINIT AS");
    let et = EncryptionType::Aes256CtsHmacSha196;
    let ok = pkinit_reply_key_agile(
        &kp.secret,
        &issued.rep.0.padata,
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    )
    .expect("KPKdc reply");
    assert_eq!(ok.as_bytes(), issued.as_rep_key.as_bytes());

    let raw = issued
        .rep
        .0
        .padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .expect("PA-PK-AS-REP");
    let cms = krb5_types::pkinit::pa_pk_as_rep_dh_signed_data(raw.padata_value.as_ref())
        .expect("dhSignedData");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");

    let (ccert, ckey) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let rogue = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        &ccert,
        &ckey,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("rogue cms");
    let err = pkinit_reply_key_agile(
        &kp.secret,
        &pkinit_rep_from_cms(rogue),
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    );
    assert!(err.is_err(), "client-cert KDC CMS must be refused: {err:?}");

    let (wcert, wkey, _) = ca.kdc_identity_for("OTHER.TEST").expect("wrong realm");
    let wrong = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        &wcert,
        &wkey,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("wrong cms");
    let err = pkinit_reply_key_agile(
        &kp.secret,
        &pkinit_rep_from_cms(wrong),
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    );
    assert!(err.is_err(), "wrong-realm KDC SAN must be refused: {err:?}");

    let (kcert, kkey, _) = ca.kdc_identity_for(TEST_REALM).expect("kdc id");
    let bad_ct = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        &kcert,
        &kkey,
        krb5_types::pkinit::ECONTENT_AUTHDATA,
    )
    .expect("authdata cms");
    let err = pkinit_reply_key_agile(
        &kp.secret,
        &pkinit_rep_from_cms(bad_ct),
        et,
        &ca.ca_cert,
        &as_req_der,
        &cname,
        TEST_REALM,
    );
    assert!(
        err.is_err(),
        "eContentType AUTHDATA must be refused: {err:?}"
    );
}

#[test]
fn pkinit_san_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname.clone(), 422, |ck| {
        pa_pk_as_req_cn(&kp.public, &ca, "other@KERBER.TEST", Some(ck)).expect("other")
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("SAN mismatch");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_ok = pkinit_as_req(cname, 423, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("user")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("matching SAN");
}

#[test]
fn pkinit_pachecksum_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let pa_missing = pa_pk_as_req(&kp.public, &ca, None).expect("missing");
    let req_missing = as_req(cname.clone(), TEST_REALM, 424, Some(vec![pa_missing])).unwrap();
    let err = krb5_kdc::issue_as(&store, &req_missing).expect_err("missing paChecksum");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_bad = pkinit_as_req(cname.clone(), 425, |ck| {
        let mut wrong = ck.to_vec();
        wrong[0] ^= 1;
        pa_pk_as_req(&kp.public, &ca, Some(&wrong)).expect("wrong")
    });
    let err = krb5_kdc::issue_as(&store, &req_bad).expect_err("bad paChecksum");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_ok = pkinit_as_req(cname, 426, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("ok")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("matching paChecksum");
}

#[test]
fn pkinit_signed_content_type_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req_ok = pkinit_as_req(cname.clone(), 427, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("ok")
    });
    let pa = req_ok
        .0
        .padata
        .as_ref()
        .and_then(|v| v.first())
        .expect("pa");
    let cms = krb5_types::pkinit::parse_pa_pk_as_req_cms(pa.padata_value.as_ref()).expect("cms");
    let inner = krb5_types::pkinit::cms_verify(&cms, &ca.ca_cert).expect("inner");
    let (cert, key) = ca
        .client_identity_for("user@KERBER.TEST")
        .expect("client id");
    let bad = krb5_types::pkinit::cms_sign_leaf_oids(
        &inner,
        &cert,
        &key,
        krb5_types::pkinit::ECONTENT_AUTHDATA,
        krb5_types::pkinit::ECONTENT_DHKEY,
    )
    .expect("split oids");
    let wrapped = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: bad.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    let mut req = req_ok;
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&wrapped).expect("pa").into(),
    }]);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("content-type");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_two_authpacks_same_second_both_issue() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp1 = p256_generate().expect("ecdh1");
    let kp2 = p256_generate().expect("ecdh2");
    let req1 = pkinit_as_req(cname.clone(), 452, |ck| {
        pa_pk_as_req(&kp1.public, &ca, Some(ck)).expect("PA-PK-AS-REQ 1")
    });
    let req2 = pkinit_as_req(cname, 452, |ck| {
        pa_pk_as_req(&kp2.public, &ca, Some(ck)).expect("PA-PK-AS-REQ 2")
    });
    krb5_kdc::issue_as(&store, &req1).expect("first AuthPack");
    krb5_kdc::issue_as(&store, &req2).expect("second AuthPack same second");
}

#[test]
fn pkinit_replayed_authpack_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(cname, 440, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    krb5_kdc::issue_as(&store, &req).expect("first PKINIT");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("replay");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

#[test]
fn pkinit_stale_ctime_is_skew() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let mut req = as_req(cname, TEST_REALM, 441, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::from_unix_seconds(1),
            nonce: 1,
            pa_checksum: Some(cksum.into()),
        },
        client_public_value: Some(krb5_types::pkinit::encode_ec_spki(&kp.public).into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack).expect("AuthPack");
    let signed = ca.sign_cms(&inner, "user").expect("cms");
    let pa = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: signed.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&pa).expect("pa").into(),
    }]);
    let err = krb5_kdc::issue_as(&store, &req).expect_err("stale ctime");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::SKEW),
        other => panic!("expected SKEW, got {other}"),
    }
}

#[test]
fn pkinit_under_fast_issues() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let armor_as = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 442);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x43u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let mut req = as_req(cname, TEST_REALM, 443, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&body);
    let inner = vec![pa_pk_as_req(&kp.public, &ca, Some(&ck)).expect("PA-PK-AS-REQ")];
    attach_fast(&mut req, &armor_ap, &akey, inner).expect("FAST wrap");
    krb5_kdc::issue_as(&store, &req).expect("PKINIT+FAST");
}

#[test]
fn pkinit_fast_inner_body_hash_mismatch_is_refused() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kp = p256_generate().expect("client ECDH");
    let armor_as = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 444);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44u8; 32])
        .expect("subkey");
    let armor_ap = build_fast_armor(
        armor_as.rep.0.ticket.clone(),
        &armor_as.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(&armor_as.session_key, Some(&sub)).expect("armor key");
    let mut req = as_req(cname, TEST_REALM, 445, None).unwrap();
    let outer = encode(&req.0.req_body).expect("outer");
    let ck = krb5_types::pkinit::kdc_req_body_checksum(&outer);
    let pa = pa_pk_as_req(&kp.public, &ca, Some(&ck)).expect("PA-PK-AS-REQ");
    let mut inner_body = req.0.req_body.clone();
    inner_body.nonce = inner_body.nonce.wrapping_add(1);
    wrap_fast_split(&mut req, &armor_ap, &akey, vec![pa], inner_body).expect("FAST wrap");
    let err = krb5_kdc::issue_as(&store, &req).expect_err("inner paChecksum");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
}

fn wrap_fast_split(
    req: &mut krb5_types::AsReq,
    armor: &krb5_types::ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<krb5_types::PaData>,
    inner_body: krb5_types::KdcReqBody,
) -> Result<(), krb5_protocol::Error> {
    wrap_fast_split_opts(
        req,
        armor,
        armor_key,
        inner_padata,
        inner_body,
        krb5_types::fast::fast_options_none(),
    )
}

fn wrap_fast_split_opts(
    req: &mut krb5_types::AsReq,
    armor: &krb5_types::ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<krb5_types::PaData>,
    inner_body: krb5_types::KdcReqBody,
    fast_options: krb5_types::fast::FastOptions,
) -> Result<(), krb5_protocol::Error> {
    let outer = encode(&req.0.req_body).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, &outer)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options,
        padata: inner_padata,
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(armor_key, enc_usage, &inner_der)?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: encode(armor)
                .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
                .into(),
        }),
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    req.0.padata = Some(vec![krb5_types::PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| krb5_protocol::Error::Asn1(e.to_string()))?
            .into(),
    }]);
    Ok(())
}

#[test]
fn pkinit_enterprise_san_binds_issued_cname() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let stored = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user@OTHER.TEST"]);
    store
        .create_password(&acl, &documented_admin_id(), &stored, b"foreign-pass")
        .expect("create");
    let ent = PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@OTHER.TEST"]);
    let kp = p256_generate().expect("client ECDH");
    let req = pkinit_as_req(ent.clone(), 428, |ck| {
        pa_pk_as_req(&kp.public, &ca, Some(ck)).expect("san user")
    });
    let err = krb5_kdc::issue_as(&store, &req).expect_err("SAN vs issued cname");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("expected PREAUTH_FAILED, got {other}"),
    }
    let req_ok = pkinit_as_req(ent, 429, |ck| {
        pa_pk_as_req_cn(&kp.public, &ca, "user@OTHER.TEST@KERBER.TEST", Some(ck))
            .expect("issued san")
    });
    krb5_kdc::issue_as(&store, &req_ok).expect("SAN matches issued cname");
}

#[test]
fn as_and_tgs_tickets_carry_verifiable_pac() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 501);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let tgt_part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&tgt_part).expect("PAC on TGT");
    verify_pac(&pac, &krbtgt.key, &krbtgt.key).expect("TGT PAC");

    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        502,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &tgs_out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&svc).expect("PAC on service ticket");
    verify_pac(&pac, &host.key, &krbtgt.key).expect("service PAC");
    let ident = store.pac_identity(&cname, TEST_REALM);
    let signed = sign_pac(
        &cname,
        tgt_part.authtime.unix_seconds(),
        &host.key,
        &krbtgt.key,
        &[],
        &ident,
        None,
    )
    .expect("sign");
    verify_pac(&signed, &host.key, &krbtgt.key).expect("re-sign");
}

fn issue_host_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("host AS")
}

fn or_host_attr(store: &mut PrincipalStore, bit: u32) {
    let host = documented_host();
    let a = store.get_name(&host).unwrap().attributes | bit;
    store
        .apply_admin_fields(&host, Some(a), None, None, None, None, false)
        .unwrap();
}

#[test]
fn s4u2self_impersonates_user() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    or_host_attr(&mut store, KDB_OK_TO_AUTH_AS_DELEGATE);
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_host_tgt(&store, 601);
    let pa = pa_for_user(&tgt.session_key, admin.clone(), TEST_REALM).expect("PA-FOR-USER");
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        602,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("S4U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Self");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    assert!(part.flags.forwardable());
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    verify_pac(&pac, &hostk.key, &krbtgt.key).expect("S4U PAC");
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
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 640);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        641,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
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
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_host_tgt(&store, 650);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        651,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("S4U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Self");
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).expect("enc");
    assert!(!part.flags.forwardable());
}

#[test]
fn s4u2self_local_tgt_referral_is_looking_up_server() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x11; 32]).unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "OTHER.TEST", ir)
        .expect("interrealm");
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_host_tgt(&store, 660);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]),
        TEST_REALM,
        661,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("S4U TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
            assert_eq!(text.as_deref(), Some("LOOKING_UP_SERVER"));
        }
        other => panic!("expected 7 LOOKING_UP_SERVER, got {other:?}"),
    }
}

#[test]
fn s4u2self_local_tgt_foreign_user_is_not_ours() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let foreign = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]);
    let tgt = issue_host_tgt(&store, 670);
    let pa = pa_for_user(&tgt.session_key, foreign, "OTHER.TEST").expect("PA-FOR-USER");
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        671,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
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

fn s4u2self_tgs(store: &PrincipalStore, for_user: PrincipalName, nonce: u32) -> krb5_types::TgsReq {
    let host = documented_host();
    let tgt = issue_host_tgt(store, nonce);
    let pa = pa_for_user(&tgt.session_key, for_user, TEST_REALM).expect("PA-FOR-USER");
    tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce + 1,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("S4U TGS-REQ")
}

fn s4u_code(e: Error) -> i32 {
    match e {
        Error::Protocol { code, .. } => code,
        other => panic!("expected protocol error, got {other:?}"),
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
        .apply_admin_fields(&admin, Some(a), None, None, None, None, false)
        .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &s4u2self_tgs(&store, admin, 620)).unwrap_err();
    assert_eq!(s4u_code(err), err::CLIENT_REVOKED);
}

#[test]
fn s4u2self_expired_for_user_is_name_exp() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store
        .apply_admin_fields(&admin, None, None, Some(1), None, None, false)
        .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &s4u2self_tgs(&store, admin, 630)).unwrap_err();
    assert_eq!(s4u_code(err), err::NAME_EXP);
}

#[test]
fn s4u2proxy_takes_cname_from_evidence() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 701);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        702,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 703);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        704,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Proxy");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    let pac = pac_from_ticket_part(&part).expect("copied PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_eq!(logon.user_id, store.get_name(&admin).unwrap().rid);
    assert_eq!(logon.effective_name.value, TEST_ADMIN);
}

#[test]
fn s4u2proxy_rejects_non_forwardable_evidence() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 711);
    let evidence_tgs = tgs_req_ex(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        712,
        KdcOptions::none(),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("non-forwardable evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_long = store.get_name(&user).unwrap().best_key().unwrap();
    let ev_part = decrypt_ticket_part(&user_long.key, &evidence.rep.0.ticket).expect("ev");
    assert!(
        !ev_part.flags.forwardable(),
        "fixture must be a non-forwardable evidence ticket"
    );
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 713);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        714,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("expected BADOPTION, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_rejects_malformed_pac_options() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 721);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        722,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 723);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let bad = krb5_types::PaData {
        padata_type: pa::PAC_OPTIONS,
        padata_value: b"not-der".to_vec().into(),
    };
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        724,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        vec![bad],
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("expected BADOPTION for malformed PA-PAC-OPTIONS, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_classic_denied_without_allowed_to() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 751);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        752,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 753);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        754,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("classic S4U2Proxy without allowed-to must deny, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_honors_pac_options_rbcd() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 731);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        732,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 733);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        734,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        vec![pa_pac_options(true).expect("PA-PAC-OPTIONS")],
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("RBCD without allow-list must deny, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_rbcd_allowed_from_succeeds() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_from(&documented_host(), &user.components_joined());
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 741);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        742,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 743);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        744,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        vec![pa_pac_options(true).expect("PA-PAC-OPTIONS")],
        pref_etypes(),
    )
    .expect("S4U2Proxy TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("RBCD allowed");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
}

#[test]
fn u2u_encrypts_ticket_in_additional_tgt_session() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 801);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 802);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        803,
        opts,
        Some(vec![admin_tgt.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .expect("U2U TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("U2U");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    assert!(
        decrypt_ticket_part(&host.key, &out.rep.0.ticket).is_err(),
        "U2U ticket must not use the service long-term key"
    );
    let part = decrypt_ticket_part(&admin_tgt.session_key, &out.rep.0.ticket).expect("U2U enc");
    assert_eq!(part.cname.components_joined(), TEST_USER);
    assert_eq!(part.key.keyvalue.as_ref(), out.session_key.as_bytes());
}

#[test]
fn s4u2self_bad_checksum_rejected() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 901);
    let mut pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).expect("PA-FOR-USER");
    let mut for_user: krb5_types::s4u::PaForUser =
        decode(pa.padata_value.as_ref()).expect("PaForUser");
    let mut ck = for_user.cksum.checksum.to_vec();
    ck[0] ^= 0xff;
    for_user.cksum.checksum = ck.into();
    pa.padata_value = encode(&for_user).expect("re-encode").into();
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        902,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .expect("TGS-REQ");
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::INAPP_CKSUM);
}

#[test]
fn as_wrong_realm_is_chaseable() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 50, None).unwrap();
    req.0.req_body.realm = ascii("OTHER.TEST");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(
        std::str::from_utf8(e.realm.as_bytes()).unwrap(),
        "OTHER.TEST"
    );
}

#[test]
fn tgs_referral_uses_interrealm_key_and_transited() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 51);
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        other.clone(),
        TEST_REALM,
        52,
    )
    .expect("referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("referral");
    assert_eq!(out.rep.0.ticket.sname, other);
    let ir = store.get_name(&other).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&ir.key, &out.rep.0.ticket).expect("inter-realm enc");
    assert!(
        part.transited
            .realms_for(TEST_REALM, "OTHER.TEST")
            .expect("expand")
            .is_empty(),
        "first-hop referral transited excludes client realm: {:?}",
        part.transited.realms_for(TEST_REALM, "OTHER.TEST")
    );
}

#[test]
fn as_rep_advertises_supported_enctypes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 53);
    let pa = issued.rep.0.padata.as_ref().expect("padata");
    let raw = pa
        .iter()
        .find(|p| p.padata_type == pa::SUPPORTED_ENCTYPES)
        .expect("PA-SUPPORTED-ENCTYPES")
        .padata_value
        .as_ref();
    assert!(raw.len() >= 4);
    let bits = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap();
    let expect = user.supported_enctypes_mask();
    assert_eq!(bits, expect, "bits must match keys on the principal");
    assert_ne!(
        bits, 0x18,
        "must not be the static AES-SHA1 mask; SHA-2 keys are present"
    );
    assert_eq!(
        bits & 0x18,
        0x18,
        "AES-SHA1 17/18 still advertised when those keys exist"
    );
}

#[test]
fn pac_logon_info_is_ndr() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 54);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("parse");
    let logon = parsed
        .buffers
        .iter()
        .find(|b| b.kind == krb5_types::pac::PAC_LOGON_INFO)
        .expect("logon");
    let (c, r) = krb5_types::pac::parse_logon_info(&logon.data).expect("NDR");
    assert_eq!(c, TEST_USER);
    assert_eq!(r, TEST_REALM);
}

#[test]
fn enterprise_as_canonicalizes_cname() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let ent = PrincipalName::new(
        PrincipalName::NT_ENTERPRISE,
        [format!("{TEST_USER}@{TEST_REALM}")],
    );
    assert!(
        store.get_name(&ent).is_some(),
        "NT-ENTERPRISE user@REALM must look up user, not user@REALM@REALM"
    );
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let mut req = as_req(
        ent,
        TEST_REALM,
        70,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::CANONICALIZE, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("enterprise AS");
    assert_eq!(issued.rep.0.cname.name_type, PrincipalName::NT_PRINCIPAL);
    assert_eq!(issued.rep.0.cname.components_joined(), TEST_USER);
}

#[test]
fn enterprise_foreign_suffix_is_not_local_user() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let ent = PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@OTHER.TEST"]);
    assert!(
        store.get_name(&ent).is_none(),
        "foreign UPN suffix must not alias the local user"
    );
    let req = as_req(ent, TEST_REALM, 72, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("foreign enterprise");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::C_PRINCIPAL_UNKNOWN),
        other => panic!("expected C_PRINCIPAL_UNKNOWN, got {other}"),
    }
}

#[test]
fn enterprise_mixed_case_suffix_is_not_local_user() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let ent = PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@kerber.test"]);
    assert!(
        store.get_name(&ent).is_none(),
        "MIT 1.22.2 enterprise suffix is exact octets"
    );
    let req = as_req(ent, TEST_REALM, 73, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("mixed-case suffix");
    match err {
        Error::Protocol { code, .. } => assert_eq!(code, err::C_PRINCIPAL_UNKNOWN),
        other => panic!("expected C_PRINCIPAL_UNKNOWN, got {other}"),
    }
}

#[test]
fn tgs_canonicalize_issues_cross_realm_krbtgt() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "OTHER.TEST",
            b"interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 61);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        host,
        "OTHER.TEST",
        62,
        KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("cross-realm TGS-REQ");
    let err = krb5_kdc::issue_tgs(&store, &tgs).expect_err("foreign body.realm");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));
        }
        other => panic!("expected 60 GET_LOCAL_TGT, got {other:?}"),
    }
}

#[test]
fn tgs_referral_ad_kerber_test_issues_krbtgt() {
    // In-tree hop for the A5 realm names. Live AD.KERBER.TEST↔KERBER.TEST
    // trust is not configured on the DC; this is not that proof.
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm(
            &acl,
            &documented_admin_id(),
            "AD.KERBER.TEST",
            b"ad-interrealm-secret",
        )
        .expect("interrealm");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 71);
    let ir_sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        ir_sname,
        TEST_REALM,
        72,
        KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("AD referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("AD referral TGS");
    assert_eq!(
        out.rep.0.ticket.sname.components_joined(),
        "krbtgt/AD.KERBER.TEST"
    );
    let ir_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let ir = store.get_name(&ir_name).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&ir.key, &out.rep.0.ticket).expect("inter-realm enc");
    assert!(
        part.transited
            .realms_for(TEST_REALM, "AD.KERBER.TEST")
            .expect("expand")
            .is_empty(),
        "first-hop referral transited excludes client realm: {:?}",
        part.transited.realms_for(TEST_REALM, "AD.KERBER.TEST")
    );
}

#[test]
fn interrealm_issue_key_is_not_the_peer_accept_key() {
    // Windows TDO inbound/outbound AES keys differ by salt. Issue toward
    // AD with the inbound key; still decrypt AD-issued referrals with the
    // outbound key.
    let issue_bytes = [0x11u8; 32];
    let accept_bytes = [0x22u8; 32];
    let issue_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &issue_bytes)
            .expect("issue key");
    let accept_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &accept_bytes)
            .expect("accept key");
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_interrealm_key(&acl, &documented_admin_id(), "AD.KERBER.TEST", issue_key)
        .expect("issue");
    store
        .add_interrealm_decrypt_key(&acl, &documented_admin_id(), "AD.KERBER.TEST", accept_key)
        .expect("accept");
    let ir_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "AD.KERBER.TEST"]);
    let ir = store.get_name(&ir_name).expect("ir");
    assert_eq!(ir.keys.len(), 2);
    assert_eq!(
        ir.best_key().unwrap().key.as_bytes(),
        issue_bytes.as_slice(),
        "TGS issue must use the inbound AD key"
    );
    assert!(ir.keys.iter().any(|k| k.key.as_bytes() == accept_bytes));
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 81);
    let tgs = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        ir_name,
        TEST_REALM,
        82,
        KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("AD referral TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("AD referral TGS");
    let issue_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &issue_bytes)
            .unwrap();
    let accept_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &accept_bytes)
            .unwrap();
    decrypt_ticket_part(&issue_key, &out.rep.0.ticket).expect("issue key must open the referral");
    assert!(
        decrypt_ticket_part(&accept_key, &out.rep.0.ticket).is_err(),
        "peer accept key must not open tickets we issue toward AD"
    );
    let part = decrypt_ticket_part(&issue_key, &out.rep.0.ticket).unwrap();
    let pac = pac_from_ticket_part(&part).expect("referral TGT must carry a PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        krb5_types::pac::RpcSid::dummy_domain().to_sddl()
    );
    let der = ticket_checksum_der(&part).expect("der");
    verify_pac_signatures(&pac, &issue_key, Some(&issue_key), Some(&der))
        .expect("referral PAC signed with inter-realm key");
}

#[test]
fn password_principal_has_rfc8009_keys() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .expect("user");
    assert!(
        user.key_for(EncryptionType::Aes256CtsHmacSha384192)
            .is_some()
    );
    assert!(
        user.key_for(EncryptionType::Aes128CtsHmacSha256128)
            .is_some()
    );
}

#[test]
fn krbtgt_and_host_have_rfc8009_keys() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let tgt = store.krbtgt().expect("krbtgt");
    assert!(
        tgt.key_for(EncryptionType::Aes256CtsHmacSha384192)
            .is_some()
    );
    let host = store.get_name(&documented_host()).expect("host");
    assert!(
        host.key_for(EncryptionType::Aes256CtsHmacSha384192)
            .is_some()
    );
}

#[test]
fn issue_as_and_tgs_with_etype_20_mint_sha2_tickets() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let sha2 = EncryptionType::Aes256CtsHmacSha384192;
    let key = string_to_key(
        sha2,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&krb5_kdc::s2k_params(sha2)),
    )
    .expect("sha2 s2k");
    let req = as_req_sname(
        cname.clone(),
        TEST_REALM,
        80,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
        PrincipalName::krbtgt(TEST_REALM),
        vec![sha2.to_iana()],
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS etype 20");
    assert_eq!(as_out.session_key.etype(), sha2);
    assert_eq!(
        as_out.rep.0.ticket.enc_part.etype,
        sha2.to_iana(),
        "TGT EncryptedData.etype must be 20, not best_key() SHA-1"
    );
    let tgs = tgs_req_ex(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        81,
        KdcOptions::forwardable(),
        None,
        Vec::new(),
        vec![sha2.to_iana()],
    )
    .expect("TGS etype 20");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS etype 20");
    assert_eq!(tgs_out.session_key.etype(), sha2);
    assert_eq!(
        tgs_out.rep.0.ticket.enc_part.etype,
        sha2.to_iana(),
        "host ticket EncryptedData.etype must be 20"
    );
}

#[test]
fn same_realm_ticket_sets_transited_policy_checked() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 70);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let tgt_part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("tgt");
    assert!(
        !tgt_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "AS-REP TGT must not set TRANSITED-POLICY-CHECKED"
    );
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        71,
    )
    .expect("tgs");
    let out = krb5_kdc::issue_tgs(&store, &tgt).expect("issue");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert!(
        part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "same-realm TGS must set TRANSITED-POLICY-CHECKED when the check ran"
    );

    let skip_opts = KdcOptions::forwardable().with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true);
    let skip = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        72,
        skip_opts.clone(),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("tgs skip");
    match krb5_kdc::issue_tgs(&store, &skip) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
        }
        other => panic!("skip + default must be POLICY (12), got {other:?}"),
    }

    let mut as_renew = as_req(
        cname.clone(),
        TEST_REALM,
        73,
        Some(vec![pa_enc_timestamp(&user_key()).expect("pa")]),
    )
    .unwrap();
    as_renew.0.req_body.kdc_options = as_renew
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    let issued_r = krb5_kdc::issue_as(&store, &as_renew).expect("AS renewable");
    let as_part = decrypt_ticket_part(
        &store.krbtgt().unwrap().best_key().unwrap().key,
        &issued_r.rep.0.ticket,
    )
    .expect("as tgt");
    assert!(
        !as_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "AS TGT is the non-T negative control"
    );
    assert!(as_part.flags.renewable());
    let renew_non_t = tgs_req_ex(
        issued_r.rep.0.ticket.clone(),
        &issued_r.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        78,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("renew non-T skip");
    match krb5_kdc::issue_tgs(&store, &renew_non_t) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
        }
        other => panic!("RENEW of a non-T ticket + skip must be POLICY, got {other:?}"),
    }
    let tgs_tgt = tgs_req_ex(
        issued_r.rep.0.ticket.clone(),
        &issued_r.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        74,
        KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("tgs tgt");
    let tgs_tgt_out = krb5_kdc::issue_tgs(&store, &tgs_tgt).expect("TGS TGT");
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let tgs_tgt_part = decrypt_ticket_part(&tgt_key.key, &tgs_tgt_out.rep.0.ticket).expect("enc");
    assert!(
        tgs_tgt_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "same-realm TGS TGT must carry T before RENEW+skip"
    );
    assert!(tgs_tgt_part.flags.renewable());
    let renew_skip = tgs_req_ex(
        tgs_tgt_out.rep.0.ticket.clone(),
        &tgs_tgt_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        75,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("renew skip");
    let renewed = krb5_kdc::issue_tgs(&store, &renew_skip).expect("RENEW skip inherits T");
    let renewed_part = decrypt_ticket_part(&tgt_key.key, &renewed.rep.0.ticket).expect("enc renew");
    assert!(
        renewed_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "RENEW of a T ticket + skip must keep T"
    );

    let (mut lax_store, _) = bootstrap_documented().expect("lax");
    lax_store.policy.reject_bad_transit = false;
    let issued_lax = issue_tgt(&lax_store, TEST_USER, TEST_USER_PASSWORD, 76);
    let skip_lax = tgs_req_ex(
        issued_lax.rep.0.ticket.clone(),
        &issued_lax.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        77,
        skip_opts,
        None,
        Vec::new(),
        pref_etypes(),
    )
    .expect("tgs skip lax");
    let skipped =
        krb5_kdc::issue_tgs(&lax_store, &skip_lax).expect("skip + reject_bad_transit=false");
    let lax_host = lax_store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let skip_part = decrypt_ticket_part(&lax_host.key, &skipped.rep.0.ticket).expect("enc skip");
    assert!(
        !skip_part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED),
        "skip + reject_bad_transit=false must leave T off"
    );
}

#[test]
fn ktadd_exports_all_kvnos_after_kpasswd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .change_password(&acl, &documented_admin_id(), &cname, b"second-pass")
        .expect("cpw");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &cname)
        .expect("ktadd");
    let kvnos: Vec<u32> = kt.entries.iter().map(|e| e.kvno).collect();
    assert!(
        !kvnos.is_empty() && kvnos.iter().all(|v| *v > 1),
        "keepold=false ktadd exports the new kvno only: {kvnos:?}"
    );
}

fn two_realm_pac_stores() -> (PrincipalStore, PrincipalStore, ProtocolKey, PrincipalName) {
    let (mut local, acl_a) = bootstrap_documented().expect("local");
    local.set_domain_sid(RpcSid::nt_domain(9, 8, 7));
    let mut foreign = PrincipalStore::bootstrap(
        "OTHER.TEST",
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .expect("foreign");
    foreign.set_domain_sid(RpcSid::nt_domain(11, 12, 13));
    let actor_b = format!("{TEST_ADMIN}@OTHER.TEST");
    let acl_b = Acl::allow_admin(&actor_b);
    let host_b = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
    foreign
        .create_host(&acl_b, &actor_b, &host_b)
        .expect("host");
    let ir =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).expect("ir key");
    local
        .create_interrealm_key(&acl_a, &documented_admin_id(), "OTHER.TEST", ir.clone())
        .expect("A→B");
    foreign
        .create_interrealm_key(&acl_b, &actor_b, TEST_REALM, ir.clone())
        .expect("B→A");
    (local, foreign, ir, host_b)
}

fn referral_from_local(local: &PrincipalStore, nonce: u32) -> (krb5_kdc::IssuedTgs, PrincipalName) {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(local, TEST_USER, TEST_USER_PASSWORD, nonce);
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        other.clone(),
        TEST_REALM,
        nonce + 1,
    )
    .expect("referral TGS-REQ");
    (
        krb5_kdc::issue_tgs(local, &tgs).expect("referral TGS"),
        cname,
    )
}

fn rewrap_ticket(
    ticket: &krb5_types::Ticket,
    part: &EncTicketPart,
    key: &ProtocolKey,
) -> krb5_types::Ticket {
    let der = encode(part).expect("enc-tkt DER");
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let cipher = encrypt(key, usage, &der).expect("encrypt");
    let mut out = ticket.clone();
    out.enc_part.cipher = cipher.into();
    out
}

fn flip_pac_sig(part: &mut EncTicketPart, kind: u32) {
    let pac = pac_from_ticket_part(part).expect("PAC");
    let mut parsed = Pac::parse(&pac).expect("parse");
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == kind)
        .expect("sig buffer");
    assert!(buf.data.len() > 4, "MAC bytes");
    buf.data[4] ^= 0xff;
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).expect("wrap"));
}

#[test]
fn tgs_copies_foreign_referral_pac_identity() {
    let (local, foreign, ir, host_b) = two_realm_pac_stores();
    assert_ne!(local.domain_sid().to_sddl(), foreign.domain_sid().to_sddl());
    let (referral, cname) = referral_from_local(&local, 9100);
    let ref_part = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    let ref_pac = pac_from_ticket_part(&ref_part).expect("referral PAC");
    let ref_logon = parse_kerb_validation_info(
        Pac::parse(&ref_pac)
            .expect("PAC")
            .buffer(PAC_LOGON_INFO)
            .expect("logon"),
    )
    .expect("NDR");
    assert_eq!(
        ref_logon.logon_domain_id.to_sddl(),
        local.domain_sid().to_sddl()
    );

    let tgs = tgs_req(
        referral.rep.0.ticket.clone(),
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b.clone(),
        "OTHER.TEST",
        9102,
    )
    .expect("foreign TGS-REQ");
    let out = krb5_kdc::issue_tgs(&foreign, &tgs).expect("foreign TGS");
    let host_key = foreign.get_name(&host_b).unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&host_key.key, &out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&part).expect("svc PAC");
    let logon = parse_kerb_validation_info(
        Pac::parse(&pac)
            .expect("PAC")
            .buffer(PAC_LOGON_INFO)
            .expect("logon"),
    )
    .expect("NDR");
    assert_eq!(logon.user_id, ref_logon.user_id);
    assert_eq!(
        logon.logon_domain_id.to_sddl(),
        local.domain_sid().to_sddl(),
        "issued PAC must keep the foreign LOGON_INFO SID, not the local store SID"
    );
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        foreign.domain_sid().to_sddl()
    );
    assert_ne!(
        logon.logon_domain_id.to_sddl(),
        RpcSid::dummy_domain().to_sddl()
    );
}

#[test]
fn tgs_rejects_corrupt_foreign_referral_pac() {
    let (local, foreign, ir, host_b) = two_realm_pac_stores();
    let (referral, cname) = referral_from_local(&local, 9200);
    let mut part = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    flip_pac_sig(&mut part, PAC_SERVER_CHECKSUM);
    let bad_server = rewrap_ticket(&referral.rep.0.ticket, &part, &ir);
    let tgs = tgs_req(
        bad_server,
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b.clone(),
        "OTHER.TEST",
        9202,
    )
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&foreign, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BAD_INTEGRITY),
        other => panic!("corrupt server checksum must fail, got {other:?}"),
    }

    let mut part16 = decrypt_ticket_part(&ir, &referral.rep.0.ticket).expect("referral enc");
    flip_pac_sig(&mut part16, PAC_TICKET_CHECKSUM);
    let bad_16 = rewrap_ticket(&referral.rep.0.ticket, &part16, &ir);
    let tgs16 = tgs_req(
        bad_16,
        &referral.session_key,
        TEST_REALM,
        &cname,
        host_b,
        "OTHER.TEST",
        9203,
    )
    .expect("TGS-REQ");
    match krb5_kdc::issue_tgs(&foreign, &tgs16) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BAD_INTEGRITY),
        other => panic!("corrupt type-16 checksum must fail, got {other:?}"),
    }
}

#[test]
fn tgs_without_pac_still_issues() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 9300);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    assert!(pac_from_ticket_part(&part).is_some());
    part.authorization_data = None;
    let stripped = rewrap_ticket(&issued.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        stripped,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        9301,
    )
    .expect("TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("MIT TGT without PAC must still issue");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("svc");
    assert!(pac_from_ticket_part(&svc).is_some());
}

#[test]
fn type16_checksum_uses_original_enc_tkt_bytes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 9400);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let plain = decrypt(
        &krbtgt.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .expect("plain");
    let part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).expect("TGT");
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let from_bytes = zero_pac_ad_data(&plain, &pac).expect("surgical PAC zero");
    let reencoded = ticket_checksum_der(&part).expect("re-encode");
    assert_eq!(
        from_bytes, reencoded,
        "self-issued rasn DER must match original-bytes PAC zero"
    );
    verify_pac_signatures(&pac, &krbtgt.key, Some(&krbtgt.key), Some(&from_bytes))
        .expect("type-16 over original bytes");
}
