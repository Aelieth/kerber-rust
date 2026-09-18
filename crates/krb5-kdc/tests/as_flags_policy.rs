//! A′-3 R26: `max_renewable_life` 0, AS `PRE_AUTHENT`, `check_tgs_opts` order.
//! A′-3 R32: PKINIT does not set `HW_AUTHENT`; RENEW uses signed header life.
//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, encrypt, p256_generate};
use krb5_kdc::{
    Error, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_SVR, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH,
    KDB_REQUIRES_PWCHANGE, PrincipalStore, Restrictions, TEST_REALM, TEST_USER, as_req,
    bootstrap_documented, documented_host, pa_enc_timestamp,
};
use krb5_protocol::{as_req_sname, pa_pk_as_req};
use krb5_testkit::{TgsReqBuilder, krbtgt, pref_etypes, status, user, user_as_bits};
use krb5_types::{
    EncKdcRepPart, EncTicketPart, EncryptedData, KdcOptions, MethodData, PrincipalName, Ticket,
    err, flag_bit, ku, pa,
};

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
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
fn as_renewable_with_zero_rlife_caps_renew_till_at_start() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let rs = Restrictions {
        max_renewable_life: Some(0),
        ..Restrictions::default()
    };
    store.impose_acl_restrictions(&user(), &rs).unwrap();
    let issued = user_as_bits(&store, 26001, &[(flag_bit::RENEWABLE, true)]);
    let part = tgt_part(&store, &issued);
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    let till = part
        .renew_till
        .as_ref()
        .expect("RENEWABLE sets renew_till")
        .unix_seconds();
    assert_eq!(till, start);
}

#[test]
fn as_without_preauth_has_no_pre_authent() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let rs = Restrictions {
        forbid_attrs: !KDB_REQUIRES_PRE_AUTH,
        ..Restrictions::default()
    };
    store.impose_acl_restrictions(&user(), &rs).unwrap();
    let req = as_req(user(), TEST_REALM, 26011, None).unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    assert!(!tgt_part(&store, &issued).flags.pre_authent());
}

fn etypes() -> Vec<i32> {
    vec![EncryptionType::Aes256CtsHmacSha196.to_iana()]
}

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
        .unwrap();
}

fn tgt_part_a3_r32(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    decode(
        &decrypt(
            &key.key,
            usage,
            issued.rep.0.ticket.enc_part.cipher.as_ref(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn tgs_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    decode(
        &decrypt(
            &key.key,
            usage,
            issued.rep.0.ticket.enc_part.cipher.as_ref(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn pkinit_as(store: &PrincipalStore, nonce: u32) -> Result<krb5_kdc::IssuedAs, Error> {
    let ca = store.pkinit_ca().expect("CA").clone();
    let kp = p256_generate().unwrap();
    let mut req = as_req(user(), TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).unwrap();
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req(&kp.public, &ca, Some(cksum.as_slice())).unwrap(),
    ]);
    krb5_kdc::issue_as(store, &req)
}

#[test]
fn pkinit_tgt_has_no_hw_authent() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    let part = tgt_part_a3_r32(&store, &pkinit_as(&store, 32001).unwrap());
    assert!(part.flags.bit(flag_bit::PRE_AUTHENT));
    assert!(!part.flags.bit(flag_bit::HW_AUTHENT));
}

#[test]
fn pkinit_client_requires_hwauth_is_needed_hw_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    or_attr(&mut store, &user(), KDB_REQUIRES_HW_AUTH);
    match pkinit_as(&store, 32002).unwrap_err() {
        Error::Protocol {
            code,
            text,
            e_data: Some(ed),
            ..
        } if code == err::PREAUTH_REQUIRED && text.as_deref() == Some("NEEDED_HW_PREAUTH") => {
            let types: Vec<i32> = decode::<MethodData>(&ed)
                .unwrap()
                .iter()
                .map(|p| p.padata_type)
                .collect();
            assert!(
                types.contains(&pa::PK_AS_REQ),
                "hw_only still advertises PA-PK-AS-REQ, got {types:?}"
            );
            assert!(
                !types.contains(&pa::PKINIT_KX),
                "pkinit_srv.c:928-929 PKINIT_KX is PA_INFO, skipped under hw_only, got {types:?}"
            );
        }
        other => panic!("expected Protocol NEEDED_HW_PREAUTH with e_data, got {other:?}"),
    }
}

#[test]
fn pkinit_tgs_requires_hwauth_is_no_hw_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().unwrap();
    let host = documented_host();
    or_attr(&mut store, &host, KDB_REQUIRES_HW_AUTH);
    let issued = pkinit_as(&store, 32003).unwrap();
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        host,
        TEST_REALM,
        32004,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::GENERIC, Some("NO HW PREAUTH")));
}

#[test]
fn renew_header_end_before_start_is_expired() {
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
        32011,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut part = tgt_part_a3_r32(&store, &issued);
    let start = part
        .starttime
        .clone()
        .unwrap_or_else(|| part.authtime.clone());
    part.endtime = start.add_seconds(-60).unwrap();
    part.flags = part.flags.with_bit(flag_bit::RENEWABLE, true);
    if part.renew_till.is_none() {
        part.renew_till = Some(start.add_hours(24).unwrap());
    }
    let tgt = Ticket {
        tkt_vno: issued.rep.0.ticket.tkt_vno,
        realm: issued.rep.0.ticket.realm.clone(),
        sname: issued.rep.0.ticket.sname.clone(),
        enc_part: EncryptedData {
            etype: issued.rep.0.ticket.enc_part.etype,
            kvno: issued.rep.0.ticket.enc_part.kvno,
            cipher: encrypt(&krbtgt_key.key, usage, &encode(&part).unwrap())
                .unwrap()
                .into(),
        },
    };
    let tgs = TgsReqBuilder::new(
        tgt,
        &issued.session_key,
        TEST_REALM,
        &user(),
        krbtgt(),
        TEST_REALM,
        32012,
    )
    .options(
        KdcOptions::none()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(etypes())
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let got = tgs_part(&store, &out);
    let start = got
        .starttime
        .as_ref()
        .unwrap_or(&got.authtime)
        .unix_seconds();
    let life = i64::from(got.endtime.unix_seconds()) - i64::from(start);
    assert_eq!(life, -60);
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

fn user_as_req(nonce: u32) -> krb5_types::AsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
    )
    .unwrap()
}

fn tgt_part_issue_acl_ap(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> EncTicketPart {
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &tgt_key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

#[test]
fn as_req_with_tgs_only_option_is_invalid_as_options() {
    // MIT AS_INVALID_OPTIONS (kdc_util.h:456-463): a TGS-only KDC option (RENEW)
    // in an AS-REQ is INVALID AS OPTIONS / BADOPTION (13), not a ticket.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 51, None).unwrap();
    req.0.req_body.kdc_options = req.0.req_body.kdc_options.with_bit(flag_bit::RENEW, true);
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(status(&err).0, err::BADOPTION);
}

#[test]
fn as_request_reserved_option_bit_is_ignored_like_mit() {
    // MIT validate_as_request tests AS_INVALID_OPTIONS only (kdc_util.c:727); a
    // reserved KDCOptions bit (RFC bit 17) is neither rejected nor acted on.
    // Before this parity fix the Rust KDC refused any unknown bit as BADOPTION
    // at validate, ahead of preauth. Now the bit passes validate, so a
    // preauth-required client reaches PREAUTH_REQUIRED, not BADOPTION.
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_REQUIRES_PRE_AUTH);
    let mut req = as_req(cname, TEST_REALM, 53, None).unwrap();
    req.0.req_body.kdc_options = req.0.req_body.kdc_options.with_bit(17, true);
    match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::PreauthRequired { .. } => {}
        Error::Protocol { code, .. } => {
            panic!("reserved bit must pass validate_as_request, got protocol code {code}")
        }
        other => panic!("want PreauthRequired, got {other:?}"),
    }
}

#[test]
fn as_request_anonymous_from_named_client_is_validate_anonymous_principal() {
    // do_as_req.c:718-724: REQUEST_ANONYMOUS demands the anonymous principal; a
    // named client is KRB5KDC_ERR_BADOPTION "VALIDATE_ANONYMOUS_PRINCIPAL"
    // before check_padata. validate_as_request lets the bit through.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let mut req = as_req(
        cname,
        TEST_REALM,
        54,
        Some(vec![pa_enc_timestamp(&key).expect("pa-ts")]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::ANONYMOUS, true);
    let (code, text) = match krb5_kdc::issue_as(&store, &req).unwrap_err() {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol, got {other:?}"),
    };
    assert_eq!(code, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("VALIDATE_ANONYMOUS_PRINCIPAL"));
}

#[test]
fn as_canonicalize_issues_the_krbtgt_under_the_canonical_db_name() {
    // do_as_req.c:660-666: CANONICALIZE on a krbtgt request whose requested and
    // DB server are both TGS principals issues the ticket (and, per :243, the
    // enc-part) under the canonical DB name -- Windows short-realm aliases.
    // krbtgt/SHORT aliases krbtgt/KERBER.TEST here.
    let short = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "SHORT"]);
    let canonical = PrincipalName::krbtgt(TEST_REALM);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let etypes = vec![EncryptionType::Aes256CtsHmacSha196.to_iana()];
    let issue = |canon: bool, nonce: u32| -> krb5_kdc::IssuedAs {
        let (mut store, _) = bootstrap_documented().expect("bootstrap");
        store
            .create_alias_in(
                &short,
                TEST_REALM,
                &canonical,
                TEST_REALM,
                "kadmin/admin@KERBER.TEST",
            )
            .expect("krbtgt alias");
        let mut req = as_req_sname(
            cname.clone(),
            TEST_REALM,
            nonce,
            Some(vec![pa_enc_timestamp(&client_key()).expect("pa-ts")]),
            short.clone(),
            etypes.clone(),
        )
        .unwrap();
        if canon {
            req.0.req_body.kdc_options = req
                .0
                .req_body
                .kdc_options
                .with_bit(flag_bit::CANONICALIZE, true);
        }
        krb5_kdc::issue_as(&store, &req).expect("AS")
    };
    // CANONICALIZE: ticket server AND enc-part server become the canonical name.
    let canon = issue(true, 61);
    assert_eq!(
        canon.rep.0.ticket.sname.components_joined(),
        canonical.components_joined(),
        "ticket server canonicalized"
    );
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(
        &canon.as_rep_key,
        usage,
        canon.rep.0.enc_part.cipher.as_ref(),
    )
    .expect("enc");
    assert_eq!(
        decode_enc_part(&plain).sname.components_joined(),
        canonical.components_joined(),
        "enc-part server follows the ticket (do_as_req.c:243)"
    );
    // Without CANONICALIZE the requested alias name is kept.
    let kept = issue(false, 62);
    assert_eq!(
        kept.rep.0.ticket.sname.components_joined(),
        short.components_joined(),
        "requested alias name kept without CANONICALIZE"
    );
}

#[test]
fn as_validate_runs_before_preauth_like_process_as_req() {
    // MIT process_as_req calls validate_as_request (do_as_req.c:630) before
    // check_padata (:758). A preauth-required client that needs a password
    // change gets REQUIRED PWCHANGE (23), not PREAUTH_REQUIRED (25).
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(
        &mut store,
        &cname,
        KDB_REQUIRES_PRE_AUTH | KDB_REQUIRES_PWCHANGE,
    );
    let req = as_req(cname, TEST_REALM, 52, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let (code, text) = match err {
        Error::Protocol { code, text, .. } => (code, text),
        other => panic!("want Protocol, got {other:?}"),
    };
    assert_eq!(code, err::KEY_EXPIRED);
    assert_eq!(text.as_deref(), Some("REQUIRED PWCHANGE"));
}

#[test]
fn as_strips_forwardable_when_disallow_forwardable() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let before = krb5_kdc::issue_as(&store, &user_as_req(60)).expect("AS");
    assert!(tgt_part_issue_acl_ap(&store, &before).flags.forwardable());
    or_attr(&mut store, &cname, KDB_DISALLOW_FORWARDABLE);
    let after = krb5_kdc::issue_as(&store, &user_as_req(61)).expect("AS");
    assert!(!tgt_part_issue_acl_ap(&store, &after).flags.forwardable());
}

#[test]
fn as_hw_auth_required_rejects_enc_ts() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    or_attr(&mut store, &cname, KDB_REQUIRES_HW_AUTH);
    let err = krb5_kdc::issue_as(&store, &user_as_req(63)).unwrap_err();
    match err {
        Error::Protocol {
            code, text, e_data, ..
        } => {
            assert_eq!(code, err::PREAUTH_REQUIRED);
            assert_eq!(text.as_deref(), Some("NEEDED_HW_PREAUTH"));
            let method: MethodData =
                decode(e_data.as_deref().expect("hint e_data")).expect("METHOD-DATA");
            let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
            assert!(types.contains(&pa::FX_FAST), "{types:?}");
            assert!(types.contains(&pa::ETYPE_INFO2), "{types:?}");
            assert!(
                !types.contains(&pa::ENC_TIMESTAMP) && !types.contains(&pa::SPAKE),
                "hw_only skips non-hardware modules: {types:?}"
            );
        }
        other => panic!("expected 25 NEEDED_HW_PREAUTH, got {other:?}"),
    }
}

#[test]
fn as_sets_proxiable_when_requested() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut req = user_as_req(90);
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::PROXIABLE, true);
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert!(tgt_part_issue_acl_ap(&store, &issued).flags.proxiable());
}

#[test]
fn as_disallow_svr_is_service_not_allowed() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | KDB_DISALLOW_SVR;
    store
        .apply_admin_fields(&host, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req_sname(cname, TEST_REALM, 416, None, host, pref_etypes()).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("DISALLOW_SVR");
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::MUST_USE_USER2USER);
            assert_eq!(text.as_deref(), Some("SERVICE NOT ALLOWED"));
        }
        other => panic!("expected 27 SERVICE NOT ALLOWED, got {other:?}"),
    }
}
