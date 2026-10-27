//! AS flag policy: a zero `max_renewable_life`, `PRE_AUTHENT` only after preauth, the
//! `check_tgs_opts` order, `HW_AUTHENT` never set by PKINIT, and RENEW judged by the signed
//! header lifetime.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, p256_generate};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};
use krb5_kdc::{Error, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, PrincipalStore, Restrictions};
use krb5_protocol::{as_req, pa_enc_timestamp};

use krb5_protocol::{as_req_sname, pa_pk_as_req};
use krb5_testkit::{TgsReqBuilder, status, user, user_as_bits};
use krb5_types::{
    EncKdcRepPart, EncTicketPart, KdcOptions, MethodData, PrincipalName, err, flag_bit, ku, pa,
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

fn etypes() -> Vec<i32> {
    vec![EncryptionType::Aes256CtsHmacSha196.to_iana()]
}

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

fn pkinit_as(
    store: &PrincipalStore,
    ca: &krb5_types::pkinit::PkinitCa,
    nonce: u32,
) -> Result<krb5_kdc::IssuedAs, Error> {
    let kp = p256_generate().unwrap();
    let mut req = as_req(user(), TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).unwrap();
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![
        pa_pk_as_req(&kp.public, ca, Some(cksum.as_slice())).unwrap(),
    ]);
    krb5_kdc::issue_as(store, &req)
}

#[test]
fn pkinit_tgt_has_no_hw_authent() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let part = tgt_part_a3_r32(&store, &pkinit_as(&store, &ca, 32001).unwrap());
    assert!(part.flags.bit(flag_bit::PRE_AUTHENT));
    assert!(!part.flags.bit(flag_bit::HW_AUTHENT));
}

#[test]
fn pkinit_client_requires_hwauth_is_needed_hw_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let ca = krb5_testkit::enable_pkinit(&mut store);
    or_attr(&mut store, &user(), KDB_REQUIRES_HW_AUTH);
    match pkinit_as(&store, &ca, 32002).unwrap_err() {
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
// oracle: differential-gate.sh tgs-hw-preauth-flag
fn pkinit_tgs_requires_hwauth_is_no_hw_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let host = documented_host();
    or_attr(&mut store, &host, KDB_REQUIRES_HW_AUTH);
    let issued = pkinit_as(&store, &ca, 32003).unwrap();
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

#[test]
fn as_request_reserved_option_bit_is_ignored_like_mit() {
    // MIT: `validate_as_request` (kdc_util.c:727-727)
    // the option test is AS_INVALID_OPTIONS
    // only; a reserved KDCOptions bit (RFC bit 17) is neither rejected nor acted on.
    // The bit passes validate, so a preauth-required client reaches
    // PREAUTH_REQUIRED, not BADOPTION.
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
fn as_canonicalize_issues_the_krbtgt_under_the_canonical_db_name() {
    // MIT: `process_as_req` (do_as_req.c:660-666)
    // CANONICALIZE on a krbtgt request whose
    // requested and DB server are both TGS principals issues the ticket (and, per :243, the
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
// oracle: differential-gate.sh as-hw-preauth
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
