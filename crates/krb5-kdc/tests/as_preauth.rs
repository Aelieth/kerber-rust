//! A′-3 item 15: hint-list order, EC outside FAST, enc_padata PAC-OPTIONS.
//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.
//! AS e_data-bearing errors carry PA-FX-COOKIE; PKINIT 65 is TYPED-DATA
//! (`do_as_req.c:785-814`, `pkinit_srv.c:932`); FAST inner FX-ERROR has no
//! e_data (`fast_util.c:384-386`).
//! Z1.4: every KDC long-term key lookup is MIT `krb5_dbe_find_enctype`
//! (`kdb_default.c:47-94`), which never returns a key whose enctype is outside
//! `permitted_enctypes` and, for the AS client key, looks only at the highest
//! kvno. Compiles at the parent `77d8a48` and fails there: `first_current_key`
//! / `key_for` took the first stored key regardless of `permitted_enctypes`
//! and `key_for` reached down to older kvnos.
//! W1-Z Z1b.3 follow-up: AS client/server lookup faults are labelled like
//! MIT `do_as_req.c:577-607` — `CANTLOCK_DB` is 29 `SVC_UNAVAILABLE` on
//! either lookup **with** the lookup's status word (`LOOKING_UP_CLIENT` /
//! `LOOKING_UP_SERVER`; Z6.3), any other backend fault is 60 with the same
//! words. No in-tree store fails a lookup; a `PrincipalRead` wrapper stands
//! in for a backend that does. Compiles at `7a44ef8` (parent-red): the
//! parent labelled a server-lookup fault `LOOKING_UP_CLIENT` (the catch-all
//! arm). The CANTLOCK e_text half was wrong until Z6.3 (`z6_lookup.rs`).
//! W1-Z Z1b.3 follow-up: MIT `filter_preauth_error` (`kdc_preauth.c:1092-1133`)
//! at the kdcpreauth module boundary (`finish_check_padata` `:1206`). A module
//! failure whose code is not on the pass-through list reaches the client as
//! 24 `PREAUTH_FAILED`, under the `PREAUTH_FAILED` status `finish_preauth`
//! sets for every module failure (`do_as_req.c:442`). Compiles at `7a44ef8`
//! (parent-red): the parent put each module's own code on the wire — 60 for
//! both cells here — and CI 550-552 were red on `differential-gate.sh`
//! `as-optimistic-encts-wrong-etype` because of the first one.
//! W1-Z Z1b.3: the KRB-ERROR encoder applies MIT `errcode_to_protocol`
//! (`kdc_util.c:691-697`, called at `do_as_req.c:804` / `do_tgs_req.c:199`):
//! only 0..=128 is a protocol error-code, anything else goes out as
//! `KRB_ERR_GENERIC` 60. Reachable only through a `KdcPolicy` handing back a
//! raw code (no in-tree path does). Compiles at `59c363b` (parent-red): the
//! parent put the raw code on the wire.
//! Z6.2: ENC-TS (2) / ENC-CHALLENGE (138) are advertised only when
//! `have_client_keys` (`kdc_preauth.c:434-447`) is true — a permitted key of
//! a requested etype at the top kvno. SPAKE (151) uses the same condition
//! via `client_keyblock` (`spake_kdc.c:309-314`). Compiles at the parent
//! and fails there: EncTsMod advertised 2 whenever armor was absent,
//! EncChallengeMod advertised 138 whenever the client had any key, SpakeMod
//! advertised 151 whenever groups were configured, and a preauth-required
//! client with no selected key was 14 `CANT_FIND_CLIENT_KEY` instead of 25.
//! Z6.3: AS lookup `CANTLOCK_DB` is 29 with MIT's status word
//! (`do_as_req.c:579-590`, `:598-606`: remap to `SVC_UNAVAILABLE`, **then**
//! `LOOKING_UP_CLIENT` / `LOOKING_UP_SERVER`), and `KRB5KDC_ERR_DISCARD`
//! from a kdcpreauth module is passed through `filter_preauth_error`
//! (`kdc_preauth.c:1125`) and suppresses the reply (`do_as_req.c:371-372`).
//! Compiles at the parent: CANTLOCK was 29 with no e_text, and DISCARD was
//! rewritten to 24 `PREAUTH_FAILED`. Forge-only — no lockable KDB in tree.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_asn1::{decode, decode_enc_kdc_rep_part, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, string_to_key};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_admin_id,
    documented_host,
};
use krb5_kdc::{
    Error, KdcEnv, KdcPolicy, KdcPreauth, KeyEntry, Policy, PolicyAdjustment, Principal,
    PrincipalRead, PrincipalStore, S2K_ITERS, clear_thread_policy, random_key, register_preauth,
    set_thread_policy,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{
    armor_key, as_req_sname, attach_fast, build_fast_armor, pa_pac_options, pa_pk_as_req_spki,
    unwrap_fast_rep,
};
use krb5_testkit::{
    TgsReqBuilder, expect_status, issue_tgt_password, password_key, pref_etypes, status, user,
    user_as,
};
use krb5_types::pac::RpcSid;
use krb5_types::{
    Checksum, EncKdcRepPart, EncTicketPart, EncryptedData, KdcOptions, KerberosTime, KrbError,
    MethodData, Microseconds, PaData, PaEncTsEnc, PaPacRequest, PrincipalName, ascii, err,
    flag_bit, ku, pa,
};
use std::sync::Arc;

#[test]
fn as_hint_list_is_136_info2_modules_cookie() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 15001, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::FX_COOKIE,
        ]
    );
}

#[test]
// oracle: differential-gate.sh ec-outside-fast
fn as_ec_outside_fast_is_preauth_failed() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        cname,
        TEST_REALM,
        15002,
        Some(vec![PaData {
            padata_type: pa::ENCRYPTED_CHALLENGE,
            padata_value: b"outside-fast".to_vec().into(),
        }]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    assert_eq!(status(&err), (err::PREAUTH_FAILED, Some("PREAUTH_FAILED")));
}

#[test]
fn tgs_pac_options_rbcd_is_echoed_in_enc_padata() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 15003);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        15004,
    )
    .options(KdcOptions::none())
    .additional_tickets(None)
    .padata(vec![pa_pac_options(true).unwrap()])
    .etypes(vec![18])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let plain = decrypt(
        &issued.session_key,
        usage,
        out.rep.0.enc_part.cipher.as_ref(),
    )
    .unwrap();
    let enc = decode_enc_kdc_rep_part(&plain).unwrap();
    let types: Vec<i32> = enc
        .encrypted_pa_data
        .as_ref()
        .into_iter()
        .flatten()
        .map(|p| p.padata_type)
        .collect();
    assert!(
        types.contains(&pa::PAC_OPTIONS),
        "enc_padata types {types:?} must echo PAC-OPTIONS"
    );
}

#[test]
fn as_fast_hint_keeps_136_151_lists_138_omits_2() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor = user_as(&store, 15005);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(cname, TEST_REALM, 15006, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let fast = unwrap_fast_rep(&akey, &Some(method)).unwrap();
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::FX_FAST),
        "FAST-inner METHOD-DATA keeps 136: {types:?}"
    );
    assert!(
        types.contains(&pa::SPAKE),
        "FAST-inner METHOD-DATA keeps 151: {types:?}"
    );
    assert!(
        types.contains(&pa::ENCRYPTED_CHALLENGE),
        "FAST-inner METHOD-DATA lists 138: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "FAST-inner METHOD-DATA omits 2: {types:?}"
    );
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

#[test]
// oracle: differential-gate.sh unknown-sname
fn as_unknown_sname_is_server_not_found() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "no-such.kerber.test"]);
    let req = as_req_sname(cname, TEST_REALM, 0x1000_0006, None, sname, pref_etypes()).unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(c, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("SERVER_NOT_FOUND"));
}

#[test]
fn as_without_preauth_is_preauth_required() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 7, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    match err {
        Error::PreauthRequired { e_data } => assert!(!e_data.is_empty()),
        other => panic!("expected PreauthRequired, got {other:?}"),
    }
}

#[test]
fn as_and_tgs_issue_decryptable_tickets() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let padata = vec![pa_enc_timestamp(&key).expect("pa-ts")];
    let req = as_req(cname.clone(), TEST_REALM, 11, Some(padata)).unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS");

    let usage_as = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage_as, issued.rep.0.enc_part.cipher.as_ref()).expect("AS enc");
    let enc = decode_enc_part(&plain);
    assert_eq!(enc.nonce, 11);
    assert_eq!(issued.session_key.as_bytes(), enc.key.keyvalue.as_ref());

    let tgt_key = store.krbtgt().expect("krbtgt").best_key().expect("key");
    let usage_tkt = KeyUsage::new(ku::TICKET).unwrap();
    assert_ne!(usage_tkt.get(), 0);
    let tkt_plain = decrypt(
        &tgt_key.key,
        usage_tkt,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .expect("TGT enc-part");
    let part: EncTicketPart = decode(&tkt_plain).expect("EncTicketPart");
    assert_eq!(part.cname.components_joined(), TEST_USER);
    assert_eq!(part.key.keyvalue.as_ref(), issued.session_key.as_bytes());

    let tgs = tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        13,
    )
    .expect("TGS-REQ");
    let tgs_issued = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let usage_tgs = KeyUsage::new(ku::TGS_REP_ENC_PART).unwrap();
    let tgs_plain = decrypt(
        &issued.session_key,
        usage_tgs,
        tgs_issued.rep.0.enc_part.cipher.as_ref(),
    )
    .expect("TGS enc");
    let tgs_enc = decode_enc_part(&tgs_plain);
    assert_eq!(tgs_enc.nonce, 13);

    let host = store.get_name(&documented_host()).expect("host");
    let host_key = host.best_key().expect("host key");
    let svc_plain = decrypt(
        &host_key.key,
        usage_tkt,
        tgs_issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .expect("service ticket");
    let svc: EncTicketPart = decode(&svc_plain).expect("host EncTicketPart");
    assert_eq!(svc.cname.components_joined(), TEST_USER);
    assert_eq!(svc.key.keyvalue.as_ref(), tgs_issued.session_key.as_bytes());
}

#[test]
fn wrong_password_yields_preauth_failed_bytes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let wrong = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"not-the-password",
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname,
        TEST_REALM,
        5,
        Some(vec![pa_enc_timestamp(&wrong).expect("pa")]),
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert!(!bytes.is_empty());
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
}

#[test]
// oracle: differential-gate.sh as-session-enctype
// oracle: differential-gate.sh etype-nosupp
fn no_common_etype_is_etype_nosupp() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let mut req = as_req(
        cname,
        TEST_REALM,
        6,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.etype = vec![23]; // rc4 session refused unless allow_rc4 + session_enctypes
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::ETYPE_NOSUPP);
    assert_eq!(
        e.e_text
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_bytes()).ok()),
        Some("BAD_ENCRYPTION_TYPE")
    );
}

#[test]
fn session_enctypes_attr_is_membership_not_client_key() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store
        .set_string(
            &PrincipalName::krbtgt(TEST_REALM),
            "session_enctypes",
            Some("aes128-cts"),
        )
        .expect("setstr");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let mut req = as_req(
        cname,
        TEST_REALM,
        61,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.etype = vec![18, 17];
    let out = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert_eq!(out.session_key.etype(), EncryptionType::Aes128CtsHmacSha196);
}

#[test]
fn session_enctypes_rc4_with_allow_rc4_issues_rc4_session() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store.policy.allow_rc4 = true;
    store
        .set_string(
            &PrincipalName::krbtgt(TEST_REALM),
            "session_enctypes",
            Some("rc4-hmac"),
        )
        .expect("setstr");
    let rc4user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["rc4user"]);
    store
        .create_password_etypes(
            &acl,
            &documented_admin_id(),
            &rc4user,
            b"rc4-secret",
            &[EncryptionType::Rc4Hmac],
        )
        .expect("addprinc -e rc4");
    let salt = rc4user.default_salt(TEST_REALM);
    let key = string_to_key(EncryptionType::Rc4Hmac, b"rc4-secret", &salt, None).expect("s2k");
    let mut req = as_req(
        rc4user,
        TEST_REALM,
        62,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.etype = vec![23];
    let out = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert_eq!(out.session_key.etype(), EncryptionType::Rc4Hmac);
    assert_ne!(out.rep.0.ticket.enc_part.etype, 23);
}

#[test]
fn allow_rc4_false_skips_rc4_session_even_if_requested() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let mut req = as_req(
        cname,
        TEST_REALM,
        63,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    req.0.req_body.etype = vec![23, 18];
    let out = krb5_kdc::issue_as(&store, &req).expect("AS");
    assert_eq!(out.session_key.etype(), EncryptionType::Aes256CtsHmacSha196);
}

#[test]
fn insert_password_honours_supported_enctypes_rc4() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store.policy.supported_enctypes = vec![EncryptionType::Rc4Hmac];
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["rc4only"]);
    store
        .create_password(&acl, &documented_admin_id(), &name, b"secret")
        .expect("create");
    let p = store.get_name(&name).expect("princ");
    assert_eq!(p.keys.len(), 1);
    assert_eq!(p.keys[0].etype, EncryptionType::Rc4Hmac);
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn issue_code(err: Error) -> i32 {
    match err {
        Error::Protocol { code, .. } => code,
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn assert_krb_error(bytes: &[u8], code: i32, e_text: &str) {
    assert_eq!(bytes.first(), Some(&0x7e), "expected KRB-ERROR");
    let e: KrbError = decode(bytes).expect("KrbError");
    assert_eq!(e.error_code, code);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some(e_text));
}

#[test]
fn every_ticket_sets_enc_pa_rep_flag_without_padata() {
    // MIT get_ticket_flags sets TKT_FLG_ENC_PA_REP on every ticket; the
    // enc-pa-rep padata is added only when the client asked (PA 149).
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&cname).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &cname,
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
    let key = user_key();
    let req = as_req(cname, TEST_REALM, 207, None).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let rep: krb5_types::AsRep = decode(&bytes).expect("AS-REP");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert!(
        enc.flags.enc_pa_rep(),
        "enc-pa-rep flag set on every ticket"
    );
    assert!(
        enc.encrypted_pa_data.is_none(),
        "no enc-pa-rep padata without PA 149"
    );
}

#[test]
fn as_rep_outer_padata_is_etype_info2_only_like_mit() {
    // MIT return_padata adds PA-ETYPE-INFO2 (plus PA-ETYPE-INFO + PW-SALT for a
    // des3/rc4-only request); MIT 1.22.2 never emits PA-SUPPORTED-ENCTYPES (165).
    // TEST_USER has aes keys, so a modern request yields exactly PA-ETYPE-INFO2.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 208);
    let mut types: Vec<i32> = issued
        .rep
        .0
        .padata
        .as_ref()
        .expect("outer padata")
        .iter()
        .map(|p| p.padata_type)
        .collect();
    types.sort_unstable();
    assert_eq!(
        types,
        vec![pa::ETYPE_INFO2],
        "MIT emits only PA-ETYPE-INFO2 for a modern request"
    );
    assert!(
        !types.contains(&165),
        "MIT 1.22.2 never emits PA-SUPPORTED-ENCTYPES (165)"
    );
}

#[test]
fn as_enc_timestamp_wrong_etype_is_preauth_failed_like_mit() {
    // enc_ts_verify (kdc_preauth_encts.c): no client key of the declared etype
    // is KRB5_KDB_NO_MATCHING_KEY, remapped to KDC_ERR_PREAUTH_FAILED (24), not
    // a NEEDED_PREAUTH round trip.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).unwrap();
    assert!(
        !user
            .keys
            .iter()
            .any(|k| k.etype == EncryptionType::Des3CbcSha1),
        "premise: TEST_USER has no des3 key"
    );
    let ed = EncryptedData {
        etype: 16,
        kvno: None,
        cipher: vec![0u8; 32].into(),
    };
    let pa = PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&ed).unwrap().into(),
    };
    let req = as_req(cname, TEST_REALM, 261, Some(vec![pa])).unwrap();
    let e = krb5_kdc::issue_as(&store, &req).expect_err("wrong-etype timestamp");
    assert_eq!(issue_code(e), err::PREAUTH_FAILED);
}

#[test]
fn as_preauth_failed_carries_the_hint_list_like_mit() {
    // MIT finish_preauth (do_as_req.c:443-447) attaches the get_preauth_hint_list
    // e_data to a PREAUTH_FAILED (24) so the client can retry with the right
    // salt/etype.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let ed = EncryptedData {
        etype: 16,
        kvno: None,
        cipher: vec![0u8; 32].into(),
    };
    let pa = PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&ed).unwrap().into(),
    };
    let req = as_req(cname, TEST_REALM, 263, Some(vec![pa])).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
    let hint = e
        .e_data
        .as_ref()
        .expect("PREAUTH_FAILED carries hint e_data");
    let method: MethodData = decode(hint.as_ref()).expect("METHOD-DATA");
    assert!(
        method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2),
        "hint carries ETYPE-INFO2"
    );
}

#[test]
fn preauth_required_hint_lists_one_etype_info2_entry_like_mit() {
    // get_preauth_hint_list emits a single ETYPE-INFO2 entry for the selected
    // client key (add_etype_info -> make_etype_info), not one entry per key.
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 262, None).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let ke: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(ke.error_code, err::PREAUTH_REQUIRED);
    let method: MethodData =
        decode(ke.e_data.as_ref().expect("e_data").as_ref()).expect("METHOD-DATA");
    let info2 = method
        .iter()
        .find(|p| p.padata_type == pa::ETYPE_INFO2)
        .expect("ETYPE-INFO2 hint");
    let entries: krb5_types::EtypeInfo2 =
        decode(info2.padata_value.as_ref()).expect("decode ETYPE-INFO2");
    assert_eq!(entries.len(), 1, "MIT hint lists exactly one entry");
}

#[test]
fn as_rep_enc_part_carries_no_kvno_like_mit() {
    // MIT sets reply.enc_part.kvno only after krb5_encode_kdc_rep, so the wire
    // AS-REP enc-part has no kvno (do_as_req.c:329).
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    // A no-preauth AS keeps skip_timestamp false, so it exercises the reply kvno.
    let attrs = store.get_name(&cname).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &cname,
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
    let req = as_req(cname, TEST_REALM, 206, None).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let rep: krb5_types::AsRep = decode(&bytes).expect("AS-REP");
    assert!(
        rep.0.enc_part.kvno.is_none(),
        "AS-REP enc-part must carry no kvno"
    );
    // The ticket's own enc-part keeps the server key kvno.
    assert!(rep.0.ticket.enc_part.kvno.is_some());
}

#[test]
fn as_req_enc_pa_rep_is_verified() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = user_key();
    let mut padata = vec![pa_enc_timestamp(&key).expect("pa")];
    padata.push(PaData {
        padata_type: pa::REQ_ENC_PA_REP,
        padata_value: Vec::new().into(),
    });
    let req = as_req(cname, TEST_REALM, 205, Some(padata)).unwrap();
    let wire = encode(&req).expect("der");
    let bytes = krb5_kdc::handle_request(&store, &wire).expect("reply");
    let rep: krb5_types::AsRep = decode(&bytes).expect("AS-REP");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert!(enc.flags.enc_pa_rep(), "RFC 6806 enc-pa-rep");
    krb5_protocol::verify_req_enc_pa_rep(&enc, &key, &wire).expect("pa 149");
    let mut bad = enc.clone();
    if let Some(epa) = bad.encrypted_pa_data.as_mut()
        && let Some(p) = epa.iter_mut().find(|p| p.padata_type == pa::REQ_ENC_PA_REP)
    {
        let mut ck: Checksum = decode(p.padata_value.as_ref()).expect("ck");
        let mut mac = ck.checksum.to_vec();
        mac[0] ^= 0xff;
        ck.checksum = mac.into();
        p.padata_value = encode(&ck).expect("re").into();
    }
    assert!(krb5_protocol::verify_req_enc_pa_rep(&bad, &key, &wire).is_err());
}

#[test]
// oracle: differential-gate.sh as-bad-msg-type
fn as_bad_msg_type_is_validate_message_type() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 410, None).unwrap();
    req.0.msg_type = krb5_types::KdcReq::MSG_TGS_REQ;
    let err = krb5_kdc::issue_as(&store, &req).expect_err("bad msg_type");
    match err {
        Error::Protocol {
            code, text, e_data, ..
        } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("VALIDATE_MESSAGE_TYPE"));
            assert!(e_data.is_none(), "no cookie");
        }
        other => panic!("expected 60 VALIDATE_MESSAGE_TYPE, got {other:?}"),
    }
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::GENERIC, "VALIDATE_MESSAGE_TYPE");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert!(e.cname.is_some(), "requested cname echoed");
    assert!(e.e_data.is_none(), "no cookie");
}

#[test]
fn as_bad_pvno_is_dropped() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 411, None).unwrap();
    req.0.pvno = 4;
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert!(bytes.is_empty(), "pvno != 5 is dropped");
}

#[test]
// oracle: differential-gate.sh wrong-realm
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
    let krbtgt_first = store.krbtgt().unwrap().first_current_key().unwrap().etype;
    assert_eq!(
        as_out.rep.0.ticket.enc_part.etype,
        krbtgt_first.to_iana(),
        "TGT EncryptedData.etype is the first current krbtgt key (get_first_current_key), not the session etype"
    );
    let tgs = TgsReqBuilder::new(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        81,
    )
    .options(KdcOptions::forwardable())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![sha2.to_iana()])
    .build()
    .expect("TGS etype 20");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS etype 20");
    assert_eq!(tgs_out.session_key.etype(), sha2);
    let host_first = store
        .get_name(&documented_host())
        .unwrap()
        .first_current_key()
        .unwrap()
        .etype;
    assert_eq!(
        tgs_out.rep.0.ticket.enc_part.etype,
        host_first.to_iana(),
        "host ticket EncryptedData.etype is the first current service key"
    );
}

fn first_ctx_tag(der: &[u8]) -> Option<u8> {
    der.iter().copied().find(|b| b & 0xc0 == 0x80)
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

fn edata_int_types(ed: &[u8]) -> Vec<i32> {
    fn read_len(buf: &[u8], i: usize) -> Option<(usize, usize)> {
        let n = *buf.get(i)? as usize;
        if n < 0x80 {
            return Some((n, i + 1));
        }
        let count = n & 0x7f;
        let mut val = 0usize;
        for j in 0..count {
            val = (val << 8) | *buf.get(i + 1 + j)? as usize;
        }
        Some((val, i + 1 + count))
    }
    fn tlv(buf: &[u8], i: usize) -> Option<(u8, &[u8], usize)> {
        let tag = *buf.get(i)?;
        let (ln, j) = read_len(buf, i + 1)?;
        let end = j.checked_add(ln)?;
        Some((tag, buf.get(j..end)?, end))
    }
    fn parse_int(val: &[u8]) -> i32 {
        let mut n: i32 = 0;
        for b in val {
            n = (n << 8) | i32::from(*b);
        }
        n
    }
    let Ok((_, seq, _)) = tlv(ed, 0).ok_or(()) else {
        return Vec::new();
    };
    let mut types = Vec::new();
    let mut i = 0;
    while i < seq.len() {
        let Some((_, pa, next)) = tlv(seq, i) else {
            break;
        };
        i = next;
        let mut j = 0;
        while j < pa.len() {
            let Some((ptag, pval, n)) = tlv(pa, j) else {
                break;
            };
            j = n;
            if ptag & 0xc0 != 0x80 {
                continue;
            }
            let inner = if ptag & 0x20 != 0 {
                tlv(pval, 0).map_or(pval, |(_, v, _)| v)
            } else {
                pval
            };
            let num = ptag & 0x1f;
            if num == 0 || num == 1 {
                types.push(parse_int(inner));
                break;
            }
        }
    }
    types
}

#[test]
fn pkinit_unknown_dh_is_typed_edata_with_cookie() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let p = vec![0xffu8; 64];
    let y = vec![0x02];
    let spki = krb5_types::pkinit::encode_dh_spki(&p, &y);
    let req = pkinit_as_req(cname, 901, |ck| {
        pa_pk_as_req_spki(&spki, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::DH_KEY_PARAMETERS_NOT_ACCEPTED);
    let ed = e.e_data.as_ref().expect("e_data");
    assert_eq!(
        first_ctx_tag(ed.as_ref()),
        Some(0xa0),
        "PKINIT 65 e_data is TYPED-DATA [0]/[1], not METHOD-DATA [1]/[2]"
    );
    let method = match decode::<MethodData>(ed.as_ref()) {
        Ok(m) if !m.is_empty() => m,
        _ => Vec::new(),
    };
    assert!(
        method.is_empty(),
        "TYPED-DATA must not decode as PA-DATA: {:?}",
        method.iter().map(|p| p.padata_type).collect::<Vec<_>>()
    );
    let types = edata_int_types(ed.as_ref());
    assert_eq!(types, vec![pa::TD_DH_PARAMETERS, pa::FX_COOKIE]);
}

#[test]
fn fast_error_inner_fx_error_omits_edata() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 910);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x51u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(cname, TEST_REALM, 911, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("preauth required");
    let ed = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&ed).expect("outer METHOD-DATA");
    let fast = unwrap_fast_rep(&akey, &Some(method)).expect("FAST inner");
    let fx = fast
        .padata
        .iter()
        .find(|p| p.padata_type == pa::FX_ERROR)
        .expect("PA-FX-ERROR");
    let inner: KrbError = decode(fx.padata_value.as_ref()).expect("inner KRB-ERROR");
    assert!(
        inner.e_data.is_none(),
        "kdc_fast_handle_error zeroes inner FX-ERROR e_data"
    );
    assert!(
        fast.padata.iter().any(|p| p.padata_type == pa::FX_COOKIE),
        "cookie travels in FAST inner padata, not the inner error: {:?}",
        fast.padata
            .iter()
            .map(|p| p.padata_type)
            .collect::<Vec<_>>()
    );
}

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;

const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn user_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn user_key_z1_permitted_key(
    store: &PrincipalStore,
    etype: EncryptionType,
) -> krb5_crypto::ProtocolKey {
    store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .filter(|k| k.etype == etype)
        .max_by_key(|k| k.kvno)
        .expect("user key of that etype")
        .key
        .clone()
}

fn store_permitting_aes256() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(store.policy().etype_permitted(AES256));
    assert!(!store.policy().etype_permitted(AES128));
    store
}

fn set_random_keys(store: &mut PrincipalStore, name: &PrincipalName, etypes: &[EncryptionType]) {
    let keys = etypes
        .iter()
        .map(|&e| KeyEntry::new(e, random_key(e).unwrap(), 0))
        .collect();
    store.set_keys(name, keys, 0).unwrap();
}

fn kinit(store: &PrincipalStore) -> krb5_kdc::IssuedAs {
    let padata = vec![pa_enc_timestamp(&user_key_z1_permitted_key(store, AES256)).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0010, Some(padata)).unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS issues")
}

fn kvno_host(
    store: &PrincipalStore,
    tgt: &krb5_kdc::IssuedAs,
) -> Result<krb5_kdc::IssuedTgs, krb5_kdc::Error> {
    let req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user_name(),
        documented_host(),
        TEST_REALM,
        0x2600_0011,
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &req)
}

fn assert_finding_server_key<T: std::fmt::Debug>(got: Result<T, krb5_kdc::Error>) {
    match got {
        Err(krb5_kdc::Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::GENERIC, "KRB_ERR_GENERIC, got {text:?}");
            assert_eq!(text.as_deref(), Some("FINDING_SERVER_KEY"));
        }
        Err(other) => panic!("expected 60 FINDING_SERVER_KEY, got {other:?}"),
        Ok(v) => panic!("a server whose only keys are non-permitted must not get a ticket: {v:?}"),
    }
}

#[test]
fn tgs_service_key_skips_a_non_permitted_first_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &documented_host(), &[AES128, AES256]);
    let tgt = kinit(&store);
    let tkt = kvno_host(&store, &tgt).expect("TGS issues under the aes256 key");
    assert_eq!(
        tkt.rep.0.ticket.enc_part.etype,
        AES256.to_iana(),
        "service ticket must be sealed with the permitted aes256 key, not the first-stored aes128"
    );
}

#[test]
fn tgs_service_key_only_non_permitted_is_finding_server_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &documented_host(), &[AES128]);
    let tgt = kinit(&store);
    assert_finding_server_key(kvno_host(&store, &tgt));
}

#[test]
fn as_server_key_skips_a_non_permitted_first_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(
        &mut store,
        &PrincipalName::krbtgt(TEST_REALM),
        &[AES128, AES256],
    );
    let tgt = kinit(&store);
    assert_eq!(
        tgt.rep.0.ticket.enc_part.etype,
        AES256.to_iana(),
        "TGT must be sealed with the permitted aes256 krbtgt key"
    );
}

#[test]
fn as_server_key_only_non_permitted_is_finding_server_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &PrincipalName::krbtgt(TEST_REALM), &[AES128]);
    let padata = vec![pa_enc_timestamp(&user_key_z1_permitted_key(&store, AES256)).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0012, Some(padata)).unwrap();
    assert_finding_server_key(krb5_kdc::issue_as(&store, &req));
}

#[test]
fn as_client_key_is_chosen_at_the_highest_kvno_only() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let old_aes256 = user_key_z1_permitted_key(&store, AES256);
    // cpw -keepold -e aes128:normal: the new top kvno holds aes128 only; the
    // aes256 key survives at the old kvno.
    let new = vec![KeyEntry::new(AES128, random_key(AES128).unwrap(), 0)];
    store.set_keys(&user_name(), new, 2).unwrap();
    let top = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(
        store
            .get_name(&user_name())
            .unwrap()
            .keys
            .iter()
            .any(|k| k.etype == AES256 && k.kvno < top),
        "the old aes256 key must still be stored below the top kvno"
    );
    let padata = vec![pa_enc_timestamp(&old_aes256).unwrap()];
    let req = as_req_sname(
        user_name(),
        TEST_REALM,
        0x2600_0013,
        Some(padata),
        PrincipalName::krbtgt(TEST_REALM),
        vec![AES256.to_iana()],
    )
    .unwrap();
    match krb5_kdc::issue_as(&store, &req) {
        Err(krb5_kdc::Error::Protocol { code, text, .. }) => {
            assert_eq!(
                code,
                err::ETYPE_NOSUPP,
                "KDC_ERR_ETYPE_NOSUPP, got {text:?}"
            );
            assert_eq!(text.as_deref(), Some("CANT_FIND_CLIENT_KEY"));
        }
        Err(other) => panic!("expected 14 CANT_FIND_CLIENT_KEY, got {other:?}"),
        Ok(_) => panic!("an etype present only at an older kvno must not select that key"),
    }
}

#[test]
fn enc_ts_under_a_retired_kvno_key_is_preauth_failed() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let stale = user_key_z1_permitted_key(&store, AES256);
    // cpw -randkey -keepold: kvno 2 aes256 on top, the kvno-1 key retained.
    let new = vec![KeyEntry::new(AES256, random_key(AES256).unwrap(), 0)];
    store.set_keys(&user_name(), new, 2).unwrap();
    let p = store.get_name(&user_name()).unwrap();
    let top = p.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(
        p.keys.iter().any(|k| k.etype == AES256 && k.kvno < top),
        "the retired aes256 key must still be stored"
    );
    // Control: a timestamp under the current key issues.
    let padata = vec![pa_enc_timestamp(&user_key_z1_permitted_key(&store, AES256)).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0015, Some(padata)).unwrap();
    krb5_kdc::issue_as(&store, &req).expect("current key issues");
    let padata = vec![pa_enc_timestamp(&stale).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0016, Some(padata)).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let e: krb5_types::KrbError = krb5_asn1::decode(&bytes)
        .unwrap_or_else(|_| panic!("a timestamp under a retired kvno's key must be refused"));
    assert_eq!(e.error_code, err::PREAUTH_FAILED, "KDC_ERR_PREAUTH_FAILED");
}

#[test]
fn as_client_key_skips_a_non_permitted_requested_etype() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &user_name(), &[AES128, AES256]);
    let padata = vec![
        pa_enc_timestamp(&user_key_z1_permitted_key(&store, AES256)).unwrap(),
        PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: encode(&PaPacRequest { include_pac: false }).unwrap().into(),
        },
    ];
    let req = as_req_sname(
        user_name(),
        TEST_REALM,
        0x2600_0014,
        Some(padata),
        PrincipalName::krbtgt(TEST_REALM),
        vec![AES128.to_iana(), AES256.to_iana()],
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS issues with the aes256 client key");
    assert_eq!(
        issued.rep.0.enc_part.etype,
        AES256.to_iana(),
        "the AS-REP must be keyed with the permitted aes256 client key"
    );
}

struct Faulty<'a> {
    inner: &'a PrincipalStore,
    fail_id: String,
    fault: fn() -> Error,
}

impl PrincipalRead for Faulty<'_> {
    fn realm(&self) -> &str {
        <PrincipalStore as PrincipalRead>::realm(self.inner)
    }
    fn policy(&self) -> &Policy {
        <PrincipalStore as PrincipalRead>::policy(self.inner)
    }
    fn domain_sid(&self) -> &RpcSid {
        <PrincipalStore as PrincipalRead>::domain_sid(self.inner)
    }
    fn env(&self) -> &KdcEnv {
        <PrincipalStore as PrincipalRead>::env(self.inner)
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        if id == self.fail_id {
            return Err((self.fault)());
        }
        <PrincipalStore as PrincipalRead>::fetch(self.inner, id)
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        <PrincipalStore as PrincipalRead>::list_ids(self.inner)
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        <PrincipalStore as PrincipalRead>::list_principals(self.inner)
    }
}

fn backend_fault() -> Error {
    Error::InvalidArgument("backend: disk read failed".into())
}

fn cantlock() -> Error {
    Error::Protocol {
        code: err::SVC_UNAVAILABLE,
        text: None,
        e_data: None,
        detail: Some("KRB5_KDB_CANTLOCK_DB".into()),
    }
}

fn as_error(fail_id: &str, fault: fn() -> Error) -> (i32, Option<String>) {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user,
        TEST_REALM,
        0x1b03,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let faulty = Faulty {
        inner: &store,
        fail_id: fail_id.to_owned(),
        fault,
    };
    let reply = krb5_kdc::handle_request(&faulty, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

#[test]
fn as_lookup_faults_are_labelled_like_do_as_req() {
    let client_id = format!("{TEST_USER}@{TEST_REALM}");
    let tgs_id = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    // :588-590 — a client-lookup fault is 60 LOOKING_UP_CLIENT.
    assert_eq!(
        as_error(&client_id, backend_fault),
        (err::GENERIC, Some("LOOKING_UP_CLIENT".into()))
    );
    // :604-606 — a server-lookup fault is 60 LOOKING_UP_SERVER (the parent
    // said LOOKING_UP_CLIENT for every fault after the decode).
    assert_eq!(
        as_error(&tgs_id, backend_fault),
        (err::GENERIC, Some("LOOKING_UP_SERVER".into()))
    );
    // :579-590, :598-606 — CANTLOCK_DB is remapped to 29, then the
    // `else if (errcode)` chain sets the lookup status (Z6.3).
    assert_eq!(
        as_error(&client_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_CLIENT".into()))
    );
    assert_eq!(
        as_error(&tgs_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_SERVER".into()))
    );
}

fn user_key_z1b_preauth_filter(store: &PrincipalStore, etype: EncryptionType) -> ProtocolKey {
    store
        .get_name(&user())
        .unwrap()
        .keys
        .iter()
        .filter(|k| k.etype == etype)
        .max_by_key(|k| k.kvno)
        .expect("user key of that etype")
        .key
        .clone()
}

fn wire(store: &PrincipalStore, nonce: u32, padata: Vec<PaData>) -> (i32, Option<String>) {
    let req = as_req(user(), TEST_REALM, nonce, Some(padata)).unwrap();
    let raw = encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(store, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .as_ref()
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

#[test]
fn encts_under_a_non_permitted_etype_is_24_like_filter_preauth_error() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(
        !store
            .policy()
            .etype_permitted(EncryptionType::Aes128CtsHmacSha196)
    );
    // The user's real aes128 key: a *correct* timestamp under a non-permitted
    // enctype, so nothing but the permitted-enctype walk can refuse it.
    let aes128 = user_key_z1b_preauth_filter(&store, EncryptionType::Aes128CtsHmacSha196);
    let padata = vec![pa_enc_timestamp(&aes128).unwrap()];
    assert_eq!(
        wire(&store, 0x1b06, padata),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into()))
    );
}

#[test]
fn encts_with_an_out_of_range_pausec_is_24_not_60() {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let key = user_key_z1b_preauth_filter(&store, EncryptionType::Aes256CtsHmacSha196);
    let ts = PaEncTsEnc {
        patimestamp: KerberosTime::now(),
        pausec: Some(Microseconds(1_000_000)),
    };
    let der = encode(&ts).unwrap();
    let cipher = encrypt(&key, KeyUsage::new(ku::PA_ENC_TIMESTAMP).unwrap(), &der).unwrap();
    let enc = EncryptedData {
        etype: key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    let padata = vec![PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&enc).unwrap().into(),
    }];
    assert_eq!(
        wire(&store, 0x1b07, padata),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into()))
    );
}

struct RawCodePolicy(i32);

impl KdcPolicy for RawCodePolicy {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Err(Error::Protocol {
            code: self.0,
            text: Some("RAW_POLICY".into()),
            e_data: None,
            detail: None,
        })
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }
}

fn wire_error_code(raw_policy_code: i32) -> i32 {
    set_thread_policy(Arc::new(RawCodePolicy(raw_policy_code)));
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user,
        TEST_REALM,
        0x1b03,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).expect("a KRB-ERROR reply");
    clear_thread_policy();
    decode::<KrbError>(&reply).expect("KRB-ERROR").error_code
}

struct FailingModule;

const PA_PRIVATE: i32 = 30_000;

impl krb5_kdc::KdcPreauth for FailingModule {
    fn name(&self) -> &'static str {
        "z1b-failing"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[PA_PRIVATE]
    }
    fn advertise(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<krb5_types::PaData> {
        Vec::new()
    }
    fn process_as(
        &self,
        rock: &krb5_kdc::PreauthRock<'_>,
    ) -> Result<Option<krb5_kdc::PreauthAction>, Error> {
        #[allow(unused_variables)]
        let krb5_kdc::PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        let Some(p) = padata.and_then(|p| p.iter().find(|p| p.padata_type == PA_PRIVATE)) else {
            return Ok(None);
        };
        Err(match p.padata_value.as_ref() {
            [0] => Error::Protocol {
                code: err::GENERIC,
                text: Some("MODULE_STATUS".into()),
                e_data: None,
                detail: None,
            },
            [1] => Error::Protocol {
                code: err::SKEW,
                text: Some("MODULE_SKEW_STATUS".into()),
                e_data: None,
                detail: None,
            },
            [2] => Error::Asn1("module decode".into()),
            [3] => Error::Protocol {
                code: err::POLICY,
                text: Some("MODULE_POLICY".into()),
                e_data: None,
                detail: None,
            },
            _ => Error::Protocol {
                code: err::PREAUTH_EXPIRED,
                text: Some("PREAUTH_FAILED".into()),
                e_data: None,
                detail: None,
            },
        })
    }
}

fn module_wire_error(selector: u8) -> (i32, Option<String>) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| krb5_kdc::register_preauth(Arc::new(FailingModule)));
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        user,
        TEST_REALM,
        0x1b05,
        Some(vec![krb5_types::PaData {
            padata_type: PA_PRIVATE,
            padata_value: vec![selector].into(),
        }]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .as_ref()
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

#[test]
fn policy_raw_library_code_reaches_the_wire_as_generic_60() {
    // Outside 0..=128 (a com_err library value the module forgot to map).
    assert_eq!(wire_error_code(1_000_000), err::GENERIC);
    assert_eq!(wire_error_code(-1_765_328_361), err::GENERIC);
    // Inside the protocol range it is passed through (`:697`).
    assert_eq!(wire_error_code(err::POLICY), err::POLICY);
}

#[test]
// oracle: differential-gate.sh skewed-timestamp
fn module_failures_pass_through_the_filter_like_kdc_preauth() {
    assert_eq!(
        module_wire_error(0),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "60 GENERIC is not on the list"
    );
    assert_eq!(
        module_wire_error(1),
        (err::SKEW, Some("PREAUTH_FAILED".into())),
        "37 SKEW passes; the status word is still finish_preauth's"
    );
    assert_eq!(
        module_wire_error(2),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "an ASN.1 failure is 24"
    );
    assert_eq!(
        module_wire_error(3),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "12 POLICY is not on the list"
    );
    assert_eq!(
        module_wire_error(4),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "90 PREAUTH_EXPIRED is not on the list"
    );
}

fn store_permitting_aes256_z6_hints() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    store
}

fn set_user_aes128_only(store: &mut PrincipalStore) {
    store
        .set_keys(
            &user_name(),
            vec![KeyEntry::new(AES128, random_key(AES128).unwrap(), 0)],
            0,
        )
        .unwrap();
}

fn hint_types(err: Error) -> Vec<i32> {
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PREAUTH_REQUIRED, got {err:?}");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    method.iter().map(|p| p.padata_type).collect()
}

#[test]
fn hint_omits_enc_ts_when_the_only_key_is_not_permitted() {
    let mut store = store_permitting_aes256_z6_hints();
    set_user_aes128_only(&mut store);
    assert!(store.get_name(&user_name()).unwrap().requires_preauth);
    let req = as_req(user_name(), TEST_REALM, 0x2600_0062, None).unwrap();
    let types = hint_types(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert!(
        types.contains(&pa::FX_FAST),
        "25 still advertises FAST: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS must be omitted when have_client_keys is false: {types:?}"
    );
    assert!(
        !types.contains(&pa::ETYPE_INFO2),
        "no selected client key → no ETYPE-INFO2: {types:?}"
    );
    assert!(
        !types.contains(&pa::SPAKE),
        "SPAKE must be omitted when client_keyblock is NULL: {types:?}"
    );
}

#[test]
// oracle: differential-gate.sh as-needpreauth-hints-unpermitted
fn hint_omits_enc_ts_when_the_only_key_is_not_requested() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    set_user_aes128_only(&mut store);
    let req = as_req_sname(
        user_name(),
        TEST_REALM,
        0x2600_0063,
        None,
        PrincipalName::krbtgt(TEST_REALM),
        vec![AES256.to_iana()],
    )
    .unwrap();
    let types = hint_types(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS must be omitted when no requested etype has a key: {types:?}"
    );
    assert!(
        !types.contains(&pa::SPAKE),
        "SPAKE must be omitted when client_keyblock is NULL: {types:?}"
    );
}

#[test]
fn fast_hint_omits_enc_challenge_when_have_client_keys_is_false() {
    let mut store = store_permitting_aes256_z6_hints();
    let key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let req = as_req(
        user_name(),
        TEST_REALM,
        0x2600_0064,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let armor = krb5_kdc::issue_as(&store, &req).expect("armor TGT");
    set_user_aes128_only(&mut store);
    let sub = ProtocolKey::from_bytes(AES256, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &user_name(),
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(user_name(), TEST_REALM, 0x2600_0065, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PREAUTH_REQUIRED, got {err:?}");
    };
    let outer: MethodData = decode(&e_data).expect("outer METHOD-DATA");
    let fast = unwrap_fast_rep(&akey, &Some(outer)).expect("FAST unwrap");
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    assert!(
        !types.contains(&pa::ENCRYPTED_CHALLENGE),
        "ENC-CHALLENGE must be omitted when have_client_keys is false: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS stays omitted under armor: {types:?}"
    );
}

const DISCARD: i32 = -1_750_600_189;

const PA_DISCARD: i32 = 30_001;

struct DiscardMod;

impl KdcPreauth for DiscardMod {
    fn name(&self) -> &'static str {
        "z6-discard"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[PA_DISCARD]
    }
    fn advertise(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<krb5_types::PaData> {
        Vec::new()
    }
    fn process_as(
        &self,
        rock: &krb5_kdc::PreauthRock<'_>,
    ) -> Result<Option<krb5_kdc::PreauthAction>, Error> {
        #[allow(unused_variables)]
        let krb5_kdc::PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        let Some(p) = padata.and_then(|p| p.iter().find(|p| p.padata_type == PA_DISCARD)) else {
            return Ok(None);
        };
        let _ = p;
        Err(Error::Protocol {
            code: DISCARD,
            text: Some("DISCARD".into()),
            e_data: None,
            detail: None,
        })
    }
}

#[test]
fn cantlock_on_client_is_29_looking_up_client() {
    let client_id = format!("{TEST_USER}@{TEST_REALM}");
    assert_eq!(
        as_error(&client_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_CLIENT".into()))
    );
}

#[test]
fn cantlock_on_server_is_29_looking_up_server() {
    let tgs_id = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    assert_eq!(
        as_error(&tgs_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_SERVER".into()))
    );
}

#[test]
fn discard_module_failure_is_no_reply() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| register_preauth(Arc::new(DiscardMod)));
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        user,
        TEST_REALM,
        0x1b05,
        Some(vec![krb5_types::PaData {
            padata_type: PA_DISCARD,
            padata_value: b"x".to_vec().into(),
        }]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).expect("handle_request");
    assert!(
        reply.is_empty(),
        "DISCARD must suppress prepare_error_as; got {} bytes",
        reply.len()
    );
}
