//! W1-B B2: TGS-REP validation. MIT `gc_via_tkt.c:247-297`
//! `krb5int_process_tgs_reply`. Live oracle: existing `kvno_plain` /
//! `kvno_s4u` cells (`MIT_tgs_reply_client`). Unit-only: these helpers
//! are new at the parent.

use krb5_protocol::{
    tgs_reply_client_ok, tgs_reply_req_times, tgs_reply_server_consistent, tgs_strip_ok_as_delegate,
};
use krb5_types::{
    EncKdcRepPart, EncryptionKey, KdcOptions, KerberosTime, OctetString, PrincipalName,
    TicketFlags, ascii, flag_bit,
};

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])
}

fn host() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.kerber.test"])
}

fn realm() -> krb5_types::Realm {
    ascii("KERBER.TEST")
}

fn krbtgt() -> PrincipalName {
    PrincipalName::krbtgt("KERBER.TEST")
}

fn enc_part(end: KerberosTime, renew: Option<KerberosTime>, flags: TicketFlags) -> EncKdcRepPart {
    let t = KerberosTime::from_unix_seconds(1_700_000_000);
    EncKdcRepPart {
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(vec![7u8; 32]),
        },
        last_req: vec![],
        nonce: 1,
        key_expiration: None,
        flags,
        authtime: t.clone(),
        starttime: Some(t.clone()),
        endtime: end,
        renew_till: renew,
        srealm: realm(),
        sname: host(),
        caddr: None,
        encrypted_pa_data: None,
    }
}

#[test]
fn b2_tgs_reply_client_matches_tgt() {
    tgs_reply_client_ok(
        &user(),
        &realm(),
        &user(),
        &realm(),
        &host(),
        &host(),
        &realm(),
        false,
        false,
    )
    .unwrap();
}

#[test]
fn b2_tgs_reply_client_ignores_name_type() {
    let nt_user = PrincipalName::new(PrincipalName::NT_UNKNOWN, ["user"]);
    tgs_reply_client_ok(
        &user(),
        &realm(),
        &nt_user,
        &realm(),
        &host(),
        &host(),
        &realm(),
        false,
        false,
    )
    .unwrap();
}

#[test]
fn b2_tgs_reply_wrong_client_is_modified() {
    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    let err = tgs_reply_client_ok(
        &user(),
        &realm(),
        &other,
        &realm(),
        &host(),
        &host(),
        &realm(),
        false,
        false,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("client does not match TGT"),
        "{err}"
    );
}

#[test]
fn b2_tgs_reply_s4u2proxy_final_skips_tgt_client() {
    let impersonated = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["impersonated"]);
    tgs_reply_client_ok(
        &user(),
        &realm(),
        &impersonated,
        &realm(),
        &host(),
        &host(),
        &realm(),
        false,
        true,
    )
    .unwrap();
}

#[test]
fn b2_tgs_reply_s4u2proxy_referral_requires_tgt_client() {
    let impersonated = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["impersonated"]);
    let err = tgs_reply_client_ok(
        &user(),
        &realm(),
        &impersonated,
        &realm(),
        &krbtgt(),
        &host(),
        &realm(),
        false,
        true,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("client does not match TGT"),
        "{err}"
    );
}

#[test]
fn b2_tgs_reply_s4u2self_client_eq_server_is_nosupp() {
    let err = tgs_reply_client_ok(
        &user(),
        &realm(),
        &host(),
        &realm(),
        &host(),
        &host(),
        &realm(),
        true,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("S4U2Self unsupported"), "{err}");
}

#[test]
fn b2_tgs_reply_s4u2self_impersonated_is_ok() {
    let impersonated = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["impersonated"]);
    tgs_reply_client_ok(
        &user(),
        &realm(),
        &impersonated,
        &realm(),
        &host(),
        &host(),
        &realm(),
        true,
        false,
    )
    .unwrap();
}

#[test]
fn b2_tgs_reply_server_consistent_ok() {
    tgs_reply_server_consistent(&host(), &realm(), &host(), &realm()).unwrap();
}

#[test]
fn b2_tgs_reply_server_mismatch_is_modified() {
    let err = tgs_reply_server_consistent(&host(), &realm(), &krbtgt(), &realm()).unwrap_err();
    assert!(err.to_string().contains("ticket server"), "{err}");
}

#[test]
fn b2_tgs_reply_strip_ok_as_delegate_foreign_without_flag() {
    let flags = TicketFlags::none().with_bit(flag_bit::OK_AS_DELEGATE, true);
    let out = tgs_strip_ok_as_delegate(false, false, flags);
    assert!(!out.bit(flag_bit::OK_AS_DELEGATE));
}

#[test]
fn b2_tgs_reply_strip_ok_as_delegate_keeps_local_and_flagged_foreign() {
    let flags = TicketFlags::none().with_bit(flag_bit::OK_AS_DELEGATE, true);
    assert!(tgs_strip_ok_as_delegate(true, false, flags.clone()).bit(flag_bit::OK_AS_DELEGATE));
    assert!(tgs_strip_ok_as_delegate(false, true, flags).bit(flag_bit::OK_AS_DELEGATE));
}

#[test]
fn b2_tgs_reply_endtime_after_till_is_modified() {
    let till = KerberosTime::from_unix_seconds(1_700_000_100);
    let enc = enc_part(
        KerberosTime::from_unix_seconds(1_700_000_200),
        None,
        TicketFlags::none(),
    );
    let err = tgs_reply_req_times(&enc, &till, None, None, &KdcOptions::none()).unwrap_err();
    assert!(
        err.to_string().contains("endtime after request till"),
        "{err}"
    );
}

#[test]
fn b2_tgs_reply_endtime_at_till_ok() {
    let till = KerberosTime::from_unix_seconds(1_700_000_200);
    let enc = enc_part(till.clone(), None, TicketFlags::none());
    tgs_reply_req_times(&enc, &till, None, None, &KdcOptions::none()).unwrap();
}

#[test]
fn b2_tgs_reply_zero_till_skips_endtime() {
    let till = KerberosTime::from_unix_seconds(0);
    let enc = enc_part(
        KerberosTime::from_unix_seconds(1_700_000_200),
        None,
        TicketFlags::none(),
    );
    tgs_reply_req_times(&enc, &till, None, None, &KdcOptions::none()).unwrap();
}
