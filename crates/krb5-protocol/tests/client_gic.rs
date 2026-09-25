//! `gic_keytab.c` highest kvno + etype sort.
//! Live oracle: `client-differential-gate.sh` two-kvno `kinit -k`.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::{
    AsRequest, AsTicketOpts, Error, KdcAddr, Keytab, KeytabEntry, as_init_creds_options,
    key_exp_should_changepw, keytab_init_creds_keys, parse_chpw_result, sort_etypes_keytab_first,
    tgs_renew_options,
};
use krb5_types::{PrincipalName, TicketFlags, ascii, err, flag_bit};

fn entry(realm: &str, name: &str, kvno: u32, key: &[u8], etype: EncryptionType) -> KeytabEntry {
    KeytabEntry {
        realm: ascii(realm),
        name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]),
        timestamp: 1,
        kvno,
        key: ProtocolKey::from_bytes(etype, key).expect("key"),
    }
}

fn sample_kt() -> Keytab {
    Keytab {
        version: 0x0502,
        entries: vec![
            entry(
                "KERBER.TEST",
                "user",
                1,
                &[1u8; 32],
                EncryptionType::Aes256CtsHmacSha196,
            ),
            entry(
                "OTHER.TEST",
                "user",
                9,
                &[9u8; 32],
                EncryptionType::Aes256CtsHmacSha196,
            ),
            entry(
                "KERBER.TEST",
                "user",
                2,
                &[2u8; 16],
                EncryptionType::Aes128CtsHmacSha196,
            ),
            entry(
                "KERBER.TEST",
                "user",
                2,
                &[3u8; 32],
                EncryptionType::Aes256CtsHmacSha196,
            ),
        ],
        skipped_unknown_etype: 0,
        unparsed: vec![],
    }
}

#[test]
fn gic_keytab_uses_highest_kvno_only() {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let (keys, etypes) = keytab_init_creds_keys(&sample_kt(), &user, "KERBER.TEST").expect("keys");
    assert_eq!(keys.len(), 2, "both etypes at kvno 2");
    assert_eq!(etypes, vec![17, 18]);
    assert_eq!(keys[0].as_bytes(), &[2u8; 16]);
    assert_eq!(keys[1].as_bytes(), &[3u8; 32]);
}

#[test]
fn gic_keytab_wrong_realm_is_ignored() {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let (keys, _) = keytab_init_creds_keys(&sample_kt(), &user, "KERBER.TEST").expect("keys");
    assert!(keys.iter().all(|k| k.as_bytes() != [9u8; 32]));
}

#[test]
fn gic_keytab_unknown_principal_is_none() {
    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
    assert!(keytab_init_creds_keys(&sample_kt(), &other, "KERBER.TEST").is_none());
}

#[test]
fn gic_keytab_sort_moves_keytab_etypes_front() {
    let mut req = [18, 17, 20, 19];
    sort_etypes_keytab_first(&mut req, &[17]);
    assert_eq!(req, [17, 18, 20, 19]);
}

fn options_of(
    ticket: AsTicketOpts,
    canonicalize: bool,
) -> (krb5_types::KdcOptions, Option<krb5_types::KerberosTime>) {
    let kdc = KdcAddr::new("127.0.0.1");
    let req = AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize,
        sname: None,
        etypes: None,
        ticket,
    };
    as_init_creds_options(&req)
}

#[test]
fn gic_opt_canonicalize_sets_kdc_option() {
    let (opts, from) = options_of(AsTicketOpts::default(), true);
    assert!(
        opts.bit(flag_bit::CANONICALIZE),
        "get_in_tkt.c:921-930 / gic_opt.c:76-83"
    );
    assert!(from.is_none());
    let (plain, _) = options_of(AsTicketOpts::default(), false);
    assert!(!plain.bit(flag_bit::CANONICALIZE));
}

#[test]
fn gic_opt_starttime_sets_postdated_and_from() {
    let (opts, from) = options_of(
        AsTicketOpts {
            starttime: Some(3600),
            ..AsTicketOpts::default()
        },
        false,
    );
    assert!(
        opts.bit(flag_bit::MAY_POSTDATE),
        "get_in_tkt.c:932-934 ALLOW_POSTDATE"
    );
    assert!(opts.bit(flag_bit::POSTDATED), "get_in_tkt.c:932-934");
    assert!(from.is_some(), "get_in_tkt.c:711-714 omits from only at 0");
    let (plain, none) = options_of(AsTicketOpts::default(), false);
    assert!(none.is_none());
    assert!(!plain.bit(flag_bit::POSTDATED));
    assert!(!plain.bit(flag_bit::MAY_POSTDATE));
}

#[test]
fn gic_pwd_key_exp_with_new_password_should_changepw() {
    let err = Error::KrbError {
        code: err::KEY_EXPIRED,
        text: Some("KEY EXPIRED".into()),
    };
    assert!(key_exp_should_changepw(&err, true, false));
}

#[test]
fn gic_pwd_key_exp_without_new_password_does_not_changepw() {
    let err = Error::KrbError {
        code: err::KEY_EXPIRED,
        text: None,
    };
    assert!(!key_exp_should_changepw(&err, false, false));
}

#[test]
fn gic_pwd_keytab_does_not_changepw() {
    let err = Error::KrbError {
        code: err::KEY_EXPIRED,
        text: None,
    };
    assert!(!key_exp_should_changepw(&err, true, true));
}

#[test]
fn chpw_success_is_ok() {
    assert_eq!(parse_chpw_result(&[0, 0], false).unwrap(), 0);
}

#[test]
fn chpw_out_of_range_is_modified() {
    let err = parse_chpw_result(&[0, 8], false).unwrap_err();
    assert!(err.to_string().contains("modified"), "{err}");
}

#[test]
fn chpw_success_from_error_is_modified() {
    let err = parse_chpw_result(&[0, 0], true).unwrap_err();
    assert!(err.to_string().contains("SUCCESS from KRB-ERROR"), "{err}");
}

#[test]
fn chpw_truncated_is_modified() {
    let err = parse_chpw_result(&[0], false).unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
}

#[test]
fn chpw_result_code_strings_match_mit() {
    use krb5_protocol::chpw_result_code_string;
    assert_eq!(chpw_result_code_string(0), "Success");
    assert_eq!(chpw_result_code_string(1), "Malformed request error");
    assert_eq!(chpw_result_code_string(2), "Server error");
    assert_eq!(chpw_result_code_string(3), "Authentication error");
    assert_eq!(chpw_result_code_string(4), "Password change rejected");
    assert_eq!(chpw_result_code_string(5), "Access denied");
    assert_eq!(chpw_result_code_string(6), "Wrong protocol version");
    assert_eq!(chpw_result_code_string(7), "Initial password required");
    assert_eq!(chpw_result_code_string(8), "Password change failed");
}

#[test]
fn chpw_message_utf8_and_fallback() {
    use krb5_protocol::chpw_message;
    assert_eq!(
        chpw_message(b"This is a valid string."),
        "This is a valid string."
    );
    assert!(chpw_message(b"\0This is not valid.").contains("contact your administrator"));
}

#[test]
fn chpw_message_ad_policy_matches_mit_test_chpw_message() {
    use krb5_protocol::chpw_message;
    let complex = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let msg = chpw_message(&complex);
    assert!(msg.contains("The password must include numbers or symbols."));
    assert!(msg.contains("Don't include any part of your name in the password."));
    let length = [
        0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(
        chpw_message(&length),
        "The password must contain at least 13 characters."
    );
    let history = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(
        chpw_message(&history),
        "The password must be different from the previous 9 passwords."
    );
    let mut age = [0u8; 30];
    age[22..30].copy_from_slice(&0x0000_0192_54d3_8000u64.to_be_bytes());
    assert_eq!(
        chpw_message(&age),
        "The password can only be changed every 2 days."
    );
    let mut all = [0u8; 30];
    all[5] = 5;
    all[9] = 13;
    all[13] = 1;
    all[22..30].copy_from_slice(&0x0000_00c9_2a69_c000u64.to_be_bytes());
    let msg = chpw_message(&all);
    assert!(msg.contains("The password can only be changed once a day."));
    assert!(msg.contains("The password must be different from the previous 13 passwords."));
    assert!(msg.contains("The password must contain at least 5 characters."));
    assert!(msg.contains("The password must include numbers or symbols."));
}

#[test]
fn renew_options_are_common_mask_plus_renew() {
    let flags = TicketFlags::from_u32(0x5480_0000);
    let opts = tgs_renew_options(&flags);
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::PROXIABLE));
    assert!(opts.bit(flag_bit::MAY_POSTDATE));
    assert!(opts.bit(flag_bit::RENEWABLE));
    assert!(opts.bit(flag_bit::RENEW), "val_renew.c:129 KDC_OPT_RENEW");
    assert!(
        !opts.bit(flag_bit::CANONICALIZE),
        "renew is not the get_creds referral walk"
    );
}

#[test]
fn renew_options_omit_unset_ticket_flags() {
    let flags = TicketFlags::from_u32(0x4000_0000);
    let opts = tgs_renew_options(&flags);
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::RENEW));
    assert!(!opts.bit(flag_bit::PROXIABLE));
    assert!(!opts.bit(flag_bit::RENEWABLE));
    assert!(!opts.bit(flag_bit::CANONICALIZE));
}
