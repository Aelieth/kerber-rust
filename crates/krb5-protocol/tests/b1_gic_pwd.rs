//! W1-B B1: `gic_pwd.c` KEY_EXP → changepw + `chpw.c` result codes.
//! Live oracle: `client-differential-gate.sh` KEY_EXP cell vs MIT kadmind.

use krb5_protocol::{Error, key_exp_should_changepw, parse_chpw_result};
use krb5_types::err;

#[test]
fn b1_gic_pwd_key_exp_with_new_password_should_changepw() {
    let err = Error::KrbError {
        code: err::KEY_EXPIRED,
        text: Some("KEY EXPIRED".into()),
    };
    assert!(key_exp_should_changepw(&err, true, false));
}

#[test]
fn b1_gic_pwd_key_exp_without_new_password_does_not_changepw() {
    let err = Error::KrbError {
        code: err::KEY_EXPIRED,
        text: None,
    };
    assert!(!key_exp_should_changepw(&err, false, false));
}

#[test]
fn b1_gic_pwd_keytab_does_not_changepw() {
    let err = Error::KrbError {
        code: err::KEY_EXPIRED,
        text: None,
    };
    assert!(!key_exp_should_changepw(&err, true, true));
}

#[test]
fn b1_chpw_success_is_ok() {
    assert_eq!(parse_chpw_result(&[0, 0], false).unwrap(), 0);
}

#[test]
fn b1_chpw_out_of_range_is_modified() {
    let err = parse_chpw_result(&[0, 8], false).unwrap_err();
    assert!(err.to_string().contains("modified"), "{err}");
}

#[test]
fn b1_chpw_success_from_error_is_modified() {
    let err = parse_chpw_result(&[0, 0], true).unwrap_err();
    assert!(err.to_string().contains("SUCCESS from KRB-ERROR"), "{err}");
}

#[test]
fn b1_chpw_truncated_is_modified() {
    let err = parse_chpw_result(&[0], false).unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
}

#[test]
fn b1_chpw_result_code_strings_match_mit() {
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
fn b1_chpw_message_utf8_and_fallback() {
    use krb5_protocol::chpw_message;
    assert_eq!(
        chpw_message(b"This is a valid string."),
        "This is a valid string."
    );
    assert!(chpw_message(b"\0This is not valid.").contains("contact your administrator"));
}

#[test]
fn b1_chpw_message_ad_policy_matches_mit_test_chpw_message() {
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
