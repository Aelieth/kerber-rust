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
