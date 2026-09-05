//! Request-realm ACL text and `mylex` YYEOF leftover (`42x` → 42 s).

use krb5_kdc::Acl;
use krb5_types::deltat;

#[test]
fn parse_42x_is_forty_two_seconds() {
    assert_eq!(deltat::parse("42x"), Ok(42));
    assert!(deltat::parse("3dd").is_err());
}

#[test]
fn acl_unknown_op_letter_includes_line() {
    let err = Acl::parse("bad@KERBER.TEST aZ\n").unwrap_err();
    assert!(
        err.to_string()
            .contains("Unrecognized ACL operation 'Z' in bad@KERBER.TEST aZ"),
        "{err}"
    );
}
