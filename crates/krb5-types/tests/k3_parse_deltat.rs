//! Public `parse_name` / `deltat::parse` (MIT `parse.c` / `x-deltat.y`).

use krb5_types::{deltat, parse_name, unparse_components, unparse_name};

#[test]
fn parse_name_escapes_and_empty_realm() {
    let (c, r) = parse_name(r"foo\/bar", "R").unwrap();
    assert_eq!(c, vec!["foo/bar".to_string()]);
    assert_eq!(r, "R");
    assert_eq!(unparse_components(&c), r"foo\/bar");
    let (c, r) = parse_name("foo@", "R").unwrap();
    assert_eq!(c, vec!["foo".to_string()]);
    assert_eq!(r, "");
    assert_eq!(unparse_name(&["foo/bar".into()], "R"), r"foo\/bar@R");
}

#[test]
fn deltat_t_c_vectors_and_hhmm() {
    assert_eq!(deltat::parse("12:34").unwrap(), 12 * 3600 + 34 * 60);
    assert_eq!(deltat::parse("3d").unwrap(), 3 * 24 * 3600);
    assert!(deltat::parse("3dd").is_err());
    assert_eq!(deltat::parse("42").unwrap(), 42);
}
