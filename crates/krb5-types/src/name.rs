//! `krb5_parse_name` / `krb5_unparse_name` (`parse.c`, `unparse.c`).

use super::{NameError, PrincipalName};

/// Result of `krb5_parse_name_flags` without context flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedName {
    /// Name components, including empty ones (`a//b`).
    pub components: Vec<String>,
    /// Realm; empty when the input was `foo@` or `NO_DEF_REALM`.
    pub realm: String,
    /// Whether an unquoted `@` started a realm (`parse.c:116`).
    pub has_realm: bool,
}

/// Parse `name[@realm]` with MIT quoting (`parse.c:62-102`).
///
/// Empty components are allowed. `foo@` keeps an empty realm. No `@`
/// uses `default_realm`. Trailing `\` is an error. `/` or a second `@`
/// in the realm is malformed.
///
/// # Errors
///
/// [`NameError::Malformed`] on a trailing `\` or a `/`/`@` in the realm.
pub fn parse_name(s: &str, default_realm: &str) -> Result<(Vec<String>, String), NameError> {
    let p = parse_name_ex(s, default_realm, false)?;
    Ok((p.components, p.realm))
}

/// Parse with MIT enterprise rules: first `@` is a component character.
///
/// # Errors
///
/// [`NameError::Malformed`] on a trailing `\` or a second `@` in the realm.
pub fn parse_name_ex(
    s: &str,
    default_realm: &str,
    enterprise: bool,
) -> Result<ParsedName, NameError> {
    let mut comps = vec![String::new()];
    let mut realm: Option<String> = None;
    let mut in_realm = false;
    let mut first_at = true;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let n = chars.next().ok_or(NameError::Malformed)?;
            let ch = match n {
                'n' => '\n',
                't' => '\t',
                'b' => '\u{8}',
                '0' => '\0',
                other => other,
            };
            push_char(&mut comps, &mut realm, in_realm, ch);
        } else if c == '/' && !enterprise {
            if in_realm {
                return Err(NameError::Malformed);
            }
            comps.push(String::new());
        } else if c == '@' && (!enterprise || !first_at) {
            if in_realm {
                return Err(NameError::Malformed);
            }
            in_realm = true;
            realm = Some(String::new());
        } else {
            if c == '@' && enterprise {
                first_at = false;
            }
            push_char(&mut comps, &mut realm, in_realm, c);
        }
    }
    let has_realm = in_realm;
    let realm = realm.unwrap_or_else(|| default_realm.to_owned());
    Ok(ParsedName {
        components: comps,
        realm,
        has_realm,
    })
}

fn push_char(comps: &mut [String], realm: &mut Option<String>, in_realm: bool, ch: char) {
    if in_realm {
        realm.get_or_insert_with(String::new).push(ch);
    } else if let Some(cur) = comps.last_mut() {
        cur.push(ch);
    }
}

/// MIT `k5_infer_principal_type` (`bld_princ.c:31-42`).
#[must_use]
pub fn infer_name_type(comps: &[String]) -> i32 {
    if comps.len() == 2 && comps[0] == "krbtgt" {
        PrincipalName::NT_SRV_INST
    } else if comps.len() >= 2 && comps[0] == "WELLKNOWN" {
        PrincipalName::NT_WELLKNOWN
    } else {
        PrincipalName::NT_PRINCIPAL
    }
}

/// Parse an unparsed name into a [`PrincipalName`] and realm.
///
/// # Errors
///
/// [`NameError`] from [`parse_name_ex`] or [`PrincipalName::try_new`].
pub fn principal_from_unparsed(
    s: &str,
    default_realm: &str,
) -> Result<(PrincipalName, String), NameError> {
    principal_from_unparsed_ex(s, default_realm, false)
}

/// Parse with enterprise rules (`KRB5_PRINCIPAL_PARSE_ENTERPRISE`).
///
/// # Errors
///
/// [`NameError`] from [`parse_name_ex`] or [`PrincipalName::try_new`].
pub fn principal_from_unparsed_ex(
    s: &str,
    default_realm: &str,
    enterprise: bool,
) -> Result<(PrincipalName, String), NameError> {
    let p = parse_name_ex(s, default_realm, enterprise)?;
    let ntype = if enterprise {
        PrincipalName::NT_ENTERPRISE
    } else {
        infer_name_type(&p.components)
    };
    Ok((PrincipalName::try_new(ntype, p.components)?, p.realm))
}

/// Quote one component (`unparse.c` `copy_component_quoting`).
#[must_use]
pub fn quote_component(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '/' | '@' | '\\' => {
                o.push('\\');
                o.push(c);
            }
            '\t' => o.push_str("\\t"),
            '\n' => o.push_str("\\n"),
            '\u{8}' => o.push_str("\\b"),
            '\0' => o.push_str("\\0"),
            other => o.push(other),
        }
    }
    o
}

/// Join quoted components with `/`.
#[must_use]
pub fn unparse_components(comps: &[String]) -> String {
    comps
        .iter()
        .map(|c| quote_component(c))
        .collect::<Vec<_>>()
        .join("/")
}

/// MIT `krb5_unparse_name`: quoted components `@` quoted realm.
#[must_use]
pub fn unparse_name(comps: &[String], realm: &str) -> String {
    format!("{}@{}", unparse_components(comps), quote_component(realm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unparse_escapes() {
        let (c, r) = parse_name(r"foo\/bar", "R").unwrap();
        assert_eq!(c, vec!["foo/bar".to_string()]);
        assert_eq!(r, "R");
        assert_eq!(unparse_components(&c), r"foo\/bar");
        let (c, r) = parse_name(r"a\@b@REALM", "").unwrap();
        assert_eq!(c, vec!["a@b".to_string()]);
        assert_eq!(r, "REALM");
        let (c, _) = parse_name(r"x\\y", "R").unwrap();
        assert_eq!(c, vec![r"x\y".to_string()]);
        let (c, _) = parse_name(r"a\nb", "R").unwrap();
        assert_eq!(c, vec!["a\nb".to_string()]);
        assert_eq!(unparse_components(&c), r"a\nb");
        let (c, _) = parse_name(r"a\tb\b0\0z", "R").unwrap();
        assert_eq!(c, vec!["a\tb\u{8}0\0z".to_string()]);
        assert_eq!(unparse_components(&c), r"a\tb\b0\0z");
        let (c, r) = parse_name("foo@", "R").unwrap();
        assert_eq!(c, vec!["foo".to_string()]);
        assert_eq!(r, "");
        let (c, _) = parse_name("a//b", "R").unwrap();
        assert_eq!(c, vec!["a".to_string(), String::new(), "b".to_string()]);
        assert!(parse_name(r"foo\", "R").is_err());
        assert!(parse_name("foo@BAR/BAZ", "R").is_err());
        assert!(parse_name("foo@BAR@BAZ", "R").is_err());
        let p = parse_name_ex("alice@ad.example.com@KERBER.TEST", "", true).unwrap();
        assert_eq!(p.components, vec!["alice@ad.example.com".to_string()]);
        assert_eq!(p.realm, "KERBER.TEST");
        let p = parse_name_ex("user@KERBER.TEST", "", true).unwrap();
        assert_eq!(p.components, vec!["user@KERBER.TEST".to_string()]);
        assert!(!p.has_realm);
        let (n, r) = principal_from_unparsed("krbtgt/KERBER.TEST@KERBER.TEST", "").unwrap();
        assert_eq!(n.name_type, PrincipalName::NT_SRV_INST);
        assert_eq!(r, "KERBER.TEST");
        let (n, _) = principal_from_unparsed("host/slashhost@KERBER.TEST", "").unwrap();
        assert_eq!(n.name_type, PrincipalName::NT_PRINCIPAL);
        assert_eq!(n.unparse(), "host/slashhost");
        assert_eq!(unparse_name(&["foo/bar".into()], "R"), r"foo\/bar@R");
    }
}
