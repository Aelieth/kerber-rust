use super::{NameError, PrincipalName};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedName {
    pub components: Vec<String>,
    pub realm: String,
    // MIT: `allocate_princ` (krb/parse.c:116-116)
    pub has_realm: bool,
}

pub fn parse_name(s: &str, default_realm: &str) -> Result<(Vec<String>, String), NameError> {
    let p = parse_name_ex(s, default_realm, false)?;
    Ok((p.components, p.realm))
}

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

// MIT: `k5_infer_principal_type` (bld_princ.c:31-42)
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

pub fn principal_from_unparsed(
    s: &str,
    default_realm: &str,
) -> Result<(PrincipalName, String), NameError> {
    principal_from_unparsed_ex(s, default_realm, false)
}

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

#[must_use]
pub fn unparse_components(comps: &[String]) -> String {
    comps
        .iter()
        .map(|c| quote_component(c))
        .collect::<Vec<_>>()
        .join("/")
}

#[must_use]
pub fn unparse_name(comps: &[String], realm: &str) -> String {
    format!("{}@{}", unparse_components(comps), quote_component(realm))
}

// MIT: `copy_component_quoting` (lib/krb5/krb/unparse.c:103-107)
// With no realm, `REALM_SEP` is copied as is.
#[must_use]
pub fn unparse_components_no_realm(comps: &[String]) -> String {
    comps
        .iter()
        .map(|c| {
            c.split('@')
                .map(quote_component)
                .collect::<Vec<_>>()
                .join("@")
        })
        .collect::<Vec<_>>()
        .join("/")
}
