//! `[otp]` (`plugins/preauth/otp/otp_state.c`): the token types MIT's otp module reads from the KDC
//! context's profile, kdc.conf first, then krb5.conf.
//!
//! Two halves. The tree: `[otp]` of one file as MIT's profile library keeps it (`util/profile`),
//! and the lookups the module makes over the files in order. The decode: `token_types_decode`. The
//! RADIUS `server` and `secret` are refused, so the module does not initialize (`docs/mit-deviations.md`).

use std::collections::BTreeMap;

use super::plugin_profile::{PluginLine, parse_plugin_line};
use super::profile::{c_isspace, mit_boolean, parse_profile_int};
use super::{KdcConf, Krb5Conf};

/// MIT `DEFAULT_TYPE_NAME` (`plugins/preauth/otp/otp_state.c:42-42`): the token type a token names when it names none.
pub const DEFAULT_OTP_TYPE: &str = "DEFAULT";

/// MIT `PROF_BAD_BOOLEAN` (`util/profile/prof_err.et:60-60`): the text of a value that is no boolean.
const BAD_BOOLEAN: &str = "Invalid boolean value";
/// MIT `PROF_BAD_INTEGER` (`util/profile/prof_err.et:61-61`): the text of a value that is no integer.
const BAD_INTEGER: &str = "Invalid integer value";
/// `strerror(EINVAL)`, the code MIT's module fails a section with.
const EINVAL: &str = "Invalid argument";

/// `[otp]` of one profile file: the subsections in `strcmp` order, a repeated one merged into the first,
/// each with its relations in file order.
///
/// MIT `profile_add_node` (`util/profile/prof_tree.c:197-250`): a node goes after the last node whose name is not greater, a repeated subsection is the first one, and a relation is dropped when a final relation of that name is already there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OtpTree {
    section_final: bool,
    types: BTreeMap<String, TypeNode>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TypeNode {
    is_final: bool,
    relations: Vec<Relation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Relation {
    name: String,
    value: String,
    is_final: bool,
}

impl OtpTree {
    /// The node of `ty`, and whether a final node was passed on the way to it.
    ///
    /// MIT `profile_node_iterator` (`util/profile/prof_tree.c:518-653`): a final section or subsection stops the walk at the end of its file.
    fn node(&self, ty: &str) -> (Option<&TypeNode>, bool) {
        let node = self.types.get(ty);
        (node, self.section_final || node.is_some_and(|n| n.is_final))
    }
}

/// The KDC context's profile as the otp module reads it: the `[otp]` of each file, first file first.
#[derive(Clone, Debug, Default)]
pub struct OtpProfile<'a> {
    files: Vec<&'a OtpTree>,
}

impl<'a> OtpProfile<'a> {
    /// A profile of these files, in lookup order.
    #[must_use]
    pub fn new(files: &[&'a OtpTree]) -> Self {
        Self {
            files: files.to_vec(),
        }
    }

    /// The names under `[otp]`: each file's in ascending order, then the next file's, none removed.
    ///
    /// MIT `profile_get_subsection_names` (`util/profile/prof_get.c:405-436`): every subsection the iterator returns is listed, repeats included.
    #[must_use]
    pub fn subsection_names(&self) -> Vec<&'a str> {
        let mut out = Vec::new();
        for file in &self.files {
            let mut final_seen = file.section_final;
            for (name, node) in &file.types {
                out.push(name.as_str());
                final_seen |= node.is_final;
            }
            if final_seen {
                break;
            }
        }
        out
    }

    /// The first value of `relation` in `ty`, from the first file that has one.
    ///
    /// MIT `profile_get_value` (`util/profile/prof_get.c:219-249`): the first value the iterator yields. A final node ends the walk at the end of its file.
    #[must_use]
    pub fn value(&self, ty: &str, relation: &str) -> Option<&'a str> {
        for file in &self.files {
            let (node, final_seen) = file.node(ty);
            if let Some(r) = node.and_then(|n| n.relations.iter().find(|r| r.name == relation)) {
                return Some(r.value.as_str());
            }
            if final_seen {
                break;
            }
        }
        None
    }

    /// Every value of `relation` in `ty`, each file's in file order, kdc.conf's first.
    ///
    /// MIT `profile_get_values` (`util/profile/prof_get.c:156-193`): all the values the iterator yields, across the files.
    #[must_use]
    pub fn values(&self, ty: &str, relation: &str) -> Vec<&'a str> {
        let mut out = Vec::new();
        for file in &self.files {
            let (node, mut final_seen) = file.node(ty);
            for r in node
                .into_iter()
                .flat_map(|n| n.relations.iter())
                .filter(|r| r.name == relation)
            {
                out.push(r.value.as_str());
                final_seen |= r.is_final;
            }
            if final_seen {
                break;
            }
        }
        out
    }
}

/// One token type of `[otp]`, as MIT's `token_type_decode` reads it, without the RADIUS `server` and `secret`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpType {
    /// The name a token's `type` selects. It also names the embedder verifier.
    pub name: String,
    /// Whether the username of a token that names none leaves the realm out.
    pub strip_realm: bool,
    /// The indicators a token of this type adds when it has none of its own, in profile order.
    pub indicators: Vec<String>,
    /// MIT's `timeout` in milliseconds. Read, unused: the verifier is in process.
    pub timeout_ms: i32,
    /// MIT's `retries`. Read, unused.
    pub retries: i32,
}

impl OtpType {
    /// The built-in type of that name.
    ///
    /// MIT `token_type_default` (`plugins/preauth/otp/otp_state.c:152-166`): the realm stays in the username, there are no indicators, the timeout is 5 s and there are 3 retries.
    #[must_use]
    pub fn builtin(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            strip_realm: false,
            indicators: Vec::new(),
            timeout_ms: 5000,
            retries: 3,
        }
    }
}

/// Why the otp module does not initialize.
///
/// MIT `load_preauth_plugins` (`kdc/kdc_preauth.c:207-219`): the module is left out and the KDC starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpInitError {
    /// MIT's message for the failing code, which ends the `preauth otp failed to initialize` line.
    pub emsg: String,
    /// The `com_err` text MIT logs before that line, when it logs one.
    pub detail: Option<String>,
}

fn init_error(emsg: &str) -> OtpInitError {
    OtpInitError {
        emsg: emsg.to_owned(),
        detail: None,
    }
}

/// MIT `profile_get_integer` (`util/profile/prof_get.c:309-334`): a relation that is absent is the default, one that is no integer fails.
fn integer(
    profile: &OtpProfile<'_>,
    ty: &str,
    relation: &str,
    default: i32,
) -> Result<i32, OtpInitError> {
    match profile.value(ty, relation) {
        None => Ok(default),
        Some(v) => parse_profile_int(v).ok_or_else(|| init_error(BAD_INTEGER)),
    }
}

/// MIT `token_type_decode` (`plugins/preauth/otp/otp_state.c:178-279`): one type from the profile.
/// The order is MIT's: `strip_realm`, `server`, `secret`, `timeout`, `retries`, `indicator`. A
/// `server` or `secret` fails the section, where MIT reads the RADIUS socket and the secret file.
fn token_type_decode(profile: &OtpProfile<'_>, name: &str) -> Result<OtpType, OtpInitError> {
    // MIT `token_type_decode` (`plugins/preauth/otp/otp_state.c:194-197`): `strip_realm` is a boolean, true when absent, and a value that is none fails.
    let strip_realm = match profile.value(name, "strip_realm") {
        None => true,
        Some(v) => mit_boolean(v).ok_or_else(|| init_error(BAD_BOOLEAN))?,
    };
    // MIT `token_type_decode` (`plugins/preauth/otp/otp_state.c:200-237`): `server` and `secret` name the RADIUS socket and its secret file.
    for relation in ["server", "secret"] {
        if profile.value(name, relation).is_some() {
            return Err(OtpInitError {
                emsg: EINVAL.to_owned(),
                detail: Some(format!(
                    "Unsupported relation '{relation}' (token type '{name}'): RADIUS is not implemented; an embedder's OtpVerifier decides"
                )),
            });
        }
    }
    // MIT `token_type_decode` (`plugins/preauth/otp/otp_state.c:240-250`): `timeout` is seconds, stored in milliseconds, and `retries` is a count.
    let timeout = integer(profile, name, "timeout", 5)?;
    let retries = integer(profile, name, "retries", 3)?;
    // MIT `token_type_decode` (`plugins/preauth/otp/otp_state.c:253-262`): every `indicator`, in order.
    let indicators = profile
        .values(name, "indicator")
        .into_iter()
        .map(str::to_owned)
        .collect();
    Ok(OtpType {
        name: name.to_owned(),
        strip_realm,
        indicators,
        timeout_ms: timeout.wrapping_mul(1000),
        retries,
    })
}

/// MIT `token_types_decode` (`plugins/preauth/otp/otp_state.c:298-344`): the built-in DEFAULT when no
/// section is named DEFAULT, then one type per name `[otp]` lists. A repeat of a name is a second,
/// identical type, as in MIT.
///
/// # Errors
///
/// The first section that fails, in listing order: [`OtpInitError`] with MIT's message for a
/// `strip_realm` that is no boolean or a `timeout` or `retries` that is no integer, and for a
/// `server` or `secret`, which are refused.
pub fn token_types_decode(profile: &OtpProfile<'_>) -> Result<Vec<OtpType>, OtpInitError> {
    let names = profile.subsection_names();
    let mut types = Vec::with_capacity(names.len() + 1);
    if !names.contains(&DEFAULT_OTP_TYPE) {
        types.push(OtpType::builtin(DEFAULT_OTP_TYPE));
    }
    for name in names {
        types.push(token_type_decode(profile, name)?);
    }
    Ok(types)
}

/// The token types for a KDC with this kdc.conf and krb5.conf.
///
/// MIT `otp_state_new` (`plugins/preauth/otp/otp_state.c:579-585`): the types come from the KDC context's profile, whose files are kdc.conf, then krb5.conf.
///
/// # Errors
///
/// As [`token_types_decode`].
pub fn kdc_otp_types(kdc: &KdcConf, krb5: &Krb5Conf) -> Result<Vec<OtpType>, OtpInitError> {
    token_types_decode(&OtpProfile::new(&[&kdc.otp, &krb5.otp]))
}

/// A section header line: its name and whether a `*` follows the `]`. A `[otp]` header enters the
/// section, and any other leaves it, starred or not.
///
/// MIT `parse_std_line` (`util/profile/prof_parse.c:92-124`): the name is the text up to the first `]`, a `*` after it marks the section final, and only blanks may follow.
pub(crate) fn section_header(line: &str) -> Option<(&str, bool)> {
    let rest = line.strip_prefix('[')?;
    let (body, after) = rest.split_once(']')?;
    let (starred, tail) = match after.strip_prefix('*') {
        Some(tail) => (true, tail),
        None => (false, after),
    };
    tail.chars().all(c_isspace).then_some((body, starred))
}

/// Reads `[otp]` out of one file's lines. The tree is shared with the file's includes and is not cleared.
pub(crate) struct Cursor {
    depth: usize,
    discard: usize,
    in_otp: bool,
    ty: Option<String>,
}

impl Cursor {
    pub(crate) fn new() -> Self {
        Self {
            depth: 0,
            discard: 0,
            in_otp: false,
            ty: None,
        }
    }

    /// `body` is the text between `[` and `]`, not lower-cased.
    ///
    /// MIT `parse_std_line` (`util/profile/prof_parse.c:76-212`): a repeated section is the same node, and one seen with the final flag discards its later values until the next section.
    pub(crate) fn observe_header(&mut self, tree: &mut OtpTree, body: &str, starred: bool) {
        if body == "otp" {
            self.in_otp = true;
            self.depth = 1;
            self.ty = None;
            self.discard = usize::from(tree.section_final);
            if starred {
                tree.section_final = true;
            }
        } else {
            self.in_otp = false;
            self.depth = 0;
            self.discard = 0;
            self.ty = None;
        }
    }

    pub(crate) fn observe_line(&mut self, tree: &mut OtpTree, line: &str) {
        if !self.in_otp {
            return;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return;
        }
        if let Some(rest) = line.strip_prefix('}') {
            self.close_brace(tree, rest.starts_with('*'));
            return;
        }
        match parse_plugin_line(line) {
            None => {}
            Some(PluginLine::Subsection { name, starred }) => self.open_sub(tree, &name, starred),
            Some(PluginLine::Relation {
                name,
                starred,
                value,
            }) => self.add_relation(tree, &name, starred, value),
        }
    }

    fn open_sub(&mut self, tree: &mut OtpTree, name: &str, starred: bool) {
        self.depth += 1;
        if self.discard != 0 || self.depth != 2 {
            return;
        }
        self.ty = Some(name.to_owned());
        let node = tree.types.entry(name.to_owned()).or_default();
        if node.is_final {
            self.discard = self.depth;
        }
        if starred {
            node.is_final = true;
        }
    }

    fn add_relation(&mut self, tree: &mut OtpTree, name: &str, starred: bool, value: String) {
        if self.discard != 0 || self.depth != 2 {
            return;
        }
        let Some(ty) = self.ty.as_deref() else {
            return;
        };
        let node = tree.types.entry(ty.to_owned()).or_default();
        if node.relations.iter().any(|r| r.name == name && r.is_final) {
            return;
        }
        node.relations.push(Relation {
            name: name.to_owned(),
            value,
            is_final: starred,
        });
    }

    fn close_brace(&mut self, tree: &mut OtpTree, starred: bool) {
        if self.depth < 2 {
            return;
        }
        if starred
            && self.discard == 0
            && self.depth == 2
            && let Some(ty) = self.ty.as_deref()
        {
            tree.types.entry(ty.to_owned()).or_default().is_final = true;
        }
        self.depth -= 1;
        if self.discard > 0 && self.depth < self.discard {
            self.discard = 0;
        }
        if self.depth < 2 {
            self.ty = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(kdc: &str, krb5: &str) -> Result<Vec<OtpType>, OtpInitError> {
        kdc_otp_types(
            &KdcConf::parse(kdc).unwrap(),
            &Krb5Conf::parse(krb5).unwrap(),
        )
    }

    /// The deviation: a `server` or `secret` anywhere fails the section as EINVAL, in MIT's order of reads.
    #[test]
    fn server_and_secret_are_refused() {
        let refused = |relation: &str, name: &str| OtpInitError {
            emsg: "Invalid argument".into(),
            detail: Some(format!(
                "Unsupported relation '{relation}' (token type '{name}'): RADIUS is not implemented; an embedder's OtpVerifier decides"
            )),
        };
        for kdc in [
            "[otp]\n A = {\n  server = 10.0.0.1:1812\n }\n",
            "[otp]\n A = {\n  server = /s/x.sock\n }\n",
            "[otp]\n A = {\n  server = \"\"\n }\n",
        ] {
            assert_eq!(
                types(kdc, "").unwrap_err(),
                refused("server", "A"),
                "{kdc:?}"
            );
        }
        assert_eq!(
            types("[otp]\n A = {\n  secret = realfile\n }\n", "").unwrap_err(),
            refused("secret", "A")
        );
        assert_eq!(
            types("[otp]\n A = {\n  secret = f\n  server = h\n }\n", "").unwrap_err(),
            refused("server", "A")
        );
        // From krb5.conf too, and in a later type.
        assert_eq!(
            types("[otp]\n A = {\n }\n", "[otp]\n B = {\n  server = h\n }\n").unwrap_err(),
            refused("server", "B")
        );
        // MIT's order: strip_realm is read before server, and server before timeout.
        let e = types(
            "[otp]\n A = {\n  strip_realm = maybe\n  server = h\n }\n",
            "",
        )
        .unwrap_err();
        assert_eq!(e, init_error("Invalid boolean value"));
        assert_eq!(
            types("[otp]\n A = {\n  timeout = x\n  server = h\n }\n", "").unwrap_err(),
            refused("server", "A")
        );
    }
}
