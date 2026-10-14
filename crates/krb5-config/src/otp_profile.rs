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

    fn names(kdc: &str, krb5: &str) -> Vec<String> {
        let (k, c) = (KdcConf::parse(kdc).unwrap(), Krb5Conf::parse(krb5).unwrap());
        OtpProfile::new(&[&k.otp, &c.otp])
            .subsection_names()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn type_names(t: &[OtpType]) -> Vec<&str> {
        t.iter().map(|t| t.name.as_str()).collect()
    }

    fn one(kdc: &str) -> OtpType {
        types(kdc, "").unwrap().pop().unwrap()
    }

    /// Settle probe c01, d03: MIT lists the types file by file, each file's in `strcmp` order, with repeats.
    #[test]
    fn names_come_in_strcmp_order_per_file_and_repeats_stay() {
        let kdc = "[otp]\n Zed = {\n  indicator = z1\n }\n Alpha = {\n  indicator = a1\n }\n mid = {\n }\n _under = {\n }\n 10 = {\n }\n";
        let krb5 = "[otp]\n Beta = {\n  indicator = b1\n }\n Alpha = {\n  indicator = a2\n }\n";
        assert_eq!(
            names(kdc, krb5),
            ["10", "Alpha", "Zed", "_under", "mid", "Alpha", "Beta"]
        );
        let t = types(kdc, krb5).unwrap();
        assert_eq!(
            type_names(&t),
            [
                "DEFAULT", "10", "Alpha", "Zed", "_under", "mid", "Alpha", "Beta"
            ]
        );
        // The two Alphas read the same relations, kdc.conf's indicator first.
        assert_eq!(t[2], t[6]);
        assert_eq!(t[2].indicators, ["a1", "a2"]);
        let odd = names(
            "[otp]\n totp.v2 = {\n }\n a@b = {\n }\n ünï = {\n }\n DEFAULT = {\n }\n",
            "",
        );
        assert_eq!(odd, ["DEFAULT", "a@b", "totp.v2", "ünï"]);
    }

    /// Settle probe c04, c05, d04, d05: the built-in DEFAULT keeps the realm; a defined one strips it.
    #[test]
    fn a_defined_default_replaces_the_builtin_one() {
        for kdc in ["[realms]\n X = {\n }\n", "[otp]\n"] {
            let t = types(kdc, "").unwrap();
            assert_eq!(t, [OtpType::builtin("DEFAULT")], "{kdc:?}");
            assert!(!t[0].strip_realm);
        }
        let t = types("[otp]\n DEFAULT = {\n }\n", "").unwrap();
        assert_eq!(type_names(&t), ["DEFAULT"]);
        assert!(t[0].strip_realm);
        // DEFAULT written in krb5.conf only still replaces it.
        let t = types(
            "[otp]\n A = {\n }\n",
            "[otp]\n DEFAULT = {\n  indicator = d\n }\n",
        )
        .unwrap();
        assert_eq!(type_names(&t), ["A", "DEFAULT"]);
        assert_eq!(t[1].indicators, ["d"]);
        // `[otp]` in krb5.conf alone is read (probe c06).
        let t = types("", "[otp]\n only = {\n  strip_realm = no\n }\n").unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "only"]);
        assert!(!t[1].strip_realm);
    }

    /// Settle probe c02, d06: a single value is the first file's that has it; `indicator` is every file's.
    #[test]
    fn kdc_conf_wins_a_single_value_and_indicators_come_from_both_files() {
        let kdc = "[otp]\n A = {\n  strip_realm = false\n  timeout = 7\n  indicator = k1\n }\n";
        let krb5 = "[otp]\n A = {\n  strip_realm = true\n  timeout = 9\n  retries = 4\n  indicator = k2\n }\n";
        let a = types(kdc, krb5).unwrap().pop().unwrap();
        assert_eq!(
            a,
            OtpType {
                name: "A".into(),
                strip_realm: false,
                indicators: vec!["k1".into(), "k2".into()],
                timeout_ms: 7000,
                retries: 4,
            }
        );
        let d = types(
            "[otp]\n DEFAULT = {\n  strip_realm = false\n }\n",
            "[otp]\n DEFAULT = {\n  strip_realm = true\n  indicator = fromkrb5\n }\n",
        )
        .unwrap();
        assert_eq!(type_names(&d), ["DEFAULT", "DEFAULT"]);
        assert!(!d[0].strip_realm);
        assert_eq!(d[0].indicators, ["fromkrb5"]);
    }

    /// Settle probe c03, c07e: a repeated section or subsection is one node, and the first relation wins.
    #[test]
    fn repeated_blocks_merge_and_the_first_relation_wins() {
        let kdc = "[otp]\n A = {\n  indicator = i1\n  strip_realm = false\n  strip_realm = true\n  indicator = i2\n }\n[libdefaults]\n x = y\n[otp]\n A = {\n  indicator = i3\n  strip_realm = true\n }\n B = {\n }\n";
        let t = types(kdc, "").unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "A", "B"]);
        assert!(!t[1].strip_realm);
        assert_eq!(t[1].indicators, ["i1", "i2", "i3"]);
    }

    /// Settle probe c07a-e: a final section, subsection or relation in kdc.conf stops krb5.conf; in one file a final relation keeps the later same-named one out.
    #[test]
    fn a_final_node_stops_the_later_file_as_mit_does() {
        let krb5 = "[otp]\n A = {\n  indicator = k2\n  strip_realm = true\n }\n B = {\n }\n";
        // The whole section: krb5.conf's A and B are not even listed.
        let t = types("[otp]*\n A = {\n  indicator = k1\n }\n", krb5).unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "A"]);
        assert_eq!(t[1].indicators, ["k1"]);
        // A final subsection (`A* = {` and `}*`) ends the listing after its file, so B goes too.
        for kdc in [
            "[otp]\n A* = {\n  indicator = k1\n }\n",
            "[otp]\n A = {\n  indicator = k1\n }*\n",
        ] {
            let t = types(kdc, krb5).unwrap();
            assert_eq!(type_names(&t), ["DEFAULT", "A"], "{kdc:?}");
            assert_eq!(t[1].indicators, ["k1"]);
        }
        // A final relation blocks only that relation: the listing still has both files' names.
        let t = types(
            "[otp]\n A = {\n  indicator* = k1\n  strip_realm* = false\n }\n",
            krb5,
        )
        .unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "A", "A", "B"]);
        assert_eq!(t[1].indicators, ["k1"]);
        assert!(!t[1].strip_realm);
        // Inside one file the later relation of a final one's name is dropped.
        let t = one(
            "[otp]\n A = {\n  strip_realm* = false\n  strip_realm = true\n  indicator* = f1\n  indicator = f2\n }\n",
        );
        assert!(!t.strip_realm);
        assert_eq!(t.indicators, ["f1"]);
        // krb5.conf's own `[otp]*` blocks nothing here: no file follows it.
        let t = types(
            "[otp]\n A = {\n  indicator = k1\n }\n",
            "[otp]*\n A = {\n  indicator = k2\n }\n",
        )
        .unwrap();
        assert_eq!(t[1].indicators, ["k1", "k2"]);
    }

    /// A starred header of another section ends `[otp]` as an unstarred one does.
    #[test]
    fn any_other_header_leaves_the_section() {
        let kdc = "[otp]\n A = {\n  indicator = a\n }\n[realms]*\n B = {\n  indicator = b\n }\n[otp]\n C = {\n }\n";
        let t = types(kdc, "[plugins]*\n D = {\n }\n").unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "A", "C"]);
    }

    /// Settle probe c12, c14: names are case-sensitive; only relations of a type subsection count.
    #[test]
    fn only_relations_of_a_type_subsection_count() {
        let kdc = "[OTP]\n lower = {\n }\n";
        let krb5 = "[otp]\n server = /s/top.sock\n C = x\n a = {\n  Indicator = wrongcase\n  Strip_Realm = false\n  nested = {\n   indicator = deep\n  }\n  indicator = ok\n }\n[x]\n";
        let t = types(kdc, krb5).unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "a"]);
        assert!(t[1].strip_realm);
        assert_eq!(t[1].indicators, ["ok"]);
    }

    /// Settle probe c08: `profile_get_boolean` spellings, without case; anything else fails the decode.
    #[test]
    fn strip_realm_takes_the_profile_booleans() {
        for (v, want) in [
            ("y", true),
            ("YES", true),
            ("true", true),
            ("T", true),
            ("1", true),
            ("On", true),
            ("n", false),
            ("no", false),
            ("False", false),
            ("nil", false),
            ("0", false),
            ("Off", false),
        ] {
            let t = one(&format!("[otp]\n A = {{\n  strip_realm = {v}\n }}\n"));
            assert_eq!(t.strip_realm, want, "{v}");
        }
        for bad in ["maybe", "2", "", " yes", "true "] {
            let e = types(
                &format!("[otp]\n A = {{\n  strip_realm = \"{bad}\"\n }}\n"),
                "",
            )
            .unwrap_err();
            assert_eq!(e, init_error("Invalid boolean value"), "{bad:?}");
        }
        // An inline comment is part of the value (probe d01); trailing blanks and tabs are not (d02).
        let e = types("[otp]\n A = {\n  strip_realm = false # no realm\n }\n", "").unwrap_err();
        assert_eq!(e.emsg, "Invalid boolean value");
        let t = one("[otp]\n\tA = {\n\t\tstrip_realm\t=\tno   \n\t\ttimeout = 5   \n\t}\n");
        assert!(!t.strip_realm);
        assert_eq!(t.timeout_ms, 5000);
    }

    /// Settle probe c09: `parse_int` is `strtol` base 10 over the whole value in `int` range; `timeout` is seconds, kept in ms.
    #[test]
    fn timeout_and_retries_follow_parse_int() {
        for bad in ["5s", "0x10", "", "99999999999", "2147483648", "5 "] {
            let e =
                types(&format!("[otp]\n A = {{\n  timeout = \"{bad}\"\n }}\n"), "").unwrap_err();
            assert_eq!(e, init_error("Invalid integer value"), "{bad:?}");
            let e =
                types(&format!("[otp]\n A = {{\n  retries = \"{bad}\"\n }}\n"), "").unwrap_err();
            assert_eq!(e.emsg, "Invalid integer value", "{bad:?}");
        }
        for (v, ms, retries) in [
            (" 5", 5000, 5),
            ("+5", 5000, 5),
            ("-1", -1000, -1),
            ("0", 0, 0),
            ("08", 8000, 8),
            ("3000000", -1_294_967_296, 3_000_000),
            ("2147483647", -1000, i32::MAX),
        ] {
            let t = one(&format!(
                "[otp]\n A = {{\n  timeout = \"{v}\"\n  retries = \"{v}\"\n }}\n"
            ));
            assert_eq!((t.timeout_ms, t.retries), (ms, retries), "{v:?}");
        }
        let t = one("[otp]\n A = {\n }\n");
        assert_eq!((t.timeout_ms, t.retries), (5000, 3));
    }

    /// Settle probe c10: the first failing section in listing order is the one reported.
    #[test]
    fn the_first_bad_section_in_listing_order_is_reported() {
        let e = types(
            "[otp]\n Z = {\n  strip_realm = nope\n }\n A = {\n  timeout = nope\n }\n",
            "",
        )
        .unwrap_err();
        assert_eq!(e.emsg, "Invalid integer value");
        let e = types(
            "[otp]\n Z = {\n  strip_realm = nope\n }\n",
            "[otp]\n A = {\n  timeout = nope\n }\n",
        )
        .unwrap_err();
        assert_eq!(e.emsg, "Invalid boolean value");
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

    /// Settle probe c13: an indicator is the whole value, quotes processed, in file order.
    #[test]
    fn indicators_are_whole_values_in_file_order() {
        let t = one(
            "[otp]\n A = {\n  indicator = \"\"\n  indicator = a b\n  indicator = a,b\n  indicator = \"q \\\"uoted\\\"\"\n  indicator =   spaced   \n }\n",
        );
        assert_eq!(t.indicators, ["", "a b", "a,b", "q \"uoted\"", "spaced"]);
    }

    /// An include is part of the including file's tree, in the order it is met.
    #[test]
    fn an_include_is_part_of_the_including_files_tree() {
        let dir = krb5_testkit::scratch_dir("otp2-inc");
        let extra = dir.join("extra.conf");
        let main = dir.join("krb5.conf");
        std::fs::write(&extra, "[otp]\n B = {\n  indicator = fromextra\n }\n").unwrap();
        std::fs::write(
            &main,
            format!(
                "[otp]\n A = {{\n  indicator = a\n }}\ninclude {}\n[otp]\n A = {{\n  indicator = a2\n }}\n",
                extra.display()
            ),
        )
        .unwrap();
        let conf = Krb5Conf::load_file(&main).unwrap();
        let t = kdc_otp_types(&KdcConf::default(), &conf).unwrap();
        assert_eq!(type_names(&t), ["DEFAULT", "A", "B"]);
        assert_eq!(t[1].indicators, ["a", "a2"]);
        assert_eq!(t[2].indicators, ["fromextra"]);
    }
}
