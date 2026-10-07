//! `[plugins]` `disable` and `enable_only` (`lib/krb5/krb/plugin.c`).
//!
//! `module` is not read. No interface is wired to this profile: a later stage asks by name.

use std::collections::BTreeMap;

use super::profile::{c_isspace, relation_value};
use super::{KdcConf, Krb5Conf};

/// `disable` and `enable_only` for one interface, in profile order.
///
/// MIT `get_profile_var` (`lib/krb5/krb/plugin.c:188-203`): a missing relation is absent, not an empty list.
/// MIT `profile_get_values` (`util/profile/prof_get.c:155-195`): each relation value is one string, in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginRelations {
    /// Values of `disable`, or absent when that relation is not set.
    pub disable: Option<Vec<String>>,
    /// Values of `enable_only`, or absent when that relation is not set.
    pub enable_only: Option<Vec<String>>,
}

/// `[plugins]` from one profile tree: every interface's `disable` and `enable_only`.
///
/// A `[plugins]*` section, a final interface, or a final relation blocks later profile files.
/// An `include` is part of this tree, not a later file.
///
/// MIT `parse_std_line` (`util/profile/prof_parse.c:75-212`): a `*` ends a name and marks that node final.
/// MIT `profile_add_node` (`util/profile/prof_tree.c:196-250`): a later value of a final relation is not stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginProfile {
    section_final: bool,
    ifaces: BTreeMap<String, IfaceRelations>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct IfaceRelations {
    disable: Vec<String>,
    disable_present: bool,
    disable_final: bool,
    enable_only: Vec<String>,
    enable_only_present: bool,
    enable_only_final: bool,
    iface_final: bool,
}

impl PluginProfile {
    /// The relations for `interface`, matched by exact name.
    #[must_use]
    pub fn relations(&self, interface: &str) -> PluginRelations {
        let Some(iface) = self.ifaces.get(interface) else {
            return PluginRelations::default();
        };
        PluginRelations {
            disable: iface.disable_present.then(|| iface.disable.clone()),
            enable_only: iface.enable_only_present.then(|| iface.enable_only.clone()),
        }
    }

    /// This profile, then `later`, as a second profile file after this one.
    ///
    /// For a KDC, pass kdc.conf's profile as `self`: that file is first.
    ///
    /// MIT `add_kdc_config_file` (`lib/krb5/os/init_os_ctx.c:339-366`): kdc.conf is inserted ahead of the krb5.conf files.
    #[must_use]
    pub fn followed_by(&self, later: &Self) -> Self {
        if self.section_final {
            return self.clone();
        }
        let mut out = self.clone();
        for (name, later_iface) in &later.ifaces {
            out.ifaces
                .entry(name.clone())
                .and_modify(|existing| merge_iface(existing, later_iface))
                .or_insert_with(|| later_iface.clone());
        }
        out.section_final = later.section_final;
        out
    }

    fn iface(&mut self, name: &str) -> &mut IfaceRelations {
        self.ifaces.entry(name.to_owned()).or_default()
    }
}

fn merge_iface(dest: &mut IfaceRelations, later: &IfaceRelations) {
    if dest.iface_final {
        return;
    }
    if !dest.disable_final {
        if later.disable_present {
            dest.disable.extend(later.disable.iter().cloned());
            dest.disable_present = true;
        }
        dest.disable_final |= later.disable_final;
    }
    if !dest.enable_only_final {
        if later.enable_only_present {
            dest.enable_only.extend(later.enable_only.iter().cloned());
            dest.enable_only_present = true;
        }
        dest.enable_only_final |= later.enable_only_final;
    }
    dest.iface_final |= later.iface_final;
}

/// Modules left after `disable`, then `enable_only`, in MIT's order.
///
/// The caller supplies the named modules, built-in and embedder-registered. `module` is not
/// applied here, and a name in the caller list is not removed except by these two relations.
///
/// ```
/// use krb5_config::{Krb5Conf, filter_plugin_modules};
/// let conf = Krb5Conf::parse(
///     "[plugins]\n hostrealm = {\n  disable = dns\n  enable_only = profile\n }\n",
/// )?;
/// let names = ["registry", "profile", "dns", "domain"];
/// let left = filter_plugin_modules(&conf.plugin_relations("hostrealm"), &names);
/// assert_eq!(left, vec!["profile".to_string()]);
/// Ok::<(), krb5_config::Error>(())
/// ```
///
/// MIT `configure_interface` (`lib/krb5/krb/plugin.c:301-347`): `disable` runs, then `enable_only`.
/// MIT `remove_disabled_modules` (`lib/krb5/krb/plugin.c:255-269`): named modules are dropped and the rest keep their order.
/// MIT `filter_enabled_modules` (`lib/krb5/krb/plugin.c:271-299`): each enabled name takes the first remaining match.
/// MIT `k5_plugin_load_all` (`lib/krb5/krb/plugin.c:421-455`): the configured names are what a caller walks.
#[must_use]
pub fn filter_plugin_modules<S: AsRef<str>>(
    relations: &PluginRelations,
    modules: &[S],
) -> Vec<String> {
    let mut list: Vec<String> = modules
        .iter()
        .map(|module| module.as_ref().to_owned())
        .collect();
    if let Some(disable) = &relations.disable {
        list.retain(|name| !disable.iter().any(|disabled| disabled == name));
    }
    let Some(enable) = &relations.enable_only else {
        return list;
    };
    let mut remaining = list;
    let mut kept = Vec::new();
    for wanted in enable {
        if let Some(index) = remaining.iter().position(|name| name == wanted) {
            kept.push(remaining.remove(index));
        }
    }
    kept
}

/// `interface` from kdc.conf's `[plugins]`, then krb5.conf's.
///
/// MIT `add_kdc_config_file` (`lib/krb5/os/init_os_ctx.c:339-366`): the KDC profile is the first file.
#[must_use]
pub fn kdc_plugin_relations(kdc: &KdcConf, krb5: &Krb5Conf, interface: &str) -> PluginRelations {
    kdc.plugins.followed_by(&krb5.plugins).relations(interface)
}

impl Krb5Conf {
    /// `[plugins]` relations for `interface` in this profile.
    ///
    /// MIT `get_profile_var` (`lib/krb5/krb/plugin.c:188-203`): the path is `plugins`, the interface, then the relation.
    #[must_use]
    pub fn plugin_relations(&self, interface: &str) -> PluginRelations {
        self.plugins.relations(interface)
    }
}

impl KdcConf {
    /// This kdc.conf file's `[plugins]` relations for `interface`.
    ///
    /// MIT `get_profile_var` (`lib/krb5/krb/plugin.c:188-203`): the path is `plugins`, the interface, then the relation.
    #[must_use]
    pub fn plugin_relations(&self, interface: &str) -> PluginRelations {
        self.plugins.relations(interface)
    }
}

/// Whether `line` is a `[plugins]*` header, optional blanks after the star.
///
/// MIT `parse_std_line` (`util/profile/prof_parse.c:92-124`): `*` after `]` marks the section final, and only blanks may follow.
#[must_use]
pub(crate) fn starred_plugins_header(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    let Some((body, after)) = rest.split_once(']') else {
        return false;
    };
    if body != "plugins" {
        return false;
    }
    let Some(tail) = after.strip_prefix('*') else {
        return false;
    };
    tail.chars().all(c_isspace)
}

/// Cursor for one file or include. The profile tree is shared and is not cleared.
pub(crate) struct Cursor {
    depth: usize,
    discard: usize,
    in_plugins: bool,
    iface: Option<String>,
}

impl Cursor {
    pub(crate) fn new() -> Self {
        Self {
            depth: 0,
            discard: 0,
            in_plugins: false,
            iface: None,
        }
    }

    /// `body` is the text between `[` and `]`, not lower-cased.
    pub(crate) fn observe_header(
        &mut self,
        profile: &mut PluginProfile,
        body: &str,
        starred: bool,
    ) {
        if body == "plugins" {
            self.in_plugins = true;
            self.depth = 1;
            self.iface = None;
            self.discard = usize::from(profile.section_final);
            if starred {
                profile.section_final = true;
            }
        } else {
            self.in_plugins = false;
            self.depth = 0;
            self.discard = 0;
            self.iface = None;
        }
    }

    pub(crate) fn observe_line(&mut self, profile: &mut PluginProfile, line: &str) {
        if !self.in_plugins {
            return;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return;
        }
        if let Some(rest) = line.strip_prefix('}') {
            self.close_brace(profile, rest.starts_with('*'));
            return;
        }
        let Some(parsed) = parse_plugin_line(line) else {
            return;
        };
        match parsed {
            PluginLine::Subsection { name, starred } => self.open_sub(profile, &name, starred),
            PluginLine::Relation {
                name,
                starred,
                value,
            } => {
                self.add_relation(profile, &name, starred, value);
            }
        }
    }

    fn open_sub(&mut self, profile: &mut PluginProfile, name: &str, starred: bool) {
        self.depth += 1;
        if self.discard != 0 || self.depth != 2 {
            return;
        }
        self.iface = Some(name.to_owned());
        let already_final = profile
            .ifaces
            .get(name)
            .is_some_and(|iface| iface.iface_final);
        if already_final {
            self.discard = self.depth;
        }
        if starred {
            profile.iface(name).iface_final = true;
        }
    }

    fn add_relation(
        &mut self,
        profile: &mut PluginProfile,
        name: &str,
        starred: bool,
        value: String,
    ) {
        if self.discard != 0 || self.depth != 2 {
            return;
        }
        if name != "disable" && name != "enable_only" {
            return;
        }
        let Some(iface_name) = self.iface.as_deref() else {
            return;
        };
        let iface = profile.iface(iface_name);
        let slot_final = if name == "disable" {
            iface.disable_final
        } else {
            iface.enable_only_final
        };
        if slot_final {
            return;
        }
        if name == "disable" {
            iface.disable.push(value);
            iface.disable_present = true;
            if starred {
                iface.disable_final = true;
            }
        } else {
            iface.enable_only.push(value);
            iface.enable_only_present = true;
            if starred {
                iface.enable_only_final = true;
            }
        }
    }

    fn close_brace(&mut self, profile: &mut PluginProfile, starred: bool) {
        if self.depth < 2 {
            return;
        }
        if starred
            && self.discard == 0
            && self.depth == 2
            && let Some(name) = self.iface.as_deref()
        {
            profile.iface(name).iface_final = true;
        }
        self.depth -= 1;
        if self.discard > 0 && self.depth < self.discard {
            self.discard = 0;
        }
        if self.depth < 2 {
            self.iface = None;
        }
    }
}

enum PluginLine {
    Subsection {
        name: String,
        starred: bool,
    },
    Relation {
        name: String,
        starred: bool,
        value: String,
    },
}

/// One relation or subsection. A tag with whitespace and then more text is skipped.
/// A quoted value is not a subsection, and the value is not split on whitespace.
fn parse_plugin_line(line: &str) -> Option<PluginLine> {
    let eq = line.find('=')?;
    if eq == 0 {
        return None;
    }
    let (tag_raw, value_raw) = line.split_at(eq);
    let value_raw = &value_raw[1..];
    let mut name_end = 0;
    for (index, ch) in tag_raw.char_indices() {
        if c_isspace(ch) {
            name_end = index;
            break;
        }
        name_end = index + ch.len_utf8();
    }
    if tag_raw[name_end..].chars().any(|ch| !c_isspace(ch)) {
        return None;
    }
    let tag = &tag_raw[..name_end];
    if tag.is_empty() {
        return None;
    }
    let (name, starred) = match tag.split_once('*') {
        Some((name, _)) => (name, true),
        None => (tag, false),
    };
    if name.is_empty() {
        return None;
    }
    if value_raw.trim_matches(c_isspace) == "{" {
        return Some(PluginLine::Subsection {
            name: name.to_owned(),
            starred,
        });
    }
    Some(PluginLine::Relation {
        name: name.to_owned(),
        starred,
        value: relation_value(value_raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_krb5_conf_paths;

    const HOST: &[&str] = &["registry", "profile", "dns", "domain"];

    fn host(text: &str) -> PluginRelations {
        Krb5Conf::parse(text).unwrap().plugin_relations("hostrealm")
    }

    fn kept(text: &str, modules: &[&str]) -> Vec<String> {
        filter_plugin_modules(&host(text), modules)
    }

    fn list(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn disable_drops_the_named_module_and_keeps_order() {
        let text = "[plugins]\n hostrealm = {\n  disable = dns\n  disable = registry\n }\n";
        assert_eq!(kept(text, HOST), list(&["profile", "domain"]));
        assert_eq!(host(text).disable, Some(list(&["dns", "registry"])));
    }

    #[test]
    fn enable_only_reorders_and_cannot_resurrect_a_disabled_module() {
        // t_pwqual.py `enable_only` after `disable`, with `module` left for the caller.
        let text = "\
[plugins]
    pwqual = {
        disable = dyn1
        disable = blt3
        enable_only = dyn2
        enable_only = blt3
        enable_only = blt2
        enable_only = dyn1
        enable_only = dyn3
        enable_only = xxx
    }
";
        let rel = Krb5Conf::parse(text).unwrap().plugin_relations("pwqual");
        let modules = ["dyn3", "dyn1", "dyn2", "blt1", "blt2", "blt3"];
        assert_eq!(
            filter_plugin_modules(&rel, &modules),
            list(&["dyn2", "blt2", "dyn3"])
        );
    }

    #[test]
    fn a_relation_value_is_one_string_not_a_word_list() {
        let modules = ["foo", "bar", "foo bar"];
        let disabled = "\
[plugins]
    hostrealm = {
        disable = foo bar
    }
";
        assert_eq!(host(disabled).disable, Some(list(&["foo bar"])));
        assert_eq!(
            filter_plugin_modules(&host(disabled), &modules),
            list(&["foo", "bar"])
        );
        let enabled = "\
[plugins]
    hostrealm = {
        enable_only = \"foo bar\"
    }
";
        assert_eq!(host(enabled).enable_only, Some(list(&["foo bar"])));
        assert_eq!(
            filter_plugin_modules(&host(enabled), &modules),
            list(&["foo bar"])
        );
    }

    #[test]
    fn an_empty_disable_value_drops_only_an_empty_name() {
        let rel = host("[plugins]\n hostrealm = {\n  disable = \"\"\n }\n");
        assert_eq!(rel.disable, Some(vec![String::new()]));
        assert_eq!(
            filter_plugin_modules(&rel, &["", "profile"]),
            list(&["profile"])
        );
    }

    #[test]
    fn a_trailing_comma_stays_in_the_value() {
        let rel = host("[plugins]\n hostrealm = {\n  disable = foo,\n }\n");
        assert_eq!(rel.disable, Some(list(&["foo,"])));
    }

    #[test]
    fn names_are_case_sensitive_and_module_is_unread() {
        let text = "\
[Plugins]
    hostrealm = {
        disable = dns
    }
[plugins]
    Hostrealm = {
        Disable = dns
        module = combo:somewhere
    }
    hostrealm = {
        module = profile:somewhere
    }
";
        let conf = Krb5Conf::parse(text).unwrap();
        assert_eq!(
            conf.plugin_relations("hostrealm"),
            PluginRelations::default()
        );
        assert_eq!(
            conf.plugin_relations("Hostrealm"),
            PluginRelations::default()
        );
        assert_eq!(
            filter_plugin_modules(&conf.plugin_relations("hostrealm"), HOST),
            list(HOST)
        );
    }

    #[test]
    fn absent_relations_return_the_caller_list_including_duplicates() {
        let rel = host("[plugins]\n hostrealm = {\n }\n");
        assert_eq!(rel, PluginRelations::default());
        assert_eq!(filter_plugin_modules(&rel, &["a", "a"]), list(&["a", "a"]));
        let empty_enable = PluginRelations {
            disable: None,
            enable_only: Some(Vec::new()),
        };
        assert_eq!(
            filter_plugin_modules(&empty_enable, HOST),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_repeated_enable_name_does_not_copy_a_module() {
        let rel = PluginRelations {
            disable: None,
            enable_only: Some(list(&["a", "a", "b"])),
        };
        assert_eq!(filter_plugin_modules(&rel, &["b", "a"]), list(&["a", "b"]));
        assert_eq!(
            filter_plugin_modules(&rel, &["a", "a", "b"]),
            list(&["a", "a", "b"])
        );
    }

    #[test]
    fn an_unknown_interface_is_unfiltered() {
        let conf = Krb5Conf::parse("[plugins]\n hostrealm = {\n  disable = dns\n }\n").unwrap();
        assert_eq!(conf.plugin_relations("nosuch"), PluginRelations::default());
        assert_eq!(
            filter_plugin_modules(&conf.plugin_relations("nosuch"), HOST),
            list(HOST)
        );
    }

    #[test]
    fn a_final_disable_drops_a_later_disable_and_keeps_enable_only() {
        let text = "\
[plugins]
    hostrealm = {
        disable* = dns
        disable = profile
        enable_only = registry
    }
";
        let rel = host(text);
        assert_eq!(rel.disable, Some(list(&["dns"])));
        assert_eq!(rel.enable_only, Some(list(&["registry"])));
    }

    #[test]
    fn a_star_inside_the_tag_ends_the_name_and_a_bad_tag_is_skipped() {
        let text = "\
[plugins]
    hostrealm = {
        dis*able = dns
        disable = domain
        dis able = registry
        *disable = profile
    }
";
        // `dis*able` is the relation `dis`, not `disable`. The spaced tag and the empty name are skipped.
        assert_eq!(host(text).disable, Some(list(&["domain"])));
        let conf = Krb5Conf::parse(text).unwrap();
        assert!(conf.context_refusal.is_none());
    }

    #[test]
    fn a_final_interface_and_a_final_section_block_later_files() {
        let dir = krb5_testkit::scratch_dir("pg1-files");
        let first = dir.join("first.conf");
        let second = dir.join("second.conf");
        std::fs::write(
            &first,
            "\
[plugins]
    hostrealm* = {
        disable = dns
    }
",
        )
        .unwrap();
        std::fs::write(
            &second,
            "\
[plugins]
    hostrealm = {
        disable = profile
        enable_only = registry
    }
    pwqual = {
        disable = dict
    }
",
        )
        .unwrap();
        let conf = load_krb5_conf_paths([&first, &second]).unwrap();
        assert_eq!(
            conf.plugin_relations("hostrealm").disable,
            Some(list(&["dns"]))
        );
        assert!(conf.plugin_relations("hostrealm").enable_only.is_none());
        assert_eq!(
            conf.plugin_relations("pwqual").disable,
            Some(list(&["dict"]))
        );

        std::fs::write(
            &first,
            "\
[plugins]*
    hostrealm = {
        disable = dns
    }
",
        )
        .unwrap();
        let blocked = load_krb5_conf_paths([&first, &second]).unwrap();
        assert_eq!(
            blocked.plugin_relations("hostrealm").disable,
            Some(list(&["dns"]))
        );
        assert_eq!(
            blocked.plugin_relations("pwqual"),
            PluginRelations::default()
        );
    }

    #[test]
    fn a_final_relation_blocks_only_that_relation_in_the_next_file() {
        let dir = krb5_testkit::scratch_dir("pg1-rel");
        let first = dir.join("a.conf");
        let second = dir.join("b.conf");
        std::fs::write(&first, "[plugins]\n hostrealm = {\n  disable* = dns\n }\n").unwrap();
        std::fs::write(
            &second,
            "[plugins]\n hostrealm = {\n  disable = profile\n  enable_only = registry\n }\n",
        )
        .unwrap();
        let conf = load_krb5_conf_paths([&first, &second]).unwrap();
        let rel = conf.plugin_relations("hostrealm");
        assert_eq!(rel.disable, Some(list(&["dns"])));
        assert_eq!(rel.enable_only, Some(list(&["registry"])));
    }

    #[test]
    fn an_include_is_the_same_tree_in_the_order_it_is_met() {
        let dir = krb5_testkit::scratch_dir("pg1-inc");
        let extra = dir.join("extra.conf");
        let main = dir.join("krb5.conf");
        std::fs::write(
            &extra,
            "[plugins]\n hostrealm = {\n  disable = domain\n  enable_only = registry\n }\n",
        )
        .unwrap();
        std::fs::write(
            &main,
            format!(
                "[plugins]\n hostrealm = {{\n  disable* = dns\ninclude {}\n  enable_only = profile\n }}\n",
                extra.display()
            ),
        )
        .unwrap();
        let rel = Krb5Conf::load_file(&main)
            .unwrap()
            .plugin_relations("hostrealm");
        assert_eq!(rel.disable, Some(list(&["dns"])));
        assert_eq!(rel.enable_only, Some(list(&["registry", "profile"])));
    }

    #[test]
    fn a_closing_star_makes_the_interface_final_for_a_later_reopen() {
        let text = "\
[plugins]
    hostrealm = {
        disable = dns
    }*
    hostrealm = {
        disable = domain
        enable_only = profile
    }
";
        let rel = host(text);
        assert_eq!(rel.disable, Some(list(&["dns"])));
        assert!(rel.enable_only.is_none());
    }

    #[test]
    fn a_nested_or_top_level_disable_is_not_the_interface_relation() {
        let text = "\
[plugins]
    disable = registry
    hostrealm = {
        nested = {
            disable = dns
        }
        disable = domain
    }
";
        assert_eq!(host(text).disable, Some(list(&["domain"])));
    }

    #[test]
    fn comments_blanks_and_a_brace_on_the_next_line_are_read() {
        let text = "\
[plugins]

    # comment
    ; comment
    hostrealm =
    {
        disable = dns
    }
";
        assert_eq!(kept(text, HOST), list(&["registry", "profile", "domain"]));
    }

    #[test]
    fn kdc_conf_plugins_come_before_krb5_conf_and_match_the_same_text() {
        let kdc_text = "[plugins]\n hostrealm = {\n  disable = dns\n }\n";
        let krb_text =
            "[plugins]\n hostrealm = {\n  disable = domain\n  enable_only = profile\n }\n";
        let kdc = KdcConf::parse(kdc_text).unwrap();
        let krb = Krb5Conf::parse(krb_text).unwrap();
        assert_eq!(
            kdc.plugin_relations("hostrealm"),
            Krb5Conf::parse(kdc_text)
                .unwrap()
                .plugin_relations("hostrealm")
        );
        let rel = kdc_plugin_relations(&kdc, &krb, "hostrealm");
        assert_eq!(rel.disable, Some(list(&["dns", "domain"])));
        assert_eq!(rel.enable_only, Some(list(&["profile"])));
        assert_eq!(filter_plugin_modules(&rel, HOST), list(&["profile"]));
    }

    #[test]
    fn a_final_kdc_relation_blocks_krb5_conf_disable_only() {
        let kdc =
            KdcConf::parse("[plugins]\n hostrealm = {\n  enable_only* = profile\n }\n").unwrap();
        let krb = Krb5Conf::parse(
            "[plugins]\n hostrealm = {\n  enable_only = dns\n  disable = registry\n }\n",
        )
        .unwrap();
        let rel = kdc_plugin_relations(&kdc, &krb, "hostrealm");
        assert_eq!(rel.enable_only, Some(list(&["profile"])));
        assert_eq!(rel.disable, Some(list(&["registry"])));
    }

    #[test]
    fn realms_beside_plugins_still_parse_and_a_star_is_only_for_plugins() {
        let conf = Krb5Conf::parse(
            "[plugins]\n hostrealm = {\n  disable = dns\n }\n[realms]\n R = {\n  kdc = kdc.example\n }\n",
        )
        .unwrap();
        assert!(conf.kdcs.contains_key("R"));
        assert_eq!(
            kept("[plugins]\n hostrealm = {\n  disable = dns\n }\n", HOST),
            list(&["registry", "profile", "domain"])
        );
        let starred = Krb5Conf::parse("[libdefaults]*\ndefault_realm = X\n").unwrap();
        assert!(starred.default_realm.is_none());
        let kdc = KdcConf::parse(
            "[plugins]\n hostrealm = {\n  disable = dns\n }\n[realms]\n R = {\n  max_life = 1h\n }\n",
        )
        .unwrap();
        assert_eq!(kdc.realm, "R");
        assert_eq!(
            kdc.plugin_relations("hostrealm").disable,
            Some(list(&["dns"]))
        );
    }

    #[test]
    fn mit_hostrealm_settle_matches_the_live_oracle() {
        // Built-ins in MIT hostrealm registration order. Each list is the reader's view of
        // one stanza settled live against MIT (disable, then enable_only).
        let base = "\
[libdefaults]
    default_realm = PROF.REALM
    dns_lookup_realm = false
[domain_realm]
    host.mapped.example = MAPPED.REALM
";
        let with = |plugins: &str| format!("{base}{plugins}");
        assert_eq!(kept(base, HOST), list(HOST));
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  disable = dns\n  enable_only = profile\n }\n"),
                HOST
            ),
            list(&["profile"])
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  disable = profile\n }\n"),
                HOST
            ),
            list(&["registry", "dns", "domain"])
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  enable_only = domain\n }\n"),
                HOST
            ),
            list(&["domain"])
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  disable = Profile\n }\n"),
                HOST
            ),
            list(HOST)
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  disable = nosuch\n }\n"),
                HOST
            ),
            list(HOST)
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  module = ignore:this.so\n }\n"),
                HOST
            ),
            list(HOST)
        );
        assert_eq!(
            kept(
                &with(
                    "[plugins]\n hostrealm = {\n  disable = profile\n  enable_only = profile\n }\n"
                ),
                HOST
            ),
            list(&[])
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  disable = profile extra\n }\n"),
                HOST
            ),
            list(HOST)
        );
        assert_eq!(
            kept(
                &with("[plugins]\n hostrealm = {\n  enable_only = profile domain\n }\n"),
                HOST
            ),
            list(&[])
        );
        assert_eq!(
            kept(
                &with(
                    "[plugins]\n hostrealm = {\n  disable = registry\n  disable = dns\n  enable_only = profile\n  enable_only = domain\n }\n"
                ),
                HOST
            ),
            list(&["profile", "domain"])
        );
        let krb = with("[plugins]\n hostrealm = {\n  enable_only = profile\n }\n");
        let merged = kdc_plugin_relations(
            &KdcConf::parse("[plugins]\n hostrealm = {\n  disable = dns\n }\n").unwrap(),
            &Krb5Conf::parse(&krb).unwrap(),
            "hostrealm",
        );
        assert_eq!(filter_plugin_modules(&merged, HOST), list(&["profile"]));
        let blocked = kdc_plugin_relations(
            &KdcConf::parse("[plugins]\n hostrealm = {\n  enable_only* = domain\n }\n").unwrap(),
            &Krb5Conf::parse(&krb).unwrap(),
            "hostrealm",
        );
        assert_eq!(filter_plugin_modules(&blocked, HOST), list(&["domain"]));
        let section = kdc_plugin_relations(
            &KdcConf::parse("[plugins]*\n hostrealm = {\n  disable = dns\n }\n").unwrap(),
            &Krb5Conf::parse(
                "[libdefaults]\n default_realm = PROF.REALM\n[plugins]\n hostrealm = {\n  disable = profile\n }\n",
            )
            .unwrap(),
            "hostrealm",
        );
        assert_eq!(
            filter_plugin_modules(&section, HOST),
            list(&["registry", "profile", "domain"])
        );
    }

    #[test]
    fn a_quoted_brace_is_a_value_and_a_quote_escape_is_kept() {
        let text = "[plugins]\n hostrealm = {\n  disable = \"{\"\n  enable_only = \"a\\tb\"\n }\n";
        let rel = host(text);
        assert_eq!(rel.disable, Some(vec!["{".to_string()]));
        assert_eq!(rel.enable_only, Some(vec!["a\tb".to_string()]));
    }
}
