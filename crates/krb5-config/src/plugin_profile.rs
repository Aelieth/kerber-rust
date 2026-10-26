use std::collections::BTreeMap;

use super::profile::{c_isspace, relation_value};
use super::{KdcConf, Krb5Conf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginRelations {
    pub disable: Option<Vec<String>>,
    pub enable_only: Option<Vec<String>>,
}

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

// MIT: `remove_disabled_modules` (lib/krb5/krb/plugin.c:255-269)
// named modules are dropped and the rest keep their order.
// MIT: `filter_enabled_modules` (lib/krb5/krb/plugin.c:271-299)
// each enabled name takes the first remaining match.
// MIT: `k5_plugin_load_all` (lib/krb5/krb/plugin.c)
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

#[must_use]
pub fn kdc_plugin_relations(kdc: &KdcConf, krb5: &Krb5Conf, interface: &str) -> PluginRelations {
    kdc.plugins.followed_by(&krb5.plugins).relations(interface)
}

impl Krb5Conf {
    #[must_use]
    pub fn plugin_relations(&self, interface: &str) -> PluginRelations {
        self.plugins.relations(interface)
    }
}

impl KdcConf {
    #[must_use]
    pub fn plugin_relations(&self, interface: &str) -> PluginRelations {
        self.plugins.relations(interface)
    }
}

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

pub(crate) enum PluginLine {
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

pub(crate) fn parse_plugin_line(line: &str) -> Option<PluginLine> {
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
