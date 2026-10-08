//! Client preauth modules selected by `[plugins] clpreauth`.
//!
//! MIT `k5_init_preauth_context` (`lib/krb5/krb/preauth2.c:120-204`): registers the built-in
//! clpreauth modules in the order `pkinit`, `spake`, `encrypted_challenge`, `encrypted_timestamp`.
//! MIT `k5_plugin_load_all` (`lib/krb5/krb/plugin.c:421-455`): applies `disable` and `enable_only`.
//! A module whose init fails, or a dynamic module that does not load, is not kept.
//! MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:648-728`): answers only a pa-type a loaded module serves.
//! `sam2` and `otp` are not implemented, so they are absent the way a module that failed to load
//! is absent. `module` is not read. Embedder modules follow the built-ins; an earlier name wins a
//! duplicate, and the first loaded module to claim a pa-type keeps it.

use std::sync::{Arc, Mutex};

use krb5_crypto::SPAKE_DEFAULT_GROUPS_CLIENT;
use krb5_types::PaData;

use crate::error::Error;

/// One clpreauth module an embedder registers by name.
///
/// MIT `krb5_clpreauth_vtable` (`include/krb5/clpreauth_plugin.h`): `name`, `pa_type_list`,
/// `flags` (`PA_REAL`) and `process`. Built-in mechanisms stay in the AS exchange; this trait is
/// how an embedder adds a named module the same reader selects.
pub trait ClPreauth: Send + Sync {
    /// MIT's module name, the string `disable` and `enable_only` match.
    fn name(&self) -> &'static str;

    /// Pa-types this module serves. A type already claimed by an earlier loaded module is a
    /// conflict and this module is not kept.
    ///
    /// MIT `k5_init_preauth_context` (`lib/krb5/krb/preauth2.c:171-181`): the first module to
    /// list a pa-type keeps it.
    fn pa_types(&self) -> &'static [i32];

    /// Whether `pa_type` is a real mechanism (`PA_REAL`). The default is real, which is MIT's
    /// when `flags` is unset.
    ///
    /// MIT `clpreauth_is_real` (`lib/krb5/krb/preauth2.c:322-328`): a module with no `flags`
    /// function is real for every type it lists.
    fn real(&self, _pa_type: i32) -> bool {
        true
    }

    /// Answer one input pa-data element. `Ok(None)` declines; `Ok(Some(out))` is the padata the
    /// next AS-REQ carries after the cookie.
    ///
    /// # Errors
    ///
    /// A module failure. The exchange does not try another mechanism after it.
    ///
    /// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:679-686`): calls the module's `process`
    /// and keeps the padata it returns.
    fn process(&self, input: &PaData) -> Result<Option<Vec<PaData>>, Error>;
}

enum Kind {
    Pkinit,
    Spake,
    EncChallenge,
    EncTs,
    Embedder(Arc<dyn ClPreauth>),
}

struct Slot {
    name: &'static str,
    pa_types: Vec<i32>,
    kind: Kind,
}

/// Which loaded module serves a pa-type.
pub(crate) enum Owner {
    /// The built-in `pkinit` module.
    Pkinit,
    /// The built-in `spake` module.
    Spake,
    /// The built-in `encrypted_challenge` module.
    EncChallenge,
    /// The built-in `encrypted_timestamp` module.
    EncTs,
    /// An embedder module.
    Embedder(Arc<dyn ClPreauth>),
}

static EXTRA: Mutex<Vec<Arc<dyn ClPreauth>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD_EXTRA: std::cell::RefCell<Option<Vec<Arc<dyn ClPreauth>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Register `module` for every thread that has not set its own list.
pub fn register_clpreauth(module: Arc<dyn ClPreauth>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

/// Install this thread's embedder modules, used in place of the process-wide ones.
pub fn set_thread_clpreauth(modules: Vec<Arc<dyn ClPreauth>>) {
    THREAD_EXTRA.with(|slot| *slot.borrow_mut() = Some(modules));
}

/// Drop this thread's embedder modules so it uses the process-wide ones.
pub fn clear_thread_clpreauth() {
    THREAD_EXTRA.with(|slot| *slot.borrow_mut() = None);
}

fn extras() -> Vec<Arc<dyn ClPreauth>> {
    if let Some(modules) = THREAD_EXTRA.with(|slot| slot.borrow().clone()) {
        return modules;
    }
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// MIT `spake_init` (`plugins/preauth/spake/spake_client.c:62-73`): no permitted group means the
/// module is not kept.
fn spake_initialized() -> bool {
    let configured = krb5_config::load_krb5_conf().and_then(|conf| conf.spake_preauth_groups);
    let words = configured.as_ref().map(|groups| groups.join(" "));
    !krb5_crypto::spake_parse_groups(words.as_deref().unwrap_or(SPAKE_DEFAULT_GROUPS_CLIENT))
        .is_empty()
}

fn push_unique(slots: &mut Vec<Slot>, slot: Slot) {
    if slots.iter().any(|have| have.name == slot.name) {
        return;
    }
    slots.push(slot);
}

fn candidates() -> Vec<Slot> {
    let mut slots = Vec::new();
    push_unique(
        &mut slots,
        Slot {
            name: "pkinit",
            pa_types: vec![krb5_types::pa::PK_AS_REQ],
            kind: Kind::Pkinit,
        },
    );
    if spake_initialized() {
        push_unique(
            &mut slots,
            Slot {
                name: "spake",
                pa_types: vec![krb5_types::pa::SPAKE],
                kind: Kind::Spake,
            },
        );
    }
    push_unique(
        &mut slots,
        Slot {
            name: "encrypted_challenge",
            pa_types: vec![krb5_types::pa::ENCRYPTED_CHALLENGE],
            kind: Kind::EncChallenge,
        },
    );
    push_unique(
        &mut slots,
        Slot {
            name: "encrypted_timestamp",
            pa_types: vec![krb5_types::pa::ENC_TIMESTAMP],
            kind: Kind::EncTs,
        },
    );
    for module in extras() {
        push_unique(
            &mut slots,
            Slot {
                name: module.name(),
                pa_types: module.pa_types().to_vec(),
                kind: Kind::Embedder(module),
            },
        );
    }
    slots
}

fn selected() -> Vec<Slot> {
    let mut slots = candidates();
    let names: Vec<&str> = slots.iter().map(|slot| slot.name).collect();
    let relations = krb5_config::load_krb5_conf()
        .map(|conf| conf.plugin_relations("clpreauth"))
        .unwrap_or_default();
    let kept = krb5_config::filter_plugin_modules(&relations, &names);
    let mut ordered = Vec::new();
    for want in kept {
        if let Some(index) = slots.iter().position(|slot| slot.name == want) {
            ordered.push(slots.remove(index));
        }
    }
    let mut claimed: Vec<i32> = Vec::new();
    ordered.retain(|slot| {
        if slot.pa_types.iter().any(|ty| claimed.contains(ty)) {
            return false;
        }
        claimed.extend(slot.pa_types.iter().copied());
        true
    });
    ordered
}

/// Whether `[plugins] clpreauth` left `name` loaded.
#[must_use]
pub(crate) fn loaded(name: &str) -> bool {
    selected().iter().any(|slot| slot.name == name)
}

/// The loaded module that owns `pa_type`, if one does.
#[must_use]
pub(crate) fn owner_of(pa_type: i32) -> Option<Owner> {
    let slot = selected()
        .into_iter()
        .find(|slot| slot.pa_types.contains(&pa_type))?;
    Some(match slot.kind {
        Kind::Pkinit => Owner::Pkinit,
        Kind::Spake => Owner::Spake,
        Kind::EncChallenge => Owner::EncChallenge,
        Kind::EncTs => Owner::EncTs,
        Kind::Embedder(module) => Owner::Embedder(module),
    })
}

/// Names left loaded, in MIT's order after `enable_only`.
#[cfg(test)]
#[must_use]
fn selected_names() -> Vec<&'static str> {
    selected().iter().map(|slot| slot.name).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ClPreauth, clear_thread_clpreauth, loaded, owner_of, selected_names, set_thread_clpreauth,
    };
    use std::sync::Arc;

    use crate::error::Error;
    use krb5_types::{PaData, pa};

    const WIDGET: i32 = 211;

    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            clear_thread_clpreauth();
        }
    }

    struct Widget;

    impl ClPreauth for Widget {
        fn name(&self) -> &'static str {
            "widget"
        }
        fn pa_types(&self) -> &'static [i32] {
            &[WIDGET]
        }
        fn process(&self, _input: &PaData) -> Result<Option<Vec<PaData>>, Error> {
            Ok(Some(vec![PaData {
                padata_type: WIDGET,
                padata_value: b"widget-answer".to_vec().into(),
            }]))
        }
    }

    fn pin(extra: &str) {
        krb5_config::isolate_test_krb5();
        let dir = krb5_testkit::scratch_dir("pg3-clpreauth-unit");
        let path = dir.join("krb5.conf");
        std::fs::write(
            &path,
            format!(
                "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n{extra}"
            ),
        )
        .unwrap();
        krb5_config::set_test_krb5_paths(Some(vec![path]));
    }

    #[test]
    fn disable_drops_encrypted_timestamp_and_keeps_the_others() {
        pin(
            "[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n        disable = nosuch\n    }\n",
        );
        let names = selected_names();
        assert!(
            !names.contains(&"encrypted_timestamp"),
            "disable drops encrypted_timestamp: {names:?}"
        );
        assert!(
            names.contains(&"spake")
                && names.contains(&"encrypted_challenge")
                && names.contains(&"pkinit"),
            "SPAKE, encrypted_challenge and pkinit stay: {names:?}"
        );
        assert!(matches!(
            owner_of(pa::ENCRYPTED_CHALLENGE),
            Some(super::Owner::EncChallenge)
        ));
        assert!(owner_of(pa::ENC_TIMESTAMP).is_none());
        assert!(loaded("spake"));
        assert!(!loaded("otp"));
    }

    #[test]
    fn enable_only_keeps_named_modules_in_that_order() {
        pin(
            "[plugins]\n    clpreauth = {\n        enable_only = encrypted_timestamp\n        enable_only = spake\n    }\n",
        );
        assert_eq!(
            selected_names(),
            vec!["encrypted_timestamp", "spake"],
            "enable_only order"
        );
    }

    #[test]
    fn an_unknown_enable_only_name_keeps_no_module() {
        pin("[plugins]\n    clpreauth = {\n        enable_only = otp\n    }\n");
        assert!(
            selected_names().is_empty(),
            "otp is not loaded, so enable_only keeps nothing: {:?}",
            selected_names()
        );
        pin("[plugins]\n    clpreauth = {\n        disable = otp\n        disable = sam2\n    }\n");
        assert!(
            loaded("encrypted_timestamp") && loaded("spake"),
            "disable of an absent name drops nothing"
        );
    }

    #[test]
    fn an_embedder_module_is_selected_and_dropped_by_name() {
        let _guard = Guard;
        set_thread_clpreauth(vec![Arc::new(Widget)]);
        pin("[plugins]\n    clpreauth = {\n        enable_only = widget\n    }\n");
        assert_eq!(selected_names(), vec!["widget"]);
        assert!(matches!(owner_of(WIDGET), Some(super::Owner::Embedder(_))));
        pin("[plugins]\n    clpreauth = {\n        disable = widget\n    }\n");
        let names = selected_names();
        assert!(
            !names.contains(&"widget"),
            "disable drops widget: {names:?}"
        );
        assert!(
            names.contains(&"encrypted_timestamp"),
            "built-ins stay: {names:?}"
        );
    }

    #[test]
    fn spake_is_absent_when_it_has_no_group() {
        pin("    spake_preauth_groups = nosuch\n");
        assert!(
            !loaded("spake"),
            "no permitted group means no SPAKE module: {:?}",
            selected_names()
        );
        assert!(loaded("encrypted_timestamp"));
    }

    struct TsThief;

    impl ClPreauth for TsThief {
        fn name(&self) -> &'static str {
            "ts_thief"
        }
        fn pa_types(&self) -> &'static [i32] {
            &[pa::ENC_TIMESTAMP, WIDGET]
        }
        fn process(&self, _input: &PaData) -> Result<Option<Vec<PaData>>, Error> {
            Ok(None)
        }
    }

    struct FakeTs;

    impl ClPreauth for FakeTs {
        fn name(&self) -> &'static str {
            "encrypted_timestamp"
        }
        fn pa_types(&self) -> &'static [i32] {
            &[WIDGET]
        }
        fn process(&self, _input: &PaData) -> Result<Option<Vec<PaData>>, Error> {
            Ok(None)
        }
    }

    #[test]
    fn an_earlier_module_keeps_a_shared_pa_type() {
        let _guard = Guard;
        set_thread_clpreauth(vec![Arc::new(TsThief), Arc::new(Widget)]);
        pin("");
        assert!(
            matches!(owner_of(pa::ENC_TIMESTAMP), Some(super::Owner::EncTs)),
            "the built-in keeps PA-ENC-TIMESTAMP"
        );
        assert!(
            !selected_names().contains(&"ts_thief"),
            "a module that lists a claimed type is not kept: {:?}",
            selected_names()
        );
        assert!(
            matches!(owner_of(WIDGET), Some(super::Owner::Embedder(_))),
            "widget still owns its own type"
        );
    }

    #[test]
    fn an_earlier_name_wins_a_duplicate() {
        let _guard = Guard;
        set_thread_clpreauth(vec![Arc::new(FakeTs)]);
        pin("");
        assert!(
            matches!(owner_of(pa::ENC_TIMESTAMP), Some(super::Owner::EncTs)),
            "the built-in name wins"
        );
        assert!(
            owner_of(WIDGET).is_none(),
            "the later duplicate name is not kept"
        );
    }

    #[test]
    fn module_is_not_applied() {
        pin("[plugins]\n    clpreauth = {\n        module = widget:widget.so\n    }\n");
        assert!(loaded("encrypted_timestamp") && loaded("spake") && loaded("pkinit"));
        assert!(!loaded("widget"));
    }
}
