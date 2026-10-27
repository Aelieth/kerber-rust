// MIT: `k5_init_preauth_context` (lib/krb5/krb/preauth2.c:120-204)
// MIT: `k5_plugin_load_all` (lib/krb5/krb/plugin.c:421-455)
//! A module whose init fails, or a dynamic one that will not load, is not kept.
// MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:648-728)
//! Only a pa-type a loaded module serves is answered.
use std::sync::{Arc, Mutex};

use krb5_config::Krb5Conf;
use krb5_crypto::SPAKE_DEFAULT_GROUPS_CLIENT;
use krb5_types::PaData;

use crate::error::Error;

pub trait ClPreauth: Send + Sync {
    fn name(&self) -> &'static str;

    // MIT: `k5_init_preauth_context` (lib/krb5/krb/preauth2.c:171-181)
    fn pa_types(&self) -> &'static [i32];

    // MIT: `clpreauth_is_real` (lib/krb5/krb/preauth2.c:322-328)
    fn real(&self, _pa_type: i32) -> bool {
        true
    }

    /// `Ok(None)` declines; `Some` is the next AS-REQ's padata, after the cookie.
    /// A failure stops the exchange; no other mechanism is tried.
    fn process(&self, input: &PaData) -> Result<Option<Vec<PaData>>, Error>;
}

enum Kind {
    Pkinit,
    Spake,
    EncChallenge,
    EncTs,
    Otp,
    Embedder(Arc<dyn ClPreauth>),
}

struct Slot {
    name: &'static str,
    pa_types: Vec<i32>,
    kind: Kind,
}

pub(crate) enum Owner {
    Pkinit,
    Spake,
    EncChallenge,
    EncTs,
    Otp,
    Embedder(Arc<dyn ClPreauth>),
}

static EXTRA: Mutex<Vec<Arc<dyn ClPreauth>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD_EXTRA: std::cell::RefCell<Option<Vec<Arc<dyn ClPreauth>>>> =
        const { std::cell::RefCell::new(None) };
}

pub fn register_clpreauth(module: Arc<dyn ClPreauth>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

pub fn set_thread_clpreauth(modules: Vec<Arc<dyn ClPreauth>>) {
    THREAD_EXTRA.with(|slot| *slot.borrow_mut() = Some(modules));
}

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

// MIT: `spake_init` (plugins/preauth/spake/spake_client.c:62-73)
fn spake_initialized(profile: &Krb5Conf) -> bool {
    let words = profile
        .spake_preauth_groups
        .as_ref()
        .map(|groups| groups.join(" "));
    !krb5_crypto::spake_parse_groups(words.as_deref().unwrap_or(SPAKE_DEFAULT_GROUPS_CLIENT))
        .is_empty()
}

fn push_unique(slots: &mut Vec<Slot>, slot: Slot) {
    if slots.iter().any(|have| have.name == slot.name) {
        return;
    }
    slots.push(slot);
}

fn candidates(profile: &Krb5Conf) -> Vec<Slot> {
    let mut slots = Vec::new();
    push_unique(
        &mut slots,
        Slot {
            name: "pkinit",
            pa_types: vec![krb5_types::pa::PK_AS_REQ],
            kind: Kind::Pkinit,
        },
    );
    if spake_initialized(profile) {
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
    push_unique(
        &mut slots,
        Slot {
            name: "otp",
            pa_types: vec![krb5_types::pa::OTP_CHALLENGE],
            kind: Kind::Otp,
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

fn selected(profile: &Krb5Conf) -> Vec<Slot> {
    let mut slots = candidates(profile);
    let names: Vec<&str> = slots.iter().map(|slot| slot.name).collect();
    let relations = profile.plugin_relations("clpreauth");
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

#[must_use]
pub fn loaded(profile: &Krb5Conf, name: &str) -> bool {
    selected(profile).iter().any(|slot| slot.name == name)
}

#[must_use]
pub(crate) fn owner_of(profile: &Krb5Conf, pa_type: i32) -> Option<Owner> {
    let slot = selected(profile)
        .into_iter()
        .find(|slot| slot.pa_types.contains(&pa_type))?;
    Some(match slot.kind {
        Kind::Pkinit => Owner::Pkinit,
        Kind::Spake => Owner::Spake,
        Kind::EncChallenge => Owner::EncChallenge,
        Kind::EncTs => Owner::EncTs,
        Kind::Otp => Owner::Otp,
        Kind::Embedder(module) => Owner::Embedder(module),
    })
}

#[cfg(test)]
#[must_use]
fn selected_names(profile: &Krb5Conf) -> Vec<&'static str> {
    selected(profile).iter().map(|slot| slot.name).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ClPreauth, Krb5Conf, clear_thread_clpreauth, loaded, owner_of, selected_names,
        set_thread_clpreauth,
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

    fn pin(extra: &str) -> Krb5Conf {
        Krb5Conf::parse(&format!(
            "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn disable_drops_encrypted_timestamp_and_keeps_the_others() {
        let profile = pin(
            "[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n        disable = nosuch\n    }\n",
        );
        let names = selected_names(&profile);
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
            owner_of(&profile, pa::ENCRYPTED_CHALLENGE),
            Some(super::Owner::EncChallenge)
        ));
        assert!(owner_of(&profile, pa::ENC_TIMESTAMP).is_none());
        assert!(loaded(&profile, "spake"));
        assert!(
            loaded(&profile, "otp"),
            "disable of encrypted_timestamp leaves otp"
        );
    }

    #[test]
    fn enable_only_keeps_named_modules_in_that_order() {
        let profile = pin(
            "[plugins]\n    clpreauth = {\n        enable_only = encrypted_timestamp\n        enable_only = spake\n    }\n",
        );
        assert_eq!(
            selected_names(&profile),
            vec!["encrypted_timestamp", "spake"],
            "enable_only order"
        );
    }

    #[test]
    fn an_unknown_enable_only_name_keeps_no_module() {
        let profile = pin("[plugins]\n    clpreauth = {\n        enable_only = nosuch\n    }\n");
        assert!(
            selected_names(&profile).is_empty(),
            "nosuch is not a module, so enable_only keeps nothing: {:?}",
            selected_names(&profile)
        );
        let profile = pin(
            "[plugins]\n    clpreauth = {\n        disable = nosuch\n        disable = sam2\n    }\n",
        );
        assert!(
            loaded(&profile, "encrypted_timestamp") && loaded(&profile, "spake"),
            "disable of an absent name drops nothing"
        );
    }

    #[test]
    fn otp_registers_after_encrypted_timestamp_and_owns_141() {
        let profile = pin("");
        let names = selected_names(&profile);
        let at = names
            .iter()
            .position(|n| *n == "encrypted_timestamp")
            .unwrap();
        assert_eq!(
            names.get(at + 1),
            Some(&"otp"),
            "MIT registers otp after encrypted_timestamp: {names:?}"
        );
        assert!(matches!(
            owner_of(&profile, pa::OTP_CHALLENGE),
            Some(super::Owner::Otp)
        ));
    }

    #[test]
    fn enable_only_otp_keeps_only_otp_and_disable_drops_it() {
        let profile = pin("[plugins]\n    clpreauth = {\n        enable_only = otp\n    }\n");
        assert_eq!(selected_names(&profile), vec!["otp"]);
        assert!(owner_of(&profile, pa::ENC_TIMESTAMP).is_none());
        let profile = pin("[plugins]\n    clpreauth = {\n        disable = otp\n    }\n");
        assert!(!loaded(&profile, "otp") && loaded(&profile, "encrypted_timestamp"));
        assert!(owner_of(&profile, pa::OTP_CHALLENGE).is_none());
    }

    struct OtpThief;

    impl ClPreauth for OtpThief {
        fn name(&self) -> &'static str {
            "otp_thief"
        }
        fn pa_types(&self) -> &'static [i32] {
            &[pa::OTP_CHALLENGE]
        }
        fn process(&self, _input: &PaData) -> Result<Option<Vec<PaData>>, Error> {
            Ok(None)
        }
    }

    #[test]
    fn an_embedder_cannot_take_141_from_the_built_in_otp() {
        let _guard = Guard;
        set_thread_clpreauth(vec![Arc::new(OtpThief)]);
        let profile = pin("");
        assert!(matches!(
            owner_of(&profile, pa::OTP_CHALLENGE),
            Some(super::Owner::Otp)
        ));
        assert!(!loaded(&profile, "otp_thief"));
    }

    #[test]
    fn an_embedder_module_is_selected_and_dropped_by_name() {
        let _guard = Guard;
        set_thread_clpreauth(vec![Arc::new(Widget)]);
        let profile = pin("[plugins]\n    clpreauth = {\n        enable_only = widget\n    }\n");
        assert_eq!(selected_names(&profile), vec!["widget"]);
        assert!(matches!(
            owner_of(&profile, WIDGET),
            Some(super::Owner::Embedder(_))
        ));
        let profile = pin("[plugins]\n    clpreauth = {\n        disable = widget\n    }\n");
        let names = selected_names(&profile);
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
        let profile = pin("    spake_preauth_groups = nosuch\n");
        assert!(
            !loaded(&profile, "spake"),
            "no permitted group means no SPAKE module: {:?}",
            selected_names(&profile)
        );
        assert!(loaded(&profile, "encrypted_timestamp"));
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
        let profile = pin("");
        assert!(
            matches!(
                owner_of(&profile, pa::ENC_TIMESTAMP),
                Some(super::Owner::EncTs)
            ),
            "the built-in keeps PA-ENC-TIMESTAMP"
        );
        assert!(
            !selected_names(&profile).contains(&"ts_thief"),
            "a module that lists a claimed type is not kept: {:?}",
            selected_names(&profile)
        );
        assert!(
            matches!(owner_of(&profile, WIDGET), Some(super::Owner::Embedder(_))),
            "widget still owns its own type"
        );
    }

    #[test]
    fn an_earlier_name_wins_a_duplicate() {
        let _guard = Guard;
        set_thread_clpreauth(vec![Arc::new(FakeTs)]);
        let profile = pin("");
        assert!(
            matches!(
                owner_of(&profile, pa::ENC_TIMESTAMP),
                Some(super::Owner::EncTs)
            ),
            "the built-in name wins"
        );
        assert!(
            owner_of(&profile, WIDGET).is_none(),
            "the later duplicate name is not kept"
        );
    }

    #[test]
    fn module_is_not_applied() {
        let profile =
            pin("[plugins]\n    clpreauth = {\n        module = widget:widget.so\n    }\n");
        assert!(
            loaded(&profile, "encrypted_timestamp")
                && loaded(&profile, "spake")
                && loaded(&profile, "pkinit")
        );
        assert!(!loaded(&profile, "widget"));
    }
}
