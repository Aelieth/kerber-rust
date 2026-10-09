//! Password-quality modules (`server_misc.c` `init_pwqual`, `pwqual.c`).
//!
//! Built-ins are `dict`, `empty`, `hesiod` and `princ`, in that order.
//! `[plugins] pwqual` `disable` then `enable_only` select them and any
//! embedder module from [`register_pwqual`]. The first error stops the walk.

use std::sync::{Arc, Mutex};

use krb5_log::klog::Severity;
use krb5_types::PrincipalName;

use super::PrincipalStore;
use super::password::{PWQUAL_DICT, PWQUAL_EMPTY, PWQUAL_PRINC};
use super::pwqual_dict::PwqualDict;
use crate::error::Error;

/// One password-quality module.
///
/// MIT `krb5_pwqual_vtable` (`include/krb5/pwqual_plugin.h`): `check` sees the password, the
/// policy name (NULL when the principal has none) and the principal.
pub trait Pwqual: Send + Sync {
    /// Module name for `[plugins] pwqual`.
    fn name(&self) -> &'static str;

    /// The built-in `dict` module reads the realm dictionary. Embedder modules leave this false.
    fn checks_dictionary(&self) -> bool {
        false
    }

    /// Reject `password`, or allow it.
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`] when this module rejects the password. The walk stops there.
    fn check(
        &self,
        password: &[u8],
        policy_name: Option<&str>,
        realm: &str,
        name: &PrincipalName,
    ) -> Result<(), Error>;
}

enum Kind {
    Dict,
    Empty,
    Hesiod,
    Princ,
}

struct Builtin {
    name: &'static str,
    kind: Kind,
}

impl Pwqual for Builtin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn checks_dictionary(&self) -> bool {
        matches!(self.kind, Kind::Dict)
    }

    fn check(
        &self,
        password: &[u8],
        policy_name: Option<&str>,
        realm: &str,
        name: &PrincipalName,
    ) -> Result<(), Error> {
        match self.kind {
            Kind::Dict | Kind::Hesiod => Ok(()),
            Kind::Empty => empty_check(password),
            Kind::Princ => princ_check(password, policy_name, realm, name),
        }
    }
}

/// MIT `dict_check` (`pwqual_dict.c:215-230`): no policy, or no dictionary, allows the password.
fn dict_check(
    password: &[u8],
    policy_name: Option<&str>,
    dict: Option<&PwqualDict>,
) -> Result<(), Error> {
    if policy_name.is_none() {
        return Ok(());
    }
    if dict.is_some_and(|words| words.contains(password)) {
        return Err(Error::PasswordPolicy(PWQUAL_DICT.into()));
    }
    Ok(())
}

/// MIT `empty_check` (`pwqual_empty.c:38-44`): an empty password is refused with or without a policy.
fn empty_check(password: &[u8]) -> Result<(), Error> {
    if password.is_empty() {
        return Err(Error::PasswordPolicy(PWQUAL_EMPTY.into()));
    }
    Ok(())
}

/// MIT `princ_check` (`pwqual_princ.c:40-58`): with a policy, the realm matches first, then each
/// component. The realm uses the dictionary text. A component sets its own text.
fn princ_check(
    password: &[u8],
    policy_name: Option<&str>,
    realm: &str,
    name: &PrincipalName,
) -> Result<(), Error> {
    if policy_name.is_none() {
        return Ok(());
    }
    if super::pwqual_dict::eq_ignore_case(realm.as_bytes(), password) {
        return Err(Error::PasswordPolicy(PWQUAL_DICT.into()));
    }
    if name
        .name_string
        .iter()
        .any(|part| super::pwqual_dict::eq_ignore_case(part.as_bytes(), password))
    {
        return Err(Error::PasswordPolicy(PWQUAL_PRINC.into()));
    }
    Ok(())
}

fn builtin(name: &'static str, kind: Kind) -> Arc<dyn Pwqual> {
    Arc::new(Builtin { name, kind })
}

/// MIT `init_pwqual` (`server_misc.c:44-57`): `dict`, `empty`, `hesiod`, `princ`.
///
/// `hesiod` is compiled without Hesiod, so its check allows every password (`pwqual_hesiod.c`
/// with `HESIOD` unset).
fn builtins() -> Vec<Arc<dyn Pwqual>> {
    vec![
        builtin("dict", Kind::Dict),
        builtin("empty", Kind::Empty),
        builtin("hesiod", Kind::Hesiod),
        builtin("princ", Kind::Princ),
    ]
}

static EXTRA: Mutex<Vec<Arc<dyn Pwqual>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD: std::cell::RefCell<Option<Vec<Arc<dyn Pwqual>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Register one named module after the built-ins, for every thread that has not set its own list.
pub fn register_pwqual(module: Arc<dyn Pwqual>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

/// Install this thread's modules in place of the built-ins and [`register_pwqual`] (tests).
///
/// The list is still filtered by `[plugins] pwqual`. An empty list checks nothing.
pub fn set_thread_pwqual(modules: Vec<Arc<dyn Pwqual>>) {
    THREAD.with(|slot| *slot.borrow_mut() = Some(modules));
}

/// Drop this thread's modules so it uses the built-ins.
pub fn clear_thread_pwqual() {
    THREAD.with(|slot| *slot.borrow_mut() = None);
}

fn candidates() -> Vec<Arc<dyn Pwqual>> {
    if let Some(modules) = THREAD.with(|slot| slot.borrow().clone()) {
        return modules;
    }
    let mut modules = builtins();
    modules.extend(
        EXTRA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    );
    modules
}

fn selected(store: &PrincipalStore) -> Vec<Arc<dyn Pwqual>> {
    let modules = candidates();
    let names: Vec<&str> = modules.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(&store.policy.pwqual, &names);
    let mut left = modules;
    let mut out = Vec::new();
    for want in kept {
        if let Some(index) = left.iter().position(|module| module.name() == want) {
            out.push(left.remove(index));
        }
    }
    out
}

/// MIT `passwd_check` (`server_misc.c:110-135`): each loaded module, and the first error returns.
///
/// `princ_realm` is the principal's realm, which may differ from the store realm. A
/// `PasswordPolicy` error is logged by `module_refusal` and then returned.
pub(super) fn run(
    store: &PrincipalStore,
    name: &PrincipalName,
    princ_realm: &str,
    policy_name: Option<&str>,
    password: &[u8],
    note: &mut dyn FnMut(Severity, &str),
) -> Result<(), Error> {
    let dict = store.pwqual_dict.as_deref();
    let princ = name.unparse_with_realm(princ_realm);
    for module in selected(store) {
        let result = if module.checks_dictionary() {
            dict_check(password, policy_name, dict)
        } else {
            module.check(password, policy_name, princ_realm, name)
        };
        match result {
            Ok(()) => {}
            Err(Error::PasswordPolicy(text)) => {
                return Err(super::password::module_refusal(
                    note,
                    module.name(),
                    &princ,
                    &text,
                ));
            }
            Err(other) => return Err(other),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct Flag {
        name: &'static str,
        reject: bool,
        hits: AtomicU64,
    }

    impl Pwqual for Flag {
        fn name(&self) -> &'static str {
            self.name
        }

        fn check(
            &self,
            _password: &[u8],
            _policy_name: Option<&str>,
            _realm: &str,
            _name: &PrincipalName,
        ) -> Result<(), Error> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            if self.reject {
                return Err(Error::PasswordPolicy("banned".into()));
            }
            Ok(())
        }
    }

    struct ClearThread;

    impl Drop for ClearThread {
        fn drop(&mut self) {
            clear_thread_pwqual();
        }
    }

    fn user() -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pwq"])
    }

    #[test]
    fn built_ins_load_in_mit_order() {
        let (store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let names: Vec<&str> = selected(&store)
            .iter()
            .map(|module| module.name())
            .collect();
        assert_eq!(names, ["dict", "empty", "hesiod", "princ"]);
    }

    #[test]
    fn disable_empty_allows_an_empty_password() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        store.policy.pwqual = krb5_config::Krb5Conf::parse(
            "[plugins]\n    pwqual = {\n        disable = empty\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("pwqual");
        store
            .check_new_password(&user(), None, b"")
            .expect("empty is not loaded");
    }

    #[test]
    fn enable_only_of_an_unknown_pwqual_keeps_nothing() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        store.policy.pwqual = krb5_config::Krb5Conf::parse(
            "[plugins]\n    pwqual = {\n        enable_only = nosuch\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("pwqual");
        assert!(selected(&store).is_empty());
        store
            .check_new_password(&user(), None, b"")
            .expect("no module rejects");
    }

    #[test]
    fn the_first_module_error_stops_the_walk() {
        let (store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let bad = Arc::new(Flag {
            name: "bad",
            reject: true,
            hits: AtomicU64::new(0),
        });
        let next = Arc::new(Flag {
            name: "next",
            reject: false,
            hits: AtomicU64::new(0),
        });
        set_thread_pwqual(vec![
            Arc::clone(&bad) as Arc<dyn Pwqual>,
            Arc::clone(&next) as Arc<dyn Pwqual>,
        ]);
        let _guard = ClearThread;
        let err = store
            .check_new_password(&user(), None, b"secret")
            .expect_err("banned");
        assert!(matches!(err, Error::PasswordPolicy(text) if text == "banned"));
        assert_eq!(bad.hits.load(Ordering::SeqCst), 1);
        assert_eq!(next.hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn kdc_conf_and_krb5_conf_pwqual_disables_both_apply() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let kdc = krb5_config::KdcConf::parse(
            "[plugins]\n    pwqual = {\n        disable = dict\n    }\n",
        )
        .expect("kdc.conf");
        let krb5 = krb5_config::Krb5Conf::parse(
            "[plugins]\n    pwqual = {\n        disable = empty\n    }\n",
        )
        .expect("krb5.conf");
        store.apply_pwqual_plugins(Some(&kdc), Some(&krb5));
        let names: Vec<&str> = selected(&store)
            .iter()
            .map(|module| module.name())
            .collect();
        assert_eq!(names, ["hesiod", "princ"]);
        store
            .check_new_password(&user(), None, b"")
            .expect("empty is disabled");
    }
}
