//! kadm5 hook modules (`kadm5_hook.c`).
//!
//! There is no built-in module. `[plugins] kadm5_hook` `disable` then
//! `enable_only` select embedder modules from [`register_kadm5_hook`].
//! A precommit error stops the walk and the operation writes nothing.
//! A postcommit error is logged and the walk continues. The operation
//! still succeeds. `module` is not read. Nothing is loaded with `dlopen`.

use std::sync::{Arc, Mutex};

use krb5_crypto::EncryptionType;
use krb5_types::PrincipalName;

use super::PrincipalStore;
use crate::error::Error;

/// `KADM5_HOOK_STAGE_PRECOMMIT` is 0 and `KADM5_HOOK_STAGE_POSTCOMMIT` is 1.
///
/// MIT `kadm5_hook_plugin.h`: the stage passed to every hook method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookStage {
    /// Before the kdb write. The first error aborts the operation.
    Precommit = 0,
    /// After a successful write. An error is logged and the walk continues.
    Postcommit = 1,
}

/// One kadm5 hook module.
///
/// MIT `kadm5_hook_vftable_1` (`include/krb5/kadm5_hook_plugin.h`): a NULL
/// method is skipped. Each method here allows the operation until an
/// embedder overrides it.
pub trait Kadm5Hook: Send + Sync {
    /// Module name for `[plugins] kadm5_hook`.
    fn name(&self) -> &'static str;

    /// MIT `k5_kadm5_hook_chpass` (`kadm5_hook.c:142-151`): each module's chpass.
    ///
    /// MIT `kadm5_randkey_principal_3` (`svr_principal.c:1485-1495`): a random key passes no password.
    /// `keepold` is the count the caller passed (`krb5_boolean` is that unsigned value).
    ///
    /// # Errors
    ///
    /// A module error. [`HookStage::Precommit`] returns it and writes nothing.
    /// [`HookStage::Postcommit`] is logged and the operation still succeeds.
    fn chpass(
        &self,
        _stage: HookStage,
        _princ: &PrincipalName,
        _realm: &str,
        _keepold: u32,
        _password: Option<&[u8]>,
        _etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        Ok(())
    }

    /// MIT `k5_kadm5_hook_create` (`kadm5_hook.c:154-162`): each module's create.
    ///
    /// `password` is `None` for a random-key create. `mask` is the request's `KADM5_*` bits.
    ///
    /// # Errors
    ///
    /// A module error. [`HookStage::Precommit`] returns it and writes nothing.
    /// [`HookStage::Postcommit`] is logged and the operation still succeeds.
    fn create(
        &self,
        _stage: HookStage,
        _princ: &PrincipalName,
        _realm: &str,
        _mask: u32,
        _password: Option<&[u8]>,
        _etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        Ok(())
    }

    /// MIT `k5_kadm5_hook_modify` (`kadm5_hook.c:165-170`): each module's modify.
    ///
    /// `mask` is the `KADM5_*` bits this modify applies.
    ///
    /// # Errors
    ///
    /// A module error. [`HookStage::Precommit`] returns it and writes nothing.
    /// [`HookStage::Postcommit`] is logged and the operation still succeeds.
    fn modify(
        &self,
        _stage: HookStage,
        _princ: &PrincipalName,
        _realm: &str,
        _mask: u32,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// MIT `k5_kadm5_hook_rename` (`kadm5_hook.c:173-178`): each module's rename.
    ///
    /// # Errors
    ///
    /// A module error. [`HookStage::Precommit`] returns it and writes nothing.
    /// [`HookStage::Postcommit`] is logged and the operation still succeeds.
    fn rename(
        &self,
        _stage: HookStage,
        _old: &PrincipalName,
        _old_realm: &str,
        _new: &PrincipalName,
        _new_realm: &str,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// MIT `k5_kadm5_hook_remove` (`kadm5_hook.c:181-186`): each module's remove.
    ///
    /// # Errors
    ///
    /// A module error. [`HookStage::Precommit`] returns it and writes nothing.
    /// [`HookStage::Postcommit`] is logged and the operation still succeeds.
    fn remove(&self, _stage: HookStage, _princ: &PrincipalName, _realm: &str) -> Result<(), Error> {
        Ok(())
    }

    /// MIT `k5_kadm5_hook_alias` (`kadm5_hook.c:189-194`): each module's alias.
    ///
    /// # Errors
    ///
    /// A module error. [`HookStage::Precommit`] returns it and writes nothing.
    /// [`HookStage::Postcommit`] is logged and the operation still succeeds.
    fn alias(
        &self,
        _stage: HookStage,
        _alias: &PrincipalName,
        _alias_realm: &str,
        _target: &PrincipalName,
        _target_realm: &str,
    ) -> Result<(), Error> {
        Ok(())
    }
}

static EXTRA: Mutex<Vec<Arc<dyn Kadm5Hook>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD: std::cell::RefCell<Option<Vec<Arc<dyn Kadm5Hook>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Register one named module for every thread that has not set its own list.
pub fn register_kadm5_hook(module: Arc<dyn Kadm5Hook>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

/// Install this thread's modules in place of [`register_kadm5_hook`] (tests).
///
/// The list is still filtered by `[plugins] kadm5_hook`. An empty list runs nothing.
pub fn set_thread_kadm5_hook(modules: Vec<Arc<dyn Kadm5Hook>>) {
    THREAD.with(|slot| *slot.borrow_mut() = Some(modules));
}

/// Drop this thread's modules so it uses the process list.
pub fn clear_thread_kadm5_hook() {
    THREAD.with(|slot| *slot.borrow_mut() = None);
}

fn candidates() -> Vec<Arc<dyn Kadm5Hook>> {
    if let Some(modules) = THREAD.with(|slot| slot.borrow().clone()) {
        return modules;
    }
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn selected(store: &PrincipalStore) -> Vec<Arc<dyn Kadm5Hook>> {
    let modules = candidates();
    let names: Vec<&str> = modules.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(&store.policy.kadm5_hook, &names);
    let mut left = modules;
    let mut out = Vec::new();
    for want in kept {
        if let Some(index) = left.iter().position(|module| module.name() == want) {
            out.push(left.remove(index));
        }
    }
    out
}

/// MIT `ITERATE` (`kadm5_hook.c`): precommit returns the first error.
/// Postcommit logs `kadm5_hook %s failed postcommit %s: %s` and continues.
fn walk(
    store: &PrincipalStore,
    stage: HookStage,
    operation: &'static str,
    mut call: impl FnMut(&dyn Kadm5Hook) -> Result<(), Error>,
) -> Result<(), Error> {
    for module in selected(store) {
        if let Err(err) = call(module.as_ref()) {
            if stage == HookStage::Precommit {
                return Err(err);
            }
            krb5_log::klog::syslog(
                krb5_log::klog::Severity::Err,
                &format!(
                    "kadm5_hook {} failed postcommit {operation}: {err}",
                    module.name()
                ),
            );
        }
    }
    Ok(())
}

pub(super) fn hook_chpass(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
    keepold: u32,
    password: Option<&[u8]>,
    etypes: &[EncryptionType],
) -> Result<(), Error> {
    walk(store, stage, "chpass", |module| {
        module.chpass(stage, princ, realm, keepold, password, etypes)
    })
}

pub(super) fn hook_create(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
    mask: u32,
    password: Option<&[u8]>,
    etypes: &[EncryptionType],
) -> Result<(), Error> {
    walk(store, stage, "create", |module| {
        module.create(stage, princ, realm, mask, password, etypes)
    })
}

pub(super) fn hook_modify(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
    mask: u32,
) -> Result<(), Error> {
    walk(store, stage, "modify", |module| {
        module.modify(stage, princ, realm, mask)
    })
}

pub(super) fn hook_rename(
    store: &PrincipalStore,
    stage: HookStage,
    old: &PrincipalName,
    old_realm: &str,
    new: &PrincipalName,
    new_realm: &str,
) -> Result<(), Error> {
    walk(store, stage, "rename", |module| {
        module.rename(stage, old, old_realm, new, new_realm)
    })
}

pub(super) fn hook_remove(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
) -> Result<(), Error> {
    walk(store, stage, "remove", |module| {
        module.remove(stage, princ, realm)
    })
}

pub(super) fn hook_alias(
    store: &PrincipalStore,
    stage: HookStage,
    alias_name: &PrincipalName,
    alias_realm: &str,
    target: &PrincipalName,
    target_realm: &str,
) -> Result<(), Error> {
    walk(store, stage, "alias", |module| {
        module.alias(stage, alias_name, alias_realm, target, target_realm)
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::store::AdminEnt;
    use crate::store::AdminFields;
    use crate::testrealm::{TEST_REALM, TEST_USER};

    struct Rec {
        name: &'static str,
        fail_pre: bool,
        fail_post: bool,
        hits: Mutex<Vec<String>>,
    }

    impl Rec {
        fn new(name: &'static str, fail_pre: bool, fail_post: bool) -> Arc<Self> {
            Arc::new(Self {
                name,
                fail_pre,
                fail_post,
                hits: Mutex::new(Vec::new()),
            })
        }

        fn note(&self, op: &str, stage: HookStage, extra: &str) -> Result<(), Error> {
            let which = match stage {
                HookStage::Precommit => "pre",
                HookStage::Postcommit => "post",
            };
            let item = if extra.is_empty() {
                format!("{op}:{which}")
            } else {
                format!("{op}:{which}:{extra}")
            };
            self.hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(item);
            if self.fail_pre && stage == HookStage::Precommit {
                return Err(Error::InvalidArgument("hook refused".into()));
            }
            if self.fail_post && stage == HookStage::Postcommit {
                return Err(Error::InvalidArgument("hook post".into()));
            }
            Ok(())
        }

        fn seen(&self) -> Vec<String> {
            self.hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl Kadm5Hook for Rec {
        fn name(&self) -> &'static str {
            self.name
        }

        fn chpass(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
            _keepold: u32,
            password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            let extra = if password.is_none() { "none" } else { "pw" };
            self.note("chpass", stage, extra)
        }

        fn create(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
            _mask: u32,
            _password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            self.note("create", stage, "")
        }

        fn modify(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
            _mask: u32,
        ) -> Result<(), Error> {
            self.note("modify", stage, "")
        }

        fn rename(
            &self,
            stage: HookStage,
            _old: &PrincipalName,
            _old_realm: &str,
            _new: &PrincipalName,
            _new_realm: &str,
        ) -> Result<(), Error> {
            self.note("rename", stage, "")
        }

        fn remove(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
        ) -> Result<(), Error> {
            self.note("remove", stage, "")
        }

        fn alias(
            &self,
            stage: HookStage,
            _alias: &PrincipalName,
            _alias_realm: &str,
            _target: &PrincipalName,
            _target_realm: &str,
        ) -> Result<(), Error> {
            self.note("alias", stage, "")
        }
    }

    struct Count {
        hits: Arc<AtomicU64>,
    }

    impl Kadm5Hook for Count {
        fn name(&self) -> &'static str {
            "nope"
        }

        fn chpass(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
            _keepold: u32,
            _password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            if stage == HookStage::Precommit {
                self.hits.fetch_add(1, Ordering::SeqCst);
                return Err(Error::InvalidArgument("hook refused".into()));
            }
            Ok(())
        }
    }

    struct ClearThread;

    impl Drop for ClearThread {
        fn drop(&mut self) {
            clear_thread_kadm5_hook();
        }
    }

    fn user() -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
    }

    fn named(component: &str) -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [component])
    }

    fn install(module: &Arc<Rec>) -> ClearThread {
        set_thread_kadm5_hook(vec![Arc::clone(module) as Arc<dyn Kadm5Hook>]);
        ClearThread
    }

    fn kvno(store: &PrincipalStore, name: &PrincipalName) -> u32 {
        let id = crate::kdb::lookup_principal_id(name, store.realm());
        store
            .get(&id)
            .expect("principal")
            .keys
            .iter()
            .map(|key| key.kvno)
            .max()
            .expect("key")
    }

    fn present(store: &PrincipalStore, name: &PrincipalName) -> bool {
        let id = crate::kdb::lookup_principal_id(name, store.realm());
        store.get(&id).is_some()
    }

    #[test]
    fn a_precommit_error_on_chpass_writes_nothing() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("bad", true, false);
        let _guard = install(&module);
        let before = kvno(&store, &user());
        let err = store
            .set_password(&user(), b"another-password")
            .expect_err("refused");
        assert!(matches!(err, Error::InvalidArgument(text) if text == "hook refused"));
        assert_eq!(kvno(&store, &user()), before);
        assert_eq!(module.seen(), ["chpass:pre:pw"]);
    }

    #[test]
    fn a_postcommit_error_does_not_fail_chpass() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("bad", false, true);
        let _guard = install(&module);
        let before = kvno(&store, &user());
        store
            .set_password(&user(), b"another-password")
            .expect("postcommit is logged");
        assert!(kvno(&store, &user()) > before);
        assert_eq!(module.seen(), ["chpass:pre:pw", "chpass:post:pw"]);
    }

    #[test]
    fn enable_only_of_an_unknown_hook_keeps_nothing() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        store.policy.kadm5_hook = krb5_config::Krb5Conf::parse(
            "[plugins]\n    kadm5_hook = {\n        enable_only = nosuch\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("kadm5_hook");
        let module = Rec::new("bad", true, false);
        let _guard = install(&module);
        store
            .set_password(&user(), b"another-password")
            .expect("no module is loaded");
        assert_eq!(module.seen(), Vec::<String>::new());
    }

    #[test]
    fn a_kept_module_sees_precommit_then_postcommit() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("yes", false, false);
        let _guard = install(&module);
        store
            .set_password(&user(), b"another-password")
            .expect("chpass");
        store.chrand(&user()).expect("randkey");
        assert_eq!(
            module.seen(),
            [
                "chpass:pre:pw",
                "chpass:post:pw",
                "chpass:pre:none",
                "chpass:post:none",
            ]
        );
    }

    #[test]
    fn precommit_errors_write_nothing_for_the_other_operations() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("bad", true, false);
        let _guard = install(&module);
        let created = named("hooknew");
        store
            .create_principal_3_in(
                &created,
                TEST_REALM,
                Some(b"long-enough"),
                &[],
                &AdminEnt::default(),
                "actor",
            )
            .expect_err("create");
        assert!(!present(&store, &created));
        let life = store
            .get(&crate::kdb::lookup_principal_id(&user(), store.realm()))
            .expect("user")
            .max_life;
        store
            .apply_admin_fields(
                &user(),
                AdminFields {
                    max_life: Some(99),
                    ..AdminFields::default()
                },
            )
            .expect_err("modify");
        assert_eq!(
            store
                .get(&crate::kdb::lookup_principal_id(&user(), store.realm()))
                .expect("user")
                .max_life,
            life
        );
        let renamed = named("hookrenamed");
        store
            .rename_unchecked(&user(), TEST_REALM, &renamed, TEST_REALM, "actor")
            .expect_err("rename");
        assert!(present(&store, &user()));
        assert!(!present(&store, &renamed));
        let alias_name = named("hookalias");
        store
            .create_alias_in(&alias_name, TEST_REALM, &user(), TEST_REALM, "actor")
            .expect_err("alias");
        assert!(!present(&store, &alias_name));
        store.remove_in(&user(), TEST_REALM).expect_err("remove");
        assert!(present(&store, &user()));
        assert_eq!(
            module.seen(),
            [
                "create:pre",
                "modify:pre",
                "rename:pre",
                "alias:pre",
                "remove:pre",
            ]
        );
    }

    #[test]
    fn a_postcommit_error_does_not_stop_the_next_module() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let first = Rec::new("bad", false, true);
        let second = Rec::new("next", false, false);
        set_thread_kadm5_hook(vec![
            Arc::clone(&first) as Arc<dyn Kadm5Hook>,
            Arc::clone(&second) as Arc<dyn Kadm5Hook>,
        ]);
        let _guard = ClearThread;
        store
            .set_password(&user(), b"another-password")
            .expect("still succeeds");
        assert_eq!(first.seen(), ["chpass:pre:pw", "chpass:post:pw"]);
        assert_eq!(second.seen(), ["chpass:pre:pw", "chpass:post:pw"]);
    }

    #[test]
    fn an_empty_thread_list_leaves_chpass_alone() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        set_thread_kadm5_hook(Vec::new());
        let _guard = ClearThread;
        let before = kvno(&store, &user());
        store
            .set_password(&user(), b"another-password")
            .expect("no module");
        assert!(kvno(&store, &user()) > before);
    }

    #[test]
    fn kdc_conf_then_krb5_conf_disables_a_hook() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let hits = Arc::new(AtomicU64::new(0));
        set_thread_kadm5_hook(vec![Arc::new(Count {
            hits: Arc::clone(&hits),
        }) as Arc<dyn Kadm5Hook>]);
        let _guard = ClearThread;
        let kdc = krb5_config::KdcConf::parse(
            "[plugins]\n    kadm5_hook = {\n        disable = nope\n    }\n",
        )
        .expect("kdc.conf");
        let krb5 = krb5_config::Krb5Conf::parse("[plugins]\n").expect("krb5.conf");
        store.apply_kadm5_hook_plugins(Some(&kdc), Some(&krb5));
        store
            .set_password(&user(), b"another-password")
            .expect("disabled");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
